package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"

	atxconformance "github.com/opena2a-standards/atx-conformance"
)

// The tests in this file hold the report to its rule for control
// characters: each string a fixture, a file name or a path supplies is
// written with every C0 control, DEL and C1 control in it escaped, never
// written as the control and never dropped, so a line of the report is one
// line on a terminal and shows what the input carried. They call Run, and
// escape_mutants_test.go runs the same checks with escapers that write less
// and shows that each of those escapers fails a check.

// controlDID is an issuer DID holding one character of each kind the report
// escapes, each after a letter: NUL, a tab, a line feed, a carriage return,
// BEL, ESC, DEL and the C1 control U+009B.
const controlDID = "did:opena2a:authority:a\x00b\tc\nd\re\x07f\x1bg\x7fh\u009bi"

// controlDIDEscaped is controlDID as the report writes it.
const controlDIDEscaped = `did:opena2a:authority:a\x00b\x09c\x0ad\x0de\x07f\x1bg\x7fh\u009bi`

// controlName is a name holding one character of each kind the report
// escapes that a file name can hold, each after a letter: a tab, a line
// feed, a carriage return, BEL, ESC, DEL and U+009B.
const controlName = "a\tb\nc\rd\x07e\x1bf\x7fg\u009bh"

// controlNameEscaped is controlName as the report writes it.
const controlNameEscaped = `a\x09b\x0ac\x0dd\x07e\x1bf\x7fg\u009bh`

// nonUTF8Name is a file name holding the byte 0x9b, a C1 control to a
// terminal that reads 8-bit codes, and the byte 0xff, neither of them UTF-8.
// A file system that takes only UTF-8 names, as APFS does, refuses it.
const nonUTF8Name = "b\x9b\xff.json"

// shippedIssuerLine is the observed line of the report of
// fixtures/wrong-issuer.json, whose issuer DID holds no control.
const shippedIssuerLine = "       observed: REJECT[UNTRUSTED_ISSUER: issuer DID did:opena2a:authority:attacker.example is not in the verifier's trusted set (untrusted issuer)]"

// controlCase is one input the escaping is checked on: the files and
// directories it lays out in an empty working directory, the arguments it
// runs with, a string the input carries with the text the report writes
// for it, the line of the report that holds that text, which the Python
// reference verifier writes the same (CONTROL_CASES in
// verifiers/python/test_verify.py), and the number of line feeds the
// report holds, that of the same input with no control in it.
type controlCase struct {
	name         string
	files        map[string][]byte
	dirs         []string
	args         []string
	raw, escaped string
	line         string
	lineFeeds    int
	// needsNonUTF8 is set where a file name is not UTF-8: the case is
	// skipped where the file system refuses that name.
	needsNonUTF8 bool
}

// wrongIssuer is the bytes of the shipped fixture fixtures/wrong-issuer.json.
func wrongIssuer(t *testing.T) []byte {
	t.Helper()
	raw, err := fs.ReadFile(atxconformance.Fixtures, "fixtures/wrong-issuer.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// withIssuerDID is fixtures/wrong-issuer.json with its credential's issuerDid
// set to did. It still rejects as the fixture expects, UNTRUSTED_ISSUER, so
// the report writes did in its observed line.
func withIssuerDID(t *testing.T, did string) []byte {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(wrongIssuer(t), &doc); err != nil {
		t.Fatal(err)
	}
	var credential map[string]json.RawMessage
	if err := json.Unmarshal(doc["atx"], &credential); err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(did)
	if err != nil {
		t.Fatal(err)
	}
	credential["issuerDid"] = value
	if doc["atx"], err = json.Marshal(credential); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// controlCases is every input the escaping is checked on.
func controlCases(t *testing.T) []controlCase {
	t.Helper()
	shipped := wrongIssuer(t)
	return []controlCase{
		{
			name:      "an issuer DID",
			files:     map[string][]byte{"issuer.json": withIssuerDID(t, controlDID)},
			args:      []string{"issuer.json"},
			raw:       controlDID,
			escaped:   controlDIDEscaped,
			line:      "       observed: REJECT[UNTRUSTED_ISSUER: issuer DID " + controlDIDEscaped + " is not in the verifier's trusted set (untrusted issuer)]",
			lineFeeds: 5,
		},
		{
			name:      "a file name",
			files:     map[string][]byte{controlName + ".json": shipped},
			args:      []string{controlName + ".json"},
			raw:       controlName,
			escaped:   controlNameEscaped,
			line:      "PASS  " + controlNameEscaped + ".json",
			lineFeeds: 5,
		},
		{
			name:      "a path that does not exist",
			args:      []string{controlName + ".json"},
			raw:       controlName,
			escaped:   controlNameEscaped,
			line:      "error: " + controlNameEscaped + ".json: no such file or directory",
			lineFeeds: 1,
		},
		{
			name:      "an unknown option",
			args:      []string{"-" + controlName},
			raw:       controlName,
			escaped:   controlNameEscaped,
			line:      "unknown option: -" + controlNameEscaped,
			lineFeeds: 1 + strings.Count(usage, "\n"),
		},
		{
			name:      "a directory holding no fixture",
			dirs:      []string{controlName},
			args:      []string{controlName},
			raw:       controlName,
			escaped:   controlNameEscaped,
			line:      "no fixture *.json files found in " + controlNameEscaped + " (subdirectories are not walked)",
			lineFeeds: 1,
		},
		{
			name:      "a path that is not UTF-8 and does not exist",
			args:      []string{nonUTF8Name},
			raw:       "\x9b",
			escaped:   `b\x9b` + "\xff.json",
			line:      "error: " + `b\x9b` + "\xff.json: no such file or directory",
			lineFeeds: 1,
		},
		{
			name:         "a file name that is not UTF-8",
			files:        map[string][]byte{nonUTF8Name: shipped},
			args:         []string{nonUTF8Name},
			raw:          "\x9b",
			escaped:      `b\x9b` + "\xff.json",
			line:         "PASS  " + `b\x9b` + "\xff.json",
			lineFeeds:    5,
			needsNonUTF8: true,
		},
	}
}

// reportOf lays out c in an empty working directory, runs report there with
// c's arguments, and returns what it wrote to standard output followed by
// what it wrote to standard error, and its exit code.
func reportOf(t *testing.T, c controlCase, report func(args []string, stdout, stderr io.Writer) int) ([]byte, int) {
	t.Helper()
	dir := t.TempDir()
	// Each error is written with %q: it names a path, which holds controls.
	for _, d := range c.dirs {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatalf("%q", err.Error())
		}
	}
	for name, body := range c.files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			// APFS refuses a name that is not UTF-8 with EILSEQ, and exFAT
			// on macOS with EINVAL.
			if c.needsNonUTF8 && (errors.Is(err, syscall.EILSEQ) || errors.Is(err, syscall.EINVAL)) {
				t.Skipf("the file system refuses the name %q: %q", name, err.Error())
			}
			t.Fatalf("%q", err.Error())
		}
	}
	chdir(t, dir)
	var stdout, stderr bytes.Buffer
	code := report(c.args, &stdout, &stderr)
	return append(stdout.Bytes(), stderr.Bytes()...), code
}

// rawControls counts what no report may hold: a C0 control other than the
// line feed, DEL, a C1 control written as UTF-8, and a byte 0x80 to 0x9f
// that is not UTF-8.
type rawControls struct{ c0, del, c1, c1Bytes int }

func countRawControls(out []byte) rawControls {
	var n rawControls
	for i := 0; i < len(out); {
		r, size := utf8.DecodeRune(out[i:])
		switch {
		case r == '\n':
		case r < 0x20:
			n.c0++
		case r == 0x7f:
			n.del++
		case 0x80 <= r && r <= 0x9f:
			n.c1++
		case r == utf8.RuneError && size == 1 && 0x80 <= out[i] && out[i] <= 0x9f:
			n.c1Bytes++
		}
		i += size
	}
	return n
}

// checkNoRawControls fails when out, a report's standard output and
// standard error, holds a raw control, or another number of line feeds than
// c's: a line feed the input carries, written as it is, splits a line.
func checkNoRawControls(c controlCase, out []byte) error {
	if n := countRawControls(out); n != (rawControls{}) {
		return fmt.Errorf("the report holds raw controls (%d C0, %d DEL, %d C1, %d C1 bytes not UTF-8)", n.c0, n.del, n.c1, n.c1Bytes)
	}
	if got := bytes.Count(out, []byte("\n")); got != c.lineFeeds {
		return fmt.Errorf("the report holds %d line feeds, want %d", got, c.lineFeeds)
	}
	return nil
}

// checkShowsEscaped fails when out does not hold the escaped text of the
// string c's input carries, or holds the string itself.
func checkShowsEscaped(c controlCase, out []byte) error {
	if !bytes.Contains(out, []byte(c.escaped)) {
		return fmt.Errorf("the report does not show %q", c.escaped)
	}
	if bytes.Contains(out, []byte(c.raw)) {
		return fmt.Errorf("the report holds %q as it is", c.raw)
	}
	return nil
}

// checkC1Escaped fails when out holds U+009B written as UTF-8, or the input
// carries U+009B and out does not show its escape.
func checkC1Escaped(c controlCase, out []byte) error {
	if bytes.Contains(out, []byte("\u009b")) {
		return errors.New("the report holds U+009B as it is")
	}
	if strings.Contains(c.raw, "\u009b") && !bytes.Contains(out, []byte(`\u009b`)) {
		return errors.New(`the report does not show U+009B as \u009b`)
	}
	return nil
}

// checkLine fails when no line of out is c's line, the line the Python
// reference verifier writes for the same input.
func checkLine(c controlCase, out []byte) error {
	for _, line := range strings.Split(string(out), "\n") {
		if line == c.line {
			return nil
		}
	}
	return fmt.Errorf("no line of the report is %q", c.line)
}

// controlChecks is every check a report of a controlCase passes.
var controlChecks = []struct {
	name  string
	check func(controlCase, []byte) error
}{
	{"no raw control", checkNoRawControls},
	{"escaped, not dropped", checkShowsEscaped},
	{"C1 escaped", checkC1Escaped},
	{"the line the Python verifier writes", checkLine},
}

// TestReportEscapesControls runs Run on each controlCase and holds its
// report to each check: each control the input carries is written as its
// escape, in the line the Python reference verifier writes, and the report
// has as many lines as that of the same input with no control in it.
func TestReportEscapesControls(t *testing.T) {
	for _, c := range controlCases(t) {
		t.Run(c.name, func(t *testing.T) {
			out, _ := reportOf(t, c, Run)
			for _, k := range controlChecks {
				if err := k.check(c, out); err != nil {
					t.Errorf("%s: %v\nreport: %q", k.name, err, out)
				}
			}
		})
	}
}

// TestReportOfControlsKeepsTheVerdict pins that a fixture whose issuer DID
// or file name carries controls is verified as the shipped fixture is: it
// rejects as UNTRUSTED_ISSUER, as it expects, and passes.
func TestReportOfControlsKeepsTheVerdict(t *testing.T) {
	for _, c := range controlCases(t)[:2] {
		t.Run(c.name, func(t *testing.T) {
			out, code := reportOf(t, c, Run)
			if code != 0 || !bytes.HasSuffix(out, []byte("\nsummary: 1 pass, 0 fail (1 fixture)\n")) {
				t.Errorf("exit %d, report %q; want exit 0 and 1 pass", code, out)
			}
		})
	}
}

// TestShippedFixtureReportHoldsNoControl pins that the report of the
// shipped fixture set holds no control, so escaping leaves it as it was:
// docs/captures/go-verifier.txt, which TestCaptureIsVerifierOutput holds to
// Run's output, is unchanged by it. It also pins the observed line of
// fixtures/wrong-issuer.json, the fixture the cases above are made from.
func TestShippedFixtureReportHoldsNoControl(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	out := append(stdout.Bytes(), stderr.Bytes()...)
	if n := countRawControls(out); n != (rawControls{}) {
		t.Errorf("the report of the shipped fixtures holds controls: %+v", n)
	}
	if !strings.Contains(stdout.String(), "PASS  fixtures/wrong-issuer.json\n       expected: REJECT [UNTRUSTED_ISSUER]\n"+shippedIssuerLine+"\n") {
		t.Errorf("the report of fixtures/wrong-issuer.json is not\n%s", shippedIssuerLine)
	}
}
