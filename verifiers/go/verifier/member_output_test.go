package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"

	atxconformance "github.com/opena2a-standards/atx-conformance"
)

// The tests in this file hold the report to its rule for the strings of a
// credential: a reason line that shows a string member of the credential
// writes it so that the report stays one block of printable ASCII lines,
// and two values that differ are written differently.
// TestReportOfEachCredentialMember walks the credential of each fixture it
// runs on and finds the members itself, so a line that shows a member is
// held to the rule whether or not a test names it. The literals below are
// JSON, and verifiers/python/test_verify.py holds the Python reference
// verifier to the same checks with the same literals (MEMBER_CELL_FIXTURES,
// MEMBER_CELL_SUFFIXES, MEMBER_CELL_LITERAL, NO_KEY_ID_LINE,
// KEY_ID_LINE_EDITS and KEY_ID_LINE_ESCAPES).

// memberCellFixtures is the shipped fixtures the cell runs on: one a
// signature rejects, whose reason shows the signature's keyId, and one the
// issuer DID rejects, whose reason shows the issuerDid.
const memberCellFixtures = `["fixtures/tampered-signature.json", "fixtures/wrong-issuer.json"]`

// memberCellSuffixes is the strings the cell appends to a member, one at a
// time: a line feed, a carriage return, ESC then [2K, NUL, DEL, the C1
// control U+0085, the zero width space U+200B, the line separator U+2028
// and the right-to-left override U+202E.
const memberCellSuffixes = `["\n", "\r", "\u001b[2K", "\u0000", "\u007f", "\u0085", "\u200b", "\u2028", "\u202e"]`

// memberCellLiteral is the four characters backslash, x, 0 and a: the text
// escapeControls writes for a line feed.
const memberCellLiteral = `"\\x0a"`

// noKeyIDLine is the observed line of fixtures/tampered-signature.json with
// its signature's keyId removed or null: the verifier reads either as the
// empty string, and the reason writes it as "".
const noKeyIDLine = `       observed: REJECT[SIGNATURE_INVALID: Ed25519 signature "" did not verify against any configured public key]`

// keyIDLineEdits is two reasons that write a signature's keyId, each as the
// edit of the first signature of fixtures/tampered-signature.json that
// leads to it: the member the edit sets, the string it sets it to, and the
// observed line the verifier then writes, as start, which runs to the end
// of the keyId as shipped, and end, which runs from the closing quote on.
// TestReportOfEachCredentialMember changes one member per run, and these
// lines show a changed keyId only when the run changes this second member
// too. With the value * the signature is not base64, and end stops before
// the decode error: the Go verifier goes on
// `illegal base64 data at input byte 0]`, the Python one
// `illegal base64 data]`. With the algorithm ML-DSA-65 the signature
// verifies under no configured key.
const keyIDLineEdits = `[
  {"member": "value", "to": "*",
   "start": "       observed: REJECT[SIGNATURE_INVALID: signature \"did:opena2a:authority:opena2a.org#key-1",
   "end": "\" has invalid base64: "},
  {"member": "algorithm", "to": "ML-DSA-65",
   "start": "       observed: REJECT[SIGNATURE_INVALID: ML-DSA-65 signature \"did:opena2a:authority:opena2a.org#key-1",
   "end": "\" did not verify against any configured public key]"}
]`

// keyIDLineEscapes is the text strconv.QuoteToASCII writes, between its
// quotes, for each string of memberCellSuffixes, in that order, and then
// for memberCellLiteral.
const keyIDLineEscapes = `["\\n", "\\r", "\\x1b[2K", "\\x00", "\\x7f", "\\u0085", "\\u200b", "\\u2028", "\\u202e", "\\\\x0a"]`

// fromJSON decodes text, one of the JSON literals above, into v.
func fromJSON(t *testing.T, text string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(text), v); err != nil {
		t.Fatal(err)
	}
}

// memberCellFixture is a shipped fixture as the cell edits it: its members
// as written, and its credential as written.
type memberCellFixture struct {
	doc map[string]json.RawMessage
	atx json.RawMessage
}

func loadMemberCellFixture(t *testing.T, name string) memberCellFixture {
	t.Helper()
	raw, err := fs.ReadFile(atxconformance.Fixtures, name)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return memberCellFixture{doc: doc, atx: doc["atx"]}
}

// credential is a new copy of the fixture's credential, decoded with
// UseNumber so that each number is written back as it is written.
func (f memberCellFixture) credential(t *testing.T) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(f.atx))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// with is the fixture with credential in place of its credential.
func (f memberCellFixture) with(t *testing.T, credential any) []byte {
	t.Helper()
	doc := make(map[string]json.RawMessage, len(f.doc))
	for name, value := range f.doc {
		doc[name] = value
	}
	atx, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	doc["atx"] = atx
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// stringMembers is the path of each string the JSON value v holds: an
// object's members in name order, and an array's items in index order.
func stringMembers(v any, at []any) [][]any {
	var paths [][]any
	switch x := v.(type) {
	case string:
		paths = append(paths, at)
	case map[string]any:
		names := make([]string, 0, len(x))
		for name := range x {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			paths = append(paths, stringMembers(x[name], append(append([]any(nil), at...), name))...)
		}
	case []any:
		for i, item := range x {
			paths = append(paths, stringMembers(item, append(append([]any(nil), at...), i))...)
		}
	}
	return paths
}

// appendAt appends suffix to the string at the path at in v, and returns v.
func appendAt(v any, at []any, suffix string) any {
	if len(at) == 0 {
		return v.(string) + suffix
	}
	switch x := v.(type) {
	case map[string]any:
		name := at[0].(string)
		x[name] = appendAt(x[name], at[1:], suffix)
	case []any:
		i := at[0].(int)
		x[i] = appendAt(x[i], at[1:], suffix)
	}
	return v
}

// pathName is the path at as the messages below name it, for example
// signatures[0].keyId.
func pathName(at []any) string {
	var b strings.Builder
	for _, p := range at {
		switch p := p.(type) {
		case string:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(p)
		case int:
			fmt.Fprintf(&b, "[%d]", p)
		}
	}
	return b.String()
}

// memberCellRun writes body as name in the working directory, runs Run on
// that name, and returns what Run wrote to standard output and its exit
// code.
func memberCellRun(t *testing.T, name string, body []byte) ([]byte, int) {
	t.Helper()
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{name}, &stdout, &stderr)
	return stdout.Bytes(), code
}

// memberCellFailures is each check that out, the standard output of one
// run, and code, its exit code, fail: standard output is printable ASCII
// plus line feeds; it holds exactly one block-marker line (PASS, FAIL or
// SKIP, then two spaces, at column 0); it holds exactly one summary: line,
// and that line is the last; and the exit code is 0 or 1.
func memberCellFailures(out []byte, code int) []string {
	var failures []string
	for _, b := range out {
		if b != '\n' && (b < ' ' || b > '~') {
			failures = append(failures, fmt.Sprintf("standard output holds the byte 0x%02x, outside printable ASCII", b))
			break
		}
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	blocks, summaries := 0, 0
	for _, line := range lines {
		if strings.HasPrefix(line, "PASS  ") || strings.HasPrefix(line, "FAIL  ") || strings.HasPrefix(line, "SKIP  ") {
			blocks++
		}
		if strings.HasPrefix(line, "summary: ") {
			summaries++
		}
	}
	if blocks != 1 {
		failures = append(failures, fmt.Sprintf("%d block-marker lines, want 1", blocks))
	}
	if summaries != 1 || !strings.HasPrefix(lines[len(lines)-1], "summary: ") {
		failures = append(failures, fmt.Sprintf("%d summary: lines, want 1, the last line", summaries))
	}
	if code != 0 && code != 1 {
		failures = append(failures, fmt.Sprintf("exit code %d, want 0 or 1", code))
	}
	return failures
}

// TestReportOfEachCredentialMember runs Run on copies of each fixture of
// memberCellFixtures, each with one suffix of memberCellSuffixes appended
// to one string member of its credential, every member and every suffix in
// turn, and holds each report to memberCellFailures. A member for which a
// suffix changes the report is one a line shows. For each such member, the
// run with a line feed appended and the run with memberCellLiteral
// appended must print different standard output, so the report tells a
// line feed in the credential from text that reads as its escape.
func TestReportOfEachCredentialMember(t *testing.T) {
	var fixtures, suffixes []string
	var literal string
	fromJSON(t, memberCellFixtures, &fixtures)
	fromJSON(t, memberCellSuffixes, &suffixes)
	fromJSON(t, memberCellLiteral, &literal)
	chdir(t, t.TempDir())
	for _, name := range fixtures {
		f := loadMemberCellFixture(t, name)
		file := path.Base(name)
		control, code := memberCellRun(t, file, f.with(t, f.credential(t)))
		if failures := memberCellFailures(control, code); failures != nil {
			t.Fatalf("%s as shipped: %s\nreport: %q", name, strings.Join(failures, "; "), control)
		}
		shown := 0
		for _, at := range stringMembers(f.credential(t), nil) {
			member := pathName(at)
			changed := false
			var lineFeed []byte
			for _, suffix := range suffixes {
				out, code := memberCellRun(t, file, f.with(t, appendAt(f.credential(t), at, suffix)))
				for _, failure := range memberCellFailures(out, code) {
					t.Errorf("%s, %s with %+q appended: %s\nreport: %q", name, member, suffix, failure, out)
				}
				changed = changed || !bytes.Equal(out, control)
				if suffix == "\n" {
					lineFeed = out
				}
			}
			if !changed {
				continue
			}
			shown++
			out, code := memberCellRun(t, file, f.with(t, appendAt(f.credential(t), at, literal)))
			for _, failure := range memberCellFailures(out, code) {
				t.Errorf("%s, %s with %s appended: %s\nreport: %q", name, member, literal, failure, out)
			}
			if bytes.Equal(out, lineFeed) {
				t.Errorf("%s, %s: the report with a line feed appended is the report with %s appended\nreport: %q", name, member, literal, out)
			}
		}
		if shown == 0 {
			t.Errorf("%s: no suffix on any member of its credential changes the report", name)
		}
	}
}

// TestSignatureWithNoKeyIDIsWrittenAsEmptyQuotes runs Run on
// fixtures/tampered-signature.json with its signature's keyId removed, and
// with it null. The verifier reads either as the empty string, and the
// reason writes it as "": noKeyIDLine, the line the Python reference
// verifier writes for the same input.
func TestSignatureWithNoKeyIDIsWrittenAsEmptyQuotes(t *testing.T) {
	f := loadMemberCellFixture(t, "fixtures/tampered-signature.json")
	chdir(t, t.TempDir())
	for _, c := range []struct {
		name string
		edit func(signature map[string]any)
	}{
		{"no keyId", func(signature map[string]any) { delete(signature, "keyId") }},
		{"a null keyId", func(signature map[string]any) { signature["keyId"] = nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			credential := f.credential(t)
			signatures, ok := credential.(map[string]any)["signatures"].([]any)
			if !ok || len(signatures) == 0 {
				t.Fatal("fixtures/tampered-signature.json carries no signature")
			}
			c.edit(signatures[0].(map[string]any))
			out, code := memberCellRun(t, "tampered-signature.json", f.with(t, credential))
			if code != 0 || !strings.Contains(string(out), "\n"+noKeyIDLine+"\n") {
				t.Errorf("exit %d, report %q; want exit 0 and the line %q", code, out, noKeyIDLine)
			}
		})
	}
}

// TestKeyIDInTheBase64AndMLDSA65Reasons runs Run on copies of
// fixtures/tampered-signature.json, each with one edit of keyIDLineEdits
// made to its first signature and with nothing, or one string of
// memberCellSuffixes or memberCellLiteral, appended to that signature's
// keyId, every edit and every string in turn. Each report must pass
// memberCellFailures and hold exactly one line that starts with the edit's
// start, then the appended string as keyIDLineEscapes writes it, then the
// edit's end. The test also holds keyIDLineEscapes to strconv.QuoteToASCII,
// and KeyIdInTheBase64AndMlDsa65Reasons in the Python suite holds the
// Python reference verifier to the same lines.
func TestKeyIDInTheBase64AndMLDSA65Reasons(t *testing.T) {
	var edits []struct {
		Member string `json:"member"`
		To     string `json:"to"`
		Start  string `json:"start"`
		End    string `json:"end"`
	}
	var suffixes, escapes []string
	var literal string
	fromJSON(t, keyIDLineEdits, &edits)
	fromJSON(t, memberCellSuffixes, &suffixes)
	fromJSON(t, memberCellLiteral, &literal)
	fromJSON(t, keyIDLineEscapes, &escapes)
	appended := append(append([]string(nil), suffixes...), literal)
	if len(escapes) != len(appended) {
		t.Fatalf("keyIDLineEscapes holds %d strings, want %d: memberCellSuffixes and memberCellLiteral", len(escapes), len(appended))
	}
	for i, suffix := range appended {
		if quoted := strconv.QuoteToASCII(suffix); quoted != `"`+escapes[i]+`"` {
			t.Errorf("keyIDLineEscapes writes %+q as %s, strconv.QuoteToASCII writes %s", suffix, escapes[i], quoted)
		}
	}
	// The first run of each edit appends nothing: the keyId as shipped.
	appended = append([]string{""}, appended...)
	escapes = append([]string{""}, escapes...)
	f := loadMemberCellFixture(t, "fixtures/tampered-signature.json")
	chdir(t, t.TempDir())
	for _, edit := range edits {
		for i, suffix := range appended {
			credential := f.credential(t)
			signatures, ok := credential.(map[string]any)["signatures"].([]any)
			if !ok || len(signatures) == 0 {
				t.Fatal("fixtures/tampered-signature.json carries no signature")
			}
			signature := signatures[0].(map[string]any)
			keyID, ok := signature["keyId"].(string)
			if !ok {
				t.Fatal("the first signature of fixtures/tampered-signature.json carries no keyId")
			}
			signature[edit.Member] = edit.To
			signature["keyId"] = keyID + suffix
			run := fmt.Sprintf("%s set to %q, %+q appended to the keyId", edit.Member, edit.To, suffix)
			out, code := memberCellRun(t, "tampered-signature.json", f.with(t, credential))
			for _, failure := range memberCellFailures(out, code) {
				t.Errorf("%s: %s\nreport: %q", run, failure, out)
			}
			want := edit.Start + escapes[i] + edit.End
			found := 0
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, want) {
					found++
				}
			}
			if found != 1 {
				t.Errorf("%s: %d lines start with %q, want 1\nreport: %q", run, found, want, out)
			}
		}
	}
}
