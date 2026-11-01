package verifier

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// TestEscapeControls pins escapeControls on each kind of character: a C0
// control, DEL and a C1 control are escaped, a byte that is not UTF-8 is
// escaped when it is 0x80 to 0x9f and written as it is otherwise, and every
// other character is written as it is, a backslash among them. The table is
// bytes in and bytes out, and verifiers/python/test_verify.py holds the same
// table for _escape_controls (ESCAPE_CONTROLS_TABLE), each byte that is not
// UTF-8 read there as the surrogate escape os.fsdecode reads it as.
func TestEscapeControls(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"did:opena2a:authority:x", "did:opena2a:authority:x"},
		{"\x00", `\x00`},
		{"\t", `\x09`},
		{"\n", `\x0a`},
		{"\r", `\x0d`},
		{"\x07", `\x07`},
		{"\x1b", `\x1b`},
		{"\x1f", `\x1f`},
		{" ~", " ~"},
		{"\x7f", `\x7f`},
		{"\u0080", `\u0080`},
		{"\u009b", `\u009b`},
		{"\u009f", `\u009f`},
		{" ", " "},
		{"é", "é"},
		{"�", "�"},
		{`\x1b`, `\x1b`},
		{"\x80", `\x80`},
		{"\x9b", `\x9b`},
		{"\x9f", `\x9f`},
		{"\xa0", "\xa0"},
		{"\xff", "\xff"},
		{"\xe2\x80", "\xe2" + `\x80`},
		{"\xc0\x80", "\xc0" + `\x80`},
		{"\xed\xa0\x80", "\xed\xa0" + `\x80`},
		{"a\x1bb\u009bc\x9bd", `a\x1bb\u009bc\x9bd`},
	} {
		if got := escapeControls(c.in); got != c.want {
			t.Errorf("escapeControls(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// writeAsIs writes each string as it is: the report of a verifier that
// escapes nothing, as Run's was before escapeControls.
func writeAsIs(s string) string { return s }

// escapeDIDOnly escapes a string that holds a DID and writes any other as it
// is: an issuer DID is escaped, and a file name or a path is not.
func escapeDIDOnly(s string) string {
	if strings.Contains(s, "did:") {
		return escapeControls(s)
	}
	return s
}

// escapeC0Only escapes each C0 control and DEL, and writes a C1 control as
// it is.
func escapeC0Only(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, `\x%02x`, r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// dropControls drops each control escapeControls escapes instead of
// escaping it.
func dropControls(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (0x80 <= r && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// reportWith is Run with esc in place of escapeControls.
func reportWith(esc func(string) string) func(args []string, stdout, stderr io.Writer) int {
	return func(args []string, stdout, stderr io.Writer) int {
		return run(args, stdout, stderr, esc)
	}
}

// TestChecksFailOnEscapersThatWriteLess runs the checks of
// TestReportEscapesControls with escapers that write less than
// escapeControls, each beside escapeControls itself, and shows that each
// such escaper fails the check named for it while escapeControls passes it:
// escaping the issuer DID but not a file name fails "no raw control" on a
// file name, escaping C0 but not C1 fails "C1 escaped", dropping controls
// fails "escaped, not dropped", and escaping in the Python verifier alone,
// as writeAsIs does here, fails "the line the Python verifier writes".
func TestChecksFailOnEscapersThatWriteLess(t *testing.T) {
	cases := map[string]controlCase{}
	for _, c := range controlCases(t) {
		cases[c.name] = c
	}
	checks := map[string]func(controlCase, []byte) error{}
	for _, k := range controlChecks {
		checks[k.name] = k.check
	}
	for _, m := range []struct {
		escaper     string
		esc         func(string) string
		input       string
		fails       string
		passesToo   []string // checks this escaper passes on the same input
		passesInput string   // an input this escaper passes every check on
	}{
		{"escapeDIDOnly", escapeDIDOnly, "a file name", "no raw control", nil, "an issuer DID"},
		{"escapeC0Only", escapeC0Only, "an issuer DID", "C1 escaped", nil, ""},
		{"dropControls", dropControls, "an issuer DID", "escaped, not dropped", []string{"no raw control"}, ""},
		{"writeAsIs", writeAsIs, "an issuer DID", "the line the Python verifier writes", nil, ""},
	} {
		t.Run(m.escaper, func(t *testing.T) {
			c, check := cases[m.input], checks[m.fails]
			if real, _ := reportOf(t, c, reportWith(escapeControls)); check(c, real) != nil {
				t.Fatalf("escapeControls fails %q on %s: %v", m.fails, m.input, check(c, real))
			}
			out, _ := reportOf(t, c, reportWith(m.esc))
			if check(c, out) == nil {
				t.Errorf("%s passes %q on %s; the check does not tell it from escapeControls\nreport: %q", m.escaper, m.fails, m.input, out)
			}
			for _, name := range m.passesToo {
				if err := checks[name](c, out); err != nil {
					t.Errorf("%s fails %q on %s too (%v); it should fail %q alone", m.escaper, name, m.input, err, m.fails)
				}
			}
			if m.passesInput != "" {
				other := cases[m.passesInput]
				out, _ := reportOf(t, other, reportWith(m.esc))
				for _, k := range controlChecks {
					if err := k.check(other, out); err != nil {
						t.Errorf("%s fails %q on %s (%v); it should pass every check there", m.escaper, k.name, m.passesInput, err)
					}
				}
			}
		})
	}
}

// TestEscapingLeavesTheShippedFixtureReport pins that the report of the
// shipped fixture set is the same written through escapeControls and
// written as it is: no string of it holds a control.
func TestEscapingLeavesTheShippedFixtureReport(t *testing.T) {
	var escaped, escapedErr, asIs, asIsErr bytes.Buffer
	escapedCode := run(nil, &escaped, &escapedErr, escapeControls)
	asIsCode := run(nil, &asIs, &asIsErr, writeAsIs)
	if escapedCode != asIsCode || !bytes.Equal(escaped.Bytes(), asIs.Bytes()) || !bytes.Equal(escapedErr.Bytes(), asIsErr.Bytes()) {
		t.Errorf("the report of the shipped fixtures differs when written through escapeControls (exit %d, %d bytes) and as it is (exit %d, %d bytes)",
			escapedCode, escaped.Len(), asIsCode, asIs.Len())
	}
}
