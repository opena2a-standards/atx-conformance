// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// The fixture counts conformance.json holds at this commit, which the
// self-tests' buckets follow: 41 fixtures, 9 that must be accepted and 32
// that must be rejected. A change to the fixture set changes them here, in
// the same commit as the README's counts.
const (
	fixturesAtThisCommit   = 41
	mustAcceptAtThisCommit = 9
	mustRejectAtThisCommit = 32
)

// fixedEnv is a runEnv with a fixed clock and a pseudo-version build.
var fixedEnv = runEnv{
	now: func() time.Time { return time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC) },
	buildInfo: func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			GoVersion: "go1.22.0",
			Main: debug.Module{
				Path:    "github.com/opena2a-standards/atx-conformance",
				Version: "v0.0.0-20261104120000-7fec04045590",
			},
		}, true
	},
}

// kitRun runs the kit with args and returns its exit code, stdout and
// stderr.
func kitRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut, fixedEnv)
	return code, out.String(), errOut.String()
}

// readReport runs the kit with --report and returns the exit code, stdout
// and the parsed JSON report, after checking the Markdown report beside it
// carries the four numbers.
func readReport(t *testing.T, args ...string) (int, string, Report) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "report")
	code, out, errOut := kitRun(t, append(args, "--report", dir)...)
	if errOut != "" {
		t.Errorf("stderr: %s", errOut)
	}
	b, err := os.ReadFile(filepath.Join(dir, reportJSONName))
	if err != nil {
		t.Fatalf("no JSON report: %v\nstdout:\n%s", err, out)
	}
	var rep Report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("the JSON report does not parse: %v", err)
	}
	md, err := os.ReadFile(filepath.Join(dir, reportMDName))
	if err != nil {
		t.Fatalf("no Markdown report: %v", err)
	}
	for _, line := range []string{
		"| Agree | " + itoa(rep.Summary.Agree) + " |",
		"| Accepted what must fail | " + itoa(rep.Summary.AcceptedMustFail) + " |",
		"| Rejected what must pass | " + itoa(rep.Summary.RejectedMustPass) + " |",
		"| Couldn't read | " + itoa(rep.Summary.CouldNotRead) + " |",
		rep.InteropNote,
	} {
		if !strings.Contains(string(md), line) {
			t.Errorf("the Markdown report lacks %q", line)
		}
	}
	return code, out, rep
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func checkSummary(t *testing.T, got Summary, want Summary) {
	t.Helper()
	if got != want {
		t.Errorf("summary = %+v, want %+v", got, want)
	}
}

func TestAnswerKeyCountsAtThisCommit(t *testing.T) {
	s, err := loadSuite()
	if err != nil {
		t.Fatal(err)
	}
	accept := 0
	for _, e := range s.entries {
		if e.mustAccept {
			accept++
		}
	}
	if len(s.entries) != fixturesAtThisCommit || accept != mustAcceptAtThisCommit || len(s.entries)-accept != mustRejectAtThisCommit {
		t.Fatalf("conformance.json holds %d fixtures, %d to accept and %d to reject; this test says %d, %d and %d",
			len(s.entries), accept, len(s.entries)-accept, fixturesAtThisCommit, mustAcceptAtThisCommit, mustRejectAtThisCommit)
	}
	if s.manifestMatches != len(s.entries) {
		t.Errorf("%d of %d embedded fixtures match MANIFEST.sha256", s.manifestMatches, len(s.entries))
	}
}

// Self-test 1: the repository's Go reference verifier through --verifier
// agrees on every fixture.
func TestSelfTest1GoReferenceVerifierAgreesOnEveryFixture(t *testing.T) {
	code, out, rep := readReport(t, "--verifier", quote(dummies["goverifier"])+" {file}", "--label", "Go reference verifier")
	checkSummary(t, rep.Summary, Summary{Agree: fixturesAtThisCommit})
	if code != 0 {
		t.Errorf("exit %d, want 0\n%s", code, out)
	}
	if len(rep.TopReasons) != 0 {
		t.Errorf("top reasons = %+v, want none", rep.TopReasons)
	}
	if !strings.Contains(out, compareLimit) || strings.Contains(out, credentialOnlyLimit) {
		t.Errorf("a command with {file} is told the comparison limit and not the credential-only limit:\n%s", out)
	}
	for _, r := range rep.Fixtures {
		if strings.HasPrefix(r.Expected, "REJECT") && !strings.HasPrefix(r.Reason, "REJECT") {
			t.Errorf("%s: reason %q does not carry the verifier's REJECT line", r.Fixture, r.Reason)
		}
	}
}

// Self-test 3: a verifier that always answers ACCEPT agrees on the fixtures
// that must be accepted and accepts every one that must fail.
func TestSelfTest3AlwaysAcceptIsCaught(t *testing.T) {
	code, out, rep := readReport(t, "--verifier", quote(dummies["acceptall"]), "--label", "always ACCEPT")
	checkSummary(t, rep.Summary, Summary{Agree: mustAcceptAtThisCommit, AcceptedMustFail: mustRejectAtThisCommit})
	if code != 1 {
		t.Errorf("exit %d, want 1\n%s", code, out)
	}
	want := "Verifier always ACCEPT answered 41 of 41 ATX credentials and agreed with the answer key on 9; it accepted 32 that must fail and rejected 0 that must pass."
	if rep.InteropNote != want {
		t.Errorf("interop note = %q, want %q", rep.InteropNote, want)
	}
}

// Self-test 4: a verifier that reads JWTs only reads none of the fixtures,
// whether it is given the credential on stdin or the fixture file.
func TestSelfTest4JWTOnlyReadsNothing(t *testing.T) {
	for _, command := range []string{quote(dummies["jwtonly"]), quote(dummies["jwtonly"]) + " {file}"} {
		code, out, rep := readReport(t, "--verifier", command, "--label", "JWT only")
		checkSummary(t, rep.Summary, Summary{CouldNotRead: fixturesAtThisCommit})
		if code != 1 {
			t.Errorf("%s: exit %d, want 1\n%s", command, code, out)
		}
		wantReason := "exit status 2: not a JWT: expected three base64url parts separated by dots"
		if len(rep.TopReasons) != 1 || rep.TopReasons[0] != (ReasonCount{Reason: wantReason, Count: fixturesAtThisCommit}) {
			t.Errorf("%s: top reasons = %+v", command, rep.TopReasons)
		}
		if !strings.HasPrefix(rep.InteropNote, "Verifier JWT only read 0 of 41 ATX credentials; every one came back as couldn't read") {
			t.Errorf("%s: interop note = %q", command, rep.InteropNote)
		}
	}
}

func TestReportRecordsTheRun(t *testing.T) {
	_, out, rep := readReport(t, "--verifier", quote(dummies["acceptall"]), "--label", "acceptall 1.0")
	manifest, err := os.ReadFile(filepath.Join("..", "MANIFEST.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][2]string{
		"kit":            {rep.Kit, kitName},
		"kitVersion":     {rep.KitVersion, "v0.0.0-20261104120000-7fec04045590"},
		"suiteCommit":    {rep.SuiteCommit, "7fec04045590"},
		"manifestSha256": {rep.ManifestSHA256, sha256Hex(manifest)},
		"manifestCheck":  {rep.ManifestCheck, "41 of 41 fixtures match MANIFEST.sha256"},
		"label":          {rep.Label, "acceptall 1.0"},
		"adapter":        {rep.Adapter, "command"},
		"form":           {rep.Form, "native"},
		"startedAt":      {rep.StartedAt, "2026-11-05T08:00:00Z"},
	}
	for field, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", field, c[0], c[1])
		}
	}
	if rep.TimeoutSeconds != 30 || rep.FixtureCount != fixturesAtThisCommit || len(rep.Fixtures) != fixturesAtThisCommit {
		t.Errorf("timeout %v, fixtureCount %d, %d rows", rep.TimeoutSeconds, rep.FixtureCount, len(rep.Fixtures))
	}
	if rep.Fixtures[0].Fixture != "baseline-valid-hybrid.json" || rep.Fixtures[0].Expected != "ACCEPT" || rep.Fixtures[0].Requirement == "" {
		t.Errorf("first row = %+v", rep.Fixtures[0])
	}
	first := strings.Index(out, "baseline-valid-hybrid.json")
	for _, limit := range []string{compareLimit, credentialOnlyLimit} {
		if i := strings.Index(out, limit); i < 0 || i > first {
			t.Errorf("the limit %q is not said before the first fixture runs", limit)
		}
	}
	for _, want := range []string{"  9  agree\n", " 32  accepted what must fail\n", "  0  rejected what must pass\n", "  0  couldn't read\n", "For the interop note: " + rep.InteropNote, "suite commit 7fec04045590"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q", want)
		}
	}
}

func TestOutputEscapesWhatAVerifierPrints(t *testing.T) {
	_, out, rep := readReport(t, "--verifier", helperCommand("exit", "1", "\x1b[2Jcleared|`x`"), "--label", "escapes")
	if strings.Contains(out, "\x1b") {
		t.Error("stdout carries a raw escape character from the verifier")
	}
	if !strings.Contains(out, `\x1b[2Jcleared`) {
		t.Errorf("stdout does not show the escaped answer:\n%s", out)
	}
	if rep.Fixtures[0].Raw != "\x1b[2Jcleared|`x`" {
		t.Errorf("the JSON report keeps the raw answer as it was: %q", rep.Fixtures[0].Raw)
	}
}

// outsideCodeSpans is line without its code spans, delimited as CommonMark
// delimits them: a run of N backticks opens a span that the next run of exactly
// N backticks closes, and a run that nothing closes is literal text.
func outsideCodeSpans(line string) string {
	runAt := func(i int) int {
		n := 0
		for i+n < len(line) && line[i+n] == '`' {
			n++
		}
		return n
	}
	closing := func(from, want int) int {
		for i := from; i < len(line); {
			switch n := runAt(i); n {
			case want:
				return i
			case 0:
				i++
			default:
				i += n
			}
		}
		return -1
	}
	var b strings.Builder
	for i := 0; i < len(line); {
		n := runAt(i)
		if n == 0 {
			b.WriteByte(line[i])
			i++
			continue
		}
		if end := closing(i+n, n); end >= 0 {
			i = end + n
			continue
		}
		b.WriteString(line[i : i+n])
		i += n
	}
	return b.String()
}

func TestOutsideCodeSpans(t *testing.T) {
	cases := []struct{ in, want string }{
		{"no span", "no span"},
		{"a `b` c", "a  c"},
		{"a ``b`c`` d", "a  d"},
		{"a `b", "a `b"},
		{"a ``b` c", "a ``b` c"},
		{"`a` b `c`", " b "},
	}
	for _, c := range cases {
		if got := outsideCodeSpans(c.in); got != c.want {
			t.Errorf("outsideCodeSpans(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMarkdownReportKeepsVerifierTextInCodeSpans holds the file the share line
// asks people to post or email: text a verifier or a label supplies stays in a
// code span, in the sentence for the interop note and in the table, so a
// Markdown renderer shows it and never acts on it. It renders nothing.
func TestMarkdownReportKeepsVerifierTextInCodeSpans(t *testing.T) {
	const hostile = "![pixel](https://evil.example/p.png) <img src=x onerror=alert(1)> [fix here](https://evil.example/fix)"
	reasonIs := func(text string) string { return `{"verdict":"ERROR","reason":"` + text + `"}` }
	cases := []struct {
		name, exit, answer, label, text string
		inTable                         bool
	}{
		{"JSON reason", "1", reasonIs(hostile), "hostile", hostile, true},
		{"JSON reason with backticks", "1", reasonIs("`` " + hostile + " `"), "hostile", "`` " + hostile + " `", true},
		{"JSON reason that ends in backticks", "1", reasonIs(hostile + " ```"), "hostile", hostile + " ```", true},
		{"JSON reason with pipes", "1", reasonIs(hostile + " | forged | cell |"), "hostile", hostile + " | forged | cell |", true},
		{"plain text at exit 2", "2", hostile, "hostile", hostile, true},
		{"label", "1", `{"verdict":"REJECT"}`, hostile, hostile, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "report")
			_, out, errOut := kitRun(t, "--verifier", helperCommand("exit", c.exit, c.answer), "--label", c.label, "--report", dir)
			if errOut != "" {
				t.Errorf("stderr: %s", errOut)
			}
			b, err := os.ReadFile(filepath.Join(dir, reportMDName))
			if err != nil {
				t.Fatalf("no Markdown report: %v\nstdout:\n%s", err, out)
			}
			md := string(b)
			for i, line := range strings.Split(md, "\n") {
				outside := outsideCodeSpans(line)
				for _, part := range []string{"![pixel]", "<img", "[fix here]", "evil.example"} {
					if strings.Contains(outside, part) {
						t.Errorf("line %d has %q outside a code span: %s", i+1, part, line)
					}
				}
			}
			_, after, found := strings.Cut(md, "## For the interop note\n\n")
			if !found {
				t.Fatalf("no interop note heading:\n%s", md)
			}
			note, _, _ := strings.Cut(after, "\n")
			if !strings.Contains(note, c.text) {
				t.Errorf("the note line does not carry the text as written: %s", note)
			}
			if rest := strings.TrimSpace(outsideCodeSpans(note)); rest != "" {
				t.Errorf("the note line has %q outside its code span: %s", rest, note)
			}
			_, table, _ := strings.Cut(md, "\n| 1 | ")
			row, _, _ := strings.Cut(table, "\n")
			row = "| 1 | " + row
			if n := strings.Count(outsideCodeSpans(row), "|"); n != 9 {
				t.Errorf("the first row has %d cell borders outside code spans, want 9: %s", n, row)
			}
			if c.inTable && !strings.Contains(row, strings.ReplaceAll(c.text, "|", `\|`)) {
				t.Errorf("the first row does not carry the text: %s", row)
			}
		})
	}
}

// TestInteropNoteCountsAnswers holds the sentence offered for publication to
// what the kit measured: it counts answers, and says "read" only for none.
func TestInteropNoteCountsAnswers(t *testing.T) {
	top := []ReasonCount{{Reason: "exit status 2: not a JWT.", Count: fixturesAtThisCommit}}
	some := []ReasonCount{{Reason: "exit status 2", Count: 40}, {Reason: "exit status 3", Count: 1}}
	cases := []struct {
		s    Summary
		top  []ReasonCount
		want string
	}{
		{Summary{Agree: 41}, nil, "Verifier v answered 41 of 41 ATX credentials and agreed with the answer key on every one."},
		{Summary{Agree: 28, AcceptedMustFail: 1, RejectedMustPass: 1, CouldNotRead: 11}, nil, "Verifier v answered 30 of 41 ATX credentials and agreed with the answer key on 28; it accepted 1 that must fail and rejected 1 that must pass, and 11 came back as couldn't read."},
		{Summary{CouldNotRead: 41}, top, "Verifier v read 0 of 41 ATX credentials; every one came back as couldn't read, with: exit status 2: not a JWT."},
		{Summary{CouldNotRead: 41}, some, "Verifier v read 0 of 41 ATX credentials; every one came back as couldn't read, most often with: exit status 2."},
	}
	for _, c := range cases {
		if got := interopNote("v", fixturesAtThisCommit, c.s, c.top); got != c.want {
			t.Errorf("interopNote(%+v) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestURLAdapterPath(t *testing.T) {
	// No listener: whatever URL adapter this build holds answers couldn't
	// read for each fixture, and nothing leaves the machine.
	code, out, rep := readReport(t, "--verifier-url", "http://127.0.0.1:1/verify", "--label", "url", "--timeout", "2")
	checkSummary(t, rep.Summary, Summary{CouldNotRead: fixturesAtThisCommit})
	if code != 1 || rep.Adapter != "url" {
		t.Errorf("exit %d, adapter %q", code, rep.Adapter)
	}
	first := strings.Index(out, "baseline-valid-hybrid.json")
	if i := strings.Index(out, urlLimit); i < 0 || i > first {
		t.Errorf("the limit %q, which names the header, is not said before the first fixture runs:\n%s", urlLimit, out)
	}
	if strings.Contains(out, credentialOnlyLimit) {
		t.Errorf("a URL run is told the limit of a command run:\n%s", out)
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"--verifier", "--help"}, {"--label", "x", "-h"}, {"--help", "--form", "native"}} {
		code, out, errOut := kitRun(t, args...)
		if code != 0 || out != usage || errOut != "" {
			t.Errorf("%q: exit %d, stdout %d bytes, stderr %q", args, code, len(out), errOut)
		}
	}
	for _, banned := range []string{"\u2014", "proof of logging", "we verify any format", "SPIFFE", "WIMSE", "the standard", "ATC"} {
		if strings.Contains(usage+shareLine+compareLimit, banned) {
			t.Errorf("the kit's text carries %q", banned)
		}
	}
}

// TestJSONWinsCarriesItsCondition holds --help and both READMEs to one wording
// of the rule the adapters apply; the adapter tables hold the rule itself, with
// a log line before the JSON leaving the exit or status code to decide.
func TestJSONWinsCarriesItsCondition(t *testing.T) {
	const condition = "JSON wins over exit and status codes when the whole answer is one JSON object"
	if !strings.Contains(usage, condition) {
		t.Errorf("--help lacks %q", condition)
	}
	for _, path := range []string{"../README.md", "../examples/README.md"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), condition) {
			t.Errorf("%s lacks %q", path, condition)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	cmd := quote(dummies["acceptall"])
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--verifier", cmd, "--verifier-url", "http://127.0.0.1:9/"}, "--verifier and --verifier-url cannot be used together"},
		{[]string{"--label", "x"}, "give your verifier with --verifier"},
		{[]string{"--verifier"}, "--verifier needs a value"},
		{[]string{"--verifier", `verify "open`}, "--verifier: a double quote is not closed"},
		{[]string{"--verifier", "   "}, "--verifier: the command is empty"},
		{[]string{"--verifier", cmd, "fixtures"}, `unexpected argument "fixtures"`},
		{[]string{"--verifier", cmd, "--form", "xml"}, `--form "xml" is not a form`},
		{[]string{"--verifier", cmd, "--timeout", "0"}, "--timeout: 0 is not more than 0"},
		{[]string{"--verifier", cmd, "--timeout", "soon"}, "--timeout: soon is not a duration"},
		{[]string{"--verifier", cmd, "--label", " "}, "--label is empty"},
		{[]string{"--verifier", cmd, "--bogus"}, "unknown option: --bogus"},
		{[]string{"--verifier-url", "localhost:8080"}, `--verifier-url: the verifier URL must start with http:// or https:// and name a host, for example http://127.0.0.1:8080/; got "localhost:8080"`},
		{[]string{"--verifier", quote(filepath.Join(t.TempDir(), "missing"))}, "the --verifier command could not be started"},
	}
	for _, c := range cases {
		code, out, errOut := kitRun(t, c.args...)
		if code != 2 || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 2 and %q", c.args, code, out, errOut, c.want)
		}
	}
}

func TestReservedFormsDoNotRun(t *testing.T) {
	for _, form := range []string{"jws", "vc"} {
		code, out, errOut := kitRun(t, "--verifier", quote(dummies["acceptall"]), "--form", form)
		want := "--form " + form + " is reserved for a later release; this release reads the native form only, so run again without --form.\n"
		if code != 2 || out != "" || errOut != want {
			t.Errorf("--form %s: exit %d, stdout %q, stderr %q", form, code, out, errOut)
		}
	}
}

func TestRequested(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--help"}, false},
		{[]string{"fixtures/baseline-valid.json"}, false},
		{[]string{"fixtures"}, false},
		{[]string{"--bogus"}, false},
		{[]string{"--version"}, false},
		{[]string{"-verifier", "x"}, false},
		{[]string{"--", "--verifier"}, false},
		{[]string{"--verifier", "x"}, true},
		{[]string{"--verifier=x"}, true},
		{[]string{"--verifier-url", "http://127.0.0.1/"}, true},
		{[]string{"--label", "x"}, true},
		{[]string{"--form=jws"}, true},
		{[]string{"--report", "out"}, true},
		{[]string{"--timeout", "5"}, true},
		{[]string{"fixtures", "--verifier", "x"}, true},
	}
	for _, c := range cases {
		if got := Requested(c.args); got != c.want {
			t.Errorf("Requested(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestProvenance(t *testing.T) {
	devel := func(settings ...debug.BuildSetting) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Path: "m", Version: "(devel)"}, Settings: settings}
	}
	cases := []struct {
		info            *debug.BuildInfo
		ok              bool
		version, commit string
	}{
		{nil, false, "unknown", "unknown"},
		{&debug.BuildInfo{Main: debug.Module{Path: "m", Version: "v0.0.0-20261104120000-7fec04045590"}}, true, "v0.0.0-20261104120000-7fec04045590", "7fec04045590"},
		{&debug.BuildInfo{Main: debug.Module{Path: "m", Version: "v1.2.4-0.20261104120000-7fec04045590"}}, true, "v1.2.4-0.20261104120000-7fec04045590", "7fec04045590"},
		{&debug.BuildInfo{Main: debug.Module{Path: "m", Version: "v1.2.3"}}, true, "v1.2.3", "unknown"},
		{&debug.BuildInfo{Main: debug.Module{Path: "m", Version: "v1.2.3-rc1"}}, true, "v1.2.3-rc1", "unknown"},
		{devel(), true, "(devel)", "unknown"},
		{devel(debug.BuildSetting{Key: "vcs.revision", Value: "7fec040455900260a457f9abf22aafef5706f586"}), true, "(devel)", "7fec040455900260a457f9abf22aafef5706f586"},
		{devel(debug.BuildSetting{Key: "vcs.revision", Value: "abc"}, debug.BuildSetting{Key: "vcs.modified", Value: "true"}), true, "(devel)", "abc (with uncommitted changes)"},
	}
	for _, c := range cases {
		v, commit := provenance(c.info, c.ok)
		if v != c.version || commit != c.commit {
			t.Errorf("provenance(%+v) = %q, %q; want %q, %q", c.info, v, commit, c.version, c.commit)
		}
	}
}
