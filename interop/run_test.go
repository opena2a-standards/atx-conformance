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
	want := "Verifier always ACCEPT read 41 of 41 ATX credentials and agreed with the answer key on 9; it accepted 32 that must fail and rejected 0 that must pass."
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

func TestURLAdapterPath(t *testing.T) {
	// No listener: whatever URL adapter this build holds answers couldn't
	// read for each fixture, and nothing leaves the machine.
	code, _, rep := readReport(t, "--verifier-url", "http://127.0.0.1:1/verify", "--label", "url", "--timeout", "2")
	checkSummary(t, rep.Summary, Summary{CouldNotRead: fixturesAtThisCommit})
	if code != 1 || rep.Adapter != "url" {
		t.Errorf("exit %d, adapter %q", code, rep.Adapter)
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
		{[]string{"--verifier-url", "localhost:8080"}, `--verifier-url "localhost:8080" is not an http:// or https:// URL`},
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
