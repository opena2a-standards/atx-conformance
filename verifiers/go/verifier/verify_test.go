package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	atxconformance "github.com/opena2a-standards/atx-conformance"
)

// repoRoot is the repository root, relative to this package's directory.
const repoRoot = "../../.."

// TestReadmeCrossReferencesResolve pins that every README §"..." or
// docs/<page>.md §"..." cross-reference in this verifier and in the fixture
// generator names a heading the file it cites carries. A reference split
// across two comment lines reads as one.
// atx-conformance#161: both sources cited §"Signed vs unsigned fields.", a
// section README never had. The section they cite moved from README.md to
// docs/scope.md with the README's other reference sections.
func TestReadmeCrossReferencesResolve(t *testing.T) {
	headings := map[string]map[string]bool{}
	headingsOf := func(doc string) map[string]bool {
		if set, ok := headings[doc]; ok {
			return set
		}
		path := repoRoot + "/" + doc
		if doc == "README" {
			path = repoRoot + "/README.md"
		}
		body, err := os.ReadFile(path) //nolint:gosec // G304: doc is "README" or "docs/<name>.md", as the reference pattern below matches it
		if err != nil {
			t.Fatalf("cannot read %s: %v", path, err)
		}
		set := map[string]bool{}
		fenced := false
		for _, line := range strings.Split(string(body), "\n") {
			switch {
			case strings.HasPrefix(line, "```"):
				fenced = !fenced
			case !fenced && strings.HasPrefix(line, "#"):
				set[strings.TrimSpace(strings.TrimLeft(line, "#"))] = true
			}
		}
		headings[doc] = set
		return set
	}

	continuation := regexp.MustCompile(`\n[ \t]*//[ \t]*`)
	reference := regexp.MustCompile(`(README|docs/[\w-]+\.md)\s+§"([^"]+)"`)
	found := 0
	for _, src := range []string{"verify.go", repoRoot + "/scripts/generate-fixtures/main.go"} {
		body, err := os.ReadFile(src) //nolint:gosec // G304: src ranges over the two fixed repository paths above
		if err != nil {
			t.Fatalf("cannot read %s: %v", src, err)
		}
		text := continuation.ReplaceAllString(string(body), " ")
		for _, m := range reference.FindAllStringSubmatch(text, -1) {
			found++
			if !headingsOf(m[1])[m[2]] {
				t.Errorf("%s cites %s §%q, which is not a heading of %s", src, m[1], m[2], m[1])
			}
		}
	}
	if found == 0 {
		t.Fatal("no README cross-reference found; refusing to pass vacuously")
	}
}

// TestCaptureIsVerifierOutput holds docs/captures/go-verifier.txt, the full
// output README.md excerpts under its first command, to what this verifier
// writes for that command on this tree. The sidecar beside the capture
// records the command as README.md states it, the command the capture script
// ran for it from this tree (`ranAs`) and the directory it ran in: `ranAs`
// must be `go run <package> <args>` for a main package that passes its
// arguments to Run. The test calls Run with <args> in that directory and
// compares its standard output with the capture byte for byte.
// scripts/capture_go_verifier.py --check holds the README excerpt and the
// sidecar to the capture but runs no verifier, so a capture that a change to
// a fixture or to this verifier left behind passed it.
func TestCaptureIsVerifierOutput(t *testing.T) {
	const (
		sidecarPath = repoRoot + "/docs/captures/go-verifier.json"
		capturePath = repoRoot + "/docs/captures/go-verifier.txt"
	)
	raw, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", sidecarPath, err)
	}
	var sidecar struct {
		Command          string `json:"command"`
		RanAs            string `json:"ranAs"`
		WorkingDirectory string `json:"workingDirectory"`
		Outputs          struct {
			Capture struct {
				Path string `json:"path"`
			} `json:"capture"`
		} `json:"outputs"`
	}
	if err := json.Unmarshal(raw, &sidecar); err != nil {
		t.Fatalf("%s: %v", sidecarPath, err)
	}
	if want := strings.TrimPrefix(capturePath, repoRoot+"/"); sidecar.Outputs.Capture.Path != want {
		t.Fatalf("%s names capture %q; this test reads %s", sidecarPath, sidecar.Outputs.Capture.Path, want)
	}
	fields := strings.Fields(sidecar.RanAs)
	if len(fields) < 3 || fields[0] != "go" || fields[1] != "run" {
		t.Fatalf("%s records ranAs %q, not `go run <package> <args>`", sidecarPath, sidecar.RanAs)
	}
	workDir := filepath.Join(repoRoot, sidecar.WorkingDirectory)
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := passesArgsToRun(filepath.Join(workDir, fields[2])); err != nil {
		t.Fatalf("%s records ranAs %q in %q: %v", sidecarPath, sidecar.RanAs, sidecar.WorkingDirectory, err)
	}
	want, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", capturePath, err)
	}

	// Run in the recorded working directory, so a relative path among <args>
	// names what it named for the capture.
	if err := os.Chdir(workDir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(here); err != nil {
			t.Error(err)
		}
	}()
	var stdout, stderr bytes.Buffer
	if code := Run(fields[3:], &stdout, &stderr); code != 0 {
		t.Errorf("`%s` in %s exits %d; the capture is of a run that exits 0 (stderr: %q)",
			sidecar.RanAs, sidecar.WorkingDirectory, code, stderr.String())
	}
	if bytes.Equal(stdout.Bytes(), want) {
		return
	}
	got, exp := strings.Split(stdout.String(), "\n"), strings.Split(string(want), "\n")
	line := 0
	for line < len(got) && line < len(exp) && got[line] == exp[line] {
		line++
	}
	at := func(lines []string) string {
		if line < len(lines) {
			return strconv.Quote(lines[line])
		}
		return "nothing (end of output)"
	}
	t.Errorf("%s line %d is %s; `%s` in %s writes %s. From the repository root, "+
		"run python3 scripts/capture_go_verifier.py and commit both files it rewrites under docs/captures/",
		capturePath, line+1, at(exp), sidecar.RanAs, sidecar.WorkingDirectory, at(got))
}

// entryCall is the call each main package of the verifier makes.
const entryCall = "os.Exit(verifier.Run(os.Args[1:], os.Stdout, os.Stderr))"

// passesArgsToRun returns nil when dir holds a main package whose non-test Go
// files make entryCall, and otherwise an error naming what it found.
func passesArgsToRun(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return err
	}
	mainClause := regexp.MustCompile(`(?m)^package main$`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f) //nolint:gosec // G304: f is a Go file of a repository directory a test names
		if err != nil {
			return err
		}
		if mainClause.Match(body) && strings.Contains(string(body), entryCall) {
			return nil
		}
	}
	return fmt.Errorf("%s holds no main package making the call %s (Go files: %q)", dir, entryCall, files)
}

// TestEntryPointsPassArgsToRun holds both main packages of the verifier,
// cmd/atx-verify (the published entry point) and verifiers/go (the one CI
// runs from a checkout), to passing their arguments to Run.
func TestEntryPointsPassArgsToRun(t *testing.T) {
	for _, dir := range []string{"cmd/atx-verify", "verifiers/go"} {
		if err := passesArgsToRun(filepath.Join(repoRoot, dir)); err != nil {
			t.Error(err)
		}
	}
	if err := passesArgsToRun("."); err == nil {
		t.Error("passesArgsToRun accepts this library package, which is no main package")
	}
}

// TestEmbeddedFixturesAreTheFixtureDirectory holds the fixture set the module
// root embeds, which run walks when it is given no argument, to
// fixtures/*.json on disk: the same names, and under each name the same bytes.
func TestEmbeddedFixturesAreTheFixtureDirectory(t *testing.T) {
	onDisk, err := filepath.Glob(filepath.Join(repoRoot, "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) == 0 {
		t.Fatal("no fixtures found on disk; refusing to pass vacuously")
	}
	entries, err := fs.ReadDir(atxconformance.Fixtures, "fixtures")
	if err != nil {
		t.Fatalf("cannot list the embedded fixtures: %v", err)
	}
	var embedded, want []string
	for _, e := range entries {
		embedded = append(embedded, e.Name())
	}
	for _, p := range onDisk {
		want = append(want, filepath.Base(p))
	}
	sort.Strings(want)
	if strings.Join(embedded, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the module root embeds %q; fixtures/ holds %q", embedded, want)
	}
	for _, name := range want {
		disk, err := os.ReadFile(filepath.Join(repoRoot, "fixtures", name)) //nolint:gosec // G304: name is a file name listed from fixtures/ above
		if err != nil {
			t.Fatal(err)
		}
		got, err := fs.ReadFile(atxconformance.Fixtures, "fixtures/"+name)
		if err != nil {
			t.Fatalf("embedded fixtures/%s: %v", name, err)
		}
		if !bytes.Equal(got, disk) {
			t.Errorf("the embedded fixtures/%s differs from the file on disk", name)
		}
	}
}

// TestNoArgumentVerifiesEmbeddedFixtures pins what the published entry point,
// `go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest`
// with no argument, writes: the report Run writes for the fixtures/
// directory, each fixture named fixtures/<name>, exiting 0 on the shipped
// set. Before the module root embedded the fixtures, the verifier with no
// argument wrote a usage line to stderr and exited 2.
func TestNoArgumentVerifiesEmbeddedFixtures(t *testing.T) {
	const dir = repoRoot + "/fixtures"
	var fromDir, fromEmbed, stderr bytes.Buffer
	if code := Run([]string{dir}, &fromDir, &stderr); code != 0 {
		t.Fatalf("Run over %s exits %d (stderr %q)", dir, code, stderr.String())
	}
	if code := Run(nil, &fromEmbed, &stderr); code != 0 {
		t.Fatalf("Run with no argument exits %d, want 0 (stderr %q)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("Run with no argument writes %q to stderr, want nothing", stderr.String())
	}
	if !strings.HasPrefix(fromEmbed.String(), "PASS  fixtures/") {
		t.Fatalf("Run with no argument starts with %q, want a `PASS  fixtures/<name>` line",
			strings.SplitN(fromEmbed.String(), "\n", 2)[0])
	}
	want := strings.ReplaceAll(fromDir.String(), dir+"/", "fixtures/")
	if got := fromEmbed.String(); got != want {
		t.Errorf("Run with no argument writes:\n%s\nwant the %s report with each path as fixtures/<name>:\n%s",
			got, dir, want)
	}
}

// TestHelpPrintsUsage pins that -h and --help write the usage lines to stdout
// and exit 0, wherever they stand among the arguments, and that the usage
// names the program atx-verify, the published entry point. It named a
// program `verify`, which neither entry point builds.
func TestHelpPrintsUsage(t *testing.T) {
	if first := strings.SplitN(usage, "\n", 2)[0]; first != "usage: atx-verify [fixture.json|dir]..." {
		t.Errorf("the usage opens with %q, want it to name atx-verify", first)
	}
	for _, args := range [][]string{{"-h"}, {"--help"}, {repoRoot + "/fixtures", "-h"}, {"--json", "--help"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 0 {
			t.Errorf("Run(%q) exits %d, want 0", args, code)
		}
		if stdout.String() != usage {
			t.Errorf("Run(%q) writes %q to stdout, want the usage lines", args, stdout.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("Run(%q) writes %q to stderr, want nothing", args, stderr.String())
		}
	}
}

// TestUnknownOptionIsNamed pins that an argument starting with "-" that is not
// an option of this verifier is named on stderr above the usage lines, exit
// 2, before any fixture is read. It was taken for a path, so `verify --json`
// wrote `error: stat --json: no such file or directory`.
func TestUnknownOptionIsNamed(t *testing.T) {
	cases := []struct {
		args    []string
		unknown string
	}{
		{[]string{"--json"}, "--json"},
		{[]string{"--verbose"}, "--verbose"},
		{[]string{"-x"}, "-x"},
		{[]string{repoRoot + "/fixtures", "--json"}, "--json"},
		{[]string{"--version", "-x"}, "-x"},
	}
	for _, c := range cases {
		var stdout, stderr bytes.Buffer
		if code := Run(c.args, &stdout, &stderr); code != 2 {
			t.Errorf("Run(%q) exits %d, want 2", c.args, code)
		}
		if want := "unknown option: " + c.unknown + "\n" + usage; stderr.String() != want {
			t.Errorf("Run(%q) writes %q to stderr, want %q", c.args, stderr.String(), want)
		}
		if stdout.Len() != 0 {
			t.Errorf("Run(%q) writes %q to stdout, want nothing", c.args, stdout.String())
		}
	}
}

// TestVersionNamesTheModuleVersion pins that --version writes one line naming
// the module path and version the binary records and the Go release that
// built it, and exits 0 without reading a fixture. Neither verifier had a
// --version, and no line of the report named the commit a `go run
// <module>/verifiers/go@latest` binary was built from.
func TestVersionNamesTheModuleVersion(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	want := versionLine(info, ok)
	for _, args := range [][]string{{"--version"}, {repoRoot + "/fixtures", "--version"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 0 {
			t.Errorf("Run(%q) exits %d, want 0 (stderr %q)", args, code, stderr.String())
		}
		if stdout.String() != want {
			t.Errorf("Run(%q) writes %q to stdout, want %q", args, stdout.String(), want)
		}
		if stderr.Len() != 0 {
			t.Errorf("Run(%q) writes %q to stderr, want nothing", args, stderr.String())
		}
	}

	const module = "github.com/opena2a-standards/atx-conformance"
	lines := []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{GoVersion: "go1.22.12", Main: debug.Module{Path: module, Version: "v0.0.0-20261018005751-ea4b48544534"}}, true,
			"atx-verify: " + module + " v0.0.0-20261018005751-ea4b48544534, built with go1.22.12\n"},
		{&debug.BuildInfo{GoVersion: "go1.26.3", Main: debug.Module{Path: module, Version: "(devel)"}}, true,
			"atx-verify: " + module + " (devel), built with go1.26.3\n"},
		{&debug.BuildInfo{GoVersion: "go1.26.3"}, true, "atx-verify: this binary records no module version\n"},
		{nil, false, "atx-verify: this binary records no module version\n"},
	}
	for _, c := range lines {
		if got := versionLine(c.info, c.ok); got != c.want {
			t.Errorf("versionLine(%+v, %t) = %q, want %q", c.info, c.ok, got, c.want)
		}
	}
}

// TestPathOutsideWorkingDirectoryIsWrittenWhole pins the name the report gives
// a fixture named by an absolute path: the path relative to the working
// directory when the fixture is under it, the absolute path when it is not.
// A fixture outside was named by a climb of ".." elements to the file system
// root, where the Python verifier writes the absolute path.
func TestPathOutsideWorkingDirectoryIsWrittenWhole(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	above := filepath.Join(wd, repoRoot, "fixtures", "baseline-valid.json")
	for _, c := range []struct{ path, want string }{
		{filepath.Join(wd, "verify.go"), "verify.go"},
		{filepath.Join(wd, "testdata", "x.json"), filepath.Join("testdata", "x.json")},
		{above, above},
		{repoRoot + "/fixtures/baseline-valid.json", repoRoot + "/fixtures/baseline-valid.json"},
	} {
		if got := relPath(c.path); got != c.want {
			t.Errorf("relPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}

	raw, err := fs.ReadFile(atxconformance.Fixtures, "fixtures/baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "baseline-valid.json")
	if err := os.WriteFile(outside, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{outside}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run(%q) exits %d, want 0 (stderr %q)", outside, code, stderr.String())
	}
	if first, want := strings.SplitN(stdout.String(), "\n", 2)[0], "PASS  "+outside; first != want {
		t.Errorf("Run(%q) writes %q first, want %q", outside, first, want)
	}
}

// chdir makes dir the working directory until the test ends.
func chdir(t *testing.T, dir string) {
	t.Helper()
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(here); err != nil {
			t.Error(err)
		}
	})
}

// TestPathUnderLinkedWorkingDirectory pins the name the report gives a
// fixture named by an absolute path when the working directory was entered
// through a symbolic link, with PWD the path through the link, as a shell
// sets it: the path relative to the working directory, whether written
// through the link or through its target. The two were compared as written,
// so the path through the link was named x.json and the path through the
// target was written whole, where the Python verifier did the reverse.
func TestPathUnderLinkedWorkingDirectory(t *testing.T) {
	baseline, err := fs.ReadFile(atxconformance.Fixtures, "fixtures/baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "x.json"), baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	chdir(t, link)
	t.Setenv("PWD", link)
	if wd, err := os.Getwd(); err != nil || wd != link {
		t.Fatalf("os.Getwd() = %q, %v; want %q, the path through the link", wd, err, link)
	}
	for _, p := range []string{filepath.Join(link, "x.json"), filepath.Join(target, "x.json")} {
		var stdout, stderr bytes.Buffer
		if code := Run([]string{p}, &stdout, &stderr); code != 0 {
			t.Fatalf("Run(%q) exits %d, want 0 (stderr %q)", p, code, stderr.String())
		}
		if first := strings.SplitN(stdout.String(), "\n", 2)[0]; first != "PASS  x.json" {
			t.Errorf("Run(%q) writes %q first, want %q", p, first, "PASS  x.json")
		}
	}
}

// observedLine matches a report's observed line, capturing the verdict and,
// for a REJECT, the category, without the reason.
var observedLine = regexp.MustCompile(`^\s+observed: (ACCEPT|REJECT\[[A-Z_]+)`)

// verdictLines returns each PASS or FAIL line of a report, each followed by
// its observed verdict and category, so a test sees which file was read as
// well as the name the report gives it.
func verdictLines(report string) []string {
	var lines []string
	for _, line := range strings.Split(report, "\n") {
		if strings.HasPrefix(line, "PASS  ") || strings.HasPrefix(line, "FAIL  ") {
			lines = append(lines, line)
		} else if m := observedLine.FindStringSubmatch(line); m != nil {
			v := "observed: " + m[1]
			if strings.HasPrefix(m[1], "REJECT") {
				v += "]"
			}
			lines = append(lines, v)
		}
	}
	return lines
}

// TestDotDotAfterALinkIsAppliedWhereTheLinkLeads pins that a ".." after a
// symbolic link names, for the file read and for the report, what the
// operating system resolves it to: the link resolved, then the "..". With
// d/link a link to elsewhere/deep, d/link/.. lists elsewhere, and its files
// were joined onto d/link/.. as filepath.Join joins them, which removes the
// ".." with the link: elsewhere/other.json was reported as d/other.json, a
// load error, as d holds no other.json, and d/x.json, which d/link/.. does
// not list, was verified in place of elsewhere/x.json. An absolute path
// $PWD/d/link/../x.json was named d/x.json while elsewhere/x.json was read,
// and r/link/.., which resolves to a directory holding fixtures/, was
// walked for its own *.json since r/fixtures does not exist. A directory
// spelled with a ".." that cleaning resolves alike, d/../d, still names its
// files as filepath.Join joins them.
func TestDotDotAfterALinkIsAppliedWhereTheLinkLeads(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, err := fs.ReadFile(atxconformance.Fixtures, "fixtures/"+name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	baseline, expired := read("baseline-valid.json"), read("expired.json")
	dir := t.TempDir()
	wd, elsewhere, root := filepath.Join(dir, "wd"), filepath.Join(dir, "elsewhere"), filepath.Join(dir, "root")
	for _, d := range []string{
		filepath.Join(wd, "d"), filepath.Join(wd, "r"), filepath.Join(elsewhere, "deep"),
		filepath.Join(root, "deep"), filepath.Join(root, "fixtures"),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, b := range map[string][]byte{
		filepath.Join(wd, "d", "x.json"):          baseline,
		filepath.Join(elsewhere, "other.json"):    expired,
		filepath.Join(elsewhere, "x.json"):        expired,
		filepath.Join(root, "fixtures", "x.json"): baseline,
		filepath.Join(root, "conformance.json"):   []byte("{}\n"),
	} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		filepath.Join(wd, "d", "link"): filepath.Join(elsewhere, "deep"),
		filepath.Join(wd, "r", "link"): filepath.Join(root, "deep"),
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	chdir(t, wd)

	const rejected = "observed: REJECT[EXPIRED]"
	for _, c := range []struct {
		arg  string
		want []string
	}{
		{"d/link/..", []string{"PASS  d/link/../other.json", rejected, "PASS  d/link/../x.json", rejected}},
		{"d/link/../", []string{"PASS  d/link/../other.json", rejected, "PASS  d/link/../x.json", rejected}},
		{wd + "/d/link/..", []string{
			"PASS  " + wd + "/d/link/../other.json", rejected, "PASS  " + wd + "/d/link/../x.json", rejected}},
		{wd + "/d/link/../x.json", []string{"PASS  " + wd + "/d/link/../x.json", rejected}},
		{"r/link/..", []string{"PASS  r/link/../fixtures/x.json", "observed: ACCEPT"}},
		{"d/../d", []string{"PASS  d/x.json", "observed: ACCEPT"}},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run([]string{c.arg}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Errorf("Run(%q) exits %d with stderr %q, want exit 0 and no stderr; stdout:\n%s",
				c.arg, code, stderr.String(), stdout.String())
		}
		if got := verdictLines(stdout.String()); !slices.Equal(got, c.want) {
			t.Errorf("Run(%q) writes verdict lines %q, want %q", c.arg, got, c.want)
		}
	}
}

// TestDoubleDashEndsOptions pins that the first "--" ends the options: each
// argument after it is a path, one that starts with "-" included, and "--"
// itself names nothing, so "--" alone verifies what no argument does. An
// option before it is still read. Run named "--" an unknown option, exit 2,
// so a fixture file named -h.json could be named only as ./-h.json.
func TestDoubleDashEndsOptions(t *testing.T) {
	baseline, err := fs.ReadFile(atxconformance.Fixtures, "fixtures/baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "-h.json"), baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	code, stdout, stderr := run("--", "-h.json")
	if code != 0 || stderr != "" || !strings.HasPrefix(stdout, "PASS  -h.json\n") ||
		!strings.HasSuffix(stdout, "\nsummary: 1 pass, 0 fail (1 fixtures)\n") {
		t.Errorf("Run(-- -h.json) exits %d with stdout %q and stderr %q; want -h.json verified, exit 0",
			code, stdout, stderr)
	}
	for _, c := range []struct {
		args   []string
		stderr string
	}{
		{[]string{"--", "-h.json", "--help"}, "error: --help: no such file or directory\n"},
		{[]string{"--", "--version"}, "error: --version: no such file or directory\n"},
		{[]string{"--", "--"}, "error: --: no such file or directory\n"},
		{[]string{"--", ""}, "error: an empty argument names no fixture file or directory\n"},
		{[]string{"-x", "--", "-h.json"}, "unknown option: -x\n" + usage},
	} {
		if code, stdout, stderr := run(c.args...); code != 2 || stdout != "" || stderr != c.stderr {
			t.Errorf("Run(%q) exits %d with stdout %q and stderr %q; want exit 2 and stderr %q",
				c.args, code, stdout, stderr, c.stderr)
		}
	}
	if code, stdout, stderr := run("--version", "--", "-x"); code != 0 || stderr != "" ||
		!strings.HasPrefix(stdout, "atx-verify: ") {
		t.Errorf("Run(--version -- -x) exits %d with stdout %q and stderr %q; want the version line, exit 0",
			code, stdout, stderr)
	}
	_, noArgument, _ := run()
	if code, stdout, stderr := run("--"); code != 0 || stderr != "" || stdout != noArgument {
		t.Errorf("Run(--) exits %d with stdout %q and stderr %q; want the report Run writes with no argument, exit 0",
			code, stdout, stderr)
	}
}

// TestNonFixtureIsALoadError pins that a file with no expected outcome the
// fixture format allows fails to load: an expected member or
// expected.verifyResult that is absent or null, or a verifyResult other than
// ACCEPT or REJECT (schemas/fixture-v1.schema.json, exact case), "" among
// them. Each gets one FAIL line naming why, with no expected or observed
// line, and counts as a fail, so the run exits 1. Before, such a verifyResult
// read as "expect REJECT": {} or an npm package.json, rejected at parse,
// passed, and a directory of them ended in "N pass, 0 fail" with exit 0. The
// shipped fixtures still all pass.
func TestNonFixtureIsALoadError(t *testing.T) {
	baseline, err := os.ReadFile(repoRoot + "/fixtures/baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	const accept = `"verifyResult": "ACCEPT"`
	if n := strings.Count(string(baseline), accept); n != 1 {
		t.Fatalf("baseline-valid.json holds %s %d times, want once", accept, n)
	}
	withVerifyResult := func(word string) string {
		return strings.Replace(string(baseline), accept, `"verifyResult": "`+word+`"`, 1)
	}
	cases := []struct{ file, content, reason string }{
		{"a-empty-object.json", `{}`, "no expected member"},
		{"b-null-expected.json", `{"expected": null}`, "no expected member"},
		{"c-empty-expected.json", `{"expected": {}}`, "no expected.verifyResult"},
		{"d-null-verify-result.json", `{"expected": {"verifyResult": null}}`, "no expected.verifyResult"},
		{"e-maybe.json", withVerifyResult("MAYBE"), `expected.verifyResult "MAYBE" is not ACCEPT or REJECT`},
		{"f-lower-case.json", withVerifyResult("accept"), `expected.verifyResult "accept" is not ACCEPT or REJECT`},
		{"g-empty-string.json", withVerifyResult(""), `expected.verifyResult "" is not ACCEPT or REJECT`},
	}
	dir := t.TempDir()
	var want strings.Builder
	for _, c := range cases {
		path := filepath.Join(dir, c.file)
		if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		want.WriteString("FAIL  " + relPath(path) + "  (load error: " + c.reason + ")\n")
	}
	want.WriteString("\nsummary: 0 pass, 7 fail (7 fixtures)\n")

	var stdout, stderr bytes.Buffer
	if code := Run([]string{dir}, &stdout, &stderr); code != 1 {
		t.Errorf("Run over files that are not fixtures exits %d, want 1 (stderr %q)", code, stderr.String())
	}
	if got := stdout.String(); got != want.String() {
		t.Errorf("Run writes:\n%s\nwant one load error line per file and no expected or observed line:\n%s", got, want.String())
	}

	const fixtures = repoRoot + "/fixtures"
	shipped, err := filepath.Glob(filepath.Join(fixtures, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{fixtures}, &stdout, &stderr); code != 0 {
		t.Errorf("Run over %s exits %d, want 0 (stderr %q)", fixtures, code, stderr.String())
	}
	n := strconv.Itoa(len(shipped))
	if summary := "\nsummary: " + n + " pass, 0 fail (" + n + " fixtures)\n"; !strings.HasSuffix(stdout.String(), summary) {
		t.Errorf("Run over %s writes:\n%s\nwant it to end in%s", fixtures, stdout.String(), summary)
	}
}

// TestEmptyArgumentIsAUsageError pins that an empty argument, alone or beside
// a path, is a usage error, as it is in the Python verifier: one line on
// stderr, nothing on stdout, exit 2. Run passed it to os.Stat and wrote
// `error: stat : no such file or directory`, while the Python verifier read
// it as the current directory and walked it.
func TestEmptyArgumentIsAUsageError(t *testing.T) {
	const want = "error: an empty argument names no fixture file or directory\n"
	for _, args := range [][]string{{""}, {repoRoot + "/fixtures", ""}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 2 {
			t.Errorf("Run(%q) exits %d, want 2", args, code)
		}
		if stderr.String() != want {
			t.Errorf("Run(%q) writes %q to stderr, want %q", args, stderr.String(), want)
		}
		if stdout.Len() != 0 {
			t.Errorf("Run(%q) writes %q to stdout, want nothing", args, stdout.String())
		}
	}
}

// TestFixturesFileEntryWalksTheDirectory pins that a directory whose fixtures
// entry is a file is walked for its own *.json, as the Python verifier walks
// it: the fixtures fallback lets a repository root be passed, and a file
// named fixtures leaves the argument an ordinary directory. Run read
// <dir>/fixtures whenever it existed and stopped with
// `open <dir>/fixtures: not a directory`.
func TestFixturesFileEntryWalksTheDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixtures"), []byte("a file, not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := fs.ReadFile(atxconformance.Fixtures, "fixtures/baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.json"), baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run(%q) exits %d, want 0 (stderr %q)", dir, code, stderr.String())
	}
	if want, first := "PASS  "+relPath(filepath.Join(dir, "x.json")),
		strings.SplitN(stdout.String(), "\n", 2)[0]; first != want {
		t.Errorf("Run(%q) starts with %q, want %q", dir, first, want)
	}
	if !strings.HasSuffix(stdout.String(), "\nsummary: 1 pass, 0 fail (1 fixtures)\n") {
		t.Errorf("Run(%q) writes:\n%s\nwant one fixture, passing", dir, stdout.String())
	}
}

// TestFoldKey pins the field-fold used by the fold-aware duplicate detector to
// encoding/json's own folding: ASCII case-insensitive plus the only two
// non-ASCII runes encoding/json folds to ASCII (Kelvin U+212A -> k, long s
// U+017F -> s). atx-conformance#16.
func TestFoldKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"trustLevel", "trustlevel"},
		{"TRUSTLEVEL", "trustlevel"},
		{"TrustLevel", "trustlevel"},
		{"category", "category"},
		{"Category", "category"},
		{"agentId", "agentid"},
		{"Kelvin", "kelvin"}, // U+212A Kelvin sign folds to ASCII k
		{"ſmart", "smart"},   // U+017F long s folds to ASCII s
		{"Éclair", "éclair"}, // any other rune: the unicode.ToLower fallback
	}
	for _, c := range cases {
		if got := foldKey(c.in); got != c.want {
			t.Errorf("foldKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Case variants and the fold targets must collide under foldKey; distinct
	// field names must not.
	if foldKey("trustLevel") != foldKey("TRUSTLEVEL") {
		t.Error("trustLevel and TRUSTLEVEL must fold together")
	}
	if foldKey("K") != foldKey("k") {
		t.Error("Kelvin sign must fold to k")
	}
	if foldKey("agentId") == foldKey("issuerDid") {
		t.Error("distinct field names must not fold together")
	}
}

// TestRawDuplicateMember covers same-name duplicates, case-variant (fold)
// duplicates at any depth, and duplicate-free credentials.
func TestRawDuplicateMember(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantDup bool
	}{
		{"same-name top level", `{"trustLevel":4,"trustLevel":9}`, true},
		{"case variant top level", `{"TRUSTLEVEL":9,"trustLevel":4}`, true},
		{"case variant nested", `{"a":{"Category":"x","category":"y"}}`, true},
		{"same-name in array", `{"a":[{"k":1,"k":2}]}`, true},
		{"kelvin fold collision", "{\"K\":1,\"k\":2}", true},
		{"non-ASCII case variant", `{"É":1,"é":2}`, true},
		// atx-conformance#187: a number outside the float64 range ahead of
		// the duplicate aborted the scan before UseNumber.
		{"after 1e400", `{"zzz":1e400,"trustLevel":1,"trustLevel":4}`, true},
		{"after -1e400", `{"zzz":-1e400,"trustLevel":1,"trustLevel":4}`, true},
		{"after 401-digit integer", `{"zzz":1` + strings.Repeat("0", 400) + `,"trustLevel":1,"trustLevel":4}`, true},
		{"after 1e400 nested in object", `{"zzz":{"n":1e400},"trustLevel":1,"trustLevel":4}`, true},
		{"after 1e400 nested in array", `{"zzz":[1e400],"trustLevel":1,"trustLevel":4}`, true},
		{"1e400 between the duplicates", `{"trustLevel":1,"zzz":1e400,"trustLevel":4}`, true},
		{"1e400 and distinct keys", `{"zzz":1e400,"trustLevel":4}`, false},
		{"distinct keys", `{"trustLevel":4,"trustScore":9}`, false},
		{"distinct nested", `{"a":{"x":1},"b":{"x":2}}`, false},
		{"empty object", `{}`, false},
	}
	for _, c := range cases {
		_, dup := rawDuplicateMember([]byte(c.raw))
		if dup != c.wantDup {
			t.Errorf("%s: rawDuplicateMember(%s) dup=%v, want %v", c.name, c.raw, dup, c.wantDup)
		}
	}
}

// TestDuplicateAfterOutOfRangeNumberRejects runs the two baseline fixtures
// through verify() with members spliced in at the start of the credential: a
// number outside the float64 range, then a trustLevel that the fixture's own
// trustLevel duplicates later in the object. Each MUST REJECT as PARSE_ERROR
// naming trustLevel; before the fix the v1.1 and v1.0 cases ACCEPTed while
// the 1e300 case rejected. atx-conformance#187.
func TestDuplicateAfterOutOfRangeNumberRejects(t *testing.T) {
	cases := []struct {
		fixture string
		prefix  string
	}{
		{repoRoot + "/fixtures/v1_1-baseline-valid.json", `"zzz":1e400,"trustLevel":1,`},
		{repoRoot + "/fixtures/v1_1-baseline-valid.json", `"zzz":1e300,"trustLevel":1,`},
		{repoRoot + "/fixtures/v1_1-baseline-valid.json", `"zzz":1` + strings.Repeat("0", 400) + `,"trustLevel":1,`},
		{repoRoot + "/fixtures/baseline-valid.json", `"declaredPurpose":1e400,"trustLevel":1,`},
	}
	for _, c := range cases {
		f, err := loadFixture(c.fixture)
		if err != nil {
			t.Fatal(err)
		}
		if got := verify(f); !got.Accepted {
			t.Fatalf("%s as shipped: got %s, want ACCEPT", c.fixture, got)
		}
		raw := strings.TrimSpace(string(f.ATX))
		if !strings.HasPrefix(raw, "{") {
			t.Fatalf("%s: atx member does not start with '{'", c.fixture)
		}
		f.ATX = json.RawMessage("{" + c.prefix + raw[1:])
		got := verify(f)
		if got.Accepted || got.RejectCategory != "PARSE_ERROR" || !strings.Contains(got.Reason, `duplicate member "trustLevel"`) {
			t.Errorf("%s with prefix %.40s: got %s, want REJECT[PARSE_ERROR] naming duplicate member \"trustLevel\"", c.fixture, c.prefix, got)
		}
	}
}

// TestSuiteCatchesCRLBlindVerifier pins that the shipped fixture set depends
// on CRL membership (atx-spec core.md §1.3 step 6). It runs every fixture
// twice: as shipped, where the reference verifier must report the pinned
// outcome, and with the CRL dropped from the verifier state, which is what a
// verifier with no CRL support sees. At least one fixture must then miss its
// pinned outcome. Without one, the revocation coverage this suite claims is
// met by a verifier that reads the credential's own revoked flag and stops.
//
// Mutation-verified: with fixtures/revoked-crl-only.json removed, the CRL-blind
// run matches every remaining fixture and this test fails.
func TestSuiteCatchesCRLBlindVerifier(t *testing.T) {
	paths, err := expandFixturePaths([]string{repoRoot + "/fixtures"})
	if err != nil {
		t.Fatalf("cannot list the shipped fixtures: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no shipped fixtures found; refusing to pass vacuously")
	}

	var caughtBy []string
	for _, p := range paths {
		f, err := loadFixture(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got := verify(f); !matchesExpected(f.Expected, got) {
			t.Errorf("%s: reference verifier observed %s, not the pinned outcome", p, got)
			continue
		}
		crlBlind := f
		crlBlind.VerifierState.CRL = nil
		if !matchesExpected(f.Expected, verify(crlBlind)) {
			caughtBy = append(caughtBy, f.Name)
		}
	}
	if len(caughtBy) == 0 {
		t.Fatalf("a verifier that never consults the CRL matches all %d fixtures: no fixture's verdict depends on CRL membership", len(paths))
	}
	t.Logf("a CRL-blind verifier misses the pinned outcome of: %s", strings.Join(caughtBy, ", "))
}

// TestMLDSA65RequiresEd25519Companion pins core.md section 13 (Cryptographic
// agility): a credential that declares an ML-DSA-65 entry MUST also carry a
// verifying Ed25519 entry. The hybrid baseline ACCEPTs; the same credential
// with its Ed25519 entry removed carries one ML-DSA-65 signature that verifies
// and MUST REJECT as SIGNATURE_INVALID. atx-conformance#133.
func TestMLDSA65RequiresEd25519Companion(t *testing.T) {
	f, err := loadFixture(repoRoot + "/fixtures/v1_1-baseline-valid-hybrid.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := verify(f); !got.Accepted || !got.Ed25519Valid || !got.MLDSA65Valid {
		t.Fatalf("hybrid baseline: got %s (ed25519=%v mldsa65=%v), want ACCEPT with both suites valid", got, got.Ed25519Valid, got.MLDSA65Valid)
	}

	var atx map[string]any
	if err := json.Unmarshal(f.ATX, &atx); err != nil {
		t.Fatal(err)
	}
	var pqOnly []any
	for _, s := range atx["signatures"].([]any) {
		if s.(map[string]any)["algorithm"] == "ML-DSA-65" {
			pqOnly = append(pqOnly, s)
		}
	}
	if len(pqOnly) != 1 {
		t.Fatalf("hybrid baseline carries %d ML-DSA-65 signatures, want 1", len(pqOnly))
	}
	atx["signatures"] = pqOnly
	if f.ATX, err = json.Marshal(atx); err != nil {
		t.Fatal(err)
	}

	got := verify(f)
	if got.Accepted {
		t.Fatal("credential with an ML-DSA-65 signature and no Ed25519 signature must not be accepted")
	}
	if got.RejectCategory != "SIGNATURE_INVALID" || !strings.Contains(got.Reason, "Ed25519") {
		t.Errorf("got %s, want REJECT[SIGNATURE_INVALID] naming the missing Ed25519 companion", got)
	}
}

// TestSuitePinsEd25519CompanionUnderEachVersion pins that the shipped fixture
// set holds the Ed25519 companion rule (core.md section 13, Cryptographic
// agility) under each atcVersion this verifier accepts. For "1.0" and for
// "1.1", a shipped fixture must be one this verifier rejects for the missing
// companion, which it reports only once every declared signature has
// verified and none of them is Ed25519, and that REJECT must be the fixture's
// pinned outcome. The rule names no atcVersion. A verifier that applies it
// under one atcVersion alone finds every declared signature of the other
// one's fixture verifying, so without a fixture under each atcVersion such a
// verifier passes the suite. atx-conformance#151.
func TestSuitePinsEd25519CompanionUnderEachVersion(t *testing.T) {
	paths, err := expandFixturePaths([]string{repoRoot + "/fixtures"})
	if err != nil {
		t.Fatalf("cannot list the shipped fixtures: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no shipped fixtures found; refusing to pass vacuously")
	}

	pinnedBy := map[string][]string{}
	for _, p := range paths {
		f, err := loadFixture(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		got := verify(f)
		if got.RejectCategory != "SIGNATURE_INVALID" || !strings.Contains(got.Reason, "without a verifying Ed25519 signature") {
			continue
		}
		if !matchesExpected(f.Expected, got) {
			t.Errorf("%s: reference verifier observed %s, not the pinned outcome", p, got)
			continue
		}
		var a atx
		if err := json.Unmarshal(f.ATX, &a); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		pinnedBy[a.ATCVersion] = append(pinnedBy[a.ATCVersion], f.Name)
	}
	for _, version := range []string{"1.0", "1.1"} {
		if len(pinnedBy[version]) == 0 {
			t.Errorf("no shipped fixture of atcVersion %s pins the REJECT of ML-DSA-65 signatures that verify with no Ed25519 companion: a verifier that applies the companion rule to the other atcVersion alone passes the suite", version)
			continue
		}
		t.Logf("atcVersion %s: the Ed25519 companion rule is pinned by %s", version, strings.Join(pinnedBy[version], ", "))
	}
}

// withSignatures returns f with its credential's signatures replaced by the
// entries at the given indexes of the ones it carries, in that order, an
// index named twice carried twice.
func withSignatures(t *testing.T, f fixture, indexes ...int) fixture {
	t.Helper()
	var atx map[string]any
	if err := json.Unmarshal(f.ATX, &atx); err != nil {
		t.Fatal(err)
	}
	carried := atx["signatures"].([]any)
	kept := []any{}
	for _, i := range indexes {
		kept = append(kept, carried[i])
	}
	atx["signatures"] = kept
	var err error
	if f.ATX, err = json.Marshal(atx); err != nil {
		t.Fatal(err)
	}
	return f
}

// thresholdReason is the reason verifySignatures writes when the declared
// Ed25519 signatures verify under fewer distinct keys than requiredSignatures.
func thresholdReason(required, distinct int) string {
	return fmt.Sprintf("signature threshold not met: requiredSignatures is %d, distinct Ed25519 keys that verified a declared signature: %d", required, distinct)
}

// TestRequiredSignaturesThreshold pins the k-of-n threshold of core.md
// section 3.1 step 8 (cosignatures from 2 of 3 key holders), which the
// verifier state sets as requiredSignatures: the declared Ed25519 signatures
// must verify under at least that many distinct keys. Each case cuts the
// credential of fixtures/threshold-2of3-cosignature.json, whose three
// signatures verify under the primary's and the two cosigners' keys, to the
// signatures it names. With requiredSignatures 2, its first signature alone is
// fixtures/threshold-1of3-cosignature.json. atx-conformance#132.
func TestRequiredSignaturesThreshold(t *testing.T) {
	base, err := loadFixture(repoRoot + "/fixtures/threshold-2of3-cosignature.json")
	if err != nil {
		t.Fatal(err)
	}
	if base.VerifierState.RequiredSignatures != nil {
		t.Fatal("threshold-2of3-cosignature sets requiredSignatures; the cases below assume it sets none")
	}
	one, two, three := 1, 2, 3
	cases := []struct {
		name       string
		required   *int
		signatures []int
		distinct   int // keys the signatures verify under, for the reason of a REJECT
		accept     bool
	}{
		{"no threshold, the primary's signature alone", nil, []int{0}, 1, true},
		{"1 required, the primary's signature alone", &one, []int{0}, 1, true},
		{"2 required, the primary's signature alone", &two, []int{0}, 1, false},
		{"2 required, a cosigner's signature alone", &two, []int{2}, 1, false},
		{"2 required, the primary's signature carried twice", &two, []int{0, 0}, 1, false},
		{"2 required, the primary and a cosigner", &two, []int{0, 1}, 2, true},
		{"2 required, the two cosigners", &two, []int{1, 2}, 2, true},
		{"2 required, all three", &two, []int{0, 1, 2}, 3, true},
		{"3 required, two of the three", &three, []int{0, 2}, 2, false},
		{"3 required, all three", &three, []int{0, 1, 2}, 3, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := withSignatures(t, base, c.signatures...)
			f.VerifierState.RequiredSignatures = c.required
			got := verify(f)
			if c.accept {
				if !got.Accepted || got.SigsValid != len(c.signatures) {
					t.Errorf("got %s with %d/%d valid, want ACCEPT with every signature valid", got, got.SigsValid, got.SigsExpected)
				}
				return
			}
			if want := thresholdReason(*c.required, c.distinct); got.Accepted || got.RejectCategory != "SIGNATURE_INVALID" || got.Reason != want {
				t.Errorf("got %s, want REJECT[SIGNATURE_INVALID: %s]", got, want)
			}
		})
	}
}

// TestRequiredSignaturesCountsKeysNotKeyIDs pins that a key counts once
// however many signatures verify under it, whatever keyId they carry (the
// rule core.md section 1.3 step 7 states for its count). The verifier state
// lists the primary's key a second time under another keyId of the issuer,
// and the credential carries the primary's signature twice, once under each
// keyId: both verify, under one key.
func TestRequiredSignaturesCountsKeysNotKeyIDs(t *testing.T) {
	f, err := loadFixture(repoRoot + "/fixtures/threshold-1of3-cosignature.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := verify(f); got.Accepted || got.Reason != thresholdReason(2, 1) {
		t.Fatalf("threshold-1of3-cosignature: got %s, want REJECT[SIGNATURE_INVALID: %s]", got, thresholdReason(2, 1))
	}
	const alias = "did:opena2a:authority:opena2a.org#key-1-alias"
	primary := f.VerifierState.PublicKeys[0]
	if primary.Role != "issuer-primary" {
		t.Fatalf("first verifier key is %s, want issuer-primary", primary.Role)
	}
	aliased := primary
	aliased.KeyID = alias
	f.VerifierState.PublicKeys = append(append([]keypairRef{}, f.VerifierState.PublicKeys...), aliased)

	var atx map[string]any
	if err := json.Unmarshal(f.ATX, &atx); err != nil {
		t.Fatal(err)
	}
	sig := atx["signatures"].([]any)[0].(map[string]any)
	second := map[string]any{"keyId": alias, "algorithm": sig["algorithm"], "value": sig["value"]}
	atx["signatures"] = []any{sig, second}
	if f.ATX, err = json.Marshal(atx); err != nil {
		t.Fatal(err)
	}

	got := verify(f)
	if got.Accepted || got.RejectCategory != "SIGNATURE_INVALID" || got.Reason != thresholdReason(2, 1) {
		t.Errorf("two signatures under one key named by two keyIds: got %s, want REJECT[SIGNATURE_INVALID: %s]", got, thresholdReason(2, 1))
	}
	f.VerifierState.RequiredSignatures = nil
	if got := verify(f); !got.Accepted || got.SigsValid != 2 {
		t.Errorf("the same credential with no threshold: got %s with %d/%d valid, want ACCEPT with both valid", got, got.SigsValid, got.SigsExpected)
	}
}

// TestRequiredSignaturesCountsEd25519Only pins that an ML-DSA-65 signature
// does not count toward requiredSignatures: core.md section 1.3a.2 names the
// Ed25519 signatures the threshold signatures and the ML-DSA-65 one the
// hybrid signature. The hybrid baselines carry one Ed25519 and one ML-DSA-65
// signature, both by the primary, and both verify.
func TestRequiredSignaturesCountsEd25519Only(t *testing.T) {
	for _, name := range []string{"baseline-valid-hybrid.json", "v1_1-baseline-valid-hybrid.json"} {
		t.Run(name, func(t *testing.T) {
			f, err := loadFixture(repoRoot + "/fixtures/" + name)
			if err != nil {
				t.Fatal(err)
			}
			one, two := 1, 2
			f.VerifierState.RequiredSignatures = &one
			if got := verify(f); !got.Accepted || !got.Ed25519Valid || !got.MLDSA65Valid {
				t.Errorf("requiredSignatures 1: got %s, want ACCEPT with both suites valid", got)
			}
			f.VerifierState.RequiredSignatures = &two
			if got := verify(f); got.Accepted || got.RejectCategory != "SIGNATURE_INVALID" || got.Reason != thresholdReason(2, 1) {
				t.Errorf("requiredSignatures 2: got %s, want REJECT[SIGNATURE_INVALID: %s]", got, thresholdReason(2, 1))
			}
		})
	}
}

// TestRequiredSignaturesBelowOneIsAConfigError pins that a requiredSignatures
// the fixture format does not allow (an integer below 1) is a verifier
// configuration error, reported before any step reads the credential, as a
// bad clock is: on fixtures/expired.json it is reported in place of EXPIRED.
func TestRequiredSignaturesBelowOneIsAConfigError(t *testing.T) {
	for _, name := range []string{"threshold-2of3-cosignature.json", "expired.json"} {
		for _, n := range []int{0, -1} {
			t.Run(fmt.Sprintf("%s/%d", name, n), func(t *testing.T) {
				f, err := loadFixture(repoRoot + "/fixtures/" + name)
				if err != nil {
					t.Fatal(err)
				}
				f.VerifierState.RequiredSignatures = &n
				want := fmt.Sprintf("bad requiredSignatures: %d is not a positive integer", n)
				if got := verify(f); got.Accepted || got.RejectCategory != "VERIFIER_CONFIG_ERROR" || got.Reason != want {
					t.Errorf("got %s, want REJECT[VERIFIER_CONFIG_ERROR: %s]", got, want)
				}
			})
		}
	}
}

// TestRequiredSignaturesDecode pins how a fixture file's requiredSignatures
// member decodes: a JSON integer in int range is the threshold, null or an
// absent member sets none, a name in another case names the same member, and
// a value of any other JSON type, a number written with a fraction or an
// exponent among them, fails to load. Each case rewrites the member of
// fixtures/threshold-1of3-cosignature.json, `"requiredSignatures": 2`.
func TestRequiredSignaturesDecode(t *testing.T) {
	raw, err := os.ReadFile(repoRoot + "/fixtures/threshold-1of3-cosignature.json")
	if err != nil {
		t.Fatal(err)
	}
	const member = `"requiredSignatures": 2`
	if bytes.Count(raw, []byte(member)) != 1 {
		t.Fatalf("threshold-1of3-cosignature does not carry %s once", member)
	}
	cases := []struct {
		member string
		load   bool
		want   string // the observed result, for a file that loads
	}{
		{`"requiredSignatures": 2`, true, "REJECT[SIGNATURE_INVALID: " + thresholdReason(2, 1) + "]"},
		{`"RequiredSignatures": 2`, true, "REJECT[SIGNATURE_INVALID: " + thresholdReason(2, 1) + "]"},
		{`"requiredSignatures": 1`, true, "ACCEPT"},
		{`"requiredSignatures": null`, true, "ACCEPT"},
		{`"requiredSignatures": null, "requiredSignatures": 2`, true, "REJECT[SIGNATURE_INVALID: " + thresholdReason(2, 1) + "]"},
		{`"requiredSignatures": 2, "RequiredSignatures": null`, true, "ACCEPT"},
		{`"requiredSignatures": -0`, true, "REJECT[VERIFIER_CONFIG_ERROR: bad requiredSignatures: 0 is not a positive integer]"},
		{`"requiredSignatures": "2"`, false, ""},
		{`"requiredSignatures": 2.0`, false, ""},
		{`"requiredSignatures": 1e0`, false, ""},
		{`"requiredSignatures": true`, false, ""},
		{`"requiredSignatures": [2]`, false, ""},
		{`"requiredSignatures": 9223372036854775808`, false, ""},
	}
	for _, c := range cases {
		t.Run(c.member, func(t *testing.T) {
			f, err := parseFixture(bytes.Replace(raw, []byte(member), []byte(c.member), 1))
			if !c.load {
				if err == nil || !strings.Contains(err.Error(), "requiredSignatures") {
					t.Errorf("loaded (err %v), want a load error naming requiredSignatures", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("load error: %v", err)
			}
			if got := verify(f).String(); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
	// An absent member sets no threshold.
	without := bytes.Replace(raw, []byte(",\n    "+member), nil, 1)
	if bytes.Equal(without, raw) {
		t.Fatal("cannot remove the requiredSignatures member")
	}
	f, err := parseFixture(without)
	if err != nil {
		t.Fatal(err)
	}
	if got := verify(f); !got.Accepted {
		t.Errorf("with no requiredSignatures member: got %s, want ACCEPT", got)
	}
}

// TestSuiteCatchesThresholdBlindVerifier pins that the shipped fixture set
// holds a verifier to requiredSignatures: run with the member dropped from
// every fixture's verifier state, which is what a verifier that reads no
// threshold sees, the reference verifier must miss at least one fixture's
// pinned outcome. Without one, a verifier that checks only that every
// declared signature verifies passes the suite, as it did before
// fixtures/threshold-1of3-cosignature.json.
func TestSuiteCatchesThresholdBlindVerifier(t *testing.T) {
	paths, err := expandFixturePaths([]string{repoRoot + "/fixtures"})
	if err != nil {
		t.Fatalf("cannot list the shipped fixtures: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no shipped fixtures found; refusing to pass vacuously")
	}

	var caughtBy []string
	for _, p := range paths {
		f, err := loadFixture(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got := verify(f); !matchesExpected(f.Expected, got) {
			t.Errorf("%s: reference verifier observed %s, not the pinned outcome", p, got)
			continue
		}
		blind := f
		blind.VerifierState.RequiredSignatures = nil
		if !matchesExpected(f.Expected, verify(blind)) {
			caughtBy = append(caughtBy, f.Name)
		}
	}
	if len(caughtBy) == 0 {
		t.Fatalf("a verifier that reads no requiredSignatures matches all %d fixtures: no fixture's verdict depends on the threshold", len(paths))
	}
	t.Logf("a threshold-blind verifier misses the pinned outcome of: %s", strings.Join(caughtBy, ", "))
}

// TestStrictParseDepthGuard is the regression for the unbounded-recursion DoS.
// A credential nested past encoding/json's own depth limit (10000) must be
// rejected without crashing. The strict-parse scan aborts at maxScanDepth and
// json.Unmarshal then rejects the over-deep input with a max-depth error, so
// verify() returns REJECT[PARSE_ERROR] rather than driving the scanner into a
// fatal stack overflow.
//
// Mutation-verified: removing the maxScanDepth guard from
// scanValueForDuplicates makes this test fatally overflow the goroutine stack
// (~11M frames). A shallower input would not catch the regression — Go stacks
// grow to ~1GB, so 200k-deep nesting does NOT overflow a guardless scan.
func TestStrictParseDepthGuard(t *testing.T) {
	const depth = 11_000_000
	deep := strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth)

	// Sanity: encoding/json itself rejects this depth with an error, not a crash.
	var sink any
	if err := json.Unmarshal([]byte(deep), &sink); err == nil {
		t.Fatal("expected json.Unmarshal to reject over-deep input, got nil error")
	}

	got := verify(fixture{ATX: json.RawMessage(deep)})
	if got.Accepted {
		t.Fatal("over-deep credential must not be accepted")
	}
	if got.RejectCategory != "PARSE_ERROR" {
		t.Errorf("over-deep credential rejected with category %q, want PARSE_ERROR", got.RejectCategory)
	}
}

// earlyRejectCategories are the reject categories of steps 0 to 4, which
// verify returns before it reaches signature verification (step 5).
var earlyRejectCategories = map[string]bool{
	"PARSE_ERROR":         true, // step 0
	"UNSUPPORTED_VERSION": true, // step 1
	"EXPIRED":             true, // step 2
	"REVOKED":             true, // step 3
	"UNTRUSTED_ISSUER":    true, // step 4
}

// TestEarlyRejectFixturesCarryValidSignatures pins the "otherwise valid"
// property of the fixtures that reject before step 5. Running the verifiers
// over fixtures/ never checks their signatures, so a fixture whose signature
// broke would still pass and would then test its gate on a credential that a
// verifier skipping that gate also rejects. Each such fixture is run through
// steps 5 to 8 with its gate lifted: last-wins decoding instead of the strict
// parse, atcVersion set to "1.0", and its issuer trusted (its DID added to the
// trusted set and its keys from keypairRefs to the verifier's keys). The clock
// and the revocation state are not read after step 4. atx-conformance#138.
func TestEarlyRejectFixturesCarryValidSignatures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(repoRoot, "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures found; refusing to pass vacuously")
	}
	early := 0
	for _, path := range paths {
		f, err := loadFixture(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !earlyRejectCategories[verify(f).RejectCategory] {
			continue
		}
		early++

		var a atx
		err = json.Unmarshal(f.ATX, &a)
		for _, member := range []*json.RawMessage{&a.DeclaredPurpose, &a.BehavioralProfile, &a.ScanSummary} {
			if err == nil {
				*member, err = lastWins(*member)
			}
		}
		if err != nil {
			t.Errorf("%s: credential does not decode with the strict parse lifted: %v", path, err)
			continue
		}
		if a.ATCVersion != "1.0" && a.ATCVersion != "1.1" {
			a.ATCVersion = "1.0"
		}
		state := f.VerifierState
		state.TrustedIssuers = append(append([]string{}, state.TrustedIssuers...), a.IssuerDID)
		state.PublicKeys = append([]keypairRef{}, state.PublicKeys...)
		for _, ref := range f.KeypairRefs {
			if controllerDID(ref.KeyID) == a.IssuerDID {
				state.PublicKeys = append(state.PublicKeys, ref)
			}
		}

		got := verifySignatures(&a, state)
		if !got.Accepted || got.SigsValid != got.SigsExpected {
			t.Errorf("%s: rejects before step 5, but with that gate lifted its signatures do not verify: %s", path, got)
		}
	}
	if early == 0 {
		t.Fatal("no fixture rejects before step 5; refusing to pass vacuously")
	}
	t.Logf("%d of %d fixtures reject before step 5; their signatures were checked with the gate lifted", early, len(paths))
}

// lastWins re-encodes a raw member as a parser without the strict check reads
// it: a repeated member keeps its last value. The v1.1 canonicalizer refuses
// duplicate members, so the strict parse is lifted here rather than there.
func lastWins(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// TestJCSVectorsThroughVerifierProjection runs this verifier's own v1.1 path
// (credential parse, TBS projection, JCS) over every jcs-vectors vector and
// requires the pinned expected.canonicalHex byte-for-byte. The byte-agreement
// gate runs this test, so the gate covers this verifier's code and not only the
// library it calls. atx-conformance#156.
func TestJCSVectorsThroughVerifierProjection(t *testing.T) {
	dir := filepath.Join(repoRoot, "jcs-vectors", "vectors")
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no vectors found in %s", dir)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path) //nolint:gosec // G304: globbed from the repository's own jcs-vectors/vectors
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				TBS      map[string]json.RawMessage `json:"tbs"`
				Expected struct {
					CanonicalHex string `json:"canonicalHex"`
				} `json:"expected"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			if v.Expected.CanonicalHex == "" {
				t.Fatal("vector has no expected.canonicalHex")
			}

			// The TBS carries trustScore as its %.6f string; the credential
			// carries the same value as a JSON number. Every other TBS member
			// is already in its wire form.
			var score string
			if err := json.Unmarshal(v.TBS["trustScore"], &score); err != nil {
				t.Fatalf("tbs.trustScore is not a string: %v", err)
			}
			v.TBS["trustScore"] = json.RawMessage(score)
			credential, err := json.Marshal(v.TBS)
			if err != nil {
				t.Fatalf("build credential from tbs: %v", err)
			}

			var a atx
			if err := json.Unmarshal(credential, &a); err != nil {
				t.Fatalf("parse credential: %v", err)
			}
			got, err := canonicalPayloadV11(&a)
			if err != nil {
				t.Fatalf("canonicalPayloadV11: %v", err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != v.Expected.CanonicalHex {
				t.Errorf("verifier canonical bytes differ from the pinned vector\n got  %s\n want %s", got, mustHexDecode(t, v.Expected.CanonicalHex))
			}
		})
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("expected.canonicalHex is not hex: %v", err)
	}
	return b
}

// TestTimestampDecode pins what the timestamp decoder behind issuedAt,
// expiresAt and every other timestamp this verifier decodes accepts. The
// Python reference verifier ports this grammar (_parse_rfc3339 in
// verifiers/python/verify.py) and test_verify.py carries the same table, so a Go
// release that changes how the decoder treats one of these inputs, for example
// by enabling the strict RFC 3339 checks the standard library has disabled
// (golang/go#54580), fails here before the two verifiers drift apart. A
// timestamp whose offset has an hour above 24 or a minute above 60 is refused
// with the error Go 1.23 and later give it, under every release, whether its
// day is in range or not, and whether text follows the offset or its sign or
// minute is malformed (checkOffset, offsetFirst).
func TestTimestampDecode(t *testing.T) {
	accepted := []struct {
		in, utc     string
		unix, nanos int64
	}{
		{"2099-12-31T23:59:59Z", "2099-12-31T23:59:59Z", 4102444799, 0},
		{"2099-12-31T23:59:59,5Z", "2099-12-31T23:59:59Z", 4102444799, 500000000},
		{"2099-12-31T23:59:59.123456789123Z", "2099-12-31T23:59:59Z", 4102444799, 123456789},
		{"2099-12-31T23:59:59+24:00", "2099-12-30T23:59:59Z", 4102358399, 0},
		{"2099-12-31T23:59:59-24:00", "2100-01-01T23:59:59Z", 4102531199, 0},
		{"2099-12-31T23:59:59+23:60", "2099-12-30T23:59:59Z", 4102358399, 0},
		{"0000-12-31T23:59:59Z", "0000-12-31T23:59:59Z", -62135596801, 0},
		{"0000-02-29T00:00:00Z", "0000-02-29T00:00:00Z", -62162121600, 0},
		{"0000-01-01T00:00:00+01:00", "-0001-12-31T23:00:00Z", -62167222800, 0},
		{"9999-12-31T23:59:59-24:00", "10000-01-01T23:59:59Z", 253402387199, 0},
		{"2000-02-29T00:00:00Z", "2000-02-29T00:00:00Z", 951782400, 0},
		{"2099-12-31T9:59:59Z", "2099-12-31T09:59:59Z", 4102394399, 0},
		{"1969-12-31T23:59:59.999999999Z", "1969-12-31T23:59:59Z", -1, 999999999},
	}
	for _, c := range accepted {
		raw, _ := json.Marshal(c.in)
		var got timestamp
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("%q: decode error %v, want %s", c.in, err, c.utc)
			continue
		}
		u := got.UTC()
		if s := u.Format(time.RFC3339); s != c.utc || u.Unix() != c.unix || int64(u.Nanosecond()) != c.nanos {
			t.Errorf("%q decoded to %s (%d, %d), want %s (%d, %d)", c.in, s, u.Unix(), u.Nanosecond(), c.utc, c.unix, c.nanos)
		}
	}
	rejected := []string{
		"2099-12-31T24:00:00Z",
		"2099-12-31T23:60:00Z",
		"2099-12-31T23:59:60Z",
		"2099-13-01T00:00:00Z",
		"2099-12-00T00:00:00Z",
		"1900-02-29T00:00:00Z",
		"2099-12-31t23:59:59Z",
		"2099-12-31T23:59:59z",
		"2099-12-31T23:59:59.Z",
		"2099-12-31T23:59:59",
		"2099-12-31T23:59:59+0100",
		"+999-12-31T23:59:59Z",
	}
	for _, in := range rejected {
		raw, _ := json.Marshal(in)
		var got timestamp
		if err := json.Unmarshal(raw, &got); err == nil {
			t.Errorf("%q decoded to %s, want a decode error", in, got.UTC().Format(time.RFC3339))
		}
	}
	// Go 1.23 and later refuse each of these with these errors. Go 1.22
	// decodes the first seven, and refuses the last two, whose day is out of
	// range, for the day; the decoder and parseRFC3339 give these errors
	// under every release.
	offsets := []struct{ in, msg string }{
		{"2099-12-31T23:59:59+25:00", "time zone offset hour out of range"},
		{"2099-12-31T23:59:59-25:00", "time zone offset hour out of range"},
		{"2099-12-31T23:59:59.5+25:00", "time zone offset hour out of range"},
		{"2099-12-31T23:59:59+23:61", "time zone offset minute out of range"},
		{"2026-05-23T00:00:00+00:61", "time zone offset minute out of range"},
		{"2099-12-31T23:59:59+25:61", "time zone offset minute out of range"},
		{"2099-12-31T23:59:59-99:99", "time zone offset minute out of range"},
		{"2099-02-30T23:59:59+25:00", "time zone offset hour out of range"},
		{"1900-02-29T00:00:00+23:61", "time zone offset minute out of range"},
	}
	// Controls: with the offset in range, every release names the day.
	days := []struct{ in, msg string }{
		{"2099-02-30T23:59:59+24:00", "day out of range"},
		{"1900-02-29T00:00:00+23:60", "day out of range"},
		{"2099-02-30T23:59:59Z", "day out of range"},
	}
	for _, c := range append(offsets, days...) {
		want := `parsing time "` + c.in + `": ` + c.msg
		raw, _ := json.Marshal(c.in)
		var got timestamp
		if err := json.Unmarshal(raw, &got); err == nil || err.Error() != want {
			t.Errorf("%q: decode error %v, want %s", c.in, err, want)
		}
		if _, err := parseRFC3339(c.in); err == nil || err.Error() != want {
			t.Errorf("%q: parseRFC3339 error %v, want %s", c.in, err, want)
		}
	}
	// Outside the RFC 3339 layout. Go 1.23 and later refuse the first nine for
	// the offset, which they check before the text after it, its sign and its
	// minute's digits; Go 1.22 refuses the first five for the extra text and
	// the last four as an offset it cannot parse. The decoder and
	// parseRFC3339 give Go 1.23's error under every release.
	const cannotParse = ` as "2006-01-02T15:04:05Z07:00": cannot parse `
	outside := []struct{ in, msg string }{
		{"2099-12-31T23:59:59+25:00x", ": time zone offset hour out of range"},
		{"2099-12-31T23:59:59+23:61x", ": time zone offset minute out of range"},
		{"2099-12-31T23:59:59.5+25:61x", ": time zone offset minute out of range"},
		{"2099-02-30T23:59:59+25:00x", ": time zone offset hour out of range"},
		{"2099-12-31T23:59:59+25:00Z", ": time zone offset hour out of range"},
		{"2026-02-30T00:00:00+25:0a", ": time zone offset hour out of range"},
		{"2099-12-31T23:59:59+25:6a", ": time zone offset hour out of range"},
		{"2099-12-31T23:59:59x25:00", ": time zone offset hour out of range"},
		{"2099-12-31T23:59:59x23:61", ": time zone offset minute out of range"},
	}
	// Controls: Go 1.23 and later do not refuse these for the offset's range,
	// whose offset is in range, follows a Z, is not six bytes with a colon
	// fourth, or has an hour that is not two digits (so its minute is not
	// read), or that has an hour out of range before the offset; every
	// release gives the same error.
	outsideControls := []struct{ in, msg string }{
		{"2099-12-31T23:59:59+24:00x", `: extra text: "x"`},
		{"2099-12-31T23:59:59Z+25:00", `: extra text: "+25:00"`},
		{"2099-12-31T23:59:59x24:00", cannotParse + `"x24:00" as "Z07:00"`},
		{"2099-12-31T23:59:59+25-00", cannotParse + `"+25-00" as "Z07:00"`},
		{"2099-12-31T23:59:59 +25:00", cannotParse + `" +25:00" as "Z07:00"`},
		{"2099-12-31T23:59:59+25:0", cannotParse + `"+25:0" as "Z07:00"`},
		{"2099-12-31T23:59:59+0a:61", cannotParse + `"+0a:61" as "Z07:00"`},
		{"2099-12-31T24:00:00+25:00x", ": hour out of range"},
	}
	for _, c := range append(outside, outsideControls...) {
		want := `parsing time "` + c.in + `"` + c.msg
		raw, _ := json.Marshal(c.in)
		var got timestamp
		if err := json.Unmarshal(raw, &got); err == nil || err.Error() != want {
			t.Errorf("%q: decode error %v, want %s", c.in, err, want)
		}
		if _, err := parseRFC3339(c.in); err == nil || err.Error() != want {
			t.Errorf("%q: parseRFC3339 error %v, want %s", c.in, err, want)
		}
	}
	// A timestamp written with a JSON escape, as raw JSON. Built with Go 1.27,
	// encoding/json decodes these into a plain time.Time field; the timestamp
	// decoder refuses them under every release, as the Python verifier does.
	for _, raw := range []string{
		"\"2026-05-23T00:00:00\\u005a\"",
		"\"\\u0032099-12-31T23:59:59Z\"",
	} {
		var got timestamp
		if err := json.Unmarshal([]byte(raw), &got); err == nil {
			t.Errorf("%s decoded to %s, want a decode error", raw, got.UTC().Format(time.RFC3339))
		}
	}
	if s := (time.Time{}).UTC().Format(time.RFC3339); s != "0001-01-01T00:00:00Z" {
		t.Errorf("zero time formats as %s, want 0001-01-01T00:00:00Z", s)
	}
}

// TestOffsetOutOfRangeVerdict pins the verdict on a time zone offset with an
// hour above 24 or a minute above 60 wherever this verifier decodes a
// timestamp. Go 1.22's time package decodes such a timestamp when its day is
// in range, so before checkOffset a Go 1.22 build reached SIGNATURE_INVALID on
// such an expiresAt and ACCEPT on such a clock. It refuses
// 2026-02-30T00:00:00+25:00 for the day, so before offsetFirst a Go 1.22
// build named the day in an issuedAt, a clock or a CRL issuedAt, where Go 1.23
// and later name the offset. Go 1.23 and later reach the verdicts below, and
// the Python verifier's GO_OFFSET_VERDICTS and GO_UNLOADABLE_OFFSETS hold the
// same.
func TestOffsetOutOfRangeVerdict(t *testing.T) {
	for _, path := range []string{repoRoot + "/fixtures/baseline-valid.json", repoRoot + "/fixtures/v1_1-baseline-valid.json"} {
		for _, c := range []struct{ member, value, msg string }{
			{"expiresAt", "2099-12-31T23:59:59+25:00", "time zone offset hour out of range"},
			{"expiresAt", "2099-12-31T23:59:59+00:61", "time zone offset minute out of range"},
			{"expiresAt", "2099-12-31T23:59:59-99:99", "time zone offset minute out of range"},
			{"issuedAt", "2026-05-23T00:00:00+25:00", "time zone offset hour out of range"},
			{"issuedAt", "2026-05-23T00:00:00+00:61", "time zone offset minute out of range"},
			{"issuedAt", "2026-02-30T00:00:00+25:00", "time zone offset hour out of range"},
		} {
			f, err := loadFixture(path)
			if err != nil {
				t.Fatal(err)
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(f.ATX, &members); err != nil {
				t.Fatal(err)
			}
			members[c.member], _ = json.Marshal(c.value)
			f.ATX, _ = json.Marshal(members)
			if got := verify(f); got.RejectCategory != "PARSE_ERROR" || !strings.Contains(got.Reason, c.msg) {
				t.Errorf("%s with %s %q: got %s, want REJECT[PARSE_ERROR] naming %s", path, c.member, c.value, got, c.msg)
			}
		}
		for _, c := range []struct{ clock, msg string }{
			{"2026-06-01T00:00:00+23:61", "time zone offset minute out of range"},
			{"2026-02-30T00:00:00+25:00", "time zone offset hour out of range"},
		} {
			f, err := loadFixture(path)
			if err != nil {
				t.Fatal(err)
			}
			f.VerifierState.ClockRFC3339 = c.clock
			if got := verify(f); got.RejectCategory != "VERIFIER_CONFIG_ERROR" || !strings.Contains(got.Reason, c.msg) {
				t.Errorf("%s with clockRfc3339 %q: got %s, want REJECT[VERIFIER_CONFIG_ERROR] naming %s", path, c.clock, got, c.msg)
			}
		}
	}
	for _, c := range []struct{ member, value, msg string }{
		{"issuedAt", "2026-05-23T00:00:00+25:00", "time zone offset hour out of range"},
		{"nextUpdate", "2026-05-23T00:00:00+25:00", "time zone offset hour out of range"},
		{"issuedAt", "2026-02-30T00:00:00+25:00", "time zone offset hour out of range"},
	} {
		var f fixture
		crl := `{"verifierState":{"crl":{"` + c.member + `":"` + c.value + `"}}}`
		if err := json.Unmarshal([]byte(crl), &f); err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("CRL %s %q: load error %v, want one naming %s", c.member, c.value, err, c.msg)
		}
	}
	var f fixture
	if err := json.Unmarshal([]byte(`{"verifierState":{"crl":{"entries":[{"revokedAt":"2026-05-23T00:00:00+00:61"}]}}}`), &f); err == nil {
		t.Error("CRL entry revokedAt +00:61: the fixture loaded, want a load error")
	}
	if p := projectBehavioralProfileV11(json.RawMessage(`{"generatedAt":"2026-05-23T00:00:00+25:00"}`)); string(p) != "null" {
		t.Errorf("behavioralProfile.generatedAt +25:00 projected as %s, want null", p)
	}
	// Control: +24:00 and +23:60 decode under every release.
	if p := projectBehavioralProfileV11(json.RawMessage(`{"generatedAt":"2026-05-23T00:00:00+24:00"}`)); string(p) == "null" {
		t.Error("behavioralProfile.generatedAt +24:00 projected as null")
	}
	if _, err := parseRFC3339("2026-06-01T00:00:00+23:60"); err != nil {
		t.Errorf("clock +23:60: %v, want it to parse", err)
	}
}

// TestOffsetOutsideLayoutVerdict pins the reason given for a timestamp outside
// the RFC 3339 layout whose time zone offset has an hour above 24: text
// follows the offset, or its minute is not two digits. Go 1.23 and later
// name the offset; before offsetFirst a Go 1.22 build named the extra text
// ("x") in the first and could not parse the offset ("+25:0a" as "Z07:00")
// in the second. The verdict category was the same under each release. The
// Python verifier refuses each issuedAt here as not in the RFC 3339 layout,
// a PARSE_ERROR too.
func TestOffsetOutsideLayoutVerdict(t *testing.T) {
	values := []string{"2099-12-31T23:59:59+25:00x", "2026-02-30T00:00:00+25:0a"}
	const msg = `": time zone offset hour out of range`
	for _, path := range []string{repoRoot + "/fixtures/baseline-valid.json", repoRoot + "/fixtures/v1_1-baseline-valid.json"} {
		for _, value := range values {
			f, err := loadFixture(path)
			if err != nil {
				t.Fatal(err)
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(f.ATX, &members); err != nil {
				t.Fatal(err)
			}
			members["issuedAt"], _ = json.Marshal(value)
			f.ATX, _ = json.Marshal(members)
			if got := verify(f); got.RejectCategory != "PARSE_ERROR" || !strings.Contains(got.Reason, `"`+value+msg) {
				t.Errorf("%s with issuedAt %q: got %s, want REJECT[PARSE_ERROR] naming the offset hour", path, value, got)
			}

			if f, err = loadFixture(path); err != nil {
				t.Fatal(err)
			}
			f.VerifierState.ClockRFC3339 = value
			if got := verify(f); got.RejectCategory != "VERIFIER_CONFIG_ERROR" || !strings.Contains(got.Reason, `"`+value+msg) {
				t.Errorf("%s with clockRfc3339 %q: got %s, want REJECT[VERIFIER_CONFIG_ERROR] naming the offset hour", path, value, got)
			}
		}
	}
	for _, value := range values {
		var f fixture
		crl := `{"verifierState":{"crl":{"issuedAt":"` + value + `"}}}`
		if err := json.Unmarshal([]byte(crl), &f); err == nil || !strings.Contains(err.Error(), `"`+value+msg) {
			t.Errorf("CRL issuedAt %q: load error %v, want one naming the offset hour", value, err)
		}
	}
}

// TestEscapedTimestampFailsToDecode pins that a timestamp written with a JSON
// escape fails to decode wherever this verifier decodes one: the credential's
// issuedAt is a PARSE_ERROR, a CRL entry's revokedAt fails to load the
// fixture, and a v1.1 behavioralProfile.generatedAt projects the profile as
// null. With plain time.Time fields, a Go 1.27 build decoded all three.
func TestEscapedTimestampFailsToDecode(t *testing.T) {
	const escaped = "\"2026-05-23T00:00:00\\u005a\""
	got := verify(fixture{ATX: json.RawMessage(`{"atcVersion":"1.1","issuedAt":` + escaped + `}`)})
	if got.RejectCategory != "PARSE_ERROR" {
		t.Errorf("escaped issuedAt: %s, want PARSE_ERROR", got)
	}
	var f fixture
	crl := `{"verifierState":{"crl":{"entries":[{"revokedAt":` + escaped + `}]}}}`
	if err := json.Unmarshal([]byte(crl), &f); err == nil {
		t.Error("escaped CRL revokedAt: the fixture loaded, want a load error")
	}
	if p := projectBehavioralProfileV11(json.RawMessage(`{"generatedAt":` + escaped + `}`)); string(p) != "null" {
		t.Errorf("escaped behavioralProfile.generatedAt projected as %s, want null", p)
	}
	// Control: the same instant without the escape decodes.
	if p := projectBehavioralProfileV11(json.RawMessage(`{"generatedAt":"2026-05-23T00:00:00Z"}`)); string(p) == "null" {
		t.Error("unescaped behavioralProfile.generatedAt projected as null")
	}
}

// v11Baseline is fixtures/v1_1-baseline-valid.json as the verifier loads it.
func v11Baseline(t *testing.T) fixture {
	t.Helper()
	f, err := loadFixture(repoRoot + "/fixtures/v1_1-baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// withMembers returns f with each named top-level member of its credential
// set to the JSON text given for it, written as given; an empty text removes
// the member.
func withMembers(t *testing.T, f fixture, members map[string]string) fixture {
	t.Helper()
	var credential map[string]json.RawMessage
	if err := json.Unmarshal(f.ATX, &credential); err != nil {
		t.Fatal(err)
	}
	for name, raw := range members {
		if raw == "" {
			delete(credential, name)
			continue
		}
		credential[name] = json.RawMessage(raw)
	}
	b, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	f.ATX = b
	return f
}

// signedByPrimary returns f with its v1.1 credential carrying one Ed25519
// signature over the credential's own JCS(TBS), made with the primary
// issuer's key: the RFC 8032 test vector in vectors/issuer-primary.json.
func signedByPrimary(t *testing.T, f fixture) fixture {
	t.Helper()
	raw, err := os.ReadFile(repoRoot + "/vectors/issuer-primary.json")
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		SeedHex string `json:"seedHex"`
		KeyID   string `json:"keyId"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(key.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("vectors/issuer-primary.json seedHex is not a %d-byte hex seed (%v)", ed25519.SeedSize, err)
	}
	var a atx
	if err := json.Unmarshal(f.ATX, &a); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalPayloadV11(&a)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := json.Marshal([]signature{{
		KeyID:     key.KeyID,
		Algorithm: "Ed25519",
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), payload)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return withMembers(t, f, map[string]string{"signatures": string(sigs)})
}

// TestDeclaredPurposeUnpairedSurrogateEscape pins the verdict on a v1.1
// credential whose declaredPurpose writes one half of a UTF-16 surrogate pair
// as a \u escape without the other half. declaredPurpose enters the TBS as
// written, and RFC 8785 §3.2.2.2 requires a canonicalizer to refuse such a
// string, so each rejects as VERIFIER_CONFIG_ERROR naming the escape: the
// category the Python reference verifier reaches (GO_SURROGATE_VERDICTS_V11
// in verifiers/python/test_verify.py). The JCS library refuses the escape
// only where the next six bytes are not another \u escape; it reads one
// followed directly by a \u escape that does not complete the pair as a
// single U+FFFD, the second escape included. Without the verifier's own
// check, such a credential was a signature failure, and a declaredPurpose
// signed holding U+FFFD verified with that pair of escapes written in its
// place. atx-conformance#173.
func TestDeclaredPurposeUnpairedSurrogateEscape(t *testing.T) {
	// u writes each UTF-16 code unit given in hex as a \u escape.
	u := func(units ...string) string { return `\u` + strings.Join(units, `\u`) }
	base := v11Baseline(t)
	for _, tc := range []struct{ purpose, want, unpaired string }{
		{`"` + u("d800") + `"`, "VERIFIER_CONFIG_ERROR", u("d800")},
		{`"` + u("dc00") + `"`, "VERIFIER_CONFIG_ERROR", u("dc00")},
		{`"` + u("d800") + `\n"`, "VERIFIER_CONFIG_ERROR", u("d800")},
		{`"` + u("d800", "0041") + `"`, "VERIFIER_CONFIG_ERROR", u("d800")},
		{`"` + u("d800", "d800") + `"`, "VERIFIER_CONFIG_ERROR", u("d800")},
		{`"` + u("dc00", "0041") + `"`, "VERIFIER_CONFIG_ERROR", u("dc00")},
		{`"` + u("dc00", "d800") + `"`, "VERIFIER_CONFIG_ERROR", u("dc00")},
		{`"` + u("DBFF", "E000") + `"`, "VERIFIER_CONFIG_ERROR", u("DBFF")},
		{`"` + u("d800", "d800", "dc00") + `"`, "VERIFIER_CONFIG_ERROR", u("d800")},
		{`"` + u("d800", "dc00", "dc00") + `"`, "VERIFIER_CONFIG_ERROR", u("dc00")},
		{`{"statement": "x` + u("d800", "0041") + `"}`, "VERIFIER_CONFIG_ERROR", u("d800")},
		{`{"x` + u("d800", "0041") + `": 1}`, "VERIFIER_CONFIG_ERROR", u("d800")},
		{`["a", "` + u("dfff", "d800") + `"]`, "VERIFIER_CONFIG_ERROR", u("dfff")},
		// No unpaired surrogate: a pair, with either case of hex digit, the
		// text \ud800 after an escaped backslash, and a pair after one. The
		// baseline signs no declaredPurpose, so each is a signature failure.
		{`"` + u("d800", "dc00") + `"`, "SIGNATURE_INVALID", ""},
		{`"` + u("D83D", "DE00") + `"`, "SIGNATURE_INVALID", ""},
		{`"\\ud800"`, "SIGNATURE_INVALID", ""},
		{`"\\` + u("d800", "dc00") + `"`, "SIGNATURE_INVALID", ""},
	} {
		got := verify(withMembers(t, base, map[string]string{"declaredPurpose": tc.purpose}))
		if got.RejectCategory != tc.want {
			t.Errorf("declaredPurpose %s: %s, want REJECT[%s]", tc.purpose, got, tc.want)
		} else if tc.unpaired != "" && !strings.Contains(got.Reason, "unpaired UTF-16 surrogate escape ("+tc.unpaired+")") {
			t.Errorf("declaredPurpose %s: %s, want the reason to name the unpaired surrogate escape %s", tc.purpose, got, tc.unpaired)
		}
	}

	// A declaredPurpose signed holding U+FFFD verifies; with the character
	// written as an unpaired surrogate escape and the \u escape after it, the
	// credential is refused, not verified against that signature.
	signed := signedByPrimary(t, withMembers(t, base, map[string]string{"declaredPurpose": `"` + u("fffd") + `"`}))
	if got := verify(signed); !got.Accepted {
		t.Fatalf("declaredPurpose signed holding U+FFFD: %s, want ACCEPT", got)
	}
	for _, units := range [][]string{{"d800", "0041"}, {"d800", "d800"}, {"dc00", "fffd"}} {
		purpose := `"` + u(units...) + `"`
		got := verify(withMembers(t, signed, map[string]string{"declaredPurpose": purpose}))
		if got.RejectCategory != "VERIFIER_CONFIG_ERROR" {
			t.Errorf("declaredPurpose %s in place of the signed U+FFFD: %s, want REJECT[VERIFIER_CONFIG_ERROR]", purpose, got)
		}
	}
}

// TestScanSummaryOutsideItsType pins the verdict on a v1.1 credential whose
// scanSummary holds a member outside the type the TBS gives it (atx-spec
// §1.3a.2 rule 2: criticalFindings and highFindings are integers, the other
// four strings), or is not an object. The TBS has no value for either, so no
// signature covers the credential and it rejects as SIGNATURE_INVALID with a
// reason naming scanSummary. The projection leaves such a member at its zero
// value, so without the check the v1.1 baseline, which signs
// criticalFindings 0, verified carrying criticalFindings "3" or 3.5
// (fixtures/v1_1-scan-summary-member-outside-type.json), and a credential
// signed with a zero scanSummary verified carrying a scanSummary of 7. An
// absent or null scanSummary or member is the zero value, and under
// atcVersion 1.0 scanSummary is unsigned (§1.3a.1); neither is refused.
// atx-conformance#173.
func TestScanSummaryOutsideItsType(t *testing.T) {
	base := v11Baseline(t)
	var credential struct {
		ScanSummary map[string]json.RawMessage `json:"scanSummary"`
	}
	if err := json.Unmarshal(base.ATX, &credential); err != nil {
		t.Fatal(err)
	}
	// scanWith is the baseline's signed scanSummary with member written as raw.
	scanWith := func(member, raw string) string {
		scan := map[string]json.RawMessage{}
		for name, value := range credential.ScanSummary {
			scan[name] = value
		}
		scan[member] = json.RawMessage(raw)
		b, err := json.Marshal(scan)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	check := func(label string, f fixture, want string) {
		t.Helper()
		got := verify(f)
		switch {
		case want == "ACCEPT":
			if !got.Accepted {
				t.Errorf("%s: %s, want ACCEPT", label, got)
			}
		case got.RejectCategory != want || !strings.Contains(got.Reason, "scanSummary") || !strings.Contains(got.Reason, "signature"):
			t.Errorf("%s: %s, want REJECT[%s] with a reason naming scanSummary and the signature", label, got, want)
		}
	}

	for _, tc := range []struct{ member, raw, want string }{
		{"criticalFindings", `"3"`, "SIGNATURE_INVALID"},
		{"criticalFindings", `3.5`, "SIGNATURE_INVALID"},
		{"criticalFindings", `3.0`, "SIGNATURE_INVALID"},
		{"criticalFindings", `1e1`, "SIGNATURE_INVALID"},
		{"criticalFindings", `true`, "SIGNATURE_INVALID"},
		{"criticalFindings", `9223372036854775808`, "SIGNATURE_INVALID"},
		{"highFindings", `"1"`, "SIGNATURE_INVALID"},
		{"hma", `7`, "SIGNATURE_INVALID"},
		{"oasbLevel", `["L1"]`, "SIGNATURE_INVALID"},
		{"criticalFindings", `null`, "ACCEPT"},
		{"criticalFindings", `-0`, "ACCEPT"},
		{"hma", `null`, "SIGNATURE_INVALID"},
	} {
		label := fmt.Sprintf("scanSummary.%s %s on the v1.1 baseline", tc.member, tc.raw)
		f := withMembers(t, base, map[string]string{"scanSummary": scanWith(tc.member, tc.raw)})
		if tc.member == "hma" && tc.raw == "null" {
			// Control: hma null is the zero value "", which the baseline does
			// not sign, so the signature fails without the scanSummary check.
			if got := verify(f); got.Accepted || got.RejectCategory != "SIGNATURE_INVALID" || strings.Contains(got.Reason, "scanSummary") {
				t.Errorf("%s: %s, want REJECT[SIGNATURE_INVALID] from the signature itself", label, got)
			}
			continue
		}
		check(label, f, tc.want)
	}

	zero := signedByPrimary(t, withMembers(t, base, map[string]string{"scanSummary": "null"}))
	check("credential signed with a zero scanSummary", zero, "ACCEPT")
	for _, raw := range []string{`7`, `"x"`, `[1.5]`, `true`, `{"criticalFindings": "3"}`, `{"hma": 0}`} {
		check("scanSummary "+raw+" on a credential signed with a zero scanSummary",
			withMembers(t, zero, map[string]string{"scanSummary": raw}), "SIGNATURE_INVALID")
	}
	for _, raw := range []string{`{}`, `{"criticalFindings": null, "hma": null}`, ""} {
		label := "scanSummary " + raw
		if raw == "" {
			label = "no scanSummary"
		}
		check(label+" on a credential signed with a zero scanSummary",
			withMembers(t, zero, map[string]string{"scanSummary": raw}), "ACCEPT")
	}

	v10, err := loadFixture(repoRoot + "/fixtures/baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	check(`scanSummary {"criticalFindings": "3"} on the v1.0 baseline, which signs no scanSummary`,
		withMembers(t, v10, map[string]string{"scanSummary": `{"criticalFindings": "3"}`}), "ACCEPT")
}
