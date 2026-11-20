// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

// actAsCommandEnv makes this test binary run main, so that a test can run the
// command as a process whose standard output and standard error are pipes.
const actAsCommandEnv = "ATX_VERIFY_TEST_ACT_AS_COMMAND"

func TestMain(m *testing.M) {
	if os.Getenv(actAsCommandEnv) == "1" {
		main()
		os.Exit(3) // not reached: main exits with the command's exit code
	}
	os.Exit(m.Run())
}

// summaryLine is the summary line of a run in which every fixture passed.
var summaryLine = regexp.MustCompile(`^summary: (\d+) pass, 0 fail \((\d+) fixtures\)$`)

// TestAtATerminalTheNextStepIsTheLastLine holds the run with no argument at a
// terminal, where standard output and standard error reach one screen, to
// ending with nextStep, a line that begins "Next: ", right below the summary
// line, and to writing to standard output the report Run writes with no
// argument and to standard error nextStep alone.
func TestAtATerminalTheNextStepIsTheLastLine(t *testing.T) {
	var report, runErr bytes.Buffer
	if code := verifier.Run(nil, &report, &runErr); code != 0 {
		t.Fatalf("Run with no argument exits %d, want 0 (stderr %q)", code, runErr.String())
	}
	var stdout, stderr bytes.Buffer
	if code := frontDoor(&stdout, &stderr, true); code != 0 {
		t.Fatalf("the run with no argument at a terminal exits %d, want 0 (stderr %q)", code, stderr.String())
	}
	if stdout.String() != report.String() {
		t.Errorf("the run with no argument at a terminal writes to standard output:\n%s\nwant the report Run writes with no argument:\n%s",
			stdout.String(), report.String())
	}
	if stderr.String() != nextStep {
		t.Errorf("the run with no argument at a terminal writes %q to standard error, want %q", stderr.String(), nextStep)
	}

	var screen bytes.Buffer
	frontDoor(&screen, &screen, true)
	lines := strings.Split(strings.TrimSuffix(screen.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("the screen holds %d lines, want the report and the next step: %q", len(lines), screen.String())
	}
	last, above := lines[len(lines)-1], lines[len(lines)-2]
	if !strings.HasPrefix(last, "Next: ") || last+"\n" != nextStep {
		t.Errorf("the screen's last line is %q, want the next step %q", last, nextStep)
	}
	if !summaryLine.MatchString(above) {
		t.Errorf("the line above the next step is %q, want the summary line of a run in which every fixture passed", above)
	}
}

// TestNextStepOnlyAfterAPassAtATerminal holds writeNextStep to writing
// nextStep after a run that exits 0 at a terminal and nothing otherwise:
// after a FAIL (exit 1) or an error (exit 2), and to a pipe or a file.
func TestNextStepOnlyAfterAPassAtATerminal(t *testing.T) {
	for _, c := range []struct {
		code     int
		terminal bool
		want     string
	}{
		{0, true, nextStep},
		{1, true, ""},
		{2, true, ""},
		{0, false, ""},
		{1, false, ""},
	} {
		var b bytes.Buffer
		writeNextStep(&b, c.code, c.terminal)
		if b.String() != c.want {
			t.Errorf("writeNextStep(code %d, terminal %t) writes %q, want %q", c.code, c.terminal, b.String(), c.want)
		}
	}
}

// runCommand runs this test binary as the command with args, its standard
// output and standard error each a pipe, and returns what it wrote to each
// and its exit code.
func runCommand(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("cannot name this test binary: %v", err)
	}
	cmd := exec.Command(exe, args...) //nolint:gosec // G204: exe is this test binary, args are the test's own
	cmd.Env = append(os.Environ(), actAsCommandEnv+"=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	var exit *exec.ExitError
	switch err := cmd.Run(); {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("cannot run %s as the command: %v", exe, err)
	}
	return out.String(), errOut.String(), code
}

// TestPipedRunsWriteWhatTheyWroteBefore runs the command as a process with
// its standard output and standard error pipes, as a script, a CI job or
// scripts/capture_go_verifier.py reads it. With no argument, and with the
// fixtures directory, it writes the report Run writes to standard output,
// nothing to standard error, and exits 0.
func TestPipedRunsWriteWhatTheyWroteBefore(t *testing.T) {
	for _, args := range [][]string{nil, {"../../fixtures"}} {
		var report, runErr bytes.Buffer
		if code := verifier.Run(args, &report, &runErr); code != 0 {
			t.Fatalf("Run(%q) exits %d, want 0 (stderr %q)", args, code, runErr.String())
		}
		stdout, stderr, code := runCommand(t, args...)
		if code != 0 {
			t.Errorf("the command with arguments %q exits %d, want 0", args, code)
		}
		if stderr != "" {
			t.Errorf("the command with arguments %q writes %q to a piped standard error, want nothing", args, stderr)
		}
		if stdout != report.String() {
			t.Errorf("the command with arguments %q writes to a piped standard output:\n%s\nwant the report Run(%q) writes:\n%s",
				args, stdout, args, report.String())
		}
	}
}

// TestIsTerminalIsFalseForAPipeAndAFile holds isTerminal to reading neither
// a pipe nor a regular file as a terminal, so that a run whose standard error
// is redirected to either writes no next step.
func TestIsTerminalIsFalseForAPipeAndAFile(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(w) {
		t.Error("isTerminal reads a pipe as a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("isTerminal reads a regular file as a terminal")
	}
}

// readmeSection is the README.md heading that nextStep links to.
const readmeSection = "Try your verifier in two minutes"

// heading is a Markdown heading line; its first group is the heading's text.
var heading = regexp.MustCompile(`^#{1,6} +(.+?) *#*$`)

// anchor is the fragment GitHub gives a README heading h: h in lower case,
// each space a hyphen, and each character other than a letter, a digit, a
// hyphen or an underscore left out.
func anchor(h string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(h) {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestNextStepLinksToTheReadmeSection holds the link in nextStep to the
// README of the module go.mod declares, at the anchor of the heading
// readmeSection, and README.md to holding that heading outside a fenced
// block.
func TestNextStepLinksToTheReadmeSection(t *testing.T) {
	if got := anchor(readmeSection); got != "try-your-verifier-in-two-minutes" {
		t.Fatalf("anchor(%q) is %q", readmeSection, got)
	}
	goMod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module := regexp.MustCompile(`(?m)^module (\S+)$`).FindSubmatch(goMod)
	if module == nil {
		t.Fatal("go.mod declares no module")
	}
	want := "https://" + string(module[1]) + "#" + anchor(readmeSection)
	if link := regexp.MustCompile(`https://\S+`).FindString(nextStep); link != want {
		t.Errorf("nextStep links to %q, want %q", link, want)
	}

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	var headings []string
	fenced := false
	for _, line := range strings.Split(string(readme), "\n") {
		if strings.HasPrefix(line, "```") {
			fenced = !fenced
			continue
		}
		if h := heading.FindStringSubmatch(line); h != nil && !fenced {
			headings = append(headings, h[1])
		}
	}
	if !slices.Contains(headings, readmeSection) {
		t.Errorf("README.md holds no heading %q outside a fenced block; its headings are %q", readmeSection, headings)
	}
}

// paragraphs returns the paragraphs of the Markdown text md that stand
// outside a fenced block, each a run of lines between blank lines, with each
// run of whitespace in it read as one space, as Markdown renders a line
// break inside a paragraph.
func paragraphs(md string) []string {
	var out, lines []string
	end := func() {
		if len(lines) > 0 {
			out = append(out, strings.Join(strings.Fields(strings.Join(lines, " ")), " "))
			lines = nil
		}
	}
	fenced := false
	for _, line := range strings.Split(md, "\n") {
		switch {
		case strings.HasPrefix(line, "```"):
			end()
			fenced = !fenced
		case fenced:
		case strings.TrimSpace(line) == "":
			end()
		default:
			lines = append(lines, line)
		}
	}
	end()
	return out
}

// nextStepTerms are what a paragraph that quotes nextStep must name besides
// the capture: where a run writes the line, the line it follows, and the
// stream the capture holds.
var nextStepTerms = []string{"terminal", "standard error", "summary line", "standard output"}

// nextStepFailures returns the failures of the Markdown text md of the page
// name, which links docs/captures/go-verifier.txt as capture, a link target
// in parentheses: one when no paragraph outside a fenced block quotes
// nextStep in a code span, and one for each of nextStepTerms and capture
// that such a paragraph does not hold.
func nextStepFailures(name, md, capture string) []string {
	quote := "`" + strings.TrimSuffix(nextStep, "\n") + "`"
	var failures []string
	quoted := false
	for _, p := range paragraphs(md) {
		if !strings.Contains(p, quote) {
			continue
		}
		quoted = true
		for _, want := range append(slices.Clone(nextStepTerms), capture) {
			if !strings.Contains(p, want) {
				failures = append(failures, fmt.Sprintf("%s: the paragraph that quotes nextStep does not hold %q: %q", name, want, p))
			}
		}
	}
	if !quoted {
		failures = append(failures, fmt.Sprintf("%s has no paragraph outside a fenced block that quotes nextStep as %s", name, quote))
	}
	return failures
}

// TestDocsQuoteTheNextStep holds README.md and docs/running-the-verifiers.md,
// where they describe the run with no argument, to quoting nextStep in a
// paragraph that says a run at a terminal writes it to standard error, below
// the summary line, and that docs/captures/go-verifier.txt holds the run's
// standard output. README.md gives that capture as the full output of its
// first command, and the capture ends at the summary line, so a reader at a
// terminal sees one line more than the capture holds. A page altered to drop
// the quote, or one of the words the paragraph must hold, fails the check.
func TestDocsQuoteTheNextStep(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile("../../docs/running-the-verifiers.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range nextStepFailures("README.md", string(readme), "(docs/captures/go-verifier.txt)") {
		t.Error(f)
	}
	for _, f := range nextStepFailures("docs/running-the-verifiers.md", string(page), "(captures/go-verifier.txt)") {
		t.Error(f)
	}

	const capture = "(docs/captures/go-verifier.txt)"
	quote := "`" + strings.TrimSuffix(nextStep, "\n") + "`"
	held := "At a terminal the run writes " + quote + " to standard error, below the\n" +
		"summary line; [the capture]" + capture + " holds its standard output.\n"
	if f := nextStepFailures("held", held, capture); len(f) != 0 {
		t.Errorf("a paragraph that holds the quote and each term fails: %q", f)
	}
	for _, c := range []struct{ label, md string }{
		{"no quote", strings.Replace(held, quote, "the next step", 1)},
		{"the quote in a fenced block alone", "```text\n" + quote + "\n```\n\n" + strings.Replace(held, quote, "it", 1)},
	} {
		if f := nextStepFailures(c.label, c.md, capture); len(f) != 1 {
			t.Errorf("%s: %d failures, want 1: %q", c.label, len(f), f)
		}
	}
	for _, term := range append(slices.Clone(nextStepTerms), capture) {
		md := strings.Replace(strings.Join(strings.Fields(held), " "), term, "", 1)
		if f := nextStepFailures("without "+term, md, capture); len(f) != 1 || !strings.Contains(f[0], strconv.Quote(term)) {
			t.Errorf("a paragraph without %q gives %q, want one failure naming it", term, f)
		}
	}
}
