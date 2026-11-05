// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// testEnv is an Env over an empty directory, logging to a buffer.
func testEnv(t *testing.T) (*Env, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	e := NewEnv(t.TempDir(), NewLog(&logBuf, "test.log"))
	e.Commit = "c0ffee0000000000000000000000000000000000"
	e.Timeout = 2 * time.Second
	return e, &logBuf
}

// okStep is a step that runs and shows one line.
func okStep(n int, title string) Step {
	return Step{
		Number:   n,
		Title:    title,
		Sentence: Text("A step that works."),
		Command:  Text("true"),
		Fallback: Text("true"),
		Run: func(context.Context, *Env) (*Output, error) {
			return &Output{Data: "fine"}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			return []string{"output of " + title}, "result of " + title, nil
		},
	}
}

// showOne runs the live tour over steps, all marked ready, with input keys.
func showOne(t *testing.T, e *Env, steps []Step, keys string, color bool) string {
	t.Helper()
	var screen bytes.Buffer
	st := &State{Repo: e.Repo, Commit: e.Commit, CheckedAt: "2026-11-05T08:00:00Z"}
	for _, s := range steps {
		st.Steps = append(st.Steps, StepState{Number: s.Number, Title: s.Title, Status: Ready})
	}
	tour := &Tour{Env: e, Steps: steps, Notes: Notes{}, Screen: NewScreen(&screen, color),
		Keys: NewKeys(strings.NewReader(keys), false, false)}
	tour.Show(context.Background(), st)
	return screen.String()
}

func TestFailingStepPrintsFallbackAndNoErrorText(t *testing.T) {
	e, logBuf := testEnv(t)
	failing := okStep(1, "Fails")
	failing.Fallback = Text("go run ./verifiers/go fixtures")
	failing.Run = func(context.Context, *Env) (*Output, error) {
		return nil, errors.New("detail-for-the-log-only: exit status 3")
	}
	out := showOne(t, e, []Step{failing, okStep(2, "Works")}, "\n\n\n", false)

	if !strings.Contains(out, "This step didn't run. Here's the command instead:") {
		t.Fatalf("no fallback line on the screen:\n%s", out)
	}
	if !strings.Contains(out, "$ go run ./verifiers/go fixtures") {
		t.Fatalf("the fallback command is not on the screen:\n%s", out)
	}
	if strings.Contains(out, "detail-for-the-log-only") || strings.Contains(out, "exit status") {
		t.Fatalf("error text reached the screen:\n%s", out)
	}
	if !strings.Contains(logBuf.String(), "detail-for-the-log-only") {
		t.Fatalf("the error is not in the log:\n%s", logBuf.String())
	}
	if !strings.Contains(out, "result of Works") {
		t.Fatalf("the tour did not continue past the failed step:\n%s", out)
	}
}

func TestPanickingStepPrintsFallbackAndNoTrace(t *testing.T) {
	e, logBuf := testEnv(t)
	broken := okStep(1, "Panics")
	broken.Trim = func(*Env, *Output) ([]string, string, error) {
		var m map[string]int
		m["x"]++ // a nil map write: a runtime panic
		return nil, "", nil
	}
	out := showOne(t, e, []Step{broken}, "\n\n", false)
	if !strings.Contains(out, failLine) {
		t.Fatalf("no fallback line for a panicking step:\n%s", out)
	}
	for _, leak := range []string{"panic", "goroutine", ".go:", "nil map"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q reached the screen:\n%s", leak, out)
		}
	}
	if !strings.Contains(logBuf.String(), "nil map") {
		t.Fatalf("the panic is not in the log:\n%s", logBuf.String())
	}
}

func TestTimedOutStepIsReported(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	e, logBuf := testEnv(t)
	e.Timeout = 300 * time.Millisecond
	slow := okStep(1, "Slow")
	slow.Run = func(ctx context.Context, e *Env) (*Output, error) {
		_, err := e.run(exec.CommandContext(ctx, "bash", "-c", "sleep 20"), "")
		return nil, err
	}

	start := time.Now()
	out := showOne(t, e, []Step{slow}, "\n\n", false)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the step was not stopped at its timeout: %s", elapsed)
	}
	if !strings.Contains(out, "It did not finish in 0 seconds.") && !strings.Contains(out, "It did not finish in") {
		t.Fatalf("the timeout is not reported on the screen:\n%s", out)
	}
	if !strings.Contains(out, failLine) {
		t.Fatalf("no fallback line for a timed-out step:\n%s", out)
	}
	if !strings.Contains(logBuf.String(), ErrTimeout.Error()) {
		t.Fatalf("the timeout is not in the log:\n%s", logBuf.String())
	}

	// The pre-flight hides the step and names the timeout as its reason.
	var screen bytes.Buffer
	st := Preflight(context.Background(), e, []Step{slow}, NewScreen(&screen, false))
	if st.Steps[0].Status != Hidden || !strings.Contains(st.Steps[0].Reason, "did not finish in") {
		t.Fatalf("pre-flight state for a timed-out step: %+v", st.Steps[0])
	}
}

var escapeRe = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

func TestNoColorRemovesEveryEscapeSequence(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	if !ColorEnabled(env(nil), true) {
		t.Fatal("a terminal with NO_COLOR unset should get color (the control)")
	}
	if ColorEnabled(env(map[string]string{"NO_COLOR": "1"}), true) {
		t.Fatal("NO_COLOR=1 left color on")
	}
	if ColorEnabled(env(nil), false) {
		t.Fatal("output that is not a terminal got color")
	}

	e, _ := testEnv(t)
	limited := okStep(1, "With a limit")
	limited.Limit = LimitText("A limit said first.")
	failing := okStep(2, "Fails")
	failing.Run = func(context.Context, *Env) (*Output, error) { return nil, errors.New("x") }
	steps := []Step{limited, failing}

	colored := showOne(t, e, steps, "\n\n\n", ColorEnabled(env(nil), true))
	if !strings.Contains(colored, "\x1b[") {
		t.Fatal("the control run printed no escape sequence, so this test proves nothing")
	}
	plain := showOne(t, e, steps, "\n\n\n", ColorEnabled(env(map[string]string{"NO_COLOR": "1"}), true))
	if strings.Contains(plain, "\x1b") {
		t.Fatalf("NO_COLOR output carries an escape byte:\n%q", plain)
	}
}

func TestEveryLineFitsEightyColumns(t *testing.T) {
	e, _ := testEnv(t)
	long := strings.Repeat("word ", 60)
	wide := okStep(1, "A title that goes on "+strings.Repeat("and on ", 20))
	wide.Sentence = Text(long)
	wide.Limit = LimitText(long)
	wide.Command = Text("go run ./verifiers/go " + strings.Repeat("fixtures/a-long-fixture-name.json ", 8))
	wide.Trim = func(*Env, *Output) ([]string, string, error) {
		return []string{strings.Repeat("x", 200), "  " + long, "REJECT[UNTRUSTED_ISSUER: " + long + "]"}, long, nil
	}
	failing := okStep(2, "Fails")
	failing.Fallback = Text(strings.Repeat("command-part ", 30))
	failing.Run = func(context.Context, *Env) (*Output, error) { return nil, errors.New("x") }
	e.Log = NewLog(&bytes.Buffer{}, "test.log")

	for _, color := range []bool{false, true} {
		tour := []Step{wide, failing}
		var screen bytes.Buffer
		st := &State{Repo: e.Repo, Commit: e.Commit, CheckedAt: strings.Repeat("9", 100)}
		for _, s := range tour {
			st.Steps = append(st.Steps, StepState{Number: s.Number, Status: Ready})
		}
		notes := Notes{1: {long}}
		tr := &Tour{Env: e, Steps: tour, Notes: notes, Screen: NewScreen(&screen, color),
			Keys: NewKeys(strings.NewReader("\n\n\n"), false, false)}
		tr.Show(context.Background(), st)
		text := escapeRe.ReplaceAllString(screen.String(), "")
		text = strings.ReplaceAll(text, "\r", "\n")
		for i, line := range strings.Split(text, "\n") {
			if n := utf8.RuneCountInString(line); n > Width {
				t.Fatalf("color=%v line %d is %d columns: %q", color, i+1, n, line)
			}
		}
		if !strings.Contains(text, "command-part") {
			t.Fatalf("the long fallback command is missing:\n%s", text)
		}
	}
}

func TestClipAndWrap(t *testing.T) {
	if got := Clip(strings.Repeat("a", 100), 80); utf8.RuneCountInString(got) != 80 || !strings.HasSuffix(got, "...") {
		t.Fatalf("Clip: %q", got)
	}
	if got := Clip("short", 80); got != "short" {
		t.Fatalf("Clip changed a short line: %q", got)
	}
	for _, line := range Wrap(strings.Repeat("abc ", 50), 30) {
		if utf8.RuneCountInString(line) > 30 {
			t.Fatalf("Wrap: %q", line)
		}
	}
}

func TestPreflightStateDecidesWhatTheTourShows(t *testing.T) {
	e, _ := testEnv(t)
	needsTool := okStep(2, "Needs a tool")
	needsTool.Needs = func(context.Context, *Env) error { return plainf("Node is not installed") }
	broken := okStep(3, "Breaks")
	broken.Run = func(context.Context, *Env) (*Output, error) { return nil, errors.New("exit status 1") }
	steps := []Step{okStep(1, "Works"), needsTool, broken}

	var pre bytes.Buffer
	st := Preflight(context.Background(), e, steps, NewScreen(&pre, false))
	want := []struct {
		status, reason string
	}{{Ready, ""}, {Hidden, "Node is not installed"}, {Hidden, "a command failed (the log has its output)"}}
	for i, w := range want {
		if st.Steps[i].Status != w.status || st.Steps[i].Reason != w.reason {
			t.Fatalf("step %d: got %+v, want %+v", i+1, st.Steps[i], w)
		}
	}
	for _, line := range []string{"step 1  ready", "step 2  hidden  Needs a tool: Node is not installed", "step 3  hidden"} {
		if !strings.Contains(pre.String(), line) {
			t.Fatalf("pre-flight output lacks %q:\n%s", line, pre.String())
		}
	}

	dir := t.TempDir()
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := StateMatches(loaded, e); !ok {
		t.Fatalf("a state saved for this clone does not match it: %s", why)
	}

	var screen bytes.Buffer
	tour := &Tour{Env: e, Steps: steps, Notes: Notes{}, Screen: NewScreen(&screen, false),
		Keys: NewKeys(strings.NewReader("\n\n\n\n"), false, false)}
	tour.Show(context.Background(), loaded)
	out := screen.String()
	if !strings.Contains(out, "Step 1. Works") {
		t.Fatalf("the ready step is not shown:\n%s", out)
	}
	if strings.Contains(out, "Needs a tool") || strings.Contains(out, "Breaks") {
		t.Fatalf("a hidden step is shown:\n%s", out)
	}
}

func TestPart2IsHiddenWithItsReasonAndNeverShown(t *testing.T) {
	for _, c := range []struct {
		demo, reason string
	}{
		{"", "no --demo path was given"},
		{t.TempDir(), "this commit does not run the delegation demo"},
	} {
		e, _ := testEnv(t)
		e.Demo = c.demo
		steps := append([]Step{okStep(1, "Works")}, Part2()...)
		var pre bytes.Buffer
		st := Preflight(context.Background(), e, steps, NewScreen(&pre, false))
		for _, s := range st.Steps[1:] {
			if s.Status != Hidden || s.Reason != c.reason {
				t.Errorf("demo %q: step %d is %q with reason %q, want hidden with %q", c.demo, s.Number, s.Status, s.Reason, c.reason)
			}
			if want := "step " + strconv.Itoa(s.Number) + "  hidden  " + s.Title; !strings.Contains(pre.String(), want) {
				t.Errorf("the pre-flight lacks %q:\n%s", want, pre.String())
			}
		}
		if !strings.Contains(pre.String(), "1 ready, 2 hidden") {
			t.Errorf("the pre-flight's last line is wrong:\n%s", pre.String())
		}
		var screen bytes.Buffer
		tour := &Tour{Env: e, Steps: steps, Notes: Notes{}, Screen: NewScreen(&screen, false),
			Keys: NewKeys(strings.NewReader("\n\n\n"), false, false)}
		tour.Show(context.Background(), st)
		for _, s := range Part2() {
			if strings.Contains(screen.String(), s.Title) {
				t.Errorf("the tour shows hidden step %d:\n%s", s.Number, screen.String())
			}
		}
	}
}

func TestTheFormLimitIsSaidBeforeTheFirstStep(t *testing.T) {
	e, _ := testEnv(t)
	out := showOne(t, e, []Step{okStep(1, "Works")}, "\n\n", false)
	limit := strings.Index(out, "native ATX credentials")
	first := strings.Index(out, "Step 1. Works")
	if limit < 0 || first < 0 || limit > first {
		t.Fatalf("the limit is not said before the first step:\n%s", out)
	}
}

func TestTourWithoutStateRunsThePreflightFirst(t *testing.T) {
	e, _ := testEnv(t)
	e.StateDir = t.TempDir()
	steps := []Step{okStep(1, "Works")}
	var screen bytes.Buffer
	code := run(context.Background(), &Options{}, e, steps, Notes{}, NewScreen(&screen, false),
		strings.NewReader("\n\n\n"), false)
	out := screen.String()
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if first != "No pre-flight result for this clone yet: running the pre-flight first." {
		t.Fatalf("first line: %q", first)
	}
	if !strings.Contains(out, "step 1  ready") || !strings.Contains(out, "Step 1. Works") {
		t.Fatalf("the pre-flight or the tour did not run:\n%s", out)
	}
	if _, err := LoadState(e.StateDir); err != nil {
		t.Fatalf("the pre-flight the tour ran was not saved: %v", err)
	}
}

func TestStateForAnotherCommitIsNotTrusted(t *testing.T) {
	e, _ := testEnv(t)
	e.StateDir = t.TempDir()
	old := &State{Repo: e.Repo, Commit: "1111111111111111111111111111111111111111",
		Steps: []StepState{{Number: 1, Title: "Works", Status: Ready}}}
	if err := SaveState(e.StateDir, old); err != nil {
		t.Fatal(err)
	}
	var screen bytes.Buffer
	run(context.Background(), &Options{}, e, []Step{okStep(1, "Works")}, Notes{}, NewScreen(&screen, false),
		strings.NewReader("\n\n"), false)
	if !strings.Contains(screen.String(), "The last pre-flight checked commit 111111111111") {
		t.Fatalf("a state for another commit was used:\n%s", screen.String())
	}
}

func TestOfflineCommandsCannotConnect(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	e, _ := testEnv(t)
	if !e.sandboxed() {
		t.Skip("no macOS sandbox on this system: the block is the Go, npm and pip settings alone")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := "PORT=" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	connect := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := e.run(exec.CommandContext(ctx, "bash", "-c", `exec 3<>"/dev/tcp/127.0.0.1/$PORT"`), "", port)
		return err
	}

	// The control: with the network on (as --setup runs), the same command connects.
	e.Online = true
	if err := connect(); err != nil {
		t.Fatalf("the control could not connect, so this test proves nothing: %v", err)
	}
	e.Online = false
	if err := connect(); err == nil {
		t.Fatal("a command run as the pre-flight runs it reached a listener")
	}
}

func TestStateForAnotherDemoPathIsNotTrusted(t *testing.T) {
	e, _ := testEnv(t)
	st := &State{Repo: e.Repo, Commit: e.Commit, Demo: "/somewhere/demo"}
	if ok, _ := StateMatches(st, e); ok {
		t.Fatal("a pre-flight run with --demo was trusted by a tour without it")
	}
	e.Demo = "/somewhere/demo"
	if ok, why := StateMatches(st, e); !ok {
		t.Fatalf("the same --demo did not match: %s", why)
	}
}

func TestKeys(t *testing.T) {
	k := NewKeys(strings.NewReader("x\nr\n\nq\n"), false, false)
	for _, want := range []Key{KeyRepeat, KeyNext, KeyQuit, KeyQuit} {
		if got := k.Next(context.Background()); got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	single := NewKeys(strings.NewReader("zr\nQ"), true, false)
	for _, want := range []Key{KeyRepeat, KeyNext, KeyQuit} {
		if got := single.Next(context.Background()); got != want {
			t.Fatalf("single: got %v, want %v", got, want)
		}
	}
}

func TestCancelledContextStopsAWaitingTour(t *testing.T) {
	// A reader that never delivers a key: only the cancel can end the wait.
	r, w := io.Pipe()
	defer func() { _ = w.Close() }()
	k := NewKeys(r, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	done := make(chan Key, 1)
	go func() { done <- k.Next(ctx) }()
	select {
	case got := <-done:
		if got != KeyQuit {
			t.Fatalf("got %v, want KeyQuit", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled tour kept waiting for a key")
	}
}

func TestRepeatRunsTheStepAgain(t *testing.T) {
	e, _ := testEnv(t)
	runs := 0
	s := okStep(1, "Counted")
	s.Run = func(context.Context, *Env) (*Output, error) { runs++; return &Output{}, nil }
	showOne(t, e, []Step{s}, "\nr\n\n", false)
	if runs != 2 {
		t.Fatalf("the step ran %d times, want 2 (once, then repeated)", runs)
	}
}

func TestParseNotes(t *testing.T) {
	notes, err := ParseNotes(strings.NewReader(NotesForm + `
# another comment
step 4: "quoted text"
Step 4: 'single quotes'
5:
  - first
  - second
`))
	if err != nil {
		t.Fatal(err)
	}
	want := Notes{
		1: {"The answer key is a file anyone can read."},
		3: {"Say the limit before pressing Enter."},
		4: {"quoted text", "single quotes"},
		5: {"first", "second"},
	}
	for n, lines := range want {
		if strings.Join(notes[n], "|") != strings.Join(lines, "|") {
			t.Fatalf("step %d: got %q, want %q", n, notes[n], lines)
		}
	}
	for _, bad := range []string{"no colon here", "x: not a number", "  - an item with no key", "0: zero"} {
		if _, err := ParseNotes(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Fatalf("%q: want an error naming line 1, got %v", bad, err)
		}
	}
}

func TestOfflineEnv(t *testing.T) {
	got := OfflineEnv([]string{
		"PATH=/bin", "HTTPS_PROXY=http://proxy.example:8080", "http_proxy=x", "GOPROXY=https://proxy.golang.org",
		"GOFLAGS=-mod=mod -trimpath", "npm_config_offline=false", "GOWORK=/somewhere/go.work",
	})
	env := map[string]string{}
	for _, kv := range got {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := env[k]; dup {
			t.Fatalf("%s is set twice", k)
		}
		env[k] = v
	}
	want := map[string]string{
		"PATH": "/bin", "GOPROXY": "off", "GOFLAGS": "-trimpath -mod=readonly", "GOTOOLCHAIN": "local",
		"GOWORK": "off", "npm_config_offline": "true", "PIP_NO_INDEX": "1",
	}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("%s=%q, want %q", k, env[k], v)
		}
	}
	for _, k := range []string{"HTTPS_PROXY", "http_proxy"} {
		if _, ok := env[k]; ok {
			t.Fatalf("%s survived", k)
		}
	}
}

// repoRoot is this repository's root, two levels up from the package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := FindRepo(".")
	if err != nil {
		t.Skip("not inside an atx-conformance clone")
	}
	return root
}

func TestTableRows(t *testing.T) {
	steps := Table()
	for i, s := range steps {
		if s.Number != i+1 {
			t.Fatalf("row %d has number %d", i, s.Number)
		}
		if s.Title == "" || s.Sentence == nil || s.Command == nil || s.Fallback == nil || s.Run == nil || s.Trim == nil {
			t.Fatalf("step %d lacks a field", s.Number)
		}
	}
}

func TestAnswerKeyStepCountsComeFromTheFiles(t *testing.T) {
	for _, tool := range []string{"bash", "shasum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	root := repoRoot(t)
	e := NewEnv(root, NewLog(&bytes.Buffer{}, "test.log"))
	out := RunStep(context.Background(), e, stepAnswerKey())
	if out.Err != nil {
		t.Fatalf("step 1 did not run: %v", out.Err)
	}
	names, _ := fs.Glob(os.DirFS(root), "fixtures/*.json")
	accept := 0
	for _, n := range names {
		f, err := readFixture(os.DirFS(root), n)
		if err != nil {
			t.Fatal(err)
		}
		if f.Expected.VerifyResult == "ACCEPT" {
			accept++
		}
	}
	want := strings.Join([]string{
		strconv.Itoa(len(names)), " fixtures: ", strconv.Itoa(accept), " must be accepted, ", strconv.Itoa(len(names) - accept),
		" must be rejected; ", strconv.Itoa(len(names)), " of ", strconv.Itoa(len(names)), " hashes match.",
	}, "")
	if out.Result != want {
		t.Fatalf("result %q, want %q", out.Result, want)
	}
}

// sources are the files of the tour that are not tests.
func sources(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	out := map[string]string{}
	for _, pattern := range []string{"tour/*.go", "tour/issuer/*.py", "cmd/atx-tour/*.go"} {
		names, _ := filepath.Glob(filepath.Join(root, pattern))
		for _, n := range names {
			if strings.HasSuffix(n, "_test.go") {
				continue
			}
			b, err := fs.ReadFile(os.DirFS(filepath.Dir(n)), filepath.Base(n))
			if err != nil {
				t.Fatal(err)
			}
			out[n] = string(b)
		}
	}
	if len(out) == 0 {
		t.Fatal("no source files found")
	}
	return out
}

func TestNoPathOfThisMachineInTheSources(t *testing.T) {
	home := "/" + "Users" + "/"
	for name, text := range sources(t) {
		if strings.Contains(text, home) || strings.Contains(text, "/home/") {
			t.Fatalf("%s names a path of one machine", name)
		}
	}
}

func TestWordsTheTourNeverPrints(t *testing.T) {
	banned := []string{"proof of logging", "we verify any format", "SPIFFE", "WIMSE", "the standard",
		"no account", "no signup", "\u2014"}
	atc := regexp.MustCompile(`\bATC\b`)
	for name, text := range sources(t) {
		for _, b := range banned {
			if strings.Contains(strings.ToLower(text), strings.ToLower(b)) {
				t.Fatalf("%s contains %q", name, b)
			}
		}
		if atc.MatchString(text) {
			t.Fatalf("%s says ATC", name)
		}
	}
}
