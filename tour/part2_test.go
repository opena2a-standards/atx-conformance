// SPDX-License-Identifier: Apache-2.0

//go:build unix

package tour

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// standinNode is a stand-in for node: it answers --version, refuses as the
// demo's launcher does when FAKE_DEMO names a refusal, and otherwise starts
// one child, prints the launcher's Ready line and waits. FAKE_DEMO=stubborn
// ignores SIGTERM, so only the process group kill stops it.
const standinNode = `#!/bin/bash
if [ "$1" = "--version" ]; then echo "${FAKE_NODE_VERSION:-v26.0.0}"; exit 0; fi
case "$FAKE_DEMO" in
port)
  echo "Port $PORT on 127.0.0.1 is in use, possibly by an earlier run of this demo."
  echo "Fix: stop the other run"
  exit 1 ;;
sandbox)
  echo "This terminal is inside another sandbox, so the demo cannot start its parts in their own macOS sandboxes."
  echo "Fix: run it from a plain terminal"
  exit 1 ;;
esac
if [ -n "$NODE_OPTIONS" ]; then echo "NODE_OPTIONS is set in this terminal."; echo "Fix: env -u NODE_OPTIONS"; exit 1; fi
case "$TMPDIR" in */atx-tour-*) ;; *) echo "TMPDIR is not the tour's"; exit 1 ;; esac
sleep 300 &
child=$!
echo "$child" > "$TMPDIR/child.pid"
if [ "$FAKE_DEMO" = "stubborn" ]; then
  trap '' TERM
else
  trap 'kill $child; echo Stopped.; exit 0' TERM INT
fi
echo "Agent banking delegation demo, build test"
echo "Ready. Open http://127.0.0.1:$PORT/ in a browser."
while kill -0 "$child" 2>/dev/null; do wait "$child"; done
`

func needTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, dir, name, text string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
}

// fakeDemo is a directory the pre-flight takes for a demo checkout: a
// launcher file and one commit, and with deps the three dependency files. It
// is never the real demo, so these tests need no Node.js and no network.
func fakeDemo(t *testing.T, launcher, deps bool) (dir, head string) {
	t.Helper()
	dir = t.TempDir()
	if launcher {
		writeFile(t, dir, demoLauncher, "// stand-in\n", 0o644)
	}
	if deps {
		for _, d := range demoDeps {
			writeFile(t, dir, d, "", 0o644)
		}
	}
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "-c", "user.name=tour test", "-c", "user.email=tour-test@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
		"commit", "-q", "--allow-empty", "-m", "stand-in")
	return dir, gitIn(t, dir, "rev-parse", "HEAD")
}

// pinTo makes head the commit the steps were measured at, for one test.
func pinTo(t *testing.T, head string) {
	t.Helper()
	old := demoCommit
	demoCommit = head
	t.Cleanup(func() { demoCommit = old })
}

// withNode makes the stand-in node the one the Env finds, or none.
func withNode(t *testing.T, e *Env, present bool, env ...string) {
	t.Helper()
	bin := t.TempDir()
	writeFile(t, bin, "node", standinNode, 0o755)
	e.LookPath = func(p string) (string, error) {
		if p == "node" {
			if !present {
				return "", exec.ErrNotFound
			}
			return filepath.Join(bin, "node"), nil
		}
		return exec.LookPath(p)
	}
	base := os.Environ()
	e.Environ = func() []string { return append(append([]string(nil), base...), env...) }
}

func TestPart2HiddenWithAReasonForEachFailedCondition(t *testing.T) {
	needTools(t, "bash", "git", "curl")
	type setup struct {
		launcher, pinned, git, node, deps bool
		env                               []string
	}
	ok := setup{launcher: true, pinned: true, git: true, node: true, deps: true}
	for _, c := range []struct {
		name   string
		s      setup
		reason string
	}{
		{"no launcher", setup{git: true}, `^the --demo directory is not a checkout of the delegation demo \(it has no bin/start\.mjs\)$`},
		{"no commit", setup{launcher: true}, `^the demo checkout's commit could not be read \(git rev-parse HEAD failed there\)$`},
		{"another commit", setup{launcher: true, git: true, node: true, deps: true},
			`^the demo checkout is at [0-9a-f]{12}, and steps 6 and 7 were measured at 259e549ad78b: run git -C \S+ checkout 259e549ad78b$`},
		{"no node", setup{launcher: true, pinned: true, git: true, deps: true}, `^Node\.js is not installed; the demo needs 22\.12\.0 or later$`},
		{"old node", setup{launcher: true, pinned: true, git: true, node: true, deps: true, env: []string{"FAKE_NODE_VERSION=v20.11.1"}},
			`^Node\.js 20\.11\.1 is older than 22\.12\.0, which the demo needs$`},
		{"no dependencies", setup{launcher: true, pinned: true, git: true, node: true},
			`^the demo's dependencies are not installed: run npm ci in the demo checkout, network on$`},
		{"port taken", setup{ok.launcher, ok.pinned, ok.git, ok.node, ok.deps, []string{"FAKE_DEMO=port"}},
			`^port [0-9]+ on 127\.0\.0\.1 was taken when the demo started; run the pre-flight again$`},
		{"inside a sandbox", setup{ok.launcher, ok.pinned, ok.git, ok.node, ok.deps, []string{"FAKE_DEMO=sandbox"}},
			`^the demo does not start inside another sandbox; run the tour from a plain terminal$`},
		{"runs, but is no demo", ok, `^the demo did not answer the scenario \(the log has curl's output\)$`},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, _ := testEnv(t)
			e.Timeout = 10 * time.Second
			var dir, head string
			if c.s.git {
				dir, head = fakeDemo(t, c.s.launcher, c.s.deps)
			} else {
				dir = t.TempDir()
				if c.s.launcher {
					writeFile(t, dir, demoLauncher, "// stand-in\n", 0o644)
				}
			}
			if c.s.pinned {
				pinTo(t, head)
			}
			withNode(t, e, c.s.node, c.s.env...)
			e.Demo = dir
			var pre bytes.Buffer
			st := Preflight(context.Background(), e, Part2(), NewScreen(&pre, false))
			re := regexp.MustCompile(c.reason)
			for _, s := range st.Steps {
				if s.Status != Hidden || !re.MatchString(s.Reason) {
					t.Errorf("step %d is %q with reason %q, want hidden with %s", s.Number, s.Status, s.Reason, c.reason)
				}
			}
			if !strings.Contains(pre.String(), "0 ready, 2 hidden") {
				t.Errorf("the pre-flight's last line is wrong:\n%s", pre.String())
			}
			if e.demo.run != nil {
				t.Error("the demo is still recorded as running after the pre-flight")
			}
		})
	}
}

func TestDemoGetsNoNodeOptionsATMPDIROfItsOwnAndAFreePort(t *testing.T) {
	needTools(t, "bash", "git")
	e, _ := testEnv(t)
	e.Timeout = 10 * time.Second
	dir, head := fakeDemo(t, true, true)
	pinTo(t, head)
	withNode(t, e, true, "NODE_OPTIONS=--require /nonexistent.js", "TMPDIR=/somewhere/else", "PORT=1")
	e.Demo = dir
	d, err := e.demoRunning(context.Background())
	if err != nil {
		t.Fatalf("the stand-in did not start: %v", err)
	}
	defer e.StopDemo()
	if d.port == 1 || !strings.Contains(filepath.Base(d.tmp), "atx-tour-") {
		t.Fatalf("the demo got port %d and TMPDIR %s", d.port, d.tmp)
	}
	// A unix socket path under a run directory of this TMPDIR stays under
	// the 104 bytes macOS allows.
	if n := len(d.tmp + "/bank-demo-run-XXXXXX/sock/broker.sock"); n > 104 {
		t.Fatalf("a socket path under %s is %d bytes", d.tmp, n)
	}
}

// procs records every process and directory of each demo run a test saw.
type procs struct {
	mu   sync.Mutex
	pids []int
	tmps []string
}

func (p *procs) record(t *testing.T, d *demo) {
	b, err := os.ReadFile(filepath.Join(d.tmp, "child.pid"))
	if err != nil {
		t.Errorf("the stand-in wrote no child pid: %v", err)
		return
	}
	child, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pids = append(p.pids, d.pid, child)
	p.tmps = append(p.tmps, d.tmp)
}

func (p *procs) launchers() map[int]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	l := map[int]bool{}
	for i := 0; i < len(p.pids); i += 2 {
		l[p.pids[i]] = true
	}
	return l
}

// gone fails the test for every process or directory of a demo run that is
// still there.
func (p *procs) gone(t *testing.T, path string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pids) == 0 {
		t.Fatalf("%s: no demo ran", path)
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, pid := range p.pids {
		for alive(pid) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if alive(pid) {
			t.Errorf("%s: process %d is still running", path, pid)
		}
	}
	for _, tmp := range p.tmps {
		if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: the demo's directory %s is still there", path, tmp)
		}
	}
}

// standinStep is a step of Part 2 against the stand-in launcher; each run
// records the processes it saw and then calls also, when set.
func standinStep(t *testing.T, n int, p *procs, also func(e *Env, d *demo) error) Step {
	s := okStep(n, "Demo step "+strconv.Itoa(n))
	s.UsesDemo = true
	s.Needs = func(ctx context.Context, e *Env) error {
		_, err := e.demoRunning(ctx)
		return err
	}
	s.Run = func(ctx context.Context, e *Env) (*Output, error) {
		d, err := e.demoRunning(ctx)
		if err != nil {
			return nil, err
		}
		p.record(t, d)
		if also != nil {
			if err := also(e, d); err != nil {
				return nil, err
			}
		}
		return &Output{Data: "ran"}, nil
	}
	return s
}

func standinEnv(t *testing.T, env ...string) *Env {
	t.Helper()
	needTools(t, "bash", "git", "ps")
	e, _ := testEnv(t)
	e.Timeout = 10 * time.Second
	dir, head := fakeDemo(t, true, true)
	pinTo(t, head)
	withNode(t, e, true, env...)
	e.Demo = dir
	return e
}

func showWith(e *Env, steps []Step, ctx context.Context, keys io.Reader) (string, int) {
	var screen bytes.Buffer
	st := &State{Repo: e.Repo, Commit: e.Commit, CheckedAt: "2026-11-05T08:00:00Z"}
	for _, s := range steps {
		st.Steps = append(st.Steps, StepState{Number: s.Number, Title: s.Title, Status: Ready})
	}
	tour := &Tour{Env: e, Steps: steps, Notes: Notes{}, Screen: NewScreen(&screen, false),
		Keys: NewKeys(keys, false, false)}
	code := tour.Show(ctx, st)
	return screen.String(), code
}

func TestDemoIsStoppedOnEveryWayOut(t *testing.T) {
	needTools(t, "ps")
	if !alive(os.Getpid()) {
		t.Fatal("alive does not see this test's own process, so no check below proves anything")
	}
	t.Run("step 7 ends", func(t *testing.T) {
		e := standinEnv(t)
		var p procs
		steps := []Step{okStep(5, "Before"), standinStep(t, 6, &p, nil), standinStep(t, 7, &p, nil)}
		screen, code := showWith(e, steps, context.Background(), strings.NewReader("\n\n\n\n"))
		if code != 0 || !strings.Contains(screen, "End of the tour.") {
			t.Fatalf("exit %d:\n%s", code, screen)
		}
		if n := len(p.launchers()); n != 1 {
			t.Errorf("steps 6 and 7 saw %d launchers, want the one started before step 6", n)
		}
		p.gone(t, "step 7 ends")
	})
	t.Run("q", func(t *testing.T) {
		e := standinEnv(t)
		var p procs
		steps := []Step{standinStep(t, 6, &p, nil), standinStep(t, 7, &p, nil)}
		_, code := showWith(e, steps, context.Background(), strings.NewReader("\nq\n"))
		if code != 0 {
			t.Fatalf("q exited %d", code)
		}
		p.gone(t, "q")
	})
	t.Run("Ctrl-C", func(t *testing.T) {
		e := standinEnv(t)
		var p procs
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ran := standinStep(t, 6, &p, func(*Env, *demo) error {
			go func() { time.Sleep(200 * time.Millisecond); cancel() }()
			return nil
		})
		keys, w := io.Pipe()
		defer func() { _ = w.Close() }()
		go func() { _, _ = io.WriteString(w, "\n") }()
		_, code := showWith(e, []Step{ran, standinStep(t, 7, &p, nil)}, ctx, keys)
		if code != 130 {
			t.Fatalf("Ctrl-C exited %d, want 130", code)
		}
		p.gone(t, "Ctrl-C")
	})
	t.Run("the demo dies mid-step", func(t *testing.T) {
		e := standinEnv(t)
		var p procs
		var firstChildGone bool
		dies := standinStep(t, 6, &p, func(_ *Env, d *demo) error {
			if err := syscall.Kill(d.pid, syscall.SIGKILL); err != nil {
				return err
			}
			<-d.exited
			return errors.New("the demo stopped answering")
		})
		after := standinStep(t, 7, &p, func(*Env, *demo) error {
			p.mu.Lock()
			firstChildGone = !alive(p.pids[1])
			p.mu.Unlock()
			return nil
		})
		screen, code := showWith(e, []Step{dies, after}, context.Background(), strings.NewReader("\n\n\n"))
		if code != 0 || !strings.Contains(screen, failLine) {
			t.Fatalf("exit %d, and the failing step showed no fallback:\n%s", code, screen)
		}
		if !firstChildGone {
			t.Error("the dead launcher's child was still running when step 7 ran")
		}
		if n := len(p.launchers()); n != 2 {
			t.Errorf("saw %d launchers, want a second one for step 7", n)
		}
		p.gone(t, "the demo dies mid-step")
	})
	t.Run("a launcher that ignores SIGTERM", func(t *testing.T) {
		old := demoStopWait
		demoStopWait = 300 * time.Millisecond
		defer func() { demoStopWait = old }()
		e := standinEnv(t, "FAKE_DEMO=stubborn")
		var p procs
		_, _ = showWith(e, []Step{standinStep(t, 6, &p, nil)}, context.Background(), strings.NewReader("\nq\n"))
		p.gone(t, "a launcher that ignores SIGTERM")
	})
	t.Run("the pre-flight", func(t *testing.T) {
		e := standinEnv(t)
		var p procs
		var pre bytes.Buffer
		st := Preflight(context.Background(), e, []Step{standinStep(t, 6, &p, nil), standinStep(t, 7, &p, nil)}, NewScreen(&pre, false))
		if len(st.ReadyNumbers()) != 2 {
			t.Fatalf("the stand-in steps are not ready:\n%s", pre.String())
		}
		p.gone(t, "the pre-flight")
	})
}

// The answers below carry the fields steps 6 and 7 read, with the values the
// demo answered at the commit the steps were measured at.
const answerScenario1 = `{"sandbox":{"applied":true},"steps":{
"setup":{"A":{"bankSaw":"Customer A","reason":"Both agents hold Customer A's username and password; the bank sees Customer A."},"B":{}},
"approve":{"A":{},"B":{"reason":"Customer B approved the bill pay agent with three payees, per payment and monthly amount limits, and an end date."}},
"1":{"A":{"bankDecision":"paid","reason":"Paid from a password session as Customer A."},
     "B":{"bankDecision":"paid","bankSaw":"Bill pay agent","reason":"An approved payee, and $86.40 is inside every limit."}}}}`

const answerScenario3 = `{"sandbox":{"applied":true},"steps":{"3":{
"A":{"bankDecision":"password changed","reason":"Customer A changed the password; the bank ended 3 sessions.",
     "effects":[{"who":"Bill pay agent","outcome":"refused at sign in"},{"who":"Budget agent","outcome":"refused at sign in"},{"who":"Customer A","outcome":"signed out"}]},
"B":{"bankDecision":"consent withdrawn","reason":"Customer B withdrew the consent for the bill pay agent; the bank removed that agent's grant and restarted its broker.",
     "effects":[{"who":"Bill pay agent","outcome":"refused by the broker"},{"who":"Budget agent","outcome":"read the balance"},{"who":"Customer B","outcome":"kept working"}]}}}}`

func answer(t *testing.T, text string, edit func(*demoAnswer)) demoAnswer {
	t.Helper()
	var a demoAnswer
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&a)
	}
	return a
}

func TestStep6ShowsTheMeasuredLinesAndRefusesAnythingElse(t *testing.T) {
	listing := strings.Fields("agent.log atx.json broker.token grant.json home stderr.log")
	trim := stepSecret().Trim
	lines, result, err := trim(nil, &Output{Data: secretData{Answer: answer(t, answerScenario1, nil), Listing: listing, Search: 1}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Password path: Both agents hold Customer A's username and password; the bank sees Customer A.",
		"Password path, a normal bill: Paid from a password session as Customer A.",
		"Grant path: Customer B approved the bill pay agent with three payees, per payment and monthly amount limits, and an end date.",
		"Grant path, a normal bill: An approved payee, and $86.40 is inside every limit. The bank saw: Bill pay agent.",
		"The grant path agent's directory holds: agent.log atx.json broker.token grant.json home stderr.log",
		"Search for a password or the customer's sign-in name in that directory: no match",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") || result == "" {
		t.Fatalf("lines:\n%s", strings.Join(lines, "\n"))
	}
	for name, d := range map[string]secretData{
		"no sandbox": {Answer: answer(t, answerScenario1, func(a *demoAnswer) { a.Sandbox.Applied = false }), Listing: listing, Search: 1},
		"a match":    {Answer: answer(t, answerScenario1, nil), Listing: listing, Search: 0},
		"grep error": {Answer: answer(t, answerScenario1, nil), Listing: listing, Search: 2},
		"no token":   {Answer: answer(t, answerScenario1, nil), Listing: listing[:2], Search: 1},
		"bank saw the customer": {Answer: answer(t, answerScenario1, func(a *demoAnswer) {
			p := a.Steps["1"]["B"]
			p.BankSaw = "Customer B"
			a.Steps["1"]["B"] = p
		}), Listing: listing, Search: 1},
	} {
		if _, _, err := trim(nil, &Output{Data: d}); err == nil {
			t.Errorf("%s: step 6 passed", name)
		}
	}
}

func TestStep7ShowsTheMeasuredLinesAndRefusesAnythingElse(t *testing.T) {
	trim := stepRevoke().Trim
	lines, result, err := trim(nil, &Output{Data: answer(t, answerScenario3, nil)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Password path: Customer A changed the password; the bank ended 3 sessions.",
		"  Bill pay agent: refused at sign in",
		"  Budget agent: refused at sign in",
		"  Customer A: signed out",
		"Grant path: Customer B withdrew the consent for the bill pay agent; the bank removed that agent's grant and restarted its broker.",
		"  Bill pay agent: refused by the broker",
		"  Budget agent: read the balance",
		"  Customer B: kept working",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") || result == "" {
		t.Fatalf("lines:\n%s", strings.Join(lines, "\n"))
	}
	for name, edit := range map[string]func(*demoAnswer){
		"no sandbox":    func(a *demoAnswer) { a.Sandbox.Applied = false },
		"not withdrawn": func(a *demoAnswer) { p := a.Steps["3"]["B"]; p.BankDecision = "paid"; a.Steps["3"]["B"] = p },
		"agent not cut": func(a *demoAnswer) { p := a.Steps["3"]["B"]; p.Effects[0].Outcome = "paid"; a.Steps["3"]["B"] = p },
		"login cut": func(a *demoAnswer) {
			p := a.Steps["3"]["B"]
			p.Effects[2].Outcome = "signed out"
			a.Steps["3"]["B"] = p
		},
		"another agent":  func(a *demoAnswer) { p := a.Steps["3"]["B"]; p.Effects = p.Effects[:2]; a.Steps["3"]["B"] = p },
		"no answer at 3": func(a *demoAnswer) { delete(a.Steps, "3") },
	} {
		if _, _, err := trim(nil, &Output{Data: answer(t, answerScenario3, edit)}); err == nil {
			t.Errorf("%s: step 7 passed", name)
		}
	}
}

func TestEveryConnectionTheDemoLoggedMustStayOnLoopback(t *testing.T) {
	tmp := t.TempDir()
	logLines := func(lines ...string) {
		writeFile(t, tmp, "bank-demo-start-x/egress.jsonl", strings.Join(lines, "\n")+"\n", 0o600)
	}
	inTree := []string{
		`{"pid":1,"kind":"hello"}`,
		`{"pid":1,"kind":"child"}`,
		`{"pid":1,"kind":"tcp","host":"127.0.0.1","port":7380}`,
		`{"pid":1,"kind":"tcp","host":"::1","port":7380}`,
		`{"pid":1,"kind":"dns","fn":"dns.lookup","name":"127.0.0.1"}`,
		`{"pid":1,"kind":"ipc","path":"` + tmp + `/bank-demo-run-x/sock/broker.sock"}`,
	}
	logLines(inTree...)
	if out := readEgress(tmp).outside(tmp); len(out) != 0 {
		t.Fatalf("loopback records were flagged: %v", out)
	}
	for _, bad := range []string{
		`{"pid":1,"kind":"tcp","host":"192.0.2.1","port":443}`,
		`{"pid":1,"kind":"dns","fn":"dns.lookup","name":"registry.example"}`,
		`{"pid":1,"kind":"ipc","path":"/var/run/other.sock"}`,
		`{"pid":1,"kind":"udp","host":"127.0.0.1","port":53}`,
	} {
		logLines(append(append([]string(nil), inTree...), bad)...)
		if out := readEgress(tmp).outside(tmp); len(out) != 1 {
			t.Errorf("%s: flagged %v", bad, out)
		}
	}
	logLines("not json")
	if readEgress(tmp).err == nil {
		t.Error("an unreadable connection log was read")
	}
}

func TestPart2FallbackNamesTheDemoCheckout(t *testing.T) {
	e, _ := testEnv(t)
	e.Demo = "/path with space/demo"
	for _, s := range Part2() {
		if fb := s.Fallback(e); !strings.HasPrefix(fb, "cd '/path with space/demo' && npm run scenarios") {
			t.Errorf("step %d's fallback: %q", s.Number, fb)
		}
	}
}
