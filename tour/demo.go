// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// demoCommit is the delegation demo commit steps 6 and 7 were measured at. A
// checkout at another commit is hidden: its lines were never checked.
var demoCommit = "259e549ad78b0ab931a22e26fedde60ea0dbd61a"

// minNode is the oldest Node.js the demo's launcher accepts.
var minNode = [3]int{22, 12, 0}

// demoLauncher is the demo's start script, relative to its checkout. It is the
// package's start script, run without npm, so no npm update check runs.
const demoLauncher = "bin/start.mjs"

// demoDeps are files of the three packages the demo's own start check
// resolves: the dependencies are installed when all three are present.
var demoDeps = []string{
	"node_modules/secretless-ai/dist/broker/index.js",
	"node_modules/@opena2a/atx-verify/package.json",
	"node_modules/@noble/post-quantum/ml-dsa.js",
}

// demoReadyRe is the launcher's line once its bank, broker, token service and
// agents answer.
var demoReadyRe = regexp.MustCompile(`^Ready\. Open http://127\.0\.0\.1:([0-9]+)/ in a browser\.$`)

// demoStopWait is how long the launcher gets to stop its parts after SIGTERM
// before the tour kills its process group.
var demoStopWait = 5 * time.Second

// errNoDemo hides Part 2 when no checkout was given, and errNotDemo when the
// directory given has no launcher.
var (
	errNoDemo  = plainf("no --demo path was given")
	errNotDemo = plainf("the --demo directory is not a checkout of the delegation demo (it has no %s)", demoLauncher)
)

// hasLauncher reports whether dir holds the demo's launcher.
func hasLauncher(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(demoLauncher)))
	return err == nil && !info.IsDir()
}

// demo is one run of the demo's launcher. The tour starts it before step 6
// and stops it, with every process it started, when step 7 ends, on q, on
// Ctrl-C and on any failure.
type demo struct {
	cmd    *exec.Cmd
	pid    int
	port   int
	tmp    string        // the TMPDIR the tour made for this run, resolved
	exited chan struct{} // closed when the launcher has exited
	read   chan struct{} // closed when its output has been read to the end
	ready  chan struct{} // closed when it printed its Ready line

	mu     sync.Mutex
	out    []string
	ready1 sync.Once
}

func (d *demo) output() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.out...)
}

func (d *demo) hasExited() bool {
	select {
	case <-d.exited:
		return true
	default:
		return false
	}
}

// demoState is the Env's view of the demo: at most one run, and at most one
// start at a time.
type demoState struct {
	mu       sync.Mutex
	run      *demo
	starting *demoStart
	failed   error // a start that failed; it is not tried again in this run
}

type demoStart struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// StartDemo starts the demo in the background, unless it is running, being
// started, or failed to start in this run. The tour calls it while the step
// before step 6 is on the screen, so step 6 does not wait for the launcher.
func (e *Env) StartDemo() { e.startDemo() }

func (e *Env) startDemo() *demoStart {
	e.demo.mu.Lock()
	defer e.demo.mu.Unlock()
	if e.demo.run != nil || e.demo.failed != nil {
		return nil
	}
	if e.demo.starting != nil {
		return e.demo.starting
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = StepTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s := &demoStart{cancel: cancel, done: make(chan struct{})}
	e.demo.starting = s
	go func() {
		defer cancel()
		d, err := e.launchDemo(ctx)
		if errors.Is(err, context.DeadlineExceeded) {
			err = plainf("the demo was not ready within %d seconds", int(timeout.Seconds()))
		}
		e.demo.mu.Lock()
		e.demo.starting = nil
		switch {
		case err == nil:
			e.demo.run = d
		case !errors.Is(err, context.Canceled):
			e.demo.failed = err
		}
		e.demo.mu.Unlock()
		close(s.done)
	}()
	return s
}

// demoRunning returns the running demo, and starts it when it is not running.
// A demo whose launcher has exited is cleaned up and started again; a start
// that failed is not.
func (e *Env) demoRunning(ctx context.Context) (*demo, error) {
	e.demo.mu.Lock()
	dead := e.demo.run != nil && e.demo.run.hasExited()
	e.demo.mu.Unlock()
	if dead {
		e.Log.Printf("the demo's launcher had exited; starting it again")
		e.StopDemo()
	}
	if s := e.startDemo(); s != nil {
		select {
		case <-s.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e.demo.mu.Lock()
	defer e.demo.mu.Unlock()
	switch {
	case e.demo.run != nil:
		return e.demo.run, nil
	case e.demo.failed != nil:
		return nil, e.demo.failed
	}
	return nil, plainf("the demo was stopped while it was starting")
}

// StopDemo stops the demo, if it runs or is starting: SIGTERM to the launcher,
// which stops its parts; after demoStopWait, SIGKILL to its process group;
// then the tour's TMPDIR for the demo is removed. It can be called any number
// of times.
func (e *Env) StopDemo() {
	e.demo.mu.Lock()
	s := e.demo.starting
	e.demo.mu.Unlock()
	if s != nil {
		s.cancel()
		<-s.done
	}
	e.demo.mu.Lock()
	d := e.demo.run
	e.demo.run = nil
	e.demo.mu.Unlock()
	if d != nil {
		e.stopDemoRun(d)
	}
}

func (e *Env) stopDemoRun(d *demo) {
	start := time.Now()
	pids := demoPids(d)
	if !d.hasExited() {
		_ = terminate(d.pid)
		select {
		case <-d.exited:
		case <-time.After(demoStopWait):
			e.Log.Printf("the demo's launcher did not stop within %s of SIGTERM; killing its process group", demoStopWait)
		}
	}
	// Whatever is left of the launcher's process group, after a clean stop
	// or a launcher that died, is killed.
	_ = killGroup(d.pid)
	select {
	case <-d.exited:
	case <-time.After(2 * time.Second):
	}
	select {
	case <-d.read:
	case <-time.After(2 * time.Second):
	}
	var left []string
	for _, pid := range pids {
		if alive(pid) {
			left = append(left, strconv.Itoa(pid))
		}
	}
	if err := os.RemoveAll(d.tmp); err != nil {
		e.Log.Printf("the demo's directory %s could not be removed: %v", d.tmp, err)
	}
	all := make([]string, len(pids))
	for i, pid := range pids {
		all[i] = strconv.Itoa(pid)
	}
	e.Log.Printf("the demo stopped in %.1f s: port %d, launcher pid %d, processes %s; %d still running%s",
		time.Since(start).Seconds(), d.port, d.pid, strings.Join(all, " "), len(left), listNote(left))
}

func listNote(pids []string) string {
	if len(pids) == 0 {
		return ""
	}
	return " (" + strings.Join(pids, " ") + ")"
}

// demoPids is the launcher and every process the demo's connection counter
// saw start: each Node.js process of the demo writes a hello line to it.
func demoPids(d *demo) []int {
	seen := map[int]bool{d.pid: true}
	pids := []int{d.pid}
	for _, r := range readEgress(d.tmp).records {
		if r.Kind == "hello" && r.Pid > 0 && !seen[r.Pid] {
			seen[r.Pid] = true
			pids = append(pids, r.Pid)
		}
	}
	return pids
}

// launchDemo checks the checkout, then starts its launcher with the network
// settings of the tour, NODE_OPTIONS removed, a TMPDIR of its own and a free
// port, and waits for its Ready line.
func (e *Env) launchDemo(ctx context.Context) (*demo, error) {
	node, err := e.demoChecks(ctx)
	if err != nil {
		return nil, err
	}
	tmp, err := demoTempDir()
	if err != nil {
		e.Log.Printf("no directory for the demo: %v", err)
		return nil, plainf("no temporary directory could be made for the demo")
	}
	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(tmp)
		e.Log.Printf("no free port: %v", err)
		return nil, plainf("no free port on 127.0.0.1 was found for the demo")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, plainf("the demo's output could not be read")
	}
	cmd := exec.Command(node, demoLauncher)
	cmd.Dir = e.Demo
	cmd.Env = demoEnv(e.Environ(), tmp, port)
	cmd.Stdout = pw
	cmd.Stderr = pw
	ownGroup(cmd)
	start := time.Now()
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = os.RemoveAll(tmp)
		e.Log.Printf("the demo's launcher did not start: %v", err)
		return nil, plainf("the demo's launcher could not be started (the log has the error)")
	}
	_ = pw.Close()
	d := &demo{cmd: cmd, pid: cmd.Process.Pid, port: port, tmp: tmp,
		exited: make(chan struct{}), read: make(chan struct{}), ready: make(chan struct{})}
	e.Log.Printf("$ %s %s\n  in the demo checkout, with NODE_OPTIONS removed, TMPDIR=%s PORT=%d; launcher pid %d",
		node, demoLauncher, tmp, port, d.pid)
	go func() {
		_ = cmd.Wait()
		close(d.exited)
	}()
	go func() {
		defer close(d.read)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			e.Log.Printf("demo | %s", line)
			d.mu.Lock()
			if len(d.out) < 200 {
				d.out = append(d.out, line)
			}
			d.mu.Unlock()
			if m := demoReadyRe.FindStringSubmatch(line); m != nil && m[1] == strconv.Itoa(port) {
				d.ready1.Do(func() { close(d.ready) })
			}
		}
		_ = pr.Close()
	}()
	select {
	case <-d.ready:
		e.Log.Printf("the demo is ready on 127.0.0.1:%d after %.1f s", port, time.Since(start).Seconds())
		return d, nil
	case <-d.exited:
		select {
		case <-d.read:
		case <-time.After(time.Second):
		}
		e.stopDemoRun(d)
		return nil, demoStartReason(d.output(), port)
	case <-ctx.Done():
		e.stopDemoRun(d)
		return nil, ctx.Err()
	}
}

// demoStartReason turns the launcher's refusal, which it prints as a sentence
// and a Fix line, into the pre-flight's reason. The launcher's own words go
// to the log.
func demoStartReason(out []string, port int) error {
	first := ""
	for _, l := range out {
		if strings.TrimSpace(l) != "" {
			first = strings.TrimSpace(l)
			break
		}
	}
	switch {
	case strings.HasPrefix(first, "Port ") && strings.Contains(first, " is in use"):
		return plainf("port %d on 127.0.0.1 was taken when the demo started; run the pre-flight again", port)
	case strings.HasPrefix(first, "This terminal is inside another sandbox"):
		return plainf("the demo does not start inside another sandbox; run the tour from a plain terminal")
	case strings.HasPrefix(first, "Dependencies are not installed"):
		return errDemoDeps
	case strings.HasPrefix(first, "This demo needs Node.js"):
		return plainf("the demo needs Node.js %s or later", versionText(minNode))
	}
	return plainf("the demo did not start (the log has its output)")
}

var errDemoDeps = plainf("the demo's dependencies are not installed: run npm ci in the demo checkout, network on")

// demoChecks is what the pre-flight checks before it starts the demo, each
// with a reason a presenter can act on. It returns the path of node.
func (e *Env) demoChecks(ctx context.Context) (string, error) {
	if e.Demo == "" {
		return "", errNoDemo
	}
	if !hasLauncher(e.Demo) {
		return "", errNotDemo
	}
	head, err := e.runIn(exec.CommandContext(ctx, "git", "rev-parse", "HEAD"), e.Demo, "the demo checkout", sandboxProfile)
	head = strings.TrimSpace(head)
	if err != nil || !commitRe.MatchString(head) {
		return "", plainf("the demo checkout's commit could not be read (git rev-parse HEAD failed there)")
	}
	if head != demoCommit {
		return "", plainf("the demo checkout is at %s, and steps 6 and 7 were measured at %s: run git -C %s checkout %s",
			shortCommit(head), shortCommit(demoCommit), shellQuote(e.Demo), shortCommit(demoCommit))
	}
	// HEAD can name the commit without the checkout holding it, and tracked
	// files can differ from it; the launcher runs only on the commit itself.
	if _, err := e.runIn(exec.CommandContext(ctx, "git", "cat-file", "-e", demoCommit+"^{commit}"), e.Demo, "the demo checkout", sandboxProfile); err != nil {
		return "", plainf("the demo checkout does not hold commit %s: run git -C %s fetch", shortCommit(demoCommit), shellQuote(e.Demo))
	}
	if _, err := e.runIn(exec.CommandContext(ctx, "git", "-c", "core.fsmonitor=false", "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD"), e.Demo, "the demo checkout", sandboxProfile); err != nil {
		return "", plainf("the demo checkout has local changes; run git -C %s status", shellQuote(e.Demo))
	}
	node, err := e.LookPath("node")
	if err != nil {
		return "", plainf("Node.js is not installed; the demo needs %s or later", versionText(minNode))
	}
	out, err := e.runIn(exec.CommandContext(ctx, node, "--version"), e.Demo, "the demo checkout", sandboxProfile)
	v, ok := parseVersion(strings.TrimSpace(out))
	if err != nil || !ok {
		return "", plainf("node --version did not answer with a version (the log has its output)")
	}
	if older(v, minNode) {
		return "", plainf("Node.js %s is older than %s, which the demo needs", versionText(v), versionText(minNode))
	}
	for _, dep := range demoDeps {
		if _, err := os.Stat(filepath.Join(e.Demo, filepath.FromSlash(dep))); err != nil {
			return "", errDemoDeps
		}
	}
	return node, nil
}

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func older(v, min [3]int) bool {
	for i := range v {
		if v[i] != min[i] {
			return v[i] < min[i]
		}
	}
	return false
}

func versionText(v [3]int) string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// shellQuote quotes a path for a command line a presenter can paste.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+~") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// demoTempDir makes the demo's TMPDIR. It is under /tmp where there is one:
// the demo's Unix sockets live under it, and macOS refuses a socket path
// longer than 104 bytes, which a run directory under the per-user temporary
// directory would pass.
func demoTempDir() (string, error) {
	parent := ""
	if info, err := os.Stat("/tmp"); err == nil && info.IsDir() {
		parent = "/tmp"
	}
	dir, err := os.MkdirTemp(parent, "atx-tour-")
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	return dir, nil
}

// freePort is a TCP port on 127.0.0.1 that nothing listens on now.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	return port, ln.Close()
}

// demoEnv is the launcher's environment: the tour's (OfflineEnv) without
// NODE_OPTIONS, which the launcher refuses, and with the tour's TMPDIR and
// port.
func demoEnv(base []string, tmp string, port int) []string {
	var out []string
	for _, kv := range OfflineEnv(base) {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "NODE_OPTIONS", "TMPDIR", "PORT":
			continue
		}
		out = append(out, kv)
	}
	return append(out, "TMPDIR="+tmp, "PORT="+strconv.Itoa(port))
}

// ---- the demo's connection counter -------------------------------------------

// egressRecord is one line of the counter file the launcher writes under its
// TMPDIR: every Node.js process of the demo, every connect and every name
// lookup it made.
type egressRecord struct {
	Pid  int    `json:"pid"`
	Kind string `json:"kind"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type egressLog struct {
	records []egressRecord
	err     error
}

// readEgress reads the counter file of the demo run under tmp.
func readEgress(tmp string) egressLog {
	fsys := os.DirFS(tmp)
	names, err := fs.Glob(fsys, "bank-demo-start-*/egress.jsonl")
	if err != nil || len(names) != 1 {
		return egressLog{err: fmt.Errorf("%d connection logs under the demo's directory", len(names))}
	}
	b, err := fs.ReadFile(fsys, names[0])
	if err != nil {
		return egressLog{err: err}
	}
	var l egressLog
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r egressRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil || r.Kind == "" {
			return egressLog{err: errors.New("a line of the connection log is not a record")}
		}
		l.records = append(l.records, r)
	}
	return l
}

var loopback = map[string]bool{"127.0.0.1": true, "::1": true}

// outside lists the records of l that left this machine's loopback: a TCP
// connect to another address, a name lookup of anything but a loopback
// literal, a Unix socket outside the demo's directory, a UDP send, or a kind
// the counter is not known to write.
func (l egressLog) outside(tmp string) []string {
	var out []string
	for _, r := range l.records {
		switch r.Kind {
		case "hello", "child", "dlopen":
		case "tcp":
			if !loopback[r.Host] {
				out = append(out, fmt.Sprintf("tcp %s:%d", r.Host, r.Port))
			}
		case "dns":
			if !loopback[r.Name] {
				out = append(out, "dns "+r.Name)
			}
		case "ipc":
			if !strings.HasPrefix(filepath.Clean(r.Path), tmp+string(filepath.Separator)) {
				out = append(out, "ipc "+r.Path)
			}
		default:
			out = append(out, r.Kind)
		}
	}
	return out
}

// tally counts the TCP connects and name lookups of l, for the log.
func (l egressLog) tally() string {
	n := map[string]int{}
	for _, r := range l.records {
		n[r.Kind]++
	}
	return fmt.Sprintf("%d processes, %d TCP connects, %d name lookups, %d Unix socket connects",
		n["hello"], n["tcp"], n["dns"], n["ipc"])
}

// checkEgress is the last check of a demo step: every connection the demo
// logged since it started stayed on this machine's loopback.
func (e *Env) checkEgress(d *demo) error {
	l := readEgress(d.tmp)
	if l.err != nil {
		e.Log.Printf("the demo's connection log could not be read: %v", l.err)
		return plainf("the demo's connection log could not be read")
	}
	if out := l.outside(d.tmp); len(out) > 0 {
		e.Log.Printf("the demo logged connections that left loopback: %s", strings.Join(out, ", "))
		return plainf("the demo logged a connection that left this machine's loopback (the log names it)")
	}
	e.Log.Printf("the demo's connection log: %s, all on loopback", l.tally())
	return nil
}
