// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// StepTimeout is how long one step may run, in the tour and in the pre-flight.
const StepTimeout = 30 * time.Second

// modulePath is the first line of the go.mod of an atx-conformance clone.
const modulePath = "module github.com/opena2a-standards/atx-conformance"

// Env is what every step runs against: the clone, the tools found on this
// laptop, the log and the environment the step's commands get.
type Env struct {
	Repo     string // the clone's root, absolute
	Commit   string // the clone's HEAD commit, or "unknown"
	StateDir string // where the pre-flight state and the logs go
	Demo     string // --demo, for tour Part 2
	Timeout  time.Duration
	// Online is true only for --setup. The tour and the pre-flight run every
	// command with the network blocked (OfflineEnv).
	Online bool

	Log      *Log
	Getenv   func(string) string
	Environ  func() []string
	LookPath func(string) (string, error)

	fsys fs.FS

	pyOnce sync.Once
	pyErr  error
	goOnce sync.Once
	goErr  error
	sbOnce sync.Once
	sb     bool
}

// On macOS every command of the tour and the pre-flight also runs under
// sandbox-exec with this profile, which refuses every outbound connection to
// an IP address, loopback included.
const (
	sandboxExec    = "/usr/bin/sandbox-exec"
	sandboxProfile = "(version 1)(allow default)(deny network-outbound (remote ip))"
)

// sandboxed reports whether commands run under the macOS sandbox: on macOS,
// when sandbox-exec is present and applies the profile.
func (e *Env) sandboxed() bool {
	e.sbOnce.Do(func() {
		if runtime.GOOS != "darwin" {
			return
		}
		if _, err := os.Stat(sandboxExec); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		e.sb = exec.CommandContext(ctx, sandboxExec, "-p", sandboxProfile, "/usr/bin/true").Run() == nil
	})
	return e.sb
}

// NetworkBlock says how the network is blocked for the commands of the tour.
func (e *Env) NetworkBlock() string {
	if e.sandboxed() {
		return "the Go, npm and pip settings, and a macOS sandbox"
	}
	return "the Go, npm and pip settings (no sandbox on this system)"
}

// NewEnv returns an Env for the clone at repo.
func NewEnv(repo string, log *Log) *Env {
	e := &Env{
		Repo:     repo,
		Commit:   "unknown",
		Timeout:  StepTimeout,
		Log:      log,
		Getenv:   os.Getenv,
		Environ:  os.Environ,
		LookPath: exec.LookPath,
		fsys:     os.DirFS(repo),
	}
	return e
}

// FS is the clone as a read-only file system: steps read the repository's
// files through it, by slash-separated paths relative to the root.
func (e *Env) FS() fs.FS { return e.fsys }

// SetFS replaces the file system steps read (tests use a fstest.MapFS).
func (e *Env) SetFS(fsys fs.FS) { e.fsys = fsys }

// Has reports whether a program is on PATH.
func (e *Env) Has(program string) bool {
	_, err := e.LookPath(program)
	return err == nil
}

// FindRepo walks up from start to the root of an atx-conformance clone: the
// first directory whose go.mod declares this module and which holds
// conformance.json.
func FindRepo(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if IsSuiteRoot(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no atx-conformance clone here or above")
		}
		dir = parent
	}
}

// IsSuiteRoot reports whether dir is the root of an atx-conformance clone.
func IsSuiteRoot(dir string) bool {
	fsys := os.DirFS(dir)
	mod, err := fs.ReadFile(fsys, "go.mod")
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(string(mod), "\n")
	if strings.TrimSpace(first) != modulePath {
		return false
	}
	_, err = fs.Stat(fsys, "conformance.json")
	return err == nil
}

// The variables OfflineEnv removes before it sets its own.
var droppedVars = map[string]bool{
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "NO_PROXY": true, "FTP_PROXY": true,
	"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true, "ftp_proxy": true,
	"npm_config_proxy": true, "npm_config_https_proxy": true,
	"NPM_CONFIG_PROXY": true, "NPM_CONFIG_HTTPS_PROXY": true, "PIP_PROXY": true,
	"GOPROXY": true, "GOFLAGS": true, "GOTOOLCHAIN": true, "GOWORK": true,
	"npm_config_offline": true, "NPM_CONFIG_OFFLINE": true, "PIP_NO_INDEX": true,
}

// OfflineEnv is the environment of every command the tour and the
// pre-flight run: no proxy variables; Go with no module proxy (GOPROXY=off),
// no go.mod or go.sum edits (-mod=readonly), no toolchain download
// (GOTOOLCHAIN=local) and no go.work from a parent directory; npm offline;
// pip with no package index. A command that needs the network fails.
func OfflineEnv(base []string) []string {
	out := make([]string, 0, len(base)+8)
	var goflags []string
	for _, kv := range base {
		name, value, _ := strings.Cut(kv, "=")
		if name == "GOFLAGS" {
			for _, f := range strings.Fields(value) {
				if !strings.HasPrefix(f, "-mod=") {
					goflags = append(goflags, f)
				}
			}
		}
		if droppedVars[name] {
			continue
		}
		out = append(out, kv)
	}
	goflags = append(goflags, "-mod=readonly")
	return append(out,
		"GOPROXY=off",
		"GOFLAGS="+strings.Join(goflags, " "),
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"npm_config_offline=true",
		"PIP_NO_INDEX=1",
		"PYTHONDONTWRITEBYTECODE=1",
		"GIT_TERMINAL_PROMPT=0",
	)
}

// setupEnv is the environment of --setup: the network is on, but go.mod and
// go.sum still may not change and no go.work applies.
func setupEnv(base []string) []string {
	out := make([]string, 0, len(base)+3)
	var goflags []string
	for _, kv := range base {
		name, value, _ := strings.Cut(kv, "=")
		switch name {
		case "GOFLAGS":
			for _, f := range strings.Fields(value) {
				if !strings.HasPrefix(f, "-mod=") {
					goflags = append(goflags, f)
				}
			}
			continue
		case "GOWORK", "PYTHONDONTWRITEBYTECODE":
			continue
		}
		out = append(out, kv)
	}
	goflags = append(goflags, "-mod=readonly")
	return append(out, "GOFLAGS="+strings.Join(goflags, " "), "GOWORK=off", "PYTHONDONTWRITEBYTECODE=1")
}

func (e *Env) childEnv() []string {
	if e.Online {
		return setupEnv(e.Environ())
	}
	return OfflineEnv(e.Environ())
}

// run executes cmd in dir, a directory of the clone given as a
// slash-separated path ("" or "." for the root). The caller builds cmd from
// constant arguments; values such as a temporary directory reach the command
// through extra, as environment variables the constant script reads. run
// returns the command's combined output, and logs the command, the output and
// the exit status.
func (e *Env) run(cmd *exec.Cmd, dir string, extra ...string) (string, error) {
	cmd.Dir = filepath.Join(e.Repo, filepath.FromSlash(dir))
	cmd.Env = append(e.childEnv(), extra...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
	setProcessGroup(cmd)
	if !e.Online && cmd.Err == nil && e.sandboxed() {
		cmd.Args = append([]string{sandboxExec, "-p", sandboxProfile, cmd.Path}, cmd.Args[1:]...)
		cmd.Path = sandboxExec
	}
	start := time.Now()
	err := cmd.Run()
	out := buf.String()
	if e.Log != nil {
		where := dir
		if where == "" {
			where = "."
		}
		e.Log.Printf("$ %s\n  in %s%s", strings.Join(cmd.Args, " "), where, extraNote(extra))
		e.Log.Block(out)
		status := "exit 0"
		if err != nil {
			status = "error: " + err.Error()
		}
		e.Log.Printf("  %s after %.1f s", status, time.Since(start).Seconds())
	}
	return out, err
}

func extraNote(extra []string) string {
	if len(extra) == 0 {
		return ""
	}
	return ", with " + strings.Join(extra, " ")
}

// pythonReady reports whether the Python verifier's virtual environment
// imports its packages. It runs the check once per process.
func (e *Env) pythonReady(ctx context.Context) error {
	e.pyOnce.Do(func() {
		if _, err := fs.Stat(e.fsys, venvPython); err != nil {
			e.pyErr = plainf("the Python packages are not installed (run --setup with the network on)")
			return
		}
		ctx, cancel := context.WithTimeout(ctx, e.Timeout)
		defer cancel()
		if _, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdPythonImports), ""); err != nil {
			e.pyErr = plainf("the Python packages do not import (run --setup with the network on)")
		}
	})
	return e.pyErr
}

// goModulesReady reports whether the modules both Go modules of the clone
// build from are in the module cache. It runs the check once per process.
func (e *Env) goModulesReady(ctx context.Context) error {
	e.goOnce.Do(func() {
		ctx, cancel := context.WithTimeout(ctx, e.Timeout)
		defer cancel()
		if _, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdGoModules), ""); err != nil {
			e.goErr = plainf("the Go modules are not downloaded (run --setup with the network on)")
		}
	})
	return e.goErr
}

// Log is the tour's log file: every command, its output and every error,
// none of which reach the screen.
type Log struct {
	mu   sync.Mutex
	w    io.Writer
	Path string
}

// NewLog returns a Log writing to w; path is what the screen names.
func NewLog(w io.Writer, path string) *Log { return &Log{w: w, Path: path} }

// Printf writes one timestamped entry.
func (l *Log) Printf(format string, args ...any) {
	if l == nil || l.w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.w, "%s %s\n", time.Now().UTC().Format("15:04:05Z"), fmt.Sprintf(format, args...))
}

// Block writes text as it is, indented.
func (l *Log) Block(text string) {
	if l == nil || l.w == nil || text == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		_, _ = io.WriteString(l.w, "    | "+line+"\n")
	}
}

// openLog creates (or empties) the log file name in dir.
func openLog(dir, name string) (*Log, io.Closer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return NewLog(f, path), f, nil
}
