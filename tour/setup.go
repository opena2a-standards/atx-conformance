// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"context"
	"io/fs"
	"os/exec"
	"time"
)

// SetupTimeout is how long one setup command may run: downloads are slow
// on venue networks.
const SetupTimeout = 10 * time.Minute

// The commands of --setup. Each runs as `bash -c <command>` in the clone's
// root with the network on.
const (
	setupGoModules    = "go mod download && cd jcs-vectors && go mod download"
	setupGoWarm       = "go run ./verifiers/go fixtures"
	setupPythonCheck  = `python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"`
	setupVenv         = "test -x verifiers/python/.venv/bin/python3 || python3 -m venv verifiers/python/.venv"
	setupPythonLock   = "verifiers/python/.venv/bin/python3 -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r verifiers/python/requirements.lock"
	setupNodePackages = "cd jcs-vectors/ts && npm ci --ignore-scripts --no-audit --no-fund"
)

// SetupCommands is the one-time setup, as a presenter can also type it, with
// the network on, from the root of a clone at the commit the tour will show.
const SetupCommands = `  go mod download && (cd jcs-vectors && go mod download)
  python3 -m venv verifiers/python/.venv
  verifiers/python/.venv/bin/python3 -m pip install --disable-pip-version-check \
      --require-hashes --only-binary=:all: -r verifiers/python/requirements.lock
  (cd jcs-vectors/ts && npm ci --ignore-scripts --no-audit --no-fund)`

// Setup installs what the steps need while the network is on: the Go
// modules of both modules, the Python verifier's packages from the
// hash-pinned lock, and the TypeScript leg's package from its lock file. It
// changes nothing tracked in the clone. It returns the process exit code.
func Setup(ctx context.Context, e *Env, scr *Screen) int {
	e.Online = true
	defer func() { e.Online = false }()
	failed := false
	report := func(what string, err error) {
		if err != nil {
			failed = true
			scr.Printf("  failed   %s (the log has the output)", what)
			return
		}
		scr.Printf("  ok       %s", what)
	}
	run := func(cmd *exec.Cmd) error {
		_, err := e.run(cmd, "")
		return err
	}
	scr.Title("Setup: what the tour needs, fetched once with the network on")
	scr.Printf("Clone: atx-conformance at %s", shortCommit(e.Commit))
	scr.Blank()

	step := func(timeout time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, timeout)
	}

	if !e.Has("bash") || !e.Has("go") {
		scr.Printf("  failed   bash and Go are both needed, and one is not installed")
		return 1
	}
	c, cancel := step(SetupTimeout)
	report("Go modules for the verifier and the JCS gate", run(exec.CommandContext(c, "bash", "-c", setupGoModules)))
	cancel()
	c, cancel = step(SetupTimeout)
	report("Go verifier built once (go run ./verifiers/go fixtures)", run(exec.CommandContext(c, "bash", "-c", setupGoWarm)))
	cancel()

	pythonOK := false
	switch {
	case !e.Has("python3"):
		scr.Printf("  skipped  Python is not installed: step 2 shows Go only; steps 4 and 5 are hidden")
	default:
		c, cancel = step(time.Minute)
		err := run(exec.CommandContext(c, "bash", "-c", setupPythonCheck))
		cancel()
		if err != nil {
			report("Python 3.11 or later (this python3 is older)", err)
			break
		}
		c, cancel = step(SetupTimeout)
		err = run(exec.CommandContext(c, "bash", "-c", setupVenv))
		cancel()
		if err == nil {
			c, cancel = step(SetupTimeout)
			err = run(exec.CommandContext(c, "bash", "-c", setupPythonLock))
			cancel()
		}
		report("Python packages from verifiers/python/requirements.lock", err)
		pythonOK = err == nil
	}

	switch {
	case !e.Has("node") || !e.Has("npm"):
		scr.Printf("  skipped  Node is not installed: step 5 is hidden")
	default:
		c, cancel = step(SetupTimeout)
		report("TypeScript package from jcs-vectors/ts/package-lock.json", run(exec.CommandContext(c, "bash", "-c", setupNodePackages)))
		cancel()
	}

	if pythonOK {
		if _, err := fs.Stat(e.FS(), "jcs-vectors/ts/node_modules/canonicalize"); err == nil {
			c, cancel = step(SetupTimeout)
			report("JCS gate built once (jcs-vectors/run-agreement.sh)", run(exec.CommandContext(c, "bash", "-c", cmdGate)))
			cancel()
		}
	}

	scr.Blank()
	if failed {
		scr.Printf("Setup did not finish: the log has each command's output.")
		return 1
	}
	scr.Printf("Setup done. Next, with the network on or off: go run ./cmd/atx-tour --check")
	return 0
}
