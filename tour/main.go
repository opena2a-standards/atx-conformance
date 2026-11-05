// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Table is every step of the tour, in order. Part 2 (the delegation demo)
// and the optional last step are later rows of this table.
func Table() []Step {
	return Part1()
}

const usageHead = `atx-tour: a guided tour of the ATX conformance suite, run from a clone.

  go run ./cmd/atx-tour --setup     once, with the network on
  go run ./cmd/atx-tour --check     the pre-flight: every step, network blocked
  go run ./cmd/atx-tour             the tour: only the steps the pre-flight passed

In the tour, Enter shows the next step, r repeats a step and q quits.

One-time setup, from a clone at the commit you will show (network on):

  git clone https://github.com/opena2a-standards/atx-conformance.git
  cd atx-conformance && git checkout <commit>
  go run ./cmd/atx-tour --setup

--setup runs these, which you can also type yourself:

`

// Options are the parsed flags.
type Options struct {
	Check, Setup bool
	Demo         string
	NotesPath    string
	Repo         string
	StateDir     string
}

func parseFlags(args []string, stderr io.Writer) (*Options, error) {
	o := &Options{}
	fl := flag.NewFlagSet("atx-tour", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.BoolVar(&o.Check, "check", false, "run the pre-flight: every step unattended, with the network blocked")
	fl.BoolVar(&o.Setup, "setup", false, "fetch what the steps need, once, with the network on")
	fl.StringVar(&o.Demo, "demo", "", "a checkout of the delegation demo, for tour Part 2")
	fl.StringVar(&o.NotesPath, "notes", "", "a local file of presenter lines per step, shown in a second color,\nwritten like this:\n"+indent(NotesForm, "    "))
	fl.StringVar(&o.Repo, "repo", "", "the atx-conformance clone (default: found from the working directory)")
	fl.StringVar(&o.StateDir, "state-dir", "", "where the pre-flight result and the logs go\n(default: atx-tour in the user cache directory)")
	fl.Usage = func() {
		_, _ = io.WriteString(stderr, usageHead+SetupCommands+"\n\nFlags:\n")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		return nil, err
	}
	if fl.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q (run with -h for the flags)", fl.Arg(0))
	}
	if o.Check && o.Setup {
		return nil, errors.New("--check and --setup are separate runs: use one at a time")
	}
	return o, nil
}

// Main is the atx-tour command. It returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "atx-tour: %v\n", err)
		return 2
	}

	repo := opts.Repo
	if repo == "" {
		wd, err := os.Getwd()
		if err == nil {
			repo, err = FindRepo(wd)
		}
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "atx-tour: run it inside an atx-conformance clone, or pass --repo <dir>")
			return 2
		}
	} else {
		abs, err := filepath.Abs(repo)
		if err != nil || !IsSuiteRoot(abs) {
			_, _ = fmt.Fprintf(stderr, "atx-tour: %s is not the root of an atx-conformance clone\n", repo)
			return 2
		}
		repo = abs
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "atx-tour: no user cache directory; pass --state-dir <dir>")
			return 2
		}
		stateDir = filepath.Join(cache, "atx-tour")
	}
	if opts.Demo != "" {
		if info, err := os.Stat(opts.Demo); err != nil || !info.IsDir() {
			_, _ = fmt.Fprintf(stderr, "atx-tour: --demo %s is not a directory\n", opts.Demo)
			return 2
		}
	}
	notes := Notes{}
	if opts.NotesPath != "" {
		b, err := fs.ReadFile(os.DirFS(filepath.Dir(opts.NotesPath)), filepath.Base(opts.NotesPath))
		if err == nil {
			notes, err = ParseNotes(strings.NewReader(string(b)))
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "atx-tour: --notes %s: %v\n", opts.NotesPath, err)
			return 2
		}
	}

	terminalIn, terminalOut := false, false
	if f, ok := stdin.(*os.File); ok {
		terminalIn = isTerminal(f)
	}
	if f, ok := stdout.(*os.File); ok {
		terminalOut = isTerminal(f)
	}
	scr := NewScreen(stdout, ColorEnabled(os.Getenv, terminalOut))

	logName := "tour.log"
	switch {
	case opts.Check:
		logName = "preflight.log"
	case opts.Setup:
		logName = "setup.log"
	}
	log, closer, err := openLog(stateDir, logName)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "atx-tour: the log could not be opened in %s\n", stateDir)
		return 2
	}
	defer func() { _ = closer.Close() }()

	e := NewEnv(repo, log)
	e.StateDir = stateDir
	e.Demo = opts.Demo
	e.Commit = headCommit(e)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := run(ctx, opts, e, Table(), notes, scr, stdin, terminalIn)
	scr.Printf("Log: %s", log.Path)
	return code
}

func run(ctx context.Context, opts *Options, e *Env, steps []Step, notes Notes, scr *Screen, stdin io.Reader, terminalIn bool) int {
	switch {
	case opts.Setup:
		return Setup(ctx, e, scr)
	case opts.Check:
		st := Preflight(ctx, e, steps, scr)
		if err := SaveState(e.StateDir, st); err != nil {
			e.Log.Printf("the state file could not be written: %v", err)
			scr.Printf("The pre-flight result could not be saved in %s.", e.StateDir)
			return 1
		}
		return 0
	}

	st, err := LoadState(e.StateDir)
	stale := ""
	if err == nil {
		if ok, why := StateMatches(st, e); !ok {
			stale = why
		}
	} else {
		if !errors.Is(err, errNoState) {
			e.Log.Printf("the state file could not be read: %v", err)
		}
		stale = "No pre-flight result for this clone yet"
	}
	if stale != "" {
		scr.Para("", stale+": running the pre-flight first.")
		scr.Blank()
		st = Preflight(ctx, e, steps, scr)
		if err := SaveState(e.StateDir, st); err != nil {
			e.Log.Printf("the state file could not be written: %v", err)
		}
		scr.Blank()
	}

	single := false
	if f, ok := stdin.(*os.File); ok && terminalIn {
		restore, ok := cbreak(f)
		if ok {
			single = true
			defer restore()
		}
	}
	t := &Tour{Env: e, Steps: steps, Notes: notes, Screen: scr, Keys: NewKeys(stdin, single, terminalIn)}
	return t.Show(ctx, st)
}

func indent(text, by string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = by + l
	}
	return strings.Join(lines, "\n")
}

// headCommit is the clone's HEAD commit, read with git.
func headCommit(e *Env) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := e.run(exec.CommandContext(ctx, "git", "rev-parse", "HEAD"), "")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(out)
}
