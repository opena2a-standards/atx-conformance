// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// selectingFlags are the options that select the interop kit in
// cmd/atx-verify. Arguments that carry none of them go to the reference
// verifier, whose output stays as it was.
var selectingFlags = []string{"--verifier", "--verifier-url", "--label", "--form", "--report", "--timeout"}

// Requested reports whether args carry one of the interop kit's options,
// spelled with two dashes, alone or as --name=value, before any "--".
func Requested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		name, _, _ := strings.Cut(a, "=")
		for _, f := range selectingFlags {
			if name == f {
				return true
			}
		}
	}
	return false
}

// defaultTimeout is how long the kit waits for one fixture's answer.
const defaultTimeout = 30 * time.Second

// maxTimeout bounds --timeout.
const maxTimeout = 24 * time.Hour

// defaultLabel names a verifier run without --label.
const defaultLabel = "unnamed verifier"

// kitName is how the reports name the kit.
const kitName = "atx-verify interop kit"

// usage is the kit's help, written for -h or --help next to a kit option.
const usage = `usage: atx-verify --verifier "<command>" [--label <name>] [--report <dir>] [--timeout <duration>]
       atx-verify --verifier-url <url> [--label <name>] [--report <dir>] [--timeout <duration>]

Sends each ATX conformance fixture built into this module version to your
verifier, one at a time, and compares each verdict with the answer key in
conformance.json. Your verifier stays yours: the kit only calls it and
compares. The kit compares ACCEPT and REJECT only: it does not compare
reject categories or the reasons a verifier gives. Nothing is uploaded;
the kit sends nothing anywhere except fixtures to the URL you pass with
--verifier-url.

  --verifier "<command>"  run <command> once per fixture. {file} in the command
                          becomes the path of the fixture file; with no {file},
                          the fixture's credential JSON (its "atx" member) goes
                          to the command's stdin. Exit 0 is ACCEPT, exit 1 is
                          REJECT, and any other exit, a crash or a timeout is
                          couldn't read.
                          No shell is started: the command is split into words
                          at spaces, and a word with a space in it goes in
                          '...' or "...". Pipes, redirects, $VARIABLES and ~
                          are not expanded. A backslash outside quotes is kept
                          as it is, so a Windows path works as written.
  --verifier-url <url>    POST each fixture's credential JSON to <url>; an
                          ATX-Fixture header names the fixture file. A 2xx
                          status is ACCEPT, 4xx is REJECT, and 5xx, no answer
                          or a timeout is couldn't read.
  --label <name>          your verifier's name and version, printed in the
                          report (default "unnamed verifier")
  --form native           the credential form; native is the default and the
                          only form in this release (jws and vc are reserved
                          for a later release)
  --report <dir>          also write <dir>/atx-interop-report.json and
                          <dir>/atx-interop-report.md (the directory is created
                          when it does not exist)
  --timeout <duration>    how long to wait for one fixture, such as 30s or 2m;
                          a plain number is seconds (default 30s)
  -h, --help              print this help and exit 0

JSON wins over exit and status codes when the whole answer is one JSON object
(stdout, or the response body): "verdict": "ACCEPT" or "valid": true is ACCEPT,
"verdict": "REJECT" or "valid": false is REJECT, and "verdict": "ERROR" is
couldn't read. An optional "reason" string is recorded, and the first 200
characters of each raw answer are kept.

Exit status: 0 when every fixture agrees with the answer key, 1 when any
does not, 2 for a usage error or when the kit could not run.
`

// credentialOnlyLimit is said before a run of a command with no {file}, which
// gets the credential alone.
const credentialOnlyLimit = "Each fixture's credential is sent alone, without the fixture's trusted issuers, keys, revocation list or clock; a command with {file} gets the whole fixture file."

// urlLimit is said before a URL run: the body is the credential alone, and a
// header names the fixture, so a partner does not discover it in their logs.
const urlLimit = "Each fixture's credential is sent alone, without the fixture's trusted issuers, keys, revocation list or clock, and its file name goes in an " + FixtureHeader + " header; a command with {file} gets the whole fixture file."

// usageHint ends each usage error.
const usageHint = "add --help to see the options"

// runEnv is what a run reads from outside its arguments: the clock and the
// build information. Run uses the real ones; tests fix them.
type runEnv struct {
	now       func() time.Time
	buildInfo func() (*debug.BuildInfo, bool)
}

// Run is the interop kit: cmd/atx-verify calls it when Requested(args).
// It parses the kit's options, sends every fixture to the verifier,
// writes a line per fixture and the summary to stdout, writes the reports
// --report names, and returns 0 when every fixture agrees with the answer
// key, 1 when any does not, and 2 for a usage error or a run that could not
// start.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, runEnv{now: time.Now, buildInfo: debug.ReadBuildInfo})
}

// options are the parsed kit options.
type options struct {
	verifier, verifierURL, label, form, report string
	timeout                                    time.Duration
	set                                        map[string]bool
}

func run(args []string, stdout, stderr io.Writer, env runEnv) int {
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "-h" || a == "--help" || a == "-help" {
			fmt.Fprint(stdout, usage)
			return 0
		}
	}
	opts, err := parseOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s (%s)\n", escapeControls(err.Error()), usageHint)
		return 2
	}
	if opts.form == "jws" || opts.form == "vc" {
		fmt.Fprintf(stderr, "--form %s is reserved for a later release; this release reads the native form only, so run again without --form.\n", opts.form)
		return 2
	}

	s, err := loadSuite()
	if err != nil {
		fmt.Fprintf(stderr, "error: the fixture set built into this binary could not be read: %s\n", escapeControls(err.Error()))
		return 2
	}

	var adapter Adapter
	adapterName, limit := "command", ""
	if opts.set["verifier"] {
		argv, _ := splitCommand(opts.verifier) // parseOptions checked it
		if !usesFile(argv) {
			limit = credentialOnlyLimit
		}
		if _, err := exec.LookPath(argv[0]); err != nil {
			fmt.Fprintf(stderr, "error: the --verifier command could not be started: %s\n", escapeControls(err.Error()))
			return 2
		}
		if usesFile(argv) {
			dir, err := os.MkdirTemp("", "atx-interop-")
			if err != nil {
				fmt.Fprintf(stderr, "error: could not make a directory for the fixture files: %s\n", escapeControls(err.Error()))
				return 2
			}
			defer os.RemoveAll(dir)
			if err := s.writeFixtures(dir); err != nil {
				fmt.Fprintf(stderr, "error: could not write the fixture files: %s\n", escapeControls(err.Error()))
				return 2
			}
		}
		adapter = NewCommandAdapter(opts.verifier, opts.timeout)
	} else {
		adapterName, limit = "url", urlLimit
		adapter = NewURLAdapter(opts.verifierURL, opts.timeout)
	}
	if opts.report != "" {
		if err := os.MkdirAll(opts.report, 0o755); err != nil {
			fmt.Fprintf(stderr, "error: --report: %s\n", escapeControls(err.Error()))
			return 2
		}
	}

	kitVersion, suiteCommit := provenance(env.buildInfo())
	rep := &Report{
		Kit:            kitName,
		KitVersion:     kitVersion,
		SuiteCommit:    suiteCommit,
		ManifestSHA256: s.manifestSHA256,
		ManifestCheck:  fmt.Sprintf("%d of %d fixtures match MANIFEST.sha256", s.manifestMatches, len(s.entries)),
		Label:          opts.label,
		Adapter:        adapterName,
		Form:           opts.form,
		TimeoutSeconds: opts.timeout.Seconds(),
		StartedAt:      env.now().UTC().Format(time.RFC3339),
		FixtureCount:   len(s.entries),
		Limits:         compareLimit,
	}

	fmt.Fprintf(stdout, "Sending %d ATX conformance fixtures to %s, one at a time (%s adapter, %s form, up to %s each)\n",
		len(s.entries), escapeControls(opts.label), adapterName, opts.form, opts.timeout)
	fmt.Fprintln(stdout, compareLimit)
	if limit != "" {
		fmt.Fprintln(stdout, limit)
	}
	fmt.Fprintln(stdout)
	width := 0
	for _, w := range outcomeWords {
		if len(w) > width {
			width = len(w)
		}
	}
	indent := strings.Repeat(" ", width+2)
	for _, e := range s.entries {
		res := adapter.Verify(context.Background(), e.fixture)
		row := Row{
			Fixture:     e.fixture.Name,
			Requirement: e.requirement,
			Level:       e.level,
			Expected:    e.expected,
			Verdict:     string(res.Verdict),
			Outcome:     outcomeOf(e.mustAccept, res.Verdict),
			Reason:      res.Reason,
			Raw:         res.Raw,
		}
		rep.Fixtures = append(rep.Fixtures, row)
		rep.Summary.add(row.Outcome)
		fmt.Fprintf(stdout, "%-*s  %s\n", width, outcomeWords[row.Outcome], escapeControls(row.Fixture))
		if row.Outcome != outcomeAgree {
			detail := fmt.Sprintf("expected %s, answered %s", row.Expected, verdictWord(res.Verdict))
			if why := reasonKey(row); why != noReason {
				detail += ": " + why
			}
			fmt.Fprintf(stdout, "%s%s\n", indent, escapeControls(detail))
		}
	}
	rep.FinishedAt = env.now().UTC().Format(time.RFC3339)
	rep.TopReasons = topReasons(rep.Fixtures)
	rep.InteropNote = interopNote(opts.label, rep.FixtureCount, rep.Summary, rep.TopReasons)
	writeText(stdout, rep)

	if opts.report != "" {
		paths, err := writeReports(opts.report, rep)
		if err != nil {
			fmt.Fprintf(stderr, "error: the report could not be written: %s\n", escapeControls(err.Error()))
			return 2
		}
		fmt.Fprintf(stdout, "\nReport written to %s and %s\n", escapeControls(paths[0]), escapeControls(paths[1]))
	}
	fmt.Fprintln(stdout, shareLine)
	if rep.Summary.Agree != rep.FixtureCount {
		return 1
	}
	return 0
}

// parseOptions reads the kit's options and checks them.
func parseOptions(args []string) (*options, error) {
	opts := &options{timeout: defaultTimeout, set: map[string]bool{}}
	fs := flag.NewFlagSet("atx-verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.verifier, "verifier", "", "")
	fs.StringVar(&opts.verifierURL, "verifier-url", "", "")
	fs.StringVar(&opts.label, "label", defaultLabel, "")
	fs.StringVar(&opts.form, "form", "native", "")
	fs.StringVar(&opts.report, "report", "", "")
	fs.Var(timeoutValue{&opts.timeout}, "timeout", "")
	if err := fs.Parse(args); err != nil {
		return nil, errors.New(flagError(err.Error()))
	}
	fs.Visit(func(f *flag.Flag) { opts.set[f.Name] = true })
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q: with --verifier or --verifier-url the kit sends every fixture built into this module version and reads no fixture path", fs.Arg(0))
	}
	switch {
	case opts.set["verifier"] && opts.set["verifier-url"]:
		return nil, errors.New("--verifier and --verifier-url cannot be used together: give one")
	case !opts.set["verifier"] && !opts.set["verifier-url"]:
		return nil, errors.New(`give your verifier with --verifier "<command>" or --verifier-url <url>`)
	case opts.set["verifier"]:
		if _, err := splitCommand(opts.verifier); err != nil {
			return nil, fmt.Errorf("--verifier: %v", err)
		}
	default:
		if err := CheckURL(opts.verifierURL); err != nil {
			return nil, fmt.Errorf("--verifier-url: %w", err)
		}
	}
	if strings.TrimSpace(opts.label) == "" {
		return nil, errors.New("--label is empty: give your verifier's name and version")
	}
	switch opts.form {
	case "native", "jws", "vc":
	default:
		return nil, fmt.Errorf("--form %q is not a form: this release reads native (jws and vc are reserved for a later release)", opts.form)
	}
	if opts.set["report"] && opts.report == "" {
		return nil, errors.New("--report is empty: give a directory")
	}
	return opts, nil
}

// flagError rewrites an error of the flag package in the spelling the help
// uses: --name, never -name.
func flagError(msg string) string {
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		return "unknown option: --" + strings.TrimPrefix(name, "-")
	}
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: -"); ok {
		return "--" + strings.TrimPrefix(name, "-") + " needs a value"
	}
	if rest, ok := strings.CutPrefix(msg, "invalid value "); ok {
		if i := strings.Index(rest, " for flag -"); i >= 0 {
			name, why, _ := strings.Cut(rest[i+len(" for flag -"):], ": ")
			return "--" + name + ": " + why
		}
	}
	return msg
}

// timeoutValue is --timeout: a Go duration such as 30s or 2m, or a plain
// number of seconds, more than 0 and at most maxTimeout.
type timeoutValue struct{ d *time.Duration }

func (t timeoutValue) String() string {
	if t.d == nil {
		return ""
	}
	return t.d.String()
}

func (t timeoutValue) Set(s string) error {
	var d time.Duration
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		if n <= 0 || n > maxTimeout.Seconds() {
			return fmt.Errorf("%s is not more than 0 and at most %s", s, maxTimeout)
		}
		d = time.Duration(n * float64(time.Second))
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return fmt.Errorf("%s is not a duration such as 30s or 2m", s)
		}
	}
	if d <= 0 || d > maxTimeout {
		return fmt.Errorf("%s is not more than 0 and at most %s", s, maxTimeout)
	}
	*t.d = d
	return nil
}
