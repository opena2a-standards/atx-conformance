// Command atx-verify runs the Go reference verifier (package
// github.com/opena2a-standards/atx-conformance/verifiers/go/verifier) with
// nothing cloned:
//
//	go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest
//	go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest <fixture.json|dir>...
//
// With no argument it walks the fixture set the module root embeds,
// fixtures/*.json of the module version go run fetched. When every fixture
// passes and standard error is a terminal, that run then writes nextStep to
// standard error, below the summary line: the step after this one, testing a
// verifier of one's own, and the README section that says how. Standard
// output holds the reference verifier's report alone, and a run whose
// standard error is a pipe or a file writes no such line, so what a program
// reads of a run is what it read before.
//
// This is the published entry point because no directory on its path has
// held a go.mod. verifiers/go held one, declaring another module path,
// before go.mod moved to the repository root; the Go module proxy keeps the
// versions it stored of that module and answers
// `go run <module>/verifiers/go@latest` with one, so that command exits 1.
//
// With --verifier "<command>" or --verifier-url <url> (or any other option
// of the interop kit: --label, --form, --report, --timeout), it runs the
// interop kit, package
// github.com/opena2a-standards/atx-conformance/interop, instead: it sends
// each embedded fixture to an outside verifier and compares the verdicts
// with the answer key in conformance.json. Add --help to one of those
// options for the kit's help. Arguments that carry none of them go to the
// reference verifier as before, so its output is unchanged.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/opena2a-standards/atx-conformance/interop"
	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

// nextStep is the line a run with no argument writes to standard error when
// every fixture passes and standard error is a terminal. It links to the
// README section "Try your verifier in two minutes", which installs the
// interop kit and points it at a verifier of the reader's own.
const nextStep = "Next: to test your own verifier against the fixtures, see " +
	"https://github.com/opena2a-standards/atx-conformance#try-your-verifier-in-two-minutes\n"

func main() {
	if interop.Requested(os.Args[1:]) {
		os.Exit(interop.Run(os.Args[1:], os.Stdout, os.Stderr))
	}
	if len(os.Args) == 1 {
		os.Exit(frontDoor(os.Stdout, os.Stderr, isTerminal(os.Stderr)))
	}
	os.Exit(verifier.Run(os.Args[1:], os.Stdout, os.Stderr))
}

// frontDoor is the run with no argument: Run over the embedded fixture set,
// then nextStep on stderr as writeNextStep decides. It returns Run's exit
// code.
func frontDoor(stdout, stderr io.Writer, terminal bool) int {
	code := verifier.Run(nil, stdout, stderr)
	writeNextStep(stderr, code, terminal)
	return code
}

// writeNextStep writes nextStep to w when code is 0, so that every fixture
// passed, and terminal says w is a terminal. After a failing run the next
// thing to read is the FAIL block above, not a verifier of one's own.
func writeNextStep(w io.Writer, code int, terminal bool) {
	if code == 0 && terminal {
		fmt.Fprint(w, nextStep)
	}
}

// isTerminal reports whether f is a terminal, as the guided tour reads it:
// a character device.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
