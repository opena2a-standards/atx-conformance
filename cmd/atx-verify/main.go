// Command atx-verify runs the Go reference verifier (package
// github.com/opena2a-standards/atx-conformance/verifiers/go/verifier) with
// nothing cloned:
//
//	go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest
//	go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest <fixture.json|dir>...
//
// With no argument it walks the fixture set the module root embeds,
// fixtures/*.json of the module version go run fetched.
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
	"os"

	"github.com/opena2a-standards/atx-conformance/interop"
	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

func main() {
	if interop.Requested(os.Args[1:]) {
		os.Exit(interop.Run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(verifier.Run(os.Args[1:], os.Stdout, os.Stderr))
}
