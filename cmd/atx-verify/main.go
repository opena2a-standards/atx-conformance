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
package main

import (
	"os"

	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

func main() {
	os.Exit(verifier.Run(os.Args[1:], os.Stdout, os.Stderr))
}
