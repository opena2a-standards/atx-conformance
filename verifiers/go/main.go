// Command go runs the Go reference verifier (package
// github.com/opena2a-standards/atx-conformance/verifiers/go/verifier) from a
// checkout:
//
//	cd verifiers/go && go run . ../../fixtures
//
// The entry point published for running it with nothing cloned is
// cmd/atx-verify. This directory held a module of its own before go.mod moved
// to the repository root, and the Go module proxy still answers
// `go run <module>/verifiers/go@latest` with that module, whose go.mod
// declares another path, so that command exits 1.
package main

import (
	"os"

	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

func main() {
	os.Exit(verifier.Run(os.Args[1:], os.Stdout, os.Stderr))
}
