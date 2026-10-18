// Package atxconformance is the root package of the Go module this
// repository publishes, github.com/opena2a-standards/atx-conformance. It
// holds the conformance fixture set, fixtures/*.json, as an embedded file
// system, so that the reference verifier at verifiers/go/verifier, run as
//
//	go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest
//
// with no argument, verifies the fixtures of the module version go run
// fetched, with nothing cloned. The verifier's test
// TestEmbeddedFixturesAreTheFixtureDirectory holds the embedded set to
// fixtures/*.json on disk.
package atxconformance

import "embed"

// Fixtures holds each fixtures/*.json file of this module version under the
// path fixtures/<name>.
//
//go:embed fixtures/*.json
var Fixtures embed.FS
