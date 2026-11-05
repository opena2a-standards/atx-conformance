// SPDX-License-Identifier: Apache-2.0

package atxconformance

import _ "embed" // for the //go:embed directives below

// AnswerKey is conformance.json of this module version: for each fixture,
// the requirement it exercises and its expected outcome. The interop kit
// (package interop, reached through the --verifier and --verifier-url flags
// of cmd/atx-verify) compares an outside verifier's verdicts with it, so a
// run needs nothing cloned. The interop test
// TestEmbeddedAnswerKeyAndManifestAreTheFilesOnDisk holds it equal to the
// file on disk.
//
//go:embed conformance.json
var AnswerKey []byte

// Manifest is MANIFEST.sha256 of this module version: the SHA-256 of each
// fixtures/*.json file. The interop kit reports the SHA-256 of these bytes
// and checks each embedded fixture against its line.
//
//go:embed MANIFEST.sha256
var Manifest []byte
