// SPDX-License-Identifier: Apache-2.0

// Package interop runs the conformance fixtures against an outside verifier
// and compares its verdicts with the answer key in conformance.json. It is
// reached through the --verifier and --verifier-url flags of cmd/atx-verify.
// It calls the outside verifier and compares; it does not verify anything
// itself, and it sends nothing anywhere except fixtures to a URL the caller
// passed with --verifier-url.
package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
)

// Verdict is what an outside verifier said about one fixture.
type Verdict string

// The three outcomes of the adapter contract.
const (
	Accept     Verdict = "ACCEPT"
	Reject     Verdict = "REJECT"
	Unreadable Verdict = "COULD_NOT_READ"
)

// Fixture is one conformance fixture handed to an adapter.
type Fixture struct {
	// Name is the fixture's file name, for example baseline-valid.json.
	Name string
	// Path is the fixture file on disk, the value that replaces {file} in a
	// --verifier command.
	Path string
	// Credential is the fixture's credential JSON: the bytes a command
	// adapter writes to stdin when the command has no {file}, and the body
	// a URL adapter POSTs.
	Credential []byte
}

// Result is one adapter answer for one fixture.
type Result struct {
	Verdict Verdict
	// Reason is the optional "reason" string of a JSON answer.
	Reason string
	// Raw is the first 200 characters of the raw response.
	Raw string
}

// Adapter calls an outside verifier once per fixture. An adapter never
// returns an error: a crash, a timeout or no answer is the Unreadable
// verdict, with what happened in Raw.
type Adapter interface {
	Verify(ctx context.Context, f Fixture) Result
}

// Classify applies the adapter contract to one raw response. fallback is the
// verdict the exit code or the HTTP status gave. When body is a JSON object
// carrying "verdict" or "valid", that wins over fallback: "verdict" of
// ACCEPT, REJECT or ERROR, or "valid" of true or false. An optional "reason"
// string is recorded. Each member is read on its own: a member of another
// type counts as absent, and the others still count.
func Classify(fallback Verdict, body []byte) Result {
	r := Result{Verdict: fallback, Raw: firstChars(string(body), 200)}
	var obj struct {
		Verdict json.RawMessage `json:"verdict"`
		Valid   json.RawMessage `json:"valid"`
		Reason  json.RawMessage `json:"reason"`
	}
	if json.Unmarshal(bytes.TrimSpace(body), &obj) != nil {
		return r
	}
	if reason := member[string](obj.Reason); reason != nil {
		r.Reason = *reason
	}
	verdict, valid := member[string](obj.Verdict), member[bool](obj.Valid)
	switch {
	case verdict != nil:
		switch strings.ToUpper(strings.TrimSpace(*verdict)) {
		case "ACCEPT":
			r.Verdict = Accept
		case "REJECT":
			r.Verdict = Reject
		case "ERROR":
			r.Verdict = Unreadable
		}
	case valid != nil:
		if *valid {
			r.Verdict = Accept
		} else {
			r.Verdict = Reject
		}
	}
	return r
}

// member decodes one member of a JSON answer, or returns nil when it is
// absent, null or of another type. The nil on an error is needed: a failed
// decode can leave the pointer allocated and holding the zero value, which
// would read "valid": "true" as false.
func member[T any](raw json.RawMessage) *T {
	var v *T
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}

func firstChars(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		runes = runes[:n]
	}
	return string(runes)
}
