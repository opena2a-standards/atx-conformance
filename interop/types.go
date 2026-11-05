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
// string is recorded.
func Classify(fallback Verdict, body []byte) Result {
	r := Result{Verdict: fallback, Raw: firstChars(string(body), 200)}
	var obj struct {
		Verdict *string `json:"verdict"`
		Valid   *bool   `json:"valid"`
		Reason  *string `json:"reason"`
	}
	if json.Unmarshal(bytes.TrimSpace(body), &obj) != nil {
		return r
	}
	if obj.Reason != nil {
		r.Reason = *obj.Reason
	}
	switch {
	case obj.Verdict != nil:
		switch strings.ToUpper(strings.TrimSpace(*obj.Verdict)) {
		case "ACCEPT":
			r.Verdict = Accept
		case "REJECT":
			r.Verdict = Reject
		case "ERROR":
			r.Verdict = Unreadable
		}
	case obj.Valid != nil:
		if *obj.Valid {
			r.Verdict = Accept
		} else {
			r.Verdict = Reject
		}
	}
	return r
}

func firstChars(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		runes = runes[:n]
	}
	return string(runes)
}
