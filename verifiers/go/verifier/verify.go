// Package verifier is the Go reference verifier for the ATX v1.0 and v1.1
// conformance fixture set. Two main packages pass their arguments to Run:
// cmd/atx-verify, the published entry point, and verifiers/go, which runs it
// from a checkout. It depends only on the Go standard library plus
// github.com/cloudflare/circl (for ML-DSA-65 verification per FIPS 204) and
// github.com/gowebpki/jcs (for RFC 8785 canonicalization of the v1.1 signed
// payload), and imports the root package of its own module, which embeds
// the fixture set it verifies when run with no argument.
//
// It does NOT import any opena2a-* SDK or registry package. The goal is to
// validate that the conformance fixtures are byte-stable and that an
// independent verifier with only the spec and the public keypair vectors can
// reproduce ACCEPT / REJECT.
//
// Spec it implements:
//   - ATX §1.1 schema, atcVersion "1.0" and "1.1" (https://github.com/opena2a-standards/atx-spec/blob/e89bed94ca0a7308e2d6915e384be4c89d3a67df/core.md)
//   - AIP §3 Hybrid Ed25519 + ML-DSA-65 (mandate at v1)
//   - Canonicalization: v1.0 signs the pipe-delimited 11-field string matching
//     opena2a-registry/pkg/atcverify/verify.go canonicalPayload() VERBATIM;
//     v1.1 signs JCS(TBS), the RFC 8785 form of the to-be-signed projection
//     (core.md §1.3a.2). See docs/scope.md
//     §"Canonicalization: v1.0 signs 11 fields; v1.1 signs JCS(TBS)".
//   - Integers in the v1.1 signed payload: once the payload canonicalizes,
//     one whose magnitude is above 2^53-1, outside the I-JSON exact range
//     (RFC 7493 §2.2), is a signature failure, because JCS reads each number
//     as an IEEE 754 double, which does not hold every integer outside that
//     range: it writes 9007199254740993 as 9007199254740992
//     (integerOutsideExactRangeV11).
//   - Numbers in the v1.1 declaredPurpose: after that check, a number
//     declaredPurpose writes with a fraction or an exponent part leaves the
//     payload with no bytes a signature is verified over, so each declared
//     signature fails, as in the Python reference verifier. JCS writes such a
//     number as the double nearest it, 1e3 as 1000, and core.md §1.3a.2
//     rule 3 keeps that number serialization out of cross-language scope
//     (hasNumberWithFractionOrExponentV11).
//   - Signature threshold (core.md §3.1 step 8, cosignatures from 2 of 3 key
//     holders): when the verifier state sets requiredSignatures, the declared
//     Ed25519 signatures must verify under at least that many distinct keys.
//
// Not performed: the distinct signer-authority count for trust level 3+
// (core.md §1.3 step 7). The asserted trustLevel is reported, never checked;
// see conformance.json notCovered.
//
// Usage, with nothing cloned (the module version go run fetches embeds
// fixtures/*.json, which a run with no argument walks):
//
//	go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest
//	go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest <fixture.json|dir>...
//
// Usage from a checkout, in verifiers/go:
//
//	go run .                             (no argument; walks the embedded fixtures/*.json)
//	go run . ../../fixtures/baseline-valid.json
//	go run . ../../fixtures/*.json
//	go run . ../../fixtures              (directory; walks *.json)
//	go run . ../..                       (repo root; walks fixtures/*.json)
//	go run . --help                      (prints the usage lines and exits 0)
//	go run . --version                   (prints the module version and exits 0)
//
// Exit 0 iff every fixture's observed result matches expected.verifyResult.
// A file that is not a fixture, one with no expected.verifyResult of ACCEPT
// or REJECT or one that writes a member more than once outside its atx
// member, fails to load and counts as a fail, so the run exits 1.
package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"

	atxconformance "github.com/opena2a-standards/atx-conformance"
)

// ---------------------------------------------------------------------------
// fixture shape (mirror of generator)
// ---------------------------------------------------------------------------

type fixture struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	KeypairRefs   []keypairRef    `json:"keypairRefs"`
	VerifierState verifierState   `json:"verifierState"`
	Expected      expectedOutcome `json:"expected"`
	ATX           json.RawMessage `json:"atx"`
	// Schema is held raw, so a $schema of any type loads as it did before
	// the field existed; the reason for a fixture with no atx member quotes
	// it when it is a string (noATXReason).
	Schema json.RawMessage `json:"$schema"`
}

type keypairRef struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

type verifierState struct {
	ClockRFC3339   string       `json:"clockRfc3339"`
	TrustedIssuers []string     `json:"trustedIssuers"`
	PublicKeys     []keypairRef `json:"publicKeys"`
	// RequiredSignatures is the k of a k-of-n signature threshold: the number
	// of distinct Ed25519 keys whose signatures must verify (verifySignatures).
	// Nil, the member absent or null, sets no threshold.
	RequiredSignatures *int `json:"requiredSignatures,omitempty"`
	CRL                *crl `json:"crl,omitempty"`
}

type crl struct {
	Version    int        `json:"version"`
	IssuedAt   timestamp  `json:"issuedAt"`
	NextUpdate timestamp  `json:"nextUpdate"`
	Entries    []crlEntry `json:"entries"`
	Signature  string     `json:"signature"`
}

type crlEntry struct {
	AgentID   string    `json:"agentId"`
	RevokedAt timestamp `json:"revokedAt"`
	Reason    string    `json:"reason"`
}

// timestamp is a time.Time decoded by time.Time's own UnmarshalJSON, which
// parses the bytes between the quotes, so a timestamp written with a JSON
// escape fails to decode. encoding/json decodes a plain time.Time field that
// way up to Go 1.26; built with Go 1.27, it unescapes the string first and
// decodes the escaped form too. Every timestamp this verifier decodes from a
// fixture is one of these, so the Go release does not change which ones
// decode (the Python verifier follows the same rule). It also refuses a time
// zone offset hour above 24 or minute above 60 (checkOffset), and names the
// offset rather than the day, the text after the offset or the offset's
// sign or minute when the timestamp is refused for one of those too
// (offsetFirst).
type timestamp struct{ time.Time }

func (t *timestamp) UnmarshalJSON(b []byte) error {
	if err := t.Time.UnmarshalJSON(b); err != nil {
		return offsetFirst(err)
	}
	if s := string(b); s != "null" {
		return checkOffset(s[1 : len(s)-1])
	}
	return nil
}

// parseRFC3339 is time.Parse(time.RFC3339, s) with checkOffset and
// offsetFirst applied.
func parseRFC3339(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, offsetFirst(err)
	}
	return t, checkOffset(s)
}

// offsetFirst returns the error Go 1.23 and later return for a timestamp in
// place of err, the error time.Time's decoder or time.Parse(time.RFC3339)
// returned for it, when err names something other than the time zone offset
// and offsetField refuses the offset. Go 1.23 and later check the offset's
// range as soon as they have read its hour and minute: before the day, before
// any text after the offset, and before they refuse its sign or a minute that
// is not two digits, so they return the offset's error themselves. Go 1.22
// does not check the range, and returns the day's error for
// 2026-02-30T00:00:00+25:00, the extra text's for 2099-12-31T23:59:59+25:00x
// and one that cannot parse the offset for 2026-02-30T00:00:00+25:0a. The
// time package reports a day out of range only once the whole timestamp has
// matched the layout, and extra text only after a Z or an offset it has read
// whole, so the offset ends the timestamp, or the part of it before the extra
// text (the error's ValueElem); an error that cannot parse the offset holds
// the timestamp from the offset on as its ValueElem.
func offsetFirst(err error) error {
	var pe *time.ParseError
	if !errors.As(err, &pe) {
		return err
	}
	field := ""
	switch {
	case pe.Message == ": day out of range":
		field = endingOffsetField(pe.Value)
	case strings.HasPrefix(pe.Message, ": extra text: ") && strings.HasSuffix(pe.Value, pe.ValueElem):
		field = endingOffsetField(strings.TrimSuffix(pe.Value, pe.ValueElem))
	case pe.Message == "" && pe.LayoutElem == "Z07:00":
		field = offsetField(pe.ValueElem)
	}
	if offsetErr := offsetRangeError(pe.Value, field); offsetErr != nil {
		return offsetErr
	}
	return err
}

// checkOffset refuses a timestamp that time.Parse(time.RFC3339, s) has
// decoded when its time zone offset has an hour above 24 or a minute above
// 60, with the error Go 1.23 and later return for it. Go 1.22 decodes such an
// offset (+25:00, +23:61) and Go 1.23 and later refuse it, so without this
// check the verdict on it depended on the Go release the verifier was built
// with. An offset of +24:00 or +23:60 decodes under every release.
func checkOffset(s string) error {
	return offsetRangeError(s, endingOffsetField(s))
}

// endingOffsetField is offsetField for the offset s ends in, or "" when s
// ends in Z.
func endingOffsetField(s string) string {
	if len(s) < len("+00:00") || s[len(s)-1] == 'Z' {
		return ""
	}
	return offsetField(s[len(s)-len("+00:00"):])
}

// offsetField returns "hour" or "minute", the field Go 1.23 and later name
// when they refuse the time zone offset v starts with, or "". They read the
// offset as six bytes, a sign, two digits of hour, a colon and two digits of
// minute; refuse it for its hour when that is above 24 and for its minute
// when that is above 60, the minute's error winning; read no minute when the
// hour is not two digits; and refuse it for its range whatever its sign is.
func offsetField(v string) string {
	if len(v) < len("+00:00") || v[3] != ':' {
		return ""
	}
	twoDigits := func(s string) (int, bool) {
		if s[0] < '0' || '9' < s[0] || s[1] < '0' || '9' < s[1] {
			return 0, false
		}
		return int(s[0]-'0')*10 + int(s[1]-'0'), true
	}
	hr, ok := twoDigits(v[1:3])
	mm := 0
	if ok {
		mm, _ = twoDigits(v[4:6])
	}
	field := ""
	if hr > 24 {
		field = "hour"
	}
	if mm > 60 {
		field = "minute"
	}
	return field
}

// offsetRangeError is the error Go 1.23 and later return for timestamp s
// when they refuse its time zone offset for field, or nil when field is "".
func offsetRangeError(s, field string) error {
	if field == "" {
		return nil
	}
	return &time.ParseError{Layout: time.RFC3339, Value: s, Message: ": time zone offset " + field + " out of range"}
}

type expectedOutcome struct {
	VerifyResult   string `json:"verifyResult"`
	RejectCategory string `json:"rejectCategory,omitempty"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

type signature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// atx is the credential as parsed by this verifier. Only the fields the
// canonicalization or verification touches are typed; the rest are tolerated
// via json.RawMessage on the fixture level.
type atx struct {
	ID                   string          `json:"id"`
	ATCVersion           string          `json:"atcVersion"`
	AgentID              string          `json:"agentId"`
	AgentDID             string          `json:"agentDid"`
	Publisher            string          `json:"publisher"`
	PublisherDID         string          `json:"publisherDid,omitempty"`
	Version              string          `json:"version"`
	ContentHash          string          `json:"contentHash"`
	BuildAttestation     string          `json:"buildAttestation,omitempty"`
	TransparencyLogIndex int64           `json:"transparencyLogIndex"`
	Capabilities         []string        `json:"capabilities"`
	DeclaredPurpose      json.RawMessage `json:"declaredPurpose,omitempty"`
	BehavioralProfile    json.RawMessage `json:"behavioralProfile,omitempty"`
	ScanSummary          json.RawMessage `json:"scanSummary"`
	TrustScore           float64         `json:"trustScore"`
	TrustLevel           int             `json:"trustLevel"`
	IssuedAt             timestamp       `json:"issuedAt"`
	ExpiresAt            timestamp       `json:"expiresAt"`
	IssuerDID            string          `json:"issuerDid"`
	IssuerChain          []string        `json:"issuerChain"`
	Signatures           []signature     `json:"signatures"`
	Revoked              bool            `json:"revoked"`
}

// canonicalPayload mirrors opena2a-registry/pkg/atcverify canonicalPayload()
// VERBATIM. It is duplicated here so the conformance verifier has zero
// dependency on the production codebase.
//
// The v1.0 signature covers exactly 11 fields. capabilities, scanSummary,
// publisher, publisherDid, transparencyLogIndex, behavioralProfile,
// revoked-related fields, and createdAt are NOT signed. See docs/scope.md
// §"Canonicalization: v1.0 signs 11 fields; v1.1 signs JCS(TBS)".
func canonicalPayload(a *atx) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%.6f|%s|%s|%s",
		a.AgentID,
		a.AgentDID,
		a.Version,
		a.ContentHash,
		a.BuildAttestation,
		a.IssuerDID,
		a.TrustLevel,
		a.TrustScore,
		a.IssuedAt.UTC().Format(time.RFC3339),
		a.ExpiresAt.UTC().Format(time.RFC3339),
		"1.0",
	))
}

// tbsScanSummaryV11, tbsBehavioralProfileV11, and tbsV11 are the v1.1
// to-be-signed projection per atx-spec core.md §1.3a.2. This is the same
// projection as opena2a-registry/pkg/atcverify and is duplicated here so the
// conformance verifier keeps zero dependency on the production codebase. The
// byte agreement is guaranteed by jcs-vectors/, not by shared code.
type tbsScanSummaryV11 struct {
	HMA              string `json:"hma"`
	CriticalFindings int    `json:"criticalFindings"`
	HighFindings     int    `json:"highFindings"`
	Secretless       string `json:"secretless"`
	CryptoServe      string `json:"cryptoServe"`
	OASBLevel        string `json:"oasbLevel"`
}

type tbsBehavioralProfileV11 struct {
	Checksum        string `json:"checksum"`
	GeneratedAt     string `json:"generatedAt"`
	ObservationDays int    `json:"observationDays"`
}

type tbsV11 struct {
	ATCVersion        string            `json:"atcVersion"`
	AgentID           string            `json:"agentId"`
	AgentDID          string            `json:"agentDid"`
	Publisher         string            `json:"publisher"`
	PublisherDID      string            `json:"publisherDid"`
	Version           string            `json:"version"`
	ContentHash       string            `json:"contentHash"`
	BuildAttestation  string            `json:"buildAttestation"`
	Capabilities      []string          `json:"capabilities"`
	DeclaredPurpose   json.RawMessage   `json:"declaredPurpose,omitempty"`
	BehavioralProfile json.RawMessage   `json:"behavioralProfile"`
	ScanSummary       tbsScanSummaryV11 `json:"scanSummary"`
	TrustScore        string            `json:"trustScore"`
	TrustLevel        int               `json:"trustLevel"`
	IssuedAt          string            `json:"issuedAt"`
	ExpiresAt         string            `json:"expiresAt"`
	IssuerDID         string            `json:"issuerDid"`
	IssuerChain       []string          `json:"issuerChain"`
}

// canonicalPayloadV11 projects the credential into the v1.1 TBS and returns its
// JCS (RFC 8785) canonicalization. Unlike canonicalPayload, this covers
// capabilities, scanSummary, issuerChain, publisher, and behavioralProfile. A
// behavioralProfile the TBS has no value for returns errBehavioralProfileForm
// (projectBehavioralProfileV11).
func canonicalPayloadV11(a *atx) ([]byte, error) {
	caps := a.Capabilities
	if caps == nil {
		caps = []string{}
	}
	chain := a.IssuerChain
	if chain == nil {
		chain = []string{}
	}
	purpose := projectDeclaredPurposeV11(a.DeclaredPurpose)
	if escape := unpairedSurrogateEscape(purpose); escape != "" {
		return nil, fmt.Errorf("declaredPurpose holds an unpaired UTF-16 surrogate escape (%s)", escape)
	}
	if hasNumberOutsideFloat64RangeV11(a) {
		return nil, errors.New("declaredPurpose holds a number outside the float64 range")
	}
	profile, err := projectBehavioralProfileV11(a.BehavioralProfile)
	if err != nil {
		return nil, err
	}
	tbs := tbsV11{
		ATCVersion:        a.ATCVersion,
		AgentID:           a.AgentID,
		AgentDID:          a.AgentDID,
		Publisher:         a.Publisher,
		PublisherDID:      a.PublisherDID,
		Version:           a.Version,
		ContentHash:       a.ContentHash,
		BuildAttestation:  a.BuildAttestation,
		Capabilities:      caps,
		DeclaredPurpose:   purpose,
		BehavioralProfile: profile,
		ScanSummary:       projectScanSummaryV11(a.ScanSummary),
		TrustScore:        fmt.Sprintf("%.6f", a.TrustScore),
		TrustLevel:        a.TrustLevel,
		IssuedAt:          a.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:         a.ExpiresAt.UTC().Format(time.RFC3339),
		IssuerDID:         a.IssuerDID,
		IssuerChain:       chain,
	}
	raw, err := json.Marshal(&tbs)
	if err != nil {
		return nil, fmt.Errorf("marshal v1.1 TBS: %w", err)
	}
	return jcs.Transform(raw)
}

// unpairedSurrogateEscape returns the first \u escape in the JSON text raw
// that writes one half of a UTF-16 surrogate pair without the other: a high
// surrogate (D800 to DBFF) that the next six bytes do not complete with the
// escape of a low one (DC00 to DFFF), or a low surrogate that does not
// complete a high one. It returns "" when raw has none. raw is JSON that
// encoding/json has decoded, so every backslash in it starts an escape
// inside a string.
//
// RFC 8785 §3.2.2.2 requires a canonicalizer to refuse a string holding a
// lone surrogate. The JCS library refuses a surrogate escape that the next
// six bytes do not follow with another \u escape, and reads one followed by
// a \u escape that does not complete the pair as a single U+FFFD, the second
// escape included. declaredPurpose enters the v1.1 TBS as written, so the
// verifier refuses every unpaired surrogate escape in it before the library
// reads it: a declaredPurpose signed holding U+FFFD would otherwise verify
// with such a pair of escapes written in its place, which another JSON
// decoder reads as two other characters.
func unpairedSurrogateEscape(raw []byte) string {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if raw[i+1] != 'u' || i+6 > len(raw) {
			i++ // the escaped character, a backslash among them
			continue
		}
		unit := escapedCodeUnit(raw[i+2 : i+6])
		if unit < 0xd800 || unit > 0xdfff {
			i += 5
			continue
		}
		if unit < 0xdc00 && i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
			if low := escapedCodeUnit(raw[i+8 : i+12]); 0xdc00 <= low && low <= 0xdfff {
				i += 11
				continue
			}
		}
		return string(raw[i : i+6])
	}
	return ""
}

// escapedCodeUnit is the UTF-16 code unit the four hex digits of a \u escape
// write, or -1 if they are not four hex digits.
func escapedCodeUnit(digits []byte) rune {
	var b [2]byte
	if len(digits) != 4 {
		return -1
	}
	if _, err := hex.Decode(b[:], digits); err != nil {
		return -1
	}
	return rune(b[0])<<8 | rune(b[1])
}

// decodeScanSummaryV11 decodes scanSummary into the six members the v1.1 TBS
// carries (atx-spec §1.3a.2 rule 2). An absent or null scanSummary, or
// member, is the zero value. A member outside its type, or a scanSummary
// that is not an object, returns the decode error, with each member that
// did not decode left at its zero value.
func decodeScanSummaryV11(raw json.RawMessage) (tbsScanSummaryV11, error) {
	var ss tbsScanSummaryV11
	if len(raw) == 0 || string(raw) == "null" {
		return ss, nil
	}
	err := json.Unmarshal(raw, &ss)
	return ss, err
}

// projectScanSummaryV11 is scanSummary as the v1.1 TBS carries it. A member
// that does not decode is left at its zero value; verifySignatures refuses
// such a credential before it reads a signature, so no signature over that
// zero value verifies it.
func projectScanSummaryV11(raw json.RawMessage) tbsScanSummaryV11 {
	ss, _ := decodeScanSummaryV11(raw)
	return ss
}

// projectDeclaredPurposeV11 implements the presence-based rule for the optional
// declaredPurpose member (atx-spec §1.3a.2 rule 5, degenerate inputs pinned per
// issue #11): emptiness is a JSON-parse-level property — missing, null, or any
// serialization of the empty object (including whitespace variants like `{ }`)
// normalizes to nil so omitempty drops it, keeping a no-purpose credential
// byte-identical to one issued before the field existed. ANY other present
// value — including non-object values — passes through verbatim so unsigned
// injected purpose content breaks the signature instead of being silently
// normalized away; JCS re-canonicalizes whatever is included.
func projectDeclaredPurposeV11(raw json.RawMessage) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj) == 0 {
		return nil
	}
	return raw
}

// decodeBehavioralProfileV11 decodes behavioralProfile into the three members
// the v1.1 TBS carries. ok is false when behavioralProfile is absent or null,
// where the TBS carries null, or does not decode (a member outside its type,
// or a value that is not an object).
func decodeBehavioralProfileV11(raw json.RawMessage) (bp tbsBehavioralProfileV11, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return bp, false
	}
	var wire struct {
		Checksum        string    `json:"checksum"`
		GeneratedAt     timestamp `json:"generatedAt"`
		ObservationDays int       `json:"observationDays"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return bp, false
	}
	return tbsBehavioralProfileV11{
		Checksum:        wire.Checksum,
		GeneratedAt:     wire.GeneratedAt.UTC().Format(time.RFC3339),
		ObservationDays: wire.ObservationDays,
	}, true
}

// errBehavioralProfileForm is the error projectBehavioralProfileV11 returns
// for a present behavioralProfile the v1.1 TBS has no value for.
var errBehavioralProfileForm = errors.New("behavioralProfile is not an object of exactly checksum (a string), generatedAt (a timestamp) and observationDays (an integer)")

// projectBehavioralProfileV11 is behavioralProfile as the v1.1 TBS carries
// it: null when the credential has none or carries null (atx-spec §1.3a.2
// rule 1), and otherwise its three members, generatedAt written in UTC to
// the second. A present behavioralProfile must be an object holding exactly
// checksum, a JSON string, generatedAt, a timestamp, and observationDays, a
// JSON integer, under those names as written: the credential schema core.md
// §1.1 points to gives it those three members and no other
// (additionalProperties false). Any other present behavioralProfile returns
// errBehavioralProfileForm: one that is not an object, a member outside the
// three or missing, a name in another case, and a member that is null or
// outside its type. The TBS has no value for such a profile. Projected as
// null, the absent form, it verified under a signature made without a
// profile; a member outside the three, which the projection drops, and a
// name encoding/json folds onto one of the three rode a signature that does
// not cover them. verifySignatures refuses the credential on this error
// before it reads a signature.
func projectBehavioralProfileV11(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage("null"), nil
	}
	// A map compares member names exactly, where a struct would match them
	// under encoding/json's folding. A null member leaves its pointer nil.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, errBehavioralProfileForm
	}
	var (
		checksum        *string
		generatedAt     *timestamp
		observationDays *int
	)
	for name, value := range members {
		var err error
		switch name {
		case "checksum":
			err = json.Unmarshal(value, &checksum)
		case "generatedAt":
			err = json.Unmarshal(value, &generatedAt)
		case "observationDays":
			err = json.Unmarshal(value, &observationDays)
		default:
			return nil, errBehavioralProfileForm
		}
		if err != nil {
			return nil, errBehavioralProfileForm
		}
	}
	if checksum == nil || generatedAt == nil || observationDays == nil {
		return nil, errBehavioralProfileForm
	}
	return json.Marshal(&tbsBehavioralProfileV11{
		Checksum:        *checksum,
		GeneratedAt:     generatedAt.UTC().Format(time.RFC3339),
		ObservationDays: *observationDays,
	})
}

// maxExactInteger is 2^53-1, the largest magnitude of an integer in the
// I-JSON exact range (RFC 7493 §2.2). The JCS library reads each number of
// the v1.1 TBS as an IEEE 754 double (RFC 8785 §3.2.2.3), which holds every
// integer in that range and writes it as its decimal digits. Outside it a
// double does not hold every integer: the library writes 9007199254740993 as
// 9007199254740992, so a signature over those bytes verifies a credential
// carrying either count. core.md §1.3a.2 rule 3 keeps that number
// serialization out of cross-language scope.
const maxExactInteger int64 = 1<<53 - 1

// integerOutsideExactRangeV11 names the first integer the v1.1 TBS of a holds
// whose magnitude is above maxExactInteger: where is its member,
// behavioralProfile.observationDays, declaredPurpose,
// scanSummary.criticalFindings, scanSummary.highFindings or trustLevel, the
// order JCS writes them in, and literal is the integer in decimal digits. In
// declaredPurpose, which enters the TBS as written, it is the first such
// integer the credential writes, a number written with no fraction and no
// exponent. It returns "" for both when the TBS holds none.
func integerOutsideExactRangeV11(a *atx) (where, literal string) {
	exact := func(n int64) bool { return -maxExactInteger <= n && n <= maxExactInteger }
	if bp, ok := decodeBehavioralProfileV11(a.BehavioralProfile); ok && !exact(int64(bp.ObservationDays)) {
		return "behavioralProfile.observationDays", strconv.Itoa(bp.ObservationDays)
	}
	for _, number := range purposeNumbersV11(a) {
		if strings.ContainsAny(string(number), ".eE") {
			continue
		}
		// A JSON integer that ParseInt refuses is outside the int64 range.
		if n, err := strconv.ParseInt(string(number), 10, 64); err != nil || !exact(n) {
			return "declaredPurpose", string(number)
		}
	}
	ss := projectScanSummaryV11(a.ScanSummary)
	if !exact(int64(ss.CriticalFindings)) {
		return "scanSummary.criticalFindings", strconv.Itoa(ss.CriticalFindings)
	}
	if !exact(int64(ss.HighFindings)) {
		return "scanSummary.highFindings", strconv.Itoa(ss.HighFindings)
	}
	if !exact(int64(a.TrustLevel)) {
		return "trustLevel", strconv.Itoa(a.TrustLevel)
	}
	return "", ""
}

// hasNumberWithFractionOrExponentV11 reports whether the declaredPurpose of a
// writes a number with a fraction or an exponent part. The JCS library writes
// such a number as the double nearest it: 1000.0, 1e3 and 1E3 as 1000, and
// 9007199254740993.0 and 9.007199254740993e15 as 9007199254740992, which
// integerOutsideExactRangeV11 does not refuse, since it reads only a number
// written as an integer. core.md §1.3a.2 rule 3 keeps that number
// serialization out of cross-language scope, and the Python reference
// verifier's serializer writes no such number (verifiers/python/rfc8785.py),
// so a TBS that holds one has no bytes the two verifiers share.
func hasNumberWithFractionOrExponentV11(a *atx) bool {
	for _, number := range purposeNumbersV11(a) {
		if strings.ContainsAny(string(number), ".eE") {
			return true
		}
	}
	return false
}

// hasNumberOutsideFloat64RangeV11 reports whether the declaredPurpose of a
// writes a number outside the float64 range (numberOutsideFloat64Range):
// 1e400, -1e400, an integer of 401 digits, or 1 followed by 1000 zeros and
// e-650. declaredPurpose enters the TBS as written, so no typed decode
// refuses such a number first, and the JCS library reads each number with
// strconv.ParseFloat, which refuses 1e400 with an error whose text the Go
// release sets and reads 1 followed by 1000 zeros and e-650 as 1e+149.
// canonicalPayloadV11 refuses the number before the library reads it, with
// the reason the Python reference verifier writes, whose float() decides the
// range on every digit written.
func hasNumberOutsideFloat64RangeV11(a *atx) bool {
	for _, number := range purposeNumbersV11(a) {
		if numberOutsideFloat64Range(string(number)) {
			return true
		}
	}
	return false
}

// float64OverflowDigits is 2^1024 - 2^970 in decimal digits: the largest
// float64 plus half a unit in its last place, the least magnitude IEEE 754
// round-to-nearest-even takes to infinity, since the tie rounds to the even
// significand, 2^1024. It has 309 digits.
var float64OverflowDigits = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1024), new(big.Int).Lsh(big.NewInt(1), 970)).String()

// numberOutsideFloat64Range reports whether the JSON number literal s, as
// json.Unmarshal has read it (an optional minus sign, an integer part, an
// optional fraction and an optional exponent part), has a magnitude of
// 2^1024 - 2^970 or more, which rounds to infinity as a float64
// (float64OverflowDigits): Python's float() returns inf for such a literal.
// It decides on the digits as written, whatever their count and whatever
// the exponent. strconv.ParseFloat keeps at most 800 digits of a literal,
// places the decimal point by the digits it kept and caps the exponent it
// reads, so it reads 1 followed by 1000 zeros and e-650, whose value is
// 10^350, as 1e+149 with no error, and 0. followed by 200000 zeros, 1 and
// e200400, whose value is 10^399, as 0. A literal with no nonzero digit is
// zero. Any other is 0.d1d2d3... × 10^point, with d1 its first nonzero digit
// and point the count of digits before the decimal point from d1 on, plus
// the exponent: it is outside the range when point is above 309, and when
// point is 309 and its digits, those past the last written being zero, are
// those of 2^1024 - 2^970 or above them. An exponent that reaches 400 past
// the length of s decides on its own, since point is within that length of
// zero, so the digits of an exponent of any length are read without
// overflow.
func numberOutsideFloat64Range(s string) bool {
	s = strings.TrimPrefix(s, "-")
	mantissa, exponent := s, ""
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mantissa, exponent = s[:i], s[i+1:]
	}
	point := strings.IndexByte(mantissa, '.')
	if point < 0 {
		point = len(mantissa)
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	significant := strings.TrimLeft(digits, "0")
	if significant == "" {
		return false
	}
	point -= len(digits) - len(significant)
	digits = significant
	if exponent != "" {
		negative := exponent[0] == '-'
		if negative || exponent[0] == '+' {
			exponent = exponent[1:]
		}
		e, limit := 0, len(s)+400
		for i := 0; i < len(exponent) && e < limit; i++ {
			e = e*10 + int(exponent[i]-'0')
		}
		if negative {
			e = -e
		}
		point += e
	}
	switch {
	case point > len(float64OverflowDigits):
		return true
	case point < len(float64OverflowDigits):
		return false
	}
	for i := 0; i < len(float64OverflowDigits); i++ {
		d := byte('0')
		if i < len(digits) {
			d = digits[i]
		}
		if d != float64OverflowDigits[i] {
			return d > float64OverflowDigits[i]
		}
	}
	return true
}

// purposeNumbersV11 returns each number the declaredPurpose of a writes, as
// written and in the order written, and none when the v1.1 TBS omits
// declaredPurpose. declaredPurpose enters the TBS as written, so no typed
// decode reads these numbers.
func purposeNumbersV11(a *atx) []json.Number {
	purpose := projectDeclaredPurposeV11(a.DeclaredPurpose)
	if purpose == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(purpose))
	dec.UseNumber()
	var numbers []json.Number
	for {
		tok, err := dec.Token()
		if err != nil {
			return numbers // io.EOF: json.Unmarshal of the credential has read this text whole
		}
		if number, ok := tok.(json.Number); ok {
			numbers = append(numbers, number)
		}
	}
}

// ---------------------------------------------------------------------------
// verification result
// ---------------------------------------------------------------------------

type result struct {
	// Step7Performed is false: this verifier does not count distinct signer
	// authorities (core.md section 1.3 step 7); see conformance.json notCovered.
	Step7Performed bool
	// TrustLevel is the credential's asserted level, carried for the report line.
	TrustLevel     int
	Accepted       bool
	RejectCategory string
	Reason         string
	// Per-signature outcomes for diagnostics.
	Ed25519Valid bool
	MLDSA65Valid bool
	SigsExpected int
	SigsValid    int
}

func (r result) String() string {
	if r.Accepted {
		return "ACCEPT"
	}
	return fmt.Sprintf("REJECT[%s: %s]", r.RejectCategory, r.Reason)
}

// maxScanDepth bounds the strict-parse recursion. It matches encoding/json's
// own maxNestingDepth (10000): anything deeper is rejected by json.Unmarshal in
// verify() below, so stopping the scan here loses no coverage while keeping
// recursion bounded. Without this bound a deeply-nested credential drives
// json.Decoder.Token (which enforces no depth limit) into unbounded recursion
// and a fatal, unrecoverable stack overflow. Reference implementation:
// opena2a-registry pkg/atcverify (registry #305 / #307). Tracked by
// atx-conformance#16.
const maxScanDepth = 10000

// rawDuplicateMember scans raw JSON for a member name that collides — under
// encoding/json's field folding (foldKey) — with an earlier member of the same
// object, at any depth, and returns the first one found. The ATX credential is
// strict-parsed as a whole: every field feeds a signed canonical form (v1.1
// JCS(TBS) projection, v1.0 pipe fields), so there is no layer with sanctioned
// RFC 7519 last-wins semantics — a duplicate member anywhere in the credential
// is the RFC 8259 §4 first-wins/last-wins parser-divergence smuggling split and
// MUST reject as PARSE_ERROR before any field is interpreted. Member equality
// is judged under folding because Go's encoding/json resolves struct fields
// case-insensitively last-wins, so a case-variant pair like
// {"trustLevel":9,"TRUSTLEVEL":1} collapses to one field — a case-sensitive
// check would miss that collapse and leave the exact divergence this guard
// closes. A duplicate in the credential is a verdict, PARSE_ERROR; a member
// the fixture file writes more than once outside the credential makes the
// file no fixture, and it fails to load (repeatedFixtureMember). (Same rule in
// verifiers/python; ported from the aap-conformance protected-header lesson,
// scoped to the whole body because ATX signs it all.)
func rawDuplicateMember(raw []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber keeps Token() from converting each number to float64. Without
	// it, a number strconv.ParseFloat refuses as outside the float64 range
	// (1e400, an integer of 401 digits) makes Token() return an error and
	// aborts the scan, although the number is valid JSON that json.Unmarshal
	// accepts in a member the atx struct holds as raw JSON (declaredPurpose)
	// or does not declare: a duplicate member after it was then not reported
	// (atx-conformance#187). strconv.ParseFloat reads 1 followed by 1000
	// zeros and e-650, whose value is 10^350, as 1e+149, so without UseNumber
	// Token() returns no error on that number
	// (TestDecoderWithoutUseNumberOnOutOfRangeNumbers).
	dec.UseNumber()
	name, dup, _ := scanValueForDuplicates(dec, 0)
	return name, dup
}

// repeatedFixtureMember scans the fixture file b for a member it writes more
// than once outside its atx member's subtree, under one name or under two
// names that fold together (foldKey), and returns the first in document
// order, named as written the second time. encoding/json decodes each repeat
// into the one fixture struct field, so a member a later object omits keeps
// the earlier object's value: a later expected object without the earlier
// one's rejectCategory still carried it here, while the Python verifier,
// which read the later object alone, reached the opposite verdict on the
// same file. A repeat inside the credential is the strict parse's
// (rawDuplicateMember), a verdict of PARSE_ERROR, so the atx member's value
// is not scanned. Its name is, and so is each other member, name and value,
// those the fixture struct does not declare included. A file whose
// top-level value is not an object has no member to repeat, and a scan that
// aborts reports none: json.Unmarshal in parseFixture then says why the file
// is not a fixture.
func repeatedFixtureMember(b []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	// As in rawDuplicateMember: a number outside the float64 range is JSON.
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", false
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", false
		}
		key, _ := keyTok.(string)
		fk := foldKey(key)
		if seen[fk] {
			return key, true
		}
		seen[fk] = true
		if fk == "atx" {
			var credential json.RawMessage
			if err := dec.Decode(&credential); err != nil {
				return "", false
			}
			continue
		}
		if name, dup, abort := scanValueForDuplicates(dec, 1); dup || abort {
			return name, dup
		}
	}
	return "", false
}

// scanValueForDuplicates consumes exactly one JSON value from dec and reports
// the first folded-duplicate member found in it. The third return, abort,
// unwinds the ENTIRE scan (not just the current subtree) when the input is
// malformed or exceeds maxScanDepth; the caller stops immediately rather than
// re-reading a token it never consumed (which would spin dec.More() forever).
// An aborted scan reports no duplicate — the json.Unmarshal in verify() is what
// then rejects the malformed / over-deep input. Numbers do not abort the scan:
// rawDuplicateMember sets UseNumber, so Token() returns each one as a
// json.Number without parsing it.
func scanValueForDuplicates(dec *json.Decoder, depth int) (name string, dup, abort bool) {
	if depth > maxScanDepth {
		return "", false, true
	}
	tok, err := dec.Token()
	if err != nil {
		return "", false, true
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return "", false, false // scalar
	}
	switch delim {
	case '{':
		seen := map[string]string{} // foldKey -> first raw key seen
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return "", false, true
			}
			key, _ := keyTok.(string)
			fk := foldKey(key)
			if _, isDup := seen[fk]; isDup {
				return key, true, false
			}
			seen[fk] = key
			if n, d, a := scanValueForDuplicates(dec, depth+1); d || a {
				return n, d, a
			}
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return "", false, true
		}
	case '[':
		for dec.More() {
			if n, d, a := scanValueForDuplicates(dec, depth+1); d || a {
				return n, d, a
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return "", false, true
		}
	}
	return "", false, false
}

// foldKey normalizes a JSON member name the way encoding/json folds names when
// matching them to struct fields: ASCII letters lowercased, plus the two
// non-ASCII letters encoding/json folds onto ASCII (Kelvin sign U+212A -> k,
// long s U+017F -> s); every other rune is kept unchanged. Two names with the
// same fold key are the same field to the unmarshaler, so treating them as a
// duplicate here catches the case-variant collapse.
//
// This is faithful for every collapse that can smuggle: ATX member names are
// ASCII (a non-ASCII member is already schema-invalid and matches no struct
// field), and the only non-ASCII runes whose simple case fold reaches an ASCII
// letter are the two special-cased above (U+0130 lowercases to i but does not
// fold to it, and encoding/json does not match it to an i). Any other
// non-ASCII rune collapses onto no struct field, and RFC 8259 §8.3 compares
// member names code unit by code unit, so two such names are one member only
// when they decode to the same name, which needs no fold. The fold is this
// fixed table, the same in verifiers/python, and reads no Unicode table, so no
// Go release changes it (docs/running-the-verifiers.md). A fallback to
// unicode.ToLower, which reads the tables of the release the verifier is built
// with, made U+1C89 and U+1C8A (a case pair from Unicode 16.0) a duplicate
// under Go 1.27 and not under Go 1.22 through 1.26 (atx-conformance#173). The
// ASCII and two-rune mappings are ported from opena2a-registry pkg/atcverify
// (registry #307). In an object this verifier decodes, a name that holds a
// character outside printable ASCII, folded together with another or not,
// is refused once this check passes (memberNameOutsidePrintableASCII).
func foldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case 'A' <= r && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r == 'K': // Kelvin sign -> k
			b.WriteRune('k')
		case r == 'ſ': // latin small letter long s -> s
			b.WriteRune('s')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// memberNameOutsidePrintableASCII returns the first member name, in document
// order, that holds a character outside printable ASCII (U+0020 to U+007E)
// in an object this verifier decodes into a struct: the credential, each
// object of its signatures array, and its scanSummary and behavioralProfile
// objects. It also returns the first such character in the name. found is
// false when there is none.
//
// The strict parse refuses such a name as PARSE_ERROR, whatever its
// characters, a rule that reads no case table. foldKey joins a name to a
// specified member by a fixed table, and a relying party that binds the
// credential's JSON again may join by another: Java 25's
// String.equalsIgnoreCase compares U+0130 followed by d equal to id, and
// U+0131 followed by ssuedAt equal to issuedAt, two pairs foldKey keeps
// apart. Beside the specified member, such a name is a member the signature
// does not cover, which that relying party can read as the specified one.
// (Same rule in verifiers/python; atx-conformance#284.)
//
// declaredPurpose is not scanned: the verifier decodes none of its members
// into a field, and v1.1 signs it as written, its member names included. Nor
// is a member the atx struct does not declare. A value that is not an object
// holds no member name; json.Unmarshal of the credential says why one this
// verifier decodes is not an object.
func memberNameOutsidePrintableASCII(raw []byte) (name string, char rune, found bool) {
	return objectNameOutsidePrintableASCII(raw, true)
}

// objectNameOutsidePrintableASCII is memberNameOutsidePrintableASCII on the
// JSON object raw. With credential set, raw is the credential, and the
// objects its signatures, scanSummary and behavioralProfile members hold are
// scanned after each member's name. Those members are matched by foldKey, as
// encoding/json matches them to the atx struct's fields; their names are
// printable ASCII by then, so the fold is ASCII's.
func objectNameOutsidePrintableASCII(raw []byte, credential bool) (string, rune, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", 0, false
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "", 0, false
		}
		key, _ := tok.(string)
		for _, r := range key {
			if r < ' ' || r > '~' {
				return key, r, true
			}
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", 0, false
		}
		if !credential {
			continue
		}
		var objects []json.RawMessage
		switch foldKey(key) {
		case "scansummary", "behavioralprofile":
			objects = []json.RawMessage{value}
		case "signatures":
			if json.Unmarshal(value, &objects) != nil {
				objects = nil // not an array
			}
		}
		for _, object := range objects {
			if name, char, found := objectNameOutsidePrintableASCII(object, false); found {
				return name, char, true
			}
		}
	}
	return "", 0, false
}

// noATXReason is the reason a fixture with no atx member rejects: the
// missing member, and the fixture's $schema when it is a string, which
// names the suite a fixture of another suite belongs to. The Python
// verifier writes the same reason.
func noATXReason(schema json.RawMessage) string {
	const reason = "the fixture has no atx member"
	var s string
	if len(schema) == 0 || schema[0] != '"' || json.Unmarshal(schema, &s) != nil {
		return reason
	}
	return fmt.Sprintf("%s (its $schema is %q)", reason, s)
}

// verify runs the ATX v1.0 and v1.1 verification algorithm with hybrid
// signing enforcement per AIP §3. Step 7 (distinct signer-authority count) is
// not performed; see the comment at that step.
func verify(f fixture) result {
	// A fixture with no atx member, such as one of another conformance
	// suite, has no credential to parse. json.Unmarshal of no bytes reports
	// "unexpected end of JSON input", which names no cause.
	if len(f.ATX) == 0 {
		return result{RejectCategory: "PARSE_ERROR", Reason: noATXReason(f.Schema)}
	}

	// Step 0: strict parse. Duplicate members reject before interpretation
	// (see rawDuplicateMember).
	if name, dup := rawDuplicateMember(f.ATX); dup {
		return result{
			RejectCategory: "PARSE_ERROR",
			Reason:         fmt.Sprintf("credential contains duplicate member %q (strict parse: the whole ATX credential is a signed body; RFC 8259 §4 duplicate names are parser-divergent)", name),
		}
	}
	// A member name outside printable ASCII in an object this verifier
	// decodes (see memberNameOutsidePrintableASCII). %+q and %U write the
	// name and the character in ASCII, so no Unicode table of the Go
	// release decides the reason's text.
	if name, char, found := memberNameOutsidePrintableASCII(f.ATX); found {
		return result{
			RejectCategory: "PARSE_ERROR",
			Reason:         fmt.Sprintf("credential member name %+q holds %U, outside printable ASCII (strict parse: a member name in the credential, a signature entry, scanSummary or behavioralProfile must be printable ASCII, U+0020 to U+007E)", name, char),
		}
	}

	var a atx
	if err := json.Unmarshal(f.ATX, &a); err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: err.Error()}
	}

	now, err := parseRFC3339(f.VerifierState.ClockRFC3339)
	if err != nil {
		return result{RejectCategory: "VERIFIER_CONFIG_ERROR", Reason: "bad clockRfc3339: " + err.Error()}
	}
	now = now.UTC()

	// A threshold is verifier configuration, as the clock is: one the fixture
	// format does not allow (schemas/fixture-v1.schema.json: an integer of at
	// least 1) is reported before any step reads the credential.
	if n := f.VerifierState.RequiredSignatures; n != nil && *n < 1 {
		return result{
			RejectCategory: "VERIFIER_CONFIG_ERROR",
			Reason:         fmt.Sprintf("bad requiredSignatures: %d is not a positive integer", *n),
		}
	}

	// Step 1: schema version. Dispatch on atcVersion: "1.0" verifies the legacy
	// pipe form, "1.1" verifies JCS(TBS) (atx-spec §1.3a).
	if a.ATCVersion != "1.0" && a.ATCVersion != "1.1" {
		return result{
			RejectCategory: "UNSUPPORTED_VERSION",
			Reason:         fmt.Sprintf("unsupported atcVersion %q (this verifier supports 1.0 and 1.1)", a.ATCVersion),
		}
	}

	// Step 2: expiry
	if now.After(a.ExpiresAt.Time) {
		return result{
			RejectCategory: "EXPIRED",
			Reason:         fmt.Sprintf("expired at %s, verifier clock is %s", a.ExpiresAt.UTC().Format(time.RFC3339), now.Format(time.RFC3339)),
		}
	}

	// Step 3: revocation (Revoked flag, then CRL).
	if a.Revoked {
		return result{RejectCategory: "REVOKED", Reason: "credential revoked field is true"}
	}
	if f.VerifierState.CRL != nil {
		for _, e := range f.VerifierState.CRL.Entries {
			if e.AgentID == a.AgentID {
				return result{RejectCategory: "REVOKED", Reason: "agent appears on CRL: " + e.Reason}
			}
		}
	}

	// Step 4: issuer DID trust.
	trusted := false
	for _, did := range f.VerifierState.TrustedIssuers {
		if did == a.IssuerDID {
			trusted = true
			break
		}
	}
	if !trusted {
		return result{
			RejectCategory: "UNTRUSTED_ISSUER",
			Reason:         "issuer DID " + a.IssuerDID + " is not in the verifier's trusted set (untrusted issuer)",
		}
	}

	return verifySignatures(&a, f.VerifierState)
}

// verifySignatures runs steps 5 to 8 on a credential that has passed steps 0
// to 4. It is separate from verify so the unit tests can check that a fixture
// rejected at an earlier step still carries signatures that verify.
func verifySignatures(a *atx, state verifierState) result {
	// Step 5: signature verification.
	// Spec mandate: every declared signature MUST verify.
	var payload []byte
	// noBytes is set when the v1.1 TBS has no bytes that both reference
	// verifiers write; no key then verifies a declared signature.
	noBytes := false
	if a.ATCVersion == "1.1" {
		// scanSummary enters the TBS as six typed members (atx-spec §1.3a.2
		// rule 2). A member outside its type, or a scanSummary that is not an
		// object, has no value there, so no signature covers the credential:
		// the projection would leave it at its zero value, and a signature
		// over that zero value would verify a credential carrying another.
		// The reason names no decode error, whose text the Go release sets,
		// so the Python reference verifier writes the same line.
		if _, err := decodeScanSummaryV11(a.ScanSummary); err != nil {
			return result{
				RejectCategory: "SIGNATURE_INVALID",
				Reason:         "no signature covers scanSummary, which holds a member outside its type or is not an object",
			}
		}
		// behavioralProfile enters the TBS as null when the credential has
		// none (atx-spec §1.3a.2 rule 1), and otherwise as an object of
		// exactly three members, each with its type. A present
		// behavioralProfile of any other form has no value there, so no
		// signature covers the credential (projectBehavioralProfileV11).
		// The reason names no decode error, so the Python reference
		// verifier writes the same line.
		if _, err := projectBehavioralProfileV11(a.BehavioralProfile); err != nil {
			return result{
				RejectCategory: "SIGNATURE_INVALID",
				Reason:         "no signature covers behavioralProfile, which is not an object of exactly checksum (a string), generatedAt (a timestamp) and observationDays (an integer)",
			}
		}
		pb, err := canonicalPayloadV11(a)
		if err != nil {
			return result{RejectCategory: "VERIFIER_CONFIG_ERROR", Reason: "v1.1 canonicalization failed: " + err.Error()}
		}
		// Outside the I-JSON exact range, JCS writes an integer of the TBS
		// as the double nearest it, which other integers can share: pb is
		// the same for 9007199254740993 as for 9007199254740992, so a
		// signature over pb does not tell them apart. Each integer of the
		// TBS outside that range is refused here (maxExactInteger). The
		// Python reference verifier refuses it at this point too, with this
		// reason.
		if where, literal := integerOutsideExactRangeV11(a); where != "" {
			return result{
				RejectCategory: "SIGNATURE_INVALID",
				Reason:         fmt.Sprintf("no signature covers %s: the integer %s is outside the I-JSON exact range, -(2^53-1) to 2^53-1", where, literal),
			}
		}
		// A number declaredPurpose writes with a fraction or an exponent
		// part leaves the TBS with no bytes the Python reference verifier
		// writes (hasNumberWithFractionOrExponentV11). pb writes it as the
		// double JCS reads it as, so a signature over pb verified a
		// credential that writes 1e3 where the signer wrote 1000. Each
		// declared signature is checked against no key below instead, and
		// fails with the reason the Python reference verifier writes.
		noBytes = hasNumberWithFractionOrExponentV11(a)
		payload = pb
	} else {
		payload = canonicalPayload(a)
	}
	res := result{SigsExpected: len(a.Signatures)}

	// Index public keys by algorithm for lookup, restricted to keys controlled by
	// the credential's issuer (key↔issuer binding). A key whose keyId's controller
	// DID is not in the authority set is not an eligible signer for this
	// credential, so one trusted authority cannot impersonate another.
	edKeys, pqKeys := indexPublicKeys(state.PublicKeys, authoritySetFor(a, state.TrustedIssuers))
	if noBytes {
		edKeys, pqKeys = nil, nil
	}

	// edSigners holds, by its bytes, each Ed25519 key a declared signature
	// verified under, for the requiredSignatures count below.
	edSigners := map[string]bool{}

	for _, sig := range a.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
		if err != nil {
			return result{
				RejectCategory: "SIGNATURE_INVALID",
				Reason:         fmt.Sprintf("signature %s has invalid base64: %v", sig.KeyID, err),
			}
		}
		switch sig.Algorithm {
		case "Ed25519":
			ok := false
			for _, pk := range edKeys {
				if ed25519.Verify(pk, payload, sigBytes) {
					ok = true
					edSigners[string(pk)] = true
					break
				}
			}
			if !ok {
				return result{
					RejectCategory: "SIGNATURE_INVALID",
					Reason:         fmt.Sprintf("Ed25519 signature %s did not verify against any configured public key", sig.KeyID),
				}
			}
			res.Ed25519Valid = true
			res.SigsValid++
		case "ML-DSA-65":
			ok := false
			for _, pk := range pqKeys {
				if mldsa65.Verify(pk, payload, nil, sigBytes) {
					ok = true
					break
				}
			}
			if !ok {
				return result{
					RejectCategory: "SIGNATURE_INVALID",
					Reason:         fmt.Sprintf("ML-DSA-65 signature %s did not verify against any configured public key", sig.KeyID),
				}
			}
			res.MLDSA65Valid = true
			res.SigsValid++
		default:
			return result{
				RejectCategory: "SIGNATURE_INVALID",
				Reason:         "unsupported signature algorithm " + sig.Algorithm,
			}
		}
	}

	if res.SigsValid == 0 {
		return result{RejectCategory: "SIGNATURE_INVALID", Reason: "no valid signatures"}
	}

	// Ed25519 companion (core.md section 13, Cryptographic agility): a
	// credential that declares an ML-DSA-65 entry MUST also carry a verifying
	// Ed25519 entry, so a post-quantum signature alone never verifies a
	// credential (fixtures/v1_1-hybrid-pq-only.json).
	if res.MLDSA65Valid && !res.Ed25519Valid {
		return result{
			RejectCategory: "SIGNATURE_INVALID",
			Reason:         "ML-DSA-65 signature declared without a verifying Ed25519 signature (an ML-DSA-65 entry requires an Ed25519 companion)",
		}
	}

	// Signature threshold (core.md section 3.1 step 8, cosignatures from 2 of
	// 3 key holders): with requiredSignatures set, the declared Ed25519
	// signatures must have verified under at least that many distinct keys.
	// A key counts once however many signatures verify under it, whatever
	// keyId they carry, the rule section 1.3 step 7 states for its count.
	// Section 1.3a.2 names the Ed25519 signatures the threshold signatures and
	// the ML-DSA-65 one the hybrid signature, so an ML-DSA-65 signature does
	// not count (fixtures/threshold-1of3-cosignature.json).
	if n := state.RequiredSignatures; n != nil && len(edSigners) < *n {
		return result{
			RejectCategory: "SIGNATURE_INVALID",
			Reason:         fmt.Sprintf("signature threshold not met: requiredSignatures is %d, distinct Ed25519 keys that verified a declared signature: %d", *n, len(edSigners)),
		}
	}

	// Step 6: content hash. Content not supplied to this verifier; skipped.

	// Step 7 (distinct signer-authority count for trust level 3+) is NOT
	// performed by this verifier: no fixture carries verified signatures from
	// more than one authority, and core.md section 1.3 step 7 forbids counting
	// the length of issuerChain, which the signer writes. Recorded on the
	// result so an ACCEPT never reads as a step-7 verdict.
	res.Step7Performed = false
	res.TrustLevel = a.TrustLevel

	// Step 8: all checks passed.
	res.Accepted = true
	return res
}

// indexPublicKeys splits the verifier's configured public keys by algorithm,
// decoding from hex, keeping only keys eligible to sign for the credential's
// issuer. A key is eligible iff its keyId's controller DID is in authoritySet,
// or it carries no keyId (an unbound key — legacy single-issuer configurations).
func indexPublicKeys(refs []keypairRef, authoritySet map[string]bool) (eds []ed25519.PublicKey, pqs []*mldsa65.PublicKey) {
	for _, r := range refs {
		if !keyEligible(r.KeyID, authoritySet) {
			continue
		}
		switch r.Algorithm {
		case "Ed25519":
			raw, err := hex.DecodeString(r.PublicKeyHex)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				continue
			}
			eds = append(eds, ed25519.PublicKey(raw))
		case "ML-DSA-65":
			raw, err := hex.DecodeString(r.PublicKeyHex)
			if err != nil {
				continue
			}
			pk := new(mldsa65.PublicKey)
			if err := pk.UnmarshalBinary(raw); err != nil {
				continue
			}
			pqs = append(pqs, pk)
		}
	}
	return
}

// authoritySetFor returns the DIDs whose keys may verify this credential's
// signatures: the issuer always, plus, under v1.1 only, each issuerChain
// authority that is ALSO in the verifier's trustedIssuers. The v1.1
// issuerChain is covered by the signature, but it is signed by the very key
// whose eligibility is in question, so on its own it cannot vouch for that
// key: a chain DID the verifier does not trust contributes no eligible key.
// Without the intersection, a signer whose key is configured under a DID-URL
// keyId could name its own DID in the chain and sign for a trusted issuer
// (fixtures/v1_1-untrusted-chain-authority.json). The v1.0 issuerChain is
// unsigned and therefore forgeable, so it contributes no eligible key at all;
// only the issuer does.
func authoritySetFor(a *atx, trustedIssuers []string) map[string]bool {
	set := map[string]bool{a.IssuerDID: true}
	if a.ATCVersion != "1.1" {
		return set
	}
	trusted := make(map[string]bool, len(trustedIssuers))
	for _, did := range trustedIssuers {
		trusted[did] = true
	}
	for _, did := range a.IssuerChain {
		if trusted[did] {
			set[did] = true
		}
	}
	return set
}

// keyEligible reports whether a key may verify a signature for an issuer in
// authoritySet. A key with no keyId is unbound (legacy) and is always eligible;
// a key with a keyId is eligible only if its controller DID is in the set.
func keyEligible(keyID string, authoritySet map[string]bool) bool {
	if keyID == "" {
		return true
	}
	return authoritySet[controllerDID(keyID)]
}

// controllerDID returns the DID portion of a keyId DID-URL (everything before
// the first '#'). A keyId of "did:opena2a:authority:opena2a.org#key-1" yields
// "did:opena2a:authority:opena2a.org".
func controllerDID(keyID string) string {
	if i := strings.IndexByte(keyID, '#'); i >= 0 {
		return keyID[:i]
	}
	return keyID
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------

// usage is what Run writes to stdout for -h or --help, and to stderr below
// the line that names an unknown option. It names the program atx-verify,
// the published entry point cmd/atx-verify.
const usage = `usage: atx-verify [fixture.json|dir]...
  no argument    verify the fixture set built into this module version (fixtures/*.json)
  -h, --help     print this usage and exit 0
  --version      print the module version this verifier was built from and exit 0
  --             end the options: every argument after it is a fixture file or directory
`

// versionLine is what Run writes for --version: the path and version of the
// module this binary was built from, as runtime/debug.ReadBuildInfo reports
// them, and the Go release that built it. Built by `go run
// <module>/cmd/atx-verify@<version>`, the version is the one go run resolved:
// the highest release tag for @latest, and for @<commit> the commit's release
// tag, or a pseudo-version naming the commit when it has no tag. A build from
// a checkout or a source archive can record (devel) instead;
// docs/running-the-verifiers.md says which builds do.
func versionLine(info *debug.BuildInfo, ok bool) string {
	if !ok || info.Main.Path == "" {
		return "atx-verify: this binary records no module version\n"
	}
	return fmt.Sprintf("atx-verify: %s %s, built with %s\n", info.Main.Path, info.Main.Version, info.GoVersion)
}

// source is one fixture to verify: the name the report writes for it and how
// to read its bytes.
type source struct {
	name string
	read func() ([]byte, error)
}

// fileSource is the fixture at path, named as relPath names it.
func fileSource(path string) source {
	return source{relPath(path), func() ([]byte, error) {
		// path originates from Run's args, which each main package passes from
		// os.Args[1:] (operator-supplied fixture file/dir); this is a
		// standalone CLI verifier with no network/request surface, so no untrusted taint.
		return os.ReadFile(path) //nolint:gosec // G304: operator-supplied CLI arg, not request-derived
	}}
}

// embeddedSources is every fixtures/*.json file the module root embeds, in
// name order, each named fixtures/<name>.
func embeddedSources() ([]source, error) {
	entries, err := fs.ReadDir(atxconformance.Fixtures, "fixtures")
	if err != nil {
		return nil, err
	}
	out := make([]source, 0, len(entries))
	for _, e := range entries {
		name := "fixtures/" + e.Name()
		out = append(out, source{name, func() ([]byte, error) {
			return fs.ReadFile(atxconformance.Fixtures, name)
		}})
	}
	return out, nil
}

// Run verifies the fixtures args name, or with no argument the fixture set
// the module root embeds, writes a record per fixture and the summary line
// to stdout, and returns the exit code. The first "--" among args ends the
// options: each argument after it is a path, one that starts with "-"
// included, and "--" itself names nothing. Options are read first, wherever
// they stand before it: -h or --help writes usage and returns 0; any other
// argument of two or more characters that starts with "-", --version
// aside, is an unknown option, named on stderr above the usage, and
// returns 2; --version writes the version line and returns 0. Then Run
// returns 2 when an argument is empty or args name no fixture or a path
// that does not exist, 1 when a fixture's observed result differs from its
// expected outcome, and 0 otherwise. The Python verifier reads its
// arguments the same way, except that it has no embedded fixture set and
// answers no argument with its usage and exit 2; scripts/parity/parity.py
// runs both on each argument list of its ARGUMENT_CASES.
// TestCaptureIsVerifierOutput holds docs/captures/go-verifier.txt to what
// it writes.
func Run(args []string, stdout, stderr io.Writer) int {
	options, operands := args, []string(nil)
	if i := slices.Index(args, "--"); i >= 0 {
		options, operands = args[:i], args[i+1:]
	}
	for _, a := range options {
		if a == "-h" || a == "--help" {
			fmt.Fprint(stdout, usage)
			return 0
		}
	}
	printVersion := false
	for _, a := range options {
		switch {
		case a == "--version":
			printVersion = true
		case len(a) > 1 && a[0] == '-':
			fmt.Fprintf(stderr, "unknown option: %s\n", a)
			fmt.Fprint(stderr, usage)
			return 2
		}
	}
	if printVersion {
		info, ok := debug.ReadBuildInfo()
		fmt.Fprint(stdout, versionLine(info, ok))
		return 0
	}
	// Each option returned above, so every argument before "--" is a path
	// too. Clip keeps append from writing over the "--" in args.
	paths := append(slices.Clip(options), operands...)
	// An empty argument names no fixture file or directory: it is a usage
	// error, as it is in the Python verifier, and not the path that does not
	// exist os.Stat("") would report.
	if slices.Contains(paths, "") {
		fmt.Fprintln(stderr, "error: an empty argument names no fixture file or directory")
		return 2
	}

	var sources []source
	if len(paths) == 0 {
		var err error
		if sources, err = embeddedSources(); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	} else {
		files, dirs, err := expandFixtureDirs(paths)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		if len(files) == 0 {
			// Every argument was a directory, each listed one level deep.
			fmt.Fprintf(stderr, "no fixture *.json files found in %s (subdirectories are not walked)\n",
				strings.Join(dirs, ", "))
			return 2
		}
		for _, f := range files {
			sources = append(sources, fileSource(f))
		}
	}

	totalPass, totalFail := 0, 0
	for _, s := range sources {
		f, err := s.load()
		if err != nil {
			fmt.Fprintf(stdout, "FAIL  %s  (load error: %v)\n", s.name, err)
			totalFail++
			continue
		}
		got := verify(f)
		ok := matchesExpected(f.Expected, got)

		status := "PASS"
		if !ok {
			status = "FAIL"
			totalFail++
		} else {
			totalPass++
		}
		fmt.Fprintf(stdout, "%s  %s\n", status, s.name)
		fmt.Fprintf(stdout, "       expected: %s", f.Expected.VerifyResult)
		if f.Expected.RejectCategory != "" {
			fmt.Fprintf(stdout, " [%s]", f.Expected.RejectCategory)
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "       observed: %s\n", got)
		if reasonMismatch(f.Expected, got) {
			// The expected and observed lines above agree on the verdict
			// and category; the substring is what failed.
			fmt.Fprintf(stdout, "       reason does not contain %q\n", f.Expected.ReasonContains)
		}
		if got.SigsExpected > 0 {
			fmt.Fprintf(stdout, "       signatures: %d/%d valid (ed25519=%t mldsa65=%t)\n",
				got.SigsValid, got.SigsExpected, got.Ed25519Valid, got.MLDSA65Valid)
		}
		if got.Accepted && got.TrustLevel >= 3 && !got.Step7Performed {
			fmt.Fprintf(stdout, "       trustLevel %d asserted; distinct-authority count (step 7) not performed by this verifier\n", got.TrustLevel)
		}
	}

	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "summary: %d pass, %d fail (%s)\n", totalPass, totalFail, fixtureCount(totalPass+totalFail))
	if totalFail > 0 {
		return 1
	}
	return 0
}

// fixtureCount is n with the noun the summary line counts: "1 fixture",
// "29 fixtures". The Python verifier writes the same.
func fixtureCount(n int) string {
	if n == 1 {
		return "1 fixture"
	}
	return fmt.Sprintf("%d fixtures", n)
}

// reasonMismatch reports whether a REJECT fixture failed on its
// reasonContains alone: the credential rejected, in the expected category
// where one is declared, with a reason that does not contain the substring.
func reasonMismatch(want expectedOutcome, got result) bool {
	if strings.EqualFold(want.VerifyResult, "ACCEPT") || got.Accepted || want.ReasonContains == "" {
		return false
	}
	if want.RejectCategory != "" && got.RejectCategory != want.RejectCategory {
		return false
	}
	return !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(want.ReasonContains))
}

// matchesExpected reports whether an observed result is the outcome a fixture
// pins: the verdict, and for a REJECT fixture the category and the reason
// substring where the fixture declares them.
func matchesExpected(want expectedOutcome, got result) bool {
	wantAccept := strings.EqualFold(want.VerifyResult, "ACCEPT")
	if wantAccept != got.Accepted {
		return false
	}
	if wantAccept {
		return true
	}
	if want.RejectCategory != "" && got.RejectCategory != want.RejectCategory {
		return false
	}
	if want.ReasonContains != "" &&
		!strings.Contains(strings.ToLower(got.Reason), strings.ToLower(want.ReasonContains)) {
		return false
	}
	return true
}

// load reads and decodes the fixture.
func (s source) load() (fixture, error) {
	b, err := s.read()
	if err != nil {
		return fixture{}, err
	}
	return parseFixture(b)
}

// loadFixture reads and decodes the fixture file at path.
func loadFixture(path string) (fixture, error) {
	return fileSource(path).load()
}

// parseFixture decodes a fixture file. A file that writes a member more than
// once outside its atx member's subtree (repeatedFixtureMember) is not a
// fixture and fails to load, before any member is decoded. A file with no
// expected outcome the fixture format allows (schemas/fixture-v1.schema.json)
// is not a fixture either and fails to load: its expected member or
// expected.verifyResult is absent or null, or its verifyResult is a string
// other than ACCEPT or REJECT, "accept" among them. Read as "expect REJECT",
// such a file passed whenever its credential rejected, and {} or a
// package.json rejects at parse. When the check passes,
// f.Expected.VerifyResult holds that verifyResult.
func parseFixture(b []byte) (fixture, error) {
	// A file that is not JSON is left to json.Unmarshal, whose error names
	// why: a scan of it could report a member repeated before the point
	// where it stops being JSON.
	if json.Valid(b) {
		if name, dup := repeatedFixtureMember(b); dup {
			return fixture{}, fmt.Errorf("the fixture repeats the member %q", name)
		}
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		return fixture{}, fixtureShapeError(err)
	}
	var wrapper struct {
		Expected json.RawMessage `json:"expected"`
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return fixture{}, err
	}
	if len(wrapper.Expected) == 0 || string(wrapper.Expected) == "null" {
		return fixture{}, errors.New("no expected member")
	}
	var expected struct {
		VerifyResult *string `json:"verifyResult"`
	}
	if err := json.Unmarshal(wrapper.Expected, &expected); err != nil {
		return fixture{}, err
	}
	switch {
	case expected.VerifyResult == nil:
		return fixture{}, errors.New("no expected.verifyResult")
	case *expected.VerifyResult != "ACCEPT" && *expected.VerifyResult != "REJECT":
		return fixture{}, fmt.Errorf("expected.verifyResult %q is not ACCEPT or REJECT", *expected.VerifyResult)
	}
	return f, nil
}

// The load errors of a file whose top-level value is not a fixture object,
// in the wording the Python verifier writes. json.Unmarshal's own errors
// differ from Python's json module's for each of these, and its type error
// names this package's fixture type.
const (
	errNotJSON       = "fixture is not valid JSON"
	errNotJSONObject = "fixture is not a JSON object"
	errTooDeep       = "arrays and objects nested deeper than 10000 levels (the limit of Go's encoding/json)"
)

// fixtureShapeError is the load error for err, json.Unmarshal's error
// decoding a whole fixture file: errTooDeep for arrays and objects nested
// past the decoder's limit, errNotJSON for any other syntax error,
// errNotJSONObject when the top-level value is an array, string, number or
// boolean, and err itself for an error inside the fixture object, which
// names the member.
func fixtureShapeError(err error) error {
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		if strings.HasSuffix(syntax.Error(), "exceeded max depth") {
			return errors.New(errTooDeep)
		}
		return errors.New(errNotJSON)
	}
	var typ *json.UnmarshalTypeError
	if errors.As(err, &typ) && typ.Field == "" {
		return errors.New(errNotJSONObject)
	}
	return err
}

// missingPathHint is what the line for an argument that names no file adds
// when the argument is a word an option spells: help and version.
var missingPathHint = map[string]string{
	"help":    " (--help prints the usage)",
	"version": " (--version prints the version line)",
}

// expandFixturePaths is expandFixtureDirs without the directories.
func expandFixturePaths(args []string) ([]string, error) {
	out, _, err := expandFixtureDirs(args)
	return out, err
}

// expandFixtureDirs returns the fixture files args name, sorted, and each
// directory it listed for them, in argument order: a directory argument,
// or its fixtures directory.
func expandFixtureDirs(args []string) ([]string, []string, error) {
	var out, dirs []string
	for _, a := range args {
		info, err := os.Stat(a) //nolint:gosec // G703: operator-supplied CLI arg, not request-derived
		if errors.Is(err, fs.ErrNotExist) {
			// The Python verifier's wording, which the parity gate holds
			// this one to.
			return nil, nil, fmt.Errorf("%s: no such file or directory%s", a, missingPathHint[a])
		}
		if err != nil {
			return nil, nil, err
		}
		switch {
		case info.IsDir():
			join := dirJoin(a, info)
			fixDir := a
			// Allow passing the repo root: look in $arg/fixtures when it is a
			// directory. A file named fixtures leaves $arg an ordinary
			// directory, walked for its own *.json.
			if fi, err := os.Stat(join(a, "fixtures")); err == nil && fi.IsDir() { //nolint:gosec // G703: operator-supplied CLI arg
				fixDir = join(a, "fixtures")
			}
			entries, err := os.ReadDir(fixDir)
			if err != nil {
				return nil, nil, err
			}
			dirs = append(dirs, fixDir)
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
					out = append(out, join(fixDir, e.Name()))
				}
			}
		default:
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, dirs, nil
}

// dirJoin returns how expandFixturePaths joins a name onto the directory
// argument a, or onto its fixtures directory, info being os.Stat(a): as
// filepath.Join joins them when a, cleaned as filepath.Clean cleans it,
// names the directory a names, and onto the directory as spelled, with one
// separator between, when it does not. The joined path is both the file
// read and the name the report gives it. Clean removes a ".." with the
// element before it, and the operating system resolves that element before
// it applies the "..", so where the element is a symbolic link the two name
// different directories: with d/link a link to elsewhere/deep, d/link/..
// lists elsewhere, and its other.json, joined as d/other.json, named a file
// of d. The Python verifier joins the names the same way.
func dirJoin(a string, info fs.FileInfo) func(dir, name string) string {
	if c, err := os.Stat(filepath.Clean(a)); err == nil && os.SameFile(info, c) {
		return func(dir, name string) string { return filepath.Join(dir, name) }
	}
	return func(dir, name string) string {
		if os.IsPathSeparator(dir[len(dir)-1]) {
			return dir + name
		}
		return dir + string(filepath.Separator) + name
	}
}

// relPath is the name the report gives the fixture at p: the path relative
// to the working directory when p is an absolute path under it, and p as
// given otherwise. An absolute path outside the working directory is
// written whole, as the Python verifier writes it, and not as a climb of
// ".." elements out of the working directory.
//
// The working directory and the directory holding p are compared with their
// symbolic links resolved, as the Python verifier compares them. os.Getwd
// returns $PWD when it names the working directory, and a shell that
// changed into a directory through a link sets $PWD to the path through the
// link, so compared as written, a path through the link was named relative
// and the same file through the link's target was written whole, the
// reverse of what the Python verifier wrote. Where either cannot be
// resolved they are compared as written.
//
// The directory holding p is resolved as p spells it, each ".." applied
// after the element before it is resolved, as the operating system applies
// it when it reads p. filepath.Dir cleaned it first, removing a ".." with
// a link before it, so $PWD/d/link/../x.json, with d/link a link to
// elsewhere/deep, was named d/x.json while elsewhere/x.json was read.
func relPath(p string) string {
	if !filepath.IsAbs(p) {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	base, target := wd, p
	if w, err := filepath.EvalSymlinks(wd); err == nil {
		dir, file := filepath.Split(p)
		if d, err := filepath.EvalSymlinks(dir); err == nil {
			base, target = w, filepath.Join(d, file)
		}
	}
	if rel, err := filepath.Rel(base, target); err == nil && filepath.IsLocal(rel) {
		return rel
	}
	return p
}
