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
// or REJECT, fails to load and counts as a fail, so the run exits 1.
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
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

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
	CRL            *crl         `json:"crl,omitempty"`
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
// zone offset hour above 24 or minute above 60 (checkOffset).
type timestamp struct{ time.Time }

func (t *timestamp) UnmarshalJSON(b []byte) error {
	if err := t.Time.UnmarshalJSON(b); err != nil {
		return err
	}
	if s := string(b); s != "null" {
		return checkOffset(s[1 : len(s)-1])
	}
	return nil
}

// parseRFC3339 is time.Parse(time.RFC3339, s) with checkOffset applied.
func parseRFC3339(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, err
	}
	return t, checkOffset(s)
}

// checkOffset refuses a timestamp that time.Parse(time.RFC3339, s) has
// decoded when its time zone offset has an hour above 24 or a minute above
// 60, with the error Go 1.23 and later return for it. Go 1.22 decodes such an
// offset (+25:00, +23:61) and Go 1.23 and later refuse it, so without this
// check the verdict on it depended on the Go release the verifier was built
// with. An offset of +24:00 or +23:60 decodes under every release.
func checkOffset(s string) error {
	if len(s) < len("+00:00") || s[len(s)-1] == 'Z' {
		return nil
	}
	off := s[len(s)-len("+00:00"):]
	hr := int(off[1]-'0')*10 + int(off[2]-'0')
	mm := int(off[4]-'0')*10 + int(off[5]-'0')
	field := ""
	if hr > 24 {
		field = "hour"
	}
	if mm > 60 {
		field = "minute"
	}
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
// capabilities, scanSummary, issuerChain, publisher, and behavioralProfile.
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
		BehavioralProfile: projectBehavioralProfileV11(a.BehavioralProfile),
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

func projectBehavioralProfileV11(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage("null")
	}
	var wire struct {
		Checksum        string    `json:"checksum"`
		GeneratedAt     timestamp `json:"generatedAt"`
		ObservationDays int       `json:"observationDays"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return json.RawMessage("null")
	}
	bp := tbsBehavioralProfileV11{
		Checksum:        wire.Checksum,
		GeneratedAt:     wire.GeneratedAt.UTC().Format(time.RFC3339),
		ObservationDays: wire.ObservationDays,
	}
	out, err := json.Marshal(&bp)
	if err != nil {
		return json.RawMessage("null")
	}
	return out
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
// closes. Strictness applies to the credential object only; the fixture wrapper
// is harness metadata and parses leniently. (Same rule in verifiers/python; ported
// from the aap-conformance protected-header lesson, scoped to the whole body
// because ATX signs it all.)
func rawDuplicateMember(raw []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber keeps Token() from converting each number to float64. Without
	// it, a number outside the float64 range (1e400, an integer of 401 digits)
	// makes Token() return an error and aborts the scan, although the number is
	// valid JSON that json.Unmarshal accepts in a member the atx struct holds as
	// raw JSON (declaredPurpose) or does not declare: a duplicate member after
	// it was then not reported. atx-conformance#187.
	dec.UseNumber()
	name, dup, _ := scanValueForDuplicates(dec, 0)
	return name, dup
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
// long s U+017F -> s); any other rune is lowercased via unicode.ToLower. Two
// names with the same fold key are the same field to the unmarshaler, so
// treating them as a duplicate here catches the case-variant collapse.
//
// This is faithful for every collapse that can smuggle: ATX member names are
// ASCII (a non-ASCII member is already schema-invalid and matches no struct
// field), and the only non-ASCII runes encoding/json folds onto ASCII field
// names are the two special-cased above. The unicode.ToLower fallback governs
// only other non-ASCII runes, which collapse onto no struct field; there it may
// diverge from encoding/json — and from the Python reference, whose str.lower
// can expand a rune Go's simple ToLower does not — but only on inputs no honest
// credential produces. unicode.ToLower uses the Unicode tables of the Go
// release the verifier is built with, so a pair of names whose case mapping a
// later Unicode version added is a duplicate under one release and not under
// another: U+1C89 and U+1C8A (Unicode 16.0) under Go 1.27 (Unicode 17.0) and
// not under Go 1.22 through 1.26 (Unicode 15.0). docs/running-the-verifiers.md
// says the same. Ported from opena2a-registry pkg/atcverify
// (registry #307).
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
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// verify runs the ATX v1.0 and v1.1 verification algorithm with hybrid
// signing enforcement per AIP §3. Step 7 (distinct signer-authority count) is
// not performed; see the comment at that step.
func verify(f fixture) result {
	// Step 0: strict parse. Duplicate members reject before interpretation
	// (see rawDuplicateMember).
	if name, dup := rawDuplicateMember(f.ATX); dup {
		return result{
			RejectCategory: "PARSE_ERROR",
			Reason:         fmt.Sprintf("credential contains duplicate member %q (strict parse: the whole ATX credential is a signed body; RFC 8259 §4 duplicate names are parser-divergent)", name),
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
		pb, err := canonicalPayloadV11(a)
		if err != nil {
			return result{RejectCategory: "VERIFIER_CONFIG_ERROR", Reason: "v1.1 canonicalization failed: " + err.Error()}
		}
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
		files, err := expandFixturePaths(paths)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		if len(files) == 0 {
			fmt.Fprintln(stderr, "no fixture *.json files found")
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
		if got.SigsExpected > 0 {
			fmt.Fprintf(stdout, "       signatures: %d/%d valid (ed25519=%t mldsa65=%t)\n",
				got.SigsValid, got.SigsExpected, got.Ed25519Valid, got.MLDSA65Valid)
		}
		if got.Accepted && got.TrustLevel >= 3 && !got.Step7Performed {
			fmt.Fprintf(stdout, "       trustLevel %d asserted; distinct-authority count (step 7) not performed by this verifier\n", got.TrustLevel)
		}
	}

	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "summary: %d pass, %d fail (%d fixtures)\n", totalPass, totalFail, totalPass+totalFail)
	if totalFail > 0 {
		return 1
	}
	return 0
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

// parseFixture decodes a fixture file. A file with no expected outcome the
// fixture format allows (schemas/fixture-v1.schema.json) is not a fixture and
// fails to load: its expected member or expected.verifyResult is absent or
// null, or its verifyResult is a string other than ACCEPT or REJECT, "accept"
// among them. Read as "expect REJECT", such a file passed whenever its
// credential rejected, and {} or a package.json rejects at parse. The check
// reads the last expected member and the last verifyResult in it, as the
// Python verifier reads them; when it passes, f.Expected.VerifyResult holds
// that verifyResult.
func parseFixture(b []byte) (fixture, error) {
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		return fixture{}, err
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

func expandFixturePaths(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a) //nolint:gosec // G703: operator-supplied CLI arg, not request-derived
		if errors.Is(err, fs.ErrNotExist) {
			// The Python verifier's wording, which the parity gate holds
			// this one to.
			return nil, fmt.Errorf("%s: no such file or directory", a)
		}
		if err != nil {
			return nil, err
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
				return nil, err
			}
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
	return out, nil
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
