// Package main is the Go reference verifier for the ATX v1.0 conformance
// fixture set. It depends only on the Go standard library plus
// github.com/cloudflare/circl (for ML-DSA-65 verification per FIPS 204).
//
// It does NOT import any opena2a-* SDK or registry package. The goal is to
// validate that the conformance fixtures are byte-stable and that an
// independent verifier with only the spec and the public keypair vectors can
// reproduce ACCEPT / REJECT.
//
// Spec it implements:
//   - ATX v1.0 §1.1 schema (https://github.com/opena2a-org/atx-spec/blob/main/core.md)
//   - AIP §3 Hybrid Ed25519 + ML-DSA-65 (mandate at v1)
//   - Canonicalization: pipe-delimited 11-field string matching
//     opena2a-registry/pkg/atcverify/verify.go canonicalPayload() VERBATIM
//
// Usage:
//
//	go run . ../../fixtures/baseline-valid.json
//	go run . ../../fixtures/*.json
//	go run . ../../fixtures              (directory; walks *.json)
//	go run . ../..                       (repo root; walks fixtures/*.json)
//
// Exit 0 iff every fixture's observed result matches expected.verifyResult.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"
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
	IssuedAt   time.Time  `json:"issuedAt"`
	NextUpdate time.Time  `json:"nextUpdate"`
	Entries    []crlEntry `json:"entries"`
	Signature  string     `json:"signature"`
}

type crlEntry struct {
	AgentID   string    `json:"agentId"`
	RevokedAt time.Time `json:"revokedAt"`
	Reason    string    `json:"reason"`
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
	IssuedAt             time.Time       `json:"issuedAt"`
	ExpiresAt            time.Time       `json:"expiresAt"`
	IssuerDID            string          `json:"issuerDid"`
	IssuerChain          []string        `json:"issuerChain"`
	Signatures           []signature     `json:"signatures"`
	Revoked              bool            `json:"revoked"`
}

// canonicalPayload mirrors opena2a-registry/pkg/atcverify/verify.go:314-329
// VERBATIM. It is duplicated here so the conformance verifier has zero
// dependency on the production codebase.
//
// The signature covers exactly 11 fields. capabilities, scanSummary,
// publisher, publisherDid, transparencyLogIndex, behavioralProfile,
// revoked-related fields, and createdAt are NOT signed. See README
// §"Signed vs unsigned fields."
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
		DeclaredPurpose:   projectDeclaredPurposeV11(a.DeclaredPurpose),
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

func projectScanSummaryV11(raw json.RawMessage) tbsScanSummaryV11 {
	var ss tbsScanSummaryV11
	if len(raw) == 0 || string(raw) == "null" {
		return ss
	}
	_ = json.Unmarshal(raw, &ss)
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
		GeneratedAt     time.Time `json:"generatedAt"`
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
// is harness metadata and parses leniently. (Same rule in ../python; ported
// from the aap-conformance protected-header lesson, scoped to the whole body
// because ATX signs it all.)
func rawDuplicateMember(raw []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	name, dup, _ := scanValueForDuplicates(dec, 0)
	return name, dup
}

// scanValueForDuplicates consumes exactly one JSON value from dec and reports
// the first folded-duplicate member found in it. The third return, abort,
// unwinds the ENTIRE scan (not just the current subtree) when the input is
// malformed or exceeds maxScanDepth; the caller stops immediately rather than
// re-reading a token it never consumed (which would spin dec.More() forever).
// An aborted scan reports no duplicate — the json.Unmarshal in verify() is what
// then rejects the malformed / over-deep input.
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
// credential produces. Ported from opena2a-registry pkg/atcverify (registry #307).
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

// verify implements the 8-step ATX v1.0 verification algorithm with hybrid
// signing enforcement per AIP §3.
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

	now, err := time.Parse(time.RFC3339, f.VerifierState.ClockRFC3339)
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
	if now.After(a.ExpiresAt) {
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

	// Step 5: signature verification.
	// Spec mandate: every declared signature MUST verify. The conformance
	// verifier does not silently skip ML-DSA-65 signatures even though the
	// current pkg/atcverify production verifier does.
	var payload []byte
	if a.ATCVersion == "1.1" {
		pb, err := canonicalPayloadV11(&a)
		if err != nil {
			return result{RejectCategory: "VERIFIER_CONFIG_ERROR", Reason: "v1.1 canonicalization failed: " + err.Error()}
		}
		payload = pb
	} else {
		payload = canonicalPayload(&a)
	}
	res := result{SigsExpected: len(a.Signatures)}

	// Index public keys by algorithm for lookup, restricted to keys controlled by
	// the credential's issuer (key↔issuer binding). A key whose keyId's controller
	// DID is not in the authority set is not an eligible signer for this
	// credential, so one trusted authority cannot impersonate another.
	edKeys, pqKeys := indexPublicKeys(f.VerifierState.PublicKeys, authoritySetFor(&a))

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

	// Step 6: content hash. Content not supplied to this verifier; skipped.

	// Step 7: issuer chain depth for trust level 3+.
	if a.TrustLevel >= 3 && len(a.IssuerChain) < 2 {
		return result{
			RejectCategory: "CHAIN_TOO_SHORT",
			Reason:         fmt.Sprintf("trust level %d requires 2+ authorities in issuer chain (got %d)", a.TrustLevel, len(a.IssuerChain)),
		}
	}

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

// authoritySetFor returns the DIDs whose keys may sign this credential: the
// issuer always, plus the issuerChain authorities for v1.1 (where issuerChain is
// covered by the signature). v1.0 issuerChain is unsigned and therefore forgeable,
// so it is NOT trusted as a signer source — only the issuer is.
func authoritySetFor(a *atx) map[string]bool {
	set := map[string]bool{a.IssuerDID: true}
	if a.ATCVersion == "1.1" {
		for _, did := range a.IssuerChain {
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify <fixture.json|dir>...")
		os.Exit(2)
	}

	paths, err := expandFixturePaths(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no fixture *.json files found in supplied args")
		os.Exit(2)
	}

	totalPass, totalFail := 0, 0
	for _, p := range paths {
		f, err := loadFixture(p)
		if err != nil {
			fmt.Printf("FAIL  %s  (load error: %v)\n", relPath(p), err)
			totalFail++
			continue
		}
		got := verify(f)
		wantAccept := strings.EqualFold(f.Expected.VerifyResult, "ACCEPT")

		ok := (wantAccept && got.Accepted) || (!wantAccept && !got.Accepted)
		// For REJECT fixtures, also verify the category matches if declared.
		if ok && !wantAccept && f.Expected.RejectCategory != "" {
			if got.RejectCategory != f.Expected.RejectCategory {
				ok = false
			}
		}
		if ok && !wantAccept && f.Expected.ReasonContains != "" {
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(f.Expected.ReasonContains)) {
				ok = false
			}
		}

		status := "PASS"
		if !ok {
			status = "FAIL"
			totalFail++
		} else {
			totalPass++
		}
		fmt.Printf("%s  %s\n", status, relPath(p))
		fmt.Printf("       expected: %s", f.Expected.VerifyResult)
		if f.Expected.RejectCategory != "" {
			fmt.Printf(" [%s]", f.Expected.RejectCategory)
		}
		fmt.Println()
		fmt.Printf("       observed: %s\n", got)
		if got.SigsExpected > 0 {
			fmt.Printf("       signatures: %d/%d valid (ed25519=%t mldsa65=%t)\n",
				got.SigsValid, got.SigsExpected, got.Ed25519Valid, got.MLDSA65Valid)
		}
	}

	fmt.Println()
	fmt.Printf("summary: %d pass, %d fail (%d fixtures)\n", totalPass, totalFail, totalPass+totalFail)
	if totalFail > 0 {
		os.Exit(1)
	}
}

func loadFixture(path string) (fixture, error) {
	// path originates from os.Args[1:] (operator-supplied fixture file/dir); this is a
	// standalone CLI verifier with no network/request surface, so no untrusted taint.
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied CLI arg, not request-derived
	if err != nil {
		return fixture{}, err
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		return fixture{}, err
	}
	return f, nil
}

func expandFixturePaths(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a) //nolint:gosec // G703: operator-supplied CLI arg, not request-derived
		if err != nil {
			return nil, err
		}
		switch {
		case info.IsDir():
			fixDir := a
			// Allow passing the repo root: look in $arg/fixtures if it exists.
			if _, err := os.Stat(filepath.Join(a, "fixtures")); err == nil { //nolint:gosec // G703: operator-supplied CLI arg
				fixDir = filepath.Join(a, "fixtures")
			}
			entries, err := os.ReadDir(fixDir)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
					out = append(out, filepath.Join(fixDir, e.Name()))
				}
			}
		default:
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, nil
}

func relPath(p string) string {
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, p); err == nil {
			return rel
		}
	}
	return p
}
