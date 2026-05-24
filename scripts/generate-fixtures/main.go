// generate-fixtures produces the ATX v1.0 conformance fixture set.
//
// Every fixture is byte-stable: same seeds, same canonicalization, same JSON
// encoding settings. Re-running the generator must produce identical bytes;
// MANIFEST.sha256 pins each fixture.
//
// Signing layer mirrors the reference verifier at
// opena2a-registry/pkg/atcverify/verify.go: the Ed25519 signature is computed
// over the pipe-delimited canonical payload defined in canonicalPayload below.
// This is the SAME function as the reference verifier; conformance fixtures and
// the reference verifier MUST agree on the canonical bytes.
//
// Hybrid signing: ML-DSA-65 signature is computed over the SAME canonical
// payload bytes. This matches the ATX v1.0 spec mandate for hybrid signing.
// The Ed25519-only reference verifier (pkg/atcverify) does not yet verify the
// ML-DSA-65 path; the conformance Go verifier in ../verifiers/go DOES, as a
// statement of what spec-conformant verifiers must do.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ATCVersion of the credential schema this generator emits.
const atcVersion = "1.0"

// fixedClock pins the verifier clock for the entire suite. Valid fixtures
// have ExpiresAt later than this; the expired fixture has ExpiresAt earlier.
const fixedClockRFC3339 = "2026-05-24T00:00:00Z"

// outDir is the conformance repo root, derived at run time relative to this
// generator's location.
var outDir string

// ATCSignature mirrors the production domain type (atc.go:42-46) verbatim.
type ATCSignature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// ATCBehavioralProfile mirrors the production domain type.
type ATCBehavioralProfile struct {
	Checksum        string    `json:"checksum"`
	GeneratedAt     time.Time `json:"generatedAt"`
	ObservationDays int       `json:"observationDays"`
}

// ATCScanSummary mirrors the production domain type.
type ATCScanSummary struct {
	HMA              string `json:"hma"`
	CriticalFindings int    `json:"criticalFindings"`
	HighFindings     int    `json:"highFindings"`
	Secretless       string `json:"secretless"`
	CryptoServe      string `json:"cryptoServe"`
	OASBLevel        string `json:"oasbLevel"`
}

// ATX is the AgentTrustCredential as serialized for this conformance suite.
// Field order matches the production AgentTrustCredential struct
// (opena2a-registry/internal/domain/atc.go:50-75) so that encoded JSON byte
// order is identical for both producers.
type ATX struct {
	ID                   string                `json:"id"`
	ATCVersion           string                `json:"atcVersion"`
	AgentID              string                `json:"agentId"`
	AgentDID             string                `json:"agentDid"`
	Publisher            string                `json:"publisher"`
	PublisherDID         string                `json:"publisherDid,omitempty"`
	Version              string                `json:"version"`
	ContentHash          string                `json:"contentHash"`
	BuildAttestation     string                `json:"buildAttestation,omitempty"`
	TransparencyLogIndex int64                 `json:"transparencyLogIndex"`
	Capabilities         []string              `json:"capabilities"`
	BehavioralProfile    *ATCBehavioralProfile `json:"behavioralProfile,omitempty"`
	ScanSummary          *ATCScanSummary       `json:"scanSummary"`
	TrustScore           float64               `json:"trustScore"`
	TrustLevel           int                   `json:"trustLevel"`
	IssuedAt             time.Time             `json:"issuedAt"`
	ExpiresAt            time.Time             `json:"expiresAt"`
	IssuerDID            string                `json:"issuerDid"`
	IssuerChain          []string              `json:"issuerChain"`
	Signatures           []ATCSignature        `json:"signatures"`
	Revoked              bool                  `json:"revoked"`
	RevokedAt            *time.Time            `json:"revokedAt,omitempty"`
	RevocationReason     string                `json:"revocationReason,omitempty"`
	CreatedAt            time.Time             `json:"createdAt"`
}

// canonicalPayload reproduces opena2a-registry/pkg/atcverify/verify.go:314-329
// VERBATIM. Any divergence here breaks signature interop with the production
// verifier. The 11 signed fields are: agentId, agentDid, version, contentHash,
// buildAttestation, issuerDid, trustLevel, trustScore, issuedAt, expiresAt,
// atcVersion. Notably, the signature does NOT cover capabilities,
// behavioralProfile, scanSummary, signatures, revoked, revokedAt,
// revocationReason, transparencyLogIndex, publisher, publisherDid, agentDid
// (wait, agentDid IS included). See README §"Signed vs unsigned fields."
func canonicalPayload(a *ATX) []byte {
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%.6f|%s|%s|%s",
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
		atcVersion,
	)
	return []byte(canonical)
}

// signEd25519 signs the canonical payload with an Ed25519 keypair derived from
// a 32-byte seed.
func signEd25519(seedHex string, payload []byte) ATCSignature {
	seed, err := hex.DecodeString(seedHex)
	must(err)
	if len(seed) != ed25519.SeedSize {
		panic(fmt.Sprintf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed)))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, payload)
	return ATCSignature{
		Algorithm: "Ed25519",
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
}

// signMLDSA65 signs the canonical payload with an ML-DSA-65 keypair derived
// from a 32-byte seed via CIRCL's deterministic KeyGen.
func signMLDSA65(seedHex string, payload []byte) (sig ATCSignature, pubKeyHex string) {
	seed, err := hex.DecodeString(seedHex)
	must(err)
	if len(seed) != 32 {
		panic(fmt.Sprintf("ML-DSA-65 seed must be 32 bytes, got %d", len(seed)))
	}
	var seedArr [32]byte
	copy(seedArr[:], seed)
	pub, priv := mldsa65.NewKeyFromSeed(&seedArr)
	sigBytes := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(priv, payload, nil, false, sigBytes); err != nil {
		panic(fmt.Sprintf("ML-DSA-65 sign: %v", err))
	}
	pubBytes, err := pub.MarshalBinary()
	must(err)
	return ATCSignature{
		Algorithm: "ML-DSA-65",
		Value:     base64.StdEncoding.EncodeToString(sigBytes),
	}, hex.EncodeToString(pubBytes)
}

// KeypairRef is a verifier-side description of one keypair the fixture
// references. Verifiers do not load the private seed; they load only the
// public key. seedHex is included for fixture-regeneration reproducibility.
type KeypairRef struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

// Fixture wraps an ATX with all the metadata a language-agnostic verifier
// needs: spec refs, expected outcome, verifier configuration.
type Fixture struct {
	Schema        string             `json:"$schema"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Spec          []SpecRef          `json:"spec"`
	KeypairRefs   []KeypairRef       `json:"keypairRefs"`
	VerifierState VerifierState      `json:"verifierState"`
	Expected      ExpectedOutcome    `json:"expected"`
	ATX           json.RawMessage    `json:"atx"`
}

// SpecRef cites a normative document.
type SpecRef struct {
	ID      string `json:"id"`
	Ref     string `json:"ref"`
	Section string `json:"section"`
}

// VerifierState is the configuration the verifier MUST apply before running.
type VerifierState struct {
	ClockRFC3339   string       `json:"clockRfc3339"`
	TrustedIssuers []string     `json:"trustedIssuers"`
	PublicKeys     []KeypairRef `json:"publicKeys"`
	CRL            *CRL         `json:"crl,omitempty"`
}

// CRL is the same shape as opena2a-registry/pkg/atcverify/verify.go:82-91.
type CRL struct {
	Version    int        `json:"version"`
	IssuedAt   time.Time  `json:"issuedAt"`
	NextUpdate time.Time  `json:"nextUpdate"`
	Entries    []CRLEntry `json:"entries"`
	Signature  string     `json:"signature"`
}

// CRLEntry is the same shape as opena2a-registry/pkg/atcverify/verify.go:93-97.
type CRLEntry struct {
	AgentID   string    `json:"agentId"`
	RevokedAt time.Time `json:"revokedAt"`
	Reason    string    `json:"reason"`
}

// ExpectedOutcome is what the verifier MUST report.
type ExpectedOutcome struct {
	VerifyResult   string `json:"verifyResult"` // "ACCEPT" or "REJECT"
	RejectCategory string `json:"rejectCategory,omitempty"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

// Pinned time anchors used across fixtures.
var (
	issuedAt    = mustParseTime("2026-05-23T00:00:00Z")
	expiresAt   = mustParseTime("2099-12-31T23:59:59Z")
	expiredAt   = mustParseTime("2025-01-01T00:00:00Z")
	createdAt   = mustParseTime("2026-05-23T00:00:00Z")
	revokedTime = mustParseTime("2026-05-23T12:00:00Z")
)

// Fixed test agent + content hash used across fixtures so reviewers can see at
// a glance that fixtures share a common base.
const (
	testAgentID    = "agent_conformance_test_001"
	testAgentDID   = "did:opena2a:agent:agent_conformance_test_001"
	testPublisher  = "opena2a-conformance"
	testVersion    = "1.0.0"
	testContentSha = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
	testBuildAtt   = "https://slsa.dev/provenance/v1#opena2a-conformance"
)

func main() {
	outDir = mustResolveOutDir()

	primary := mustLoadKeyVector("vectors/issuer-primary.json")
	cos1 := mustLoadKeyVector("vectors/issuer-cosigner-1.json")
	cos2 := mustLoadKeyVector("vectors/issuer-cosigner-2.json")
	untrusted := mustLoadKeyVector("vectors/issuer-untrusted.json")
	mldsa := mustLoadKeyVector("vectors/mldsa65-seed.json")

	// Resolve ML-DSA-65 public key from seed and persist it into the vector
	// file (only on first run; subsequent runs see the pinned value).
	_, mldsaPubHex := signMLDSA65(mldsa.SeedHex, []byte("__pubkey_resolution__"))
	if mldsa.PublicKeyHex == "PINNED_BY_GENERATOR" {
		mldsa.PublicKeyHex = mldsaPubHex
		mustWritePinnedMLDSAPubKey(mldsa)
	} else if mldsa.PublicKeyHex != mldsaPubHex {
		panic(fmt.Sprintf("ML-DSA-65 pubkey drift: vector says %s, generator computed %s",
			mldsa.PublicKeyHex[:16]+"...", mldsaPubHex[:16]+"..."))
	}

	defaultVerifierState := VerifierState{
		ClockRFC3339:   fixedClockRFC3339,
		TrustedIssuers: []string{primary.IssuerDID},
		PublicKeys: []KeypairRef{
			keypairRefFor(primary, "vectors/issuer-primary.json"),
			keypairRefFor(cos1, "vectors/issuer-cosigner-1.json"),
			keypairRefFor(cos2, "vectors/issuer-cosigner-2.json"),
		},
	}

	// Hybrid verifier state additionally publishes the ML-DSA-65 public key.
	hybridVerifierState := defaultVerifierState
	hybridVerifierState.PublicKeys = append(append([]KeypairRef{},
		defaultVerifierState.PublicKeys...),
		KeypairRef{
			Role:         mldsa.Role,
			Path:         "vectors/mldsa65-seed.json",
			Algorithm:    mldsa.Algorithm,
			PublicKeyHex: mldsa.PublicKeyHex,
			KeyID:        mldsa.KeyID,
		})

	type fixtureSpec struct {
		writePath string
		build     func() Fixture
	}

	fixtures := []fixtureSpec{
		{"fixtures/baseline-valid.json", func() Fixture {
			atx := newBaselineATX()
			atx.Signatures = []ATCSignature{signWithKey(primary, atx)}
			return wrap("atx-v1/baseline-valid",
				"A baseline ATX v1.0 credential issued by a single trusted authority with one Ed25519 signature. Verifier MUST ACCEPT.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/baseline-valid-hybrid.json", func() Fixture {
			atx := newBaselineATX()
			ed := signWithKey(primary, atx)
			pq, _ := signMLDSA65(mldsa.SeedHex, canonicalPayload(&atx))
			pq.KeyID = mldsa.KeyID
			atx.Signatures = []ATCSignature{ed, pq}
			return wrap("atx-v1/baseline-valid-hybrid",
				"An ATX v1.0 credential carrying both an Ed25519 signature and an ML-DSA-65 signature over the same canonical payload. This is the hybrid signing path the ATX v1.0 spec mandates. A spec-conformant verifier MUST verify BOTH signatures and ACCEPT only when both are valid. NOTE: the current opena2a-registry/pkg/atcverify verifier verifies Ed25519 only and silently ignores ML-DSA-65 signatures; the conformance Go verifier in ../verifiers/go DOES verify both, per spec.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					{Role: mldsa.Role, Path: "vectors/mldsa65-seed.json", Algorithm: mldsa.Algorithm, PublicKeyHex: mldsa.PublicKeyHex, KeyID: mldsa.KeyID},
				},
				hybridVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/revoked.json", func() Fixture {
			atx := newBaselineATX()
			atx.Signatures = []ATCSignature{signWithKey(primary, atx)}
			// Per the production verifier (verify.go:209-220) the Revoked
			// flag is checked BEFORE the CRL. We populate both so the
			// fixture exercises both rejection paths.
			atx.Revoked = true
			rt := revokedTime
			atx.RevokedAt = &rt
			atx.RevocationReason = "key compromise (test)"
			vs := defaultVerifierState
			vs.CRL = &CRL{
				Version:    1,
				IssuedAt:   mustParseTime("2026-05-23T12:00:00Z"),
				NextUpdate: mustParseTime("2026-05-30T12:00:00Z"),
				Entries: []CRLEntry{{
					AgentID:   atx.AgentID,
					RevokedAt: rt,
					Reason:    "key compromise (test)",
				}},
				Signature: "TEST_ONLY_UNSIGNED_CRL",
			}
			return wrap("atx-v1/revoked",
				"A previously-valid ATX whose credential-level Revoked flag is set and whose AgentID also appears in the verifier's CRL. Verifier MUST REJECT with revocation reason. Both rejection paths are exercised.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				vs,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "REVOKED", ReasonContains: "revoked"},
				atx)
		}},
		{"fixtures/threshold-2of3-cosignature.json", func() Fixture {
			atx := newBaselineATX()
			atx.TrustLevel = 4
			atx.IssuerChain = []string{primary.IssuerDID, "did:opena2a:authority:opena2a.org-root"}
			ed1 := signWithKey(primary, atx)
			ed2 := signWithKey(cos1, atx)
			ed3 := signWithKey(cos2, atx)
			atx.Signatures = []ATCSignature{ed1, ed2, ed3}
			return wrap("atx-v1/threshold-2of3-cosignature",
				"An ATX cosigned by all three keys of a 2-of-3 threshold issuer (primary plus two cosigners). All three signatures are Ed25519 and cover the same canonical payload. Verifier MUST ACCEPT. A spec-conformant verifier additionally MUST validate at least two of the three signatures for trust level 4.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(cos1, "vectors/issuer-cosigner-1.json"),
					keypairRefFor(cos2, "vectors/issuer-cosigner-2.json"),
				},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/expired.json", func() Fixture {
			atx := newBaselineATX()
			atx.IssuedAt = mustParseTime("2024-12-25T00:00:00Z")
			atx.ExpiresAt = expiredAt
			atx.Signatures = []ATCSignature{signWithKey(primary, atx)}
			return wrap("atx-v1/expired",
				"An otherwise-valid ATX whose ExpiresAt is earlier than the verifier's pinned clock. Verifier MUST REJECT with an expiry reason.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "EXPIRED", ReasonContains: "expired"},
				atx)
		}},
		{"fixtures/wrong-issuer.json", func() Fixture {
			atx := newBaselineATX()
			atx.IssuerDID = untrusted.IssuerDID
			atx.IssuerChain = []string{untrusted.IssuerDID}
			atx.TrustLevel = 1
			atx.Signatures = []ATCSignature{signWithKey(untrusted, atx)}
			return wrap("atx-v1/wrong-issuer",
				"A syntactically valid ATX signed by a real keypair, but issued under a DID that is NOT in the verifier's trusted set. The signature itself is valid; the issuer is not. Verifier MUST REJECT with an untrusted-issuer reason.",
				[]KeypairRef{keypairRefFor(untrusted, "vectors/issuer-untrusted.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "UNTRUSTED_ISSUER", ReasonContains: "untrusted"},
				atx)
		}},
		{"fixtures/tampered-signature.json", func() Fixture {
			atx := newBaselineATX()
			sig := signWithKey(primary, atx)
			tampered, err := base64.StdEncoding.DecodeString(sig.Value)
			must(err)
			tampered[0] ^= 0x01
			sig.Value = base64.StdEncoding.EncodeToString(tampered)
			atx.Signatures = []ATCSignature{sig}
			return wrap("atx-v1/tampered-signature",
				"An ATX whose Ed25519 signature has been flipped by one bit after signing. All other fields are unchanged. Verifier MUST REJECT with a signature-validation reason.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/malformed-schema.json", func() Fixture {
			atx := newBaselineATX()
			atx.ATCVersion = "2.0" // unsupported per the v1.0 spec
			atx.Signatures = []ATCSignature{signWithKey(primary, atx)}
			return wrap("atx-v1/malformed-schema",
				"An ATX whose atcVersion claims a version (2.0) that is not the v1.0 supported by this conformance suite. Verifier MUST REJECT at step 1 (schema-version check) with an unsupported-version reason. NOTE: the signature is computed using ATCVersion=\"1.0\" canonical bytes because the production canonicalPayload function hardcodes \"1.0\" in the canonical string regardless of the credential's atcVersion field. This is itself a discrepancy worth noting in the reconciliation log; the conformance fixture intentionally still produces a syntactically reasonable file so verifiers can demonstrate they reject on schema-version alone.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "UNSUPPORTED_VERSION", ReasonContains: "version"},
				atx)
		}},
	}

	type manifestEntry struct {
		path string
		sha  string
	}
	var manifest []manifestEntry

	for _, fs := range fixtures {
		f := fs.build()
		path := filepath.Join(outDir, fs.writePath)
		mustWriteJSONPretty(path, f)
		sha := sha256FileHex(path)
		manifest = append(manifest, manifestEntry{path: fs.writePath, sha: sha})
		fmt.Printf("wrote %s (sha256=%s)\n", fs.writePath, sha)
	}

	// MANIFEST.sha256: one line per fixture, in path-sorted order.
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].path < manifest[j].path })
	manifestPath := filepath.Join(outDir, "MANIFEST.sha256")
	var manifestLines []byte
	for _, e := range manifest {
		manifestLines = append(manifestLines, []byte(fmt.Sprintf("%s  %s\n", e.sha, e.path))...)
	}
	must(os.WriteFile(manifestPath, manifestLines, 0o644))
	fmt.Printf("wrote MANIFEST.sha256 (%d fixtures)\n", len(manifest))
}

// newBaselineATX returns the credential template all fixtures derive from.
// Adjustments are made per-fixture in the builder closures above.
func newBaselineATX() ATX {
	return ATX{
		ID:                   "00000000-0000-0000-0000-000000000001",
		ATCVersion:           atcVersion,
		AgentID:              testAgentID,
		AgentDID:             testAgentDID,
		Publisher:            testPublisher,
		PublisherDID:         "did:opena2a:publisher:opena2a-conformance",
		Version:              testVersion,
		ContentHash:          testContentSha,
		BuildAttestation:     testBuildAtt,
		TransparencyLogIndex: 42,
		Capabilities:         []string{"read:public", "write:owned"},
		ScanSummary: &ATCScanSummary{
			HMA: "passed", CriticalFindings: 0, HighFindings: 0,
			Secretless: "clean", CryptoServe: "no-weak-crypto", OASBLevel: "L1",
		},
		TrustScore:  87.500000,
		TrustLevel:  4,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
		IssuerDID:   "did:opena2a:authority:opena2a.org",
		IssuerChain: []string{"did:opena2a:authority:opena2a.org", "did:opena2a:authority:opena2a.org-root"},
		Signatures:  nil, // filled by caller
		Revoked:     false,
		CreatedAt:   createdAt,
	}
}

// signWithKey signs the canonical payload using a vector's seed and attaches
// the vector's keyId to the resulting signature.
func signWithKey(v keyVector, a ATX) ATCSignature {
	sig := signEd25519(v.SeedHex, canonicalPayload(&a))
	sig.KeyID = v.KeyID
	return sig
}

// wrap bundles the signed ATX with its fixture metadata.
func wrap(name, description string, refs []KeypairRef, vs VerifierState, expected ExpectedOutcome, atx ATX) Fixture {
	atxBytes, err := marshalIndent(atx)
	must(err)
	return Fixture{
		Schema:      "https://atx.opena2a.org/schemas/fixture-v1.json",
		Name:        name,
		Description: description,
		Spec: []SpecRef{
			{ID: "ATX", Ref: "https://github.com/opena2a-org/atx-spec/blob/main/core.md", Section: "§1.1 Credential schema and §6 Threshold cosignature"},
			{ID: "AIP", Ref: "https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md", Section: "§3 Hybrid Ed25519 + ML-DSA-65 signing, §6.1 9-factor trust scoring"},
			{ID: "RFC 8032", Ref: "https://datatracker.ietf.org/doc/html/rfc8032", Section: "§7.1 Test 1 (Ed25519 keypair source for issuer-primary)"},
			{ID: "FIPS 204", Ref: "https://csrc.nist.gov/pubs/fips/204/final", Section: "ML-DSA-65 (Module-Lattice-Based DSA)"},
		},
		KeypairRefs:   refs,
		VerifierState: vs,
		Expected:      expected,
		ATX:           atxBytes,
	}
}

// ----------------------------------------------------------------------------
// utility helpers
// ----------------------------------------------------------------------------

type keyVector struct {
	Role         string `json:"role"`
	Algorithm    string `json:"algorithm"`
	SeedHex      string `json:"seedHex"`
	PublicKeyHex string `json:"publicKeyHex"`
	IssuerDID    string `json:"issuerDid"`
	KeyID        string `json:"keyId"`
}

func mustLoadKeyVector(relPath string) keyVector {
	b, err := os.ReadFile(filepath.Join(outDir, relPath))
	must(err)
	var v keyVector
	must(json.Unmarshal(b, &v))
	if v.Algorithm == "Ed25519" {
		// Sanity check: derive pubkey from seed and confirm vector matches.
		seed, err := hex.DecodeString(v.SeedHex)
		must(err)
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		want, err := hex.DecodeString(v.PublicKeyHex)
		must(err)
		if string(pub) != string(want) {
			panic(fmt.Sprintf("keypair vector mismatch in %s: seed-derived pubkey does not match", relPath))
		}
	}
	return v
}

func keypairRefFor(v keyVector, path string) KeypairRef {
	return KeypairRef{
		Role:         v.Role,
		Path:         path,
		Algorithm:    v.Algorithm,
		PublicKeyHex: v.PublicKeyHex,
		KeyID:        v.KeyID,
	}
}

func mustWritePinnedMLDSAPubKey(v keyVector) {
	b, err := os.ReadFile(filepath.Join(outDir, "vectors/mldsa65-seed.json"))
	must(err)
	var m map[string]any
	must(json.Unmarshal(b, &m))
	m["publicKeyHex"] = v.PublicKeyHex
	out, err := json.MarshalIndent(m, "", "  ")
	must(err)
	out = append(out, '\n')
	must(os.WriteFile(filepath.Join(outDir, "vectors/mldsa65-seed.json"), out, 0o644))
	fmt.Printf("pinned ML-DSA-65 publicKeyHex in vectors/mldsa65-seed.json\n")
}

func mustWriteJSONPretty(path string, v any) {
	b, err := marshalIndent(v)
	must(err)
	// Marshal twice for fixtures (the outer fixture wrapper, then format).
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}

func marshalIndent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func sha256FileHex(path string) string {
	b, err := os.ReadFile(path)
	must(err)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	must(err)
	return t.UTC()
}

func mustResolveOutDir() string {
	// generator runs from scripts/generate-fixtures/, repo root is two levels up.
	wd, err := os.Getwd()
	must(err)
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "LICENSE")); err != nil {
		panic(fmt.Sprintf("did not find LICENSE at %s; run generator from scripts/generate-fixtures/", root))
	}
	return root
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
