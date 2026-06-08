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
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"
)

// ATCVersion of the legacy credential schema this generator emits. v1.1 fixtures
// set atcVersion "1.1" and sign JCS(TBS); see canonicalPayloadV11.
const atcVersion = "1.0"
const atcVersionV11 = "1.1"

// jcsBaselineCanonicalHex is the canonical JCS(TBS) of the baseline vector in
// jcs-vectors/vectors/01-baseline.json. The v1.1 baseline fixture must reproduce
// it, or the fixtures and the cross-language byte-agreement gate have diverged.
const jcsBaselineCanonicalHex = "7b226167656e74446964223a226469643a6f70656e6132613a6167656e743a6167656e745f636f6e666f726d616e63655f746573745f303031222c226167656e744964223a226167656e745f636f6e666f726d616e63655f746573745f303031222c2261746356657273696f6e223a22312e31222c226265686176696f72616c50726f66696c65223a7b22636865636b73756d223a227368613235363a676869373839222c2267656e6572617465644174223a22323032362d30352d31395430303a30303a30305a222c226f62736572766174696f6e44617973223a31347d2c226275696c644174746573746174696f6e223a2268747470733a2f2f736c73612e6465762f70726f76656e616e63652f7631236f70656e6132612d636f6e666f726d616e6365222c226361706162696c6974696573223a5b22726561643a7075626c6963222c2277726974653a6f776e6564225d2c22636f6e74656e7448617368223a2230303030313131313232323233333333343434343535353536363636373737373838383839393939616161616262626263636363646464646565656566666666222c22657870697265734174223a22323039392d31322d33315432333a35393a35395a222c226973737565644174223a22323032362d30352d32335430303a30303a30305a222c22697373756572436861696e223a5b226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f72672d726f6f74222c226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267225d2c22697373756572446964223a226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267222c227075626c6973686572223a226f70656e6132612d636f6e666f726d616e6365222c227075626c6973686572446964223a226469643a6f70656e6132613a7075626c69736865723a6f70656e6132612d636f6e666f726d616e6365222c227363616e53756d6d617279223a7b22637269746963616c46696e64696e6773223a302c2263727970746f5365727665223a226e6f2d7765616b2d63727970746f222c226869676846696e64696e6773223a302c22686d61223a22706173736564222c226f6173624c6576656c223a224c31222c227365637265746c657373223a22636c65616e227d2c2274727573744c6576656c223a342c22747275737453636f7265223a2238372e353030303030222c2276657273696f6e223a22312e302e30227d"

// jcsDeclaredPurposeCanonicalHex is the canonical JCS(TBS) of the present-case
// vector in jcs-vectors/vectors/08-declared-purpose.json. The baseline-v1.1
// credential carrying presentDeclaredPurpose must reproduce it, or the present-case
// fixtures and the byte-agreement gate have diverged on declaredPurpose.
const jcsDeclaredPurposeCanonicalHex = "7b226167656e74446964223a226469643a6f70656e6132613a6167656e743a6167656e745f636f6e666f726d616e63655f746573745f303031222c226167656e744964223a226167656e745f636f6e666f726d616e63655f746573745f303031222c2261746356657273696f6e223a22312e31222c226265686176696f72616c50726f66696c65223a7b22636865636b73756d223a227368613235363a676869373839222c2267656e6572617465644174223a22323032362d30352d31395430303a30303a30305a222c226f62736572766174696f6e44617973223a31347d2c226275696c644174746573746174696f6e223a2268747470733a2f2f736c73612e6465762f70726f76656e616e63652f7631236f70656e6132612d636f6e666f726d616e6365222c226361706162696c6974696573223a5b22726561643a7075626c6963222c2277726974653a6f776e6564225d2c22636f6e74656e7448617368223a2230303030313131313232323233333333343434343535353536363636373737373838383839393939616161616262626263636363646464646565656566666666222c226465636c61726564507572706f7365223a7b226175746f6e6f6d79223a2273757065727669736564222c226361706162696c6974794a757374696669636174696f6e223a7b22726561643a7075626c6963223a5b2262696c6c696e673a696e7175697279225d2c2277726974653a6f776e6564223a5b2262696c6c696e673a726566756e64225d7d2c2263617465676f7279223a2266696e616e6369616c2d6f7065726174696f6e73222c226461746153636f706573223a5b22637573746f6d65722e62696c6c696e67222c22637573746f6d65722e636f6e74616374225d2c2265677265737353636f706573223a5b226170692e7374726970652e636f6d222c22686f6f6b732e696e7465726e616c2e61636d652e636f6d225d2c2273746174656d656e74223a2250726f63657373657320637573746f6d65722062696c6c696e6720696e7175697269657320616e642069737375657320726566756e647320757020746f20612073757065727669736f722d736574206c696d69742e20e58c97e4baac222c227461736b53636f706573223a5b2262696c6c696e673a696e7175697279222c2262696c6c696e673a726566756e64225d2c22766f63616256657273696f6e223a2231227d2c22657870697265734174223a22323039392d31322d33315432333a35393a35395a222c226973737565644174223a22323032362d30352d32335430303a30303a30305a222c22697373756572436861696e223a5b226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f72672d726f6f74222c226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267225d2c22697373756572446964223a226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267222c227075626c6973686572223a226f70656e6132612d636f6e666f726d616e6365222c227075626c6973686572446964223a226469643a6f70656e6132613a7075626c69736865723a6f70656e6132612d636f6e666f726d616e6365222c227363616e53756d6d617279223a7b22637269746963616c46696e64696e6773223a302c2263727970746f5365727665223a226e6f2d7765616b2d63727970746f222c226869676846696e64696e6773223a302c22686d61223a22706173736564222c226f6173624c6576656c223a224c31222c227365637265746c657373223a22636c65616e227d2c2274727573744c6576656c223a342c22747275737453636f7265223a2238372e353030303030222c2276657273696f6e223a22312e302e30227d"

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
	DeclaredPurpose      json.RawMessage       `json:"declaredPurpose,omitempty"`
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

// tbsV11 and friends are the ATX v1.1 to-be-signed projection (atx-spec
// core.md §1.3a.2), identical to opena2a-registry/pkg/atcverify and the
// conformance verifier. JCS sorts member names, so field order is irrelevant.
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

// canonicalPayloadV11 projects an ATX into the v1.1 TBS and returns JCS(TBS).
func canonicalPayloadV11(a *ATX) []byte {
	caps := a.Capabilities
	if caps == nil {
		caps = []string{}
	}
	chain := a.IssuerChain
	if chain == nil {
		chain = []string{}
	}
	var ss tbsScanSummaryV11
	if a.ScanSummary != nil {
		ss = tbsScanSummaryV11{
			HMA: a.ScanSummary.HMA, CriticalFindings: a.ScanSummary.CriticalFindings,
			HighFindings: a.ScanSummary.HighFindings, Secretless: a.ScanSummary.Secretless,
			CryptoServe: a.ScanSummary.CryptoServe, OASBLevel: a.ScanSummary.OASBLevel,
		}
	}
	bp := json.RawMessage("null")
	if a.BehavioralProfile != nil {
		bpObj := tbsBehavioralProfileV11{
			Checksum:        a.BehavioralProfile.Checksum,
			GeneratedAt:     a.BehavioralProfile.GeneratedAt.UTC().Format(time.RFC3339),
			ObservationDays: a.BehavioralProfile.ObservationDays,
		}
		b, err := json.Marshal(&bpObj)
		must(err)
		bp = b
	}
	tbs := tbsV11{
		ATCVersion: a.ATCVersion, AgentID: a.AgentID, AgentDID: a.AgentDID,
		Publisher: a.Publisher, PublisherDID: a.PublisherDID, Version: a.Version,
		ContentHash: a.ContentHash, BuildAttestation: a.BuildAttestation,
		Capabilities: caps, DeclaredPurpose: projectDeclaredPurposeV11(a.DeclaredPurpose),
		BehavioralProfile: bp, ScanSummary: ss,
		TrustScore: fmt.Sprintf("%.6f", a.TrustScore), TrustLevel: a.TrustLevel,
		IssuedAt: a.IssuedAt.UTC().Format(time.RFC3339), ExpiresAt: a.ExpiresAt.UTC().Format(time.RFC3339),
		IssuerDID: a.IssuerDID, IssuerChain: chain,
	}
	raw, err := json.Marshal(&tbs)
	must(err)
	out, err := jcs.Transform(raw)
	must(err)
	return out
}

// projectDeclaredPurposeV11 implements the presence-based rule for the optional
// declaredPurpose TBS member (atx-spec §1.3a.2 rule 5), byte-identical to
// opena2a-registry (pkg/atcverify + internal/application) and ../verifiers: an
// absent purpose (missing, null, or {}) normalizes to nil so omitempty drops it
// from the TBS, keeping a no-purpose credential byte-identical to one issued
// before the field existed; a present object passes through for JCS to sort.
func projectDeclaredPurposeV11(raw json.RawMessage) json.RawMessage {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "{}":
		return nil
	default:
		return raw
	}
}

// signV11WithKey signs JCS(TBS) with a vector's Ed25519 seed.
func signV11WithKey(v keyVector, a ATX) ATCSignature {
	sig := signEd25519(v.SeedHex, canonicalPayloadV11(&a))
	sig.KeyID = v.KeyID
	return sig
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
	Schema        string          `json:"$schema"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Spec          []SpecRef       `json:"spec"`
	KeypairRefs   []KeypairRef    `json:"keypairRefs"`
	VerifierState VerifierState   `json:"verifierState"`
	Expected      ExpectedOutcome `json:"expected"`
	ATX           json.RawMessage `json:"atx"`
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

// presentDeclaredPurpose is the populated declaredPurpose object the present-case
// v1.1 fixtures carry. Its logical content matches jcs-vectors/vectors/
// 08-declared-purpose.json, so a baseline-v1.1 credential carrying it canonicalizes
// to that vector's pinned bytes (JCS sorts members, so the authored order here is
// irrelevant). Capabilities (read:public, write:owned) cover the
// capabilityJustification keys, per atx-spec §1.5.2.
const presentDeclaredPurpose = `{
  "vocabVersion": "1",
  "statement": "Processes customer billing inquiries and issues refunds up to a supervisor-set limit. 北京",
  "category": "financial-operations",
  "taskScopes": ["billing:inquiry", "billing:refund"],
  "capabilityJustification": {
    "read:public": ["billing:inquiry"],
    "write:owned": ["billing:refund"]
  },
  "autonomy": "supervised",
  "dataScopes": ["customer.billing", "customer.contact"],
  "egressScopes": ["api.stripe.com", "hooks.internal.acme.com"]
}`

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

	// Cross-check: the v1.1 baseline must canonicalize to the bytes pinned in
	// jcs-vectors/vectors/01-baseline.json.
	if base := newBaselineV11ATX(); hex.EncodeToString(canonicalPayloadV11(&base)) != jcsBaselineCanonicalHex {
		panic("v1.1 baseline canonical bytes diverge from jcs-vectors baseline vector; fixtures and the byte-agreement gate are out of sync")
	}

	// Cross-check: the present-case credential (baseline + presentDeclaredPurpose)
	// must canonicalize to the bytes pinned in jcs-vectors/vectors/08-declared-purpose.json,
	// so the declaredPurpose fixtures and the cross-language byte-agreement gate stay in sync.
	dpBase := newBaselineV11ATX()
	dpBase.DeclaredPurpose = json.RawMessage(presentDeclaredPurpose)
	if hex.EncodeToString(canonicalPayloadV11(&dpBase)) != jcsDeclaredPurposeCanonicalHex {
		panic("present-case declaredPurpose canonical bytes diverge from jcs-vectors 08-declared-purpose vector; fixtures and the byte-agreement gate are out of sync")
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
		// ---- ATX v1.1 fixtures (additive; sign JCS(TBS), atx-spec §1.3a.2) ----
		{"fixtures/v1_1-baseline-valid.json", func() Fixture {
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/baseline-valid",
				"A baseline ATX v1.1 credential. The single Ed25519 signature covers JCS(TBS) per atx-spec core.md §1.3a.2, so capabilities, scanSummary, issuerChain, publisher, and behavioralProfile are integrity-protected. Verifier MUST ACCEPT. The canonical bytes equal the jcs-vectors baseline vector.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/v1_1-baseline-valid-hybrid.json", func() Fixture {
			atx := newBaselineV11ATX()
			ed := signV11WithKey(primary, atx)
			pq, _ := signMLDSA65(mldsa.SeedHex, canonicalPayloadV11(&atx))
			pq.KeyID = mldsa.KeyID
			atx.Signatures = []ATCSignature{ed, pq}
			return wrap("atx-v1_1/baseline-valid-hybrid",
				"An ATX v1.1 credential carrying both an Ed25519 signature and an ML-DSA-65 signature over the SAME JCS(TBS) bytes. A spec-conformant verifier MUST verify both and ACCEPT.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					{Role: mldsa.Role, Path: "vectors/mldsa65-seed.json", Algorithm: mldsa.Algorithm, PublicKeyHex: mldsa.PublicKeyHex, KeyID: mldsa.KeyID},
				},
				hybridVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/v1_1-tampered-capabilities.json", func() Fixture {
			// The v1.1 win, made concrete. Sign the TBS with the honest
			// capabilities, then escalate capabilities AFTER signing. Under
			// v1.0 the signature would still verify (capabilities unsigned);
			// under v1.1 the recomputed JCS(TBS) no longer matches the
			// signature, so the verifier MUST REJECT.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			atx.Capabilities = []string{"read:public", "write:owned", "admin:all"}
			return wrap("atx-v1_1/tampered-capabilities",
				"An ATX v1.1 credential whose capabilities were escalated to include admin:all AFTER signing. Because v1.1 signs JCS(TBS), capabilities are covered by the signature; the verifier recomputes the canonical bytes, finds they no longer match, and MUST REJECT with a signature-validation reason. This is the integrity property v1.0 lacked.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-declared-purpose-valid.json", func() Fixture {
			// PRESENT-CASE: a credential that actually CARRIES a declaredPurpose
			// (atx-spec §1.5). The purpose object is part of JCS(TBS), so the single
			// Ed25519 signature covers it; the verifier reprojects the same bytes and
			// MUST ACCEPT. Exercises the presence-based member end-to-end.
			atx := newBaselineV11ATX()
			atx.DeclaredPurpose = json.RawMessage(presentDeclaredPurpose)
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/declared-purpose-valid",
				"A baseline ATX v1.1 credential carrying a populated declaredPurpose (atx-spec §1.5): vocabVersion, statement, category, taskScopes, capabilityJustification, autonomy, dataScopes, egressScopes. declaredPurpose is the one presence-based TBS member (§1.3a.2 rule 5); when present it is signed as part of JCS(TBS). Verifier MUST ACCEPT. Canonical bytes equal the jcs-vectors 08-declared-purpose vector.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/v1_1-tampered-declared-purpose.json", func() Fixture {
			// The purpose-laundering defense, made concrete. Sign with the honest
			// category (financial-operations), then rewrite declaredPurpose.category
			// to a broader one AFTER signing. Because declaredPurpose is in JCS(TBS),
			// the recomputed canonical bytes no longer match the signature, so the
			// verifier MUST REJECT — a publisher cannot forge what its agent claimed
			// to be for after issuance.
			atx := newBaselineV11ATX()
			atx.DeclaredPurpose = json.RawMessage(presentDeclaredPurpose)
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			atx.DeclaredPurpose = json.RawMessage(strings.Replace(presentDeclaredPurpose, "financial-operations", "agent-orchestration", 1))
			return wrap("atx-v1_1/tampered-declared-purpose",
				"An ATX v1.1 credential whose declaredPurpose.category was rewritten from financial-operations to agent-orchestration AFTER signing. Because v1.1 signs JCS(TBS) and declaredPurpose is part of it, the verifier recomputes the canonical bytes, finds they no longer match the signature, and MUST REJECT. This is the integrity property that makes a declared purpose binding and non-repudiable (§1.5).",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
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

// newBaselineV11ATX returns the v1.1 baseline credential. It mirrors the
// jcs-vectors baseline vector: atcVersion 1.1, a populated behavioralProfile,
// and a root-first issuerChain (atx-spec §1.3a.2). Its JCS(TBS) bytes therefore
// equal that vector's pinned canonical bytes.
func newBaselineV11ATX() ATX {
	a := newBaselineATX()
	a.ATCVersion = atcVersionV11
	a.BehavioralProfile = &ATCBehavioralProfile{
		Checksum:        "sha256:ghi789",
		GeneratedAt:     mustParseTime("2026-05-19T00:00:00Z"),
		ObservationDays: 14,
	}
	// Root-first order per §1.3a.2 (the v1.0 baseline uses the legacy order).
	a.IssuerChain = []string{"did:opena2a:authority:opena2a.org-root", "did:opena2a:authority:opena2a.org"}
	return a
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
