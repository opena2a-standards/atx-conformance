// generate-fixtures produces the ATX v1.0 and v1.1 conformance fixture set.
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
package main

import (
	"bytes"
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
const jcsBaselineCanonicalHex = "7b226167656e74446964223a226469643a6f70656e6132613a6167656e743a6167656e745f636f6e666f726d616e63655f746573745f303031222c226167656e744964223a226167656e745f636f6e666f726d616e63655f746573745f303031222c2261746356657273696f6e223a22312e31222c226265686176696f72616c50726f66696c65223a7b22636865636b73756d223a227368613235363a676869373839222c2267656e6572617465644174223a22323032362d30352d31395430303a30303a30305a222c226f62736572766174696f6e44617973223a31347d2c226275696c644174746573746174696f6e223a2268747470733a2f2f736c73612e6465762f70726f76656e616e63652f7631236f70656e6132612d636f6e666f726d616e6365222c226361706162696c6974696573223a5b2264623a72656164222c2264623a7772697465225d2c22636f6e74656e7448617368223a2230303030313131313232323233333333343434343535353536363636373737373838383839393939616161616262626263636363646464646565656566666666222c22657870697265734174223a22323039392d31322d33315432333a35393a35395a222c226973737565644174223a22323032362d30352d32335430303a30303a30305a222c22697373756572436861696e223a5b226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f72672d726f6f74222c226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267225d2c22697373756572446964223a226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267222c227075626c6973686572223a226f70656e6132612d636f6e666f726d616e6365222c227075626c6973686572446964223a226469643a6f70656e6132613a7075626c69736865723a6f70656e6132612d636f6e666f726d616e6365222c227363616e53756d6d617279223a7b22637269746963616c46696e64696e6773223a302c2263727970746f5365727665223a226e6f2d7765616b2d63727970746f222c226869676846696e64696e6773223a302c22686d61223a22706173736564222c226f6173624c6576656c223a224c31222c227365637265746c657373223a22636c65616e227d2c2274727573744c6576656c223a342c22747275737453636f7265223a2238372e353030303030222c2276657273696f6e223a22312e302e30227d"

// jcsDeclaredPurposeCanonicalHex is the canonical JCS(TBS) of the present-case
// vector in jcs-vectors/vectors/08-declared-purpose.json. The baseline-v1.1
// credential carrying presentDeclaredPurpose must reproduce it, or the present-case
// fixtures and the byte-agreement gate have diverged on declaredPurpose.
const jcsDeclaredPurposeCanonicalHex = "7b226167656e74446964223a226469643a6f70656e6132613a6167656e743a6167656e745f636f6e666f726d616e63655f746573745f303031222c226167656e744964223a226167656e745f636f6e666f726d616e63655f746573745f303031222c2261746356657273696f6e223a22312e31222c226265686176696f72616c50726f66696c65223a7b22636865636b73756d223a227368613235363a676869373839222c2267656e6572617465644174223a22323032362d30352d31395430303a30303a30305a222c226f62736572766174696f6e44617973223a31347d2c226275696c644174746573746174696f6e223a2268747470733a2f2f736c73612e6465762f70726f76656e616e63652f7631236f70656e6132612d636f6e666f726d616e6365222c226361706162696c6974696573223a5b2264623a72656164222c2264623a7772697465225d2c22636f6e74656e7448617368223a2230303030313131313232323233333333343434343535353536363636373737373838383839393939616161616262626263636363646464646565656566666666222c226465636c61726564507572706f7365223a7b226175746f6e6f6d79223a2273757065727669736564222c226361706162696c6974794a757374696669636174696f6e223a7b2264623a72656164223a5b2262696c6c696e673a696e7175697279225d2c2264623a7772697465223a5b2262696c6c696e673a726566756e64225d7d2c2263617465676f7279223a2266696e616e6369616c2d6f7065726174696f6e73222c226461746153636f706573223a5b22637573746f6d65722e62696c6c696e67222c22637573746f6d65722e636f6e74616374225d2c2265677265737353636f706573223a5b226170692e7374726970652e636f6d222c22686f6f6b732e696e7465726e616c2e61636d652e636f6d225d2c2273746174656d656e74223a2250726f63657373657320637573746f6d65722062696c6c696e6720696e7175697269657320616e642069737375657320726566756e647320757020746f20612073757065727669736f722d736574206c696d69742e20e58c97e4baac222c227461736b53636f706573223a5b2262696c6c696e673a696e7175697279222c2262696c6c696e673a726566756e64225d2c22766f63616256657273696f6e223a2231227d2c22657870697265734174223a22323039392d31322d33315432333a35393a35395a222c226973737565644174223a22323032362d30352d32335430303a30303a30305a222c22697373756572436861696e223a5b226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f72672d726f6f74222c226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267225d2c22697373756572446964223a226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267222c227075626c6973686572223a226f70656e6132612d636f6e666f726d616e6365222c227075626c6973686572446964223a226469643a6f70656e6132613a7075626c69736865723a6f70656e6132612d636f6e666f726d616e6365222c227363616e53756d6d617279223a7b22637269746963616c46696e64696e6773223a302c2263727970746f5365727665223a226e6f2d7765616b2d63727970746f222c226869676846696e64696e6773223a302c22686d61223a22706173736564222c226f6173624c6576656c223a224c31222c227365637265746c657373223a22636c65616e227d2c2274727573744c6576656c223a342c22747275737453636f7265223a2238372e353030303030222c2276657273696f6e223a22312e302e30227d"

// fixedClock pins the verifier clock for the entire suite. Valid fixtures
// have ExpiresAt later than this; the expired fixture has ExpiresAt earlier.
const fixedClockRFC3339 = "2026-05-24T00:00:00Z"

// outDir is the conformance repo root, derived at run time relative to this
// generator's location.
var outDir string

// ATCSignature mirrors the production domain type in opena2a-registry
// internal/domain (ATCSignature) verbatim.
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
// (opena2a-registry/internal/domain, AgentTrustCredential) so that encoded JSON byte
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
	TransparencyLogIndex *int64                `json:"transparencyLogIndex,omitempty"`
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

// canonicalPayload reproduces opena2a-registry/pkg/atcverify canonicalPayload()
// VERBATIM. Any divergence here breaks signature interop with the production
// verifier. The 11 signed fields are: agentId, agentDid, version, contentHash,
// buildAttestation, issuerDid, trustLevel, trustScore, issuedAt, expiresAt,
// atcVersion. Notably, the signature does NOT cover capabilities,
// behavioralProfile, scanSummary, signatures, revoked, revokedAt,
// revocationReason, transparencyLogIndex, publisher, publisherDid, agentDid
// (wait, agentDid IS included). See docs/scope.md
// §"Canonicalization: v1.0 signs 11 fields; v1.1 signs JCS(TBS)".
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
// declaredPurpose TBS member (atx-spec §1.3a.2 rule 5, degenerate inputs pinned
// per issue #11), mirrored in ../verifiers: emptiness is a JSON-parse-level
// property — absent, null, or any serialization of the empty object (including
// whitespace variants like `{ }`) normalizes to nil so omitempty drops it from
// the TBS, keeping a no-purpose credential byte-identical to one issued before
// the field existed. ANY other value — including non-object values — passes
// through verbatim, so unsigned injected purpose content breaks the signature
// instead of being silently normalized away.
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
// needs: the requirement it tests, spec refs, expected outcome, verifier
// configuration.
type Fixture struct {
	Schema        string          `json:"$schema"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Requirement   string          `json:"requirement"`
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
	// RequiredSignatures is the k of a k-of-n signature threshold: the number
	// of distinct Ed25519 keys whose signatures must verify. Zero is left out,
	// so a fixture that sets no threshold carries no such member.
	RequiredSignatures int  `json:"requiredSignatures,omitempty"`
	CRL                *CRL `json:"crl,omitempty"`
}

// CRL is the same shape as opena2a-registry/pkg/atcverify CRL.
type CRL struct {
	Version    int        `json:"version"`
	IssuedAt   time.Time  `json:"issuedAt"`
	NextUpdate time.Time  `json:"nextUpdate"`
	Entries    []CRLEntry `json:"entries"`
	Signature  string     `json:"signature"`
}

// CRLEntry is the same shape as opena2a-registry/pkg/atcverify CRLEntry.
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
// irrelevant). Capabilities (db:read, db:write) cover the
// capabilityJustification keys, per atx-spec §1.5.2.
const presentDeclaredPurpose = `{
  "vocabVersion": "1",
  "statement": "Processes customer billing inquiries and issues refunds up to a supervisor-set limit. 北京",
  "category": "financial-operations",
  "taskScopes": ["billing:inquiry", "billing:refund"],
  "capabilityJustification": {
    "db:read": ["billing:inquiry"],
    "db:write": ["billing:refund"]
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
	secondary := mustLoadKeyVector("vectors/issuer-secondary.json")
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

	// Cross-issuer verifier state: trusts BOTH the primary authority AND a second,
	// unrelated authority (secondary), and publishes the secondary's key. Used by
	// the cross-issuer-key fixtures to prove a verifier binds each signature to a
	// key controlled by the credential's issuer — so one trusted authority cannot
	// impersonate another (key↔issuer binding, atx-spec core.md §1 steps 3-4).
	crossIssuerVerifierState := defaultVerifierState
	crossIssuerVerifierState.TrustedIssuers = []string{primary.IssuerDID, secondary.IssuerDID}
	crossIssuerVerifierState.PublicKeys = append(append([]KeypairRef{},
		defaultVerifierState.PublicKeys...),
		keypairRefFor(secondary, "vectors/issuer-secondary.json"))

	// Untrusted-chain verifier state: trusts ONLY the primary authority as an
	// issuer, but its configured public keys also carry the untrusted
	// authority's key under a DID-URL keyId (the multi-issuer anchor shape).
	// Used by the untrusted-chain-authority fixture to prove a verifier
	// intersects the signed v1.1 issuerChain with its trusted issuers before
	// treating a chain DID as a key-eligible authority: a chain DID that is
	// not a trusted issuer contributes no eligible key.
	untrustedChainVerifierState := defaultVerifierState
	untrustedChainVerifierState.PublicKeys = append(append([]KeypairRef{},
		defaultVerifierState.PublicKeys...),
		keypairRefFor(untrusted, "vectors/issuer-untrusted.json"))

	// Threshold verifier state: the default state, which holds the issuer's
	// three Ed25519 keys (primary and two cosigners), requiring the signatures
	// of two of them (core.md section 3.1 step 8: cosignatures from 2 of 3 key
	// holders). Used by the threshold-1of3-cosignature fixture.
	thresholdVerifierState := defaultVerifierState
	thresholdVerifierState.RequiredSignatures = 2

	// Revoking verifier state: the default state plus a CRL whose one entry
	// names the test agent, issued before the pinned clock and not yet due for
	// its next update. Used by both revocation fixtures.
	revokingVerifierState := defaultVerifierState
	revokingVerifierState.CRL = &CRL{
		Version:    1,
		IssuedAt:   mustParseTime("2026-05-23T12:00:00Z"),
		NextUpdate: mustParseTime("2026-05-30T12:00:00Z"),
		Entries: []CRLEntry{{
			AgentID:   testAgentID,
			RevokedAt: revokedTime,
			Reason:    "key compromise (test)",
		}},
		Signature: "TEST_ONLY_UNSIGNED_CRL",
	}

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
				"An ATX v1.0 credential carrying both an Ed25519 signature and an ML-DSA-65 signature over the same canonical payload. This is the hybrid signing path the ATX v1.0 spec mandates. A spec-conformant verifier MUST verify BOTH signatures and ACCEPT only when both are valid. The ML-DSA-65 signature value is a raw FIPS 204 ML-DSA-65 signature (3309 bytes decoded) over the same canonical bytes as the Ed25519 signature; no container or combined-blob framing is used.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					{Role: mldsa.Role, Path: "vectors/mldsa65-seed.json", Algorithm: mldsa.Algorithm, PublicKeyHex: mldsa.PublicKeyHex, KeyID: mldsa.KeyID},
				},
				hybridVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/hybrid-pq-only.json", func() Fixture {
			// The missing-classical-companion control under atcVersion 1.0.
			// The v1.0 hybrid baseline with the Ed25519 entry removed, so the
			// credential carries one ML-DSA-65 signature that verifies over
			// the legacy canonical bytes. core.md section 13 (Cryptographic
			// agility) requires a credential that declares an ML-DSA-65 entry
			// to also carry a verifying Ed25519 entry, and names no
			// atcVersion. fixtures/v1_1-hybrid-pq-only.json pins the rule
			// under atcVersion 1.1, so without this fixture a verifier that
			// applies it to v1.1 alone passes the suite.
			atx := newBaselineATX()
			pq, _ := signMLDSA65(mldsa.SeedHex, canonicalPayload(&atx))
			pq.KeyID = mldsa.KeyID
			atx.Signatures = []ATCSignature{pq}
			return wrap("atx-v1/hybrid-pq-only",
				"An ATX v1.0 credential carrying a single ML-DSA-65 signature that verifies over the legacy canonical payload, and no Ed25519 signature: the v1.0 hybrid baseline with its Ed25519 entry removed. The spec requires a credential that declares an ML-DSA-65 entry to also carry a verifying Ed25519 entry, and names no atcVersion, so a post-quantum signature alone cannot verify a v1.0 credential either. Verifier MUST REJECT with a signature-validation reason. A verifier that checks only that every declared signature verifies, or that applies the rule to atcVersion 1.1 alone, wrongly ACCEPTs.",
				[]KeypairRef{
					{Role: mldsa.Role, Path: "vectors/mldsa65-seed.json", Algorithm: mldsa.Algorithm, PublicKeyHex: mldsa.PublicKeyHex, KeyID: mldsa.KeyID},
				},
				hybridVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/revoked.json", func() Fixture {
			atx := newBaselineATX()
			atx.Signatures = []ATCSignature{signWithKey(primary, atx)}
			// The fixture populates both the revoked flag and a CRL entry, but
			// it pins the flag only: both reference verifiers read the flag
			// first and return, and reasonContains "revoked" is not met by a
			// rejection that names the CRL. fixtures/revoked-crl-only.json is
			// the fixture whose verdict depends on the CRL.
			atx.Revoked = true
			rt := revokedTime
			atx.RevokedAt = &rt
			atx.RevocationReason = "key compromise (test)"
			return wrap("atx-v1/revoked",
				"A previously-valid ATX whose credential-level Revoked flag is set and whose AgentID also appears in the verifier's CRL. Verifier MUST REJECT with revocation reason. The flag is what rejects it in both reference verifiers, which read the flag before the CRL and return on it; fixtures/revoked-crl-only.json is the fixture whose verdict depends on the CRL.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				revokingVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "REVOKED", ReasonContains: "revoked"},
				atx)
		}},
		{"fixtures/revoked-crl-only.json", func() Fixture {
			// The credential is the accepted baseline, byte for byte: revoked
			// is false and it carries no revokedAt or revocationReason. Its
			// agentId on the verifier's CRL is the only thing that revokes it
			// (core.md §1.3 step 6), so a verifier that reads the credential's
			// own flag and never consults the CRL accepts it.
			atx := newBaselineATX()
			atx.Signatures = []ATCSignature{signWithKey(primary, atx)}
			return wrap("atx-v1/revoked-crl-only",
				"An ATX v1.0 credential whose own revoked flag is false and whose AgentID appears in the verifier's CRL. It is the accepted baseline in every other respect: a trusted issuer, unexpired, one Ed25519 signature that verifies. CRL membership is the only thing that revokes it, so a verifier that reads the credential's revoked flag and never consults the CRL wrongly accepts. The flag is outside the signed bytes of both signing forms, so it can be cleared on a revoked credential without breaking the signature; the CRL entry cannot. Verifier MUST REJECT with a revocation reason that names the CRL.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				revokingVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "REVOKED", ReasonContains: "CRL"},
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
		{"fixtures/threshold-1of3-cosignature.json", func() Fixture {
			// The threshold-2of3-cosignature credential cut to the first of
			// its three signatures, the primary's, under a verifier state that
			// requires two of the three keys (atx-conformance#132). The one
			// signature verifies, so a verifier that checks only that every
			// declared signature verifies, and reads no threshold, accepts it.
			atx := newBaselineATX()
			atx.TrustLevel = 4
			atx.IssuerChain = []string{primary.IssuerDID, "did:opena2a:authority:opena2a.org-root"}
			atx.Signatures = []ATCSignature{signWithKey(primary, atx)}
			return wrap("atx-v1/threshold-1of3-cosignature",
				"The threshold-2of3-cosignature credential cut to one of its three signatures, the primary's, under a verifier state that holds the issuer's three Ed25519 keys and requires two of them (requiredSignatures: 2). The one signature verifies, so a verifier that checks only that every declared signature verifies, and reads no threshold, wrongly accepts. Verifier MUST REJECT with a threshold reason.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				thresholdVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "threshold"},
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
				"An ATX whose atcVersion claims a version (2.0) that is not the v1.0 supported by this conformance suite. Verifier MUST REJECT at step 1 (schema-version check) with an unsupported-version reason. NOTE: the signature is computed over v1.0 canonical bytes, whose eleventh field is the literal \"1.0\" independent of the credential's atcVersion field; the fixture is otherwise well formed so that a verifier can demonstrate it rejects on the schema-version check alone.",
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
		{"fixtures/v1_1-no-transparency-log-index.json", func() Fixture {
			// The optionality control. atx-spec §1.1 makes transparencyLogIndex
			// optional: it is the log-assigned index of the issuance entry, set
			// after signing and outside both signing forms, and a verifier MUST
			// NOT read it as evidence of log inclusion. Every other fixture
			// carries it, so without this one a verifier that still REQUIRES the
			// field passes the whole suite unchanged.
			atx := newBaselineV11ATX()
			atx.TransparencyLogIndex = nil
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/no-transparency-log-index",
				"An ATX v1.1 credential that omits the optional transparencyLogIndex. The field is assigned by the log after signing and is outside JCS(TBS), so its absence changes no canonical bytes and no signature; this credential's JCS(TBS) is byte-identical to the v1.1 baseline's. Verifier MUST ACCEPT. A verifier that requires the field, or that reads its presence as evidence of transparency-log inclusion, wrongly REJECTs.",
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
		{"fixtures/v1_1-hybrid-mldsa-tampered.json", func() Fixture {
			// The forged-post-quantum control. The hybrid baseline with the
			// Ed25519 signature entry left intact and one bit of the ML-DSA-65
			// signature value flipped after signing (the tampered-signature.json
			// recipe applied to the post-quantum entry). A verifier that
			// verifies both declared suites MUST REJECT; a verifier that only
			// records the ML-DSA-65 entry as present wrongly ACCEPTs on the
			// strength of the intact Ed25519 signature.
			atx := newBaselineV11ATX()
			ed := signV11WithKey(primary, atx)
			pq, _ := signMLDSA65(mldsa.SeedHex, canonicalPayloadV11(&atx))
			pq.KeyID = mldsa.KeyID
			tampered, err := base64.StdEncoding.DecodeString(pq.Value)
			must(err)
			tampered[0] ^= 0x01
			pq.Value = base64.StdEncoding.EncodeToString(tampered)
			atx.Signatures = []ATCSignature{ed, pq}
			return wrap("atx-v1_1/hybrid-mldsa-tampered",
				"An ATX v1.1 hybrid credential whose Ed25519 signature is intact and whose ML-DSA-65 signature has been flipped by one bit after signing. The spec mandates that every declared signature verifies, so the forged post-quantum entry MUST fail verification even though the classical entry is valid. Verifier MUST REJECT with a signature-validation reason. A verifier that records ML-DSA-65 signatures as present without verifying them wrongly ACCEPTs.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					{Role: mldsa.Role, Path: "vectors/mldsa65-seed.json", Algorithm: mldsa.Algorithm, PublicKeyHex: mldsa.PublicKeyHex, KeyID: mldsa.KeyID},
				},
				hybridVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-hybrid-pq-only.json", func() Fixture {
			// The missing-classical-companion control. The hybrid baseline
			// with the Ed25519 entry removed, so the credential carries one
			// ML-DSA-65 signature that verifies. core.md section 13
			// (Cryptographic agility) requires a credential that declares an
			// ML-DSA-65 entry to also carry a verifying Ed25519 entry. A
			// verifier that checks only that every declared signature verifies
			// wrongly ACCEPTs.
			atx := newBaselineV11ATX()
			pq, _ := signMLDSA65(mldsa.SeedHex, canonicalPayloadV11(&atx))
			pq.KeyID = mldsa.KeyID
			atx.Signatures = []ATCSignature{pq}
			return wrap("atx-v1_1/hybrid-pq-only",
				"An ATX v1.1 credential carrying a single ML-DSA-65 signature that verifies over JCS(TBS), and no Ed25519 signature. The spec requires a credential that declares an ML-DSA-65 entry to also carry a verifying Ed25519 entry, so a post-quantum signature alone cannot verify a credential. Verifier MUST REJECT with a signature-validation reason. A verifier that checks only that every declared signature verifies wrongly ACCEPTs.",
				[]KeypairRef{
					{Role: mldsa.Role, Path: "vectors/mldsa65-seed.json", Algorithm: mldsa.Algorithm, PublicKeyHex: mldsa.PublicKeyHex, KeyID: mldsa.KeyID},
				},
				hybridVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
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
			atx.Capabilities = []string{"db:read", "db:write", "system:exec"}
			return wrap("atx-v1_1/tampered-capabilities",
				"An ATX v1.1 credential whose capabilities were escalated to include system:exec AFTER signing. Because v1.1 signs JCS(TBS), capabilities are covered by the signature; the verifier recomputes the canonical bytes, finds they no longer match, and MUST REJECT with a signature-validation reason. This is the integrity property v1.0 lacked.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-scan-summary-member-outside-type.json", func() Fixture {
			// A SCANSUMMARY MEMBER OUTSIDE ITS TYPE. Sign the baseline, whose
			// scanSummary.criticalFindings is 0, then write that member as the
			// JSON string "3" AFTER signing (postWrite, below: ATCScanSummary
			// holds the count as an int, so the string is written at the byte
			// level). The TBS holds criticalFindings as an integer (§1.3a.2
			// rule 2), so no signature covers the string. A verifier that
			// leaves a member it cannot decode at its zero value projects the
			// signed 0 and wrongly ACCEPTs a credential carrying a count its
			// signature does not cover.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/scan-summary-member-outside-type",
				"An ATX v1.1 credential signed with scanSummary.criticalFindings 0, carrying the JSON string \"3\" in that member, written AFTER signing. v1.1 signs JCS(TBS), which holds each scanSummary member with its type, criticalFindings as an integer (atx-spec §1.3a.2 rule 2), so no signature covers a string there. The verifier MUST REJECT with a signature-validation reason. A verifier that leaves a member it cannot decode at its zero value projects the signed 0 and wrongly ACCEPTs a credential carrying a count its signature does not cover.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-integer-outside-exact-range.json", func() Fixture {
			// A TBS INTEGER OUTSIDE THE I-JSON EXACT RANGE. The baseline with
			// scanSummary.criticalFindings 2^53+1, signed over its JCS(TBS)
			// as canonicalPayloadV11 writes it. The JCS library reads each
			// number as an IEEE 754 double, which does not hold 2^53+1, and
			// writes the count as 9007199254740992 (2^53), the bytes it
			// writes for a credential carrying 2^53 too. A verifier that
			// canonicalizes the count the same way verifies the signature
			// and wrongly ACCEPTs a count its signature does not cover.
			atx := newBaselineV11ATX()
			atx.ScanSummary.CriticalFindings = 1<<53 + 1
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/integer-outside-exact-range",
				"An ATX v1.1 credential carrying scanSummary.criticalFindings 9007199254740993, which is 2^53+1 and outside the I-JSON exact range, -(2^53-1) to 2^53-1 (RFC 7493 §2.2). Its Ed25519 signature covers JCS(TBS) as an RFC 8785 serializer that reads each number as an IEEE 754 double writes it, with criticalFindings 9007199254740992: the bytes that serializer writes for a credential carrying 9007199254740992 too. The signature does not tell the two counts apart, so it does not cover the count this credential carries (atx-spec §1.3a.2 rule 3 keeps RFC 8785 number serialization out of cross-language scope). The verifier MUST REJECT with a signature-validation reason. A verifier that canonicalizes the count as that serializer does verifies the signature and wrongly ACCEPTs a count its signature does not cover.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		// ---- behavioralProfile form (§1.1 schema, §1.3a.2 rule 1, atx-conformance#277) ----
		{"fixtures/v1_1-behavioral-profile-extra-member.json", func() Fixture {
			// A MEMBER OUTSIDE THE THREE. Sign the baseline, whose
			// behavioralProfile holds checksum, generatedAt and
			// observationDays, then add a fourth member, riskLevel "low",
			// AFTER signing (postWrite, below: ATCBehavioralProfile has no
			// field for it, so it is written at the byte level). The
			// credential schema gives behavioralProfile those three members
			// and no other, so the TBS has no value for this profile and no
			// signature covers it. A verifier that decodes the profile into
			// its three fields drops the fourth, projects the signed profile
			// and wrongly ACCEPTs.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/behavioral-profile-extra-member",
				"An ATX v1.1 credential signed with the baseline behavioralProfile (checksum, generatedAt, observationDays), carrying a fourth member in it, riskLevel \"low\", written AFTER signing. The credential schema of atx-spec §1.1 gives behavioralProfile exactly those three members (additionalProperties false), and JCS(TBS) holds the profile as those three members (§1.3a.2), so no signature covers a profile with a fourth. The verifier MUST REJECT with a signature-validation reason. A verifier that decodes the profile into its three fields drops the fourth member, projects the signed profile and wrongly ACCEPTs a credential carrying a member its signature does not cover.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-behavioral-profile-case-variant-member.json", func() Fixture {
			// A NAME IN ANOTHER CASE. Sign the baseline, then rename its
			// behavioralProfile.observationDays to OBSERVATIONDAYS AFTER
			// signing, the value 14 unchanged (postWrite, below). Member
			// names are compared exactly, so the profile lacks
			// observationDays and carries a member outside the three. Go's
			// encoding/json matches the name to the observationDays field
			// case-insensitively, so a verifier that decodes the profile
			// into a struct projects the signed profile and wrongly ACCEPTs.
			// The renamed member stands alone, so the fold-aware duplicate
			// check does not reject it.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/behavioral-profile-case-variant-member",
				"An ATX v1.1 credential signed with the baseline behavioralProfile, carrying its observationDays member under the name OBSERVATIONDAYS, value unchanged (14), renamed AFTER signing. Member names are compared exactly, and the credential schema of atx-spec §1.1 gives behavioralProfile exactly checksum, generatedAt and observationDays (additionalProperties false), so this profile lacks observationDays and carries a member outside the three: JCS(TBS) has no value for it (§1.3a.2) and no signature covers it. The verifier MUST REJECT with a signature-validation reason. Go's encoding/json matches a member name to a struct field case-insensitively, so a verifier that decodes the profile into a struct reads OBSERVATIONDAYS as observationDays, projects the signed profile and wrongly ACCEPTs, while a case-sensitive reader of the same bytes finds no observationDays. The renamed member is the only one of its name, so a duplicate-member check does not reject it.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-behavioral-profile-not-object.json", func() Fixture {
			// A PROFILE THAT IS NOT AN OBJECT, on a credential signed with
			// none. Sign the baseline with no behavioralProfile, whose TBS
			// holds null there (§1.3a.2 rule 1), then add the JSON string
			// "sha256:ghi789" as its behavioralProfile AFTER signing
			// (postWrite, below). A verifier that projects a profile it
			// cannot decode as null, the absent form, reaches the bytes the
			// signature covers and wrongly ACCEPTs.
			atx := newBaselineV11ATX()
			atx.BehavioralProfile = nil
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/behavioral-profile-not-object",
				"An ATX v1.1 credential signed with no behavioralProfile, carrying the JSON string \"sha256:ghi789\" as its behavioralProfile, added AFTER signing. JCS(TBS) holds null for a credential with no profile (atx-spec §1.3a.2 rule 1) and otherwise an object of the profile's three members (the credential schema of §1.1), so no signature covers a profile that is not an object. The verifier MUST REJECT with a signature-validation reason. A verifier that projects a profile it cannot decode as null, the absent form, reaches the bytes the signature covers and wrongly ACCEPTs a credential carrying a profile its signature does not cover.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-behavioral-profile-member-outside-type.json", func() Fixture {
			// A PROFILE MEMBER OUTSIDE ITS TYPE, on a credential signed with
			// no profile. Sign the baseline with no behavioralProfile, then
			// carry the baseline's profile with observationDays written as
			// the JSON string "14" (postWrite, below: ATCBehavioralProfile
			// holds the count as an int). The TBS holds null for a
			// credential with no profile and otherwise observationDays as an
			// integer, so no signature covers this profile. A verifier that
			// projects a profile it cannot decode as null reaches the bytes
			// the signature covers and wrongly ACCEPTs.
			atx := newBaselineV11ATX()
			unsigned := atx
			unsigned.BehavioralProfile = nil
			atx.Signatures = []ATCSignature{signV11WithKey(primary, unsigned)}
			return wrap("atx-v1_1/behavioral-profile-member-outside-type",
				"An ATX v1.1 credential signed with no behavioralProfile, carrying one added AFTER signing whose observationDays is the JSON string \"14\", not an integer; its checksum and generatedAt are the baseline's. JCS(TBS) holds null for a credential with no profile (atx-spec §1.3a.2 rule 1) and otherwise the profile's three members with their types (the credential schema of §1.1: observationDays an integer), so no signature covers a profile with a string there. The verifier MUST REJECT with a signature-validation reason. A verifier that projects a profile it cannot decode as null, the absent form, reaches the bytes the signature covers and wrongly ACCEPTs a credential carrying a profile its signature does not cover.",
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
		{"fixtures/cross-issuer-key.json", func() Fixture {
			// KEY↔ISSUER BINDING. The credential is issued by the primary
			// authority (issuerDid = opena2a.org) but is signed by the SECONDARY
			// authority's key. The secondary is independently trusted and its key
			// is in the verifier's set, and the signature is cryptographically
			// valid over the canonical payload (which commits to issuerDid =
			// opena2a.org). A naive verifier that tries every configured key would
			// ACCEPT, letting one trusted authority impersonate another. A
			// spec-conformant verifier binds each signature to a key controlled by
			// the credential's issuer (the keyId's controller DID must be the
			// issuer, or for v1.1 a signed issuerChain authority that is also a
			// trusted issuer) and MUST REJECT:
			// the secondary's key is not controlled by opena2a.org and is not in
			// the issuerChain, so no eligible key verifies.
			atx := newBaselineATX()
			atx.Signatures = []ATCSignature{signWithKey(secondary, atx)}
			return wrap("atx-v1/cross-issuer-key",
				"An ATX v1.0 credential issued by the primary authority (issuerDid = did:opena2a:authority:opena2a.org) but signed by a DIFFERENT trusted authority's key (did:opena2a:authority:partner.example#key-1). The signature is valid over the canonical payload and the signing authority is independently trusted, yet that key is not controlled by the credential's issuer and is not in its issuerChain. A verifier MUST bind each signature to a key controlled by the credential's issuer and MUST REJECT with a signature-validation reason, so a trusted authority cannot impersonate another. A verifier that tries every configured key would wrongly ACCEPT.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(secondary, "vectors/issuer-secondary.json"),
				},
				crossIssuerVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-cross-issuer-key.json", func() Fixture {
			// Same key↔issuer-binding property under v1.1 (signs JCS(TBS)). The
			// issuerChain is signed in v1.1, but the secondary authority is NOT in
			// it, so its key is still not an eligible signer for this credential.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(secondary, atx)}
			return wrap("atx-v1_1/cross-issuer-key",
				"An ATX v1.1 credential issued by the primary authority but signed by a different trusted authority's key (partner.example). The secondary authority is trusted and its key is configured, and the signature is valid over JCS(TBS), but the secondary is neither the issuer nor present in the signed issuerChain. A spec-conformant verifier binds each signature to a key controlled by the issuer, or by an authority that is both named in the signed issuerChain and in the verifier's trusted issuers, and MUST REJECT with a signature-validation reason.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(secondary, "vectors/issuer-secondary.json"),
				},
				crossIssuerVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-untrusted-chain-authority.json", func() Fixture {
			// UNTRUSTED CHAIN AUTHORITY. The credential claims issuerDid = the
			// primary (trusted) authority and a signed issuerChain that names
			// the primary AND the untrusted authority (attacker.example). It is
			// signed ONLY by the untrusted key, over JCS(TBS), so the chain that
			// names the signer is inside the signed bytes. The untrusted key is
			// in the verifier's configured public keys under a DID-URL keyId,
			// but attacker.example is NOT in trustedIssuers. A verifier that
			// derives the eligible-key authority set from the credential's own
			// issuerChain ACCEPTs: the chain names the signer's DID and the
			// signer's key is configured. That chain is signed by the very key
			// whose eligibility is in question, so it cannot vouch for that
			// key. A chain DID that is not a trusted issuer contributes no
			// eligible key, so no configured key verifies the signature and
			// the verifier MUST REJECT with a signature-validation reason.
			atx := newBaselineV11ATX()
			atx.IssuerChain = []string{primary.IssuerDID, untrusted.IssuerDID}
			atx.Signatures = []ATCSignature{signV11WithKey(untrusted, atx)}
			return wrap("atx-v1_1/untrusted-chain-authority",
				"An ATX v1.1 credential whose issuerDid is the primary authority (did:opena2a:authority:opena2a.org) and whose signed issuerChain names the primary authority and an untrusted authority (did:opena2a:authority:attacker.example). It carries one Ed25519 signature made ONLY by the untrusted authority's key over JCS(TBS), so the chain that names the signer is inside the signed bytes. The verifier trusts only the primary authority as an issuer, but the untrusted key is present in its configured public keys under a DID-URL keyId. A verifier that derives the eligible signing authorities from the credential's own issuerChain wrongly ACCEPTs: the chain names the signer's DID and the signer's key is configured. That chain is signed by the very key whose eligibility is in question, so it cannot vouch for that key. A signature verifies only against a key resolved for an authority the verifier trusts for this credential: the issuerDid, or an authority that is both named in the signed issuerChain and in the verifier's trusted issuers. A chain DID that is not a trusted issuer contributes no eligible key, so no configured key verifies the signature and the verifier MUST REJECT with a signature-validation reason.",
				[]KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(untrusted, "vectors/issuer-untrusted.json"),
				},
				untrustedChainVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		// ---- degenerate declaredPurpose pins (issue #11, §1.3a.2 rule 5) ----
		{"fixtures/v1_1-declared-purpose-empty-whitespace.json", func() Fixture {
			// MALLEABILITY, PINNED BENIGN. Sign WITHOUT declaredPurpose, then
			// append a whitespace-empty object AFTER signing (the postWrite
			// transform keeps the interior space in the file bytes, which
			// encoding/json would otherwise normalize). Emptiness is decided at
			// the JSON parse level: `{ }` IS the empty object, treated as
			// absent and omitted from the TBS, so the recomputed canonical
			// bytes still match. Verifier MUST ACCEPT.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			atx.DeclaredPurpose = json.RawMessage("{}")
			return wrap("atx-v1_1/declared-purpose-empty-whitespace",
				"An ATX v1.1 credential signed with no declaredPurpose, carrying a whitespace-empty declaredPurpose object ({ }) appended after signing. Emptiness is a JSON-parse-level property (atx-spec \u00a71.3a.2 rule 5): any serialization of the empty object is the empty object, treated as absent and omitted from the TBS, so the signature still verifies. Verifier MUST ACCEPT. A verifier that compares the raw byte string against \"{}\" instead of parsing wrongly includes the value and REJECTs.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "ACCEPT"},
				atx)
		}},
		{"fixtures/v1_1-declared-purpose-array-injected.json", func() Fixture {
			// UNSIGNED INJECTION. Sign WITHOUT declaredPurpose, then append a
			// non-object (array) value AFTER signing. Rule 5 requires any
			// present non-empty value — including non-objects — to enter the
			// TBS verbatim, so the recomputed bytes no longer match. Verifier
			// MUST REJECT. A verifier that silently omits non-object values
			// (the pre-#11 Python reference) wrongly ACCEPTs a credential
			// carrying unsigned purpose content.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			atx.DeclaredPurpose = json.RawMessage(`["billing:inquiry", "act-autonomously"]`)
			return wrap("atx-v1_1/declared-purpose-array-injected",
				"An ATX v1.1 credential signed with no declaredPurpose, carrying an attacker-appended ARRAY declaredPurpose value. Non-object values are included in the TBS verbatim (atx-spec \u00a71.3a.2 rule 5), so the recomputed canonical bytes no longer match the signature and the verifier MUST REJECT with a signature-validation reason. A verifier that normalizes non-object values away would accept unsigned purpose content riding a valid signature.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-declared-purpose-string-injected.json", func() Fixture {
			// Same injection with a STRING value.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			atx.DeclaredPurpose = json.RawMessage(`"customer-support"`)
			return wrap("atx-v1_1/declared-purpose-string-injected",
				"An ATX v1.1 credential signed with no declaredPurpose, carrying an attacker-appended STRING declaredPurpose value. Non-object values are included in the TBS verbatim (atx-spec \u00a71.3a.2 rule 5), so the recomputed canonical bytes no longer match the signature and the verifier MUST REJECT with a signature-validation reason.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		{"fixtures/v1_1-declared-purpose-number-injected.json", func() Fixture {
			// Same injection with a NUMBER value that is not an integer
			// (atx-conformance#130). JCS writes it with the number
			// serialization of RFC 8785 section 3.2.2.3, which a serializer
			// that handles integers only does not implement. Such a verifier
			// has no canonical bytes for a signature to verify over, and the
			// fixture holds it to the same REJECT, not to an error that ends
			// its run without a verdict.
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			atx.DeclaredPurpose = json.RawMessage(`1.5`)
			return wrap("atx-v1_1/declared-purpose-number-injected",
				"An ATX v1.1 credential signed with no declaredPurpose, carrying an attacker-appended NUMBER declaredPurpose value, 1.5, which is not an integer. Non-object values are included in the TBS verbatim (atx-spec \u00a71.3a.2 rule 5), so the recomputed canonical bytes no longer match the signature and the verifier MUST REJECT with a signature-validation reason. JCS writes a number that is not an integer with the number serialization of RFC 8785 \u00a73.2.2.3; a verifier whose serializer does not implement it has no canonical bytes for a signature to verify over, and its expected outcome is the same REJECT.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "signature"},
				atx)
		}},
		// ---- duplicate-member strict parse (issue opena2a-registry#305) ----
		{"fixtures/v1_1-duplicate-purpose-member.json", func() Fixture {
			// DUPLICATE-MEMBER SMUGGLING. Sign the honest purpose (category
			// financial-operations), then inject a DECOY duplicate `category`
			// member BEFORE the signed one in the raw credential bytes. RFC 8259
			// \u00a74 leaves duplicate names undefined: a last-wins parser collapses
			// to the signed content, so the signature VERIFIES over smuggled
			// bytes; a first-wins parser sees the decoy and fails the signature
			// with the wrong category. The whole ATX credential feeds signed
			// canonical forms (v1.1 JCS(TBS); v1.0 pipe fields) \u2014 there is no
			// layer with sanctioned last-wins semantics \u2014 so verifiers MUST
			// strict-parse the credential and reject duplicate members at any
			// depth as PARSE_ERROR before interpreting any field.
			atx := newBaselineV11ATX()
			atx.DeclaredPurpose = json.RawMessage(presentDeclaredPurpose)
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			atx.DeclaredPurpose = json.RawMessage(strings.Replace(presentDeclaredPurpose,
				`"category":`, `"category": "customer-support", "category":`, 1))
			return wrap("atx-v1_1/duplicate-purpose-member",
				"An ATX v1.1 credential whose declaredPurpose bytes contain the category member twice: a decoy (customer-support) followed by the signed value (financial-operations). The Ed25519 signature is REAL and covers the last-wins interpretation, so a lenient last-wins parser sees a verifying credential while a first-wins parser sees different content \u2014 the classic RFC 8259 \u00a74 duplicate-member smuggling split. Because the entire ATX credential feeds the signed canonical form (JCS(TBS), \u00a71.3a.2), verifiers MUST strict-parse the credential object and REJECT duplicate members at any depth with PARSE_ERROR, before interpreting any field. A verifier that parses last-wins without a duplicate check wrongly ACCEPTs; a first-wins verifier rejects with the wrong category (SIGNATURE_INVALID).",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "PARSE_ERROR", ReasonContains: "duplicate"},
				atx)
		}},
		// ---- case-variant member (fold-collapse) strict parse (atx-conformance#16) ----
		{"fixtures/v1_1-case-variant-member.json", func() Fixture {
			// CASE-VARIANT SMUGGLING (fold collapse). Sign the honest baseline
			// (trustLevel 4). A decoy top-level `TRUSTLEVEL` member (9) is injected
			// into the raw credential bytes AFTER signing (postWrite, below):
			// encoding/json can't emit two case-variant struct fields, so the decoy
			// is added at the byte level. TRUSTLEVEL and trustLevel fold to the same
			// field. Go's encoding/json resolves struct fields case-insensitively
			// last-wins, so `{"TRUSTLEVEL":9,...,"trustLevel":4}` collapses to
			// trustLevel=4 — the SIGNED value — and a lenient Go verifier ACCEPTs,
			// silently carrying a stray fold-colliding TRUSTLEVEL member. The same
			// bytes read differently under other conforming parsers: a
			// case-insensitive FIRST-wins parser reads 9, and a case-sensitive parser
			// (this suite's Python json.loads) keeps both as distinct members,
			// reading trustLevel=4 alongside a separate TRUSTLEVEL=9. A
			// case-SENSITIVE duplicate check flags neither. Because encoding/json's
			// field folding makes the credential mean different things to different
			// conforming parsers — the RFC 8259 §4 first-wins/last-wins divergence
			// the strict parse exists to close — verifiers MUST fold member names and
			// REJECT fold-colliding members as PARSE_ERROR before interpreting any
			// field (foldKey in verifiers/{go,python}).
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/case-variant-member",
				"An ATX v1.1 credential carrying a decoy top-level TRUSTLEVEL member (value 9) injected before the signed trustLevel member (value 4) — two names that fold to the same field. Go's encoding/json resolves struct fields case-insensitively last-wins, so it collapses the pair to the signed trustLevel=4: a lenient Go verifier ACCEPTs, silently carrying a stray fold-colliding TRUSTLEVEL member. The same bytes read differently under other conforming parsers: a case-insensitive first-wins parser reads 9, and a case-sensitive parser (this suite's Python json.loads) keeps both as distinct members, reading trustLevel=4 alongside a separate TRUSTLEVEL=9. A case-SENSITIVE duplicate check flags neither. Because encoding/json's field folding makes the credential mean different things to different conforming parsers — the RFC 8259 §4 first-wins/last-wins parser divergence the strict parse exists to close — verifiers MUST fold member names and REJECT fold-colliding members with PARSE_ERROR before interpreting any field. Reference: foldKey in verifiers/go and verifiers/python (atx-conformance#16).",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "PARSE_ERROR", ReasonContains: "duplicate"},
				atx)
		}},
		// ---- member name outside printable ASCII (atx-conformance#284) ----
		// Each signs the v1.1 baseline, then carries one member its issuer did
		// not write, added after signing directly after the signed member its
		// name spells (memberAddedAfter, below): ATX has no field for it.
		// JCS(TBS) holds no member the credential does not specify, so the
		// signature verifies, and a verifier that folds names by ASCII case,
		// or by a table that keeps the dotted capital I and the dotless i
		// apart from i, accepts.
		{"fixtures/v1_1-dotted-capital-i-member.json", func() Fixture {
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/dotted-capital-i-member",
				"An ATX v1.1 credential whose Ed25519 signature verifies, carrying one member its issuer did not write: a member named U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) followed by d, holding x, written directly after its id member once the credential is signed. JCS(TBS) holds no member the credential does not specify, so the signature does not cover it. Java 25's String.equalsIgnoreCase compares that name equal to id, so a relying party that binds the credential's JSON again by such a comparison, keeping the last of the members it joins, reads x as the credential's id, where the verifier read the id the issuer wrote. Verifiers MUST reject a member name outside printable ASCII (U+0020 to U+007E) in an object they decode (the credential, a signature entry, scanSummary or behavioralProfile) as PARSE_ERROR before interpreting any field, a rule that needs no case table. A verifier that folds names by ASCII case, or by a table that keeps U+0130 apart from i, wrongly ACCEPTs.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "PARSE_ERROR", ReasonContains: "printable ASCII"},
				atx)
		}},
		{"fixtures/v1_1-dotless-i-member.json", func() Fixture {
			atx := newBaselineV11ATX()
			atx.Signatures = []ATCSignature{signV11WithKey(primary, atx)}
			return wrap("atx-v1_1/dotless-i-member",
				"An ATX v1.1 credential whose Ed25519 signature verifies, carrying one member its issuer did not write: a member named U+0131 (LATIN SMALL LETTER DOTLESS I) followed by ssuedAt, holding 2099-01-01T00:00:00Z, written directly after its signed issuedAt member once the credential is signed. JCS(TBS) holds no member the credential does not specify, so the signature does not cover it. Java 25's String.equalsIgnoreCase compares that name equal to issuedAt, so a relying party that binds the credential's JSON again by such a comparison, keeping the last of the members it joins, reads an issuedAt of 2099-01-01T00:00:00Z, where the signature covers 2026-05-23T00:00:00Z. Verifiers MUST reject a member name outside printable ASCII (U+0020 to U+007E) in an object they decode (the credential, a signature entry, scanSummary or behavioralProfile) as PARSE_ERROR before interpreting any field, a rule that needs no case table. A verifier that folds names by ASCII case, or by a table that keeps U+0131 apart from i, wrongly ACCEPTs.",
				[]KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				defaultVerifierState,
				ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "PARSE_ERROR", ReasonContains: "printable ASCII"},
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
		if fs.writePath == "fixtures/v1_1-declared-purpose-empty-whitespace.json" {
			// encoding/json normalizes the raw `{ }` to `{}` on marshal; restore
			// the interior whitespace so the on-disk fixture pins the
			// parse-level emptiness rule (issue #11) at the byte level.
			b, err := os.ReadFile(path) //nolint:gosec // G304: file just written above
			must(err)
			replaced := bytes.Replace(b, []byte(`"declaredPurpose": {}`), []byte(`"declaredPurpose": { }`), 1)
			if bytes.Equal(replaced, b) {
				panic("empty-whitespace fixture: substitution target not found")
			}
			//nolint:gosec // G703: build-time tool rewriting the fixture it just wrote under outDir
			must(os.WriteFile(path, replaced, 0o644))
		}
		if fs.writePath == "fixtures/v1_1-case-variant-member.json" {
			// Inject a decoy top-level TRUSTLEVEL member immediately BEFORE the
			// signed trustLevel. encoding/json cannot emit two case-variant struct
			// fields, so the decoy is added at the byte level after signing; a
			// lenient Go parse collapses the pair last-wins to the signed
			// trustLevel=4, making this a real silent smuggle a fold-aware
			// duplicate check (foldKey) must reject as PARSE_ERROR.
			b, err := os.ReadFile(path) //nolint:gosec // G304: file just written above
			must(err)
			replaced := bytes.Replace(b, []byte("    \"trustLevel\": 4,"), []byte("    \"TRUSTLEVEL\": 9,\n    \"trustLevel\": 4,"), 1)
			if bytes.Equal(replaced, b) {
				panic("case-variant fixture: trustLevel substitution target not found")
			}
			//nolint:gosec // G703: build-time tool rewriting the fixture it just wrote under outDir
			must(os.WriteFile(path, replaced, 0o644))
		}
		if fs.writePath == "fixtures/v1_1-scan-summary-member-outside-type.json" {
			// Write the signed criticalFindings 0 as the JSON string "3".
			// ATCScanSummary holds the count as an int, so the string is
			// written at the byte level after signing; every other byte is
			// the credential the signature covers.
			b, err := os.ReadFile(path) //nolint:gosec // G304: file just written above
			must(err)
			target := []byte(`"criticalFindings": 0,`)
			if n := bytes.Count(b, target); n != 1 {
				panic(fmt.Sprintf("scan-summary-member-outside-type fixture: %d criticalFindings substitution targets, want 1", n))
			}
			replaced := bytes.Replace(b, target, []byte(`"criticalFindings": "3",`), 1)
			//nolint:gosec // G703: build-time tool rewriting the fixture it just wrote under outDir
			must(os.WriteFile(path, replaced, 0o644))
		}
		if added, ok := memberAddedAfter[fs.writePath]; ok {
			// Write the member directly after the line it follows. ATX has no
			// field for it, so it is added at the byte level after signing;
			// every other byte is the credential the signature covers.
			b, err := os.ReadFile(path) //nolint:gosec // G304: file just written above
			must(err)
			if n := bytes.Count(b, []byte(added.after)); n != 1 {
				panic(fmt.Sprintf("%s: %d substitution targets for %q, want 1", fs.writePath, n, added.after))
			}
			replaced := bytes.Replace(b, []byte(added.after), []byte(added.after+"\n"+added.member), 1)
			//nolint:gosec // G703: build-time tool rewriting the fixture it just wrote under outDir
			must(os.WriteFile(path, replaced, 0o644))
		}
		if write, ok := behavioralProfileWrites[fs.writePath]; ok {
			// ATCBehavioralProfile cannot hold the profile these fixtures
			// carry, so it is written at the byte level after signing;
			// every other byte is the credential the signature covers.
			b, err := os.ReadFile(path) //nolint:gosec // G304: file just written above
			must(err)
			if n := bytes.Count(b, []byte(write.from)); n != 1 {
				panic(fmt.Sprintf("%s: %d behavioralProfile substitution targets, want 1", fs.writePath, n))
			}
			replaced := bytes.Replace(b, []byte(write.from), []byte(write.to), 1)
			//nolint:gosec // G703: build-time tool rewriting the fixture it just wrote under outDir
			must(os.WriteFile(path, replaced, 0o644))
			behavioralProfileWritten[fs.writePath] = true
		}
		sha := sha256FileHex(path)
		manifest = append(manifest, manifestEntry{path: fs.writePath, sha: sha})
		fmt.Printf("wrote %s (sha256=%s)\n", fs.writePath, sha)
	}
	for name := range fixtureSections {
		if !fixtureSectionsUsed[name] {
			panic("fixtureSections names no fixture: " + name)
		}
	}
	for name := range fixtureRequirements {
		if !fixtureRequirementsUsed[name] {
			panic("fixtureRequirements names no fixture: " + name)
		}
	}
	for name := range fixtureOtherRefs {
		if !fixtureOtherRefsUsed[name] {
			panic("fixtureOtherRefs names no fixture: " + name)
		}
	}
	for path := range memberAddedAfter {
		written := false
		for _, e := range manifest {
			written = written || e.path == path
		}
		if !written {
			panic("memberAddedAfter names no fixture: " + path)
		}
	}
	for path := range behavioralProfileWrites {
		if !behavioralProfileWritten[path] {
			panic("behavioralProfileWrites names no fixture: " + path)
		}
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

// memberAddedAfter holds, for each fixture whose credential carries a member
// its issuer did not write under a name ATX has no field for, the line of the
// written fixture the member follows and the line that writes it. main writes
// the member after signing. Each name holds one character outside printable
// ASCII, written as its UTF-8 bytes: U+0130, LATIN CAPITAL LETTER I WITH DOT
// ABOVE, and U+0131, LATIN SMALL LETTER DOTLESS I (atx-conformance#284).
var memberAddedAfter = map[string]struct{ after, member string }{
	"fixtures/v1_1-dotted-capital-i-member.json": {
		after:  `    "id": "00000000-0000-0000-0000-000000000001",`,
		member: `    "` + string(rune(0x0130)) + `d": "x",`,
	},
	"fixtures/v1_1-dotless-i-member.json": {
		after:  `    "issuedAt": "2026-05-23T00:00:00Z",`,
		member: `    "` + string(rune(0x0131)) + `ssuedAt": "2099-01-01T00:00:00Z",`,
	},
}

// behavioralProfileWrites is the byte-level write main makes after signing
// in each behavioralProfile fixture (atx-conformance#277): the text it
// replaces, which the fixture must hold exactly once, and the text it writes
// in its place.
var behavioralProfileWrites = map[string]struct{ from, to string }{
	"fixtures/v1_1-behavioral-profile-extra-member.json": {
		"      \"observationDays\": 14\n    },",
		"      \"observationDays\": 14,\n      \"riskLevel\": \"low\"\n    },",
	},
	"fixtures/v1_1-behavioral-profile-case-variant-member.json": {
		"      \"observationDays\": 14\n",
		"      \"OBSERVATIONDAYS\": 14\n",
	},
	"fixtures/v1_1-behavioral-profile-not-object.json": {
		"    \"scanSummary\": {",
		"    \"behavioralProfile\": \"sha256:ghi789\",\n    \"scanSummary\": {",
	},
	"fixtures/v1_1-behavioral-profile-member-outside-type.json": {
		"      \"observationDays\": 14\n",
		"      \"observationDays\": \"14\"\n",
	},
}

// behavioralProfileWritten records which behavioralProfileWrites entries main
// applied; main fails on an entry that names no fixture.
var behavioralProfileWritten = map[string]bool{}

// logIndex returns a pointer to the log-assigned issuance index, so a fixture
// can omit transparencyLogIndex entirely by leaving the field nil. The field is
// optional in atx-spec §1.1 and sits outside both signing forms, so its absence
// changes no canonical bytes and no signature.
func logIndex(n int64) *int64 { return &n }

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
		TransparencyLogIndex: logIndex(42),
		Capabilities:         []string{"db:read", "db:write"},
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

// atxCoreRef is atx-spec core.md at the commit its headings are checked
// against (CORE_REF in scripts/check_spec_refs.py), so a published citation
// opens the text it was checked against after core.md changes on main.
const atxCoreRef = "https://github.com/opena2a-standards/atx-spec/blob/e89bed94ca0a7308e2d6915e384be4c89d3a67df/core.md"

// aipSpecRef is AIP-SPEC.md at the commit docs/version-pinning.md pins
// (AIP_REF in scripts/conformance_profile.py), so the AIP citation opens the
// 1.2.0-draft text it names after AIP-SPEC.md changes on main.
const aipSpecRef = "https://github.com/opena2a-standards/agent-identity-protocol/blob/80db7b2304b2f37bddf1c82e788c27e1ab874b3d/AIP-SPEC.md"

// AIP-SPEC citations: §3.1 scoped to the signature algorithms a credential
// carries (aipSigningSection), and §6.1 for the trustScore member every
// credential carries. scripts/conformance_profile.py --check holds each
// fixture to the same text.
const (
	aipSigningEd25519 = "§3.1 Cryptographic Identity (Ed25519 signing)"
	aipSigningHybrid  = "§3.1 Cryptographic Identity (hybrid Ed25519 + ML-DSA-65 signing)"
	aipSigningPQOnly  = "§3.1 Cryptographic Identity (an ML-DSA-65 signature with no Ed25519 signature)"
	aipTrustScoring   = "§6.1 Multi-Factor Algorithm"
)

// aipSigningSection is the AIP-SPEC §3.1 citation for the signature
// algorithms a credential carries.
func aipSigningSection(sigs []ATCSignature) string {
	var ed25519, mldsa bool
	for _, sig := range sigs {
		switch sig.Algorithm {
		case "Ed25519":
			ed25519 = true
		case "ML-DSA-65":
			mldsa = true
		}
	}
	switch {
	case ed25519 && mldsa:
		return aipSigningHybrid
	case mldsa:
		return aipSigningPQOnly
	default:
		return aipSigningEd25519
	}
}

// core.md heading text, verbatim (scripts/check_spec_refs.py).
const (
	secSchema          = "1.1 ATX schema"
	secVerification    = "1.3 Local verification algorithm"
	secLegacyForm      = "1.3a.1 Legacy form (`atcVersion` = \"1.0\")"
	secJCSForm         = "1.3a.2 JCS form (`atcVersion` = \"1.1\")"
	secSignedFields    = "1.3a.4 Authorization on signed fields requires v1.1"
	secDeclaredPurpose = "1.5 Declared purpose (optional)"
	secIssuance        = "3.1 Issuance flow"
	secRevocation      = "3.3 Revocation flow"
	secSecurity        = "13. Security considerations"
)

// fixtureSections names the core.md sections a fixture exercises beyond the
// ones atxSections gives every fixture of its atcVersion. main fails on an
// entry that names no fixture, so a renamed fixture cannot drop its citation.
var fixtureSections = map[string][]string{
	"atx-v1/revoked":                             {secRevocation},
	"atx-v1/revoked-crl-only":                    {secRevocation},
	"atx-v1/threshold-1of3-cosignature":          {secIssuance},
	"atx-v1/wrong-issuer":                        {secSecurity},
	"atx-v1/hybrid-pq-only":                      {secSecurity},
	"atx-v1_1/hybrid-pq-only":                    {secSecurity},
	"atx-v1_1/tampered-capabilities":             {secSignedFields},
	"atx-v1_1/scan-summary-member-outside-type":  {secSignedFields},
	"atx-v1_1/integer-outside-exact-range":       {secSignedFields},
	"atx-v1_1/declared-purpose-valid":            {secDeclaredPurpose},
	"atx-v1_1/tampered-declared-purpose":         {secDeclaredPurpose},
	"atx-v1_1/declared-purpose-empty-whitespace": {secDeclaredPurpose},
	"atx-v1_1/declared-purpose-array-injected":   {secDeclaredPurpose},
	"atx-v1_1/declared-purpose-string-injected":  {secDeclaredPurpose},
	"atx-v1_1/declared-purpose-number-injected":  {secDeclaredPurpose},
	"atx-v1_1/duplicate-purpose-member":          {secDeclaredPurpose},
}

// fixtureSectionsUsed records which fixtureSections entries wrap consumed.
var fixtureSectionsUsed = map[string]bool{}

// fixtureRequirements names the requirement each fixture tests: the § number
// of the core.md section it comes from, which the fixture's spec list cites,
// then the step or rule. scripts/conformance_profile.py --check fails on a
// fixture whose requirement names a section it does not cite, or repeats
// another fixture's. wrap fails on a fixture with no entry, and main on an
// entry that names no fixture.
var fixtureRequirements = map[string]string{
	"atx-v1/baseline-valid":                      "§1.3 step 8: a v1.0 credential whose one Ed25519 signature, made with its issuer's key, verifies over the legacy canonical bytes passes every step and is accepted",
	"atx-v1/baseline-valid-hybrid":               "§1.3 step 5: every declared signature verifies, the ML-DSA-65 signature included, so a v1.0 hybrid credential is accepted",
	"atx-v1/hybrid-pq-only":                      "§13, Cryptographic agility: under atcVersion 1.0 too, a credential that declares an ML-DSA-65 signature must also carry a verifying Ed25519 signature, so an ML-DSA-65 signature alone over the legacy canonical bytes is a signature failure",
	"atx-v1/revoked":                             "§3.3 step 7: a credential its issuing node marked revoked is rejected; its revoked flag is set and its agentId is also on the verifier's CRL",
	"atx-v1/revoked-crl-only":                    "§1.3 step 6: an agentId listed on the verifier's CRL is rejected although the credential's own revoked flag is false",
	"atx-v1/threshold-2of3-cosignature":          "§1.3 step 5: every declared signature verifies, here three Ed25519 signatures by three keys, so the credential is accepted; the 2-of-3 threshold of §3.1 step 8 is not tested",
	"atx-v1/threshold-1of3-cosignature":          "§3.1 step 8: under a verifier state that requires the signatures of 2 of the issuer's 3 Ed25519 keys, a credential whose one signature verifies is a signature failure",
	"atx-v1/expired":                             "§1.3 step 2: a credential whose expiresAt is earlier than the verifier's clock is rejected",
	"atx-v1/wrong-issuer":                        "§13, Key substitution at resolution: an issuer the verifier does not trust is rejected even when its own signature verifies",
	"atx-v1/tampered-signature":                  "§1.3 step 4: an Ed25519 signature that does not verify over the legacy canonical bytes is a signature failure",
	"atx-v1/malformed-schema":                    "§1.3 step 1: a credential whose atcVersion (2.0) is not a supported schema version is rejected",
	"atx-v1/cross-issuer-key":                    "§1.3 step 4, key eligibility: under atcVersion 1.0 only a key resolved for the issuerDid is eligible, so a signature made with another trusted authority's key is a signature failure",
	"atx-v1_1/baseline-valid":                    "§1.3a.2: a v1.1 credential whose one Ed25519 signature verifies over JCS(TBS) is accepted",
	"atx-v1_1/no-transparency-log-index":         "§1.1: transparencyLogIndex is optional and outside JCS(TBS), so a v1.1 credential that omits it is accepted",
	"atx-v1_1/baseline-valid-hybrid":             "§1.3 step 5: every declared signature verifies, the ML-DSA-65 signature included, so a v1.1 hybrid credential is accepted",
	"atx-v1_1/hybrid-mldsa-tampered":             "§1.3 step 5: a declared ML-DSA-65 signature that does not verify is a signature failure, although the Ed25519 signature verifies",
	"atx-v1_1/hybrid-pq-only":                    "§13, Cryptographic agility: a credential that declares an ML-DSA-65 signature must also carry a verifying Ed25519 signature, so an ML-DSA-65 signature alone is a signature failure",
	"atx-v1_1/tampered-capabilities":             "§1.3a.4: capabilities are under the v1.1 signature, so capabilities changed after signing are a signature failure",
	"atx-v1_1/scan-summary-member-outside-type":  "§1.3a.2 rule 2: each scanSummary member enters the TBS with its type, so a member written outside that type after signing, criticalFindings as the string \"3\", has no value the signature covers and is a signature failure",
	"atx-v1_1/integer-outside-exact-range":       "§1.3a.2 rule 3: RFC 8785 number serialization is kept out of cross-language scope, and outside the I-JSON exact range it does not write every integer as its digits, so criticalFindings 9007199254740993, which it writes as 9007199254740992, has no value the signature covers and is a signature failure",
	"atx-v1_1/declared-purpose-valid":            "§1.5: a present declaredPurpose object is signed as part of JCS(TBS) (§1.3a.2 rule 5), and a credential carrying one is accepted",
	"atx-v1_1/tampered-declared-purpose":         "§1.5: declaredPurpose is under the v1.1 signature, so a declaredPurpose changed after signing is a signature failure",
	"atx-v1_1/declared-purpose-empty-whitespace": "§1.3a.2 rule 5: an empty declaredPurpose object, whatever whitespace it is written with, is treated as absent and left out of the TBS",
	"atx-v1_1/declared-purpose-array-injected":   "§1.3a.2 rule 5: a present non-object declaredPurpose value enters the TBS verbatim, so an array added after signing is a signature failure",
	"atx-v1_1/declared-purpose-string-injected":  "§1.3a.2 rule 5: a present non-object declaredPurpose value enters the TBS verbatim, so a string added after signing is a signature failure",
	"atx-v1_1/declared-purpose-number-injected":  "§1.3a.2 rule 5: a present non-object declaredPurpose value enters the TBS verbatim, so a number that is not an integer, added after signing, is a signature failure",
	"atx-v1_1/duplicate-purpose-member":          "§1.3 step 1: parsing the credential rejects an object member repeated at any depth (RFC 8259 §4) as PARSE_ERROR before any field is read (§12)",
	"atx-v1_1/case-variant-member":               "§1.3 step 1: parsing the credential rejects two member names that fold to one field (TRUSTLEVEL and trustLevel) as PARSE_ERROR before any field is read (§12)",
	"atx-v1_1/dotted-capital-i-member":           "§1.3 step 1: parsing the credential rejects a member name outside printable ASCII in an object the verifier decodes (U+0130 followed by d, beside id) as PARSE_ERROR before any field is read (§12)",
	"atx-v1_1/dotless-i-member":                  "§1.3 step 1: parsing the credential rejects a member name outside printable ASCII in an object the verifier decodes (U+0131 followed by ssuedAt, beside issuedAt) as PARSE_ERROR before any field is read (§12)",
	"atx-v1_1/cross-issuer-key":                  "§1.3 step 4, key eligibility: under atcVersion 1.1 a key is eligible only for the issuerDid or a trusted issuer the signed issuerChain names, so a signature made with a trusted authority's key outside both is a signature failure",
	"atx-v1_1/untrusted-chain-authority":         "§1.3 step 4, key eligibility: a DID the signed issuerChain names that is not a trusted issuer contributes no eligible key, so a signature made with its key is a signature failure",

	// behavioralProfile form (atx-conformance#277).
	"atx-v1_1/behavioral-profile-extra-member":        "§1.1: the credential schema gives behavioralProfile exactly checksum, generatedAt and observationDays, so a fourth member added after signing leaves a profile the TBS has no value for, a signature failure",
	"atx-v1_1/behavioral-profile-case-variant-member": "§1.1: behavioralProfile member names are compared exactly, so observationDays renamed OBSERVATIONDAYS after signing leaves a profile the TBS has no value for, a signature failure",
	"atx-v1_1/behavioral-profile-not-object":          "§1.3a.2 rule 1: the TBS holds null for a credential with no behavioralProfile and otherwise an object of its three members, so a string added as the profile after signing is a signature failure",
	"atx-v1_1/behavioral-profile-member-outside-type": "§1.3a.2 rule 1: a behavioralProfile added after signing whose observationDays is a string has no value in the TBS, where a credential with no profile holds null, so it is a signature failure",
}

// fixtureRequirementsUsed records which fixtureRequirements entries wrap consumed.
var fixtureRequirementsUsed = map[string]bool{}

// fixtureOtherRefs names the documents a fixture cites beyond core.md,
// AIP-SPEC, RFC 8032 and FIPS 204, which wrap cites by rule. main fails on an
// entry that names no fixture.
var fixtureOtherRefs = map[string][]SpecRef{
	"atx-v1_1/integer-outside-exact-range": {
		{ID: "RFC 7493", Ref: "https://datatracker.ietf.org/doc/html/rfc7493", Section: "§2.2 Numbers (the I-JSON exact integer range, -(2^53-1) to 2^53-1)"},
		{ID: "RFC 8785", Ref: "https://datatracker.ietf.org/doc/html/rfc8785", Section: "§3.2.2.3 Serialization of Numbers"},
	},
}

// fixtureOtherRefsUsed records which fixtureOtherRefs entries wrap consumed.
var fixtureOtherRefsUsed = map[string]bool{}

// atxSections lists the core.md sections a fixture cites: the schema and the
// verification algorithm, the canonical signing form its atcVersion selects
// (none for a version core.md does not define), then its fixtureSections.
func atxSections(name, version string) []string {
	sections := []string{secSchema, secVerification}
	switch version {
	case atcVersion:
		sections = append(sections, secLegacyForm)
	case atcVersionV11:
		sections = append(sections, secJCSForm)
	}
	if extra, ok := fixtureSections[name]; ok {
		fixtureSectionsUsed[name] = true
		sections = append(sections, extra...)
	}
	return sections
}

// wrap bundles the signed ATX with its fixture metadata.
func wrap(name, description string, refs []KeypairRef, vs VerifierState, expected ExpectedOutcome, atx ATX) Fixture {
	atxBytes, err := marshalIndent(atx)
	must(err)
	var spec []SpecRef
	for _, section := range atxSections(name, atx.ATCVersion) {
		spec = append(spec, SpecRef{ID: "ATX", Ref: atxCoreRef, Section: section})
	}
	spec = append(spec,
		SpecRef{ID: "AIP", Ref: aipSpecRef, Section: aipSigningSection(atx.Signatures)},
		SpecRef{ID: "AIP", Ref: aipSpecRef, Section: aipTrustScoring},
		SpecRef{ID: "RFC 8032", Ref: "https://datatracker.ietf.org/doc/html/rfc8032", Section: "§7.1 Test 1 (Ed25519 keypair source for issuer-primary)"},
	)
	if other, ok := fixtureOtherRefs[name]; ok {
		fixtureOtherRefsUsed[name] = true
		spec = append(spec, other...)
	}
	// FIPS 204 is cited only by a credential that carries an ML-DSA-65
	// signature (scripts/conformance_profile.py --check).
	for _, sig := range atx.Signatures {
		if sig.Algorithm == "ML-DSA-65" {
			spec = append(spec, SpecRef{ID: "FIPS 204", Ref: "https://csrc.nist.gov/pubs/fips/204/final", Section: "ML-DSA-65 (Module-Lattice-Based DSA)"})
			break
		}
	}
	requirement, ok := fixtureRequirements[name]
	if !ok {
		panic("fixtureRequirements has no entry for " + name)
	}
	fixtureRequirementsUsed[name] = true
	return Fixture{
		Schema:        "https://raw.githubusercontent.com/opena2a-standards/atx-conformance/main/schemas/fixture-v1.schema.json",
		Name:          name,
		Description:   description,
		Requirement:   requirement,
		Spec:          spec,
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
	b, err := os.ReadFile(filepath.Join(outDir, relPath)) //nolint:gosec // G304: build-time tool; outDir + constant relPath, no untrusted input
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
	b, err := os.ReadFile(filepath.Join(outDir, "vectors/mldsa65-seed.json")) //nolint:gosec // G304: build-time tool; outDir + constant path, no untrusted input
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
	b, err := os.ReadFile(path) //nolint:gosec // G304: build-time tool hashing files it just wrote under outDir
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
