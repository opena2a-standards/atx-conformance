// Command pin authors the ATX v1.1 JCS (RFC 8785) cross-language byte-agreement
// vectors. It is the ONLY producer of the files in ../vectors/. Run it once when
// a vector's to-be-signed (TBS) input changes; commit the regenerated artifacts.
//
// For each vector it:
//  1. Canonicalizes the authored TBS object with github.com/gowebpki/jcs
//     (the webpki.org RFC 8785 reference port).
//  2. Signs the canonical bytes with the suite's Ed25519 issuer-primary seed
//     (RFC 8032 §7.1 Test 1) and the ML-DSA-65 seed, both deterministic.
//  3. Writes vectors/NN-name.json with the TBS plus the pinned expected
//     canonical string, canonical hex, sha-256, and the two signatures.
//
// The cross-language merge gate is NOT this tool. The gate is the trio of
// independent checkers (check/ in Go, python/, ts/) each recomputing the
// canonical bytes from the same TBS and asserting they reproduce the pinned hex
// byte-for-byte. This tool only establishes the pinned values that those three
// independent implementations must agree on.
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

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"
)

// vector is an authored TBS plus its identity. The tbs field is raw JSON whose
// key order is intentional: several vectors scramble key order to prove JCS
// sorting makes the canonical bytes order-independent.
type vector struct {
	file string
	name string
	desc string
	tbs  string
}

// The seven vectors. Authored TBS objects use deliberately unsorted keys; JCS
// sorts them. trustScore is a STRING in every TBS (the %.6f projection rule, so
// the float -> JCS-number cross-language hazard never arises). trustLevel is the
// only JSON number in the TBS and is always an integer.
var vectors = []vector{
	{
		file: "01-baseline.json",
		name: "baseline",
		desc: "Fully populated ATX v1.1 TBS mirroring the baseline-valid v1.0 fixture, upgraded to atcVersion 1.1. Authored key order is unsorted; JCS sorts it.",
		tbs: `{
  "atcVersion": "1.1",
  "agentId": "agent_conformance_test_001",
  "agentDid": "did:opena2a:agent:agent_conformance_test_001",
  "publisher": "opena2a-conformance",
  "publisherDid": "did:opena2a:publisher:opena2a-conformance",
  "version": "1.0.0",
  "contentHash": "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
  "buildAttestation": "https://slsa.dev/provenance/v1#opena2a-conformance",
  "capabilities": ["read:public", "write:owned"],
  "behavioralProfile": {
    "checksum": "sha256:ghi789",
    "generatedAt": "2026-05-19T00:00:00Z",
    "observationDays": 14
  },
  "scanSummary": {
    "hma": "passed",
    "criticalFindings": 0,
    "highFindings": 0,
    "secretless": "clean",
    "cryptoServe": "no-weak-crypto",
    "oasbLevel": "L1"
  },
  "trustScore": "87.500000",
  "trustLevel": 4,
  "issuedAt": "2026-05-23T00:00:00Z",
  "expiresAt": "2099-12-31T23:59:59Z",
  "issuerDid": "did:opena2a:authority:opena2a.org",
  "issuerChain": ["did:opena2a:authority:opena2a.org-root", "did:opena2a:authority:opena2a.org"]
}`,
	},
	{
		file: "02-unicode-and-escaping.json",
		name: "unicode-and-escaping",
		desc: "publisher and a capability carry a double-quote, backslash, newline, a U+0001 control char, and multi-byte UTF-8 (CJK + emoji). Exercises RFC 8785 minimal escaping: only \", \\, and control chars escape; all other code points emit as raw UTF-8.",
		tbs: `{
  "atcVersion": "1.1",
  "agentId": "agent_conformance_test_001",
  "agentDid": "did:opena2a:agent:agent_conformance_test_001",
  "publisher": "a\"b\\c\nd\u0001e 北京 🤖",
  "publisherDid": "",
  "version": "1.0.0",
  "contentHash": "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
  "buildAttestation": "",
  "capabilities": ["read:北京", "write:a\tb"],
  "behavioralProfile": null,
  "scanSummary": {
    "hma": "passed",
    "criticalFindings": 0,
    "highFindings": 0,
    "secretless": "clean",
    "cryptoServe": "no-weak-crypto",
    "oasbLevel": "L1"
  },
  "trustScore": "87.500000",
  "trustLevel": 4,
  "issuedAt": "2026-05-23T00:00:00Z",
  "expiresAt": "2099-12-31T23:59:59Z",
  "issuerDid": "did:opena2a:authority:opena2a.org",
  "issuerChain": ["did:opena2a:authority:opena2a.org-root", "did:opena2a:authority:opena2a.org"]
}`,
	},
	{
		file: "03-canonical-empties.json",
		name: "canonical-empties",
		desc: "Minimal credential exercising the canonical-empty projection rules: optional strings -> \"\", behavioralProfile absent -> null, capabilities/issuerChain absent -> [], scanSummary always a full zero-valued object. trustScore 0.000000, trustLevel 0.",
		tbs: `{
  "atcVersion": "1.1",
  "agentId": "agent_minimal_001",
  "agentDid": "did:opena2a:agent:agent_minimal_001",
  "publisher": "minimal-publisher",
  "publisherDid": "",
  "version": "0.0.1",
  "contentHash": "1111111111111111111111111111111111111111111111111111111111111111",
  "buildAttestation": "",
  "capabilities": [],
  "behavioralProfile": null,
  "scanSummary": {
    "hma": "",
    "criticalFindings": 0,
    "highFindings": 0,
    "secretless": "",
    "cryptoServe": "",
    "oasbLevel": ""
  },
  "trustScore": "0.000000",
  "trustLevel": 0,
  "issuedAt": "2026-05-23T00:00:00Z",
  "expiresAt": "2026-05-30T00:00:00Z",
  "issuerDid": "did:opena2a:authority:opena2a.org",
  "issuerChain": []
}`,
	},
	{
		file: "04-key-order-scramble.json",
		name: "key-order-scramble",
		desc: "Byte-identical logical content to 01-baseline, but every object's keys are authored in scrambled order. MUST canonicalize to the exact same bytes as 01-baseline (the pin tool asserts hex equality). Proves JCS object-key sorting.",
		tbs: `{
  "issuerChain": ["did:opena2a:authority:opena2a.org-root", "did:opena2a:authority:opena2a.org"],
  "issuerDid": "did:opena2a:authority:opena2a.org",
  "expiresAt": "2099-12-31T23:59:59Z",
  "issuedAt": "2026-05-23T00:00:00Z",
  "trustLevel": 4,
  "trustScore": "87.500000",
  "scanSummary": {
    "oasbLevel": "L1",
    "cryptoServe": "no-weak-crypto",
    "secretless": "clean",
    "highFindings": 0,
    "criticalFindings": 0,
    "hma": "passed"
  },
  "behavioralProfile": {
    "observationDays": 14,
    "generatedAt": "2026-05-19T00:00:00Z",
    "checksum": "sha256:ghi789"
  },
  "capabilities": ["read:public", "write:owned"],
  "buildAttestation": "https://slsa.dev/provenance/v1#opena2a-conformance",
  "contentHash": "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
  "version": "1.0.0",
  "publisherDid": "did:opena2a:publisher:opena2a-conformance",
  "publisher": "opena2a-conformance",
  "agentDid": "did:opena2a:agent:agent_conformance_test_001",
  "agentId": "agent_conformance_test_001",
  "atcVersion": "1.1"
}`,
	},
	{
		file: "05-issuer-chain-order.json",
		name: "issuer-chain-order",
		desc: "Three-authority issuerChain in normative root-first order. Array order is significant: JCS preserves it, never sorts arrays. Reordering the chain changes the canonical bytes and therefore the signature (see README; the check tools include a reorder negative).",
		tbs: `{
  "atcVersion": "1.1",
  "agentId": "agent_conformance_test_001",
  "agentDid": "did:opena2a:agent:agent_conformance_test_001",
  "publisher": "opena2a-conformance",
  "publisherDid": "did:opena2a:publisher:opena2a-conformance",
  "version": "1.0.0",
  "contentHash": "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
  "buildAttestation": "https://slsa.dev/provenance/v1#opena2a-conformance",
  "capabilities": ["read:public"],
  "behavioralProfile": null,
  "scanSummary": {
    "hma": "passed",
    "criticalFindings": 0,
    "highFindings": 0,
    "secretless": "clean",
    "cryptoServe": "no-weak-crypto",
    "oasbLevel": "L2"
  },
  "trustScore": "91.250000",
  "trustLevel": 3,
  "issuedAt": "2026-05-23T00:00:00Z",
  "expiresAt": "2099-12-31T23:59:59Z",
  "issuerDid": "did:opena2a:authority:enterprise.example.com",
  "issuerChain": ["did:opena2a:authority:opena2a.org-root", "did:opena2a:authority:opena2a.org", "did:opena2a:authority:enterprise.example.com"]
}`,
	},
	{
		file: "06-trustscore-string.json",
		name: "trustscore-string",
		desc: "trustScore is carried in the TBS as the fixed %.6f STRING form, never a JSON number. This vector pins a rounded value (66.666667) so a verifier that accidentally emits a JSON number, or formats with different precision, fails the gate.",
		tbs: `{
  "atcVersion": "1.1",
  "agentId": "agent_conformance_test_001",
  "agentDid": "did:opena2a:agent:agent_conformance_test_001",
  "publisher": "opena2a-conformance",
  "publisherDid": "did:opena2a:publisher:opena2a-conformance",
  "version": "1.0.0",
  "contentHash": "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
  "buildAttestation": "https://slsa.dev/provenance/v1#opena2a-conformance",
  "capabilities": ["read:public", "write:owned"],
  "behavioralProfile": null,
  "scanSummary": {
    "hma": "warnings",
    "criticalFindings": 0,
    "highFindings": 2,
    "secretless": "clean",
    "cryptoServe": "no-weak-crypto",
    "oasbLevel": "L1"
  },
  "trustScore": "66.666667",
  "trustLevel": 2,
  "issuedAt": "2026-05-23T00:00:00Z",
  "expiresAt": "2099-12-31T23:59:59Z",
  "issuerDid": "did:opena2a:authority:opena2a.org",
  "issuerChain": ["did:opena2a:authority:opena2a.org-root", "did:opena2a:authority:opena2a.org"]
}`,
	},
	{
		file: "07-nested-and-unicode-arrays.json",
		name: "nested-and-unicode-arrays",
		desc: "behavioralProfile present, non-zero scanSummary counts, and a capabilities array whose elements carry unicode and an escaped solidus. Stresses nested-object plus array-of-strings canonicalization together.",
		tbs: `{
  "atcVersion": "1.1",
  "agentId": "agent_conformance_test_002",
  "agentDid": "did:opena2a:agent:agent_conformance_test_002",
  "publisher": "É京 Corp",
  "publisherDid": "did:opena2a:publisher:nested",
  "version": "2.1.4",
  "contentHash": "2222222222222222222222222222222222222222222222222222222222222222",
  "buildAttestation": "https://slsa.dev/provenance/v1#nested",
  "capabilities": ["db:read", "api:call", "fs:北京", "net:a/b"],
  "behavioralProfile": {
    "checksum": "sha256:nestedabc",
    "generatedAt": "2026-05-19T12:34:56Z",
    "observationDays": 30
  },
  "scanSummary": {
    "hma": "passed",
    "criticalFindings": 1,
    "highFindings": 3,
    "secretless": "findings",
    "cryptoServe": "findings",
    "oasbLevel": "L3"
  },
  "trustScore": "73.125000",
  "trustLevel": 3,
  "issuedAt": "2026-05-19T00:00:00Z",
  "expiresAt": "2099-12-31T23:59:59Z",
  "issuerDid": "did:opena2a:authority:opena2a.org",
  "issuerChain": ["did:opena2a:authority:opena2a.org-root", "did:opena2a:authority:google.com", "did:opena2a:authority:opena2a.org"]
}`,
	},
}

type edVector struct {
	SeedHex      string `json:"seedHex"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

type mldsaVector struct {
	SeedHex      string `json:"seedHex"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

func main() {
	root := repoRoot()
	ed := loadEd(filepath.Join(root, "vectors/issuer-primary.json"))
	pq := loadMLDSA(filepath.Join(root, "vectors/mldsa65-seed.json"))

	edSeed, err := hex.DecodeString(ed.SeedHex)
	must(err)
	edPriv := ed25519.NewKeyFromSeed(edSeed)

	pqSeed, err := hex.DecodeString(pq.SeedHex)
	must(err)
	var pqSeedArr [32]byte
	copy(pqSeedArr[:], pqSeed)
	_, pqPriv := mldsa65.NewKeyFromSeed(&pqSeedArr)

	outDir := filepath.Join(root, "jcs-vectors", "vectors")
	must(os.MkdirAll(outDir, 0o755))

	hexByName := map[string]string{}
	type manifestEntry struct{ sha, path string }
	var manifest []manifestEntry

	for _, v := range vectors {
		canonical, err := jcs.Transform([]byte(v.tbs))
		if err != nil {
			panic(fmt.Sprintf("%s: jcs.Transform: %v", v.file, err))
		}
		canonicalHex := hex.EncodeToString(canonical)
		sum := sha256.Sum256(canonical)

		edSig := ed25519.Sign(edPriv, canonical)
		pqSig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(pqPriv, canonical, nil, false, pqSig); err != nil {
			panic(fmt.Sprintf("%s: ML-DSA-65 sign: %v", v.file, err))
		}

		out := buildVectorFile(v, canonical, canonicalHex, hex.EncodeToString(sum[:]), ed, pq, edSig, pqSig)
		dst := filepath.Join(outDir, v.file)
		must(os.WriteFile(dst, out, 0o644))

		fileSum := sha256.Sum256(out)
		manifest = append(manifest, manifestEntry{hex.EncodeToString(fileSum[:]), "jcs-vectors/vectors/" + v.file})
		hexByName[v.name] = canonicalHex
		fmt.Printf("wrote %-34s  bytes=%d  sha256=%s\n", v.file, len(canonical), hex.EncodeToString(sum[:])[:16]+"...")
	}

	// Invariant: scramble must canonicalize identically to baseline.
	if hexByName["key-order-scramble"] != hexByName["baseline"] {
		panic("INVARIANT VIOLATED: key-order-scramble canonical bytes differ from baseline; JCS sorting is not order-independent here")
	}
	fmt.Println("invariant ok: key-order-scramble == baseline canonical bytes")

	sort.Slice(manifest, func(i, j int) bool { return manifest[i].path < manifest[j].path })
	var mb bytes.Buffer
	for _, e := range manifest {
		fmt.Fprintf(&mb, "%s  %s\n", e.sha, e.path)
	}
	must(os.WriteFile(filepath.Join(root, "jcs-vectors", "MANIFEST.sha256"), mb.Bytes(), 0o644))
	fmt.Printf("wrote jcs-vectors/MANIFEST.sha256 (%d vectors)\n", len(manifest))
}

// buildVectorFile assembles the on-disk vector. The TBS is re-indented with
// json.Indent, which preserves the authored key order verbatim (the check tools
// canonicalize this exact byte sequence). expected.* are the pinned values the
// three independent canonicalizers must reproduce.
func buildVectorFile(v vector, canonical []byte, canonicalHex, canonicalSha string, ed edVector, pq mldsaVector, edSig, pqSig []byte) []byte {
	var tbsIndented bytes.Buffer
	must(json.Indent(&tbsIndented, []byte(v.tbs), "  ", "  "))

	// canonicalString is stored as a JSON string for human inspection; the
	// authoritative comparison is always canonicalHex.
	canonStrJSON, err := json.Marshal(string(canonical))
	must(err)

	var b bytes.Buffer
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("{\n")
	w("  \"$schema\": \"https://atx.opena2a.org/schemas/jcs-vector-v1.json\",\n")
	w("  \"name\": %s,\n", jsonStr(v.name))
	w("  \"description\": %s,\n", jsonStr(v.desc))
	w("  \"spec\": {\n")
	w("    \"id\": \"ATX\",\n")
	w("    \"ref\": \"https://github.com/opena2a-org/atx-spec/blob/main/core.md\",\n")
	w("    \"section\": \"§1.3a ATX v1.1 TBS canonical form (JCS / RFC 8785)\"\n")
	w("  },\n")
	w("  \"tbs\": %s,\n", tbsIndented.String())
	w("  \"expected\": {\n")
	w("    \"canonicalString\": %s,\n", string(canonStrJSON))
	w("    \"canonicalHex\": %s,\n", jsonStr(canonicalHex))
	w("    \"canonicalSha256\": %s,\n", jsonStr(canonicalSha))
	w("    \"ed25519\": {\n")
	w("      \"keyId\": %s,\n", jsonStr(ed.KeyID))
	w("      \"seedRef\": \"vectors/issuer-primary.json\",\n")
	w("      \"publicKeyHex\": %s,\n", jsonStr(ed.PublicKeyHex))
	w("      \"signatureB64\": %s\n", jsonStr(base64.StdEncoding.EncodeToString(edSig)))
	w("    },\n")
	w("    \"mldsa65\": {\n")
	w("      \"keyId\": %s,\n", jsonStr(pq.KeyID))
	w("      \"seedRef\": \"vectors/mldsa65-seed.json\",\n")
	w("      \"publicKeyHex\": %s,\n", jsonStr(pq.PublicKeyHex))
	w("      \"signatureB64\": %s\n", jsonStr(base64.StdEncoding.EncodeToString(pqSig)))
	w("    }\n")
	w("  }\n")
	w("}\n")

	// Validate the assembled file is well-formed JSON before writing.
	var sink any
	if err := json.Unmarshal(b.Bytes(), &sink); err != nil {
		panic(fmt.Sprintf("%s: assembled vector is not valid JSON: %v", v.file, err))
	}
	return b.Bytes()
}

func jsonStr(s string) string {
	b, err := json.Marshal(s)
	must(err)
	return string(b)
}

func loadEd(path string) edVector {
	b, err := os.ReadFile(path)
	must(err)
	var v edVector
	must(json.Unmarshal(b, &v))
	seed, err := hex.DecodeString(v.SeedHex)
	must(err)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != v.PublicKeyHex {
		panic("issuer-primary seed does not derive the pinned publicKeyHex")
	}
	return v
}

func loadMLDSA(path string) mldsaVector {
	b, err := os.ReadFile(path)
	must(err)
	var v mldsaVector
	must(json.Unmarshal(b, &v))
	seed, err := hex.DecodeString(v.SeedHex)
	must(err)
	var arr [32]byte
	copy(arr[:], seed)
	pub, _ := mldsa65.NewKeyFromSeed(&arr)
	pb, err := pub.MarshalBinary()
	must(err)
	if hex.EncodeToString(pb) != v.PublicKeyHex {
		panic("mldsa65 seed does not derive the pinned publicKeyHex")
	}
	return v
}

func repoRoot() string {
	wd, err := os.Getwd()
	must(err)
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "LICENSE")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "MANIFEST.sha256")); err == nil {
				return dir
			}
		}
		dir = filepath.Dir(dir)
	}
	panic("could not locate atx-conformance repo root (LICENSE + MANIFEST.sha256) above " + wd)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
