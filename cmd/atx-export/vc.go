package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"regexp"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"
)

const (
	// vcContextV2 is the JSON-LD context of W3C Verifiable Credentials
	// Data Model 2.0, the credential's only context.
	vcContextV2        = "https://www.w3.org/ns/credentials/v2"
	credentialType     = "AgentTrustCredential"
	dataIntegrityProof = "DataIntegrityProof"
	assertionMethod    = "assertionMethod"

	// suiteEdDSAJCS2022 is defined by W3C Data Integrity EdDSA Cryptosuites
	// v1.0, a W3C Recommendation of 15 May 2025, section 3.3.
	suiteEdDSAJCS2022 = "eddsa-jcs-2022"

	// suiteMLDSA65JCS2024 is experimental. It is defined by the revision of
	// the W3C Quantum-Resistant Cryptosuites v1.0 Editor's Draft committed
	// on 2026-03-01 (w3c/vc-di-quantum-resistant commit
	// 6fc1195722f6e97ac8d78ddf3de4d1a91f04dae1), sections "ML-DSA
	// Cyphersuites" and "Common Algorithms". Later revisions of that draft
	// leave the ML-DSA-65 suites out.
	suiteMLDSA65JCS2024 = "mldsa65-jcs-2024"
)

// credential returns the unsecured credential for the members of a native
// atx object: the members below and no others, each value as written. A
// member whose native member is absent is omitted. tbsSHA256 is the
// lowercase hex SHA-256 of the native signed bytes.
func credential(atx map[string]any, tbsSHA256 string) (map[string]any, error) {
	cred := map[string]any{
		"@context":     []any{vcContextV2},
		"type":         []any{"VerifiableCredential", credentialType},
		"atxTbsSha256": tbsSHA256,
	}
	if v, ok := atx["id"]; ok {
		id, isString := v.(string)
		if !isString {
			return nil, errors.New("atx: id is not a string")
		}
		cred["id"] = "urn:uuid:" + id
	}
	copyMember(cred, "issuer", atx, "issuerDid")
	copyMember(cred, "validFrom", atx, "issuedAt")
	copyMember(cred, "validUntil", atx, "expiresAt")
	copyMember(cred, "issuerChain", atx, "issuerChain")

	subject := map[string]any{}
	copyMember(subject, "id", atx, "agentDid")
	for _, name := range []string{"atcVersion", "agentId", "publisher", "publisherDid", "version", "contentHash", "buildAttestation", "capabilities"} {
		copyMember(subject, name, atx, name)
	}
	if v, ok := atx["declaredPurpose"]; ok && !isNullOrEmptyObject(v) {
		subject["declaredPurpose"] = v
	}
	copyMember(subject, "behavioralProfile", atx, "behavioralProfile")
	copyMember(subject, "scanSummary", atx, "scanSummary")
	copyMember(subject, "atxTrustScore", atx, "trustScore")
	copyMember(subject, "trustLevel", atx, "trustLevel")
	cred["credentialSubject"] = subject
	return cred, nil
}

// copyMember sets dst[to] to src[from], as written, when src has from.
func copyMember(dst map[string]any, to string, src map[string]any, from string) {
	if v, ok := src[from]; ok {
		dst[to] = v
	}
}

func isNullOrEmptyObject(v any) bool {
	if v == nil {
		return true
	}
	obj, ok := v.(map[string]any)
	return ok && len(obj) == 0
}

// proofOptions returns the options of one Data Integrity proof: type,
// cryptosuite, created (when the credential has an issuedAt),
// verificationMethod and proofPurpose.
func proofOptions(suite string, created any, verificationMethod string) map[string]any {
	opts := map[string]any{
		"type":               dataIntegrityProof,
		"cryptosuite":        suite,
		"verificationMethod": verificationMethod,
		"proofPurpose":       assertionMethod,
	}
	if created != nil {
		opts["created"] = created
	}
	return opts
}

// canonicalJSON returns the RFC 8785 canonical bytes of v.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode ends the text with a line feed, which jcs.Transform refuses
	// after a top-level number.
	return jcs.Transform(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// createEdDSAJCS2022Proof follows "3.3.1 Create Proof (eddsa-jcs-2022)" of
// W3C Data Integrity EdDSA Cryptosuites v1.0 (Recommendation, 15 May 2025).
func createEdDSAJCS2022Proof(unsecured, options map[string]any, key ed25519.PrivateKey) (map[string]any, error) {
	// 1. Let proof be a clone of the proof options.
	proof := cloneMap(options)
	// 2. If unsecuredDocument.@context is present, set proof.@context to
	// unsecuredDocument.@context.
	if c, ok := unsecured["@context"]; ok {
		proof["@context"] = c
	}
	// 3. Proof Configuration (3.3.5), with proof as the proof options.
	proofConfig, err := proofConfiguration(proof, suiteEdDSAJCS2022)
	if err != nil {
		return nil, err
	}
	// 4. Transformation (3.3.3), with unsecuredDocument and options.
	transformed, err := transformation(unsecured, options, suiteEdDSAJCS2022)
	if err != nil {
		return nil, err
	}
	// 5. Hashing (3.3.4): SHA-256.
	hashData := hashing(sha256.New, transformed, proofConfig)
	// 6. Proof Serialization (3.3.6): Ed25519 (Pure EdDSA) over hashData.
	proofBytes := ed25519.Sign(key, hashData)
	// 7. proof.proofValue: the base58-btc Multibase value of proofBytes.
	proof["proofValue"] = "z" + base58btc(proofBytes)
	return proof, nil
}

// createMLDSA65JCS2024Proof follows "Create Proof (ML-DSA)" of the
// Quantum-Resistant Cryptosuites v1.0 Editor's Draft at the revision named
// at suiteMLDSA65JCS2024, with that draft's parameters for
// mldsa65-jcs-2024: canonicalization JCS, signature ML-DSA-65, hash SHA-384.
// The signature is deterministic ML-DSA-65 with an empty context string, as
// the fixture generator signs; the draft names no other variant.
func createMLDSA65JCS2024Proof(unsecured, options map[string]any, key *mldsa65.PrivateKey) (map[string]any, error) {
	// 1. Let proof be a clone of the proof options.
	proof := cloneMap(options)
	// 2. Proof Configuration, with options. That algorithm sets
	// proofConfig.@context to unsecuredDocument.@context.
	config := cloneMap(options)
	if c, ok := unsecured["@context"]; ok {
		config["@context"] = c
	}
	proofConfig, err := proofConfiguration(config, suiteMLDSA65JCS2024)
	if err != nil {
		return nil, err
	}
	// 3. Transformation, with unsecuredDocument and options.
	transformed, err := transformation(unsecured, options, suiteMLDSA65JCS2024)
	if err != nil {
		return nil, err
	}
	// 4. Hashing, with SHA-384.
	hashData := hashing(sha512.New384, transformed, proofConfig)
	// 5. Proof Serialization: ML-DSA-65 over hashData.
	proofBytes := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(key, hashData, nil, false, proofBytes); err != nil {
		return nil, err
	}
	// 6. proof.proofValue: the base64-url-nopad Multibase value (header u).
	proof["proofValue"] = "u" + base64.RawURLEncoding.EncodeToString(proofBytes)
	return proof, nil
}

// proofConfiguration checks the proof configuration's type, cryptosuite and
// created, and returns its JCS bytes (3.3.5 of the EdDSA Recommendation; the
// draft's Proof Configuration differs only in setting @context, which the
// caller does).
func proofConfiguration(config map[string]any, suite string) ([]byte, error) {
	if config["type"] != dataIntegrityProof || config["cryptosuite"] != suite {
		return nil, fmt.Errorf("proof configuration: type is not %s or cryptosuite is not %s", dataIntegrityProof, suite)
	}
	if created, ok := config["created"]; ok {
		s, isString := created.(string)
		if !isString || !xsdDateTime.MatchString(s) {
			return nil, fmt.Errorf("proof configuration: created %v is not an XML Schema dateTime", created)
		}
	}
	return canonicalJSON(config)
}

// transformation returns the JCS bytes of the unsecured document, after
// checking the options' type and cryptosuite (3.3.3 of the EdDSA
// Recommendation, and the draft's Transformation with canonicalization jcs).
func transformation(unsecured, options map[string]any, suite string) ([]byte, error) {
	if options["type"] != dataIntegrityProof || options["cryptosuite"] != suite {
		return nil, fmt.Errorf("transformation: type is not %s or cryptosuite is not %s", dataIntegrityProof, suite)
	}
	return canonicalJSON(unsecured)
}

// hashing returns hash(canonicalProofConfig) followed by
// hash(transformedDocument) (3.3.4 of the EdDSA Recommendation, and the
// draft's Hashing).
func hashing(newHash func() hash.Hash, transformedDocument, canonicalProofConfig []byte) []byte {
	h := newHash()
	h.Write(canonicalProofConfig)
	proofConfigHash := h.Sum(nil)
	h = newHash()
	h.Write(transformedDocument)
	return append(proofConfigHash, h.Sum(nil)...)
}

// xsdDateTime is the lexical space of the XML Schema 1.1 dateTime datatype.
var xsdDateTime = regexp.MustCompile(`^-?([1-9][0-9]{3,}|0[0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?|(24:00:00(\.0+)?))(Z|(\+|-)((0[0-9]|1[0-3]):[0-5][0-9]|14:00))?$`)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58btc encodes b with the Bitcoin base-58 alphabet: each leading zero
// byte becomes "1", and the rest is the big-endian number in base 58.
func base58btc(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	// out collects the base-58 digits, least significant first.
	var out []byte
	n := new(big.Int).SetBytes(b)
	radix, digit := big.NewInt(58), new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, radix, digit)
		out = append(out, base58Alphabet[digit.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, base58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// exportVC returns the credential of the fixture at path as an ATX as VC,
// in RFC 8785 canonical form.
func exportVC(path string, withMLDSA65 bool) ([]byte, error) {
	f, err := readFixture(path)
	if err != nil {
		return nil, err
	}

	// A behavioralProfile of a "1.1" credential that the v1.1 TBS has no
	// value for is refused before the native bytes are computed, as the
	// reference verifiers refuse it before they read a signature. Where one
	// of its three members is null or absent, those bytes hold the member's
	// zero value, which the credential does not write.
	if profileOutsideForm(&f.native, f.profile) {
		return nil, &refusal{exitNativeSignature, "no native signature covers " + behavioralProfileForm + "; not re-signing"}
	}

	// A number of a "1.1" credential that the native bytes do not hold as
	// written is refused before those bytes are computed, as the reference
	// verifiers refuse it before they canonicalize: the native signatures
	// verify over the bytes whichever number the credential writes.
	if where, literal, fractionOrExponent := uncoveredNumber(&f.native); where != "" {
		reason := fmt.Sprintf("the integer %s is outside the I-JSON exact range, -(2^53-1) to 2^53-1", literal)
		if fractionOrExponent {
			reason = fmt.Sprintf("the number %s is written with a fraction or an exponent part, not as an integer", literal)
		}
		return nil, &refusal{exitNativeSignature, fmt.Sprintf("no native signature covers %s: %s; not re-signing", where, reason)}
	}

	// Every native signature must verify over the native bytes before
	// anything is signed.
	native, err := nativeSignedBytes(&f.native)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, sig := range f.native.Signatures {
		if !f.nativeSignatureVerifies(sig, native) {
			return nil, &refusal{exitNativeSignature, fmt.Sprintf("native signature %d does not verify over the native bytes; not re-signing", i)}
		}
	}
	if name, found := uncoveredMember(&f.native, f.members); found {
		return nil, &refusal{exitNativeSignature, fmt.Sprintf("member %s is not covered by the native signatures; not re-signing", name)}
	}

	edSig, ok := firstSignature(f.native.Signatures, "Ed25519")
	if !ok {
		return nil, &refusal{exitUsage, "--form vc needs a native Ed25519 signature"}
	}
	edKey, err := f.ed25519Key(edSig.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var pqSig ATCSignature
	var pqKey *mldsa65.PrivateKey
	if withMLDSA65 {
		if pqSig, ok = firstSignature(f.native.Signatures, "ML-DSA-65"); !ok {
			return nil, &refusal{exitUsage, "--mldsa65-proof needs a native ML-DSA-65 signature"}
		}
		if pqKey, err = f.mldsa65Key(pqSig.KeyID); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}

	digest := sha256.Sum256(native)
	unsecured, err := credential(f.members, hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	created := f.members["issuedAt"]
	edProof, err := createEdDSAJCS2022Proof(unsecured, proofOptions(suiteEdDSAJCS2022, created, edSig.KeyID), edKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	secured := cloneMap(unsecured)
	if withMLDSA65 {
		// A proof set: each proof is computed over the credential without a
		// proof, and neither names a previousProof.
		pqProof, err := createMLDSA65JCS2024Proof(unsecured, proofOptions(suiteMLDSA65JCS2024, created, pqSig.KeyID), pqKey)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		secured["proof"] = []any{edProof, pqProof}
	} else {
		secured["proof"] = edProof
	}
	return canonicalJSON(secured)
}

// firstSignature returns the first native signature of the algorithm.
func firstSignature(sigs []ATCSignature, algorithm string) (ATCSignature, bool) {
	for _, s := range sigs {
		if s.Algorithm == algorithm {
			return s, true
		}
	}
	return ATCSignature{}, false
}
