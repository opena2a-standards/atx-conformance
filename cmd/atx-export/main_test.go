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
	"io/fs"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"
)

// repoDir is the repository root, two directories above this package.
var repoDir = filepath.Join("..", "..")

var repo = os.DirFS(repoDir)

// fixtureNames returns the base names of the fixtures whose
// expected.verifyResult is want, or of every fixture when want is "".
func fixtureNames(t *testing.T, want string) []string {
	t.Helper()
	paths, err := fs.Glob(repo, "fixtures/*.json")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range paths {
		raw, err := fs.ReadFile(repo, p)
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			Expected struct {
				VerifyResult string `json:"verifyResult"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if want == "" || fx.Expected.VerifyResult == want {
			names = append(names, path.Base(p))
		}
	}
	if len(names) == 0 {
		t.Fatalf("no fixture with expected.verifyResult %q", want)
	}
	return names
}

func fixturePath(name string) string { return filepath.Join(repoDir, "fixtures", name) }

// export runs the command in process and returns its exit status, stdout
// and stderr.
func export(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func hasMLDSA65(t *testing.T, name string) bool {
	t.Helper()
	f, err := readFixture(fixturePath(name))
	if err != nil {
		t.Fatal(err)
	}
	_, ok := firstSignature(f.native.Signatures, "ML-DSA-65")
	return ok
}

// TestJCSVectors holds the exporter's RFC 8785 library to the bytes the
// cross-language byte-agreement gate pins: JCS of each vector's tbs equals
// its expected bytes.
func TestJCSVectors(t *testing.T) {
	paths, err := fs.Glob(repo, "jcs-vectors/vectors/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no jcs-vectors/vectors/*.json")
	}
	for _, p := range paths {
		raw, err := fs.ReadFile(repo, p)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			TBS      json.RawMessage `json:"tbs"`
			Expected struct {
				CanonicalString string `json:"canonicalString"`
				CanonicalHex    string `json:"canonicalHex"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		got, err := jcs.Transform(v.TBS)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if hex.EncodeToString(got) != v.Expected.CanonicalHex || string(got) != v.Expected.CanonicalString {
			t.Errorf("%s: JCS(tbs) differs from the expected bytes", p)
		}
	}
	t.Logf("%d vectors", len(paths))
}

// TestNativeSignaturesVerifyOverNativeBytes holds the copied canonical
// payload functions to the generator that signed the fixtures: every
// native signature of every ACCEPT fixture verifies over them.
func TestNativeSignaturesVerifyOverNativeBytes(t *testing.T) {
	names := fixtureNames(t, "ACCEPT")
	for _, name := range names {
		f, err := readFixture(fixturePath(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		native, err := nativeSignedBytes(&f.native)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(f.native.Signatures) == 0 {
			t.Errorf("%s: no native signature", name)
		}
		for i, sig := range f.native.Signatures {
			if !f.nativeSignatureVerifies(sig, native) {
				t.Errorf("%s: native signature %d (%s) does not verify", name, i, sig.Algorithm)
			}
		}
	}
	t.Logf("%d ACCEPT fixtures", len(names))
}

// TestExportIsDeterministic runs the export twice for every ACCEPT fixture,
// and twice with --mldsa65-proof for every ACCEPT fixture that carries an
// ML-DSA-65 signature, and requires identical bytes.
func TestExportIsDeterministic(t *testing.T) {
	withPQ := 0
	for _, name := range fixtureNames(t, "ACCEPT") {
		variants := [][]string{{"--form", "vc"}}
		if hasMLDSA65(t, name) {
			variants = append(variants, []string{"--form", "vc", "--mldsa65-proof"})
			withPQ++
		}
		for _, flags := range variants {
			args := append(append([]string{}, flags...), fixturePath(name))
			code1, out1, errOut := export(args...)
			if code1 != exitOK {
				t.Fatalf("%s %v: exit %d: %s", name, flags, code1, errOut)
			}
			code2, out2, _ := export(args...)
			if code2 != exitOK || out1 != out2 {
				t.Errorf("%s %v: two runs differ", name, flags)
			}
			if !strings.HasSuffix(out1, "}\n") || strings.Count(out1, "\n") != 1 {
				t.Errorf("%s %v: output is not one JSON text and one line feed", name, flags)
			}
		}
	}
	if withPQ == 0 {
		t.Error("no ACCEPT fixture carries an ML-DSA-65 signature")
	}
}

// TestExportedCredential checks, for every ACCEPT fixture, the credential's
// members, its canonical form, and each proof under the suite's Verify Proof
// algorithm with the public key the fixture's keypairRefs give for the
// proof's verificationMethod.
func TestExportedCredential(t *testing.T) {
	for _, name := range fixtureNames(t, "ACCEPT") {
		f, err := readFixture(fixturePath(name))
		if err != nil {
			t.Fatal(err)
		}
		variants := [][]string{{"--form", "vc"}}
		if hasMLDSA65(t, name) {
			variants = append(variants, []string{"--form", "vc", "--mldsa65-proof"})
		}
		for _, flags := range variants {
			code, out, errOut := export(append(append([]string{}, flags...), fixturePath(name))...)
			if code != exitOK {
				t.Fatalf("%s %v: exit %d: %s", name, flags, code, errOut)
			}
			body := strings.TrimSuffix(out, "\n")
			canon, err := jcs.Transform([]byte(body))
			if err != nil || string(canon) != body {
				t.Errorf("%s %v: output is not in RFC 8785 canonical form", name, flags)
			}
			secured, err := decodeObject([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			checkMembers(t, name, secured, f)

			proofs := []any{secured["proof"]}
			if set, ok := secured["proof"].([]any); ok {
				proofs = set
			}
			wantProofs := 1
			if len(flags) == 3 {
				wantProofs = 2
			}
			if len(proofs) != wantProofs {
				t.Fatalf("%s %v: %d proofs, want %d", name, flags, len(proofs), wantProofs)
			}
			for i, p := range proofs {
				proof, _ := p.(map[string]any)
				suite, _ := proof["cryptosuite"].(string)
				ref, ok := f.refFor(stringMember(proof, "verificationMethod"))
				if !ok {
					t.Fatalf("%s %v: proof %d names no keypairRef", name, flags, i)
				}
				pub, _ := hex.DecodeString(ref.PublicKeyHex)
				verified := false
				switch suite {
				case suiteEdDSAJCS2022:
					verified = verifyEdDSAJCS2022(t, secured, proof, pub)
				case suiteMLDSA65JCS2024:
					verified = verifyMLDSA65JCS2024(t, secured, proof, pub)
				}
				if !verified {
					t.Errorf("%s %v: proof %d (%s) does not verify", name, flags, i, suite)
				}
				// A claim changed after export breaks the proof.
				tampered := cloneMap(secured)
				subject := cloneMap(secured["credentialSubject"].(map[string]any))
				subject["trustLevel"] = json.Number("0")
				tampered["credentialSubject"] = subject
				if suite == suiteEdDSAJCS2022 && verifyEdDSAJCS2022(t, tampered, proof, pub) {
					t.Errorf("%s %v: proof %d verifies over a changed trustLevel", name, flags, i)
				}
				if suite == suiteMLDSA65JCS2024 && verifyMLDSA65JCS2024(t, tampered, proof, pub) {
					t.Errorf("%s %v: proof %d verifies over a changed trustLevel", name, flags, i)
				}
			}
		}
	}
}

// checkMembers holds the credential to the members the form defines, and to
// the native values it carries.
func checkMembers(t *testing.T, name string, vc map[string]any, f *fixture) {
	t.Helper()
	top := []string{"@context", "atxTbsSha256", "credentialSubject", "id", "issuer", "issuerChain", "proof", "type", "validFrom", "validUntil"}
	if got := sortedNames(vc); !reflect.DeepEqual(got, top) {
		t.Errorf("%s: credential members %v, want %v", name, got, top)
	}
	if !reflect.DeepEqual(vc["@context"], []any{vcContextV2}) ||
		!reflect.DeepEqual(vc["type"], []any{"VerifiableCredential", credentialType}) {
		t.Errorf("%s: @context or type differs", name)
	}
	a := f.members
	if vc["id"] != "urn:uuid:"+a["id"].(string) || vc["issuer"] != a["issuerDid"] ||
		vc["validFrom"] != a["issuedAt"] || vc["validUntil"] != a["expiresAt"] ||
		!reflect.DeepEqual(vc["issuerChain"], a["issuerChain"]) {
		t.Errorf("%s: id, issuer, validFrom, validUntil or issuerChain differs from the native credential", name)
	}
	native, err := nativeSignedBytes(&f.native)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(native)
	if vc["atxTbsSha256"] != hex.EncodeToString(digest[:]) {
		t.Errorf("%s: atxTbsSha256 is not the SHA-256 of the native signed bytes", name)
	}
	subject, _ := vc["credentialSubject"].(map[string]any)
	allowed := map[string]string{
		"id": "agentDid", "atcVersion": "atcVersion", "agentId": "agentId", "publisher": "publisher",
		"publisherDid": "publisherDid", "version": "version", "contentHash": "contentHash",
		"buildAttestation": "buildAttestation", "capabilities": "capabilities",
		"declaredPurpose": "declaredPurpose", "behavioralProfile": "behavioralProfile",
		"scanSummary": "scanSummary", "atxTrustScore": "trustScore", "trustLevel": "trustLevel",
	}
	for k, v := range subject {
		from, ok := allowed[k]
		if !ok {
			t.Errorf("%s: credentialSubject has member %q", name, k)
			continue
		}
		if !sameJSON(t, v, a[from]) {
			t.Errorf("%s: credentialSubject.%s differs from the native %s", name, k, from)
		}
	}
	for k, from := range allowed {
		if _, carried := subject[k]; !carried {
			if v, ok := a[from]; ok && !(from == "declaredPurpose" && isNullOrEmptyObject(v)) {
				t.Errorf("%s: credentialSubject lacks %s", name, k)
			}
		}
	}
}

// sameJSON compares two JSON values by their RFC 8785 canonical forms.
func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	ca, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := canonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(ca, cb)
}

func jcsOf(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// withoutProofs returns the secured credential with its proof member
// removed. For a proof set every proof is computed over that document.
func withoutProofs(secured map[string]any) map[string]any {
	doc := cloneMap(secured)
	delete(doc, "proof")
	return doc
}

// verifyEdDSAJCS2022 follows "3.3.2 Verify Proof (eddsa-jcs-2022)" of the
// EdDSA Cryptosuites Recommendation, written here without the exporter's
// helpers.
func verifyEdDSAJCS2022(t *testing.T, secured, proof map[string]any, pub []byte) bool {
	t.Helper()
	unsecured := withoutProofs(secured)
	options := cloneMap(proof)
	delete(options, "proofValue")
	value, _ := proof["proofValue"].(string)
	if !strings.HasPrefix(value, "z") {
		return false
	}
	proofBytes, err := decodeBase58(value[1:])
	if err != nil {
		return false
	}
	if ctx, ok := options["@context"]; ok {
		docCtx, _ := secured["@context"].([]any)
		want, _ := ctx.([]any)
		if len(want) > len(docCtx) || !reflect.DeepEqual(docCtx[:len(want)], want) {
			return false
		}
		unsecured["@context"] = ctx
	}
	if options["type"] != "DataIntegrityProof" || options["cryptosuite"] != "eddsa-jcs-2022" {
		return false
	}
	docHash := sha256.Sum256(jcsOf(t, unsecured))
	configHash := sha256.Sum256(jcsOf(t, options))
	hashData := append(configHash[:], docHash[:]...)
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, hashData, proofBytes)
}

// verifyMLDSA65JCS2024 follows "Verify Proof (ML-DSA)" of the draft revision
// named at suiteMLDSA65JCS2024, with JCS, SHA-384 and ML-DSA-65, written here
// without the exporter's helpers.
func verifyMLDSA65JCS2024(t *testing.T, secured, proof map[string]any, pub []byte) bool {
	t.Helper()
	unsecured := withoutProofs(secured)
	options := cloneMap(proof)
	delete(options, "proofValue")
	value, _ := proof["proofValue"].(string)
	if !strings.HasPrefix(value, "u") {
		return false
	}
	proofBytes, err := base64.RawURLEncoding.DecodeString(value[1:])
	if err != nil {
		return false
	}
	if options["type"] != "DataIntegrityProof" || options["cryptosuite"] != "mldsa65-jcs-2024" {
		return false
	}
	config := cloneMap(options)
	config["@context"] = unsecured["@context"]
	docHash := sha512.Sum384(jcsOf(t, unsecured))
	configHash := sha512.Sum384(jcsOf(t, config))
	hashData := append(configHash[:], docHash[:]...)
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil {
		return false
	}
	return mldsa65.Verify(&pk, hashData, nil, proofBytes)
}

// TestRefusals checks the exit status and message of each refusal.
func TestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		code  int
		match string
	}{
		{"tampered claims", []string{"--form", "vc", fixturePath("v1_1-tampered-capabilities.json")}, exitNativeSignature,
			"atx-export: native signature 0 does not verify over the native bytes; not re-signing\n"},
		{"no Ed25519 signature", []string{"--form", "vc", fixturePath("hybrid-pq-only.json")}, exitUsage,
			"atx-export: --form vc needs a native Ed25519 signature\n"},
		{"no ML-DSA-65 signature", []string{"--form", "vc", "--mldsa65-proof", fixturePath("v1_1-baseline-valid.json")}, exitUsage,
			"atx-export: --mldsa65-proof needs a native ML-DSA-65 signature\n"},
		{"member written after signing", []string{"--form", "vc", fixturePath("v1_1-behavioral-profile-extra-member.json")}, exitNativeSignature,
			"atx-export: member behavioralProfile.riskLevel is not covered by the native signatures; not re-signing\n"},
		{"case-variant member", []string{"--form", "vc", fixturePath("v1_1-case-variant-member.json")}, exitInput,
			`differs from member "trustLevel" only by letter case`},
		{"duplicate member", []string{"--form", "vc", fixturePath("v1_1-duplicate-purpose-member.json")}, exitInput,
			"Duplicate key"},
		{"no fixture file", []string{"--form", "vc", fixturePath("no-such-fixture.json")}, exitInput,
			"no-such-fixture.json"},
	}
	for _, c := range cases {
		code, out, errOut := export(c.args...)
		if code != c.code || out != "" || !strings.Contains(errOut, c.match) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit %d and stderr with %q", c.name, code, out, errOut, c.code, c.match)
		}
		if c.code == exitNativeSignature || c.code == exitUsage {
			if errOut != c.match {
				t.Errorf("%s: stderr %q, want %q", c.name, errOut, c.match)
			}
		}
	}
}

// TestUsage checks the command line.
func TestUsage(t *testing.T) {
	baseline := fixturePath("v1_1-baseline-valid.json")
	cases := []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"jws", []string{"--form", "jws", baseline}, exitUsage, "atx-export: --form jws is not built yet\n"},
		{"no arguments", nil, exitUsage, "atx-export: --form is required\n" + usageLine + "\n"},
		{"no fixture", []string{"--form", "vc"}, exitUsage, "atx-export: name exactly one fixture file\n" + usageLine + "\n"},
		{"two fixtures", []string{"--form", "vc", baseline, baseline}, exitUsage, "atx-export: name exactly one fixture file\n" + usageLine + "\n"},
		{"unknown form", []string{"--form", "xml", baseline}, exitUsage, "atx-export: --form \"xml\" is not a form this command writes\n" + usageLine + "\n"},
		{"unknown flag", []string{"--sign-with", "x", baseline}, exitUsage, "atx-export: flag provided but not defined: -sign-with\n" + usageLine + "\n"},
	}
	for _, c := range cases {
		code, out, errOut := export(c.args...)
		if code != c.code || out != "" || errOut != c.stderr {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit %d, stderr %q", c.name, code, out, errOut, c.code, c.stderr)
		}
	}
	code, out, errOut := export("--help")
	if code != exitOK || !strings.HasPrefix(out, usageLine+"\n") || errOut != "" {
		t.Errorf("--help: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// TestEdDSAJCS2022RecommendationVector reproduces the eddsa-jcs-2022 test
// vector of W3C Data Integrity EdDSA Cryptosuites v1.0 (Recommendation,
// 15 May 2025), Appendix B.3, Examples 29 to 39, byte for byte. The values
// are in testdata/eddsa-jcs-2022-test-vector.json, copied from the
// Recommendation.
func TestEdDSAJCS2022RecommendationVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "eddsa-jcs-2022-test-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PublicKeyMultibase    string          `json:"publicKeyMultibase"`
		SecretKeyMultibase    string          `json:"secretKeyMultibase"`
		Credential            json.RawMessage `json:"credential"`
		CanonicalCredential   string          `json:"canonicalCredential"`
		CredentialHashHex     string          `json:"credentialHashHex"`
		ProofOptions          json.RawMessage `json:"proofOptions"`
		CanonicalProofOptions string          `json:"canonicalProofOptions"`
		ProofOptionsHashHex   string          `json:"proofOptionsHashHex"`
		CombinedHashHex       string          `json:"combinedHashHex"`
		SignatureHex          string          `json:"signatureHex"`
		ProofValue            string          `json:"proofValue"`
		SignedCredential      json.RawMessage `json:"signedCredential"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	// The secret key is a 2-byte Multikey header and the 32-byte seed. The
	// seed is right when it derives the public key of Example 29, whose
	// Multikey header is 0xed01.
	secret, err := decodeBase58(strings.TrimPrefix(v.SecretKeyMultibase, "z"))
	if err != nil || len(secret) != 34 {
		t.Fatalf("secretKeyMultibase: %d bytes, %v", len(secret), err)
	}
	key := ed25519.NewKeyFromSeed(secret[2:])
	pub, _ := key.Public().(ed25519.PublicKey)
	if got := "z" + base58btc(append([]byte{0xed, 0x01}, pub...)); got != v.PublicKeyMultibase {
		t.Fatalf("Example 29: derived publicKeyMultibase %s, want %s", got, v.PublicKeyMultibase)
	}

	unsecured, err := decodeObject(v.Credential)
	if err != nil {
		t.Fatal(err)
	}
	// Example 33 is the proof options after Create Proof step 2, which
	// copies the credential's @context into them.
	example33, err := decodeObject(v.ProofOptions)
	if err != nil {
		t.Fatal(err)
	}
	options := cloneMap(example33)
	delete(options, "@context")
	if want := proofOptions(suiteEdDSAJCS2022, options["created"], stringMember(options, "verificationMethod")); !reflect.DeepEqual(options, want) {
		t.Fatalf("Example 33 has members other than the proof options this command writes: %v", options)
	}
	if !reflect.DeepEqual(example33["@context"], unsecured["@context"]) {
		t.Fatal("Example 33's @context is not the credential's")
	}

	transformed, err := transformation(unsecured, options, suiteEdDSAJCS2022)
	if err != nil || string(transformed) != v.CanonicalCredential {
		t.Fatalf("Example 31: transformation gives %s, %v", transformed, err)
	}
	if h := sha256.Sum256(transformed); hex.EncodeToString(h[:]) != v.CredentialHashHex {
		t.Fatalf("Example 32: hash %x", h)
	}
	config, err := proofConfiguration(example33, suiteEdDSAJCS2022)
	if err != nil || string(config) != v.CanonicalProofOptions {
		t.Fatalf("Example 34: proof configuration gives %s, %v", config, err)
	}
	if h := sha256.Sum256(config); hex.EncodeToString(h[:]) != v.ProofOptionsHashHex {
		t.Fatalf("Example 35: hash %x", h)
	}
	hashData := hashing(sha256.New, transformed, config)
	if hex.EncodeToString(hashData) != v.CombinedHashHex {
		t.Fatalf("Example 36: combined hash %x", hashData)
	}
	sig := ed25519.Sign(key, hashData)
	if hex.EncodeToString(sig) != v.SignatureHex {
		t.Fatalf("Example 37: signature %x", sig)
	}
	if got := "z" + base58btc(sig); got != v.ProofValue {
		t.Fatalf("Example 38: base58-btc %s", got)
	}

	proof, err := createEdDSAJCS2022Proof(unsecured, options, key)
	if err != nil {
		t.Fatal(err)
	}
	secured := cloneMap(unsecured)
	secured["proof"] = proof
	want, err := decodeObject(v.SignedCredential)
	if err != nil {
		t.Fatal(err)
	}
	if got, w := jcsOf(t, secured), jcsOf(t, want); !bytes.Equal(got, w) {
		t.Fatalf("Example 39: signed credential\n got %s\nwant %s", got, w)
	}
	if !verifyEdDSAJCS2022(t, secured, proof, pub) {
		t.Fatal("Example 39 does not verify")
	}
}

// TestBase58 round-trips values with and without leading zero bytes.
func TestBase58(t *testing.T) {
	values := [][]byte{{}, {0}, {0, 0, 1}, {0xff}, {0, 0x28, 0x7f, 0xb4, 0xcd}, bytes.Repeat([]byte{0xa5}, 64)}
	for _, v := range values {
		enc := base58btc(v)
		dec, err := decodeBase58(enc)
		if err != nil || !bytes.Equal(dec, v) {
			t.Errorf("%x: encodes to %q, decodes to %x, %v", v, enc, dec, err)
		}
		if strings.Trim(enc, base58Alphabet) != "" {
			t.Errorf("%x: %q leaves the alphabet", v, enc)
		}
	}
	if base58btc([]byte{0, 0, 1}) != "112" {
		t.Errorf("leading zero bytes: %q", base58btc([]byte{0, 0, 1}))
	}
}

// decodeBase58 decodes the Bitcoin base-58 alphabet.
func decodeBase58(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == base58Alphabet[0] {
		zeros++
	}
	n, radix := new(big.Int), big.NewInt(58)
	for _, c := range s[zeros:] {
		d := strings.IndexRune(base58Alphabet, c)
		if d < 0 {
			return nil, errors.New("not base-58")
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(d)))
	}
	return append(make([]byte, zeros), n.Bytes()...), nil
}

// TestXSDDateTime checks the dateTime pattern the proof configuration
// applies to created.
func TestXSDDateTime(t *testing.T) {
	for _, s := range []string{"2026-05-23T00:00:00Z", "2023-02-24T23:36:38Z", "2026-05-23T02:00:00.5+02:00", "2026-05-23T00:00:00"} {
		if !xsdDateTime.MatchString(s) {
			t.Errorf("%q: not matched", s)
		}
	}
	for _, s := range []string{"2026-05-23", "2026-13-01T00:00:00Z", "2026-05-23 00:00:00Z", "2026-05-23T25:00:00Z", ""} {
		if xsdDateTime.MatchString(s) {
			t.Errorf("%q: matched", s)
		}
	}
}

// TestFixtureNamesAreSorted guards the order fixtureNames relies on.
func TestFixtureNamesAreSorted(t *testing.T) {
	names := fixtureNames(t, "")
	if !sort.StringsAreSorted(names) {
		t.Error("fs.Glob did not return sorted names")
	}
}
