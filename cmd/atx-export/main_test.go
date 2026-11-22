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
	"math"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"

	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
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
		if !sameNumbersAsWritten(v, a[from]) {
			t.Errorf("%s: credentialSubject.%s does not hold each number as the native %s writes it", name, k, from)
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

// sameNumbersAsWritten reports whether a and b, two JSON values decoded with
// numbers as written, hold at the same places numbers written alike.
// sameJSON compares canonical forms, in which 9007199254740993 and
// 9007199254740992 are one number, and so are 1e3 and 1000.
func sameNumbersAsWritten(a, b any) bool {
	switch a := a.(type) {
	case json.Number:
		n, ok := b.(json.Number)
		return ok && n == a
	case map[string]any:
		m, ok := b.(map[string]any)
		if !ok || len(m) != len(a) {
			return false
		}
		for k, v := range a {
			if w, ok := m[k]; !ok || !sameNumbersAsWritten(v, w) {
				return false
			}
		}
		return true
	case []any:
		s, ok := b.([]any)
		if !ok || len(s) != len(a) {
			return false
		}
		for i := range a {
			if !sameNumbersAsWritten(a[i], s[i]) {
				return false
			}
		}
		return true
	default:
		_, isNumber := b.(json.Number)
		return !isNumber
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
	emptyTechniques, _, _ := alteredFixture(t, "v1_1-baseline-valid.json", func(atx map[string]any) {
		atx["scanSummary"].(map[string]any)["techniques"] = []any{}
	})
	nullChecksum, _, _ := signedAlteredFixture(t, "v1_1-baseline-valid.json", func(atx map[string]any) {
		atx["behavioralProfile"].(map[string]any)["checksum"] = nil
	})
	unpairedEscape, _, _ := signedAlteredFixture(t, "v1_1-baseline-valid.json", func(atx map[string]any) {
		atx["declaredPurpose"] = json.RawMessage(`{"s":"` + backslashU + "d800" + backslashU + `0041"}`)
	})
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
		{"scanSummary member written after signing", []string{"--form", "vc", fixturePath("v1_1-scan-summary-extra-member.json")}, exitNativeSignature,
			"atx-export: member scanSummary.extra is not covered by the native signatures; not re-signing\n"},
		{"empty scanSummary.techniques", []string{"--form", "vc", emptyTechniques}, exitNativeSignature,
			"atx-export: member scanSummary.techniques is not covered by the native signatures; not re-signing\n"},
		{"null behavioralProfile.checksum, signed over the empty string", []string{"--form", "vc", nullChecksum}, exitNativeSignature,
			"atx-export: no native signature covers behavioralProfile, which is not an object of exactly checksum (a string), generatedAt (a timestamp) and observationDays (an integer); not re-signing\n"},
		{"count above 2^53-1", []string{"--form", "vc", fixturePath("v1_1-integer-outside-exact-range.json")}, exitNativeSignature,
			"atx-export: no native signature covers scanSummary.criticalFindings: the integer 9007199254740993 is outside the I-JSON exact range, -(2^53-1) to 2^53-1; not re-signing\n"},
		{"declaredPurpose integer above 2^53-1", []string{"--form", "vc", fixturePath("v1_1-declared-purpose-integer-outside-range.json")}, exitNativeSignature,
			"atx-export: no native signature covers declaredPurpose: the integer 9007199254740993 is outside the I-JSON exact range, -(2^53-1) to 2^53-1; not re-signing\n"},
		{"declaredPurpose number with an exponent part", []string{"--form", "vc", fixturePath("v1_1-declared-purpose-integer-respelled-exponent.json")}, exitNativeSignature,
			"atx-export: no native signature covers declaredPurpose: the number 1e3 is written with a fraction or an exponent part, not as an integer; not re-signing\n"},
		{"declaredPurpose number with a fraction", []string{"--form", "vc", fixturePath("v1_1-declared-purpose-integer-respelled-fraction.json")}, exitNativeSignature,
			"atx-export: no native signature covers declaredPurpose: the number 1000.0 is written with a fraction or an exponent part, not as an integer; not re-signing\n"},
		{"declaredPurpose number with an upper-case exponent part", []string{"--form", "vc", fixturePath("v1_1-declared-purpose-integer-respelled-upper-exponent.json")}, exitNativeSignature,
			"atx-export: no native signature covers declaredPurpose: the number 1E3 is written with a fraction or an exponent part, not as an integer; not re-signing\n"},
		{"case-variant member", []string{"--form", "vc", fixturePath("v1_1-case-variant-member.json")}, exitInput,
			`differs from member "trustLevel" only by letter case`},
		{"duplicate member", []string{"--form", "vc", fixturePath("v1_1-duplicate-purpose-member.json")}, exitInput,
			"Duplicate key"},
		{"declaredPurpose with an unpaired surrogate escape, signed over the bytes the library gives", []string{"--form", "vc", unpairedEscape}, exitInput,
			"atx cannot be canonicalized (RFC 8785): declaredPurpose holds an unpaired UTF-16 surrogate escape (" + backslashU + "d800)\n"},
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

// noSignatureCovers opens each reason the Go reference verifier gives for a
// credential it rejects because no signature covers something the
// credential holds.
const noSignatureCovers = "no signature covers "

// alteredFixture writes a copy of the suite fixture name, its atx object
// changed by alter, into a new folder laid out as the suite is: the copy
// under fixtures/, beside a vectors/ folder holding the suite's vector
// files. It returns the copy's path, and its atx and verifierState members
// as the copy holds them. Each number alter does not change stays as the
// fixture writes it.
func alteredFixture(t *testing.T, name string, alter func(atx map[string]any)) (file string, atxRaw, state []byte) {
	t.Helper()
	raw, err := fs.ReadFile(repo, "fixtures/"+name)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	atx, err := decodeObject(top["atx"])
	if err != nil {
		t.Fatal(err)
	}
	alter(atx)
	if top["atx"], err = json.Marshal(atx); err != nil {
		t.Fatal(err)
	}
	text, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, sub := range []string{"fixtures", "vectors"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	vectors, err := fs.Glob(repo, "vectors/*.json")
	if err != nil || len(vectors) == 0 {
		t.Fatalf("vectors/*.json: %d files, %v", len(vectors), err)
	}
	for _, v := range vectors {
		data, err := fs.ReadFile(repo, v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vectors", path.Base(v)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file = filepath.Join(dir, "fixtures", name)
	if err := os.WriteFile(file, text, 0o600); err != nil {
		t.Fatal(err)
	}
	return file, top["atx"], top["verifierState"]
}

// TestAlteredFixtureCopyExports guards the helper above: a copy that
// changes nothing exports the bytes the suite's own fixture exports, so a
// refusal of an altered copy is a refusal of the change.
func TestAlteredFixtureCopyExports(t *testing.T) {
	const name = "v1_1-baseline-valid.json"
	file, _, _ := alteredFixture(t, name, func(map[string]any) {})
	code, out, errOut := export("--form", "vc", file)
	wantCode, want, _ := export("--form", "vc", fixturePath(name))
	if code != exitOK || wantCode != exitOK || out == "" || out != want {
		t.Errorf("an unchanged copy of %s: exit %d, stderr %q; the fixture: exit %d; same output: %t", name, code, errOut, wantCode, out == want)
	}
}

// signedAlteredFixture is alteredFixture with every native signature of the
// copy made again: over the bytes the command computes for the altered
// credential, with the suite's published test key the signature names. A
// copy that keeps the fixture's signatures is refused for the first of them
// whatever else it holds; a copy signed this way is refused only for what it
// holds. Every native signature of the fixture must be Ed25519, and the
// command must be able to read the altered copy.
func signedAlteredFixture(t *testing.T, name string, alter func(atx map[string]any)) (file string, atxRaw, state []byte) {
	t.Helper()
	unsigned, _, _ := alteredFixture(t, name, alter)
	f, err := readFixture(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	native, err := nativeSignedBytes(&f.native)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]string, len(f.native.Signatures))
	for i, sig := range f.native.Signatures {
		key, err := f.ed25519Key(sig.KeyID)
		if err != nil {
			t.Fatalf("%s: native signature %d: %v", name, i, err)
		}
		values[i] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, native))
	}
	return alteredFixture(t, name, func(atx map[string]any) {
		alter(atx)
		sigs, _ := atx["signatures"].([]any)
		if len(sigs) != len(values) {
			t.Fatalf("%s: the altered copy holds %d signatures, the command read %d", name, len(sigs), len(values))
		}
		for i, value := range values {
			sigs[i].(map[string]any)["value"] = value
		}
	})
}

// signedAsReadFixture is alteredFixture with every native signature of the
// copy made again: over the bytes the command computes for the copy that
// read writes, with the suite's published test key the signature names.
// read writes a member as a build of the command that reads the member alter
// writes reads it, so the copy alter writes is one whose native signatures
// verify for such a build, even when the command cannot read that copy.
// Every native signature of the fixture must be Ed25519, and the command
// must be able to read the copy read writes.
func signedAsReadFixture(t *testing.T, name string, read, alter func(atx map[string]any)) (file string, atxRaw, state []byte) {
	t.Helper()
	unsigned, _, _ := alteredFixture(t, name, read)
	f, err := readFixture(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	native, err := nativeSignedBytes(&f.native)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]string, len(f.native.Signatures))
	for i, sig := range f.native.Signatures {
		key, err := f.ed25519Key(sig.KeyID)
		if err != nil {
			t.Fatalf("%s: native signature %d: %v", name, i, err)
		}
		values[i] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, native))
	}
	return alteredFixture(t, name, func(atx map[string]any) {
		alter(atx)
		sigs, _ := atx["signatures"].([]any)
		if len(sigs) != len(values) {
			t.Fatalf("%s: the altered copy holds %d signatures, the fixture %d", name, len(sigs), len(values))
		}
		for i, value := range values {
			sigs[i].(map[string]any)["value"] = value
		}
	})
}

// TestSignedAlteredFixtureCopyIsTheFixture guards the helper above: for a
// copy that changes nothing, the signature it makes is the fixture's own, so
// the copy holds the credential the unsigned helper writes.
func TestSignedAlteredFixtureCopyIsTheFixture(t *testing.T) {
	const name = "v1_1-baseline-valid.json"
	_, signed, _ := signedAlteredFixture(t, name, func(map[string]any) {})
	_, kept, _ := alteredFixture(t, name, func(map[string]any) {})
	if len(signed) == 0 || !bytes.Equal(signed, kept) {
		t.Errorf("an unchanged copy of %s, signed again, differs from the copy that keeps the fixture's signature", name)
	}
	_, read, _ := signedAsReadFixture(t, name, func(map[string]any) {}, func(map[string]any) {})
	if len(read) == 0 || !bytes.Equal(read, kept) {
		t.Errorf("an unchanged copy of %s, signed again as read, differs from the copy that keeps the fixture's signature", name)
	}
}

// TestNumbersNoNativeSignatureCovers holds the command's rule for the
// numbers of a "1.1" credential to the Go reference verifier's, on copies
// of the v1.1 baseline that change one or two numbers. Where the row names
// a member, the verifier rejects the copy because no signature covers that
// member's number, and the command exits 3 naming the same member and
// number in the verifier's words. Where it names none, the number is in the
// exact range, the verifier rejects the copy for the signature the change
// breaks, and the command refuses that native signature.
func TestNumbersNoNativeSignatureCovers(t *testing.T) {
	number := func(s string) json.Number { return json.Number(s) }
	inObject := func(object, member, value string) func(map[string]any) {
		return func(atx map[string]any) {
			atx[object].(map[string]any)[member] = number(value)
		}
	}
	both := func(alter ...func(map[string]any)) func(map[string]any) {
		return func(atx map[string]any) {
			for _, a := range alter {
				a(atx)
			}
		}
	}
	trustLevel := func(value string) func(map[string]any) {
		return func(atx map[string]any) { atx["trustLevel"] = number(value) }
	}
	purpose := func(value any) func(map[string]any) {
		return func(atx map[string]any) { atx["declaredPurpose"] = value }
	}
	cases := []struct {
		name  string
		alter func(atx map[string]any)
		where string
	}{
		{"criticalFindings 2^53", inObject("scanSummary", "criticalFindings", "9007199254740992"), "scanSummary.criticalFindings"},
		{"criticalFindings -(2^53)", inObject("scanSummary", "criticalFindings", "-9007199254740992"), "scanSummary.criticalFindings"},
		{"highFindings 2^53+1", inObject("scanSummary", "highFindings", "9007199254740993"), "scanSummary.highFindings"},
		{"observationDays 2^53", inObject("behavioralProfile", "observationDays", "9007199254740992"), "behavioralProfile.observationDays"},
		{"trustLevel 2^53", trustLevel("9007199254740992"), "trustLevel"},
		{"trustLevel -(2^53)", trustLevel("-9007199254740992"), "trustLevel"},
		{"declaredPurpose: a fraction before an integer above 2^53-1",
			purpose(map[string]any{"a": number("1"), "b": []any{number("2.5"), number("9007199254740993")}}), "declaredPurpose"},
		{"declaredPurpose: an integer above 2^53-1 before a fraction",
			purpose(map[string]any{"a": number("9007199254740993"), "b": number("2.5")}), "declaredPurpose"},
		{"declaredPurpose: an integer outside the int64 range", purpose(map[string]any{"n": number("12345678901234567890")}), "declaredPurpose"},
		{"declaredPurpose: -(2^53)", purpose(map[string]any{"n": number("-9007199254740992")}), "declaredPurpose"},
		{"declaredPurpose: an exponent part, nested", purpose(map[string]any{"a": map[string]any{"b": []any{number("0e0")}}}), "declaredPurpose"},
		{"declaredPurpose: a number, not an object", purpose(number("1E3")), "declaredPurpose"},
		{"observationDays before trustLevel",
			both(inObject("behavioralProfile", "observationDays", "9007199254740992"), trustLevel("9007199254740993")), "behavioralProfile.observationDays"},
		{"declaredPurpose before criticalFindings",
			both(purpose(map[string]any{"n": number("9007199254740992")}), inObject("scanSummary", "criticalFindings", "9007199254740993")), "declaredPurpose"},
		{"criticalFindings before highFindings",
			both(inObject("scanSummary", "criticalFindings", "9007199254740992"), inObject("scanSummary", "highFindings", "9007199254740993")), "scanSummary.criticalFindings"},
		{"highFindings before trustLevel",
			both(inObject("scanSummary", "highFindings", "9007199254740992"), trustLevel("9007199254740993")), "scanSummary.highFindings"},
		{"criticalFindings 2^53-1", inObject("scanSummary", "criticalFindings", "9007199254740991"), ""},
		{"highFindings -(2^53-1)", inObject("scanSummary", "highFindings", "-9007199254740991"), ""},
		{"observationDays 2^53-1", inObject("behavioralProfile", "observationDays", "9007199254740991"), ""},
		{"trustLevel 2^53-1", trustLevel("9007199254740991"), ""},
		{"declaredPurpose: 2^53-1 and -(2^53-1)", purpose(map[string]any{"a": number("9007199254740991"), "b": number("-9007199254740991")}), ""},
	}
	for _, c := range cases {
		file, atxRaw, state := alteredFixture(t, "v1_1-baseline-valid.json", c.alter)
		outcome := verifier.VerifyCredential(atxRaw, state)
		want := "atx-export: native signature 0 does not verify over the native bytes; not re-signing\n"
		switch {
		case outcome.Verdict != "REJECT" || outcome.RejectCategory != "SIGNATURE_INVALID":
			t.Errorf("%s: the reference verifier gives %s %s (%s), want REJECT SIGNATURE_INVALID", c.name, outcome.Verdict, outcome.RejectCategory, outcome.Reason)
			continue
		case c.where != "" && !strings.HasPrefix(outcome.Reason, noSignatureCovers+c.where+": "):
			t.Errorf("%s: the reference verifier's reason is %q, want one that starts %q", c.name, outcome.Reason, noSignatureCovers+c.where+": ")
			continue
		case c.where == "" && strings.HasPrefix(outcome.Reason, noSignatureCovers):
			t.Errorf("%s: the reference verifier's reason is %q, want the signature the change breaks", c.name, outcome.Reason)
			continue
		case c.where != "":
			want = "atx-export: no native signature covers " + strings.TrimPrefix(outcome.Reason, noSignatureCovers) + "; not re-signing\n"
		}
		code, out, errOut := export("--form", "vc", file)
		if code != exitNativeSignature || out != "" || errOut != want {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit %d and stderr %q", c.name, code, out, errOut, exitNativeSignature, want)
		}
	}
}

// TestUncoveredNumberReadsOnlyV11 checks that the rule is the "1.1" signed
// bytes' own: a "1.0" credential's signed string writes trustLevel digit for
// digit and holds no other number the rule reads, and a "1.1" credential
// with no behavioralProfile, scanSummary or declaredPurpose has none of
// their numbers.
func TestUncoveredNumberReadsOnlyV11(t *testing.T) {
	over := maxExactInteger + 1
	big := int(over)
	if int64(big) != over {
		t.Skip("int is narrower than 64 bits here: it holds no integer above 2^53-1")
	}
	full := func(version string) *ATX {
		return &ATX{
			ATCVersion:        version,
			TrustLevel:        big,
			BehavioralProfile: &ATCBehavioralProfile{ObservationDays: big},
			ScanSummary:       &ATCScanSummary{CriticalFindings: big, HighFindings: big},
			DeclaredPurpose:   json.RawMessage(`{"n":1e3}`),
		}
	}
	if where, literal, _ := uncoveredNumber(full(atcVersion)); where != "" {
		t.Errorf("a %q credential: %s %s", atcVersion, where, literal)
	}
	if where, _, _ := uncoveredNumber(full(atcVersionV11)); where != "behavioralProfile.observationDays" {
		t.Errorf("a %q credential: %q, want behavioralProfile.observationDays", atcVersionV11, where)
	}
	for _, purpose := range []string{"", "null", "{}", " { } ", `{"n":9007199254740991}`, `"1e3"`} {
		bare := &ATX{ATCVersion: atcVersionV11, TrustLevel: 4, DeclaredPurpose: json.RawMessage(purpose)}
		if where, literal, _ := uncoveredNumber(bare); where != "" {
			t.Errorf("declaredPurpose %q and no behavioralProfile or scanSummary: %s %s", purpose, where, literal)
		}
	}
}

// TestScanSummaryTechniquesIsNotCovered checks that a scanSummary member
// named techniques is refused whatever it holds, null and an empty array
// included: the v1.1 signed bytes carry scanSummary's six members and no
// other, and the Go reference verifier rejects each of these copies of the
// v1.1 baseline because scanSummary holds a member other than its six. The
// change leaves the signed bytes as they were, so the native signature
// still verifies and the refusal is of the member.
func TestScanSummaryTechniquesIsNotCovered(t *testing.T) {
	values := []struct {
		name  string
		value any
	}{
		{"null", nil},
		{"an empty array", []any{}},
		{"an array of one technique", []any{"T-1001"}},
		{"an empty object", map[string]any{}},
		{"an empty string", ""},
	}
	for _, v := range values {
		file, atxRaw, state := alteredFixture(t, "v1_1-baseline-valid.json", func(atx map[string]any) {
			atx["scanSummary"].(map[string]any)["techniques"] = v.value
		})
		outcome := verifier.VerifyCredential(atxRaw, state)
		if wantReason := noSignatureCovers + "scanSummary, which holds a member other than its six"; outcome.Verdict != "REJECT" || outcome.Reason != wantReason {
			t.Errorf("techniques %s: the reference verifier gives %s (%s), want REJECT with the reason %q", v.name, outcome.Verdict, outcome.Reason, wantReason)
		}
		for _, flags := range [][]string{{"--form", "vc"}, {"--form", "vc", "--mldsa65-proof"}} {
			code, out, errOut := export(append(append([]string{}, flags...), file)...)
			want := "atx-export: member scanSummary.techniques is not covered by the native signatures; not re-signing\n"
			if code != exitNativeSignature || out != "" || errOut != want {
				t.Errorf("techniques %s %v: exit %d, %d bytes written, stderr %q; want exit %d and stderr %q", v.name, flags, code, len(out), errOut, exitNativeSignature, want)
			}
		}
	}
}

// TestBehavioralProfileOutsideItsForm holds the command to the Go reference
// verifier on copies of the v1.1 baseline that write behavioralProfile as
// each row gives it. The v1.1 signed bytes have a value for a profile that
// is absent or null, and for an object of exactly checksum (a string),
// generatedAt (a timestamp) and observationDays (an integer); the verifier
// rejects a copy holding any other profile before it reads a signature.
//
// A row marked outside is such a profile. The command writes nothing for
// it. Where the command can read the copy, it is run twice, keeping the
// fixture's signature and signed again over the bytes the command computes,
// and exits 3 both times in the verifier's words, with and without
// --mldsa65-proof: the typed decode reads a member that is null or absent as
// its zero value, so the signature made again verifies. Where the typed
// decode of this Go release refuses the profile, the command cannot read
// the copy and exits 1; which rows those are depends on the release for the
// three rows that write generatedAt in a form only some releases read.
//
// A row marked member holds a member outside the three, which the command
// refuses by name once the native signatures have verified. Every other row
// is a profile the signed bytes have a value for: signed again, the
// verifier accepts the copy and the command exports it.
func TestBehavioralProfileOutsideItsForm(t *testing.T) {
	const (
		name        = "v1_1-baseline-valid.json"
		checksum    = `"checksum":"sha256:ghi789"`
		generatedAt = `"generatedAt":"2026-05-19T00:00:00Z"`
		days        = `"observationDays":14`
		wantReason  = noSignatureCovers + "behavioralProfile, which is not an object of exactly checksum (a string), generatedAt (a timestamp) and observationDays (an integer)"
		wantRefusal = "atx-export: no native signature covers behavioralProfile, which is not an object of exactly checksum (a string), generatedAt (a timestamp) and observationDays (an integer); not re-signing\n"
		wantMember  = "atx-export: member behavioralProfile.riskLevel is not covered by the native signatures; not re-signing\n"
	)
	object := func(members ...string) string { return "{" + strings.Join(members, ",") + "}" }
	at := func(timestamp string) string { return `"generatedAt":"` + timestamp + `"` }
	// The baseline's generatedAt with its first hyphen written as the JSON
	// escape of U+002D. The backslash is built here, so that this file
	// holds no escape for a tool to decode on the way in.
	escaped := at("2026" + string(rune(0x5c)) + "u002d05-19T00:00:00Z")
	const (
		inside = iota
		outside
		member
	)
	rows := []struct {
		name    string
		profile string // as written; "" for a credential with no behavioralProfile
		kind    int
	}{
		{"the baseline's profile", object(checksum, generatedAt, days), inside},
		{"null", "null", inside},
		{"no behavioralProfile", "", inside},
		{"generatedAt with a time zone offset of +24:00", object(checksum, at("2026-05-19T00:00:00+24:00"), days), inside},
		{"generatedAt with a time zone offset of +23:60", object(checksum, at("2026-05-19T00:00:00+23:60"), days), inside},
		{"a member outside the three", object(checksum, generatedAt, days, `"riskLevel":"low"`), member},
		{"checksum null", object(`"checksum":null`, generatedAt, days), outside},
		{"no checksum", object(generatedAt, days), outside},
		{"generatedAt null", object(checksum, `"generatedAt":null`, days), outside},
		{"no generatedAt", object(checksum, days), outside},
		{"observationDays null", object(checksum, generatedAt, `"observationDays":null`), outside},
		{"no observationDays", object(checksum, generatedAt), outside},
		{"an empty object", object(), outside},
		{"generatedAt with a time zone offset hour of 25", object(checksum, at("2026-05-19T00:00:00+25:00"), days), outside},
		{"generatedAt with a time zone offset minute of 61", object(checksum, at("2026-05-19T00:00:00+23:61"), days), outside},
		{"generatedAt written with a JSON escape", object(checksum, escaped, days), outside},
		{"generatedAt a date", object(checksum, at("2026-05-19"), days), outside},
		{"generatedAt a number", object(checksum, `"generatedAt":5`, days), outside},
		{"checksum a number", object(`"checksum":5`, generatedAt, days), outside},
		{"observationDays a string", object(checksum, generatedAt, `"observationDays":"14"`), outside},
		{"observationDays with a fraction part", object(checksum, generatedAt, `"observationDays":14.0`), outside},
		{"a number", "7", outside},
		{"an array", "[]", outside},
	}
	for _, row := range rows {
		alter := func(atx map[string]any) {
			if row.profile == "" {
				delete(atx, "behavioralProfile")
				return
			}
			atx["behavioralProfile"] = json.RawMessage(row.profile)
		}
		if got := profileOutsideForm(&ATX{ATCVersion: atcVersionV11}, json.RawMessage(row.profile)); got != (row.kind == outside) {
			t.Errorf("%s: profileOutsideForm gives %t", row.name, got)
		}
		kept, atxRaw, state := alteredFixture(t, name, alter)
		if !bytes.Contains(atxRaw, []byte(row.profile)) {
			t.Fatalf("%s: the copy does not hold the profile as the row writes it", row.name)
		}
		// The verifier's reason is the profile's form for a row outside the
		// form and for a member outside the three, and for no other row.
		reason := verifier.VerifyCredential(atxRaw, state).Reason
		if (reason == wantReason) != (row.kind != inside) {
			t.Errorf("%s: the reference verifier's reason is %q", row.name, reason)
			continue
		}
		if _, err := readFixture(kept); err != nil {
			code, out, errOut := export("--form", "vc", kept)
			if row.kind != outside || code != exitInput || out != "" {
				t.Errorf("%s: the command cannot read the copy (%v): exit %d, %d bytes written, stderr %q; want exit %d and nothing written, for a row outside the form", row.name, err, code, len(out), errOut, exitInput)
			}
			continue
		}
		signed, signedRaw, _ := signedAlteredFixture(t, name, alter)
		if row.kind == inside {
			if outcome := verifier.VerifyCredential(signedRaw, state); outcome.Verdict != "ACCEPT" {
				t.Errorf("%s, signed again: the reference verifier gives %s %s (%s), want ACCEPT", row.name, outcome.Verdict, outcome.RejectCategory, outcome.Reason)
			}
			if code, out, errOut := export("--form", "vc", signed); code != exitOK || out == "" {
				t.Errorf("%s, signed again: exit %d, %d bytes written, stderr %q; want exit %d and a credential", row.name, code, len(out), errOut, exitOK)
			}
			continue
		}
		want := wantRefusal
		if row.kind == member {
			want = wantMember
		}
		for _, file := range []string{kept, signed} {
			for _, flags := range [][]string{{"--form", "vc"}, {"--form", "vc", "--mldsa65-proof"}} {
				code, out, errOut := export(append(append([]string{}, flags...), file)...)
				if code != exitNativeSignature || out != "" || errOut != want {
					t.Errorf("%s, signed again %t, %v: exit %d, %d bytes written, stderr %q; want exit %d and stderr %q", row.name, file == signed, flags, code, len(out), errOut, exitNativeSignature, want)
				}
			}
		}
	}
	if profileOutsideForm(&ATX{ATCVersion: atcVersion}, json.RawMessage("{}")) {
		t.Errorf("a %q credential: profileOutsideForm reads its behavioralProfile, which no %q signature covers", atcVersion, atcVersion)
	}
}

// TestOffsetOutOfRange checks the reading of a time zone offset that
// profileOutsideForm applies to a generatedAt this Go release has decoded.
func TestOffsetOutOfRange(t *testing.T) {
	for timestamp, want := range map[string]bool{
		"2026-05-19T00:00:00Z":      false,
		"2026-05-19T00:00:00+00:00": false,
		"2026-05-19T00:00:00+24:00": false,
		"2026-05-19T00:00:00+23:60": false,
		"2026-05-19T00:00:00-24:60": false,
		"2026-05-19T00:00:00+25:00": true,
		"2026-05-19T00:00:00-25:00": true,
		"2026-05-19T00:00:00+23:61": true,
		"2026-05-19T00:00:00+99:99": true,
		"":                          false,
	} {
		if got := offsetOutOfRange(timestamp); got != want {
			t.Errorf("%q: %t, want %t", timestamp, got, want)
		}
	}
}

// backslashU opens the JSON escape of a UTF-16 code unit. It is built here,
// so that this file holds no such escape for a tool to decode on the way in.
var backslashU = string(rune(0x5c)) + "u"

// TestDeclaredPurposeUnpairedSurrogateEscape holds the command to the Go
// reference verifier on copies of the v1.1 baseline whose declaredPurpose
// holds a UTF-16 surrogate escape that is one half of a pair without the
// other. RFC 8785 refuses such a string. The library that computes the
// native bytes refuses the escape only when no other escape follows it
// directly: followed by one, it reads the two as a single U+FFFD, where
// encoding/json, which decodes the declaredPurpose the credential carries,
// reads U+FFFD and then the second escape's character. Each such copy is
// signed again over the bytes the library gives, so its native signature
// verifies; the verifier rejects it before it canonicalizes, naming the
// escape, and the command exits 1 naming the same escape, with and without
// --mldsa65-proof. In a row marked accepted the declaredPurpose holds no
// unpaired escape: the verifier accepts the copy, and the command exports it
// with the declaredPurpose the native bytes hold.
func TestDeclaredPurposeUnpairedSurrogateEscape(t *testing.T) {
	const (
		name           = "v1_1-baseline-valid.json"
		canonicalizing = "v1.1 canonicalization failed: "
		unpaired       = "declaredPurpose holds an unpaired UTF-16 surrogate escape ("
	)
	esc := func(unit string) string { return backslashU + unit }
	text := func(s string) string { return `{"s":"` + s + `"}` }
	rows := []struct {
		name    string
		purpose string // declaredPurpose as written
		escape  string // the escape the refusal names; "" for a row that is accepted
	}{
		{"a high surrogate, then the escape of a letter", text("x" + esc("d800") + esc("0041") + "y"), esc("d800")},
		{"a low surrogate, then the escape of a letter", text("x" + esc("dc00") + esc("0041") + "y"), esc("dc00")},
		{"two high surrogates", text(esc("d800") + esc("d800")), esc("d800")},
		{"a low surrogate, then a high one", text(esc("dc00") + esc("d800")), esc("dc00")},
		{"two low surrogates", text(esc("dfff") + esc("dfff")), esc("dfff")},
		{"the last high surrogate, then the escape of a space", `{"a":[{"b":"` + esc("dbff") + esc("0020") + `"}]}`, esc("dbff")},
		{"upper-case digits", text(esc("D800") + esc("0041")), esc("D800")},
		{"in a member name", `{"` + esc("d800") + esc("0041") + `":1}`, esc("d800")},
		{"a declaredPurpose that is a string", `"` + esc("d800") + esc("0041") + `"`, esc("d800")},
		{"after a complete pair", text(esc("d83d") + esc("de00") + esc("d800") + esc("0041")), esc("d800")},
		{"beside a number with an exponent part", `{"n":1e3,"s":"` + esc("d800") + esc("0041") + `"}`, esc("d800")},
		{"a literal U+FFFD", text("x" + string(rune(0xfffd)) + "y"), ""},
		{"a complete pair", text("x" + esc("d83d") + esc("de00") + "y"), ""},
		{"the escape of a letter and of U+FFFD", text(esc("0041") + esc("fffd")), ""},
		{"an escaped backslash before the letters of an escape", text("x" + string(rune(0x5c)) + backslashU + "d800y"), ""},
	}
	for _, row := range rows {
		file, atxRaw, state := signedAlteredFixture(t, name, func(atx map[string]any) {
			atx["declaredPurpose"] = json.RawMessage(row.purpose)
		})
		if !bytes.Contains(atxRaw, []byte(row.purpose)) {
			t.Fatalf("%s: the copy does not hold the declaredPurpose as the row writes it", row.name)
		}
		outcome := verifier.VerifyCredential(atxRaw, state)
		if row.escape == "" {
			if outcome.Verdict != "ACCEPT" {
				t.Errorf("%s: the reference verifier gives %s %s (%s), want ACCEPT", row.name, outcome.Verdict, outcome.RejectCategory, outcome.Reason)
				continue
			}
			code, out, errOut := export("--form", "vc", file)
			if code != exitOK {
				t.Errorf("%s: exit %d, stderr %q; want exit %d and a credential", row.name, code, errOut, exitOK)
				continue
			}
			secured, err := decodeObject([]byte(strings.TrimSuffix(out, "\n")))
			if err != nil {
				t.Fatal(err)
			}
			subject, _ := secured["credentialSubject"].(map[string]any)
			written, err := canonicalJSON(subject["declaredPurpose"])
			if err != nil {
				t.Fatal(err)
			}
			native, err := jcs.Transform([]byte(row.purpose))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(written, native) {
				t.Errorf("%s: the credential carries the declaredPurpose %s, the native bytes hold %s", row.name, written, native)
			}
			continue
		}
		wantReason := canonicalizing + unpaired + row.escape + ")"
		if outcome.Verdict != "REJECT" || outcome.RejectCategory != "VERIFIER_CONFIG_ERROR" || outcome.Reason != wantReason {
			t.Errorf("%s: the reference verifier gives %s %s (%s), want REJECT VERIFIER_CONFIG_ERROR with the reason %q", row.name, outcome.Verdict, outcome.RejectCategory, outcome.Reason, wantReason)
			continue
		}
		want := "atx-export: " + file + ": atx cannot be canonicalized (RFC 8785): " + strings.TrimPrefix(outcome.Reason, canonicalizing) + "\n"
		for _, flags := range [][]string{{"--form", "vc"}, {"--form", "vc", "--mldsa65-proof"}} {
			code, out, errOut := export(append(append([]string{}, flags...), file)...)
			if code != exitInput || out != "" || errOut != want {
				t.Errorf("%s %v: exit %d, %d bytes written, stderr %q; want exit %d and stderr %q", row.name, flags, code, len(out), errOut, exitInput, want)
			}
		}
	}

	// An unpaired escape that no other escape follows directly is one the
	// library refuses, so the command cannot read the copy, which keeps the
	// fixture's signature: there are no native bytes to sign it over.
	for _, purpose := range []string{text("x" + esc("d800") + "y"), text(esc("dc00")), text(esc("d800") + string(rune(0x5c)) + "n")} {
		file, atxRaw, state := alteredFixture(t, name, func(atx map[string]any) {
			atx["declaredPurpose"] = json.RawMessage(purpose)
		})
		outcome := verifier.VerifyCredential(atxRaw, state)
		if outcome.Verdict != "REJECT" || outcome.RejectCategory != "VERIFIER_CONFIG_ERROR" || !strings.HasPrefix(outcome.Reason, canonicalizing+unpaired) {
			t.Errorf("declaredPurpose %s: the reference verifier gives %s %s (%s), want REJECT VERIFIER_CONFIG_ERROR naming the escape", purpose, outcome.Verdict, outcome.RejectCategory, outcome.Reason)
		}
		code, out, errOut := export("--form", "vc", file)
		if code != exitInput || out != "" || !strings.Contains(errOut, "atx cannot be canonicalized (RFC 8785)") {
			t.Errorf("declaredPurpose %s: exit %d, %d bytes written, stderr %q; want exit %d and a message that the atx cannot be canonicalized", purpose, code, len(out), errOut, exitInput)
		}
	}
}

// TestPurposeSurrogateEscapeReadsOnlyV11 checks that the rule is the "1.1"
// signed bytes' own: a "1.0" credential's signed string holds no part of
// declaredPurpose, and a "1.1" credential whose signed bytes omit
// declaredPurpose has no text for the rule to read.
func TestPurposeSurrogateEscapeReadsOnlyV11(t *testing.T) {
	unpaired := json.RawMessage(`{"s":"` + backslashU + "d800" + backslashU + `0041"}`)
	if escape := purposeSurrogateEscape(&ATX{ATCVersion: atcVersion, DeclaredPurpose: unpaired}); escape != "" {
		t.Errorf("a %q credential: %s", atcVersion, escape)
	}
	if escape := purposeSurrogateEscape(&ATX{ATCVersion: atcVersionV11, DeclaredPurpose: unpaired}); escape != backslashU+"d800" {
		t.Errorf("a %q credential: %q, want the escape of the code unit D800", atcVersionV11, escape)
	}
	for _, purpose := range []string{"", "null", "{}", " { } "} {
		if escape := purposeSurrogateEscape(&ATX{ATCVersion: atcVersionV11, DeclaredPurpose: json.RawMessage(purpose)}); escape != "" {
			t.Errorf("declaredPurpose %q: %s", purpose, escape)
		}
	}
}

// TestNumberOutsideTheDoubleRangeIsNotRead checks that a number the RFC 8785
// library refuses to read, 1e400, makes a fixture the command cannot read,
// in declaredPurpose and in trustScore: exit status 1 and nothing written.
// The Go reference verifier rejects both copies.
func TestNumberOutsideTheDoubleRangeIsNotRead(t *testing.T) {
	alterations := map[string]func(atx map[string]any){
		"declaredPurpose": func(atx map[string]any) { atx["declaredPurpose"] = map[string]any{"n": json.Number("1e400")} },
		"trustScore":      func(atx map[string]any) { atx["trustScore"] = json.Number("1e400") },
	}
	for member, alter := range alterations {
		file, atxRaw, state := alteredFixture(t, "v1_1-baseline-valid.json", alter)
		if outcome := verifier.VerifyCredential(atxRaw, state); outcome.Verdict != "REJECT" {
			t.Errorf("1e400 in %s: the reference verifier gives %s", member, outcome.Verdict)
		}
		code, out, errOut := export("--form", "vc", file)
		if code != exitInput || out != "" || !strings.Contains(errOut, "atx cannot be canonicalized (RFC 8785)") {
			t.Errorf("1e400 in %s: exit %d, stdout %q, stderr %q; want exit %d and a message that the atx cannot be canonicalized", member, code, out, errOut, exitInput)
		}
	}
}

// TestNumberOutsideTheDoubleRangeWhateverTheRelease holds the command to
// the digits a number outside the IEEE 754 double range is written with,
// whatever Go release builds it. The copy of the v1.1 baseline whose
// trustScore is 1 followed by 1000 zeros and e-650, whose value is 10^350,
// is signed over the trustScore a build with go1.22.0 or go1.26.3 read it
// as, 1e+149: such a build exported the copy with atxTrustScore 1e+149, and
// a build with go1.27.0 exited 1. The Go reference verifier rejects the copy
// as PARSE_ERROR. The command exits 1 for it, and for the same number in
// declaredPurpose, where a build with go1.26.3 exited 3, naming the member
// and the number, with and without --mldsa65-proof. In the table, each
// number is written as the trustScore of a copy of the baseline: the
// verifier rejects the copy as PARSE_ERROR when the number is outside the
// range and the command exits 1 naming it, and for a number inside the
// range the verifier does not reject the copy as PARSE_ERROR and the command
// exits 3.
func TestNumberOutsideTheDoubleRangeWhateverTheRelease(t *testing.T) {
	const name = "v1_1-baseline-valid.json"
	tenTo350 := "1" + strings.Repeat("0", 1000) + "e-650"
	outsideRange := func(file, where, literal string) string {
		return "atx-export: " + file + ": atx cannot be canonicalized (RFC 8785): " + where + " holds the number " + literal + ", which is outside the IEEE 754 double range\n"
	}
	signed, atxRaw, state := signedAsReadFixture(t, name,
		func(atx map[string]any) { atx["trustScore"] = json.Number("1e+149") },
		func(atx map[string]any) { atx["trustScore"] = json.Number(tenTo350) })
	if outcome := verifier.VerifyCredential(atxRaw, state); outcome.Verdict != "REJECT" || outcome.RejectCategory != "PARSE_ERROR" {
		t.Errorf("trustScore 10^350: the reference verifier gives %s %s, want REJECT PARSE_ERROR", outcome.Verdict, outcome.RejectCategory)
	}
	inPurpose, purposeRaw, purposeState := alteredFixture(t, name, func(atx map[string]any) {
		atx["declaredPurpose"] = map[string]any{"n": json.Number(tenTo350)}
	})
	if outcome := verifier.VerifyCredential(purposeRaw, purposeState); outcome.Verdict != "REJECT" {
		t.Errorf("declaredPurpose 10^350: the reference verifier gives %s", outcome.Verdict)
	}
	for _, c := range []struct{ file, where string }{{signed, "trustScore"}, {inPurpose, "declaredPurpose"}} {
		for _, flags := range [][]string{{"--form", "vc"}, {"--form", "vc", "--mldsa65-proof"}} {
			code, out, errOut := export(append(append([]string{}, flags...), c.file)...)
			if want := outsideRange(c.file, c.where, tenTo350); code != exitInput || out != "" || errOut != want {
				t.Errorf("10^350 in %s %v: exit %d, %d bytes written, stderr %.300q; want exit %d and stderr %.300q", c.where, flags, code, len(out), errOut, exitInput, want)
			}
		}
	}

	// edge is the largest float64 and half a unit in its last place,
	// 2^1024 - 2^970, which rounds to infinity; one less rounds to the
	// largest float64.
	sum := new(big.Float).SetPrec(2000).SetFloat64(math.MaxFloat64)
	sum.Add(sum, new(big.Float).SetMantExp(big.NewFloat(1), 970))
	edge, _ := sum.Int(nil)
	belowEdge := new(big.Int).Sub(edge, big.NewInt(1))
	for _, row := range []struct {
		literal string
		outside bool
	}{
		{"1e400", true},
		{"-1e400", true},
		{tenTo350, true},
		{"0." + strings.Repeat("0", 2000) + "1e2400", true},
		{edge.String(), true},
		{"1.7976931348623159e308", true},
		{belowEdge.String(), false},
		{"1.7976931348623157e308", false},
		{"1" + strings.Repeat("0", 1000) + "e-700", false},
		{"1e-400", false},
	} {
		file, atxRaw, state := alteredFixture(t, name, func(atx map[string]any) { atx["trustScore"] = json.Number(row.literal) })
		if outcome := verifier.VerifyCredential(atxRaw, state); (outcome.RejectCategory == "PARSE_ERROR") != row.outside {
			t.Errorf("trustScore %.40s (%d bytes): the reference verifier gives %s %s", row.literal, len(row.literal), outcome.Verdict, outcome.RejectCategory)
		}
		code, out, errOut := export("--form", "vc", file)
		want := exitNativeSignature
		if row.outside {
			want = exitInput
		}
		if code != want || out != "" || (errOut == outsideRange(file, "trustScore", row.literal)) != row.outside {
			t.Errorf("trustScore %.40s (%d bytes): exit %d, %d bytes written, stderr %.300q; want exit %d", row.literal, len(row.literal), code, len(out), errOut, want)
		}
	}
}

// TestNumbersTheCredentialCannotHold holds the credential to each number as
// the fixture writes it. The command writes the credential as RFC 8785
// canonical JSON, which writes each number as the IEEE 754 double nearest
// it, so it wrote trustLevel 9007199254740993 of a "1.0" credential, which
// the native signature covers digit for digit, as 9007199254740992. Each row
// changes one number of a copy of the v1.0 or the v1.1 baseline, signed
// again where the change alters the bytes the native signatures cover, and
// the Go reference verifier accepts each copy. Where the row names a
// member, RFC 8785 writes the number in another form than the row does: the
// command exits 3 and writes nothing, and its message names the number, the
// member and the form RFC 8785 writes it in, with and without
// --mldsa65-proof. Where it names none, RFC 8785 writes each number as the
// row does, and the command exports the copy, each number of the credential
// as the copy writes it (checkMembers).
func TestNumbersTheCredentialCannotHold(t *testing.T) {
	const (
		v10 = "baseline-valid.json"
		v11 = "v1_1-baseline-valid.json"
	)
	member := func(name, value string) func(map[string]any) {
		return func(atx map[string]any) { atx[name] = json.Number(value) }
	}
	inObject := func(object, name, value string) func(map[string]any) {
		return func(atx map[string]any) { atx[object].(map[string]any)[name] = json.Number(value) }
	}
	written := func(name, text string) func(map[string]any) {
		return func(atx map[string]any) { atx[name] = json.RawMessage(text) }
	}
	rows := []struct {
		name, fixture string
		alter         func(atx map[string]any)
		resign        bool
		// where is the member the refusal names, "" for a copy the command
		// exports; literal is the number as the copy writes it, and
		// canonical as RFC 8785 writes it.
		where, literal, canonical string
	}{
		{"a 1.0 trustLevel of 2^53+1", v10, member("trustLevel", "9007199254740993"), true, "trustLevel", "9007199254740993", "9007199254740992"},
		{"a 1.0 trustLevel of -0", v10, member("trustLevel", "-0"), true, "trustLevel", "-0", "0"},
		{"a 1.0 scanSummary.criticalFindings of 2^53+1", v10, inObject("scanSummary", "criticalFindings", "9007199254740993"), false,
			"scanSummary.criticalFindings", "9007199254740993", "9007199254740992"},
		{"a 1.0 declaredPurpose number with an exponent part", v10, written("declaredPurpose", `{"n":1e3}`), false, "declaredPurpose", "1e3", "1000"},
		{"a 1.0 behavioralProfile member with an exponent part", v10,
			written("behavioralProfile", `{"checksum":"sha256:ghi789","generatedAt":"2026-05-19T00:00:00Z","observationDays":14,"weight":1E3}`), false,
			"behavioralProfile.weight", "1E3", "1000"},
		{"a 1.1 trustScore of 2^53+1", v11, member("trustScore", "9007199254740993"), true, "trustScore", "9007199254740993", "9007199254740992"},
		{"a 1.1 trustScore of -0", v11, member("trustScore", "-0"), true, "trustScore", "-0", "0"},
		{"a 1.1 trustScore with a trailing zero", v11, member("trustScore", "87.50"), false, "trustScore", "87.50", "87.5"},
		{"a 1.1 declaredPurpose number of -0", v11, written("declaredPurpose", `{"n":-0}`), true, "declaredPurpose", "-0", "0"},
		{"a 1.0 trustLevel of 2^53", v10, member("trustLevel", "9007199254740992"), true, "", "", ""},
		{"a 1.0 declaredPurpose whose numbers RFC 8785 writes as written", v10,
			written("declaredPurpose", `{"a":1000,"b":0.5,"c":5e-7,"d":-12,"e":1e+21,"f":[0,100000000000000000000]}`), false, "", "", ""},
		{"a 1.1 trustScore written as an integer", v11, member("trustScore", "90"), true, "", "", ""},
	}
	for _, row := range rows {
		file, atxRaw, state := alteredFixture(t, row.fixture, row.alter)
		if row.resign {
			file, atxRaw, state = signedAlteredFixture(t, row.fixture, row.alter)
		}
		if outcome := verifier.VerifyCredential(atxRaw, state); outcome.Verdict != "ACCEPT" {
			t.Errorf("%s: the reference verifier gives %s %s (%s), want ACCEPT", row.name, outcome.Verdict, outcome.RejectCategory, outcome.Reason)
			continue
		}
		if row.where == "" {
			code, out, errOut := export("--form", "vc", file)
			if code != exitOK {
				t.Errorf("%s: exit %d, stderr %q; want exit %d and a credential", row.name, code, errOut, exitOK)
				continue
			}
			secured, err := decodeObject([]byte(strings.TrimSuffix(out, "\n")))
			if err != nil {
				t.Fatal(err)
			}
			f, err := readFixture(file)
			if err != nil {
				t.Fatal(err)
			}
			checkMembers(t, row.name, secured, f)
			continue
		}
		want := "atx-export: the credential cannot hold the number " + row.literal + " in " + row.where + " as written: RFC 8785 writes it as " + row.canonical + "; not re-signing\n"
		for _, flags := range [][]string{{"--form", "vc"}, {"--form", "vc", "--mldsa65-proof"}} {
			code, out, errOut := export(append(append([]string{}, flags...), file)...)
			if code != exitNativeSignature || out != "" || errOut != want {
				t.Errorf("%s %v: exit %d, %d bytes written, stderr %q; want exit %d and stderr %q", row.name, flags, code, len(out), errOut, exitNativeSignature, want)
			}
		}
	}
}

// TestCanonicalNumber holds canonicalNumber to the RFC 8785 library's own
// form of each literal of the table, and to 87.5 for 875 followed by 900
// zeros and e-901, whose value is 87.5: the library writes that literal as
// 8.75e-102 built with go1.22.0 or go1.26.3, and as 87.5 built with go1.27.0.
func TestCanonicalNumber(t *testing.T) {
	for literal, want := range map[string]string{
		"9007199254740993":      "9007199254740992",
		"9007199254740992":      "9007199254740992",
		"-0":                    "0",
		"1e3":                   "1000",
		"1000.0":                "1000",
		"87.50":                 "87.5",
		"87.5":                  "87.5",
		"5e-7":                  "5e-7",
		"1e21":                  "1e+21",
		"1e-400":                "0",
		"100000000000000000000": "100000000000000000000",
	} {
		if got := canonicalNumber(literal); got != want {
			t.Errorf("%s: %q, want %q", literal, got, want)
		}
		if library, err := jcs.Transform([]byte(literal)); err != nil || string(library) != want {
			t.Errorf("%s: the RFC 8785 library writes %q (%v), want %q", literal, library, err, want)
		}
	}
	if got := canonicalNumber("875" + strings.Repeat("0", 900) + "e-901"); got != "87.5" {
		t.Errorf("875 followed by 900 zeros and e-901: %q, want 87.5", got)
	}
}

// TestCredentialMembers checks that credentialMembers names each native
// member credential copies into the credential and no other, so that
// rewrittenNumber reads each number the credential carries.
func TestCredentialMembers(t *testing.T) {
	const marker = "value of "
	atx := map[string]any{}
	for _, name := range jsonNames(reflect.TypeOf(ATX{})) {
		atx[name] = marker + name
	}
	cred, err := credential(atx, "")
	if err != nil {
		t.Fatal(err)
	}
	var copied []string
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			if i := strings.Index(v, marker); i >= 0 {
				copied = append(copied, v[i+len(marker):])
			}
		case map[string]any:
			for _, e := range v {
				walk(e)
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(cred)
	sort.Strings(copied)
	if !reflect.DeepEqual(copied, credentialMembers) {
		t.Errorf("credential copies %v; credentialMembers is %v", copied, credentialMembers)
	}
}

// TestIssuedAtAndExpiresAtAsTheVerifierReadsThem holds the command's reading
// of issuedAt and expiresAt to the Go reference verifier's, on copies of the
// v1.1 baseline, whatever Go release builds the command. A build with
// go1.22.0 read a time zone offset hour above 24 or minute above 60, and
// exported an expiresAt written so as validUntil; a build with go1.27.0 read
// a timestamp written with a JSON escape; a build with go1.26.3 read
// neither. A row marked refused is signed over the bytes a build that read
// it computed, and the verifier rejects the copy as PARSE_ERROR: the command
// exits 1, writes nothing, and names the verifier's reason, with and without
// --mldsa65-proof. A row marked kept as well writes a timestamp no release
// reads, refused for its offset and for its day, the text after it or its
// minute: the copy keeps the fixture's signature, and the reason names the
// offset under every release, as Go 1.23 and later name it (offsetFirst).
// Every other row writes an offset each of those builds reads: signed
// again, the verifier accepts the copy, and the command exports it with the
// member as written.
func TestIssuedAtAndExpiresAtAsTheVerifierReadsThem(t *testing.T) {
	const name = "v1_1-baseline-valid.json"
	// escaped writes the first hyphen of s as the JSON escape of U+002D.
	escaped := func(s string) string { return strings.Replace(s, "-", backslashU+"002d", 1) }
	rows := []struct {
		name, member, written string
		refused, kept         bool
	}{
		{"expiresAt with a time zone offset hour of 25", "expiresAt", "2099-12-31T23:59:59+25:00", true, false},
		{"expiresAt with a time zone offset hour of -25", "expiresAt", "2099-12-31T23:59:59-25:00", true, false},
		{"expiresAt with a time zone offset minute of 61", "expiresAt", "2099-12-31T23:59:59+23:61", true, false},
		{"expiresAt with a time zone offset of +99:99", "expiresAt", "2099-12-31T23:59:59+99:99", true, false},
		{"issuedAt with a time zone offset hour of 25", "issuedAt", "2026-05-23T00:00:00+25:00", true, false},
		{"issuedAt written with a JSON escape", "issuedAt", escaped("2026-05-23T00:00:00Z"), true, false},
		{"expiresAt written with a JSON escape", "expiresAt", escaped("2099-12-31T23:59:59Z"), true, false},
		{"expiresAt with an offset hour of 25 on February 30", "expiresAt", "2099-02-30T23:59:59+25:00", true, true},
		{"expiresAt with an offset hour of 25 and text after it", "expiresAt", "2099-12-31T23:59:59+25:00x", true, true},
		{"expiresAt with an offset hour of 25 and a minute that is not two digits", "expiresAt", "2099-02-30T23:59:59+25:0a", true, true},
		{"expiresAt with a time zone offset of +24:00", "expiresAt", "2099-12-31T23:59:59+24:00", false, false},
		{"expiresAt with a time zone offset of +23:60", "expiresAt", "2099-12-31T23:59:59+23:60", false, false},
	}
	for _, row := range rows {
		alter := func(atx map[string]any) { atx[row.member] = json.RawMessage(`"` + row.written + `"`) }
		read := func(atx map[string]any) { atx[row.member] = readAsGo122(t, row.written).Format(time.RFC3339) }
		var file string
		var atxRaw, state []byte
		if row.kept {
			file, atxRaw, state = alteredFixture(t, name, alter)
		} else {
			file, atxRaw, state = signedAsReadFixture(t, name, read, alter)
		}
		if !bytes.Contains(atxRaw, []byte(`"`+row.written+`"`)) {
			t.Fatalf("%s: the copy does not hold %s as the row writes it", row.name, row.member)
		}
		outcome := verifier.VerifyCredential(atxRaw, state)
		if !row.refused {
			if outcome.Verdict != "ACCEPT" {
				t.Errorf("%s: the reference verifier gives %s %s (%s), want ACCEPT", row.name, outcome.Verdict, outcome.RejectCategory, outcome.Reason)
				continue
			}
			code, out, errOut := export("--form", "vc", file)
			if code != exitOK {
				t.Errorf("%s: exit %d, stderr %q; want exit %d and a credential", row.name, code, errOut, exitOK)
				continue
			}
			secured, err := decodeObject([]byte(strings.TrimSuffix(out, "\n")))
			if err != nil {
				t.Fatal(err)
			}
			if secured["validUntil"] != row.written {
				t.Errorf("%s: validUntil %v, want %s", row.name, secured["validUntil"], row.written)
			}
			continue
		}
		if outcome.Verdict != "REJECT" || outcome.RejectCategory != "PARSE_ERROR" {
			t.Errorf("%s: the reference verifier gives %s %s (%s), want REJECT PARSE_ERROR", row.name, outcome.Verdict, outcome.RejectCategory, outcome.Reason)
			continue
		}
		want := "atx-export: " + file + ": atx: " + outcome.Reason + "\n"
		for _, flags := range [][]string{{"--form", "vc"}, {"--form", "vc", "--mldsa65-proof"}} {
			code, out, errOut := export(append(append([]string{}, flags...), file)...)
			if code != exitInput || out != "" || errOut != want {
				t.Errorf("%s %v: exit %d, %d bytes written, stderr %q; want exit %d and stderr %q", row.name, flags, code, len(out), errOut, exitInput, want)
			}
		}
	}
}

// readAsGo122 returns the instant a time.Time decoder built with go1.22.0,
// handed s with its escapes resolved, reads: the date and time before the
// time zone offset, less the offset read as two digits of hour and two of
// minute whatever their range, so +25:00 is 25 hours and +23:61 is 23 hours
// and 61 minutes.
func readAsGo122(t *testing.T, s string) time.Time {
	t.Helper()
	s = strings.Replace(s, backslashU+"002d", "-", 1)
	if strings.HasSuffix(s, "Z") {
		at, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	local, offset := s[:len(s)-len("+00:00")], s[len(s)-len("+00:00"):]
	at, err := time.Parse("2006-01-02T15:04:05", local)
	if err != nil {
		t.Fatal(err)
	}
	hours, errHours := strconv.Atoi(offset[1:3])
	minutes, errMinutes := strconv.Atoi(offset[4:6])
	if errHours != nil || errMinutes != nil {
		t.Fatalf("%s: the offset is not two digits of hour and two of minute", s)
	}
	shift := time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute
	if offset[0] == '-' {
		shift = -shift
	}
	return at.Add(-shift).UTC()
}

// TestNothingExportedWhereNoSignatureCovers holds the command to the Go
// reference verifier on every fixture of the suite: where the verifier
// rejects the fixture's credential with a reason that starts "no signature
// covers", the command writes nothing to standard output and exits with a
// status other than 0.
func TestNothingExportedWhereNoSignatureCovers(t *testing.T) {
	refused := 0
	for _, name := range fixtureNames(t, "") {
		raw, err := fs.ReadFile(repo, "fixtures/"+name)
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			ATX           json.RawMessage `json:"atx"`
			VerifierState json.RawMessage `json:"verifierState"`
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		reason := verifier.VerifyCredential(fx.ATX, fx.VerifierState).Reason
		if !strings.HasPrefix(reason, noSignatureCovers) {
			continue
		}
		refused++
		for _, flags := range [][]string{{"--form", "vc"}, {"--form", "vc", "--mldsa65-proof"}} {
			code, out, _ := export(append(append([]string{}, flags...), fixturePath(name))...)
			if code == exitOK || out != "" {
				t.Errorf("%s %v: exit %d, %d bytes written; the reference verifier: %s", name, flags, code, len(out), reason)
			}
		}
	}
	if refused == 0 {
		t.Fatalf("the reference verifier gives no fixture a reason that starts %q", noSignatureCovers)
	}
	t.Logf("%d fixtures", refused)
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
