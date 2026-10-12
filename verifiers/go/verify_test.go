package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFoldKey pins the field-fold used by the fold-aware duplicate detector to
// encoding/json's own folding: ASCII case-insensitive plus the only two
// non-ASCII runes encoding/json folds to ASCII (Kelvin U+212A -> k, long s
// U+017F -> s). atx-conformance#16.
func TestFoldKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"trustLevel", "trustlevel"},
		{"TRUSTLEVEL", "trustlevel"},
		{"TrustLevel", "trustlevel"},
		{"category", "category"},
		{"Category", "category"},
		{"agentId", "agentid"},
		{"Kelvin", "kelvin"}, // U+212A Kelvin sign folds to ASCII k
		{"ſmart", "smart"},   // U+017F long s folds to ASCII s
	}
	for _, c := range cases {
		if got := foldKey(c.in); got != c.want {
			t.Errorf("foldKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Case variants and the fold targets must collide under foldKey; distinct
	// field names must not.
	if foldKey("trustLevel") != foldKey("TRUSTLEVEL") {
		t.Error("trustLevel and TRUSTLEVEL must fold together")
	}
	if foldKey("K") != foldKey("k") {
		t.Error("Kelvin sign must fold to k")
	}
	if foldKey("agentId") == foldKey("issuerDid") {
		t.Error("distinct field names must not fold together")
	}
}

// TestRawDuplicateMember covers same-name duplicates, case-variant (fold)
// duplicates at any depth, and duplicate-free credentials.
func TestRawDuplicateMember(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantDup bool
	}{
		{"same-name top level", `{"trustLevel":4,"trustLevel":9}`, true},
		{"case variant top level", `{"TRUSTLEVEL":9,"trustLevel":4}`, true},
		{"case variant nested", `{"a":{"Category":"x","category":"y"}}`, true},
		{"same-name in array", `{"a":[{"k":1,"k":2}]}`, true},
		{"kelvin fold collision", "{\"K\":1,\"k\":2}", true},
		{"distinct keys", `{"trustLevel":4,"trustScore":9}`, false},
		{"distinct nested", `{"a":{"x":1},"b":{"x":2}}`, false},
		{"empty object", `{}`, false},
	}
	for _, c := range cases {
		_, dup := rawDuplicateMember([]byte(c.raw))
		if dup != c.wantDup {
			t.Errorf("%s: rawDuplicateMember(%s) dup=%v, want %v", c.name, c.raw, dup, c.wantDup)
		}
	}
}

// TestSuiteCatchesCRLBlindVerifier pins that the shipped fixture set depends
// on CRL membership (atx-spec core.md §1.3 step 6). It runs every fixture
// twice: as shipped, where the reference verifier must report the pinned
// outcome, and with the CRL dropped from the verifier state, which is what a
// verifier with no CRL support sees. At least one fixture must then miss its
// pinned outcome. Without one, the revocation coverage this suite claims is
// met by a verifier that reads the credential's own revoked flag and stops.
//
// Mutation-verified: with fixtures/revoked-crl-only.json removed, the CRL-blind
// run matches every remaining fixture and this test fails.
func TestSuiteCatchesCRLBlindVerifier(t *testing.T) {
	paths, err := expandFixturePaths([]string{"../../fixtures"})
	if err != nil {
		t.Fatalf("cannot list the shipped fixtures: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no shipped fixtures found; refusing to pass vacuously")
	}

	var caughtBy []string
	for _, p := range paths {
		f, err := loadFixture(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got := verify(f); !matchesExpected(f.Expected, got) {
			t.Errorf("%s: reference verifier observed %s, not the pinned outcome", p, got)
			continue
		}
		crlBlind := f
		crlBlind.VerifierState.CRL = nil
		if !matchesExpected(f.Expected, verify(crlBlind)) {
			caughtBy = append(caughtBy, f.Name)
		}
	}
	if len(caughtBy) == 0 {
		t.Fatalf("a verifier that never consults the CRL matches all %d fixtures: no fixture's verdict depends on CRL membership", len(paths))
	}
	t.Logf("a CRL-blind verifier misses the pinned outcome of: %s", strings.Join(caughtBy, ", "))
}

// TestMLDSA65RequiresEd25519Companion pins core.md section 13 (Cryptographic
// agility): a credential that declares an ML-DSA-65 entry MUST also carry a
// verifying Ed25519 entry. The hybrid baseline ACCEPTs; the same credential
// with its Ed25519 entry removed carries one ML-DSA-65 signature that verifies
// and MUST REJECT as SIGNATURE_INVALID. atx-conformance#133.
func TestMLDSA65RequiresEd25519Companion(t *testing.T) {
	f, err := loadFixture("../../fixtures/v1_1-baseline-valid-hybrid.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := verify(f); !got.Accepted || !got.Ed25519Valid || !got.MLDSA65Valid {
		t.Fatalf("hybrid baseline: got %s (ed25519=%v mldsa65=%v), want ACCEPT with both suites valid", got, got.Ed25519Valid, got.MLDSA65Valid)
	}

	var atx map[string]any
	if err := json.Unmarshal(f.ATX, &atx); err != nil {
		t.Fatal(err)
	}
	var pqOnly []any
	for _, s := range atx["signatures"].([]any) {
		if s.(map[string]any)["algorithm"] == "ML-DSA-65" {
			pqOnly = append(pqOnly, s)
		}
	}
	if len(pqOnly) != 1 {
		t.Fatalf("hybrid baseline carries %d ML-DSA-65 signatures, want 1", len(pqOnly))
	}
	atx["signatures"] = pqOnly
	if f.ATX, err = json.Marshal(atx); err != nil {
		t.Fatal(err)
	}

	got := verify(f)
	if got.Accepted {
		t.Fatal("credential with an ML-DSA-65 signature and no Ed25519 signature must not be accepted")
	}
	if got.RejectCategory != "SIGNATURE_INVALID" || !strings.Contains(got.Reason, "Ed25519") {
		t.Errorf("got %s, want REJECT[SIGNATURE_INVALID] naming the missing Ed25519 companion", got)
	}
}

// TestStrictParseDepthGuard is the regression for the unbounded-recursion DoS.
// A credential nested past encoding/json's own depth limit (10000) must be
// rejected without crashing. The strict-parse scan aborts at maxScanDepth and
// json.Unmarshal then rejects the over-deep input with a max-depth error, so
// verify() returns REJECT[PARSE_ERROR] rather than driving the scanner into a
// fatal stack overflow.
//
// Mutation-verified: removing the maxScanDepth guard from
// scanValueForDuplicates makes this test fatally overflow the goroutine stack
// (~11M frames). A shallower input would not catch the regression — Go stacks
// grow to ~1GB, so 200k-deep nesting does NOT overflow a guardless scan.
func TestStrictParseDepthGuard(t *testing.T) {
	const depth = 11_000_000
	deep := strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth)

	// Sanity: encoding/json itself rejects this depth with an error, not a crash.
	var sink any
	if err := json.Unmarshal([]byte(deep), &sink); err == nil {
		t.Fatal("expected json.Unmarshal to reject over-deep input, got nil error")
	}

	got := verify(fixture{ATX: json.RawMessage(deep)})
	if got.Accepted {
		t.Fatal("over-deep credential must not be accepted")
	}
	if got.RejectCategory != "PARSE_ERROR" {
		t.Errorf("over-deep credential rejected with category %q, want PARSE_ERROR", got.RejectCategory)
	}
}

// TestJCSVectorsThroughVerifierProjection runs this verifier's own v1.1 path
// (credential parse, TBS projection, JCS) over every jcs-vectors vector and
// requires the pinned expected.canonicalHex byte-for-byte. The byte-agreement
// gate runs this test, so the gate covers this verifier's code and not only the
// library it calls. atx-conformance#156.
func TestJCSVectorsThroughVerifierProjection(t *testing.T) {
	dir := filepath.Join("..", "..", "jcs-vectors", "vectors")
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no vectors found in %s", dir)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path) //nolint:gosec // G304: globbed from the repository's own jcs-vectors/vectors
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				TBS      map[string]json.RawMessage `json:"tbs"`
				Expected struct {
					CanonicalHex string `json:"canonicalHex"`
				} `json:"expected"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			if v.Expected.CanonicalHex == "" {
				t.Fatal("vector has no expected.canonicalHex")
			}

			// The TBS carries trustScore as its %.6f string; the credential
			// carries the same value as a JSON number. Every other TBS member
			// is already in its wire form.
			var score string
			if err := json.Unmarshal(v.TBS["trustScore"], &score); err != nil {
				t.Fatalf("tbs.trustScore is not a string: %v", err)
			}
			v.TBS["trustScore"] = json.RawMessage(score)
			credential, err := json.Marshal(v.TBS)
			if err != nil {
				t.Fatalf("build credential from tbs: %v", err)
			}

			var a atx
			if err := json.Unmarshal(credential, &a); err != nil {
				t.Fatalf("parse credential: %v", err)
			}
			got, err := canonicalPayloadV11(&a)
			if err != nil {
				t.Fatalf("canonicalPayloadV11: %v", err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != v.Expected.CanonicalHex {
				t.Errorf("verifier canonical bytes differ from the pinned vector\n got  %s\n want %s", got, mustHexDecode(t, v.Expected.CanonicalHex))
			}
		})
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("expected.canonicalHex is not hex: %v", err)
	}
	return b
}
