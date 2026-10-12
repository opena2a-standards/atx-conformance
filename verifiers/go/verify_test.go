package main

import (
	"encoding/json"
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
