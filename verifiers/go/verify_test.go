package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestReadmeCrossReferencesResolve pins that every README §"..." cross-reference
// in this verifier and in the fixture generator names a heading README.md
// carries. A reference split across two comment lines reads as one.
// atx-conformance#161: both sources cited §"Signed vs unsigned fields.", a
// section README never had.
func TestReadmeCrossReferencesResolve(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("cannot read README.md: %v", err)
	}
	headings := map[string]bool{}
	fenced := false
	for _, line := range strings.Split(string(readme), "\n") {
		switch {
		case strings.HasPrefix(line, "```"):
			fenced = !fenced
		case !fenced && strings.HasPrefix(line, "#"):
			headings[strings.TrimSpace(strings.TrimLeft(line, "#"))] = true
		}
	}

	continuation := regexp.MustCompile(`\n[ \t]*//[ \t]*`)
	reference := regexp.MustCompile(`README\s+§"([^"]+)"`)
	found := 0
	for _, src := range []string{"verify.go", "../../scripts/generate-fixtures/main.go"} {
		body, err := os.ReadFile(src) //nolint:gosec // G304: src ranges over the two fixed repository paths above
		if err != nil {
			t.Fatalf("cannot read %s: %v", src, err)
		}
		text := continuation.ReplaceAllString(string(body), " ")
		for _, m := range reference.FindAllStringSubmatch(text, -1) {
			found++
			if !headings[m[1]] {
				t.Errorf("%s cites README §%q, which is not a README heading", src, m[1])
			}
		}
	}
	if found == 0 {
		t.Fatal("no README cross-reference found; refusing to pass vacuously")
	}
}

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

// earlyRejectCategories are the reject categories of steps 0 to 4, which
// verify returns before it reaches signature verification (step 5).
var earlyRejectCategories = map[string]bool{
	"PARSE_ERROR":         true, // step 0
	"UNSUPPORTED_VERSION": true, // step 1
	"EXPIRED":             true, // step 2
	"REVOKED":             true, // step 3
	"UNTRUSTED_ISSUER":    true, // step 4
}

// TestEarlyRejectFixturesCarryValidSignatures pins the "otherwise valid"
// property of the fixtures that reject before step 5. Running the verifiers
// over fixtures/ never checks their signatures, so a fixture whose signature
// broke would still pass and would then test its gate on a credential that a
// verifier skipping that gate also rejects. Each such fixture is run through
// steps 5 to 8 with its gate lifted: last-wins decoding instead of the strict
// parse, atcVersion set to "1.0", and its issuer trusted (its DID added to the
// trusted set and its keys from keypairRefs to the verifier's keys). The clock
// and the revocation state are not read after step 4. atx-conformance#138.
func TestEarlyRejectFixturesCarryValidSignatures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures found; refusing to pass vacuously")
	}
	early := 0
	for _, path := range paths {
		f, err := loadFixture(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !earlyRejectCategories[verify(f).RejectCategory] {
			continue
		}
		early++

		var a atx
		err = json.Unmarshal(f.ATX, &a)
		for _, member := range []*json.RawMessage{&a.DeclaredPurpose, &a.BehavioralProfile, &a.ScanSummary} {
			if err == nil {
				*member, err = lastWins(*member)
			}
		}
		if err != nil {
			t.Errorf("%s: credential does not decode with the strict parse lifted: %v", path, err)
			continue
		}
		if a.ATCVersion != "1.0" && a.ATCVersion != "1.1" {
			a.ATCVersion = "1.0"
		}
		state := f.VerifierState
		state.TrustedIssuers = append(append([]string{}, state.TrustedIssuers...), a.IssuerDID)
		state.PublicKeys = append([]keypairRef{}, state.PublicKeys...)
		for _, ref := range f.KeypairRefs {
			if controllerDID(ref.KeyID) == a.IssuerDID {
				state.PublicKeys = append(state.PublicKeys, ref)
			}
		}

		got := verifySignatures(&a, state)
		if !got.Accepted || got.SigsValid != got.SigsExpected {
			t.Errorf("%s: rejects before step 5, but with that gate lifted its signatures do not verify: %s", path, got)
		}
	}
	if early == 0 {
		t.Fatal("no fixture rejects before step 5; refusing to pass vacuously")
	}
	t.Logf("%d of %d fixtures reject before step 5; their signatures were checked with the gate lifted", early, len(paths))
}

// lastWins re-encodes a raw member as a parser without the strict check reads
// it: a repeated member keeps its last value. The v1.1 canonicalizer refuses
// duplicate members, so the strict parse is lifted here rather than there.
func lastWins(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
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

// TestTimestampDecode pins what the time.Time decoder behind issuedAt and
// expiresAt accepts. The Python reference verifier ports this grammar
// (_parse_rfc3339 in ../python/verify.py) and test_verify.py carries the same
// table, so a Go release that changes how the decoder treats one of these
// inputs, for example by enabling the strict RFC 3339 checks the standard
// library has disabled (golang/go#54580), fails here before the two verifiers
// drift apart. An offset hour above 24 or an offset minute above 60 is in
// neither table: Go 1.22, which CI builds with, decodes it, and Go 1.23 and
// later reject it.
func TestTimestampDecode(t *testing.T) {
	accepted := []struct {
		in, utc     string
		unix, nanos int64
	}{
		{"2099-12-31T23:59:59Z", "2099-12-31T23:59:59Z", 4102444799, 0},
		{"2099-12-31T23:59:59,5Z", "2099-12-31T23:59:59Z", 4102444799, 500000000},
		{"2099-12-31T23:59:59.123456789123Z", "2099-12-31T23:59:59Z", 4102444799, 123456789},
		{"2099-12-31T23:59:59+24:00", "2099-12-30T23:59:59Z", 4102358399, 0},
		{"2099-12-31T23:59:59-24:00", "2100-01-01T23:59:59Z", 4102531199, 0},
		{"2099-12-31T23:59:59+23:60", "2099-12-30T23:59:59Z", 4102358399, 0},
		{"0000-12-31T23:59:59Z", "0000-12-31T23:59:59Z", -62135596801, 0},
		{"0000-02-29T00:00:00Z", "0000-02-29T00:00:00Z", -62162121600, 0},
		{"0000-01-01T00:00:00+01:00", "-0001-12-31T23:00:00Z", -62167222800, 0},
		{"9999-12-31T23:59:59-24:00", "10000-01-01T23:59:59Z", 253402387199, 0},
		{"2000-02-29T00:00:00Z", "2000-02-29T00:00:00Z", 951782400, 0},
		{"2099-12-31T9:59:59Z", "2099-12-31T09:59:59Z", 4102394399, 0},
		{"1969-12-31T23:59:59.999999999Z", "1969-12-31T23:59:59Z", -1, 999999999},
	}
	for _, c := range accepted {
		raw, _ := json.Marshal(c.in)
		var got time.Time
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("%q: decode error %v, want %s", c.in, err, c.utc)
			continue
		}
		u := got.UTC()
		if s := u.Format(time.RFC3339); s != c.utc || u.Unix() != c.unix || int64(u.Nanosecond()) != c.nanos {
			t.Errorf("%q decoded to %s (%d, %d), want %s (%d, %d)", c.in, s, u.Unix(), u.Nanosecond(), c.utc, c.unix, c.nanos)
		}
	}
	rejected := []string{
		"2099-12-31T24:00:00Z",
		"2099-12-31T23:60:00Z",
		"2099-12-31T23:59:60Z",
		"2099-13-01T00:00:00Z",
		"2099-12-00T00:00:00Z",
		"1900-02-29T00:00:00Z",
		"2099-12-31t23:59:59Z",
		"2099-12-31T23:59:59z",
		"2099-12-31T23:59:59.Z",
		"2099-12-31T23:59:59",
		"2099-12-31T23:59:59+0100",
		"+999-12-31T23:59:59Z",
	}
	for _, in := range rejected {
		raw, _ := json.Marshal(in)
		var got time.Time
		if err := json.Unmarshal(raw, &got); err == nil {
			t.Errorf("%q decoded to %s, want a decode error", in, got.UTC().Format(time.RFC3339))
		}
	}
	if s := (time.Time{}).UTC().Format(time.RFC3339); s != "0001-01-01T00:00:00Z" {
		t.Errorf("zero time formats as %s, want 0001-01-01T00:00:00Z", s)
	}
}
