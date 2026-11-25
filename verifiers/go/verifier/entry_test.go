package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	atxconformance "github.com/opena2a-standards/atx-conformance"
)

// The tests in this file hold VerifyCredential, the entry point a web page
// (cmd/atx-verify-wasm) or an HTTP handler calls with a credential and a
// verifier state, to verify, the function Run calls for each fixture. There
// is one verification path: the entry point adds the decoding of the
// verifier state and the shape of its answer, nothing else. Each test name
// starts with TestEntry, so `go test -run Entry` runs them all.

// entryFixture is an embedded fixture as these tests use it: the fixture as
// Run loads it, and the text of its verifierState member, which
// VerifyCredential takes beside the text of its atx member (f.ATX).
type entryFixture struct {
	name  string
	f     fixture
	state []byte
}

// embeddedEntryFixtures loads each fixture the module root embeds, as Run
// loads it with no argument. It fails the test when there is none, so no
// test over them passes vacuously.
func embeddedEntryFixtures(t *testing.T) []entryFixture {
	t.Helper()
	sources, err := embeddedSources()
	if err != nil {
		t.Fatalf("cannot list the embedded fixtures: %v", err)
	}
	if len(sources) == 0 {
		t.Fatal("the module root embeds no fixture; refusing to pass vacuously")
	}
	out := make([]entryFixture, 0, len(sources))
	for _, s := range sources {
		b, err := s.read()
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		out = append(out, loadEntryFixture(t, s.name, b))
	}
	return out
}

// loadEntryFixture decodes the fixture file b, named name, as Run does and
// keeps the text of its verifierState member.
func loadEntryFixture(t *testing.T, name string, b []byte) entryFixture {
	t.Helper()
	f, err := parseFixture(b)
	if err != nil {
		t.Fatalf("%s does not load: %v", name, err)
	}
	var members struct {
		VerifierState json.RawMessage `json:"verifierState"`
	}
	if err := json.Unmarshal(b, &members); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(members.VerifierState) == 0 {
		t.Fatalf("%s writes no verifierState member, which schemas/fixture-v1.schema.json requires", name)
	}
	return entryFixture{name, f, members.VerifierState}
}

// baselineEntryFixture is fixtures/baseline-valid.json, a credential the
// baseline verifier state accepts, and the file's text.
func baselineEntryFixture(t *testing.T) (entryFixture, []byte) {
	t.Helper()
	const name = "fixtures/baseline-valid.json"
	b, err := fs.ReadFile(atxconformance.Fixtures, name)
	if err != nil {
		t.Fatal(err)
	}
	ef := loadEntryFixture(t, name, b)
	if got := verify(ef.f); !got.Accepted {
		t.Fatalf("verify gives %s for %s, which the controls below take as an accepted credential", got, name)
	}
	return ef, b
}

// verdictOf is the verdict an Outcome writes for r, a result of verify.
func verdictOf(r result) string {
	if r.Accepted {
		return "ACCEPT"
	}
	return "REJECT"
}

// TestEntryAgreesWithVerifyOnEachEmbeddedFixture runs VerifyCredential on
// the text of the atx and verifierState members of each embedded fixture.
// It requires the verdict, reject category and reason verify returns for
// the fixture, and the outcome the fixture expects, as matchesExpected
// reads it. The trust level, the step 7 members and the signature counts
// are those of verify's result. So are issuerDid and agentDid: the members
// verify read, which a credential the strict parse rejects carries none of
// (core.md section 1.3 step 8: a relying party acts on the members the
// verifier read, never on a second decode of the credential). selfIssued
// is true exactly when the two are equal and not empty.
func TestEntryAgreesWithVerifyOnEachEmbeddedFixture(t *testing.T) {
	fixtures := embeddedEntryFixtures(t)
	agree, named := 0, 0
	for _, ef := range fixtures {
		want := verify(ef.f)
		got := VerifyCredential(ef.f.ATX, ef.state)
		failed := false
		fail := func(format string, args ...any) {
			failed = true
			t.Errorf("%s: %s", ef.name, fmt.Sprintf(format, args...))
		}

		if got.Verdict != verdictOf(want) || got.RejectCategory != want.RejectCategory || got.Reason != want.Reason {
			fail("VerifyCredential gives %s [%s: %q]; verify gives %s", got.Verdict, got.RejectCategory, got.Reason, want)
		}
		exp := ef.f.Expected
		switch {
		case got.Verdict != exp.VerifyResult:
			fail("VerifyCredential gives %s; the fixture expects %s", got.Verdict, exp.VerifyResult)
		case exp.VerifyResult == "ACCEPT":
		case exp.RejectCategory != "" && got.RejectCategory != exp.RejectCategory:
			fail("VerifyCredential rejects as %s; the fixture expects %s", got.RejectCategory, exp.RejectCategory)
		case exp.ReasonContains != "" && !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(exp.ReasonContains)):
			fail("VerifyCredential's reason %q does not contain %q", got.Reason, exp.ReasonContains)
		}

		if got.TrustLevel != want.TrustLevel || got.Step7Performed != want.Step7Performed ||
			got.SignerAuthorities != want.SignerAuthorities ||
			got.SignaturesExpected != want.SigsExpected || got.SignaturesValid != want.SigsValid {
			fail("VerifyCredential carries trustLevel %d, step 7 %t with %d authorities, signatures %d/%d; "+
				"verify's result carries %d, %t with %d, %d/%d",
				got.TrustLevel, got.Step7Performed, got.SignerAuthorities, got.SignaturesValid, got.SignaturesExpected,
				want.TrustLevel, want.Step7Performed, want.SignerAuthorities, want.SigsValid, want.SigsExpected)
		}
		if got.IssuerDID != want.IssuerDID || got.AgentDID != want.AgentDID {
			fail("VerifyCredential carries issuerDid %q and agentDid %q; verify's result carries %q and %q",
				got.IssuerDID, got.AgentDID, want.IssuerDID, want.AgentDID)
		}
		if want.RejectCategory == "PARSE_ERROR" {
			if got.IssuerDID != "" || got.AgentDID != "" {
				fail("the strict parse rejects the credential, and VerifyCredential still carries issuerDid %q and agentDid %q",
					got.IssuerDID, got.AgentDID)
			}
		} else {
			var a atx
			if err := json.Unmarshal(ef.f.ATX, &a); err != nil {
				fail("verify parsed the credential, and json.Unmarshal into atx fails: %v", err)
			} else if got.IssuerDID != a.IssuerDID || got.AgentDID != a.AgentDID {
				fail("VerifyCredential carries issuerDid %q and agentDid %q; the credential's members are %q and %q",
					got.IssuerDID, got.AgentDID, a.IssuerDID, a.AgentDID)
			}
			if a.IssuerDID != "" && a.AgentDID != "" {
				named++
			}
		}
		if wantSelf := got.IssuerDID != "" && got.IssuerDID == got.AgentDID; got.SelfIssued != wantSelf {
			fail("selfIssued is %t with issuerDid %q and agentDid %q", got.SelfIssued, got.IssuerDID, got.AgentDID)
		}
		if !failed {
			agree++
		}
	}
	if named == 0 {
		t.Error("no embedded fixture past the strict parse names an issuer and an agent, so the issuerDid and agentDid checks above checked nothing")
	}
	t.Logf("VerifyCredential equals verify on %d of %d embedded fixtures (%d past the strict parse naming an issuer and an agent)",
		agree, len(fixtures), named)
}

// TestEntryVerifierStateThatDoesNotDecodeIsAnError holds that a verifier
// state encoding/json cannot decode into the fixtures' verifierState shape
// reaches no verdict: VerifyCredential returns ERROR, no reject category,
// the decoder's reason, and no other member.
func TestEntryVerifierStateThatDoesNotDecodeIsAnError(t *testing.T) {
	baseline, _ := baselineEntryFixture(t)
	for _, state := range []string{
		"not json",
		"",
		`{"clockRfc3339": "2026-01-01T00:00:00Z"`,
		`{"clockRfc3339": "2026-01-01T00:00:00Z"} {}`,
		"[]",
		`"did:opena2a:authority:opena2a.org"`,
		`{"trustedIssuers": "did:opena2a:authority:opena2a.org"}`,
		`{"clockRfc3339": 20260101}`,
		`{"requiredSignatures": 1.5}`,
	} {
		var s verifierState
		decodeErr := json.Unmarshal([]byte(state), &s)
		if decodeErr == nil {
			t.Fatalf("%q decodes as a verifier state, so it controls nothing", state)
		}
		got := VerifyCredential(baseline.f.ATX, []byte(state))
		if got.Verdict != "ERROR" || got.RejectCategory != "" || !strings.HasSuffix(got.Reason, decodeErr.Error()) {
			t.Errorf("state %q: VerifyCredential gives %s [%s: %q], want ERROR with the decoder's reason %q",
				state, got.Verdict, got.RejectCategory, got.Reason, decodeErr.Error())
		}
		if only := (Outcome{Verdict: got.Verdict, Reason: got.Reason}); got != only {
			t.Errorf("state %q: the outcome is %+v, want no member besides verdict and reason", state, got)
		}
	}
}

// TestEntryVerifierStateRepeatingAMemberIsAnError holds that a verifier
// state writing a member twice, under one name or under two names that
// fold together, is an ERROR naming the member as written the second time,
// as parseFixture refuses a fixture whose verifierState member does so
// (repeatedFixtureMember): encoding/json keeps the last of the two, and a
// reader that keeps the first trusts another issuer set.
func TestEntryVerifierStateRepeatingAMemberIsAnError(t *testing.T) {
	baseline, baselineText := baselineEntryFixture(t)
	const clock = `"clockRfc3339":"2026-01-01T00:00:00Z"`
	for _, c := range []struct{ state, member string }{
		{`{` + clock + `,"trustedIssuers":["did:a"],"trustedIssuers":["did:b"]}`, "trustedIssuers"},
		{`{` + clock + `,"trustedIssuers":["did:a"],"TrustedIssuers":["did:b"]}`, "TrustedIssuers"},
		{`{` + clock + `,"publicKeys":[{"keyId":"did:a#k","keyId":"did:b#k"}]}`, "keyId"},
		{`{` + clock + `,` + clock + `}`, "clockRfc3339"},
	} {
		got := VerifyCredential(baseline.f.ATX, []byte(c.state))
		want := Outcome{Verdict: "ERROR", Reason: fmt.Sprintf("the verifier state repeats the member %q", c.member)}
		if got != want {
			t.Errorf("state %s: VerifyCredential gives %+v, want %+v", c.state, got, want)
		}

		var doc map[string]json.RawMessage
		if err := json.Unmarshal(baselineText, &doc); err != nil {
			t.Fatal(err)
		}
		doc["verifierState"] = json.RawMessage(c.state)
		file, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseFixture(file); err == nil || !strings.Contains(err.Error(), strconv.Quote(c.member)) {
			t.Errorf("state %s: the baseline fixture holding it loads with error %v, want one naming %q",
				c.state, err, c.member)
		}
	}
}

// TestEntryCredentialThatDoesNotParseRejects holds that the credential's
// bytes go to verify as they are: a credential that is not JSON, or not a
// JSON object, rejects at the strict parse with PARSE_ERROR and the reason
// verify gives for it, the function Run calls, and carries no member. The
// empty credential takes the reason verify gives a fixture with no atx
// member.
func TestEntryCredentialThatDoesNotParseRejects(t *testing.T) {
	baseline, _ := baselineEntryFixture(t)
	for _, credential := range []string{
		"not json",
		"",
		"{",
		`{"atcVersion":"1.1",}`,
		"[]",
		`"did:opena2a:agent:agent_conformance_test_001"`,
		`{"agentDid":"did:a","agentDid":"did:a"}`,
	} {
		want := verify(fixture{ATX: json.RawMessage(credential), VerifierState: baseline.f.VerifierState})
		if want.RejectCategory != "PARSE_ERROR" {
			t.Fatalf("verify gives %s for the credential %q, so it controls nothing here", want, credential)
		}
		got := VerifyCredential([]byte(credential), baseline.state)
		if only := (Outcome{Verdict: "REJECT", RejectCategory: "PARSE_ERROR", Reason: want.Reason}); got != only {
			t.Errorf("credential %q: VerifyCredential gives %+v, want %+v", credential, got, only)
		}
	}
}

// TestEntrySelfIssuedIsTheIssuerNamingItsAgent holds selfIssued to the
// credential naming its own agent as issuer: the issuerDid and agentDid
// verify read, equal and not empty, whatever the verdict. No embedded
// fixture is self-issued, so the credential here is the baseline's with its
// issuerDid set to its agentDid. Verify reads both and rejects it at step 4
// (untrusted issuer) under the baseline verifier state, and goes on past
// step 4 when the state also trusts the agent's DID. A credential naming
// neither is not self-issued, though its two empty members are equal.
func TestEntrySelfIssuedIsTheIssuerNamingItsAgent(t *testing.T) {
	baseline, _ := baselineEntryFixture(t)
	var credential map[string]json.RawMessage
	if err := json.Unmarshal(baseline.f.ATX, &credential); err != nil {
		t.Fatal(err)
	}
	var agent string
	if err := json.Unmarshal(credential["agentDid"], &agent); err != nil || agent == "" {
		t.Fatalf("the baseline credential's agentDid is %s (%v), not a DID", credential["agentDid"], err)
	}
	credential["issuerDid"] = credential["agentDid"]
	selfIssued, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}

	var state map[string]json.RawMessage
	if err := json.Unmarshal(baseline.state, &state); err != nil {
		t.Fatal(err)
	}
	var trusted []string
	if err := json.Unmarshal(state["trustedIssuers"], &trusted); err != nil {
		t.Fatal(err)
	}
	if state["trustedIssuers"], err = json.Marshal(append(trusted, agent)); err != nil {
		t.Fatal(err)
	}
	trustingAgent, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name         string
		state        []byte
		pastStep4    bool
		wantCategory string
	}{
		{"baseline state", baseline.state, false, "UNTRUSTED_ISSUER"},
		{"state trusting the agent's DID", trustingAgent, true, ""},
	} {
		got := VerifyCredential(selfIssued, c.state)
		var s verifierState
		if err := json.Unmarshal(c.state, &s); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		want := verify(fixture{ATX: selfIssued, VerifierState: s})
		if got.Verdict != verdictOf(want) || got.RejectCategory != want.RejectCategory || got.Reason != want.Reason {
			t.Errorf("%s: VerifyCredential gives %s [%s: %q]; verify gives %s", c.name, got.Verdict, got.RejectCategory, got.Reason, want)
		}
		if c.wantCategory != "" && got.RejectCategory != c.wantCategory {
			t.Errorf("%s: VerifyCredential rejects as %q, want %s", c.name, got.RejectCategory, c.wantCategory)
		}
		if c.pastStep4 && got.RejectCategory == "UNTRUSTED_ISSUER" {
			t.Errorf("%s: VerifyCredential still rejects at step 4: %q", c.name, got.Reason)
		}
		if !got.SelfIssued || got.IssuerDID != agent || got.AgentDID != agent {
			t.Errorf("%s: the outcome is selfIssued %t with issuerDid %q and agentDid %q, want true with both %q",
				c.name, got.SelfIssued, got.IssuerDID, got.AgentDID, agent)
		}
	}

	got := VerifyCredential([]byte(`{}`), baseline.state)
	if got.Verdict != "REJECT" || got.SelfIssued || got.IssuerDID != "" || got.AgentDID != "" {
		t.Errorf("a credential naming no issuer and no agent gives %+v, want a REJECT that is not self-issued", got)
	}
}

// TestEntryVersionLineIsWhatVersionWrites holds VersionLine to the line
// `atx-verify --version` writes, without its newline, so a page or a
// response header can show it as it is.
func TestEntryVersionLineIsWhatVersionWrites(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--version"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("Run(--version) exits %d and writes %q to stderr", code, stderr.String())
	}
	got := VersionLine()
	if got+"\n" != stdout.String() || strings.ContainsAny(got, "\r\n") {
		t.Errorf("VersionLine() = %q; --version writes %q", got, stdout.String())
	}
}

// TestEntryOutcomeJSONMembers pins the members a page and an HTTP handler
// read from an Outcome encoded as JSON: camelCase names in this order, and
// rejectCategory written only when there is one.
func TestEntryOutcomeJSONMembers(t *testing.T) {
	for _, c := range []struct {
		o    Outcome
		want string
	}{
		{
			Outcome{Verdict: "ACCEPT", TrustLevel: 2, IssuerDID: "did:i", AgentDID: "did:a", Step7Performed: true,
				SignerAuthorities: 1, SignaturesExpected: 2, SignaturesValid: 2},
			`{"verdict":"ACCEPT","reason":"","trustLevel":2,"issuerDid":"did:i","agentDid":"did:a","selfIssued":false,` +
				`"step7Performed":true,"signerAuthorities":1,"signaturesExpected":2,"signaturesValid":2}`,
		},
		{
			Outcome{Verdict: "REJECT", RejectCategory: "UNTRUSTED_ISSUER", Reason: "r", IssuerDID: "did:a", AgentDID: "did:a", SelfIssued: true},
			`{"verdict":"REJECT","rejectCategory":"UNTRUSTED_ISSUER","reason":"r","trustLevel":0,"issuerDid":"did:a",` +
				`"agentDid":"did:a","selfIssued":true,"step7Performed":false,"signerAuthorities":0,"signaturesExpected":0,"signaturesValid":0}`,
		},
		{
			Outcome{Verdict: "ERROR", Reason: "r"},
			`{"verdict":"ERROR","reason":"r","trustLevel":0,"issuerDid":"","agentDid":"","selfIssued":false,` +
				`"step7Performed":false,"signerAuthorities":0,"signaturesExpected":0,"signaturesValid":0}`,
		},
	} {
		b, err := json.Marshal(c.o)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != c.want {
			t.Errorf("json.Marshal(%+v) =\n%s\nwant\n%s", c.o, b, c.want)
		}
	}
}
