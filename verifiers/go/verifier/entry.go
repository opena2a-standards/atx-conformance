package verifier

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
)

// Outcome is what VerifyCredential returns for one credential: the verdict,
// and the members of the credential this verifier read, from which a
// relying party takes each value it acts on (core.md section 1.3 step 8).
// Its JSON encoding is what cmd/atx-verify-wasm returns to a page.
//
// Reason, IssuerDID and AgentDID can hold text the credential supplies. A
// page writes them as text, never as markup.
type Outcome struct {
	// Verdict is ACCEPT or REJECT, the verdict verify reached, or ERROR
	// when the verifier state did not decode, so that no step ran.
	Verdict string `json:"verdict"`
	// RejectCategory is the category of a REJECT, as a fixture's
	// expected.rejectCategory names it. The JSON encoding omits it when
	// it is empty.
	RejectCategory string `json:"rejectCategory,omitempty"`
	// Reason is the reason verify gave for a REJECT, before the escaping
	// the CLI's report applies, or why the call is an ERROR. It is empty
	// on an ACCEPT.
	Reason string `json:"reason"`
	// TrustLevel is the trust level the credential asserts, as step 7 read
	// it. TrustLevel, Step7Performed, SignerAuthorities, SignaturesExpected
	// and SignaturesValid are set when every signature the credential
	// declares has verified: on an ACCEPT, and on a REJECT whose category
	// is INSUFFICIENT_SIGNER_AUTHORITIES. They are zero on any other
	// outcome.
	TrustLevel int `json:"trustLevel"`
	// IssuerDID and AgentDID are the credential's issuerDid and agentDid
	// as verify read them. They are set whatever the verdict once the
	// strict parse has passed, and empty when it rejected the credential
	// (PARSE_ERROR) or on an ERROR.
	IssuerDID string `json:"issuerDid"`
	AgentDID  string `json:"agentDid"`
	// SelfIssued is true when the credential names its own agent as its
	// issuer: IssuerDID and AgentDID are equal and not empty. It is set
	// whatever the verdict.
	SelfIssued bool `json:"selfIssued"`
	// Step7Performed records whether step 7, the count of distinct signer
	// authorities, ran, and SignerAuthorities is that count.
	Step7Performed    bool `json:"step7Performed"`
	SignerAuthorities int  `json:"signerAuthorities"`
	// SignaturesExpected is the number of signatures the credential
	// declares, and SignaturesValid the number that verified.
	SignaturesExpected int `json:"signaturesExpected"`
	SignaturesValid    int `json:"signaturesValid"`
}

// VerifyCredential verifies one credential against one verifier state with
// verify, the function Run calls for each fixture, and returns the outcome.
//
// credential is the JSON text of the credential, the value a fixture's atx
// member holds. It goes to verify as it is, so a credential that does not
// parse rejects as PARSE_ERROR, as it does in the CLI. An empty credential
// takes the reason verify gives a fixture with no atx member.
//
// verifierState is the JSON text of a verifier state, the value a fixture's
// verifierState member holds: the issuers and keys the relying party
// trusts, what it requires, and clockRfc3339, the time it verifies at.
// VerifyCredential reads no clock, no file and no network. The state is
// decoded as parseFixture decodes a fixture's verifierState member. A state
// that does not decode, or writes a member twice, returns ERROR with the
// reason, and no step runs.
func VerifyCredential(credential, verifierState []byte) Outcome {
	state, err := decodeVerifierState(verifierState)
	if err != nil {
		return Outcome{Verdict: "ERROR", Reason: err.Error()}
	}
	r := verify(fixture{ATX: credential, VerifierState: state})
	verdict := "REJECT"
	if r.Accepted {
		verdict = "ACCEPT"
	}
	return Outcome{
		Verdict:            verdict,
		RejectCategory:     r.RejectCategory,
		Reason:             r.Reason,
		TrustLevel:         r.TrustLevel,
		IssuerDID:          r.IssuerDID,
		AgentDID:           r.AgentDID,
		SelfIssued:         r.IssuerDID != "" && r.IssuerDID == r.AgentDID,
		Step7Performed:     r.Step7Performed,
		SignerAuthorities:  r.SignerAuthorities,
		SignaturesExpected: r.SigsExpected,
		SignaturesValid:    r.SigsValid,
	}
}

// decodeVerifierState decodes b, the JSON text of a verifier state, as
// parseFixture decodes the verifierState member of a fixture file. A member
// written twice, under one name or under two names that fold together,
// refuses the state, as repeatedFixtureMember refuses the file: encoding/json
// keeps the last of the two, and a reader that keeps the first trusts other
// issuers. encoding/json decodes the rest, and its error says why a state
// does not decode.
func decodeVerifierState(b []byte) (verifierState, error) {
	if json.Valid(b) {
		if name, dup := rawDuplicateMember(b); dup {
			return verifierState{}, fmt.Errorf("the verifier state repeats the member %q", name)
		}
	}
	var s verifierState
	if err := json.Unmarshal(b, &s); err != nil {
		return verifierState{}, fmt.Errorf("the verifier state does not decode: %w", err)
	}
	return s, nil
}

// VersionLine returns the line atx-verify --version writes, without its
// newline.
func VersionLine() string {
	info, ok := debug.ReadBuildInfo()
	return strings.TrimSuffix(versionLine(info, ok), "\n")
}
