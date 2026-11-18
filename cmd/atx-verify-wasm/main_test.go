//go:build js && wasm

package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"strings"
	"sync"
	"syscall/js"
	"testing"

	atxconformance "github.com/opena2a-standards/atx-conformance"
	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

// These tests run in the runtime a page runs the command in. From the
// repository root:
//
//	PATH="$(go env GOROOT)/lib/wasm:$PATH" GOOS=js GOARCH=wasm go test ./cmd/atx-verify-wasm/
//
// go_js_wasm_exec, which older Go releases keep in $(go env GOROOT)/misc/wasm,
// runs the test binary under node.

var registerOnce sync.Once

// global returns the JavaScript global function name, once register has set
// the command's functions as main does, and fails the test when the global
// is not a function.
func global(t *testing.T, name string) js.Value {
	t.Helper()
	registerOnce.Do(register)
	fn := js.Global().Get(name)
	if fn.Type() != js.TypeFunction {
		t.Fatalf("the JavaScript global %s is %s, not a function", name, fn.Type())
	}
	return fn
}

// outcome decodes what atxVerify returned: a JSON string holding the members
// of verifier.Outcome and no other.
func outcome(t *testing.T, v js.Value) verifier.Outcome {
	t.Helper()
	if v.Type() != js.TypeString {
		t.Fatalf("atxVerify returns %s, not a string", v.Type())
	}
	dec := json.NewDecoder(strings.NewReader(v.String()))
	dec.DisallowUnknownFields()
	var o verifier.Outcome
	if err := dec.Decode(&o); err != nil {
		t.Fatalf("atxVerify returns %q, not an outcome: %v", v.String(), err)
	}
	return o
}

// embeddedFixture is the text of the atx and verifierState members of an
// embedded fixture, the two arguments a page passes atxVerify, and the
// outcome the fixture expects.
type embeddedFixture struct {
	ATX           json.RawMessage `json:"atx"`
	VerifierState json.RawMessage `json:"verifierState"`
	Expected      struct {
		VerifyResult   string `json:"verifyResult"`
		RejectCategory string `json:"rejectCategory"`
	} `json:"expected"`
}

func readEmbeddedFixture(t *testing.T, name string) embeddedFixture {
	t.Helper()
	b, err := fs.ReadFile(atxconformance.Fixtures, name)
	if err != nil {
		t.Fatal(err)
	}
	var fx embeddedFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return fx
}

// observation is a verdict and a reject category as a report line writes
// them.
type observation struct{ verdict, category string }

// cliObservations runs the CLI's verifier with no argument, as atx-verify
// runs it, in this runtime, and returns the verdict and reject category its
// report observes for each embedded fixture, by name.
func cliObservations(t *testing.T) map[string]observation {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := verifier.Run(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("verifier.Run with no argument exits %d (stderr %q)", code, stderr.String())
	}
	out := map[string]observation{}
	name := ""
	for _, line := range strings.Split(stdout.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "PASS  "); ok {
			name = rest
			continue
		}
		observed, ok := strings.CutPrefix(line, "       observed: ")
		if !ok || name == "" {
			continue
		}
		switch {
		case observed == "ACCEPT":
			out[name] = observation{"ACCEPT", ""}
		case strings.HasPrefix(observed, "REJECT["):
			category, _, _ := strings.Cut(strings.TrimPrefix(observed, "REJECT["), ":")
			out[name] = observation{"REJECT", category}
		default:
			t.Fatalf("%s: the report observes %q", name, observed)
		}
		name = ""
	}
	return out
}

// TestAtxVerifyAgreesWithTheCLIOnEachEmbeddedFixture calls atxVerify as a
// page does, through the JavaScript global object, with the text of the atx
// and verifierState members of each fixture the module root embeds. Each
// verdict and reject category must be the one the fixture expects and the
// one the CLI's verifier observes for it in the same runtime.
func TestAtxVerifyAgreesWithTheCLIOnEachEmbeddedFixture(t *testing.T) {
	atxVerify := global(t, "atxVerify")
	cli := cliObservations(t)
	entries, err := fs.ReadDir(atxconformance.Fixtures, "fixtures")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the module root embeds no fixture; refusing to pass vacuously")
	}
	agree := 0
	for _, e := range entries {
		name := "fixtures/" + e.Name()
		fx := readEmbeddedFixture(t, name)
		got := outcome(t, atxVerify.Invoke(string(fx.ATX), string(fx.VerifierState)))
		exp, observed := fx.Expected, cli[name]
		ok := true
		if got.Verdict != exp.VerifyResult ||
			(exp.VerifyResult == "REJECT" && exp.RejectCategory != "" && got.RejectCategory != exp.RejectCategory) {
			ok = false
			t.Errorf("%s: atxVerify gives %s [%s]; the fixture expects %s [%s]",
				name, got.Verdict, got.RejectCategory, exp.VerifyResult, exp.RejectCategory)
		}
		if got.Verdict != observed.verdict || got.RejectCategory != observed.category {
			ok = false
			t.Errorf("%s: atxVerify gives %s [%s]; the CLI observes %s [%s]",
				name, got.Verdict, got.RejectCategory, observed.verdict, observed.category)
		}
		if ok {
			agree++
		}
	}
	if len(cli) != len(entries) {
		t.Errorf("the CLI's report observes %d fixtures; the module root embeds %d", len(cli), len(entries))
	}
	t.Logf("atxVerify agrees with the expected outcome and the CLI on %d of %d embedded fixtures", agree, len(entries))
}

// TestAtxVersionIsTheVersionLine holds atxVersion to verifier.VersionLine,
// the line atx-verify --version writes.
func TestAtxVersionIsTheVersionLine(t *testing.T) {
	v := global(t, "atxVersion").Invoke()
	if v.Type() != js.TypeString || v.String() != verifier.VersionLine() || !strings.HasPrefix(v.String(), "atx-verify: ") {
		t.Errorf("atxVersion() returns %s %q; verifier.VersionLine() is %q", v.Type(), v.String(), verifier.VersionLine())
	}
}

// TestAtxVerifyWithoutTwoStringsIsAnError holds atxVerify to its two string
// arguments. Called with another number of arguments, or with one that is
// not a string, it returns an ERROR outcome that says so: js.Value.String
// spells a number as "<number: 1>", which atxVerify would otherwise verify
// as a credential's text.
func TestAtxVerifyWithoutTwoStringsIsAnError(t *testing.T) {
	atxVerify := global(t, "atxVerify")
	fx := readEmbeddedFixture(t, "fixtures/baseline-valid.json")
	credential, state := string(fx.ATX), string(fx.VerifierState)
	if got := outcome(t, atxVerify.Invoke(credential, state)); got.Verdict != "ACCEPT" {
		t.Fatalf("atxVerify gives %+v for the baseline fixture, which the cases below take as an accepted credential", got)
	}
	for _, args := range [][]any{
		{},
		{credential},
		{credential, state, state},
		{nil, state},
		{credential, js.Undefined()},
		{1, state},
		{credential, map[string]any{"clockRfc3339": "2026-01-01T00:00:00Z"}},
		{js.Global().Get("Uint8Array").New(len(credential)), state},
	} {
		got := outcome(t, atxVerify.Invoke(args...))
		if want := (verifier.Outcome{Verdict: "ERROR", Reason: argumentsReason}); got != want {
			t.Errorf("atxVerify with %d arguments %v gives %+v, want %+v", len(args), args, got, want)
		}
	}
}
