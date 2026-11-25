//go:build js && wasm

// Command atx-verify-wasm is the Go reference verifier (package
// github.com/opena2a-standards/atx-conformance/verifiers/go/verifier) built
// for a web page:
//
//	GOOS=js GOARCH=wasm go build -trimpath -o atx-verify.wasm ./cmd/atx-verify-wasm
//
// A page runs atx-verify.wasm with the wasm_exec.js of the Go release that
// built it, in $(go env GOROOT)/lib/wasm (misc/wasm in older releases). The
// command sets two functions on the JavaScript global object, then waits
// for calls:
//
//	atxVerify(credentialJSON, verifierStateJSON)
//	    verifier.VerifyCredential on the two strings, its outcome as a JSON string
//	atxVersion()
//	    verifier.VersionLine(), the line atx-verify --version writes
//
// credentialJSON is the credential's JSON text, and verifierStateJSON the
// JSON text of a verifier state, in the shape of a fixture's verifierState
// member. Verification reads the time from the state's clockRfc3339, as in
// every fixture, and reads no clock of its own. The command reads no file
// and opens no connection.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

// argumentsReason is the reason of the ERROR outcome atxVerify returns when
// it is not called with two strings.
const argumentsReason = "atxVerify takes two strings: the credential JSON and the verifier state JSON"

func main() {
	register()
	select {} // wait for calls; each one runs when the page calls a function
}

// register sets atxVerify and atxVersion on the JavaScript global object.
func register() {
	js.Global().Set("atxVerify", js.FuncOf(atxVerify))
	js.Global().Set("atxVersion", js.FuncOf(atxVersion))
}

// atxVerify is the global function atxVerify. js.Value.String spells a value
// that is not a string as a description ("<number: 1>"), so a call with
// other than two strings is an ERROR outcome, not a credential to verify.
func atxVerify(_ js.Value, args []js.Value) any {
	if len(args) != 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString {
		return encode(verifier.Outcome{Verdict: "ERROR", Reason: argumentsReason})
	}
	return encode(verifier.VerifyCredential([]byte(args[0].String()), []byte(args[1].String())))
}

// atxVersion is the global function atxVersion.
func atxVersion(js.Value, []js.Value) any {
	return verifier.VersionLine()
}

// encode returns o as JSON text. json.Marshal returns no error for an
// Outcome, whose members are strings, integers and booleans.
func encode(o verifier.Outcome) string {
	b, err := json.Marshal(o)
	if err != nil {
		panic(err)
	}
	return string(b)
}
