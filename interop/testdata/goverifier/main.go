// SPDX-License-Identifier: Apache-2.0

// Command goverifier puts the repository's Go reference verifier behind the
// --verifier contract, for the interop self-test: `goverifier <fixture.json>`
// verifies that one fixture file and prints the verifier's verdict as JSON,
// exiting 0 for ACCEPT and 1 for REJECT, or 2 when the verifier wrote no
// verdict. The reference verifier's own exit code says whether its verdict
// matched the fixture's expected outcome, not what the verdict was, so this
// reads the verdict from its "observed:" line.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: goverifier <fixture.json>")
		os.Exit(2)
	}
	var out, errOut bytes.Buffer
	verifier.Run([]string{"--", os.Args[1]}, &out, &errOut)
	for _, line := range strings.Split(out.String(), "\n") {
		observed, ok := strings.CutPrefix(strings.TrimSpace(line), "observed: ")
		if !ok {
			continue
		}
		switch {
		case observed == "ACCEPT":
			answer(map[string]string{"verdict": "ACCEPT"}, 0)
		case strings.HasPrefix(observed, "REJECT"):
			answer(map[string]string{"verdict": "REJECT", "reason": observed}, 1)
		}
	}
	fmt.Fprintf(os.Stderr, "the reference verifier wrote no verdict: %s%s\n", out.String(), errOut.String())
	os.Exit(2)
}

func answer(v map[string]string, code int) {
	b, err := json.Marshal(v)
	if err != nil {
		os.Exit(2)
	}
	fmt.Println(string(b))
	os.Exit(code)
}
