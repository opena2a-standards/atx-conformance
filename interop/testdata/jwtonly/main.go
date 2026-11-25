// SPDX-License-Identifier: Apache-2.0

// Command jwtonly is a dummy verifier for the interop self-test that reads
// JWTs only: it reads the file its argument names, or stdin when it has no
// argument, and when the input is not three base64url parts separated by
// dots it says so on stderr and exits 2, an exit that is neither ACCEPT nor
// REJECT. It checks no signature: a JWT-shaped input is printed back as
// ACCEPT.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func main() {
	var in []byte
	var err error
	switch len(os.Args) {
	case 1:
		in, err = io.ReadAll(os.Stdin)
	case 2:
		in, err = os.ReadFile(os.Args[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: jwtonly [token-file]")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read the input:", err)
		os.Exit(2)
	}
	parts := bytes.Split(bytes.TrimSpace(in), []byte("."))
	if len(parts) != 3 || !base64url(parts[0]) || !base64url(parts[1]) || !base64url(parts[2]) {
		fmt.Fprintln(os.Stderr, "not a JWT: expected three base64url parts separated by dots")
		os.Exit(2)
	}
	fmt.Println(`{"verdict": "ACCEPT"}`)
}

func base64url(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
