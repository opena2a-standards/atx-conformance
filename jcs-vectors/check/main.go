// Command check is the Go leg of the ATX v1.1 JCS byte-agreement gate. For each
// vector it INDEPENDENTLY recomputes the canonical bytes from the vector's tbs
// object (it does not read expected.canonicalHex to derive anything) and asserts
// the recomputation reproduces the pinned hex byte-for-byte. It additionally
// re-verifies the pinned Ed25519 and ML-DSA-65 signatures against the recomputed
// bytes, so the vectors double as signing known-answer tests for the registry
// and conformance verifiers.
//
// Exit 0 iff every vector reproduces its pinned canonical bytes and both
// signatures verify. Run via ../run-agreement.sh alongside the Python and TS
// legs; the three must all pass for the suite to be byte-agreed.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"
)

type vectorFile struct {
	Name     string          `json:"name"`
	TBS      json.RawMessage `json:"tbs"`
	Expected struct {
		CanonicalHex    string `json:"canonicalHex"`
		CanonicalSha256 string `json:"canonicalSha256"`
		Ed25519         struct {
			PublicKeyHex string `json:"publicKeyHex"`
			SignatureB64 string `json:"signatureB64"`
		} `json:"ed25519"`
		MLDSA65 struct {
			PublicKeyHex string `json:"publicKeyHex"`
			SignatureB64 string `json:"signatureB64"`
		} `json:"mldsa65"`
	} `json:"expected"`
}

func main() {
	dir := vectorsDir()
	entries, err := os.ReadDir(dir)
	must(err)

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		fail("no vector files found in %s", dir)
	}

	hexByName := map[string]string{}
	pass, failures := 0, 0
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		must(err)
		var v vectorFile
		must(json.Unmarshal(b, &v))

		canonical, err := jcs.Transform(v.TBS)
		if err != nil {
			report(n, false, "jcs.Transform error: "+err.Error())
			failures++
			continue
		}
		gotHex := hex.EncodeToString(canonical)
		hexByName[v.Name] = gotHex

		if gotHex != v.Expected.CanonicalHex {
			report(n, false, "canonical hex mismatch")
			fmt.Printf("       want: %s\n", v.Expected.CanonicalHex)
			fmt.Printf("       got:  %s\n", gotHex)
			failures++
			continue
		}
		sum := sha256.Sum256(canonical)
		if hex.EncodeToString(sum[:]) != v.Expected.CanonicalSha256 {
			report(n, false, "canonical sha256 mismatch")
			failures++
			continue
		}

		// Re-verify Ed25519 over the recomputed bytes.
		edPub, err := hex.DecodeString(v.Expected.Ed25519.PublicKeyHex)
		must(err)
		edSig, err := base64.StdEncoding.DecodeString(v.Expected.Ed25519.SignatureB64)
		must(err)
		if !ed25519.Verify(ed25519.PublicKey(edPub), canonical, edSig) {
			report(n, false, "Ed25519 signature did not verify over recomputed canonical bytes")
			failures++
			continue
		}

		// Re-verify ML-DSA-65 over the recomputed bytes.
		pqRaw, err := hex.DecodeString(v.Expected.MLDSA65.PublicKeyHex)
		must(err)
		pqPub := new(mldsa65.PublicKey)
		must(pqPub.UnmarshalBinary(pqRaw))
		pqSig, err := base64.StdEncoding.DecodeString(v.Expected.MLDSA65.SignatureB64)
		must(err)
		if !mldsa65.Verify(pqPub, canonical, nil, pqSig) {
			report(n, false, "ML-DSA-65 signature did not verify over recomputed canonical bytes")
			failures++
			continue
		}

		report(n, true, fmt.Sprintf("%d bytes, ed25519+ml-dsa-65 verified", len(canonical)))
		pass++
	}

	// Cross-vector invariant: scramble must equal baseline.
	if a, b := hexByName["key-order-scramble"], hexByName["baseline"]; a != "" && b != "" && a != b {
		report("invariant:scramble==baseline", false, "scramble canonical bytes differ from baseline")
		failures++
	} else if a != "" && b != "" {
		report("invariant:scramble==baseline", true, "identical canonical bytes")
	}

	fmt.Printf("\n[go]     %d pass, %d fail (%d vectors)\n", pass, failures, len(names))
	if failures > 0 {
		os.Exit(1)
	}
}

func vectorsDir() string {
	// check/ binary runs from the jcs-vectors module dir; vectors are ../vectors.
	wd, err := os.Getwd()
	must(err)
	for _, cand := range []string{
		filepath.Join(wd, "vectors"),
		filepath.Join(wd, "..", "vectors"),
	} {
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	fail("could not locate vectors/ dir from %s", wd)
	return ""
}

func report(name string, ok bool, detail string) {
	status := "PASS"
	if !ok {
		status = "FAIL"
	}
	fmt.Printf("[go]   %s  %-34s  %s\n", status, name, detail)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[go] error: "+format+"\n", args...)
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}
