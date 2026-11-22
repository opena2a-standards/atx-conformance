// Command atx-export writes the credential of a native ATX conformance
// fixture in an alternate form, signed with the suite's published test keys,
// so that anyone can reproduce the output byte for byte.
//
// Usage:
//
//	atx-export --form vc [--mldsa65-proof] <fixture.json>
//
// From a clone of this repository:
//
//	go run ./cmd/atx-export --form vc fixtures/v1_1-baseline-valid-hybrid.json
//
// --form vc writes the credential as a W3C Verifiable Credential 2.0 with one
// Data Integrity proof of the eddsa-jcs-2022 cryptosuite (W3C Data Integrity
// EdDSA Cryptosuites v1.0, a W3C Recommendation). The output is the RFC 8785
// canonical JSON of the credential followed by one line feed, and every run
// writes the same bytes. --mldsa65-proof adds a second proof of the
// experimental mldsa65-jcs-2024 cryptosuite, so that the proof is a proof
// set. --form jws is not built yet.
//
// The credential carries the native credential's claims, and atxTbsSha256,
// the SHA-256 of the bytes the native signatures cover. The proof is signed
// with the key of the fixture's first native Ed25519 signature, and names
// that signature's keyId as its verificationMethod. The key's seed is read
// from the vector file the fixture's keypairRefs name for that keyId.
//
// Before it signs anything, atx-export verifies every native signature of
// the fixture over the native bytes, and it refuses a fixture whose native
// signatures do not all verify. It also refuses an atcVersion "1.1"
// credential whose behavioralProfile or scanSummary holds a member the
// v1.1 to-be-signed projection leaves out, because no native signature
// covers that member, and one that writes a number the native bytes do not
// hold as written: an integer of that projection whose magnitude is above
// 2^53-1, or a declaredPurpose number written with a fraction or an
// exponent part. RFC 8785 writes such a number as the double nearest it,
// 9007199254740993 as 9007199254740992 and 1e3 as 1000, so the native
// signatures verify whichever of the two the credential writes, and the
// reference verifiers reject the credential. It refuses as well an
// atcVersion "1.1" credential whose behavioralProfile holds null for
// checksum, generatedAt or observationDays, or lacks one of them: the
// native bytes hold that member's zero value, so a native signature made
// over the zero value verifies a credential that does not write it, and the
// reference verifiers reject the credential. The same refusal meets a
// generatedAt that this build of the command reads and the reference
// verifiers do not read as a timestamp: one with a time zone offset hour
// above 24 or minute above 60, which Go 1.22 reads, and one written with a
// JSON escape, which Go 1.27 reads.
//
// An atcVersion "1.1" credential whose declaredPurpose holds an unpaired
// UTF-16 surrogate escape is one the command cannot read. RFC 8785 refuses
// a string that holds a lone surrogate, and the library that computes the
// native bytes reads such an escape and an escape directly after it as a
// single U+FFFD, so a native signature made over a declaredPurpose that
// holds U+FFFD verifies a credential that writes the two escapes in its
// place. The reference verifiers reject the credential.
//
// Exit status:
//
//	0  the credential was written
//	1  the fixture, or a vector file it names, cannot be read as the
//	   conformance suite writes them; a fixture whose atcVersion "1.1"
//	   credential holds an unpaired UTF-16 surrogate escape in its
//	   declaredPurpose is one
//	2  usage error; --form jws; or the fixture has no native signature of
//	   the algorithm a proof needs
//	3  a native signature does not verify over the native bytes, or an
//	   atcVersion "1.1" credential holds a behavioralProfile or scanSummary
//	   member those bytes leave out, a behavioralProfile in which checksum,
//	   generatedAt or observationDays is null or absent, or whose
//	   generatedAt this build reads and the reference verifiers do not, or
//	   a number those bytes do not hold as written; nothing was signed
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	exitOK              = 0
	exitInput           = 1
	exitUsage           = 2
	exitNativeSignature = 3
)

const usageLine = "usage: atx-export --form vc [--mldsa65-proof] <fixture.json>"

const help = usageLine + `

Writes the credential of a native ATX fixture as a W3C Verifiable Credential
2.0 with one eddsa-jcs-2022 Data Integrity proof, signed with the suite's
published test keys. The output is the RFC 8785 canonical JSON of the
credential and one line feed; every run writes the same bytes.

  --form vc          the form to write (--form jws is not built yet)
  --mldsa65-proof    add a second proof, of the experimental mldsa65-jcs-2024
                     cryptosuite (a proof set)

Exit status: 0 written; 1 the fixture or a vector file it names cannot be
read, or the declaredPurpose of an ATX v1.1 credential holds an unpaired
UTF-16 surrogate escape; 2 usage error, or the fixture has no native
signature of the algorithm a proof needs; 3 a native signature does not
verify over the native bytes, or an ATX v1.1 credential holds a
behavioralProfile or scanSummary member those bytes leave out, or a
behavioralProfile in which checksum, generatedAt or observationDays is null
or absent (or whose generatedAt this build reads and the reference verifiers
do not read as a timestamp), or a number they do not hold as written (an
integer above 2^53-1 in magnitude, or a declaredPurpose number with a
fraction or an exponent part), and nothing was signed.
`

// refusal is an error that ends the command with its own exit status and
// message.
type refusal struct {
	code int
	msg  string
}

func (r *refusal) Error() string { return r.msg }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("atx-export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	form := flags.String("form", "", "the alternate form to write: vc")
	withMLDSA65 := flags.Bool("mldsa65-proof", false, "add a second proof, of the experimental mldsa65-jcs-2024 cryptosuite")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, help)
			return exitOK
		}
		return usageError(stderr, err.Error())
	}
	switch {
	case *form == "jws":
		fmt.Fprintln(stderr, "atx-export: --form jws is not built yet")
		return exitUsage
	case *form == "":
		return usageError(stderr, "--form is required")
	case *form != "vc":
		return usageError(stderr, fmt.Sprintf("--form %q is not a form this command writes", *form))
	case flags.NArg() != 1:
		return usageError(stderr, "name exactly one fixture file")
	}

	out, err := exportVC(flags.Arg(0), *withMLDSA65)
	if err != nil {
		var r *refusal
		if errors.As(err, &r) {
			fmt.Fprintf(stderr, "atx-export: %s\n", r.msg)
			return r.code
		}
		fmt.Fprintf(stderr, "atx-export: %v\n", err)
		return exitInput
	}
	if _, err := stdout.Write(append(out, '\n')); err != nil {
		fmt.Fprintf(stderr, "atx-export: %v\n", err)
		return exitInput
	}
	return exitOK
}

func usageError(stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "atx-export: %s\n%s\n", msg, usageLine)
	return exitUsage
}
