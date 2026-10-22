# atx-conformance: continuous verification

The gates CI runs on this repository. The commands that run the verifiers
by hand are in the [README](../README.md#running-the-verifiers).

## Continuous verification

[`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml)
runs the following gates on every pull request and every push to `main`.
They cover the counts, the verifier results, the fixture bytes and the
claims the README and its pages under `docs/` make about them -- not every
sentence below:

1. Both reference verifiers run against `fixtures/` and must report
   `30 pass, 0 fail`. `go test ./...` in `verifiers/go` runs the Go verifier in
   the directory and with the arguments of the command the capture's
   sidecar records it ran (`ranAs`) and requires its standard output to
   equal [`docs/captures/go-verifier.txt`](captures/go-verifier.txt), the
   full output the README excerpts, byte for byte.
2. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
3. The JCS byte-agreement gate
   ([`jcs-vectors/run-agreement.sh`](../jcs-vectors/run-agreement.sh)) must
   pass across the independent Go, Python, and TypeScript canonicalizers
   and across both reference verifiers' own v1.1 projection
   (`verifiers/go`, `verifiers/python`; the gate needs the Python
   verifier's dependencies), and every Go module in the repository must pin
   one `cloudflare/circl` version
   ([`scripts/check_circl_pin.sh`](../scripts/check_circl_pin.sh)), so the
   vectors and the verifier share one crypto tree.
4. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](../scripts/parity/parity.py)) asserts the Go
   and Python verifiers agree per fixture on gate status, verdict, and
   reject category, and publishes `parity-report.json` as a CI artifact.
   It runs each argument list of its argument table from a symbolic link to
   a scratch directory, with `PWD` naming the link. On each (an empty
   argument, `-h` and `--help` at several positions, `--version` and an
   unknown option after a path, an unknown option that is not UTF-8, `-`
   alone, a repository root, a directory whose `fixtures` entry is a file,
   a path that does not exist, a path that is not UTF-8, a file whose name
   is not UTF-8 and a directory holding it, a directory with no `*.json`,
   a directory holding a subdirectory named `*.json`, a directory holding
   a symbolic link to a fixture and one holding a link to a directory, a
   directory that cannot be listed and a repository root whose `fixtures`
   directory cannot be, a file that cannot be read, its name UTF-8 or not,
   spelled with `./` and `//` and found in a directory, a path named
   twice, a file spelled with `./` and `//` and one spelled with `..`, a
   directory spelled with `./` and `//` and one spelled with `..`, a
   directory spelled with a `..` after a symbolic link, with a trailing
   `/` and without, a file named with a trailing `/`, a path and an option
   after `--`, an absolute path through the link, through its target, with
   a `..` after a symbolic link and outside the working directory, a
   fixture that writes `expected` twice, under one name, under two that
   differ in case and with a member the second omits, one that writes
   `verifierState` twice, one that writes `verifyResult` twice in
   `expected` and one that writes `clockRfc3339` twice in `verifierState`,
   each of which both must fail to load, and a credential that writes a
   member twice) the two must exit with the same code and write
   the same first stderr line and verdict lines, the load error a FAIL line
   names included. Where
   the file system refuses a file name that is not UTF-8, as APFS does, the
   three cases that need one are skipped, their rows saying why. Only
   `EILSEQ` or `EINVAL`, raised writing the scratch file so named, is a
   refusal; another error writing it, `ENOSPC` for one, fails the gate, as
   does an error reading the fixture copied there, whatever its errno. The
   six cases that need a path of mode 000 are skipped where that mode does
   not deny the gate access, as it does not where the gate runs as root:
   their rows name the path the gate opened and its effective uid. With
   no argument, and with `--` alone, they must differ as documented: the Go
   verifier verifies its embedded fixture set, every fixture passing, and
   the Python verifier prints its usage and exits 2.
5. `conformance.json` must match the fixture set, and every ATX citation in
   each fixture's `spec` list, each JCS vector's `spec` member and the
   `requirements[].specRefs` of `conformance.json` must link to atx-spec
   `core.md` at the pinned atx-spec commit and name one of its headings
   exactly ([`scripts/check_spec_refs.py`](../scripts/check_spec_refs.py)).
   A citation id must be a string, and one that differs from `ATX` only in
   case or surrounding blanks fails rather than being skipped. Every link to
   atx-spec `core.md` in the README, in its pages under `docs/` and in
   `verifiers/go/verifier/verify.go` must be the same pinned link. The top-level
   `spec.ref` of
   `conformance.json` is written from that link, so the staleness check holds
   it to the pin; the prose of `notCovered[].item` is not checked. Headings
   are read from the copy vendored at `schemas/vendor/atx-spec/core.md` from
   the same pinned atx-spec ref as the schema. That copy must carry the
   SHA-256 of `core.md` at that ref, and the ref recorded with it must be the
   one the schema drift gate checks out, so the copy cannot gain a heading by
   being edited or fall behind a moved pin.
6. Schema validation
   ([`scripts/schema_validation.py`](../scripts/schema_validation.py)): every
   fixture's `atx` member must validate against the atx-spec machine-readable
   credential schema, vendored under `schemas/vendor/atx-spec/` and
   byte-drift-gated against a pinned atx-spec ref; the `malformed-schema`
   fixture must fail on exactly the `atcVersion` registry enum. Before that,
   every fixture and `conformance.json` must name in `$schema` the `$id` of a
   schema under `schemas/` and validate against it in full
   (`schemas/fixture-v1.schema.json`,
   `schemas/conformance-profile-v1.schema.json`), and each schema's `$id` must
   be the address GitHub serves that file from on `main`
   (`https://raw.githubusercontent.com/opena2a-standards/atx-conformance/main/`
   followed by its path); a self-test first proves the check fails on altered
   copies of each document and on copies of each schema that name another
   address.
