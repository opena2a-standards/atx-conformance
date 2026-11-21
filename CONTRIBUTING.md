# Contributing to atx-conformance

Where to raise a change, and where each part of the repository lives. The
gates a pull request must pass are in
[docs/continuous-verification.md](docs/continuous-verification.md).

## Contributing

Issues and PRs welcome on this repository. Second-party implementations and
cosigners are coordinated on its
[issue tracker](https://github.com/opena2a-standards/atx-conformance/issues).
Substantive coordination on the ATX wire format itself happens in
[`opena2a-standards/atx-spec`](https://github.com/opena2a-standards/atx-spec).

## Repository layout

```
LICENSE                          Apache 2.0
README.md                        what the suite is and how to run it
CONTRIBUTING.md                  this file
COSIGNERS.md                     how a second party cosigns a verifier run, and the
                                 cosignature log
CHANGELOG.md                     changes to existing fixtures, by commit
MANIFEST.sha256                  per-fixture SHA-256 (path-sorted)
conformance.json                 requirement-to-fixture profile (generated from the
                                 fixtures, drift-checked in CI)
go.mod, go.sum                   the Go module the repository publishes,
                                 github.com/opena2a-standards/atx-conformance;
                                 cmd/atx-verify and verifiers/go are its main
                                 packages
fixtures.go                      the module's root package: fixtures/*.json as an
                                 embedded file system, the set the Go verifier
                                 walks when run with no argument
answerkey.go                     conformance.json and MANIFEST.sha256 embedded in
                                 the root package, for the interop kit
cmd/atx-verify/                  the Go verifier's published entry point,
                                 go run <module>/cmd/atx-verify@latest; with
                                 --verifier or --verifier-url, the interop kit
cmd/atx-tour/                    the guided tour's command, run from a clone
interop/                         the interop kit: sends each fixture to an outside
                                 verifier and compares its verdicts with the answer
                                 key
examples/                        wrappers that put a verifier behind the interop
                                 kit's contract
tour/                            the guided tour's steps, pre-flight and runner
docs/                            scope, fixtures, gates, dependencies, network
                                 use, version pinning and stability (the pages
                                 the README links), and the full output of its
                                 Go run with a JSON sidecar saying how it was
                                 taken
fixtures/                        the 57 conformance fixtures (byte-stable JSON)
jcs-vectors/                     JCS(TBS) byte-agreement vectors and the Go, Python
                                 and TypeScript canonicalizers that must agree on them
schemas/*.schema.json            fixture-v1, conformance-profile-v1 and wall-v1 file
                                 formats
schemas/vendor/atx-spec/         vendored atx-spec credential schema and core.md
                                 (pinned ref)
vectors/                         test keypair vectors (TEST-ONLY)
verifiers/go/                    Go reference verifier (full hybrid): the package
                                 verifiers/go/verifier, with its benchmark
                                 (verify_bench_test.go), and a main package that
                                 runs it from a checkout
verifiers/python/                Python reference verifier (full hybrid) and its
                                 benchmark (bench_verify.py)
wall/                            the verifier wall: verifiers.json, which lists the
                                 verifiers whose maintainers ran the interop kit at
                                 a released version and passed (wall-v1 format),
                                 and README.md, what a row holds and how to add
                                 and check one
scripts/generate-fixtures/       deterministic fixture generator (Go)
scripts/parity/                  Go/Python per-fixture parity gate
scripts/*.py                     CI gates: README counts, spec references, schema
                                 validation, conformance profile, implementation
                                 status
scripts/check_fixture_immutability.py
                                 each fixture's atx, verifierState and expected
                                 members against the merge base with origin/main
                                 (run by hand)
scripts/check_sibling_rows.py    sibling-repositories table against the sibling
                                 repositories (network, run by hand)
scripts/capture_go_verifier.py   runs the README's Go command from the tree and
                                 rewrites its capture and sidecar under docs/captures/;
                                 --check holds them to the README excerpt and
                                 the sidecar's input tree ids to the working
                                 tree (run by hand)
scripts/bench_report.py          runs the benchmark of each reference verifier and
                                 prints each figure with the commit and the CPU
                                 it ran on (run by hand)
scripts/check_wall.py            each row of wall/verifiers.json against the wall-v1
                                 format, the pass rule and the repository's tags
                                 (run by hand from the repository root as
                                 python3 -I scripts/check_wall.py; --file names
                                 another wall file, --repo another repository)
scripts/check_circl_pin.sh       CI gate: one cloudflare/circl version per Go module
scripts/test_script_options.py   CI gate: every script's -h, --help and unknown-argument
                                 handling
scripts/test_bench_report.py     CI gate: bench_report.py's figure lines and exit
                                 status, and both benchmarks timing the same
                                 fixtures
scripts/test_demo_recording.py   CI gate: adds docs/demo/test_record_atx_verify.py to the
                                 workflow's unittest discovery run over scripts/
scripts/test_check_sibling_rows.py
                                 CI gate: check_sibling_rows.py's self-test, and its
                                 fixture count over a tree with a file in a
                                 subdirectory of fixtures/ (no network)
scripts/test_check_step7_coverage.py
                                 CI gate: the file check_step7_coverage.py's
                                 docstring names as saying "the two drop it
                                 together" holds that sentence
scripts/test_check_wall.py       CI gate: check_wall.py's cases, each on a git
                                 repository built in a temporary directory; the
                                 wall-v1 schema against the members and forms
                                 the check holds; wall/verifiers.json against
                                 that schema
```
