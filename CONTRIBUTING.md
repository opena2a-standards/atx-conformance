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
docs/                            scope, fixtures, gates, dependencies, version
                                 pinning and stability (the pages the README
                                 links), and the full output of its Go run with
                                 a JSON sidecar saying how it was taken
fixtures/                        the 47 conformance fixtures (byte-stable JSON)
jcs-vectors/                     JCS(TBS) byte-agreement vectors and the Go, Python
                                 and TypeScript canonicalizers that must agree on them
schemas/*.schema.json            fixture-v1 and conformance-profile-v1 file formats
schemas/vendor/atx-spec/         vendored atx-spec credential schema and core.md
                                 (pinned ref)
vectors/                         test keypair vectors (TEST-ONLY)
verifiers/go/                    Go reference verifier (full hybrid): the package
                                 verifiers/go/verifier and a main package that
                                 runs it from a checkout
verifiers/python/                Python reference verifier (full hybrid)
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
scripts/check_circl_pin.sh       CI gate: one cloudflare/circl version per Go module
scripts/test_script_options.py   CI gate: every script's -h, --help and unknown-argument
                                 handling
scripts/test_demo_recording.py   CI gate: adds docs/demo/test_record_atx_verify.py to the
                                 workflow's unittest discovery run over scripts/
scripts/test_check_sibling_rows.py
                                 CI gate: check_sibling_rows.py's self-test, and its
                                 fixture count over a tree with a file in a
                                 subdirectory of fixtures/ (no network)
```
