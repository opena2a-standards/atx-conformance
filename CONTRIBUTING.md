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
cmd/atx-verify/                  the Go verifier's published entry point,
                                 go run <module>/cmd/atx-verify@latest
docs/                            scope, fixtures, gates, dependencies, version
                                 pinning and stability (the pages the README
                                 links), and the full output of its Go run with
                                 a JSON sidecar saying how it was taken
fixtures/                        the 27 conformance fixtures (byte-stable JSON)
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
scripts/test_script_options.py   every script's -h, --help and unknown-argument
                                 handling (run by hand)
```
