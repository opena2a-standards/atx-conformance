# atx-conformance

Conformance fixtures and reference verifiers for the
[ATX v1.0 and v1.1 credential schema](https://github.com/opena2a-standards/atx-spec).

Each fixture is a byte-stable JSON file that bundles an Agent Trust Credential
with verifier configuration and an expected outcome (ACCEPT or REJECT). Two
SDK-independent reference verifiers (Go and Python) walk the fixture set and
report PASS or FAIL per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

License: Apache 2.0. All keypairs, seeds, and credential identifiers in this
repository are TEST-ONLY.

```bash
cd verifiers/go && go run . ../../fixtures
```
What `go run . ../../fixtures` prints ([full output](docs/captures/go-verifier.txt), trimmed):
```text
PASS  ../../fixtures/baseline-valid-hybrid.json
       expected: ACCEPT
       observed: ACCEPT
       signatures: 2/2 valid (ed25519=true mldsa65=true)
       trustLevel 4 asserted; distinct-authority count (step 7) not performed by this verifier
...
PASS  ../../fixtures/wrong-issuer.json
       expected: REJECT [UNTRUSTED_ISSUER]
       observed: REJECT[UNTRUSTED_ISSUER: issuer DID did:opena2a:authority:attacker.example is not in the verifier's trusted set (untrusted issuer)]

summary: 25 pass, 0 fail (25 fixtures)
```

The command exits 1 when any fixture's result differs from its expected
outcome. On its first run, `go run` downloads the modules listed in
[`verifiers/go/go.mod`](verifiers/go/go.mod).

The suite does not check `contentHash` against an agent binary, transparency
log inclusion, build attestations or behavioral profiles;
[docs/scope.md](docs/scope.md) lists what it covers and the notes to read
before relying on a result.

## Running the verifiers

Both verifiers walk every `*.json` file in the directory you point them at
(or you may pass individual fixture files).

The Python verifier, from the repository root:

```bash
cd verifiers/python
pip install -r requirements.txt
python verify.py ../../fixtures
```

`pip install` downloads the packages `requirements.txt` names, and their
dependencies, into the active Python environment.

Each verifier needs a minimum toolchain release,
and the release can change a result on inputs no fixture carries:
[docs/running-the-verifiers.md](docs/running-the-verifiers.md) lists the
minimums, the modules and packages each verifier pins, and those inputs.

### Expected output

Both verifiers report `summary: 25 pass, 0 fail (25 fixtures)` against the
shipped fixture set.

A verifier prints a FAIL line when its result on a
fixture differs from the fixture's expected outcome, which is how drift in
verifier semantics (the verifier no longer follows the spec) shows up.

The verifiers check verdicts, not bytes. An edit that leaves the verdict
unchanged still reports PASS: a change to an unsigned v1.0 field, to a v1.1
field outside the signed `JCS(TBS)` payload, or to a fixture's
`description`.

The byte check is `MANIFEST.sha256`. Run it from the
repository root:

```bash
shasum -a 256 -c MANIFEST.sha256
```

Each line reads `OK` when that fixture's bytes match the published set. A
modified fixture reads `FAILED` and the command exits non-zero. On Linux,
`sha256sum -c MANIFEST.sha256` does the same.

## Implementations that validate against this suite

| Implementation | Verifier | Status |
|---|---|---|
| `opena2a-standards/atx-conformance/verifiers/go` (this repo) | Go, full Ed25519 plus ML-DSA-65, v1.0 + v1.1 | 25 / 25 PASS |
| `opena2a-standards/atx-conformance/verifiers/python` (this repo) | Python, full Ed25519 plus ML-DSA-65, v1.0 + v1.1 | 25 / 25 PASS |

To list an independent second-party implementation here, or to arrange a
cosignature, open an issue on this repository's
[issue tracker](https://github.com/opena2a-standards/atx-conformance/issues).
The cosignature itself is recorded by pull request, as
[`COSIGNERS.md`](./COSIGNERS.md#how-to-cosign) describes.

## Documentation

- [Scope](docs/scope.md): what the suite verifies, what it does not, and
  notes on canonicalization, hybrid signing, issuer DIDs and trust scoring.
- [Fixtures](docs/fixtures.md): the issuer, agent, verifier clock and keys
  every fixture shares, and what each fixture exercises.
- [Running the verifiers](docs/running-the-verifiers.md): the exit code,
  toolchain minimums, pinned modules and packages, and results that depend on
  the toolchain release.
- [Continuous verification](docs/continuous-verification.md): the gates CI
  runs on every pull request.
- [Reproducing the fixtures](docs/reproducing-the-fixtures.md): what the
  generator does when you run `cd scripts/generate-fixtures && go run .`.
- [Version pinning](docs/version-pinning.md): the spec, DID method, key and
  library versions the suite is pinned to.
- [Versioning and stability](docs/versioning.md): what may change in a
  fixture and what ships under a new name.
- [Sibling repositories](docs/sibling-repositories.md): the
  [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance)
  and [`aip-conformance`](https://github.com/opena2a-standards/aip-conformance)
  suites for the other OpenA2A specs.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): where to raise a change, and the
  repository layout, which describes [`conformance.json`](conformance.json),
  [`COSIGNERS.md`](COSIGNERS.md) and [`CHANGELOG.md`](CHANGELOG.md).

## License

Apache 2.0, see [`LICENSE`](./LICENSE).
