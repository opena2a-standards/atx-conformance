# atx-conformance

Conformance fixtures and reference verifiers for the
[ATX v1.0 and v1.1 credential schema](https://github.com/opena2a-standards/atx-spec).

Each fixture is a byte-stable JSON file that bundles an ATX
with verifier configuration and an expected outcome (ACCEPT or REJECT). Two
SDK-independent reference verifiers (Go and Python) walk the fixture set and
report PASS or FAIL per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

License: Apache 2.0. All keypairs, seeds, and credential identifiers in this
repository are TEST-ONLY.

The command below needs Go 1.22 or later ([go.dev/dl](https://go.dev/dl/));
the Python verifier needs Python 3.11 or later
([python.org/downloads](https://www.python.org/downloads/)).

```bash
go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest
```
What `go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest` prints ([full output](docs/captures/go-verifier.txt), trimmed):
```text
PASS  fixtures/baseline-valid-hybrid.json
       expected: ACCEPT
       observed: ACCEPT
       signatures: 2/2 valid (ed25519=true mldsa65=true)
       trustLevel 4 asserted; distinct-authority count (step 7) not performed by this verifier
...
PASS  fixtures/wrong-issuer.json
       expected: REJECT [UNTRUSTED_ISSUER]
       observed: REJECT[UNTRUSTED_ISSUER: issuer DID did:opena2a:authority:attacker.example is not in the verifier's trusted set (untrusted issuer)]

summary: 41 pass, 0 fail (41 fixtures)
```

With no argument the verifier walks the fixture set built into the module
version `go run` fetched, `fixtures/*.json` of that commit, with nothing
cloned. The command exits 1 when any fixture's result differs from its
expected outcome. On its first run, `go run` downloads the module and the
modules listed in [`go.mod`](go.mod).

This repository has no release tag, so `@latest` resolves to a
pseudo-version (a version Go builds from a commit's time and hash) of the
commit on `main` that the Go module proxy reports as latest.
[Which version `go run` fetches](docs/running-the-verifiers.md#which-version-go-run-fetches)
says how to run the verifier and fixtures of one commit instead.

The suite does not check `contentHash` against an agent binary, transparency
log inclusion, build attestations or the content of behavioral profiles;
[docs/scope.md](docs/scope.md) lists what it covers and the notes to read
before relying on a result.

## Try your verifier in two minutes

The kit sends each of the 41 fixtures to your verifier and compares its
verdicts with the answer key in [`conformance.json`](conformance.json). Your
verifier stays yours. The kit uploads nothing: the fixtures go to your
verifier only, and the report stays on your laptop unless you share it.

The fixtures are native ATX credentials. A verifier that reads JWT or W3C
credentials cannot parse them; when it answers as in the "Couldn't read"
column below, the kit records that as a result, not as a REJECT.
`--form jws` and `--form vc` are reserved for JWS and VC forms.

With Go 1.22 or later and a network connection, a verifier you run as a
command, then one you run as a service (yours goes in the angle brackets):

```bash
go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@COMMIT --verifier "<your command> {file}" --label "<name and version>"
```

```bash
go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@COMMIT --verifier-url "<your URL>" --label "<name and version>"
```

`{file}` becomes each fixture's path; the file holds the credential in `atx`
and the settings to judge it by in `verifierState`. Without `{file}`, and
through a URL (a JSON POST), your verifier gets the credential alone and
judges it by its own settings.

| Adapter | ACCEPT | REJECT | Couldn't read |
|---|---|---|---|
| Command | exit 0 | exit 1 | any other exit, a crash, or a timeout |
| URL | 2xx | 4xx | 5xx, no answer, or a timeout |
| Either, if it prints JSON | "verdict": "ACCEPT" or "valid": true | "verdict": "REJECT" or "valid": false | "verdict": "ERROR" |

JSON wins over exit and status codes. An optional "reason" string is
recorded, and the first 200 characters of each raw response are kept in the
report, so a person can judge.

The kit prints four numbers: agree, accepted what must fail, rejected what
must pass, and couldn't read. It exits 0 only when all 41 agree.
`--report <dir>` writes `atx-interop-report.md` and `atx-interop-report.json`.
To share a result, open an issue on this repository titled
`<verifier> fails <fixture>.json at <suite commit>`, or email info@opena2a.org.

Wrappers for any verifier are in [`examples/`](examples/). The guided tour
runs from a clone: `go run ./cmd/atx-tour --setup` once with the network on,
then `go run ./cmd/atx-tour --check` and `go run ./cmd/atx-tour`.

## Running the verifiers

Both verifiers walk every `*.json` file in the directory you point them at
(or you may pass individual fixture files). The Go verifier over fixture
files of your own:

```bash
go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest path/to/fixtures
```

From a checkout of this repository, at its root, the Go verifier of that
checkout over its fixtures:

```bash
go run ./verifiers/go fixtures
```

The Python verifier, from the repository root:

```bash
cd verifiers/python
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --disable-pip-version-check -r requirements.txt
python3 verify.py ../../fixtures
```

The commands expect a virtual environment: the second and third lines
create one in `verifiers/python/.venv` and activate it, and
`python3 -m pip install` downloads the packages `requirements.txt` names,
and their dependencies, into it. `--disable-pip-version-check` stops pip
from looking up whether a newer release of pip exists; without it, pip
writes a notice to standard error suggesting an upgrade of pip when there is
one. Outside a virtual environment a system may provide `python3` and
`pip3` only, with no `python` or `pip` on `PATH`.

Each verifier needs a minimum toolchain release,
and the release can change a result on inputs no fixture carries:
[docs/running-the-verifiers.md](docs/running-the-verifiers.md) lists the
minimums, the modules and packages each verifier pins, and those inputs.

### Expected output

Both verifiers report `summary: 41 pass, 0 fail (41 fixtures)` against the
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
| `opena2a-standards/atx-conformance/verifiers/go` (this repo) | Go, full Ed25519 plus ML-DSA-65, v1.0 + v1.1 | 41 / 41 PASS |
| `opena2a-standards/atx-conformance/verifiers/python` (this repo) | Python, full Ed25519 plus ML-DSA-65, v1.0 + v1.1 | 41 / 41 PASS |

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
  the module version `go run` fetches, toolchain minimums, pinned modules and
  packages, and results that depend on the toolchain release.
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
