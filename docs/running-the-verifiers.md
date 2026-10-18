# atx-conformance: running the verifiers

What each reference verifier depends on, and where the toolchain release
changes a result. The [README](../README.md#running-the-verifiers) runs both
verifiers and says what they print.

## Exit code

Exit code is 0 if every fixture's observed result matches the expected
result and the rejection category matches (when declared). A file that is
not a fixture, one with no `expected.verifyResult` of `ACCEPT` or `REJECT`,
is a load error: both verifiers print `FAIL  <file>  (load error: <reason>)`
for it, count it as a fail and exit 1.

## Arguments

Both verifiers read their arguments the same way, options first, wherever
they stand before the first `--`. `-h` or `--help` prints the usage and
exits 0, and nothing else runs. Any other argument that starts with `-`, `-`
alone and `--version` aside, is an unknown option, named on stderr above the
usage, with exit 2; `--version` prints one version line and exits 0. The
first `--` ends the options: each argument after it is a path, one that
starts with `-` included, so `-- -h.json` names a fixture file `-h.json`.
Then an empty argument is a usage error,
`error: an empty argument names no fixture file or directory` with exit 2,
and nothing is verified. A directory is walked for `fixtures/*.json` when its
`fixtures` entry is a directory, so a repository root can be passed, and for
its own `*.json` otherwise, as when `fixtures` is a file. A path named twice
is verified twice. A file is named in the report as its argument spells it,
`./` and `//` included: for `../../fixtures/./baseline-valid.json` both
verifiers print `PASS  ../../fixtures/./baseline-valid.json`. A file found by
walking a directory is named by the directory and file name joined as Go's
`filepath.Join` joins them: a `.` element and a repeated `/` are dropped,
and each `..` is removed with the element before it. When the directory,
cleaned that way, names another directory than its argument does, as it can
when a `..` follows a symbolic link, which the operating system resolves
before it applies the `..`, the file is named and read as the argument
spells the directory, then the file name, with a `/` between the two unless
the directory as spelled ends in `/`: with `d/link` a link to
`elsewhere/deep` and `elsewhere/other.json` a copy of
`fixtures/expired.json`, both verifiers verify that copy for `d/link/..`
and for `d/link/../`, and print `PASS  d/link/../other.json` for each. A
file named with a trailing `/` is refused,
`error: stat <path>: not a directory` with exit 2.
A fixture named by an absolute path under the working directory is reported
relative to it instead, the two compared with their symbolic links
resolved, each `..` applied after the element before it is resolved, as the
operating system applies it, so it gets the same name whether the path runs
through a link to the working directory or through the link's target; one
outside the working directory is reported by its whole path.

With no path argument, `--` alone included, the two differ: the Go verifier
verifies the fixture set built into it and the Python verifier, which has no
embedded set, prints its usage and exits 2. Their usage lines say so,
`atx-verify [fixture.json|dir]...` and `verify.py <fixture.json|dir>...`.
The parity gate runs both verifiers on each of these shapes, no argument
included, which it holds to this difference
([continuous verification](continuous-verification.md)).

## Which commit a run verified

`--version` prints one line naming what the verifier was built from. The Go
verifier's line names the module version its binary records:

- Run through the module proxy, as
  `go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@<version> --version`,
  it names the version `go run` resolved, a pseudo-version naming the commit
  while the repository has no tags: at `20799e3`,
  `v0.0.0-20261018142916-20799e3db50c`.
- Built from a git clone, it names the commit's pseudo-version under Go 1.24
  and later (measured with 1.24.0 and 1.26.3) and `(devel)` under Go 1.22 and
  1.23 (measured with 1.22.12 and 1.23.0). A build in a linked
  `git worktree` named `(devel)` under 1.26.3.
- Built from a source archive, a `git archive` copy with no `.git`, it names
  `(devel)` (measured with 1.22.12 and 1.26.3): the archive holds no commit.

The Python verifier's line names the commit git reports for the checkout it
runs from, and `no commit recorded (not run from a git checkout)` when it
runs from a source archive. To trace a result to its commit, run the Go
verifier through the module proxy at that version, or either verifier from a
git clone, the Go verifier built with Go 1.24 or later.

## Dependencies

### Go (full hybrid Ed25519 plus ML-DSA-65)

```bash
go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest
```

With no argument the verifier walks the fixture set built into the module
version `go run` fetched, `fixtures/*.json` of that commit; name fixture
files or a directory to walk those instead. `go.mod` at the repository root
declares the module, `github.com/opena2a-standards/atx-conformance`. The
verifier is the package `verifiers/go/verifier`; `cmd/atx-verify` and
`verifiers/go` are main packages that run it, so from a checkout:

```bash
cd verifiers/go
go run . ../../fixtures
```

Depends on:

- Go 1.22 or later. The release can change a fixture's result when one of its
  timestamps has a time zone offset with an hour above 24 or a minute above 60
  (`+25:00`, `+23:61`); no fixture carries one. Go 1.22, which CI builds this
  verifier with and which the Python verifier follows, decodes such a
  timestamp. Go 1.23 and later reject it where the verifier decodes it: in a
  CRL's `issuedAt` or `nextUpdate` or a CRL entry's `revokedAt` the fixture
  fails to load, in the credential's `issuedAt` or `expiresAt` the rejection
  is a `PARSE_ERROR`, in the verifier clock `clockRfc3339` it is a
  `VERIFIER_CONFIG_ERROR`, and in a v1.1 credential's
  `behavioralProfile.generatedAt` the signed payload carries
  `behavioralProfile` as null, so a signature made over the profile fails as
  `SIGNATURE_INVALID`. To build with the release CI uses, run
  `GOTOOLCHAIN=go1.22.12 go run . ../../fixtures`.

  A timestamp written with a JSON escape (the `Z` written as a `\u` escape,
  for example) fails to decode under every release, as it does in the Python
  verifier: the verifier decodes each timestamp with `time.Time`'s own
  `UnmarshalJSON`, which parses the bytes between the quotes. A plain
  `time.Time` field decodes the escaped form when built with Go 1.27.

  The release also sets the Unicode version of the case folding the
  duplicate-member check applies to a non-ASCII member name. Two names whose
  lowercase mapping a later Unicode version added are a duplicate, and the
  credential a `PARSE_ERROR`, under one release and not under another: U+1C89
  and U+1C8A, mapped in Unicode 16.0, are a duplicate under Go 1.27 (Unicode
  17.0) and not under Go 1.22 through 1.26 (Unicode 15.0). No fixture carries
  a non-ASCII member name.
- `github.com/cloudflare/circl v1.6.2` (resolved by `go mod tidy`)
- `github.com/gowebpki/jcs v1.0.1` (RFC 8785 canonicalization of the v1.1
  signed payload; resolved the same way)

### Python (full hybrid Ed25519 plus ML-DSA-65)

```bash
cd verifiers/python
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 verify.py ../../fixtures
```

The commands expect a virtual environment, which the second and third lines
create in `verifiers/python/.venv` and activate; outside one a system may
provide `python3` and `pip3` only, with no `python` or `pip` on `PATH`.

Depends on:

- Python 3.11 or later. As with the Go release, the Python release sets the
  Unicode version of the case folding the duplicate-member check applies to a
  non-ASCII member name: U+1C89 and U+1C8A are a duplicate under Python 3.14
  (Unicode 16.0) and not under Python 3.12 (Unicode 15.0), which CI uses.
  `python3 verify.py --help` prints the usage lines, and `--version` the
  commit of the checkout the verifier runs from
  ([which commit a run verified](#which-commit-a-run-verified)).
- `cryptography >= 42.0.0`
- `dilithium-py >= 1.1.0` (ML-DSA-65 per FIPS 204)
