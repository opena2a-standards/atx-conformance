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
they stand. `-h` or `--help` prints the usage and exits 0, and nothing else
runs. Any other argument that starts with `-`, `-` alone and `--version`
aside, is an unknown option, named on stderr above the usage, with exit 2;
`--version` prints one version line and exits 0. Then an empty argument is a
usage error, `error: an empty argument names no fixture file or directory`
with exit 2, and nothing is verified. A directory is walked for
`fixtures/*.json` when its `fixtures` entry is a directory, so a repository
root can be passed, and for its own `*.json` otherwise, as when `fixtures` is
a file. A path named twice is verified twice. A file is named in the report
as its argument spells it, `./` and `//` included: for
`../../fixtures/./baseline-valid.json` both verifiers print
`PASS  ../../fixtures/./baseline-valid.json`. A file found by walking a
directory is named by the directory and file name joined as Go's
`filepath.Join` joins them: a `.` element and a repeated `/` are dropped,
and each `..` is removed with the element before it. A file named with a
trailing `/` is refused, `error: stat <path>: not a directory` with exit 2.
The parity gate runs both verifiers on each of these shapes
([continuous verification](continuous-verification.md)).

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
pip install -r requirements.txt
python verify.py ../../fixtures
```

Depends on:

- Python 3.11 or later. As with the Go release, the Python release sets the
  Unicode version of the case folding the duplicate-member check applies to a
  non-ASCII member name: U+1C89 and U+1C8A are a duplicate under Python 3.14
  (Unicode 16.0) and not under Python 3.12 (Unicode 15.0), which CI uses.
  `python verify.py --help` prints the usage lines, and `--version` the
  commit of the checkout the verifier runs from. The Go verifier's
  `--version` prints the module version `go run` built it from.
- `cryptography >= 42.0.0`
- `dilithium-py >= 1.1.0` (ML-DSA-65 per FIPS 204)
