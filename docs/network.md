# atx-conformance: what needs the network

Running a reference verifier over fixtures makes no network request.
Building the Go verifier, and installing the Python verifier's packages,
fetch the modules and packages this page names. The interop day kit
carries both already fetched: a prebuilt Go binary for each platform, and
the Python packages as wheels. The
[README](../README.md#running-the-verifiers) runs both verifiers.

## Build time

### Go verifier

From a checkout, with an empty module cache, `go build ./cmd/atx-verify`
fetches three modules from the Go module proxy, the `.info`, `.mod` and
`.zip` file of each. `go.sum` holds their hashes, so it makes no checksum
database lookup:

- `github.com/cloudflare/circl v1.6.2` (ML-DSA-65)
- `github.com/gowebpki/jcs v1.0.1` (RFC 8785 canonicalization)
- `golang.org/x/sys v0.28.0` (required by circl)

Once the module cache holds them, `go run ./verifiers/go fixtures` builds
and runs with the network denied.

`go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest`
needs nothing cloned, and needs the network each time it runs: it asks the
proxy which version `@latest` names, fetches that version of the
atx-conformance module and the same three modules, and looks up each of
the four in the Go checksum database. With the module cache filled by such
a run and the network denied, the same command fails. `go install
github.com/opena2a-standards/atx-conformance/cmd/atx-verify@<commit>`
fetches the same modules and makes the same four lookups, and the binary
it installs runs with the network denied.

Go's defaults name proxy.golang.org as the module proxy and sum.golang.org
as the checksum database; `GOPROXY` and `GOSUMDB` set others. Measured with
Go 1.26.3.

### Python verifier

From `verifiers/python`, `python3 -m pip install -r requirements.txt`
downloads from PyPI the newest `cryptography` and `dilithium-py` releases
its lower bounds admit, and their dependencies `cffi` and `pycparser`. On
2026-11-19, pip 26.0 on Python 3.14 resolved cryptography 50.0.2,
dilithium-py 1.5.1, cffi 2.1.1 and pycparser 3.12.

`verifiers/python/requirements.lock` pins the releases the kit ships, each
by version and by the SHA-256 of every wheel:

- `cffi 2.1.1`
- `cryptography 46.0.3`
- `dilithium-py 1.5.1`
- `pycparser 3.12`

### The interop day kit

Assembling the kit fetches the Go modules above to build its binaries, and
downloads the locked wheels into `verifiers/python/wheels`. In the kit,
`./verify` and `verify.cmd` run a prebuilt binary, and `PYTHON.md` installs
the wheels from the kit's folder with `pip install --no-index`.

## Run time

The reference verifiers read fixture files and print a result for each.
The source files of the Go verifier (`verifiers/go` and its package
`verifiers/go/verifier`) and of the Python verifier (`verifiers/python`,
apart from its tests) import no network package.
`python3 scripts/kit/test/test_kit.py --ci` checks that, and that this page
names each module `go.mod` requires and each package `requirements.lock`
pins, at its version.

Measured on 2026-11-19 with the network denied, each set of runs beside a
control in which a host reachable outside the denial was not reachable
inside it:

- macOS 26.6.2 on arm64, under `sandbox-exec` with `(deny network*)`:
  `atx-verify` built from a checkout, over its embedded fixtures and over
  `fixtures/`; the `atx-verify` that `go install` put in place;
  `go run ./verifiers/go fixtures` with the module cache filled; and the
  Python verifier, installed from the locked wheels with the commands in
  the kit's `PYTHON.md`, then run over `fixtures/`. Each run passed every
  fixture and exited 0.
- Linux on arm64, in containers started with `docker run --network none`:
  `atx-verify` built for linux/arm64, over its embedded fixtures and over
  `fixtures/`; and the Python verifier, installed from the locked wheels
  under Python 3.12, then run over `fixtures/`. Each run passed every
  fixture and exited 0.
- Windows: not measured with the network denied. The runs above were made
  on one Mac, the Linux ones in containers on it.

On macOS, `python3 scripts/kit/test/test_kit.py --offline` makes such a
measurement on the commit you have checked out. It first checks that a
listener on 127.0.0.1 is reachable outside `sandbox-exec` and refused
inside it. From a copy of the commit, it then builds `atx-verify` and the
Go verifier with `go build`, and installs the Python verifier from the
wheels `requirements.lock` pins, with the options of the kit's `PYTHON.md`
install command. These builds run with the network allowed: `go build`
fetches the modules the module cache lacks, and `pip download` fetches
the wheels for the Python running the check. It runs `atx-verify` over
its embedded fixtures and over `fixtures/`, the kit's `./verify`
launcher, the Go verifier and the Python verifier inside `sandbox-exec`
with `(deny network*)` and outside it, with the same arguments, folder
and environment. A run passes when, with the network denied, it exits 0 and
its last line is `summary: N pass, 0 fail (N fixtures)`, N being the
number of fixtures, and its standard output is the same as with the
network allowed. The same checks must refuse three stand-in verifiers:
one that exits 1 when it cannot connect to 127.0.0.1, one that prints one
more line when it can, and one that prints a summary with a failure. It
prints one line for the control, one for the builds and one for each run,
then how many of them passed, and exits 1 when any of them fails.

In `atx-verify`, `--verifier-url <url>` is the option that uses the
network: the interop kit sends each fixture to the URL you give. With
`--verifier "<command>"` it runs your command, which may use the network
itself.
