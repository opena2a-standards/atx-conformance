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
- Linux on arm64, by `test_kit.py --offline` (below), which runs each
  such command in a new network namespace made by `unshare --user --net`:
  in a Debian 13 container with util-linux 2.41.5, Go 1.26.11 and
  Python 3.12.15, run as a user without root and started with
  `--security-opt seccomp=unconfined`. `atx-verify` built for linux/arm64,
  over its embedded fixtures and over `fixtures/`; the kit's `./verify`
  launcher; `verifiers/go` built with `go build`; and the Python verifier,
  installed from the locked wheels, then run over `fixtures/`. Each run
  passed every fixture and exited 0.
- Windows: not measured with the network denied. The runs above were made
  on one Mac, the Linux ones in containers on it.

On macOS and on Linux, `python3 scripts/kit/test/test_kit.py --offline`
makes such a measurement on the commit you have checked out. On macOS it
denies the network with `sandbox-exec` and `(deny network*)`. On Linux it
runs each command it denies the network to in a new user and network
namespace, with `unshare --user --net` from util-linux. In a container
started with Docker's default seccomp profile, `unshare` is refused: the
first cell fails, naming the refusal, and no other cell runs. Before any
run, the check makes sure a listener on 127.0.0.1 is reachable outside the
denial and refused inside it, and that inside it a UDP socket cannot be
connected to 192.0.2.1 or to 2001:db8::1. Connecting a UDP socket sends no
datagram. From a copy of the commit, it then builds `atx-verify` and the Go
verifier with `go build`, and installs the Python verifier from the wheels
`requirements.lock` pins, with the options of the kit's `PYTHON.md` install
command. These builds run with the network allowed: `go build` fetches the
modules the module cache lacks, and `pip download` fetches the wheels for
the Python running the check. It runs `atx-verify` over its embedded
fixtures and over `fixtures/`, the kit's `./verify` launcher, the Go
verifier and the Python verifier with the network denied and outside the
denial, with the same arguments, folder and environment. A run passes when,
with the network denied, it exits 0 and its last line is
`summary: N pass, 0 fail (N fixtures)`, N being the number of fixtures, and
its standard output is the same as with the network allowed. The same
checks must refuse three stand-in verifiers: one that exits 1 when it
cannot connect to 127.0.0.1, one that prints one more line when it can, and
one that prints a summary with a failure. It prints one line for the
control, one for the builds and one for each run, then how many of them
passed, and exits 1 when any of them fails. The copy is made with git:
with git not on PATH, it exits 2 before any check runs and names the
reason, and `--kit <folder>`, below, needs neither git nor Go.

With `--log <folder>`, a folder that is new or empty, the check keeps the
record of the run there. `offline.log` names the commit it copied, the time
the run started and the system it ran on, and holds the line of each cell,
the command of each run and how many cells passed; the control's line says
how the connection to 127.0.0.1 was refused inside the denial. For each
run, the folder keeps the standard output and the standard error with the
network denied and with it allowed: `o2.denied.stdout`,
`o2.denied.stderr`, `o2.allowed.stdout`, `o2.allowed.stderr`, and so on.
In the folder, `shasum -a 256 o2.denied.stdout` (Linux:
`sha256sum o2.denied.stdout`) prints the sha256 whose first 16 digits the
o2 line records, and `cmp o2.denied.stdout o2.allowed.stdout` compares the
two runs. The check then reads the folder back, and must refuse four
altered copies of it: one without the control's line, one with a run's
output one line longer, one without a run's output with the network
allowed, and one naming another commit.

With `--commit <commit>`, a tag, a branch or a sha of this repository, the
check measures that commit with the checks of the commit you have checked
out: it copies that commit, builds its verifiers and runs them over its own
fixtures. `offline.log` names the commit it copied, and the commit
`test_kit.py` came from. `--commit` without `--offline`, with no commit
after it, or naming no commit of this repository exits 2 before any check
runs. On 2026-11-20 (UTC),
`test_kit.py --offline --commit kit-2026-11-14 --log <folder>` measured
a38e000, the commit the kit release `kit-2026-11-14` carries, on macOS
26.6.2 on arm64 and on Linux on arm64 in the Debian 13 container above.
On each, it passed 15 of 15 cells, and each of the five runs passed all 47
fixtures with the network denied and exited 0; their standard output was
the same on both systems.

With `--kit <folder>`, the folder of an unpacked interop day kit, the check
measures the kit's own files instead of a copy of a commit, and needs
neither git nor Go. Inside the denial, it installs the Python verifier from
the kit's wheels into a new environment outside the kit, with the options
of the kit's `PYTHON.md` install command. It then runs the kit's
`atx-verify` for the machine it runs on, over its embedded fixtures and
over `fixtures/`, the kit's `./verify` launcher and the Python verifier,
with the network denied and with it allowed, and checks each run as above.
With the network denied, `./verify` must also print the kit's
`captures/<os>-<arch>.txt` for that machine when the kit holds one: the
release workflow writes that file from what `./verify` prints on a runner
of that platform. The install's line, o1, gives the sha256 of the kit's
`atx-verify` that ran, to compare with the release's `SHA256SUMS`, and
`offline.log` names the commit the kit's `CONTACT.txt` names. Where git
names no commit for `test_kit.py`, `offline.log` names it by its sha256.
`--kit` without `--offline`, with no folder after it, with `--commit`, or
naming a folder that lacks a file these runs read exits 2 before any check
runs.

On 2026-11-20 (UTC), `test_kit.py --offline --kit <folder> --log <folder>`
measured the kit of the release `kit-2026-11-14`, downloaded from the
release, every file of it matching the release's `SHA256SUMS`: on macOS
26.6.2 on arm64, with Python 3.14.3; and with Python 3.12.16 in
`python:3.12-slim` containers, which hold neither git nor Go, with the kit
mounted read-only, on Linux on arm64 and on Linux on amd64. The containers
ran on the same Mac, the amd64 one by translation, not on an amd64
processor. On each, it passed 14 of 14 cells, and each of the four runs
passed all 47 fixtures with the network denied and exited 0. Their
standard output was the same on the three, `./verify` printed the kit's
capture for that machine, and the sha256 of each `atx-verify` that ran is
the one `SHA256SUMS` lists. After the runs, every file of the kit still
matched `SHA256SUMS`, and the kit held no new file.

On 2026-11-20 (UTC), the same command measured the same kit in a virtual
machine with no network adapter: VirtualBox 7.2.6 on a Mac with macOS
26.6.2 on arm64, the machine booted from a new copy of the Fedora Cloud
Base Generic 45-1.4 image for aarch64, whose SHA-256 is the one Fedora's
`CHECKSUM` file lists. In the machine, which ran Linux 7.2.11 on arm64 with
Python 3.15.0 and util-linux 2.42.4, `lo` was the only network interface
and `ip route` listed no route, for IPv4 or for IPv6. At its first boot,
the machine unpacked the kit and `test_kit.py` from a disk that held only
them and the release's `SHA256SUMS`, ran the check from a systemd service
as a user without root, and wrote the `--log` folder to another disk. The
control's line records that in the machine no UDP socket could be
connected to 192.0.2.1 or to 2001:db8::1 outside the denial either. In
each of two boots, each from a new copy of the image, the check passed 14
of 14 cells, and each of the four runs passed all 47 fixtures with the
network denied and exited 0. Their standard output was the same bytes as
the kit's captures for macOS and for Linux, the sha256 of the `atx-verify`
that ran is the one `SHA256SUMS` lists, and after the runs every file of
the kit still matched `SHA256SUMS`, and the kit held no new file.

In `atx-verify`, `--verifier-url <url>` is the option that uses the
network: the interop kit sends each fixture to the URL you give. With
`--verifier "<command>"` it runs your command, which may use the network
itself.
