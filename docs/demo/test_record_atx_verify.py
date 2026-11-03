#!/usr/bin/env python3
"""Tests of record-atx-verify.sh: the images it reads from the Dockerfile, the --pids-limit it
gives its render container, and where its render writes.

DockerfileImages: the script refuses a Dockerfile that references an image it does not read. It
reads the images of two FROM lines of docs/demo/docker/Dockerfile, the build stage
(`AS vhsbuild`) and the render stage, and the sidecar's `recorder` records them as
`builderImage` and `baseImage`. Before the change these cases came with, it read no other line:
`--dry-run` exited 0 on a Dockerfile with a third FROM line, upper or lower case, or with a
`COPY --from` or a `RUN --mount` that names an image.

Each of these cases writes one Dockerfile into a scratch copy of docs/demo and runs the scratch
copy of the script, with and without `--dry-run`, with DOCKER set to DOCKER_STUB, a stub that logs
its arguments and exits 1. On a Dockerfile it refuses, the script must exit 1 with one line on
standard error, which names the Dockerfile line it refuses except for a NUL byte and a base image
named by tag alone, and must run no docker command.

PidsLimit: the pids cgroup counts threads as well as processes, and the render's peak grows with
the CPU count: read from the render container's pids.peak on Docker Desktop (linux/arm64), it was
254 tasks with 16 CPUs, and 211 with the render held to 8 of them by --cpuset-cpus 0-7. Before the
change these cases came with, the script set --pids-limit 256 whatever the CPU count.

Each of these cases copies the script, the tape and docs/demo/docker into a scratch git checkout
and runs the script there with DOCKER naming RENDER_DOCKER_STUB, a stub that prints a CPU count
for `docker info`, records the arguments of `docker create` and exits 7 in its place, so no image
is built, no container starts and this checkout is not written to. The check the script's
in-container program makes of the limits it is told is read out of the script and run on its own,
as the rest of that program needs the container.

RenderOutput: the render container runs as root with --cap-drop ALL. Root then has no
CAP_DAC_OVERRIDE and gets the ordinary owner, group and other checks, and a rootful Linux Docker
Engine without user-namespace remapping keeps a bind mount's host owner and mode. Before the
change these cases came with, the script mounted a directory made by `mktemp -d` (owned by the
caller, mode 0700) at /work/docs/demo for the render's output, so the render's first write,
os.makedirs('docs/demo/out'), was refused and the render failed (#312). The defect needs a caller
other than root: a caller that is root owns the directory, and the container's root writes into
it as its owner.

Each of these cases copies the script and the files it reads into a new git checkout, its
directories with mode 0755 and its files with mode 0644, the modes of a checkout made with umask
022, which let a user other than their owner read them. It runs the script there with DOCKER
naming a stand-in for docker: this file, run as `fake-docker`. The stand-in runs no image. It
keeps each container's flags and a model of its file system, in which the image's own directories
are owned by root (/ and /work with mode 0755, /tmp with mode 1777, as the render image has them)
and a bind mount is the host directory with its host owner and mode. In place of the render it
reads the tape and the narration, makes docs/demo/out, the home directory and the directory the
tape's hidden set-up enters, and writes the files the tape names, the capture and the sidecar, in
that order. It refuses each of those calls as the kernel refuses it for the container's user and
capabilities, printing a line in the form Python prints, and then exits 1 as the render does. It
answers info, build, image inspect, context inspect, run, create, start, cp and rm, and exits 125
on a call or an option it does not model.

Needs bash and git; no docker, network or image is used.

    python3 docs/demo/test_record_atx_verify.py
"""

import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "record-atx-verify.sh"
TAPE = HERE / "atx-verify.tape"
PATCH = HERE / "docker" / "vhs-0.12.0-render-context.patch"
COMMITTED = (HERE / "docker" / "Dockerfile").read_text(encoding="utf-8")
LINES = COMMITTED.split("\n")

DOCKER_STUB = """#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
exit 1
"""


def index_of(prefix):
    """The index in LINES of the committed Dockerfile's first line that starts with prefix."""
    for i, line in enumerate(LINES):
        if line.startswith(prefix):
            return i
    raise AssertionError(f"docs/demo/docker/Dockerfile has no line that starts with {prefix!r}")


BUILD_FROM = LINES[index_of("FROM golang:")]
RENDER_FROM = LINES[index_of("FROM ghcr.io/charmbracelet/vhs@sha256:")]
BUILDER_REF = BUILD_FROM.split()[1]
BASE_REF = RENDER_FROM.split()[1]
# A new stage goes in front of the render stage; a line of the render stage goes after its last
# COPY --from=vhsbuild.
BEFORE_RENDER = index_of("FROM ghcr.io/charmbracelet/vhs@sha256:")
IN_RENDER = index_of("COPY --from=vhsbuild /usr/local/go ") + 1


def inserted(at, *new):
    """The committed Dockerfile with lines put in at index `at`, and the line number of the first."""
    return "\n".join(LINES[:at] + list(new) + LINES[at:]), at + 1


def replaced(at, new):
    return "\n".join(LINES[:at] + [new] + LINES[at + 1:])


def appended(new):
    return COMMITTED + new + "\n", len(LINES)


COPY_FROM = "the script reads a --from of COPY only when it is vhsbuild, the build stage"
MOUNT_FROM = "the script reads a from= key of RUN --mount only when it is vhsbuild, the build stage"

# name: (Dockerfile, the line number the refusal names or None, a part of the refusal)
REFUSED = {
    "a new stage": (*inserted(BEFORE_RENDER, "FROM busybox:latest AS helper"),
                    "`FROM busybox:latest AS helper` is a FROM line the script does not read"),
    "a new stage in lower case": (*inserted(BEFORE_RENDER, "from busybox:latest AS helper"),
                                  "`from busybox:latest AS helper` is a FROM line the script does not read"),
    "a new stage in mixed case": (*inserted(BEFORE_RENDER, "From busybox:latest AS helper"),
                                  "`From busybox:latest AS helper` is a FROM line the script does not read"),
    "a new stage with --platform": (
        *inserted(BEFORE_RENDER, "FROM --platform=linux/amd64 busybox:latest AS helper"),
        "`FROM --platform=linux/amd64 busybox:latest AS helper` is a FROM line the script does not read"),
    "a new stage over two lines": (*inserted(BEFORE_RENDER, "FROM busybox:latest \\", "AS helper"),
                                   "`FROM busybox:latest AS helper` is a FROM line the script does not read"),
    "a new stage with no stage name, pinned by digest": (
        *appended(RENDER_FROM), "a second FROM line with no stage name"),
    "a second build stage": (*appended(BUILD_FROM), "a second FROM line of the build stage"),
    "COPY --from an image": (
        *inserted(IN_RENDER, "COPY --from=busybox:latest /bin/busybox /bin/busybox"),
        f"`COPY --from=busybox:latest`: {COPY_FROM}"),
    "COPY with a tab before its flag": (
        *inserted(IN_RENDER, "COPY\t--from=busybox:latest /bin/busybox /bin/busybox"),
        f"`COPY --from=busybox:latest`: {COPY_FROM}"),
    "COPY --from an image pinned by digest": (
        *inserted(IN_RENDER, f"COPY --from={BASE_REF} /usr/bin/vhs /tmp/vhs"),
        f"`COPY --from={BASE_REF}`: {COPY_FROM}"),
    "COPY --from the build stage by its index": (
        *inserted(IN_RENDER, "COPY --from=0 /vhs /tmp/vhs"), f"`COPY --from=0`: {COPY_FROM}"),
    "COPY --from on a continuation line": (
        *inserted(IN_RENDER, "COPY \\", "# a comment inside the instruction", "",
                  "  --from=busybox:latest /bin/busybox /bin/busybox"),
        f"`COPY --from=busybox:latest`: {COPY_FROM}"),
    "RUN --mount from an image": (
        *inserted(IN_RENDER, "RUN --mount=type=bind,from=busybox:latest,target=/bb true"),
        f"`RUN --mount=type=bind,from=busybox:latest,target=/bb`: {MOUNT_FROM}"),
    "RUN --mount with FROM= in upper case": (
        *inserted(IN_RENDER, "run --mount=type=cache,FROM=busybox:latest,target=/c true"),
        f"`run --mount=type=cache,FROM=busybox:latest,target=/c`: {MOUNT_FROM}"),
    "a flag written with quotes": (
        *inserted(IN_RENDER, 'COPY --"from"=busybox:latest /bin/busybox /bin/busybox'),
        "is written with a quote or a backslash, which the script does not read"),
    "a flag written with a backslash": (
        *inserted(IN_RENDER, "COPY --fr\\om=busybox:latest /bin/busybox /bin/busybox"),
        "is written with a quote or a backslash, which the script does not read"),
    "a heredoc": (*inserted(IN_RENDER, "RUN <<EOF", "true", "EOF"),
                  "RUN carries <<, the form of a heredoc, which the script does not read"),
    "ONBUILD": (*inserted(IN_RENDER, "ONBUILD COPY --from=busybox:latest /bin/busybox /bin/busybox"),
                "ONBUILD, which the script does not read"),
    "a word that is not an instruction": (*inserted(IN_RENDER, "IMPORT busybox:latest"),
                                          "IMPORT is not an instruction the script reads"),
    "a syntax parser directive": (*inserted(0, "# syntax=docker/dockerfile:1"),
                                  "in the form of a parser directive (# name=value)"),
    "a no-break space between two flags": (
        *inserted(IN_RENDER, "COPY --chown=0\xa0--from=busybox:latest /bin/busybox /bin/busybox"),
        "a character other than printable ASCII or a tab outside a comment"),
    "a NUL byte": (inserted(IN_RENDER, "COPY /a /b \\\x00",
                            "COPY --from=busybox:latest /bin/busybox /bin/busybox")[0],
                   None, "holds a NUL byte, which the script does not read"),
    "the render stage named by tag alone": (
        replaced(BEFORE_RENDER, "FROM ghcr.io/charmbracelet/vhs:v0.12.0"), None,
        "names ghcr.io/charmbracelet/vhs:v0.12.0 in a FROM line, not an image by the digest of its index"),
}

# name: Dockerfile; each is read, and passes the dry run.
READ = {
    "the committed Dockerfile": COMMITTED,
    "COPY --from=vhsbuild over three lines with a comment and a blank line between": inserted(
        IN_RENDER, "COPY \\", "# a comment inside the instruction", "",
        "  --from=vhsbuild /vhs /tmp/vhs")[0],
    "RUN --mount from the build stage": inserted(
        IN_RENDER, "RUN --mount=type=bind,from=vhsbuild,source=/vhs,target=/tmp/vhs true")[0],
}


class DockerfileImages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = pathlib.Path(tempfile.mkdtemp())
        demo = cls.root / "repo" / "docs" / "demo"
        (demo / "docker").mkdir(parents=True)
        shutil.copy2(SCRIPT, demo / SCRIPT.name)
        shutil.copy2(TAPE, demo / TAPE.name)
        shutil.copy2(PATCH, demo / "docker" / PATCH.name)
        cls.script = demo / SCRIPT.name
        cls.dockerfile = demo / "docker" / "Dockerfile"
        for name in ("home", "tmp"):
            (cls.root / name).mkdir()
        cls.stub = cls.root / "docker-stub"
        cls.stub.write_text(DOCKER_STUB)
        cls.stub.chmod(cls.stub.stat().st_mode | stat.S_IXUSR)
        # The script reads HEAD and the tags that point at it, so the scratch copy is a repository
        # with one empty commit.
        git_env = {"PATH": os.environ.get("PATH", ""), "HOME": str(cls.root / "home"),
                   "GIT_CONFIG_NOSYSTEM": "1"}
        repo = str(cls.root / "repo")
        subprocess.run(["git", "-c", "init.defaultBranch=main", "init", "-q", repo], check=True,
                       env=git_env, capture_output=True)
        subprocess.run(["git", "-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "scratch"],
                       check=True, env=git_env, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def run_script(self, dockerfile, *args):
        self.dockerfile.write_bytes(dockerfile.encode("utf-8"))
        log = self.root / "docker.log"
        log.write_text("")
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.root / "home"),
               "TMPDIR": str(self.root / "tmp"), "DOCKER": str(self.stub), "STUB_LOG": str(log)}
        for name in ("LANG", "LC_ALL", "LC_CTYPE"):
            if name in os.environ:
                env[name] = os.environ[name]
        proc = subprocess.run(["bash", str(self.script), *args], env=env, capture_output=True, timeout=60)
        return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
                proc.stderr.decode("utf-8", "replace"), log.read_text())

    def test_a_dockerfile_that_references_another_image_is_refused(self):
        for name, (dockerfile, line, says) in REFUSED.items():
            for args in (("--dry-run",), ()):
                with self.subTest(name, args=args):
                    code, out, err, docker = self.run_script(dockerfile, *args)
                    self.assertEqual((code, out, docker), (1, "", ""), err)
                    where = "docs/demo/docker/Dockerfile" + (f":{line}:" if line else "")
                    self.assertTrue(err.startswith(f"record-atx-verify.sh: {where}"), err)
                    self.assertIn(says, err)
                    self.assertEqual(err.count("\n"), 1, err)

    def test_a_dockerfile_it_reads_passes_the_dry_run(self):
        for name, dockerfile in READ.items():
            with self.subTest(name):
                code, out, err, docker = self.run_script(dockerfile, "--dry-run")
                self.assertEqual((code, err, docker), (0, "", ""), out)
                self.assertIn(f"\n  bases     {BUILDER_REF} {BASE_REF}\n", out)


# What the script reads on the host side before `docker create`, by its path under docs/demo.
INPUTS = ("record-atx-verify.sh", "atx-verify.tape", "docker/Dockerfile",
          "docker/vhs-0.12.0-render-context.patch")
# The render's peak task count, read from its container's pids.peak, by the CPUs it ran on.
MEASURED_PEAKS = {8: 211, 16: 254}
# The limit is held to at least this many times the measured peak, and to growing at least
# this many times as fast a CPU as the peak grew from 8 CPUs to 16.
HEADROOM = 2
# The exit code of RENDER_DOCKER_STUB's `docker create`.
CREATE_EXIT = 7

RENDER_DOCKER_STUB = r"""#!/bin/sh
# docker, as record-atx-verify.sh calls it. Each call's first argument goes to $STUB_LOG.
# `info` prints $STUB_CPUS and exits $STUB_INFO_EXIT; `create` writes its arguments to
# $STUB_CREATE_ARGS, one a line, and exits 7.
echo "$1" >> "$STUB_LOG"
case "$1" in
  info) printf '%s\n' "$STUB_CPUS"; exit "$STUB_INFO_EXIT" ;;
  build) exit 0 ;;
  image) echo stub; exit 0 ;;
  create) shift; printf '%s\n' "$@" > "$STUB_CREATE_ARGS"; exit 7 ;;
esac
echo "docker stub: unexpected call: $*" >&2
exit 64
"""


def container_unaccounted(run_flags):
    """The limits the in-container program finds neither run nor dropped with a reason, told RUN_FLAGS.

    Its LIMITS and DROPPED and the lines of its check are read out of the script and run here.
    """
    script = SCRIPT.read_text(encoding="utf-8")
    program = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    lines = (program[program.index("LIMITS = ("):program.index("PACE = {")]
             + program[program.index("ran_flags = re.findall("):program.index("if unaccounted:")])
    scope = {"re": re, "os": types.SimpleNamespace(environ={"RUN_FLAGS": run_flags}),
             "NAME": "atx-verify", "MODULE": "github.com/opena2a-standards/atx-conformance"}
    exec(lines, scope)
    return scope["unaccounted"]


class PidsLimit(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        demo = self.root / "docs" / "demo"
        for name in INPUTS:
            (demo / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(HERE / name, demo / name)
        self.script = demo / "record-atx-verify.sh"
        for name in ("home", "tmp", "bin"):
            (self.root / name).mkdir()
        self.stub = self.root / "bin" / "docker"
        self.stub.write_text(RENDER_DOCKER_STUB)
        self.stub.chmod(self.stub.stat().st_mode | stat.S_IXUSR)
        self.env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        author = {"GIT_AUTHOR_NAME": "scratch", "GIT_AUTHOR_EMAIL": "scratch@example.invalid",
                  "GIT_COMMITTER_NAME": "scratch", "GIT_COMMITTER_EMAIL": "scratch@example.invalid"}
        for args in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "scratch"]):
            subprocess.run(["git", "-C", str(self.root), *args], env={**self.env, **author},
                           stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=60)

    def render(self, *args, cpus="16", info_exit="0"):
        """Runs the script; returns the process, the stub's calls and `docker create`'s arguments.

        The script removes the directory it made for the render's files with mktemp -d, which
        macOS's mktemp places outside TMPDIR, when `docker create` exits non-zero, as the stub's
        does: the script leaves that directory only after the container ran.
        """
        log, create_args = self.root / "stub.log", self.root / "create-args"
        for path in (log, create_args):
            path.unlink(missing_ok=True)
        env = dict(self.env, DOCKER=str(self.stub), DOCKER_HOST="unix:///nonexistent/docker.sock",
                   STUB_LOG=str(log), STUB_CREATE_ARGS=str(create_args), STUB_CPUS=cpus,
                   STUB_INFO_EXIT=info_exit)
        proc = subprocess.run(["bash", str(self.script), *args], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)
        calls = log.read_text().split() if log.exists() else []
        flags = create_args.read_text().split("\n")[:-1] if create_args.exists() else None
        return proc, calls, flags

    def limit(self, cpus):
        """The --pids-limit `docker create` is given when `docker info` counts this many CPUs."""
        proc, _calls, flags = self.render(cpus=str(cpus))
        self.assertEqual(proc.returncode, CREATE_EXIT, proc.stderr)
        self.assertIsNotNone(flags, f"no `docker create` call with {cpus} CPUs: {proc.stderr}")
        self.assertEqual(flags.count("--pids-limit"), 1, flags)
        return int(flags[flags.index("--pids-limit") + 1])

    def test_limit_leaves_headroom_over_the_measured_peaks(self):
        for cpus, peak in MEASURED_PEAKS.items():
            with self.subTest(cpus=cpus):
                self.assertGreaterEqual(self.limit(cpus), HEADROOM * peak,
                                        f"the render peaked at {peak} tasks with {cpus} CPUs")

    def test_limit_grows_with_the_cpu_count(self):
        (low, low_peak), (high, high_peak) = sorted(MEASURED_PEAKS.items())
        growth = (high_peak - low_peak) / (high - low)
        counts = (high, 64, 256)
        limits = {cpus: self.limit(cpus) for cpus in counts}
        for a, b in zip(counts, counts[1:]):
            with self.subTest(cpus=(a, b)):
                self.assertGreaterEqual((limits[b] - limits[a]) / (b - a), HEADROOM * growth,
                                        f"limits {limits}; the peak grew {growth} tasks a CPU "
                                        f"from {low} CPUs to {high}")

    def test_dry_run_names_the_rule_a_render_applies(self):
        proc, calls, _flags = self.render("--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(calls, [], "--dry-run ran a docker command")
        line = next((line for line in proc.stdout.splitlines()
                     if line.lstrip().startswith("container ")), "")
        rule = re.search(r"--pids-limit (\d+) plus (\d+) for each CPU", line)
        self.assertIsNotNone(rule, proc.stdout)
        base, per_cpu = int(rule[1]), int(rule[2])
        for cpus in (1, 16, 256):
            with self.subTest(cpus=cpus):
                self.assertEqual(self.limit(cpus), base + per_cpu * cpus, line)

    def test_container_is_told_the_limit_it_runs_with(self):
        proc, _calls, flags = self.render(cpus="16")
        self.assertIsNotNone(flags, proc.stderr)
        limit = flags[flags.index("--pids-limit") + 1]
        told = next((flag.removeprefix("RUN_FLAGS=") for flag in flags
                     if flag.startswith("RUN_FLAGS=")), "")
        words = told.split()
        self.assertIn("--pids-limit", words, flags)
        self.assertEqual(words[words.index("--pids-limit") + 1], limit, flags)
        self.assertEqual(container_unaccounted(told), [], told)

    def test_container_check_needs_a_pids_limit_with_a_number(self):
        others = "--cap-drop ALL --security-opt no-new-privileges"
        self.assertEqual(container_unaccounted(f"{others} --pids-limit 4096"), [])
        for run_flags in (others, f"{others} --pids-limit", f"{others} --pids-limit 0",
                          f"{others} --pids-limit -1"):
            with self.subTest(run_flags=run_flags):
                self.assertEqual(container_unaccounted(run_flags), ["--pids-limit"])

    def test_no_cpu_count_stops_before_the_build(self):
        for cpus, info_exit in (("", "1"), ("16", "1"), ("0", "0"), ("sixteen", "0"), ("", "0")):
            with self.subTest(cpus=cpus, info_exit=info_exit):
                proc, calls, flags = self.render(cpus=cpus, info_exit=info_exit)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("not the docker host's CPU count", proc.stderr)
                self.assertNotIn("build", calls)
                self.assertIsNone(flags)


NAME = "atx-verify"
# The files of docs/demo copied into each RenderOutput test's checkout: INPUTS, and the narration,
# which the stand-in's render reads through the read-only mount, as the render does.
RENDER_INPUTS = (*INPUTS, f"{NAME}.narration.json")
# Written into the stand-in's state directory, it makes the render exit 3 after the capture and
# before the sidecar, as a render that breaks the pace rule does.
EXIT_3_AFTER_CAPTURE = "render-exits-3-after-capture"
# Written there, it makes docker cp exit 1 having copied nothing.
COPY_FAILS = "docker-cp-fails"
# The docker host's CPU count, which the stand-in's `docker info --format '{{.NCPU}}'` prints; the
# script derives the container's --pids-limit from it before the build.
HOST_CPUS = 16

# Docker's default capability set, which --cap-drop and --cap-add change.
DEFAULT_CAPS = frozenset({"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
                          "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID",
                          "SYS_CHROOT"})
# The directories of the render image the render reaches, with their owner, group and mode.
IMAGE_DIRS = {"/": (0, 0, 0o755), "/work": (0, 0, 0o755), "/tmp": (0, 0, 0o1777)}
VALUE_OPTIONS = {"--pull", "--hostname", "--shm-size", "--cap-drop", "--cap-add", "--security-opt",
                 "--pids-limit", "-e", "--env", "-v", "--volume", "--mount", "--entrypoint", "-u", "--user",
                 "--network", "--name", "--cidfile", "-w", "--workdir"}
FLAG_OPTIONS = {"--rm", "--privileged"}


def output_text(path: str) -> bytes:
    """What the stand-in's render writes into a file it makes."""
    return f"written by the render: {path}\n".encode()


SIDECAR = json.dumps({"schema": "demo-sidecar/2", "tool": NAME, "writtenBy": "stand-in"}).encode() + b"\n"


class Unmodelled(Exception):
    """A call or an option the stand-in does not model."""


class Refused(Exception):
    """A call of the render's that the kernel refuses, with the line Python prints for it."""


def allowed(owner: tuple, is_dir: bool, want: str, uid: int, gid: int, caps: set) -> bool:
    """The kernel's check of a process against a file's owner, group and mode."""
    st_uid, st_gid, mode = owner
    if "DAC_OVERRIDE" in caps and not ("x" in want and not is_dir and not mode & 0o111):
        return True
    if "DAC_READ_SEARCH" in caps and set(want) <= ({"r", "x"} if is_dir else {"r"}):
        return True
    bits = (mode >> 6) & 7 if uid == st_uid else (mode >> 3) & 7 if gid == st_gid else mode & 7
    need = sum({"r": 4, "w": 2, "x": 1}[c] for c in want)
    return bits & need == need


class FileSystem:
    """A container's file system: the image's own directories, and the bind mounts over them."""

    def __init__(self, state: pathlib.Path, container: dict):
        self.container = container
        self.root = state / "rootfs" / container["id"]
        self.uid, self.gid = container["user"]
        self.caps = set(container["caps"])

    def where(self, path: str) -> tuple:
        """The host path behind a container path, the bind mount it lies under or None."""
        best = None
        for mount in self.container["mounts"]:
            target = mount["target"]
            if (path == target or path.startswith(target + "/")) and (
                    best is None or len(target) > len(best["target"])):
                best = mount
        if best is not None:
            return pathlib.Path(best["source"] + path[len(best["target"]):]), best
        return self.root / path.lstrip("/"), None

    def exists(self, path: str) -> bool:
        host, mount = self.where(path)
        return host.exists() if mount else path in self.container["meta"]

    def owner(self, path: str) -> tuple:
        host, mount = self.where(path)
        if mount:
            # A bind mount keeps the host's owner and mode.
            found = os.stat(host)
            return found.st_uid, found.st_gid, stat.S_IMODE(found.st_mode)
        return tuple(self.container["meta"][path])

    def check(self, path: str, want: str, call: str) -> None:
        """Refuse call, a call on the path call names, unless the process may do want on path."""
        host, _mount = self.where(path)
        if not allowed(self.owner(path), host.is_dir(), want, self.uid, self.gid, self.caps):
            raise Refused(f"PermissionError: [Errno 13] Permission denied: '{call}'")

    def search(self, path: str) -> None:
        """Search permission on each directory above path."""
        current = ""
        self.check("/", "x", path)
        for part in path.strip("/").split("/")[:-1]:
            current += "/" + part
            self.check(current, "x", path)

    def make(self, path: str, data: bytes = None) -> None:
        """Make a directory, or a file holding data, in a directory that exists."""
        self.search(path)
        host, mount = self.where(path)
        if mount and mount["readonly"]:
            raise Refused(f"OSError: [Errno 30] Read-only file system: '{path}'")
        self.check(path.rsplit("/", 1)[0] or "/", "wx", path)
        if data is None:
            host.mkdir()
        else:
            host.write_bytes(data)
        if not mount:
            self.container["meta"][path] = [self.uid, self.gid, 0o644 if data is not None else 0o755]

    def makedirs(self, path: str) -> None:
        current = ""
        for part in path.strip("/").split("/"):
            current += "/" + part
            if not self.exists(current):
                self.make(current)

    def write(self, path: str, data: bytes) -> None:
        if self.exists(path):
            self.search(path)
            self.check(path, "w", path)
            self.where(path)[0].write_bytes(data)
        else:
            self.make(path, data)

    def read(self, path: str) -> str:
        self.search(path)
        self.check(path, "r", path)
        return self.where(path)[0].read_text(encoding="utf-8")


def render(state: pathlib.Path, container: dict) -> int:
    """The render's calls on the file system, in its order, each refused as the kernel refuses it."""
    fs = FileSystem(state, container)
    demo = "/work/input/docs/demo"
    try:
        tape = fs.read(f"{demo}/{NAME}.tape")
        fs.read(f"{demo}/{NAME}.narration.json")
        fs.makedirs("/work/docs/demo/out")
        fs.makedirs(container["env"]["HOME"])
        for directory in re.findall(r"mkdir -p (/\S+)", tape):
            fs.makedirs(directory)
        for path in re.findall(r"^(?:Output|Screenshot) (\S+)$", tape, re.M):
            fs.write(f"/work/{path}", output_text(path))
        fs.write(f"/work/docs/demo/{NAME}-capture.txt", output_text(f"docs/demo/{NAME}-capture.txt"))
        if (state / EXIT_3_AFTER_CAPTURE).exists():
            print(f"record-{NAME}.sh: the render breaks the pace rule; no sidecar was written:", file=sys.stderr)
            return 3
        fs.write(f"/work/docs/demo/{NAME}.json", SIDECAR)
    except Refused as refusal:
        print(refusal, file=sys.stderr)
        return 1
    print(f"rendered: {NAME} (stand-in)")
    return 0


def parse_container(state: pathlib.Path, args: list) -> dict:
    """A container from the options of docker create or docker run, before its image."""
    container = {"env": {}, "mounts": [], "securityOpt": [], "user": [0, 0], "rm": False, "pidsLimit": None,
                 "meta": {path: list(owner) for path, owner in IMAGE_DIRS.items()}}
    drop, add, privileged, cidfile = set(), set(), False, None
    i = 0
    while i < len(args) and args[i].startswith("-"):
        option, has_value, value = args[i].partition("=")
        i += 1
        if option in FLAG_OPTIONS and not has_value:
            container["rm"] = container["rm"] or option == "--rm"
            privileged = privileged or option == "--privileged"
            continue
        if option not in VALUE_OPTIONS:
            raise Unmodelled(f"the option {option}")
        if not has_value:
            value = args[i]
            i += 1
        if option in ("-e", "--env"):
            key, _, val = value.partition("=")
            container["env"][key] = val
        elif option in ("-v", "--volume", "--mount"):
            if option == "--mount":
                fields = dict(f.partition("=")[::2] for f in value.split(","))
                if fields.get("type") != "bind":
                    raise Unmodelled(f"the mount {value}")
                source = fields.get("source") or fields.get("src")
                target = fields.get("target") or fields.get("destination") or fields.get("dst")
                readonly = "readonly" in fields or "ro" in fields
            else:
                source, _, rest = value.partition(":")
                target, _, mode = rest.partition(":")
                readonly = "ro" in mode.split(",")
            if not source.startswith("/"):
                raise Unmodelled(f"the volume {value}; the stand-in models bind mounts of host directories")
            container["mounts"].append({"source": source.rstrip("/") or "/", "target": target.rstrip("/"),
                                        "readonly": readonly})
        elif option == "--cap-drop":
            drop |= {c.upper().removeprefix("CAP_") for c in value.split(",")}
        elif option == "--cap-add":
            add |= {c.upper().removeprefix("CAP_") for c in value.split(",")}
        elif option == "--security-opt":
            container["securityOpt"].append(value)
        elif option == "--pids-limit":
            container["pidsLimit"] = int(value)
        elif option in ("-u", "--user"):
            ids = [0 if part == "root" else int(part) for part in value.split(":")]
            container["user"] = [ids[0], ids[1] if len(ids) > 1 else ids[0]]
        elif option == "--cidfile":
            cidfile = value
        elif option in ("-w", "--workdir") and value != "/work":
            raise Unmodelled(f"the working directory {value}")
    if i + 1 >= len(args):
        raise Unmodelled("a container with no image or no command")
    if args[i + 1:][-1:] != ["--in-container"]:
        raise Unmodelled(f"the command {args[i + 1:]}; the stand-in runs the render alone")
    caps = set(DEFAULT_CAPS) if not privileged else {"ALL"}
    caps = (set() if "ALL" in drop else caps - drop) | add
    container["caps"] = sorted({"DAC_OVERRIDE", "DAC_READ_SEARCH"} | caps if "ALL" in caps else caps)
    counter = state / "next-id"
    number = int(counter.read_text()) if counter.exists() else 1
    counter.write_text(str(number + 1))
    container["id"] = f"stand-in-container-{number}"
    container["state"] = "created"
    root = state / "rootfs" / container["id"]
    for path in container["meta"]:
        (root / path.lstrip("/")).mkdir(parents=True, exist_ok=True)
    for mount in container["mounts"]:
        # Docker makes the directories above a mount's target in the image's file system, owned by root.
        current = ""
        for part in mount["target"].strip("/").split("/")[:-1]:
            current += "/" + part
            if current not in container["meta"]:
                container["meta"][current] = [0, 0, 0o755]
                (root / current.lstrip("/")).mkdir(parents=True, exist_ok=True)
    if cidfile:
        pathlib.Path(cidfile).write_text(container["id"])
    save(state, container)
    return container


def save(state: pathlib.Path, container: dict) -> None:
    (state / "containers").mkdir(exist_ok=True)
    (state / "containers" / f"{container['id']}.json").write_text(json.dumps(container))


def load(state: pathlib.Path, ident: str) -> dict:
    path = state / "containers" / f"{ident}.json"
    return json.loads(path.read_text()) if path.exists() else None


def remove(state: pathlib.Path, ident: str) -> None:
    (state / "containers" / f"{ident}.json").unlink()
    shutil.rmtree(state / "rootfs" / ident)


def start(state: pathlib.Path, container: dict) -> int:
    if container["state"] != "created":
        raise Unmodelled(f"starting container {container['id']} a second time")
    code = render(state, container)
    container.update(state="exited", exitCode=code)
    save(state, container)
    with open(state / "ran.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({key: container[key] for key in
                            ("id", "user", "caps", "securityOpt", "pidsLimit", "mounts", "exitCode")}) + "\n")
    return code


def copy_out(state: pathlib.Path, args: list) -> int:
    """docker cp CONTAINER:PATH HOST_PATH, the copies made as the caller's files."""
    operands = [a for a in args if a not in ("-q", "--quiet")]
    if len(operands) != 2 or ":" not in operands[0] or any(a.startswith("-") for a in operands):
        raise Unmodelled(f"docker cp {' '.join(args)}")
    ident, _, path = operands[0].partition(":")
    container = load(state, ident)
    if container is None:
        print(f"Error response from daemon: No such container: {ident}", file=sys.stderr)
        return 1
    if (state / COPY_FAILS).exists():
        print("Error response from daemon: the stand-in was told to fail this copy", file=sys.stderr)
        return 1
    contents = path.endswith("/.")
    source, _mount = FileSystem(state, container).where(path[:-2] if contents else path)
    if not source.exists():
        print(f"Error response from daemon: Could not find the file {path} in container {ident}", file=sys.stderr)
        return 1
    destination = pathlib.Path(operands[1])
    if source.is_dir():
        if not contents and destination.exists():
            destination = destination / source.name
        shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)
    else:
        shutil.copy2(source, destination)
    return 0


def stand_in(state: pathlib.Path, args: list) -> int:
    """The stand-in for docker."""
    try:
        if args[:2] == ["context", "inspect"]:
            print("unix:///stand-in/docker.sock")
            return 0
        if args[:1] == ["info"]:
            if args[1:] != ["--format", "{{.NCPU}}"]:
                raise Unmodelled(f"docker {' '.join(args)}")
            print(HOST_CPUS)
            return 0
        if args[:1] == ["build"]:
            return 0
        if args[:2] == ["image", "inspect"]:
            print("sha256:stand-in-image" if any(".Id" in a for a in args) else "stand-in")
            return 0
        if args[:1] == ["create"]:
            print(parse_container(state, args[1:])["id"])
            return 0
        if args[:1] == ["run"]:
            container = parse_container(state, args[1:])
            code = start(state, container)
            if container["rm"]:
                remove(state, container["id"])
            return code
        if args[:1] == ["start"]:
            options = [a for a in args[1:] if a.startswith("-")]
            idents = [a for a in args[1:] if not a.startswith("-")]
            if not set(options) <= {"-a", "--attach"} or len(idents) != 1 or load(state, idents[0]) is None:
                raise Unmodelled(f"docker start {' '.join(args[1:])}")
            code = start(state, load(state, idents[0]))
            if options:
                return code
            print(idents[0])
            return 0
        if args[:1] == ["cp"]:
            return copy_out(state, args[1:])
        if args[:1] == ["rm"]:
            force = any(a in ("-f", "--force") for a in args[1:])
            code = 0
            for ident in (a for a in args[1:] if not a.startswith("-")):
                if load(state, ident) is not None:
                    remove(state, ident)
                    print(ident)
                elif not force:
                    print(f"Error response from daemon: No such container: {ident}", file=sys.stderr)
                    code = 1
            return code
        raise Unmodelled(f"docker {' '.join(args[:2])}")
    except Unmodelled as gap:
        print(f"stand-in docker: {gap} is not modelled", file=sys.stderr)
        return 125


class RenderOutput(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="record-test-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.checkout = self.work / "checkout"
        for name in RENDER_INPUTS:
            (self.checkout / "docs/demo" / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE / name, self.checkout / "docs/demo" / name)
        for path in [self.checkout, *self.checkout.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        self.state = self.work / "docker-state"
        (self.state / "bin").mkdir(parents=True)
        self.docker = self.state / "bin" / "docker"
        self.docker.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(str(a)) for a in (
            sys.executable, "-I", pathlib.Path(__file__).resolve(), "fake-docker", self.state)) + ' "$@"\n')
        self.docker.chmod(0o755)
        # Each `mktemp -d` of the script makes its directory under $TMPDIR, where the test looks for
        # what the script leaves.
        real_mktemp = shlex.quote(shutil.which("mktemp"))
        mktemp = self.state / "bin" / "mktemp"
        mktemp.write_text("#!/bin/sh\n"
                          f'if [ "$#" -eq 1 ] && [ "$1" = -d ]; then exec {real_mktemp} -d "$TMPDIR/tmp.XXXXXXXXXX"; fi\n'
                          f'exec {real_mktemp} "$@"\n')
        mktemp.chmod(0o755)
        self.tmp = self.work / "tmp"
        self.home = self.work / "home"
        self.tmp.mkdir()
        self.home.mkdir()
        self.env = {"PATH": f"{self.docker.parent}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                    "HOME": str(self.home), "TMPDIR": str(self.tmp), "LANG": "C", "DOCKER": str(self.docker),
                    "DOCKER_HOST": "unix:///stand-in/docker.sock", "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1"}
        for command in (["init", "-q"], ["-c", "user.name=test", "-c", "user.email=test@example.invalid",
                                         "commit", "-q", "--allow-empty", "-m", "checkout"]):
            subprocess.run(["git", "-c", "init.defaultBranch=main", *command], cwd=self.checkout, env=self.env,
                           check=True, capture_output=True)
        tape = TAPE.read_text(encoding="utf-8")
        self.writes = re.findall(r"^(?:Output|Screenshot) (\S+)$", tape, re.M) + [f"docs/demo/{NAME}-capture.txt"]

    def record(self) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(self.checkout / f"docs/demo/record-{NAME}.sh")], cwd=self.checkout,
                              env=self.env, capture_output=True, text=True, timeout=120)

    def assert_no_container_left(self):
        left = sorted(p.stem for p in (self.state / "containers").glob("*.json"))
        self.assertEqual(left, [], "the script left these containers")

    def assert_capabilities_dropped(self):
        ran = [json.loads(line) for line in (self.state / "ran.jsonl").read_text().splitlines()]
        self.assertTrue(ran, "no container ran")
        for container in ran:
            self.assertEqual(container["caps"], [], container)
            self.assertIn("no-new-privileges", [o.partition(":")[0].partition("=")[0] for o in container["securityOpt"]],
                          container)

    def test_the_render_writes_its_output_and_the_script_copies_it_into_docs_demo(self):
        done = self.record()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.splitlines()[-1],
                         f"sidecar: docs/demo/{NAME}.json sha256 {hashlib.sha256(SIDECAR).hexdigest()}")
        for path in self.writes:
            self.assertEqual((self.checkout / path).read_bytes(), output_text(path), path)
        self.assertEqual((self.checkout / f"docs/demo/{NAME}.json").read_bytes(), SIDECAR)
        self.assert_capabilities_dropped()
        self.assert_no_container_left()
        self.assertEqual(sorted(os.listdir(self.tmp)), [], "the script left these temporary files")

    def test_a_render_that_stops_part_way_leaves_its_files_in_the_directory_the_script_names(self):
        for path in [*self.writes, f"docs/demo/{NAME}.json"]:
            (self.checkout / path).parent.mkdir(parents=True, exist_ok=True)
            (self.checkout / path).write_text("an earlier render\n")
        (self.state / EXIT_3_AFTER_CAPTURE).touch()
        done = self.record()
        self.assertEqual(done.returncode, 3, done.stderr)
        named = re.search(r"the render exited 3; nothing was copied into docs/demo, and what the render wrote "
                          r"is in (\S+)\.$", done.stderr, re.M)
        self.assertIsNotNone(named, done.stderr)
        kept = pathlib.Path(named.group(1))
        for path in self.writes:
            relative = path.removeprefix("docs/demo/")
            self.assertEqual((kept / relative).read_bytes(), output_text(path), path)
            self.assertFalse((self.checkout / path).exists(), path)
        self.assertFalse((kept / f"{NAME}.json").exists())
        self.assertFalse((self.checkout / f"docs/demo/{NAME}.json").exists())
        self.assert_capabilities_dropped()
        self.assert_no_container_left()
        self.assertEqual(sorted(os.listdir(self.tmp)), [kept.name], "the script left these temporary files")

    def test_a_failed_copy_out_of_the_container_copies_nothing_into_docs_demo(self):
        (self.state / COPY_FAILS).touch()
        done = self.record()
        self.assertEqual(done.returncode, 1, done.stderr)
        named = re.search(r"cp exited 1; nothing was copied into docs/demo, and what it copied of the render's "
                          r"files is in (\S+)\.$", done.stderr, re.M)
        self.assertIsNotNone(named, done.stderr)
        for path in [*self.writes, f"docs/demo/{NAME}.json"]:
            self.assertFalse((self.checkout / path).exists(), path)
        self.assert_capabilities_dropped()
        self.assert_no_container_left()
        self.assertEqual(sorted(os.listdir(self.tmp)), [pathlib.Path(named.group(1)).name],
                         "the script left these temporary files")


if __name__ == "__main__":
    if sys.argv[1:2] == ["fake-docker"]:
        sys.exit(stand_in(pathlib.Path(sys.argv[2]), sys.argv[3:]))
    unittest.main()
