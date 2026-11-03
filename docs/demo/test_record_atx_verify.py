#!/usr/bin/env python3
"""Tests of record-atx-verify.sh: the images it reads from the Dockerfile, and the --pids-limit it
gives its render container.

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
for `docker info`, records the arguments of `docker run` and exits 7 in its place, so no image is
built, no container starts and this checkout is not written to. The check the script's
in-container program makes of the limits it is told is read out of the script and run on its own,
as the rest of that program needs the container.

Needs bash and git; no docker, network or image is used.

    python3 docs/demo/test_record_atx_verify.py
"""

import os
import pathlib
import re
import shutil
import stat
import subprocess
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
        *inserted(IN_RENDER, "COPY --chown=0 --from=busybox:latest /bin/busybox /bin/busybox"),
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


# What the script reads on the host side before `docker run`, by its path under docs/demo.
INPUTS = ("record-atx-verify.sh", "atx-verify.tape", "docker/Dockerfile",
          "docker/vhs-0.12.0-render-context.patch")
# The render's peak task count, read from its container's pids.peak, by the CPUs it ran on.
MEASURED_PEAKS = {8: 211, 16: 254}
# The limit is held to at least this many times the measured peak, and to growing at least
# this many times as fast a CPU as the peak grew from 8 CPUs to 16.
HEADROOM = 2
# The exit code of RENDER_DOCKER_STUB's `docker run`.
RUN_EXIT = 7

RENDER_DOCKER_STUB = r"""#!/bin/sh
# docker, as record-atx-verify.sh calls it. Each call's first argument goes to $STUB_LOG.
# `info` prints $STUB_CPUS and exits $STUB_INFO_EXIT; `run` writes its arguments to
# $STUB_RUN_ARGS, one a line, and exits 7.
echo "$1" >> "$STUB_LOG"
case "$1" in
  info) printf '%s\n' "$STUB_CPUS"; exit "$STUB_INFO_EXIT" ;;
  build) exit 0 ;;
  image) echo stub; exit 0 ;;
  run) shift; printf '%s\n' "$@" > "$STUB_RUN_ARGS"; exit 7 ;;
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
        """Runs the script; returns the process, the stub's calls and `docker run`'s arguments."""
        log, run_args = self.root / "stub.log", self.root / "run-args"
        for path in (log, run_args):
            path.unlink(missing_ok=True)
        env = dict(self.env, DOCKER=str(self.stub), DOCKER_HOST="unix:///nonexistent/docker.sock",
                   STUB_LOG=str(log), STUB_RUN_ARGS=str(run_args), STUB_CPUS=cpus,
                   STUB_INFO_EXIT=info_exit)
        proc = subprocess.run(["bash", str(self.script), *args], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)
        calls = log.read_text().split() if log.exists() else []
        flags = run_args.read_text().split("\n")[:-1] if run_args.exists() else None
        # A render the stub stopped leaves the directory the script made for the render's files with
        # mktemp -d, which macOS's mktemp places outside TMPDIR. The stub writes nothing into it, so it
        # is removed here as an empty directory.
        for flag in flags or []:
            render_dir = flag.removesuffix(":/work/docs/demo")
            if render_dir != flag and os.path.isdir(render_dir):
                os.rmdir(render_dir)
        return proc, calls, flags

    def limit(self, cpus):
        """The --pids-limit `docker run` is given when `docker info` counts this many CPUs."""
        proc, _calls, flags = self.render(cpus=str(cpus))
        self.assertEqual(proc.returncode, RUN_EXIT, proc.stderr)
        self.assertIsNotNone(flags, f"no `docker run` call with {cpus} CPUs: {proc.stderr}")
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


if __name__ == "__main__":
    unittest.main()
