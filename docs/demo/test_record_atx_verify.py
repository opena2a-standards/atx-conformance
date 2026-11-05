#!/usr/bin/env python3
"""record-atx-verify.sh refuses a Dockerfile that references an image it does not read.

The script reads the images of two FROM lines of docs/demo/docker/Dockerfile, the build stage
(`AS vhsbuild`) and the render stage, and the sidecar's `recorder` records them as
`builderImage` and `baseImage`. Before the change this test came with, it read no other line:
`--dry-run` exited 0 on a Dockerfile with a third FROM line, upper or lower case, or with a
`COPY --from` or a `RUN --mount` that names an image.

Each case writes one Dockerfile into a scratch copy of docs/demo and runs the scratch copy of
the script, with and without `--dry-run`, with DOCKER set to a stub that logs its arguments and
exits 1. On a Dockerfile it refuses, the script must exit 1 with one line on standard error,
which names the Dockerfile line it refuses except for a NUL byte and a base image named by tag
alone, and must run no docker command. Needs bash and git; no docker, network or image is used.

    python3 docs/demo/test_record_atx_verify.py
"""

import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
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


if __name__ == "__main__":
    unittest.main()
