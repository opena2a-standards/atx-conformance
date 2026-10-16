#!/usr/bin/env python3
"""Write (or verify) the capture of README.md's Go verifier run and its sidecar.

README.md opens with one command in a fenced block, `cd <dir> && <command>`,
then a label line, "What `<command>` prints ([full output](<capture>),
trimmed):", and a fenced excerpt of that output. This script reads the
working directory, the command and the capture path from those lines, runs
the command there, and writes its standard output to the capture
(docs/captures/go-verifier.txt) and a sidecar beside it with the same name
ending in .json. The sidecar says how the capture was taken: the command
and its working directory, the Go release and platform, the paths the
command reads and the git tree id of each as the run read it, the
uncommitted files under those paths, the time, the exit code, the number
of lines written to standard error (not captured), the summary line, and
the capture's SHA-256 and byte and line counts. A run that exits non-zero,
prints no `summary:` line last, or prints bytes that are not UTF-8 writes
nothing.

The sidecar records tree ids, not a commit id. A capture is committed on
a branch that is squash-merged, so the commit a run sees is left off the
default branch. A tree id hashes only the names, modes and bytes of the
files under the path, so once the branch is merged `git rev-parse
HEAD:<path>` on the default branch gives the recorded id until the path
changes.

`--check` runs no Go command and needs no Go toolchain; it runs git. It
fails when the sidecar is missing, is not a JSON object, lacks a member or
holds one of the wrong type, names another command, working directory,
capture or list of input paths than README.md, records tree ids other than
those the input paths hold in the working tree, records a non-zero exit
code, or does not describe the committed capture's bytes and last line;
and when README.md's excerpt is not the capture's lines, in order, with a
line holding only `...` standing for the lines left out. It runs the
self-test first. A self-test case that raises because git cannot be
started or a git command exits non-zero is red and prints the error under
its label; the cases after it still run, and the run ends in its
`N/N cases green` line.

Each git command runs in the repository root, or in one of the self-test's
temporary repositories, with every GIT_* variable removed from its
environment and with git told not to look for a repository above that
directory. A GIT_DIR, GIT_WORK_TREE or GIT_INDEX_FILE that git exports to a
hook running `--check` does not move a command to another repository or
index.

Usage:
    python3 scripts/capture_go_verifier.py              # run README.md's Go command, (re)write the capture and its sidecar
    python3 scripts/capture_go_verifier.py --check      # exit 1 if the sidecar, the capture, README.md's excerpt and the inputs disagree
    python3 scripts/capture_go_verifier.py --self-test  # prove each altered capture, sidecar or excerpt fails
    python3 scripts/capture_go_verifier.py --help       # print this usage
"""
from __future__ import annotations

import contextlib
import datetime
import functools
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
README = "README.md"
# Not sliced from __doc__, which `python -OO` strips. The self-test holds the
# docstring's Usage block equal to this text.
USAGE = """\
Usage:
    python3 scripts/capture_go_verifier.py              # run README.md's Go command, (re)write the capture and its sidecar
    python3 scripts/capture_go_verifier.py --check      # exit 1 if the sidecar, the capture, README.md's excerpt and the inputs disagree
    python3 scripts/capture_go_verifier.py --self-test  # prove each altered capture, sidecar or excerpt fails
    python3 scripts/capture_go_verifier.py --help       # print this usage
"""

START = re.compile(r"cd (?P<dir>[^\s&;|]+) && (?P<cmd>[^&;|`]+)")
LABEL = re.compile(r"What `(?P<cmd>[^`]+)` prints "
                   r"\(\[full output\]\((?P<path>docs/captures/[^)/\s]+\.txt)\)(?P<trimmed>, trimmed)?\):")
ELISION = "..."
SUMMARY = "summary: "
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
# Sidecar members, in the order they are written, and the type each holds.
MEMBERS: tuple[tuple[str, type], ...] = (
    ("command", str), ("workingDirectory", str), ("stream", str), ("goVersion", str),
    ("platform", str), ("inputs", list), ("inputTrees", dict), ("inputsUncommitted", list),
    ("ranAtUtc", str), ("exitCode", int), ("stderrLines", int), ("summary", str),
    ("outputs", dict),
)


@dataclass
class Start:
    working_directory: str
    command: str
    capture: str
    trimmed: bool
    excerpt: list[str]
    excerpt_line: int  # README.md line number of the excerpt's first line

    @property
    def sidecar(self) -> str:
        return self.capture[: -len(".txt")] + ".json"


@dataclass
class Run:
    stdout: bytes
    stderr: bytes
    returncode: int


Runner = Callable[[list[str], Path], Run]
Describer = Callable[[Path, Start], dict]


def _fence(line: str) -> bool:
    return line.lstrip().startswith(("```", "~~~"))


def _block(lines: list[str], i: int) -> tuple[list[str], int] | None:
    """The body of the fenced block opening at lines[i], and the index of the
    line after its closing fence; None when lines[i] opens no block."""
    if i >= len(lines) or not _fence(lines[i]):
        return None
    for j in range(i + 1, len(lines)):
        if _fence(lines[j]):
            return lines[i + 1:j], j + 1
    return None


def read_start(root: Path) -> tuple[Start | None, list[str]]:
    """The start block of README.md: its command, the label naming the
    capture, and the excerpt the label introduces."""
    try:
        lines = (root / README).read_text(encoding="utf-8").split("\n")
    except (OSError, UnicodeDecodeError) as exc:
        return None, [f"{README}: cannot be read ({exc})"]
    first = next((i for i, line in enumerate(lines) if _fence(line)), None)
    command = _block(lines, first) if first is not None else None
    if command is None:
        return None, [f"{README}: no fenced block holds the first command"]
    body, after = command
    start = START.fullmatch(body[0]) if len(body) == 1 else None
    if start is None:
        return None, [f"{README}:{first + 2}: the first fenced block is not one line "
                      "`cd <dir> && <command>`"]
    label = LABEL.fullmatch(lines[after]) if after < len(lines) else None
    if label is None:
        return None, [f"{README}:{after + 1}: the line after the first command is not "
                      "\"What `<command>` prints ([full output](docs/captures/<name>.txt)[, trimmed]):\""]
    if label["cmd"] != start["cmd"]:
        return None, [f"{README}:{after + 1}: the label names `{label['cmd']}`, "
                      f"the first command runs `{start['cmd']}`"]
    excerpt = _block(lines, after + 1)
    if excerpt is None:
        return None, [f"{README}:{after + 2}: no fenced excerpt follows the label"]
    return Start(start["dir"], start["cmd"], label["path"], bool(label["trimmed"]),
                 excerpt[0], after + 3), []


def _lines(text: str) -> list[str]:
    lines = text.split("\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


def excerpt_failures(start: Start, capture: list[str]) -> list[str]:
    """README.md's excerpt must be runs of the capture's lines, in order, with
    an elision line only between two runs."""
    runs: list[tuple[int, list[str]]] = [(start.excerpt_line, [])]
    for n, line in enumerate(start.excerpt, start.excerpt_line):
        if line == ELISION:
            runs.append((n + 1, []))
        else:
            runs[-1][1].append(line)
    if any(not run for _, run in runs):
        return [f"{README}:{start.excerpt_line}: an elision line `{ELISION}` opens or closes "
                "the excerpt, or follows another"]
    if len(runs) > 1 and not start.trimmed:
        return [f"{README}:{start.excerpt_line - 2}: the excerpt elides lines and the label "
                "does not say trimmed"]
    if not start.trimmed and runs[0][1] != capture:
        return [f"{README}:{start.excerpt_line - 2}: the label does not say trimmed and the "
                f"excerpt is not the whole of {start.capture}"]
    at = 0
    for n, run in runs:
        found = next((i for i in range(at, len(capture) - len(run) + 1)
                      if capture[i:i + len(run)] == run), None)
        if found is None:
            return [f"{README}:{n}: the excerpt's lines from `{run[0]}` are not the next "
                    f"run of lines in {start.capture}"]
        at = found + len(run)
    return []


def sidecar_failures(root: Path, start: Start, data: bytes) -> list[str]:
    path = root / start.sidecar
    if not path.is_file():
        return [f"{start.sidecar} missing; run scripts/capture_go_verifier.py"]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [f"{start.sidecar}: not JSON ({exc})"]
    if not isinstance(doc, dict):
        return [f"{start.sidecar}: not a JSON object"]
    failures = []
    for name, kind in MEMBERS:
        value = doc.get(name)
        if name not in doc:
            failures.append(f"{start.sidecar}: no `{name}` member")
        elif not isinstance(value, kind) or isinstance(value, bool):
            failures.append(f"{start.sidecar}: `{name}` is not a JSON {kind.__name__}")
    if failures:
        return failures
    lines = _lines(data.decode("utf-8", errors="replace"))
    paths = inputs(root, start)
    expected = {
        "command": start.command,
        "workingDirectory": start.working_directory,
        "inputs": paths,
        "exitCode": 0,
        "summary": lines[-1] if lines else "",
        "outputs": {"capture": {"path": start.capture,
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "bytes": len(data),
                                "lines": len(lines)}},
    }
    for name, want in expected.items():
        if doc[name] != want:
            failures.append(f"{start.sidecar}: `{name}` is {json.dumps(doc[name])}, "
                            f"{start.capture} and {README} give {json.dumps(want)}")
    try:
        trees = input_trees(root, paths)
    except (OSError, subprocess.CalledProcessError) as exc:
        failures.append(f"{start.sidecar}: cannot read the git tree ids of "
                        f"{', '.join(paths)} to compare with `inputTrees` ({exc})")
    else:
        if doc["inputTrees"] != trees:
            failures.append(f"{start.sidecar}: `inputTrees` is {json.dumps(doc['inputTrees'])}, "
                            f"the paths the command reads in this tree are {json.dumps(trees)}; "
                            "the capture was taken on other inputs: run "
                            "scripts/capture_go_verifier.py")
    if not UTC.fullmatch(doc["ranAtUtc"]):
        failures.append(f"{start.sidecar}: `ranAtUtc` is not a UTC time "
                        "(YYYY-MM-DDTHH:MM:SSZ)")
    return failures


def check(root: Path) -> list[str]:
    start, failures = read_start(root)
    if start is None:
        return failures
    try:
        data = (root / start.capture).read_bytes()
    except OSError:
        return [f"{start.capture} missing; run scripts/capture_go_verifier.py"]
    capture = _lines(data.decode("utf-8", errors="replace"))
    return sidecar_failures(root, start, data) + excerpt_failures(start, capture)


def check_tree(root: Path) -> int:
    failures = check(root)
    for f in failures:
        print(f"FAIL {f}")
    if failures:
        return 1
    print("capture, sidecar and README.md excerpt agree")
    return 0


def run_command(argv: list[str], cwd: Path) -> Run:
    done = subprocess.run(argv, cwd=cwd, capture_output=True, check=False)
    return Run(done.stdout, done.stderr, done.returncode)


def _output(argv: list[str], cwd: Path) -> list[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                          check=True).stdout.splitlines()


def git_env(root: Path, **extra: str) -> dict[str, str]:
    """The environment of a git command run in `root`: this process's without
    any GIT_* variable, so a GIT_DIR, GIT_WORK_TREE or GIT_INDEX_FILE that git
    exports to a hook does not point the command at another repository or
    index, and with GIT_CEILING_DIRECTORIES set to the directory above
    `root`, so git looks for the repository in `root` and not above it."""
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    return {**env, "GIT_CEILING_DIRECTORIES": str(root.resolve().parent), **extra}


def git(root: Path, *args: str, **extra: str) -> list[str]:
    """The output lines of `git <args>` run in `root` with git_env(root, **extra)."""
    return subprocess.run(["git", *args], cwd=root, env=git_env(root, **extra),
                          capture_output=True, text=True, check=True).stdout.splitlines()


def inputs(root: Path, start: Start) -> list[str]:
    """The working directory and each command argument naming a path inside
    the repository, relative to the repository root."""
    workdir = (root / start.working_directory).resolve()
    found = [workdir]
    for arg in shlex.split(start.command)[1:]:
        p = (workdir / arg).resolve()
        if p.exists() and p.is_relative_to(root.resolve()) and p not in found:
            found.append(p)
    return [p.relative_to(root.resolve()).as_posix() or "." for p in found]


def input_trees(root: Path, paths: list[str]) -> dict[str, str]:
    """The git tree id of each path as the working tree holds it: HEAD's
    files with the uncommitted and untracked (not ignored) ones applied. A
    tree id hashes only the names, modes and bytes of the files under the
    path, so it survives the squash merge that lands a capture: on the
    default branch, `git rev-parse HEAD:<path>` gives the same id while the
    path is unchanged. It is built in a temporary index, so the repository's
    own index is not touched."""
    with tempfile.TemporaryDirectory() as tmp:
        index = str(Path(tmp) / "index")

        def run(*args: str) -> list[str]:
            return git(root, *args, GIT_INDEX_FILE=index, GIT_LITERAL_PATHSPECS="1")

        run("read-tree", "HEAD")
        run("add", "--all", "--", *paths)
        tree = run("write-tree")[0]
        ids = run("rev-parse", *(f"{tree}:" if p == "." else f"{tree}:{p}" for p in paths))
    return dict(zip(paths, ids))


def git_inputs(root: Path, start: Start) -> dict:
    paths = inputs(root, start)
    uncommitted = sorted(set(
        git(root, "diff", "--name-only", "HEAD", "--", *paths)
        + git(root, "ls-files", "--others", "--exclude-standard", "--", *paths)))
    return {
        "inputs": paths,
        "inputTrees": input_trees(root, paths),
        "inputsUncommitted": uncommitted,
    }


def describe(root: Path, start: Start) -> dict:
    workdir = root / start.working_directory
    version, goos, goarch = _output(["go", "env", "GOVERSION", "GOOS", "GOARCH"], workdir)
    return {
        "goVersion": version,
        "platform": f"{goos}/{goarch}",
        **git_inputs(root, start),
        "ranAtUtc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def write(root: Path, runner: Runner = run_command, describer: Describer = describe) -> int:
    start, failures = read_start(root)
    if start is None:
        for f in failures:
            print(f"FAIL {f}")
        return 1
    try:
        run = runner(shlex.split(start.command), root / start.working_directory)
    except OSError as exc:
        print(f"`{start.command}` in {start.working_directory} did not start ({exc}); "
              "nothing written")
        return 1
    try:
        lines = _lines(run.stdout.decode("utf-8"))
    except UnicodeDecodeError:
        lines = None
    problem = ("its output is not UTF-8" if lines is None
               else f"it exited {run.returncode}" if run.returncode != 0
               else f"its last line is not a `{SUMMARY}` line"
               if not lines or not lines[-1].startswith(SUMMARY) else None)
    if problem:
        sys.stdout.write(run.stdout.decode("utf-8", errors="replace"))
        sys.stdout.write(run.stderr.decode("utf-8", errors="replace"))
        print(f"`{start.command}` in {start.working_directory}: {problem}; nothing written")
        return 1
    try:
        provenance = describer(root, start)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"cannot read the Go release or the inputs' git tree ids ({exc}); nothing written")
        return 1
    sidecar = {
        "command": start.command,
        "workingDirectory": start.working_directory,
        "stream": "stdout",
        **provenance,
        "exitCode": run.returncode,
        "stderrLines": len(_lines(run.stderr.decode("utf-8", errors="replace"))),
        "summary": lines[-1],
        "outputs": {"capture": {"path": start.capture,
                                "sha256": hashlib.sha256(run.stdout).hexdigest(),
                                "bytes": len(run.stdout),
                                "lines": len(lines)}},
    }
    sidecar = {name: sidecar[name] for name, _ in MEMBERS}
    (root / start.capture).parent.mkdir(parents=True, exist_ok=True)
    (root / start.capture).write_bytes(run.stdout)
    (root / start.sidecar).write_text(json.dumps(sidecar, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    print(f"wrote {start.capture} ({len(lines)} lines) and {start.sidecar}: {lines[-1]}")
    return 0


# --- self-test ---------------------------------------------------------------
#
# Each case alters one part of a copy of the published README.md and capture,
# with a sidecar written for them by write() through a runner that prints the
# published capture, and runs the real check() on it. A case is green only
# when the copy fails as named, and the unaltered copy must pass, so a tree
# that is already stale does not make every case look red-as-expected. The
# copy is a temporary git repository, so the sidecar's git members are read
# by the real git_inputs(); only the Go release and the time are fixed.

INPUT = "input.txt"  # the file the copy holds under each path the command reads


def _fake_describe(root: Path, start: Start) -> dict:
    return {"goVersion": "go-test", "platform": "test/test", **git_inputs(root, start),
            "ranAtUtc": "2000-01-01T00:00:00Z"}


def _git(root: Path, *args: str) -> list[str]:
    return git(root, "-c", "user.name=self-test", "-c", "user.email=self-test@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args)


def _commit_all(root: Path, message: str) -> None:
    # The repository is a temporary one, so adding everything in it adds
    # exactly the copy's files.
    _git(root, "add", "--all")
    _git(root, "commit", "-q", "--allow-empty", "-m", message)


@contextlib.contextmanager
def _tree(published: Path = REPO_ROOT):
    """A temporary git repository whose `main` commit holds a copy of
    README.md and a file under each path the command reads, with the capture
    and a sidecar written for them on top; and the start block read from the
    copy."""
    start, failures = read_start(published)
    if start is None:
        raise SystemExit("\n".join(failures))
    data = (published / start.capture).read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / start.capture).parent.mkdir(parents=True)
        shutil.copyfile(published / README, root / README)
        for p in inputs(published, start):
            f = root / p / INPUT if (published / p).is_dir() else root / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(f"{p}\n", encoding="utf-8")
        _git(root, "-c", "init.defaultBranch=main", "init", "-q")
        _commit_all(root, "inputs")
        with contextlib.redirect_stdout(io.StringIO()):
            write(root, lambda argv, cwd: Run(data, b"", 0), _fake_describe)
        yield root, start


def _fails(alter: Callable[[Path, Start], None], needle: str) -> bool:
    with _tree() as (root, start):
        alter(root, start)
        return any(needle in f for f in check(root))


def _edit(rel: Callable[[Start], str], old: str, new: str, count: int = 1):
    def alter(root: Path, start: Start) -> None:
        p = root / rel(start)
        text = p.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"{rel(start)} holds no {old!r}")
        p.write_text(text.replace(old, new, count), encoding="utf-8")
    return alter


_DROP = object()


def _set(name: str, value: object):
    """Set sidecar member `name` to `value`, or remove it when `value` is _DROP."""
    def alter(root: Path, start: Start) -> None:
        p = root / start.sidecar
        doc = json.loads(p.read_text(encoding="utf-8"))
        if value is _DROP:
            del doc[name]
        else:
            doc[name] = value
        p.write_text(json.dumps(doc), encoding="utf-8")
    return alter


def _readme(start: Start) -> str:
    return README


def _capture(start: Start) -> str:
    return start.capture


def _excerpt(transform: Callable[[list[str]], list[str]]):
    def alter(root: Path, start: Start) -> None:
        p = root / README
        lines = p.read_text(encoding="utf-8").split("\n")
        first = start.excerpt_line - 1
        lines[first:first + len(start.excerpt)] = transform(list(start.excerpt))
        p.write_text("\n".join(lines), encoding="utf-8")
    return alter


def _swap_runs(excerpt: list[str]) -> list[str]:
    i = excerpt.index(ELISION)
    return excerpt[i + 1:] + [ELISION] + excerpt[:i]


def _write_on(run: Run) -> tuple[int, bool, list]:
    """write() through a runner returning `run` on a copy whose capture and
    sidecar are removed: its exit code, whether it wrote neither file, and
    the argv and working directory it ran."""
    seen: list = []

    def runner(argv: list[str], cwd: Path) -> Run:
        seen.append((argv, cwd))
        return run

    with _tree() as (root, start):
        (root / start.capture).unlink()
        (root / start.sidecar).unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = write(root, runner, _fake_describe)
        nothing = not (root / start.capture).exists() and not (root / start.sidecar).exists()
        return rc, nothing, [(argv, cwd.relative_to(root).as_posix()) for argv, cwd in seen]


def _check_tree_on(alter: Callable[[Path, Start], None]) -> tuple[int, str]:
    out = io.StringIO()
    with _tree() as (root, start):
        alter(root, start)
        with contextlib.redirect_stdout(out):
            rc = check_tree(root)
    return rc, out.getvalue()


def _main_on(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _after_squash() -> tuple[list[str], list[str], list[str]]:
    """Take a capture the way a pull request does: on a branch, change an
    input and commit it, write the capture and sidecar and commit them. Then
    squash-merge the branch into `main` and clone `main` from scratch, as a
    reader does. Returns check() on the clone, the 40-hex object ids its
    sidecar records, and those of them the clone cannot resolve."""
    with _tree() as (root, start), tempfile.TemporaryDirectory() as tmp:
        data = (root / start.capture).read_bytes()
        _git(root, "checkout", "-q", "-b", "capture")
        changed = root / start.working_directory / INPUT
        changed.write_text(changed.read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
        _commit_all(root, "change an input")
        with contextlib.redirect_stdout(io.StringIO()):
            write(root, lambda argv, cwd: Run(data, b"", 0), _fake_describe)
        _commit_all(root, "capture")
        _git(root, "checkout", "-q", "main")
        _git(root, "merge", "-q", "--squash", "capture")
        _commit_all(root, "squash")
        clone = Path(tmp) / "clone"
        # --no-local copies only the objects reachable from main, as a clone
        # over the network does.
        _git(root, "clone", "-q", "--no-local", "--single-branch", "--branch", "main",
             str(root), str(clone))
        ids = re.findall(r'"([0-9a-f]{40})"', (clone / start.sidecar).read_text(encoding="utf-8"))
        unresolved = [i for i in ids
                      if subprocess.run(["git", "cat-file", "-e", i], cwd=clone, env=git_env(clone),
                                        capture_output=True, check=False).returncode != 0]
        return check(clone), ids, unresolved


def _files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def _beside_other(run: Callable[[Path], object]) -> tuple[object, bool]:
    """run(other), `other` being a git repository with one commit made in a
    temporary directory first. Returns what run returns, or the OSError or
    CalledProcessError it raises, and whether every file under `other`,
    .git included, holds the bytes it held before."""
    with tempfile.TemporaryDirectory() as tmp:
        other = Path(tmp)
        (other / INPUT).write_text("other\n", encoding="utf-8")
        _git(other, "-c", "init.defaultBranch=main", "init", "-q")
        _commit_all(other, "other")
        before = _files(other)
        try:
            result = run(other)
        except (OSError, subprocess.CalledProcessError) as exc:
            result = exc
        return result, _files(other) == before


def _squash_in_hook_env(other: Path) -> tuple[list[str], list[str], list[str]]:
    """_after_squash() with GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE naming
    `other`, as git exports them to a hook."""
    env = {"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other),
           "GIT_INDEX_FILE": str(other / ".git" / "index")}
    saved = {name: os.environ.get(name) for name in env}
    os.environ.update(env)
    try:
        return _after_squash()
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _no_work_tree_inside(other: Path) -> bool:
    """The "not a git work tree" case with the copy made inside `other`'s
    work tree, so a git that looks above the copy finds `other`."""
    saved, tempfile.tempdir = tempfile.tempdir, str(other)
    try:
        return _fails(lambda root, s: shutil.rmtree(root / ".git"), "cannot read the git tree ids")
    finally:
        tempfile.tempdir = saved


# A case is a label and a function that returns whether the case holds. It
# runs when it is reported, so a case that cannot run git is reported red
# with the error, and the cases after it still run.
Case = tuple[str, Callable[[], bool]]


def _raised(exc: OSError | subprocess.CalledProcessError) -> list[str]:
    """The lines a case that raised prints under its label: the command that
    exited non-zero and its standard error, or the error that stopped it."""
    if isinstance(exc, subprocess.CalledProcessError):
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(
            "utf-8", errors="replace")
        return [f"`{shlex.join(exc.cmd)}` exited {exc.returncode}", *_lines(err.strip())]
    return [f"raised {type(exc).__name__}: {exc}"]


def _report(cases: list[Case]) -> int:
    failed = 0
    for label, case in cases:
        try:
            ok, why = case(), []
        except (OSError, subprocess.CalledProcessError) as exc:
            ok, why = False, _raised(exc)
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        for line in why:
            print(f"          {line}")
        failed += not ok
    print(f"capture-go-verifier self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


def _red_with(start: Start, env: dict[str, str], needle: str) -> bool:
    """With `env` set in the environment, _cases() builds its cases and
    _report() on them exits 1, ends in the summary line, and prints a line
    holding `needle` under the label of each red case."""
    out = io.StringIO()
    with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out):
        cases = _cases(start)
        rc = _report(cases)
    lines = out.getvalue().splitlines()
    red = [i for i, line in enumerate(lines) if line.startswith("  [RED  ] ")]
    return (rc == 1 and bool(red) and all(needle in lines[i + 1] for i in red)
            and lines[-1] == "capture-go-verifier self-test: "
                             f"{len(cases) - len(red)}/{len(cases)} cases green")


def _cases(start: Start) -> list[Case]:
    data = (REPO_ROOT / start.capture).read_bytes()
    capture = _lines(data.decode("utf-8"))
    summary = capture[-1]
    first = start.excerpt[0]
    kept = next(line for line in start.excerpt if "observed: ACCEPT" in line)
    ok_run = Run(data, b"", 0)

    @functools.cache
    def published() -> tuple[list[str], dict, dict[str, str]]:
        """check() on the unaltered copy, the sidecar write() wrote for it,
        and the tree id `git rev-parse HEAD:<path>` gives for each input."""
        with _tree() as (root, _):
            return (check(root), json.loads((root / start.sidecar).read_text(encoding="utf-8")),
                    {p: _git(root, "rev-parse", "HEAD:" if p == "." else f"HEAD:{p}")[0]
                     for p in inputs(root, start)})

    def written() -> dict:
        return published()[1]

    def check_tree_names_missing_sidecar() -> bool:
        rc, out = _check_tree_on(lambda root, s: (root / s.sidecar).unlink())
        return rc == 1 and f"FAIL {start.sidecar} missing" in out

    def squash_passes() -> bool:
        squash_failures, ids, unresolved = _after_squash()
        return not squash_failures and bool(ids) and not unresolved

    def hook_env_squash_passes() -> bool:
        hook_squash, other_kept = _beside_other(_squash_in_hook_env)
        return (isinstance(hook_squash, tuple) and not hook_squash[0] and bool(hook_squash[1])
                and not hook_squash[2] and other_kept)

    def nested_no_work_tree_fails() -> bool:
        nested_fails, other_kept = _beside_other(_no_work_tree_inside)
        return nested_fails is True and other_kept

    return [
        ("the published README.md and capture, with a sidecar written for them, pass",
         lambda: not published()[0]),
        ("write() records the published capture's line count and last line",
         lambda: written()["outputs"]["capture"]["lines"] == len(capture)
         and written()["summary"] == summary),
        ("inputs() lists the working directory and the fixture directory",
         lambda: inputs(REPO_ROOT, start) == ["verifiers/go", "fixtures"]),
        ("write() writes the sidecar members in order",
         lambda: list(written()) == [name for name, _ in MEMBERS]),
        ("write() runs README.md's command as argv in its working directory",
         lambda: _write_on(ok_run)
         == (0, False, [(shlex.split(start.command), start.working_directory)])),
        ("write() writes nothing when the command exits 1",
         lambda: _write_on(Run(data, b"", 1))[:2] == (1, True)),
        ("write() writes nothing when the last line is not a summary line",
         lambda: _write_on(Run(data.replace(summary.encode(), b"done"), b"", 0))[:2] == (1, True)),
        ("write() writes nothing when the output is not UTF-8",
         lambda: _write_on(Run(data + b"\xff\n" + summary.encode() + b"\n", b"", 0))[:2]
         == (1, True)),
        ("fails when the capture's first token is edited",
         lambda: _fails(_edit(_capture, first, first.replace("PASS", "FAIL", 1)), "`outputs`")),
        ("fails when a line is appended to the capture",
         lambda: _fails(lambda root, s: (root / s.capture).write_bytes(data + b"extra\n"),
                        "`outputs`")),
        ("fails when the capture is missing",
         lambda: _fails(lambda root, s: (root / s.capture).unlink(), f"{start.capture} missing")),
        ("fails when the sidecar is missing",
         lambda: _fails(lambda root, s: (root / s.sidecar).unlink(), f"{start.sidecar} missing")),
        ("fails when the sidecar is not JSON",
         lambda: _fails(lambda root, s: (root / s.sidecar).write_text("{", encoding="utf-8"),
                        "not JSON")),
        ("fails when the sidecar is a JSON array",
         lambda: _fails(lambda root, s: (root / s.sidecar).write_text("[]", encoding="utf-8"),
                        "not a JSON object")),
        *((f"fails when the sidecar has no `{name}` member",
           lambda name=name: _fails(_set(name, _DROP), f"no `{name}` member"))
          for name, _ in MEMBERS),
        ("fails when `exitCode` is true",
         lambda: _fails(_set("exitCode", True), "`exitCode` is not")),
        ("fails when `stderrLines` is a string",
         lambda: _fails(_set("stderrLines", "0"), "`stderrLines` is not")),
        ("fails when the sidecar names another command",
         lambda: _fails(_set("command", start.command + " extra"), "`command`")),
        ("fails when the sidecar names another working directory",
         lambda: _fails(_set("workingDirectory", "verifiers/python"), "`workingDirectory`")),
        ("fails when the sidecar records exit code 1",
         lambda: _fails(_set("exitCode", 1), "`exitCode`")),
        ("fails when the sidecar's summary is not the capture's last line",
         lambda: _fails(_set("summary", summary.replace("pass", "passed")), "`summary`")),
        ("fails when the sidecar names another capture path",
         lambda: _fails(_set("outputs", {"capture": {**written()["outputs"]["capture"],
                                                     "path": "docs/captures/other.txt"}}),
                        "`outputs`")),
        ("write() records, for each path the command reads, the tree id "
         "`git rev-parse HEAD:<path>` gives on the commit holding the inputs",
         lambda: written()["inputTrees"] == published()[2]
         and list(published()[2]) == written()["inputs"]),
        ("fails when the sidecar lists other inputs",
         lambda: _fails(_set("inputs", written()["inputs"][:1]), "`inputs`")),
        ("fails when `inputTrees` records another tree for an input",
         lambda: _fails(_set("inputTrees", {**written()["inputTrees"],
                                            start.working_directory: "0" * 40}),
                        "`inputTrees`")),
        ("fails when a file under an input path changes after the capture",
         lambda: _fails(lambda root, s: (root / s.working_directory / INPUT).write_text(
             "changed\n", encoding="utf-8"), "`inputTrees`")),
        ("fails when a file is added under an input path after the capture",
         lambda: _fails(lambda root, s: (root / s.working_directory / "added.txt").write_text(
             "added\n", encoding="utf-8"), "`inputTrees`")),
        ("fails when the tree is not a git work tree",
         lambda: _fails(lambda root, s: shutil.rmtree(root / ".git"),
                        "cannot read the git tree ids")),
        ("fails when `ranAtUtc` is not a UTC time",
         lambda: _fails(_set("ranAtUtc", "2000-01-01 00:00:00"), "`ranAtUtc`")),
        ("fails when a token of a kept excerpt line is edited",
         lambda: _fails(_edit(_readme, kept, kept.replace("ACCEPT", "REJECT")),
                        "are not the next run")),
        ("fails when the excerpt's two runs are swapped",
         lambda: _fails(_excerpt(_swap_runs), "are not the next run")),
        ("fails when the elision line is removed and the runs are joined",
         lambda: _fails(_excerpt(lambda e: [x for x in e if x != ELISION]),
                        "are not the next run")),
        ("fails when an elision line opens the excerpt",
         lambda: _fails(_excerpt(lambda e: [ELISION, *e]), "opens or closes")),
        ("fails when the label does not say trimmed and the excerpt elides lines",
         lambda: _fails(_edit(_readme, f"]({start.capture}), trimmed):", f"]({start.capture})):"),
                        "does not say trimmed")),
        ("fails when the label names another command than the first command",
         lambda: _fails(_edit(_readme, f"What `{start.command}`", f"What `{start.command} -v`"),
                        "the label names")),
        ("fails when the label links another capture",
         lambda: _fails(_edit(_readme, f"]({start.capture})", "](docs/captures/other.txt)"),
                        "docs/captures/other.txt missing")),
        ("fails when the first command is not `cd <dir> && <command>`",
         lambda: _fails(_edit(_readme, f"cd {start.working_directory} && ", ""),
                        "is not one line")),
        ("check_tree exits 1 and prints the failure when the sidecar is missing",
         check_tree_names_missing_sidecar),
        ("a capture taken on a branch passes in a fresh clone of `main` after a squash merge, "
         "and each object id its sidecar records resolves there", squash_passes),
        ("with GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE naming another repository, as git "
         "exports them to a hook, the squash-merge case passes and that repository's files "
         "are unchanged", hook_env_squash_passes),
        ("with the copy inside another repository's work tree, the not-a-git-work-tree case "
         "fails as named and that repository's files are unchanged", nested_no_work_tree_fails),
        ("--help prints usage", lambda: _main_on(["--help"])[:2] == (0, USAGE)),
        ("-h prints usage", lambda: _main_on(["-h"])[:2] == (0, USAGE)),
        ("an unknown argument prints usage to stderr and exits 2",
         lambda: _main_on(["--bogus"]) == (2, "", USAGE)),
        ("the docstring's Usage block is USAGE",
         lambda: __doc__ is None or __doc__.endswith(USAGE)),
    ]


def self_test() -> int:
    start, failures = read_start(REPO_ROOT)
    if start is None:
        for f in failures:
            print(f"FAIL {f}")
        return 1

    def without_git() -> bool:
        with tempfile.TemporaryDirectory() as empty:
            return _red_with(start, {"PATH": empty}, "No such file or directory: 'git'")

    def with_failing_git() -> bool:
        # A `git` that exits 128, as git does when it cannot read its
        # configuration, is the only command on PATH. It fails whatever
        # environment git is run with.
        with tempfile.TemporaryDirectory() as bin_dir:
            stub = Path(bin_dir) / "git"
            stub.write_text("#!/bin/sh\necho 'fatal: self-test git' >&2\nexit 128\n",
                            encoding="utf-8")
            stub.chmod(0o755)
            return _red_with(start, {"PATH": bin_dir}, "` exited 128")

    return _report([
        *_cases(start),
        ("with no git on PATH, the cases above exit 1 after the summary line, and each red "
         "one prints the missing git under its label", without_git),
        ("with a git on PATH that exits 128, the cases above exit 1 after the summary line, "
         "and each red one prints the git command and its exit code", with_failing_git),
    ])


def main(argv: list[str], root: Path = REPO_ROOT) -> int:
    if argv in (["-h"], ["--help"]):
        print(USAGE, end="")
        return 0
    if argv == ["--self-test"]:
        return self_test()
    if argv == ["--check"]:
        return self_test() or check_tree(root)
    if argv:
        print(USAGE, end="", file=sys.stderr)
        return 2
    return write(root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
