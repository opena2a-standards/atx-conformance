#!/usr/bin/env python3
"""Write (or verify) the capture of README.md's Go verifier run and its sidecar.

README.md opens with one command in a fenced block, `cd <dir> && <command>`,
then a label line, "What `<command>` prints ([full output](<capture>),
trimmed):", and a fenced excerpt of that output. This script reads the
working directory, the command and the capture path from those lines, runs
the command there, and writes its standard output to the capture
(docs/captures/go-verifier.txt) and a sidecar beside it with the same name
ending in .json. The sidecar says how the capture was taken: the command
and its working directory, the Go release and platform, the commit, the
uncommitted files under the paths the command reads, the time, the exit
code, the number of lines written to standard error (not captured), the
summary line, and the capture's SHA-256 and byte and line counts. A run
that exits non-zero, prints no `summary:` line last, or prints bytes that
are not UTF-8 writes nothing.

`--check` runs no command and needs no Go toolchain. It fails when the
sidecar is missing, is not a JSON object, lacks a member or holds one of
the wrong type, names another command, working directory or capture than
README.md, records a non-zero exit code, or does not describe the committed
capture's bytes and last line; and when README.md's excerpt is not the
capture's lines, in order, with a line holding only `...` standing for the
lines left out. It runs the self-test first.

Usage:
    python3 scripts/capture_go_verifier.py              # run README.md's Go command, (re)write the capture and its sidecar
    python3 scripts/capture_go_verifier.py --check      # exit 1 if the sidecar, the capture and README.md's excerpt disagree
    python3 scripts/capture_go_verifier.py --self-test  # prove each altered capture, sidecar or excerpt fails
    python3 scripts/capture_go_verifier.py --help       # print this usage
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import io
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = "README.md"
# Not sliced from __doc__, which `python -OO` strips. The self-test holds the
# docstring's Usage block equal to this text.
USAGE = """\
Usage:
    python3 scripts/capture_go_verifier.py              # run README.md's Go command, (re)write the capture and its sidecar
    python3 scripts/capture_go_verifier.py --check      # exit 1 if the sidecar, the capture and README.md's excerpt disagree
    python3 scripts/capture_go_verifier.py --self-test  # prove each altered capture, sidecar or excerpt fails
    python3 scripts/capture_go_verifier.py --help       # print this usage
"""

START = re.compile(r"cd (?P<dir>[^\s&;|]+) && (?P<cmd>[^&;|`]+)")
LABEL = re.compile(r"What `(?P<cmd>[^`]+)` prints "
                   r"\(\[full output\]\((?P<path>docs/captures/[^)/\s]+\.txt)\)(?P<trimmed>, trimmed)?\):")
ELISION = "..."
SUMMARY = "summary: "
COMMIT = re.compile(r"[0-9a-f]{40}")
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
# Sidecar members, in the order they are written, and the type each holds.
MEMBERS: tuple[tuple[str, type], ...] = (
    ("command", str), ("workingDirectory", str), ("stream", str), ("goVersion", str),
    ("platform", str), ("commit", str), ("inputs", list), ("inputsUncommitted", list),
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
    expected = {
        "command": start.command,
        "workingDirectory": start.working_directory,
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
    if not COMMIT.fullmatch(doc["commit"]):
        failures.append(f"{start.sidecar}: `commit` is not a 40-character commit id")
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


def describe(root: Path, start: Start) -> dict:
    workdir = root / start.working_directory
    version, goos, goarch = _output(["go", "env", "GOVERSION", "GOOS", "GOARCH"], workdir)
    paths = inputs(root, start)
    uncommitted = sorted(set(
        _output(["git", "diff", "--name-only", "HEAD", "--", *paths], root)
        + _output(["git", "ls-files", "--others", "--exclude-standard", "--", *paths], root)))
    return {
        "goVersion": version,
        "platform": f"{goos}/{goarch}",
        "commit": _output(["git", "rev-parse", "HEAD"], root)[0],
        "inputs": paths,
        "inputsUncommitted": uncommitted,
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
        print(f"cannot read the Go release or the commit ({exc}); nothing written")
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
# that is already stale does not make every case look red-as-expected.

FAKE_COMMIT = "0" * 40


def _fake_describe(root: Path, start: Start) -> dict:
    return {"goVersion": "go-test", "platform": "test/test", "commit": FAKE_COMMIT,
            "inputs": inputs(root, start), "inputsUncommitted": [],
            "ranAtUtc": "2000-01-01T00:00:00Z"}


@contextlib.contextmanager
def _tree(published: Path = REPO_ROOT):
    """A temporary copy of README.md and its capture, a sidecar written for
    them, and the start block read from the copy."""
    start, failures = read_start(published)
    if start is None:
        raise SystemExit("\n".join(failures))
    data = (published / start.capture).read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / start.working_directory).mkdir(parents=True)
        (root / start.capture).parent.mkdir(parents=True)
        shutil.copyfile(published / README, root / README)
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


def self_test() -> int:
    start, failures = read_start(REPO_ROOT)
    if start is None:
        for f in failures:
            print(f"FAIL {f}")
        return 1
    data = (REPO_ROOT / start.capture).read_bytes()
    capture = _lines(data.decode("utf-8"))
    with _tree() as (root, _):
        baseline = check(root)
        written = json.loads((root / start.sidecar).read_text(encoding="utf-8"))
    summary = capture[-1]
    first = start.excerpt[0]
    kept = next(line for line in start.excerpt if "observed: ACCEPT" in line)
    ok_run = Run(data, b"", 0)
    write_rc, write_nothing, write_seen = _write_on(ok_run)
    fail_rc, fail_nothing, _ = _write_on(Run(data, b"", 1))
    nosum_rc, nosum_nothing, _ = _write_on(Run(data.replace(summary.encode(), b"done"), b"", 0))
    bin_rc, bin_nothing, _ = _write_on(Run(data + b"\xff\n" + summary.encode() + b"\n", b"", 0))
    tree_rc, tree_out = _check_tree_on(lambda root, s: (root / s.sidecar).unlink())
    help_rc, help_out, _ = _main_on(["--help"])
    h_rc, h_out, _ = _main_on(["-h"])
    bad_rc, bad_out, bad_err = _main_on(["--bogus"])
    cases: list[tuple[str, bool]] = [
        ("the published README.md and capture, with a sidecar written for them, pass",
         not baseline),
        ("write() records the published capture's line count and last line",
         written["outputs"]["capture"]["lines"] == len(capture) and written["summary"] == summary),
        ("inputs() lists the working directory and the fixture directory",
         inputs(REPO_ROOT, start) == ["verifiers/go", "fixtures"]),
        ("write() writes the sidecar members in order",
         list(written) == [name for name, _ in MEMBERS]),
        ("write() runs README.md's command as argv in its working directory",
         write_rc == 0 and not write_nothing
         and write_seen == [(shlex.split(start.command), start.working_directory)]),
        ("write() writes nothing when the command exits 1", fail_rc == 1 and fail_nothing),
        ("write() writes nothing when the last line is not a summary line",
         nosum_rc == 1 and nosum_nothing),
        ("write() writes nothing when the output is not UTF-8", bin_rc == 1 and bin_nothing),
        ("fails when the capture's first token is edited",
         _fails(_edit(_capture, first, first.replace("PASS", "FAIL", 1)), "`outputs`")),
        ("fails when a line is appended to the capture",
         _fails(lambda root, s: (root / s.capture).write_bytes(data + b"extra\n"), "`outputs`")),
        ("fails when the capture is missing",
         _fails(lambda root, s: (root / s.capture).unlink(), f"{start.capture} missing")),
        ("fails when the sidecar is missing",
         _fails(lambda root, s: (root / s.sidecar).unlink(), f"{start.sidecar} missing")),
        ("fails when the sidecar is not JSON",
         _fails(lambda root, s: (root / s.sidecar).write_text("{", encoding="utf-8"), "not JSON")),
        ("fails when the sidecar is a JSON array",
         _fails(lambda root, s: (root / s.sidecar).write_text("[]", encoding="utf-8"),
                "not a JSON object")),
        *((f"fails when the sidecar has no `{name}` member",
           _fails(_set(name, _DROP), f"no `{name}` member")) for name, _ in MEMBERS),
        ("fails when `exitCode` is true", _fails(_set("exitCode", True), "`exitCode` is not")),
        ("fails when `stderrLines` is a string",
         _fails(_set("stderrLines", "0"), "`stderrLines` is not")),
        ("fails when the sidecar names another command",
         _fails(_set("command", start.command + " extra"), "`command`")),
        ("fails when the sidecar names another working directory",
         _fails(_set("workingDirectory", "verifiers/python"), "`workingDirectory`")),
        ("fails when the sidecar records exit code 1", _fails(_set("exitCode", 1), "`exitCode`")),
        ("fails when the sidecar's summary is not the capture's last line",
         _fails(_set("summary", summary.replace("pass", "passed")), "`summary`")),
        ("fails when the sidecar names another capture path",
         _fails(_set("outputs", {"capture": {**written["outputs"]["capture"],
                                             "path": "docs/captures/other.txt"}}), "`outputs`")),
        ("fails when `commit` is not a commit id", _fails(_set("commit", "HEAD"), "`commit`")),
        ("fails when `ranAtUtc` is not a UTC time",
         _fails(_set("ranAtUtc", "2000-01-01 00:00:00"), "`ranAtUtc`")),
        ("fails when a token of a kept excerpt line is edited",
         _fails(_edit(_readme, kept, kept.replace("ACCEPT", "REJECT")), "are not the next run")),
        ("fails when the excerpt's two runs are swapped",
         _fails(_excerpt(_swap_runs), "are not the next run")),
        ("fails when the elision line is removed and the runs are joined",
         _fails(_excerpt(lambda e: [x for x in e if x != ELISION]), "are not the next run")),
        ("fails when an elision line opens the excerpt",
         _fails(_excerpt(lambda e: [ELISION, *e]), "opens or closes")),
        ("fails when the label does not say trimmed and the excerpt elides lines",
         _fails(_edit(_readme, f"]({start.capture}), trimmed):", f"]({start.capture})):"),
                "does not say trimmed")),
        ("fails when the label names another command than the first command",
         _fails(_edit(_readme, f"What `{start.command}`", f"What `{start.command} -v`"),
                "the label names")),
        ("fails when the label links another capture",
         _fails(_edit(_readme, f"]({start.capture})", "](docs/captures/other.txt)"),
                "docs/captures/other.txt missing")),
        ("fails when the first command is not `cd <dir> && <command>`",
         _fails(_edit(_readme, f"cd {start.working_directory} && ", ""), "is not one line")),
        ("check_tree exits 1 and prints the failure when the sidecar is missing",
         tree_rc == 1 and f"FAIL {start.sidecar} missing" in tree_out),
        ("--help prints usage", help_rc == 0 and help_out == USAGE),
        ("-h prints usage", h_rc == 0 and h_out == USAGE),
        ("an unknown argument prints usage to stderr and exits 2",
         bad_rc == 2 and bad_err == USAGE and not bad_out),
        ("the docstring's Usage block is USAGE", __doc__ is None or __doc__.endswith(USAGE)),
    ]
    failed = 0
    for label, ok in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        failed += not ok
    print(f"capture-go-verifier self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


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
