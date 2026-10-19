#!/usr/bin/env python3
"""Cross-implementation parity gate.

Runs every reference verifier in this repository over the byte-pinned
fixture set and asserts that all implementations agree per fixture on:

  1. gate status   -- PASS/FAIL against the fixture's pinned `expected` block
  2. verdict       -- ACCEPT vs REJECT
  3. reject category (when REJECT)

The verifiers already self-check against each fixture's `expected` block, so
a green run of each verifier proves agreement with the pinned oracle. This
script makes the cross-implementation agreement explicit and machine-readable:
it fails if any verifier skips a fixture the other saw, disagrees on verdict
or category, or exits non-zero.

Both verifiers verify both declared signature suites: Ed25519 and ML-DSA-65
(FIPS 204), each over the same canonical payload (v1.1 JCS(TBS), v1.0 pipe
form). Per-fixture agreement on verdict and category is therefore fully
cryptographic on the hybrid fixtures, including the forged-post-quantum
control fixtures/v1_1-hybrid-mldsa-tampered.json.

A verifier that exits non-zero has its stderr relayed in the report. One that
exits non-zero before reporting any fixture (a missing dependency, a bad
argument) is reported by that exit and stderr alone, not as a fixture set
mismatch naming every fixture it never reached, and has one line above the
per-fixture table in place of a MISSING cell on every row. The --json report
names it in `unreported`.

After the fixture table the gate runs the argument table, ARGUMENT_CASES:
argument lists no fixture can carry (an empty argument, -h and --help at
several positions, --version and an unknown option after a path, an
unknown option that is not UTF-8, - alone, a repository root, a directory
whose `fixtures` entry is a file, a path that does not exist, a path that
is not UTF-8, a file whose name is not UTF-8 and a directory holding it, a
directory with no *.json, a directory holding a subdirectory named *.json,
a directory holding a symbolic link to a fixture and one holding a link to
a directory, a directory that cannot be listed and a repository root whose
`fixtures` directory cannot be, a file that cannot be read, its name UTF-8
or not, spelled with ./ and // and found in a directory, a path named
twice, a file spelled with ./ and // and one spelled with .., a directory
spelled with ./ and // and one spelled with .., a directory spelled with a
.. after a symbolic link, with a trailing / and without, a file named with
a trailing /, a path and an option after `--`, an absolute path through a
symbolic link to the working directory, through its target, with a ..
after a symbolic link and outside it), each run on both
verifiers from a symbolic link to a scratch directory holding the paths it
names, with PWD naming the link, as a shell names a directory it changed
into through one. Both must exit with the same code and write the same
first stderr line and the same verdict lines (each PASS or FAIL line, with
the load error a FAIL line names, its observed verdict and category, the
summary), once the program name each
verifier calls itself (`atx-verify`, `verify.py`) is stripped; a case they
differ on is a divergence. A byte of their output that is not UTF-8 is read
as a surrogate escape, so the byte 0xff and the six characters \\udcff
differ. Where the file system refuses a file name that is not UTF-8, as
APFS does, the three cases that need one are skipped, not run: their rows say
so, a skipped case is no divergence, and the PASS line counts them. Only
EILSEQ or EINVAL, raised writing the scratch file so named, is a refusal;
another error writing it, ENOSPC for one, is raised, and the gate exits 1. No
argument and -- alone, which names no path either, are the two cases the
two answer differently by design: on each the Go verifier must verify the
fixture set its module embeds, each fixture passing, and exit 0, and the
Python verifier, which has none, must write its usage and exit 2; any
other outcome is a divergence. The Go verifier runs there as a binary
built for the table, since `go run` reports a program's exit 2 as its own
exit 1. The --json report holds the table under `arguments`.

Every run starts with the self-test, which proves on stand-in verifiers that
the gate reports a disagreement, a skipped fixture, a failed verifier and a
verifier that exits 0 without reporting any fixture, that a fixtures
directory holding no *.json fails, that the --json report names a verifier
that exited before reporting any fixture, that an argument case one
verifier answers with another exit code, first stderr line or verdict lines,
the load error a FAIL line names included, fails the gate, as does a
verifier that answers no argument or -- alone other than its
spec says, that the cases with an absolute path via the link and via its
target run from a symbolic link with PWD naming it, that the cases needing a
file name that is not UTF-8 are skipped where the file system refuses one,
whatever the verifiers would write, and counted in the PASS line, that of
the errors writing the scratch file so named, EILSEQ and EINVAL are
refusals and ENOSPC, EACCES, EROFS and EIO are raised, by the gate for
ENOSPC, that --json is refused
with --self-test by a usage message the self-test holds word for word, so
rewording that message turns the self-test red, and that an unknown
argument is named on the line above the usage.

Usage:
    python3 scripts/parity/parity.py [--json parity-report.json]
    python3 scripts/parity/parity.py --self-test

--self-test writes no parity report, so it is refused with --json rather than
leaving the report path unwritten.

Exit codes:
    0  all implementations agree; with --self-test, every case is green
    1  a divergence or verifier error, a red self-test case (every run
       starts with the self-test), or no *.json in fixtures/
    2  usage error
"""
from __future__ import annotations

import argparse
import contextlib
import errno
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# Not sliced from __doc__, which `python -OO` strips. The self-test holds the
# docstring's Exit codes block equal to this text.
EXIT_CODES = """\
Exit codes:
    0  all implementations agree; with --self-test, every case is green
    1  a divergence or verifier error, a red self-test case (every run
       starts with the self-test), or no *.json in fixtures/
    2  usage error
"""
# The failure for a fixtures directory holding no *.json, in main and in the
# self-test.
NO_FIXTURES = "[parity] no fixtures found\n"

VERIFIERS = {
    "go": {
        "cwd": REPO_ROOT / "verifiers" / "go",
        "cmd": ["go", "run", ".", "../../fixtures"],
    },
    "python": {
        "cwd": REPO_ROOT / "verifiers" / "python",
        "cmd": [sys.executable, "verify.py", "../../fixtures"],
    },
}

# `PASS  <path>` or `FAIL  <path>` opens a per-fixture block. A fixture that
# fails to load has no block: its FAIL line names the load error after the
# path, `FAIL  <path>  (load error: <reason>)`.
BLOCK_RE = re.compile(r"^(PASS|FAIL)\s+(\S+)(?:\s+(\(load error: .*\)))?")
# `observed: ACCEPT` or `observed: REJECT[CATEGORY: reason]`
OBSERVED_RE = re.compile(r"^\s*observed:\s+(ACCEPT|REJECT\[([A-Z_]+))")

# The argument table: (case, arguments). Each list runs from a symbolic link
# to a scratch directory _argument_scratch lays out, with PWD naming the
# link: fixfile/ holds a file named fixtures and ARGUMENT_FIXTURE as x.json,
# root/ holds ARGUMENT_FIXTURE as fixtures/x.json beside conformance.json, a
# *.json that is not a fixture, as a repository root does, nojson/ holds no
# *.json, subdir/ holds ARGUMENT_FIXTURE as x.json beside a directory named
# sub.json, filelink/ holds link.json, a symbolic link to fixfile/x.json,
# dirlink/ holds link.json, a symbolic link to away/deep, locked/ holds
# ARGUMENT_FIXTURE as x.json and has mode 000 while the cases run,
# lockedroot/ holds ARGUMENT_FIXTURE as fixtures/x.json, its fixtures/ of
# mode 000 while the cases run, noread/ holds ARGUMENT_FIXTURE as x.json
# and, where the file system takes that name, as {xff}.json, each of mode
# 000, hop/link is a symbolic link to away/deep, away/ holding
# ARGUMENT_FIXTURE as x.json, -h.json is ARGUMENT_FIXTURE, xff/ holds
# ARGUMENT_FIXTURE as {xff}.json where the file system takes that name, and
# nothing there is named missing or -. In an argument, {link} is the link's
# absolute path, {target} the directory's, its symbolic links resolved,
# {fixture} the absolute path of the fixture the table copies, outside both,
# and {xff} NOT_UTF8, which as a whole argument names nothing there either.
ARGUMENT_CASES: list[tuple[str, list[str]]] = [
    ("no argument", []),
    ("-- alone", ["--"]),
    ("an empty argument", [""]),
    ("--help first", ["--help", "fixfile"]),
    ("--help last", ["fixfile", "--help"]),
    ("--help between two paths", ["fixfile/x.json", "--help", "fixfile"]),
    ("-h alone", ["-h"]),
    ("--version after a path", ["fixfile", "--version"]),
    ("an unknown option after a path", ["fixfile", "--bogus"]),
    ("an unknown option that is not UTF-8", ["-{xff}"]),
    ("- alone", ["-"]),
    ("a repository root", ["root"]),
    ("a fixtures entry that is a file", ["fixfile"]),
    ("a path that does not exist", ["missing"]),
    ("a path that is not UTF-8", ["{xff}"]),
    ("a file whose name is not UTF-8", ["xff/{xff}.json"]),
    ("a directory whose file name is not UTF-8", ["xff"]),
    ("a directory with no *.json", ["nojson"]),
    ("a subdirectory named *.json", ["subdir"]),
    ("a directory holding a link to a fixture", ["filelink"]),
    ("a directory holding a link to a directory", ["dirlink"]),
    ("a directory that cannot be listed", ["locked"]),
    ("a repository root whose fixtures cannot be listed", ["lockedroot"]),
    ("a file that cannot be read", ["noread/x.json"]),
    ("a file that cannot be read spelled with ./ and //", ["./noread//x.json"]),
    ("a directory holding a file that cannot be read", ["noread"]),
    ("a file that cannot be read whose name is not UTF-8", ["noread/{xff}.json"]),
    ("a path named twice", ["fixfile/x.json", "fixfile/x.json"]),
    ("a file spelled with ./ and //", ["fixfile//x.json", "./fixfile/./x.json"]),
    ("a file spelled with ..", ["fixfile/../fixfile/x.json"]),
    ("a directory spelled with ./ and //", [".//fixfile"]),
    ("a directory spelled with ..", ["fixfile/../fixfile"]),
    ("a .. after a symbolic link", ["hop/link/.."]),
    ("a .. after a symbolic link, with a trailing /", ["hop/link/../"]),
    ("a file named with a trailing /", ["fixfile/x.json/"]),
    ("a path after --", ["--", "-h.json"]),
    ("an option after --", ["--", "-h.json", "--help"]),
    ("an absolute path via the link", ["{link}/fixfile/x.json"]),
    ("an absolute path via its target", ["{target}/fixfile/x.json"]),
    ("an absolute path with a .. after a symbolic link", ["{link}/hop/link/../x.json"]),
    ("an absolute path outside the cwd", ["{fixture}"]),
]
# The argument lists that name no path: no argument, and -- alone, which ends
# the options and names nothing. The verifiers answer each differently by
# design, as _answers_no_argument says.
NO_PATH_ARGUMENTS: tuple[list[str], ...] = ([], ["--"])
# The directories _argument_scratch sets to mode 000. shutil.rmtree raises
# PermissionError on a directory it cannot list, so each is set to mode 755
# before scratch is removed.
LOCKED_DIRS = ("locked", "lockedroot/fixtures")
# The shipped fixture the argument table copies to fixfile/x.json.
ARGUMENT_FIXTURE = "baseline-valid.json"
# The argument {xff} stands for: the byte 0xff, which is not UTF-8, as
# sys.argv holds it, a surrogate escape, which subprocess passes as the byte.
NOT_UTF8 = os.fsdecode(b"\xff")
# The cases that need xff/{xff}.json or noread/{xff}.json, skipped where the
# file system refuses a name that is not UTF-8.
NOT_UTF8_NAME_CASES = (
    "a file whose name is not UTF-8", "a directory whose file name is not UTF-8",
    "a file that cannot be read whose name is not UTF-8",
)
# The errnos taken for a file system refusing that name: APFS raises EILSEQ,
# and exFAT on macOS EINVAL. An error writing xff/{xff}.json or
# noread/{xff}.json with another errno is raised, as an error writing another
# scratch file is.
NOT_UTF8_NAME_REFUSALS = (errno.EILSEQ, errno.EINVAL)
# Verdict lines an outcome in a report line names one by one; a longer run,
# such as the walk of a whole fixture set, is named by its count and last line.
SHOWN_VERDICT_LINES = 5


def run_verifier(name: str, spec: dict) -> tuple[int, dict[str, dict], str]:
    """Run one verifier; return (exit_code, {fixture_basename: record}, stderr)."""
    proc = subprocess.run(
        spec["cmd"], cwd=spec["cwd"], capture_output=True, text=True
    )
    records: dict[str, dict] = {}
    current: str | None = None
    for line in proc.stdout.splitlines():
        m = BLOCK_RE.match(line)
        if m:
            current = Path(m.group(2)).name
            records[current] = {"gate": m.group(1), "verdict": None, "category": None}
            continue
        if current is None:
            continue
        om = OBSERVED_RE.match(line)
        if om:
            if om.group(1) == "ACCEPT":
                records[current]["verdict"] = "ACCEPT"
            else:
                records[current]["verdict"] = "REJECT"
                records[current]["category"] = om.group(2)
    if proc.returncode != 0:
        sys.stderr.write(f"[parity] {name} verifier exited {proc.returncode}\n")
        sys.stderr.write(proc.stdout[-2000:] + proc.stderr[-2000:] + "\n")
    return proc.returncode, records, proc.stderr.strip()[-2000:]


def compare(
    fixture_files: list[str], verifiers: dict[str, dict]
) -> tuple[dict[str, dict], dict[str, int], list[str], list[str]]:
    """Run every verifier over fixture_files.

    Return (table, exit_codes, divergences, unreported), where unreported
    names each verifier that exited non-zero before reporting any fixture.
    """
    results: dict[str, dict[str, dict]] = {}
    exit_codes: dict[str, int] = {}
    divergences: list[str] = []
    unreported: list[str] = []
    for name, spec in verifiers.items():
        code, records, stderr = run_verifier(name, spec)
        exit_codes[name] = code
        results[name] = records
        if code != 0:
            d = f"{name} verifier exited {code} (expected 0)"
            if not records:
                d += " before reporting any fixture"
                unreported.append(name)
            divergences.append(f"{d}: {stderr}" if stderr else d)

    for name, records in results.items():
        # A verifier that failed before reporting any fixture is already
        # reported by its exit code and stderr; listing every fixture as
        # missing would hide that cause behind a fixture set mismatch.
        if name in unreported:
            continue
        seen = sorted(records)
        if seen != fixture_files:
            missing = set(fixture_files) - set(seen)
            extra = set(seen) - set(fixture_files)
            divergences.append(
                f"{name} fixture set mismatch: missing={sorted(missing)} extra={sorted(extra)}"
            )

    names = list(verifiers)
    table: dict[str, dict] = {}
    for fx in fixture_files:
        row = {n: results[n].get(fx) for n in names}
        table[fx] = row
        present = [n for n in names if row[n] is not None]
        for field in ("gate", "verdict", "category"):
            vals = {n: row[n][field] for n in present}
            if len(set(vals.values())) > 1:
                divergences.append(f"{fx}: {field} divergence {vals}")
    return table, exit_codes, divergences, unreported


def render_table(
    table: dict[str, dict], names: list[str],
    exit_codes: dict[str, int], unreported: list[str],
) -> list[str]:
    """Return the lines of the per-fixture table.

    A verifier that exited before reporting any fixture has no column: one
    line names its exit instead of a MISSING cell on every row, since its
    exit code and stderr are already in the summary below the table.
    """
    shown = [n for n in names if n not in unreported]
    lines = [f"parity: {len(table)} fixtures x {len(names)} verifiers"]
    for n in unreported:
        lines.append(
            f"  {n}: exited {exit_codes[n]} before reporting any fixture "
            "(see PARITY: FAIL below)"
        )
    if not shown:
        return lines
    for fx, row in table.items():
        cells = []
        for n in shown:
            r = row[n]
            if r is None:
                cells.append(f"{n}=MISSING")
            else:
                v = r["verdict"] or "?"
                cat = f"[{r['category']}]" if r["category"] else ""
                cells.append(f"{n}={r['gate']}:{v}{cat}")
        lines.append(f"  {fx:44s} {'  '.join(cells)}")
    return lines


def build_report(
    table: dict[str, dict], exit_codes: dict[str, int],
    divergences: list[str], unreported: list[str],
    arguments: list[dict] | None = None,
) -> dict:
    """Return the --json parity report.

    `unreported` names each verifier that exited before reporting any
    fixture, as the line above the table does, so a consumer need not infer
    it from a non-zero exit code and a null cell on every fixture.
    `arguments` is the argument table, one row per case in ARGUMENT_CASES
    order, empty when it did not run; a row's `skipped` names why the case
    was not run, null when it ran.
    """
    return {
        "fixtures": table,
        "arguments": arguments or [],
        "exitCodes": exit_codes,
        "unreported": unreported,
        "divergences": divergences,
        "agree": not divergences,
    }


# --- argument table ----------------------------------------------------------

class BuildError(Exception):
    """A verifier the argument table runs could not be built."""


def argument_verifiers(bin_dir: Path) -> dict[str, dict]:
    """The verifiers of the argument table: the argv a case's arguments
    follow, the program name the verifier calls itself, and whether it
    embeds a fixture set, which it verifies when given no argument.

    The Go verifier is built into bin_dir and run as that binary: `go run`
    reports a program's exit 2 as its own exit 1, and adds an
    `exit status 2` line to stderr.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    binary = bin_dir / "atx-verify"
    build = subprocess.run(
        ["go", "build", "-o", str(binary), "."],
        cwd=VERIFIERS["go"]["cwd"], capture_output=True, text=True,
    )
    if build.returncode != 0:
        raise BuildError(f"go build exited {build.returncode}: {build.stderr.strip()[-2000:]}")
    return {
        "go": {"argv": [str(binary)], "program": "atx-verify", "embeds": True},
        "python": {
            "argv": [sys.executable, str(VERIFIERS["python"]["cwd"] / "verify.py")],
            "program": "verify.py",
            "embeds": False,
        },
    }


def _argument_scratch(scratch: Path, fixture: Path) -> tuple[Path, str]:
    """Lay out under scratch/dir the paths ARGUMENT_CASES name, and return
    scratch/link, a symbolic link to it, which the cases run from, and the
    reason the file system refused xff/{xff}.json or noread/{xff}.json, ""
    when it took both. An error writing either file with an errno outside
    NOT_UTF8_NAME_REFUSALS is no refusal, and is raised."""
    root = scratch / "dir"
    (root / "fixfile").mkdir(parents=True)
    (root / "fixfile" / "fixtures").write_text("a file, not a directory\n")
    (root / "fixfile" / "x.json").write_bytes(fixture.read_bytes())
    (root / "root" / "fixtures").mkdir(parents=True)
    (root / "root" / "fixtures" / "x.json").write_bytes(fixture.read_bytes())
    (root / "root" / "conformance.json").write_text("{}\n")
    (root / "nojson").mkdir()
    (root / "nojson" / "README.md").write_text("not a fixture\n")
    (root / "subdir" / "sub.json").mkdir(parents=True)
    (root / "subdir" / "x.json").write_bytes(fixture.read_bytes())
    (root / "filelink").mkdir()
    (root / "filelink" / "link.json").symlink_to("../fixfile/x.json")
    (root / "dirlink").mkdir()
    (root / "dirlink" / "link.json").symlink_to("../away/deep", target_is_directory=True)
    (root / "locked").mkdir()
    (root / "locked" / "x.json").write_bytes(fixture.read_bytes())
    (root / "locked").chmod(0)
    (root / "lockedroot" / "fixtures").mkdir(parents=True)
    (root / "lockedroot" / "fixtures" / "x.json").write_bytes(fixture.read_bytes())
    (root / "lockedroot" / "fixtures").chmod(0)
    (root / "noread").mkdir()
    (root / "noread" / "x.json").write_bytes(fixture.read_bytes())
    (root / "noread" / "x.json").chmod(0)
    (root / "away" / "deep").mkdir(parents=True)
    (root / "away" / "x.json").write_bytes(fixture.read_bytes())
    (root / "hop").mkdir()
    (root / "hop" / "link").symlink_to("../away/deep", target_is_directory=True)
    (root / "-h.json").write_bytes(fixture.read_bytes())
    (root / "xff").mkdir()
    refusal = ""
    try:
        (root / "xff" / f"{NOT_UTF8}.json").write_bytes(fixture.read_bytes())
        (root / "noread" / f"{NOT_UTF8}.json").write_bytes(fixture.read_bytes())
        (root / "noread" / f"{NOT_UTF8}.json").chmod(0)
    except OSError as exc:
        if exc.errno not in NOT_UTF8_NAME_REFUSALS:
            raise
        refusal = f"the file system refuses a name that is not UTF-8 ({exc.strerror or exc})"
    link = scratch / "link"
    link.symlink_to("dir", target_is_directory=True)
    return link, refusal


def _without_program(line: str, program: str) -> str:
    """line without the program name it opens with or names after `usage: `,
    so the two verifiers' lines compare on their wording alone."""
    return re.sub(rf"^(usage:\s+)?{re.escape(program)}(?![\w.])", r"\1", line)


def verdict_lines(stdout: str) -> list[str]:
    """The report lines that carry a verdict: each `PASS  <path>` or
    `FAIL  <path>` line, with the load error a FAIL line names, its observed
    verdict and category, and the summary. The rest of a block is each
    verifier's own wording."""
    lines: list[str] = []
    for line in stdout.splitlines():
        if m := BLOCK_RE.match(line):
            lines.append(f"{m.group(1)}  {m.group(2)}" + (f"  {m.group(3)}" if m.group(3) else ""))
        elif m := OBSERVED_RE.match(line):
            lines.append(f"observed: {m.group(1)}" + ("]" if m.group(2) else ""))
        elif line.startswith("summary:"):
            lines.append(line)
    return lines


def run_case(spec: dict, args: list[str], cwd: Path) -> dict:
    """One verifier's outcome on one argument list, run from cwd with PWD
    naming it: its exit code, first stderr line and verdict lines, without
    its program name. Its output is read as UTF-8, a byte that is not UTF-8
    as a surrogate escape: read strictly, the byte 0xff the Go verifier
    writes for the argument {xff} raised UnicodeDecodeError."""
    proc = subprocess.run(
        spec["argv"] + args, cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="surrogateescape", env={**os.environ, "PWD": str(cwd)},
    )
    stderr = proc.stderr.splitlines()
    return {
        "exitCode": proc.returncode,
        "stderr": _without_program(stderr[0], spec["program"]) if stderr else "",
        "verdicts": [_without_program(v, spec["program"]) for v in verdict_lines(proc.stdout)],
    }


def _outcome(outcome: dict) -> str:
    text = f"exit {outcome['exitCode']}"
    if outcome["stderr"]:
        text += f", stderr {outcome['stderr']!r}"
    verdicts = outcome["verdicts"]
    if len(verdicts) > SHOWN_VERDICT_LINES:
        text += f", {len(verdicts)} verdict lines ending {verdicts[-1]!r}"
    elif verdicts:
        text += f", verdict lines {verdicts!r}"
    return text


def _outcomes(outcomes: dict[str, dict]) -> str:
    return "; ".join(f"{name} {_outcome(o)}" for name, o in outcomes.items())


def _answers_no_argument(spec: dict, outcome: dict, fixtures: list[str]) -> bool:
    """Whether outcome is the answer that spec documents to an argument
    list of NO_PATH_ARGUMENTS, no argument or -- alone: a verifier that
    embeds a fixture set reports it, here fixtures, each named
    fixtures/<name> and passing, and exits 0; one that embeds none writes
    its usage on stderr, reports nothing and exits 2."""
    verdicts = outcome["verdicts"]
    if not spec.get("embeds"):
        return outcome["exitCode"] == 2 and outcome["stderr"].startswith("usage:") and not verdicts
    n = len(fixtures)
    return (
        outcome["exitCode"] == 0 and outcome["stderr"] == ""
        and [v for v in verdicts if BLOCK_RE.match(v)] == [f"PASS  fixtures/{f}" for f in fixtures]
        and verdicts[-1:] == [f"summary: {n} pass, 0 fail ({n} fixtures)"]
    )


def compare_arguments(
    programs: dict[str, dict], fixture: Path, scratch: Path,
    cases: list[tuple[str, list[str]]] = ARGUMENT_CASES,
    refusal: str | None = None,
) -> tuple[list[dict], list[str]]:
    """Run every case of cases on every verifier in programs, from a
    symbolic link to scratch, with fixture as fixfile/x.json. A verifier that
    embeds a fixture set is taken to embed the *.json beside fixture.

    Return (rows, divergences): a row per case holding each verifier's
    outcome, and a divergence naming each case the outcomes differ on, or,
    for an argument list of NO_PATH_ARGUMENTS, are not each the one
    _answers_no_argument documents.
    A case of NOT_UTF8_NAME_CASES is skipped where the file system refused
    xff/{xff}.json: its row holds that reason under `skipped`, no outcome,
    and `agree` null, and it is no divergence. refusal, when given, stands
    in for the file system's answer, "" for a name it took, so the
    self-test runs those cases on stand-ins, which read no file, or skips
    them, on any file system.
    """
    cwd, refused = _argument_scratch(scratch, fixture)
    if refusal is not None:
        refused = refusal
    # str.format expands {link}, {target}, {fixture} and {xff}, so a
    # misspelt name raises instead of reaching a verifier as written.
    names = {
        "link": str(cwd), "target": os.path.realpath(cwd), "fixture": os.path.abspath(fixture),
        "xff": NOT_UTF8,
    }
    embedded = sorted(p.name for p in fixture.parent.glob("*.json"))
    rows: list[dict] = []
    divergences: list[str] = []
    try:
        for case, args in cases:
            if refused and case in NOT_UTF8_NAME_CASES:
                rows.append({"case": case, "args": args, "agree": None, "skipped": refused,
                             "outcomes": {}})
                continue
            argv = [arg.format(**names) for arg in args]
            outcomes = {name: run_case(spec, argv, cwd) for name, spec in programs.items()}
            if args in NO_PATH_ARGUMENTS:
                agree = all(_answers_no_argument(programs[name], o, embedded)
                            for name, o in outcomes.items())
            else:
                agree = len({json.dumps(o, sort_keys=True) for o in outcomes.values()}) == 1
            rows.append({"case": case, "args": args, "agree": agree, "skipped": None,
                         "outcomes": outcomes})
            if not agree:
                divergences.append(
                    f'argument case "{case}" ({shlex.join(args)}): {_outcomes(outcomes)}')
    finally:
        for name in LOCKED_DIRS:
            (cwd / name).chmod(0o755)
    return rows, divergences


def _argument_row(case: str, args: list[str], text: str) -> str:
    return f"  {case:32s} {shlex.join(args):30s} {text}"


def render_arguments(rows: list[dict]) -> list[str]:
    """Return the lines of the argument table: per case its arguments and
    the outcome the verifiers share, or each verifier's where they differ
    and for an argument list of NO_PATH_ARGUMENTS, which they answer
    differently by design, or why it was skipped."""
    if not rows:
        return ["arguments: not run (see PARITY: FAIL below)"]
    # A skipped row holds no outcome, so it does not count the verifiers.
    verifiers = max(len(row["outcomes"]) for row in rows)
    lines = [f"arguments: {len(rows)} cases x {verifiers} verifiers"]
    for row in rows:
        if row.get("skipped"):
            text = "skipped: " + row["skipped"]
        elif row["args"] in NO_PATH_ARGUMENTS:
            text = ("as documented: " if row["agree"] else "not as documented: ") \
                + _outcomes(row["outcomes"])
        elif row["agree"]:
            text = "agree: " + _outcome(next(iter(row["outcomes"].values())))
        else:
            text = "differ: " + _outcomes(row["outcomes"])
        lines.append(_argument_row(row["case"], row["args"], text))
    return lines


# --- self-test ---------------------------------------------------------------
# Stand-in verifiers print the PASS/FAIL block format the real ones print, so
# the self-test drives compare() through run_verifier() without Go, the
# fixtures or the Python verifier's dependencies.

MISSING_DEP = (
    "missing dependency: dilithium-py. install with `python3 -m pip install -r requirements.txt`"
)


def _stand_in(stdout: str, stderr: str = "", code: int = 0) -> dict:
    src = (
        "import sys\n"
        f"sys.stdout.write({stdout!r})\n"
        f"sys.stderr.write({stderr!r})\n"
        f"sys.exit({code})\n"
    )
    return {"cwd": REPO_ROOT, "cmd": [sys.executable, "-c", src]}


def _block(fixture: str, observed: str) -> str:
    return f"PASS  fixtures/{fixture}\n  observed: {observed}\n"


def _run(
    fixture_files: list[str], verifiers: dict[str, dict]
) -> tuple[list[str], list[str], dict]:
    """Return (divergences, table lines, --json report) for one run of the stand-ins."""
    with contextlib.redirect_stderr(io.StringIO()):
        table, exit_codes, divergences, unreported = compare(fixture_files, verifiers)
    return (
        divergences,
        render_table(table, list(verifiers), exit_codes, unreported),
        build_report(table, exit_codes, divergences, unreported),
    )


def _divergences(fixture_files: list[str], verifiers: dict[str, dict]) -> list[str]:
    return _run(fixture_files, verifiers)[0]


def _row(fixture: str, *cells: str) -> str:
    return f"  {fixture:44s} {'  '.join(cells)}"


def _usage_error(argv: list[str]) -> tuple[int, str] | None:
    """(exit code, last stderr line) when parse_args(argv) refuses argv, else None."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            parse_args(argv)
    except SystemExit as e:
        lines = err.getvalue().strip().splitlines()
        return e.code, lines[-1] if lines else ""
    return None


def _refusal(argv: list[str]) -> tuple[int, str] | None:
    """(exit code, all of stderr) when parse_args(argv) refuses argv, else None."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            parse_args(argv)
    except SystemExit as e:
        return e.code, err.getvalue()
    return None


def _gate_without_fixtures(verifiers: dict[str, dict]) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) of the gate over a directory with no *.json."""
    out, err = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "README.md").write_text("not a fixture\n")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = gate(Path(d), verifiers, None)
    return code, out.getvalue(), err.getvalue()


def _refuses_self_test_with_json() -> bool:
    """The usage-error case: --self-test with --json is refused, and each flag
    alone is accepted.

    The refusal is held to its message written out here, not built from
    SELF_TEST_JSON_ERROR: built from the constant parse_args() prints, it
    would match whatever the constant says, so no change to the wording could
    turn the case red.
    """
    return (
        _usage_error(["--self-test", "--json", "out.json"])
        == (2, "parity.py: error: --json cannot be used with --self-test: "
               "--self-test writes no parity report")
        and _usage_error(["--self-test"]) is None
        and _usage_error(["--json", "out.json"]) is None
    )


def _reworded(message: str) -> tuple[tuple[int, str] | None, bool]:
    """(the refusal of --self-test with --json, the usage-error case) while
    parse_args() refuses it with message in place of SELF_TEST_JSON_ERROR."""
    global SELF_TEST_JSON_ERROR
    kept = SELF_TEST_JSON_ERROR
    SELF_TEST_JSON_ERROR = message
    try:
        return (_usage_error(["--self-test", "--json", "out.json"]),
                _refuses_self_test_with_json())
    finally:
        SELF_TEST_JSON_ERROR = kept


def _argument_stand_in(
    program: str, outcomes: dict[tuple[str, ...], tuple[str, str, int]],
    embeds: bool = False,
) -> dict:
    """An argument-table stand-in calling itself program, embedding a
    fixture set or not: for an argument list outcomes holds it writes that
    stdout and stderr and exits with that code; for any other it writes
    nothing and exits 0. It writes each as the bytes os.fsencode gives, so a
    surrogate escape, NOT_UTF8 for one, is written as the byte it stands for,
    as the Go verifier writes an argument's bytes."""
    src = (
        "import os, sys\n"
        f"out, err, code = {outcomes!r}.get(tuple(sys.argv[1:]), ('', '', 0))\n"
        "sys.stdout.buffer.write(os.fsencode(out))\n"
        "sys.stderr.buffer.write(os.fsencode(err))\n"
        "sys.exit(code)\n"
    )
    return {"argv": [sys.executable, "-c", src], "program": program, "embeds": embeds}


def _naming_stand_in(program: str, wd: str) -> dict:
    """An argument-table stand-in calling itself program that reports each
    argument as a passing fixture, named relative to wd when under it: the
    directory PWD names, as the Go verifier's os.Getwd reads it, for "PWD",
    and the one os.getcwd() names, its links resolved, for "cwd". So the two
    verifiers named a path before both compared resolved paths."""
    src = (
        "import os, sys\n"
        f"wd = os.environ['PWD'] if {wd!r} == 'PWD' else os.getcwd()\n"
        "for a in sys.argv[1:]:\n"
        "    print('PASS  ' + (os.path.relpath(a, wd) if a.startswith(wd + os.sep) else a))\n"
    )
    return {"argv": [sys.executable, "-c", src], "program": program}


def _resolving_stand_in(program: str, clean_first: bool) -> dict:
    """An argument-table stand-in calling itself program that reports each
    argument as a passing fixture, named relative to the working directory
    when under it, both with their symbolic links resolved: the directory
    holding the argument resolved as spelled, each .. applied after the
    element before it is resolved, as the operating system applies it, or,
    for clean_first, cleaned first, as os.path.normpath cleans it, which
    removes a .. with the element before it. So one resolves the directory
    of an absolute path with a .. after a symbolic link as both verifiers
    do, and the other as both did before they resolved it as spelled."""
    src = (
        "import os, sys\n"
        "wd = os.path.realpath(os.getcwd())\n"
        "for a in sys.argv[1:]:\n"
        f"    d, f = os.path.split(os.path.normpath(a) if {clean_first!r} else a)\n"
        "    p = os.path.join(os.path.realpath(d), f)\n"
        "    print('PASS  ' + (os.path.relpath(p, wd) if p.startswith(wd + os.sep) else a))\n"
    )
    return {"argv": [sys.executable, "-c", src], "program": program}


def _argument_rows(
    programs: dict[str, dict], *cases: str, refusal: str = "",
) -> tuple[list[dict], list[str]]:
    """The rows and divergences of the argument-table cases named cases, run
    on stand-ins, refusal standing in for the file system's answer to
    xff/{xff}.json: "", which runs the cases that need it on any file
    system, or the reason it refused the name."""
    run = [(case, args) for case, args in ARGUMENT_CASES if case in cases]
    if len(run) != len(cases):
        raise ValueError(f"not every one of {cases} is a case of ARGUMENT_CASES")
    with tempfile.TemporaryDirectory() as d:
        fixture = Path(d) / ARGUMENT_FIXTURE
        fixture.write_text("{}\n")
        return compare_arguments(programs, fixture, Path(d) / "run", run, refusal)


def _argument_divergences(programs: dict[str, dict], *cases: str) -> list[str]:
    """The divergences of the argument-table cases named cases, run on
    stand-ins on any file system."""
    return _argument_rows(programs, *cases)[1]


def _gate_with_arguments(
    programs: Callable[[Path], dict[str, dict]], refusal: str | None = "",
) -> tuple[int, str, dict]:
    """(exit code, stdout, --json report) of the gate over one fixture the
    fixture-table stand-ins agree on, with programs giving the argument
    table's verifiers, every case run on any file system or, given a
    refusal, the cases needing a name that is not UTF-8 skipped, or, given
    None, the file system's answer to xff/{xff}.json deciding."""
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as d:
        fixtures, report = Path(d) / "fixtures", Path(d) / "report.json"
        fixtures.mkdir()
        (fixtures / ARGUMENT_FIXTURE).write_text("{}\n")
        agree = _stand_in(_block(ARGUMENT_FIXTURE, "ACCEPT"))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = gate(fixtures, {"one": agree, "two": agree}, str(report), programs, refusal)
        return code, out.getvalue(), json.loads(report.read_text())


def _not_built(bin_dir: Path) -> dict[str, dict]:
    raise BuildError("go build exited 1: boom")


def _writing_xff_raising(error: int, run: Callable[[], object]) -> object:
    """What run returns while writing xff/{xff}.json raises an OSError with
    errno error, on any file system, or the errno of the OSError run raises."""
    write_bytes = Path.write_bytes

    def failing(path: Path, data: bytes) -> int:
        if path.name == f"{NOT_UTF8}.json":
            raise OSError(error, os.strerror(error))
        return write_bytes(path, data)

    try:
        with mock.patch.object(Path, "write_bytes", failing):
            return run()
    except OSError as exc:
        return exc.errno


def _scratch_refusal() -> str:
    """The refusal _argument_scratch returns for xff/{xff}.json, laying out
    a scratch directory with a fixture of {}."""
    with tempfile.TemporaryDirectory() as d:
        fixture, scratch = Path(d) / ARGUMENT_FIXTURE, Path(d) / "run"
        fixture.write_text("{}\n")
        try:
            return _argument_scratch(scratch, fixture)[1]
        finally:
            # As compare_arguments does, so the scratch can be removed.
            for name in LOCKED_DIRS:
                (scratch / "dir" / name).chmod(0o755)


def self_test() -> int:
    fx = ["a.json", "b.json"]
    both = _block("a.json", "ACCEPT") + _block("b.json", "REJECT[EXPIRED: past expiry]")
    agree = _divergences(fx, {"one": _stand_in(both), "two": _stand_in(both)})
    flipped = _divergences(fx, {
        "one": _stand_in(both),
        "two": _stand_in(_block("a.json", "ACCEPT") + _block("b.json", "ACCEPT")),
    })
    skipped = _divergences(fx, {
        "one": _stand_in(both), "two": _stand_in(_block("a.json", "ACCEPT")),
    })
    no_dep, no_dep_table, no_dep_report = _run(fx, {
        "one": _stand_in(both), "two": _stand_in("", MISSING_DEP + "\n", 2),
    })
    crashed, crashed_table, crashed_report = _run(fx, {
        "one": _stand_in(both),
        "two": _stand_in(_block("a.json", "ACCEPT"), "Traceback: boom\n", 1),
    })
    silent = _divergences(fx, {"one": _stand_in(both), "two": _stand_in("")})
    _, none_ran, none_ran_report = _run(fx, {
        "one": _stand_in("", MISSING_DEP + "\n", 2),
        "two": _stand_in("", "", 1),
    })
    no_fixtures = _gate_without_fixtures({"one": _stand_in(both), "two": _stand_in(both)})
    unknown = _refusal(["--bogus"])

    # Argument-table stand-ins: "one", which embeds a fixture set, writes kept
    # for twenty-nine cases and for no argument and -- alone its report of
    # that set, the ARGUMENT_FIXTURE beside the table's fixture; "two", which
    # embeds none, writes kept and for no argument and -- alone its usage,
    # with one case's outcome changed. A case is run alone, by name, except
    # in the gate runs, which run the whole table.
    empty_case, fixfile_case, missing_case = (
        "an empty argument", "a fixtures entry that is a file", "a path that does not exist")
    version_case, unknown_case, root_case = (
        "--version after a path", "an unknown option after a path", "a repository root")
    spelled_case, dotdot_case, slash_case = (
        "a file spelled with ./ and //", "a directory spelled with ..",
        "a file named with a trailing /")
    twice_case, no_argument_case, dashdash_case = (
        "a path named twice", "no argument", "a path after --")
    link_case, target_case = "an absolute path via the link", "an absolute path via its target"
    link_dotdot_case, subdir_case = "a .. after a symbolic link", "a subdirectory named *.json"
    locked_case, xff_case = "a directory that cannot be listed", "a path that is not UTF-8"
    xff_file_case, xff_dir_case = (
        "a file whose name is not UTF-8", "a directory whose file name is not UTF-8")
    unread_case, unread_xff_case = (
        "a file that cannot be read", "a file that cannot be read whose name is not UTF-8")
    dashdash_alone_case, dash_case, xff_option_case = (
        "-- alone", "- alone", "an unknown option that is not UTF-8")
    filelink_case, dirlink_case = (
        "a directory holding a link to a fixture", "a directory holding a link to a directory")
    locked_root_case = "a repository root whose fixtures cannot be listed"
    unread_spelled_case, unread_dir_case = (
        "a file that cannot be read spelled with ./ and //",
        "a directory holding a file that cannot be read")
    file_dotdot_case, dir_spelled_case = (
        "a file spelled with ..", "a directory spelled with ./ and //")
    link_dotdot_slash_case, abs_dotdot_case = (
        "a .. after a symbolic link, with a trailing /",
        "an absolute path with a .. after a symbolic link")
    argv_of = {case: tuple(args) for case, args in ARGUMENT_CASES}
    fixfile = (
        "PASS  fixfile/x.json\n       expected: ACCEPT\n       observed: ACCEPT\n"
        "       signatures: 1/1 valid (ed25519=true mldsa65=false)\n"
        "\nsummary: 1 pass, 0 fail (1 fixtures)\n", "", 0,
    )

    def passes(*names: str) -> tuple[str, str, int]:
        """What a verifier writes and exits with when it verifies
        fixfile/x.json once under each of names, in that order."""
        block = fixfile[0][:fixfile[0].index("\n\n") + 1]
        report = "".join(block.replace("fixfile/x.json", name) for name in names)
        return (report + f"\nsummary: {len(names)} pass, 0 fail ({len(names)} fixtures)\n",
                "", 0)

    def unreadable(name: str, reason: str = "") -> tuple[str, str, int]:
        """What a verifier writes and exits with when it cannot read the file
        name names: its FAIL line, naming reason as the load error, by
        default the Go verifier's error for a file of mode 000."""
        reason = reason or f"open {name}: permission denied"
        return (f"FAIL  {name}  (load error: {reason})\n\nsummary: 0 pass, 1 fail (1 fixtures)\n",
                "", 1)

    missing = ("", "error: missing: no such file or directory\n", 2)
    kept = {
        argv_of[empty_case]: (
            "", "error: an empty argument names no fixture file or directory\n", 2),
        argv_of[fixfile_case]: fixfile,
        argv_of[missing_case]: missing,
        argv_of[version_case]: ("atx-verify: (devel), built with go1.22.12\n", "", 0),
        argv_of[unknown_case]: ("", "unknown option: --bogus\n", 2),
        argv_of[dash_case]: ("", "error: -: no such file or directory\n", 2),
        argv_of[root_case]: (
            fixfile[0].replace("fixfile/x.json", "root/fixtures/x.json"), "", 0),
        argv_of[twice_case]: (
            fixfile[0].replace("\nsummary: 1 pass, 0 fail (1 fixtures)\n", "")
            + fixfile[0].replace("summary: 1 pass, 0 fail (1 fixtures)",
                                 "summary: 2 pass, 0 fail (2 fixtures)"), "", 0),
        argv_of[spelled_case]: passes("./fixfile/./x.json", "fixfile//x.json"),
        argv_of[file_dotdot_case]: passes("fixfile/../fixfile/x.json"),
        argv_of[dir_spelled_case]: passes("fixfile/x.json"),
        argv_of[dotdot_case]: passes("fixfile/x.json"),
        argv_of[link_dotdot_case]: passes("hop/link/../x.json"),
        argv_of[link_dotdot_slash_case]: passes("hop/link/../x.json"),
        argv_of[subdir_case]: passes("subdir/x.json"),
        argv_of[filelink_case]: passes("filelink/link.json"),
        argv_of[dirlink_case]: unreadable(
            "dirlink/link.json", "read dirlink/link.json: is a directory"),
        argv_of[locked_case]: ("", "error: open locked: permission denied\n", 2),
        argv_of[locked_root_case]: (
            "", "error: open lockedroot/fixtures: permission denied\n", 2),
        argv_of[unread_case]: unreadable("noread/x.json"),
        argv_of[unread_spelled_case]: unreadable("./noread//x.json"),
        argv_of[unread_dir_case]: unreadable("noread/x.json"),
        argv_of[slash_case]: ("", "error: stat fixfile/x.json/: not a directory\n", 2),
        argv_of[dashdash_case]: (fixfile[0].replace("fixfile/x.json", "-h.json"), "", 0),
        # Keyed on the argument as the stand-in's sys.argv holds it, not on
        # {xff} as ARGUMENT_CASES writes it.
        (NOT_UTF8,): ("", f"error: {NOT_UTF8}: no such file or directory\n", 2),
        (f"-{NOT_UTF8}",): ("", f"unknown option: -{NOT_UTF8}\n", 2),
        (f"xff/{NOT_UTF8}.json",): passes(f"xff/{NOT_UTF8}.json"),
        argv_of[xff_dir_case]: passes(f"xff/{NOT_UTF8}.json"),
        (f"noread/{NOT_UTF8}.json",): unreadable(f"noread/{NOT_UTF8}.json"),
    }
    embedded = (fixfile[0].replace("fixfile/x.json", f"fixtures/{ARGUMENT_FIXTURE}"), "", 0)
    no_argument = argv_of[no_argument_case]
    no_path = (no_argument, argv_of[dashdash_alone_case])

    def changed(
        outcomes: dict[tuple[str, ...], tuple[str, str, int]],
        one: dict[tuple[str, ...], tuple[str, str, int]] | None = None,
    ) -> dict[str, dict]:
        return {
            "one": _argument_stand_in(
                "atx-verify", {**kept, **dict.fromkeys(no_path, embedded), **(one or {})},
                embeds=True),
            "two": _argument_stand_in("verify.py", {
                **kept,
                **dict.fromkeys(no_path, ("", "usage: verify.py <fixture.json|dir>...\n", 2)),
                **outcomes}),
        }

    exit_changed = {argv_of[missing_case]: ("", missing[1], 1)}
    args_exit = _argument_divergences(changed(exit_changed), missing_case)
    args_stderr = _argument_divergences(changed(
        {argv_of[empty_case]: ("", "error: stat : no such file or directory\n", 2)}),
        empty_case)
    args_verdicts = _argument_divergences(changed({argv_of[fixfile_case]: (
        fixfile[0].replace("observed: ACCEPT", "observed: REJECT[EXPIRED: past expiry]"),
        "", 0)}), fixfile_case)
    args_wording = _argument_divergences(changed({
        argv_of[fixfile_case]: (
            fixfile[0].replace("=true", "=True").replace("=false", "=False"), "", 0),
        argv_of[missing_case]: ("", missing[1] + "run with --help for the usage\n", 2),
    }), fixfile_case, missing_case)
    args_named = _argument_divergences({
        "one": _argument_stand_in("verify", {
            argv_of[empty_case]: ("", "usage: verify [fixture.json|dir]...\n", 2),
            argv_of[missing_case]: ("", "verify: missing: no such file or directory\n", 2),
        }),
        "two": _argument_stand_in("verify.py", {
            argv_of[empty_case]: ("", "usage: verify.py [fixture.json|dir]...\n", 2),
            argv_of[missing_case]: ("", "verify.py: missing: no such file or directory\n", 2),
        }),
    }, empty_case, missing_case)
    args_unnamed = _argument_divergences({
        "one": _argument_stand_in(
            "verify", {argv_of[missing_case]: ("", "verify.py: missing\n", 2)}),
        "two": _argument_stand_in(
            "verify.py", {argv_of[missing_case]: ("", "verify: missing\n", 2)}),
    }, missing_case)
    # "two" as a verifier that reads --version only as its first argument,
    # one with no unknown-option rule, one that walks a repository root
    # for its own *.json, which loads conformance.json there, one that
    # verifies a path named twice once, and one that reads each argument as
    # a pathlib.Path does: it drops ./ and a trailing / and collapses //, and
    # keeps a .. that Go's filepath.Join removes.
    args_version = _argument_divergences(changed(
        {argv_of[version_case]: ("", "error: --version: no such file or directory\n", 2)}),
        version_case)
    args_unknown = _argument_divergences(changed(
        {argv_of[unknown_case]: ("", "error: --bogus: no such file or directory\n", 2)}),
        unknown_case)
    args_root = _argument_divergences(changed({argv_of[root_case]: (
        "FAIL  root/conformance.json  (load error: no expected member)\n"
        "\nsummary: 0 pass, 1 fail (1 fixtures)\n", "", 1)}), root_case)
    args_twice = _argument_divergences(
        changed({argv_of[twice_case]: fixfile}), twice_case)
    args_spelled = _argument_divergences(changed(
        {argv_of[spelled_case]: passes("fixfile/x.json", "fixfile/x.json")}), spelled_case)
    args_dotdot = _argument_divergences(changed(
        {argv_of[dotdot_case]: passes("fixfile/../fixfile/x.json")}), dotdot_case)
    # "two" as a verifier that joins the files of hop/link/.. onto it as Go's
    # filepath.Join does, which removes the .. with the link: it lists away/,
    # which hop/link/.. resolves to, and reads hop/x.json, which does not
    # exist.
    args_link_dotdot = _argument_divergences(changed({argv_of[link_dotdot_case]: (
        "FAIL  hop/x.json  (load error: open hop/x.json: no such file or directory)\n"
        "\nsummary: 0 pass, 1 fail (1 fixtures)\n", "", 1)}), link_dotdot_case)
    # "two" as a verifier that lists subdir/sub.json, a directory, with the
    # files of subdir, as Path.glob lists it, and reports it as a load error.
    args_subdir = _argument_divergences(changed({argv_of[subdir_case]: (
        "FAIL  subdir/sub.json  (load error: [Errno 21] Is a directory: 'subdir/sub.json')\n"
        + passes("subdir/x.json")[0].replace(
            "summary: 1 pass, 0 fail (1 fixtures)", "summary: 1 pass, 1 fail (2 fixtures)"),
        "", 1)}), subdir_case)
    # "two" as a verifier that gives no name for a directory it cannot list
    # and writes that it found no *.json.
    args_locked = _argument_divergences(changed(
        {argv_of[locked_case]: ("", "no fixture *.json files found\n", 2)}), locked_case)
    args_slash = _argument_divergences(changed(
        {argv_of[slash_case]: passes("fixfile/x.json")}), slash_case)
    # "two" as a verifier that writes the byte 0xff of an argument as the
    # six characters \udcff, as sys.stderr writes the surrogate escape
    # sys.argv holds for it.
    args_xff = _argument_divergences(changed(
        {(NOT_UTF8,): ("", "error: \\udcff: no such file or directory\n", 2)}), xff_case)
    # "two" as a verifier that writes the byte 0xff of a fixture's name as
    # the six characters \udcff in its PASS line, as the Python verifier
    # wrote the surrogate escape sys.argv and os.scandir hold for it; then
    # the same two where the file system refuses that name.
    escaped_name = changed({
        (f"xff/{NOT_UTF8}.json",): passes("xff/\\udcff.json"),
        argv_of[xff_dir_case]: passes("xff/\\udcff.json"),
    })
    args_xff_name = _argument_divergences(escaped_name, xff_file_case, xff_dir_case)
    # "two" as a verifier that writes the load error of a file it cannot read
    # as Python's OSError writes it, the path quoted through repr, which
    # writes the byte 0xff as the six characters \udcff; then one that words
    # it as the Go verifier does and still writes that byte as those
    # characters, though its FAIL line writes the byte.
    args_unread = _argument_divergences(changed({argv_of[unread_case]: unreadable(
        "noread/x.json", "[Errno 13] Permission denied: 'noread/x.json'")}), unread_case)
    args_unread_xff = _argument_divergences(changed({(f"noread/{NOT_UTF8}.json",): unreadable(
        f"noread/{NOT_UTF8}.json", "[Errno 13] Permission denied: 'noread/\\udcff.json'")}),
        unread_xff_case)
    args_unread_escaped = _argument_divergences(changed({(f"noread/{NOT_UTF8}.json",): unreadable(
        f"noread/{NOT_UTF8}.json", "open noread/\\udcff.json: permission denied")}),
        unread_xff_case)
    refused = "the file system refuses a name that is not UTF-8 (Illegal byte sequence)"
    xff_skipped = _argument_rows(escaped_name, xff_file_case, xff_dir_case, refusal=refused)
    # With no argument: both as documented; "one" writing its usage although
    # it embeds a fixture set; "two" reporting a set although it embeds none.
    args_documented = _argument_divergences(changed({}), no_argument_case)
    args_no_walk = _argument_divergences(changed({}, {
        no_argument: ("", "usage: atx-verify [fixture.json|dir]...\n", 2)}), no_argument_case)
    args_walks = _argument_divergences(changed({no_argument: embedded}), no_argument_case)
    # "two" as a verifier with no "--" rule, and two that name a path under
    # the working directory relative to PWD and to os.getcwd(), as the Go and
    # the Python verifier named it before both compared resolved paths.
    args_dashdash = _argument_divergences(changed(
        {argv_of[dashdash_case]: ("", "unknown option: --\n", 2)}), dashdash_case)
    args_link = _argument_divergences({
        "one": _naming_stand_in("atx-verify", "PWD"),
        "two": _naming_stand_in("verify.py", "cwd"),
    }, link_case, target_case)
    # With -- alone: both as documented; "one" taking -- alone for a path
    # although it embeds a fixture set.
    args_dashdash_alone = _argument_divergences(changed({}), dashdash_alone_case)
    args_dashdash_alone_path = _argument_divergences(changed({}, {
        argv_of[dashdash_alone_case]: ("", "error: --: no such file or directory\n", 2)}),
        dashdash_alone_case)
    # "two" as a verifier that takes - alone for an unknown option, and one
    # that writes the byte 0xff of an unknown option as the six characters
    # \udcff.
    args_dash = _argument_divergences(changed(
        {argv_of[dash_case]: ("", "unknown option: -\n", 2)}), dash_case)
    args_xff_option = _argument_divergences(changed(
        {(f"-{NOT_UTF8}",): ("", "unknown option: -\\udcff\n", 2)}), xff_option_case)
    # "two" as a verifier that skips a symbolic link a walk finds, and one
    # that skips a link to a directory as it skips a directory, as
    # Path.is_dir(), which follows the link, reads it.
    args_filelink = _argument_divergences(changed(
        {argv_of[filelink_case]: ("", "no fixture *.json files found\n", 2)}), filelink_case)
    args_dirlink = _argument_divergences(changed(
        {argv_of[dirlink_case]: ("", "no fixture *.json files found\n", 2)}), dirlink_case)
    # "two" as a verifier that names a repository root it cannot list by the
    # root rather than by its fixtures directory.
    args_locked_root = _argument_divergences(changed(
        {argv_of[locked_root_case]: ("", "error: open lockedroot: permission denied\n", 2)}),
        locked_root_case)
    # "two" as a verifier that names the path of a file it cannot read in the
    # load error as pathlib.Path holds it, ./ and // dropped, and one that
    # stops at such a file a walk finds, as at a directory it cannot list.
    args_unread_spelled = _argument_divergences(changed({argv_of[unread_spelled_case]: unreadable(
        "./noread//x.json", "open noread/x.json: permission denied")}), unread_spelled_case)
    args_unread_dir = _argument_divergences(changed(
        {argv_of[unread_dir_case]: ("", "error: open noread/x.json: permission denied\n", 2)}),
        unread_dir_case)
    # "two" as a verifier that names a file argument with its .. removed, as
    # os.path.normpath removes it, one that joins the file names of a
    # directory onto it as spelled, ./ and // kept, and one that puts a /
    # between hop/link/../ and a file name, though it ends in one.
    args_file_dotdot = _argument_divergences(changed(
        {argv_of[file_dotdot_case]: passes("fixfile/x.json")}), file_dotdot_case)
    args_dir_spelled = _argument_divergences(changed(
        {argv_of[dir_spelled_case]: passes(".//fixfile/x.json")}), dir_spelled_case)
    args_link_dotdot_slash = _argument_divergences(changed(
        {argv_of[link_dotdot_slash_case]: passes("hop/link/..//x.json")}), link_dotdot_slash_case)
    # Two that resolve the directory of an absolute path as spelled, and
    # with the .. removed with the link before it, as both verifiers resolved
    # it before.
    args_abs_dotdot = _argument_divergences({
        "one": _resolving_stand_in("atx-verify", clean_first=False),
        "two": _resolving_stand_in("verify.py", clean_first=True),
    }, abs_dotdot_case)
    gate_fails = _gate_with_arguments(lambda bin_dir: changed(exit_changed))
    gate_passes = _gate_with_arguments(lambda bin_dir: changed({}))
    gate_skips = _gate_with_arguments(lambda bin_dir: changed({}), refused)
    gate_not_built = _gate_with_arguments(_not_built)
    # Writing xff/{xff}.json raising an OSError with each errno: EILSEQ and
    # EINVAL are the file system refusing the name, and the others are
    # raised, by the gate too, which reads the file system's own answer.
    scratch_errors = (
        errno.EILSEQ, errno.EINVAL, errno.ENOSPC, errno.EACCES, errno.EROFS, errno.EIO)
    scratch_answers = [_writing_xff_raising(e, _scratch_refusal) for e in scratch_errors]
    gate_out_of_space = _writing_xff_raising(
        errno.ENOSPC, lambda: _gate_with_arguments(lambda bin_dir: changed({}), None))
    cases: list[tuple[str, bool]] = [
        ("verifiers that agree report no divergence", agree == []),
        ("a verdict divergence is reported by fixture",
         flipped == ["b.json: verdict divergence {'one': 'REJECT', 'two': 'ACCEPT'}",
                     "b.json: category divergence {'one': 'EXPIRED', 'two': None}"]),
        ("a fixture a verifier skipped is reported as a fixture set mismatch",
         skipped == ["two fixture set mismatch: missing=['b.json'] extra=[]"]),
        ("a verifier that exits 2 before reporting any fixture is reported by its "
         "exit code and stderr, not as a fixture set mismatch",
         no_dep == [f"two verifier exited 2 (expected 0) before reporting any fixture: "
                    f"{MISSING_DEP}"]),
        ("a verifier that fails partway is reported by its exit code and stderr "
         "and by the fixtures it did not reach",
         crashed == ["two verifier exited 1 (expected 0): Traceback: boom",
                     "two fixture set mismatch: missing=['b.json'] extra=[]"]),
        ("a verifier that exits 0 without reporting any fixture is reported as a "
         "fixture set mismatch naming every fixture",
         silent == ["two fixture set mismatch: missing=['a.json', 'b.json'] extra=[]"]),
        ("--self-test with --json is refused as a usage error, since it writes no report, "
         "and each flag alone is accepted",
         _refuses_self_test_with_json()),
        ("a reworded usage message turns the usage-error case red, since the case holds "
         "the message written out rather than reading it from the code that prints it",
         _reworded("--json cannot be used with --self-test")
         == ((2, "parity.py: error: --json cannot be used with --self-test"), False)),
        ("an unknown argument is named on its own line above the usage, in the words every "
         "script under scripts/ uses, and exits 2",
         unknown is not None and unknown[0] == 2
         and unknown[1].startswith("unknown argument(s): --bogus\nusage: parity.py ")),
        ("a verifier that exits before reporting any fixture has one line above "
         "the table, not a MISSING cell on every row",
         no_dep_table == [
             "parity: 2 fixtures x 2 verifiers",
             "  two: exited 2 before reporting any fixture "
             "(see PARITY: FAIL below)",
             _row("a.json", "one=PASS:ACCEPT"),
             _row("b.json", "one=PASS:REJECT[EXPIRED]"),
         ]),
        ("a verifier that fails partway keeps its column, MISSING where it stopped",
         crashed_table == [
             "parity: 2 fixtures x 2 verifiers",
             _row("a.json", "one=PASS:ACCEPT", "two=PASS:ACCEPT"),
             _row("b.json", "one=PASS:REJECT[EXPIRED]", "two=MISSING"),
         ]),
        ("when no verifier reports any fixture, the table has no fixture rows",
         none_ran == [
             "parity: 2 fixtures x 2 verifiers",
             "  one: exited 2 before reporting any fixture "
             "(see PARITY: FAIL below)",
             "  two: exited 1 before reporting any fixture "
             "(see PARITY: FAIL below)",
         ]),
        ("a fixtures directory holding no *.json exits 1 and says so, before "
         "any verifier runs",
         no_fixtures == (1, "", NO_FIXTURES)),
        ("the docstring's Exit codes block is EXIT_CODES",
         __doc__ is None or __doc__.endswith(EXIT_CODES)),
        ("the --json report names a verifier that exits before reporting any "
         "fixture, as the table does",
         no_dep_report.get("unreported") == ["two"]
         and no_dep_report["exitCodes"] == {"one": 0, "two": 2}
         and no_dep_report["agree"] is False),
        ("the --json report does not name a verifier that fails partway as "
         "unreported",
         crashed_report.get("unreported") == []),
        ("the --json report names every verifier when none reports any fixture",
         none_ran_report.get("unreported") == ["one", "two"]),
        ("an argument case on which a verifier exits with another code is a "
         "divergence naming the case and both outcomes",
         args_exit == [
             'argument case "a path that does not exist" (missing): '
             "one exit 2, stderr 'error: missing: no such file or directory'; "
             "two exit 1, stderr 'error: missing: no such file or directory'"]),
        ("an argument case on which a verifier writes another first stderr line "
         "is a divergence",
         args_stderr == [
             "argument case \"an empty argument\" (''): "
             "one exit 2, stderr 'error: an empty argument names no fixture file or directory'; "
             "two exit 2, stderr 'error: stat : no such file or directory'"]),
        ("an argument case on which a verifier writes other verdict lines is a "
         "divergence",
         args_verdicts == [
             'argument case "a fixtures entry that is a file" (fixfile): '
             "one exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: REJECT[EXPIRED]', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("a later stderr line, and a report line that is not a verdict line, are "
         "each verifier's own wording and make no divergence",
         args_wording == []),
        ("the program name a first stderr line opens with, or names after "
         "`usage: `, is stripped before the lines are compared",
         args_named == []),
        ("only a verifier's own program name is stripped",
         args_unnamed == [
             'argument case "a path that does not exist" (missing): '
             "one exit 2, stderr 'verify.py: missing'; two exit 2, stderr 'verify: missing'"]),
        ("--version after a path, which one verifier takes for a path, is a divergence",
         args_version == [
             'argument case "--version after a path" (fixfile --version): '
             "one exit 0; two exit 2, stderr 'error: --version: no such file or directory'"]),
        ("an unknown option after a path, which one verifier reports as a missing path, "
         "is a divergence",
         args_unknown == [
             'argument case "an unknown option after a path" (fixfile --bogus): '
             "one exit 2, stderr 'unknown option: --bogus'; "
             "two exit 2, stderr 'error: --bogus: no such file or directory'"]),
        ("a repository root, which one verifier walks for its own *.json rather than "
         "fixtures/*.json, is a divergence",
         args_root == [
             'argument case "a repository root" (root): '
             "one exit 0, verdict lines ['PASS  root/fixtures/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 1, verdict lines ['FAIL  root/conformance.json  "
             "(load error: no expected member)', 'summary: 0 pass, 1 fail (1 fixtures)']"]),
        ("a path named twice, which one verifier verifies once, is a divergence",
         args_twice == [
             'argument case "a path named twice" (fixfile/x.json fixfile/x.json): '
             "one exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 2 pass, 0 fail (2 fixtures)']; "
             "two exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("a file spelled with ./ and //, which one verifier names without them, is a "
         "divergence",
         args_spelled == [
             'argument case "a file spelled with ./ and //" '
             "(fixfile//x.json ./fixfile/./x.json): "
             "one exit 0, verdict lines ['PASS  ./fixfile/./x.json', 'observed: ACCEPT', "
             "'PASS  fixfile//x.json', 'observed: ACCEPT', "
             "'summary: 2 pass, 0 fail (2 fixtures)']; "
             "two exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 2 pass, 0 fail (2 fixtures)']"]),
        ("a directory spelled with .., whose files one verifier names with the .., is a "
         "divergence",
         args_dotdot == [
             'argument case "a directory spelled with .." (fixfile/../fixfile): '
             "one exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 0, verdict lines ['PASS  fixfile/../fixfile/x.json', "
             "'observed: ACCEPT', 'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("a .. after a symbolic link, whose files one verifier names with the .. removed "
         "with the link, is a divergence",
         args_link_dotdot == [
             'argument case "a .. after a symbolic link" (hop/link/..): '
             "one exit 0, verdict lines ['PASS  hop/link/../x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 1, verdict lines ['FAIL  hop/x.json  (load error: open hop/x.json: "
             "no such file or directory)', 'summary: 0 pass, 1 fail (1 fixtures)']"]),
        ("a subdirectory named *.json, which one verifier reports as a fixture that fails "
         "to load, is a divergence",
         args_subdir == [
             'argument case "a subdirectory named *.json" (subdir): '
             "one exit 0, verdict lines ['PASS  subdir/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 1, verdict lines [\"FAIL  subdir/sub.json  (load error: [Errno 21] "
             "Is a directory: 'subdir/sub.json')\", 'PASS  subdir/x.json', "
             "'observed: ACCEPT', 'summary: 1 pass, 1 fail (2 fixtures)']"]),
        ("a directory that cannot be listed, for which one verifier writes that it found "
         "no *.json, is a divergence",
         args_locked == [
             'argument case "a directory that cannot be listed" (locked): '
             "one exit 2, stderr 'error: open locked: permission denied'; "
             "two exit 2, stderr 'no fixture *.json files found'"]),
        ("a file named with a trailing /, which one verifier verifies, is a divergence",
         args_slash == [
             'argument case "a file named with a trailing /" (fixfile/x.json/): '
             "one exit 2, stderr 'error: stat fixfile/x.json/: not a directory'; "
             "two exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("a path that is not UTF-8, which one verifier writes as a backslash escape "
         "rather than as its byte, is a divergence",
         args_xff == [
             "argument case \"a path that is not UTF-8\" ('{xff}'): "
             r"one exit 2, stderr 'error: \udcff: no such file or directory'; "
             r"two exit 2, stderr 'error: \\udcff: no such file or directory'"]),
        ("a file whose name is not UTF-8, named as a file or found in a directory, which "
         "one verifier names with a backslash escape rather than its byte, is a divergence",
         args_xff_name == [
             f"argument case \"{case}\" ({spelled}): "
             r"one exit 0, verdict lines ['PASS  xff/\udcff.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             r"two exit 0, verdict lines ['PASS  xff/\\udcff.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"
             for case, spelled in ((xff_file_case, "'xff/{xff}.json'"), (xff_dir_case, "xff"))]),
        ("a file that cannot be read, whose load error one verifier writes as Python's "
         "OSError writes it, is a divergence, though both FAIL it under one name",
         args_unread == [
             'argument case "a file that cannot be read" (noread/x.json): '
             "one exit 1, verdict lines ['FAIL  noread/x.json  (load error: open "
             "noread/x.json: permission denied)', 'summary: 0 pass, 1 fail (1 fixtures)']; "
             "two exit 1, verdict lines [\"FAIL  noread/x.json  (load error: [Errno 13] "
             "Permission denied: 'noread/x.json')\", 'summary: 0 pass, 1 fail (1 fixtures)']"]),
        ("a file that cannot be read whose name is not UTF-8, whose load error one verifier "
         "writes as Python's OSError writes it, is a divergence",
         args_unread_xff == [
             "argument case \"a file that cannot be read whose name is not UTF-8\" "
             "('noread/{xff}.json'): "
             r"one exit 1, verdict lines ['FAIL  noread/\udcff.json  (load error: open "
             r"noread/\udcff.json: permission denied)', 'summary: 0 pass, 1 fail (1 fixtures)']; "
             r"""two exit 1, verdict lines ["FAIL  noread/\udcff.json  (load error: [Errno 13] """
             r"""Permission denied: 'noread/\\udcff.json')", 'summary: 0 pass, 1 fail """
             "(1 fixtures)']"]),
        ("a load error that writes the byte 0xff of a path as the six characters \\udcff, "
         "where its FAIL line writes the byte, is a divergence",
         args_unread_escaped == [
             "argument case \"a file that cannot be read whose name is not UTF-8\" "
             "('noread/{xff}.json'): "
             r"one exit 1, verdict lines ['FAIL  noread/\udcff.json  (load error: open "
             r"noread/\udcff.json: permission denied)', 'summary: 0 pass, 1 fail (1 fixtures)']; "
             r"two exit 1, verdict lines ['FAIL  noread/\udcff.json  (load error: open "
             r"noread/\\udcff.json: permission denied)', 'summary: 0 pass, 1 fail (1 fixtures)']"]),
        ("where the file system refuses a name that is not UTF-8, the cases that need one "
         "are skipped whatever the verifiers would write, each row naming the refusal, "
         "and are no divergence",
         xff_skipped[1] == []
         and [(r["case"], r["agree"], r["skipped"], r["outcomes"]) for r in xff_skipped[0]]
         == [(xff_file_case, None, refused, {}), (xff_dir_case, None, refused, {})]
         and render_arguments(xff_skipped[0])[1:] == [
             _argument_row(xff_file_case, list(argv_of[xff_file_case]), f"skipped: {refused}"),
             _argument_row(xff_dir_case, list(argv_of[xff_dir_case]), f"skipped: {refused}")]),
        ("writing xff/{xff}.json, EILSEQ and EINVAL are the file system refusing the name, "
         "the refusal naming the error, and ENOSPC, EACCES, EROFS and EIO are raised rather "
         "than taken for a refusal",
         scratch_answers == [
             f"the file system refuses a name that is not UTF-8 ({os.strerror(errno.EILSEQ)})",
             f"the file system refuses a name that is not UTF-8 ({os.strerror(errno.EINVAL)})",
             errno.ENOSPC, errno.EACCES, errno.EROFS, errno.EIO]),
        ("with no argument, a verifier that embeds a fixture set reports it and exits 0, "
         "and one that embeds none writes its usage and exits 2, which is no divergence",
         args_documented == []),
        ("a verifier that embeds a fixture set and writes its usage for no argument is a "
         "divergence",
         args_no_walk == [
             'argument case "no argument" (): '
             "one exit 2, stderr 'usage:  [fixture.json|dir]...'; "
             "two exit 2, stderr 'usage:  <fixture.json|dir>...'"]),
        ("a verifier that embeds no fixture set and reports one for no argument is a "
         "divergence",
         args_walks == [
             'argument case "no argument" (): '
             "one exit 0, verdict lines ['PASS  fixtures/baseline-valid.json', "
             "'observed: ACCEPT', 'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 0, verdict lines ['PASS  fixtures/baseline-valid.json', "
             "'observed: ACCEPT', 'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("a path after --, which one verifier names an unknown option, is a divergence",
         args_dashdash == [
             'argument case "a path after --" (-- -h.json): '
             "one exit 0, verdict lines ['PASS  -h.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 2, stderr 'unknown option: --'"]),
        ("the cases with an absolute path via the link and via its target run from a "
         "symbolic link with PWD naming it, so a verifier naming a path relative to PWD "
         "and one naming it relative to the directory os.getcwd() names diverge on both",
         [d.split(" (", 1)[0] for d in args_link]
         == [f'argument case "{link_case}"', f'argument case "{target_case}"']
         and all(d.count("verdict lines ['PASS  fixfile/x.json']") == 1 for d in args_link)),
        ("-- alone, which names no path, is held to the answer to no argument: as "
         "documented it is no divergence, and a verifier that embeds a fixture set and "
         "takes -- alone for a path is one",
         args_dashdash_alone == []
         and args_dashdash_alone_path == [
             'argument case "-- alone" (--): '
             "one exit 2, stderr 'error: --: no such file or directory'; "
             "two exit 2, stderr 'usage:  <fixture.json|dir>...'"]),
        ("- alone, which one verifier names an unknown option, is a divergence",
         args_dash == [
             'argument case "- alone" (-): '
             "one exit 2, stderr 'error: -: no such file or directory'; "
             "two exit 2, stderr 'unknown option: -'"]),
        ("an unknown option that is not UTF-8, which one verifier writes as a backslash "
         "escape rather than as its byte, is a divergence",
         args_xff_option == [
             "argument case \"an unknown option that is not UTF-8\" ('-{xff}'): "
             r"one exit 2, stderr 'unknown option: -\udcff'; "
             r"two exit 2, stderr 'unknown option: -\\udcff'"]),
        ("a directory holding a symbolic link to a fixture, which one verifier skips, is a "
         "divergence",
         args_filelink == [
             'argument case "a directory holding a link to a fixture" (filelink): '
             "one exit 0, verdict lines ['PASS  filelink/link.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 2, stderr 'no fixture *.json files found'"]),
        ("a directory holding a symbolic link to a directory, which one verifier skips as "
         "a directory where the other fails to load it, is a divergence",
         args_dirlink == [
             'argument case "a directory holding a link to a directory" (dirlink): '
             "one exit 1, verdict lines ['FAIL  dirlink/link.json  (load error: read "
             "dirlink/link.json: is a directory)', 'summary: 0 pass, 1 fail (1 fixtures)']; "
             "two exit 2, stderr 'no fixture *.json files found'"]),
        ("a repository root whose fixtures directory cannot be listed, which one verifier "
         "names by the root, is a divergence",
         args_locked_root == [
             'argument case "a repository root whose fixtures cannot be listed" '
             "(lockedroot): "
             "one exit 2, stderr 'error: open lockedroot/fixtures: permission denied'; "
             "two exit 2, stderr 'error: open lockedroot: permission denied'"]),
        ("a file that cannot be read spelled with ./ and //, whose load error one verifier "
         "writes without them, is a divergence",
         args_unread_spelled == [
             'argument case "a file that cannot be read spelled with ./ and //" '
             "(./noread//x.json): "
             "one exit 1, verdict lines ['FAIL  ./noread//x.json  (load error: open "
             "./noread//x.json: permission denied)', 'summary: 0 pass, 1 fail (1 fixtures)']; "
             "two exit 1, verdict lines ['FAIL  ./noread//x.json  (load error: open "
             "noread/x.json: permission denied)', 'summary: 0 pass, 1 fail (1 fixtures)']"]),
        ("a directory holding a file that cannot be read, which one verifier refuses "
         "rather than reporting a load error, is a divergence",
         args_unread_dir == [
             'argument case "a directory holding a file that cannot be read" (noread): '
             "one exit 1, verdict lines ['FAIL  noread/x.json  (load error: open "
             "noread/x.json: permission denied)', 'summary: 0 pass, 1 fail (1 fixtures)']; "
             "two exit 2, stderr 'error: open noread/x.json: permission denied'"]),
        ("a file spelled with .., which one verifier names with the .. removed, is a "
         "divergence",
         args_file_dotdot == [
             'argument case "a file spelled with .." (fixfile/../fixfile/x.json): '
             "one exit 0, verdict lines ['PASS  fixfile/../fixfile/x.json', "
             "'observed: ACCEPT', 'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("a directory spelled with ./ and //, whose files one verifier names with them, is "
         "a divergence",
         args_dir_spelled == [
             'argument case "a directory spelled with ./ and //" (.//fixfile): '
             "one exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 0, verdict lines ['PASS  .//fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("a .. after a symbolic link with a trailing /, whose files one verifier names with "
         "a second /, is a divergence",
         args_link_dotdot_slash == [
             'argument case "a .. after a symbolic link, with a trailing /" (hop/link/../): '
             "one exit 0, verdict lines ['PASS  hop/link/../x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']; "
             "two exit 0, verdict lines ['PASS  hop/link/..//x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"]),
        ("an absolute path with a .. after a symbolic link, which one verifier names with "
         "the .. removed with the link, is a divergence",
         args_abs_dotdot == [
             "argument case \"an absolute path with a .. after a symbolic link\" "
             "('{link}/hop/link/../x.json'): "
             "one exit 0, verdict lines ['PASS  away/x.json']; "
             "two exit 0, verdict lines ['PASS  hop/x.json']"]),
        ("the gate fails on an argument case one verifier diverges on, and that "
         "case's row in the argument table names both outcomes",
         gate_fails[0] == 1
         and "\nPARITY: FAIL\n" in gate_fails[1]
         and _argument_row(missing_case, list(argv_of[missing_case]),
                           "differ: one exit 2, stderr 'error: missing: no such file "
                           "or directory'; two exit 1, stderr 'error: missing: no "
                           "such file or directory'") in gate_fails[1].splitlines()),
        ("the --json report holds the argument table under `arguments`, the "
         "diverging case marked",
         [(r["case"], r["agree"]) for r in gate_fails[2].get("arguments", [])]
         == [(case, case != missing_case) for case, _ in ARGUMENT_CASES]
         and gate_fails[2]["agree"] is False),
        ("the gate passes when the verifiers agree on every fixture and every "
         "argument case",
         gate_passes[0] == 0
         and "\nPARITY: PASS" in gate_passes[1]
         and len(gate_passes[2].get("arguments", [])) == len(ARGUMENT_CASES)
         and all(r["agree"] for r in gate_passes[2]["arguments"])),
        ("the gate passes where the file system refuses a name that is not UTF-8, its "
         "PASS line naming the skipped cases, which the --json report marks",
         gate_skips[0] == 0
         and "\nPARITY: PASS (all implementations agree on gate, verdict, and category, "
             "and on every argument case but the 3 skipped)\n" in gate_skips[1]
         and [(r["case"], r["agree"], r["skipped"]) for r in gate_skips[2].get("arguments", [])
              if r["agree"] is not True]
         == [(xff_file_case, None, refused), (xff_dir_case, None, refused),
             (unread_xff_case, None, refused)]),
        ("the gate raises ENOSPC writing xff/{xff}.json, rather than passing with the "
         "cases that need that name skipped",
         gate_out_of_space == errno.ENOSPC),
        ("a verifier the argument table cannot build fails the gate, which names "
         "the build error",
         gate_not_built[0] == 1
         and gate_not_built[2]["divergences"] == [
             "argument table not run: go build exited 1: boom"]
         and gate_not_built[2].get("arguments") == []),
    ]
    failed = 0
    for label, ok in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        failed += not ok
    print(f"parity self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


SELF_TEST_JSON_ERROR = "--json cannot be used with --self-test: --self-test writes no parity report"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="parity.py")
    ap.add_argument("--json", metavar="PATH", help="write a JSON parity report")
    ap.add_argument(
        "--self-test", action="store_true",
        help="prove on stand-in verifiers that the gate can fail, then stop "
             "(writes no report; not accepted with --json)",
    )
    args, unknown = ap.parse_known_args(argv)
    if unknown:
        # In the words every script under scripts/ names one with.
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        ap.print_usage(sys.stderr)
        ap.exit(2)
    if args.self_test and args.json is not None:
        ap.error(SELF_TEST_JSON_ERROR)
    return args


def gate(
    fixtures_dir: Path, verifiers: dict[str, dict], json_path: str | None,
    programs: Callable[[Path], dict[str, dict]] = argument_verifiers,
    refusal: str | None = None,
) -> int:
    """Run the verifiers over the *.json in fixtures_dir, then the argument
    table on the verifiers programs returns for a scratch directory; return
    the exit code. refusal is compare_arguments' own."""
    fixture_files = sorted(p.name for p in fixtures_dir.glob("*.json"))
    if not fixture_files:
        sys.stderr.write(NO_FIXTURES)
        return 1

    table, exit_codes, divergences, unreported = compare(fixture_files, verifiers)
    arguments: list[dict] = []
    with tempfile.TemporaryDirectory() as scratch:
        try:
            argument_programs = programs(Path(scratch) / "bin")
        except BuildError as exc:
            divergences.append(f"argument table not run: {exc}")
        else:
            arguments, argument_divergences = compare_arguments(
                argument_programs, fixtures_dir / ARGUMENT_FIXTURE, Path(scratch) / "run",
                refusal=refusal)
            divergences += argument_divergences

    print()
    print("\n".join(render_table(table, list(verifiers), exit_codes, unreported)))
    print()
    print("\n".join(render_arguments(arguments)))

    if json_path:
        Path(json_path).write_text(
            json.dumps(
                build_report(table, exit_codes, divergences, unreported, arguments),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    if divergences:
        print("\nPARITY: FAIL")
        for d in divergences:
            # Relayed stderr can span lines; keep them under their bullet.
            print("  - " + d.replace("\n", "\n    "))
        return 1
    skipped = sum(1 for row in arguments if row.get("skipped"))
    cases = f"every argument case but the {skipped} skipped" if skipped else "every argument case"
    print("\nPARITY: PASS (all implementations agree on gate, verdict, and category, "
          f"and on {cases})")
    return 0


def main() -> int:
    args = parse_args()

    if self_test():
        return 1
    if args.self_test:
        return 0

    return gate(REPO_ROOT / "fixtures", VERIFIERS, args.json)


if __name__ == "__main__":
    sys.exit(main())
