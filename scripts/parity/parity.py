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
several positions, --version and an unknown option after a path, a
repository root, a directory whose `fixtures` entry is a file, a path that
does not exist, a directory with no *.json, a path named twice, a file spelled
with ./ and //, a directory spelled with .., a file named with a trailing /,
a path and an option after `--`, an absolute path through a symbolic link to
the working directory, through its target and outside it), each run on both
verifiers from a symbolic link to a scratch directory holding the paths it
names, with PWD naming the link, as a shell names a directory it changed
into through one. Both must exit with the same code and write the same
first stderr line and the same verdict lines (each PASS or FAIL line, its
observed verdict and category, the summary), once the program name each
verifier calls itself (`atx-verify`, `verify.py`) is stripped; a case they
differ on is a divergence. No argument is the one case the two answer
differently by design: the Go verifier must verify the fixture set its
module embeds, each fixture passing, and exit 0, and the Python verifier,
which has none, must write its usage and exit 2; any other outcome is a
divergence. The Go verifier runs there as a binary built for the table,
since `go run` reports a program's exit 2 as its own exit 1. The --json
report holds the table under `arguments`.

Every run starts with the self-test, which proves on stand-in verifiers that
the gate reports a disagreement, a skipped fixture, a failed verifier and a
verifier that exits 0 without reporting any fixture, that a fixtures
directory holding no *.json fails, that the --json report names a verifier
that exited before reporting any fixture, that an argument case one
verifier answers with another exit code, first stderr line or verdict lines
fails the gate, as does a verifier that answers no argument other than its
spec says, that the cases with an absolute path via the link and via its
target run from a symbolic link with PWD naming it, that --json is refused
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

# `PASS  <path>` or `FAIL  <path>` opens a per-fixture block.
BLOCK_RE = re.compile(r"^(PASS|FAIL)\s+(\S+)")
# `observed: ACCEPT` or `observed: REJECT[CATEGORY: reason]`
OBSERVED_RE = re.compile(r"^\s*observed:\s+(ACCEPT|REJECT\[([A-Z_]+))")

# The argument table: (case, arguments). Each list runs from a symbolic link
# to a scratch directory _argument_scratch lays out, with PWD naming the
# link: fixfile/ holds a file named fixtures and ARGUMENT_FIXTURE as x.json,
# root/ holds ARGUMENT_FIXTURE as fixtures/x.json beside conformance.json, a
# *.json that is not a fixture, as a repository root does, nojson/ holds no
# *.json, -h.json is ARGUMENT_FIXTURE, and nothing there is named missing.
# In an argument, {link} is the link's absolute path, {target} the
# directory's, its symbolic links resolved, and {fixture} the absolute path
# of the fixture the table copies, outside both.
ARGUMENT_CASES: list[tuple[str, list[str]]] = [
    ("no argument", []),
    ("an empty argument", [""]),
    ("--help first", ["--help", "fixfile"]),
    ("--help last", ["fixfile", "--help"]),
    ("--help between two paths", ["fixfile/x.json", "--help", "fixfile"]),
    ("-h alone", ["-h"]),
    ("--version after a path", ["fixfile", "--version"]),
    ("an unknown option after a path", ["fixfile", "--bogus"]),
    ("a repository root", ["root"]),
    ("a fixtures entry that is a file", ["fixfile"]),
    ("a path that does not exist", ["missing"]),
    ("a directory with no *.json", ["nojson"]),
    ("a path named twice", ["fixfile/x.json", "fixfile/x.json"]),
    ("a file spelled with ./ and //", ["fixfile//x.json", "./fixfile/./x.json"]),
    ("a directory spelled with ..", ["fixfile/../fixfile"]),
    ("a file named with a trailing /", ["fixfile/x.json/"]),
    ("a path after --", ["--", "-h.json"]),
    ("an option after --", ["--", "-h.json", "--help"]),
    ("an absolute path via the link", ["{link}/fixfile/x.json"]),
    ("an absolute path via its target", ["{target}/fixfile/x.json"]),
    ("an absolute path outside the cwd", ["{fixture}"]),
]
# The shipped fixture the argument table copies to fixfile/x.json.
ARGUMENT_FIXTURE = "baseline-valid.json"
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
    order, empty when it did not run.
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


def _argument_scratch(scratch: Path, fixture: Path) -> Path:
    """Lay out under scratch/dir the paths ARGUMENT_CASES name, and return
    scratch/link, a symbolic link to it, which the cases run from."""
    root = scratch / "dir"
    (root / "fixfile").mkdir(parents=True)
    (root / "fixfile" / "fixtures").write_text("a file, not a directory\n")
    (root / "fixfile" / "x.json").write_bytes(fixture.read_bytes())
    (root / "root" / "fixtures").mkdir(parents=True)
    (root / "root" / "fixtures" / "x.json").write_bytes(fixture.read_bytes())
    (root / "root" / "conformance.json").write_text("{}\n")
    (root / "nojson").mkdir()
    (root / "nojson" / "README.md").write_text("not a fixture\n")
    (root / "-h.json").write_bytes(fixture.read_bytes())
    link = scratch / "link"
    link.symlink_to("dir", target_is_directory=True)
    return link


def _without_program(line: str, program: str) -> str:
    """line without the program name it opens with or names after `usage: `,
    so the two verifiers' lines compare on their wording alone."""
    return re.sub(rf"^(usage:\s+)?{re.escape(program)}(?![\w.])", r"\1", line)


def verdict_lines(stdout: str) -> list[str]:
    """The report lines that carry a verdict: each `PASS  <path>` or
    `FAIL  <path>` line, its observed verdict and category, and the summary.
    The rest of a block is each verifier's own wording."""
    lines: list[str] = []
    for line in stdout.splitlines():
        if m := BLOCK_RE.match(line):
            lines.append(f"{m.group(1)}  {m.group(2)}")
        elif m := OBSERVED_RE.match(line):
            lines.append(f"observed: {m.group(1)}" + ("]" if m.group(2) else ""))
        elif line.startswith("summary:"):
            lines.append(line)
    return lines


def run_case(spec: dict, args: list[str], cwd: Path) -> dict:
    """One verifier's outcome on one argument list, run from cwd with PWD
    naming it: its exit code, first stderr line and verdict lines, without
    its program name."""
    proc = subprocess.run(
        spec["argv"] + args, cwd=cwd, capture_output=True, text=True,
        env={**os.environ, "PWD": str(cwd)},
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
    """Whether outcome is the answer to no argument that spec documents: a
    verifier that embeds a fixture set reports it, here fixtures, each
    named fixtures/<name> and passing, and exits 0; one that embeds none
    writes its usage on stderr, reports nothing and exits 2."""
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
) -> tuple[list[dict], list[str]]:
    """Run every case of cases on every verifier in programs, from a
    symbolic link to scratch, with fixture as fixfile/x.json. A verifier that
    embeds a fixture set is taken to embed the *.json beside fixture.

    Return (rows, divergences): a row per case holding each verifier's
    outcome, and a divergence naming each case the outcomes differ on, or,
    for no argument, are not each the one _answers_no_argument documents.
    """
    cwd = _argument_scratch(scratch, fixture)
    # str.format expands {link}, {target} and {fixture}, so a misspelt name
    # raises instead of reaching a verifier as written.
    names = {
        "link": str(cwd), "target": os.path.realpath(cwd), "fixture": os.path.abspath(fixture),
    }
    embedded = sorted(p.name for p in fixture.parent.glob("*.json"))
    rows: list[dict] = []
    divergences: list[str] = []
    for case, args in cases:
        argv = [arg.format(**names) for arg in args]
        outcomes = {name: run_case(spec, argv, cwd) for name, spec in programs.items()}
        if args:
            agree = len({json.dumps(o, sort_keys=True) for o in outcomes.values()}) == 1
        else:
            agree = all(_answers_no_argument(programs[name], o, embedded)
                        for name, o in outcomes.items())
        rows.append({"case": case, "args": args, "agree": agree, "outcomes": outcomes})
        if not agree:
            divergences.append(
                f'argument case "{case}" ({shlex.join(args)}): {_outcomes(outcomes)}')
    return rows, divergences


def _argument_row(case: str, args: list[str], text: str) -> str:
    return f"  {case:32s} {shlex.join(args):30s} {text}"


def render_arguments(rows: list[dict]) -> list[str]:
    """Return the lines of the argument table: per case its arguments and
    the outcome the verifiers share, or each verifier's where they differ
    and for no argument, which they answer differently by design."""
    if not rows:
        return ["arguments: not run (see PARITY: FAIL below)"]
    lines = [f"arguments: {len(rows)} cases x {len(rows[0]['outcomes'])} verifiers"]
    for row in rows:
        if not row["args"]:
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
    nothing and exits 0."""
    src = (
        "import sys\n"
        f"out, err, code = {outcomes!r}.get(tuple(sys.argv[1:]), ('', '', 0))\n"
        "sys.stdout.write(out)\n"
        "sys.stderr.write(err)\n"
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


def _argument_divergences(programs: dict[str, dict], *cases: str) -> list[str]:
    """The divergences of the argument-table cases named cases, run on
    stand-ins."""
    run = [(case, args) for case, args in ARGUMENT_CASES if case in cases]
    if len(run) != len(cases):
        raise ValueError(f"not every one of {cases} is a case of ARGUMENT_CASES")
    with tempfile.TemporaryDirectory() as d:
        fixture = Path(d) / ARGUMENT_FIXTURE
        fixture.write_text("{}\n")
        return compare_arguments(programs, fixture, Path(d) / "run", run)[1]


def _gate_with_arguments(
    programs: Callable[[Path], dict[str, dict]],
) -> tuple[int, str, dict]:
    """(exit code, stdout, --json report) of the gate over one fixture the
    fixture-table stand-ins agree on, with programs giving the argument
    table's verifiers."""
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as d:
        fixtures, report = Path(d) / "fixtures", Path(d) / "report.json"
        fixtures.mkdir()
        (fixtures / ARGUMENT_FIXTURE).write_text("{}\n")
        agree = _stand_in(_block(ARGUMENT_FIXTURE, "ACCEPT"))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = gate(fixtures, {"one": agree, "two": agree}, str(report), programs)
        return code, out.getvalue(), json.loads(report.read_text())


def _not_built(bin_dir: Path) -> dict[str, dict]:
    raise BuildError("go build exited 1: boom")


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
    # for eleven cases and for no argument its report of that set, the
    # ARGUMENT_FIXTURE beside the table's fixture; "two", which embeds none,
    # writes kept and for no argument its usage, with one case's outcome
    # changed. A case is run alone, by name, except in the gate runs, which
    # run the whole table.
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

    missing = ("", "error: missing: no such file or directory\n", 2)
    kept = {
        argv_of[empty_case]: (
            "", "error: an empty argument names no fixture file or directory\n", 2),
        argv_of[fixfile_case]: fixfile,
        argv_of[missing_case]: missing,
        argv_of[version_case]: ("atx-verify: (devel), built with go1.22.12\n", "", 0),
        argv_of[unknown_case]: ("", "unknown option: --bogus\n", 2),
        argv_of[root_case]: (
            fixfile[0].replace("fixfile/x.json", "root/fixtures/x.json"), "", 0),
        argv_of[twice_case]: (
            fixfile[0].replace("\nsummary: 1 pass, 0 fail (1 fixtures)\n", "")
            + fixfile[0].replace("summary: 1 pass, 0 fail (1 fixtures)",
                                 "summary: 2 pass, 0 fail (2 fixtures)"), "", 0),
        argv_of[spelled_case]: passes("./fixfile/./x.json", "fixfile//x.json"),
        argv_of[dotdot_case]: passes("fixfile/x.json"),
        argv_of[slash_case]: ("", "error: stat fixfile/x.json/: not a directory\n", 2),
        argv_of[dashdash_case]: (fixfile[0].replace("fixfile/x.json", "-h.json"), "", 0),
    }
    embedded = (fixfile[0].replace("fixfile/x.json", f"fixtures/{ARGUMENT_FIXTURE}"), "", 0)
    no_argument = argv_of[no_argument_case]

    def changed(
        outcomes: dict[tuple[str, ...], tuple[str, str, int]],
        one: dict[tuple[str, ...], tuple[str, str, int]] | None = None,
    ) -> dict[str, dict]:
        return {
            "one": _argument_stand_in(
                "atx-verify", {**kept, no_argument: embedded, **(one or {})}, embeds=True),
            "two": _argument_stand_in("verify.py", {
                **kept, no_argument: ("", "usage: verify.py <fixture.json|dir>...\n", 2),
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
    args_slash = _argument_divergences(changed(
        {argv_of[slash_case]: passes("fixfile/x.json")}), slash_case)
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
    gate_fails = _gate_with_arguments(lambda bin_dir: changed(exit_changed))
    gate_passes = _gate_with_arguments(lambda bin_dir: changed({}))
    gate_not_built = _gate_with_arguments(_not_built)
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
             "two exit 1, verdict lines ['FAIL  root/conformance.json', "
             "'summary: 0 pass, 1 fail (1 fixtures)']"]),
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
        ("a file named with a trailing /, which one verifier verifies, is a divergence",
         args_slash == [
             'argument case "a file named with a trailing /" (fixfile/x.json/): '
             "one exit 2, stderr 'error: stat fixfile/x.json/: not a directory'; "
             "two exit 0, verdict lines ['PASS  fixfile/x.json', 'observed: ACCEPT', "
             "'summary: 1 pass, 0 fail (1 fixtures)']"]),
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
) -> int:
    """Run the verifiers over the *.json in fixtures_dir, then the argument
    table on the verifiers programs returns for a scratch directory; return
    the exit code."""
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
                argument_programs, fixtures_dir / ARGUMENT_FIXTURE, Path(scratch) / "run")
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
    print("\nPARITY: PASS (all implementations agree on gate, verdict, and category, "
          "and on every argument case)")
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
