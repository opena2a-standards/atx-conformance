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
mismatch naming every fixture it never reached.

Every run starts with the self-test, which proves on stand-in verifiers that
the gate reports a disagreement, a skipped fixture, a failed verifier and a
verifier that exits 0 without reporting any fixture, and that --json is
refused with --self-test.

Usage:
    python3 scripts/parity/parity.py [--json parity-report.json]
    python3 scripts/parity/parity.py --self-test

--self-test writes no parity report, so it is refused with --json rather than
leaving the report path unwritten.

Exit codes: 0 = all implementations agree, 1 = divergence or verifier error,
2 = usage error.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

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
) -> tuple[dict[str, dict], dict[str, int], list[str]]:
    """Run every verifier over fixture_files; return (table, exit_codes, divergences)."""
    results: dict[str, dict[str, dict]] = {}
    exit_codes: dict[str, int] = {}
    divergences: list[str] = []
    for name, spec in verifiers.items():
        code, records, stderr = run_verifier(name, spec)
        exit_codes[name] = code
        results[name] = records
        if code != 0:
            d = f"{name} verifier exited {code} (expected 0)"
            if not records:
                d += " before reporting any fixture"
            divergences.append(f"{d}: {stderr}" if stderr else d)

    for name, records in results.items():
        # A verifier that failed before reporting any fixture is already
        # reported by its exit code and stderr; listing every fixture as
        # missing would hide that cause behind a fixture set mismatch.
        if exit_codes[name] != 0 and not records:
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
    return table, exit_codes, divergences


# --- self-test ---------------------------------------------------------------
# Stand-in verifiers print the PASS/FAIL block format the real ones print, so
# the self-test drives compare() through run_verifier() without Go, the
# fixtures or the Python verifier's dependencies.

MISSING_DEP = (
    "missing dependency: dilithium-py. install with `pip install -r requirements.txt`"
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


def _divergences(fixture_files: list[str], verifiers: dict[str, dict]) -> list[str]:
    with contextlib.redirect_stderr(io.StringIO()):
        return compare(fixture_files, verifiers)[2]


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
    no_dep = _divergences(fx, {
        "one": _stand_in(both), "two": _stand_in("", MISSING_DEP + "\n", 2),
    })
    crashed = _divergences(fx, {
        "one": _stand_in(both),
        "two": _stand_in(_block("a.json", "ACCEPT"), "Traceback: boom\n", 1),
    })
    silent = _divergences(fx, {"one": _stand_in(both), "two": _stand_in("")})
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
         _usage_error(["--self-test", "--json", "out.json"])
         == (2, f"parity.py: error: {SELF_TEST_JSON_ERROR}")
         and _usage_error(["--self-test"]) is None
         and _usage_error(["--json", "out.json"]) is None),
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
    args = ap.parse_args(argv)
    if args.self_test and args.json is not None:
        ap.error(SELF_TEST_JSON_ERROR)
    return args


def main() -> int:
    args = parse_args()

    if self_test():
        return 1
    if args.self_test:
        return 0

    fixture_files = sorted(p.name for p in (REPO_ROOT / "fixtures").glob("*.json"))
    if not fixture_files:
        sys.stderr.write("[parity] no fixtures found\n")
        return 1

    table, exit_codes, divergences = compare(fixture_files, VERIFIERS)
    names = list(VERIFIERS)

    print(f"\nparity: {len(fixture_files)} fixtures x {len(names)} verifiers")
    for fx, row in table.items():
        cells = []
        for n in names:
            r = row[n]
            if r is None:
                cells.append(f"{n}=MISSING")
            else:
                v = r["verdict"] or "?"
                cat = f"[{r['category']}]" if r["category"] else ""
                cells.append(f"{n}={r['gate']}:{v}{cat}")
        print(f"  {fx:44s} {'  '.join(cells)}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "fixtures": table,
                    "exitCodes": exit_codes,
                    "divergences": divergences,
                    "agree": not divergences,
                },
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
    print("\nPARITY: PASS (all implementations agree on gate, verdict, and category)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
