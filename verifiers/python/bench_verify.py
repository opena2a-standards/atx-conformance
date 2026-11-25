#!/usr/bin/env python3
"""Benchmark of the Python reference verifier: the time verify_fixture takes
to verify one credential, its strict parse, its checks and every signature it
declares.

It times the fixtures BENCHMARK_FIXTURES names, the fixtures the Go reference
verifier's BenchmarkVerify times (verifiers/go/verifier/verify_bench_test.go):
the baseline credential of ATX v1.0 and of v1.1, each signed with Ed25519
alone and with Ed25519 plus ML-DSA-65 (the -hybrid names). Each fixture is
read with load_fixture once, before its timing starts, so reading and
decoding the file is not timed. verify_fixture must first accept the
credential, as the fixture's expected outcome says; it is then called again
and again until --benchtime seconds (1 by default) have passed, and one line
gives the number of timed calls and their mean time in nanoseconds, in the
form `go test -bench` writes its figures:

    BenchmarkVerify/v1_1-baseline-valid-hybrid<TAB><calls><TAB><mean> ns/op

scripts/bench_report.py runs this benchmark and the Go one, and prints each
figure with the commit and the CPU it ran on.

The exit status depends on no time: 0 when a line was written for every
fixture, 1 when a fixture cannot be read or is not accepted (its name and why
on standard error; the other fixtures are still timed), and 2 when an
argument is not one this script reads. Importing verify.py exits 2 with its
own message when a dependency is missing.

Needs the verifier's dependencies (requirements.txt). Run from this directory:

    python3 bench_verify.py
    python3 bench_verify.py --benchtime 0.5
"""

from __future__ import annotations

import math
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import verify  # noqa: E402

FIXTURES = HERE.parent.parent / "fixtures"
BENCHMARK_FIXTURES = (
    "baseline-valid",
    "baseline-valid-hybrid",
    "v1_1-baseline-valid",
    "v1_1-baseline-valid-hybrid",
)
USAGE = "usage: bench_verify.py [--benchtime <seconds>]\n"


def accepted_fixture(path: Path) -> dict[str, Any]:
    """The fixture at path, once verify_fixture has accepted its credential
    as its expected outcome says. Raises ValueError when it is not accepted,
    and what load_fixture raises when the file cannot be loaded."""
    fixture = verify.load_fixture(path)
    expected = verify._expected_outcome(fixture)
    got = verify.verify_fixture(fixture)
    if expected["verifyResult"] != "ACCEPT" or not got.accepted:
        raise ValueError(
            f"expected {expected['verifyResult']}, observed {got}; a benchmark fixture must expect and reach ACCEPT"
        )
    return fixture


def time_calls(fixture: dict[str, Any], benchtime: float) -> tuple[int, float]:
    """Call verify_fixture(fixture) until benchtime seconds have passed, at
    least once, and return the number of calls and their mean time in
    nanoseconds."""
    calls = 0
    start = time.perf_counter_ns()
    deadline = start + benchtime * 1e9
    while True:
        verify.verify_fixture(fixture)
        calls += 1
        now = time.perf_counter_ns()
        if now >= deadline:
            return calls, (now - start) / calls


def seconds(value: str | None) -> float | None:
    """value read as a number of seconds above 0, or None when it is absent,
    not a number, not finite or not above 0."""
    try:
        number = float(value) if value is not None else math.nan
    except ValueError:
        return None
    return number if math.isfinite(number) and number > 0 else None


def main(argv: list[str], fixtures: tuple[str, ...] = BENCHMARK_FIXTURES) -> int:
    args = argv[1:]
    if "-h" in args or "--help" in args:
        sys.stdout.write(USAGE)
        return 0
    benchtime, unknown = 1.0, []
    rest = iter(args)
    for arg in rest:
        if arg != "--benchtime":
            unknown.append(arg)
            continue
        value = next(rest, None)
        given = seconds(value)
        if given is None:
            given_as = "" if value is None else ", not " + repr(value)
            sys.stderr.write(f"--benchtime takes a number of seconds above 0{given_as}\n{USAGE}")
            return 2
        benchtime = given
    if unknown:
        sys.stderr.write(f"unknown argument(s): {' '.join(unknown)}\n{USAGE}")
        return 2
    status = 0
    for name in fixtures:
        try:
            fixture = accepted_fixture(FIXTURES / f"{name}.json")
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"{name}: {exc}\n")
            status = 1
            continue
        calls, mean = time_calls(fixture, benchtime)
        print(f"BenchmarkVerify/{name}\t{calls}\t{mean:.0f} ns/op", flush=True)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
