#!/usr/bin/env python3
"""Tests of bench_verify.py, the benchmark of the Python reference verifier.

They hold its output to one line per benchmark fixture in the form
`go test -bench` writes its figures; each benchmark fixture to what its name
says (verify_fixture accepts it with every signature valid, an ML-DSA-65
signature among them exactly when the name ends in -hybrid, and leaves the
fixture as it found it, so each timed call does the same work); a fixture
that is not accepted or cannot be read to exit 1 with the others still
timed; the exit status to no time, with a clock that says one call took 1 ns
and one that says it took 10^15 ns; and its arguments to --help, an unknown
argument and a --benchtime that is not a number of seconds above 0.

Needs the same dependencies as verify.py. Run from this directory:

    python3 -m unittest -v test_bench_verify
"""

from __future__ import annotations

import contextlib
import copy
import io
import itertools
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import bench_verify  # noqa: E402
import verify  # noqa: E402

FIGURE = re.compile(r"BenchmarkVerify/(\S+)\t(\d+)\t(\d+) ns/op")


def call(*args: str, fixtures: tuple[str, ...] = bench_verify.BENCHMARK_FIXTURES) -> tuple[int, str, str]:
    """main run with args: its exit status, standard output and standard
    error."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = bench_verify.main(["bench_verify.py", *args], fixtures)
    return status, out.getvalue(), err.getvalue()


class BenchVerify(unittest.TestCase):
    def test_writes_one_line_per_fixture_in_the_go_form(self):
        status, out, err = call("--benchtime", "0.001")
        self.assertEqual((status, err), (0, ""))
        lines = out.splitlines()
        self.assertTrue(all(FIGURE.fullmatch(line) for line in lines), out)
        self.assertEqual([FIGURE.fullmatch(line).group(1) for line in lines],
                         list(bench_verify.BENCHMARK_FIXTURES))
        self.assertTrue(all(int(FIGURE.fullmatch(line).group(2)) >= 1 for line in lines), out)

    def test_each_fixture_is_accepted_with_its_signatures(self):
        for name in bench_verify.BENCHMARK_FIXTURES:
            with self.subTest(fixture=name):
                fixture = bench_verify.accepted_fixture(bench_verify.FIXTURES / f"{name}.json")
                before = copy.deepcopy(fixture)
                got = verify.verify_fixture(fixture)
                self.assertTrue(got.accepted, got)
                self.assertGreater(got.sigs_expected, 0)
                self.assertEqual(got.sigs_valid, got.sigs_expected)
                self.assertTrue(got.ed25519_valid)
                self.assertEqual(got.mldsa65_valid, name.endswith("-hybrid"))
                self.assertEqual(fixture, before)
                self.assertEqual(verify.verify_fixture(fixture), got)

    def test_a_fixture_it_does_not_accept_exits_1_and_the_others_are_timed(self):
        status, out, err = call("--benchtime", "0.001", fixtures=("tampered-signature", "no-such-fixture", "baseline-valid"))
        self.assertEqual(status, 1)
        self.assertEqual([FIGURE.fullmatch(line).group(1) for line in out.splitlines()], ["baseline-valid"])
        rejected, missing = err.splitlines()
        self.assertTrue(rejected.startswith("tampered-signature: expected REJECT, observed REJECT["), err)
        self.assertTrue(missing.startswith("no-such-fixture: "), err)

    def test_no_exit_status_depends_on_a_time(self):
        for step in (1, 10**15):
            with self.subTest(nanoseconds=step):
                ticks = itertools.count(0, step)
                with mock.patch.object(bench_verify.time, "perf_counter_ns", side_effect=lambda: next(ticks)):
                    status, out, err = call("--benchtime", "1e-9", fixtures=("baseline-valid",))
                self.assertEqual((status, out, err), (0, f"BenchmarkVerify/baseline-valid\t1\t{step} ns/op\n", ""))

    def test_arguments(self):
        for flag in ("-h", "--help"):
            with self.subTest(args=flag):
                self.assertEqual(call(flag), (0, bench_verify.USAGE, ""))
        self.assertEqual(call("--bogus"), (2, "", "unknown argument(s): --bogus\n" + bench_verify.USAGE))
        for args in (["--benchtime"], ["--benchtime", "0"], ["--benchtime", "-1"], ["--benchtime", "nan"],
                     ["--benchtime", "inf"], ["--benchtime", "x"]):
            with self.subTest(args=args):
                status, out, err = call(*args)
                self.assertEqual((status, out), (2, ""))
                self.assertTrue(err.startswith("--benchtime takes a number of seconds above 0"), err)
                self.assertTrue(err.endswith(bench_verify.USAGE), err)


if __name__ == "__main__":
    unittest.main()
