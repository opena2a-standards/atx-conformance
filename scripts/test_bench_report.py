#!/usr/bin/env python3
"""Tests of scripts/bench_report.py, which prints each benchmark figure of the
reference verifiers on a line of its own with the benchmark's name, the
commit and the CPU it ran on.

Most tests give main a runner that answers the two benchmark commands and
`go env GOVERSION` with fixed text and runs every other command, git among
them. They hold each printed line to its fields in their order, and the exit
status to whether each benchmark exited 0 and wrote a figure, never to a
figure's value. Others hold the commit and uncommittedChanges fields to a
scratch git repository, the CPU model to the line of /proc/cpuinfo or lscpu
that names it, and a value outside the plain characters to a JSON string.
One test runs the script for a short time with both benchmarks and holds the
Go and the Python benchmark to timing the same fixtures under the same
names; it needs Go and the Python verifier's dependencies. Run from the
repository root:

    python3 -m unittest discover -v -s scripts -t scripts -p 'test_bench_report.py'
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import bench_report  # noqa: E402

# The fields of a printed line, in their order.
KEYS = ["verifier", "benchmark", "msPerOp", "calls", "commit", "uncommittedChanges", "cpu", "cores", "runtime"]
FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^ "]+)(?: |$)')
# The fixtures both benchmarks time, as the docs and both benchmark files
# name them.
FIXTURES = ["baseline-valid", "baseline-valid-hybrid", "v1_1-baseline-valid", "v1_1-baseline-valid-hybrid"]
PYTHON_RUNTIME = platform.python_implementation().lower() + platform.python_version()
# Output in the forms go test -bench and bench_verify.py write.
GO_OUTPUT = (
    "goos: linux\ngoarch: amd64\n"
    "pkg: github.com/opena2a-standards/atx-conformance/verifiers/go/verifier\n"
    "cpu: AMD EPYC 7763 64-Core Processor\n"
    "BenchmarkVerify/baseline-valid         \t   20000\t     61234 ns/op\n"
    "BenchmarkVerify/v1_1-baseline-valid-hybrid         \t    5000\t    212345 ns/op\n"
    "PASS\nok  \tgithub.com/opena2a-standards/atx-conformance/verifiers/go/verifier\t3.008s\n"
)
PYTHON_OUTPUT = (
    "BenchmarkVerify/baseline-valid\t9000\t110000 ns/op\n"
    "BenchmarkVerify/v1_1-baseline-valid-hybrid\t170\t5760000 ns/op\n"
)
GIT_ENV = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}


def fields(line: str) -> dict[str, str]:
    """The key=value fields line is made of, each JSON string decoded. Raises
    AssertionError where line is not a run of such fields."""
    found, at = {}, 0
    while at < len(line):
        match = FIELD.match(line, at)
        if match is None:
            raise AssertionError(f"not a key=value field at {at}: {line!r}")
        value = match.group(2)
        found[match.group(1)] = json.loads(value) if value.startswith('"') else value
        at = match.end()
    return found


def head(repo: Path = ROOT) -> str:
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], env=GIT_ENV,
                          capture_output=True, text=True, check=True).stdout.strip()


def fake(go=(0, GO_OUTPUT), python=(0, PYTHON_OUTPUT)):
    """A runner that answers the Go benchmark, the Python benchmark and
    `go env GOVERSION` with (exit status, standard output), raising the
    status instead when it is an exception, and runs any other command."""

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["go", "test"]:
            status, out = go
        elif len(argv) > 1 and argv[1] == "verifiers/python/bench_verify.py":
            status, out = python
        elif argv == ["go", "env", "GOVERSION"]:
            status, out = 0, "go1.22.12\n"
        else:
            return bench_report.run(argv)
        if isinstance(status, BaseException):
            raise status
        return subprocess.CompletedProcess(argv, status, out, "")

    return runner


def call(runner, *args: str) -> tuple[int, str, str]:
    """main run with runner and args: its exit status, standard output and
    standard error."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = bench_report.main(["bench_report.py", *args], runner)
    return status, out.getvalue(), err.getvalue()


class FigureLines(unittest.TestCase):
    def test_each_figure_is_a_line_with_its_benchmark_commit_cpu_and_cores(self):
        status, out, err = call(fake())
        self.assertEqual((status, err), (0, ""))
        rows = [fields(line) for line in out.splitlines()]
        for row in rows:
            self.assertEqual(list(row), KEYS)
            self.assertEqual(row["commit"], head())
            self.assertIn(row["uncommittedChanges"], ("true", "false"))
            self.assertEqual(row["cpu"], bench_report.cpu_model(bench_report.run))
            self.assertNotEqual(row["cpu"], "unknown")
            self.assertEqual(row["cores"], str(os.cpu_count()))
        self.assertEqual([(row["verifier"], row["benchmark"], row["msPerOp"], row["calls"], row["runtime"])
                          for row in rows], [
            ("go", "BenchmarkVerify/baseline-valid", "0.0612", "20000", "go1.22.12"),
            ("go", "BenchmarkVerify/v1_1-baseline-valid-hybrid", "0.2123", "5000", "go1.22.12"),
            ("python", "BenchmarkVerify/baseline-valid", "0.1100", "9000", PYTHON_RUNTIME),
            ("python", "BenchmarkVerify/v1_1-baseline-valid-hybrid", "5.7600", "170", PYTHON_RUNTIME),
        ])

    def test_no_exit_status_depends_on_a_figure(self):
        for nanoseconds, ms in (("1", "0.0000"), ("1000000000000000", "1000000000.0000")):
            with self.subTest(nanoseconds=nanoseconds):
                figure = f"BenchmarkVerify/baseline-valid\t1\t{nanoseconds} ns/op\n"
                status, out, err = call(fake(go=(0, figure), python=(0, figure)))
                self.assertEqual((status, err), (0, ""))
                self.assertEqual([fields(line)["msPerOp"] for line in out.splitlines()], [ms, ms])

    def test_a_benchmark_that_fails_fails_the_run_and_the_other_is_printed(self):
        failed = "--- FAIL: BenchmarkVerify/baseline-valid\nFAIL\n"
        status, out, err = call(fake(go=(1, failed)))
        self.assertEqual(status, 1)
        self.assertEqual([fields(line)["verifier"] for line in out.splitlines()], ["python", "python"])
        self.assertTrue(err.startswith("the go benchmark exited 1 and wrote 0 figures: go test "), err)
        self.assertTrue(err.endswith("\n" + failed), err)

    def test_a_benchmark_that_writes_no_figure_fails_the_run(self):
        status, out, err = call(fake(python=(0, "")))
        self.assertEqual(status, 1)
        self.assertEqual([fields(line)["verifier"] for line in out.splitlines()], ["go", "go"])
        self.assertTrue(err.startswith("the python benchmark exited 0 and wrote 0 figures: "), err)

    def test_a_benchmark_that_cannot_start_fails_the_run(self):
        missing = FileNotFoundError(2, "No such file or directory", "go")
        status, out, err = call(fake(go=(missing, "")))
        self.assertEqual(status, 1)
        self.assertEqual([fields(line)["verifier"] for line in out.splitlines()], ["python", "python"])
        self.assertTrue(err.startswith("the go benchmark did not run ("), err)

    def test_benchtime_reaches_both_benchmarks(self):
        commands = dict(bench_report.benchmarks(0.25))
        self.assertEqual(commands["go"][commands["go"].index("-benchtime") + 1], "250000000ns")
        self.assertEqual(commands["python"][-2:], ["--benchtime", "0.25"])
        for args in (["--benchtime"], ["--benchtime", "0"], ["--benchtime", "-1"], ["--benchtime", "nan"],
                     ["--benchtime", "inf"], ["--benchtime", "x"]):
            with self.subTest(args=args):
                status, out, err = call(fake(), *args)
                self.assertEqual((status, out), (2, ""))
                self.assertTrue(err.startswith("--benchtime takes a number of seconds above 0"), err)
                self.assertTrue(err.endswith(bench_report.USAGE), err)


class Commit(unittest.TestCase):
    def test_the_commit_is_head_and_a_changed_tracked_file_is_named(self):
        env = {**GIT_ENV, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        with tempfile.TemporaryDirectory() as scratch:
            repo = Path(scratch)

            def git(*args: str) -> None:
                subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, check=True)

            self.assertEqual(bench_report.commit(bench_report.run, repo), ("unknown", "unknown"))
            git("init", "-q")
            (repo / "tracked.txt").write_text("1\n")
            git("add", "tracked.txt")
            git("-c", "user.name=bench", "-c", "user.email=bench@example.invalid", "commit", "-q", "-m", "one")
            sha = head(repo)
            self.assertEqual(bench_report.commit(bench_report.run, repo), (sha, "false"))
            (repo / "untracked.txt").write_text("not added\n")
            self.assertEqual(bench_report.commit(bench_report.run, repo), (sha, "false"))
            (repo / "tracked.txt").write_text("2\n")
            self.assertEqual(bench_report.commit(bench_report.run, repo), (sha, "true"))


class CPUModel(unittest.TestCase):
    def test_the_model_name_line_of_proc_cpuinfo(self):
        cpuinfo = ("processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel\t\t: 1\n"
                   "model name\t: AMD EPYC 7763 64-Core   Processor\n")
        self.assertEqual(bench_report.model_name(cpuinfo, "model name"), "AMD EPYC 7763 64-Core Processor")

    def test_the_model_name_line_of_lscpu(self):
        lscpu = "Architecture:             aarch64\nModel name:               Neoverse-N2\nModel:                    0\n"
        self.assertEqual(bench_report.model_name(lscpu, "Model name"), "Neoverse-N2")

    def test_no_model_line_reads_as_empty(self):
        arm64_cpuinfo = "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: 0xd49\n"
        self.assertEqual(bench_report.model_name(arm64_cpuinfo, "model name"), "")


class Fields(unittest.TestCase):
    def test_a_value_outside_the_plain_characters_is_a_json_string(self):
        self.assertEqual(bench_report.field("benchmark", "BenchmarkVerify/v1_1-baseline-valid-hybrid"),
                         "benchmark=BenchmarkVerify/v1_1-baseline-valid-hybrid")
        self.assertEqual(bench_report.field("cpu", "Apple M4 Max"), 'cpu="Apple M4 Max"')
        self.assertEqual(bench_report.field("cpu", 'a "b" c=d'), 'cpu="a \\"b\\" c=d"')
        self.assertEqual(bench_report.field("cpu", ""), 'cpu=""')


class BothVerifiers(unittest.TestCase):
    def test_both_reference_verifiers_time_the_same_fixtures(self):
        done = subprocess.run([sys.executable, str(SCRIPTS / "bench_report.py"), "--benchtime", "0.001"],
                              cwd=ROOT, capture_output=True, text=True, timeout=1200)
        self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
        rows = [fields(line) for line in done.stdout.splitlines()]
        want = [f"BenchmarkVerify/{name}" for name in FIXTURES]
        for verifier in ("go", "python"):
            with self.subTest(verifier=verifier):
                self.assertEqual([row["benchmark"] for row in rows if row["verifier"] == verifier], want)
        self.assertEqual(len(rows), 2 * len(want))
        for row in rows:
            self.assertEqual(list(row), KEYS)
            self.assertEqual(row["commit"], head())
            self.assertGreaterEqual(int(row["calls"]), 1)
            self.assertNotEqual(row["runtime"], "unknown")


if __name__ == "__main__":
    unittest.main()
