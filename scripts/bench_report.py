#!/usr/bin/env python3
"""Runs the benchmark of each reference verifier and prints each figure on a
line of its own, with the benchmark's name, the commit of this checkout and
the CPU it ran on.

The benchmarks, each run from the repository root:

  go      BenchmarkVerify (verifiers/go/verifier/verify_bench_test.go), as
          go test -run '^$' -bench '^BenchmarkVerify$' -benchtime <n>ns
          -cpu 1 -count 1 ./verifiers/go/verifier
  python  verifiers/python/bench_verify.py --benchtime <seconds>, run by the
          Python that runs this script

Each times the verification of one credential on the baseline credential of
ATX v1.0 and of v1.1, each signed with Ed25519 alone and with Ed25519 plus
ML-DSA-65, and writes a line per fixture in the form `go test -bench` writes
its figures. For each such line this script prints one line of key=value
fields, in this order:

  verifier            go or python
  benchmark           the benchmark's name, BenchmarkVerify/<fixture>
  msPerOp             the mean time of one verification, in milliseconds
  calls               the number of timed verifications the mean is over
  commit              what `git rev-parse HEAD` names in the checkout this
                      script is in: `git -C .suite rev-parse HEAD` when it
                      runs as .suite/scripts/bench_report.py
  uncommittedChanges  true when a tracked file there differs from that commit
  cpu                 the CPU model the operating system reports
  cores               the number of logical CPUs, os.cpu_count()
  runtime             the Go or Python release the benchmark ran on

A value holding a character outside [A-Za-z0-9._/:+@-] is written as a JSON
string, and a value this script cannot read as unknown.

No exit status depends on a figure: the exit status is 0 when each benchmark
exited 0 and wrote at least one figure, 1 when one did not (the command and
what it wrote go to standard error; the other benchmark's figures are still
printed), and 2 when an argument is not one this script reads.

The Python benchmark needs the verifier's dependencies
(verifiers/python/requirements.txt). Usage:

    python3 scripts/bench_report.py
    python3 scripts/bench_report.py --benchtime 0.2
"""

from __future__ import annotations

import json
import math
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
USAGE = "usage: bench_report.py [--benchtime <seconds>]\n"
# A figure line of `go test -bench`, and of verifiers/python/bench_verify.py:
# the benchmark's name, the number of timed calls and nanoseconds per call.
FIGURE = re.compile(r"(Benchmark\S+)\s+(\d+)\s+(\d+(?:\.\d+)?) ns/op(?:\s|$)")
# A value made of these characters is written as it is.
PLAIN = re.compile(r"[A-Za-z0-9._/:+@-]+")
TIMEOUT_SECONDS = 1800

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """argv run in the repository root, its output captured as text, with no
    GIT_* variable in its environment, so one that a hook exports does not
    name another repository to git."""
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    return subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS)


def output(runner: Runner, argv: list[str]) -> str:
    """What argv writes to standard output, stripped, or "" when it cannot
    run or exits other than 0."""
    try:
        done = runner(argv)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def commit(runner: Runner, root: Path = ROOT) -> tuple[str, str]:
    """The commit git names as HEAD of the checkout at root, and "true" when a
    tracked file there differs from it, else "false"; "unknown" for what git
    cannot answer, such as in a directory that is not a checkout."""
    head = output(runner, ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"])
    if not head:
        return "unknown", "unknown"
    try:
        status = runner(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"])
    except (OSError, subprocess.SubprocessError):
        return head, "unknown"
    if status.returncode != 0:
        return head, "unknown"
    return head, "true" if status.stdout.strip() else "false"


def model_name(text: str, key: str) -> str:
    """The value of the first line of text that reads `<key>: <value>`, the
    key matched with the blanks around it ignored and runs of blanks in the
    value written as one, or "" when no line has that key."""
    for line in text.splitlines():
        name, colon, value = line.partition(":")
        if colon and name.strip() == key:
            return " ".join(value.split())
    return ""


def cpu_model(runner: Runner) -> str:
    """The CPU model the operating system reports: on macOS the
    machdep.cpu.brand_string sysctl, on Linux the "model name" line of
    /proc/cpuinfo or, where it has none (as on arm64), the "Model name" line
    of lscpu, and elsewhere platform.processor(); "unknown" when none names
    one."""
    model = ""
    if sys.platform == "darwin":
        model = output(runner, ["sysctl", "-n", "machdep.cpu.brand_string"])
    elif sys.platform.startswith("linux"):
        try:
            model = model_name(Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace"), "model name")
        except OSError:
            model = ""
        if not model:
            model = model_name(output(runner, ["env", "LC_ALL=C", "lscpu"]), "Model name")
    model = " ".join((model or platform.processor()).split())
    return model or "unknown"


def cores() -> str:
    """The number of logical CPUs, os.cpu_count(), or "unknown"."""
    count = os.cpu_count()
    return str(count) if count else "unknown"


def field(key: str, value: object) -> str:
    """key=value, the value written as a JSON string unless it is made of
    PLAIN characters alone."""
    text = str(value)
    return f"{key}={text if PLAIN.fullmatch(text) else json.dumps(text)}"


def figures(text: str) -> list[tuple[str, int, float]]:
    """Each figure line of text, as the benchmark's name, the number of timed
    calls and the nanoseconds per call."""
    found = []
    for line in text.splitlines():
        match = FIGURE.match(line)
        if match:
            found.append((match.group(1), int(match.group(2)), float(match.group(3))))
    return found


def benchmarks(benchtime: float) -> list[tuple[str, list[str]]]:
    """Each verifier's name and the command that runs its benchmark for
    benchtime seconds per fixture."""
    nanoseconds = max(1, round(benchtime * 1e9))
    return [
        ("go", ["go", "test", "-run", "^$", "-bench", "^BenchmarkVerify$", "-benchtime", f"{nanoseconds}ns",
                "-cpu", "1", "-count", "1", "./verifiers/go/verifier"]),
        ("python", [sys.executable or "python3", "verifiers/python/bench_verify.py", "--benchtime", repr(benchtime)]),
    ]


def runtime(verifier: str, runner: Runner) -> str:
    """The Go release `go env GOVERSION` names, or the Python implementation
    and release running this script, which runs the Python benchmark."""
    if verifier == "go":
        return output(runner, ["go", "env", "GOVERSION"]) or "unknown"
    return platform.python_implementation().lower() + platform.python_version()


def count(n: int) -> str:
    return f"{n} figure" if n == 1 else f"{n} figures"


def seconds(value: str | None) -> float | None:
    """value read as a number of seconds above 0, or None when it is absent,
    not a number, not finite or not above 0."""
    try:
        number = float(value) if value is not None else math.nan
    except ValueError:
        return None
    return number if math.isfinite(number) and number > 0 else None


def main(argv: list[str], runner: Runner = run) -> int:
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

    head, changed = commit(runner)
    where = [field("commit", head), field("uncommittedChanges", changed),
             field("cpu", cpu_model(runner)), field("cores", cores())]
    status = 0
    for verifier, command in benchmarks(benchtime):
        try:
            done = runner(command)
            outcome, written = f"exited {done.returncode}", done.stdout + done.stderr
            ok = done.returncode == 0
        except (OSError, subprocess.SubprocessError) as exc:
            outcome, written, ok, done = f"did not run ({exc})", "", False, None
        found = figures(done.stdout) if done is not None else []
        version = runtime(verifier, runner) if found else "unknown"
        for name, calls, nanoseconds in found:
            print(" ".join([field("verifier", verifier), field("benchmark", name),
                            field("msPerOp", f"{nanoseconds / 1e6:.4f}"), field("calls", calls),
                            *where, field("runtime", version)]), flush=True)
        if not ok or not found:
            status = 1
            if written and not written.endswith("\n"):
                written += "\n"
            sys.stderr.write(f"the {verifier} benchmark {outcome} and wrote {count(len(found))}: "
                             f"{' '.join(command)}\n{written}")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
