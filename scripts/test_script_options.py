#!/usr/bin/env python3
"""Every script under scripts/ reads -h, --help and an unknown argument alike.

Each script runs as its own process. -h and --help must write its usage to
standard output, write nothing to standard error and exit 0. An unknown
argument must be named on the first line of standard error, in the words
`unknown argument(s): <argument>`, with the usage following on the next
line, and the script must exit 2 and write nothing to standard output. The
usage after that line must open as the --help output opens.

Before the change this test came with, check_circl_pin.sh took --help for
the directory to search; check_sibling_rows.py, check_readme_counts.py,
check_no_implementation_status.py and schema_validation.py refused --help
as an unknown argument; capture_go_verifier.py, check_spec_refs.py and
conformance_profile.py printed the usage without naming the argument; and
check_fixture_immutability.py and parity/parity.py named it in argparse's
words, `error: unrecognized arguments: --bogus`.

Each script reads its arguments before anything else in main, so no run here
reaches the network. Needs jsonschema, which schema_validation.py imports
first. Run from the repository root:

    python3 scripts/test_script_options.py
"""

import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
# What each script is run with.
RUNNERS = {".py": [sys.executable], ".sh": ["bash"]}


def scripts() -> list[Path]:
    """Every script under scripts/ and the directories in it, but this test."""
    found = [path for path in SCRIPTS.rglob("*")
             if path.suffix in RUNNERS and path.is_file() and not path.name.startswith("test_")]
    return sorted(found)


def run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([*RUNNERS[script.suffix], str(script), *args], capture_output=True,
                          text=True, cwd=SCRIPTS.parent, timeout=120)


class ScriptOptions(unittest.TestCase):
    def test_there_are_scripts_to_hold(self):
        names = {path.relative_to(SCRIPTS).as_posix() for path in scripts()}
        self.assertTrue({"check_circl_pin.sh", "parity/parity.py"} <= names, names)

    def test_help_writes_the_usage_and_exits_0(self):
        for script in scripts():
            help_out = run(script, "--help")
            for flag in ("--help", "-h"):
                with self.subTest(script=script.name, flag=flag):
                    done = run(script, flag)
                    self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
                    self.assertTrue(done.stdout.lower().startswith("usage:"), done.stdout)
                    self.assertEqual(done.stdout, help_out.stdout)

    def test_unknown_argument_is_named_above_the_usage(self):
        for script in scripts():
            with self.subTest(script=script.name):
                done = run(script, "--bogus")
                self.assertEqual((done.returncode, done.stdout), (2, ""), done.stderr)
                named, _, usage = done.stderr.partition("\n")
                self.assertEqual(named, "unknown argument(s): --bogus")
                first = run(script, "--help").stdout.splitlines()[0]
                self.assertEqual(usage.splitlines()[0], first)


if __name__ == "__main__":
    unittest.main()
