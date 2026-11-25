#!/usr/bin/env python3
"""check_sibling_rows.py counts the fixtures/*.json files directly in a
sibling repository's fixtures/ directory, and its self-test passes on
docs/sibling-repositories.md.

Before the change this test came with, load_sibling() counted every .json
file under fixtures/ at any depth, by its file name. At aip-conformance
commit 169d5d6 the check counted 16 §5.1 challenge-response fixtures where
that repository holds 14 files named fixtures/challenge-response-*.json: it
also counted the 2 challenge-response-*.json files in fixtures/load-errors/,
which that repository's docs/checks.md says are not part of fixtures/*.json.

No case reads the network: load_sibling() reads its tree, tags and
conformance.json through a stand-in for fetch_json(), and the self-test
builds its sibling data from the page. Run from the repository root:

    python3 scripts/test_check_sibling_rows.py
"""

import base64
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parent / "check_sibling_rows.py"
_SPEC = importlib.util.spec_from_file_location(SCRIPT.stem, SCRIPT)
check_sibling_rows = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_sibling_rows)

REPO = "aip-conformance"
API_REPO = f"repos/{check_sibling_rows.ORG}/{REPO}"
# The tree the stand-in returns: (path, type) as the git/trees API lists them.
TREE = (
    ("fixtures", "tree"),
    ("fixtures/challenge-response-replay.json", "blob"),
    ("fixtures/challenge-response-valid.json", "blob"),
    ("fixtures/trust-score-unscored-zero-event-agent.json", "blob"),
    ("fixtures/load-errors", "tree"),
    ("fixtures/load-errors/challenge-response-repeated-challenge.json", "blob"),
    ("fixtures/load-errors/verifier-state-seen-nonces-not-an-array.json", "blob"),
    ("verifiers", "tree"),
    ("verifiers/go", "tree"),
    ("verifiers/go/verifier", "tree"),
    ("verifiers/go/verifier/verify.go", "blob"),
    ("verifiers/python", "tree"),
    ("verifiers/python/verify.py", "blob"),
)
ROW = ("| [`aip-conformance`](https://github.com/opena2a-standards/aip-conformance) "
       "| AIP v1.2.0-draft identity protocol | §5.1 challenge-response covered by {count} "
       "dedicated fixtures + Go/Python verifiers; §6.1 trust-score composition covered "
       "by 1 fixture |")


def fetch_json(path):
    """The stand-in for check_sibling_rows.fetch_json(): TREE, no tags, and a
    conformance.json declaring AIP 1.2.0-draft."""
    if path == f"{API_REPO}/git/trees/HEAD?recursive=1":
        return {"tree": [{"path": p, "type": t} for p, t in TREE], "truncated": False}
    if path.startswith(f"{API_REPO}/tags?"):
        return []
    if path == f"{API_REPO}/contents/conformance.json":
        profile = json.dumps({"spec": {"id": "AIP", "version": "1.2.0-draft"}})
        return {"encoding": "base64",
                "content": base64.b64encode(profile.encode("utf-8")).decode("ascii")}
    raise AssertionError(f"the check read {path}, which the stand-in does not hold")


def load_aip():
    with mock.patch.object(check_sibling_rows, "fetch_json", fetch_json):
        return check_sibling_rows.load_sibling(REPO)


class FixtureCount(unittest.TestCase):
    def test_a_file_in_a_subdirectory_of_fixtures_is_not_counted(self):
        data = load_aip()
        self.assertEqual(data["fixtures"], [
            "challenge-response-replay.json",
            "challenge-response-valid.json",
            "trust-score-unscored-zero-event-agent.json",
        ])
        self.assertEqual(data["verifiers"], ["go", "python"])

    def test_the_row_is_held_to_the_files_directly_in_fixtures(self):
        siblings = {REPO: load_aip()}

        def failures(count):
            page = (f"{check_sibling_rows.HEADING}\n\n| Repo | Spec | Status |\n"
                    f"|---|---|---|\n{ROW.format(count=count)}\n")
            return [f for f in check_sibling_rows.check(page, siblings)
                    if f.startswith(REPO)]

        self.assertEqual(failures(2), [])
        self.assertEqual(failures(3), [
            "aip-conformance row states 3 as its §5.1 challenge-response fixture count, "
            "but opena2a-standards/aip-conformance has 2 "
            "fixtures/challenge-response-*.json files",
        ])


class SelfTest(unittest.TestCase):
    def test_the_self_test_passes_on_the_page(self):
        done = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
        self.assertIn("self-test passed: the check fails on each of ", done.stdout)


if __name__ == "__main__":
    unittest.main()
