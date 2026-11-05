#!/usr/bin/env python3
"""The workflow's unittest discovery run over scripts/ runs docs/demo/test_record_atx_verify.py.

The Python unit tests step of .github/workflows/conformance.yml discovers test_*.py under scripts/.
Before the change this test came with, that run held 3 tests, none of them from docs/demo, and no
workflow named docs/demo, so no CI job ran the test of how docs/demo/record-atx-verify.sh reads a
Dockerfile. load_tests adds the cases of the demo test to a discovery run over scripts/.

Each case here reads the discovery command from the workflow and runs it, with -k naming the demo
case it needs: without -k, the run would hold the cases of this file again. Needs bash and git, as
the demo test does; no docker, network or image is used.

    python3 scripts/test_demo_recording.py
"""

import importlib.util
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

THIS = pathlib.Path(__file__).resolve()
ROOT = THIS.parents[1]
DEMO = ROOT / "docs" / "demo"
WORKFLOW = ROOT / ".github" / "workflows" / "conformance.yml"
# The demo case that reads the Dockerfile as committed: it runs the script 3 times, where the other
# demo case runs it for each Dockerfile the demo test refuses, with and without --dry-run.
READ_CASE = "test_a_dockerfile_it_reads_passes_the_dry_run"


def load_tests(loader, tests, pattern):
    """Add the demo test's cases to the run. A demo test that is gone is an error of the run, which
    discovery reports from the exception this raises."""
    path = DEMO / "test_record_atx_verify.py"
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    tests.addTests(loader.loadTestsFromModule(module))
    return tests


def discovery_run(cwd, *more):
    """Run the workflow's discovery command in cwd; its exit status and its output."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    found = re.findall(r"^\s*python3 -m unittest discover (.*?) 2>&1", workflow, re.M)
    assert len(found) == 1, f"{WORKFLOW.name} has {len(found)} unittest discovery commands, this reads 1"
    proc = subprocess.run([sys.executable, "-m", "unittest", "discover", *shlex.split(found[0]), *more],
                          cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


class DiscoveryOverScripts(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "scripts").mkdir()
        shutil.copy2(THIS, self.root / "scripts" / THIS.name)

    def copy_demo(self):
        demo = self.root / "docs" / "demo"
        shutil.copytree(DEMO / "docker", demo / "docker")
        for name in ("test_record_atx_verify.py", "record-atx-verify.sh", "atx-verify.tape"):
            shutil.copy2(DEMO / name, demo / name)
        return demo

    def test_the_run_holds_the_demo_test(self):
        code, out = discovery_run(ROOT, "-k", READ_CASE)
        self.assertEqual(code, 0, out)
        self.assertIn(f"test_record_atx_verify.DockerfileImages.{READ_CASE}", out)
        self.assertIn("Ran 1 test ", out)

    def test_a_dockerfile_the_script_refuses_fails_the_run(self):
        dockerfile = self.copy_demo() / "docker" / "Dockerfile"
        dockerfile.write_text(dockerfile.read_text(encoding="utf-8") + "FROM busybox:latest AS helper\n",
                              encoding="utf-8")
        code, out = discovery_run(self.root, "-k", READ_CASE)
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: {READ_CASE}", out)
        # The start of the script's refusal, which the failure's diff of two tuples wraps after this.
        self.assertRegex(out, r"record-atx-verify\.sh: docs/demo/docker/Dockerfile:\d+: `FROM busybox")

    def test_a_demo_test_that_is_gone_fails_the_run(self):
        code, out = discovery_run(self.root, "-k", READ_CASE)
        self.assertEqual(code, 1, out)
        self.assertIn("test_record_atx_verify.py", out)


if __name__ == "__main__":
    unittest.main()
