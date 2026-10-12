"""Tests for run-agreement.sh's handling of its TS/JS dependency install.

Each case copies run-agreement.sh into a scratch tree and runs it with `go`,
`python3`, `node` and `npm` replaced by stubs on PATH, so the only leg that
can fail is the one a case sets up to fail. No network, Go, Node or verifier
dependency is needed.

    python3 jcs-vectors/test_run_agreement.py
"""

import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "run-agreement.sh"

# `go test -v -run ^Name$` prints the test's PASS line unless the name is the
# one the gate uses to show its Go verifier leg can fail.
GO_STUB = r"""#!/bin/sh
name=
for a in "$@"; do
  case "$a" in '^'*) name=${a#^}; name=${name%\$} ;; esac
done
if [ "$1" = test ] && [ "$name" != TestNoSuchVerifierTest ]; then
  echo "--- PASS: $name (0.00s)"
fi
exit 0
"""

OK_STUB = """#!/bin/sh
echo "$(basename "$0") $*" >> "$STUB_LOG"
exit 0
"""

NPM_FAIL_STUB = """#!/bin/sh
echo "npm $*" >> "$STUB_LOG"
echo "npm error code ECONNREFUSED (stub)" >&2
exit 1
"""

NPM_OK_STUB = """#!/bin/sh
echo "npm $*" >> "$STUB_LOG"
mkdir -p node_modules/canonicalize
exit 0
"""


def _write_exe(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RunAgreementInstall(unittest.TestCase):
    def run_gate(self, npm_stub):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        gate = root / "jcs-vectors"
        (gate / "ts").mkdir(parents=True)
        shutil.copy2(SCRIPT, gate / "run-agreement.sh")
        (gate / "MANIFEST.sha256").write_text("")
        for d in ("go", "python"):
            (root / "verifiers" / d).mkdir(parents=True)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        _write_exe(bin_dir / "go", GO_STUB)
        _write_exe(bin_dir / "python3", OK_STUB)
        _write_exe(bin_dir / "node", OK_STUB)
        _write_exe(bin_dir / "npm", npm_stub)
        log = root / "stub.log"
        log.write_text("")
        env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(root),
            "STUB_LOG": str(log),
        }
        proc = subprocess.run(
            ["bash", str(gate / "run-agreement.sh")],
            env=env, capture_output=True, text=True, timeout=60,
        )
        return proc, log.read_text().splitlines()

    def test_failed_install_reports_reason_runs_other_legs_and_summary(self):
        proc, calls = self.run_gate(NPM_FAIL_STUB)
        out = proc.stdout
        self.assertEqual(proc.returncode, 1, out + proc.stderr)
        self.assertIn("npm error code ECONNREFUSED (stub)", out)
        self.assertIn("[ts] FAIL  npm ci in jcs-vectors/ts failed", out)
        self.assertIn("=== [verifier/go]", out)
        self.assertIn("=== [verifier/py]", out)
        self.assertIn("MANIFEST.sha256 OK", out)
        self.assertEqual(out.rstrip().splitlines()[-1], "BYTE-AGREEMENT GATE: FAIL")
        self.assertNotIn("node ts/check.mjs", calls)

    def test_install_uses_the_lockfile(self):
        _, calls = self.run_gate(NPM_FAIL_STUB)
        npm_calls = [c for c in calls if c.startswith("npm ")]
        self.assertEqual(len(npm_calls), 1, calls)
        self.assertEqual(npm_calls[0].split()[1], "ci", calls)

    def test_successful_install_runs_ts_leg_and_passes(self):
        proc, calls = self.run_gate(NPM_OK_STUB)
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, out + proc.stderr)
        self.assertIn("node ts/check.mjs", calls)
        self.assertTrue(out.rstrip().splitlines()[-1].startswith("BYTE-AGREEMENT GATE: PASS"), out)


if __name__ == "__main__":
    unittest.main()
