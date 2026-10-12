#!/usr/bin/env python3
"""Unit tests for the Python reference verifier.

These pin behaviour on inputs that no shipped fixture carries: a credential
whose unsigned declaredPurpose holds a non-integer JSON number. Needs the same
dependencies as verify.py. Run from this directory:

    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import verify  # noqa: E402

BASELINE_V11 = ROOT / "fixtures" / "v1_1-baseline-valid.json"

# Both vendored copies of the JCS serializer: the verifier's, and the
# byte-agreement gate's.
SERIALIZERS = (
    HERE / "rfc8785.py",
    ROOT / "jcs-vectors" / "python" / "rfc8785.py",
)

# The outcome the injected-purpose fixtures declare (array and string values).
INJECTED_EXPECTED = {
    "verifyResult": "REJECT",
    "rejectCategory": "SIGNATURE_INVALID",
    "reasonContains": "signature",
}


def _write_injected(directory: Path, name: str, purpose) -> Path:
    """Write the v1.1 baseline with declaredPurpose set AFTER signing, the
    shape of the declared-purpose-*-injected fixtures, and return its path."""
    fixture = json.loads(BASELINE_V11.read_text())
    fixture["atx"]["declaredPurpose"] = purpose
    fixture["expected"] = dict(INJECTED_EXPECTED)
    path = directory / name
    path.write_text(json.dumps(fixture))
    return path


def _verdict(purpose) -> verify.VerifyResult:
    # Through a file and the verifier's own loader, so the number reaches
    # verify_fixture exactly as it does in a run over fixtures.
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_injected(Path(tmp), "injected.json", purpose)
        return verify.verify_fixture(verify.load_fixture(path))


def _load_serializer(path: Path):
    spec = importlib.util.spec_from_file_location("rfc8785_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InjectedNumberPurpose(unittest.TestCase):
    def test_non_integer_number_rejects_as_signature_invalid(self):
        # atx-spec §1.3a.2 rule 5: a present non-empty declaredPurpose enters
        # the TBS verbatim, so unsigned content fails the signature. A
        # non-integer number must reach that verdict too, not an exception.
        for purpose in (1.5, {"autonomy": 0.5}, ["billing:inquiry", 0.25]):
            with self.subTest(purpose=purpose):
                got = _verdict(purpose)
                self.assertFalse(got.accepted)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID")
                self.assertIn("signature", got.reason.lower())

    def test_integer_and_boolean_reject_in_the_same_category(self):
        # Controls: values the serializer does canonicalize reach the verdict
        # through signature verification itself.
        for purpose in (7, True):
            with self.subTest(purpose=purpose):
                got = _verdict(purpose)
                self.assertFalse(got.accepted)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID")
                self.assertIn("signature", got.reason.lower())

    def test_directory_run_reaches_the_summary_line(self):
        # One fixture the verifier cannot canonicalize must not end the run:
        # it gets its own block, and the fixtures after it are still verified.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_injected(directory, "a-number-injected.json", 1.5)
            (directory / "b-baseline-valid.json").write_text(BASELINE_V11.read_text())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = verify.main(["verify.py", str(directory)])
        text = out.getvalue()
        self.assertEqual(code, 0, text)
        self.assertIn("observed: REJECT[SIGNATURE_INVALID: ", text)
        self.assertIn("observed: ACCEPT", text)
        self.assertEqual(text.splitlines()[-1], "summary: 2 pass, 0 fail (2 fixtures)")


class SerializerRefusal(unittest.TestCase):
    def test_refusal_message_names_the_number(self):
        # The refusal is the serializer's stated contract; building its
        # message must not raise a different error in its place.
        for path in SERIALIZERS:
            with self.subTest(serializer=str(path.relative_to(ROOT))):
                serializer = _load_serializer(path)
                with self.assertRaises(NotImplementedError) as raised:
                    serializer.canonicalize({"declaredPurpose": {"autonomy": 0.5}})
                message = str(raised.exception)
                self.assertIn("Got float 0.5.", message)
                self.assertIn("string-encoded as %.6f", message)


if __name__ == "__main__":
    unittest.main()
