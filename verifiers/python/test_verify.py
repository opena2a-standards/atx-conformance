#!/usr/bin/env python3
"""Unit tests for the Python reference verifier.

These pin behaviour on inputs that no shipped fixture carries: a credential
whose unsigned declaredPurpose holds a non-integer JSON number, a malformed
trustScore, trustLevel, issuedAt or expiresAt, a NaN or Infinity literal, and a
path that does not exist. Needs the same dependencies as verify.py. Run from
this directory:

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
BASELINE_V10 = ROOT / "fixtures" / "baseline-valid.json"

# The outcome the Go reference verifier reaches on a malformed typed member.
PARSE_ERROR_EXPECTED = {"verifyResult": "REJECT", "rejectCategory": "PARSE_ERROR"}

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


def _write_member(directory: Path, name: str, baseline: Path, member: str, literal: str) -> Path:
    """Write `baseline` with atx[member] replaced by the raw JSON `literal`,
    so values json.dumps cannot write (1e400, NaN) reach the loader as text."""
    fixture = json.loads(baseline.read_text())
    fixture["atx"][member] = "@@MEMBER@@"
    fixture["expected"] = dict(PARSE_ERROR_EXPECTED)
    path = directory / name
    path.write_text(json.dumps(fixture).replace('"@@MEMBER@@"', literal))
    return path


def _member_verdict(baseline: Path, member: str, literal: str) -> verify.VerifyResult:
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_member(Path(tmp), "member.json", baseline, member, literal)
        return verify.verify_fixture(verify.load_fixture(path))


def _run_main(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = verify.main(["verify.py", *args])
    return code, out.getvalue(), err.getvalue()


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


# Raw JSON values the Go reference verifier's typed decode refuses, so it
# rejects them as PARSE_ERROR: a string, boolean or out-of-range number where
# float64 trustScore or int trustLevel is declared, and a timestamp that is not
# an RFC 3339 string.
MALFORMED_MEMBERS = (
    ("trustScore", '"abc"'),
    ("trustScore", '"87.5"'),
    ("trustScore", "true"),
    ("trustScore", "1e400"),
    ("trustLevel", '"4x"'),
    ("trustLevel", '"4"'),
    ("trustLevel", "4.5"),
    ("trustLevel", "4.0"),
    ("trustLevel", "true"),
    ("trustLevel", "9223372036854775808"),
    ("expiresAt", '"not-a-date"'),
    ("expiresAt", '"2099-12-31"'),
    ("expiresAt", '"2099-12-31 23:59:59Z"'),
    ("expiresAt", "20991231"),
    ("issuedAt", '"not-a-date"'),
    ("issuedAt", '"2026-02-30T00:00:00Z"'),
)


class MalformedTypedMember(unittest.TestCase):
    def test_malformed_member_rejects_as_parse_error(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for member, literal in MALFORMED_MEMBERS:
                with self.subTest(baseline=baseline.name, member=member, value=literal):
                    got = _member_verdict(baseline, member, literal)
                    self.assertFalse(got.accepted)
                    self.assertEqual(got.reject_category, "PARSE_ERROR", got.reason)
                    self.assertTrue(got.reason.startswith(member + " "), got.reason)

    def test_well_typed_values_pass_the_check(self):
        # Controls: values of the declared type are not a parse error. They
        # differ from the signed values, so the signature rejects them.
        for member, literal in (
            ("trustScore", "90"),
            ("trustLevel", "9223372036854775807"),
            ("expiresAt", '"2099-12-31T23:59:59.5+01:00"'),
        ):
            with self.subTest(member=member, value=literal):
                got = _member_verdict(BASELINE_V11, member, literal)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)

    def test_shipped_fixtures_pass_the_check(self):
        for path in sorted((ROOT / "fixtures").glob("*.json")):
            with self.subTest(fixture=path.name):
                atx = verify.load_fixture(path)["atx"]
                self.assertIsNone(verify._typed_member_error(atx))

    def test_directory_run_reaches_the_summary_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_member(directory, "a-trust-score.json", BASELINE_V11, "trustScore", '"abc"')
            _write_member(directory, "b-expires-at.json", BASELINE_V10, "expiresAt", '"not-a-date"')
            (directory / "c-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text, _ = _run_main(str(directory))
        self.assertEqual(code, 0, text)
        self.assertEqual(text.count("observed: REJECT[PARSE_ERROR: "), 2, text)
        self.assertEqual(text.splitlines()[-1], "summary: 3 pass, 0 fail (3 fixtures)")


class NonStandardConstant(unittest.TestCase):
    def test_constant_fails_to_load(self):
        # RFC 8259 §6 has no NaN or Infinity; the Go reference verifier fails
        # to load a file carrying one, and so must this verifier.
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as tmp:
                path = _write_member(Path(tmp), "c.json", BASELINE_V11, "declaredPurpose", literal)
                with self.assertRaises(ValueError) as raised:
                    verify.load_fixture(path)
                self.assertIn(literal, str(raised.exception))

    def test_directory_run_reports_a_load_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_member(directory, "a-nan.json", BASELINE_V11, "declaredPurpose", "NaN")
            (directory / "b-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text, _ = _run_main(str(directory))
        self.assertEqual(code, 1, text)
        self.assertIn("a-nan.json  (load error: NaN is not a JSON value", text)
        self.assertEqual(text.splitlines()[-1], "summary: 1 pass, 1 fail (2 fixtures)")


class MissingPath(unittest.TestCase):
    def test_missing_path_exits_2_with_one_error_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "does-not-exist")
            code, out, err = _run_main(missing)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, f"error: {missing}: no such file or directory\n")


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
