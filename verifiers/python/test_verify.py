#!/usr/bin/env python3
"""Unit tests for the Python reference verifier.

These pin behaviour on inputs that no shipped fixture carries: a credential
whose unsigned declaredPurpose holds a non-integer JSON number, a credential
member outside the type the Go reference verifier decodes it into, an absent or
null member, timestamps at the edges of Go's RFC 3339 grammar, a NaN or
Infinity literal, a fixture the verifier raises on, a path that does not exist,
and the verifier's own v1.1 projection over every jcs-vectors vector. Needs the
same dependencies as verify.py. Run from this directory:

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
from datetime import date
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import verify  # noqa: E402

BASELINE_V11 = ROOT / "fixtures" / "v1_1-baseline-valid.json"
BASELINE_V10 = ROOT / "fixtures" / "baseline-valid.json"
JCS_VECTORS = ROOT / "jcs-vectors" / "vectors"

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


def _write_member(
    directory: Path,
    name: str,
    baseline: Path,
    member: str,
    literal: str | None,
    expected: dict | None = None,
) -> Path:
    """Write `baseline` with atx[member] replaced by the raw JSON `literal`,
    so values json.dumps cannot write (1e400, NaN) reach the loader as text.
    A literal of None removes the member."""
    fixture = json.loads(baseline.read_text())
    fixture["expected"] = dict(expected or PARSE_ERROR_EXPECTED)
    path = directory / name
    if literal is None:
        del fixture["atx"][member]
        path.write_text(json.dumps(fixture))
    else:
        fixture["atx"][member] = "@@MEMBER@@"
        path.write_text(json.dumps(fixture).replace('"@@MEMBER@@"', literal))
    return path


def _member_verdict(baseline: Path, member: str, literal: str | None) -> verify.VerifyResult:
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
# rejects them as PARSE_ERROR: a value of another JSON type or out of range for
# a string, int64, float64, bool, []string or []signature field, and a
# timestamp outside the grammar of Go's time.Parse(time.RFC3339).
MALFORMED_MEMBERS = (
    ("id", "[]"),
    ("agentId", "7"),
    ("publisher", "7"),
    ("transparencyLogIndex", '"x"'),
    ("transparencyLogIndex", "1.5"),
    ("transparencyLogIndex", "1e2"),
    ("transparencyLogIndex", "9223372036854775808"),
    ("capabilities", '"abc"'),
    ("issuerChain", "7"),
    ("signatures", '"x"'),
    ("revoked", '"yes"'),
    ("revoked", "1"),
    ("expiresAt", '"2099-12-31T24:00:00Z"'),
    ("issuedAt", '"2026-05-23T24:00:00Z"'),
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
                verify._decode_credential(atx)

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


# Timestamps Go's time.Time decoder, which the Go reference verifier uses for
# issuedAt and expiresAt, accepts, with what Go then holds: the UTC time it
# formats with time.RFC3339, and its Unix seconds and nanoseconds. Recorded
# from Go; TestTimestampDecode in ../go pins the same table against the Go
# toolchain.
GO_ACCEPTED_TIMESTAMPS = (
    ("2099-12-31T23:59:59Z", "2099-12-31T23:59:59Z", 4102444799, 0),
    ("2099-12-31T23:59:59,5Z", "2099-12-31T23:59:59Z", 4102444799, 500000000),
    ("2099-12-31T23:59:59.123456789123Z", "2099-12-31T23:59:59Z", 4102444799, 123456789),
    ("2099-12-31T23:59:59+24:00", "2099-12-30T23:59:59Z", 4102358399, 0),
    ("2099-12-31T23:59:59-24:00", "2100-01-01T23:59:59Z", 4102531199, 0),
    ("2099-12-31T23:59:59+23:60", "2099-12-30T23:59:59Z", 4102358399, 0),
    ("0000-12-31T23:59:59Z", "0000-12-31T23:59:59Z", -62135596801, 0),
    ("0000-02-29T00:00:00Z", "0000-02-29T00:00:00Z", -62162121600, 0),
    ("0000-01-01T00:00:00+01:00", "-0001-12-31T23:00:00Z", -62167222800, 0),
    ("9999-12-31T23:59:59-24:00", "10000-01-01T23:59:59Z", 253402387199, 0),
    ("2000-02-29T00:00:00Z", "2000-02-29T00:00:00Z", 951782400, 0),
    ("2099-12-31T9:59:59Z", "2099-12-31T09:59:59Z", 4102394399, 0),
    ("1969-12-31T23:59:59.999999999Z", "1969-12-31T23:59:59Z", -1, 999999999),
)

# Timestamps Go's time.Time decoder rejects. TestTimestampDecode pins these too.
GO_REJECTED_TIMESTAMPS = (
    "2099-12-31T24:00:00Z",
    "2099-12-31T23:60:00Z",
    "2099-12-31T23:59:60Z",
    "2099-13-01T00:00:00Z",
    "2099-12-00T00:00:00Z",
    "1900-02-29T00:00:00Z",
    "2099-12-31t23:59:59Z",
    "2099-12-31T23:59:59z",
    "2099-12-31T23:59:59.Z",
    "2099-12-31T23:59:59",
    "2099-12-31T23:59:59+0100",
    "+999-12-31T23:59:59Z",
)

# Offsets past +24:00 or +23:60. Go 1.22, which CI builds the Go reference
# verifier with, decodes them, and Go 1.23 and later reject them, so
# TestTimestampDecode pins neither outcome; this verifier follows Go 1.22.
# Recorded from Go 1.22.12.
GO122_OFFSET_TIMESTAMPS = (
    ("2099-12-31T23:59:59+25:00", "2099-12-30T22:59:59Z", 4102354799, 0),
    ("2099-12-31T23:59:59+23:61", "2099-12-30T23:58:59Z", 4102358339, 0),
    ("2099-12-31T23:59:59-99:99", "2100-01-05T04:38:59Z", 4102807139, 0),
    ("2026-05-23T00:00:00+00:61", "2026-05-22T22:59:00Z", 1779490740, 0),
)

# The verdict `go run .` in ../go reaches with Go 1.22.12 on the v1.0 and v1.1
# baselines when atx[member] holds one of those offsets: the timestamp decodes,
# it no longer matches the signed value, and the signature rejects. Built with
# Go 1.23 or later, the Go verifier reaches PARSE_ERROR instead.
GO122_OFFSET_VERDICTS = (
    ("expiresAt", '"2099-12-31T23:59:59+25:00"', "SIGNATURE_INVALID"),
    ("expiresAt", '"2099-12-31T23:59:59+00:61"', "SIGNATURE_INVALID"),
    ("expiresAt", '"2099-12-31T23:59:59-99:99"', "SIGNATURE_INVALID"),
    ("issuedAt", '"2026-05-23T00:00:00+00:61"', "SIGNATURE_INVALID"),
    ("issuedAt", '"2026-05-23T00:00:00+25:00"', "SIGNATURE_INVALID"),
)

# The verdict the Go reference verifier reaches when atx[member] holds the raw
# JSON literal (None: the member is absent), the same on the v1.0 and v1.1
# baselines, with text its reason and this verifier's both contain. Recorded
# from `go run .` in ../go. Go leaves an absent or null member at its zero
# value, so a null expiresAt is the zero time and expired.
GO_VERDICTS = (
    ("expiresAt", '"2099-12-31T23:59:59,5Z"', "ACCEPT", ""),
    ("expiresAt", '"2099-12-31T23:59:59+24:00"', "SIGNATURE_INVALID", ""),
    ("expiresAt", '"0000-12-31T23:59:59Z"', "EXPIRED", "expired at 0000-12-31T23:59:59Z"),
    ("issuedAt", '"0000-01-01T00:00:00Z"', "SIGNATURE_INVALID", ""),
    ("issuedAt", '"2026-05-23T01:00:00+01:00"', "ACCEPT", ""),
    ("issuedAt", '"2026-05-23T0:00:00Z"', "ACCEPT", ""),
    ("expiresAt", '"2099-12-31T24:00:00Z"', "PARSE_ERROR", "hour out of range"),
    ("issuedAt", '"2026-05-23T24:00:00Z"', "PARSE_ERROR", "hour out of range"),
    ("transparencyLogIndex", '"x"', "PARSE_ERROR", "transparencyLogIndex"),
    ("transparencyLogIndex", "1.5", "PARSE_ERROR", "transparencyLogIndex"),
    ("transparencyLogIndex", "null", "ACCEPT", ""),
    ("issuerChain", "7", "PARSE_ERROR", "issuerChain"),
    ("issuerChain", "[7]", "PARSE_ERROR", "issuerChain"),
    ("signatures", '"x"', "PARSE_ERROR", "signatures"),
    ("signatures", '["x"]', "PARSE_ERROR", "signatures"),
    ("signatures", '[{"value": 7}]', "PARSE_ERROR", "signatures"),
    ("signatures", "null", "SIGNATURE_INVALID", "no valid signatures"),
    ("signatures", "[null]", "SIGNATURE_INVALID", "unsupported signature algorithm"),
    ("signatures", None, "SIGNATURE_INVALID", "no valid signatures"),
    ("trustScore", "null", "SIGNATURE_INVALID", ""),
    ("trustLevel", "null", "SIGNATURE_INVALID", ""),
    ("issuedAt", "null", "SIGNATURE_INVALID", ""),
    ("issuedAt", None, "SIGNATURE_INVALID", ""),
    ("expiresAt", "null", "EXPIRED", "expired at 0001-01-01T00:00:00Z"),
    ("expiresAt", None, "EXPIRED", "expired at 0001-01-01T00:00:00Z"),
    ("agentId", None, "SIGNATURE_INVALID", ""),
    ("revoked", '"yes"', "PARSE_ERROR", "revoked"),
    ("revoked", "null", "ACCEPT", ""),
    ("capabilities", '"abc"', "PARSE_ERROR", "capabilities"),
    ("publisher", "7", "PARSE_ERROR", "publisher"),
)


def _outcome(got: verify.VerifyResult) -> str:
    return "ACCEPT" if got.accepted else got.reject_category


class GoTimestampGrammar(unittest.TestCase):
    def test_accepted_timestamps_decode_as_go_does(self):
        for text, utc, seconds, nanos in GO_ACCEPTED_TIMESTAMPS:
            with self.subTest(timestamp=text):
                instant = verify._parse_rfc3339(text)
                self.assertEqual(instant, verify._Instant(seconds, nanos))
                self.assertEqual(verify._format_rfc3339(instant), utc)

    def test_rejected_timestamps_raise(self):
        for text in GO_REJECTED_TIMESTAMPS:
            with self.subTest(timestamp=text), self.assertRaises(ValueError):
                verify._parse_rfc3339(text)

    def test_offsets_past_24_hours_decode_as_go_1_22_does(self):
        for text, utc, seconds, nanos in GO122_OFFSET_TIMESTAMPS:
            with self.subTest(timestamp=text):
                instant = verify._parse_rfc3339(text)
                self.assertEqual(instant, verify._Instant(seconds, nanos))
                self.assertEqual(verify._format_rfc3339(instant), utc)

    def test_zero_time_is_go_zero_time(self):
        self.assertEqual(verify._GO_ZERO_TIME, verify._Instant(-62135596800, 0))
        self.assertEqual(verify._format_rfc3339(verify._GO_ZERO_TIME), "0001-01-01T00:00:00Z")

    def test_day_count_agrees_with_datetime(self):
        epoch = date(1970, 1, 1).toordinal()
        for ordinal in range(date.min.toordinal(), date.max.toordinal() + 1, 997):
            day = date.fromordinal(ordinal)
            with self.subTest(date=day.isoformat()):
                days = verify._days_from_civil(day.year, day.month, day.day)
                self.assertEqual(days, ordinal - epoch)
                self.assertEqual(verify._civil_from_days(days), (day.year, day.month, day.day))


class GoDecodedVerdict(unittest.TestCase):
    def test_member_reaches_the_go_verdict(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for member, literal, outcome, fragment in GO_VERDICTS:
                with self.subTest(baseline=baseline.name, member=member, value=literal):
                    got = _member_verdict(baseline, member, literal)
                    self.assertEqual(_outcome(got), outcome, got.reason)
                    self.assertIn(fragment, got.reason)

    def test_offset_past_24_hours_reaches_the_go_1_22_verdict(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for member, literal, outcome in GO122_OFFSET_VERDICTS:
                with self.subTest(baseline=baseline.name, member=member, value=literal):
                    got = _member_verdict(baseline, member, literal)
                    self.assertEqual(_outcome(got), outcome, got.reason)

    def test_directory_run_reaches_the_summary_line(self):
        # Each of these used to end the run with a traceback, or reach a
        # verdict the Go reference verifier does not.
        shapes = (
            ("issuerChain", "7"),
            ("signatures", '"x"'),
            ("trustScore", "null"),
            ("trustLevel", "null"),
            ("issuedAt", "null"),
            ("expiresAt", "null"),
            ("revoked", '"yes"'),
            ("transparencyLogIndex", '"x"'),
        )
        verdicts = {(m, lit): outcome for m, lit, outcome, _ in GO_VERDICTS}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for i, (member, literal) in enumerate(shapes):
                category = verdicts[(member, literal)]
                expected = {"verifyResult": "REJECT", "rejectCategory": category}
                _write_member(directory, f"{i}-{member}.json", BASELINE_V11, member, literal, expected)
            (directory / "z-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 0, text + err)
        self.assertNotIn("verify error", text)
        self.assertEqual(text.splitlines()[-1], "summary: 9 pass, 0 fail (9 fixtures)")

    def test_bad_clock_is_a_config_error(self):
        # Go parses the verifier clock with time.Parse(time.RFC3339).
        fixture = json.loads(BASELINE_V11.read_text())
        fixture["verifierState"]["clockRfc3339"] = "not-a-clock"
        got = verify.verify_fixture(fixture)
        self.assertEqual(got.reject_category, "VERIFIER_CONFIG_ERROR", got.reason)


class VerifyError(unittest.TestCase):
    def test_raising_fixture_gets_a_fail_line_and_the_run_continues(self):
        real = verify.verify_fixture

        def raises_on_one(fixture):
            if fixture.get("name") == "raises":
                raise RuntimeError("unexpected input")
            return real(fixture)

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture = json.loads(BASELINE_V11.read_text())
            fixture["name"] = "raises"
            (directory / "a-raises.json").write_text(json.dumps(fixture))
            (directory / "b-baseline-valid.json").write_text(BASELINE_V11.read_text())
            with mock.patch.object(verify, "verify_fixture", raises_on_one):
                code, text, _ = _run_main(str(directory))
        self.assertEqual(code, 1, text)
        self.assertIn("a-raises.json  (verify error: RuntimeError: unexpected input)", text)
        self.assertIn("observed: ACCEPT", text)
        self.assertEqual(text.splitlines()[-1], "summary: 1 pass, 1 fail (2 fixtures)")


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


class JCSVectorsThroughVerifierProjection(unittest.TestCase):
    # The byte-agreement gate runs this class, so the gate covers this
    # verifier's code (TBS projection, then JCS) and not only the serializer
    # it vendors. atx-conformance#156.
    def test_every_vector_reproduces_its_pinned_bytes(self):
        paths = sorted(JCS_VECTORS.glob("*.json"))
        self.assertTrue(paths, f"no vectors found in {JCS_VECTORS}")
        for path in paths:
            with self.subTest(vector=path.name):
                vector = json.loads(path.read_text(encoding="utf-8"))
                # The TBS carries trustScore as its %.6f string; the credential
                # carries the same value as a JSON number. Every other TBS
                # member is already in its wire form. The projection reads the
                # credential as _decode_credential returns it, so decode first,
                # as the Go test parses the credential before projecting.
                credential = dict(vector["tbs"])
                credential["trustScore"] = json.loads(credential["trustScore"])
                got = verify.canonical_payload_v11(verify._decode_credential(credential))
                self.assertEqual(got.hex(), vector["expected"]["canonicalHex"])


if __name__ == "__main__":
    unittest.main()
