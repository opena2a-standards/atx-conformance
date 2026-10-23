#!/usr/bin/env python3
"""Unit tests for the Python reference verifier.

These pin behaviour on inputs that no shipped fixture carries: a credential
whose unsigned declaredPurpose holds a non-integer JSON number or one outside
the float64 range, a credential
member outside the type the Go reference verifier decodes it into, an absent or
null member, timestamps at the edges of Go's RFC 3339 grammar, a
behavioralProfile.generatedAt outside it, a NaN or Infinity literal, a fixture
the verifier raises on, a path that does not exist, and the verifier's own v1.1
projection over every jcs-vectors vector. They also pin what Go's encoding/json
makes of a member name in another case, a timestamp written with a JSON
escape, an unpaired surrogate escape and a trustScore of -0, the projection of
behavioralProfile and scanSummary members outside their Go type, the signature
base64 alphabet, a fixture whose expected member is not an object, a file
with no expected.verifyResult of ACCEPT or REJECT, and a report line standard
output cannot encode. They also pin the decode of the
fixture wrapper: members outside their Go type, names in another case, a
member written twice outside the credential, under one name or two, which
fails to load (a first value outside its Go type included), a public key
that is not hex, arrays and objects nested to Go's
depth limit (in declaredPurpose too, which the JCS serializer walks, and in a
typed member, whose decode error writes the value to 8 levels), an integer
with more digits than int() converts, bytes that are not UTF-8, the
single-pass string-literal scan, --help, an unknown option, --version, an
empty argument, a directory whose fixtures entry is a file, a directory
holding a subdirectory or a symbolic link named *.json, a directory that
cannot be listed, a fixture file that cannot be read, whose load error is
worded as the Go reference verifier words it, a path spelled
with ./, // or .., which the report names as the Go reference verifier names
it, a file named with a trailing /, "--", a path under a working
directory entered through a symbolic link, a .. after a symbolic link,
which is read and named where the link leads, an argument that is not
UTF-8, which a line on stderr writes as its bytes, and a fixture path that
is not UTF-8, which the report line naming it, and the load error of such a
file that cannot be read, write as its bytes.
They pin the requiredSignatures threshold of the verifier state: the
distinct Ed25519 keys a credential's signatures verify under, each counted
once whatever keyId names it and no ML-DSA-65 signature counted, against
the count it sets, a count below 1 reported as a configuration error, and
the member decoded as the Go reference verifier decodes it.
They hold the report to the Go reference verifier's text: a boolean, a
string a reason quotes, and the whole report over fixtures/, which must be
docs/captures/go-verifier.txt byte for byte. Two tests
read verify.py itself: it imports no name it does not use, and its module
docstring lists only the checks the verifier runs. Another test reads the
"Arguments" section of docs/running-the-verifiers.md, which must quote
d/link/.. and d/link/../ and the PASS line the verifier prints for each.
One test imports this file with an os whose name is "nt" and which has no
geteuid, as Python's os is on Windows: it must import, with NonUTF8Argument
and ArgumentContract's test of a directory that cannot be listed skipped.
Needs the same dependencies as verify.py. Run from this directory:

    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import ast
import base64
import contextlib
import errno
import importlib.util
import io
import json
import os
import re
import string
import subprocess
import sys
import tempfile
import time
import types
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
# The fixture whose verifier state carries a CRL.
BASELINE_CRL = ROOT / "fixtures" / "revoked-crl-only.json"
# The fixture whose verifier state sets requiredSignatures (2), and the
# fixture whose credential it carries cut to the first of three signatures.
THRESHOLD_1OF3 = ROOT / "fixtures" / "threshold-1of3-cosignature.json"
THRESHOLD_2OF3 = ROOT / "fixtures" / "threshold-2of3-cosignature.json"
# The fixture whose credential rejects as UNTRUSTED_ISSUER, and the two whose
# credential repeats a member, which the strict parse rejects as PARSE_ERROR.
WRONG_ISSUER = ROOT / "fixtures" / "wrong-issuer.json"
DUPLICATE_CREDENTIALS = (
    ROOT / "fixtures" / "v1_1-case-variant-member.json",
    ROOT / "fixtures" / "v1_1-duplicate-purpose-member.json",
)
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


def _write_generated_at(directory: Path, name: str, literal: str, outcome: str) -> Path:
    """Write the v1.1 baseline with behavioralProfile.generatedAt replaced by
    the raw JSON `literal`, expecting `outcome` (ACCEPT or a reject category)."""
    fixture = json.loads(BASELINE_V11.read_text())
    if outcome == "ACCEPT":
        fixture["expected"] = {"verifyResult": "ACCEPT"}
    else:
        fixture["expected"] = {"verifyResult": "REJECT", "rejectCategory": outcome}
    fixture["atx"]["behavioralProfile"]["generatedAt"] = "@@MEMBER@@"
    path = directory / name
    path.write_text(json.dumps(fixture).replace('"@@MEMBER@@"', literal))
    return path


def _member_verdict(baseline: Path, member: str, literal: str | None) -> verify.VerifyResult:
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_member(Path(tmp), "member.json", baseline, member, literal)
        return verify.verify_fixture(verify.load_fixture(path))


# In place of a raw literal: the member keeps the value the baseline gives it.
KEEP = object()


def _write_at(
    directory: Path,
    name: str,
    baseline: Path,
    path: tuple,
    literal,
    rename: str | None = None,
    expected: dict | None = None,
) -> Path:
    """Write `baseline` with the atx member at `path` replaced by the raw JSON
    `literal` and, with `rename`, written under that name. A path step is a
    member name or an array index, so ("signatures", 0, "value") is the first
    signature's value. A literal of None removes the member; KEEP keeps its
    value, for a rename alone."""
    fixture = json.loads(baseline.read_text())
    fixture["expected"] = dict(expected or PARSE_ERROR_EXPECTED)
    parent = fixture["atx"]
    for step in path[:-1]:
        parent = parent[step]
    value = parent.pop(path[-1], None)
    if literal is KEEP:
        literal = json.dumps(value)
    if literal is not None:
        parent[rename or path[-1]] = "@@MEMBER@@"
    out = directory / name
    out.write_text(json.dumps(fixture).replace('"@@MEMBER@@"', literal or ""))
    return out


def _at_verdict(baseline: Path, path: tuple, literal, rename: str | None = None) -> verify.VerifyResult:
    with tempfile.TemporaryDirectory() as tmp:
        written = _write_at(Path(tmp), "member.json", baseline, path, literal, rename)
        return verify.verify_fixture(verify.load_fixture(written))


def _credential_at(baseline: Path, path: tuple, literal, rename: str | None = None) -> dict:
    """The credential _write_at writes, as _decode_credential returns it."""
    with tempfile.TemporaryDirectory() as tmp:
        written = _write_at(Path(tmp), "member.json", baseline, path, literal, rename)
        return verify._decode_credential(verify.load_fixture(written)["atx"])


def _projection_at(path: tuple, literal) -> dict:
    """The v1.1 signed payload of the credential _write_at writes from the
    v1.1 baseline, parsed."""
    return json.loads(verify.canonical_payload_v11(_credential_at(BASELINE_V11, path, literal)))


def _write_wrapper(directory: Path, name: str, baseline: Path, member: str, literal: str) -> Path:
    """Write `baseline` with the fixture's own member (expected, atx) replaced
    by the raw JSON `literal`."""
    fixture = json.loads(baseline.read_text())
    fixture[member] = "@@MEMBER@@"
    out = directory / name
    out.write_text(json.dumps(fixture).replace('"@@MEMBER@@"', literal))
    return out


def _write_fixture_at(
    directory: Path, name: str, baseline: Path, path: tuple, literal, rename: str | None = None
) -> Path:
    """_write_at for a member of the fixture itself, keeping its expected
    member: path starts at the fixture object, so ("verifierState", "crl",
    "entries", 0, "revokedAt") is the first CRL entry's revokedAt. A literal
    of bytes is written as those bytes, unchecked."""
    fixture = json.loads(baseline.read_text())
    parent = fixture
    for step in path[:-1]:
        parent = parent[step]
    value = parent.pop(path[-1], None)
    if literal is KEEP:
        literal = json.dumps(value)
    if literal is not None:
        parent[rename or path[-1]] = "@@MEMBER@@"
    text = json.dumps(fixture).encode("utf-8")
    if isinstance(literal, str):
        literal = literal.encode("utf-8")
    out = directory / name
    out.write_bytes(text.replace(b'"@@MEMBER@@"', literal or b""))
    return out


def _write_repeated(
    directory: Path, name: str, baseline: Path, path: tuple, first_name: str | None, literal: str
) -> Path:
    """_write_fixture_at with the member at path written twice: first under
    first_name (its own name when None) holding the raw JSON literal, then
    under its own name with the value the baseline gives it."""
    fixture = json.loads(baseline.read_text())
    parent = fixture
    for step in path[:-1]:
        parent = parent[step]
    second = f"{json.dumps(path[-1])}: {json.dumps(parent[path[-1]])}"
    return _write_fixture_at(directory, name, baseline, path, f"{literal}, {second}", first_name)


def _fixture_verdict(baseline: Path, path: tuple, literal, rename: str | None = None) -> verify.VerifyResult:
    with tempfile.TemporaryDirectory() as tmp:
        written = _write_fixture_at(Path(tmp), "fixture.json", baseline, path, literal, rename)
        return verify.verify_fixture(verify.load_fixture(written))


def _write_signed_v11(directory: Path, name: str, fixture: dict) -> Path:
    """Write fixture, whose atx is a v1.1 credential, with that credential
    carrying one Ed25519 signature over its own JCS(TBS) as this verifier
    projects it, made with the primary issuer's key (the RFC 8032 test vector
    in vectors/issuer-primary.json), and return its path."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = json.loads((ROOT / "vectors" / "issuer-primary.json").read_text())
    path = directory / name
    path.write_text(json.dumps(fixture))
    payload = verify.canonical_payload_v11(verify._decode_credential(verify.load_fixture(path)["atx"]))
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["seedHex"]))
    signed = json.loads(json.dumps(fixture))
    signed["atx"]["signatures"] = [{
        "keyId": key["keyId"],
        "algorithm": "Ed25519",
        "value": base64.b64encode(signer.sign(payload)).decode("ascii"),
    }]
    path.write_text(json.dumps(signed))
    return path


def _run_main(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = verify.main(["verify.py", *args])
    return code, out.getvalue(), err.getvalue()


def _verdict_lines(out: str) -> list[str]:
    """Each PASS or FAIL line of a report, each followed by its observed
    verdict and category without the reason, so a test sees which file was
    read as well as the name the report gives it."""
    lines = []
    for line in out.splitlines():
        if line.startswith(("PASS  ", "FAIL  ")):
            lines.append(line)
        elif m := re.match(r"\s+observed: (ACCEPT|REJECT\[[A-Z_]+)", line):
            lines.append(f"observed: {m.group(1)}" + ("]" if m.group(1).startswith("REJECT") else ""))
    return lines


def _run_main_utf8(*args: str) -> tuple[int, str]:
    """verify.main with standard output a strict UTF-8 stream, which is what a
    pipe or a file gives it. The io.StringIO of _run_main accepts an unpaired
    surrogate that such a stream refuses."""
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="utf-8", newline="\n")
    with contextlib.redirect_stdout(out):
        code = verify.main(["verify.py", *args])
        out.flush()
    return code, raw.getvalue().decode("utf-8")


def _run_main_stdout_bytes(*args: str) -> tuple[int, bytes]:
    """verify.main with standard output a strict UTF-8 stream over bytes, as
    _run_main_utf8 sets it, and the bytes written to it, which
    _run_main_utf8 would fail to decode where a path is not UTF-8."""
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="utf-8", newline="\n")
    with contextlib.redirect_stdout(out):
        code = verify.main(["verify.py", *args])
        out.flush()
    return code, raw.getvalue()


def _run_main_stderr_bytes(*args: str) -> tuple[int, str, bytes]:
    """verify.main with standard error a UTF-8 stream over bytes that writes
    a character it cannot encode as a backslash escape, as sys.stderr writes
    it, and the bytes written to it. The io.StringIO of _run_main holds an
    argument's surrogate escapes as they are, and has no bytes under it."""
    raw = io.BytesIO()
    err = io.TextIOWrapper(raw, encoding="utf-8", errors="backslashreplace", newline="\n")
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = verify.main(["verify.py", *args])
        err.flush()
    return code, out.getvalue(), raw.getvalue()


def _load_serializer(path: Path):
    spec = importlib.util.spec_from_file_location("rfc8785_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The largest float64 plus half a unit in its last place: the smallest integer
# that rounds past it, to infinity, under round-half-to-even.
FLOAT64_EDGE = 2**1024 - 2**970

# Numbers written into an unsigned declaredPurpose, and the category the Go
# reference verifier reports for each, read from its run over these values.
GO_PURPOSE_NUMBER_VERDICTS = (
    ("1e400", "VERIFIER_CONFIG_ERROR"),
    ("-1e400", "VERIFIER_CONFIG_ERROR"),
    ("1.7976931348623159e308", "VERIFIER_CONFIG_ERROR"),
    (str(FLOAT64_EDGE), "VERIFIER_CONFIG_ERROR"),
    (str(-FLOAT64_EDGE), "VERIFIER_CONFIG_ERROR"),
    ('{"limit": 1e400}', "VERIFIER_CONFIG_ERROR"),
    ('["billing:inquiry", 1e400]', "VERIFIER_CONFIG_ERROR"),
    ("[1.5, 1e400]", "VERIFIER_CONFIG_ERROR"),
    ("[" * 9997 + "1e400" + "]" * 9997, "VERIFIER_CONFIG_ERROR"),
    ("1.7976931348623158e308", "SIGNATURE_INVALID"),
    (str(FLOAT64_EDGE - 1), "SIGNATURE_INVALID"),
    ("1e308", "SIGNATURE_INVALID"),
    ("1e-400", "SIGNATURE_INVALID"),
)


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

    def test_reason_is_the_go_verifier_reason(self):
        # Neither reference verifier verifies a signature over a number
        # written with a fraction or an exponent part (GoPurposeNumberSpellings):
        # each checks every declared signature against no key, and the reason
        # names it in the Go verifier's words, read from its run over these
        # values. GoReportText holds the report over fixtures/, which holds
        # fixtures/v1_1-declared-purpose-number-injected.json, to the Go
        # capture.
        for purpose in (1.5, {"autonomy": 0.5}, ["billing:inquiry", 0.25]):
            with self.subTest(purpose=purpose):
                self.assertEqual(
                    _verdict(purpose).reason,
                    "Ed25519 signature did:opena2a:authority:opena2a.org#key-1 "
                    "did not verify against any configured public key",
                )

    def test_integer_and_boolean_reject_in_the_same_category(self):
        # Controls: values the serializer does canonicalize reach the verdict
        # through signature verification itself.
        for purpose in (7, True):
            with self.subTest(purpose=purpose):
                got = _verdict(purpose)
                self.assertFalse(got.accepted)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID")
                self.assertIn("signature", got.reason.lower())

    def test_number_outside_float64_range_reaches_the_go_category(self):
        # The Go reference verifier's JCS library parses each number with
        # strconv.ParseFloat: one it cannot hold rejects as
        # VERIFIER_CONFIG_ERROR, one it holds is canonicalized and the
        # signature fails. Python's float() rounds at the same edge.
        for literal, category in GO_PURPOSE_NUMBER_VERDICTS:
            with self.subTest(literal=literal[:40], length=len(literal)):
                got = _at_verdict(BASELINE_V11, ("declaredPurpose",), literal)
                self.assertFalse(got.accepted)
                self.assertEqual(got.reject_category, category, got.reason[:200])

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
# timestamp outside the grammar of Go's time.Parse(time.RFC3339) or written
# with a JSON escape. The Go verifier decodes each timestamp with time.Time's
# own UnmarshalJSON, which refuses the escaped form under every Go release; a
# plain time.Time field decodes it when built with Go 1.27.
MALFORMED_MEMBERS = (
    ("expiresAt", '"2099-12-31T23:59:59\\u005a"'),
    ("expiresAt", '"\\u0032099-12-31T23:59:59Z"'),
    ("issuedAt", '"2026-05-23T00:00:00\\u005A"'),
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

# Offsets with an hour above 24 or a minute above 60, and the error the Go
# reference verifier refuses each with: the error time.Parse gives in Go 1.23
# and later, which check the offset before the day. Built with Go 1.22, the Go
# verifier gives the same error: checkOffset for the first seven, which Go
# 1.22 decodes, and offsetFirst for the last two, which Go 1.22 refuses
# for the day. The offsets table in TestTimestampDecode carries the same rows.
GO_OFFSET_OUT_OF_RANGE = (
    ("2099-12-31T23:59:59+25:00", "time zone offset hour out of range"),
    ("2099-12-31T23:59:59-25:00", "time zone offset hour out of range"),
    ("2099-12-31T23:59:59.5+25:00", "time zone offset hour out of range"),
    ("2099-12-31T23:59:59+23:61", "time zone offset minute out of range"),
    ("2026-05-23T00:00:00+00:61", "time zone offset minute out of range"),
    ("2099-12-31T23:59:59+25:61", "time zone offset minute out of range"),
    ("2099-12-31T23:59:59-99:99", "time zone offset minute out of range"),
    ("2099-02-30T23:59:59+25:00", "time zone offset hour out of range"),
    ("1900-02-29T00:00:00+23:61", "time zone offset minute out of range"),
)

# The verdict `go run .` in ../go reaches on the v1.0 and v1.1 baselines when
# atx[member] holds one of those offsets, built with Go 1.22.12 and with Go
# 1.26.3, which agree on each. Built with Go 1.22 before checkOffset, it
# reached SIGNATURE_INVALID on each but the last, whose day is out of range:
# built with Go 1.22.12, it named the day in that one until offsetFirst.
GO_OFFSET_VERDICTS = (
    ("expiresAt", '"2099-12-31T23:59:59+25:00"', "time zone offset hour out of range"),
    ("expiresAt", '"2099-12-31T23:59:59+00:61"', "time zone offset minute out of range"),
    ("expiresAt", '"2099-12-31T23:59:59-99:99"', "time zone offset minute out of range"),
    ("issuedAt", '"2026-05-23T00:00:00+00:61"', "time zone offset minute out of range"),
    ("issuedAt", '"2026-05-23T00:00:00+25:00"', "time zone offset hour out of range"),
    ("issuedAt", '"2026-02-30T00:00:00+25:00"', "time zone offset hour out of range"),
)

# A CRL timestamp with such an offset, on the CRL baseline: the file fails to
# load in the Go verifier built with Go 1.22.12 and with Go 1.26.3. (path from
# the fixture object, raw literal, the member this verifier's load error
# names).
GO_UNLOADABLE_OFFSETS = (
    (("verifierState", "crl", "issuedAt"), '"2026-05-23T00:00:00+25:00"', "verifierState.crl.issuedAt"),
    (("verifierState", "crl", "issuedAt"), '"2026-02-30T00:00:00+25:00"', "verifierState.crl.issuedAt"),
    (("verifierState", "crl", "nextUpdate"), '"2026-05-23T00:00:00+23:61"', "verifierState.crl.nextUpdate"),
    (
        ("verifierState", "crl", "entries", 0, "revokedAt"),
        '"2026-05-23T12:00:00+00:61"',
        "verifierState.crl.entries[0].revokedAt",
    ),
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

# The verdict the Go reference verifier reaches when the v1.1 baseline's
# behavioralProfile.generatedAt holds the raw JSON literal. Recorded from
# `go run .` in ../go with Go 1.22.12 and with Go 1.26.3, which agree on each;
# the escaped row holds with Go 1.27.2 too, since the Go verifier decodes the
# timestamp with time.Time's own UnmarshalJSON.
# A generatedAt Go's time.Time decoder refuses makes the Go verifier project
# the whole behavioralProfile as null, so the signature rejects; one that
# decodes to the signed instant projects as signed.
GO_GENERATED_AT_VERDICTS = (
    ('"2026-05-19T00:00:00"', "SIGNATURE_INVALID"),
    ('"2026-05-19"', "SIGNATURE_INVALID"),
    ('"20991231T235959Z"', "SIGNATURE_INVALID"),
    ('"2099-W52-1T00:00:00Z"', "SIGNATURE_INVALID"),
    ('"2026-05-19 00:00:00Z"', "SIGNATURE_INVALID"),
    ('"2026-05-19T00:00:00+0000"', "SIGNATURE_INVALID"),
    ('"2026-05-19T24:00:00Z"', "SIGNATURE_INVALID"),
    ("7", "SIGNATURE_INVALID"),
    ("true", "SIGNATURE_INVALID"),
    ('"2026-05-19T01:00:00+01:00"', "ACCEPT"),
    ('"2026-05-19T00:00:00.5Z"', "ACCEPT"),
    ('"2026-05-19T00:00:00\\u005a"', "SIGNATURE_INVALID"),
    ('"2026-05-19T00:00:00+25:00"', "SIGNATURE_INVALID"),
    ('"2026-05-19T00:00:00+00:61"', "SIGNATURE_INVALID"),
)

# The tables below were recorded from the Go reference verifier in ../go, from
# `go run .` for a verdict and from canonicalPayload and canonicalPayloadV11
# for a signed payload, built with Go 1.22.12 and with Go 1.26.3, which agree
# on every row.

# A JSON escape outside issuedAt and expiresAt: Go decodes it, so the baselines
# still verify. (path, raw literal).
GO_ACCEPTED_ESCAPES = (
    (("agentId",), '"\\u0061gent_conformance_test_001"'),
    (("issuerDid",), '"did:opena2a:authority:opena2a\\u002eorg"'),
    (("createdAt",), '"2026-05-23T00:00:00\\u005a"'),
)

# A member whose name differs from the Go struct field's only in case, or by
# the two letters Go folds onto ASCII (Kelvin sign U+212A, long s U+017F): Go
# reads it as that member. (path, name as written, raw literal, Go verdict).
GO_FOLDED_NAME_VERDICTS = (
    (("revoked",), "Revoked", "true", "REVOKED"),
    (("revoked",), "REVOKED", "true", "REVOKED"),
    (("revoked",), "revo\u212aed", "true", "REVOKED"),
    (("signatures",), "\u017fignatures", "[]", "SIGNATURE_INVALID"),
    (("expiresAt",), "ExpiresAt", KEEP, "ACCEPT"),
    (("expiresAt",), "expiresat", '"2000-01-01T00:00:00Z"', "EXPIRED"),
    (("agentId",), "AGENTID", KEEP, "ACCEPT"),
    (("trustScore",), "TrustScore", KEEP, "ACCEPT"),
    (("atcVersion",), "ATCVERSION", '"9.9"', "UNSUPPORTED_VERSION"),
    (("issuerDid",), "ISSUERDID", '"did:x:y"', "UNTRUSTED_ISSUER"),
    (("id",), "ID", "7", "PARSE_ERROR"),
    (("signatures", 0, "value"), "VALUE", KEEP, "ACCEPT"),
    (("signatures", 0, "value"), "VALUE", "7", "PARSE_ERROR"),
    (("signatures", 0, "algorithm"), "Algorithm", '"none"', "SIGNATURE_INVALID"),
)

# The same for members only the v1.1 payload signs, on the v1.1 baseline.
GO_FOLDED_NAME_VERDICTS_V11 = (
    (("declaredPurpose",), "DeclaredPurpose", '{"x": 1}', "SIGNATURE_INVALID"),
    (("behavioralProfile",), "BEHAVIORALPROFILE", KEEP, "ACCEPT"),
    (("behavioralProfile",), "BehavioralProfile", "null", "SIGNATURE_INVALID"),
    (("behavioralProfile", "checksum"), "Checksum", KEEP, "ACCEPT"),
    (("behavioralProfile", "generatedAt"), "GENERATEDAT", KEEP, "ACCEPT"),
    (("behavioralProfile", "generatedAt"), "GeneratedAt", '"2026-05-19"', "SIGNATURE_INVALID"),
    (("behavioralProfile", "observationDays"), "ObservationDays", KEEP, "ACCEPT"),
    (("scanSummary",), "ScanSummary", KEEP, "ACCEPT"),
    (("scanSummary", "hma"), "HMA", KEEP, "ACCEPT"),
    (("scanSummary", "criticalFindings"), "CRITICALFINDINGS", "3", "SIGNATURE_INVALID"),
    (("scanSummary", "secretless"), "SECRETLESS", '"dirty"', "SIGNATURE_INVALID"),
    (("capabilities",), "Capabilities", KEEP, "ACCEPT"),
    (("issuerChain",), "IssuerChain", "[]", "SIGNATURE_INVALID"),
    (("publisher",), "PUBLISHER", '"x"', "SIGNATURE_INVALID"),
)

# What Go's base64.StdEncoding.DecodeString makes of the first signature's
# value after an edit: it skips CR and LF, keeps a final group's unused bits,
# and refuses every other character outside the padded standard alphabet.
# (edit, what it does to the value, Go verdict). A refused value rejects with
# "invalid base64" in the reason.
BASE64_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
GO_BASE64_VERDICTS = (
    ("two characters outside the alphabet appended", lambda v: v + "!!", "SIGNATURE_INVALID"),
    ("one inserted", lambda v: v[:10] + "!" + v[10:], "SIGNATURE_INVALID"),
    ("space appended", lambda v: v + " ", "SIGNATURE_INVALID"),
    ("space prepended", lambda v: " " + v, "SIGNATURE_INVALID"),
    ("tab appended", lambda v: v + "\t", "SIGNATURE_INVALID"),
    ("NUL appended", lambda v: v + "\x00", "SIGNATURE_INVALID"),
    ("third padding character", lambda v: v + "=", "SIGNATURE_INVALID"),
    ("data after the padding", lambda v: v + "AAAA", "SIGNATURE_INVALID"),
    ("padding removed", lambda v: v[:-2], "SIGNATURE_INVALID"),
    ("half the padding removed", lambda v: v[:-1], "SIGNATURE_INVALID"),
    ("URL-safe alphabet", lambda v: v.replace("+", "-").replace("/", "_"), "SIGNATURE_INVALID"),
    ("padding alone", lambda v: "====", "SIGNATURE_INVALID"),
    ("unpaired surrogate", lambda v: "\ud800", "SIGNATURE_INVALID"),
    ("LF appended", lambda v: v + "\n", "ACCEPT"),
    ("LF prepended", lambda v: "\n" + v, "ACCEPT"),
    ("CRLF inserted", lambda v: v[:40] + "\r\n" + v[40:], "ACCEPT"),
    ("LF inside the padding", lambda v: v[:-1] + "\n=", "ACCEPT"),
    # The last character before "==" carries four unused bits; setting one
    # leaves the decoded signature as it was.
    (
        "unused bit set",
        lambda v: v[:-3] + BASE64_ALPHABET[BASE64_ALPHABET.index(v[-3]) | 1] + "==",
        "ACCEPT",
    ),
)

# An unpaired UTF-16 surrogate escape in a string member, which Go's
# encoding/json decodes to U+FFFD. (path, raw literal, the string Go holds).
GO_SURROGATE_DECODES = (
    (("agentId",), '"\\ud800"', "\ufffd"),
    (("agentId",), '"\\udc00"', "\ufffd"),
    (("agentId",), '"a\\ud800b"', "a\ufffdb"),
    (("agentId",), '"\\ud800\\ud800"', "\ufffd\ufffd"),
    (("agentId",), '"\\udc00\\ud800"', "\ufffd\ufffd"),
    (("agentId",), '"\\ud800\\ud800\\udc00"', "\ufffd\U00010000"),
    (("publisher",), '"\\ud83d\\ude00"', "\U0001f600"),
    (("issuerDid",), '"did:x:\\ud800"', "did:x:\ufffd"),
)

# The verdict on each baseline with such an escape. (path, raw literal, Go
# verdict).
GO_SURROGATE_VERDICTS = (
    (("agentId",), '"\\ud800"', "SIGNATURE_INVALID"),
    (("agentId",), '"a\\ud800b"', "SIGNATURE_INVALID"),
    (("issuerDid",), '"did:x:\\ud800"', "UNTRUSTED_ISSUER"),
    (("id",), '"\\udfff"', "ACCEPT"),
    (("signatures", 0, "keyId"), '"\\ud800"', "ACCEPT"),
    (("signatures", 0, "value"), '"\\ud800"', "SIGNATURE_INVALID"),
)

# The same on the v1.1 baseline, for members only the v1.1 payload signs.
# declaredPurpose enters that payload undecoded, and the Go verifier refuses
# an unpaired surrogate escape in it before its JCS library reads it, one
# followed by another \u escape included, which that library reads as a
# single U+FFFD, and one beside a number the Python verifier's JCS serializer
# cannot write, 1.5.
GO_SURROGATE_VERDICTS_V11 = (
    (("publisher",), '"\\ud800"', "SIGNATURE_INVALID"),
    (("capabilities",), '["\\ud800"]', "SIGNATURE_INVALID"),
    (("issuerChain",), '["\\ud800"]', "SIGNATURE_INVALID"),
    (("behavioralProfile", "checksum"), '"\\ud800"', "SIGNATURE_INVALID"),
    (("scanSummary", "hma"), '"\\ud800"', "SIGNATURE_INVALID"),
    (("declaredPurpose",), '"\\ud800"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\udc00"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"k": "\\ud800"}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"\\ud800": 1}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '["\\ud800"]', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\ud800\\u0041"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\ud800\\ud800"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\udc00\\u0041"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\udc00\\ud800"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\udbff\\ue000"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\ud800\\udc00\\udc00"', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"k": "x\\ud800\\u0041"}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"x\\ud800\\u0041": 1}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"a": 1.5, "b": "\\ud800\\u0041"}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"a": 1.5, "b": "\\ud800"}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"b": "\\ud800\\u0041", "c": 1.5}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '["\\ud800\\u0041", 1.5]', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '{"a": 1.5, "\\udc00x": 1}', "VERIFIER_CONFIG_ERROR"),
    (("declaredPurpose",), '"\\ud83d\\ude00"', "SIGNATURE_INVALID"),
    (("declaredPurpose",), '"\\\\ud800"', "SIGNATURE_INVALID"),
    (("declaredPurpose",), '{"a": 1.5, "b": "\\ud83d\\ude00"}', "SIGNATURE_INVALID"),
    (("declaredPurpose",), '["\\\\ud800", 1.5]', "SIGNATURE_INVALID"),
)

# trustScore as Go formats it with %.6f into both signed payloads: the float64
# decode keeps the sign of a zero. (raw literal, formatted).
GO_TRUST_SCORE_FORMATS = (
    ("-0", "-0.000000"),
    ("-0.0", "-0.000000"),
    ("-0e0", "-0.000000"),
    ("-1e-9", "-0.000000"),
    ("0", "0.000000"),
    ("0.0000005", "0.000000"),
    ("87.5", "87.500000"),
)

# The v1.1 baseline's behavioralProfile and scanSummary as signed.
SIGNED_PROFILE = {
    "checksum": "sha256:ghi789",
    "generatedAt": "2026-05-19T00:00:00Z",
    "observationDays": 14,
}
SIGNED_SCAN = {
    "hma": "passed",
    "criticalFindings": 0,
    "highFindings": 0,
    "secretless": "clean",
    "cryptoServe": "no-weak-crypto",
    "oasbLevel": "L1",
}
GO_ZERO_TIME = "0001-01-01T00:00:00Z"
ZERO_PROFILE = {"checksum": "", "generatedAt": GO_ZERO_TIME, "observationDays": 0}
ZERO_SCAN = {
    "hma": "",
    "criticalFindings": 0,
    "highFindings": 0,
    "secretless": "",
    "cryptoServe": "",
    "oasbLevel": "",
}

# behavioralProfile as the Go verifier's projectBehavioralProfileV11 projects
# it into the v1.1 signed payload when the member at path holds the raw
# literal (None: absent). A member outside its Go type projects the whole
# profile as null; an absent or null member takes the Go zero value.
# (path, raw literal, projection).
GO_BEHAVIORAL_PROFILE_PROJECTIONS = (
    (("behavioralProfile", "generatedAt"), '"2026-05-19"', None),
    (("behavioralProfile", "generatedAt"), '"2026-05-19T00:00:00\\u005a"', None),
    (("behavioralProfile", "generatedAt"), '""', None),
    (("behavioralProfile", "generatedAt"), "0", None),
    (("behavioralProfile", "generatedAt"), "false", None),
    (("behavioralProfile", "generatedAt"), "[]", None),
    (("behavioralProfile", "generatedAt"), "{}", None),
    (("behavioralProfile", "generatedAt"), "null", {**SIGNED_PROFILE, "generatedAt": GO_ZERO_TIME}),
    (("behavioralProfile", "generatedAt"), None, {**SIGNED_PROFILE, "generatedAt": GO_ZERO_TIME}),
    (("behavioralProfile", "generatedAt"), '"2026-05-19T01:00:00+01:00"', SIGNED_PROFILE),
    (("behavioralProfile", "observationDays"), '"14"', None),
    (("behavioralProfile", "observationDays"), "14.0", None),
    (("behavioralProfile", "observationDays"), "14.5", None),
    (("behavioralProfile", "observationDays"), "1e1", None),
    (("behavioralProfile", "observationDays"), "true", None),
    (("behavioralProfile", "observationDays"), '"abc"', None),
    (("behavioralProfile", "observationDays"), "[]", None),
    (("behavioralProfile", "observationDays"), "9223372036854775808", None),
    (("behavioralProfile", "observationDays"), "null", {**SIGNED_PROFILE, "observationDays": 0}),
    (("behavioralProfile", "observationDays"), None, {**SIGNED_PROFILE, "observationDays": 0}),
    (("behavioralProfile", "observationDays"), "-0", {**SIGNED_PROFILE, "observationDays": 0}),
    (("behavioralProfile", "observationDays"), "-1", {**SIGNED_PROFILE, "observationDays": -1}),
    (("behavioralProfile", "checksum"), "7", None),
    (("behavioralProfile", "checksum"), "[]", None),
    (("behavioralProfile", "checksum"), "true", None),
    (("behavioralProfile", "checksum"), "{}", None),
    (("behavioralProfile", "checksum"), "null", {**SIGNED_PROFILE, "checksum": ""}),
    (("behavioralProfile", "checksum"), None, {**SIGNED_PROFILE, "checksum": ""}),
    (("behavioralProfile", "checksum"), '"\\ud800"', {**SIGNED_PROFILE, "checksum": "\ufffd"}),
    (("behavioralProfile",), "7", None),
    (("behavioralProfile",), '"x"', None),
    (("behavioralProfile",), "[]", None),
    (("behavioralProfile",), "true", None),
    (("behavioralProfile",), "null", None),
    (("behavioralProfile",), None, None),
    (("behavioralProfile",), "{}", ZERO_PROFILE),
)

# scanSummary as the Go verifier's projectScanSummaryV11 projects it. It
# ignores the decode error, so a member outside its Go type takes the zero
# value and the others keep theirs; the verifier refuses such a credential
# before it reads a signature over that projection (the verdicts below).
# (path, raw literal, projection).
GO_SCAN_SUMMARY_PROJECTIONS = (
    (("scanSummary", "criticalFindings"), "3", {**SIGNED_SCAN, "criticalFindings": 3}),
    (("scanSummary", "criticalFindings"), '"3"', SIGNED_SCAN),
    (("scanSummary", "criticalFindings"), "3.5", SIGNED_SCAN),
    (("scanSummary", "criticalFindings"), "3.0", SIGNED_SCAN),
    (("scanSummary", "criticalFindings"), "1e1", SIGNED_SCAN),
    (("scanSummary", "criticalFindings"), "true", SIGNED_SCAN),
    (("scanSummary", "criticalFindings"), '"abc"', SIGNED_SCAN),
    (("scanSummary", "criticalFindings"), "9223372036854775808", SIGNED_SCAN),
    (("scanSummary", "criticalFindings"), "null", SIGNED_SCAN),
    (("scanSummary", "highFindings"), '"1"', SIGNED_SCAN),
    (("scanSummary", "hma"), "7", {**SIGNED_SCAN, "hma": ""}),
    (("scanSummary", "hma"), "1.5", {**SIGNED_SCAN, "hma": ""}),
    (("scanSummary", "hma"), "true", {**SIGNED_SCAN, "hma": ""}),
    (("scanSummary", "hma"), "[]", {**SIGNED_SCAN, "hma": ""}),
    (("scanSummary", "hma"), "null", {**SIGNED_SCAN, "hma": ""}),
    (("scanSummary", "hma"), '"\\ud800"', {**SIGNED_SCAN, "hma": "\ufffd"}),
    (("scanSummary", "oasbLevel"), "2", {**SIGNED_SCAN, "oasbLevel": ""}),
    (("scanSummary", "secretless"), None, {**SIGNED_SCAN, "secretless": ""}),
    (("scanSummary",), "7", ZERO_SCAN),
    (("scanSummary",), '"x"', ZERO_SCAN),
    (("scanSummary",), "[1.5]", ZERO_SCAN),
    (("scanSummary",), "null", ZERO_SCAN),
    (("scanSummary",), None, ZERO_SCAN),
)

# The verdict on the v1.1 baseline with such a member. The baseline signs
# criticalFindings 0 and highFindings 0, so a scanSummary count the Go verifier
# cannot decode projects the signed 0; it has no value in the signed payload,
# which holds each scanSummary member typed, so the Go verifier refuses the
# credential as no signature covers it (decodeScanSummaryV11), and a null
# behavioralProfile is not what was signed. (path, raw literal, Go verdict).
GO_UNDECODABLE_MEMBER_VERDICTS = (
    (("scanSummary", "criticalFindings"), '"3"', "SIGNATURE_INVALID"),
    (("scanSummary", "criticalFindings"), "3.5", "SIGNATURE_INVALID"),
    (("scanSummary", "criticalFindings"), '"abc"', "SIGNATURE_INVALID"),
    (("scanSummary", "highFindings"), '"1"', "SIGNATURE_INVALID"),
    (("scanSummary", "criticalFindings"), "3", "SIGNATURE_INVALID"),
    (("scanSummary", "hma"), "7", "SIGNATURE_INVALID"),
    (("scanSummary", "criticalFindings"), "null", "ACCEPT"),
    (("behavioralProfile", "observationDays"), '"14"', "SIGNATURE_INVALID"),
    (("behavioralProfile", "observationDays"), "14.0", "SIGNATURE_INVALID"),
    (("behavioralProfile", "observationDays"), "14.5", "SIGNATURE_INVALID"),
    (("behavioralProfile", "observationDays"), '"abc"', "SIGNATURE_INVALID"),
    (("behavioralProfile", "checksum"), "7", "SIGNATURE_INVALID"),
)

# A fixture whose credential is not an object. Go's decode refuses a number,
# an array, a string or a boolean, and leaves null or {} at the zero value,
# whose atcVersion is "". (raw literal, Go verdict).
GO_CREDENTIAL_VERDICTS = (
    ("7", "PARSE_ERROR"),
    ("[]", "PARSE_ERROR"),
    ('"x"', "PARSE_ERROR"),
    ("true", "PARSE_ERROR"),
    ("null", "UNSUPPORTED_VERSION"),
    ("{}", "UNSUPPORTED_VERSION"),
)

# An expiresAt of 2099-12-31T23:59:59.5Z against a verifier clock in the same
# second: the comparison keeps the fraction. (clock, Go verdict).
GO_SUBSECOND_EXPIRY_VERDICTS = (
    ("2099-12-31T23:59:59.6Z", "EXPIRED"),
    ("2099-12-31T23:59:59.5Z", "ACCEPT"),
    ("2099-12-31T23:59:59.4Z", "ACCEPT"),
)

# A fixture whose expected member the Go verifier's expectedOutcome struct
# cannot hold, so the file fails to load there, with what this verifier's
# load error names.
GO_UNLOADABLE_EXPECTED = (
    ("7", "expected 7 is not a JSON object"),
    ('"ACCEPT"', "expected 'ACCEPT' is not a JSON object"),
    ("[]", "expected [] is not a JSON object"),
    ("true", "expected True is not a JSON object"),
    ('{"verifyResult": 7}', "expected.verifyResult 7 is not a JSON string"),
    ('{"verifyResult": "REJECT", "rejectCategory": 7}', "expected.rejectCategory 7 is not a JSON string"),
    ('{"verifyResult": "REJECT", "reasonContains": 7}', "expected.reasonContains 7 is not a JSON string"),
)

# The tables below were recorded from `go run .` in ../go, built with Go
# 1.22.12 and with Go 1.27.2, which agree on every row.

# A fixture member outside the type the Go verifier's fixture struct gives it,
# on the CRL baseline: the file fails to load there. (path from the fixture
# object, raw literal, the member this verifier's load error names).
GO_UNLOADABLE_WRAPPERS = (
    (("name",), '{"a": 1}', "name"),
    (("description",), "7", "description"),
    (("keypairRefs",), '"x"', "keypairRefs"),
    (("keypairRefs",), "[7]", "keypairRefs[0]"),
    (("keypairRefs", 0, "publicKeyHex"), "7", "keypairRefs[0].publicKeyHex"),
    (("verifierState",), "[]", "verifierState"),
    (("verifierState", "clockRfc3339"), "7", "verifierState.clockRfc3339"),
    (("verifierState", "trustedIssuers"), '"x"', "verifierState.trustedIssuers"),
    (("verifierState", "trustedIssuers"), "[7]", "verifierState.trustedIssuers[0]"),
    (("verifierState", "publicKeys"), '{"x": 1}', "verifierState.publicKeys"),
    (("verifierState", "publicKeys", 0, "keyId"), "7", "verifierState.publicKeys[0].keyId"),
    (("verifierState", "crl"), '"x"', "verifierState.crl"),
    (("verifierState", "crl", "version"), "1.5", "verifierState.crl.version"),
    (("verifierState", "crl", "version"), '"1"', "verifierState.crl.version"),
    (("verifierState", "crl", "issuedAt"), '"2026-05-23"', "verifierState.crl.issuedAt"),
    (("verifierState", "crl", "nextUpdate"), "7", "verifierState.crl.nextUpdate"),
    (("verifierState", "crl", "entries"), "[7]", "verifierState.crl.entries[0]"),
    (("verifierState", "crl", "entries", 0, "agentId"), "7", "verifierState.crl.entries[0].agentId"),
    (
        ("verifierState", "crl", "entries", 0, "revokedAt"),
        '"2026-05-23T12:00:00\\u005a"',
        "verifierState.crl.entries[0].revokedAt",
    ),
    (("verifierState", "crl", "signature"), "7", "verifierState.crl.signature"),
)

# The verdict when a fixture member is renamed to another case (rename), holds
# the raw literal, or is absent (None). Go matches a fixture member name to its
# field in any case, leaves a null or absent member at its zero value, and
# holds no credential at all when atx is absent. (baseline, path, raw literal,
# rename, Go verdict).
GO_WRAPPER_VERDICTS = (
    (BASELINE_V11, ("verifierState", "trustedIssuers"), KEEP, "TrustedIssuers", "ACCEPT"),
    (BASELINE_V11, ("verifierState", "clockRfc3339"), KEEP, "CLOCKRFC3339", "ACCEPT"),
    (BASELINE_V11, ("verifierState", "publicKeys"), KEEP, "PublicKeys", "ACCEPT"),
    (BASELINE_V11, ("verifierState", "publicKeys", 0, "publicKeyHex"), KEEP, "PUBLICKEYHEX", "ACCEPT"),
    (BASELINE_V11, ("verifierState",), KEEP, "VerifierState", "ACCEPT"),
    (BASELINE_V11, ("atx",), KEEP, "ATX", "ACCEPT"),
    (BASELINE_V11, ("name",), "null", None, "ACCEPT"),
    (BASELINE_V11, ("keypairRefs",), "null", None, "ACCEPT"),
    (BASELINE_V11, ("verifierState", "trustedIssuers"), None, None, "UNTRUSTED_ISSUER"),
    (BASELINE_V11, ("verifierState", "clockRfc3339"), None, None, "VERIFIER_CONFIG_ERROR"),
    (BASELINE_V11, ("verifierState",), "null", None, "VERIFIER_CONFIG_ERROR"),
    (BASELINE_V11, ("atx",), None, None, "PARSE_ERROR"),
    (BASELINE_CRL, ("verifierState", "crl"), KEEP, "CRL", "REVOKED"),
    (BASELINE_CRL, ("verifierState", "crl", "entries"), KEEP, "Entries", "REVOKED"),
    (BASELINE_CRL, ("verifierState", "crl", "entries", 0, "agentId"), KEEP, "AGENTID", "REVOKED"),
    (BASELINE_CRL, ("verifierState", "crl"), "null", None, "ACCEPT"),
    (BASELINE_CRL, ("verifierState", "crl", "entries"), "[null]", None, "ACCEPT"),
    (BASELINE_CRL, ("verifierState", "crl", "revokedAt"), '"not-a-date"', None, "REVOKED"),
)

# An expected member that repeats a name, with a case variant between the
# repeats or in place of the second. The file fails to load, its load error
# naming the member as written the second time. (raw literal, that member).
GO_REPEATED_EXPECTED_NAMES = (
    ('{"verifyResult": "ACCEPT", "VerifyResult": "REJECT", "verifyResult": "ACCEPT"}', "VerifyResult"),
    ('{"verifyResult": "REJECT", "VerifyResult": "ACCEPT", "verifyResult": "REJECT"}', "VerifyResult"),
    ('{"VerifyResult": "REJECT", "verifyResult": "ACCEPT"}', "verifyResult"),
    ('{"verifyResult": "REJECT", "VERIFYRESULT": "ACCEPT"}', "VERIFYRESULT"),
)

# The two tables below were recorded from `go run .` in ../go built with Go
# 1.26.3, on fixtures _write_repeated writes: the member at path written
# first under the name given (its own when None) holding the raw literal,
# then as the baseline writes it. Each file fails to load for the repeat,
# before any member is decoded, whatever the first value holds: the load
# error names the member as written the second time, its own name.

# A repeated fixture member whose first value is outside its Go type, on the
# CRL baseline. Go reported the type error once it had decoded the second
# value; it now reports the repeat. (path, first name, raw literal, the
# member the load error names).
GO_UNLOADABLE_REPEATS = (
    (("verifierState", "clockRfc3339"), None, "5", "clockRfc3339"),
    (("verifierState", "clockRfc3339"), None, "9" * 401, "clockRfc3339"),
    (("verifierState", "clockRfc3339"), None, "9" * 5001, "clockRfc3339"),
    (("verifierState", "clockRfc3339"), "ClockRfc3339", "9" * 5001, "clockRfc3339"),
    (("name",), "NAME", "5", "name"),
    (("expected", "verifyResult"), "VerifyResult", "7", "verifyResult"),
    (("keypairRefs", 0, "keyId"), None, "7", "keyId"),
    (("verifierState",), None, "[]", "verifierState"),
    (("verifierState",), None, '{"clockRfc3339": 5}', "verifierState"),
    (("verifierState", "crl", "issuedAt"), None, '"2026-05-23T00:00:00\\u005a"', "issuedAt"),
    (("verifierState", "crl"), None, '{"issuedAt": "2026-05-23T00:00:00\\u005a"}', "crl"),
    (
        ("verifierState", "crl", "entries", 0, "revokedAt"),
        "RevokedAt",
        '"2026-05-23T12:00:00\\u005a"',
        "revokedAt",
    ),
)

# A repeated fixture member whose first value is inside its Go type. Go
# verified the second value; the file now fails to load. (baseline, path,
# first name, raw literal, the member the load error names).
GO_REPEATS_INSIDE_THEIR_TYPE = (
    (BASELINE_V11, ("verifierState", "clockRfc3339"), None, "null", "clockRfc3339"),
    (BASELINE_V11, ("verifierState", "clockRfc3339"), None, '"2100-01-01T00:00:00Z"', "clockRfc3339"),
    (BASELINE_V11, ("name",), "NAME", '"another name"', "name"),
    (BASELINE_CRL, ("verifierState", "crl", "issuedAt"), None, '"2026-05-23T00:00:00Z"', "issuedAt"),
)

# What Go's hex.DecodeString makes of a public key's publicKeyHex, None where
# it returns an error and the Go verifier skips the key.
GO_HEX_DECODES = (
    ("", b""),
    ("ABcd", b"\xab\xcd"),
    ("zz", None),
    ("abc", None),
    ("ab cd", None),
    (" abcd", None),
    ("abcd\n", None),
)

# Nesting at the edge of Go's encoding/json depth limit, 10000 levels with
# the fixture object: (where, how many arrays nest there, Go verdict, or None
# where the file fails to load). declaredPurpose enters the v1.1 TBS as
# written, so there the arrays are canonicalized at that depth too. A member
# Go decodes into a typed field is a PARSE_ERROR when it holds an array, and
# one of scanSummary or behavioralProfile, which the v1.1 projection decodes
# without failing, leaves a payload the signature does not cover.
GO_NESTING_VERDICTS = (
    (("deep",), 5000, "ACCEPT"),
    (("deep",), 9999, "ACCEPT"),
    (("deep",), 10000, None),
    (("atx", "extra"), 5000, "ACCEPT"),
    (("atx", "extra"), 9999, None),
    (("atx", "declaredPurpose"), 3000, "SIGNATURE_INVALID"),
    (("atx", "declaredPurpose"), 9998, "SIGNATURE_INVALID"),
    (("atx", "declaredPurpose"), 9999, None),
    (("atx",), 9999, "PARSE_ERROR"),
    (("atx",), 10000, None),
    (("atx", "publisher"), 9998, "PARSE_ERROR"),
    (("atx", "publisher"), 9999, None),
    (("atx", "transparencyLogIndex"), 9998, "PARSE_ERROR"),
    (("atx", "trustScore"), 9998, "PARSE_ERROR"),
    (("atx", "revoked"), 9998, "PARSE_ERROR"),
    (("atx", "issuedAt"), 9998, "PARSE_ERROR"),
    (("atx", "capabilities"), 9998, "PARSE_ERROR"),
    (("atx", "issuerChain"), 9998, "PARSE_ERROR"),
    (("atx", "signatures"), 9998, "PARSE_ERROR"),
    (("atx", "scanSummary", "hma"), 9997, "SIGNATURE_INVALID"),
    (("atx", "scanSummary", "hma"), 9998, None),
    (("atx", "behavioralProfile", "checksum"), 9997, "SIGNATURE_INVALID"),
)

# The same edge with objects nested in place of the arrays, each the member
# "a" of the one around it: (where, how many objects nest there, Go verdict,
# or None where the file fails to load). A member Go decodes into a slice
# (capabilities, issuerChain, signatures) is a PARSE_ERROR when it holds an
# object, which no row of arrays reaches: an array there is refused at its
# first entry.
GO_OBJECT_NESTING_VERDICTS = (
    (("atx", "extra"), 9998, "ACCEPT"),
    (("atx", "extra"), 9999, None),
    (("atx", "capabilities"), 3001, "PARSE_ERROR"),
    (("atx", "capabilities"), 9998, "PARSE_ERROR"),
    (("atx", "capabilities"), 9999, None),
    (("atx", "issuerChain"), 9998, "PARSE_ERROR"),
    (("atx", "signatures"), 9998, "PARSE_ERROR"),
    (("atx", "publisher"), 9998, "PARSE_ERROR"),
    (("atx", "trustScore"), 9998, "PARSE_ERROR"),
    (("atx", "scanSummary", "hma"), 9997, "SIGNATURE_INVALID"),
    (("atx", "behavioralProfile", "checksum"), 9997, "SIGNATURE_INVALID"),
)

# A fixture member the Go verifier's fixture struct decodes into a string,
# holding arrays nested to Go's depth limit: the file fails to load there.
# (path from the fixture object, how many arrays nest there).
GO_NESTED_WRAPPERS = (
    (("expected", "verifyResult"), 9998),
    (("verifierState", "clockRfc3339"), 9998),
)

# A fixture member that struct decodes into a slice, holding objects nested
# to Go's depth limit: the file fails to load there too. (path from the
# fixture object, how many objects nest there).
GO_OBJECT_NESTED_WRAPPERS = (
    (("keypairRefs",), 9999),
    (("verifierState", "trustedIssuers"), 9998),
    (("verifierState", "publicKeys"), 9998),
)

# A JSON integer of 5001 digits. From Python 3.11, int() refuses a literal of
# more than sys.get_int_max_str_digits() digits, 4300 unless the interpreter
# is set otherwise.
LONG_INTEGER = "1" + "0" * 5000

# Where a fixture holds that integer, or the negative one as long: (path from
# the fixture object, Go verdict, or None where the file fails to load). Go
# keeps a member no struct declares as bytes it never decodes, so there the
# fixture verifies as the baseline does. The number is out of range for a
# member Go decodes into int64 or float64 and of the wrong type for any other
# typed member. A scanSummary member the v1.1 projection cannot decode has no
# value in the signed payload, so the verifier refuses it before it reads a
# signature, though the projection holds the 0 the baseline signs in its place.
GO_LONG_INTEGER_VERDICTS = (
    (("unknownMember",), "ACCEPT"),
    (("atx", "unknownMember"), "ACCEPT"),
    (("verifierState", "unknownMember"), "ACCEPT"),
    (("atx", "scanSummary", "criticalFindings"), "SIGNATURE_INVALID"),
    (("atx", "scanSummary", "hma"), "SIGNATURE_INVALID"),
    (("atx", "behavioralProfile", "observationDays"), "SIGNATURE_INVALID"),
    (("atx",), "PARSE_ERROR"),
    (("atx", "trustLevel"), "PARSE_ERROR"),
    (("atx", "transparencyLogIndex"), "PARSE_ERROR"),
    (("atx", "trustScore"), "PARSE_ERROR"),
    (("atx", "revoked"), "PARSE_ERROR"),
    (("atx", "publisher"), "PARSE_ERROR"),
    (("atx", "issuedAt"), "PARSE_ERROR"),
    (("atx", "capabilities"), "PARSE_ERROR"),
    (("atx", "signatures", 0, "value"), "PARSE_ERROR"),
    (("name",), None),
    (("expected", "verifyResult"), None),
    (("verifierState", "clockRfc3339"), None),
)

# Bytes that are not UTF-8 inside a string: Go decodes each byte of an
# invalid sequence to U+FFFD. (raw bytes of the name member's literal, the
# name Go holds).
GO_INVALID_UTF8_DECODES = (
    (b'"ab\xffcd"', "ab�cd"),
    (b'"ab\xe2\x82cd"', "ab��cd"),
    (b'"\xed\xa0\x80"', "���"),
    (b'"\xf0\x9f\x98"', "���"),
    (b'"\xc0\xaf"', "��"),
    (b'"\xf0\x9f\x98\x80"', "\U0001f600"),
)


def _outcome(got: verify.VerifyResult) -> str:
    return "ACCEPT" if got.accepted else got.reject_category


def _arrays(n: int) -> str:
    """n arrays, each the one entry of the array around it."""
    return "[" * n + "]" * n


def _objects(n: int) -> str:
    """n objects, each the member "a" of the object around it."""
    return '{"a":' * (n - 1) + "{}" + "}" * (n - 1)


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

    def test_offsets_out_of_range_raise_as_go_does(self):
        for text, message in GO_OFFSET_OUT_OF_RANGE:
            with self.subTest(timestamp=text):
                with self.assertRaises(ValueError) as raised:
                    verify._parse_rfc3339(text)
                self.assertEqual(str(raised.exception), message)

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

    def test_offset_out_of_range_is_a_parse_error(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for member, literal, message in GO_OFFSET_VERDICTS:
                with self.subTest(baseline=baseline.name, member=member, value=literal):
                    got = _member_verdict(baseline, member, literal)
                    self.assertEqual(_outcome(got), "PARSE_ERROR", got.reason)
                    self.assertIn(message, got.reason)

    def test_clock_offset_out_of_range_is_a_config_error(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for clock, message in (
                ("2026-06-01T00:00:00+23:61", "time zone offset minute out of range"),
                ("2026-02-30T00:00:00+25:00", "time zone offset hour out of range"),
            ):
                with self.subTest(baseline=baseline.name, clock=clock):
                    fixture = json.loads(baseline.read_text())
                    fixture["verifierState"]["clockRfc3339"] = clock
                    got = verify.verify_fixture(fixture)
                    self.assertEqual(got.reject_category, "VERIFIER_CONFIG_ERROR", got.reason)
                    self.assertIn(message, got.reason)

    def test_crl_offset_out_of_range_is_a_load_error(self):
        for path, literal, member in GO_UNLOADABLE_OFFSETS:
            with self.subTest(path=path, value=literal), tempfile.TemporaryDirectory() as tmp:
                written = _write_fixture_at(Path(tmp), "w.json", BASELINE_CRL, path, literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(written))
                self.assertTrue(str(raised.exception).startswith(member + " "), raised.exception)
                self.assertIn("time zone offset", str(raised.exception))

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


class GoGeneratedAtProjection(unittest.TestCase):
    def test_generated_at_reaches_the_go_verdict(self):
        for literal, outcome in GO_GENERATED_AT_VERDICTS:
            with self.subTest(value=literal), tempfile.TemporaryDirectory() as tmp:
                path = _write_generated_at(Path(tmp), "generated-at.json", literal, outcome)
                got = verify.verify_fixture(verify.load_fixture(path))
                self.assertEqual(_outcome(got), outcome, got.reason)

    def test_directory_run_reaches_the_summary_line(self):
        # Each generatedAt outside the layout used to end in a verify error
        # with no verdict.
        n = len(GO_GENERATED_AT_VERDICTS)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for i, (literal, outcome) in enumerate(GO_GENERATED_AT_VERDICTS):
                _write_generated_at(directory, f"{i:02d}-generated-at.json", literal, outcome)
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 0, text + err)
        self.assertNotIn("verify error", text)
        self.assertEqual(text.splitlines()[-1], f"summary: {n} pass, 0 fail ({n} fixtures)")


class GoMemberNameFolding(unittest.TestCase):
    def test_folded_name_reaches_the_go_verdict(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for path, name, literal, outcome in GO_FOLDED_NAME_VERDICTS:
                with self.subTest(baseline=baseline.name, path=path, name=name, value=literal):
                    got = _at_verdict(baseline, path, literal, rename=name)
                    self.assertEqual(_outcome(got), outcome, got.reason)

    def test_folded_name_of_a_v1_1_member_reaches_the_go_verdict(self):
        for path, name, literal, outcome in GO_FOLDED_NAME_VERDICTS_V11:
            with self.subTest(path=path, name=name, value=literal):
                got = _at_verdict(BASELINE_V11, path, literal, rename=name)
                self.assertEqual(_outcome(got), outcome, got.reason)

    def test_non_ascii_names_fold_only_through_the_fixed_table(self):
        # The fold is ASCII A-Z, the Kelvin sign and the long s, the letters
        # Go folds onto an ASCII field name, and every other character
        # unchanged, so no Python release's Unicode tables decide it: other
        # names are one member only when they decode to the same name, as in
        # the Go verifier. str.lower() made U+1C89 and U+1C8A, a case pair
        # from Unicode 16.0, a duplicate under Python 3.14 and not 3.12, and
        # folded U+0130 to i followed by U+0307.
        self.assertEqual(verify._fold_key("Éclair"), "Éclair")
        self.assertEqual(verify._fold_key("\u0130d"), "\u0130d")
        for literal in (
            '{"É": 1, "é": 2}',
            '{"\\u1c89x": 1, "\\u1c8ax": 2}',
            '{"\\u0130d": 1, "id": 2}',
            '{"\\u0130x": 1, "i\\u0307x": 2}',
        ):
            with self.subTest(value=literal):
                got = _at_verdict(BASELINE_V11, ("extra",), literal)
                self.assertTrue(got.accepted, got.reason)
        got = _at_verdict(BASELINE_V11, ("extra",), '{"É": 1, "É": 2}')
        self.assertEqual(got.reject_category, "PARSE_ERROR", got.reason)
        self.assertIn('duplicate member "É"', got.reason)

    def test_another_name_is_not_the_member(self):
        # Control: folding joins case variants only. "revoked_" is no member
        # of the credential, so revoked is absent, false, and the baseline
        # verifies.
        for baseline in (BASELINE_V10, BASELINE_V11):
            with self.subTest(baseline=baseline.name):
                got = _at_verdict(baseline, ("revoked",), "true", rename="revoked_")
                self.assertTrue(got.accepted, got.reason)


class GoEscapedString(unittest.TestCase):
    def test_escape_outside_a_timestamp_is_decoded(self):
        # MALFORMED_MEMBERS holds the other half: an escape in issuedAt or
        # expiresAt is a PARSE_ERROR.
        for baseline in (BASELINE_V10, BASELINE_V11):
            for path, literal in GO_ACCEPTED_ESCAPES:
                with self.subTest(baseline=baseline.name, path=path, value=literal):
                    got = _at_verdict(baseline, path, literal)
                    self.assertTrue(got.accepted, got.reason)

    def test_escaped_verifier_clock_is_decoded(self):
        # Go holds clockRfc3339 as a string and parses it once decoded.
        fixture = json.loads(BASELINE_V11.read_text())
        fixture["verifierState"]["clockRfc3339"] = "@@CLOCK@@"
        text = json.dumps(fixture).replace("@@CLOCK@@", "2026-05-24T00:00:00\\u005a")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clock.json"
            path.write_text(text)
            got = verify.verify_fixture(verify.load_fixture(path))
        self.assertTrue(got.accepted, got.reason)


class GoSignatureBase64(unittest.TestCase):
    def test_signature_value_reaches_the_go_verdict(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            value = json.loads(baseline.read_text())["atx"]["signatures"][0]["value"]
            for label, edit, outcome in GO_BASE64_VERDICTS:
                with self.subTest(baseline=baseline.name, edit=label):
                    self.assertNotEqual(edit(value), value)
                    path = ("signatures", 0, "value")
                    got = _at_verdict(baseline, path, json.dumps(edit(value)))
                    self.assertEqual(_outcome(got), outcome, got.reason)
                    if outcome != "ACCEPT":
                        self.assertIn("invalid base64", got.reason)


class GoUnpairedSurrogate(unittest.TestCase):
    def test_string_member_decodes_to_the_replacement_character(self):
        for path, literal, decoded in GO_SURROGATE_DECODES:
            with self.subTest(path=path, value=literal):
                credential = _credential_at(BASELINE_V11, path, literal)
                self.assertEqual(credential[path[0]], decoded)

    def test_signed_payloads_carry_the_replacement_character(self):
        v10 = verify.canonical_payload(_credential_at(BASELINE_V10, ("agentId",), '"a\\ud800b"'))
        self.assertTrue(v10.startswith("a\ufffdb|".encode("utf-8")), v10)
        v11 = _projection_at(("agentId",), '"a\\ud800b"')
        self.assertEqual(v11["agentId"], "a\ufffdb")

    def test_member_reaches_the_go_verdict(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for path, literal, outcome in GO_SURROGATE_VERDICTS:
                with self.subTest(baseline=baseline.name, path=path, value=literal):
                    got = _at_verdict(baseline, path, literal)
                    self.assertEqual(_outcome(got), outcome, got.reason)

    def test_v1_1_member_reaches_the_go_verdict(self):
        for path, literal, outcome in GO_SURROGATE_VERDICTS_V11:
            with self.subTest(path=path, value=literal):
                got = _at_verdict(BASELINE_V11, path, literal)
                self.assertEqual(_outcome(got), outcome, got.reason)

    def test_declared_purpose_escape_is_refused_before_a_number(self):
        # The JCS serializer cannot write 1.5, which left no payload to
        # verify, so a declaredPurpose holding one beside an unpaired
        # surrogate escape was a signature failure here. The Go verifier
        # refuses the escape before it canonicalizes, naming the first one
        # the text writes, and so does this one, before the 1e400 it would
        # otherwise name.
        for literal, escape in (
            ('{"a": 1.5, "b": "\\ud800\\u0041"}', "\\ud800"),
            ('{"a": 1.5, "b": "\\ud800"}', "\\ud800"),
            ('["\\ud800\\udc00\\udc00", 2.5]', "\\udc00"),
            ('{"a": 1e400, "b": "\\ud800"}', "\\ud800"),
        ):
            with self.subTest(value=literal):
                got = _at_verdict(BASELINE_V11, ("declaredPurpose",), literal)
                self.assertEqual(got.reject_category, "VERIFIER_CONFIG_ERROR", got.reason)
                self.assertEqual(
                    got.reason,
                    "v1.1 canonicalization failed: declaredPurpose holds an unpaired "
                    f"UTF-16 surrogate escape ({escape})",
                )

    def test_declared_purpose_signed_with_the_replacement_character(self):
        # The Go verifier's JCS library reads an unpaired surrogate escape
        # followed by another \u escape as one U+FFFD, the second escape
        # included, so before the Go verifier refused the escape itself a
        # credential signed holding U+FFFD verified there with such a pair
        # written in its place. Both verifiers refuse it.
        fixture = json.loads(BASELINE_V11.read_text())
        fixture["atx"]["declaredPurpose"] = "\N{REPLACEMENT CHARACTER}"
        with tempfile.TemporaryDirectory() as tmp:
            signed = _write_signed_v11(Path(tmp), "signed.json", fixture)
            got = verify.verify_fixture(verify.load_fixture(signed))
            self.assertTrue(got.accepted, got.reason)
            for literal in ('"\\ud800\\u0041"', '"\\ud800\\ud800"', '"\\udc00\\ufffd"'):
                with self.subTest(value=literal):
                    got = _at_verdict(signed, ("declaredPurpose",), literal)
                    self.assertEqual(got.reject_category, "VERIFIER_CONFIG_ERROR", got.reason)

    def test_names_that_decode_alike_are_duplicates(self):
        # Go decodes both names to U+FFFD, so its strict parse sees one name
        # twice, at the top of the credential and below it.
        for literal in (
            '{"\\ud800": 1, "\\ufffd": 2}',
            '{"\\ud800": 1, "\\udbff": 2}',
            '[{"\\udc00": 1, "\\ud800": 2}]',
        ):
            with self.subTest(value=literal):
                got = _at_verdict(BASELINE_V11, ("extra",), literal)
                self.assertEqual(got.reject_category, "PARSE_ERROR", got.reason)
                self.assertIn("duplicate member", got.reason)

    def test_verifier_state_strings_decode_the_same_way(self):
        # Go decodes the CRL's agentId and the trusted issuers as it decodes
        # the credential, so an unpaired surrogate on one side matches U+FFFD
        # or another unpaired surrogate on the other.
        for baseline in (BASELINE_V10, BASELINE_V11):
            for agent_id, revoked_id in (("a\ud800", "a\ufffd"), ("a\ufffd", "a\udc00")):
                with self.subTest(baseline=baseline.name, agent=agent_id, crl=revoked_id):
                    fixture = json.loads(baseline.read_text())
                    fixture["atx"]["agentId"] = agent_id
                    fixture["verifierState"]["crl"] = {
                        "entries": [{"agentId": revoked_id, "reason": "r\ud800"}]
                    }
                    with tempfile.TemporaryDirectory() as tmp:
                        path = Path(tmp) / "crl.json"
                        path.write_text(json.dumps(fixture))
                        got = verify.verify_fixture(verify.load_fixture(path))
                    self.assertEqual(got.reject_category, "REVOKED", got.reason)
                    self.assertEqual(got.reason, "agent appears on CRL: r\ufffd")
            with self.subTest(baseline=baseline.name, trusted="did:x:\\udfff"):
                fixture = json.loads(baseline.read_text())
                fixture["atx"]["issuerDid"] = "did:x:\ud800"
                fixture["verifierState"]["trustedIssuers"] = ["did:x:\udfff"]
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "trusted.json"
                    path.write_text(json.dumps(fixture))
                    got = verify.verify_fixture(verify.load_fixture(path))
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)


class GoNegativeZero(unittest.TestCase):
    def test_trust_score_formats_as_go_formats_it(self):
        for literal, formatted in GO_TRUST_SCORE_FORMATS:
            with self.subTest(value=literal):
                v10 = verify.canonical_payload(_credential_at(BASELINE_V10, ("trustScore",), literal))
                self.assertEqual(v10.decode("utf-8").split("|")[7], formatted)
                self.assertEqual(_projection_at(("trustScore",), literal)["trustScore"], formatted)

    def test_negative_zero_is_an_integer(self):
        # Controls: Go decodes -0 into an int64 or int field as 0, so it is
        # not a PARSE_ERROR. transparencyLogIndex is unsigned by both payloads;
        # trustLevel 0 is not the signed 4.
        for baseline in (BASELINE_V10, BASELINE_V11):
            with self.subTest(baseline=baseline.name):
                got = _at_verdict(baseline, ("transparencyLogIndex",), "-0")
                self.assertTrue(got.accepted, got.reason)
                got = _at_verdict(baseline, ("trustLevel",), "-0")
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)


class GoUndecodableProjection(unittest.TestCase):
    # The verdict alone does not tell a null behavioralProfile from any other
    # projection the baseline's signature does not cover, so these compare the
    # projected member with the one the Go verifier signs over.
    def test_behavioral_profile_projects_as_go_projects_it(self):
        for path, literal, projection in GO_BEHAVIORAL_PROFILE_PROJECTIONS:
            with self.subTest(path=path, value=literal):
                self.assertEqual(_projection_at(path, literal)["behavioralProfile"], projection)

    def test_scan_summary_projects_as_go_projects_it(self):
        for path, literal, projection in GO_SCAN_SUMMARY_PROJECTIONS:
            with self.subTest(path=path, value=literal):
                self.assertEqual(_projection_at(path, literal)["scanSummary"], projection)

    def test_baseline_projects_what_it_signs(self):
        payload = _projection_at(("createdAt",), KEEP)
        self.assertEqual(payload["behavioralProfile"], SIGNED_PROFILE)
        self.assertEqual(payload["scanSummary"], SIGNED_SCAN)

    def test_member_reaches_the_go_verdict(self):
        for path, literal, outcome in GO_UNDECODABLE_MEMBER_VERDICTS:
            with self.subTest(path=path, value=literal):
                got = _at_verdict(BASELINE_V11, path, literal)
                self.assertEqual(_outcome(got), outcome, got.reason)

    def test_directory_run_reaches_the_summary_line(self):
        # A non-numeric observationDays or criticalFindings used to end in a
        # verify error with no verdict.
        n = len(GO_UNDECODABLE_MEMBER_VERDICTS)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for i, (path, literal, outcome) in enumerate(GO_UNDECODABLE_MEMBER_VERDICTS):
                expected = {"verifyResult": "ACCEPT"}
                if outcome != "ACCEPT":
                    expected = {"verifyResult": "REJECT", "rejectCategory": outcome}
                _write_at(directory, f"{i:02d}.json", BASELINE_V11, path, literal, expected=expected)
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 0, text + err)
        self.assertNotIn("verify error", text)
        self.assertEqual(text.splitlines()[-1], f"summary: {n} pass, 0 fail ({n} fixtures)")


class GoScanSummaryOutsideItsType(unittest.TestCase):
    """A v1.1 scanSummary member outside its Go type, or a scanSummary that is
    not an object, has no value in the signed payload, which holds each of
    its six members typed, so the Go verifier refuses the credential as no
    signature covers it, before it reads one, naming scanSummary
    (fixtures/v1_1-scan-summary-member-outside-type.json). Its projection
    would hold the zero value in that member's place."""

    def test_baseline_member_outside_its_type_names_scan_summary(self):
        for path, literal in (
            (("scanSummary", "criticalFindings"), '"3"'),
            (("scanSummary", "criticalFindings"), "3.5"),
            (("scanSummary", "criticalFindings"), "1e1"),
            (("scanSummary", "criticalFindings"), "9223372036854775808"),
            (("scanSummary", "highFindings"), '"1"'),
            (("scanSummary", "hma"), "7"),
            (("scanSummary", "oasbLevel"), '["L1"]'),
        ):
            with self.subTest(path=path, value=literal):
                got = _at_verdict(BASELINE_V11, path, literal)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)
                self.assertIn("scanSummary", got.reason)
                self.assertIn("signature", got.reason)

    def test_credential_signed_with_a_zero_scan_summary(self):
        # The baseline signs a scanSummary that is not zero, so one projected
        # as zero fails that signature whether or not it is refused first; a
        # credential signed with a zero scanSummary is where the two differ.
        fixture = json.loads(BASELINE_V11.read_text())
        fixture["atx"]["scanSummary"] = None
        with tempfile.TemporaryDirectory() as tmp:
            signed = _write_signed_v11(Path(tmp), "signed.json", fixture)
            got = verify.verify_fixture(verify.load_fixture(signed))
            self.assertTrue(got.accepted, got.reason)
            for literal, outcome in (
                ("7", "SIGNATURE_INVALID"),
                ('"x"', "SIGNATURE_INVALID"),
                ("[1.5]", "SIGNATURE_INVALID"),
                ("true", "SIGNATURE_INVALID"),
                ('{"criticalFindings": "3"}', "SIGNATURE_INVALID"),
                ('{"hma": 0}', "SIGNATURE_INVALID"),
                ("{}", "ACCEPT"),
                ('{"criticalFindings": null, "hma": null}', "ACCEPT"),
                (None, "ACCEPT"),
            ):
                with self.subTest(value=literal):
                    got = _at_verdict(signed, ("scanSummary",), literal)
                    self.assertEqual(_outcome(got), outcome, got.reason)
                    if outcome != "ACCEPT":
                        self.assertIn("scanSummary", got.reason)

    def test_v1_0_scan_summary_is_not_read(self):
        # atcVersion 1.0 signs no scanSummary (core.md section 1.3a.1).
        got = _at_verdict(BASELINE_V10, ("scanSummary", "criticalFindings"), '"3"')
        self.assertTrue(got.accepted, got.reason)


def _write_with(directory: Path, name: str, baseline: Path, edits: dict, expected: dict | None = None) -> Path:
    """_write_at for several members: `baseline` with each atx member at a
    path of `edits` replaced by the raw JSON literal it maps to."""
    fixture = json.loads(baseline.read_text())
    fixture["expected"] = dict(expected or PARSE_ERROR_EXPECTED)
    for i, path in enumerate(edits):
        parent = fixture["atx"]
        for step in path[:-1]:
            parent = parent[step]
        parent[path[-1]] = f"@@MEMBER{i}@@"
    text = json.dumps(fixture)
    for i, literal in enumerate(edits.values()):
        text = text.replace(f'"@@MEMBER{i}@@"', literal)
    out = directory / name
    out.write_text(text)
    return out


def _with_verdict(baseline: Path, edits: dict) -> verify.VerifyResult:
    with tempfile.TemporaryDirectory() as tmp:
        written = _write_with(Path(tmp), "members.json", baseline, edits)
        return verify.verify_fixture(verify.load_fixture(written))


def _exact_range_reason(where: str, literal: str) -> str:
    return f"no signature covers {where}: the integer {literal} is outside the I-JSON exact range, -(2^53-1) to 2^53-1"


CRITICAL = ("scanSummary", "criticalFindings")
HIGH = ("scanSummary", "highFindings")
OBSERVATION_DAYS = ("behavioralProfile", "observationDays")
TRUST_LEVEL = ("trustLevel",)
PURPOSE = ("declaredPurpose",)
INTEGER_OUTSIDE_EXACT_RANGE = ROOT / "fixtures" / "v1_1-integer-outside-exact-range.json"

# Integers of the v1.1 signed payload outside the I-JSON exact range, written
# on the v1.1 baseline, and the member and integer the Go reference verifier's
# reason names for each: with several, the first in the order JCS writes the
# members, and in declaredPurpose the first integer written.
GO_INTEGER_OUTSIDE_EXACT_RANGE = (
    ({CRITICAL: "9007199254740992"}, "scanSummary.criticalFindings", "9007199254740992"),
    ({CRITICAL: "9007199254740993"}, "scanSummary.criticalFindings", "9007199254740993"),
    ({CRITICAL: "-9007199254740992"}, "scanSummary.criticalFindings", "-9007199254740992"),
    ({CRITICAL: "9223372036854775807"}, "scanSummary.criticalFindings", "9223372036854775807"),
    ({HIGH: "9007199254740992"}, "scanSummary.highFindings", "9007199254740992"),
    ({OBSERVATION_DAYS: "9007199254740992"}, "behavioralProfile.observationDays", "9007199254740992"),
    ({TRUST_LEVEL: "9007199254740993"}, "trustLevel", "9007199254740993"),
    ({TRUST_LEVEL: "-9007199254740993"}, "trustLevel", "-9007199254740993"),
    ({PURPOSE: "9007199254740993"}, "declaredPurpose", "9007199254740993"),
    ({PURPOSE: '{"limits": {"refund": 18014398509481985}}'}, "declaredPurpose", "18014398509481985"),
    ({PURPOSE: '[1.5, "18014398509481985", 1e21, 9007199254740993, -9007199254740993]'}, "declaredPurpose", "9007199254740993"),
    ({PURPOSE: "[100000000000000000000]"}, "declaredPurpose", "100000000000000000000"),
    ({OBSERVATION_DAYS: "9007199254740992", TRUST_LEVEL: "9007199254740993"}, "behavioralProfile.observationDays", "9007199254740992"),
    ({CRITICAL: "9007199254740993", PURPOSE: '{"a": -9007199254740992}'}, "declaredPurpose", "-9007199254740992"),
    ({CRITICAL: "9007199254740994", HIGH: "9007199254740993"}, "scanSummary.criticalFindings", "9007199254740994"),
    ({HIGH: "9007199254740995", TRUST_LEVEL: "9007199254740992"}, "scanSummary.highFindings", "9007199254740995"),
)


class GoIntegerOutsideExactRange(unittest.TestCase):
    """An integer of the v1.1 signed payload whose magnitude is above
    2**53 - 1, outside the I-JSON exact range (RFC 7493 section 2.2). The Go
    reference verifier's JCS library writes 9007199254740993 as
    9007199254740992, so it accepted a credential signed over those bytes
    (fixtures/v1_1-integer-outside-exact-range.json) that this verifier,
    writing the count's digits, rejected for a signature that did not
    verify. Both now refuse each such integer as SIGNATURE_INVALID with one
    reason. atx-conformance#278."""

    def test_integer_outside_the_range_is_refused_with_the_go_reason(self):
        for edits, where, literal in GO_INTEGER_OUTSIDE_EXACT_RANGE:
            with self.subTest(edits=edits):
                got = _with_verdict(BASELINE_V11, edits)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)
                self.assertEqual(got.reason, _exact_range_reason(where, literal))

    def test_inside_the_range_or_not_an_integer_is_not_refused(self):
        # The baseline signs none of these, so the signature itself fails.
        for edits in (
            {CRITICAL: "9007199254740991"},
            {CRITICAL: "-9007199254740991"},
            {TRUST_LEVEL: "9007199254740991"},
            {PURPOSE: "1e21"},
            {PURPOSE: "9007199254740993.0"},
        ):
            with self.subTest(edits=edits):
                got = _with_verdict(BASELINE_V11, edits)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)
                self.assertNotIn("I-JSON", got.reason)
        fixture = json.loads(BASELINE_V11.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            for count in (2**53 - 1, -(2**53 - 1)):
                with self.subTest(signed=count):
                    fixture["atx"]["scanSummary"]["criticalFindings"] = count
                    signed = _write_signed_v11(Path(tmp), "signed.json", fixture)
                    got = verify.verify_fixture(verify.load_fixture(signed))
                    self.assertTrue(got.accepted, got.reason)

    def test_shipped_fixture_is_signed_over_the_bytes_go_writes(self):
        # Its signature verifies over JCS(TBS) with criticalFindings
        # 9007199254740992, the bytes the Go verifier writes for the
        # 9007199254740993 it carries, so a verifier without the refusal
        # accepts it.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        fixture = verify.load_fixture(INTEGER_OUTSIDE_EXACT_RANGE)
        credential = verify._decode_credential(fixture["atx"])
        self.assertEqual(credential["scanSummary"]["criticalFindings"], 2**53 + 1)
        credential["scanSummary"] = dict(credential["scanSummary"], criticalFindings=0)
        zero = verify.canonical_payload_v11(credential)
        self.assertEqual(zero.count(b'"criticalFindings":0,'), 1)
        payload = zero.replace(b'"criticalFindings":0,', b'"criticalFindings":9007199254740992,')
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(fixture["verifierState"]["publicKeys"][0]["publicKeyHex"]))
        (signature,) = fixture["atx"]["signatures"]
        key.verify(base64.b64decode(signature["value"]), payload)

        got = verify.verify_fixture(fixture)
        self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)
        self.assertEqual(got.reason, _exact_range_reason("scanSummary.criticalFindings", "9007199254740993"))
        got = _at_verdict(INTEGER_OUTSIDE_EXACT_RANGE, CRITICAL, "9007199254740992")
        self.assertEqual(got.reason, _exact_range_reason("scanSummary.criticalFindings", "9007199254740992"))

    def test_checks_that_run_first_keep_their_verdicts(self):
        for edits, category, held in (
            ({PURPOSE: "[1e400, 9007199254740993]"}, "VERIFIER_CONFIG_ERROR", "v1.1 canonicalization failed"),
            ({CRITICAL: "9007199254740993", PURPOSE: '"\\ud800"'}, "VERIFIER_CONFIG_ERROR", "unpaired UTF-16 surrogate"),
            ({CRITICAL: "9007199254740993", ("scanSummary", "hma"): "7"}, "SIGNATURE_INVALID", "member outside its type"),
        ):
            with self.subTest(edits=edits):
                got = _with_verdict(BASELINE_V11, edits)
                self.assertEqual(got.reject_category, category, got.reason)
                self.assertIn(held, got.reason)

    def test_v1_0_trust_level_is_not_refused(self):
        # The pipe form writes trustLevel as its digits; the v1.0 baseline
        # signs trustLevel 4, so the signature itself fails.
        got = _with_verdict(BASELINE_V10, {TRUST_LEVEL: "9007199254740993"})
        self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)
        self.assertNotIn("I-JSON", got.reason)

    def test_directory_run_reaches_the_summary_line(self):
        n = len(GO_INTEGER_OUTSIDE_EXACT_RANGE)
        expected = {"verifyResult": "REJECT", "rejectCategory": "SIGNATURE_INVALID", "reasonContains": "signature"}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for i, (edits, _where, _literal) in enumerate(GO_INTEGER_OUTSIDE_EXACT_RANGE):
                _write_with(directory, f"{i:02d}.json", BASELINE_V11, edits, expected=expected)
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 0, text + err)
        self.assertEqual(text.splitlines()[-1], f"summary: {n} pass, 0 fail ({n} fixtures)")


def _write_signed_purpose(directory: Path, name: str, written: str, signed: bytes) -> Path:
    """Write the v1.1 baseline with declaredPurpose written as the raw JSON
    text written, under one Ed25519 signature made with the primary issuer's
    key (the RFC 8032 test vector in vectors/issuer-primary.json) over its
    JCS(TBS) with signed, canonical JSON bytes, as declaredPurpose, and
    return its path. This verifier's serializer writes neither 1.5 nor
    9007199254740992, so the TBS is canonicalized with a string in
    declaredPurpose's place, which JCS orders by the member's name alone,
    and signed is put where that string was."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = json.loads((ROOT / "vectors" / "issuer-primary.json").read_text())
    fixture = json.loads(BASELINE_V11.read_text())
    fixture["atx"]["declaredPurpose"] = "@@PURPOSE@@"
    path = directory / name
    path.write_text(json.dumps(fixture))
    tbs = verify.canonical_payload_v11(verify._decode_credential(verify.load_fixture(path)["atx"]))
    placeholder = b'"declaredPurpose":"@@PURPOSE@@"'
    if tbs.count(placeholder) != 1:
        raise ValueError(f"JCS(TBS) holds {placeholder!r} {tbs.count(placeholder)} times, not once")
    payload = tbs.replace(placeholder, b'"declaredPurpose":' + signed)
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["seedHex"]))
    fixture["atx"]["signatures"] = [{
        "keyId": key["keyId"],
        "algorithm": "Ed25519",
        "value": base64.b64encode(signer.sign(payload)).decode("ascii"),
    }]
    path.write_text(json.dumps(fixture).replace('"@@PURPOSE@@"', written, 1))
    return path


# The reason both reference verifiers write when no configured key verifies
# the Ed25519 signature of the v1.1 baseline.
ED25519_NOT_VERIFIED = (
    "Ed25519 signature did:opena2a:authority:opena2a.org#key-1 "
    "did not verify against any configured public key"
)

# The two tables below were recorded from `go run .` in ../go, built with
# Go 1.26.3, on the files _write_signed_purpose writes.
#
# A declaredPurpose number written with a fraction or an exponent part, and
# the bytes the Go reference verifier's JCS library writes for it, which the
# signature covers: 1000.0, 1e3 and 1E3 as 1000, and 9007199254740993.0 and
# 9.007199254740993e15 as 9007199254740992. The Go verifier accepted each
# under that signature before atx-conformance#283, and this verifier, whose
# serializer writes no such number, rejected each. Both now reject each as
# SIGNATURE_INVALID, with ED25519_NOT_VERIFIED.
GO_PURPOSE_NUMBER_SPELLINGS = (
    ('{"n": 1000.0}', b'{"n":1000}'),
    ('{"n": 1e3}', b'{"n":1000}'),
    ('{"n": 1E3}', b'{"n":1000}'),
    ('{"n": 1e+3}', b'{"n":1000}'),
    ('{"n": 10000e-1}', b'{"n":1000}'),
    ('{"n": 9007199254740993.0}', b'{"n":9007199254740992}'),
    ('{"n": 9.007199254740993e15}', b'{"n":9007199254740992}'),
    ('{"n": 1.5}', b'{"n":1.5}'),
    ('{"n": -0.0}', b'{"n":0}'),
    ("[1000.0]", b"[1000]"),
    ("1e3", b"1000"),
    ('{"limits": {"refund": [1, 2.5e1]}}', b'{"limits":{"refund":[1,25]}}'),
)

# declaredPurpose written as the bytes the signature covers: integers in the
# I-JSON exact range, and a fraction and an exponent inside a member name and
# a string. The Go reference verifier accepts each, as this verifier does.
GO_PURPOSE_SIGNED_AS_WRITTEN = (
    ('{"n": 1000}', b'{"n":1000}'),
    ('{"n": 0}', b'{"n":0}'),
    ("[1000]", b"[1000]"),
    ("1000", b"1000"),
    ('{"1.5": "2e3", "n": [1, -7]}', b'{"1.5":"2e3","n":[1,-7]}'),
)


class GoPurposeNumberSpellings(unittest.TestCase):
    """A declaredPurpose number written with a fraction or an exponent part,
    under a signature over the bytes the Go reference verifier's JCS library
    writes for it. That library writes such a number as the double nearest
    it, so the Go verifier accepted a credential signed over 1000 that
    carried 1e3, while this verifier's serializer writes no such number and
    rejected it. Neither verifies a signature over such a number now, so
    both reject it with one reason. atx-conformance#283."""

    def _verdict(self, written: str, signed: bytes) -> verify.VerifyResult:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_signed_purpose(Path(tmp), "purpose.json", written, signed)
            return verify.verify_fixture(verify.load_fixture(path))

    def test_number_with_a_fraction_or_exponent_rejects_with_the_go_reason(self):
        for written, signed in GO_PURPOSE_NUMBER_SPELLINGS:
            with self.subTest(written=written):
                got = self._verdict(written, signed)
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)
                self.assertEqual(got.reason, ED25519_NOT_VERIFIED)

    def test_written_as_signed_is_accepted(self):
        # The signature _write_signed_purpose makes verifies wherever
        # declaredPurpose is written as the bytes it covers.
        for written, signed in GO_PURPOSE_SIGNED_AS_WRITTEN:
            with self.subTest(written=written):
                got = self._verdict(written, signed)
                self.assertTrue(got.accepted, got.reason)

    def test_integer_outside_the_exact_range_keeps_its_reason(self):
        got = self._verdict('{"n": 9007199254740993}', b'{"n":9007199254740992}')
        self.assertEqual(got.reject_category, "SIGNATURE_INVALID", got.reason)
        self.assertEqual(got.reason, _exact_range_reason("declaredPurpose", "9007199254740993"))

    def test_v1_0_declared_purpose_is_not_signed(self):
        # The legacy form signs no declaredPurpose, so a number in it leaves
        # the v1.0 baseline accepted, as it does in the Go reference verifier.
        got = _at_verdict(BASELINE_V10, PURPOSE, '{"n": 1e3}')
        self.assertTrue(got.accepted, got.reason)


class GoNonObjectCredential(unittest.TestCase):
    def test_credential_reaches_the_go_verdict(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for literal, outcome in GO_CREDENTIAL_VERDICTS:
                with self.subTest(baseline=baseline.name, atx=literal), tempfile.TemporaryDirectory() as tmp:
                    path = _write_wrapper(Path(tmp), "atx.json", baseline, "atx", literal)
                    got = verify.verify_fixture(verify.load_fixture(path))
                    self.assertEqual(_outcome(got), outcome, got.reason)
                    if outcome == "PARSE_ERROR":
                        self.assertTrue(got.reason.startswith("credential "), got.reason)


class GoSubSecondExpiry(unittest.TestCase):
    def test_expiry_compares_the_fraction_of_a_second(self):
        for baseline in (BASELINE_V10, BASELINE_V11):
            for clock, outcome in GO_SUBSECOND_EXPIRY_VERDICTS:
                with self.subTest(baseline=baseline.name, clock=clock):
                    fixture = json.loads(baseline.read_text())
                    fixture["atx"]["expiresAt"] = "2099-12-31T23:59:59.5Z"
                    fixture["verifierState"]["clockRfc3339"] = clock
                    got = verify.verify_fixture(fixture)
                    self.assertEqual(_outcome(got), outcome, got.reason)


class ExpectedMember(unittest.TestCase):
    def test_expected_outside_its_go_type_is_a_load_error(self):
        for literal, message in GO_UNLOADABLE_EXPECTED:
            with self.subTest(expected=literal), tempfile.TemporaryDirectory() as tmp:
                path = _write_wrapper(Path(tmp), "e.json", BASELINE_V11, "expected", literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(path))
                self.assertEqual(str(raised.exception), message)

    def test_absent_or_null_expected_or_verify_result_is_a_load_error(self):
        # The fixture format requires expected.verifyResult. Go leaves an
        # absent or null one at "", which read as "expect REJECT", so a JSON
        # object that is not a fixture rejected at parse and passed. Both
        # verifiers now refuse to load it, with the same reason.
        for fixture, message in (
            ({}, "no expected member"),
            ({"expected": None}, "no expected member"),
            ({"expected": {}}, "no expected.verifyResult"),
            ({"expected": {"verifyResult": None}}, "no expected.verifyResult"),
        ):
            with self.subTest(fixture=fixture):
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(fixture)
                self.assertEqual(str(raised.exception), message)

    def test_unknown_verify_result_is_a_load_error(self):
        # The fixture format allows ACCEPT and REJECT, in that case. Any
        # other string, "" included, fails to load where it read as "expect
        # REJECT", and "accept" as ACCEPT. The reason quotes the value as Go's
        # %q does.
        cases = (
            ("a-maybe.json", "MAYBE", 'expected.verifyResult "MAYBE" is not ACCEPT or REJECT'),
            ("b-lower-case.json", "accept", 'expected.verifyResult "accept" is not ACCEPT or REJECT'),
            ("c-empty-string.json", "", 'expected.verifyResult "" is not ACCEPT or REJECT'),
        )
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name, word, _ in cases:
                literal = json.dumps({"verifyResult": word})
                _write_wrapper(directory, name, BASELINE_V10, "expected", literal)
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 1, text + err)
        want = "".join(f"FAIL  {directory / name}  (load error: {message})\n" for name, _, message in cases)
        self.assertEqual(text, want + f"\nsummary: 0 pass, {len(cases)} fail ({len(cases)} fixtures)\n")

    def test_directory_run_reaches_the_summary_line(self):
        # Each of the first two used to end the run with an AttributeError
        # traceback.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_wrapper(directory, "a-number.json", BASELINE_V11, "expected", "7")
            _write_wrapper(directory, "b-null.json", BASELINE_V11, "expected", "null")
            _write_wrapper(directory, "c-member.json", BASELINE_V11, "expected", '{"verifyResult": 7}')
            (directory / "d-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 1, text + err)
        self.assertIn("a-number.json  (load error: expected 7 is not a JSON object)", text)
        self.assertIn("c-member.json  (load error: expected.verifyResult 7 is not", text)
        # b-null.json expects nothing, so it is not a fixture and fails to
        # load, where its credential verified and the mismatch got a report
        # block of its own.
        self.assertIn("b-null.json  (load error: no expected member)\n", text)
        self.assertNotIn("expected: \n", text)
        self.assertEqual(text.splitlines()[-1], "summary: 1 pass, 3 fail (4 fixtures)")


class UnencodableReportLine(unittest.TestCase):
    def test_unpaired_surrogate_in_a_reason_does_not_end_the_run(self):
        # The issuer DID is quoted in the reason. It used to reach a UTF-8
        # standard output as an unpaired surrogate and raise there.
        untrusted = {"verifyResult": "REJECT", "rejectCategory": "UNTRUSTED_ISSUER"}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_at(
                directory, "a-issuer.json", BASELINE_V11, ("issuerDid",), '"did:x:\\ud800"',
                expected=untrusted,
            )
            (directory / "b-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text = _run_main_utf8(str(directory))
        self.assertEqual(code, 0, text)
        self.assertIn("issuer DID did:x:\ufffd is not in the verifier's trusted set", text)
        self.assertEqual(text.splitlines()[-1], "summary: 2 pass, 0 fail (2 fixtures)")

    def test_line_standard_output_cannot_encode_is_escaped(self):
        # Whatever puts such a character in a report line, the line is
        # written with it escaped and the run goes on.
        real = verify.verify_fixture

        def surrogate_in_reason(fixture):
            if fixture.get("name") == "surrogate":
                return verify.VerifyResult(reject_category="PARSE_ERROR", reason="bad \ud800 name")
            return real(fixture)

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture = json.loads(BASELINE_V11.read_text())
            fixture["name"] = "surrogate"
            fixture["expected"] = dict(PARSE_ERROR_EXPECTED)
            (directory / "a-surrogate.json").write_text(json.dumps(fixture))
            (directory / "b-baseline-valid.json").write_text(BASELINE_V11.read_text())
            with mock.patch.object(verify, "verify_fixture", surrogate_in_reason):
                code, text = _run_main_utf8(str(directory))
        self.assertEqual(code, 0, text)
        self.assertIn("observed: REJECT[PARSE_ERROR: bad \\ud800 name]", text)
        self.assertEqual(text.splitlines()[-1], "summary: 2 pass, 0 fail (2 fixtures)")


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
        # to load a file carrying one as a file that is not JSON, and so must
        # this verifier, with the same reason.
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as tmp:
                path = _write_member(Path(tmp), "c.json", BASELINE_V11, "declaredPurpose", literal)
                with self.assertRaises(ValueError) as raised:
                    verify.load_fixture(path)
                self.assertEqual(str(raised.exception), "fixture is not valid JSON")

    def test_directory_run_reports_a_load_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_member(directory, "a-nan.json", BASELINE_V11, "declaredPurpose", "NaN")
            (directory / "b-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text, _ = _run_main(str(directory))
        self.assertEqual(code, 1, text)
        self.assertIn("a-nan.json  (load error: fixture is not valid JSON)\n", text)
        self.assertEqual(text.splitlines()[-1], "summary: 1 pass, 1 fail (2 fixtures)")


class MissingPath(unittest.TestCase):
    def test_missing_path_exits_2_with_one_error_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "does-not-exist")
            code, out, err = _run_main(missing)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, f"error: {missing}: no such file or directory\n")


class RepeatedPath(unittest.TestCase):
    def test_a_path_named_twice_is_verified_twice(self):
        path = str(BASELINE_V10)
        code, out, err = _run_main(path, path)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            [line for line in out.splitlines() if line.startswith(("PASS", "FAIL"))],
            [f"PASS  {path}", f"PASS  {path}"])
        self.assertIn("summary: 2 pass, 0 fail (2 fixtures)", out)


class PathSpelling(unittest.TestCase):
    """A fixture is named in the report as the Go reference verifier names
    it, however its argument is spelled. This verifier made each argument a
    Path, which drops ./ and a trailing / and collapses //, and wrote
    `PASS  d/x.json` for ./d//x.json, where the Go verifier writes
    `PASS  ./d//x.json`."""

    def _report(self, *args: str) -> tuple[int, list[str], str]:
        """(exit code, PASS and FAIL lines, stderr) of a run on args, each
        with {cwd} replaced by the working directory, from a directory
        holding the fixture as d/x.json and {} as e/bad.json."""
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            os.mkdir("d")
            os.mkdir("e")
            Path("d", "x.json").write_bytes(BASELINE_V10.read_bytes())
            Path("e", "bad.json").write_text("{}\n", encoding="utf-8")
            code, out, err = _run_main(*(arg.replace("{cwd}", os.getcwd()) for arg in args))
        lines = [line for line in out.splitlines() if line.startswith(("PASS", "FAIL"))]
        return code, lines, err

    def test_a_file_is_named_as_its_argument_spells_it(self):
        # In the Go verifier's order, byte by byte.
        self.assertEqual(self._report("d//x.json", "./d/x.json", "d/./x.json"), (
            0, ["PASS  ./d/x.json", "PASS  d/./x.json", "PASS  d//x.json"], ""))

    def test_a_load_error_names_the_file_as_its_argument_spells_it(self):
        self.assertEqual(self._report("./e//bad.json"), (
            1, ["FAIL  ./e//bad.json  (load error: no expected member)"], ""))

    def test_a_directory_names_its_files_as_go_joins_them(self):
        for arg in ("d/../d", "./d/", "d//"):
            with self.subTest(arg=arg):
                self.assertEqual(self._report(arg), (0, ["PASS  d/x.json"], ""))

    def test_an_absolute_path_under_the_working_directory_is_named_relative_to_it(self):
        self.assertEqual(self._report("{cwd}/d/../d//x.json"), (0, ["PASS  d/x.json"], ""))

    def test_a_file_named_with_a_trailing_slash_is_refused(self):
        self.assertEqual(self._report("d/x.json/"), (
            2, [], "error: stat d/x.json/: not a directory\n"))


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

    def test_integer_outside_the_exact_range_is_refused(self):
        # The Go and TypeScript legs write 9007199254740993 as
        # 9007199254740992 and 10**21 as 1e+21; this serializer wrote their
        # digits. It writes each integer in the I-JSON exact range, -(2**53 -
        # 1) to 2**53 - 1, as its digits and refuses every other one, naming
        # it, or its size where it has more digits than str() converts.
        # atx-conformance#278.
        for path in SERIALIZERS:
            serializer = _load_serializer(path)
            for n in (2**53 - 1, -(2**53 - 1), 0, -1):
                with self.subTest(serializer=str(path.relative_to(ROOT)), n=n):
                    self.assertEqual(serializer.canonicalize({"n": n}), b'{"n":%d}' % n)
            for n, named in (
                (2**53, "Got integer 9007199254740992."),
                (2**53 + 1, "Got integer 9007199254740993."),
                (-(2**53), "Got integer -9007199254740992."),
                (2**60, "Got integer 1152921504606846976."),
                (10**21, "Got integer 1000000000000000000000."),
                (10**5000, "Got an integer of 16610 bits."),
            ):
                with self.subTest(serializer=str(path.relative_to(ROOT)), bits=n.bit_length(), negative=n < 0):
                    with self.assertRaises(NotImplementedError) as raised:
                        serializer.canonicalize({"declaredPurpose": [1, {"n": n}]})
                    self.assertIn(named, str(raised.exception))
                    self.assertIn("I-JSON exact range", str(raised.exception))


class SerializerNesting(unittest.TestCase):
    def test_nesting_past_the_recursion_limit_serializes(self):
        # Go's JCS library canonicalizes a declaredPurpose of any depth its
        # decoder accepts, up to 10000 levels. The serializer this one
        # replaced recursed through two frames per level (_serialize and its
        # generator expression) and, at the default recursion limit of 1000,
        # raised RecursionError from 497 nested arrays or objects in a
        # declaredPurpose (from 331 on Python 3.11).
        n = 3 * sys.getrecursionlimit()
        arrays: list = []
        objects: dict = {}
        for _ in range(n):
            arrays = [arrays]
            objects = {"a": objects}
        for path in SERIALIZERS:
            with self.subTest(serializer=str(path.relative_to(ROOT))):
                serializer = _load_serializer(path)
                self.assertEqual(serializer.canonicalize(arrays), b"[" * (n + 1) + b"]" * (n + 1))
                self.assertEqual(serializer.canonicalize(objects), b'{"a":' * n + b"{}" + b"}" * n)

    def test_order_and_separators(self):
        value = {"b": [1, [], {}, "x", None, True, False], "a": {"d": [[2], 3], "c": "é"}, "": -4}
        want = '{"":-4,"a":{"c":"é","d":[[2],3]},"b":[1,[],{},"x",null,true,false]}'.encode("utf-8")
        for path in SERIALIZERS:
            with self.subTest(serializer=str(path.relative_to(ROOT))):
                self.assertEqual(_load_serializer(path).canonicalize(value), want)

    def test_first_number_in_canonical_order_is_refused(self):
        # Members serialize in sorted order, so "a" comes before "b".
        for path in SERIALIZERS:
            with self.subTest(serializer=str(path.relative_to(ROOT))):
                with self.assertRaises(NotImplementedError) as raised:
                    _load_serializer(path).canonicalize({"b": 0.25, "a": [1, 0.5]})
                self.assertIn("Got float 0.5.", str(raised.exception))


class Imports(unittest.TestCase):
    def test_verify_uses_every_name_it_imports(self):
        # verify.py imported `os` and dataclasses.field and used neither.
        tree = ast.parse(Path(verify.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imported.update((alias.asname or alias.name).split(".")[0]
                                for alias in node.names)
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertEqual(sorted(imported - used), [])


class FixtureWrapper(unittest.TestCase):
    def test_wrapper_outside_its_go_type_is_a_load_error(self):
        for path, literal, member in GO_UNLOADABLE_WRAPPERS:
            with self.subTest(path=path, value=literal), tempfile.TemporaryDirectory() as tmp:
                written = _write_fixture_at(Path(tmp), "w.json", BASELINE_CRL, path, literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(written))
                self.assertTrue(str(raised.exception).startswith(member + " "), raised.exception)

    def test_wrapper_member_reaches_the_go_verdict(self):
        for baseline, path, literal, rename, outcome in GO_WRAPPER_VERDICTS:
            with self.subTest(baseline=baseline.name, path=path, value=literal, name=rename):
                got = _fixture_verdict(baseline, path, literal, rename)
                self.assertEqual(_outcome(got), outcome, got.reason)

    def test_repeated_expected_name_is_a_load_error(self):
        # This verifier read the last of the names that fold together, and Go
        # decoded each into the one field.
        for literal, member in GO_REPEATED_EXPECTED_NAMES:
            with self.subTest(expected=literal), tempfile.TemporaryDirectory() as tmp:
                path = _write_wrapper(Path(tmp), "e.json", BASELINE_V11, "expected", literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(path))
                self.assertEqual(str(raised.exception), f'the fixture repeats the member "{member}"')

    def test_repeat_outside_its_go_type_is_a_load_error(self):
        # Each of these files loaded while only the second value was
        # decoded, then failed to load for the first value's type; it fails
        # for the repeat now, before any member is decoded.
        for path, first_name, literal, member in GO_UNLOADABLE_REPEATS:
            with self.subTest(path=path, name=first_name, value=literal[:40]), \
                    tempfile.TemporaryDirectory() as tmp:
                written = _write_repeated(Path(tmp), "r.json", BASELINE_CRL, path, first_name, literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(written))
                self.assertEqual(str(raised.exception), f'the fixture repeats the member "{member}"')

    def test_repeat_inside_its_go_type_is_a_load_error(self):
        for baseline, path, first_name, literal, member in GO_REPEATS_INSIDE_THEIR_TYPE:
            with self.subTest(baseline=baseline.name, path=path, name=first_name, value=literal), \
                    tempfile.TemporaryDirectory() as tmp:
                written = _write_repeated(Path(tmp), "r.json", baseline, path, first_name, literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(written))
                self.assertEqual(str(raised.exception), f'the fixture repeats the member "{member}"')

    def test_null_fixture_is_the_zero_value_with_no_expected_member(self):
        # Go decodes a fixture file holding null into its zero value, which
        # has no credential and no expected member, so the file fails to load.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "null.json"
            path.write_text("null")
            fixture = verify.load_fixture(path)
            with self.assertRaises(ValueError) as raised:
                verify._expected_outcome(fixture)
            self.assertEqual(str(raised.exception), "no expected member")
            got = verify.verify_fixture(fixture)
        self.assertEqual(got.reject_category, "PARSE_ERROR", got.reason)

    def test_directory_run_reaches_the_summary_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_fixture_at(directory, "a-name.json", BASELINE_V11, ("name",), '{"a": 1}')
            _write_fixture_at(
                directory, "b-trusted.json", BASELINE_V11,
                ("verifierState", "trustedIssuers"), KEEP, "TrustedIssuers",
            )
            (directory / "c-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 1, text + err)
        self.assertIn("a-name.json  (load error: name {'a': 1} is not a JSON string)", text)
        self.assertEqual(text.count("observed: ACCEPT"), 2, text)
        self.assertEqual(text.splitlines()[-1], "summary: 2 pass, 1 fail (3 fixtures)")


class RepeatedFixtureMember(unittest.TestCase):
    """A fixture file that writes a member more than once outside its atx
    member's subtree, under one name or under two that fold together, is not
    a fixture: it fails to load, the load error naming the member as written
    the second time, as it fails to load in the Go reference verifier. Go's
    encoding/json decodes each repeat into the one field, so a member a later
    object omits keeps the earlier object's value, where this verifier read
    the later object alone: on fixtures/wrong-issuer.json with an expected of
    REJECT [SIGNATURE_INVALID] followed by an expected of REJECT, the Go
    verifier wrote FAIL and this one PASS. A repeat inside the credential is
    still a verdict, PARSE_ERROR."""

    def _write_repeats(self, directory: Path) -> list[tuple[Path, str]]:
        """Write the fixtures that repeat a member, each with the member its
        load error names."""
        v11 = json.loads(BASELINE_V11.read_text())
        state, atx = json.dumps(v11["verifierState"]), json.dumps(v11["atx"])
        clock = json.dumps({"clockRfc3339": v11["verifierState"]["clockRfc3339"]})
        category = '{"verifyResult": "REJECT", "rejectCategory": "SIGNATURE_INVALID"}'
        reason = '{"verifyResult": "REJECT", "reasonContains": "zz-not-in-reason"}'
        later = '{"verifyResult": "REJECT"}'
        return [
            (_write_wrapper(directory, "a-expected-twice.json", WRONG_ISSUER, "expected",
                            f'{category}, "expected": {later}'), "expected"),
            (_write_wrapper(directory, "b-expected-case-variant.json", WRONG_ISSUER, "expected",
                            f'{category}, "EXPECTED": {later}'), "EXPECTED"),
            (_write_wrapper(directory, "c-expected-omits-a-member.json", WRONG_ISSUER, "expected",
                            f'{reason}, "EXPECTED": {later}'), "EXPECTED"),
            (_write_wrapper(directory, "d-verifier-state-twice.json", BASELINE_V11, "verifierState",
                            f'{state}, "verifierState": {clock}'), "verifierState"),
            (_write_wrapper(directory, "e-verify-result-twice.json", BASELINE_V11, "expected",
                            '{"verifyResult": "ACCEPT", "verifyResult": "ACCEPT"}'), "verifyResult"),
            (_write_wrapper(directory, "f-atx-twice.json", BASELINE_V11, "atx",
                            f'{atx}, "ATX": {atx}'), "ATX"),
            (_write_wrapper(directory, "g-undeclared-member.json", BASELINE_V11, "notes",
                            '{"by": "a", "BY": "b"}'), "BY"),
            (_write_repeated(directory, "h-clock-twice.json", BASELINE_V11,
                             ("verifierState", "clockRfc3339"), None, '"2100-01-01T00:00:00Z"'),
             "clockRfc3339"),
            (_write_repeated(directory, "i-crl-entry-case-variant.json", BASELINE_CRL,
                             ("verifierState", "crl", "entries", 0, "agentId"), "AgentId", '"x"'),
             "agentId"),
        ]

    def test_repeat_outside_the_credential_is_a_load_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            cases = self._write_repeats(directory)
            code, text, err = _run_main(str(directory))
        self.assertEqual(code, 1, text + err)
        want = "".join(
            f'FAIL  {path}  (load error: the fixture repeats the member "{member}")\n' for path, member in cases
        )
        self.assertEqual(text, want + f"\nsummary: 0 pass, {len(cases)} fail ({len(cases)} fixtures)\n")

    def test_load_fixture_alone_refuses_a_repeat_of_or_in_the_verifier_state(self):
        # verify_fixture(load_fixture(path)) never calls _expected_outcome, so
        # the refusal must be load_fixture's own; past it, this verifier would
        # read the later verifierState alone, with no CRL or
        # requiredSignatures that copy omits.
        with tempfile.TemporaryDirectory() as tmp:
            written = {path.name: (path, member) for path, member in self._write_repeats(Path(tmp))}
            for name in ("d-verifier-state-twice.json", "h-clock-twice.json"):
                path, member = written[name]
                with self.subTest(fixture=name):
                    with self.assertRaises(ValueError) as raised:
                        verify.load_fixture(path)
                    self.assertEqual(str(raised.exception), f'the fixture repeats the member "{member}"')

    def test_repeat_inside_the_credential_is_still_a_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            atx = json.dumps(json.loads(BASELINE_V11.read_text())["atx"])
            twice = '{"revoked": false, "revoked": false, ' + atx[1:]
            written = _write_wrapper(Path(tmp), "credential-twice.json", BASELINE_V11, "atx", twice)
            for path, status in ((written, "FAIL"), *((p, "PASS") for p in DUPLICATE_CREDENTIALS)):
                with self.subTest(fixture=path.name):
                    code, text, err = _run_main(str(path))
                    self.assertEqual(code, 1 if status == "FAIL" else 0, text + err)
                    self.assertEqual(
                        _verdict_lines(text),
                        [f"{status}  {verify._rel_path(str(path))}", "observed: REJECT[PARSE_ERROR]"],
                    )
                    self.assertIn("credential contains duplicate member", text)


def _threshold_observed(required: int, distinct: int) -> str:
    """The result the Go reference verifier writes when the declared Ed25519
    signatures verify under `distinct` keys, fewer than `required`."""
    return (
        "REJECT[SIGNATURE_INVALID: signature threshold not met: requiredSignatures is "
        f"{required}, distinct Ed25519 keys that verified a declared signature: {distinct}]"
    )


def _threshold_verdict(baseline: Path, required, signatures=None, edit=None) -> verify.VerifyResult:
    """The verdict on `baseline` with its verifier state's requiredSignatures
    set to `required` (None writes null; KEEP leaves the member as the
    baseline has it), its credential carrying, with `signatures`, the
    signatures at those indexes of the ones it carries, in that order, and
    `edit` applied last to the fixture object."""
    fixture = json.loads(baseline.read_text())
    if required is not KEEP:
        fixture["verifierState"]["requiredSignatures"] = required
    if signatures is not None:
        carried = fixture["atx"]["signatures"]
        fixture["atx"]["signatures"] = [carried[i] for i in signatures]
    if edit is not None:
        edit(fixture)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "threshold.json"
        path.write_text(json.dumps(fixture))
        return verify.verify_fixture(verify.load_fixture(path))


# Each case cuts the credential of the 2-of-3 fixture, whose three signatures
# verify under the primary's and the two cosigners' keys, to the signatures at
# the given indexes, under a verifier state whose requiredSignatures is the
# value given (None: no threshold). The Go reference verifier's
# TestRequiredSignaturesThreshold runs the same cases. (required, signature
# indexes, the result the verifier writes).
THRESHOLD_CASES = (
    (None, (0,), "ACCEPT"),
    (1, (0,), "ACCEPT"),
    (2, (0,), _threshold_observed(2, 1)),
    (2, (2,), _threshold_observed(2, 1)),
    (2, (0, 0), _threshold_observed(2, 1)),
    (2, (0, 1), "ACCEPT"),
    (2, (1, 2), "ACCEPT"),
    (2, (0, 1, 2), "ACCEPT"),
    (3, (0, 2), _threshold_observed(3, 2)),
    (3, (0, 1, 2), "ACCEPT"),
)

# The three tables below were recorded from `go run .` in ../go, built with
# Go 1.26.3, on files _write_fixture_at and _write_repeated write with the
# member at REQUIRED_SIGNATURES.
REQUIRED_SIGNATURES = ("verifierState", "requiredSignatures")

# A requiredSignatures value outside the Go verifier's int field, written in
# place of the 1-of-3 fixture's: the file fails to load. (raw literal).
GO_UNLOADABLE_THRESHOLDS = (
    '"2"',
    "2.5",
    "2.0",
    "1e0",
    "true",
    "[2]",
    '{"k": 2}',
    "9223372036854775808",
    "-9223372036854775809",
)

# The result when requiredSignatures is renamed to another case (rename),
# holds the raw literal, or is absent (None). Go matches the member name in
# any case and leaves a null or absent member nil, which sets no threshold.
# (baseline, raw literal, rename, the result the Go verifier wrote).
GO_THRESHOLD_VERDICTS = (
    (THRESHOLD_1OF3, KEEP, "RequiredSignatures", _threshold_observed(2, 1)),
    (THRESHOLD_1OF3, KEEP, "REQUIREDSIGNATURES", _threshold_observed(2, 1)),
    (THRESHOLD_1OF3, "null", None, "ACCEPT"),
    (THRESHOLD_1OF3, None, None, "ACCEPT"),
    (THRESHOLD_1OF3, "0", None, "REJECT[VERIFIER_CONFIG_ERROR: bad requiredSignatures: 0 is not a positive integer]"),
    (THRESHOLD_1OF3, "-1", None, "REJECT[VERIFIER_CONFIG_ERROR: bad requiredSignatures: -1 is not a positive integer]"),
    (THRESHOLD_1OF3, "-0", None, "REJECT[VERIFIER_CONFIG_ERROR: bad requiredSignatures: 0 is not a positive integer]"),
    (
        THRESHOLD_1OF3,
        "-9223372036854775808",
        None,
        "REJECT[VERIFIER_CONFIG_ERROR: bad requiredSignatures: -9223372036854775808 is not a positive integer]",
    ),
    (THRESHOLD_1OF3, "1", None, "ACCEPT"),
    (THRESHOLD_1OF3, "3", None, _threshold_observed(3, 1)),
    (THRESHOLD_1OF3, "9223372036854775807", None, _threshold_observed(9223372036854775807, 1)),
    (THRESHOLD_2OF3, "1", None, "ACCEPT"),
    (THRESHOLD_2OF3, "2", None, "ACCEPT"),
    (THRESHOLD_2OF3, "3", None, "ACCEPT"),
    (THRESHOLD_2OF3, "4", None, _threshold_observed(4, 3)),
)

# The 1-of-3 fixture's requiredSignatures written twice: first under the name
# given (its own when None) holding the raw literal, then as the fixture
# writes it, 2. Go decoded both into the one field and kept the last, failing
# to load the file only when the first was outside the field's type; the file
# now fails to load for the repeat whatever the first holds, the load error
# naming requiredSignatures, as written the second time. (first name, raw
# literal).
GO_THRESHOLD_REPEATS = (
    (None, '"x"'),
    ("RequiredSignatures", "2.5"),
    (None, "null"),
    (None, "5"),
    ("RequiredSignatures", "0"),
)


class RequiredSignaturesThreshold(unittest.TestCase):
    """The k-of-n threshold of core.md section 3.1 step 8 (cosignatures from
    2 of 3 key holders), which the verifier state sets as requiredSignatures:
    the declared Ed25519 signatures must verify under at least that many
    distinct keys. A key counts once however many signatures verify under it,
    whatever keyId they carry, and an ML-DSA-65 signature does not count.
    atx-conformance#132."""

    def test_threshold_counts_the_keys_the_signatures_verify_under(self):
        for required, signatures, observed in THRESHOLD_CASES:
            with self.subTest(required=required, signatures=signatures):
                got = _threshold_verdict(THRESHOLD_2OF3, required, signatures)
                self.assertEqual(str(got), observed)
                if got.accepted:
                    self.assertEqual(got.sigs_valid, len(signatures))

    def test_shipped_fixture_rejects_and_a_threshold_blind_run_accepts(self):
        # The 1-of-3 fixture is the 2-of-3 credential cut to its first
        # signature: with its requiredSignatures dropped, which is what a
        # verifier that reads no threshold sees, it is accepted.
        fixture = verify.load_fixture(THRESHOLD_1OF3)
        self.assertEqual(fixture["verifierState"]["requiredSignatures"], 2)
        got = verify.verify_fixture(fixture)
        self.assertEqual(str(got), _threshold_observed(2, 1))
        self.assertEqual(verify._expected_outcome(fixture)["reasonContains"], "threshold")
        blind = _threshold_verdict(THRESHOLD_1OF3, KEEP, edit=lambda f: f["verifierState"].pop("requiredSignatures"))
        self.assertTrue(blind.accepted, blind.reason)

    def test_a_key_counts_once_whatever_key_id_it_is_listed_under(self):
        # The verifier state lists the primary's key a second time under
        # another keyId of the issuer, and the credential carries the
        # primary's signature twice, once under each keyId: both verify,
        # under one key.
        alias = "did:opena2a:authority:opena2a.org#key-1-alias"

        def aliased(fixture):
            keys = fixture["verifierState"]["publicKeys"]
            self.assertEqual(keys[0]["role"], "issuer-primary")
            keys.append(dict(keys[0], keyId=alias))
            signature = fixture["atx"]["signatures"][0]
            fixture["atx"]["signatures"] = [signature, dict(signature, keyId=alias)]

        got = _threshold_verdict(THRESHOLD_1OF3, KEEP, edit=aliased)
        self.assertEqual(str(got), _threshold_observed(2, 1))
        without = _threshold_verdict(THRESHOLD_1OF3, None, edit=aliased)
        self.assertTrue(without.accepted, without.reason)
        self.assertEqual(without.sigs_valid, 2)

    def test_an_ml_dsa_65_signature_does_not_count(self):
        # The hybrid baselines carry one Ed25519 and one ML-DSA-65 signature,
        # both by the primary, and both verify.
        for name in ("baseline-valid-hybrid.json", "v1_1-baseline-valid-hybrid.json"):
            with self.subTest(fixture=name):
                baseline = ROOT / "fixtures" / name
                got = _threshold_verdict(baseline, 1)
                self.assertTrue(got.accepted and got.ed25519_valid and got.mldsa65_valid, got.reason)
                self.assertEqual(str(_threshold_verdict(baseline, 2)), _threshold_observed(2, 1))

    def test_below_one_is_a_config_error_before_any_step(self):
        # Reported before any step reads the credential, as a bad clock is:
        # on the expired fixture it is reported in place of EXPIRED.
        for name in ("threshold-2of3-cosignature.json", "expired.json"):
            for required in (0, -1):
                with self.subTest(fixture=name, required=required):
                    got = _threshold_verdict(ROOT / "fixtures" / name, required)
                    self.assertEqual(
                        str(got),
                        f"REJECT[VERIFIER_CONFIG_ERROR: bad requiredSignatures: {required} is not a positive integer]",
                    )

    def test_member_outside_its_go_type_is_a_load_error(self):
        for literal in GO_UNLOADABLE_THRESHOLDS:
            with self.subTest(value=literal), tempfile.TemporaryDirectory() as tmp:
                written = _write_fixture_at(Path(tmp), "t.json", THRESHOLD_1OF3, REQUIRED_SIGNATURES, literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(written))
                self.assertTrue(
                    str(raised.exception).startswith("verifierState.requiredSignatures "), raised.exception
                )

    def test_member_reaches_the_go_verdict(self):
        for baseline, literal, rename, observed in GO_THRESHOLD_VERDICTS:
            with self.subTest(baseline=baseline.name, value=literal, name=rename):
                got = _fixture_verdict(baseline, REQUIRED_SIGNATURES, literal, rename)
                self.assertEqual(str(got), observed)

    def test_repeated_member_is_a_load_error(self):
        for first_name, literal in GO_THRESHOLD_REPEATS:
            with self.subTest(name=first_name, value=literal), tempfile.TemporaryDirectory() as tmp:
                written = _write_repeated(Path(tmp), "r.json", THRESHOLD_1OF3, REQUIRED_SIGNATURES, first_name, literal)
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(written))
                self.assertEqual(str(raised.exception), 'the fixture repeats the member "requiredSignatures"')

    def test_a_later_null_under_another_case_is_a_load_error(self):
        # Go kept the last of the names that fold together, here a null,
        # which left the field nil and set no threshold.
        with tempfile.TemporaryDirectory() as tmp:
            text = THRESHOLD_1OF3.read_text().replace(
                '"requiredSignatures": 2', '"requiredSignatures": 2, "RequiredSignatures": null', 1
            )
            path = Path(tmp) / "null-last.json"
            path.write_text(text)
            with self.assertRaises(ValueError) as raised:
                verify.load_fixture(path)
        self.assertEqual(str(raised.exception), 'the fixture repeats the member "RequiredSignatures"')


class PublicKeyHex(unittest.TestCase):
    def test_hex_decodes_as_go_decodes_it(self):
        for text, decoded in GO_HEX_DECODES:
            with self.subTest(hex=text):
                self.assertEqual(verify._decode_hex(text), decoded)

    def test_key_go_cannot_decode_is_skipped(self):
        # A key that is not hex ahead of the signing key is skipped, and the
        # signing key still verifies. The signing key itself written with a
        # space inside its hex is skipped too, so no key verifies.
        def prepend_non_hex_key(keys):
            keys.insert(0, {**keys[0], "publicKeyHex": "zz"})

        def space_in_signing_key(keys):
            text = keys[0]["publicKeyHex"]
            keys[0]["publicKeyHex"] = text[:2] + " " + text[2:]

        for edit, outcome in (
            (prepend_non_hex_key, "ACCEPT"),
            (space_in_signing_key, "SIGNATURE_INVALID"),
        ):
            with self.subTest(edit=edit.__name__):
                fixture = json.loads(BASELINE_V11.read_text())
                edit(fixture["verifierState"]["publicKeys"])
                got = verify.verify_fixture(fixture)
                self.assertEqual(_outcome(got), outcome, got.reason)


class NestingDepth(unittest.TestCase):
    def test_nesting_reaches_the_go_verdict(self):
        # 9999 arrays under the fixture object are the 10000 levels Go
        # decodes; one more fails to load. The json.loads of Python 3.12 and
        # 3.13 stops short of that depth, so there this also runs the
        # pure-Python parse.
        cases = [(_arrays, row) for row in GO_NESTING_VERDICTS]
        cases += [(_objects, row) for row in GO_OBJECT_NESTING_VERDICTS]
        for nest, (path, n, outcome) in cases:
            with self.subTest(nest=nest.__name__, path=path, depth=n), \
                    tempfile.TemporaryDirectory() as tmp:
                written = _write_fixture_at(Path(tmp), "deep.json", BASELINE_V11, path, nest(n))
                if outcome is None:
                    with self.assertRaises(ValueError) as raised:
                        verify.load_fixture(written)
                    self.assertIn("nested deeper than 10000 levels", str(raised.exception))
                else:
                    got = verify.verify_fixture(verify.load_fixture(written))
                    self.assertEqual(_outcome(got), outcome, got.reason[:200])
                    # Go's error names the member and not its value. Writing
                    # the whole value out raised RecursionError here on
                    # Python 3.11 to 3.13, and on 3.14 ran to 20,000
                    # characters.
                    self.assertLess(len(got.reason), 200, got.reason[:200])

    def test_nested_wrapper_member_is_a_load_error(self):
        cases = [(_arrays, row) for row in GO_NESTED_WRAPPERS]
        cases += [(_objects, row) for row in GO_OBJECT_NESTED_WRAPPERS]
        for nest, (path, n) in cases:
            with self.subTest(nest=nest.__name__, path=path, depth=n), \
                    tempfile.TemporaryDirectory() as tmp:
                written = _write_fixture_at(Path(tmp), "deep.json", BASELINE_V11, path, nest(n))
                with self.assertRaises(ValueError) as raised:
                    verify._expected_outcome(verify.load_fixture(written))
                message = str(raised.exception)
                self.assertTrue(message.startswith(".".join(path) + " "), message[:200])
                self.assertLess(len(message), 200, message[:200])

    def test_decode_error_writes_the_value_to_a_bounded_depth(self):
        depth = verify._REPR_DEPTH
        arrays: list = [1]
        objects: dict = {"a": None}
        for _ in range(depth - 1):
            arrays = [arrays, "x"]
            objects = {"a": objects, "b": []}
        for value in (7, -1.5, "x", True, None, [], {}, arrays, objects):
            with self.subTest(value=value):
                self.assertEqual(verify._value_repr(value), repr(value))
        self.assertEqual(verify._value_repr([[[1]]], 2), "[[[...]]]")
        self.assertEqual(verify._value_repr([[[]]], 2), "[[[]]]")
        self.assertEqual(verify._value_repr({"a": {"b": {"c": 1}}}, 2), "{'a': {'b': {...}}}")
        self.assertEqual(verify._value_repr({"a": {"b": {}}}, 2), "{'a': {'b': {}}}")

    def test_decode_error_writes_8_levels_of_the_value(self):
        # The count CHANGELOG states, in the reason itself: of ten levels,
        # eight are written out and the ninth as [...] or {...}. A slice
        # member holding an object is the "is not a JSON array" error.
        arrays = "[" * 8 + "[...]" + "]" * 8
        objects = "{'a': " * 8 + "{...}" + "}" * 8
        for member, literal, reason in (
            ("publisher", _arrays(10), f"publisher {arrays} is not a JSON string"),
            ("publisher", _objects(10), f"publisher {objects} is not a JSON string"),
            ("trustLevel", _objects(10), f"trustLevel {objects} is not a JSON integer in int64 range"),
            ("capabilities", _objects(10), f"capabilities {objects} is not a JSON array"),
            ("capabilities", f"[{_arrays(10)}]", f"capabilities[0] {arrays} is not a JSON string"),
            ("issuerChain", _objects(10), f"issuerChain {objects} is not a JSON array"),
            ("signatures", _objects(10), f"signatures {objects} is not a JSON array"),
            ("signatures", f"[{_arrays(10)}]", f"signatures[0] {arrays} is not a JSON object"),
        ):
            with self.subTest(member=member, value=literal):
                got = _at_verdict(BASELINE_V11, (member,), literal)
                self.assertEqual(got.reject_category, "PARSE_ERROR")
                self.assertEqual(got.reason, reason)
        # Nine levels end in an empty array or object, which is written as it
        # is, so the reason holds the whole value.
        got = _at_verdict(BASELINE_V11, ("capabilities",), _objects(9))
        self.assertEqual(
            got.reason, "capabilities " + "{'a': " * 8 + "{}" + "}" * 8 + " is not a JSON array"
        )
        with tempfile.TemporaryDirectory() as tmp:
            written = _write_fixture_at(
                Path(tmp), "deep.json", BASELINE_V11, ("verifierState", "trustedIssuers"), _objects(10)
            )
            with self.assertRaises(ValueError) as raised:
                verify._expected_outcome(verify.load_fixture(written))
        self.assertEqual(
            str(raised.exception), f"verifierState.trustedIssuers {objects} is not a JSON array"
        )

    def test_brackets_inside_a_string_do_not_nest(self):
        self.assertEqual(len(verify._string_literals('{"a": "' + "[" * 20000 + '"}')), 2)


class LongInteger(unittest.TestCase):
    def setUp(self):
        # The default limit, whatever limit this interpreter was started with.
        self.addCleanup(sys.set_int_max_str_digits, sys.get_int_max_str_digits())
        sys.set_int_max_str_digits(4300)

    def test_long_integer_reaches_the_go_verdict(self):
        # At the default limit int() refuses the literal. With the limit
        # lifted (0) it converts, and the verdict and the reason are the same.
        for limit in (4300, 0):
            sys.set_int_max_str_digits(limit)
            for literal in (LONG_INTEGER, "-" + LONG_INTEGER):
                for path, outcome in GO_LONG_INTEGER_VERDICTS:
                    with self.subTest(limit=limit, negative=literal[0] == "-", path=path), \
                            tempfile.TemporaryDirectory() as tmp:
                        written = _write_fixture_at(Path(tmp), "long.json", BASELINE_V11, path, literal)
                        fixture = verify.load_fixture(written)
                        if outcome is None:
                            with self.assertRaises(ValueError) as raised:
                                verify._expected_outcome(fixture)
                            self.assertEqual(
                                str(raised.exception),
                                f"{'.'.join(path)} {literal} is not a JSON string",
                            )
                            continue
                        got = verify.verify_fixture(fixture)
                        self.assertEqual(_outcome(got), outcome, got.reason[:200])
                        if outcome == "PARSE_ERROR":
                            # The reason writes the number as the file does.
                            self.assertIn(f" {literal} is not ", got.reason)

    def test_integer_at_the_limit_loads_as_an_int(self):
        # 4300 digits convert. One more does not: the number is written back
        # as its literal and is held as the infinity 1e5000 loads as.
        at_limit = "9" * 4300
        with self.assertRaises(ValueError):
            int(at_limit + "0")
        with tempfile.TemporaryDirectory() as tmp:
            written = _write_fixture_at(
                Path(tmp), "numbers.json", BASELINE_V11, ("numbers",),
                f"[{at_limit}, -{at_limit}, {at_limit}0, -{at_limit}0, 1e5000]",
            )
            fixture = verify.load_fixture(written)
        numbers = fixture["numbers"]
        self.assertEqual([type(n) for n in numbers[:2]], [int, int])
        self.assertEqual(numbers[:2], [int(at_limit), -int(at_limit)])
        self.assertEqual([repr(n) for n in numbers[2:4]], [at_limit + "0", "-" + at_limit + "0"])
        self.assertEqual(numbers[2:], [float("inf"), float("-inf"), float("inf")])
        self.assertTrue(verify.verify_fixture(fixture).accepted)

    def test_declared_purpose_rejects_as_it_does_for_a_shorter_integer(self):
        # declaredPurpose enters the v1.1 signed payload as written, so no
        # typed decode refuses the number there. An integer of 401 digits,
        # which int() converts, is outside float64 range too, and the Go
        # verifier's JCS library refuses both (VERIFIER_CONFIG_ERROR).
        shorter = "1" + "0" * 400
        for purpose in ("%s", "-%s", '{"x": %s}', "[7, %s]"):
            with self.subTest(purpose=purpose):
                got = _at_verdict(BASELINE_V11, ("declaredPurpose",), purpose % LONG_INTEGER)
                control = _at_verdict(BASELINE_V11, ("declaredPurpose",), purpose % shorter)
                self.assertFalse(got.accepted)
                self.assertEqual(got.reject_category, control.reject_category)
                self.assertEqual(got.reject_category, "VERIFIER_CONFIG_ERROR", got.reason[:200])

    def test_directory_run_reaches_the_summary_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _write_fixture_at(
                directory, "a-unknown-member.json", BASELINE_V11, ("atx", "unknownMember"), LONG_INTEGER
            )
            _write_at(directory, "b-trust-level.json", BASELINE_V11, ("trustLevel",), LONG_INTEGER)
            (directory / "c-baseline-valid.json").write_text(BASELINE_V11.read_text())
            code, text, _ = _run_main(str(directory))
        self.assertEqual(code, 0, text[-400:])
        self.assertNotIn("load error", text)
        self.assertEqual(text.count("observed: ACCEPT"), 2)
        self.assertEqual(text.count("observed: REJECT[PARSE_ERROR: trustLevel 1000"), 1)
        self.assertEqual(text.splitlines()[-1], "summary: 3 pass, 0 fail (3 fixtures)")


# Between the growth of the string-literal scan from 2,500 to 40,000 escaped
# quotes (16 for a linear scan; 19 to 39 measured on a host with a load
# average of 13 to 16, the time to allocate and touch memory growing faster
# than the text) and that of the quadratic one it replaced from 250 to 4,000
# (256 in theory; 242 to 259 measured on the same host).
_GROWTH_BOUND = 100


def _growth_to_16n(scan, n: int) -> float:
    """How many times as long scan takes on a quote and 16n escaped quotes as
    on a quote and n. Each length is timed at its fastest of five runs, taken
    in turn, so load during one run does not move the figure, and a host
    that runs every scan slower moves both lengths alike."""
    texts = ['"' + '\\"' * count for count in (n, 16 * n)]
    fastest = [float("inf")] * len(texts)
    for _ in range(5):
        for i, text in enumerate(texts):
            started = time.perf_counter()
            scan(text)
            fastest[i] = min(fastest[i], time.perf_counter() - started)
    return fastest[1] / fastest[0]


class StringLiteralScan(unittest.TestCase):
    def test_literals_and_names_are_found(self):
        text = '{"k" : "v\\"w", "n": ["x\\\\", 1], "e": "\\u0041"}'
        literals = verify._string_literals(text)
        self.assertEqual(
            [(text[start:end], is_name) for start, end, is_name in literals],
            [('"k"', True), ('"v\\"w"', False), ('"n"', True), ('"x\\\\"', False),
             ('"e"', True), ('"\\u0041"', False)],
        )
        self.assertEqual(
            verify._escaped_values_nulled(text, literals),
            '{"k" : null, "n": [null, 1], "e": null}',
        )

    def test_unterminated_literal_ends_the_scan(self):
        self.assertEqual(verify._string_literals('{"a": "b\\"}'), [(1, 4, True)])

    def test_unterminated_literal_is_scanned_in_linear_time(self):
        # A quote and n escaped quotes. A regular expression searched over
        # the text retries from each of them: the pattern this scan replaced
        # took 3.4 s at 20,000 in one measurement, and four times that at
        # twice the count. The bound is on how the time grows from 2,500 to
        # 40,000, not on the time itself, so a slow or loaded host passes.
        def scan(text):
            literals = verify._string_literals(text)
            verify._escaped_values_nulled(text, literals)
            self.assertEqual(literals, [])

        self.assertLess(_growth_to_16n(scan, 2_500), _GROWTH_BOUND)

    def test_growth_bound_fails_the_replaced_scan(self):
        # The pattern the scan replaced, searched over the text: the bound
        # still tells a quadratic scan from a linear one.
        replaced = re.compile(r'"(?:[^"\\]|\\.)*"([ \t\n\r]*:)?', re.DOTALL)
        self.assertGreater(
            _growth_to_16n(lambda text: list(replaced.finditer(text)), 250), _GROWTH_BOUND
        )

    def test_linear_time_bound_does_not_depend_on_the_host(self):
        # A clock that counts each second as an hour stands for a host on
        # which every scan takes 3,600 times as long.
        clock = time.perf_counter
        with mock.patch.object(time, "perf_counter", lambda: clock() * 3600):
            self.test_unterminated_literal_is_scanned_in_linear_time()

    def test_load_fixture_scans_before_it_parses(self):
        # The scan meets an unterminated literal only because it runs before
        # json.loads, which rejects one; that is why it has to be linear.
        calls = []
        scan, parse = verify._string_literals, verify._parse_json

        def recording_scan(text):
            calls.append("scan")
            return scan(text)

        def recording_parse(text, **hooks):
            calls.append("parse")
            return parse(text, **hooks)

        with tempfile.TemporaryDirectory() as tmp:
            written = Path(tmp) / "unterminated.json"
            written.write_text('{"atx": "' + '\\"' * 20_000)
            with mock.patch.object(verify, "_string_literals", recording_scan), \
                    mock.patch.object(verify, "_parse_json", recording_parse), \
                    self.assertRaises(ValueError):
                verify.load_fixture(written)
        self.assertEqual(calls, ["scan", "parse"])


class InvalidUTF8(unittest.TestCase):
    def test_invalid_byte_decodes_as_go_decodes_it(self):
        for raw, name in GO_INVALID_UTF8_DECODES:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as tmp:
                written = _write_fixture_at(Path(tmp), "u.json", BASELINE_V11, ("name",), raw)
                fixture = verify.load_fixture(written)
                self.assertEqual(fixture["name"], name)
                self.assertTrue(verify.verify_fixture(fixture).accepted)

    def test_invalid_byte_outside_a_string_fails_to_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = _write_fixture_at(Path(tmp), "u.json", BASELINE_V11, ("name",), b'"ab"\xff')
            with self.assertRaises(ValueError):
                verify.load_fixture(written)


USAGE = (
    "usage: verify.py <fixture.json|dir>...\n"
    "  -h, --help     print this usage and exit 0\n"
    "  --version      print the commit this verifier runs from and exit 0\n"
    "  --             end the options: every argument after it is a fixture file or directory\n"
)


class Options(unittest.TestCase):
    def test_help_prints_the_usage_lines_and_exits_0(self):
        for args in (("--help",), ("-h",), (str(BASELINE_V10), "-h"), ("--json", "--help")):
            with self.subTest(args=args):
                self.assertEqual(_run_main(*args), (0, USAGE, ""))

    def test_no_argument_is_a_usage_error(self):
        self.assertEqual(_run_main(), (2, "", USAGE))

    def test_unknown_option_is_named_above_the_usage(self):
        # Each was taken for a path: `error: --json: no such file or
        # directory`, exit 2. The Go reference verifier names it the same way.
        cases = (
            (("--json",), "--json"),
            (("--verbose",), "--verbose"),
            (("-x",), "-x"),
            ((str(BASELINE_V10), "--json"), "--json"),
            (("--version", "-x"), "-x"),
        )
        for args, unknown in cases:
            with self.subTest(args=args):
                self.assertEqual(_run_main(*args), (2, "", f"unknown option: {unknown}\n{USAGE}"))

    def test_version_names_the_commit_git_reads(self):
        # git runs in this file's directory with no GIT_* variable, so a
        # GIT_DIR a hook exports does not name another repository.
        commit = "1234567890" * 4
        python = f"run with Python {sys.version.split()[0]}"
        cases = (
            ([(0, commit + "\n"), (0, "")], f"verify.py: commit {commit}, {python}\n"),
            ([(0, commit + "\n"), (0, " M verify.py\n")],
             f"verify.py: commit {commit}, with uncommitted changes in its directory, {python}\n"),
            ([(128, "")], f"verify.py: no commit recorded (not run from a git checkout), {python}\n"),
            ([FileNotFoundError("git")],
             f"verify.py: no commit recorded (not run from a git checkout), {python}\n"),
        )
        for results, want in cases:
            calls = []

            def fake_run(cmd, results=iter(results), **kwargs):
                calls.append((cmd, kwargs))
                result = next(results)
                if isinstance(result, Exception):
                    raise result
                return subprocess.CompletedProcess(cmd, result[0], result[1], "")

            with self.subTest(want=want), mock.patch.dict(os.environ, {"GIT_DIR": "/elsewhere"}), \
                    mock.patch.object(verify.subprocess, "run", fake_run):
                self.assertEqual(_run_main("--version"), (0, want, ""))
                for cmd, kwargs in calls:
                    self.assertEqual(cmd[:3], ["git", "-C", str(HERE)])
                    self.assertFalse([name for name in kwargs["env"] if name.startswith("GIT_")])

    def test_version_runs_git(self):
        code, out, err = _run_main("--version")
        self.assertEqual((code, err), (0, ""))
        self.assertRegex(
            out,
            r"\Averify\.py: (commit [0-9a-f]{40}(, with uncommitted changes in its directory)?"
            r"|no commit recorded \(not run from a git checkout\)), run with Python \S+\n\Z",
        )


# Go's %q of each string, as the Go reference verifier writes it (Go 1.26.3).
# No character here is one a Unicode version after 6.1 assigned, so the table
# does not depend on the Unicode tables of the Python release.
GO_QUOTED = (
    ("2.0", '"2.0"'),
    ("", '""'),
    ('a"b\\c', r'"a\"b\\c"'),
    ("tab\there", r'"tab\there"'),
    ("\x00\x07\x1b\x7f", r'"\x00\a\x1b\x7f"'),
    ("\n", r'"\n"'),
    ("\x85", '"\\u0085"'),
    ("\N{NO-BREAK SPACE}", '"\\u00a0"'),
    ("\N{LATIN SMALL LETTER E WITH ACUTE}", '"\N{LATIN SMALL LETTER E WITH ACUTE}"'),
    ("\N{LINE SEPARATOR}", '"\\u2028"'),
    (chr(0xE000), '"\\ue000"'),
    ("\N{REPLACEMENT CHARACTER}", '"\N{REPLACEMENT CHARACTER}"'),
    ("\U0001f600", '"\U0001f600"'),
    ("\U000e0001", r'"\U000e0001"'),
    ("\U0010ffff", r'"\U0010ffff"'),
    # Go's encoding/json has decoded an unpaired surrogate to U+FFFD.
    (chr(0xD800), '"\N{REPLACEMENT CHARACTER}"'),
)


class GoReportText(unittest.TestCase):
    """The report reads as the Go reference verifier's: the signatures line
    writes each boolean as Go's %t does, and a reason that quotes the
    credential's atcVersion or a duplicate member name quotes it as Go's %q
    does. This verifier wrote True and False, and Python's repr ('2.0'), so
    9 of the 93 lines of the two reports over fixtures/ differed."""

    def test_report_over_the_fixtures_is_the_go_capture(self):
        # docs/captures/go-verifier.txt is the Go reference verifier's report
        # over fixtures/*.json, each named fixtures/<name>; its own test,
        # TestCaptureIsVerifierOutput, holds it to that verifier. Run from the
        # repository root over fixtures, this verifier names each one the same.
        with contextlib.chdir(ROOT):
            code, out, err = _run_main("fixtures")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, (ROOT / "docs" / "captures" / "go-verifier.txt").read_text(encoding="utf-8"))

    def test_signatures_line_writes_each_boolean_as_go(self):
        code, out, _ = _run_main(str(BASELINE_V10))
        self.assertEqual(code, 0, out)
        self.assertIn("       signatures: 1/1 valid (ed25519=true mldsa65=false)\n", out)

    def test_go_quote(self):
        for value, quoted in GO_QUOTED:
            with self.subTest(value=value):
                self.assertEqual(verify._go_quote(value), quoted)

    def test_unsupported_version_is_quoted_as_go(self):
        version = (
            '2"0\\\x07\N{LATIN SMALL LETTER E WITH ACUTE}\N{NO-BREAK SPACE}'
            "\N{LINE SEPARATOR}\U000e0001"
        )
        got = _member_verdict(BASELINE_V10, "atcVersion", json.dumps(version))
        self.assertEqual(got.reject_category, "UNSUPPORTED_VERSION")
        self.assertEqual(
            got.reason,
            'unsupported atcVersion "2\\"0\\\\\\a\N{LATIN SMALL LETTER E WITH ACUTE}'
            '\\u00a0\\u2028\\U000e0001" (this verifier supports 1.0 and 1.1)',
        )

    def test_duplicate_member_is_quoted_as_go(self):
        fixture = json.loads(BASELINE_V11.read_text())
        fixture["atx"]["@@DUP@@"] = 0
        fixture["expected"] = dict(PARSE_ERROR_EXPECTED)
        text = json.dumps(fixture).replace('"@@DUP@@": 0', r'"q\"1\u0001": 1, "Q\"1\u0001": 2')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.json"
            path.write_text(text)
            got = verify.verify_fixture(verify.load_fixture(path))
        self.assertEqual(got.reject_category, "PARSE_ERROR")
        self.assertTrue(got.reason.startswith(r'credential contains duplicate member "Q\"1\x01" (strict parse:'),
                        got.reason)


def _doc_section(doc: str, heading: str) -> str:
    """The lines under the `## heading` of the page `doc` names, up to its
    next `## ` heading, joined with a space."""
    lines = (ROOT / doc).read_text(encoding="utf-8").splitlines()
    start = lines.index(f"## {heading}") + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines))
    return " ".join(lines[start:end])


class ArgumentContract(unittest.TestCase):
    """The argument rules the Go reference verifier keeps too, and which
    scripts/parity/parity.py runs both verifiers on."""

    def test_empty_argument_is_a_usage_error(self):
        # Path("") is the current directory, which a run walked: run here
        # from a directory holding a fixture, so a walk would verify it.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "x.json").write_bytes(BASELINE_V10.read_bytes())
            with contextlib.chdir(tmp):
                for args in (("",), (str(ROOT / "fixtures"), "")):
                    with self.subTest(args=args):
                        self.assertEqual(_run_main(*args), (
                            2, "", "error: an empty argument names no fixture file or directory\n"))

    def test_fixtures_file_entry_walks_the_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "fixtures").write_text("a file, not a directory\n", encoding="utf-8")
            (directory / "x.json").write_bytes(BASELINE_V10.read_bytes())
            code, out, err = _run_main(str(directory))
        self.assertEqual((code, err), (0, ""), out)
        lines = out.splitlines()
        self.assertEqual(lines[0], f"PASS  {directory / 'x.json'}")
        self.assertEqual(lines[-1], "summary: 1 pass, 0 fail (1 fixture)")

    def test_a_subdirectory_named_json_is_skipped(self):
        # Path.glob("*.json") listed a subdirectory named sub.json with the
        # files of the directory it was in, and the run reported it as a
        # load error and exited 1. The Go reference verifier keeps the *.json
        # entries os.ReadDir does not type as a directory: it skips the
        # subdirectory, in a directory argument and in a repository root's
        # fixtures/, and keeps a symbolic link named *.json whatever it links
        # to, so a link to a directory fails to load, with the error
        # os.ReadFile returns there.
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            for directory in ("d/sub.json", "r/fixtures/sub.json", "l/real"):
                os.makedirs(directory)
            for path in ("d/x.json", "r/fixtures/x.json", "l/x.json"):
                Path(path).write_bytes(BASELINE_V10.read_bytes())
            Path("l", "link.json").symlink_to("real", target_is_directory=True)
            for arg, code, want, summary in (
                ("d", 0, ["PASS  d/x.json", "observed: ACCEPT"],
                 "summary: 1 pass, 0 fail (1 fixture)"),
                ("r", 0, ["PASS  r/fixtures/x.json", "observed: ACCEPT"],
                 "summary: 1 pass, 0 fail (1 fixture)"),
                ("l", 1, ["FAIL  l/link.json  (load error: read l/link.json: is a directory)",
                          "PASS  l/x.json", "observed: ACCEPT"],
                 "summary: 1 pass, 1 fail (2 fixtures)"),
            ):
                with self.subTest(arg=arg):
                    got, out, err = _run_main(arg)
                    self.assertEqual((got, err), (code, ""), out)
                    self.assertEqual(_verdict_lines(out), want)
                    self.assertEqual(out.splitlines()[-1], summary)

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a POSIX user other than root")
    def test_a_directory_that_cannot_be_listed_is_refused(self):
        # A directory os.scandir could not open gave no name, and the run
        # wrote `no fixture *.json files found`, exit 2, though the directory
        # held a fixture. The Go reference verifier writes the error
        # os.ReadDir returns, `error: open locked: permission denied`, exit 2,
        # naming the directory as the argument spells it, or a repository
        # root's fixtures/ when that is the directory it cannot list.
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            locked = ("locked", "r/fixtures")
            for directory in locked:
                os.makedirs(directory)
                Path(directory, "x.json").write_bytes(BASELINE_V10.read_bytes())
                os.chmod(directory, 0)
            try:
                for arg, named in (("locked", "locked"), ("locked/", "locked/"),
                                   ("./locked", "./locked"), ("r", "r/fixtures")):
                    with self.subTest(arg=arg):
                        self.assertEqual(_run_main(arg), (
                            2, "", f"error: open {named}: permission denied\n"))
            finally:
                for directory in locked:
                    os.chmod(directory, 0o755)

    def test_double_dash_ends_the_options(self):
        # "--" was an unknown option, exit 2, so a fixture file named -h.json
        # could be named only as ./-h.json. After the first "--" each argument
        # is a path, and "--" alone is no path argument; an option before it
        # is still read.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "-h.json").write_bytes(BASELINE_V10.read_bytes())
            with contextlib.chdir(tmp):
                code, out, err = _run_main("--", "-h.json")
                self.assertEqual((code, err), (0, ""), out)
                self.assertTrue(out.startswith("PASS  -h.json\n"), out)
                self.assertTrue(out.endswith("\nsummary: 1 pass, 0 fail (1 fixture)\n"), out)
                for args, stderr in (
                    (("--", "-h.json", "--help"), "error: --help: no such file or directory\n"),
                    (("--", "--version"), "error: --version: no such file or directory\n"),
                    (("--", "--"), "error: --: no such file or directory\n"),
                    (("--", ""), "error: an empty argument names no fixture file or directory\n"),
                    (("-x", "--", "-h.json"), f"unknown option: -x\n{USAGE}"),
                    (("--",), USAGE),
                ):
                    with self.subTest(args=args):
                        self.assertEqual(_run_main(*args), (2, "", stderr))
                code, out, err = _run_main("--version", "--", "-x")
                self.assertEqual((code, err), (0, ""))
                self.assertTrue(out.startswith("verify.py: "), out)

    def test_path_under_a_linked_working_directory_is_named_relative(self):
        # Entered through a symbolic link, the working directory os.getcwd()
        # names is the link's target, so a path written through the link was
        # written whole and one written through the target named relative.
        # The Go reference verifier did the reverse: its os.Getwd returns PWD,
        # which a shell sets to the path through the link. Both now compare
        # the two with their links resolved.
        with tempfile.TemporaryDirectory() as tmp:
            target, link = Path(tmp) / "target", Path(tmp) / "link"
            target.mkdir()
            (target / "x.json").write_bytes(BASELINE_V10.read_bytes())
            link.symlink_to("target", target_is_directory=True)
            with contextlib.chdir(link):
                for path in (link / "x.json", target / "x.json"):
                    with self.subTest(path=str(path)):
                        code, out, err = _run_main(str(path))
                        self.assertEqual((code, err), (0, ""), out)
                        self.assertEqual(out.splitlines()[0], "PASS  x.json")

    def test_dotdot_after_a_link_is_applied_where_the_link_leads(self):
        # The operating system resolves a symbolic link before it applies
        # the .. after it; os.path.normpath, as Go's filepath.Join and
        # filepath.Dir, removes the .. with the element before it, the link
        # included. With d/link a link to elsewhere/deep, d/link/.. lists
        # elsewhere, and its other.json was reported as d/other.json, a load
        # error, as d holds no other.json, and d/x.json, which d/link/.. does
        # not list, was verified in place of elsewhere/x.json. An absolute
        # path $PWD/d/link/../x.json was named d/x.json while
        # elsewhere/x.json was read, and r/link/.., which resolves to a
        # directory holding fixtures/, was walked for its own *.json since
        # r/fixtures does not exist. Each is now read and named where the
        # link leads, as the Go reference verifier reads and names it;
        # d/../d, which cleaning resolves alike, keeps the name
        # filepath.Join gives its file.
        expired = (ROOT / "fixtures" / "expired.json").read_bytes()
        rejected = "observed: REJECT[EXPIRED]"
        with tempfile.TemporaryDirectory() as tmp:
            wd, elsewhere, root = Path(tmp) / "wd", Path(tmp) / "elsewhere", Path(tmp) / "root"
            for directory in (wd / "d", wd / "r", elsewhere / "deep", root / "deep", root / "fixtures"):
                directory.mkdir(parents=True)
            (wd / "d" / "x.json").write_bytes(BASELINE_V10.read_bytes())
            (elsewhere / "other.json").write_bytes(expired)
            (elsewhere / "x.json").write_bytes(expired)
            (root / "fixtures" / "x.json").write_bytes(BASELINE_V10.read_bytes())
            (root / "conformance.json").write_text("{}\n", encoding="utf-8")
            (wd / "d" / "link").symlink_to(elsewhere / "deep", target_is_directory=True)
            (wd / "r" / "link").symlink_to(root / "deep", target_is_directory=True)
            with contextlib.chdir(wd):
                for arg, want in (
                    ("d/link/..", ["PASS  d/link/../other.json", rejected,
                                   "PASS  d/link/../x.json", rejected]),
                    ("d/link/../", ["PASS  d/link/../other.json", rejected,
                                    "PASS  d/link/../x.json", rejected]),
                    (f"{wd}/d/link/..", [f"PASS  {wd}/d/link/../other.json", rejected,
                                         f"PASS  {wd}/d/link/../x.json", rejected]),
                    (f"{wd}/d/link/../x.json", [f"PASS  {wd}/d/link/../x.json", rejected]),
                    ("r/link/..", ["PASS  r/link/../fixtures/x.json", "observed: ACCEPT"]),
                    ("d/../d", ["PASS  d/x.json", "observed: ACCEPT"]),
                ):
                    with self.subTest(arg=arg):
                        code, out, err = _run_main(arg)
                        self.assertEqual((code, err), (0, ""), out)
                        self.assertEqual(_verdict_lines(out), want)

    def test_arguments_section_names_the_file_of_a_dotdot_after_a_link_as_printed(self):
        # The "Arguments" section of docs/running-the-verifiers.md said the
        # file of a directory argument with a .. after a symbolic link is
        # named as the argument spells the directory, then a / and the file
        # name: d/link/..//other.json for d/link/../, for which this verifier
        # and the Go reference verifier print PASS  d/link/../other.json. In
        # the layout the section describes, the section must quote d/link/..
        # and d/link/../ and the PASS line this verifier prints for each.
        text = _doc_section("docs/running-the-verifiers.md", "Arguments")
        with tempfile.TemporaryDirectory() as tmp:
            wd, elsewhere = Path(tmp) / "wd", Path(tmp) / "elsewhere"
            for directory in (wd / "d", elsewhere / "deep"):
                directory.mkdir(parents=True)
            (elsewhere / "other.json").write_bytes((ROOT / "fixtures" / "expired.json").read_bytes())
            (wd / "d" / "link").symlink_to(elsewhere / "deep", target_is_directory=True)
            with contextlib.chdir(wd):
                for arg in ("d/link/..", "d/link/../"):
                    with self.subTest(arg=arg):
                        code, out, err = _run_main(arg)
                        self.assertEqual((code, err), (0, ""), out)
                        printed = out.splitlines()[0]
                        self.assertEqual(_verdict_lines(out), [printed, "observed: REJECT[EXPIRED]"])
                        self.assertIn(f"`{arg}`", text)
                        self.assertIn(f"`{printed}`", text)


class UnreadableFixture(unittest.TestCase):
    """A fixture file the verifier cannot read fails to load with the error
    the Go reference verifier's os.ReadFile returns, which names the step
    that failed and the path as spelled. Path.read_bytes raised Python's
    OSError, `[Errno 13] Permission denied: 'd/x.json'`, the path written
    as a Path holds it and quoted through repr. scripts/parity/parity.py
    runs both verifiers on such a file."""

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a POSIX user other than root")
    def test_a_file_that_cannot_be_read_is_named_as_go_names_it(self):
        # The error names the path as spelled, ./d//x.json as written where a
        # Path wrote d/x.json, and an absolute path whole, though the report
        # line names that file relative to the working directory.
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            os.mkdir("d")
            Path("d", "x.json").write_bytes(BASELINE_V10.read_bytes())
            os.chmod(os.path.join("d", "x.json"), 0)
            absolute = os.path.join(os.getcwd(), "d", "x.json")
            for arg, line in (
                ("d", "FAIL  d/x.json  (load error: open d/x.json: permission denied)"),
                ("d/x.json", "FAIL  d/x.json  (load error: open d/x.json: permission denied)"),
                ("./d//x.json",
                 "FAIL  ./d//x.json  (load error: open ./d//x.json: permission denied)"),
                (absolute, f"FAIL  d/x.json  (load error: open {absolute}: permission denied)"),
            ):
                with self.subTest(arg=arg):
                    self.assertEqual(_run_main(arg), (
                        1, f"{line}\n\nsummary: 0 pass, 1 fail (1 fixture)\n", ""))

    def test_a_failed_read_is_named_as_go_names_it(self):
        # os.ReadFile writes an error of the read after the file opened as
        # `read <path>: <reason>`. The file here opens, and its read raises
        # the OSError of an I/O error, which names no path.
        class FailingRead(io.BytesIO):
            def read(self, *args):
                raise OSError(errno.EIO, os.strerror(errno.EIO))

        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("x.json").write_bytes(BASELINE_V10.read_bytes())
            with mock.patch.object(verify, "open", lambda path, mode: FailingRead(), create=True):
                code, out, err = _run_main("x.json")
        self.assertEqual((code, err), (1, ""), out)
        self.assertEqual(out.splitlines()[0],
                         "FAIL  x.json  (load error: read x.json: input/output error)")


@unittest.skipIf(os.name != "posix", "an argument of bytes that are not UTF-8 is a POSIX argument")
class NonUTF8Argument(unittest.TestCase):
    """An argument the operating system passes as bytes that are not UTF-8,
    which sys.argv holds with each byte that does not decode as a surrogate
    escape, the byte 0xff as \\udcff. sys.stderr wrote that escape as the
    six characters \\udcff in a line that quotes the argument, where the Go
    reference verifier writes the byte. scripts/parity/parity.py runs both
    verifiers on the byte 0xff."""

    def test_a_line_on_stderr_writes_the_argument_as_its_bytes(self):
        xff = os.fsdecode(b"\xff")
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("x.json").write_bytes(BASELINE_V10.read_bytes())
            for args, stderr in (
                ((xff,), b"error: \xff: no such file or directory\n"),
                ((f"x.json/{xff}",), b"error: stat x.json/\xff: not a directory\n"),
                ((f"-{xff}",), b"unknown option: -\xff\n" + USAGE.encode()),
            ):
                with self.subTest(args=args):
                    self.assertEqual(_run_main_stderr_bytes(*args), (2, "", stderr))

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a POSIX user other than root")
    def test_a_directory_that_cannot_be_listed_is_named_by_its_bytes(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            try:
                os.mkdir(b"\xff")
            except OSError as exc:
                # A file system that takes only UTF-8 names refuses it,
                # APFS with EILSEQ.
                self.skipTest(f"the file system refuses a name that is not UTF-8: {exc}")
            Path(os.fsdecode(b"\xff"), "x.json").write_bytes(BASELINE_V10.read_bytes())
            os.chmod(b"\xff", 0)
            try:
                self.assertEqual(_run_main_stderr_bytes(os.fsdecode(b"\xff")), (
                    2, "", b"error: open \xff: permission denied\n"))
            finally:
                os.chmod(b"\xff", 0o755)

    def test_a_run_writes_the_first_stderr_line_go_writes(self):
        # Run as a shell runs it, writing to the stream sys.stderr is: the
        # Go reference verifier writes `error: `, the byte 0xff, then
        # `: no such file or directory`, and exits 2.
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(HERE / "verify.py"), b"\xff"],
                cwd=tmp, capture_output=True, timeout=120,
            )
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr),
                         (2, b"", b"error: \xff: no such file or directory\n"))


@unittest.skipIf(os.name != "posix", "a path of bytes that are not UTF-8 is a POSIX path")
class NonUTF8FixtureName(unittest.TestCase):
    """A fixture whose path is not UTF-8, which sys.argv and os.scandir hold
    with each byte that does not decode as a surrogate escape, the byte 0xff
    as \\udcff. The report line naming it wrote that escape as the six
    characters \\udcff, where the Go reference verifier writes the byte, and
    so did the load error of such a file the verifier cannot read.
    scripts/parity/parity.py runs both verifiers on such a fixture, named as
    a file and found in a directory, and on such a file of mode 000, where
    the file system takes the name."""

    def test_a_report_line_writes_a_listed_name_as_its_bytes(self):
        # _json_names gives the name os.scandir gives a file named by the
        # byte 0xff then .json, so this runs where the file system refuses
        # such a name, and standard output is a strict UTF-8 stream over
        # bytes, as a pipe gives it, which main sets to write the surrogate
        # escape as its byte. Another character it cannot encode, U+D800 in
        # the verify error, is still a backslash escape.
        real_load, real_verify = verify.load_fixture, verify.verify_fixture

        def raises(fixture):
            raise RuntimeError("bad \ud800")

        for verifier, code, first in (
            (real_verify, 0, b"PASS  d/\xff.json"),
            (raises, 1, b"FAIL  d/\xff.json  (verify error: RuntimeError: bad \\ud800)"),
        ):
            with self.subTest(first=first), tempfile.TemporaryDirectory() as tmp, \
                    contextlib.chdir(tmp):
                Path("d").mkdir()
                with mock.patch.object(verify, "_json_names",
                                       return_value=[os.fsdecode(b"\xff.json")]), \
                        mock.patch.object(verify, "load_fixture",
                                          lambda path: real_load(BASELINE_V10)), \
                        mock.patch.object(verify, "verify_fixture", verifier):
                    got, out = _run_main_stdout_bytes("d")
                self.assertEqual((got, out.splitlines()[0]), (code, first), out)

    def test_a_run_names_the_fixture_by_its_bytes(self):
        # Run as a shell runs it, writing to the stream sys.stdout is: the
        # Go reference verifier writes `PASS  d/`, the byte 0xff, then
        # `.json`, for the directory and for the file named as an argument.
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "d"))
            try:
                Path(tmp, "d", os.fsdecode(b"\xff.json")).write_bytes(BASELINE_V10.read_bytes())
            except OSError as exc:
                # A file system that takes only UTF-8 names refuses it,
                # APFS with EILSEQ.
                self.skipTest(f"the file system refuses a name that is not UTF-8: {exc}")
            for arg in (b"d", b"d/\xff.json"):
                with self.subTest(arg=arg):
                    proc = subprocess.run(
                        [sys.executable, str(HERE / "verify.py"), arg],
                        cwd=tmp, capture_output=True, timeout=120,
                    )
                    self.assertEqual((proc.returncode, proc.stderr), (0, b""), proc.stdout)
                    self.assertEqual(proc.stdout.splitlines()[0], b"PASS  d/\xff.json")

    def test_a_load_error_writes_a_listed_name_as_its_bytes(self):
        # The load error quoted the path through repr, which writes the byte
        # 0xff as the six characters \udcff, so the FAIL line named the file
        # once by its byte and once by those characters. _json_names gives
        # the name os.scandir gives such a file, so this runs where the file
        # system refuses the name; d holds no file of that name.
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("d").mkdir()
            with mock.patch.object(verify, "_json_names", return_value=[os.fsdecode(b"\xff.json")]):
                got, out = _run_main_stdout_bytes("d")
        self.assertEqual((got, out.splitlines()[0]), (
            1, b"FAIL  d/\xff.json  (load error: open d/\xff.json: no such file or directory)"), out)

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a POSIX user other than root")
    def test_a_run_names_a_fixture_it_cannot_read_by_its_bytes(self):
        # Run as a shell runs it: the Go reference verifier writes the path's
        # bytes in the FAIL line and in its load error, for the directory and
        # for the file named as an argument, and exits 1.
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "d"))
            name = os.path.join(tmp, "d", os.fsdecode(b"\xff.json"))
            try:
                Path(name).write_bytes(BASELINE_V10.read_bytes())
            except OSError as exc:
                # A file system that takes only UTF-8 names refuses it,
                # APFS with EILSEQ.
                self.skipTest(f"the file system refuses a name that is not UTF-8: {exc}")
            os.chmod(name, 0)
            for arg in (b"d", b"d/\xff.json"):
                with self.subTest(arg=arg):
                    proc = subprocess.run(
                        [sys.executable, str(HERE / "verify.py"), arg],
                        cwd=tmp, capture_output=True, timeout=120,
                    )
                    self.assertEqual((proc.returncode, proc.stderr), (1, b""), proc.stdout)
                    self.assertEqual(
                        proc.stdout.splitlines()[0],
                        b"FAIL  d/\xff.json  (load error: open d/\xff.json: permission denied)")


class OsWithoutGeteuid(unittest.TestCase):
    """An os module whose name is "nt" and which has no geteuid, as Python's
    os module is on Windows. A decorator on a method is evaluated when its
    class body runs, at import, before a skipIf on the class applies, so this
    file must import with that os."""

    def test_this_file_imports_with_the_posix_tests_skipped(self):
        # NonUTF8Argument's test of a directory that cannot be listed was
        # decorated with skipIf(os.geteuid() == 0, ...): with this os its
        # class definition raised AttributeError, which stopped the import.
        # That guard reads os.name first, as ArgumentContract's does.
        nt = types.ModuleType("os")
        vars(nt).update(vars(os))
        vars(nt).pop("geteuid", None)
        nt.name = "nt"
        spec = importlib.util.spec_from_file_location("test_verify_on_nt", HERE / "test_verify.py")
        module = importlib.util.module_from_spec(spec)
        # The file's `import os` takes nt from sys.modules, and its
        # sys.path.insert changes a copy.
        with mock.patch.dict(sys.modules, {"os": nt}), mock.patch.object(sys, "path", list(sys.path)):
            spec.loader.exec_module(module)
        self.assertIs(module.os, nt)
        self.assertTrue(getattr(module.NonUTF8Argument, "__unittest_skip__", False))
        test = module.ArgumentContract.test_a_directory_that_cannot_be_listed_is_refused
        self.assertTrue(getattr(test, "__unittest_skip__", False))


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


def _readme_headings(doc: str = "README") -> set[str]:
    """The headings of README.md, or of the docs/ page `doc` names."""
    path = ROOT / ("README.md" if doc == "README" else doc)
    headings, fenced = set(), False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("#"):
            headings.add(line.lstrip("#").strip())
    return headings


class HeaderDocs(unittest.TestCase):
    """The module docstring lists only the checks verify_fixture performs, and
    its README cross-references name real headings. atx-conformance#161."""

    def _spec_coverage(self) -> str:
        doc = verify.__doc__
        start = doc.index("Spec coverage:")
        return doc[start : doc.index("\n\n", start)]

    def test_lists_every_supported_version(self):
        coverage = self._spec_coverage()
        for version in (verify.SUPPORTED_ATC_VERSION, verify.SUPPORTED_ATC_VERSION_V11):
            with self.subTest(version=version):
                self.assertIn(f'atcVersion="{version}"', coverage)

    def test_does_not_claim_the_step7_check(self):
        # A trust level 3+ credential is accepted without the distinct
        # signer-authority count, so the coverage list must not claim one.
        got = verify.verify_fixture(verify.load_fixture(ROOT / "fixtures" / "baseline-valid.json"))
        self.assertTrue(got.accepted)
        self.assertGreaterEqual(got.trust_level, 3)
        self.assertFalse(got.step7_performed)
        coverage = self._spec_coverage().lower()
        for claim in ("trust level", "chain check"):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, coverage)

    def test_readme_cross_references_resolve(self):
        # Join continuation lines so a reference split across two lines of a
        # docstring or comment reads as one.
        text = re.sub(r"\n[ \t]*(#[ \t]*)?", " ", (HERE / "verify.py").read_text(encoding="utf-8"))
        # A reference names README or the docs/ page that took the cited
        # section from it.
        refs = re.findall(r'(README|docs/[\w-]+\.md)\s+§"([^"]+)"', text)
        self.assertTrue(refs, "no README cross-reference found; refusing to pass vacuously")
        for doc, ref in refs:
            with self.subTest(doc=doc, ref=ref):
                self.assertIn(ref, _readme_headings(doc))


class ReportWording(unittest.TestCase):
    """The lines the Go reference verifier's tests of the same names pin:
    the summary's noun, a bare help or version word, the line for
    directories with no *.json, the reason for a fixture with no atx
    member, the load error of a file that is not a fixture object, and the
    line naming a reasonContains substring the reason lacks."""

    def test_summary_counts_one_fixture_in_the_singular(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("x.json").write_text(BASELINE_V10.read_text())
            for args, want in ((["x.json"], "\nsummary: 1 pass, 0 fail (1 fixture)\n"),
                               (["x.json", "x.json"], "\nsummary: 2 pass, 0 fail (2 fixtures)\n")):
                with self.subTest(args=args):
                    code, out, err = _run_main(*args)
                    self.assertEqual((code, err), (0, ""), out)
                    self.assertTrue(out.endswith(want), out)

    def test_bare_help_and_version_words_point_at_the_option(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            for arg, want in (
                ("help", "error: help: no such file or directory (--help prints the usage)\n"),
                ("version", "error: version: no such file or directory (--version prints the version line)\n"),
                ("helps", "error: helps: no such file or directory\n"),
            ):
                with self.subTest(arg=arg):
                    self.assertEqual(_run_main(arg), (2, "", want))

    def test_no_fixtures_line_names_the_directories(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            for d in ("empty", "onlysub/sub", "root/fixtures"):
                Path(d).mkdir(parents=True)
            Path("onlysub/sub/x.json").write_text(BASELINE_V10.read_text())
            for args, dirs in ((["empty"], "empty"), (["onlysub"], "onlysub"),
                               (["empty", "root"], "empty, root/fixtures")):
                with self.subTest(args=args):
                    self.assertEqual(_run_main(*args), (
                        2, "", f"no fixture *.json files found in {dirs} (subdirectories are not walked)\n"))

    def test_fixture_with_no_atx_member_names_the_cause(self):
        for doc, reason in (
            ({"$schema": "https://atp.opena2a.org/schemas/fixture-v1.json", "expected": {"verifyResult": "ACCEPT"}},
             'the fixture has no atx member (its $schema is "https://atp.opena2a.org/schemas/fixture-v1.json")'),
            ({"expected": {"verifyResult": "ACCEPT"}}, "the fixture has no atx member"),
            ({"$schema": 7, "expected": {"verifyResult": "ACCEPT"}}, "the fixture has no atx member"),
        ):
            with self.subTest(doc=doc), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "f.json"
                path.write_text(json.dumps(doc))
                got = verify.verify_fixture(verify.load_fixture(path))
                self.assertEqual((got.accepted, got.reject_category, got.reason), (False, "PARSE_ERROR", reason))

    def test_load_error_names_the_file_shape(self):
        deep = "[" * 200000 + "]" * 200000
        for text, reason in (
            ("not json at all", "fixture is not valid JSON"),
            ("", "fixture is not valid JSON"),
            ('{"expected": {"verifyResult": "ACCEPT"}} trailing', "fixture is not valid JSON"),
            ('{"name": NaN}', "fixture is not valid JSON"),
            ('{"name": Infinity}', "fixture is not valid JSON"),
            ('{"name": -Infinity}', "fixture is not valid JSON"),
            ("[NaN]", "fixture is not valid JSON"),
            ("[1,2,3]", "fixture is not a JSON object"),
            ('"text"', "fixture is not a JSON object"),
            ("7", "fixture is not a JSON object"),
            (deep, "arrays and objects nested deeper than 10000 levels (the limit of Go's encoding/json)"),
        ):
            with self.subTest(text=text[:40]), tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
                Path("f.json").write_text(text)
                self.assertEqual(_run_main("f.json"), (
                    1, f"FAIL  f.json  (load error: {reason})\n\nsummary: 0 pass, 1 fail (1 fixture)\n", ""))

    def test_reason_contains_mismatch_names_the_substring(self):
        doc = json.loads((ROOT / "fixtures" / "wrong-issuer.json").read_text())
        doc["expected"]["reasonContains"] = "zz-not-in-reason"
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("r1.json").write_text(json.dumps(doc))
            code, out, _ = _run_main("r1.json")
        lines = out.splitlines()
        self.assertEqual(code, 1, out)
        self.assertEqual(lines[0], "FAIL  r1.json", out)
        self.assertTrue(lines[2].startswith("       observed: REJECT[UNTRUSTED_ISSUER: "), out)
        self.assertEqual(lines[3], '       reason does not contain "zz-not-in-reason"', out)
        # The shipped fixture, which passes, has no such line.
        with contextlib.chdir(ROOT):
            code, out, _ = _run_main("fixtures/wrong-issuer.json")
        self.assertEqual(code, 0, out)
        self.assertNotIn("reason does not contain", out)


if __name__ == "__main__":
    unittest.main()
