#!/usr/bin/env python3
"""Python reference verifier for the ATX v1.0 and v1.1 conformance fixture set.

Depends only on the Python standard library plus the `cryptography` package
(for Ed25519 verification) and the `dilithium-py` package (for ML-DSA-65
verification per FIPS 204). Does NOT import any opena2a-* SDK. The goal is to
demonstrate that an independent verifier in a second language reaches the same
ACCEPT / REJECT verdict as the Go reference verifier for every fixture.

Spec coverage:
  - ATX v1.0 schema (atcVersion="1.0") and v1.1 schema (atcVersion="1.1");
    any other atcVersion rejects as UNSUPPORTED_VERSION
  - Canonicalization: v1.0 signs the pipe-delimited 11-field string matching
    opena2a-registry/pkg/atcverify/verify.go canonicalPayload() VERBATIM;
    v1.1 signs JCS(TBS), the RFC 8785 form of the to-be-signed projection
    (core.md section 1.3a.2). See docs/scope.md
    §"Canonicalization: v1.0 signs 11 fields; v1.1 signs JCS(TBS)".
  - Integers in the v1.1 signed payload: once the checks that refuse a
    payload the Go reference verifier cannot canonicalize pass, one whose
    magnitude is above 2**53 - 1, outside the I-JSON exact range (RFC 7493
    section 2.2), rejects as SIGNATURE_INVALID. The Go verifier's JCS library
    reads each number as an IEEE 754 double, which does not hold every such
    integer, and writes 9007199254740993 as 9007199254740992, so a signature
    over those bytes does not tell the two apart
    (_integer_outside_exact_range).
  - Ed25519 and ML-DSA-65 (FIPS 204) hybrid signature verification over the
    same canonical payload (every declared signature must verify and at
    least one must be present; an ML-DSA-65 signature needs a verifying
    Ed25519 companion; with requiredSignatures set in the verifier state,
    the Ed25519 signatures must verify under at least that many distinct
    keys, the k-of-n threshold of core.md section 3.1 step 8), expiry,
    revocation (the credential's revoked flag and the verifier's CRL),
    issuer-trust.

Not performed: the distinct signer-authority count for trust level 3+
(core.md section 1.3 step 7). The asserted trustLevel is reported, never
checked; see conformance.json notCovered.

Parsing rule (strict parse, ported from the aap-conformance protected-header
lesson and scoped to the whole body because ATX signs it all):
  - the ATX credential is STRICT-parsed as a whole: a duplicate object member
    at ANY depth of the credential rejects as PARSE_ERROR before any field is
    interpreted. Every credential field feeds a signed canonical form (v1.1
    JCS(TBS) projection, v1.0 pipe fields), so there is no layer with
    sanctioned RFC 7519 last-wins semantics — duplicates are the RFC 8259 §4
    first-wins/last-wins parser-divergence smuggling split.
  - the fixture wrapper (name/verifierState/expected) is harness metadata and
    parses leniently: a duplicate member there is no error. It is decoded as
    the Go reference verifier's fixture struct decodes it: each member the
    struct declares (name, description, keypairRefs, verifierState and every
    member of it, expected) is type-checked against its field, a member name
    in another case names the same member, and a member written more than
    once, under one name or in two cases, is type-checked each time, as Go
    type-checks each. A fixture the Go decode refuses, a name that is not a
    string, even with a string name written after it, or a CRL entry's
    revokedAt outside the timestamp grammar for example, fails to load, as
    it does there. Of a member written more than once the last value is the
    one read. Go decodes each into the same field, so a repeat whose last
    value is null or an object can still differ: Go keeps a clockRfc3339
    that a later null follows, and merges a later verifierState object into
    the earlier one, where this verifier reads the null and the later object
    alone. A verifierState public key whose publicKeyHex is not an even run
    of hex digits is skipped, as Go's hex.DecodeString leads the Go verifier
    to skip it.
  - each member the Go reference verifier's atx struct declares with a typed
    field is type-checked against that field: strings, integers in int64
    range, a finite trustScore, a boolean revoked, arrays of strings,
    signature objects, and issuedAt/expiresAt in the date-time grammar of Go
    1.23's time.Parse(time.RFC3339). A value outside its type rejects as
    PARSE_ERROR instead of raising; an absent or null member takes the Go zero
    value.
  - a member is read as Go's encoding/json reads it into that struct: a name
    that differs from the field's only in case names the same member, an
    unpaired UTF-16 surrogate escape in a string decodes to U+FFFD, a
    trustScore written as -0 keeps its sign, and a timestamp written with a
    JSON escape is outside the grammar: the Go reference verifier decodes
    every timestamp with time.Time's own UnmarshalJSON, which parses the
    bytes between the quotes under every Go release (a plain time.Time field
    decodes the escaped form when built with Go 1.27). The members of
    scanSummary, behavioralProfile and each signatures entry are read the
    same way.
  - under atcVersion 1.1 a scanSummary member outside its type, or a
    scanSummary that is not an object, rejects as SIGNATURE_INVALID: the
    signed payload holds each of its six members typed (core.md section
    1.3a.2 rule 2), so no signature covers such a value, and the Go reference
    verifier refuses it before projecting the zero value in its place.
  - declaredPurpose is the one member no decoder reads: it enters the v1.1
    signed payload as written. An unpaired surrogate escape in it, alone or
    followed directly by another \\u escape, cannot be canonicalized (RFC 8785
    section 3.2.2.2) and rejects as VERIFIER_CONFIG_ERROR, as it does in the
    Go reference verifier, which refuses it before its JCS library reads the
    escape. This verifier refuses it before it canonicalizes the payload too,
    so a number beside it that the serializer cannot write (1.5) does not
    make the credential a signature failure. A number in it outside the
    float64 range (1e400, or an integer of 401 digits) rejects as
    VERIFIER_CONFIG_ERROR too: that library parses every number as a float64.
    An integer in it inside that range but outside the I-JSON exact range
    rejects after these two checks, as SIGNATURE_INVALID (Spec coverage).
  - NaN, Infinity and -Infinity are not JSON, so a file carrying one fails to
    load, as it does in the Go reference verifier.
  - the file is read as UTF-8 the way Go's encoding/json reads it: each byte
    of an invalid sequence inside a string decodes to U+FFFD, and arrays and
    objects nested deeper than 10000 levels, the fixture object included,
    fail to load.
  - a JSON integer of any length loads, as it does in the Go reference
    verifier. Python's int() refuses one of more than 4300 digits by default;
    such a number is kept as its literal, is out of range for every member
    with a numeric type, and is not read in a member no Go struct declares.

Usage:
    python3 verify.py ../../fixtures/baseline-valid.json
    python3 verify.py ../../fixtures
    python3 verify.py ../..                # repo root; walks fixtures/*.json
    python3 verify.py -- -h.json           # -- ends the options; -h.json is a file
    python3 verify.py --help               # the usage lines
    python3 verify.py --version            # the commit this file runs from

Exit 0 iff every fixture's observed result matches expected.verifyResult, and
after --help, -h or --version. A file with no expected.verifyResult of ACCEPT
or REJECT is not a fixture: it fails to load and counts as a fail, so the run
exits 1. Exit 2 on a usage error (no path argument, an empty one, or an
unknown option, which is named above the usage lines), a path that does not
exist or that os.stat refuses (a file named with a trailing /), a directory
os.scandir cannot open, or no fixture files. With no path argument the Go
reference verifier verifies the fixture set its module embeds; this verifier
has no embedded set.

A fixture named as a file is named in the report as its argument spells it,
./ and // included, as the Go reference verifier names it. The line naming
an unknown option and the error line of a path that does not exist or
cannot be read are written as bytes (_say_err), so an argument that is not
UTF-8 is written as the bytes it was given, as the Go reference verifier
writes it, and not as a backslash escape. A report line naming a fixture
whose path is not UTF-8, its PASS or FAIL line, writes the path's bytes too,
as the argument gave them or as the directory listing named the file:
standard output is set to write each surrogate escape as the byte it stands
for before the first report line (_write_surrogate_escapes_as_bytes, _say).
A fixture file that cannot be read fails to load with the error the Go
reference verifier's os.ReadFile returns, which names the step that failed
and the path as spelled, its bytes where it is not UTF-8: run as a user
other than root, `open d/x.json: permission denied` for a file of mode 000
(_read_file).

The signatures line writes each boolean as true or false, and a rejection
reason that quotes the credential's atcVersion or a duplicate member name
quotes it as Go's %q does (_go_quote), so those lines read as the Go
reference verifier writes them.
"""

from __future__ import annotations

import base64
import codecs
import json
import math
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from json.scanner import py_make_scanner
from pathlib import Path
from typing import Any, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rfc8785 import canonicalize as _jcs_canonicalize  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write(
        "missing dependency: cryptography. install with `python3 -m pip install -r requirements.txt`\n"
    )
    sys.exit(2)

try:
    from dilithium_py.ml_dsa import ML_DSA_65
except ImportError:
    sys.stderr.write(
        "missing dependency: dilithium-py. install with `python3 -m pip install -r requirements.txt`\n"
    )
    sys.exit(2)

# ML-DSA-65 public key size per FIPS 204 (32-byte rho + 6 x 320-byte t1).
MLDSA65_PUBLIC_KEY_SIZE = 1952


SUPPORTED_ATC_VERSION = "1.0"
SUPPORTED_ATC_VERSION_V11 = "1.1"

# The date-time layout of Go's time.Parse(time.RFC3339, s), which the Go
# reference verifier's time.Time decoder applies (the Go standard library has
# its stricter RFC 3339 checks disabled, golang/go#54580): a four-digit year, a
# "T" separator, a one- or two-digit hour, seconds, an optional fraction after
# "." or ",", and "Z" or a +hh:mm / -hh:mm offset. _parse_rfc3339 checks the
# field ranges.
_RFC3339 = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?"
    r"(?:Z|([+-])(\d{2}):(\d{2}))",
    re.ASCII,
)

# The range of the Go reference verifier's int64 and int (trustLevel).
_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1

# An unpaired UTF-16 surrogate, which json.loads keeps when a JSON string
# escapes one with no partner beside it ("\ud800"). Go's encoding/json decodes
# each to U+FFFD.
_UNPAIRED_SURROGATE = re.compile("[\ud800-\udfff]")
_REPLACEMENT_CHARACTER = chr(0xFFFD)

# The rest of a JSON string literal after its opening quote, through the
# closing quote, and the colon after it when the literal is a member name.
_STRING_REST = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*"([ \t\n\r]*:)?', re.DOTALL)
_BRACKET = re.compile(r"[\[\]{}]")

# The deepest nesting of arrays and objects Go's encoding/json decodes, the
# outermost value included (maxNestingDepth in its scanner).
_GO_MAX_DEPTH = 10000

# The error handler load_fixture decodes a file's bytes with (_go_replace).
_GO_UTF8_ERRORS = "atx-conformance-go-utf8"

# What Go's base64.StdEncoding.DecodeString accepts once it has dropped every
# CR and LF: four-character groups of the standard alphabet, the last one
# padded with "=" when the data ends short.
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# What Go's hex.DecodeString accepts: pairs of hex digits in either case, and
# nothing else (bytes.fromhex also skips whitespace).
_HEX = re.compile(r"(?:[0-9A-Fa-f]{2})*")


class _Instant(NamedTuple):
    """A point in time as Go's time.Time holds it: whole seconds since
    1970-01-01T00:00:00Z and nanoseconds within that second, so instants
    compare in time order. Unlike datetime it reaches year 0 and, through an
    offset, the years before and after 0000-9999."""

    seconds: int
    nanos: int


def _days_in(month: int, year: int) -> int:
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days from 1970-01-01 to a date of the proleptic Gregorian calendar."""
    if month <= 2:
        year -= 1
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(days: int) -> tuple[int, int, int]:
    """The (year, month, day) that _days_from_civil maps to days."""
    days += 719468
    era = days // 146097
    doe = days - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    return yoe + era * 400 + (1 if month <= 2 else 0), month, day


# Go's zero time.Time, which an absent or null timestamp member decodes to.
_GO_ZERO_TIME = _Instant(_days_from_civil(1, 1, 1) * 86400, 0)


def _parse_rfc3339(value: Any) -> _Instant:
    """Parse a timestamp as the Go reference verifier does, or raise
    ValueError. The ranges are those of Go 1.23's time.Parse(time.RFC3339,
    value): year 0000-9999, hour 0-23, minute and second 0-59, offset hour
    0-24 and offset minute 0-60; a fraction keeps nine digits. Go 1.22 decodes
    an offset hour above 24 or minute above 60, and the Go verifier refuses
    them itself (checkOffset in verifiers/go/verifier/verify.go), so its
    verdict does not depend on the Go release."""
    if not isinstance(value, str):
        raise ValueError("not a JSON string")
    m = _RFC3339.fullmatch(value)
    if m is None:
        raise ValueError("not in the RFC 3339 layout")
    year, month, day, hour, minute, second = (int(g) for g in m.group(1, 2, 3, 4, 5, 6))
    fraction, sign, offset_hour, offset_minute = m.group(7, 8, 9, 10)
    if not 1 <= month <= 12:
        raise ValueError("month out of range")
    if hour > 23:
        raise ValueError("hour out of range")
    if minute > 59:
        raise ValueError("minute out of range")
    if second > 59:
        raise ValueError("second out of range")
    offset = 0
    if sign is not None:
        # Go checks the offset before the day, and the minute's error wins.
        if int(offset_minute) > 60:
            raise ValueError("time zone offset minute out of range")
        if int(offset_hour) > 24:
            raise ValueError("time zone offset hour out of range")
        offset = (int(offset_hour) * 60 + int(offset_minute)) * 60
        if sign == "-":
            offset = -offset
    if not 1 <= day <= _days_in(month, year):
        raise ValueError("day out of range")
    seconds = (
        _days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second - offset
    )
    return _Instant(seconds, int((fraction or "")[:9].ljust(9, "0")))


def _format_rfc3339(t: _Instant) -> str:
    """Go's t.UTC().Format(time.RFC3339): UTC with seconds precision."""
    days, secs = divmod(t.seconds, 86400)
    year, month, day = _civil_from_days(days)
    year_text = f"-{-year:04d}" if year < 0 else f"{year:04d}"
    return (
        f"{year_text}-{month:02d}-{day:02d}"
        f"T{secs // 3600:02d}:{secs // 60 % 60:02d}:{secs % 60:02d}Z"
    )


class _DupMarkedDict(dict):
    """dict that remembers the first duplicate member name seen in this object
    or any descendant (None when the subtree is duplicate-free). Values keep
    standard last-wins semantics so everything outside the strict-parse check
    behaves exactly as a plain json.loads. names lists the name of each
    member, as written, in document order, which the dict's own order does
    not give: it keeps a repeated name at its first position. shadowed holds
    the value of each member that a later member of the same name replaced in
    the dict, by its index in names, or is None when no member was replaced."""

    __slots__ = ("duplicate_member", "names", "shadowed")


def _subtree_duplicate(value: Any) -> str | None:
    # Without recursion, so a deeply nested array does not exhaust the stack.
    # Each object below carries its own mark, so only arrays are walked.
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, _DupMarkedDict):
            if node.duplicate_member is not None:
                return node.duplicate_member
        elif isinstance(node, list):
            pending.extend(reversed(node))
    return None


def _fold_key(s: str) -> str:
    """Fold a JSON member name the way Go's encoding/json folds struct field
    names, matching the Go reference verifier's foldKey (verifiers/go/verifier/verify.go):
    ASCII uppercase lowercased, Kelvin sign U+212A -> k, long s U+017F -> s, any
    other rune kept unchanged. Two names with the same fold key collapse to one
    struct field under a Go last-wins unmarshaler, so treating them as duplicates
    here keeps this verifier category-consistent (PARSE_ERROR) with the Go
    reference on case-variant members — a deliberate ecosystem rule, since a
    fold-colliding member is ambiguous across conforming parsers. This verifier's
    own json.loads is case-sensitive and would not otherwise collapse them. ATX
    member names are ASCII, and the Kelvin sign and the long s are the only
    non-ASCII runes whose simple case fold reaches an ASCII letter, so any other
    non-ASCII rune collapses onto no struct field; RFC 8259 §8.3 compares names
    code unit by code unit, so two such names are one member only when they
    decode to the same name. See atx-conformance#16. The table is fixed, the
    same as the Go foldKey's, and reads no Unicode table, so no Python release
    changes it (docs/running-the-verifiers.md). A fallback to str.lower(), which
    reads the tables of the release, made U+1C89 and U+1C8A (a case pair from
    Unicode 16.0) a duplicate under Python 3.14 and not under Python 3.12, and
    folded U+0130 to i followed by U+0307 (atx-conformance#173).
    """
    out: list[str] = []
    for ch in s:
        if "A" <= ch <= "Z":
            out.append(chr(ord(ch) + 32))
        elif ch == "K":  # Kelvin sign -> k
            out.append("k")
        elif ch == "ſ":  # latin small letter long s -> s
            out.append("s")
        else:
            out.append(ch)
    return "".join(out)


def _go_string(value: str) -> str:
    """A JSON string as Go's encoding/json decodes it: each unpaired UTF-16
    surrogate becomes U+FFFD."""
    return _UNPAIRED_SURROGATE.sub(_REPLACEMENT_CHARACTER, value)


# The escapes Go's strconv.Quote writes for a character it does not write as
# itself: the quote and the backslash, and the seven C escapes.
_GO_QUOTE_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\a": "\\a", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v",
}


def _go_quote(value: str) -> str:
    """value as the Go reference verifier's %q writes it (strconv.Quote), so a
    reason that quotes a credential's string reads the same in both reports:
    in double quotes, with a quote or a backslash escaped, each printable
    character written as itself, and every other one escaped: a C escape
    where Go has one, \\xHH below U+0020 and for U+007F, \\uHHHH or
    \\UHHHHHHHH above. Printable is a letter, mark, number, punctuation or
    symbol, or the ASCII space, for str.isprintable and for Go's
    strconv.IsPrint alike, each by the Unicode tables of its release. An
    unpaired surrogate is U+FFFD, as _go_string reads it."""
    out = ['"']
    for ch in _go_string(value):
        if ch in _GO_QUOTE_ESCAPES:
            out.append(_GO_QUOTE_ESCAPES[ch])
        elif ch.isprintable():
            out.append(ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        elif ord(ch) < 0x10000:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(f"\\U{ord(ch):08x}")
    out.append('"')
    return "".join(out)


def _dup_marking_pairs(pairs: list[tuple[str, Any]]) -> "_DupMarkedDict":
    out = _DupMarkedDict()
    dup: str | None = None
    folded: set[str] = set()
    names: list[str] = []
    last_index: dict[str, int] = {}
    shadowed: dict[int, Any] | None = None
    for key, value in pairs:
        # Names are compared as Go decodes them, so two names that escape
        # different unpaired surrogates are one name. The object keeps the
        # name as written.
        name = _go_string(key)
        fk = _fold_key(name)
        if dup is None and fk in folded:
            dup = name
        folded.add(fk)
        if dup is None:
            dup = _subtree_duplicate(value)
        if key in last_index:
            if shadowed is None:
                shadowed = {}
            shadowed[last_index[key]] = out[key]
        last_index[key] = len(names)
        names.append(key)
        out[key] = value
    out.duplicate_member = dup
    out.names = names
    out.shadowed = shadowed
    return out


@dataclass
class VerifyResult:
    accepted: bool = False
    reject_category: str = ""
    reason: str = ""
    ed25519_valid: bool = False
    mldsa65_valid: bool = False
    sigs_expected: int = 0
    sigs_valid: int = 0
    # False: this verifier does not count distinct signer authorities
    # (core.md section 1.3 step 7); see conformance.json notCovered.
    step7_performed: bool = False
    trust_level: int = 0

    def __str__(self) -> str:
        if self.accepted:
            return "ACCEPT"
        return f"REJECT[{self.reject_category}: {self.reason}]"


def canonical_payload(atx: dict[str, Any]) -> bytes:
    """Mirror opena2a-registry/pkg/atcverify/verify.go canonicalPayload() VERBATIM.

    The Go signature uses fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%.6f|%s|%s|%s", ...)
    with the 11 fields enumerated below. Python's f-string %.6f matches Go's
    %.6f for finite floats in the ranges we use (0.0 to ~100.0). The
    atcVersion in the canonical string is the literal "1.0" regardless of the
    credential's atcVersion field, a property of the v1.0 canonical form itself.
    atx is the credential as _decode_credential returns it.
    """
    return (
        f"{atx['agentId']}|"
        f"{atx['agentDid']}|"
        f"{atx['version']}|"
        f"{atx['contentHash']}|"
        f"{atx.get('buildAttestation', '')}|"
        f"{atx['issuerDid']}|"
        f"{atx['trustLevel']}|"
        f"{atx['trustScore']:.6f}|"
        f"{_format_rfc3339(atx['issuedAt'])}|"
        f"{_format_rfc3339(atx['expiresAt'])}|"
        f"{SUPPORTED_ATC_VERSION}"
    ).encode("utf-8")


def canonical_payload_v11(atx: dict[str, Any]) -> bytes:
    """Project the credential into the ATX v1.1 TBS and JCS-canonicalize it.

    atx-spec core.md §1.3a.2. Unlike canonical_payload, this covers capabilities,
    scanSummary, issuerChain, publisher, and behavioralProfile. The byte
    agreement with the Go and TypeScript verifiers is guaranteed by the
    jcs-vectors suite, not by shared code. atx is the credential as
    _decode_credential returns it.
    """
    return _jcs_canonicalize(_tbs_v11(atx))


# 2**53 - 1, the largest magnitude of an integer in the I-JSON exact range
# (RFC 7493 section 2.2), as the Go reference verifier's maxExactInteger.
_MAX_EXACT_INTEGER = 2**53 - 1


def _integer_outside_exact_range(tbs: dict[str, Any]) -> tuple[str, int] | None:
    """The first integer of the v1.1 TBS (as _tbs_v11 projects it) whose
    magnitude is above 2**53 - 1, with its member, as the Go reference
    verifier's integerOutsideExactRangeV11 names it: the members
    behavioralProfile.observationDays, declaredPurpose,
    scanSummary.criticalFindings, scanSummary.highFindings and trustLevel, in
    the order JCS writes them, and in declaredPurpose, which enters the TBS
    as written, the first such integer the credential writes. None when the
    TBS holds none. Walked with a stack, as _first_unpaired_surrogate is."""

    def outside(n: Any) -> bool:
        return (
            isinstance(n, int)
            and not isinstance(n, bool)
            and not -_MAX_EXACT_INTEGER <= n <= _MAX_EXACT_INTEGER
        )

    profile = tbs["behavioralProfile"]
    if profile is not None and outside(profile["observationDays"]):
        return "behavioralProfile.observationDays", profile["observationDays"]
    stack = [tbs.get("declaredPurpose")]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            stack.extend(reversed(item))
        elif outside(item):
            return "declaredPurpose", item
    for name in ("criticalFindings", "highFindings"):
        if outside(tbs["scanSummary"][name]):
            return f"scanSummary.{name}", tbs["scanSummary"][name]
    if outside(tbs["trustLevel"]):
        return "trustLevel", tbs["trustLevel"]
    return None


def _tbs_v11(atx: dict[str, Any]) -> dict[str, Any]:
    """The ATX v1.1 TBS object of the credential, which canonical_payload_v11
    JCS-canonicalizes. atx is the credential as _decode_credential returns
    it."""
    # The Go verifier's projectScanSummaryV11 ignores a decode error, which
    # leaves each member it could not decode at its zero value; a scanSummary
    # that is not an object leaves all six there. verify_fixture refuses such
    # a credential before it reads a signature (_decode_scan_summary).
    scan_summary = _decode_scan_summary(atx.get("scanSummary"), lenient=True)

    # The Go verifier's projectBehavioralProfileV11 projects behavioralProfile
    # as null when it is absent, null or not an object, and when one member
    # fails its decode: a checksum that is not a string, an observationDays
    # that is not an integer, a generatedAt outside the time.Time grammar. An
    # absent or null generatedAt is the zero time, 0001-01-01T00:00:00Z.
    bp_in = atx.get("behavioralProfile")
    behavioral_profile: Any = None
    if isinstance(bp_in, dict):
        try:
            behavioral_profile = _decode_members(
                _BEHAVIORAL_PROFILE_TYPES, bp_in, "behavioralProfile."
            )
        except _DecodeError:
            behavioral_profile = None
        else:
            behavioral_profile["generatedAt"] = _format_rfc3339(behavioral_profile["generatedAt"])

    # declaredPurpose is the one presence-based TBS member (atx-spec §1.3a.2
    # rule 5, degenerate inputs pinned per issue #11): absent / null /
    # empty-object are all "absent" (a parse-level property) and the key is
    # omitted entirely (added below), keeping a no-purpose credential
    # byte-identical to one issued before the field existed. ANY other value —
    # including non-object values — is included verbatim so unsigned injected
    # purpose content breaks the signature instead of being silently omitted.
    dp_in = atx.get("declaredPurpose")
    declared_purpose = None if dp_in is None or dp_in == {} else dp_in

    tbs = {
        "atcVersion": atx["atcVersion"],
        "agentId": atx["agentId"],
        "agentDid": atx["agentDid"],
        "publisher": atx.get("publisher", "") or "",
        "publisherDid": atx.get("publisherDid", "") or "",
        "version": atx["version"],
        "contentHash": atx["contentHash"],
        "buildAttestation": atx.get("buildAttestation", "") or "",
        "capabilities": list(atx.get("capabilities") or []),
        "behavioralProfile": behavioral_profile,
        "scanSummary": scan_summary,
        # trustScore is string-encoded %.6f so every JSON number left is an integer.
        "trustScore": "%.6f" % float(atx["trustScore"]),
        "trustLevel": int(atx["trustLevel"]),
        "issuedAt": _format_rfc3339(atx["issuedAt"]),
        "expiresAt": _format_rfc3339(atx["expiresAt"]),
        "issuerDid": atx["issuerDid"],
        "issuerChain": list(atx["issuerChain"]),
    }
    if declared_purpose is not None:
        tbs["declaredPurpose"] = declared_purpose
    return tbs


def _controller_did(key_id: str) -> str:
    """DID portion of a keyId DID-URL (everything before the first '#')."""
    return key_id.split("#", 1)[0]


def _authority_set_for(atx: dict[str, Any], trusted_issuers: list[str]) -> set[str]:
    """DIDs whose keys may verify this credential's signatures: the issuer
    always, plus, under v1.1 only, each issuerChain authority that is ALSO in
    the verifier's trustedIssuers. The v1.1 issuerChain is covered by the
    signature, but it is signed by the very key whose eligibility is in
    question, so on its own it cannot vouch for that key: a chain DID the
    verifier does not trust contributes no eligible key. Without the
    intersection, a signer whose key is configured under a DID-URL keyId could
    name its own DID in the chain and sign for a trusted issuer
    (fixtures/v1_1-untrusted-chain-authority.json). The v1.0 issuerChain is
    unsigned and therefore forgeable, so it contributes no eligible key at
    all; only the issuer does.
    """
    authorities = {atx["issuerDid"]}
    if atx.get("atcVersion") == SUPPORTED_ATC_VERSION_V11:
        trusted = set(trusted_issuers)
        authorities.update(did for did in (atx.get("issuerChain") or []) if did in trusted)
    return authorities


def _decode_hex(text: str) -> bytes | None:
    """text decoded as Go's hex.DecodeString decodes it, or None where that
    returns an error."""
    if _HEX.fullmatch(text) is None:
        return None
    return bytes.fromhex(text)


def index_public_keys(refs: list[dict[str, Any]], authority_set: set[str]):
    # Key↔issuer binding: a key is eligible to verify a signature for this
    # credential only if its keyId's controller DID is in authority_set. A key
    # with no keyId is unbound (legacy single-issuer configs) and stays eligible.
    # refs are the verifierState public keys as _decode_fixture returns them.
    # A key whose hex or length is unusable is skipped, as the Go reference
    # verifier skips it.
    eds: list[Ed25519PublicKey] = []
    pqs: list[bytes] = []
    for r in refs:
        key_id = r["keyId"]
        if key_id and _controller_did(key_id) not in authority_set:
            continue
        if r["algorithm"] == "Ed25519":
            raw = _decode_hex(r["publicKeyHex"])
            if raw is None or len(raw) != 32:
                continue
            eds.append(Ed25519PublicKey.from_public_bytes(raw))
        elif r["algorithm"] == "ML-DSA-65":
            raw = _decode_hex(r["publicKeyHex"])
            if raw is None or len(raw) != MLDSA65_PUBLIC_KEY_SIZE:
                continue
            pqs.append(raw)
    return eds, pqs


def _finite_number(value: Any) -> bool:
    # A JSON boolean is not a number, although Python's bool is an int. An
    # integer too large for a float64 overflows, as it does in Go's decoder.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _holds_number_outside_float64(value: Any) -> bool:
    """True if the raw JSON value holds, at any depth, a number that is not
    finite as a float64. The Go reference verifier's JCS library parses each
    number it canonicalizes with strconv.ParseFloat, which refuses such a
    literal. Walked with a stack, not by recursion, so a value nested as deep
    as load_fixture allows is read whole."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, (int, float)) and not isinstance(item, bool) and not _finite_number(item):
            return True
    return False


def _first_unpaired_surrogate(value: Any) -> str | None:
    """The first unpaired UTF-16 surrogate in a string or member name of the
    raw JSON value, in the order the text writes them, or None. json.loads
    joins a high surrogate escape and the low one directly after it into one
    character and keeps every other surrogate escape as that surrogate, so
    each one found is an escape the Go reference verifier's
    unpairedSurrogateEscape finds; a byte of the file outside UTF-8 loads as
    U+FFFD (_go_replace), never as a surrogate. Walked with a stack, not by
    recursion, as _holds_number_outside_float64 is."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            found = _UNPAIRED_SURROGATE.search(item)
            if found is not None:
                return found.group()
        elif isinstance(item, dict):
            # Pushed last to first, so each name is read before its value and
            # the members in the order the text writes them.
            for name, member in reversed(list(item.items())):
                stack.append(member)
                stack.append(name)
        elif isinstance(item, list):
            stack.extend(reversed(item))
    return None


# The Go type of each credential member the Go reference verifier's atx struct
# declares. Members it holds as raw JSON (declaredPurpose, behavioralProfile,
# scanSummary) or does not declare (createdAt) are not decoded.
_MEMBER_TYPES = {
    "id": "string",
    "atcVersion": "string",
    "agentId": "string",
    "agentDid": "string",
    "publisher": "string",
    "publisherDid": "string",
    "version": "string",
    "contentHash": "string",
    "buildAttestation": "string",
    "transparencyLogIndex": "int64",
    "capabilities": "[]string",
    "trustScore": "float64",
    "trustLevel": "int64",
    "issuedAt": "time.Time",
    "expiresAt": "time.Time",
    "issuerDid": "string",
    "issuerChain": "[]string",
    "signatures": "[]signature",
    "revoked": "bool",
}

# The members the Go reference verifier's atx struct holds as raw JSON and
# decodes only when it projects the v1.1 signed payload, or never
# (declaredPurpose).
_RAW_MEMBERS = ("declaredPurpose", "behavioralProfile", "scanSummary")

# The Go type of each member of one signatures entry, of behavioralProfile as
# the Go verifier's projectBehavioralProfileV11 decodes it, of scanSummary as
# its tbsScanSummaryV11 does, and of a fixture's expected object.
_SIGNATURE_TYPES = {"keyId": "string", "algorithm": "string", "value": "string"}
_BEHAVIORAL_PROFILE_TYPES = {
    "checksum": "string",
    "generatedAt": "time.Time",
    "observationDays": "int64",
}
_SCAN_SUMMARY_TYPES = {
    "hma": "string",
    "criticalFindings": "int64",
    "highFindings": "int64",
    "secretless": "string",
    "cryptoServe": "string",
    "oasbLevel": "string",
}
_EXPECTED_TYPES = {
    "verifyResult": "string",
    "rejectCategory": "string",
    "reasonContains": "string",
}

# The Go reference verifier's fixture struct, which holds atx as raw JSON, and
# the structs of its verifier state and key references.
_FIXTURE_TYPES = {
    "name": "string",
    "description": "string",
    "keypairRefs": "[]keypairRef",
    "verifierState": "verifierState",
    "expected": "expectedOutcome",
}
_VERIFIER_STATE_TYPES = {
    "clockRfc3339": "string",
    "trustedIssuers": "[]string",
    "publicKeys": "[]keypairRef",
    "requiredSignatures": "*int64",
    "crl": "*crl",
}
_KEYPAIR_REF_TYPES = {
    "role": "string",
    "path": "string",
    "algorithm": "string",
    "publicKeyHex": "string",
    "keyId": "string",
}
_CRL_TYPES = {
    "version": "int64",
    "issuedAt": "time.Time",
    "nextUpdate": "time.Time",
    "entries": "[]crlEntry",
    "signature": "string",
}
_CRL_ENTRY_TYPES = {"agentId": "string", "revokedAt": "time.Time", "reason": "string"}

# Each struct type above by its Go name. A go_type of "[]T" is a slice of T,
# and "*T" a pointer to T, which a null leaves nil (None).
_STRUCT_TYPES = {
    "signature": _SIGNATURE_TYPES,
    "verifierState": _VERIFIER_STATE_TYPES,
    "keypairRef": _KEYPAIR_REF_TYPES,
    "crl": _CRL_TYPES,
    "crlEntry": _CRL_ENTRY_TYPES,
    "expectedOutcome": _EXPECTED_TYPES,
}

# The atx of a fixture that has none, which the Go fixture struct holds as no
# bytes at all.
_ABSENT = object()


class _DecodeError(ValueError):
    """A member holds a value outside its Go type."""


class _EscapedString(str):
    """A string value whose JSON literal carries a backslash escape, as
    load_fixture marks it. The Go reference verifier decodes every timestamp
    with time.Time's own UnmarshalJSON, which parses the bytes between the
    quotes under every Go release, so it refuses a timestamp written with
    one; every other reader takes the decoded string."""

    __slots__ = ()


class _NegativeZero(int):
    """The JSON number -0, which json.loads reads as the integer 0, as
    load_fixture marks it. Go's float64 decode keeps the sign."""

    __slots__ = ()


class _LongInteger(float):
    """A JSON integer with more digits than int() converts, as load_fixture
    marks it: from Python 3.11 int() refuses a literal of more than
    sys.get_int_max_str_digits() digits, 4300 unless the interpreter is set
    otherwise and never fewer than 640. Go's encoding/json loads such a
    number, and it is out of range for every member the Go reference verifier
    decodes into an int64 or a float64, so its value is never needed. It is
    held as the infinity a float literal that large (1e5000) loads as, and
    written as its literal."""

    __slots__ = ("literal",)

    def __new__(cls, literal: str) -> "_LongInteger":
        number = super().__new__(cls, "-inf" if literal.startswith("-") else "inf")
        number.literal = literal
        return number

    def __repr__(self) -> str:
        return self.literal


# The levels of arrays and objects a decode error writes out. On Python 3.11,
# 3.12 and 3.13, repr() raises RecursionError on a value nested short of the
# 10000 levels Go's encoding/json decodes, where the Go reference verifier's
# error names the member and not its value.
_REPR_DEPTH = 8


def _value_repr(value: Any, depth: int = _REPR_DEPTH) -> str:
    """repr(value) for a value as load_fixture loads it, with each non-empty
    array or object more than depth levels down written as [...] or {...}."""
    if isinstance(value, list) and value:
        if depth == 0:
            return "[...]"
        return "[" + ", ".join(_value_repr(item, depth - 1) for item in value) + "]"
    if isinstance(value, dict) and value:
        if depth == 0:
            return "{...}"
        members = (f"{key!r}: {_value_repr(item, depth - 1)}" for key, item in value.items())
        return "{" + ", ".join(members) + "}"
    return repr(value)


def _decode_member(name: str, go_type: str, value: Any) -> Any:
    """Type-check one member against go_type, its type in the Go reference
    verifier, and return the value Go's encoding/json decodes it to, or raise
    _DecodeError. A null takes the Go zero value; a timestamp decodes to an
    _Instant, a struct (a name in _STRUCT_TYPES) to a dict of its members."""
    if go_type == "string":
        if value is None:
            return ""
        if isinstance(value, str):
            return _go_string(value)
        raise _DecodeError(f"{name} {_value_repr(value)} is not a JSON string")
    if go_type == "int64":
        if value is None:
            return 0
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and _INT64_MIN <= value <= _INT64_MAX
        ):
            return int(value)
        raise _DecodeError(f"{name} {_value_repr(value)} is not a JSON integer in int64 range")
    if go_type == "float64":
        if value is None:
            return 0.0
        if isinstance(value, _NegativeZero):
            return -0.0
        if _finite_number(value):
            return float(value)
        raise _DecodeError(f"{name} {_value_repr(value)} is not a finite JSON number")
    if go_type == "bool":
        if value is None or isinstance(value, bool):
            return bool(value)
        raise _DecodeError(f"{name} {_value_repr(value)} is not a JSON boolean")
    if go_type == "time.Time":
        if value is None:
            return _GO_ZERO_TIME
        try:
            if isinstance(value, _EscapedString):
                raise ValueError("written with a JSON escape")
            return _parse_rfc3339(value)
        except ValueError as exc:
            raise _DecodeError(f"{name} {_value_repr(value)} is not an RFC 3339 date-time ({exc})") from None
    if go_type.startswith("*"):
        return None if value is None else _decode_member(name, go_type[1:], value)
    if go_type.startswith("[]"):
        if value is None:
            return []
        if not isinstance(value, list):
            raise _DecodeError(f"{name} {_value_repr(value)} is not a JSON array")
        return [_decode_member(f"{name}[{i}]", go_type[2:], item) for i, item in enumerate(value)]
    # A struct. A null leaves every member at its zero value.
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise _DecodeError(f"{name} {_value_repr(value)} is not a JSON object")
    return _decode_members(_STRUCT_TYPES[go_type], value, f"{name}.")


def _members_by_folded_name(value: dict[str, Any]) -> dict[str, list[Any]]:
    """The members of a JSON object under the name folding Go's encoding/json
    matches a member to a struct field with: "Revoked" and "REVOKED" are the
    member "revoked". Each folded name maps to the value of every member
    whose name folds to it, in document order for an object load_fixture
    built (dict order otherwise), so a member written twice, under one name
    or two, has two values. Go's encoding/json decodes each one into the
    field. The strict parse has already refused a credential in which two
    names fold together."""
    names = getattr(value, "names", None)
    if names is None:
        pairs = value.items()
    else:
        shadowed = value.shadowed or {}
        pairs = ((key, shadowed[i] if i in shadowed else value[key]) for i, key in enumerate(names))
    members: dict[str, list[Any]] = {}
    for key, member in pairs:
        members.setdefault(_fold_key(_go_string(key)), []).append(member)
    return members


def _decode_members(
    types: dict[str, str], value: dict[str, Any], prefix: str = "", lenient: bool = False
) -> dict[str, Any]:
    """Each member named in types, decoded from the JSON object value as Go's
    encoding/json decodes it into a struct field of that type: matched by
    folded name, the zero value when absent. A member written more than once
    is decoded each time, in document order, and holds the last value. A
    value outside the member's type raises _DecodeError, the first value of
    a repeated member included, which Go reports after decoding the later
    one. With lenient such a value leaves the member at the value decoded
    before it, the zero value when there is none, which is what a Go caller
    that ignores the decode error is left with."""
    members = _members_by_folded_name(value)
    decoded = {}
    for name, go_type in types.items():
        decoded[name] = _decode_member(prefix + name, go_type, None)
        for member in members.get(_fold_key(name), ()):
            try:
                decoded[name] = _decode_member(prefix + name, go_type, member)
            except _DecodeError:
                if not lenient:
                    raise
    return decoded


# The reason a v1.1 credential whose scanSummary _decode_scan_summary refuses
# rejects with, the Go reference verifier's text, which names no Go decode
# error, so a report over the fixtures reads the same under every Go release.
_SCAN_SUMMARY_UNSIGNED = "no signature covers scanSummary, which holds a member outside its type or is not an object"


def _decode_scan_summary(scan: Any, lenient: bool = False) -> dict[str, Any]:
    """scanSummary as the Go reference verifier's decodeScanSummaryV11 decodes
    it into the six members the v1.1 signed payload holds, each the zero value
    when it is absent or null, as is all of an absent or null scanSummary. A
    member outside its type, or a scanSummary that is not an object, raises
    _DecodeError. With lenient, as in the Go verifier's projectScanSummaryV11,
    such a member keeps the value decoded before it, the zero value when
    there is none, and a scanSummary that is not an object leaves all six at
    the zero value."""
    if scan is None:
        scan = {}
    if not isinstance(scan, dict):
        if not lenient:
            raise _DecodeError(f"scanSummary {_value_repr(scan)} is not a JSON object")
        scan = {}
    return _decode_members(_SCAN_SUMMARY_TYPES, scan, "scanSummary.", lenient=lenient)


def _decode_credential(atx: Any) -> dict[str, Any]:
    """The credential as the Go reference verifier's atx struct holds it, or
    raise _DecodeError. Each member in _MEMBER_TYPES is type-checked against
    its field and holds the value Go's encoding/json decodes it to: the Go
    zero value when it is absent or null, an _Instant for a timestamp, U+FFFD
    for an unpaired UTF-16 surrogate escape in a string, -0.0 for a trustScore
    written as -0. Each member in _RAW_MEMBERS holds its JSON value as loaded,
    None when absent. A member is matched by its name under Go's case
    folding, so "Revoked" is read as revoked. Other members are copied
    unchanged.

    The Go reference verifier rejects a member outside its type as PARSE_ERROR
    before interpreting any field, and so does this one, instead of raising
    from float(), int() or iteration later.
    """
    if atx is None:
        atx = {}
    if not isinstance(atx, dict):
        raise _DecodeError(f"credential {_value_repr(atx)} is not a JSON object")
    decoded = dict(atx)
    decoded.update(_decode_members(_MEMBER_TYPES, atx))
    members = _members_by_folded_name(atx)
    for name in _RAW_MEMBERS:
        decoded[name] = members.get(_fold_key(name), [None])[-1]
    return decoded


def _decode_fixture(fixture: Any) -> dict[str, Any]:
    """The fixture as the Go reference verifier's fixture struct holds it, or
    raise ValueError: the Go verifier fails to load such a file. Each member
    in _FIXTURE_TYPES is decoded as _decode_member decodes it, matched by
    folded name; atx, which the struct holds as raw JSON, is the value as
    loaded, or _ABSENT when the fixture has none. A null fixture is the zero
    value, as it is in Go."""
    if fixture is None:
        fixture = {}
    if not isinstance(fixture, dict):
        raise ValueError("fixture is not a JSON object")
    decoded = _decode_members(_FIXTURE_TYPES, fixture)
    decoded["atx"] = _members_by_folded_name(fixture).get("atx", [_ABSENT])[-1]
    return decoded


def _expected_outcome(fixture: Any) -> dict[str, str]:
    """The fixture's expected member as the Go reference verifier's
    expectedOutcome struct holds it: verifyResult, rejectCategory and
    reasonContains, each "" when absent or null. The whole fixture is
    decoded, so this raises ValueError for any fixture _decode_fixture
    refuses, such as one whose expected member is not a JSON object or holds
    a member that is not a string.

    It raises ValueError too for a file with no expected outcome the fixture
    format allows (schemas/fixture-v1.schema.json), which is not a fixture
    and fails to load in the Go reference verifier as well: its expected
    member or expected.verifyResult is absent or null, or its verifyResult is
    a string other than ACCEPT or REJECT, "accept" among them. Read as
    "expect REJECT", such a file passed whenever its credential rejected, and
    {} or a package.json rejects at parse. The check reads the last expected
    member and the last verifyResult in it, the values decoded here."""
    expected = _decode_fixture(fixture)["expected"]
    member = _members_by_folded_name(fixture or {}).get(_fold_key("expected"), [None])[-1]
    if member is None:
        raise ValueError("no expected member")
    if _members_by_folded_name(member).get(_fold_key("verifyResult"), [None])[-1] is None:
        raise ValueError("no expected.verifyResult")
    if expected["verifyResult"] not in ("ACCEPT", "REJECT"):
        raise ValueError(f"expected.verifyResult {_go_quote(expected['verifyResult'])} is not ACCEPT or REJECT")
    return expected


def _decode_base64(value: str) -> bytes:
    """Decode a signature value as Go's base64.StdEncoding.DecodeString does,
    or raise ValueError: CR and LF are skipped, and any other character
    outside the padded standard alphabet is refused, where base64.b64decode
    discards it."""
    text = value.replace("\r", "").replace("\n", "")
    if _BASE64.fullmatch(text) is None:
        raise ValueError("illegal base64 data")
    return base64.b64decode(text)


def _scalars(value: Any):
    """Each (container, key) in value that holds a scalar, at any depth and
    without recursion, so a deeply nested document does not exhaust the
    stack. The members of an object load_fixture built that a later member
    of the same name replaced are walked in its shadowed dict."""
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            keys = list(node)
            if getattr(node, "shadowed", None):
                pending.append(node.shadowed)
        elif isinstance(node, list):
            keys = range(len(node))
        else:
            continue
        for key in keys:
            if isinstance(node[key], (dict, list)):
                pending.append(node[key])
            else:
                yield node, key


def verify_fixture(fixture: dict[str, Any]) -> VerifyResult:
    # The Go reference verifier decodes the verifier state into typed fields,
    # so its strings are read the way the credential's are: the CRL's agentId
    # and the trusted issuers are compared with decoded credential members.
    # Raises ValueError for a fixture that verifier fails to load.
    wrapper = _decode_fixture(fixture)
    vs = wrapper["verifierState"]
    atx = wrapper["atx"]
    if atx is _ABSENT:
        # A fixture with no atx member, such as one of another conformance
        # suite, has no credential to parse. The reason quotes its $schema
        # when that is a string, as the Go reference verifier's noATXReason
        # does; the member is matched by folded name, the last one read.
        reason = "the fixture has no atx member"
        schema = _members_by_folded_name(fixture or {}).get(_fold_key("$schema"), [None])[-1]
        if isinstance(schema, str):
            reason += f" (its $schema is {_go_quote(schema)})"
        return VerifyResult(reject_category="PARSE_ERROR", reason=reason)

    # Step 0: strict parse. A duplicate member at any depth of the CREDENTIAL
    # rejects before any field is interpreted (see module docstring). The
    # fixture wrapper stays lenient: only the atx subtree is consulted.
    dup = _subtree_duplicate(atx)
    if dup is not None:
        return VerifyResult(
            reject_category="PARSE_ERROR",
            reason=f"credential contains duplicate member {_go_quote(dup)} (strict parse: the whole ATX credential is a signed body; RFC 8259 §4 duplicate names are parser-divergent)",
        )
    try:
        atx = _decode_credential(atx)
    except _DecodeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))

    try:
        now = _parse_rfc3339(vs["clockRfc3339"])
    except ValueError as exc:
        return VerifyResult(reject_category="VERIFIER_CONFIG_ERROR", reason=f"bad clockRfc3339: {exc}")

    # A threshold is verifier configuration, as the clock is: one the fixture
    # format does not allow (schemas/fixture-v1.schema.json: an integer of at
    # least 1) is reported before any step reads the credential. None, the
    # member absent or null, sets no threshold.
    required = vs["requiredSignatures"]
    if required is not None and required < 1:
        return VerifyResult(
            reject_category="VERIFIER_CONFIG_ERROR",
            reason=f"bad requiredSignatures: {required} is not a positive integer",
        )

    # Step 1: schema version. Dispatch on atcVersion: "1.0" verifies the legacy
    # pipe form, "1.1" verifies JCS(TBS) (atx-spec §1.3a).
    version = atx.get("atcVersion")
    if version not in (SUPPORTED_ATC_VERSION, SUPPORTED_ATC_VERSION_V11):
        return VerifyResult(
            reject_category="UNSUPPORTED_VERSION",
            reason=f"unsupported atcVersion {_go_quote(version)} (this verifier supports {SUPPORTED_ATC_VERSION} and {SUPPORTED_ATC_VERSION_V11})",
        )

    # Step 2: expiry.
    expires = atx["expiresAt"]
    if now > expires:
        return VerifyResult(
            reject_category="EXPIRED",
            reason=f"expired at {_format_rfc3339(expires)}, verifier clock is {_format_rfc3339(now)}",
        )

    # Step 3: revocation.
    if atx["revoked"]:
        return VerifyResult(reject_category="REVOKED", reason="credential revoked field is true")
    crl = vs["crl"]
    if crl is not None:
        for entry in crl["entries"]:
            if entry["agentId"] == atx["agentId"]:
                return VerifyResult(
                    reject_category="REVOKED",
                    reason=f"agent appears on CRL: {entry['reason']}",
                )

    # Step 4: issuer trust.
    if atx["issuerDid"] not in vs["trustedIssuers"]:
        return VerifyResult(
            reject_category="UNTRUSTED_ISSUER",
            reason=f"issuer DID {atx['issuerDid']} is not in the verifier's trusted set (untrusted issuer)",
        )

    # Step 5: signature verification.
    # Spec mandate: every declared signature MUST verify.
    if version == SUPPORTED_ATC_VERSION_V11:
        # scanSummary enters the TBS as six typed members (atx-spec §1.3a.2
        # rule 2). A member outside its type, or a scanSummary that is not an
        # object, has no value there, so no signature covers the credential:
        # the projection would leave it at its zero value, and a signature
        # over that zero value would verify a credential carrying another.
        # The Go reference verifier rejects it here too, before the checks
        # below.
        try:
            _decode_scan_summary(atx.get("scanSummary"))
        except _DecodeError:
            return VerifyResult(reject_category="SIGNATURE_INVALID", reason=_SCAN_SUMMARY_UNSIGNED)
        surrogate = _first_unpaired_surrogate(atx.get("declaredPurpose"))
        if surrogate is not None:
            # declaredPurpose enters the TBS as written, and RFC 8785
            # §3.2.2.2 refuses a string holding a lone surrogate. The Go
            # reference verifier refuses the escape before it canonicalizes
            # the TBS, and so does this one: a number beside it that this
            # serializer cannot write (1.5) would otherwise leave no payload,
            # and the credential would reject as SIGNATURE_INVALID. The
            # reason is the Go verifier's, which repeats the escape as
            # written; this one writes its hex digits in lower case.
            return VerifyResult(
                reject_category="VERIFIER_CONFIG_ERROR",
                reason="v1.1 canonicalization failed: declaredPurpose holds an unpaired "
                f"UTF-16 surrogate escape (\\u{ord(surrogate):04x})",
            )
        if _holds_number_outside_float64(atx.get("declaredPurpose")):
            # declaredPurpose enters the TBS as written, so no typed decode
            # refuses the number first. The Go reference verifier's JCS
            # library cannot canonicalize it and the verifier reports the
            # category below, where this serializer would refuse it as a
            # float (1e400) or write it out (an integer of 401 digits).
            return VerifyResult(
                reject_category="VERIFIER_CONFIG_ERROR",
                reason="v1.1 canonicalization failed: declaredPurpose holds a number outside the float64 range",
            )
        tbs = _tbs_v11(atx)
        outside = _integer_outside_exact_range(tbs)
        if outside is not None:
            # The Go reference verifier's JCS library writes such an integer
            # as the IEEE 754 double nearest it, which other integers can
            # share (9007199254740993 and 9007199254740992 are written
            # alike), so a signature over those bytes does not tell them
            # apart; this serializer refuses it. The Go verifier refuses it
            # once its canonicalization succeeds, which is after the two
            # checks above, and the reason is its.
            where, integer = outside
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"no signature covers {where}: the integer {integer} is outside the I-JSON exact range, -(2^53-1) to 2^53-1",
            )
        try:
            payload = _jcs_canonicalize(tbs)
        except NotImplementedError:
            # The vendored JCS serializer refuses non-integer numbers
            # (rfc8785.py); a schema-valid v1.1 TBS carries none. One can still
            # arrive in content the signer never signed, e.g. a number
            # injected into declaredPurpose, which enters the TBS verbatim
            # (fixtures/v1_1-declared-purpose-number-injected.json). Without
            # the canonical bytes no declared signature can verify, so the
            # loop below runs with no key to verify against, instead of
            # raising out of the run. On content the signer never signed, each
            # signature then fails with the reason the Go reference verifier
            # writes: it canonicalizes the number, and the signature does not
            # verify over those bytes.
            payload = None
        except UnicodeEncodeError as exc:
            # Every decoded member holds U+FFFD where an unpaired surrogate
            # was escaped, so this is declaredPurpose, which enters the TBS as
            # written. The Go reference verifier refuses an unpaired surrogate
            # escape in it, alone or followed by another \u escape, before its
            # JCS library reads it, and reports the category below.
            return VerifyResult(
                reject_category="VERIFIER_CONFIG_ERROR",
                reason=f"v1.1 canonicalization failed: declaredPurpose holds an unpaired UTF-16 surrogate ({exc})",
            )
    else:
        payload = canonical_payload(atx)
    eds, pqs = index_public_keys(vs["publicKeys"], _authority_set_for(atx, vs["trustedIssuers"]))
    if payload is None:
        # No key verifies a signature over bytes the serializer cannot write.
        eds, pqs = [], []
    result = VerifyResult(sigs_expected=len(atx["signatures"]))
    # The raw bytes of each Ed25519 key a declared signature verified under,
    # for the requiredSignatures count below.
    ed_signers: set[bytes] = set()

    for sig in atx["signatures"]:
        try:
            sig_bytes = _decode_base64(sig["value"])
        except ValueError as exc:
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"signature {sig.get('keyId')} has invalid base64: {exc}",
            )

        if sig["algorithm"] == "Ed25519":
            verified = False
            for pk in eds:
                try:
                    pk.verify(sig_bytes, payload)
                    verified = True
                    ed_signers.add(pk.public_bytes_raw())
                    break
                except InvalidSignature:
                    continue
            if not verified:
                return VerifyResult(
                    reject_category="SIGNATURE_INVALID",
                    reason=f"Ed25519 signature {sig.get('keyId')} did not verify against any configured public key",
                )
            result.ed25519_valid = True
            result.sigs_valid += 1
        elif sig["algorithm"] == "ML-DSA-65":
            verified = False
            for pk in pqs:
                if ML_DSA_65.verify(pk, payload, sig_bytes):
                    verified = True
                    break
            if not verified:
                return VerifyResult(
                    reject_category="SIGNATURE_INVALID",
                    reason=f"ML-DSA-65 signature {sig.get('keyId')} did not verify against any configured public key",
                )
            result.mldsa65_valid = True
            result.sigs_valid += 1
        else:
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"unsupported signature algorithm {sig['algorithm']}",
            )

    if result.sigs_valid == 0:
        return VerifyResult(reject_category="SIGNATURE_INVALID", reason="no valid signatures")

    # Ed25519 companion (core.md section 13, Cryptographic agility): a
    # credential that declares an ML-DSA-65 entry MUST also carry a verifying
    # Ed25519 entry, so a post-quantum signature alone never verifies a
    # credential (fixtures/v1_1-hybrid-pq-only.json).
    if result.mldsa65_valid and not result.ed25519_valid:
        return VerifyResult(
            reject_category="SIGNATURE_INVALID",
            reason="ML-DSA-65 signature declared without a verifying Ed25519 signature (an ML-DSA-65 entry requires an Ed25519 companion)",
        )

    # Signature threshold (core.md section 3.1 step 8, cosignatures from 2 of
    # 3 key holders): with requiredSignatures set, the declared Ed25519
    # signatures must have verified under at least that many distinct keys.
    # A key counts once however many signatures verify under it, whatever
    # keyId they carry, the rule section 1.3 step 7 states for its count.
    # Section 1.3a.2 names the Ed25519 signatures the threshold signatures and
    # the ML-DSA-65 one the hybrid signature, so an ML-DSA-65 signature does
    # not count (fixtures/threshold-1of3-cosignature.json).
    if required is not None and len(ed_signers) < required:
        return VerifyResult(
            reject_category="SIGNATURE_INVALID",
            reason=f"signature threshold not met: requiredSignatures is {required}, distinct Ed25519 keys that verified a declared signature: {len(ed_signers)}",
        )

    # Step 7 (distinct signer-authority count for trust level 3+) is NOT
    # performed by this verifier: no fixture carries verified signatures from
    # more than one authority, and core.md section 1.3 step 7 forbids counting
    # the length of issuerChain, which the signer writes. Recorded on the
    # result so an ACCEPT never reads as a step-7 verdict.
    result.step7_performed = False
    result.trust_level = atx["trustLevel"]

    result.accepted = True
    return result


def _reject_constant(name: str) -> Any:
    # json.loads accepts NaN, Infinity and -Infinity by default; RFC 8259 §6
    # has none of them, and the Go reference verifier fails to load them.
    raise ValueError(f"{name} is not a JSON value (RFC 8259 §6)")


def _parse_int(literal: str) -> int | _LongInteger:
    if literal == "-0":
        return _NegativeZero()
    try:
        return int(literal)
    except ValueError:
        # json.loads passes the literal of a JSON integer, which int() refuses
        # for the count of its digits alone.
        return _LongInteger(literal)


def _go_replace(exc: UnicodeError) -> tuple[str, int]:
    # Go's encoding/json decodes each byte of an invalid UTF-8 sequence inside
    # a string to U+FFFD. The decoder reports a sequence a maximal subpart at a
    # time (a lead byte and the continuation bytes after it), every byte of
    # which Go replaces on its own. Outside a string the U+FFFD is a syntax
    # error, as the byte is in Go.
    if not isinstance(exc, UnicodeDecodeError):
        raise exc
    return _REPLACEMENT_CHARACTER * (exc.end - exc.start), exc.end


codecs.register_error(_GO_UTF8_ERRORS, _go_replace)


def _string_literals(text: str) -> list[tuple[int, int, bool]]:
    """Each JSON string literal of text in document order, as (start, end,
    is_name), found in one pass: a literal is matched once, from its opening
    quote, and an unterminated one ends the pass, since the rest of the text
    is inside it. A regular expression searched over the whole text would
    instead retry from every quote inside an unterminated literal, which
    takes quadratic time. Raises ValueError where arrays and objects nest
    deeper than Go's encoding/json decodes; the Go verifier fails to load
    such a file."""
    literals = []
    depth = pos = 0
    while True:
        start = text.find('"', pos)
        for bracket in _BRACKET.finditer(text, pos, len(text) if start < 0 else start):
            if bracket.group() in "[{":
                depth += 1
                if depth > _GO_MAX_DEPTH:
                    raise ValueError(
                        f"arrays and objects nested deeper than {_GO_MAX_DEPTH} levels "
                        "(the limit of Go's encoding/json)"
                    )
            else:
                depth -= 1
        if start < 0:
            return literals
        rest = _STRING_REST.match(text, start + 1)
        if rest is None:
            return literals
        is_name = rest.group(1) is not None
        literals.append((start, rest.start(1) if is_name else rest.end(), is_name))
        pos = rest.end()


def _escaped_values_nulled(text: str, literals: list[tuple[int, int, bool]]) -> str:
    """text with each string value written with a backslash escape replaced
    by null. A member name keeps its literal, so a parse of the result builds
    the same objects with the same members as a parse of text."""
    pieces = []
    pos = 0
    for start, end, is_name in literals:
        if not is_name and text.find("\\", start, end) >= 0:
            pieces += (text[pos:start], "null")
            pos = end
    pieces.append(text[pos:])
    return "".join(pieces)


def _parse_json(text: str, **hooks: Any) -> Any:
    """json.loads(text, **hooks). Where the C scanner of json.loads runs out
    of nesting depth before Go's encoding/json does (on Python 3.12 and 3.13
    it stops short of 10000 levels), the text is parsed again by the
    pure-Python scanner with the recursion limit raised to cover Go's depth.
    From Python 3.11 a call from Python code to a Python function takes no C
    stack, and that scanner makes no other call that recurses, so the raised
    limit is safe; an earlier release keeps the RecursionError."""
    try:
        return json.loads(text, **hooks)
    except RecursionError:
        if sys.version_info < (3, 11):
            raise
    decoder = json.JSONDecoder(**hooks)
    decoder.scan_once = py_make_scanner(decoder)
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, 3 * _GO_MAX_DEPTH))
    try:
        return decoder.decode(text)
    finally:
        sys.setrecursionlimit(limit)


def _read_file(path: str) -> bytes:
    """The bytes of the file at path, as the Go reference verifier's
    os.ReadFile reads them, or OSError worded as the error it returns: the
    step that failed and path as spelled (_go_path_error). Run as a user
    other than root, that is `open d/x.json: permission denied` for a file
    of mode 000, and `read l/link.json: is a directory` for a symbolic link
    to a directory, which os.ReadFile opens and fails to read and Python's
    open refuses. Path.read_bytes raised
    `[Errno 13] Permission denied: 'd/x.json'`, the path quoted through
    repr, which writes the byte 0xff of a path that is not UTF-8 as the six
    characters \\udcff, so the load-error line named such a file once by
    its bytes and once by those characters."""
    try:
        f = open(path, "rb")
    except IsADirectoryError as exc:
        raise _go_path_error("read", path, exc) from None
    except OSError as exc:
        raise _go_path_error("open", path, exc) from None
    with f:
        try:
            return f.read()
        except OSError as exc:
            raise _go_path_error("read", path, exc) from None


def load_fixture(path: str | os.PathLike[str]) -> dict[str, Any]:
    """The fixture file at path as the Go reference verifier's json.Unmarshal
    reads it, before its members are decoded (_decode_fixture). Raises
    ValueError where Go fails to load the file, and OSError, worded as Go
    words it, where the file cannot be read (_read_file)."""
    text = _read_file(os.fspath(path)).decode("utf-8", _GO_UTF8_ERRORS)
    literals = _string_literals(text)
    # The duplicate-marking hook preserves last-wins values (plain dict
    # semantics) while recording duplicates for the strict-parse check in
    # verify_fixture, which consults only the atx subtree.
    try:
        fixture = _parse_json(
            text,
            object_pairs_hook=_dup_marking_pairs,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
        )
    except json.JSONDecodeError:
        # The Go reference verifier's wording for a syntax error; the
        # decoders' own texts and positions differ.
        raise ValueError("fixture is not valid JSON") from None
    # json.loads does not say which strings were written with an escape, and
    # the Go reference verifier's timestamp decoder refuses a timestamp that
    # was. A second parse, with each such string value replaced by null, has
    # the same shape as the first, down to the members a later member of the
    # same name replaced, since it builds its objects with the same hook. It
    # holds null at each of those values and also at every null of the
    # document, where the first parse holds None and not a string: the
    # isinstance test below is what keeps a literal null from being taken
    # for an escaped string. It reads integers as the first parse does, so
    # one int() refuses does not fail it either.
    shadow = _parse_json(
        _escaped_values_nulled(text, literals),
        object_pairs_hook=_dup_marking_pairs,
        parse_int=_parse_int,
    )
    for (node, key), (other, _) in zip(_scalars(fixture), _scalars(shadow)):
        if other[key] is None and isinstance(node[key], str):
            node[key] = _EscapedString(node[key])
    return fixture


def _go_clean(path: str) -> str:
    """path cleaned as Go's filepath.Clean cleans it: os.path.normpath,
    except that normpath keeps the two slashes a path may begin with and
    Clean writes one."""
    cleaned = os.path.normpath(path)
    return cleaned[1:] if cleaned.startswith("//") else cleaned


def _go_join(directory: str, name: str) -> str:
    """directory and name joined as Go's filepath.Join joins them, which
    cleans the result as filepath.Clean does."""
    return _go_clean(os.path.join(directory, name))


def _spelled_join(directory: str, name: str) -> str:
    """name joined onto directory as directory is spelled, with one
    separator between."""
    return directory + name if directory[-1:] in (os.sep, os.altsep) else directory + os.sep + name


def _cleans_to_itself(directory: str, st: os.stat_result) -> bool:
    """Whether directory, cleaned as Go's filepath.Clean cleans it, names
    the directory it names, st being os.stat(directory). Clean removes a ..
    with the element before it, and the operating system resolves that
    element before it applies the .., so where the element is a symbolic
    link the two name different directories."""
    try:
        return os.path.samestat(st, os.stat(_go_clean(directory)))
    except OSError:
        return False


def _go_path_error(op: str, path: str, exc: OSError) -> OSError:
    """exc worded as the Go reference verifier writes the error of op on
    path, its reason lowercase: `stat d/x.json/: not a directory`."""
    reason = exc.strerror or str(exc)
    return OSError(f"{op} {path}: {reason[:1].lower()}{reason[1:]}")


def _json_names(directory: str) -> list[str]:
    """The names of the entries of directory that end in .json and are not
    directories, the entries of os.ReadDir the Go reference verifier's
    expandFixturePaths keeps. Each entry's own type decides, so a symbolic
    link named *.json is kept whatever it links to, and a link to a
    directory then fails to load, as it does there. Path.glob("*.json")
    gave a subdirectory named *.json too, which then failed to load. A
    directory os.scandir cannot open raises the error os.ReadDir returns
    there, `open locked: permission denied` for a directory of mode 000
    run as a user other than root. It gave no name, and the run wrote
    `no fixture *.json files found`."""
    try:
        it = os.scandir(directory)
    except OSError as exc:
        raise _go_path_error("open", directory, exc) from None
    with it:
        entries = list(it)
    return [e.name for e in entries
            if e.name.endswith(".json") and not e.is_dir(follow_symlinks=False)]


# What the line for an argument that names no file adds when the argument is
# a word an option spells, as the Go reference verifier adds it.
_MISSING_PATH_HINTS = {
    "help": " (--help prints the usage)",
    "version": " (--version prints the version line)",
}


def expand_paths(args: list[str]) -> list[str]:
    """expand_fixture_dirs without the directories."""
    return expand_fixture_dirs(args)[0]


def expand_fixture_dirs(args: list[str]) -> tuple[list[str], list[str]]:
    """The fixture files args name, and each directory listed for them in
    argument order, as the Go reference verifier's expandFixtureDirs
    returns them: a directory argument, or its fixtures directory. The
    files are spelled as the Go reference verifier's
    expandFixturePaths spells them: a file as its argument spells it, ./ and
    // included, and a *.json file of a directory as _go_join writes the
    directory and the file's name, or, where the directory cleaned names
    another directory, as _spelled_join writes them. Each name is also the
    path the file is read from. An argument is read as the string it is,
    not as a Path, which drops a ./ and a trailing / and collapses a //."""
    out: list[str] = []
    dirs: list[str] = []
    for a in args:
        try:
            st = os.stat(a)
        except FileNotFoundError:
            hint = _MISSING_PATH_HINTS.get(a, "")
            raise FileNotFoundError(f"{a}: no such file or directory{hint}") from None
        except OSError as exc:
            # Go's os.Stat error as the Go reference verifier writes it:
            # `stat d/x.json/: not a directory` for a file named with a
            # trailing /.
            raise _go_path_error("stat", a, exc) from None
        if stat.S_ISDIR(st.st_mode):
            # The Go reference verifier's dirJoin: with d/link a symbolic
            # link to elsewhere/deep, d/link/.. lists elsewhere, and its
            # other.json is d/link/../other.json, not d/other.json.
            join = _go_join if _cleans_to_itself(a, st) else _spelled_join
            fixtures_dir = join(a, "fixtures")
            target = fixtures_dir if os.path.isdir(fixtures_dir) else a
            out.extend(join(target, name) for name in _json_names(target))
            dirs.append(target)
        else:
            out.append(a)
    # A path named twice is verified twice, as the Go reference verifier
    # verifies it, and the names sort byte by byte, as its sort.Strings sorts
    # them: ./d/x.json before d/./x.json before d//x.json.
    return sorted(out, key=os.fsencode), dirs


def _rel_path(path: str) -> str:
    """The name the report gives the fixture at path, as the Go reference
    verifier's relPath gives it: the path relative to the working directory,
    cleaned as filepath.Rel cleans it, when path is an absolute path under
    it, and path as given otherwise. The working directory and the directory
    holding path are compared with their symbolic links resolved, as the Go
    reference verifier compares them, so a path written through a link to
    the working directory and one written through its target get the same
    name. The directory is resolved as path spells it, each .. applied
    after the element before it is resolved, as the operating system
    applies it when it reads path. Cleaned first, as filepath.Dir cleans
    it, the directory of $PWD/d/link/../x.json, with d/link a link to
    elsewhere/deep, was $PWD/d, and the file was named d/x.json while
    elsewhere/x.json was read."""
    if not os.path.isabs(path):
        return path
    try:
        cwd = os.path.realpath(os.getcwd())
        directory = os.path.realpath(os.path.dirname(path))
        rel = os.path.relpath(os.path.join(directory, os.path.basename(path)), cwd)
    except (OSError, ValueError):
        return path
    if rel != os.pardir and not rel.startswith(os.pardir + os.sep):
        return rel
    return path


# A run of surrogate escapes, U+DC80 to U+DCFF: os.fsdecode, and so sys.argv
# and os.scandir, hold each byte of a path that does not decode as one, the
# byte 0xff as \udcff.
_SURROGATE_ESCAPES = re.compile("([\udc80-\udcff]+)")


def _say(text: str, end: str = "\n") -> None:
    """print() for a line that quotes a fixture or its path. A character
    standard output cannot encode, an unpaired surrogate for one, is written
    as a backslash escape instead of raising and ending the run, except a
    surrogate escape where standard output writes it as the byte it stands
    for (errors="surrogateescape"), as main sets it to before the first
    report line. sys.argv and os.scandir hold each byte of a path that does
    not decode as one, so a path that is not UTF-8 is then written as its
    bytes, as the Go reference verifier writes it, where the line was
    written with the six characters \\udcff for the byte 0xff, in
    `PASS  d/\\udcff.json`."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"

    def escaped(part: str) -> str:
        return part.encode(encoding, "backslashreplace").decode(encoding)

    if getattr(sys.stdout, "errors", None) != "surrogateescape":
        print(escaped(text), end=end)
        return
    # split puts each run of surrogate escapes at an odd index.
    parts = _SURROGATE_ESCAPES.split(text)
    print("".join(part if i % 2 else escaped(part) for i, part in enumerate(parts)), end=end)


def _write_surrogate_escapes_as_bytes(stream: Any) -> None:
    """Set stream, standard output, to write each surrogate escape as the
    byte it stands for, so _say writes a path that is not UTF-8 as its
    bytes. A stream that cannot be reconfigured, such as an io.StringIO, is
    left as it is. reconfigure flushes the stream before it sets errors, so
    main calls this before the first report line, with nothing yet written
    to flush. Writing a line's bytes to sys.stdout.buffer instead would need
    a flush of the text written before it, to keep the lines in order."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="surrogateescape")


def _say_err(text: str) -> None:
    """sys.stderr.write for a line that quotes an argument. sys.argv holds
    each byte of an argument that does not decode, as 0xff does not, as a
    surrogate escape, which sys.stderr writes as a backslash escape, the six
    characters \\udcff for the byte 0xff in
    `error: \\udcff: no such file or directory`, where the Go reference
    verifier writes the byte. The line is written to the binary stream under
    sys.stderr as the bytes os.fsencode gives, the argument's own bytes among
    them, and as text to a stream with no binary stream under it, such as an
    io.StringIO."""
    stream = getattr(sys.stderr, "buffer", None)
    if stream is None:
        sys.stderr.write(text)
        return
    sys.stderr.flush()
    stream.write(os.fsencode(text))
    stream.flush()


_USAGE = """\
usage: verify.py <fixture.json|dir>...
  -h, --help     print this usage and exit 0
  --version      print the commit this verifier runs from and exit 0
  --             end the options: every argument after it is a fixture file or directory
"""


def _version_line() -> str:
    """The line --version writes: the commit git names as HEAD of the
    repository this file is in, whether a tracked file in this file's
    directory differs from it, and the Python release running the verifier.
    Every GIT_* variable is left out of git's environment, so one that a hook
    exports does not name another repository."""
    here = Path(__file__).resolve().parent
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}

    def git(*args: str) -> subprocess.CompletedProcess | None:
        try:
            return subprocess.run(
                ["git", "-C", str(here), *args], capture_output=True, text=True, env=env, timeout=60
            )
        except (OSError, subprocess.SubprocessError):
            return None

    python = f"run with Python {sys.version.split()[0]}"
    head = git("rev-parse", "--verify", "HEAD")
    if head is None or head.returncode != 0:
        return f"verify.py: no commit recorded (not run from a git checkout), {python}\n"
    status = git("status", "--porcelain", "--untracked-files=no", "--", ".")
    modified = status is not None and status.returncode == 0 and status.stdout.strip() != ""
    changes = ", with uncommitted changes in its directory" if modified else ""
    return f"verify.py: commit {head.stdout.strip()}{changes}, {python}\n"


def _fixture_count(n: int) -> str:
    """n with the noun the summary line counts, as the Go reference
    verifier's fixtureCount writes it: "1 fixture", "29 fixtures"."""
    return "1 fixture" if n == 1 else f"{n} fixtures"


def main(argv: list[str]) -> int:
    # The Go reference verifier reads its arguments the same way, except that
    # with no path it verifies the fixture set its module embeds, which this
    # verifier has none of; scripts/parity/parity.py runs both on each
    # argument list of its ARGUMENT_CASES.
    args = argv[1:]
    # The first "--" ends the options: each argument after it is a path, one
    # that starts with "-" included, and "--" itself names nothing.
    options, operands = args, []
    if "--" in args:
        end = args.index("--")
        options, operands = args[:end], args[end + 1 :]
    if any(arg in ("-h", "--help") for arg in options):
        sys.stdout.write(_USAGE)
        return 0
    # Options are read before any path, as the Go reference verifier reads
    # them: an argument that starts with "-", "-" alone and --version aside,
    # is no path, and is named rather than reported as a missing file.
    for arg in options:
        if len(arg) > 1 and arg.startswith("-") and arg != "--version":
            _say_err(f"unknown option: {arg}\n{_USAGE}")
            return 2
    if "--version" in options:
        sys.stdout.write(_version_line())
        return 0
    args = options + operands
    if not args:
        sys.stderr.write(_USAGE)
        return 2
    # An empty argument names no path, as it names none in the Go verifier:
    # it is a usage error, where expand_paths would report a missing path.
    if "" in args:
        sys.stderr.write("error: an empty argument names no fixture file or directory\n")
        return 2
    try:
        paths, dirs = expand_fixture_dirs(args)
    except OSError as exc:
        _say_err(f"error: {exc}\n")
        return 2
    if not paths:
        # Every argument was a directory, each listed one level deep.
        _say_err(f"no fixture *.json files found in {', '.join(dirs)} (subdirectories are not walked)\n")
        return 2

    _write_surrogate_escapes_as_bytes(sys.stdout)
    total_pass = total_fail = 0
    for path in paths:
        name = _rel_path(path)
        # A fixture the Go reference verifier's fixture struct cannot hold
        # fails to load, as it does there. path is read as spelled, so the
        # error of a file that cannot be read names it as Go's does.
        try:
            fixture = load_fixture(path)
            expected = _expected_outcome(fixture)
        except Exception as exc:
            _say(f"FAIL  {name}  (load error: {exc})")
            total_fail += 1
            continue

        # A fixture this verifier cannot handle gets a FAIL line of its own;
        # the fixtures after it are still verified and the summary printed.
        try:
            got = verify_fixture(fixture)
        except Exception as exc:
            _say(f"FAIL  {name}  (verify error: {type(exc).__name__}: {exc})")
            total_fail += 1
            continue
        want_accept = expected["verifyResult"].upper() == "ACCEPT"

        ok = (want_accept and got.accepted) or (not want_accept and not got.accepted)
        if ok and not want_accept and expected["rejectCategory"]:
            ok = got.reject_category == expected["rejectCategory"]
        # A REJECT fixture that failed on its reasonContains alone: the
        # expected and observed lines agree on the verdict and category, so
        # the substring is named on a line of its own.
        reason_missing = False
        if ok and not want_accept and expected["reasonContains"]:
            ok = expected["reasonContains"].lower() in got.reason.lower()
            reason_missing = not ok

        status = "PASS" if ok else "FAIL"
        if ok:
            total_pass += 1
        else:
            total_fail += 1

        _say(f"{status}  {name}")
        _say(f"       expected: {expected['verifyResult']}", end="")
        if expected["rejectCategory"]:
            _say(f" [{expected['rejectCategory']}]")
        else:
            print()
        _say(f"       observed: {got}")
        if reason_missing:
            _say(f"       reason does not contain {_go_quote(expected['reasonContains'])}")
        if got.sigs_expected:
            # Each boolean as the Go reference verifier's %t writes it.
            print(
                f"       signatures: {got.sigs_valid}/{got.sigs_expected} valid "
                f"(ed25519={str(got.ed25519_valid).lower()} mldsa65={str(got.mldsa65_valid).lower()})"
            )
        if got.accepted and got.trust_level >= 3 and not got.step7_performed:
            print(
                f"       trustLevel {got.trust_level} asserted; distinct-authority count (step 7) not performed by this verifier"
            )

    print()
    print(f"summary: {total_pass} pass, {total_fail} fail ({_fixture_count(total_pass + total_fail)})")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
