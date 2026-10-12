#!/usr/bin/env python3
"""Python reference verifier for the ATX v1.0 and v1.1 conformance fixture set.

Depends only on the Python standard library plus the `cryptography` package
(for Ed25519 verification) and the `dilithium-py` package (for ML-DSA-65
verification per FIPS 204). Does NOT import any opena2a-* SDK. The goal is to
demonstrate that an independent verifier in a second language reaches the same
ACCEPT / REJECT verdict as the Go reference verifier for every fixture.

Spec coverage:
  - ATX v1.0 schema (atcVersion="1.0")
  - Canonicalization: pipe-delimited 11-field string matching
    opena2a-registry/pkg/atcverify/verify.go canonicalPayload() VERBATIM
  - ATX v1.1 (atcVersion="1.1"): signed over the RFC 8785 JCS form of the
    v1.1 TBS projection
  - Ed25519 and ML-DSA-65 (FIPS 204) hybrid signature verification over the
    same canonical payload (every declared signature must verify and at
    least one must be present; no k-of-n threshold is read), trust level 3+ chain
    check, expiry, revocation, issuer-trust.

Parsing rule (strict parse, ported from the aap-conformance protected-header
lesson and scoped to the whole body because ATX signs it all):
  - the ATX credential is STRICT-parsed as a whole: a duplicate object member
    at ANY depth of the credential rejects as PARSE_ERROR before any field is
    interpreted. Every credential field feeds a signed canonical form (v1.1
    JCS(TBS) projection, v1.0 pipe fields), so there is no layer with
    sanctioned RFC 7519 last-wins semantics — duplicates are the RFC 8259 §4
    first-wins/last-wins parser-divergence smuggling split.
  - the fixture wrapper (name/verifierState/expected) is harness metadata and
    parses leniently. A fixture whose expected member is not an object of
    strings fails to load, as it does in the Go reference verifier.
  - each member the Go reference verifier's atx struct declares with a typed
    field is type-checked against that field: strings, integers in int64
    range, a finite trustScore, a boolean revoked, arrays of strings,
    signature objects, and issuedAt/expiresAt in the date-time grammar of Go
    1.22's time.Parse(time.RFC3339). A value outside its type rejects as
    PARSE_ERROR instead of raising; an absent or null member takes the Go zero
    value.
  - a member is read as Go's encoding/json reads it into that struct: a name
    that differs from the field's only in case names the same member, an
    unpaired UTF-16 surrogate escape in a string decodes to U+FFFD, a
    trustScore written as -0 keeps its sign, and a timestamp written with a
    JSON escape is outside the grammar, because Go parses the bytes between
    its quotes. The members of scanSummary, behavioralProfile and each
    signatures entry are read the same way.
  - declaredPurpose is the one member no decoder reads: it enters the v1.1
    signed payload as written. An unpaired surrogate escape in it cannot be
    canonicalized and rejects as VERIFIER_CONFIG_ERROR, the category the Go
    reference verifier's JCS library leads to. One input still differs: an
    unpaired surrogate escape followed directly by another \\u escape, which
    that library reads as a single U+FFFD and this verifier refuses.
  - NaN, Infinity and -Infinity are not JSON, so a file carrying one fails to
    load, as it does in the Go reference verifier.

Usage:
    python verify.py ../../fixtures/baseline-valid.json
    python verify.py ../../fixtures
    python verify.py ../..                 # repo root; walks fixtures/*.json

Exit 0 iff every fixture's observed result matches expected.verifyResult.
Exit 2 on a usage error, a path that does not exist, or no fixture files.
"""

from __future__ import annotations

import base64
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rfc8785 import canonicalize as _jcs_canonicalize  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write(
        "missing dependency: cryptography. install with `pip install -r requirements.txt`\n"
    )
    sys.exit(2)

try:
    from dilithium_py.ml_dsa import ML_DSA_65
except ImportError:
    sys.stderr.write(
        "missing dependency: dilithium-py. install with `pip install -r requirements.txt`\n"
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

# A JSON string literal in a document json.loads has accepted, with the colon
# after it when it is a member name.
_STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"([ \t\n\r]*:)?', re.DOTALL)

# What Go's base64.StdEncoding.DecodeString accepts once it has dropped every
# CR and LF: four-character groups of the standard alphabet, the last one
# padded with "=" when the data ends short.
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


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
    """Parse a timestamp as Go 1.22's time.Parse(time.RFC3339, value) does, or
    raise ValueError. The ranges are Go's: year 0000-9999, hour 0-23, minute
    and second 0-59, and any two-digit offset hour and minute; a fraction keeps
    nine digits. Go 1.23 and later also reject an offset hour above 24 or an
    offset minute above 60; CI builds the Go reference verifier with Go 1.22,
    which does not (README "Running the verifiers" says the same)."""
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
    behaves exactly as a plain json.loads."""

    __slots__ = ("duplicate_member",)


def _subtree_duplicate(value: Any) -> str | None:
    if isinstance(value, _DupMarkedDict):
        return value.duplicate_member
    if isinstance(value, list):
        for item in value:
            dup = _subtree_duplicate(item)
            if dup is not None:
                return dup
    return None


def _fold_key(s: str) -> str:
    """Fold a JSON member name the way Go's encoding/json folds struct field
    names, matching the Go reference verifier's foldKey (verifiers/go/verify.go):
    ASCII uppercase lowercased, Kelvin sign U+212A -> k, long s U+017F -> s, any
    other rune via str.lower(). Two names with the same fold key collapse to one
    struct field under a Go last-wins unmarshaler, so treating them as duplicates
    here keeps this verifier category-consistent (PARSE_ERROR) with the Go
    reference on case-variant members — a deliberate ecosystem rule, since a
    fold-colliding member is ambiguous across conforming parsers. This verifier's
    own json.loads is case-sensitive and would not otherwise collapse them. This
    matches the Go foldKey for ASCII names and the two special runes — the domain
    that matters, since ATX member names are ASCII. For other non-ASCII runes
    str.lower() can diverge from Go's simple unicode.ToLower, but no honest
    credential has non-ASCII member names (they are already schema-invalid). See
    atx-conformance#16.
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
            out.append(ch.lower())
    return "".join(out)


def _go_string(value: str) -> str:
    """A JSON string as Go's encoding/json decodes it: each unpaired UTF-16
    surrogate becomes U+FFFD."""
    return _UNPAIRED_SURROGATE.sub(_REPLACEMENT_CHARACTER, value)


def _dup_marking_pairs(pairs: list[tuple[str, Any]]) -> "_DupMarkedDict":
    out = _DupMarkedDict()
    dup: str | None = None
    seen_folded: dict[str, str] = {}
    for key, value in pairs:
        # Names are compared as Go decodes them, so two names that escape
        # different unpaired surrogates are one name. The object keeps the
        # name as written.
        name = _go_string(key)
        fk = _fold_key(name)
        if dup is None and fk in seen_folded:
            dup = name
        seen_folded[fk] = name
        if dup is None:
            dup = _subtree_duplicate(value)
        out[key] = value
    out.duplicate_member = dup
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
    # The Go verifier's projectScanSummaryV11 ignores a decode error, which
    # leaves each member it could not decode at its zero value; a scanSummary
    # that is not an object leaves all six there.
    scan = atx.get("scanSummary")
    scan_summary = _decode_members(
        _SCAN_SUMMARY_TYPES, scan if isinstance(scan, dict) else {}, "scanSummary.", lenient=True
    )

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
    return _jcs_canonicalize(tbs)


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


def index_public_keys(refs: list[dict[str, Any]], authority_set: set[str]):
    # Key↔issuer binding: a key is eligible to verify a signature for this
    # credential only if its keyId's controller DID is in authority_set. A key
    # with no keyId is unbound (legacy single-issuer configs) and stays eligible.
    eds: list[Ed25519PublicKey] = []
    pqs: list[bytes] = []
    for r in refs:
        key_id = r.get("keyId", "") or ""
        if key_id and _controller_did(key_id) not in authority_set:
            continue
        if r["algorithm"] == "Ed25519":
            raw = bytes.fromhex(r["publicKeyHex"])
            if len(raw) != 32:
                continue
            eds.append(Ed25519PublicKey.from_public_bytes(raw))
        elif r["algorithm"] == "ML-DSA-65":
            raw = bytes.fromhex(r["publicKeyHex"])
            if len(raw) != MLDSA65_PUBLIC_KEY_SIZE:
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


class _DecodeError(ValueError):
    """A member holds a value outside its Go type."""


class _EscapedString(str):
    """A string value whose JSON literal carries a backslash escape, as
    load_fixture marks it. Go's time.Time decoder parses the bytes between the
    quotes, so it refuses a timestamp written with one; every other reader
    takes the decoded string."""

    __slots__ = ()


class _NegativeZero(int):
    """The JSON number -0, which json.loads reads as the integer 0, as
    load_fixture marks it. Go's float64 decode keeps the sign."""

    __slots__ = ()


def _decode_member(name: str, go_type: str, value: Any) -> Any:
    """Type-check one member against go_type, its type in the Go reference
    verifier, and return the value Go's encoding/json decodes it to, or raise
    _DecodeError. A null takes the Go zero value; a timestamp decodes to an
    _Instant."""
    if go_type == "string":
        if value is None:
            return ""
        if isinstance(value, str):
            return _go_string(value)
        raise _DecodeError(f"{name} {value!r} is not a JSON string")
    if go_type == "int64":
        if value is None:
            return 0
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and _INT64_MIN <= value <= _INT64_MAX
        ):
            return int(value)
        raise _DecodeError(f"{name} {value!r} is not a JSON integer in int64 range")
    if go_type == "float64":
        if value is None:
            return 0.0
        if isinstance(value, _NegativeZero):
            return -0.0
        if _finite_number(value):
            return float(value)
        raise _DecodeError(f"{name} {value!r} is not a finite JSON number")
    if go_type == "bool":
        if value is None or isinstance(value, bool):
            return bool(value)
        raise _DecodeError(f"{name} {value!r} is not a JSON boolean")
    if go_type == "time.Time":
        if value is None:
            return _GO_ZERO_TIME
        try:
            if isinstance(value, _EscapedString):
                raise ValueError("written with a JSON escape")
            return _parse_rfc3339(value)
        except ValueError as exc:
            raise _DecodeError(f"{name} {value!r} is not an RFC 3339 date-time ({exc})") from None
    if value is None:
        return []
    if not isinstance(value, list):
        raise _DecodeError(f"{name} {value!r} is not a JSON array")
    if go_type == "[]string":
        return [_decode_member(f"{name}[{i}]", "string", item) for i, item in enumerate(value)]
    return [_decode_signature(f"{name}[{i}]", item) for i, item in enumerate(value)]


def _members_by_folded_name(value: dict[str, Any]) -> dict[str, Any]:
    """The members of a JSON object under the name folding Go's encoding/json
    matches a member to a struct field with: "Revoked" and "REVOKED" are the
    member "revoked". The strict parse has already refused a credential in
    which two names fold together; elsewhere the last one wins, as it does in
    Go."""
    return {_fold_key(key): member for key, member in value.items()}


def _decode_members(
    types: dict[str, str], value: dict[str, Any], prefix: str = "", lenient: bool = False
) -> dict[str, Any]:
    """Each member named in types, decoded from the JSON object value as Go's
    encoding/json decodes it into a struct field of that type: matched by
    folded name, the zero value when absent. A member outside its type raises
    _DecodeError, or with lenient takes the zero value, which is what a Go
    caller that ignores the decode error is left with."""
    members = _members_by_folded_name(value)
    decoded = {}
    for name, go_type in types.items():
        try:
            decoded[name] = _decode_member(prefix + name, go_type, members.get(_fold_key(name)))
        except _DecodeError:
            if not lenient:
                raise
            decoded[name] = _decode_member(prefix + name, go_type, None)
    return decoded


def _decode_signature(name: str, value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise _DecodeError(f"{name} {value!r} is not a JSON object")
    return _decode_members(_SIGNATURE_TYPES, value, f"{name}.")


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
        raise _DecodeError(f"credential {atx!r} is not a JSON object")
    decoded = dict(atx)
    decoded.update(_decode_members(_MEMBER_TYPES, atx))
    members = _members_by_folded_name(atx)
    for name in _RAW_MEMBERS:
        decoded[name] = members.get(_fold_key(name))
    return decoded


def _expected_outcome(fixture: Any) -> dict[str, str]:
    """The fixture's expected member as the Go reference verifier's
    expectedOutcome struct holds it: verifyResult, rejectCategory and
    reasonContains, each "" when absent or null. Raises ValueError for a
    fixture or an expected member that is not a JSON object, or a member of
    it that is not a string; the Go verifier fails to load such a file."""
    if not isinstance(fixture, dict):
        raise ValueError("fixture is not a JSON object")
    expected = fixture.get("expected")
    if expected is None:
        expected = {}
    if not isinstance(expected, dict):
        raise ValueError(f"expected {expected!r} is not a JSON object")
    return _decode_members(_EXPECTED_TYPES, expected, "expected.")


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
    stack."""
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            keys = list(node)
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
    atx = fixture["atx"]
    vs = fixture["verifierState"]

    # The Go reference verifier decodes the verifier state into typed fields,
    # so its strings are read the way the credential's are: the CRL's agentId
    # and the trusted issuers are compared with decoded credential members.
    for node, key in _scalars(vs):
        if isinstance(node[key], str):
            node[key] = _go_string(node[key])

    # Step 0: strict parse. A duplicate member at any depth of the CREDENTIAL
    # rejects before any field is interpreted (see module docstring). The
    # fixture wrapper stays lenient: only the atx subtree is consulted.
    dup = _subtree_duplicate(atx)
    if dup is not None:
        return VerifyResult(
            reject_category="PARSE_ERROR",
            reason=f'credential contains duplicate member "{dup}" (strict parse: the whole ATX credential is a signed body; RFC 8259 §4 duplicate names are parser-divergent)',
        )
    try:
        atx = _decode_credential(atx)
    except _DecodeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))

    try:
        now = _parse_rfc3339(vs.get("clockRfc3339", ""))
    except ValueError as exc:
        return VerifyResult(reject_category="VERIFIER_CONFIG_ERROR", reason=f"bad clockRfc3339: {exc}")

    # Step 1: schema version. Dispatch on atcVersion: "1.0" verifies the legacy
    # pipe form, "1.1" verifies JCS(TBS) (atx-spec §1.3a).
    version = atx.get("atcVersion")
    if version not in (SUPPORTED_ATC_VERSION, SUPPORTED_ATC_VERSION_V11):
        return VerifyResult(
            reject_category="UNSUPPORTED_VERSION",
            reason=f"unsupported atcVersion {version!r} (this verifier supports {SUPPORTED_ATC_VERSION} and {SUPPORTED_ATC_VERSION_V11})",
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
    crl = vs.get("crl")
    if crl:
        for entry in crl.get("entries", []):
            if entry["agentId"] == atx["agentId"]:
                return VerifyResult(
                    reject_category="REVOKED",
                    reason=f"agent appears on CRL: {entry.get('reason', '')}",
                )

    # Step 4: issuer trust.
    if atx["issuerDid"] not in vs.get("trustedIssuers", []):
        return VerifyResult(
            reject_category="UNTRUSTED_ISSUER",
            reason=f"issuer DID {atx['issuerDid']} is not in the verifier's trusted set (untrusted issuer)",
        )

    # Step 5: signature verification.
    # Spec mandate: every declared signature MUST verify.
    if version == SUPPORTED_ATC_VERSION_V11:
        try:
            payload = canonical_payload_v11(atx)
        except NotImplementedError as exc:
            # The vendored JCS serializer refuses non-integer numbers
            # (rfc8785.py); a schema-valid v1.1 TBS carries none. One can still
            # arrive in content the signer never signed, e.g. a number
            # injected into declaredPurpose, which enters the TBS verbatim.
            # Without the canonical bytes no declared signature can verify, so
            # reject in the category a verifier that does canonicalize the
            # number reaches (the Go reference) instead of raising out of the
            # run.
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"no signature can be verified: the to-be-signed object cannot be canonicalized ({exc})",
            )
        except UnicodeEncodeError as exc:
            # Every decoded member holds U+FFFD where an unpaired surrogate
            # was escaped, so this is declaredPurpose, which enters the TBS as
            # written. The Go reference verifier's JCS library refuses the
            # escape and the verifier reports the category below.
            return VerifyResult(
                reject_category="VERIFIER_CONFIG_ERROR",
                reason=f"v1.1 canonicalization failed: declaredPurpose holds an unpaired UTF-16 surrogate ({exc})",
            )
    else:
        payload = canonical_payload(atx)
    eds, pqs = index_public_keys(
        vs["publicKeys"], _authority_set_for(atx, vs.get("trustedIssuers", []))
    )
    result = VerifyResult(sigs_expected=len(atx["signatures"]))

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


def _parse_int(literal: str) -> int:
    return _NegativeZero() if literal == "-0" else int(literal)


def _null_if_escaped(literal: re.Match) -> str:
    # A member name keeps its literal, so both parses build the same objects.
    if literal.group(1) is None and "\\" in literal.group(0):
        return "null"
    return literal.group(0)


def load_fixture(path: Path) -> dict[str, Any]:
    # The duplicate-marking hook preserves last-wins values (plain dict
    # semantics) while recording duplicates for the strict-parse check in
    # verify_fixture, which consults only the atx subtree.
    text = path.read_text()
    fixture = json.loads(
        text,
        object_pairs_hook=_dup_marking_pairs,
        parse_constant=_reject_constant,
        parse_int=_parse_int,
    )
    # json.loads does not say which strings were written with an escape, and
    # Go's time.Time decoder refuses a timestamp that was. A second parse,
    # with each such string value replaced by null, has the same shape as the
    # first and holds null exactly where the first holds one of them.
    shadow = json.loads(_STRING_LITERAL.sub(_null_if_escaped, text))
    for (node, key), (other, _) in zip(_scalars(fixture), _scalars(shadow)):
        if other[key] is None and isinstance(node[key], str):
            node[key] = _EscapedString(node[key])
    return fixture


def expand_paths(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        if not p.exists():
            raise FileNotFoundError(f"{a}: no such file or directory")
        if p.is_dir():
            fixtures_dir = p / "fixtures"
            target = fixtures_dir if fixtures_dir.is_dir() else p
            out.extend(sorted(target.glob("*.json")))
        else:
            out.append(p)
    return sorted(set(out))


def _say(text: str, end: str = "\n") -> None:
    """print() for a line that quotes a fixture or its path. A character
    standard output cannot encode, an unpaired surrogate for one, is written
    as a backslash escape instead of raising and ending the run."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(text.encode(encoding, "backslashreplace").decode(encoding), end=end)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: verify.py <fixture.json|dir>...\n")
        return 2
    try:
        paths = expand_paths(argv[1:])
    except OSError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    if not paths:
        sys.stderr.write("no fixture *.json files found\n")
        return 2

    total_pass = total_fail = 0
    for p in paths:
        # A fixture whose expected member is not the object the Go reference
        # verifier decodes fails to load, as it does there.
        try:
            fixture = load_fixture(p)
            expected = _expected_outcome(fixture)
        except Exception as exc:
            _say(f"FAIL  {p}  (load error: {exc})")
            total_fail += 1
            continue

        # A fixture this verifier cannot handle gets a FAIL line of its own;
        # the fixtures after it are still verified and the summary printed.
        try:
            got = verify_fixture(fixture)
        except Exception as exc:
            _say(f"FAIL  {p}  (verify error: {type(exc).__name__}: {exc})")
            total_fail += 1
            continue
        want_accept = expected["verifyResult"].upper() == "ACCEPT"

        ok = (want_accept and got.accepted) or (not want_accept and not got.accepted)
        if ok and not want_accept and expected["rejectCategory"]:
            ok = got.reject_category == expected["rejectCategory"]
        if ok and not want_accept and expected["reasonContains"]:
            ok = expected["reasonContains"].lower() in got.reason.lower()

        status = "PASS" if ok else "FAIL"
        if ok:
            total_pass += 1
        else:
            total_fail += 1

        try:
            rel = p.relative_to(Path.cwd())
        except ValueError:
            rel = p
        _say(f"{status}  {rel}")
        _say(f"       expected: {expected['verifyResult']}", end="")
        if expected["rejectCategory"]:
            _say(f" [{expected['rejectCategory']}]")
        else:
            print()
        _say(f"       observed: {got}")
        if got.sigs_expected:
            print(
                f"       signatures: {got.sigs_valid}/{got.sigs_expected} valid (ed25519={got.ed25519_valid} mldsa65={got.mldsa65_valid})"
            )
        if got.accepted and got.trust_level >= 3 and not got.step7_performed:
            print(
                f"       trustLevel {got.trust_level} asserted; distinct-authority count (step 7) not performed by this verifier"
            )

    print()
    print(f"summary: {total_pass} pass, {total_fail} fail ({total_pass + total_fail} fixtures)")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
