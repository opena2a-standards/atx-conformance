#!/usr/bin/env python3
"""Python reference verifier for the ATX v1.0 conformance fixture set.

Depends only on the Python standard library plus the `cryptography` package
(for Ed25519 verification). Does NOT import any opena2a-* SDK. The goal is to
demonstrate that an independent verifier in a second language reaches the same
ACCEPT / REJECT verdict as the Go reference verifier for every fixture.

Spec coverage:
  - ATX v1.0 schema (atcVersion="1.0")
  - Canonicalization: pipe-delimited 11-field string matching
    opena2a-registry/pkg/atcverify/verify.go canonicalPayload() VERBATIM
  - Ed25519 verification, threshold (>=1 valid), trust level 3+ chain check,
    expiry, revocation, issuer-trust.

Out of scope:
  - ML-DSA-65 verification. The post-quantum library landscape in Python is
    fragmented (no stdlib support, liboqs / dilithium-py require optional
    native dependencies). The hybrid fixture is annotated and accepted on
    the Ed25519 path alone. For spec-mandate full hybrid verification, run
    the Go reference verifier in ../go.

Usage:
    python verify.py ../../fixtures/baseline-valid.json
    python verify.py ../../fixtures
    python verify.py ../..                 # repo root; walks fixtures/*.json

Exit 0 iff every fixture's observed result matches expected.verifyResult.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write(
        "missing dependency: cryptography. install with `pip install -r requirements.txt`\n"
    )
    sys.exit(2)


SUPPORTED_ATC_VERSION = "1.0"


@dataclass
class VerifyResult:
    accepted: bool = False
    reject_category: str = ""
    reason: str = ""
    ed25519_valid: bool = False
    mldsa65_present: bool = False
    mldsa65_skipped: bool = False
    sigs_expected: int = 0
    sigs_valid: int = 0

    def __str__(self) -> str:
        if self.accepted:
            return "ACCEPT"
        return f"REJECT[{self.reject_category}: {self.reason}]"


def canonical_payload(atx: dict[str, Any]) -> bytes:
    """Mirror opena2a-registry/pkg/atcverify/verify.go canonicalPayload() VERBATIM.

    The Go signature uses fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%.6f|%s|%s|%s", ...)
    with the 11 fields enumerated below. Python's f-string %.6f matches Go's
    %.6f for finite floats in the ranges we use (0.0 to ~100.0). The
    atcVersion in the canonical string is hardcoded to "1.0" in Go regardless
    of the credential's atcVersion field; we replicate that quirk here.
    """
    return (
        f"{atx['agentId']}|"
        f"{atx['agentDid']}|"
        f"{atx['version']}|"
        f"{atx['contentHash']}|"
        f"{atx.get('buildAttestation', '')}|"
        f"{atx['issuerDid']}|"
        f"{int(atx['trustLevel'])}|"
        f"{float(atx['trustScore']):.6f}|"
        f"{_normalize_rfc3339(atx['issuedAt'])}|"
        f"{_normalize_rfc3339(atx['expiresAt'])}|"
        f"{SUPPORTED_ATC_VERSION}"
    ).encode("utf-8")


def _normalize_rfc3339(s: str) -> str:
    """Round-trip RFC 3339 through Python's datetime, normalize to UTC ISO with
    seconds precision (matching Go's time.RFC3339 "2006-01-02T15:04:05Z07:00").

    Go's RFC3339 format is "2006-01-02T15:04:05Z07:00" which means
    "<seconds>Z" for UTC times. We reproduce that exact shape.
    """
    # Python's fromisoformat handles trailing Z since 3.11; for portability
    # we normalize manually.
    s2 = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s2).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def index_public_keys(refs: list[dict[str, Any]]):
    eds: list[Ed25519PublicKey] = []
    mldsa_keys_present = False
    for r in refs:
        if r["algorithm"] == "Ed25519":
            raw = bytes.fromhex(r["publicKeyHex"])
            if len(raw) != 32:
                continue
            eds.append(Ed25519PublicKey.from_public_bytes(raw))
        elif r["algorithm"] == "ML-DSA-65":
            mldsa_keys_present = True
    return eds, mldsa_keys_present


def verify_fixture(fixture: dict[str, Any]) -> VerifyResult:
    atx = fixture["atx"]
    vs = fixture["verifierState"]

    now = datetime.fromisoformat(vs["clockRfc3339"].replace("Z", "+00:00")).astimezone(timezone.utc)

    # Step 1: schema version.
    if atx.get("atcVersion") != SUPPORTED_ATC_VERSION:
        return VerifyResult(
            reject_category="UNSUPPORTED_VERSION",
            reason=f"unsupported atcVersion {atx.get('atcVersion')!r} (this verifier supports {SUPPORTED_ATC_VERSION})",
        )

    # Step 2: expiry.
    expires = datetime.fromisoformat(atx["expiresAt"].replace("Z", "+00:00")).astimezone(timezone.utc)
    if now > expires:
        return VerifyResult(
            reject_category="EXPIRED",
            reason=f"expired at {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}, verifier clock is {now.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        )

    # Step 3: revocation.
    if atx.get("revoked"):
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

    # Step 5: signature verification (Ed25519 fully, ML-DSA-65 marked skipped).
    payload = canonical_payload(atx)
    eds, mldsa_keys_present = index_public_keys(vs["publicKeys"])
    result = VerifyResult(sigs_expected=len(atx.get("signatures", [])))

    for sig in atx.get("signatures", []):
        try:
            sig_bytes = base64.b64decode(sig["value"])
        except Exception as exc:
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
            # Out of scope for this Python reference verifier. The presence
            # of an ML-DSA-65 signature is recorded; verification itself is
            # not attempted. See module docstring.
            result.mldsa65_present = True
            result.mldsa65_skipped = True
            # Don't count as valid AND don't count as invalid; the fixture's
            # Ed25519 signature is still the gate for acceptance here.
        else:
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"unsupported signature algorithm {sig['algorithm']}",
            )

    if result.sigs_valid == 0 and not result.ed25519_valid:
        return VerifyResult(reject_category="SIGNATURE_INVALID", reason="no valid Ed25519 signatures")

    # Step 7: issuer chain depth for trust level 3+.
    trust_level = int(atx.get("trustLevel", 0))
    issuer_chain = atx.get("issuerChain", [])
    if trust_level >= 3 and len(issuer_chain) < 2:
        return VerifyResult(
            reject_category="CHAIN_TOO_SHORT",
            reason=f"trust level {trust_level} requires 2+ authorities in issuer chain (got {len(issuer_chain)})",
        )

    result.accepted = True
    return result


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def expand_paths(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        if not p.exists():
            raise FileNotFoundError(a)
        if p.is_dir():
            fixtures_dir = p / "fixtures"
            target = fixtures_dir if fixtures_dir.is_dir() else p
            out.extend(sorted(target.glob("*.json")))
        else:
            out.append(p)
    return sorted(set(out))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: verify.py <fixture.json|dir>...\n")
        return 2
    paths = expand_paths(argv[1:])
    if not paths:
        sys.stderr.write("no fixture *.json files found\n")
        return 2

    total_pass = total_fail = 0
    for p in paths:
        try:
            fixture = load_fixture(p)
        except Exception as exc:
            print(f"FAIL  {p}  (load error: {exc})")
            total_fail += 1
            continue

        got = verify_fixture(fixture)
        expected = fixture.get("expected", {})
        want_accept = expected.get("verifyResult", "").upper() == "ACCEPT"

        ok = (want_accept and got.accepted) or (not want_accept and not got.accepted)
        if ok and not want_accept and expected.get("rejectCategory"):
            ok = got.reject_category == expected["rejectCategory"]
        if ok and not want_accept and expected.get("reasonContains"):
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
        print(f"{status}  {rel}")
        print(f"       expected: {expected.get('verifyResult', '')}", end="")
        if expected.get("rejectCategory"):
            print(f" [{expected['rejectCategory']}]")
        else:
            print()
        print(f"       observed: {got}")
        if got.sigs_expected:
            mldsa_note = ""
            if got.mldsa65_present:
                mldsa_note = " (ML-DSA-65 present, verification out of scope for this Python reference; use Go verifier for full hybrid)"
            print(
                f"       signatures: {got.sigs_valid}/{got.sigs_expected} valid (ed25519={got.ed25519_valid}){mldsa_note}"
            )

    print()
    print(f"summary: {total_pass} pass, {total_fail} fail ({total_pass + total_fail} fixtures)")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
