#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if committed file is stale
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "atx-conformance",
    "spec": {
        "id": "ATX",
        "name": "Agent Trust eXtension",
        "version": "1.0 (v1.1 fixtures included: JCS/RFC 8785 TBS signing, declaredPurpose)",
        "ref": "https://github.com/opena2a-standards/atx-spec/blob/main/core.md",
    },
    "fixtureManifest": "MANIFEST.sha256",
    "verifiers": [
        {
            "language": "go",
            "path": "verifiers/go",
            "coverage": "full: Ed25519 and ML-DSA-65 (FIPS 204) hybrid signatures, v1.0 pipe canonical form and v1.1 JCS(TBS)",
        },
        {
            "language": "python",
            "path": "verifiers/python",
            "coverage": "Ed25519 (v1.0 and v1.1 via vendored RFC 8785); ML-DSA-65 signatures recorded as present, verification delegated to the Go verifier",
        },
    ],
    "additionalGates": [
        {
            "name": "jcs-byte-agreement",
            "path": "jcs-vectors/run-agreement.sh",
            "description": "three independent canonicalizers (Go gowebpki/jcs, vendored Python RFC 8785, TypeScript erdtman/canonicalize) must reproduce each vector's pinned canonical bytes exactly",
        }
    ],
    "notCovered": [
        {
            "item": "Content hash matching the agent binary",
            "reason": "contentHash is pinned for byte-stability but no agent binary ships; verifiers stop at the signature step",
        },
        {
            "item": "Transparency log inclusion proofs",
            "reason": "transparencyLogIndex is populated for byte-stability; the conformance verifiers do not consult a log",
        },
        {
            "item": "Build attestation predicate verification",
            "reason": "buildAttestation is a string field in ATX v1.0, not an inline structured SLSA v1 predicate; verifiers do not parse it",
        },
        {
            "item": "Behavioral profile validation",
            "reason": "field omitted from these fixtures",
        },
    ],
}


def build() -> dict:
    requirements = []
    for path in sorted((REPO_ROOT / "fixtures").glob("*.json")):
        fx = json.loads(path.read_text())
        expected = fx["expected"]
        outcome = expected["verifyResult"]
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        requirements.append(
            {
                "fixture": f"fixtures/{path.name}",
                "name": fx["name"],
                "fixtureType": fx.get("fixtureType", "atx-credential"),
                "level": "MUST",
                "specRefs": fx["spec"],
                "expected": outcome,
                "description": fx["description"],
            }
        )
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def main() -> int:
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
        return 0
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(build()['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
