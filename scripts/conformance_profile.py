#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.
`--check` also runs scripts/check_spec_refs.py: every ATX citation must name a
heading of the vendored, pinned core.md. The top-level `spec.ref` is that
script's CORE_REF, core.md at the pinned atx-spec commit, so moving the pin
makes the committed profile stale until it is regenerated.

A fixture that cannot be read into a requirement (not JSON, not an object, a
required member missing, unreadable or nested too deeply) fails by name, in
both modes, and nothing is written.

Usage:
    python3 scripts/conformance_profile.py              # (re)write conformance.json
    python3 scripts/conformance_profile.py --check      # exit 1 if stale or a citation is not a core.md heading
    python3 scripts/conformance_profile.py --self-test  # prove a broken fixture fails by name
"""
from __future__ import annotations

import contextlib
import json
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import check_spec_refs  # noqa: E402

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "atx-conformance",
    "spec": {
        "id": "ATX",
        "name": "Agent Trust eXtension",
        "version": "1.0 (v1.1 fixtures included: JCS/RFC 8785 TBS signing, declaredPurpose)",
        "ref": check_spec_refs.CORE_REF,
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
            "coverage": "full: Ed25519 and ML-DSA-65 (FIPS 204, via dilithium-py) hybrid signatures, v1.0 pipe canonical form and v1.1 JCS(TBS) via vendored RFC 8785",
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
            "item": "Distinct signer-authority count (ATX core.md section 1.3 step 7)",
            "reason": "no fixture carries verified signatures from more than one distinct authority, and the fixture format has no field for the required trust level that step 7's condition reads, so a verifier that omits step 7 entirely passes the suite; a length-of-issuerChain test is not step 7 (the spec says the chain length MUST NOT be counted) and implementations MUST self-attest this requirement until a fixture exists for it",
        },
        {
            "item": "Cosignature requirements (ATX core.md section 7: federation cosigning, and the root cosignature at trust level 4)",
            "reason": "the threshold fixture pins one 2-of-3 cosignature over the signing bytes; no fixture asserts that a trust level 4 credential carries the root cosignature or that a federated issuance carries its peer's cosignature",
        },
        {
            "item": "Revocation propagation timing (ATX core.md section 3.3)",
            "reason": "the revoked fixture pins the verdict for an agentId that is on the verifier's CRL; no fixture exercises the 5-minute cache bound or a stale-CRL window",
        },
        {
            "item": "Transparency-log monitor behavior (ATX core.md section 6.4)",
            "reason": "no fixture models a monitor and the conformance verifiers do not consult a log",
        },
    ],
}

# The deepest a requirement may nest. A deeper one is refused before anything
# is rendered: the text json.dumps(indent=2) writes grows with the square of
# the depth, and how deep it can write at all depends on the Python version.
MAX_DEPTH = 100


def render(doc: object) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _nests_deeper_than(limit: int, value: object) -> bool:
    """Whether arrays and objects in a parsed JSON value nest more than limit
    levels deep, counted with a stack so any depth json.loads returns can be
    measured."""
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > limit:
                return True
            children = node.values() if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)
    return False


def requirement(path: Path, failures: list[str]) -> dict | None:
    """The requirement a fixture defines, or None with its failure recorded."""
    where = f"fixtures/{path.name}"
    try:
        fx = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        failures.append(f"{where}: is not JSON ({exc})")
        return None
    except OSError as exc:
        failures.append(f"{where}: cannot be read ({exc.strerror or type(exc).__name__})")
        return None
    except RecursionError:
        failures.append(f"{where}: is nested too deeply to read as JSON")
        return None
    if not isinstance(fx, dict):
        failures.append(f"{where}: is not a JSON object")
        return None
    missing = [k for k in ("name", "description", "spec", "expected") if k not in fx]
    if missing:
        noun = "member" if len(missing) == 1 else "members"
        failures.append(f"{where}: has no {', '.join(map(repr, missing))} {noun}")
        return None
    expected = fx["expected"]
    if not isinstance(expected, dict) or "verifyResult" not in expected:
        failures.append(f"{where}: 'expected' is not an object with a 'verifyResult' member")
        return None
    outcome = expected["verifyResult"]
    category = expected.get("rejectCategory")
    if category:
        if not isinstance(category, str):
            failures.append(f"{where}: 'expected.rejectCategory' is not a string")
            return None
        outcome = f"REJECT[{category}]"
    req = {
        "fixture": where,
        "name": fx["name"],
        "fixtureType": fx.get("fixtureType", "atx-credential"),
        "level": "MUST",
        "specRefs": fx["spec"],
        "expected": outcome,
        "description": fx["description"],
    }
    # A member that parsed can still be too deep to write back out.
    if _nests_deeper_than(MAX_DEPTH, req):
        failures.append(f"{where}: is nested too deeply to write into conformance.json")
        return None
    return req


def build(root: Path = REPO_ROOT) -> tuple[dict, list[str]]:
    """The profile, and a failure for each fixture that cannot be read into a
    requirement."""
    requirements: list[dict] = []
    failures: list[str] = []
    for path in sorted((root / "fixtures").glob("*.json")):
        req = requirement(path, failures)
        if req is not None:
            requirements.append(req)
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile, failures


# --- self-test ---------------------------------------------------------------


@contextlib.contextmanager
def _fixtures(make: object) -> Iterator[Path]:
    """A temporary tree whose fixtures/probe.json is written from a str, made
    by calling make(path), or written as JSON."""
    tmp = Path(tempfile.mkdtemp(prefix="conformance-profile-"))
    try:
        probe = tmp / "fixtures" / "probe.json"
        probe.parent.mkdir()
        if isinstance(make, str):
            probe.write_text(make, encoding="utf-8")
        elif callable(make):
            make(probe)
        else:
            probe.write_text(json.dumps(make), encoding="utf-8")
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _fails_by_name(make: object) -> bool:
    with _fixtures(make) as root:
        profile, failures = build(root)
    return (len(failures) == 1 and failures[0].startswith("fixtures/probe.json: ")
            and not profile["requirements"])


def _builds(make: object) -> bool:
    with _fixtures(make) as root:
        profile, failures = build(root)
    return not failures and len(profile["requirements"]) == 1


def _nested(depth: int) -> str:
    """A fixture nested depth levels deep: its spec is arrays nested one level
    less, so its requirement nests as deep as it does."""
    n = depth - 1
    return ('{"name": "p", "description": "d", "spec": ' + "[" * n + "]" * n
            + ', "expected": {"verifyResult": "ACCEPT"}}')


def self_test() -> int:
    good = {"name": "probe", "description": "d", "spec": [], "expected": {"verifyResult": "ACCEPT"}}
    with _fixtures(good) as root:
        profile, failures = build(root)
    cases: list[tuple[str, bool]] = [
        ("builds a well-formed fixture", not failures and len(profile["requirements"]) == 1),
        ("spec.ref is core.md at the pinned atx-spec commit",
         profile["spec"]["ref"] == check_spec_refs.CORE_REF),
        ("reports a fixture that is not JSON by name", _fails_by_name("{")),
        ("reports a fixture that is a JSON array by name", _fails_by_name([good])),
        ("reports a fixture that is a JSON number by name", _fails_by_name("5")),
        ("reports a fixture with no expected member by name",
         _fails_by_name({k: v for k, v in good.items() if k != "expected"})),
        ("reports an expected member that is not an object by name",
         _fails_by_name({**good, "expected": "ACCEPT"})),
        ("reports a rejectCategory that is not a string by name",
         _fails_by_name({**good, "expected": {"verifyResult": "REJECT", "rejectCategory": ["x"]}})),
        ("reports a directory named like a fixture by name", _fails_by_name(Path.mkdir)),
        (f"builds a fixture nested {MAX_DEPTH} levels deep", _builds(_nested(MAX_DEPTH))),
        (f"reports a fixture nested {MAX_DEPTH + 1} levels deep by name",
         _fails_by_name(_nested(MAX_DEPTH + 1))),
        # Past what json.loads reads before Python 3.14; 3.14 reads it, and the
        # depth limit refuses it before anything is rendered.
        (f"reports a fixture nested {check_spec_refs.DEEP:,} levels deep by name",
         _fails_by_name(_nested(check_spec_refs.DEEP))),
    ]
    failed = 0
    for label, ok in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        failed += not ok
    print(f"conformance-profile self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    profile, failures = build()
    if failures:
        for f in failures:
            print(f"FAIL {f}")
        print(f"{len(failures)} fixture(s) cannot be read into conformance.json; nothing written")
        return 1
    rendered = render(profile)
    if "--check" in sys.argv:
        if self_test():
            return 1
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
        # Every ATX citation must name a heading of the pinned core.md. The
        # self-test runs first so the check is proven able to fail.
        if check_spec_refs.self_test() or check_spec_refs.report():
            return 1
        return 0
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(profile['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
