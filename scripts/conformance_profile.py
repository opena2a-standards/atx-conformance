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

Each fixture names the requirement it tests in its `requirement` member: the
§ number of the core.md section the rule comes from, then the step or rule
("§1.3 step 2: ..."). The section must be one the fixture's `spec` list cites
as ATX, and no two fixtures may name the same requirement. A fixture cites
FIPS 204 exactly when its credential carries an ML-DSA-65 signature.

A fixture that cannot be read into a requirement (not JSON, not an object, a
required member missing, unreadable, or nested more than MAX_DEPTH levels
deep) or written into the profile (carrying text with no UTF-8 form, such as
a lone surrogate escape) fails by name, in both modes, and nothing is written.

Usage:
    python3 scripts/conformance_profile.py              # (re)write conformance.json
    python3 scripts/conformance_profile.py --check      # exit 1 if stale or a citation is not a core.md heading
    python3 scripts/conformance_profile.py --self-test  # prove a broken fixture fails by name
    python3 scripts/conformance_profile.py --help       # print this usage
"""
from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILE = "conformance.json"
# Not sliced from __doc__, which `python -OO` strips. The self-test holds the
# docstring's Usage block equal to this text.
USAGE = """\
Usage:
    python3 scripts/conformance_profile.py              # (re)write conformance.json
    python3 scripts/conformance_profile.py --check      # exit 1 if stale or a citation is not a core.md heading
    python3 scripts/conformance_profile.py --self-test  # prove a broken fixture fails by name
    python3 scripts/conformance_profile.py --help       # print this usage
"""

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
            "item": "k-of-n threshold issuance (ATX core.md section 3.1 step 8: cosignatures from 2 of 3 key holders)",
            "reason": "the fixture format has no field for the required signature count and neither reference verifier reads one: both require every declared signature to verify and at least one to be present, so the threshold fixture's credential cut to one of its three signatures is accepted, and a verifier that checks only the first signature passes the threshold fixture",
        },
        {
            "item": "Cosignature requirements (ATX core.md section 7: federation cosigning, and the root cosignature at trust level 4)",
            "reason": "the threshold fixture pins three signatures over the signing bytes, each of which must verify; no fixture asserts that a trust level 4 credential carries the root cosignature or that a federated issuance carries its peer's cosignature",
        },
        {
            "item": "Revocation propagation timing (ATX core.md section 3.3)",
            "reason": "the revoked-crl-only fixture pins the verdict for an agentId that is on the verifier's CRL; no fixture exercises the 5-minute cache bound or a stale-CRL window",
        },
        {
            "item": "Transparency-log monitor behavior (ATX core.md section 6.4)",
            "reason": "no fixture models a monitor and the conformance verifiers do not consult a log",
        },
    ],
}

# A fixture's `requirement` opens with the number of the core.md section it
# comes from, then names the step or rule: "§1.3 step 2: ...". The number must
# be that of a heading the fixture's `spec` list cites as ATX, and
# scripts/check_spec_refs.py holds every such heading to the pinned core.md.
REQUIREMENT_SECTION = re.compile(r"§(\d+(?:\.\d+[a-z]?)*)(?=[ ,:])")

# A fixture cites FIPS 204 exactly when its credential carries a signature of
# this algorithm.
FIPS_204 = "FIPS 204"
ML_DSA_65 = "ML-DSA-65"

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


def _cited_atx_sections(spec: object) -> set[str]:
    """The section numbers of a spec list's ATX citations: "1.3a.1" for the
    heading "1.3a.1 Legacy form ...", "13" for "13. Security considerations"."""
    if not isinstance(spec, list):
        return set()
    return {
        ref["section"].split(" ", 1)[0].rstrip(".")
        for ref in spec
        if isinstance(ref, dict) and ref.get("id") == "ATX" and isinstance(ref.get("section"), str)
    }


def _cites(spec: object, ident: str) -> bool:
    return isinstance(spec, list) and any(isinstance(r, dict) and r.get("id") == ident for r in spec)


def _signs_with(atx: object, algorithm: str) -> bool:
    sigs = atx.get("signatures") if isinstance(atx, dict) else None
    return isinstance(sigs, list) and any(
        isinstance(s, dict) and s.get("algorithm") == algorithm for s in sigs)


def _requirement_key(text: str) -> str:
    """Two requirements that differ only in case and blanks are the same one."""
    return " ".join(text.split()).casefold()


def requirement(path: Path, failures: list[str]) -> dict | None:
    """The requirement a fixture defines, or None with its failure recorded."""
    name = f"fixtures/{path.name}"
    # A failure names the fixture in a form that prints under a UTF-8 locale;
    # the requirement keeps the name as read, so one that has no UTF-8 form
    # fails the encoding check below.
    where = check_spec_refs.printable(name)
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
    missing = [k for k in ("name", "description", "requirement", "spec", "expected") if k not in fx]
    if missing:
        noun = "member" if len(missing) == 1 else "members"
        failures.append(f"{where}: has no {', '.join(map(repr, missing))} {noun}")
        return None
    text = fx["requirement"]
    if not isinstance(text, str) or not text.strip():
        failures.append(f"{where}: 'requirement' is not a non-empty string")
        return None
    section = REQUIREMENT_SECTION.match(text)
    if section is None:
        failures.append(f"{where}: 'requirement' does not open with the § number of a core.md section")
        return None
    if section.group(1) not in _cited_atx_sections(fx["spec"]):
        failures.append(
            f"{where}: 'requirement' names §{section.group(1)}, "
            "which no ATX citation in its 'spec' list carries"
        )
        return None
    cites_fips, signs_mldsa = _cites(fx["spec"], FIPS_204), _signs_with(fx.get("atx"), ML_DSA_65)
    if cites_fips and not signs_mldsa:
        failures.append(f"{where}: cites {FIPS_204} but its credential carries no {ML_DSA_65} signature")
        return None
    if signs_mldsa and not cites_fips:
        failures.append(f"{where}: its credential carries an {ML_DSA_65} signature but it does not cite {FIPS_204}")
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
        "fixture": name,
        "name": fx["name"],
        "requirement": text,
        "fixtureType": fx.get("fixtureType", "atx-credential"),
        "level": "MUST",
        "specRefs": fx["spec"],
        "expected": outcome,
        "description": fx["description"],
    }
    # A member that parsed can still be too deep to write back out, which is
    # refused before anything is rendered, or carry a lone surrogate escape,
    # which has no UTF-8 form: the requirement is encoded as the profile is.
    if _nests_deeper_than(MAX_DEPTH, req):
        failures.append(f"{where}: is nested too deeply to write into conformance.json")
        return None
    try:
        render(req).encode("utf-8")
    except UnicodeEncodeError as exc:
        failures.append(
            f"{where}: cannot be written into conformance.json as UTF-8 "
            f"({exc.reason}: {exc.object[exc.start:exc.end]!r})"
        )
        return None
    return req


def build(root: Path = REPO_ROOT) -> tuple[dict, list[str]]:
    """The profile, and a failure for each fixture that cannot be read into a
    requirement."""
    requirements: list[dict] = []
    failures: list[str] = []
    first_with: dict[str, str] = {}
    for path in sorted((root / "fixtures").glob("*.json")):
        req = requirement(path, failures)
        if req is None:
            continue
        # A requirement two fixtures share says which section both exercise,
        # not what either one tests.
        first = first_with.setdefault(_requirement_key(req["requirement"]), req["fixture"])
        if first != req["fixture"]:
            failures.append(f"{req['fixture']}: 'requirement' repeats that of {first}")
            continue
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


def _build(make: object) -> tuple[dict, list[str]] | None:
    """build() on a temporary tree, or None if it raised: a traceback is the
    defect these cases look for, so it shows as a red case."""
    with _fixtures(make) as root:
        try:
            return build(root)
        except Exception:
            return None


def _fails_by_name(make: object) -> bool:
    built = _build(make)
    return (built is not None and len(built[1]) == 1
            and built[1][0].startswith("fixtures/probe.json: ")
            and not built[0]["requirements"])


def _builds(make: object) -> bool:
    built = _build(make)
    return built is not None and not built[1] and len(built[0]["requirements"]) == 1


class _Renamed:
    """A fixture read from path under another file name. On Linux pathlib
    reads a name that is not valid UTF-8 with a lone surrogate per
    undecodable byte; macOS refuses to create such a file."""

    def __init__(self, path: Path, name: str) -> None:
        self.path, self.name = path, name

    def read_text(self, encoding: str) -> str:
        return self.path.read_text(encoding=encoding)


def _names_undecodable(fixture: object) -> bool:
    """requirement() on a fixture named bad-<0xFF>.json fails by name, and the
    failure prints under a UTF-8 locale."""
    failures: list[str] = []
    with _fixtures(fixture) as root:
        req = requirement(_Renamed(root / "fixtures" / "probe.json", "bad-\udcff.json"), failures)
    try:
        "".join(failures).encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (req is None and len(failures) == 1
            and failures[0].startswith("fixtures/bad-\\udcff.json: "))


def _cite(section: str) -> dict:
    """An ATX citation of a core.md heading."""
    return {"id": "ATX", "ref": check_spec_refs.CORE_REF, "section": section}


def _nested(depth: int) -> str:
    """A fixture nested depth levels deep: its spec holds a citation and arrays
    nested two levels less, so its requirement nests as deep as it does."""
    n = depth - 2
    return ('{"name": "p", "description": "d", "requirement": "§1.1: p", "spec": ['
            + json.dumps(_cite("1.1 ATX schema")) + ", " + "[" * n + "]" * n
            + '], "expected": {"verifyResult": "ACCEPT"}}')


def _with_other(fixture: dict, other: dict) -> object:
    """A maker writing fixture to fixtures/probe.json and other to
    fixtures/other.json, which sorts and is read first."""
    def make(probe: Path) -> None:
        probe.write_text(json.dumps(fixture), encoding="utf-8")
        (probe.parent / "other.json").write_text(json.dumps(other), encoding="utf-8")
    return make


def _repeat_reported(fixture: dict, other: dict) -> bool:
    """build() reports probe.json, by name, as repeating other.json's
    requirement, and keeps other.json's."""
    built = _build(_with_other(fixture, other))
    return (built is not None and len(built[1]) == 1
            and built[1][0].startswith("fixtures/probe.json: ")
            and "fixtures/other.json" in built[1][0]
            and [r["fixture"] for r in built[0]["requirements"]] == ["fixtures/other.json"])


def _main_on(make: object, argv: list[str]) -> tuple[int, str, str, bool]:
    """main(argv) on a temporary tree whose conformance.json holds a sentinel:
    the exit code, stdout, stderr, and whether conformance.json is unchanged."""
    sentinel = "sentinel\n"
    out, err = io.StringIO(), io.StringIO()
    with _fixtures(make) as root:
        (root / PROFILE).write_text(sentinel, encoding="utf-8")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv, root)
        unchanged = (root / PROFILE).read_text(encoding="utf-8") == sentinel
    return rc, out.getvalue(), err.getvalue(), unchanged


def self_test() -> int:
    good = {"name": "probe", "description": "d", "requirement": "§1.3 step 2: probe",
            "spec": [_cite("1.1 ATX schema"), _cite("1.3 Local verification algorithm")],
            "expected": {"verifyResult": "ACCEPT"}}
    fips = {"id": "FIPS 204", "ref": "https://csrc.nist.gov/pubs/fips/204/final", "section": "ML-DSA-65"}
    hybrid = {**good, "spec": [*good["spec"], fips],
              "atx": {"signatures": [{"algorithm": "Ed25519"}, {"algorithm": "ML-DSA-65"}]}}
    with _fixtures(good) as root:
        profile, failures = build(root)
    write_rc, _, _, write_unchanged = _main_on(good, [])
    broken_rc, _, _, broken_unchanged = _main_on("{", [])
    help_rc, help_out, _, help_unchanged = _main_on(good, ["--help"])
    h_rc, h_out, _, h_unchanged = _main_on(good, ["-h"])
    bad_rc, bad_out, bad_err, bad_unchanged = _main_on(good, ["--bogus"])
    cases: list[tuple[str, bool]] = [
        ("builds a well-formed fixture", not failures and len(profile["requirements"]) == 1),
        ("the requirement entry carries the fixture's requirement",
         [r.get("requirement") for r in profile["requirements"]] == [good["requirement"]]),
        ("spec.ref is core.md at the pinned atx-spec commit",
         profile["spec"]["ref"] == check_spec_refs.CORE_REF),
        ("reports a fixture with no requirement member by name",
         _fails_by_name({k: v for k, v in good.items() if k != "requirement"})),
        ("reports a requirement that is not a string by name",
         _fails_by_name({**good, "requirement": [good["requirement"]]})),
        ("reports a blank requirement by name", _fails_by_name({**good, "requirement": " \t"})),
        ("reports a requirement that does not open with a § section number by name",
         _fails_by_name({**good, "requirement": "step 2 of the verification algorithm"})),
        ("reports a requirement whose § section number comes after other text by name",
         _fails_by_name({**good, "requirement": "expiry, §1.3 step 2"})),
        ("reports a requirement naming a section the fixture does not cite by name",
         _fails_by_name({**good, "requirement": "§1.5: probe"})),
        ("reports a requirement whose section only a non-ATX citation names by name",
         _fails_by_name({**good, "requirement": "§3: probe",
                         "spec": [{"id": "AIP", "ref": "x", "section": "3 Signing"}]})),
        ("reads §13 from the heading '13. Security considerations'",
         _builds({**good, "requirement": "§13, Cryptographic agility: probe",
                  "spec": [_cite("13. Security considerations")]})),
        ("reads §1.3a.2 from the heading '1.3a.2 JCS form ...'",
         _builds({**good, "requirement": "§1.3a.2 rule 5: probe",
                  "spec": [_cite('1.3a.2 JCS form (`atcVersion` = "1.1")')]})),
        ("reports a requirement naming §1.3a.2 where the fixture cites only §1.3 by name",
         _fails_by_name({**good, "requirement": "§1.3a.2 rule 5: probe"})),
        ("reports a second fixture repeating another's requirement by name",
         _repeat_reported(good, {**good, "name": "other"})),
        ("reports a requirement that repeats another's but for case and blanks by name",
         _repeat_reported(good, {**good, "name": "other", "requirement": "§1.3  STEP 2:\tProbe "})),
        ("builds two fixtures with distinct requirements",
         (lambda b: b is not None and not b[1] and len(b[0]["requirements"]) == 2)(
             _build(_with_other(good, {**good, "name": "other", "requirement": "§1.3 step 3: probe"})))),
        ("builds a fixture citing FIPS 204 that carries an ML-DSA-65 signature", _builds(hybrid)),
        ("reports a fixture citing FIPS 204 with no ML-DSA-65 signature by name",
         _fails_by_name({**hybrid, "atx": {"signatures": [{"algorithm": "Ed25519"}]}})),
        ("reports a fixture citing FIPS 204 with no atx member by name",
         _fails_by_name({k: v for k, v in hybrid.items() if k != "atx"})),
        ("reports a fixture carrying an ML-DSA-65 signature that does not cite FIPS 204 by name",
         _fails_by_name({**hybrid, "spec": good["spec"]})),
        ("reports a fixture that is not JSON by name", _fails_by_name("{")),
        ("reports a fixture that is a JSON array by name", _fails_by_name([good])),
        ("reports a fixture that is a JSON number by name", _fails_by_name("5")),
        ("reports a fixture with no expected member by name",
         _fails_by_name({k: v for k, v in good.items() if k != "expected"})),
        ("reports an expected member that is not an object by name",
         _fails_by_name({**good, "expected": "ACCEPT"})),
        ("reports an expected member that is the string 'verifyResult' by name",
         _fails_by_name({**good, "expected": "verifyResult"})),
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
        ("reports a fixture carrying a lone surrogate escape by name",
         _fails_by_name(json.dumps({**good, "description": "SURROGATE"})
                        .replace("SURROGATE", "\\ud800"))),
        ("reports a fixture whose file name is not valid UTF-8 by name, in printable form",
         _names_undecodable(good)),
        ("writes conformance.json for a well-formed fixture", write_rc == 0 and not write_unchanged),
        ("refuses to write conformance.json when a fixture is broken",
         broken_rc == 1 and broken_unchanged),
        ("--help prints usage and writes nothing",
         help_rc == 0 and help_out == USAGE and help_unchanged),
        ("-h prints usage and writes nothing", h_rc == 0 and h_out == USAGE and h_unchanged),
        ("an unknown argument prints usage to stderr, exits 2 and writes nothing",
         bad_rc == 2 and bad_err == USAGE and not bad_out and bad_unchanged),
        ("the docstring's Usage block is USAGE", __doc__ is None or __doc__.endswith(USAGE)),
    ]
    failed = 0
    for label, ok in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        failed += not ok
    print(f"conformance-profile self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


def main(argv: list[str], root: Path = REPO_ROOT) -> int:
    if argv in (["-h"], ["--help"]):
        print(USAGE, end="")
        return 0
    if argv == ["--self-test"]:
        return self_test()
    if argv not in ([], ["--check"]):
        print(USAGE, end="", file=sys.stderr)
        return 2
    out = root / PROFILE
    profile, failures = build(root)
    if failures:
        for f in failures:
            print(f"FAIL {f}")
        print(f"{len(failures)} fixture(s) cannot go into conformance.json; nothing written")
        return 1
    rendered = render(profile)
    if argv == ["--check"]:
        if self_test():
            return 1
        if not out.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if out.read_text(encoding="utf-8") != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
        # Every ATX citation must name a heading of the pinned core.md. The
        # self-test runs first so the check is proven able to fail.
        if check_spec_refs.self_test() or check_spec_refs.report(root):
            return 1
        return 0
    out.write_text(rendered, encoding="utf-8")
    print(f"wrote conformance.json ({len(profile['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
