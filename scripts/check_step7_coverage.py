#!/usr/bin/env python3
"""conformance.json and the pinned core.md drop section 1.3 step 7 together.

WHAT HAPPENED. conformance.json lists the distinct signer-authority count of
ATX core.md §1.3 step 7 under `notCovered`, because the Coverage paragraph of
core.md at the pinned atx-spec commit lists step 7 among the requirements no
fixture exercises, and the README says the two drop it together. No script
compared them: with the step 7 entry removed from the profile,
`scripts/conformance_profile.py --check` still reported the profile current.

WHAT THIS ENFORCES.

  * Coupling. `notCovered` in conformance.json has an entry whose `item`
    names "section 1.3 step 7" exactly when the sentence of the Coverage
    paragraph of the vendored core.md that lists the requirements no fixture
    exercises names "§1.3 step 7". Neither drops step 7, or adds it back,
    without the other.
  * Fixtures first. When neither lists step 7, the fixture set must exercise
    it: at least one fixture whose `verifierState.requiredTrustLevel` is an
    integer of 3 or higher expects ACCEPT, and at least one expects REJECT
    with `rejectCategory` INSUFFICIENT_SIGNER_AUTHORITIES.

scripts/check_spec_refs.py holds the vendored core.md to the pinned atx-spec
commit, so the Coverage paragraph changes only with a re-pin, and a re-pin
that drops step 7 from it fails here until `notCovered` drops it too.

WHAT THIS CANNOT DO. It finds the list by its wording: exactly one paragraph
outside fenced code that opens with "**Coverage.**", and in it exactly one
sentence containing "no fixture exercises" in any letter case. A re-pinned
core.md that words
either another way fails here until this script is updated in the same
change. It checks that the step 7 fixtures exist with those verdicts, not what
a verifier does with them; the reference verifiers run them.

`scripts/conformance_profile.py --check` runs this self-test and check after
those of scripts/check_spec_refs.py, so CI enforces it through the existing
conformance-profile step.

Usage:
    python3 scripts/check_step7_coverage.py               run the check
    python3 scripts/check_step7_coverage.py --self-test   prove the check can fail
    python3 scripts/check_step7_coverage.py --help        print this usage
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

# One definition of the vendored core.md path and of fenced code, shared with
# the citation check that holds that copy to the pinned commit.
from check_spec_refs import CORE_MD, FENCE_RE

ROOT = Path(__file__).resolve().parent.parent
# Not sliced from __doc__, which `python -OO` strips. The self-test holds the
# docstring's Usage block equal to this text.
USAGE = """\
Usage:
    python3 scripts/check_step7_coverage.py               run the check
    python3 scripts/check_step7_coverage.py --self-test   prove the check can fail
    python3 scripts/check_step7_coverage.py --help        print this usage
"""
OPTIONS = ("-h", "--help", "--self-test")
PROFILE = Path("conformance.json")
FIXTURES = Path("fixtures")

COVERAGE_OPEN = "**Coverage.**"
NOT_EXERCISED_RE = re.compile(r"\bno fixture exercises\b", re.IGNORECASE)
CORE_STEP7_RE = re.compile(r"§1\.3 step 7\b")
PROFILE_STEP7_RE = re.compile(r"\bsection 1\.3 step 7\b")
REJECT_CATEGORY = "INSUFFICIENT_SIGNER_AUTHORITIES"
# A sentence ends at a full stop followed by white space and a capital letter.
SENTENCE_BREAK_RE = re.compile(r"(?<=\.)\s+(?=[A-Z])")


def paragraphs(text: str) -> list[str]:
    """Each paragraph of a markdown document outside fenced code, its lines joined by one space."""
    out: list[str] = []
    lines: list[str] = []
    fence: str | None = None
    for line in text.splitlines() + [""]:
        m = FENCE_RE.match(line)
        if fence is not None:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            continue
        if m:
            fence = m.group(1)
        if m or not line.strip():
            if lines:
                out.append(" ".join(lines))
                lines = []
            continue
        lines.append(line.strip())
    return out


def coverage_lists_step7(core_text: str) -> tuple[bool | None, str]:
    """Whether the Coverage paragraph lists §1.3 step 7 among the requirements no
    fixture exercises; (None, why) when that paragraph or sentence is not found once."""
    found = [p for p in paragraphs(core_text) if p.startswith(COVERAGE_OPEN)]
    if len(found) != 1:
        return None, f"{CORE_MD} has {len(found)} paragraphs that open with {COVERAGE_OPEN}, not 1"
    sentences = [s for s in SENTENCE_BREAK_RE.split(found[0]) if NOT_EXERCISED_RE.search(s)]
    if len(sentences) != 1:
        return None, (
            f"the Coverage paragraph of {CORE_MD} has {len(sentences)} sentences that say "
            f"'no fixture exercises', not 1"
        )
    return bool(CORE_STEP7_RE.search(sentences[0])), ""


def profile_lists_step7(profile: dict) -> bool:
    """Whether a notCovered item (not its reason) names section 1.3 step 7."""
    return any(
        isinstance(entry, dict) and bool(PROFILE_STEP7_RE.search(str(entry.get("item", ""))))
        for entry in profile.get("notCovered", [])
    )


def step7_arms(root: Path) -> tuple[list[str], list[str]]:
    """Fixtures whose verifierState.requiredTrustLevel is an integer of 3 or higher:
    (those expecting ACCEPT, those expecting REJECT[INSUFFICIENT_SIGNER_AUTHORITIES])."""
    accept: list[str] = []
    reject: list[str] = []
    for path in sorted((root / FIXTURES).glob("*.json")):
        fx = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(fx, dict):
            continue
        level = (fx.get("verifierState") or {}).get("requiredTrustLevel")
        if type(level) is not int or level < 3:
            continue
        expected = fx.get("expected") or {}
        verdict = str(expected.get("verifyResult", "")).upper()
        if verdict == "ACCEPT":
            accept.append(path.name)
        elif verdict == "REJECT" and expected.get("rejectCategory") == REJECT_CATEGORY:
            reject.append(path.name)
    return accept, reject


def check(root: Path) -> list[str]:
    """The failures of the step 7 coupling of notCovered, the Coverage paragraph and the fixtures."""
    if not (root / CORE_MD).exists():
        return [f"{CORE_MD} is missing; vendor core.md from the pinned atx-spec ref"]
    if not (root / PROFILE).exists():
        return [f"{PROFILE} is missing; run scripts/conformance_profile.py"]
    in_core, why = coverage_lists_step7((root / CORE_MD).read_text(encoding="utf-8"))
    if in_core is None:
        return [f"{why}. Update scripts/check_step7_coverage.py in the change that re-pins core.md."]
    in_profile = profile_lists_step7(json.loads((root / PROFILE).read_text(encoding="utf-8")))
    if in_core and not in_profile:
        return [
            f"the Coverage paragraph of {CORE_MD} lists §1.3 step 7 among the requirements no "
            f"fixture exercises, but no {PROFILE} notCovered item names section 1.3 step 7. The two "
            f"drop step 7 together: restore the entry in scripts/conformance_profile.py and regenerate."
        ]
    if in_profile and not in_core:
        return [
            f"{PROFILE} notCovered names section 1.3 step 7, but the Coverage paragraph of {CORE_MD} "
            f"does not list it among the requirements no fixture exercises. Drop the entry from "
            f"scripts/conformance_profile.py in the change that re-pins core.md, and regenerate."
        ]
    if in_core:
        return []
    accept, reject = step7_arms(root)
    failures: list[str] = []
    dropped = f"§1.3 step 7 is off both {PROFILE} notCovered and the Coverage paragraph of {CORE_MD}"
    if not accept:
        failures.append(
            f"{dropped}, but no fixture whose verifierState.requiredTrustLevel is 3 or higher "
            f"expects ACCEPT. Step 7 leaves both only while its fixtures exist."
        )
    if not reject:
        failures.append(
            f"{dropped}, but no fixture whose verifierState.requiredTrustLevel is 3 or higher "
            f"expects REJECT[{REJECT_CATEGORY}]. Step 7 leaves both only while its fixtures exist."
        )
    return failures


# --- self-test ---------------------------------------------------------------
#
# Drives the real check() against temporary trees. The Coverage paragraphs are
# shaped like the vendored one: an opening sentence, the sentence that lists
# what no fixture exercises, and a closing sentence.

WITH = (
    "**Coverage.** The suite is the executable definition of the requirements it has fixtures "
    "for, and no more. Requirements stated normatively in this document that no fixture "
    "exercises include the distinct-signer-authority count of §1.3 step 7, and revocation "
    "propagation timing (§3.3). An implementation MUST self-attest these requirements until "
    "fixtures exist for them."
)
WITHOUT = WITH.replace("the distinct-signer-authority count of §1.3 step 7, and ", "")
ELSEWHERE = WITHOUT + " The suite exercises §1.3 step 7 through its required-trust-level fixtures."
FENCED_WITH = "```\n" + WITH + "\n```"

STEP7 = {"item": "Distinct signer-authority count (ATX core.md section 1.3 step 7)", "reason": "probe"}
OTHER = {"item": "Revocation propagation timing (ATX core.md section 3.3)", "reason": "probe"}
STEP7_IN_REASON = {
    "item": "Cosignature requirements (ATX core.md section 7)",
    "reason": "the required-trust-level fixtures pin the section 1.3 step 7 count",
}


def _fx(level: object, verdict: str, category: str | None = None) -> dict:
    expected = {"verifyResult": verdict}
    if category:
        expected["rejectCategory"] = category
    state = {} if level is None else {"requiredTrustLevel": level}
    return {"verifierState": state, "expected": expected}


ARMS = {
    "accept.json": _fx(3, "ACCEPT"),
    "reject.json": _fx(3, "REJECT", REJECT_CATEGORY),
}


def _probe(paras: list[str], not_covered: list[dict], fixtures: dict[str, dict]) -> list[str]:
    tmp = Path(tempfile.mkdtemp(prefix="step7-coverage-"))
    try:
        (tmp / CORE_MD).parent.mkdir(parents=True)
        (tmp / CORE_MD).write_text("# ATX core architecture\n\n" + "\n\n".join(paras) + "\n", encoding="utf-8")
        (tmp / PROFILE).write_text(json.dumps({"notCovered": not_covered}), encoding="utf-8")
        (tmp / FIXTURES).mkdir()
        for name, fx in fixtures.items():
            (tmp / FIXTURES / name).write_text(json.dumps(fx), encoding="utf-8")
        return check(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def self_test() -> int:
    cases: list[tuple[str, bool]] = [
        ("accepts both listing step 7 before any step 7 fixture exists",
         not _probe([WITH], [STEP7, OTHER], {})),
        ("rejects notCovered without step 7 while the Coverage paragraph lists it",
         bool(_probe([WITH], [OTHER], ARMS))),
        ("rejects notCovered with step 7 while the Coverage paragraph does not list it",
         bool(_probe([WITHOUT], [STEP7, OTHER], ARMS))),
        ("accepts both without step 7 when an ACCEPT and an INSUFFICIENT_SIGNER_AUTHORITIES "
         "REJECT fixture require trust level 3",
         not _probe([WITHOUT], [OTHER], ARMS)),
        ("rejects both without step 7 when no fixture sets requiredTrustLevel",
         bool(_probe([WITHOUT], [OTHER], {
             "accept.json": _fx(None, "ACCEPT"),
             "reject.json": _fx(None, "REJECT", REJECT_CATEGORY),
         }))),
        ("rejects both without step 7 when the fixtures require trust level 2",
         bool(_probe([WITHOUT], [OTHER], {
             "accept.json": _fx(2, "ACCEPT"),
             "reject.json": _fx(2, "REJECT", REJECT_CATEGORY),
         }))),
        ("rejects both without step 7 when no step 7 fixture expects ACCEPT",
         bool(_probe([WITHOUT], [OTHER], {"reject.json": ARMS["reject.json"]}))),
        ("rejects both without step 7 when no step 7 REJECT is INSUFFICIENT_SIGNER_AUTHORITIES",
         bool(_probe([WITHOUT], [OTHER], {
             "accept.json": ARMS["accept.json"],
             "reject.json": _fx(3, "REJECT", "SIGNATURE_INVALID"),
         }))),
        ("does not take a requiredTrustLevel of true or of the string 3 as trust level 3",
         bool(_probe([WITHOUT], [OTHER], {
             "accept.json": _fx(True, "ACCEPT"),
             "reject.json": _fx("3", "REJECT", REJECT_CATEGORY),
         }))),
        ("does not take section 1.3 step 7 in another entry's reason as the step 7 entry",
         bool(_probe([WITH], [STEP7_IN_REASON, OTHER], ARMS))),
        ("reads step 7 from the not-exercised sentence only, not elsewhere in the paragraph",
         not _probe([ELSEWHERE], [OTHER], ARMS)),
        ("ignores a Coverage paragraph inside fenced code",
         not _probe([FENCED_WITH, WITHOUT], [OTHER], ARMS)),
        ("fails closed when core.md has no Coverage paragraph",
         bool(_probe(["Some other paragraph that no fixture exercises."], [OTHER], ARMS))),
        ("fails closed when core.md has two Coverage paragraphs",
         bool(_probe([WITHOUT, WITHOUT], [OTHER], ARMS))),
        ("fails closed when the Coverage paragraph has no not-exercised sentence",
         bool(_probe(["**Coverage.** The suite is the executable definition of its fixtures."],
                     [OTHER], ARMS))),
        ("fails closed when the Coverage paragraph has two not-exercised sentences",
         bool(_probe([WITHOUT + " Another list that no fixture exercises names §6.4."], [OTHER], ARMS))),
        ("the docstring's Usage block is USAGE", __doc__ is None or __doc__.endswith(USAGE)),
    ]
    failed = 0
    for label, ok in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        failed += not ok
    print(f"self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


def report(root: Path = ROOT) -> int:
    failures = check(root)
    for f in failures:
        print(f"FAIL {f}")
    if failures:
        return 1
    listed, _ = coverage_lists_step7((root / CORE_MD).read_text(encoding="utf-8"))
    if listed:
        print(f"{PROFILE} notCovered and the Coverage paragraph of {CORE_MD} both list §1.3 step 7")
    else:
        print(
            f"neither {PROFILE} notCovered nor the Coverage paragraph of {CORE_MD} lists §1.3 "
            f"step 7, and its fixtures exist"
        )
    return 0


def main(argv: list[str]) -> int:
    if argv in (["-h"], ["--help"]):
        print(USAGE, end="")
        return 0
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        unknown = [arg for arg in argv if arg not in OPTIONS]
        if unknown:
            print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(USAGE, end="", file=sys.stderr)
        return 2
    return report()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
