#!/usr/bin/env python3
"""Binding Decision 10: no other codebase is named in this suite's generated artifacts.

WHAT HAPPENED. A fixture description in this suite stated what a private verifier
in another repository does. The statement was wrong. It stood for seven weeks,
was corrected in the README, and came back 39 days later -- because the
correction edited the JSON and the fixture GENERATOR still held the string, so
the next regeneration wrote it straight back.

WHAT THIS ENFORCES. Exactly what Binding Decision 10 asks for and nothing more:

    zero occurrences of another codebase's identifiers in the generated
    artifacts (fixtures/, conformance.json, and the two vector directories).

It is an exact, case-insensitive substring test over a short list of names. It is
deliberately dumb. There is no allowlist, no resolver, no attempt to decide
whether a sentence is a "claim". Everything below is chosen so the check has no
false positives by construction: the identifiers are names of OTHER
repositories, and this suite has no legitimate reason to write them into a file
a generator produces.

WHY IT IS THIS SMALL, which is the expensive lesson. Three earlier versions tried
to decide the general question -- may this text name that thing, and is it
asserting something about it. Three independent adversarial reviews found 7, then
40, then 51 reproduced bypasses, each round reviewing the previous round's fix.
The count did not fall when the attack surface was cut in half, because "is this
sentence a claim about another codebase" has an unbounded input space and no
finite rule set fails closed over it. The last version also shipped two defects
of its own: an allowlist entry added for a legitimate provenance citation
silently re-permitted the retracted sentence at the same site, and its self-test
validated the rule against a clean fixture rather than against the shipped
configuration, so it reported 8 of 8 published claims caught while 2 of 8 were
green in production.

WHAT THIS CANNOT DO. Stated plainly, because the previous versions' failure was
promising more than they delivered:

  L1  It catches RECURRENCE, not invention. A NEW claim about a codebase not
      named below passes. That is the accepted trade: the measured failure mode
      here was the same string returning through the generator, and this closes
      exactly that.
  L2  It governs GENERATED artifacts only. Hand-maintained source and prose are
      reviewed by humans, and they legitimately cite the package these verifiers
      are derived from -- `opena2a-registry` appears 15 times in tracked source
      on main, every one of them a provenance citation in a file a reviewer
      reads. Scoping to generated files is what gives this check zero false
      positives.
  L3  It says nothing about whether a claim is TRUE. No CI check can.

Adding a name below is cheap and expected: when this suite is found naming
another codebase in a generated file, fix the generator and add the identifier
here so it cannot come back a third time.

Usage:
    python3 scripts/check_no_implementation_status.py
    python3 scripts/check_no_implementation_status.py --self-test
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Files a generator writes. Decision 10 names `fixtures/` and `conformance.json`;
# the two vector directories are the same class of artifact and are included so
# the rule covers everything nobody edits by hand.
GENERATED_GLOBS = [
    "fixtures/*.json",
    "conformance.json",
    "jcs-vectors/vectors/*.json",
    "vectors/*.json",
]

# Identifiers of OTHER codebases, each taken from text this repository actually
# published and has since retracted. Matched case-insensitively as a substring.
#
# Every entry must satisfy two properties, and --self-test enforces both:
#   * it FIRES -- writing it into a generated artifact fails the check, so no
#     entry is decoration;
#   * it is ABSENT from the current tree, so the check is green on a clean repo.
DENIED = [
    ("opena2a-registry",
     "The private registry repository. The retracted claim named its offline "
     "verifier."),
    ("atcverify",
     "The registry's offline verifier package. Subsumes the `pkg/atcverify` "
     "spelling, which is how the claim was usually written."),
    ("agent-identity-management",
     "A second private repository, named by a retracted README paragraph about "
     "its credential issuer."),
    ("atc_issuer",
     "The issuer source file in that repository."),
    ("RealATCIssuer",
     "The issuer type in that repository."),
    ("atc_service",
     "The registry-side issuance path, named by a retracted README section."),
    ("did:opena2a:registry:opena2a.org",
     "A trusted-issuer DID a retracted sentence said the production verifier "
     "hardcodes."),
]

WS_RE = re.compile(r"\s+")


def normalise(text: str) -> str:
    """Lower-case and collapse whitespace.

    Collapsing whitespace means a name split across a line break, or padded with
    extra spaces, is still the same name. A generator writes JSON on one line so
    this rarely matters, but it costs nothing and removes a way to be clever.
    """
    return WS_RE.sub(" ", text).lower()


def generated_files(root: Path) -> list[Path]:
    out: set[Path] = set()
    for glob in GENERATED_GLOBS:
        for p in root.glob(glob):
            if p.is_file():
                out.add(p)
    return sorted(out)


def check(root: Path) -> list[str]:
    """Every occurrence of a denied identifier in a generated artifact."""
    failures: list[str] = []
    for path in generated_files(root):
        raw = path.read_text(encoding="utf-8")
        hay = normalise(raw)
        for name, _why in DENIED:
            needle = normalise(name)
            start = hay.find(needle)
            if start < 0:
                continue
            excerpt = hay[max(0, start - 60):start + len(needle) + 60].strip()
            failures.append(
                f"{path.relative_to(root)}: names '{name}', which belongs to "
                f"another codebase.\n      ...{excerpt}...\n      This file is "
                f"GENERATED. Fix the generator string and regenerate; editing "
                f"the JSON is what let this return once already."
            )
    return failures


# --- self-test ---------------------------------------------------------------
#
# Two properties, both of which an earlier version of this file got wrong.
#
# It drives the REAL check() against temporary directories rather than
# re-implementing the rule, because a self-test that rebuilds the rule it tests
# proves only that two copies of one idea agree.
#
# And it measures every mutant through the real entry point rather than through
# the handle it just rebound. An earlier version computed `bool(f(ctx))` directly
# after binding that name to a function returning [] -- `bool([])` by
# construction, an assertion that could not fail.


def _probe(body: str, rel: str = "fixtures/probe.json") -> list[str]:
    tmp = Path(tempfile.mkdtemp(prefix="decision10-"))
    try:
        target = tmp / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return check(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _report(cases: list[tuple[bool, str, str]]) -> int:
    failed = 0
    for ok, label, detail in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        if not ok:
            print(f"          {detail}")
            failed += 1
    return failed


def _entry_cases() -> list[tuple[bool, str, str]]:
    """Every DENIED entry fires, and none of them is already in the tree."""
    out = []
    seen: set[str] = set()
    for name, why in DENIED:
        key = normalise(name)
        if not name.strip():
            out.append((False, "denied entry is empty", "an empty needle matches everything"))
            continue
        if key in seen:
            out.append((False, f"denied entry '{name}' is a duplicate",
                        "a duplicate entry reports the same finding twice"))
            continue
        seen.add(key)
        if not why.strip():
            out.append((False, f"denied entry '{name}' has no reason",
                        "every entry records the retracted text it came from"))
        fired = bool(_probe(json.dumps({"description": f"NOTE: the {name} verifier."})))
        out.append((fired, f"'{name}' fires when written into a generated artifact",
                    "this entry is decoration -- check() does not act on it"))
    return out


def _scope_cases() -> list[tuple[bool, str, str]]:
    """The rule reaches every generated glob, and stops at the boundary."""
    out = []
    for glob in GENERATED_GLOBS:
        rel = glob.replace("*", "probe")
        fired = bool(_probe(json.dumps({"description": "see opena2a-registry"}), rel))
        out.append((fired, f"scope: {glob} reaches {rel}",
                    "this pattern matched nothing the rule reads"))
    # Hand-maintained files are NOT governed. This is limit L2, asserted rather
    # than assumed: the provenance citations in tracked source must stay legal,
    # or this check acquires the false positives it exists to avoid.
    for rel in ("README.md", "verifiers/go/verify.go", "scripts/generate-fixtures/main.go"):
        quiet = not _probe("canonicalPayload mirrors opena2a-registry/pkg/atcverify.\n", rel)
        out.append((quiet, f"scope: {rel} is NOT governed (limit L2)",
                    "a hand-maintained file was governed -- the provenance "
                    "citations on main would fail the build"))
    return out


def _mutant_cases() -> list[tuple[bool, str, str]]:
    """A check that stopped looking must not read as a clean tree."""
    out = []
    body = json.dumps({"description": "NOTE: opena2a-registry verifies Ed25519 only."})
    live = len(_probe(body))
    out.append((live > 0, "mutant-harness: the probe artifact has findings",
                "HARNESS: no findings at all, so every mutant below proves nothing"))
    for label, name, value in (("DENIED = []", "DENIED", []),
                               ("GENERATED_GLOBS = []", "GENERATED_GLOBS", []),
                               ("normalise() -> ''", "normalise", lambda _t: "")):
        original = globals()[name]
        globals()[name] = value
        try:
            mutated = len(_probe(body))
        finally:
            globals()[name] = original
        # The property is that the mutation is OBSERVABLE through the real
        # entry point -- not that it is quieter. Asserting `mutated < live` was
        # wrong in one direction and this case caught it: emptying normalise()
        # makes every needle the empty string, which matches everything, so the
        # check fires MORE. Both directions are defects, and both are detected
        # by asking whether the output changed at all.
        out.append((live > 0 and mutated != live, f"mutant KILLED: {label}",
                    f"SURVIVED: {mutated} findings, same as unmutated ({live}) -- "
                    f"the check does not read {name} at call time"))
    return out


def _tree_case() -> list[tuple[bool, str, str]]:
    """The check is green on the real tree, so a red run means something changed."""
    findings = check(ROOT)
    return [(not findings, f"the current tree is clean "
                           f"({len(generated_files(ROOT))} generated artifacts)",
             f"{findings[:1]}")]


# A section that runs no cases would otherwise report success.
FLOORS = {"entries": len(DENIED), "scope": 4, "mutants": 4, "tree": 1}


def self_test() -> int:
    failed = 0
    for key, heading, fn in (
        ("entries", "every denied identifier fires, and is not already here", _entry_cases),
        ("scope", "the rule reaches every generated glob and stops at the boundary", _scope_cases),
        ("mutants", "a check that stopped looking must not read as clean", _mutant_cases),
        ("tree", "the real tree", _tree_case),
    ):
        print(f"\n{heading}\n")
        cases = fn()
        failed += _report(cases)
        if len(cases) < FLOORS[key]:
            print(f"  [RED  ] section '{key}' ran {len(cases)} cases, floor is {FLOORS[key]}")
            failed += 1
    return failed


CAVEAT = (
    "  This checks that the identifiers listed in DENIED do not appear in a\n"
    "  GENERATED artifact. It catches the recurrence of a known claim, not the\n"
    "  invention of a new one, and it does not govern hand-maintained source or\n"
    "  prose -- those are reviewed by people. See L1-L3 in this file's header."
)


def main() -> int:
    # An unrecognised flag must not fall through to the default check and exit 0.
    # `--self-tets` would then report success while never running the self-test:
    # the same "believed to have run" failure this file exists to prevent.
    unknown = [a for a in sys.argv[1:] if a != "--self-test"]
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(f"usage: {Path(sys.argv[0]).name} [--self-test]", file=sys.stderr)
        return 2

    if "--self-test" in sys.argv:
        failed = self_test()
        if failed:
            print(f"\nself-test FAILED: {failed} case(s)", file=sys.stderr)
            return 1
        print("\nself-test passed: every denied identifier fires, every mutant is "
              "killed,\nhand-maintained files stay ungoverned, the tree is clean")
        return 0

    failures = check(ROOT)
    if failures:
        print("implementation-status check failed:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"no other codebase is named in the {len(generated_files(ROOT))} "
          f"generated artifacts")
    print(CAVEAT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
