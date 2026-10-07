#!/usr/bin/env python3
"""Every ATX citation this suite publishes names a real heading of core.md.

WHAT HAPPENED. Every fixture cited ATX core.md as "§1.1 Credential schema and
§6 Threshold cosignature", and every JCS vector as "§1.3a ATX v1.1 TBS
canonical form (JCS / RFC 8785)". Neither matched the spec: core.md's §1.1 is
"ATX schema", its §6 is "Transparency log", and §1.3a is "Canonical signing
form". The strings were written by the two generators, so nothing compared
them with the document they cite.

WHAT THIS ENFORCES. In every file a generator writes that carries citations
(fixtures/*.json, jcs-vectors/vectors/*.json, and the requirements of
conformance.json), each citation with id "ATX":

  * points at atx-spec core.md, and
  * has a `section` string EQUAL to the text of one heading of core.md, as
    vendored at the pinned atx-spec commit in schemas/vendor/atx-spec/core.md.

Each of those files must also carry at least one ATX citation, so a file that
drops its citation cannot pass by having nothing to check.

Equality is exact on purpose: "1.1 ATX schema" passes, "§1.1 ATX schema" and
"ATX schema" do not. A citation that must name two sections carries two ATX
entries.

The vendored copy is held to the pinned commit, so a heading cannot be made to
exist by editing it:

  * its SHA-256 must equal CORE_MD_SHA256, the digest of core.md at atx-spec
    commit CORE_MD_SPEC_REF, and
  * CORE_MD_SPEC_REF must be the one atx-spec commit that the CI workflow
    checks out for the vendored-schema drift gate, so moving that pin without
    re-vendoring core.md fails here.

WHAT THIS CANNOT DO. It proves a cited heading exists, not that it is the right
section for the fixture. The digest is recorded in this script, so it proves
the copy is unchanged since it was vendored, not that it was fetched correctly;
the gh command beside CORE_MD_SHA256 confirms that against atx-spec.

`scripts/conformance_profile.py --check` runs the self-test and the check, so
CI enforces this through the existing conformance-profile step.

Usage:
    python3 scripts/check_spec_refs.py
    python3 scripts/check_spec_refs.py --self-test
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_MD = Path("schemas/vendor/atx-spec/core.md")
CORE_REF_SUFFIX = "/atx-spec/blob/main/core.md"
WORKFLOW = Path(".github/workflows/conformance.yml")

# The atx-spec commit core.md was vendored from, and the SHA-256 of core.md at
# that commit. When the atx-spec pin in WORKFLOW moves, re-vendor core.md from
# the new commit and update both constants together. To confirm the digest
# against the source:
#   gh api "repos/opena2a-standards/atx-spec/contents/core.md?ref=<CORE_MD_SPEC_REF>" \
#     -H "Accept: application/vnd.github.raw" | shasum -a 256
CORE_MD_SPEC_REF = "e89bed94ca0a7308e2d6915e384be4c89d3a67df"
CORE_MD_SHA256 = "0639fe4e2fd3acf9277cacd639ac0da27cf538c2b64648b349d4db48de730d3d"

# ATX headings (CommonMark): up to three spaces of indent, 1-6 `#`, a space,
# the text, an optional closing run of `#`. Lines inside fenced code blocks are
# not headings.
HEADING_RE = re.compile(r"^ {0,3}#{1,6}[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# The atx-spec checkout in WORKFLOW: `repository:` followed by its `ref:`.
SPEC_PIN_RE = re.compile(
    r"repository:[ \t]*opena2a-standards/atx-spec[ \t]*\r?\n[ \t]*ref:[ \t]*([0-9a-f]{40})\b"
)


def core_headings(text: str) -> set[str]:
    """The text of every heading in a markdown document."""
    headings: set[str] = set()
    fence: str | None = None
    for line in text.splitlines():
        m = FENCE_RE.match(line)
        if m:
            marker = m.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None:
            h = HEADING_RE.match(line)
            if h:
                headings.add(h.group(1))
    return headings


def cited_files(root: Path) -> list[tuple[Path, list[dict]]]:
    """(file, citations) for every generated file that carries citations."""
    out: list[tuple[Path, list[dict]]] = []
    for path in sorted((root / "fixtures").glob("*.json")):
        out.append((path, json.loads(path.read_text(encoding="utf-8"))["spec"]))
    for path in sorted((root / "jcs-vectors" / "vectors").glob("*.json")):
        out.append((path, [json.loads(path.read_text(encoding="utf-8"))["spec"]]))
    profile = root / "conformance.json"
    if profile.exists():
        for req in json.loads(profile.read_text(encoding="utf-8"))["requirements"]:
            out.append((profile, req["specRefs"]))
    return out


def pin_failures(root: Path) -> list[str]:
    """Whether the vendored core.md is core.md at the atx-spec commit CI pins."""
    failures: list[str] = []
    digest = hashlib.sha256((root / CORE_MD).read_bytes()).hexdigest()
    if digest != CORE_MD_SHA256:
        failures.append(
            f"{CORE_MD} has SHA-256 {digest}, not {CORE_MD_SHA256} (core.md at atx-spec "
            f"{CORE_MD_SPEC_REF}). Re-vendor it from the pinned commit; do not edit it."
        )
    workflow = root / WORKFLOW
    pins = set(SPEC_PIN_RE.findall(workflow.read_text(encoding="utf-8"))) if workflow.exists() else set()
    if pins != {CORE_MD_SPEC_REF}:
        failures.append(
            f"{WORKFLOW} pins atx-spec at {', '.join(sorted(pins)) or 'no commit'}, but {CORE_MD} "
            f"was vendored at {CORE_MD_SPEC_REF}. Re-vendor core.md from the pinned commit and "
            f"update CORE_MD_SPEC_REF and CORE_MD_SHA256 in scripts/check_spec_refs.py."
        )
    return failures


def check(root: Path) -> list[str]:
    """Every ATX citation that does not name a heading of the vendored core.md."""
    core = root / CORE_MD
    if not core.exists():
        return [f"{CORE_MD} is missing; vendor core.md from the pinned atx-spec ref"]
    failures = pin_failures(root)
    headings = core_headings(core.read_text(encoding="utf-8"))
    for path, refs in cited_files(root):
        rel = path.relative_to(root)
        atx = [r for r in refs if r.get("id") == "ATX"]
        if not atx:
            failures.append(f"{rel}: carries no ATX citation")
        for ref in atx:
            if not str(ref.get("ref", "")).endswith(CORE_REF_SUFFIX):
                failures.append(f"{rel}: ATX citation points at {ref.get('ref')!r}, not core.md")
            elif ref.get("section") not in headings:
                failures.append(
                    f"{rel}: ATX section {ref.get('section')!r} is not a heading of "
                    f"{CORE_MD}. Cite the heading text exactly; fix the generator "
                    f"and regenerate."
                )
    return failures


# --- self-test ---------------------------------------------------------------
#
# Drives the real check() against a temporary tree that holds the real vendored
# core.md, so the rule is proven against the document it actually reads.

RETIRED_SECTIONS = [
    "§1.1 Credential schema and §6 Threshold cosignature",
    "§1.3a ATX v1.1 TBS canonical form (JCS / RFC 8785)",
]


def _probe(refs: list[dict], core_extra: str = "", workflow: str | None = None) -> list[str]:
    tmp = Path(tempfile.mkdtemp(prefix="spec-refs-"))
    try:
        (tmp / CORE_MD).parent.mkdir(parents=True)
        (tmp / CORE_MD).write_bytes((ROOT / CORE_MD).read_bytes() + core_extra.encode("utf-8"))
        (tmp / WORKFLOW).parent.mkdir(parents=True)
        if workflow is None:
            shutil.copyfile(ROOT / WORKFLOW, tmp / WORKFLOW)
        else:
            (tmp / WORKFLOW).write_text(workflow, encoding="utf-8")
        (tmp / "fixtures").mkdir()
        (tmp / "fixtures" / "probe.json").write_text(json.dumps({"spec": refs}), encoding="utf-8")
        return check(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _atx(section: str, ref: str = "https://github.com/opena2a-standards" + CORE_REF_SUFFIX) -> dict:
    return {"id": "ATX", "ref": ref, "section": section}


def self_test() -> int:
    aip = {"id": "AIP", "ref": "https://example.org/AIP-SPEC.md", "section": "anything"}
    workflow = (ROOT / WORKFLOW).read_text(encoding="utf-8")
    cases: list[tuple[str, bool]] = [(f"rejects retired string {s!r}", bool(_probe([_atx(s)])))
                                     for s in RETIRED_SECTIONS]
    cases += [
        ("accepts heading '1.1 ATX schema'", not _probe([_atx("1.1 ATX schema")])),
        ("accepts heading '6. Transparency log'", not _probe([_atx("6. Transparency log")])),
        ("rejects a section sign added to a heading", bool(_probe([_atx("§1.1 ATX schema")]))),
        ("rejects a heading without its number", bool(_probe([_atx("Transparency log")]))),
        ("rejects a heading in other case", bool(_probe([_atx("1.1 atx schema")]))),
        ("rejects an ATX citation of another document",
         bool(_probe([_atx("1.1 ATX schema", ref="https://example.org/other.md")]))),
        ("rejects a file with no ATX citation", bool(_probe([aip]))),
        ("ignores non-ATX citations", not _probe([_atx("1.1 ATX schema"), aip])),
        ("rejects a retired string added as a heading to the vendored core.md",
         bool(_probe([_atx(RETIRED_SECTIONS[0])], core_extra=f"\n## {RETIRED_SECTIONS[0]}\n"))),
        ("rejects a workflow that pins atx-spec at another commit",
         bool(_probe([_atx("1.1 ATX schema")], workflow=workflow.replace(CORE_MD_SPEC_REF, "0" * 40)))),
        ("rejects a workflow that pins no atx-spec commit",
         bool(_probe([_atx("1.1 ATX schema")], workflow=""))),
        ("skips fenced code when reading headings",
         core_headings("```\n# not a heading\n```\n## 1. Real\n") == {"1. Real"}),
        ("strips a closing # run", core_headings("## 2. Closed ##\n") == {"2. Closed"}),
    ]
    failed = 0
    for label, ok in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        failed += not ok
    print(f"self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


def report() -> int:
    failures = check(ROOT)
    for f in failures:
        print(f"FAIL {f}")
    if failures:
        print(f"{len(failures)} ATX citation(s) do not name a heading of {CORE_MD}")
        return 1
    print(f"every ATX citation names a heading of {CORE_MD}")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return report()


if __name__ == "__main__":
    sys.exit(main())
