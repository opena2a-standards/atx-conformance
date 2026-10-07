#!/usr/bin/env python3
"""Every ATX citation this suite publishes names a real heading of core.md.

WHAT HAPPENED. Every fixture cited ATX core.md as "§1.1 Credential schema and
§6 Threshold cosignature", and every JCS vector as "§1.3a ATX v1.1 TBS
canonical form (JCS / RFC 8785)". Neither matched the spec: core.md's §1.1 is
"ATX schema", its §6 is "Transparency log", and §1.3a is "Canonical signing
form". The strings were written by the two generators, so nothing compared
them with the document they cite.

WHAT THIS ENFORCES. It reads these citation lists, which the generators write,
and no others:

  * the `spec` list of every fixtures/*.json,
  * the `spec` member of every jcs-vectors/vectors/*.json, and
  * `requirements[].specRefs` in conformance.json.

Prose that mentions core.md, such as conformance.json `notCovered[].item`, and
the top-level `spec` member of conformance.json are not read.

In those lists, each citation with id "ATX":

  * has a `ref` EQUAL to CORE_REF, core.md at the pinned atx-spec commit on
    its canonical host, so the published link opens the text the heading was
    checked against, and
  * has a `section` string EQUAL to the text of one heading of core.md, as
    vendored at that commit in schemas/vendor/atx-spec/core.md.

Each list must carry at least one ATX citation, so a file that drops its
citation cannot pass by having nothing to check. A file or member that cannot
be read as a citation list fails by name.

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

CORE_REF carries CORE_MD_SPEC_REF, so moving the pin also fails every citation
until the generators cite the new commit (atxCoreRef in
scripts/generate-fixtures/main.go and jcs-vectors/pin/main.go) and the
fixtures, vectors and conformance.json are regenerated.

WHAT THIS CANNOT DO. It proves a cited heading exists, not that it is the right
section for the fixture. The digest is recorded in this script, so it proves
the copy is unchanged since it was vendored, not that it was fetched correctly;
the gh command beside CORE_MD_SHA256 confirms that against atx-spec.

`scripts/conformance_profile.py --check` runs the self-test and the check, so
CI enforces this through the existing conformance-profile step.

Usage:
    python3 scripts/check_spec_refs.py               run the check
    python3 scripts/check_spec_refs.py --self-test   prove the check can fail
    python3 scripts/check_spec_refs.py --help        print this usage
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_MD = Path("schemas/vendor/atx-spec/core.md")
WORKFLOW = Path(".github/workflows/conformance.yml")
USAGE = __doc__[__doc__.index("Usage:"):]

# The atx-spec commit core.md was vendored from, and the SHA-256 of core.md at
# that commit. When the atx-spec pin in WORKFLOW moves, re-vendor core.md from
# the new commit and update both constants together. To confirm the digest
# against the source:
#   gh api "repos/opena2a-standards/atx-spec/contents/core.md?ref=<CORE_MD_SPEC_REF>" \
#     -H "Accept: application/vnd.github.raw" | shasum -a 256
CORE_MD_SPEC_REF = "e89bed94ca0a7308e2d6915e384be4c89d3a67df"
CORE_MD_SHA256 = "0639fe4e2fd3acf9277cacd639ac0da27cf538c2b64648b349d4db48de730d3d"
# The one URL an ATX citation may carry: core.md at that commit.
CORE_REF = f"https://github.com/opena2a-standards/atx-spec/blob/{CORE_MD_SPEC_REF}/core.md"

# ATX headings (CommonMark): up to three spaces of indent, 1-6 `#`, then a
# space or tab. heading_text() takes the rest of the line apart with string
# methods; a pattern that matches the text lazily before an optional closing
# run backtracks quadratically on a long run of blanks. Lines inside fenced
# code blocks are not headings.
HEADING_RE = re.compile(r" {0,3}#{1,6}[ \t]")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# The atx-spec checkout in WORKFLOW: `repository:` followed by its `ref:`.
SPEC_PIN_RE = re.compile(
    r"repository:[ \t]*opena2a-standards/atx-spec[ \t]*\r?\n[ \t]*ref:[ \t]*([0-9a-f]{40})\b"
)

# Returned in place of a value that could not be read; its failure is recorded.
_UNREADABLE = object()


def heading_text(line: str) -> str | None:
    """The text of an ATX heading line, or None if the line is not one."""
    m = HEADING_RE.match(line)
    if not m:
        return None
    text = line[m.end():].strip(" \t")
    # A closing run of `#` ends the heading only when a blank precedes it.
    bare = text.rstrip("#")
    if bare != text and (not bare or bare[-1] in " \t"):
        text = bare.rstrip(" \t")
    return text or None


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
            heading = heading_text(line)
            if heading:
                headings.add(heading)
    return headings


def _load(path: Path, where: str, failures: list[str]) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        failures.append(f"{where}: is not JSON ({exc})")
        return _UNREADABLE


def _member(doc: object, key: str, where: str, failures: list[str]) -> object:
    if doc is _UNREADABLE:
        return _UNREADABLE
    if isinstance(doc, dict) and key in doc:
        return doc[key]
    failures.append(f"{where}: has no {key!r} member")
    return _UNREADABLE


def cited_files(root: Path) -> tuple[list[tuple[str, object]], list[str]]:
    """(where, citations) for every citation list the check reads, and a
    failure for each file or member that cannot be read as one."""
    lists: list[tuple[str, object]] = []
    failures: list[str] = []
    for path in sorted((root / "fixtures").glob("*.json")):
        where = str(path.relative_to(root))
        spec = _member(_load(path, where, failures), "spec", where, failures)
        if spec is not _UNREADABLE:
            lists.append((where, spec))
    for path in sorted((root / "jcs-vectors" / "vectors").glob("*.json")):
        where = str(path.relative_to(root))
        spec = _member(_load(path, where, failures), "spec", where, failures)
        if spec is not _UNREADABLE:
            # A vector carries one citation object, not a list.
            lists.append((where, [spec]))
    profile = root / "conformance.json"
    if profile.exists():
        where = "conformance.json"
        reqs = _member(_load(profile, where, failures), "requirements", where, failures)
        if reqs is not _UNREADABLE and not isinstance(reqs, list):
            failures.append(f"{where}: 'requirements' is not a list")
        elif reqs is not _UNREADABLE:
            for i, req in enumerate(reqs):
                where = f"conformance.json requirements[{i}]"
                refs = _member(req, "specRefs", where, failures)
                if refs is not _UNREADABLE:
                    lists.append((where, refs))
    return lists, failures


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
    """Every check failure: the vendored core.md is not the pinned one, or an
    ATX citation does not name a heading of it."""
    core = root / CORE_MD
    if not core.exists():
        return [f"{CORE_MD} is missing; vendor core.md from the pinned atx-spec ref"]
    failures = pin_failures(root)
    headings = core_headings(core.read_text(encoding="utf-8"))
    lists, unreadable = cited_files(root)
    failures += unreadable
    for where, refs in lists:
        if not isinstance(refs, list) or not all(isinstance(r, dict) for r in refs):
            failures.append(f"{where}: citations must be a list of objects with id, ref and section")
            continue
        atx = [r for r in refs if r.get("id") == "ATX"]
        if not atx:
            failures.append(f"{where}: carries no ATX citation")
        for ref in atx:
            section = ref.get("section")
            if ref.get("ref") != CORE_REF:
                failures.append(
                    f"{where}: ATX citation points at {ref.get('ref')!r}, not {CORE_REF}. "
                    f"Cite core.md at the pinned commit; fix the generator and regenerate."
                )
            elif not isinstance(section, str) or section not in headings:
                failures.append(
                    f"{where}: ATX section {section!r} is not a heading of "
                    f"{CORE_MD}. Cite the heading text exactly; fix the generator "
                    f"and regenerate."
                )
    return failures


def report(root: Path = ROOT) -> int:
    failures = check(root)
    for f in failures:
        print(f"FAIL {f}")
    if failures:
        print(f"{len(failures)} check failure(s)")
        return 1
    print(f"every ATX citation names a heading of {CORE_MD}")
    return 0


# --- self-test ---------------------------------------------------------------
#
# Drives the real check() against a temporary tree that holds the real vendored
# core.md, so the rule is proven against the document it actually reads.

RETIRED_SECTIONS = [
    "§1.1 Credential schema and §6 Threshold cosignature",
    "§1.3a ATX v1.1 TBS canonical form (JCS / RFC 8785)",
]


@contextlib.contextmanager
def _tree(fixture: object, vector: object = None, profile: object = None,
          core_extra: str = "", workflow: str | None = None) -> Iterator[Path]:
    """A temporary tree with one fixture and, when given, one JCS vector and a
    conformance.json. A str is written verbatim, anything else as JSON."""
    def write(path: Path, doc: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")

    tmp = Path(tempfile.mkdtemp(prefix="spec-refs-"))
    try:
        (tmp / CORE_MD).parent.mkdir(parents=True)
        (tmp / CORE_MD).write_bytes((ROOT / CORE_MD).read_bytes() + core_extra.encode("utf-8"))
        (tmp / WORKFLOW).parent.mkdir(parents=True)
        if workflow is None:
            shutil.copyfile(ROOT / WORKFLOW, tmp / WORKFLOW)
        else:
            (tmp / WORKFLOW).write_text(workflow, encoding="utf-8")
        write(tmp / "fixtures" / "probe.json", fixture)
        if vector is not None:
            write(tmp / "jcs-vectors" / "vectors" / "probe.json", vector)
        if profile is not None:
            write(tmp / "conformance.json", profile)
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _probe(refs: object, **tree: object) -> list[str]:
    with _tree({"spec": refs}, **tree) as root:
        return check(root)


def _probe_doc(fixture: object, **tree: object) -> list[str]:
    with _tree(fixture, **tree) as root:
        return check(root)


def _names_probe(failures: list[str], where: str = "fixtures/probe.json") -> bool:
    return bool(failures) and all(f.startswith(where) for f in failures)


def _atx(section: object, ref: str = CORE_REF) -> dict:
    return {"id": "ATX", "ref": ref, "section": section}


def _report_last_line(**tree: object) -> str:
    out = io.StringIO()
    with _tree({"spec": [_atx("1.1 ATX schema")]}, **tree) as root, contextlib.redirect_stdout(out):
        report(root)
    return out.getvalue().splitlines()[-1]


def _main_output(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(argv)
    return rc, out.getvalue()


def _linear_heading(n: int) -> bool:
    line = "# a" + " \t" * n + "x"
    start = time.perf_counter()
    ok = core_headings(line + "\n") == {line[2:]}
    return ok and time.perf_counter() - start < 1.0


def self_test() -> int:
    aip = {"id": "AIP", "ref": "https://example.org/AIP-SPEC.md", "section": "anything"}
    good = _atx("1.1 ATX schema")
    jcs = _atx('1.3a.2 JCS form (`atcVersion` = "1.1")')
    workflow = (ROOT / WORKFLOW).read_text(encoding="utf-8")
    second_pin = workflow + (
        "\n      - uses: actions/checkout@v4\n        with:\n"
        f"          repository: opena2a-standards/atx-spec\n          ref: {'0' * 40}\n"
        "          path: .spec-other\n"
    )
    help_rc, help_out = _main_output(["--help"])
    cases: list[tuple[str, bool]] = [(f"rejects retired string {s!r}", bool(_probe([_atx(s)])))
                                     for s in RETIRED_SECTIONS]
    cases += [
        ("accepts heading '1.1 ATX schema'", not _probe([good])),
        ("accepts heading '6. Transparency log'", not _probe([_atx("6. Transparency log")])),
        ("rejects a section sign added to a heading", bool(_probe([_atx("§1.1 ATX schema")]))),
        ("rejects a heading without its number", bool(_probe([_atx("Transparency log")]))),
        ("rejects a heading in other case", bool(_probe([_atx("1.1 atx schema")]))),
        ("rejects an ATX citation of another document",
         bool(_probe([_atx("1.1 ATX schema", ref="https://example.org/other.md")]))),
        ("rejects core.md cited on another host",
         bool(_probe([_atx("1.1 ATX schema", ref=CORE_REF.replace(
             "https://github.com/opena2a-standards", "https://example.invalid"))]))),
        ("rejects core.md cited at atx-spec main, not the pinned commit",
         bool(_probe([_atx("1.1 ATX schema", ref=CORE_REF.replace(CORE_MD_SPEC_REF, "main"))]))),
        ("rejects a file with no ATX citation", bool(_probe([aip]))),
        ("ignores non-ATX citations", not _probe([good, aip])),
        ("accepts a JCS vector and a requirement that cite headings",
         not _probe([good], vector={"spec": jcs}, profile={"requirements": [{"specRefs": [good]}]})),
        ("rejects a JCS vector whose section is not a heading",
         _names_probe(_probe([good], vector={"spec": _atx(RETIRED_SECTIONS[1])}),
                      "jcs-vectors/vectors/probe.json")),
        ("rejects a conformance.json requirement whose section is not a heading",
         _names_probe(_probe([good], profile={"requirements": [{"specRefs": [_atx("ATX schema")]}]}),
                      "conformance.json requirements[0]")),
        ("rejects a retired string added as a heading to the vendored core.md",
         bool(_probe([_atx(RETIRED_SECTIONS[0])], core_extra=f"\n## {RETIRED_SECTIONS[0]}\n"))),
        ("rejects a workflow that pins atx-spec at another commit",
         bool(_probe([good], workflow=workflow.replace(CORE_MD_SPEC_REF, "0" * 40)))),
        ("rejects a workflow that adds a second, different atx-spec pin",
         bool(_probe([good], workflow=second_pin))),
        ("rejects a workflow that pins no atx-spec commit", bool(_probe([good], workflow=""))),
        ("reports a fixture with no spec member by name", _names_probe(_probe_doc({"name": "x"}))),
        ("reports a fixture that is not JSON by name", _names_probe(_probe_doc("{"))),
        ("reports a citation that is not an object by name", _names_probe(_probe(["ATX"]))),
        ("reports a list-valued section by name", _names_probe(_probe([_atx(["1.1 ATX schema"])]))),
        ("reports a JCS vector with no spec member by name",
         _names_probe(_probe([good], vector={"name": "x"}), "jcs-vectors/vectors/probe.json")),
        ("reports a conformance.json with no requirements by name",
         _names_probe(_probe([good], profile={}), "conformance.json")),
        ("summarizes a digest failure as a check failure, not a citation failure",
         _report_last_line(core_extra="\nappended\n") == "1 check failure(s)"),
        ("--help prints usage and runs no check",
         help_rc == 0 and help_out.startswith("Usage:") and "every ATX citation" not in help_out),
        ("skips fenced code when reading headings",
         core_headings("```\n# not a heading\n```\n## 1. Real\n") == {"1. Real"}),
        ("strips a closing # run", core_headings("## 2. Closed ##\n") == {"2. Closed"}),
        ("strips a closing # run followed by blanks", core_headings("## 2. Closed ## \t\n") == {"2. Closed"}),
        ("keeps a # that no blank precedes", core_headings("## 2. C#\n") == {"2. C#"}),
        ("reads a heading with a long run of blanks in linear time", _linear_heading(16000)),
    ]
    failed = 0
    for label, ok in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        failed += not ok
    print(f"self-test: {len(cases) - failed}/{len(cases)} cases green")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv in (["-h"], ["--help"]):
        print(USAGE, end="")
        return 0
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        print(USAGE, end="", file=sys.stderr)
        return 2
    return report()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
