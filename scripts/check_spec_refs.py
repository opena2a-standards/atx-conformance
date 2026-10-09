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

Prose that mentions core.md, such as conformance.json `notCovered[].item`, is
not read. The top-level `spec.ref` of conformance.json is not read here either:
scripts/conformance_profile.py writes it from CORE_REF, so its staleness check
holds it to the pin.

In those lists, each citation id is a string, and an id that differs from
"ATX" only in case or surrounding blanks ("atx", " ATX") fails rather than
being skipped. Any other id, such as "AXT" or "ATX.", is read as a citation of
another document and is not checked. Each citation with id "ATX":

  * has a `ref` EQUAL to CORE_REF, core.md at the pinned atx-spec commit on
    its canonical host, so the published link opens the text the heading was
    checked against, and
  * has a `section` string EQUAL to the text of one heading of core.md, as
    vendored at that commit in schemas/vendor/atx-spec/core.md.

Each list must carry at least one ATX citation, so a file that drops its
citation cannot pass by having nothing to check. For the same reason
fixtures/ and jcs-vectors/vectors/ must each hold at least one *.json file: a
directory that is missing, holds none or cannot be listed fails by name. A
file or member that cannot be read as a citation list fails by name: one that
is not JSON, cannot be opened (a directory, no read permission, a directory
that cannot be searched) or is nested too deeply to parse. A conformance.json
that does not exist is not read.

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

A core.md or workflow that cannot be read as UTF-8 text fails by name, as does
a core.md that cannot be opened (a directory, no read permission, a directory
that cannot be searched), once; no citation is held to the headings of a
core.md that cannot be read. A missing workflow fails by name, as one to
restore. The self-test copies core.md, and the workflow, into the trees its
cases build, so a core.md or workflow it cannot read fails by name before any
case runs; a missing core.md or workflow fails there in the words the check
uses for it. The self-test also fails a temporary tree it could not remove.

Every link to atx-spec core.md in LINKED_DOCS (README.md and
verifiers/go/verify.go) must also equal CORE_REF, apart from a query string, a
#fragment, the punctuation a GitHub autolink drops after it (.,:!*_~) or a
semicolon, trailing slashes, and the case of everything before the file name,
so the prose links open the text the citations were checked against. A URL
ends at a blank, a quote, a bracket or a `|`, so a link in a table cell ends
at the cell's border. A URL carried in the query string or #fragment of
another link, such as a redirect target, is checked the same way, each query
parameter on its own; a percent-encoded one is not read. A line that carries
a URL more than MAX_URL_DEPTH links deep fails rather than being read to any
depth, so a line costs a bounded number of reads however many `?` and `#` it
holds. A file in LINKED_DOCS that cannot be opened (a directory, no read
permission, a directory that cannot be searched) or read as UTF-8 fails by
name; one that does not exist is not read.

CORE_REF carries CORE_MD_SPEC_REF, so moving the pin also fails every citation
until the generators cite the new commit (atxCoreRef in
scripts/generate-fixtures/main.go and jcs-vectors/pin/main.go) and the
fixtures, vectors and conformance.json are regenerated. It also fails every
link in LINKED_DOCS until that link is re-pointed.

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
import errno
import functools
import hashlib
import io
import json
import os
import re
import reprlib
import shutil
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Callable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_MD = Path("schemas/vendor/atx-spec/core.md")
# The failure for a tree with no core.md, in the check and in the self-test.
CORE_MD_MISSING = f"{CORE_MD} is missing; vendor core.md from the pinned atx-spec ref"
WORKFLOW = Path(".github/workflows/conformance.yml")
# The failure for a tree with no workflow, in the check and in the self-test.
WORKFLOW_MISSING = (
    f"{WORKFLOW} is missing; restore it, as its atx-spec checkout pins the commit "
    f"{CORE_MD} was vendored at"
)
# The directories of the generated files whose `spec` the check reads.
CITATION_DIRS = (Path("fixtures"), Path("jcs-vectors/vectors"))
# Not sliced from __doc__: `python -OO` strips docstrings, and this module is
# imported by scripts/conformance_profile.py. The self-test holds the
# docstring's Usage block equal to this text.
USAGE = """\
Usage:
    python3 scripts/check_spec_refs.py               run the check
    python3 scripts/check_spec_refs.py --self-test   prove the check can fail
    python3 scripts/check_spec_refs.py --help        print this usage
"""
# Files whose prose links core.md; each link must be CORE_REF.
LINKED_DOCS = (Path("README.md"), Path("verifiers/go/verify.go"))

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

# A URL in prose, its scheme in any case: it ends at a blank, a quote, a
# bracket or a `|`, so a markdown link's closing parenthesis is not part of it,
# nor is the border of a table cell, which GitHub splits on before it reads
# the cell's link.
URL_RE = re.compile(r"https?://[^\s<>()\[\]\"'`|]+", re.IGNORECASE)
# How many links deep linked_urls() reads URLs carried in another URL's query
# string or #fragment. Each level reads at most the whole line once, so the
# cap bounds a line's cost however many `?` and `#` it holds; a line that
# carries a URL deeper fails. The failure tells the author this number, so the
# self-test pins its value.
MAX_URL_DEPTH = 8
# What link_base() strips from the end of a URL once its query and fragment are
# split off: the trailing punctuation a GitHub autolink leaves out of the link
# (`?` cannot remain after the split) and a semicolon.
TRAILING = ".,;:!*_~"

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


def printable(name: str) -> str:
    """A file name as a failure names it. pathlib reads a name that is not
    valid UTF-8 with a lone surrogate per undecodable byte, which cannot be
    printed under a UTF-8 locale; it is written as a backslash escape."""
    return name.encode("utf-8", "backslashreplace").decode("utf-8")


def _show(value: object) -> str:
    """repr() of a value read from a citation file. A container is shown to a
    bounded depth, so a deeply nested one cannot exhaust the stack."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return repr(value)
    return reprlib.repr(value)


def _load(path: Path, where: str, failures: list[str], missing_ok: bool = False) -> object:
    """The JSON value in path, or _UNREADABLE with a failure that names where.
    A path that does not exist is no failure when missing_ok: see _unread()
    for why it is opened rather than asked whether it exists."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        failures.append(f"{where}: is not JSON ({exc})")
    except OSError as exc:
        if not (missing_ok and isinstance(exc, (FileNotFoundError, NotADirectoryError))):
            failures.append(f"{where}: cannot be read ({exc.strerror or type(exc).__name__})")
    except RecursionError:
        failures.append(f"{where}: is nested too deeply to read as JSON")
    return _UNREADABLE


def _unread(rel: Path, exc: OSError, missing: str | None) -> str:
    """The failure for rel, which could not be opened: `missing` when given and
    rel does not exist, else that rel cannot be read. Opening rel, rather than
    asking Path.exists() first, is what tells the two apart: for a path in a
    directory that cannot be searched, exists() raises on Python 3.12 and 3.13
    and answers False on 3.14."""
    if missing is not None and isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        return missing
    return f"{rel}: cannot be read ({exc.strerror or type(exc).__name__})"


def _read_bytes(root: Path, rel: Path, failures: list[str], missing: str | None = None) -> bytes | None:
    """The bytes of root/rel, or None with a failure that names rel: `missing`
    when given and rel does not exist."""
    try:
        return (root / rel).read_bytes()
    except OSError as exc:
        failures.append(_unread(rel, exc, missing))
    return None


def _not_utf8(rel: Path, exc: ValueError, what: str) -> str:
    return f"{rel}: is not UTF-8 text ({exc}), so {what} cannot be read"


def _decode(rel: Path, data: bytes, what: str, failures: list[str]) -> str | None:
    """data, the bytes already read from rel, as UTF-8 text, or None with a
    failure that names rel and says that `what` cannot be read."""
    try:
        return data.decode("utf-8")
    except ValueError as exc:
        failures.append(_not_utf8(rel, exc, what))
    return None


def _read_text(root: Path, rel: Path, what: str, failures: list[str],
               missing: str | None = None) -> str | None:
    """The text of root/rel, or None with a failure that names rel and says
    that `what` cannot be read: `missing` when given and rel does not exist."""
    try:
        return (root / rel).read_text(encoding="utf-8")
    except ValueError as exc:
        failures.append(_not_utf8(rel, exc, what))
    except OSError as exc:
        failures.append(_unread(rel, exc, missing))
    return None


def _member(doc: object, key: str, where: str, failures: list[str]) -> object:
    if doc is _UNREADABLE:
        return _UNREADABLE
    if isinstance(doc, dict) and key in doc:
        return doc[key]
    failures.append(f"{where}: has no {key!r} member")
    return _UNREADABLE


def citation_files(root: Path, rel: Path, failures: list[str]) -> list[Path]:
    """Every *.json file in root/rel, sorted, with a failure that names rel
    when it is missing, holds none or cannot be listed: a directory with no
    file has no citation to check, so it must not pass. Path.glob() yields
    nothing for each of those, so the directory is listed instead."""
    try:
        paths = sorted(p for p in (root / rel).iterdir() if p.name.endswith(".json"))
    except FileNotFoundError:
        failures.append(f"{rel}/ is missing, so none of its citations is checked; regenerate it")
        return []
    except OSError as exc:
        failures.append(f"{rel}/: cannot be listed ({exc.strerror or type(exc).__name__})")
        return []
    if not paths:
        failures.append(f"{rel}/ holds no *.json file, so none of its citations is checked; "
                        f"regenerate it")
    return paths


def cited_files(root: Path) -> tuple[list[tuple[str, object]], list[str]]:
    """(where, citations) for every citation list the check reads, and a
    failure for each directory, file or member that cannot be read as one."""
    lists: list[tuple[str, object]] = []
    failures: list[str] = []
    fixtures, vectors = CITATION_DIRS
    for path in citation_files(root, fixtures, failures):
        where = printable(str(path.relative_to(root)))
        spec = _member(_load(path, where, failures), "spec", where, failures)
        if spec is not _UNREADABLE:
            lists.append((where, spec))
    for path in citation_files(root, vectors, failures):
        where = printable(str(path.relative_to(root)))
        spec = _member(_load(path, where, failures), "spec", where, failures)
        if spec is not _UNREADABLE:
            # A vector carries one citation object, not a list.
            lists.append((where, [spec]))
    where = "conformance.json"
    doc = _load(root / where, where, failures, missing_ok=True)
    if doc is not _UNREADABLE:
        reqs = _member(doc, "requirements", where, failures)
        if reqs is not _UNREADABLE and not isinstance(reqs, list):
            failures.append(f"{where}: 'requirements' is not a list")
        elif reqs is not _UNREADABLE:
            for i, req in enumerate(reqs):
                where = f"conformance.json requirements[{i}]"
                refs = _member(req, "specRefs", where, failures)
                if refs is not _UNREADABLE:
                    lists.append((where, refs))
    return lists, failures


def pin_failures(root: Path, core: bytes | None) -> list[str]:
    """Whether core, the bytes of the vendored core.md, is core.md at the
    atx-spec commit CI pins. core is None when core.md cannot be read: that
    has failed, and no digest is taken."""
    failures: list[str] = []
    digest = None if core is None else hashlib.sha256(core).hexdigest()
    if digest is not None and digest != CORE_MD_SHA256:
        failures.append(
            f"{CORE_MD} has SHA-256 {digest}, not {CORE_MD_SHA256} (core.md at atx-spec "
            f"{CORE_MD_SPEC_REF}). Re-vendor it from the pinned commit; do not edit it."
        )
    # A missing workflow pins no commit; it is to be restored, not re-pinned.
    text = _read_text(root, WORKFLOW, "its atx-spec pin", failures, missing=WORKFLOW_MISSING)
    if text is None:
        return failures
    pins = set(SPEC_PIN_RE.findall(text))
    if pins != {CORE_MD_SPEC_REF}:
        failures.append(pin_mismatch(pins))
    return failures


def pin_mismatch(pins: set[str]) -> str:
    """The failure for a WORKFLOW whose atx-spec pins are pins, not the one
    commit core.md was vendored at."""
    return (
        f"{WORKFLOW} pins atx-spec at {', '.join(sorted(pins)) or 'no commit'}, but {CORE_MD} "
        f"was vendored at {CORE_MD_SPEC_REF}. Re-vendor core.md from the pinned commit and "
        f"update CORE_MD_SPEC_REF and CORE_MD_SHA256 in scripts/check_spec_refs.py."
    )


def link_base(url: str) -> str:
    """A URL as the link check compares it with CORE_REF: without its query,
    its #fragment, the TRAILING punctuation after it or trailing slashes, and
    in lower case up to its file name. GitHub serves an owner or repository
    name in any case, and core.md with a trailing slash."""
    base = re.split(r"[?#]", url, maxsplit=1)[0].rstrip(TRAILING).rstrip("/")
    head, sep, name = base.rpartition("/")
    return head.lower() + sep + name


def linked_urls(text: str) -> Iterator[tuple[int, str]]:
    """(depth, url) for every URL in text (depth 0), then for every URL
    carried in the query string or #fragment of one (depth 1), and so on, each
    query parameter read on its own, shallower URLs first. The URLs of one
    depth are disjoint parts of text, so each depth reads text at most once;
    a URL deeper than MAX_URL_DEPTH is yielded, but what it carries is not
    read."""
    pending = deque([(text, 0)])
    while pending:
        segment, depth = pending.popleft()
        for url in URL_RE.findall(segment):
            yield depth, url
            rest = re.split(r"[?#]", url, maxsplit=1)[1:]
            if rest and depth <= MAX_URL_DEPTH:
                pending.extend((part, depth + 1) for part in rest[0].split("&"))


def link_failures(root: Path) -> list[str]:
    """Every link to atx-spec core.md in LINKED_DOCS that is not CORE_REF,
    every line that carries a URL deeper than MAX_URL_DEPTH, and every file in
    LINKED_DOCS that cannot be opened or read as UTF-8. A file that does not
    exist is not read: see _unread() for why it is opened rather than asked
    whether it is a file."""
    failures: list[str] = []
    for rel in LINKED_DOCS:
        try:
            data = (root / rel).read_bytes()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            failures.append(_unread(rel, exc, None))
            continue
        text = _decode(rel, data, "its links", failures)
        if text is None:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for depth, url in linked_urls(line):
                if depth > MAX_URL_DEPTH:
                    # linked_urls() yields shallower URLs first, so every URL
                    # the check reads on this line has been checked.
                    failures.append(
                        f"{rel}:{n}: carries a URL more than {MAX_URL_DEPTH} links deep in "
                        f"other links' query strings or #fragments, deeper than the check "
                        f"reads. Link it at most {MAX_URL_DEPTH} deep."
                    )
                    break
                base = link_base(url)
                if "/atx-spec/" in base and base.endswith("/core.md") and base != CORE_REF:
                    failures.append(
                        f"{rel}:{n}: links {url}, not {CORE_REF}. "
                        f"Link core.md at the pinned commit."
                    )
    return failures


def check(root: Path) -> list[str]:
    """Every check failure: the vendored core.md is not the pinned one, an
    ATX citation does not name a heading of it, or a prose link to core.md is
    not the pinned one."""
    failures: list[str] = []
    core_bytes = _read_bytes(root, CORE_MD, failures, missing=CORE_MD_MISSING)
    # A missing core.md is the one failure: there is nothing to check against.
    if failures == [CORE_MD_MISSING]:
        return failures
    failures += pin_failures(root, core_bytes) + link_failures(root)
    # The headings are decoded from the bytes whose digest was taken, so they
    # cannot come from a core.md changed after that read. A core.md that cannot
    # be opened has failed above, once, and has no text to decode.
    core_text = None if core_bytes is None else _decode(CORE_MD, core_bytes, "its headings", failures)
    # None when core.md cannot be read: that has failed, and no section is
    # held to headings that could not be read.
    headings = None if core_text is None else core_headings(core_text)
    lists, unreadable = cited_files(root)
    failures += unreadable
    for where, refs in lists:
        if not isinstance(refs, list) or not all(isinstance(r, dict) for r in refs):
            failures.append(f"{where}: citations must be a list of objects with id, ref and section")
            continue
        for r in refs:
            cid = r.get("id")
            if not isinstance(cid, str):
                failures.append(f"{where}: citation id {_show(cid)} is not a string")
            elif cid != "ATX" and cid.strip(" \t").casefold() == "atx":
                failures.append(
                    f"{where}: citation id {cid!r} is not \"ATX\", so it would not be "
                    f"checked. Write the id exactly; fix the generator and regenerate."
                )
        atx = [r for r in refs if r.get("id") == "ATX"]
        if not atx:
            failures.append(f"{where}: carries no ATX citation")
        for ref in atx:
            section = ref.get("section")
            if ref.get("ref") != CORE_REF:
                failures.append(
                    f"{where}: ATX citation points at {_show(ref.get('ref'))}, not {CORE_REF}. "
                    f"Cite core.md at the pinned commit; fix the generator and regenerate."
                )
            elif headings is not None and (not isinstance(section, str) or section not in headings):
                failures.append(
                    f"{where}: ATX section {_show(section)} is not a heading of "
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
    print(f"every ATX citation names a heading of {CORE_MD}, and every core.md link is pinned")
    return 0


# --- self-test ---------------------------------------------------------------
#
# Drives the real check() against a temporary tree that holds the real vendored
# core.md, so the rule is proven against the document it actually reads.

RETIRED_SECTIONS = [
    "§1.1 Credential schema and §6 Threshold cosignature",
    "§1.3a ATX v1.1 TBS canonical form (JCS / RFC 8785)",
]
# Deeper than json.loads accepts before Python 3.14, and than repr() accepts on
# 3.14, which parses it.
DEEP = 100_000
# Every temporary tree a case built that _remove() could not remove; the last
# case of the self-test fails when it holds any.
_LEFT: list[Path] = []
# What _check_unreadable() has caught, each as _raised() words it, since
# _reasoned() last emptied it to run a case; that case's label ends with it.
_RAISED: list[str] = []


def _remove(tmp: Path) -> None:
    """Removes tmp, a temporary tree, recording it in _LEFT if it remains."""
    shutil.rmtree(tmp, ignore_errors=True)
    if os.path.lexists(tmp):
        _LEFT.append(tmp)


@contextlib.contextmanager
def _tree(fixture: object, vector: object = None, profile: object = None,
          core_extra: str | bytes = "", workflow: str | bytes | None = None,
          docs: dict[str, str | bytes] | None = None) -> Iterator[Path]:
    """A temporary tree with one fixture, one JCS vector (by default one that
    cites a heading) and, when given, a conformance.json and prose files
    (path: text). A str or bytes is written verbatim, anything else as JSON;
    core_extra is appended to core.md."""
    def write(path: Path, doc: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(doc, bytes):
            path.write_bytes(doc)
        else:
            path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")

    tmp = Path(tempfile.mkdtemp(prefix="spec-refs-"))
    try:
        (tmp / CORE_MD).parent.mkdir(parents=True)
        extra = core_extra if isinstance(core_extra, bytes) else core_extra.encode("utf-8")
        (tmp / CORE_MD).write_bytes((ROOT / CORE_MD).read_bytes() + extra)
        (tmp / WORKFLOW).parent.mkdir(parents=True)
        if workflow is None:
            shutil.copyfile(ROOT / WORKFLOW, tmp / WORKFLOW)
        else:
            write(tmp / WORKFLOW, workflow)
        fixtures, vectors = CITATION_DIRS
        write(tmp / fixtures / "probe.json", fixture)
        write(tmp / vectors / "probe.json", {"spec": _atx("1.1 ATX schema")} if vector is None else vector)
        if profile is not None:
            write(tmp / "conformance.json", profile)
        for rel, text in (docs or {}).items():
            write(tmp / rel, text)
        yield tmp
    finally:
        # A case may leave the tree's root, a citation directory or the
        # directory of core.md, of the workflow or of a linked file with no
        # permissions; each is given back, the root first, so the tree can be
        # removed. A directory left out here fails the self-test's last case.
        parents = (rel.parent for rel in (CORE_MD, WORKFLOW, *LINKED_DOCS))
        for rel in (Path(), *CITATION_DIRS, *parents):
            with contextlib.suppress(OSError):
                (tmp / rel).chmod(0o700)
        _remove(tmp)


def _probe(refs: object, **tree: object) -> list[str]:
    with _tree({"spec": refs}, **tree) as root:
        return check(root)


def _probe_doc(fixture: object, **tree: object) -> list[str]:
    with _tree(fixture, **tree) as root:
        return check(root)


def _probe_tree(mutate: Callable[[Path], object], refs: object = None) -> list[str]:
    """check() on a tree whose fixture cites refs, by default one heading,
    after mutate(root) has changed it."""
    with _tree({"spec": [_atx("1.1 ATX schema")] if refs is None else refs}) as root:
        mutate(root)
        return check(root)


def _deep(n: int = DEEP) -> str:
    return "[" * n + "]" * n


def _names_probe(failures: list[str], where: str = "fixtures/probe.json") -> bool:
    return bool(failures) and all(f.startswith(where) for f in failures)


def _atx(section: object, ref: str = CORE_REF) -> dict:
    return {"id": "ATX", "ref": ref, "section": section}


def _readme(text: str) -> list[str]:
    """check() on a tree whose README.md is text."""
    return _probe([_atx("1.1 ATX schema")], docs={"README.md": text})


def _once(failures: list[str], where: str) -> bool:
    return len(failures) == 1 and _names_probe(failures, where)


def _report_last_line(**tree: object) -> str:
    out = io.StringIO()
    with _tree({"spec": [_atx("1.1 ATX schema")]}, **tree) as root, contextlib.redirect_stdout(out):
        report(root)
    return out.getvalue().splitlines()[-1]


def _main_output(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _run(argv: list[str], timeout: float = 60) -> subprocess.CompletedProcess[str] | None:
    """The finished child process, or None, which fails the case, when it has
    not ended within timeout seconds; subprocess.run() has then killed it."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None


def _hung_child() -> tuple[bool, float]:
    """Whether _run() returns None for a child that outlives its timeout,
    rather than raising TimeoutExpired out of the self-test, and the seconds
    that took. A timeout of a few hundredths of a second proves that as well
    as a long one does. The time is a case of its own, printed in its label,
    so a longer one does not quietly add to every self-test run and a slow
    run is not read as _run() returning a process."""
    start = time.perf_counter()
    hung = _run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.05) is None
    return hung, time.perf_counter() - start


def _usage_under_oo() -> bool:
    """`python -OO` strips docstrings; the module must still import and print
    its usage."""
    proc = _run([sys.executable, "-OO", str(Path(__file__).resolve()), "--help"])
    return proc is not None and proc.returncode == 0 and proc.stdout == USAGE


def _self_test_without(*rels: Path, make: Callable[[Path], object] = Path.unlink,
                       says: tuple[str, ...] | None = None) -> bool:
    """--self-test in a tree where make(root / rel) has left each of rels
    unreadable (by default, removed) names each and exits 1, with no
    traceback. Its failures, one per rel in the order given, are `says` when
    given, else that each rel cannot be read."""
    with _tree({"spec": [_atx("1.1 ATX schema")]}) as root:
        for rel in rels:
            make(root / rel)
        script = root / "scripts" / Path(__file__).name
        script.parent.mkdir()
        shutil.copyfile(Path(__file__).resolve(), script)
        proc = _run([sys.executable, str(script), "--self-test"])
    if proc is None:
        return False
    lines = proc.stdout.splitlines()
    fails = lines[:-1]
    return (proc.returncode == 1 and not proc.stderr and len(lines) == len(rels) + 1
            and (fails == [f"FAIL {said}" for said in says] if says is not None
                 else all(line.startswith(f"FAIL {rel}: cannot be read (")
                          for line, rel in zip(fails, rels)))
            and lines[-1] == "self-test: not run")


def _shows_deep() -> bool:
    """_show() on a list nested DEEP levels, built in Python so no parser
    limit stops it first; plain repr() raises RecursionError on it."""
    deep: list = []
    for _ in range(DEEP):
        deep = [deep]
    try:
        return len(_show(deep)) < 100
    except RecursionError:
        return False


def _linear_heading(n: int) -> bool:
    line = "# a" + " \t" * n + "x"
    start = time.perf_counter()
    ok = core_headings(line + "\n") == {line[2:]}
    return ok and time.perf_counter() - start < 1.0


def _too_deep(failures: list[str]) -> bool:
    return _once(failures, "README.md:1:") and f"more than {MAX_URL_DEPTH} links deep" in failures[0]


def _linear_links(sep: str, n: int = 20_000) -> bool:
    """A line of n links, each carried in the query string or #fragment (sep)
    of the one before, is read to the end by linked_urls() and fails once in
    a README, as too deep, in linear time."""
    line = f"https://a/{sep}" * n
    start = time.perf_counter()
    read = deque(linked_urls(line), maxlen=1)
    ok = read[0][0] == MAX_URL_DEPTH + 1 and _too_deep(_readme(line + "\n"))
    return ok and time.perf_counter() - start < 1.0


def _permissions_stop_reads() -> bool:
    """Whether a file with no read permission, in a directory made as _tree()
    makes one, fails to open. Tried rather than read from the effective uid:
    root, a process holding CAP_DAC_OVERRIDE and a filesystem that ignores
    mode bits all open it, so the cases that need it are skipped there. False
    too where the chmod that takes its read permission raises, as on a
    filesystem that refuses it (EPERM, ENOTSUP), so those cases are skipped
    there rather than ending the self-test in a traceback."""
    tmp = Path(tempfile.mkdtemp(prefix="spec-refs-"))
    try:
        probe = tmp / "probe"
        probe.write_bytes(b"")
        try:
            probe.chmod(0)
        except OSError:
            return False
        try:
            probe.open("rb").close()
        except PermissionError:
            return True
        return False
    finally:
        _remove(tmp)


def _chmod_does_nothing() -> bool:
    """Whether Path.chmod leaves a file's mode as it was. False where it
    raises instead, as where pathlib bound at import time an os.chmod that
    refuses, so the case that reads this skips rather than ending the
    self-test in a traceback."""
    tmp = Path(tempfile.mkdtemp(prefix="spec-refs-"))
    try:
        probe = tmp / "probe"
        probe.write_bytes(b"")
        mode = probe.stat().st_mode
        try:
            probe.chmod(0)
        except OSError:
            return False
        return probe.stat().st_mode == mode
    finally:
        _remove(tmp)


@contextlib.contextmanager
def _mode_bits_ignored() -> Iterator[bool]:
    """os.chmod does nothing inside, as on a filesystem that ignores mode
    bits, so a file left with no read permission can still be read. Yields
    whether Path.chmod, which the cases call, does nothing too: it does while
    pathlib calls os.chmod through the module, as CPython 3.12 to 3.14 do,
    and not where pathlib bound the function at import time."""
    chmod = os.chmod
    os.chmod = lambda *args, **kwargs: None
    try:
        yield _chmod_does_nothing()
    finally:
        os.chmod = chmod


def _chmod_raises() -> bool:
    """Whether Path.chmod raises an OSError on a file it could create."""
    tmp = Path(tempfile.mkdtemp(prefix="spec-refs-"))
    try:
        probe = tmp / "probe"
        probe.write_bytes(b"")
        try:
            probe.chmod(0)
        except OSError:
            return True
        return False
    finally:
        _remove(tmp)


@contextlib.contextmanager
def _chmod_refused() -> Iterator[bool]:
    """os.chmod raises inside, as on a filesystem that refuses it. Yields
    whether Path.chmod, which the cases call, raises too, as
    _mode_bits_ignored() yields whether it does nothing."""
    chmod = os.chmod

    def refuse(path: object, *args: object, **kwargs: object) -> None:
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP), str(path))

    os.chmod = refuse
    try:
        yield _chmod_raises()
    finally:
        os.chmod = chmod


def _unreadable_readme() -> bool | None:
    """check() names a README.md with no read permission; None (skipped)
    where permissions do not stop a read."""
    if not _permissions_stop_reads():
        return None
    with _tree({"spec": [_atx("1.1 ATX schema")]}, docs={"README.md": "x\n"}) as root:
        (root / "README.md").chmod(0)
        return check(root) == ["README.md: cannot be read (Permission denied)"]


def _as_directory(path: Path) -> None:
    path.unlink()
    path.mkdir()


def _unreadable_core(make: Callable[[Path], object]) -> bool:
    """check() names, once, a vendored core.md that make(path) has left
    unreadable. A read with no handler raises, which fails the case; make()
    raising is not a check failure, and is raised."""
    with _tree({"spec": [_atx("1.1 ATX schema")]}) as root:
        make(root / CORE_MD)
        try:
            failures = check(root)
        except OSError:
            return False
    return _once(failures, f"{CORE_MD}: cannot be read (")


def _core_no_read_permission() -> bool | None:
    """_unreadable_core() on a core.md with no read permission; None (skipped)
    where permissions do not stop a read."""
    if not _permissions_stop_reads():
        return None
    return _unreadable_core(lambda core: core.chmod(0))


def _unsearchable(path: Path) -> None:
    """Takes every permission from the directory path is in, so path cannot
    be opened, nor stat()ed, through it. _tree() gives it back."""
    path.parent.chmod(0)


def _core_dir_unsearchable() -> bool | None:
    """_unreadable_core() on a core.md in a directory with no search
    permission; None (skipped) where permissions do not stop a read."""
    if not _permissions_stop_reads():
        return None
    return _unreadable_core(_unsearchable)


def _workflow_dir_unsearchable() -> bool | None:
    """check() names a workflow in a directory with no search permission as
    unreadable, not as one that pins no commit; None (skipped) where
    permissions do not stop a read."""
    if not _permissions_stop_reads():
        return None
    with _tree({"spec": [_atx("1.1 ATX schema")]}) as root:
        _unsearchable(root / WORKFLOW)
        try:
            failures = check(root)
        except OSError:
            return False
    return failures == [f"{WORKFLOW}: cannot be read (Permission denied)"]


def _check_unreadable(make: Callable[[Path], object], **tree: object) -> list[str] | None:
    """check() on a tree that cites one heading, after make(root) has left
    part of it unreadable; None, which fails the case, if either raises any
    Exception, not only an OSError. What it raised is kept in _RAISED, for
    _reasoned() to end the case's label with."""
    with _tree({"spec": [_atx("1.1 ATX schema")]}, **tree) as root:
        try:
            make(root)
            return check(root)
        except Exception as exc:
            _RAISED.append(_raised(exc))
            return None


# Every control character, and every other character str.splitlines() ends a
# line at, as the backslash escape repr() writes it, and a backslash doubled,
# as repr() writes it, so an escape cannot be read as text that carried one.
_ONE_LINE = {c: repr(chr(c))[1:-1] for c in (*range(0x20), *range(0x7F, 0xA0), 0x2028, 0x2029, 0x5C)}


def _raised(exc: Exception) -> str:
    """exc's type and text, as the last line of a traceback gives them, then
    the innermost line of this script it was raised through and the function
    that line is in, which the traceback would have named. A line break or
    other control character in the text is written as a backslash escape, so
    the label this ends stays on one line, and a backslash in the text is
    doubled, so a newline and the two characters backslash and n are not
    written alike. The text is escaped before printable() writes a character
    that is not valid UTF-8 as a backslash escape, so that escape is not
    doubled."""
    where, tb = "", exc.__traceback__
    while tb is not None:
        if tb.tb_frame.f_globals is globals():
            where = f", at line {tb.tb_lineno} in {tb.tb_frame.f_code.co_name}"
        tb = tb.tb_next
    return printable(f"{type(exc).__name__}: {exc}{where}".translate(_ONE_LINE))


def _reasoned(label: str, case: Callable[[], bool | None]) -> tuple[str, bool | None]:
    """The case (label, case()), its label ended with what _check_unreadable()
    caught while case() ran, so a case that is red because make() or check()
    raised says what was raised, as the hung-child case carries its time.
    _RAISED is emptied first, so the label carries nothing an earlier case
    left there."""
    _RAISED.clear()
    ok = case()
    return label + "".join(f" (raised {why})" for why in _RAISED), ok


def _linked_as_directory(rel: Path) -> bool:
    """check() names, once, a directory named like rel, a file in LINKED_DOCS,
    as unreadable, rather than skipping it as it does one that does not
    exist."""
    failures = _check_unreadable(lambda root: (root / rel).mkdir(parents=True))
    return failures is not None and _once(failures, f"{rel}: cannot be read (")


def _linked_dir_unsearchable() -> bool | None:
    """check() names a verify.go in a directory with no search permission as
    unreadable, rather than raising on Python 3.12 and 3.13 or skipping it on
    3.14; None (skipped) where permissions do not stop a read."""
    if not _permissions_stop_reads():
        return None
    rel = Path("verifiers/go/verify.go")
    return (_check_unreadable(lambda root: _unsearchable(root / rel), docs={str(rel): f"// {CORE_REF}\n"})
            == [f"{rel}: cannot be read (Permission denied)"])


def _citation_dir_unlistable(rel: Path) -> bool | None:
    """check() names rel, a citation directory with no permissions, as one it
    cannot list, not as missing or empty; None (skipped) where permissions do
    not stop a read."""
    if not _permissions_stop_reads():
        return None
    return (_check_unreadable(lambda root: (root / rel).chmod(0))
            == [f"{rel}/: cannot be listed (Permission denied)"])


def _root_unsearchable() -> bool | None:
    """check() names a conformance.json in a tree root with no permissions,
    which it cannot tell from a missing one, as unreadable, rather than
    raising on Python 3.12 and 3.13 or skipping it on 3.14; None (skipped)
    where permissions do not stop a read."""
    if not _permissions_stop_reads():
        return None
    failures = _check_unreadable(lambda root: root.chmod(0), profile={"requirements": []})
    return failures is not None and "conformance.json: cannot be read (Permission denied)" in failures


# The label of every case that skips where Path.chmod raises: each
# no-read-permission case, the case that binds Path.chmod at import time and
# the case that runs --self-test where os.chmod raises. self_test() passes
# each through _chmod_skips() where it lists the case, so
# _self_test_where_chmod_refuses() can name the cases its child must skip.
_CHMOD_SKIPS: set[str] = set()


def _chmod_skips(label: str) -> str:
    """label, kept in _CHMOD_SKIPS as that of a case that skips where
    Path.chmod raises."""
    _CHMOD_SKIPS.add(label)
    return label


def _unreadable_tree_cases() -> list[tuple[str, bool | None]]:
    """Every case that runs check() through _check_unreadable(), each made by
    _reasoned(), so one that is red because something raised says what."""
    return [
        *(_reasoned(_chmod_skips(f"reports a {rel}/ it has no permission to list by name, not as "
                                 "missing or empty"),
                    functools.partial(_citation_dir_unlistable, rel)) for rel in CITATION_DIRS),
        *(_reasoned(f"reports, once, a directory named like {rel} by name, rather than skipping it "
                    "as missing", functools.partial(_linked_as_directory, rel)) for rel in LINKED_DOCS),
        _reasoned(_chmod_skips("reports a verify.go in a directory it cannot search as unreadable, "
                               "rather than raising or skipping it"), _linked_dir_unsearchable),
        _reasoned(_chmod_skips("reports a conformance.json in a tree root it cannot search as "
                               "unreadable, rather than raising or skipping it"), _root_unsearchable),
    ]


def _self_test_core_dir_unsearchable() -> bool | None:
    """--self-test in a tree whose core.md is in a directory with no search
    permission names core.md as unreadable, not as missing, and exits 1, with
    no traceback; None (skipped) where permissions do not stop a read."""
    if not _permissions_stop_reads():
        return None
    return _self_test_without(CORE_MD, make=_unsearchable,
                              says=(f"{CORE_MD}: cannot be read (Permission denied)",))


def _no_read_permission_cases() -> tuple[Callable[[], bool | None], ...]:
    """Every case that _permissions_stop_reads() skips."""
    return (_unreadable_readme, _core_no_read_permission, _core_dir_unsearchable,
            _workflow_dir_unsearchable, _self_test_core_dir_unsearchable,
            _linked_dir_unsearchable, _root_unsearchable,
            *(functools.partial(_citation_dir_unlistable, rel) for rel in CITATION_DIRS))


def _skips_where_reads_allowed() -> bool | None:
    """Every no-read-permission case skips, rather than fails, where a file
    with no read permission can still be read. None (skipped) where
    _mode_bits_ignored() cannot stop Path.chmod, which would fail it falsely."""
    with _mode_bits_ignored() as ignored:
        if not ignored:
            return None
        return all(case() is None for case in _no_read_permission_cases())


def _skips_where_chmod_raises() -> bool | None:
    """Every no-read-permission case skips, rather than raising out of the
    self-test, where chmod raises. None (skipped) where _chmod_refused()
    cannot make Path.chmod raise, which would fail it falsely."""
    with _chmod_refused() as refused:
        if not refused:
            return None
        try:
            return all(case() is None for case in _no_read_permission_cases())
        except OSError:
            return False


@contextlib.contextmanager
def _chmod_bound_at_import() -> Iterator[None]:
    """Path.chmod calls the os.chmod in place on entry, not the module's, as a
    pathlib that bound the function at import time would."""
    cls, chmod = type(Path()), os.chmod
    own = vars(cls).get("chmod")
    cls.chmod = lambda self, mode, *, follow_symlinks=True: chmod(
        self, mode, follow_symlinks=follow_symlinks)
    try:
        yield
    finally:
        if own is None:
            del cls.chmod
        else:
            cls.chmod = own


def _skips_where_chmod_bound() -> bool | None:
    """_skips_where_reads_allowed() and _skips_where_chmod_raises() are
    skipped, not failed, where Path.chmod does not call os.chmod through the
    module. None (skipped) where Path.chmod already raises: a chmod bound at
    import time cannot then be told from one that refuses, and the cases
    inside would run under a chmod that raises either way."""
    if _chmod_raises():
        return None
    with _chmod_bound_at_import():
        return _skips_where_reads_allowed() is None and _skips_where_chmod_raises() is None


def _skips_where_bound_chmod_raises() -> bool:
    """_skips_where_reads_allowed() is skipped, not ended in a traceback,
    where Path.chmod calls an os.chmod bound at import time that raises, so
    the os.chmod that does nothing in its place is never called: the OSError
    reaches _chmod_does_nothing(), which reads it as False."""
    with _chmod_refused(), _chmod_bound_at_import():
        try:
            return _skips_where_reads_allowed() is None
        except OSError:
            return False


def _self_test_where_chmod_refuses() -> bool | None:
    """--self-test in a child whose os.chmod raises before the script runs,
    as on a filesystem that refuses it, runs every case to the end with no
    traceback, reaching its summary line with nothing on stderr, and skips
    exactly the cases in _CHMOD_SKIPS: the no-read-permission cases, the case
    that binds Path.chmod at import time and this one. A case the child runs
    and finds red is red in this process too, so it does not turn this one
    red as well. None (skipped) where Path.chmod already raises, which is the
    child's own state."""
    if _chmod_raises():
        return None
    refusing = ("import errno, os, runpy, sys\n"
                "def refuse(path, *args, **kwargs):\n"
                "    raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP), str(path))\n"
                "os.chmod = refuse\n"
                "sys.argv = [sys.argv[1], '--self-test']\n"
                "runpy.run_path(sys.argv[0], run_name='__main__')\n")
    proc = _run([sys.executable, "-c", refusing, str(Path(__file__).resolve())])
    if proc is None:
        return False
    lines = proc.stdout.splitlines()
    summary = (re.fullmatch(r"self-test: (\d+)/(\d+) cases green, (\d+) skipped", lines[-1])
               if lines else None)
    if not summary or proc.stderr:
        return False
    skip = "  [SKIP ] "
    skipped = [line[len(skip):] for line in lines if line.startswith(skip)]
    return (proc.returncode == (0 if summary[1] == summary[2] else 1)
            and int(summary[3]) == len(skipped) == len(_no_read_permission_cases()) + 2
            and set(skipped) == _CHMOD_SKIPS)


def _restores_chmod() -> bool:
    """_chmod_bound_at_import() leaves Path.chmod as it found it, whether it
    exits normally or by an exception: not set on the class when the class
    did not set it, and the class's own function when it did. The class is
    put back as this found it either way."""
    cls, absent = type(Path()), object()
    found = vars(cls).get("chmod", absent)

    def stand_in(self: Path, mode: int, *, follow_symlinks: bool = True) -> None:
        """The class's own chmod: a function of its own, so that one put back
        as Path.chmod, the function the class inherits, does not match it."""
        os.chmod(self, mode, follow_symlinks=follow_symlinks)

    def left_as_found(own: object) -> bool:
        with _chmod_bound_at_import():
            pass
        if vars(cls).get("chmod", absent) is not own:
            return False
        with contextlib.suppress(LookupError), _chmod_bound_at_import():
            raise LookupError
        return vars(cls).get("chmod", absent) is own

    try:
        if found is not absent:
            del cls.chmod
        if not left_as_found(absent):
            return False
        cls.chmod = stand_in
        return left_as_found(stand_in)
    finally:
        if found is not absent:
            cls.chmod = found
        elif "chmod" in vars(cls):
            del cls.chmod


def _unmade_core_raises() -> bool:
    """A core.md that _unreadable_core() could not make unreadable raises out
    of it, rather than reading as check() failing on it."""
    def refuse(path: Path) -> None:
        raise PermissionError(13, "Permission denied", str(path))
    try:
        _unreadable_core(refuse)
    except PermissionError:
        return True
    return False


def _unmade_tree_fails(make: Callable[[Path], object],
                       helper: Callable[..., list[str] | None] = _check_unreadable) -> bool:
    """A tree that helper, _check_unreadable() unless a case gives another,
    could not make unreadable, as make(root) raised, fails the case, as None,
    rather than raising out of the self-test. False, not raised, where helper
    lets any Exception out, not only an OSError."""
    try:
        return helper(make, docs={"README.md": "x\n"}) is None
    except Exception:
        return False


def _mkdir_on_readme(root: Path) -> None:
    """A make that raises an OSError: a mkdir on the README.md the tree
    already holds."""
    (root / "README.md").mkdir()


def _refuse_not_os(root: Path) -> None:
    """A make that raises an exception other than an OSError."""
    raise ValueError(f"{root}: not made unreadable")


def _check_unguarded(make: Callable[[Path], object], **tree: object) -> list[str]:
    """_check_unreadable() with no handler: what make(root) raises comes out
    of it."""
    with _tree({"spec": [_atx("1.1 ATX schema")]}, **tree) as root:
        make(root)
        return check(root)


@contextlib.contextmanager
def _check_broken(text: str = "probe") -> Iterator[None]:
    """check() raises a TypeError with text inside, on any tree, as a defect
    in it would."""
    global check
    real = check

    def broken(root: Path) -> list[str]:
        raise TypeError(text)

    check = broken
    try:
        yield
    finally:
        check = real


def _red_cases_say_why() -> bool:
    """Every case of _unreadable_tree_cases() that is not skipped, run while
    check() raises as a defect in it would, is red and ends its label with
    what was raised: its type and text, then the line and the function of
    this script, here the stand-in for check(), that raised it. The cases on
    a directory named like a file in LINKED_DOCS are never skipped."""
    with _check_broken():
        ran = [(label, ok) for label, ok in _unreadable_tree_cases() if ok is not None]
    said = re.compile(r" \(raised TypeError: probe, at line [1-9][0-9]* in broken\)\Z")
    return len(ran) >= len(LINKED_DOCS) and all(
        ok is False and said.search(label) is not None for label, ok in ran)


def _red_labels_one_line() -> bool:
    """Every case of _unreadable_tree_cases() that is not skipped, run while
    check() raises with text that carries line breaks and other control
    characters, ends its label, still one line, with that text, each such
    character written as a backslash escape, each backslash the text carries
    doubled, and a character that is not valid UTF-8 written as the one
    backslash escape printable() writes."""
    with _check_broken("line one\nline two\r\tthree\x00\x85\u2028four\\nfive\udcff\\udcffsix"):
        ran = [label for label, ok in _unreadable_tree_cases() if ok is not None]
    said = re.compile(r" \(raised TypeError: line one\\nline two\\r\\tthree\\x00\\x85\\u2028four"
                      r"\\\\nfive\\udcff\\\\udcffsix, at line [1-9][0-9]* in broken\)\Z")
    return len(ran) >= len(LINKED_DOCS) and all(
        len(label.splitlines()) == 1 and said.search(label) is not None for label in ran)


def _says_only_its_own() -> bool:
    """_reasoned() ends a label with what make(root) raised in its own case,
    naming the function that raised it, and ends the label of a case in which
    nothing raised with nothing, whatever an earlier case left in _RAISED."""
    label, ok = _reasoned("label", lambda: _check_unreadable(_refuse_not_os) is not None)
    said = r"label \(raised ValueError: .+: not made unreadable, at line [1-9][0-9]* in _refuse_not_os\)"
    return (ok is False and re.fullmatch(said, label) is not None and len(_RAISED) == 1
            and _reasoned("label", lambda: True) == ("label", True))


# A label that picks out another case by where it stands among the cases, as
# "the first of the two cases above" did, turns wrong when a case moves, and
# nothing turns red. A rank word, an ordinal ("first", "fifth", "21st",
# "second-to-last") or a word such as "last", "next", "previous" or
# "latter", is read as naming a case where "case", "cases", "of", "where",
# "above", "below" or "one" follows it, a count such as "two" allowed between
# them; "both cases" and "the two cases" name cases by rank as well. A
# possessive "one's" is not read as a case, so "the last one's query string",
# which names a link, is not.
_COUNTS = ("two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "[0-9]+")
_RANKS = ("first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth",
          "tenth", "eleventh", "twelfth", "[a-z]+teenth", "[a-z]+tieth", "hundredth",
          "[0-9]+(?:st|nd|rd|th)", "last", "final", "penultimate", "former", "latter", "next",
          "previous", "preceding", "following", "earlier", "later", "prior")
_AFTER_RANKS = ("cases?", "of", "where", "above", "below", "one(?!['’])")


def _by_rank_re(ranks: tuple[str, ...] = _RANKS, counts: tuple[str, ...] = _COUNTS,
                after: tuple[str, ...] = _AFTER_RANKS,
                flags: int = re.IGNORECASE) -> re.Pattern[str]:
    """The pattern _by_rank() reads a label with, built from the words it
    reads as a rank, as a count and after them."""
    count = f"(?:{'|'.join(counts)})"
    return re.compile(rf"\bthe (?:[a-z]+-)*(?:{'|'.join(ranks)})(?: {count})?"
                      rf" (?:{'|'.join(after)})\b|\b(?:both|the {count}) cases\b", flags)


_BY_RANK_RE = _by_rank_re()
# Wordings _by_rank() must read as naming a case by rank, and wordings it
# must not.
_BY_RANK_WORDINGS = (
    "the first of the two cases above", "the second where its helper lets",
    "the OSError, as the next case above does", "the previous one", "the fifth case",
    "both cases above", "the two cases above", "the preceding case", "the following case",
    "the earlier case", "the later case", "the 12th case", "the twenty-first case",
    "the second-to-last case", "the last two cases", "the third case", "the fourth case",
    "the sixth case", "the seventh case", "the eighth case", "the ninth case", "the tenth case",
    "the eleventh case", "the twelfth case", "the thirteenth case", "the twentieth case",
    "the hundredth case", "the final case", "the penultimate case", "the former case",
    "the latter case", "the prior case", "The Last Case", "the last three cases",
    "the first four cases", "the five cases above", "the next six cases", "the seven cases below",
    "the last eight cases", "the nine cases above", "the first ten cases", "the 11 cases above",
    "as the first above does", "the next below", "the last of them")
_NOT_BY_RANK_WORDINGS = (
    "each in the last one's query string", "each in the last one’s #fragment",
    "nothing an earlier case raised")


def _by_rank(labels: list[str]) -> list[str]:
    """The labels that name another case by its rank among the cases rather
    than by what it runs."""
    return [label for label in labels if _BY_RANK_RE.search(label)]


def _unneeded_words() -> list[str]:
    """Each word _by_rank() reads as a rank, as a count or after them, and its
    re.IGNORECASE flag, that no wording in _BY_RANK_WORDINGS needs: with it
    taken out, every one of them still reads as naming a case by rank, so
    taking it out would leave the self-test green."""
    def all_read(pattern: re.Pattern[str]) -> bool:
        return all(pattern.search(wording) for wording in _BY_RANK_WORDINGS)

    unneeded = [word for name, words in (("ranks", _RANKS), ("counts", _COUNTS),
                                         ("after", _AFTER_RANKS))
                for word in words
                if all_read(_by_rank_re(**{name: tuple(w for w in words if w != word)}))]
    return unneeded + (["re.IGNORECASE"] if all_read(_by_rank_re(flags=0)) else [])


class _Undecodable(type(Path())):
    """A path whose name, relative to the tree, is bad-<0xFF>.json in place of
    probe.json. On Linux pathlib reads a file name that is not valid UTF-8
    with a lone surrogate per undecodable byte; macOS refuses to create such a
    file."""

    def relative_to(self, *args: object, **kwargs: object) -> Path:
        rel = super().relative_to(*args, **kwargs)
        return rel.with_name("bad-\udcff.json") if rel.name == "probe.json" else rel


class _EmptiedAfterRead(type(Path())):
    """A path whose core.md is emptied on disk as soon as its bytes are read,
    as if it changed between two reads."""

    def read_bytes(self) -> bytes:
        data = super().read_bytes()
        if self.name == CORE_MD.name:
            self.write_bytes(b"")
        return data


def _reads_core_once() -> bool:
    """check() takes the headings from the core.md bytes whose digest it took:
    a core.md emptied after that read still has every heading cited."""
    with _tree({"spec": [_atx("1.1 ATX schema")]}) as root:
        return not check(_EmptiedAfterRead(root))


def _names_undecodable() -> bool:
    """cited_files() names a fixture and a JCS vector called bad-<0xFF>.json
    by name, in a form that prints under a UTF-8 locale."""
    with _tree({"name": "x"}, vector={"name": "x"}) as root:
        _, failures = cited_files(_Undecodable(root))
    try:
        "".join(failures).encode("utf-8")
    except UnicodeEncodeError:
        return False
    return failures == [
        "fixtures/bad-\\udcff.json: has no 'spec' member",
        "jcs-vectors/vectors/bad-\\udcff.json: has no 'spec' member",
    ]


def self_test() -> int:
    aip = {"id": "AIP", "ref": "https://example.org/AIP-SPEC.md", "section": "anything"}
    good = _atx("1.1 ATX schema")
    jcs = _atx('1.3a.2 JCS form (`atcVersion` = "1.1")')
    # A case that builds a tree copies the vendored core.md into it and,
    # unless it writes its own workflow text, the CI workflow; the cases that
    # edit the workflow start from its text. Both are read here, before any
    # case runs, so one that cannot be read fails by name, not in a traceback.
    # A missing workflow or core.md fails in the words check() uses for it.
    unread: list[str] = []
    _LEFT.clear()
    _CHMOD_SKIPS.clear()
    workflow = _read_text(ROOT, WORKFLOW, "its atx-spec pin", unread, missing=WORKFLOW_MISSING)
    _read_bytes(ROOT, CORE_MD, unread, missing=CORE_MD_MISSING)
    if workflow is None or unread:
        for f in unread:
            print(f"FAIL {f}")
        print("self-test: not run")
        return 1
    second_pin = workflow + (
        "\n      - uses: actions/checkout@v4\n        with:\n"
        f"          repository: opena2a-standards/atx-spec\n          ref: {'0' * 40}\n"
        "          path: .spec-other\n"
    )
    help_rc, help_out, _ = _main_output(["--help"])
    h_rc, h_out, _ = _main_output(["-h"])
    bad_rc, bad_out, bad_err = _main_output(["--bogus"])
    stale = "https://github.com/opena2a-standards/atx-spec/blob/main/core.md"
    core_not_utf8 = _probe([good], core_extra=b"\xff")
    workflow_not_utf8 = _probe([good], workflow=workflow.encode("utf-8") + b"\xff")
    no_workflow = _probe_tree(lambda root: (root / WORKFLOW).unlink())
    hung, hung_seconds = _hung_child()
    # None marks a case skipped where it cannot run.
    cases: list[tuple[str, bool | None]] = [(f"rejects retired string {s!r}", bool(_probe([_atx(s)])))
                                     for s in RETIRED_SECTIONS]
    cases += [
        ("accepts heading '1.1 ATX schema'", not _probe([good])),
        ("accepts the tree that each _probe_tree() case changes", not _probe_tree(lambda root: None)),
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
        ("rejects a tree with no workflow by name, as its one failure, and tells the author to "
         "restore it, not to re-vendor core.md",
         no_workflow == [WORKFLOW_MISSING]
         and WORKFLOW_MISSING == f"{WORKFLOW} is missing; restore it, as its atx-spec checkout "
                                 f"pins the commit {CORE_MD} was vendored at"),
        ("--self-test in a tree with no workflow names it as missing, in the check's words, "
         "and exits 1, with no traceback", _self_test_without(WORKFLOW, says=(WORKFLOW_MISSING,))),
        (_chmod_skips("--self-test in a tree whose vendored core.md is in a directory it cannot "
                      "search names core.md as unreadable, not missing, and exits 1, with no "
                      "traceback"),
         _self_test_core_dir_unsearchable()),
        ("--self-test in a tree with no vendored core.md names it as missing, in the check's "
         "words, and exits 1, with no traceback",
         _self_test_without(CORE_MD, says=(CORE_MD_MISSING,))),
        ("--self-test in a tree with a directory named like the vendored core.md names it and "
         "exits 1, with no traceback", _self_test_without(CORE_MD, make=_as_directory)),
        ("--self-test in a tree with neither the workflow nor the vendored core.md names both "
         "as missing, in the check's words, one failure each, and exits 1, with no traceback",
         _self_test_without(WORKFLOW, CORE_MD, says=(WORKFLOW_MISSING, CORE_MD_MISSING))),
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
        ("reports a conformance.json whose requirements is not a list",
         _probe([good], profile={"requirements": {"specRefs": [good]}})
         == ["conformance.json: 'requirements' is not a list"]),
        ("reports a directory named like a fixture by name",
         _names_probe(_probe_tree(lambda root: _as_directory(root / "fixtures" / "probe.json")))),
        ("reports a fixture nested too deeply to parse by name",
         _names_probe(_probe_doc('{"spec": ' + _deep() + "}"))),
        ("reports a deeply nested ATX ref by name",
         _names_probe(_probe_doc('{"spec": [{"id": "ATX", "ref": ' + _deep()
                                 + ', "section": "1.1 ATX schema"}]}'))),
        ("shows a list nested 100,000 levels deep without a traceback", _shows_deep()),
        ("reports a deeply nested ATX section by name",
         _names_probe(_probe_doc('{"spec": [{"id": "ATX", "ref": "' + CORE_REF
                                 + '", "section": ' + _deep() + "}]}"))),
        ("rejects a citation id 'atx' beside an ATX citation",
         _names_probe(_probe([good, {**_atx("not a heading"), "id": "atx"}]))),
        ("rejects a citation id ' ATX' with a leading blank",
         _names_probe(_probe([good, {**_atx("not a heading"), "id": " ATX"}]))),
        ("rejects a citation id that is not a string",
         _names_probe(_probe([good, {**_atx("not a heading"), "id": ["ATX"]}]))),
        ("rejects a citation with no id", _names_probe(_probe([good, {"section": "x"}]))),
        ("accepts a README link to core.md at the pinned commit, with a fragment",
         not _probe([good], docs={"README.md": f"[core]({CORE_REF}#6-transparency-log)\n"})),
        ("ignores a link to the atx-spec repository root",
         not _probe([good], docs={"README.md": "[spec](https://github.com/opena2a-standards/atx-spec)\n"})),
        ("rejects a README link to core.md at atx-spec main",
         _names_probe(_probe([good], docs={"README.md": f"x\n[core]({stale})\n"}), "README.md:2:")),
        ("rejects a core.md link at atx-spec main that carries a #fragment",
         _names_probe(_probe([good], docs={"README.md": f"[core]({stale}#6-transparency-log)\n"}),
                      "README.md:1:")),
    ]
    # A citation directory with no file to read has no citation to check.
    for rel in CITATION_DIRS:
        cases += [
            (f"rejects a tree with no {rel}/ by name, as its one failure",
             _probe_tree(lambda root: shutil.rmtree(root / rel))
             == [f"{rel}/ is missing, so none of its citations is checked; regenerate it"]),
            (f"rejects a {rel}/ that holds no *.json file by name, as its one failure",
             _probe_tree(lambda root: (root / rel / "probe.json").rename(root / rel / "probe.txt"))
             == [f"{rel}/ holds no *.json file, so none of its citations is checked; regenerate it"]),
        ]
    # One case per character link_base() strips, written out here rather than
    # read from TRAILING, so dropping a character from TRAILING turns its case red.
    cases += [(f"rejects a core.md link at atx-spec main followed by {c!r}",
               _names_probe(_readme(f"See {stale}{c}\n"), "README.md:1:"))
              for c in ".,;:!*_~"]
    redirect = "https://example.com/r"
    deepest = _readme(f"{redirect}?u=" * MAX_URL_DEPTH + f"{stale}\n")
    cases += [
        ("rejects a core.md link at atx-spec main wrapped in ** emphasis",
         _names_probe(_readme(f"**{stale}**\n"), "README.md:1:")),
        ("rejects a core.md link at atx-spec main ending in a slash",
         _names_probe(_readme(f"{stale}/\n"), "README.md:1:")),
        ("rejects a core.md link at atx-spec main ending in a slash and a period",
         _names_probe(_readme(f"{stale}/.\n"), "README.md:1:")),
        ("rejects a core.md link at atx-spec main in a table cell with no blank around it",
         _once(_readme(f"| a |{stale}|b|\n"), "README.md:1:")),
        ("rejects a core.md link at atx-spec main naming the repository in upper case",
         _names_probe(_readme(stale.replace("/atx-spec/", "/ATX-SPEC/") + "\n"), "README.md:1:")),
        ("rejects, once, a core.md link at atx-spec main carried in another link's query string",
         _once(_readme(f"{redirect}?u={stale}\n"), "README.md:1:")),
        ("rejects a core.md link at atx-spec main carried in another link's #fragment",
         _once(_readme(f"{redirect}#{stale}\n"), "README.md:1:")),
        ("rejects a core.md link at atx-spec main carried in a query parameter before another",
         _once(_readme(f"{redirect}?u={stale}&v=1\n"), "README.md:1:")),
        ("rejects a core.md link at atx-spec main carried two links deep",
         _once(_readme(f"{redirect}?u={redirect}?v={stale}\n"), "README.md:1:")),
        (f"rejects a core.md link at atx-spec main carried {MAX_URL_DEPTH} links deep",
         _once(deepest, "README.md:1:") and f"links {stale}," in deepest[0]),
        (f"accepts a pinned core.md link carried {MAX_URL_DEPTH} links deep",
         not _readme(f"{redirect}#" * MAX_URL_DEPTH + f"{CORE_REF}\n")),
        (f"rejects, once, a line carrying a pinned core.md link {MAX_URL_DEPTH + 1} links deep",
         _too_deep(_readme(f"{redirect}#" * (MAX_URL_DEPTH + 1) + f"{CORE_REF}\n"))),
        (f"rejects, once, a line carrying two URLs more than {MAX_URL_DEPTH} links deep",
         _too_deep(_readme(f"{redirect}#" * (MAX_URL_DEPTH + 1) + f"{CORE_REF} "
                           + f"{redirect}#" * (MAX_URL_DEPTH + 1) + f"{CORE_REF}\n"))),
        (f"rejects, once and as too deep, a core.md link at atx-spec main {MAX_URL_DEPTH + 1} links deep",
         _too_deep(_readme(f"{redirect}#" * (MAX_URL_DEPTH + 1) + f"{stale}\n"))),
        ("reads a line of 20,000 links, each in the last one's query string, in linear time",
         _linear_links("?")),
        ("reads a line of 20,000 links, each in the last one's #fragment, in linear time",
         _linear_links("#")),
        ("accepts a pinned core.md link in emphasis, ending in a slash, naming the repository "
         "in upper case, carried in a query parameter or in a table cell",
         not _readme(f"**{CORE_REF}**\n{CORE_REF}/\n{CORE_REF.replace('/atx-spec/', '/ATX-SPEC/')}\n"
                     f"{redirect}?u={CORE_REF}&v=1\n| a |{CORE_REF}|b|\n")),
        ("rejects a core.md link at atx-spec main that carries a query string",
         _names_probe(_probe([good], docs={"README.md": f"See {stale}?plain=1\n"}), "README.md:1:")),
        ("rejects a core.md link at atx-spec main with an upper-case scheme",
         _names_probe(_probe([good], docs={"README.md": f"See {stale.replace('https', 'HTTPS', 1)}\n"}),
                      "README.md:1:")),
        ("accepts a pinned core.md link followed by a period, with a query or an upper-case scheme",
         not _probe([good], docs={"README.md": f"See {CORE_REF}.\n{CORE_REF}?plain=1\n"
                                                f"{CORE_REF.replace('https', 'HTTPS', 1)}\n"})),
        ("rejects a Go comment linking core.md on the old host",
         _names_probe(_probe([good], docs={"verifiers/go/verify.go": f"// ({stale.replace('-standards', '-org')})\n"}),
                      "verifiers/go/verify.go:1:")),
        ("reports a README.md and a verify.go that are not UTF-8 by name",
         [f.split(":", 1)[0] for f in _probe([good], docs={"README.md": b"x \xff y\n",
                                                          "verifiers/go/verify.go": b"// \xff\n"})]
         == ["README.md", "verifiers/go/verify.go"]),
        (_chmod_skips("reports a README.md it has no permission to read by name"),
         _unreadable_readme()),
        ("reports a vendored core.md that is not UTF-8 by name, after its digest failure",
         len(core_not_utf8) == 2 and core_not_utf8[0].startswith(f"{CORE_MD} has SHA-256 ")
         and core_not_utf8[1].startswith(f"{CORE_MD}: is not UTF-8 text")),
        ("reports a workflow that is not UTF-8 by name, and no pin failure",
         len(workflow_not_utf8) == 1 and workflow_not_utf8[0].startswith(f"{WORKFLOW}: is not UTF-8 text")),
        ("reports a missing vendored core.md by name, as its one failure even beside a "
         "citation that would fail, and tells the author to vendor it from the pinned atx-spec ref",
         _probe_tree(lambda root: (root / CORE_MD).unlink(), [_atx("1.1 ATX schema", ref=stale)])
         == [CORE_MD_MISSING]
         and CORE_MD_MISSING == f"{CORE_MD} is missing; vendor core.md from the pinned atx-spec ref"),
        (_chmod_skips("reports, once, a vendored core.md it has no permission to read by name"),
         _core_no_read_permission()),
        (_chmod_skips("reports, once, a vendored core.md in a directory it cannot search as "
                      "unreadable, not missing"), _core_dir_unsearchable()),
        (_chmod_skips("reports a workflow in a directory it cannot search as unreadable, not as "
                      "pinning no atx-spec commit"), _workflow_dir_unsearchable()),
        *_unreadable_tree_cases(),
        ("reports, once, a directory named like the vendored core.md by name",
         _unreadable_core(_as_directory)),
        ("reads the headings from the core.md bytes whose digest it took, not a second read",
         _reads_core_once()),
        ("skips every no-read-permission case, rather than failing it, where a file with "
         "no read permission can still be read", _skips_where_reads_allowed()),
        ("skips every no-read-permission case, with no traceback, where chmod raises",
         _skips_where_chmod_raises()),
        ("skips, with no traceback, the case that runs every no-read-permission case where a "
         "file with no read permission can still be read, where Path.chmod calls an os.chmod "
         "bound at import time that raises", _skips_where_bound_chmod_raises()),
        (_chmod_skips("skips, rather than fails, the cases that run every no-read-permission "
                      "case where a file with no read permission can still be read and where "
                      "chmod raises, where Path.chmod does not call os.chmod through the module"),
         _skips_where_chmod_bound()),
        ("puts Path.chmod back as it found it on leaving the case above, normally or by an "
         "exception, whether or not the path class set its own", _restores_chmod()),
        ("raises, rather than reading as a check failure, a vendored core.md a case could not "
         "make unreadable", _unmade_core_raises()),
        ("fails, with no traceback, a case whose tree it could not make unreadable, here by "
         "a mkdir on a README.md the tree already holds", _unmade_tree_fails(_mkdir_on_readme)),
        ("fails, with no traceback, a case whose tree it could not make unreadable by an "
         "exception other than an OSError", _unmade_tree_fails(_refuse_not_os)),
        ("fails, with no traceback, a case whose helper lets out, rather than returning None, "
         "the OSError of a mkdir on a README.md the tree already holds",
         not _unmade_tree_fails(_mkdir_on_readme, _check_unguarded)),
        ("fails, with no traceback, a case whose helper lets out, rather than returning None, "
         "an exception other than an OSError",
         not _unmade_tree_fails(_refuse_not_os, _check_unguarded)),
        ("says, in the label of every case that is red because check() raised on its "
         "unreadable tree, what was raised and the line and function that raised it",
         _red_cases_say_why()),
        ("keeps on one line the label of a case that is red because check() raised with "
         "text that carries a line break or other control character, written as a "
         "backslash escape, with each backslash the text carries doubled",
         _red_labels_one_line()),
        ("says what a case's make() raised in that case's label, and nothing an earlier "
         "case raised in the label of one in which nothing raised", _says_only_its_own()),
        ("--help prints usage and runs no check",
         help_rc == 0 and help_out == USAGE and "every ATX citation" not in help_out),
        ("-h prints usage and runs no check", h_rc == 0 and h_out == USAGE),
        ("an unknown argument prints usage to stderr, exits 2 and runs no check",
         bad_rc == 2 and bad_err == USAGE and not bad_out),
        ("the docstring's Usage block is USAGE", __doc__ is None or __doc__.endswith(USAGE)),
        ("imports and prints usage under python -OO", _usage_under_oo()),
        ("fails, with no traceback, a case whose child process outlives its timeout", hung),
        (f"ends a child process that outlives its timeout in under 0.4 s (took {hung_seconds:.3f} s)",
         hung_seconds < 0.4),
        ("skips fenced code when reading headings",
         core_headings("```\n# not a heading\n```\n## 1. Real\n") == {"1. Real"}),
        ("strips a closing # run", core_headings("## 2. Closed ##\n") == {"2. Closed"}),
        ("strips a closing # run followed by blanks", core_headings("## 2. Closed ## \t\n") == {"2. Closed"}),
        ("keeps a # that no blank precedes", core_headings("## 2. C#\n") == {"2. C#"}),
        ("reads a heading with a long run of blanks in linear time", _linear_heading(16000)),
        ("writes a file name that is not valid UTF-8 as a backslash escape",
         printable("fixtures/bad-\udcff.json") == "fixtures/bad-\\udcff.json"),
        ("leaves a UTF-8 file name unchanged", printable("fixtures/café.json") == "fixtures/café.json"),
        ("names a fixture and a JCS vector whose names are not valid UTF-8 as backslash escapes",
         _names_undecodable()),
    ]
    # Written out here rather than read from MAX_URL_DEPTH: the failure tells
    # the author the cap, so changing it turns this case red.
    cases += [
        ("reads a link 8 deep, and tells the author of a line carrying one 9 deep to link "
         "it at most 8 deep",
         not _readme("https://r/#" * 8 + f"{CORE_REF}\n")
         and _readme("https://r/#" * 9 + f"{CORE_REF}\n") == [
             "README.md:1: carries a URL more than 8 links deep in other links' query strings "
             "or #fragments, deeper than the check reads. Link it at most 8 deep."]),
    ]
    # After every case that skips where Path.chmod raises, so _CHMOD_SKIPS
    # holds each one's label, this one's included, by the time it compares.
    cases.append((_chmod_skips("runs every case to the end, with no traceback, where os.chmod "
                               "raises before --self-test starts, skipping exactly the "
                               "no-read-permission cases, the case that binds Path.chmod at "
                               "import time and itself"),
                  _self_test_where_chmod_refuses()))
    # After every other case but the last, so it reads their labels. It also
    # holds _by_rank() to the wordings that name a case by rank, the two a
    # label once named two cases by among them, and to those that do not,
    # and holds those wordings to needing every word _by_rank() reads.
    ranked = _by_rank([label for label, _ in cases])
    missed = [wording for wording in _BY_RANK_WORDINGS if not _by_rank([wording])]
    misread = _by_rank(list(_NOT_BY_RANK_WORDINGS))
    unneeded = _unneeded_words()
    cases.append(("names, in every label, another case by what it runs rather than by its rank "
                  "among the cases" + "".join(f" (by rank: {label})" for label in ranked)
                  + "".join(f" (not read as by rank: {wording})" for wording in missed)
                  + "".join(f" (read as by rank: {wording})" for wording in misread)
                  + "".join(f" (needed by no wording: {word})" for word in unneeded),
                  not ranked and not missed and not misread and not unneeded))
    # Last, so it sees every temporary tree the cases above built.
    left = ", ".join(printable(str(tmp)) for tmp in _LEFT)
    cases.append(("removes every temporary tree it builds" + (f" (left: {left})" if left else ""),
                  not _LEFT))
    failed = skipped = 0
    for label, ok in cases:
        mark = "SKIP " if ok is None else "GREEN" if ok else "RED  "
        print(f"  [{mark}] {label}")
        failed += ok is not None and not ok
        skipped += ok is None
    run = len(cases) - skipped
    print(f"self-test: {run - failed}/{run} cases green"
          + (f", {skipped} skipped" if skipped else ""))
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
