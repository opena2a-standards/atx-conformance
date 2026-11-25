#!/usr/bin/env python3
"""Writes the interop day kit's text files from scripts/kit/templates, and checks them.

  render.py texts <facts.json> <templates-dir> <kit-dir> <dist-dir>
      Writes README-START-HERE.md, CONTACT.txt and PYTHON.md into the kit and
      release-notes.md and release-title.txt into <dist-dir>, then runs
      check-readme on the README. Every value comes from facts.json, which the
      assembly writes from the tree, the tag and the per-platform runs.
  render.py check-readme <README-START-HERE.md> <expected-last-line>
      The first-run screen's form: at most 45 lines and 80 columns, printable
      ASCII only, no line starting with #, | or <, no line indented four
      spaces after a blank line; the eight anchors in order within lines 1 to
      30; the expected last line as captured; PYTHON.md named once and no pip
      line on this screen.
  render.py check-claims <release-notes.md> <version-line-file>...
      Refuses when the notes name a --version form (a Go version such as
      v0.6.0 or v0.0.0-<time>-<sha12>, or "(devel), commit <sha>") that is
      not the whole version a binary prints.
  render.py go-version <commit> <committer-time> <tags-at-commit> <tags-in-history>
      Prints the version Go stamps into a clean build of the commit, from
      the tags git lists on the commit and on the commit and its ancestors
      (two arguments, each the refs/tags/ names one per line): vX.Y.Z when
      the highest version tag on the commit is vX.Y.Z; else
      vX.Y.(Z+1)-0.<time>-<sha12> when the highest version tag on the commit
      or an ancestor is vX.Y.Z; else v0.0.0-<time>-<sha12>. Refuses when the
      version Go would stamp comes from a tag with a pre-release or build
      part, a form the kit check does not derive.

Template lines: "@title <left>|<right>" is written with <right> ending at
column 80; "@f5 <line>" is written only when the terminal-safety fallback
applies and "@nof5 <line>" only when it does not; "@nottested <line>" only
when a platform had no runner of its own. Every placeholder is a literal
<name>; a placeholder left unfilled refuses.
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path

PLACEHOLDERS = (
    "<sha>", "<sha7>", "<date>", "<N>", "<platforms>", "<release URL>", "<owner/repo>",
    "<file>", "<tag>", "<event>", "<tested>", "<not tested>", "<workflow file>",
    "<expected last line>", "<python expected last line>", "<version>",
)
# A version tag as Go reads one: v and a semantic version
# (https://semver.org/spec/v2.0.0.html). The groups are the major, minor and
# patch versions, the pre-release part and the build part.
SEMVER = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")
# Go's own pattern for a pseudo-version (golang.org/x/mod/module): Go reads no
# tag of that shape as a version.
PSEUDO = re.compile(r"v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?",
                    re.ASCII)
# A --version claim in the release notes: any word shaped as a Go version.
CLAIM = re.compile(r"\bv[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
ANCHORS = (
    r"^This kit carries", r"^Running a verifier", r"^Check before you run", r"^Run the fixtures",
    r"Expected last line", r"^Every private key", r"^A credential of your own", r"^To check a credential",
)
OS_NAMES = {"darwin": "macOS", "linux": "Linux", "windows": "Windows"}


def fail(message: str) -> None:
    print(f"render: {message}", file=sys.stderr)
    sys.exit(1)


def render(template: str, values: dict[str, str], f5: bool, not_tested: bool) -> str:
    out: list[str] = []
    for line in template.split("\n")[:-1] if template.endswith("\n") else template.split("\n"):
        for directive, keep in (("@f5", f5), ("@nof5", not f5), ("@nottested", not_tested)):
            if line == directive or line.startswith(directive + " "):
                if not keep:
                    line = None  # type: ignore[assignment]
                else:
                    line = line[len(directive) + 1:]
                break
        if line is None:
            continue
        title = line.startswith("@title ")
        if title:
            line = line[len("@title "):]
        for key, value in values.items():
            line = line.replace(key, value)
        if title:
            left, sep, right = line.partition("|")
            if not sep or len(left) + 1 + len(right) > 80:
                fail(f"title line does not fit 80 columns: {line!r}")
            line = left + " " * (80 - len(left) - len(right)) + right
        out.append(line)
    text = "\n".join(out) + "\n"
    left = [p for p in PLACEHOLDERS if p in text]
    if left:
        fail(f"placeholder(s) left unfilled: {', '.join(left)}")
    return text


def check_readme(text: str, expected: str) -> list[str]:
    problems: list[str] = []
    if not text.endswith("\n"):
        problems.append("does not end with a newline")
    lines = text.split("\n")[:-1]
    if len(lines) > 45:
        problems.append(f"{len(lines)} lines, more than 45")
    for n, line in enumerate(lines, 1):
        if len(line) > 80:
            problems.append(f"line {n} is {len(line)} columns, more than 80")
        if re.search(r"[^ -~]", line):
            problems.append(f"line {n} holds a byte outside printable ASCII")
        if line[:1] in ("#", "|", "<"):
            problems.append(f"line {n} starts with {line[0]!r}")
        if n > 1 and lines[n - 2] == "" and line.startswith("    "):
            problems.append(f"line {n} is indented four spaces after a blank line")
    combined = re.compile("|".join(ANCHORS))
    hits = [(n, line) for n, line in enumerate(lines, 1) if combined.search(line)]
    if len(hits) != len(ANCHORS):
        problems.append(f"{len(hits)} anchor lines, not {len(ANCHORS)}")
    else:
        for (n, line), anchor in zip(hits, ANCHORS):
            if not re.search(anchor, line):
                problems.append(f"line {n} is out of order: expected {anchor!r}")
            if n > 30:
                problems.append(f"anchor {anchor!r} at line {n}, after line 30")
    expected_lines = [line for line in lines if "Expected last line:" in line]
    if len(expected_lines) != 1 or expected not in expected_lines[0]:
        problems.append(f"the Expected last line does not carry the captured line {expected!r}")
    if text.count("PYTHON.md") != 1:
        problems.append(f"PYTHON.md named {text.count('PYTHON.md')} times, not once")
    if re.search(r"\bpip\b", text):
        problems.append("a pip line on the first-run screen (the install line lives in PYTHON.md)")
    return problems


def utc(epoch: int, fmt: str) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(fmt)


def go_reads(tag: str) -> bool:
    """Whether Go reads the tag as a version of this module, whose go.mod is
    at the repository root and whose path has no /vN suffix: a semantic
    version of major version 0 or 1 that is not shaped as a pseudo-version.
    Go passes over every other tag (kit-YYYY-MM-DD, v1.2, v2.0.0)."""
    m = SEMVER.fullmatch(tag)
    return m is not None and m.group(1) in ("0", "1") and not (tag.count("-") >= 2 and PSEUDO.fullmatch(tag))


def highest_release(tags: list[str], where: str) -> tuple[int, int, int]:
    """The highest of tags as Go compares them (semantic version precedence,
    the build part ignored). It must be a release vX.Y.Z given by a tag of
    exactly that form; a pre-release or a build part refuses."""
    parsed = [(t, SEMVER.fullmatch(t)) for t in tags]
    top = max((int(m.group(1)), int(m.group(2)), int(m.group(3))) for _, m in parsed)
    at_top = [(t, m) for t, m in parsed if (int(m.group(1)), int(m.group(2)), int(m.group(3))) == top]
    named = ", ".join(sorted(t for t, _ in at_top))
    if all(m.group(4) is not None for _, m in at_top):
        fail(f"the highest Go version tag {where} is a pre-release ({named}); "
             "Go stamps a version the kit check does not derive")
    if not any(m.group(4) is None and m.group(5) is None for _, m in at_top):
        fail(f"the highest Go version tag {where} has a build part ({named}); "
             "the kit check derives the version only from a tag vX.Y.Z")
    return top


def go_version(sha: str, commit_time: int, at_commit: list[str], in_history: list[str]) -> str:
    """The version Go stamps into a clean build of commit sha in a checkout
    of it: the highest version tag on the commit (Go takes only a tag with no
    build part there); else a pseudo-version after the highest version tag on
    the commit or an ancestor; else v0.0.0-<time>-<sha12>. <time> is the
    committer time, UTC. A tag Go does not read changes nothing."""
    stamp = utc(commit_time, "%Y%m%d%H%M%S")
    on = [t for t in at_commit if go_reads(t) and SEMVER.fullmatch(t).group(5) is None]
    if on:
        major, minor, patch = highest_release(on, f"on {sha[:12]}")
        return f"v{major}.{minor}.{patch}"
    seen = [t for t in in_history if go_reads(t)]
    if seen:
        major, minor, patch = highest_release(seen, f"on {sha[:12]} or an ancestor")
        return f"v{major}.{minor}.{patch + 1}-0.{stamp}-{sha[:12]}"
    return f"v0.0.0-{stamp}-{sha[:12]}"


def is_stamped_form(version: str, sha: str) -> bool:
    """Whether version is one of the three forms go_version gives for sha."""
    n, t, sha12 = r"(?:0|[1-9][0-9]*)", r"[0-9]{14}", re.escape(sha[:12])
    return any(re.fullmatch(p, version, re.ASCII) for p in (
        rf"v0\.0\.0-{t}-{sha12}", rf"v[01]\.{n}\.{n}", rf"v[01]\.{n}\.[1-9][0-9]*-0\.{t}-{sha12}"))


def cmd_texts(facts_path: Path, templates: Path, kit: Path, dist: Path) -> None:
    f = json.loads(facts_path.read_text(encoding="utf-8"))
    sha, tag, repo = f["sha"], f["tag"], f["repo"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        fail(f"not a full commit id: {sha}")
    if not re.fullmatch(r"kit-[0-9]{4}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?", tag):
        fail(f"not a kit tag: {tag}")
    if not is_stamped_form(f["version"], sha):
        fail(f"not a version Go stamps for {sha}: {f['version']!r}")
    oses = []
    for target in f["targets"]:
        os_name = OS_NAMES[target.split("/")[0]]
        if os_name not in oses:
            oses.append(os_name)
    common = {
        "<sha>": sha,
        "<sha7>": sha[:7],
        "<owner/repo>": repo,
        "<release URL>": f"https://github.com/{repo}/releases/tag/{tag}",
        "<file>": "SHA256SUMS",
        "<tag>": tag,
        "<workflow file>": f["workflow"],
        "<N>": str(f["n"]),
    }
    readme_values = dict(common, **{
        "<date>": utc(f["commitTime"], "%Y-%m-%d"),
        "<platforms>": "/".join(oses),
        "<expected last line>": f["expected"],
    })
    notes_values = dict(common, **{
        "<version>": f["version"],
        "<tested>": ", ".join(f["tested"]),
        "<not tested>": ", ".join(f["notTested"]),
        "<event>": tag[len("kit-"):],
    })
    f5, not_tested = bool(f["f5"]), bool(f["notTested"])

    def write(name: str, out: Path, values: dict[str, str]) -> str:
        text = render((templates / name).read_text(encoding="ascii"), values, f5, not_tested)
        out.write_text(text, encoding="ascii")
        return text

    readme = write("README-START-HERE.md.in", kit / "README-START-HERE.md", readme_values)
    write("CONTACT.txt.in", kit / "CONTACT.txt", common)
    write("PYTHON.md.in", kit / "PYTHON.md",
          dict(common, **{"<python expected last line>": f["pythonExpected"]}))
    write("release-notes.md.in", dist / "release-notes.md", notes_values)
    write("release-title.txt.in", dist / "release-title.txt", notes_values)
    problems = check_readme(readme, f["expected"])
    if problems:
        fail("README-START-HERE.md is not in its form:\n  " + "\n  ".join(problems))
    lines = readme.split("\n")[:-1]
    print(f"render: README-START-HERE.md {len(lines)} lines, longest {max(map(len, lines))} columns, "
          f"anchors within line 30, {'with' if f5 else 'without'} the terminal-safety lines")


def cmd_check_readme(path: Path, expected: str) -> None:
    problems = check_readme(path.read_bytes().decode("utf-8", errors="replace"), expected)
    if problems:
        fail("\n  ".join([f"{path.name} is not in its form:"] + problems))
    print(f"render: {path.name} is in its form")


def cmd_check_claims(notes_path: Path, version_files: list[Path]) -> None:
    notes = notes_path.read_text(encoding="utf-8")
    claims = CLAIM.findall(notes)
    claims += re.findall(r"\(devel\), commit [0-9a-f]{40}", notes)
    if not version_files:
        fail("no version line to check the notes against")
    problems = []
    for vf in version_files:
        line = vf.read_text(encoding="utf-8").strip()
        for claim in claims:
            # The claim is the whole version the line names, between the module
            # path and ", built with": never a part of it.
            if f" {claim}, built with " not in line:
                problems.append(f"the notes say --version prints {claim}; {vf.stem} prints: {line}")
    if problems:
        fail("the release notes name a --version form the binaries do not print:\n  "
             + "\n  ".join(problems))
    print(f"render: the notes' {len(claims)} --version claim(s) match all {len(version_files)} binaries")


def tag_names(refs: str, what: str) -> list[str]:
    names = []
    for ref in refs.split("\n"):
        if not ref:
            continue
        if not ref.startswith("refs/tags/"):
            fail(f"{what}: not a tag: {ref!r}")
        names.append(ref[len("refs/tags/"):])
    return names


def cmd_go_version(sha: str, commit_time: str, at_commit: str, in_history: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        fail(f"not a full commit id: {sha}")
    if not re.fullmatch(r"[0-9]+", commit_time):
        fail(f"not a committer time in seconds: {commit_time!r}")
    print(go_version(sha, int(commit_time), tag_names(at_commit, "the tags on the commit"),
                     tag_names(in_history, "the tags on the commit and its ancestors")))


# -h or --help prints USAGE on stdout. An option, or a first argument that
# names no command, is named on stderr above USAGE, and main exits 2 before it
# reads or writes a file.
USAGE = """\
usage: render.py texts <facts.json> <templates-dir> <kit-dir> <dist-dir>
       render.py check-readme <README-START-HERE.md> <expected-last-line>
       render.py check-claims <release-notes.md> <version-line-file>...
       render.py go-version <commit> <committer-time> <tags-at-commit> <tags-in-history>
       render.py -h | --help
"""
COMMANDS = ("texts", "check-readme", "check-claims", "go-version")


def is_option(arg: str) -> bool:
    return arg.startswith("-") and arg != "-"


def read_options(argv: list[str]) -> tuple[bool, list[str]]:
    """Whether -h or --help is given, and the arguments this script does not know."""
    unknown = [argv[0]] if argv and argv[0] and argv[0] not in COMMANDS and not is_option(argv[0]) else []
    unknown += [arg for arg in argv if is_option(arg) and arg not in ("-h", "--help")]
    return "-h" in argv or "--help" in argv, unknown


def main(argv: list[str]) -> None:
    wants_help, unknown = read_options(argv)
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(USAGE, end="", file=sys.stderr)
        sys.exit(2)
    if wants_help:
        print(USAGE, end="")
        sys.exit(0)
    if len(argv) == 5 and argv[0] == "texts":
        cmd_texts(Path(argv[1]), Path(argv[2]), Path(argv[3]), Path(argv[4]))
    elif len(argv) == 3 and argv[0] == "check-readme":
        cmd_check_readme(Path(argv[1]), argv[2])
    elif len(argv) >= 2 and argv[0] == "check-claims":
        cmd_check_claims(Path(argv[1]), [Path(a) for a in argv[2:]])
    elif len(argv) == 5 and argv[0] == "go-version":
        cmd_go_version(argv[1], argv[2], argv[3], argv[4])
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
