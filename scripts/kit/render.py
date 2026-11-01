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
      Refuses when the notes name a --version form (a v0.0.0 pseudo-version
      or "(devel), commit <sha>") that a binary does not print.

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
    "<expected last line>", "<python expected last line>",
    "<first 12 characters of the commit>",
)
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


def cmd_texts(facts_path: Path, templates: Path, kit: Path, dist: Path) -> None:
    f = json.loads(facts_path.read_text(encoding="utf-8"))
    sha, tag, repo = f["sha"], f["tag"], f["repo"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        fail(f"not a full commit id: {sha}")
    if not re.fullmatch(r"kit-[0-9]{4}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?", tag):
        fail(f"not a kit tag: {tag}")
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
        "<date>": utc(f["commitTime"], "%Y%m%d%H%M%S"),
        "<first 12 characters of the commit>": sha[:12],
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
    claims = re.findall(r"v0\.0\.0-[0-9]{14}-[0-9a-f]{12}", notes)
    claims += re.findall(r"\(devel\), commit [0-9a-f]{40}", notes)
    if not version_files:
        fail("no version line to check the notes against")
    problems = []
    for vf in version_files:
        line = vf.read_text(encoding="utf-8").strip()
        for claim in claims:
            if claim not in line:
                problems.append(f"the notes say --version prints {claim}; {vf.stem} prints: {line}")
    if problems:
        fail("the release notes name a --version form the binaries do not print:\n  "
             + "\n  ".join(problems))
    print(f"render: the notes' {len(claims)} --version claim(s) match all {len(version_files)} binaries")


def main(argv: list[str]) -> None:
    if len(argv) == 5 and argv[0] == "texts":
        cmd_texts(Path(argv[1]), Path(argv[2]), Path(argv[3]), Path(argv[4]))
    elif len(argv) == 3 and argv[0] == "check-readme":
        cmd_check_readme(Path(argv[1]), argv[2])
    elif len(argv) >= 2 and argv[0] == "check-claims":
        cmd_check_claims(Path(argv[1]), [Path(a) for a in argv[2:]])
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
