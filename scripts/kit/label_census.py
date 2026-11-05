#!/usr/bin/env python3
"""Census of the private test keys in a folder: every JSON file that holds a
private seed must say, in the file, that its key is a test key.

  label_census.py <folder>

A JSON file holds a private seed when any object in it has a member whose
name contains "seed", "privateKey" or "secretKey" (case and separators
ignored) and whose value is a string of 16 or more characters drawn from the
hexadecimal and base64 alphabets. A member such as seedRef, whose value names
another file, holds no seed. The file is labelled when its top-level object
has a "$comment" string containing TEST-ONLY.

Prints one line per seed-bearing file and a summary, and exits 1 when:
  - a seed-bearing file carries no label;
  - a file under fixtures/ holds a seed (the Go binaries embed fixtures/*.json,
    which hold public keys only);
  - a .json file does not parse, so its seeds cannot be counted;
  - no seed-bearing file is found at all: this suite publishes its test seeds
    in vectors/, so a census that finds none is not reading the folder.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SEED_NAME = re.compile(r"seed|private[-_]?key|secret[-_]?key", re.IGNORECASE)
REFERENCE_NAME = re.compile(r"(ref|refs|path|file)$", re.IGNORECASE)
SEED_VALUE = re.compile(r"[0-9A-Za-z+/=_-]{16,}")
LABEL = "TEST-ONLY"


def seed_members(value, path="$"):
    if isinstance(value, dict):
        for key, inner in value.items():
            here = f"{path}.{key}"
            if (SEED_NAME.search(key) and not REFERENCE_NAME.search(key)
                    and isinstance(inner, str) and SEED_VALUE.fullmatch(inner)):
                yield here
            yield from seed_members(inner, here)
    elif isinstance(value, list):
        for i, inner in enumerate(value):
            yield from seed_members(inner, f"{path}[{i}]")


# -h or --help prints USAGE on stdout. Any other option is named on stderr above
# USAGE, and main returns 2 before it reads the folder.
USAGE = """\
usage: label_census.py <folder>
       label_census.py -h | --help
"""


def read_options(argv: list[str]) -> tuple[bool, list[str]]:
    """Whether -h or --help is given, and the options this script does not take."""
    unknown = [arg for arg in argv if arg.startswith("-") and arg != "-" and arg not in ("-h", "--help")]
    return "-h" in argv or "--help" in argv, unknown


def main(argv: list[str]) -> int:
    wants_help, unknown = read_options(argv)
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(USAGE, end="", file=sys.stderr)
        return 2
    if wants_help:
        print(USAGE, end="")
        return 0
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[0])
    if not root.is_dir():
        print(f"label census: not a folder: {root}", file=sys.stderr)
        return 2
    files = sorted(p for p in root.rglob("*.json") if p.is_file())
    bad: list[str] = []
    seeded = labelled = 0
    for p in files:
        rel = p.relative_to(root).as_posix()
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            bad.append(f"{rel}: does not parse as JSON ({e.__class__.__name__}), so its seeds cannot be counted")
            continue
        members = list(seed_members(doc))
        if not members:
            continue
        seeded += 1
        comment = doc.get("$comment") if isinstance(doc, dict) else None
        has_label = isinstance(comment, str) and LABEL in comment
        labelled += has_label
        print(f"label census: {rel}: seed in {', '.join(members)}; "
              f"{'labelled ' + LABEL if has_label else 'NO TEST LABEL'}")
        if not has_label:
            bad.append(f"{rel}: holds a private seed and its $comment does not say {LABEL}")
        if rel.split("/")[0] == "fixtures":
            bad.append(f"{rel}: a fixture holds a private seed; fixtures hold public keys only")
    print(f"label census: {len(files)} JSON files read, {seeded} seed-bearing, {labelled} labelled")
    if seeded == 0:
        bad.append("0 seed-bearing files: the census found none of the published test seeds, so it is not reading this folder")
    for line in bad:
        print(f"label census: REFUSED: {line}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
