#!/usr/bin/env python3
"""Python leg of the ATX v1.1 JCS byte-agreement gate.

For each vector under ../vectors, independently recompute the canonical bytes
from the vector's `tbs` object using the vendored RFC 8785 serializer, then
assert they reproduce the pinned `expected.canonicalHex` byte-for-byte. The
Python leg does not verify signatures (the post-quantum ML-DSA-65 library
landscape in Python is fragmented); the Go leg covers signature KATs. Agreement
on the canonical bytes is the property this leg proves.

Exit 0 iff every vector reproduces its pinned hex. Run via ../run-agreement.sh.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rfc8785 import canonicalize  # noqa: E402


def vectors_dir() -> Path:
    here = Path(__file__).resolve().parent
    for cand in (here.parent / "vectors", here / "vectors"):
        if cand.is_dir():
            return cand
    sys.stderr.write("[py] error: could not locate vectors/ dir\n")
    sys.exit(2)


def main() -> int:
    vdir = vectors_dir()
    files = sorted(p for p in vdir.glob("*.json"))
    if not files:
        sys.stderr.write(f"[py] error: no vector files in {vdir}\n")
        return 2

    hex_by_name: dict[str, str] = {}
    npass = nfail = 0
    for path in files:
        vec = json.loads(path.read_text())
        name = vec["name"]
        want = vec["expected"]["canonicalHex"]
        got = canonicalize(vec["tbs"]).hex()
        hex_by_name[name] = got
        if got == want:
            print(f"[py]   PASS  {name:<34}  {len(got)//2} bytes")
            npass += 1
        else:
            print(f"[py]   FAIL  {name:<34}  canonical hex mismatch")
            print(f"       want: {want}")
            print(f"       got:  {got}")
            nfail += 1

    a, b = hex_by_name.get("key-order-scramble"), hex_by_name.get("baseline")
    if a is not None and b is not None:
        if a == b:
            print(f"[py]   PASS  {'invariant:scramble==baseline':<34}  identical canonical bytes")
        else:
            print(f"[py]   FAIL  {'invariant:scramble==baseline':<34}  scramble differs from baseline")
            nfail += 1

    print(f"\n[py]     {npass} pass, {nfail} fail ({len(files)} vectors)")
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
