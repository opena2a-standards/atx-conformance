#!/usr/bin/env python3
"""Measures whether the kit's verifiers print raw control characters taken
from the files they read.

  terminal_probe.py <fixture.json> <go-binary> <python> <verify.py>

Writes two probes into a new scratch folder, both built from <fixture.json>:
a copy whose file name carries ESC, and a copy whose issuer DID, issuer chain,
key ids, name and description carry ESC, BEL and CR. Runs the Go binary and
the Python verifier on that folder and counts the bytes 0x00-0x08,
0x0b-0x1f and 0x7f in everything each prints (tab and newline are not
counted).

Exit 0: both printed 0 such bytes (the release needs no warning about it).
Exit 1: at least one printed some; the counts are on standard output.
Exit 2: the probe could not run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOSTILE = "\x1b[31m\x07\r"
CONTROL = set(range(0x00, 0x09)) | set(range(0x0B, 0x20)) | {0x7F}


def taint(value: str) -> str:
    return value.replace("authority:", "authority:" + HOSTILE, 1) if "authority:" in value else HOSTILE + value


def hostile_copy(doc: dict) -> dict:
    atx = doc.get("atx", {})
    for key in ("issuerDid",):
        if isinstance(atx.get(key), str):
            atx[key] = taint(atx[key])
    if isinstance(atx.get("issuerChain"), list):
        atx["issuerChain"] = [taint(v) if isinstance(v, str) else v for v in atx["issuerChain"]]
    for sig in atx.get("signatures", []) or []:
        if isinstance(sig, dict) and isinstance(sig.get("keyId"), str):
            sig["keyId"] = taint(sig["keyId"])
    for key in ("name", "description"):
        if isinstance(doc.get(key), str):
            doc[key] = HOSTILE + doc[key]
    return doc


def count(data: bytes) -> dict[str, int]:
    counts = {"ESC": data.count(0x1B), "BEL": data.count(0x07), "CR": data.count(0x0D)}
    counts["other"] = sum(1 for b in data if b in CONTROL) - sum(counts.values())
    return counts


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    fixture, go_binary, python, verify_py = (Path(a) for a in argv)
    doc = json.loads(fixture.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="kit-terminal-probe-") as tmp:
        probe = Path(tmp) / "probe"
        probe.mkdir()
        (probe / "probe-name-\x1b[31m.json").write_bytes(fixture.read_bytes())
        (probe / "probe-fields.json").write_text(json.dumps(hostile_copy(doc), indent=2), encoding="utf-8")
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        runs = {
            "go": [str(go_binary.resolve()), "probe"],
            "python": [str(python), "-B", str(verify_py.resolve()), "probe"],
        }
        dirty = False
        for name, cmd in runs.items():
            try:
                done = subprocess.run(cmd, cwd=tmp, env=env, capture_output=True, timeout=120)
            except (OSError, subprocess.TimeoutExpired) as e:
                print(f"terminal probe: {name} verifier did not run: {e}", file=sys.stderr)
                return 2
            out = done.stdout + done.stderr
            if b"summary:" not in done.stdout:
                print(f"terminal probe: {name} verifier printed no summary line (exit {done.returncode})",
                      file=sys.stderr)
                return 2
            c = count(out)
            total = sum(c.values())
            dirty |= total > 0
            print(f"terminal probe: {name} verifier printed {total} raw control bytes "
                  f"(ESC {c['ESC']}, BEL {c['BEL']}, CR {c['CR']}, other {c['other']})")
    return 1 if dirty else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
