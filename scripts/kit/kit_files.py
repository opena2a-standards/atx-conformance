#!/usr/bin/env python3
"""File operations of the interop day kit, with no tool but the standard library.

  kit_files.py sums <kit-dir>
      Writes SHA256SUMS for every file under <kit-dir> to standard output, one
      "<sha256>  <path>" line per file (the GNU coreutils form), sorted by path.
  kit_files.py listcheck <kit-dir> <SHA256SUMS>
      Refuses unless the files under <kit-dir> are exactly the files SHA256SUMS
      names: `sha256sum -c` passes with an unlisted file present, so this is the
      check that catches one. Also refuses a link, a special file, an empty
      directory and a path outside [A-Za-z0-9._/-].
  kit_files.py archive <kit-dir> <out> --mtime <unix-time> [--plain]
      Writes <kit-dir> as one tar.gz (or, with --plain, a tar) whose bytes depend
      only on the files: entries sorted, owner 0, the given time on every entry,
      mode 0755 for a directory or a file with an execute bit and 0644 otherwise,
      no time and no name in the gzip header.
  kit_files.py extract <archive> <dest-dir>
      Extracts an archive written by `archive`, refusing a link, a special file,
      an absolute path, a ".." component and a second top-level name.
  kit_files.py flip <file> <out>
      Writes a copy of <file> with its last byte changed.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import stat
import sys
import tarfile
from pathlib import Path
from typing import NoReturn

NAME_OK = re.compile(r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*")
SUMS_LINE = re.compile(r"([0-9a-f]{64})  (\S(?:.*\S)?)")


def fail(message: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"kit_files: {message}", file=sys.stderr)
    sys.exit(1)


def check_name(rel: str) -> None:
    if not NAME_OK.fullmatch(rel) or any(part in (".", "..") for part in rel.split("/")):
        fail(f"path outside [A-Za-z0-9._/-] or with a . or .. component: {rel!r}")


def walk(root: Path) -> list[str]:
    """Every regular file under root, as a sorted list of '/'-joined relative paths."""
    if not root.is_dir() or root.is_symlink():
        fail(f"not a directory: {root}")
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        entries = dirnames + filenames
        if not entries and here != root:
            fail(f"empty directory: {here.relative_to(root).as_posix()}")
        for name in dirnames:
            p = here / name
            if p.is_symlink():
                fail(f"link: {p.relative_to(root).as_posix()}")
        for name in filenames:
            p = here / name
            rel = p.relative_to(root).as_posix()
            mode = os.lstat(p).st_mode
            if not stat.S_ISREG(mode):
                fail(f"not a regular file: {rel}")
            check_name(rel)
            files.append(rel)
    return sorted(files, key=lambda s: s.encode())


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def cmd_sums(kit: Path) -> None:
    files = walk(kit)
    if not files:
        fail(f"no files under {kit}")
    out = sys.stdout.buffer
    for rel in files:
        out.write(f"{sha256_file(kit / rel)}  {rel}\n".encode("ascii"))


def read_sums(path: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    data = path.read_bytes()
    if not data.endswith(b"\n"):
        fail(f"{path.name} does not end with a newline")
    for n, raw in enumerate(data.decode("ascii").split("\n")[:-1], 1):
        m = SUMS_LINE.fullmatch(raw)
        if not m:
            fail(f"{path.name}:{n} is not a '<sha256>  <path>' line")
        rel = m.group(2)
        check_name(rel)
        if rel in names:
            fail(f"{path.name}:{n} names {rel} a second time")
        names[rel] = m.group(1)
    if not names:
        fail(f"{path.name} names no file")
    return names


def cmd_listcheck(kit: Path, sums: Path) -> None:
    listed = set(read_sums(sums))
    present = set(walk(kit))
    extra = sorted(present - listed)
    missing = sorted(listed - present)
    if extra or missing:
        for rel in extra[:20]:
            print(f"kit_files: in the folder, not in {sums.name}: {rel}", file=sys.stderr)
        for rel in missing[:20]:
            print(f"kit_files: in {sums.name}, not in the folder: {rel}", file=sys.stderr)
        fail(f"file list differs: {len(extra)} unlisted, {len(missing)} missing")
    print(f"kit_files: file list equal: {len(present)} files, each named once in {sums.name}")


def cmd_archive(kit: Path, out: Path, mtime: int, plain: bool) -> None:
    files = walk(kit)
    top = kit.name
    check_name(top)
    dirs = sorted({"/".join(rel.split("/")[:i]) for rel in files for i in range(1, rel.count("/") + 1)},
                  key=lambda s: s.encode())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        def add(rel: str, is_dir: bool) -> None:
            info = tarfile.TarInfo(f"{top}/{rel}" if rel else top)
            info.mtime = mtime
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if is_dir:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
                return
            path = kit / rel
            info.mode = 0o755 if os.stat(path).st_mode & 0o111 else 0o644
            info.size = path.stat().st_size
            with open(path, "rb") as f:
                tar.addfile(info, f)
        add("", True)
        entries = [(d, True) for d in dirs] + [(f, False) for f in files]
        for rel, is_dir in sorted(entries, key=lambda e: e[0].encode()):
            add(rel, is_dir)
    data = buf.getvalue()
    if not plain:
        gz = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=gz, mtime=0, compresslevel=9) as g:
            g.write(data)
        data = gz.getvalue()
    out.write_bytes(data)
    print(f"kit_files: wrote {out.name}: {len(files)} files, {len(data)} bytes")


def cmd_extract(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        fail(f"destination is not empty: {dest}")
    with tarfile.open(archive, mode="r:*") as tar:
        members = tar.getmembers()
        tops = set()
        for m in members:
            name = m.name
            if name.startswith("/") or ".." in name.split("/"):
                fail(f"member with an absolute or .. path: {name!r}")
            if not (m.isreg() or m.isdir()):
                fail(f"member that is not a file or a directory: {name!r}")
            check_name(name)
            tops.add(name.split("/")[0])
        if len(tops) != 1:
            fail(f"archive with {len(tops)} top-level names")
        if hasattr(tarfile, "data_filter"):
            tar.extractall(dest, members=members, filter="data")
        else:
            tar.extractall(dest, members=members)
    print(f"kit_files: extracted {sum(1 for m in members if m.isreg())} files into {dest}")


def cmd_flip(src: Path, out: Path) -> None:
    data = bytearray(src.read_bytes())
    if not data:
        fail(f"empty file: {src}")
    data[-1] ^= 0x01
    out.write_bytes(bytes(data))


def main(argv: list[str]) -> None:
    if len(argv) >= 2 and argv[0] == "sums" and len(argv) == 2:
        cmd_sums(Path(argv[1]))
    elif len(argv) == 3 and argv[0] == "listcheck":
        cmd_listcheck(Path(argv[1]), Path(argv[2]))
    elif len(argv) in (5, 6) and argv[0] == "archive" and argv[3] == "--mtime":
        plain = argv[5:] == ["--plain"]
        if len(argv) == 6 and not plain:
            fail("usage: kit_files.py archive <kit-dir> <out> --mtime <unix-time> [--plain]")
        cmd_archive(Path(argv[1]), Path(argv[2]), int(argv[4]), plain)
    elif len(argv) == 3 and argv[0] == "extract":
        cmd_extract(Path(argv[1]), Path(argv[2]))
    elif len(argv) == 3 and argv[0] == "flip":
        cmd_flip(Path(argv[1]), Path(argv[2]))
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
