#!/usr/bin/env python3
"""Checks the interop day kit's release workflow, and the signing job of
conformance.yml, for the controls they must hold.

  check_workflow.py pins <workflow.yml> [--job <job-id>]
      Every `uses:` line (in the whole file, or in one job) names a 40-hex
      commit. Prints "<n> uses: lines, <n> pinned by commit, <n> unpinned".
  check_workflow.py release <kit-release.yml>
      The release workflow's shape:
      - triggers: a push of tags matching kit-* and nothing else, and
        workflow_dispatch; no pull_request_target;
      - permissions: none at the top; stage, test, build, verify and
        verify-candidate hold read scopes only; publish holds exactly
        contents: write; attest holds exactly id-token: write,
        attestations: write and contents: read, the two write scopes the
        attestation step needs, and no other job holds two write scopes;
      - every actions/checkout sets persist-credentials: false and no ref;
      - no `${{ }}` expression inside a run: block (inputs reach a shell
        through env: only);
      - no run: line of a cmd step has a `%...%` expansion directly before
        `>` (cmd expands the variable before it reads redirections, so a
        one-digit value such as the exit code 0 is read as a handle number
        and the file gets nothing); a step's shell is its own `shell:`, or,
        when it sets none, its job's `defaults: run: shell:`, or, when the
        job sets none either, the workflow's;
      - publish creates the release as a draft, uploads the assets, then
        publishes with --latest=false, with gh only;
      - the stage job compiles before anything is written, and writes no
        README-START-HERE.md, CONTACT.txt or release notes;
      - Go is pinned to an exact version.

The reader accepts the YAML this repository writes (block mappings and
sequences, plain and quoted scalars, one-level flow collections, block
scalars) and refuses anything else, so a form it cannot read is a failure,
never a pass. A workflow path it cannot open, such as one that does not
exist or a directory, and a file that is not UTF-8 text are refused the same
way, on one stderr line, `check_workflow: cannot read the workflow:
'<path>': <reason>`, with exit 1.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PIN = re.compile(r"[^@\s]+@[0-9a-f]{40}")
READ_SCOPES = {"contents", "actions", "attestations"}


class Unreadable(Exception):
    pass


def strip_comment(text: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def scalar(text: str):
    text = text.strip()
    if text == "":
        return None
    if text[0] in "'\"":
        if len(text) < 2 or text[-1] != text[0]:
            raise Unreadable(f"unterminated quote: {text}")
        return text[1:-1]
    if text[0] == "[":
        if not text.endswith("]"):
            raise Unreadable(f"flow sequence over several lines: {text}")
        inner = text[1:-1].strip()
        if any(c in inner for c in "[]{}"):
            raise Unreadable(f"nested flow collection: {text}")
        return [] if not inner else [scalar(p) for p in inner.split(",")]
    if text[0] == "{":
        if text.replace(" ", "") != "{}":
            raise Unreadable(f"flow mapping: {text}")
        return {}
    if text[0] in "&*!|>":
        raise Unreadable(f"unsupported YAML node: {text}")
    return text


class Reader:
    def __init__(self, text: str):
        self.lines = text.split("\n")
        self.i = 0

    def next_content(self):
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                raise Unreadable(f"line {self.i + 1}: tab indentation")
            body = strip_comment(raw)
            if body.strip():
                return len(body) - len(body.lstrip()), body.strip()
            self.i += 1
        return None

    def block_scalar(self, parent_indent: int) -> str:
        out = []
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if raw.strip() and len(raw) - len(raw.lstrip()) <= parent_indent:
                break
            out.append(raw)
            self.i += 1
        while out and not out[-1].strip():
            out.pop()
        return "\n".join(out)

    def value(self, rest: str, indent: int, line_no: int):
        if rest in ("|", "|-", "|+", ">", ">-", ">+"):
            return self.block_scalar(indent)
        if rest == "":
            nxt = self.next_content()
            if nxt and nxt[0] > indent:
                return self.block(nxt[0])
            if nxt and nxt[0] == indent and nxt[1].startswith("- "):
                return self.block(indent)
            return None
        return scalar(rest)

    def block(self, indent: int):
        first = self.next_content()
        if first is None:
            return None
        if first[1].startswith("- ") or first[1] == "-":
            return self.sequence(indent)
        return self.mapping(indent)

    def mapping(self, indent: int, first_inline: str | None = None):
        result: dict = {}
        pending = first_inline
        while True:
            if pending is not None:
                body, pending = pending, None
                line_no = self.i
            else:
                nxt = self.next_content()
                if nxt is None or nxt[0] < indent:
                    return result
                if nxt[0] > indent:
                    raise Unreadable(f"line {self.i + 1}: unexpected indentation")
                body = nxt[1]
                if body.startswith("- "):
                    return result
                line_no = self.i
                self.i += 1
            m = re.fullmatch(r"('[^']*'|\"[^\"]*\"|[^\s:'\"][^:]*?)\s*:(?:\s+(.*))?", body)
            if not m:
                raise Unreadable(f"line {line_no + 1}: not a key: value line: {body}")
            key = scalar(m.group(1))
            if key in result:
                raise Unreadable(f"line {line_no + 1}: duplicate key {key}")
            result[key] = self.value((m.group(2) or "").strip(), indent, line_no)

    def sequence(self, indent: int):
        result = []
        while True:
            nxt = self.next_content()
            if nxt is None or nxt[0] < indent:
                return result
            if nxt[0] != indent or not (nxt[1].startswith("- ") or nxt[1] == "-"):
                return result
            line_no = self.i
            self.i += 1
            item = nxt[1][1:].strip()
            if item == "":
                result.append(self.value("", indent, line_no))
            elif re.match(r"('[^']*'|\"[^\"]*\"|[^\s:'\"\[{][^:]*?)\s*:(\s|$)", item):
                result.append(self.mapping(indent + 2, first_inline=item))
            else:
                result.append(scalar(item))


def read(path: Path) -> str:
    """The workflow's text. An OSError from reading the path, or a file that
    is not UTF-8, raises Unreadable naming the path as a quoted string, which
    main prints on one line in place of a traceback."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        raise Unreadable(f"{str(path)!r}: {e.strerror or e}")
    except UnicodeDecodeError as e:
        raise Unreadable(f"{str(path)!r}: {e}")


def load(path: Path):
    text = read(path)
    reader = Reader(text)
    doc = reader.block(0)
    if reader.next_content() is not None:
        raise Unreadable(f"line {reader.i + 1}: content after the document")
    if not isinstance(doc, dict):
        raise Unreadable("the workflow is not a mapping")
    return doc, text


def uses_lines(text: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"^\s*(?:-\s+)?uses:\s*(\S+)", text, re.M)]


def job_text(text: str, job: str) -> str:
    lines = text.split("\n")
    start = next((i for i, l in enumerate(lines) if l == f"  {job}:"), None)
    if start is None:
        raise Unreadable(f"no job {job}")
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"  \S", lines[i])), len(lines))
    return "\n".join(lines[start:end])


def cmd_pins(path: Path, job: str | None) -> int:
    text = read(path)
    if job:
        text = job_text(text, job)
    uses = uses_lines(text)
    pinned = [u for u in uses if PIN.fullmatch(u)]
    unpinned = [u for u in uses if not PIN.fullmatch(u)]
    where = f"{path.name}" + (f" job {job}" if job else "")
    print(f"pins: {where}: {len(uses)} uses: lines, {len(pinned)} pinned by commit, {len(unpinned)} unpinned")
    for u in unpinned:
        print(f"pins: not pinned by commit: {u}", file=sys.stderr)
    if not uses:
        print(f"pins: {where} has no uses: line", file=sys.stderr)
        return 1
    return 1 if unpinned else 0


def steps_of(job: dict) -> list[dict]:
    steps = job.get("steps") or []
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        raise Unreadable("steps is not a list of mappings")
    return steps


def default_shell(holder: dict, where: str):
    """The shell: under defaults: run: in a job, or at the top of the
    workflow; None when it names none."""
    defaults = holder.get("defaults")
    if defaults is None:
        return None
    run = defaults.get("run") if isinstance(defaults, dict) else None
    if not isinstance(defaults, dict) or not isinstance(run, (dict, type(None))):
        raise Unreadable(f"{where}'s defaults: is not a mapping whose run: is a mapping")
    return None if run is None else run.get("shell")


def cmd_release(path: Path) -> int:
    doc, text = load(path)
    problems: list[str] = []
    on = doc.get("on", doc.get(True))
    if not isinstance(on, dict):
        problems.append("on: is not a mapping")
        on = {}
    if set(on) != {"push", "workflow_dispatch"}:
        problems.append(f"triggers are {sorted(map(str, on))}, not push and workflow_dispatch")
    push = on.get("push") or {}
    if not isinstance(push, dict) or set(push) != {"tags"} or push.get("tags") != ["kit-*"]:
        problems.append(f"push is {push!r}, not tags: ['kit-*'] alone")
    if "pull_request_target" in text:
        problems.append("pull_request_target appears in the workflow")
    if doc.get("permissions") != {}:
        problems.append(f"top-level permissions are {doc.get('permissions')!r}, not {{}}")
    env = doc.get("env") or {}
    if not re.fullmatch(r"1\.[0-9]+\.[0-9]+", str(env.get("KIT_GO_VERSION", ""))):
        problems.append(f"KIT_GO_VERSION is {env.get('KIT_GO_VERSION')!r}, not an exact Go version")
    jobs = doc.get("jobs") or {}
    want_jobs = {"stage", "test", "build", "attest", "publish", "verify", "verify-candidate"}
    if set(jobs) != want_jobs:
        problems.append(f"jobs are {sorted(jobs)}, not {sorted(want_jobs)}")
    workflow_shell = default_shell(doc, "the workflow")
    for name, job in jobs.items():
        if not isinstance(job, dict):
            problems.append(f"job {name} is not a mapping")
            continue
        perms = job.get("permissions")
        if not isinstance(perms, dict) or not perms:
            problems.append(f"job {name} declares no permissions block")
            perms = {}
        writes = sorted(k for k, v in perms.items() if v == "write")
        if any(v not in ("read", "write", "none") for v in perms.values()):
            problems.append(f"job {name} has a permission that is not read, write or none")
        if len(writes) > 1 and name != "attest":
            problems.append(f"job {name} holds {len(writes)} write scopes: {writes}")
        if name in ("stage", "test", "build", "verify", "verify-candidate"):
            if writes or not set(perms) <= READ_SCOPES or perms.get("contents") != "read":
                problems.append(f"job {name} holds {perms!r}, not read scopes only")
        if name == "attest" and perms != {"id-token": "write", "attestations": "write", "contents": "read"}:
            problems.append(f"job attest holds {perms!r}, not id-token: write, attestations: write, contents: read")
        if name == "publish" and perms != {"contents": "write"}:
            problems.append(f"job publish holds {perms!r}, not contents: write alone")
        job_shell = default_shell(job, f"job {name}")
        for step in steps_of(job):
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/checkout@"):
                w = step.get("with") or {}
                if str(w.get("persist-credentials")).lower() != "false":
                    problems.append(f"job {name}: a checkout without persist-credentials: false")
                if "ref" in w:
                    problems.append(f"job {name}: a checkout with ref:")
            run = step.get("run")
            if isinstance(run, str) and "${{" in run:
                problems.append(f"job {name}: an expression inside a run: block ({step.get('name', 'unnamed')})")
            # The step's own shell:, else its job's defaults: run: shell:, else the workflow's.
            shell = next((s for s in (step.get("shell"), job_shell, workflow_shell) if s is not None), None)
            if shell == "cmd" and isinstance(run, str):
                for line in run.split("\n"):
                    if re.search(r"%[^%\s]+%>", line):
                        problems.append(f"job {name}: a %...% expansion directly before > in a cmd step"
                                        f" ({step.get('name', 'unnamed')}); cmd expands the variable before it"
                                        " reads redirections, so a one-digit value such as the exit code 0 is"
                                        " read as a handle number and the file gets nothing")
            if name == "publish" and uses and not uses.startswith("actions/download-artifact@"):
                problems.append(f"job publish uses {uses}; it runs gh on the runner and downloads its files, nothing else")
    publish_runs = "\n".join(str(s.get("run", "")) for s in steps_of(jobs.get("publish") or {}))
    order = [publish_runs.find(p) for p in ("gh release create", "gh release upload", "gh release edit")]
    if -1 in order or order != sorted(order):
        problems.append("publish does not run gh release create, upload, then edit, in that order")
    create = re.search(r"gh release create[^\n]*", publish_runs)
    edit = re.search(r"gh release edit[^\n]*", publish_runs)
    if not create or "--draft" not in create.group() or "--latest=false" not in create.group():
        problems.append("gh release create is not --draft with --latest=false")
    if not edit or "--draft=false" not in edit.group() or "--latest=false" not in edit.group():
        problems.append("gh release edit is not --draft=false with --latest=false")
    stage_runs = [str(s.get("run", "")) for s in steps_of(jobs.get("stage") or {})]
    compile_at = next((i for i, r in enumerate(stage_runs) if "assemble.sh stage" in r), None)
    if compile_at is None:
        problems.append("the stage job does not compile with assemble.sh stage")
    for r in stage_runs:
        if re.search(r"README-START-HERE|CONTACT\.txt|release-notes|assemble\.sh kit", r):
            problems.append("the stage job writes a generated text file")
    for p in problems:
        print(f"release workflow: {p}", file=sys.stderr)
    print(f"release workflow: {path.name}: {len(jobs)} jobs, {len(problems)} problems")
    return 1 if problems else 0


# -h or --help prints USAGE on stdout. An option this script does not take, or
# a first argument that names no command, is named on stderr above USAGE, and
# main returns 2 before it reads a workflow.
USAGE = """\
usage: check_workflow.py pins <workflow.yml> [--job <job-id>]
       check_workflow.py release <kit-release.yml>
       check_workflow.py -h | --help
"""
COMMANDS = ("pins", "release")
OPTIONS = {"--job": 1}  # each option this script takes, and how many values follow it


def is_option(arg: str) -> bool:
    return arg.startswith("-") and arg != "-"


def read_options(argv: list[str]) -> tuple[bool, list[str]]:
    """Whether -h or --help is given, and the arguments this script does not know."""
    unknown = [argv[0]] if argv and argv[0] and argv[0] not in COMMANDS and not is_option(argv[0]) else []
    wants_help, values = False, 0
    for arg in argv:
        if values:
            values -= 1
        elif arg in ("-h", "--help"):
            wants_help = True
        elif arg in OPTIONS:
            values = OPTIONS[arg]
        elif is_option(arg):
            unknown.append(arg)
    return wants_help, unknown


def main(argv: list[str]) -> int:
    wants_help, unknown = read_options(argv)
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(USAGE, end="", file=sys.stderr)
        return 2
    if wants_help:
        print(USAGE, end="")
        return 0
    try:
        if len(argv) in (2, 4) and argv[0] == "pins":
            job = argv[3] if len(argv) == 4 and argv[2] == "--job" else None
            if len(argv) == 4 and job is None:
                raise SystemExit(__doc__)
            return cmd_pins(Path(argv[1]), job)
        if len(argv) == 2 and argv[0] == "release":
            return cmd_release(Path(argv[1]))
    except Unreadable as e:
        print(f"check_workflow: cannot read the workflow: {e}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
