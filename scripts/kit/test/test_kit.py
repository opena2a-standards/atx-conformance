#!/usr/bin/env python3
"""The interop day kit's checks, each run on the real input (it must pass)
and on a scratch input that violates it (it must refuse). A violating input
is always a scratch file or a test double; no script is edited to make a
check fail.

  test_kit.py --ci
      Cells that need no network and no gh: the action pins, the release
      workflow's shape, the one-line refusal of a workflow path the checks
      cannot read, SHA256SUMS and the file-list check, the label census,
      the data protection kit check, the first-run screen's form, the
      release notes' --version claim, check-capture as the release
      workflow's test job runs it: the kit's own copy, unpacked outside any
      repository, with no Python to call, and the version line under each
      Go version tag view, with tags made only in a scratch clone.
  test_kit.py --sandboxed
      Cells that run the scripts naming gh (candidate_equal.sh,
      verify_release.sh, write_stick.sh) with test doubles for gh, git and
      diskutil, inside sandbox-exec with the network denied (macOS only).
      Before any cell: HARNESS_NO_LIVE_TRANSPORT=1 is set for every command,
      each double resolves first in bash, and a listener on 127.0.0.1 is
      reachable outside the sandbox and refused inside it; a guard that does
      not hold stops the run.
  test_kit.py --slow
      Two full assemblies of HEAD, from two clones with their own Go and pip
      caches, must write byte-equal SHA256SUMS (network: Go modules and the
      pinned wheels).

Prints one line per cell and exits 1 if any cell fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

KIT = Path(__file__).resolve().parent.parent
REPO = KIT.parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "kit-release.yml"
CONFORMANCE = REPO / ".github" / "workflows" / "conformance.yml"
PY = sys.executable
RESULTS: list[tuple[str, bool, str]] = []
SCRATCH = Path(tempfile.mkdtemp(prefix="kit-test-"))
SANDBOX_ENV: dict[str, str] | None = None
SANDBOX_PROFILE = ""


def cell(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def run(cmd, cwd=None, env=None, sandboxed=False):
    if sandboxed:
        cmd = ["/usr/bin/sandbox-exec", "-p", SANDBOX_PROFILE] + list(cmd)
        env = dict(env or SANDBOX_ENV)
    full_env = dict(env if env is not None else os.environ)
    full_env["PYTHONDONTWRITEBYTECODE"] = "1"
    full_env["HARNESS_NO_LIVE_TRANSPORT"] = "1"
    return subprocess.run([str(c) for c in cmd], cwd=cwd, env=full_env, capture_output=True, text=True)


def scratch(name: str) -> Path:
    p = SCRATCH / name
    p.mkdir(parents=True)
    return p


def git(*args) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, check=True).stdout.strip()


def tree_into(dest: Path, *paths: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar", "HEAD", *paths],
                             capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive, check=True)


def head_facts() -> dict:
    sha = git("rev-parse", "HEAD")
    n = len(list((REPO / "fixtures").glob("*.json")))
    targets = ["darwin/arm64", "darwin/amd64", "linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64"]
    expected = f"summary: {n} pass, 0 fail ({n} fixtures)"
    commit_time = int(git("show", "-s", "--format=%ct", "HEAD"))
    # The version Go stamps for HEAD with no Go version tag; the cells that
    # take another tag view set their own.
    version = f"v0.0.0-{time.strftime('%Y%m%d%H%M%S', time.gmtime(commit_time))}-{sha[:12]}"
    return {"sha": sha, "tag": "kit-2026-11-05", "repo": "opena2a-standards/atx-conformance",
            "workflow": ".github/workflows/kit-release.yml", "n": n, "expected": expected,
            "pythonExpected": expected, "commitTime": commit_time, "version": version,
            "f5": False, "targets": targets, "tested": targets, "notTested": []}


def scratch_kit(dest_parent: Path, facts: dict | None = None, bins: bool = False) -> Path:
    """A small kit: the tree at HEAD and the texts the build writes (no wheels;
    with bins, one stand-in file per binary path)."""
    kit = dest_parent / "interop-day-kit"
    tree_into(kit)
    dist = dest_parent / "dist"
    dist.mkdir()
    facts_path = dest_parent / "facts.json"
    facts_path.write_text(json.dumps(facts or head_facts()))
    r = run([PY, "-I", KIT / "render.py", "texts", facts_path, KIT / "templates", kit, dist])
    if r.returncode != 0:
        raise SystemExit(f"render failed: {r.stderr}")
    if bins:
        for t in ("linux-amd64", "darwin-arm64"):
            b = kit / "bin" / t / "atx-verify"
            b.parent.mkdir(parents=True)
            b.write_text(f"stand-in for the {t} binary\n")
            b.chmod(0o755)
    return kit


def sums_for(kit: Path, out: Path) -> None:
    r = run([PY, "-I", KIT / "kit_files.py", "sums", kit])
    if r.returncode != 0:
        raise SystemExit(f"sums failed: {r.stderr}")
    out.write_text(r.stdout)


def sha256sum_check(kit: Path, sums: Path):
    tool = ["sha256sum"] if shutil.which("sha256sum") else ["shasum", "-a", "256"]
    return run(tool + ["-c", sums], cwd=kit)


def kit_check(kit: Path, env=None, sandboxed=False) -> list[str]:
    r = run(["bash", KIT / "kit-check.sh", kit], env=env, sandboxed=sandboxed)
    return [line.rsplit(": ", 1)[-1] for line in r.stdout.strip().split("\n")]


# ---------------------------------------------------------------- --ci cells

def cells_pins() -> None:
    r = run([PY, "-I", KIT / "check_workflow.py", "pins", WORKFLOW])
    m = re.search(r"(\d+) uses: lines, (\d+) pinned by commit, (\d+) unpinned", r.stdout)
    cell("a1 kit-release.yml: every uses: line pinned by a 40-hex commit",
         r.returncode == 0 and m is not None and m.group(1) == m.group(2) and m.group(3) == "0",
         m.group(0) if m else r.stderr.strip())
    r = run([PY, "-I", KIT / "check_workflow.py", "pins", CONFORMANCE, "--job", "sign-manifest"])
    m = re.search(r"(\d+) uses: lines, (\d+) pinned by commit, (\d+) unpinned", r.stdout)
    cell("a2 conformance.yml sign-manifest: every uses: line pinned by a 40-hex commit",
         r.returncode == 0 and m is not None and m.group(1) == m.group(2) == "3" and m.group(3) == "0",
         m.group(0) if m else r.stderr.strip())
    d = scratch("a3")
    text = WORKFLOW.read_text()
    first = re.search(r"uses: (actions/[a-z-]+)@[0-9a-f]{40}[^\n]*", text)
    mutant = text.replace(first.group(0), f"uses: {first.group(1)}@v4", 1)
    (d / "kit-release.yml").write_text(mutant)
    r = run([PY, "-I", KIT / "check_workflow.py", "pins", d / "kit-release.yml"])
    cell("a3 control: a scratch copy with one @v4 line reads 1 unpinned and refuses",
         r.returncode == 1 and " 1 unpinned" in r.stdout, r.stdout.strip())


# Edits to the test job's Windows step and to where it takes its shell from. An
# entry below that lists several edits applies them in order (see edited()).
STEP_ECHO_BEFORE_GT = ("          >..\\capture.rc echo %ERRORLEVEL%\n", "          echo %ERRORLEVEL%> ..\\capture.rc\n")
WINDOWS_IF = "        if: runner.os == 'Windows'\n"
STEP_NO_SHELL = (WINDOWS_IF + "        shell: cmd\n", WINDOWS_IF)
STEP_BASH = (WINDOWS_IF + "        shell: cmd\n", WINDOWS_IF + "        shell: bash\n")
TEST_JOB = "    needs: stage\n    runs-on: ${{ matrix.runner }}\n"
JOB_CMD = (TEST_JOB, TEST_JOB + "    defaults:\n      run:\n        shell: cmd\n")
JOB_BASH = (TEST_JOB, TEST_JOB + "    defaults:\n      run:\n        shell: bash\n")
WORKFLOW_CMD = ("permissions: {}\n", "permissions: {}\ndefaults:\n  run:\n    shell: cmd\n")
# A custom shell: template whose first word is cmd, and one whose first word is pwsh.
CMD_TEMPLATE = 'cmd /D /E:ON /V:OFF /S /C "CALL "{0}""'
PWSH_TEMPLATE = "pwsh -command \". '{0}'\""
STEP_CMD_TEMPLATE = (WINDOWS_IF + "        shell: cmd\n", WINDOWS_IF + "        shell: " + CMD_TEMPLATE + "\n")
STEP_PWSH_TEMPLATE = (WINDOWS_IF + "        shell: cmd\n", WINDOWS_IF + "        shell: " + PWSH_TEMPLATE + "\n")
JOB_CMD_TEMPLATE = (TEST_JOB, TEST_JOB + "    defaults:\n      run:\n        shell: " + CMD_TEMPLATE + "\n")
WORKFLOW_CMD_TEMPLATE = ("permissions: {}\n", "permissions: {}\ndefaults:\n  run:\n    shell: " + CMD_TEMPLATE + "\n")
# Custom templates whose first word names cmd other than as the word cmd: with
# the .exe extension, in capitals, in mixed case, and by a full path. And one
# whose first word is pwsh.exe in a directory named cmd, which is not cmd.
CMD_EXE_TEMPLATE = 'cmd.exe /D /E:ON /V:OFF /S /C "CALL "{0}""'
CMD_CAPITALS_TEMPLATE = 'CMD /D /E:ON /V:OFF /S /C "CALL "{0}""'
CMD_MIXED_CASE_TEMPLATE = "Cmd.exe /C {0}"
CMD_PATH_TEMPLATE = 'C:\\Windows\\System32\\cmd.exe /D /S /C "CALL "{0}""'
PWSH_IN_CMD_DIRECTORY_TEMPLATE = "C:\\cmd\\pwsh.exe -command \". '{0}'\""


def step_shell(shell: str) -> tuple[str, str]:
    """The edit that sets shell: of the test job's Windows step to shell."""
    return (WINDOWS_IF + "        shell: cmd\n", WINDOWS_IF + "        shell: " + shell + "\n")


WORKFLOW_MUTANTS = [
    ("publish also holds id-token: write",
     ("    permissions:\n      contents: write\n", "    permissions:\n      contents: write\n      id-token: write\n"),
     "job publish holds"),
    ("build holds contents: write",
     ("    permissions:\n      contents: read\n      actions: read\n", "    permissions:\n      contents: write\n      actions: read\n"),
     "job build holds"),
    ("a checkout carries ref:",
     ("          persist-credentials: false\n          fetch-depth: 0\n",
      "          persist-credentials: false\n          fetch-depth: 0\n          ref: main\n"),
     "a checkout with ref:"),
    ("a checkout without persist-credentials: false",
     ("        with:\n          persist-credentials: false\n\n      - name: The checkout is the commit that started the run\n        run: test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"\n\n      - uses: actions/download-artifact",
      "        with:\n          fetch-depth: 1\n\n      - name: The checkout is the commit that started the run\n        run: test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"\n\n      - uses: actions/download-artifact"),
     "without persist-credentials"),
    ("a pull_request_target trigger",
     ("  workflow_dispatch:\n", "  pull_request_target:\n  workflow_dispatch:\n"),
     "pull_request_target"),
    ("an input expanded inside a run: block",
     ('            tag=$INPUT_TAG\n', '            tag=${{ inputs.tag }}\n'),
     "an expression inside a run: block"),
    ("a v* tag starts a kit build",
     ("    tags:\n      - 'kit-*'\n", "    tags:\n      - 'kit-*'\n      - 'v*'\n"),
     "not tags: ['kit-*'] alone"),
    ("the release is created without --latest=false",
     ("--draft --verify-tag --latest=false", "--draft --verify-tag"),
     "gh release create is not --draft with --latest=false"),
    ("the release is published before its assets are uploaded",
     ("          gh release upload \"$TAG\" interop-day-kit.tar.gz SHA256SUMS\n          gh release edit \"$TAG\" --draft=false --latest=false\n",
      "          gh release edit \"$TAG\" --draft=false --latest=false\n          gh release upload \"$TAG\" interop-day-kit.tar.gz SHA256SUMS\n"),
     "create, upload, then edit"),
    ("top-level permissions grant contents: read",
     ("permissions: {}\n", "permissions:\n  contents: read\n"),
     "top-level permissions"),
    ("attest without attestations: write",
     ("      id-token: write\n      attestations: write\n      contents: read\n", "      id-token: write\n      contents: read\n"),
     "job attest holds"),
    ("Go pinned to a minor version only",
     ("KIT_GO_VERSION: '1.27.3'", "KIT_GO_VERSION: '1.27'"),
     "not an exact Go version"),
    ("the stage job writes README-START-HERE.md",
     ("        run: bash scripts/kit/assemble.sh stage \"$RUNNER_TEMP/stage\"\n",
      "        run: bash scripts/kit/assemble.sh stage \"$RUNNER_TEMP/stage\" && touch README-START-HERE.md\n"),
     "writes a generated text file"),
    ("a cmd step writes %ERRORLEVEL% directly before >",
     STEP_ECHO_BEFORE_GT,
     "directly before > in a cmd step"),
    ("a step that sets no shell, under the job's defaults: run: shell: cmd, writes %ERRORLEVEL% directly before >",
     [JOB_CMD, STEP_NO_SHELL, STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets no shell, under the workflow's defaults: run: shell: cmd, writes %ERRORLEVEL% directly before >",
     [WORKFLOW_CMD, STEP_NO_SHELL, STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets shell: " + CMD_TEMPLATE + " writes %ERRORLEVEL% directly before >",
     [STEP_CMD_TEMPLATE, STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets no shell, under the job's defaults: run: shell: " + CMD_TEMPLATE
     + ", writes %ERRORLEVEL% directly before >",
     [JOB_CMD_TEMPLATE, STEP_NO_SHELL, STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets no shell, under the workflow's defaults: run: shell: " + CMD_TEMPLATE
     + ", writes %ERRORLEVEL% directly before >",
     [WORKFLOW_CMD_TEMPLATE, STEP_NO_SHELL, STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets shell: " + CMD_EXE_TEMPLATE + " writes %ERRORLEVEL% directly before >",
     [step_shell(CMD_EXE_TEMPLATE), STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets shell: " + CMD_CAPITALS_TEMPLATE + " writes %ERRORLEVEL% directly before >",
     [step_shell(CMD_CAPITALS_TEMPLATE), STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets shell: " + CMD_MIXED_CASE_TEMPLATE + " writes %ERRORLEVEL% directly before >",
     [step_shell(CMD_MIXED_CASE_TEMPLATE), STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
    ("a step that sets shell: " + CMD_PATH_TEMPLATE + " writes %ERRORLEVEL% directly before >",
     [step_shell(CMD_PATH_TEMPLATE), STEP_ECHO_BEFORE_GT],
     "directly before > in a cmd step"),
]

# Inputs the release check accepts: it reads a step's own shell: before its
# job's defaults: run: shell:, and the job's before the workflow's, and holds a
# step to the cmd rule only when the first word of that shell, less any
# directory part, is cmd or cmd.exe in any letter case, so it holds none of the
# Windows steps below to the cmd rule.
WORKFLOW_CONTROLS = [
    ("a step that sets shell: bash, under the job's defaults: run: shell: cmd, writes %ERRORLEVEL% directly before >",
     [JOB_CMD, STEP_BASH, STEP_ECHO_BEFORE_GT]),
    ("a step that sets no shell, in a job whose defaults: run: shell: bash is under the workflow's cmd,"
     " writes %ERRORLEVEL% directly before >",
     [WORKFLOW_CMD, JOB_BASH, STEP_NO_SHELL, STEP_ECHO_BEFORE_GT]),
    ("a step that sets shell: " + PWSH_TEMPLATE + " writes %ERRORLEVEL% directly before >",
     [STEP_PWSH_TEMPLATE, STEP_ECHO_BEFORE_GT]),
    ("a step that sets shell: " + PWSH_IN_CMD_DIRECTORY_TEMPLATE + " writes %ERRORLEVEL% directly before >",
     [step_shell(PWSH_IN_CMD_DIRECTORY_TEMPLATE), STEP_ECHO_BEFORE_GT]),
]


def edited(text: str, edits) -> str | None:
    """text with edits applied: one (old, new) pair at the first place its
    old text stands, or a list of pairs in turn, each at the one place its old
    text stands in the text it is applied to. None when an old text is not
    there, or, in a list, stands there more than once: an edit early in a list
    can add a second copy of a later edit's old text, as a defaults: block
    whose shell: line has the indentation of a step's does."""
    if not isinstance(edits, list):
        old, new = edits
        return text.replace(old, new, 1) if old in text else None
    for old, new in edits:
        if text.count(old) != 1:
            return None
        text = text.replace(old, new)
    return text


def cells_workflow() -> None:
    r = run([PY, "-I", KIT / "check_workflow.py", "release", WORKFLOW])
    cell("b1 kit-release.yml: triggers, scopes, checkouts, env-only inputs, draft-then-publish, compile-first",
         r.returncode == 0 and "0 problems" in r.stdout, (r.stdout + r.stderr).strip().split("\n")[-1])
    text = WORKFLOW.read_text()
    for i, (what, edits, expect) in enumerate(WORKFLOW_MUTANTS, 2):
        d = scratch(f"b{i}")
        mutant = edited(text, edits)
        if mutant is None:
            cell(f"b{i} mutant input: {what}", False,
                 "an anchor of the mutant is not in the workflow, or, in a list of edits, not once")
            continue
        (d / "kit-release.yml").write_text(mutant)
        r = run([PY, "-I", KIT / "check_workflow.py", "release", d / "kit-release.yml"])
        cell(f"b{i} mutant input refused: {what}", r.returncode == 1 and expect in r.stderr,
             next((l for l in r.stderr.split("\n") if expect in l), r.stderr.strip()[:120]))
    for i, (what, edits) in enumerate(WORKFLOW_CONTROLS, len(WORKFLOW_MUTANTS) + 2):
        d = scratch(f"b{i}")
        control = edited(text, edits)
        if control is None:
            cell(f"b{i} control input: {what}", False,
                 "an anchor of the control is not in the workflow, or, in a list of edits, not once")
            continue
        (d / "kit-release.yml").write_text(control)
        r = run([PY, "-I", KIT / "check_workflow.py", "release", d / "kit-release.yml"])
        cell(f"b{i} control input accepted: {what}", r.returncode == 0 and "0 problems" in r.stdout,
             (r.stdout + r.stderr).strip().split("\n")[-1])


def cells_unreadable_path() -> None:
    """A workflow path the checks cannot read is refused in one stderr line,
    `check_workflow: cannot read the workflow: '<path>': <reason>`, with exit
    1 and nothing on stdout. Each path is given to both commands."""
    d = scratch("k")
    missing = d / "no-such-file.yml"
    folder = d / "a-folder.yml"
    folder.mkdir()
    latin1 = d / "latin-1.yml"
    latin1.write_bytes(b"name: caf\xe9\n")
    cases = [
        (["release", missing], "a path that does not exist"),
        (["pins", missing], "a path that does not exist"),
        (["pins", missing, "--job", "sign-manifest"], "a path that does not exist"),
        (["release", folder], "a directory"),
        (["pins", folder], "a directory"),
        (["release", latin1], "a file that is not UTF-8"),
        (["pins", latin1], "a file that is not UTF-8"),
    ]
    for i, (args, what) in enumerate(cases, 1):
        r = run([PY, "-I", KIT / "check_workflow.py", *args])
        lines = r.stderr.splitlines()
        want = f"check_workflow: cannot read the workflow: {str(args[1])!r}: "
        ok = (r.returncode == 1 and r.stdout == "" and len(lines) == 1
              and lines[0].startswith(want) and len(lines[0]) > len(want))
        command = " ".join([args[0], *map(str, args[2:])])
        cell(f"k{i} {command} on {what}: refused in one stderr line, exit 1", ok,
             f"exit {r.returncode}, {len(lines)} stderr line(s), last: "
             + (lines[-1].replace(str(d), "<scratch>")[:160] if lines else "none"))


def cells_sums() -> None:
    d = scratch("c")
    kit = d / "interop-day-kit"
    tree_into(kit, "fixtures", "vectors", "README.md")
    sums = d / "SHA256SUMS"
    sums_for(kit, sums)
    lines = len(sums.read_text().splitlines())
    r = sha256sum_check(kit, sums)
    cell("c1 SHA256SUMS: sha256sum -c exits 0 on the folder it was written for",
         r.returncode == 0 and r.stdout.count(": OK") == lines, f"{r.stdout.count(': OK')} of {lines} OK")
    r = run([PY, "-I", KIT / "kit_files.py", "listcheck", kit, sums])
    cell("c2 file list: equal to SHA256SUMS on that folder", r.returncode == 0, r.stdout.strip())
    target = kit / "README.md"
    original = target.read_bytes()
    target.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    r = sha256sum_check(kit, sums)
    cell("c3 one byte changed: sha256sum -c exits non-zero", r.returncode != 0, f"exit {r.returncode}")
    target.write_bytes(original)
    (kit / "unlisted.txt").write_text("a file SHA256SUMS does not name\n")
    r = sha256sum_check(kit, sums)
    r2 = run([PY, "-I", KIT / "kit_files.py", "listcheck", kit, sums])
    cell("c4 an unlisted file: sha256sum -c still exits 0, the file-list check refuses",
         r.returncode == 0 and r2.returncode == 1 and "unlisted.txt" in r2.stderr,
         f"sha256sum -c exit {r.returncode}; file list exit {r2.returncode}")


def cells_census() -> None:
    d = scratch("d1")
    tree_into(d, "vectors")
    r = run([PY, "-I", KIT / "label_census.py", d])
    cell("d1 label census: the vectors/ files at HEAD read 6 seed-bearing, 6 labelled",
         r.returncode == 0 and "6 seed-bearing, 6 labelled" in r.stdout, r.stdout.strip().split("\n")[-1])
    d = scratch("d2")
    tree_into(d, "vectors")
    doc = json.loads((d / "vectors" / "issuer-primary.json").read_text())
    doc["$comment"] = "Primary issuer keypair."
    (d / "vectors" / "issuer-primary.json").write_text(json.dumps(doc))
    r = run([PY, "-I", KIT / "label_census.py", d])
    cell("d2 a seed-bearing JSON file with no test label refuses",
         r.returncode == 1 and "issuer-primary.json" in r.stderr, r.stderr.strip().split("\n")[0][:120])
    d = scratch("d3")
    r = run([PY, "-I", KIT / "label_census.py", d])
    cell("d3 an empty folder refuses (0 seed-bearing files)", r.returncode == 1 and "0 seed-bearing" in r.stderr,
         r.stderr.strip()[:120])
    d = scratch("d4")
    tree_into(d, "vectors", "fixtures/baseline-valid.json")
    fx = json.loads((d / "fixtures" / "baseline-valid.json").read_text())
    fx["$comment"] = "TEST-ONLY"
    fx["verifierState"]["publicKeys"][0]["seedHex"] = hashlib.sha256(b"kit test seed").hexdigest()
    (d / "fixtures" / "baseline-valid.json").write_text(json.dumps(fx))
    r = run([PY, "-I", KIT / "label_census.py", d])
    cell("d4 a fixture holding a seed refuses, labelled or not",
         r.returncode == 1 and "a fixture holds a private seed" in r.stderr, r.stderr.strip()[:120])


def cells_kit_check() -> None:
    d = scratch("e1")
    kit = scratch_kit(d)
    got = kit_check(kit)
    cell("e1 data protection kit check on a scratch assembly prints 1 1 1 1", got == ["1", "1", "1", "1"],
         " ".join(got))
    home = os.environ.get("HOME", "")
    mutants = [
        ("an OS metadata file", 0, lambda k: (k / ".DS_Store").write_bytes(b"\0")),
        ("a file holding the builder's home path", 1, lambda k: (k / "notes.txt").write_text(f"built in {home}\n")),
        ("an address outside the contact and example domains", 2,
         lambda k: (k / "notes.txt").write_text("mutant" + chr(64) + "kit-check-mutant.org\n")),
        ("a link with a query in CONTACT.txt", 3,
         lambda k: (k / "CONTACT.txt").open("a").write("https://github.com/opena2a-standards/x?" + "q=1\n")),
    ]
    for i, (what, line, apply) in enumerate(mutants, 2):
        if line == 1 and len(home) < 2:
            cell(f"e{i} mutant input: {what}", False, "HOME is not set")
            continue
        dm = scratch(f"e{i}")
        km = scratch_kit(dm)
        apply(km)
        got = kit_check(km)
        cell(f"e{i} mutant input: {what}: line {line + 1} reads 2", got[line] == "2" and got.count("1") == 3,
             " ".join(got))
    # e6 and e7: the address shapes the binaries of a real kit carried, built at run time so that no
    # file of the repository, and so no kit, carries them: the contact address running into the next
    # string, as compiled string data lies end to end, and six bytes of compressed debug data that
    # match the address pattern. A real kit's binaries hold a NUL byte; e6 puts the shapes in such a
    # file at the kit root, not under bin/, so line 3 passes only by skipping files by what they are.
    shapes = (b"\n" + ("info" + chr(64) + "opena2a.org.These").encode("ascii") + b"\n"
              + bytes.fromhex("2e40562e4d67") + b"\n")
    d6 = scratch("e6")
    k6 = scratch_kit(d6)
    (k6 / "noise.bin").write_bytes(b"\0" * 8 + shapes + b"\0" * 8)
    got = kit_check(k6)
    cell("e6 a file with a NUL byte holding a real kit's address shapes: the kit check prints 1 1 1 1",
         got == ["1", "1", "1", "1"], " ".join(got))
    d7 = scratch("e7")
    k7 = scratch_kit(d7)
    (k7 / "noise.txt").write_bytes(shapes)
    got = kit_check(k7)
    cell("e7 control: the same shapes in a text file: line 3 reads 3", got[2] == "3" and got.count("1") == 3,
         " ".join(got))


def readme_text() -> tuple[str, str]:
    d = scratch("h0")
    kit = scratch_kit(d)
    return (kit / "README-START-HERE.md").read_text(), head_facts()["expected"]


def cells_readme() -> None:
    text, expected = readme_text()
    d = scratch("h")
    good = d / "README-START-HERE.md"
    good.write_text(text)
    r = run([PY, "-I", KIT / "render.py", "check-readme", good, expected])
    lines = text.split("\n")[:-1]
    cell("h1 first-run screen: in its form as rendered", r.returncode == 0,
         f"{len(lines)} lines, longest {max(map(len, lines))}")
    anchors = [n for n, l in enumerate(lines, 1) if re.search(
        r"^This kit carries|^Running a verifier|^Check before you run|^Run the fixtures|Expected last line|"
        r"^Every private key|^A credential of your own|^To check a credential", l)]
    cell("h2 first-run screen: 8 anchors in order, every one within line 30",
         len(anchors) == 8 and max(anchors) <= 30, ",".join(map(str, anchors)))
    f5 = dict(head_facts(), f5=True)
    d5 = scratch("h3")
    k5 = scratch_kit(d5, facts=f5)
    r = run([PY, "-I", KIT / "render.py", "check-readme", k5 / "README-START-HERE.md", expected])
    t5 = (k5 / "README-START-HERE.md").read_text()
    cell("h3 first-run screen with the terminal-safety lines: in its form", r.returncode == 0 and "cat -v" in t5,
         f"{len(t5.splitlines())} lines")
    mutants = [
        ("a 46th line", lambda t: t + "one line too many\n", "more than 45"),
        ("an 81-column line", lambda t: t.replace("In this folder:", "In this folder:" + " " * 66 + "x", 1), "more than 80"),
        ("a byte outside printable ASCII", lambda t: t.replace("Run the fixtures", "Run the fixtures ", 1), "outside printable ASCII"),
        ("a line starting with #", lambda t: t.replace("In this folder:", "# In this folder:", 1), "starts with"),
        ("a four-space line after a blank line", lambda t: t.replace("\nIn this folder:", "\n\n    In this folder:", 1), "indented four spaces"),
        ("two anchors out of order", lambda t: t.replace("Every private key", "XEvery private key", 1)
         .replace("Run the fixtures, one", "Every private key; Run the fixtures, one", 1), "anchor"),
        ("the expected last line not as captured", lambda t: t.replace(expected, expected.replace(" 0 fail", " 1 fail"), 1),
         "captured line"),
        ("the install line on the first screen", lambda t: t.replace("README.md and docs/fixtures.md.",
                                                                     "pip install -r verifiers/python/requirements.lock", 1), "pip line"),
    ]
    for i, (what, change, expect) in enumerate(mutants, 4):
        m = d / f"mutant-{i}.md"
        m.write_text(change(text))
        r = run([PY, "-I", KIT / "render.py", "check-readme", m, expected])
        cell(f"h{i} first-run screen mutant refused: {what}", r.returncode == 1 and expect in r.stderr,
             next((l.strip() for l in r.stderr.split("\n") if expect in l), r.stderr.strip()[:100]))

    # render.py writes the release notes, which carry the Mac step (cell i4),
    # to its dist folder, not into the kit, so the kit's own screen says where
    # the step is. In both renderings: one line names the Mac step, after the
    # check paragraph's gh attestation line and before "Run the fixtures", and
    # says it is in the release notes on the release page; the notes rendered
    # for HEAD carry the step's command and call it the Mac step.
    step = "xattr -d com.apple.quarantine verify bin/darwin-arm64/atx-verify bin/darwin-amd64/atx-verify"
    notes = (d5 / "dist" / "release-notes.md").read_text().replace("\n", " ")
    places = []
    for rendering in (text, t5):
        ls = rendering.split("\n")[:-1]
        mac = [n for n, l in enumerate(ls, 1) if "Mac step" in l]
        check = [n for n, l in enumerate(ls, 1) if l.startswith("gh attestation verify ")]
        run_at = [n for n, l in enumerate(ls, 1) if l.startswith("Run the fixtures")]
        placed = (len(mac) == 1 and len(check) == 1 and len(run_at) == 1 and check[0] < mac[0] < run_at[0]
                  and "the release notes on that page" in ls[mac[0] - 1])
        places.append((placed, mac, check, run_at))
    in_notes = step in notes and "the Mac step" in notes
    cell(f"h{len(mutants) + 4} first-run screen: one line after the check paragraph, before Run the fixtures, "
         "names the Mac step and the release notes on that page, with and without the terminal-safety lines; "
         "the notes carry the step",
         all(p[0] for p in places) and in_notes,
         "; ".join(f"{label}: Mac step line(s) {mac}, gh attestation line {check}, Run the fixtures {run_at}"
                   for label, (_, mac, check, run_at) in zip(("without", "with"), places))
         + f"; the notes carry the step's command and its name: {in_notes}")


def cells_claims() -> None:
    d = scratch("i")
    sha = "0123456789abcdef0123456789abcdef01234567"
    notes = d / "release-notes.md"
    notes.write_text(f"`atx-verify --version` prints `v0.0.0-20261029200411-{sha[:12]}`.\n")
    devel = d / "linux-amd64.version"
    devel.write_text(f"atx-verify: github.com/opena2a-standards/atx-conformance (devel), commit {sha}, built with go1.27.3\n")
    pseudo = d / "linux-arm64.version"
    pseudo.write_text(f"atx-verify: github.com/opena2a-standards/atx-conformance v0.0.0-20261029200411-{sha[:12]}, built with go1.27.3\n")
    r = run([PY, "-I", KIT / "render.py", "check-claims", notes, pseudo])
    cell("i1 notes' --version claim matching what the binary prints passes", r.returncode == 0, r.stdout.strip())
    r = run([PY, "-I", KIT / "render.py", "check-claims", notes, devel])
    cell("i2 notes naming a pseudo-version a (devel) binary does not print refuse", r.returncode == 1,
         r.stderr.strip().split("\n")[0])

    # The notes as render.py writes them for HEAD, against the line a binary
    # built at HEAD prints: check-capture must take that line (it compares the
    # whole --version line with the line stage writes into the kit,
    # bin/version-line.txt, here the one for HEAD with no Go version tag),
    # check-claims must pass on the version file check-capture writes, and it
    # must refuse a (devel) line.
    d = scratch("i3")
    facts = head_facts()
    kit = scratch_kit(d, facts)
    notes = d / "dist" / "release-notes.md"
    module = re.search(r"^module (\S+)$", (kit / "go.mod").read_text(), re.M).group(1)
    pseudo = f"v0.0.0-{time.strftime('%Y%m%d%H%M%S', time.gmtime(facts['commitTime']))}-{facts['sha'][:12]}"
    stand_in = kit / "bin" / "linux-amd64" / "atx-verify"
    stand_in.parent.mkdir(parents=True)
    stand_in.write_text(f"#!/bin/sh\nprintf '%s\\n' 'atx-verify: {module} {pseudo}, built with go1.27.3'\n")
    stand_in.chmod(0o755)
    (kit / "bin" / "version-line.txt").write_text(f"atx-verify: {module} {pseudo}, built with go1.27.3\n")
    (d / "capture.txt").write_text(facts["expected"] + "\n")
    (d / "capture.rc").write_text("0\n")
    taken = run(["bash", KIT / "assemble.sh", "check-capture", kit, d / "capture.txt", d / "capture.rc",
                 "linux-amd64", d / "captures"],
                env=dict(os.environ, KIT_COMMIT=facts["sha"], KIT_GO_VERSION="1.27.3"))
    taken_line = d / "captures" / "linux-amd64.version"
    devel = d / "devel" / "linux-amd64.version"
    devel.parent.mkdir()
    devel.write_text(f"atx-verify: {module} (devel), commit {facts['sha']}, built with go1.27.3\n")
    passed = run([PY, "-I", KIT / "render.py", "check-claims", notes, taken_line]) if taken_line.exists() else None
    refused = run([PY, "-I", KIT / "render.py", "check-claims", notes, devel])
    last = (taken.stdout + taken.stderr).strip().split("\n")[-1][:160]
    cell("i3 notes rendered for HEAD: the line check-capture takes passes check-claims; a (devel) line refuses",
         taken.returncode == 0 and pseudo in notes.read_text() and passed is not None and passed.returncode == 0
         and refused.returncode == 1 and "do not print" in refused.stderr,
         f"check-capture exit {taken.returncode} ({last}); check-claims exit "
         f"{passed.returncode if passed else 'not run'}, on the (devel) line exit {refused.returncode}")

    # The Mac step in the notes as render.py writes them for HEAD, line feeds
    # read as spaces: the command that names the three files that run stands
    # after the check and before the paragraph on notarization, the dialog's
    # Done follows it, and neither `xattr -dr` nor "turn off a protection"
    # occurs.
    d = scratch("i4")
    scratch_kit(d)
    text = (d / "dist" / "release-notes.md").read_text().replace("\n", " ")
    step = "xattr -d com.apple.quarantine verify bin/darwin-arm64/atx-verify bin/darwin-amd64/atx-verify"
    at, check, notarized = (text.find(s) for s in (step, "Check before you run", "The binaries are not notarized"))
    done = at >= 0 and "click Done, never Move to Trash" in text[at + len(step):]
    recursive, untrue = "xattr -dr" in text, "turn off a protection" in text
    cell("i4 notes rendered for HEAD: the Mac step names its three files, after the check and before the "
         "notarization paragraph, Done after it; no xattr -dr, no 'turn off a protection'",
         0 <= check < at < notarized and done and not recursive and not untrue,
         f"step at {at}, check at {check}, notarization paragraph at {notarized}, Done after the step {done}, "
         f"xattr -dr {'present' if recursive else 'absent'}, "
         f"'turn off a protection' {'present' if untrue else 'absent'}")


def cells_capture_in_the_unpacked_kit() -> None:
    """check-capture as the release workflow's test job runs it: the kit's own
    copy of assemble.sh (git archive HEAD, unpacked in a scratch folder outside
    any repository), never the repository's, with KIT_PYTHON naming a file that
    does not exist, so any Python call fails the cell. The copy holds the line
    stage writes for HEAD with no Go version tag, bin/version-line.txt."""
    parent = scratch("j")
    copy = parent / "interop-day-kit"
    tree_into(copy)
    sha = git("rev-parse", "HEAD")
    commit_time = int(git("show", "-s", "--format=%ct", "HEAD"))
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(commit_time))
    go_version = "1.27.3"
    module = re.search(r"^module (\S+)$", (copy / "go.mod").read_text(), re.M).group(1)
    n = len(list((copy / "fixtures").glob("*.json")))
    (parent / "capture.txt").write_text(f"summary: {n} pass, 0 fail ({n} fixtures)\n")
    (parent / "capture.rc").write_text("0\n")
    no_python = parent / "no-python" / "python3"
    env = {"KIT_COMMIT": sha, "KIT_GO_VERSION": go_version, "PATH": os.environ.get("PATH", ""),
           "HOME": os.environ.get("HOME", ""), "KIT_PYTHON": str(no_python)}
    stand_in = copy / "bin" / "linux-amd64" / "atx-verify"
    stand_in.parent.mkdir(parents=True)

    def line(t: str = stamp, sha12: str = sha[:12], go: str = go_version) -> str:
        return f"atx-verify: {module} v0.0.0-{t}-{sha12}, built with go{go}"

    (copy / "bin" / "version-line.txt").write_text(line() + "\n")

    def check_capture(printed: str, out: str):
        # The precondition witness first: git finds no repository from the
        # copy's scripts/kit, and KIT_PYTHON names nothing. A witness that does
        # not hold fails the cell; it is never a skip.
        witness = run(["git", "-C", copy / "scripts" / "kit", "rev-parse", "--git-dir"], env=env)
        stand_in.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(printed)}\n")
        stand_in.chmod(0o755)
        r = run(["bash", "interop-day-kit/scripts/kit/assemble.sh", "check-capture", "interop-day-kit",
                 "capture.txt", "capture.rc", "linux-amd64", out], cwd=parent, env=env)
        detail = (f"git rev-parse --git-dir exit {witness.returncode}; check-capture exit {r.returncode}: "
                  + (r.stdout + r.stderr).strip().split("\n")[-1][:160])
        return witness.returncode != 0 and not no_python.exists(), r, detail

    held, r, detail = check_capture(line(), "out-head")
    wrote = [parent / "out-head" / f"linux-amd64{ext}" for ext in (".txt", ".version", ".sha256")]
    cell("j1 the kit's own check-capture, unpacked outside any repository, with no Python: "
         "the line for HEAD passes and linux-amd64.version holds it",
         held and r.returncode == 0 and all(p.exists() for p in wrote)
         and wrote[0].read_text() == (parent / "capture.txt").read_text()
         and wrote[1].read_text() == line() + "\n"
         and wrote[2].read_text().strip() == hashlib.sha256(stand_in.read_bytes()).hexdigest(),
         detail)

    parent_commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--verify", "-q", "HEAD^"],
                                   capture_output=True, text=True).stdout.strip()
    refusals = [
        ("a +dirty build", f"atx-verify: {module} v0.0.0-{stamp}-{sha[:12]}+dirty, built with go{go_version}"),
        ("a (devel), commit <sha> line", f"atx-verify: {module} (devel), commit {sha}, built with go{go_version}"),
        ("another commit's 12 hex (HEAD's parent)", line(sha12=parent_commit[:12]) if parent_commit else None),
        ("HEAD's 12 hex with the twelfth changed", line(sha12=sha[:11] + ("1" if sha[11] == "0" else "0"))),
        ("another Go version (go1.27.2)", line(go="1.27.2")),
        ("a 13-digit time", line(t=stamp[:13])),
        ("a 15-digit time", line(t=stamp + "0")),
        ("text before the line", "x" + line()),
        ("text after the line", line() + " "),
    ]
    for i, (what, printed) in enumerate(refusals, 2):
        name = f"j{i} the kit's own check-capture refuses {what} with its own line"
        if printed is None:
            cell(name, False, "HEAD^ is not in this clone")
            continue
        held, r, detail = check_capture(printed, f"out-{i}")
        cell(name, held and r.returncode == 1 and f"linux-amd64: --version prints '{printed}', not '" in r.stderr
             and not (parent / f"out-{i}").exists(), detail)

    # A 14-digit time that is not the commit's: check-capture compares the
    # whole line with the line stage wrote and refuses it, and kit(), run from
    # the repository, refuses a capture whose version file holds it.
    later = line(t=time.strftime("%Y%m%d%H%M%S", time.gmtime(commit_time + 1)))
    held, taken, _ = check_capture(later, "out-later")
    captures = parent / "captures-later"
    captures.mkdir()
    (captures / "linux-amd64.txt").write_text((parent / "capture.txt").read_text())
    (captures / "linux-amd64.version").write_text(later + "\n")
    (captures / "linux-amd64.sha256").write_text(hashlib.sha256(stand_in.read_bytes()).hexdigest() + "\n")
    stage_tar = parent / "kit-stage.tar"
    archived = run([PY, "-I", KIT / "kit_files.py", "archive", copy, stage_tar, "--mtime", "0", "--plain"])
    r = run(["bash", KIT / "assemble.sh", "kit", stage_tar, captures, scratch("j-kit")],
            env=dict(os.environ, KIT_TAG="kit-2026-11-05", KIT_REPO="opena2a-standards/atx-conformance",
                     KIT_COMMIT=sha, KIT_GO_VERSION=go_version, KIT_PYTHON=PY))
    cell(f"j{len(refusals) + 2} a 14-digit time that is not HEAD's: the kit's check-capture refuses it, and "
         "kit() from the repository refuses a capture whose version file holds it",
         held and taken.returncode == 1 and not (parent / "out-later").exists()
         and archived.returncode == 0 and r.returncode == 1 and "the version line is not" in r.stderr,
         f"check-capture exit {taken.returncode}; kit exit {r.returncode}: "
         + (r.stdout + r.stderr).strip().split("\n")[-1][:160])


def cells_version_under_tags() -> None:
    """The version line under each of the three tag views, as Go stamps it
    into a clean build: no Go version tag on the commit or an ancestor,
    v0.0.0-<time>-<sha12>; a tag vX.Y.Z on the commit, vX.Y.Z; vX.Y.Z on an
    ancestor only, the derived pseudo-version vX.Y.(Z+1)-0.<time>-<sha12>.
    Tags are made only in a scratch clone of HEAD (git clone --no-tags), and
    the last cell holds that this repository's tags are the same after the
    cells as before. Each view is checked where the release workflow checks
    it: the line stage derives from the clone's tags (assemble.sh
    version-line, the clone's own copy); the kit's own check-capture,
    unpacked outside any repository with no Python, on a stand-in binary;
    kit() from the repository; and the release notes' --version claim."""
    repo_tags = git("tag", "-l")
    parent = scratch("t")
    sha = git("rev-parse", "HEAD")
    commit_time = int(git("show", "-s", "--format=%ct", "HEAD"))
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(commit_time))
    go_version = "1.27.3"
    clone = parent / "clone"

    def in_clone(*args) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(clone), "-c", "user.name=kit-test", "-c", "user.email=kit-test",
                               *args], capture_output=True, text=True)

    made = subprocess.run(["git", "clone", "-q", "--no-hardlinks", "--no-tags", str(REPO), str(clone)],
                          capture_output=True, text=True)
    if made.returncode == 0:
        made = in_clone("checkout", "-q", "--detach", sha)
    head = in_clone("rev-parse", "HEAD").stdout.strip() if made.returncode == 0 else ""
    ancestors = bool(head) and in_clone("rev-parse", "--verify", "-q", "HEAD~2").returncode == 0
    cell("t0 a scratch clone of HEAD holding no tag, with HEAD^ and HEAD~2",
         head == sha and ancestors and in_clone("tag", "-l").stdout == "",
         f"clone exit {made.returncode}; HEAD {head[:12] or 'none'}; HEAD~2 {'present' if ancestors else 'absent'}")
    if head != sha or not ancestors:
        return
    later_commit = in_clone("commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "a scratch commit after HEAD").stdout.strip()
    parent_sha = in_clone("rev-parse", "HEAD^").stdout.strip()

    def set_tags(*tags: tuple) -> str:
        """Leaves the clone with exactly these tags, each (name, revision) or
        (name, revision, "annotated"), and returns their names as git lists them."""
        for old in in_clone("tag", "-l").stdout.split():
            in_clone("tag", "-d", old)
        for name, rev, *annotated in tags:
            in_clone("tag", *(["-a", "-m", name] if annotated else []), name, rev)
        return " ".join(in_clone("tag", "-l").stdout.split())

    module = re.search(r"^module (\S+)$", (clone / "go.mod").read_text(), re.M).group(1)

    def line(version: str, go: str = go_version) -> str:
        return f"atx-verify: {module} {version}, built with go{go}"

    untagged = f"v0.0.0-{stamp}-{sha[:12]}"
    tagged = "v0.6.0"
    after = f"v0.6.1-0.{stamp}-{sha[:12]}"
    derive_env = dict(os.environ, KIT_COMMIT=sha, KIT_GO_VERSION=go_version, KIT_PYTHON=PY)

    def derive(*tags: tuple):
        listed = set_tags(*tags)
        return listed, run(["bash", clone / "scripts" / "kit" / "assemble.sh", "version-line"], env=derive_env)

    # The line stage derives from the clone's tags. Each tag view with the
    # version go build stamps for it in a scratch clone holding those tags.
    views = [
        ("no Go version tag (a kit tag on HEAD, which Go does not read)",
         [("kit-2026-11-14", "HEAD")], untagged, "v0.0.0-<time>-<sha12>"),
        ("v0.6.0 on HEAD", [("v0.6.0", "HEAD")], tagged, "v0.6.0"),
        ("v0.6.0 on HEAD, an annotated tag", [("v0.6.0", "HEAD", "annotated")], tagged, "v0.6.0"),
        ("v1.0.0 on HEAD (Go reads major version 1 for a module path with no /vN)",
         [("v1.0.0", "HEAD")], "v1.0.0", "v1.0.0"),
        ("v0.6.0 on HEAD^ only", [("v0.6.0", "HEAD^")], after, "v0.6.1-0.<time>-<sha12>"),
        ("v0.6.0 on HEAD~2 and v0.5.0 on HEAD^ (the highest tag among the ancestors, not the nearest)",
         [("v0.6.0", "HEAD~2"), ("v0.5.0", "HEAD^")], after, "v0.6.1-0.<time>-<sha12>"),
        ("v0.5.0-rc.1 on HEAD~2 and v0.6.0 on HEAD^ (a pre-release below the highest release)",
         [("v0.5.0-rc.1", "HEAD~2"), ("v0.6.0", "HEAD^")], after, "v0.6.1-0.<time>-<sha12>"),
        ("v0.7.0 on a commit after HEAD only, which is not an ancestor",
         [("v0.7.0", later_commit)], untagged, "v0.0.0-<time>-<sha12>"),
        ("v1.2 and v2.0.0 on HEAD and a pseudo-version-shaped tag on HEAD^, none of which Go reads",
         [("v1.2", "HEAD"), ("v2.0.0", "HEAD"), (f"v0.0.0-20260101000000-{parent_sha[:12]}", "HEAD^")],
         untagged, "v0.0.0-<time>-<sha12>"),
    ]
    i = 0
    for what, tags, version, form in views:
        i += 1
        listed, r = derive(*tags)
        cell(f"t{i} stage's version line with {what}: {form}",
             r.returncode == 0 and r.stdout == line(version) + "\n",
             f"tags [{listed}]; exit {r.returncode}: " + (r.stdout + r.stderr).strip().split("\n")[-1][:160])
    outside = [
        ("v0.6.0-rc.1 on HEAD, where Go stamps the pre-release v0.6.0-rc.1", [("v0.6.0-rc.1", "HEAD")], "v0.6.0-rc.1"),
        ("v0.6.0-rc.1 on HEAD~2 above v0.5.0 on HEAD^, where Go stamps v0.6.0-rc.1.0.<time>-<sha12>",
         [("v0.6.0-rc.1", "HEAD~2"), ("v0.5.0", "HEAD^")], "v0.6.0-rc.1"),
        ("v0.6.0+meta on HEAD^, a tag with build metadata", [("v0.6.0+meta", "HEAD^")], "v0.6.0+meta"),
    ]
    for what, tags, named in outside:
        i += 1
        listed, r = derive(*tags)
        cell(f"t{i} stage refuses a tag view outside the three, {what}, and names the tag",
             r.returncode == 1 and r.stdout == "" and named in r.stderr,
             f"tags [{listed}]; exit {r.returncode}: " + (r.stdout + r.stderr).strip().split("\n")[-1][:160])
    set_tags()

    # The kit's own check-capture, as in cells_capture_in_the_unpacked_kit, with
    # the line stage wrote for each tag view in bin/version-line.txt.
    kit_parent = parent / "kit"
    copy = kit_parent / "interop-day-kit"
    tree_into(copy)
    n = len(list((copy / "fixtures").glob("*.json")))
    (kit_parent / "capture.txt").write_text(f"summary: {n} pass, 0 fail ({n} fixtures)\n")
    (kit_parent / "capture.rc").write_text("0\n")
    no_python = kit_parent / "no-python" / "python3"
    capture_env = {"KIT_COMMIT": sha, "KIT_GO_VERSION": go_version, "PATH": os.environ.get("PATH", ""),
                   "HOME": os.environ.get("HOME", ""), "KIT_PYTHON": str(no_python)}
    stand_in = copy / "bin" / "linux-amd64" / "atx-verify"
    stand_in.parent.mkdir(parents=True)
    stage_file = copy / "bin" / "version-line.txt"

    def stage_and_print(stage_line: str | None, printed: str) -> None:
        if stage_line is None:
            stage_file.unlink(missing_ok=True)
        else:
            stage_file.write_text(stage_line + "\n")
        stand_in.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(printed)}\n")
        stand_in.chmod(0o755)

    def check_capture(stage_line: str | None, printed: str, out: str):
        stage_and_print(stage_line, printed)
        witness = run(["git", "-C", copy / "scripts" / "kit", "rev-parse", "--git-dir"], env=capture_env)
        r = run(["bash", "interop-day-kit/scripts/kit/assemble.sh", "check-capture", "interop-day-kit",
                 "capture.txt", "capture.rc", "linux-amd64", out], cwd=kit_parent, env=capture_env)
        detail = (f"git rev-parse --git-dir exit {witness.returncode}; check-capture exit {r.returncode}: "
                  + (r.stdout + r.stderr).strip().split("\n")[-1][:160])
        return witness.returncode != 0 and not no_python.exists(), r, detail

    three = [("no Go version tag", "untagged", untagged), ("v0.6.0 on HEAD", "tagged", tagged),
             ("v0.6.0 on HEAD^ only", "after", after)]
    for what, key, version in three:
        i += 1
        held, r, detail = check_capture(line(version), line(version), f"out-{key}")
        wrote = kit_parent / f"out-{key}" / "linux-amd64.version"
        cell(f"t{i} the kit's own check-capture, {what}: the line stage wrote passes and linux-amd64.version "
             "holds it", held and r.returncode == 0 and wrote.exists() and wrote.read_text() == line(version) + "\n",
             detail)
    devel = line(f"(devel), commit {sha}")
    controls = [
        ("no Go version tag", untagged, "the line of a tag on the commit (v0.6.0)", line(tagged)),
        ("no Go version tag", untagged, "the line of a tag on an ancestor (v0.6.1-0.)", line(after)),
        ("v0.6.0 on HEAD", tagged, "the line with no Go version tag, the form the check took before",
         line(untagged)),
        ("v0.6.0 on HEAD", tagged, "another tag's line (v0.6.1)", line("v0.6.1")),
        ("v0.6.0 on HEAD", tagged, "the pseudo-version after the tag (v0.6.1-0.)", line(after)),
        ("v0.6.0 on HEAD", tagged, "a +dirty build", line(tagged + "+dirty")),
        ("v0.6.0 on HEAD", tagged, "a (devel), commit <sha> line", devel),
        ("v0.6.0 on HEAD^ only", after, "the tag's own line (v0.6.0)", line(tagged)),
        ("v0.6.0 on HEAD^ only", after, "the line with no Go version tag", line(untagged)),
        ("v0.6.0 on HEAD^ only", after, "a pseudo-version whose base is not raised (v0.6.0-0.)",
         line(f"v0.6.0-0.{stamp}-{sha[:12]}")),
        ("v0.6.0 on HEAD^ only", after, "a pseudo-version after another tag (v0.5.1-0.)",
         line(f"v0.5.1-0.{stamp}-{sha[:12]}")),
        ("v0.6.0 on HEAD^ only", after, "a +dirty build", line(after + "+dirty")),
        ("v0.6.0 on HEAD^ only", after, "a (devel), commit <sha> line", devel),
    ]
    for k, (view, version, what, printed) in enumerate(controls):
        i += 1
        out = f"out-control-{k}"
        held, r, detail = check_capture(line(version), printed, out)
        cell(f"t{i} the kit's own check-capture, {view}: refuses {what}",
             held and r.returncode == 1 and f"linux-amd64: --version prints '{printed}', not '" in r.stderr
             and not (kit_parent / out).exists(), detail)
    stage_controls = [
        ("names HEAD^'s 12 hex", line(f"v0.0.0-{stamp}-{parent_sha[:12]}")),
        ("names go1.27.2", line(untagged, go="1.27.2")),
        ("names a pre-release (v0.6.0-rc.1), a form stage does not derive", line("v0.6.0-rc.1")),
        ("is missing", None),
    ]
    for k, (what, stage_line) in enumerate(stage_controls):
        i += 1
        out = f"out-stage-{k}"
        held, r, detail = check_capture(stage_line, stage_line or line(untagged), out)
        cell(f"t{i} the kit's own check-capture refuses when the line stage wrote {what}, whatever the binary "
             "prints", held and r.returncode == 1 and "bin/version-line.txt" in r.stderr
             and not (kit_parent / out).exists(), detail)

    # The release notes' --version claim, held to the line check-capture took.
    others = {"untagged": ("v0.6.0 on HEAD", line(tagged)), "tagged": ("v0.6.0 on HEAD^ only", line(after)),
              "after": ("v0.6.0 on HEAD", line(tagged))}
    for what, key, version in three:
        i += 1
        d = parent / f"notes-{key}"
        d.mkdir()
        scratch_kit(d, dict(head_facts(), version=version))
        notes = d / "dist" / "release-notes.md"
        taken = kit_parent / f"out-{key}" / "linux-amd64.version"
        other_view, other_line = others[key]
        other = d / "other.version"
        other.write_text(other_line + "\n")
        passed = run([PY, "-I", KIT / "render.py", "check-claims", notes, taken]) if taken.exists() else None
        refused = run([PY, "-I", KIT / "render.py", "check-claims", notes, other])
        cell(f"t{i} release notes rendered with {what}: they name the version stage derived; check-claims passes "
             f"on the line check-capture took and refuses the line of {other_view}",
             f"`{version}`" in notes.read_text() and passed is not None and passed.returncode == 0
             and refused.returncode == 1 and "do not print" in refused.stderr,
             f"version named {'yes' if f'`{version}`' in notes.read_text() else 'no'}; check-claims exit "
             f"{passed.returncode if passed else 'not run'}; on the other line exit {refused.returncode}")
    i += 1
    d = parent / "notes-prefix"
    d.mkdir()
    (d / "release-notes.md").write_text("`atx-verify --version` prints `v0.6.1`.\n")
    (d / "linux-amd64.version").write_text(line(after) + "\n")
    r = run([PY, "-I", KIT / "render.py", "check-claims", d / "release-notes.md", d / "linux-amd64.version"])
    cell(f"t{i} check-claims refuses notes naming v0.6.1 when the binary prints v0.6.1-0.<time>-<sha12>: a claim "
         "is the whole version, never a part of it", r.returncode == 1 and "do not print" in r.stderr,
         f"exit {r.returncode}: " + (r.stdout + r.stderr).strip().split("\n")[-1][:160])

    # kit() from the repository, on a stage holding the line stage wrote.
    def kit_run(stage_line: str, printed: str, version_file: str, name: str):
        stage_and_print(stage_line, printed)
        captures = parent / f"captures-{name}"
        captures.mkdir()
        (captures / "linux-amd64.txt").write_text((kit_parent / "capture.txt").read_text())
        (captures / "linux-amd64.version").write_text(version_file + "\n")
        (captures / "linux-amd64.sha256").write_text(hashlib.sha256(stand_in.read_bytes()).hexdigest() + "\n")
        stage_tar = parent / f"stage-{name}.tar"
        archived = run([PY, "-I", KIT / "kit_files.py", "archive", copy, stage_tar, "--mtime", "0", "--plain"])
        out = parent / f"kit-{name}"
        r = run(["bash", KIT / "assemble.sh", "kit", stage_tar, captures, out],
                env=dict(os.environ, KIT_TAG="kit-2026-11-05", KIT_REPO="opena2a-standards/atx-conformance",
                         KIT_COMMIT=sha, KIT_GO_VERSION=go_version, KIT_PYTHON=PY))
        detail = f"kit exit {r.returncode}: " + (r.stdout + r.stderr).strip().split("\n")[-1][:160]
        return archived.returncode == 0, r, out, detail

    for what, key, version in three:
        i += 1
        archived, r, out, detail = kit_run(line(version), line(version), line(version), f"take-{key}")
        left = (out / "interop-day-kit" / "bin" / "version-line.txt").exists()
        cell(f"t{i} kit() from the repository, {what}: takes the capture holding the line stage wrote (it "
             "reaches its captures line) and leaves bin/version-line.txt out of the kit",
             archived and f"assemble: captures: 1 platforms ran all {n} fixtures" in r.stdout and not left,
             f"bin/version-line.txt {'left in' if left else 'not in'} the kit; {detail}")
    i += 1
    archived, r, out, detail = kit_run(line(tagged), line(tagged), line(untagged), "mismatch")
    cell(f"t{i} kit() from the repository, v0.6.0 on HEAD: refuses a capture whose version file holds the line "
         "with no Go version tag", archived and r.returncode == 1 and "the version line is not" in r.stderr, detail)
    later_stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(commit_time + 1))
    for what, key, version in (("with no Go version tag", "untagged", f"v0.0.0-{later_stamp}-{sha[:12]}"),
                               ("after a tag", "after", f"v0.6.1-0.{later_stamp}-{sha[:12]}")):
        i += 1
        archived, r, out, detail = kit_run(line(version), line(version), line(version), f"time-{key}")
        cell(f"t{i} kit() from the repository refuses a line stage wrote {what} whose 14-digit time is not the "
             "commit's committer time, read from the checkout",
             archived and r.returncode == 1 and "committer time" in r.stderr, detail)

    i += 1
    cell(f"t{i} this repository's tags are the same after the t cells as before: tags were made only in the "
         "scratch clone", git("tag", "-l") == repo_tags, f"{len(repo_tags.split())} tag(s) before and after")


# ---------------------------------------------------------- --sandboxed cells

def write_stub(directory: Path, name: str, body: str) -> None:
    p = directory / name
    p.write_text("#!/bin/bash\n" + body)
    p.chmod(0o755)


STUB_GH = r'''printf '%s\n' "$*" >>"$STUB_STATE/gh.log"
hash_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
case "$1 $2" in
  "release download")
    dest=; while [ $# -gt 0 ]; do [ "$1" = -D ] && dest=$2; shift; done
    cp "$STUB_STATE"/release/* "$dest"/ ;;
  "release verify") exit "${STUB_RELEASE_VERIFY_RC:-0}" ;;
  "attestation verify")
    if [ "${STUB_ATTEST_ALL:-}" = 1 ] || grep -q -x "$(hash_of "$3")" "$STUB_STATE/attested"; then exit 0; fi
    echo "no attestation for $3" >&2; exit 1 ;;
  "run list") cat "$STUB_STATE/run-list" 2>/dev/null || true ;;
  "run download")
    dest=; id=$3; while [ $# -gt 0 ]; do [ "$1" = -D ] && dest=$2; shift; done
    cp "$STUB_STATE/runs/$id/SHA256SUMS" "$dest"/ ;;
  *) echo "gh double: not answered: $*" >&2; exit 98 ;;
esac
'''
STUB_DISKUTIL = r'''printf '%s\n' "$*" >>"$STUB_STATE/diskutil.log"
[ "$1" = info ] && [ $# -eq 2 ] || { echo "diskutil double: only info <volume> is answered" >&2; exit 98; }
printf '   Device Identifier:         disk9s1\n'
printf '   Protocol:                  %s\n' "$STUB_PROTOCOL"
printf '   Removable Media:           %s\n' "$STUB_REMOVABLE"
printf '   Mount Point:               %s\n' "${STUB_MOUNT:-$2}"
'''
STUB_GIT = r'''printf '%s\n' "$*" >>"$STUB_STATE/git.log"
[ "$1" = ls-remote ] || { echo "git double: only ls-remote is answered" >&2; exit 98; }
printf '%s\trefs/tags/%s\n' "$STUB_COMMIT" "$STUB_TAG"
'''


def sandbox_setup() -> str | None:
    """Builds the doubles and the sandbox; returns a reason when a guard fails."""
    global SANDBOX_ENV, SANDBOX_PROFILE
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists():
        return "sandbox-exec is not available on this machine"
    real_home = os.environ.get("HOME", "")
    if len(real_home) < 2:
        return "HOME is not set"
    SANDBOX_PROFILE = ("(version 1)(allow default)(deny network*)"
                       f'(deny file-read* (subpath "{real_home}/.secretless-ai"))'
                       '(deny process-exec (literal "/usr/bin/security"))')
    stubs = scratch("doubles")
    for name, body in (("gh", STUB_GH), ("diskutil", STUB_DISKUTIL), ("git", STUB_GIT)):
        write_stub(stubs, name, body)
    pybin = scratch("pybin")
    (pybin / "python3").symlink_to(PY)
    home = scratch("home")
    SANDBOX_ENV = {
        "PATH": f"{stubs}:{pybin}:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home), "GH_CONFIG_DIR": str(home / "gh"), "LC_ALL": "C", "TMPDIR": str(scratch("tmp")),
        "KIT_PYTHON": "python3", "HARNESS_NO_LIVE_TRANSPORT": "1", "KIT_ATTEST_TRIES": "1",
    }
    guard = run(["bash", "-c",
                 '[ "${HARNESS_NO_LIVE_TRANSPORT:-}" = 1 ] || exit 3; '
                 'for t in gh git diskutil; do p=$(command -v "$t") || exit 4; '
                 'case "$p" in "$1"/*) ;; *) echo "$t resolves to $p"; exit 5 ;; esac; done', "guard", stubs],
                sandboxed=True)
    if guard.returncode != 0:
        return f"guard: the doubles do not resolve first in bash, or the tripwire is unset (exit {guard.returncode}) {guard.stdout.strip()}"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
                conn.close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()
    probe = f"import socket; socket.create_connection(('127.0.0.1', {port}), 3).close()"
    outside = run([PY, "-I", "-c", probe])
    inside = run([PY, "-I", "-c", probe], sandboxed=True)
    stop.set()
    listener.close()
    if outside.returncode != 0:
        return "control: the loopback listener is not reachable outside the sandbox"
    if inside.returncode == 0:
        return "control: the loopback listener is reachable inside the sandbox, so its network is not denied"
    cell("s0 guards: tripwire set, doubles resolve first in bash, 127.0.0.1 reachable outside and refused inside",
         True, f"port {port}")
    return None


def stub_state(name: str, kit_parent: Path, attest: list[Path]) -> tuple[Path, dict]:
    """A release built from a scratch kit: the archive, SHA256SUMS, and the
    digests the gh double treats as attested."""
    state = scratch(name)
    rel = state / "release"
    rel.mkdir()
    kit = kit_parent / "interop-day-kit"
    sums_for(kit, rel / "SHA256SUMS")
    r = run([PY, "-I", KIT / "kit_files.py", "archive", kit, rel / "interop-day-kit.tar.gz", "--mtime", "0"])
    if r.returncode != 0:
        raise SystemExit(r.stderr)
    digests = [hashlib.sha256(p.read_bytes()).hexdigest() for p in
               [rel / "interop-day-kit.tar.gz", rel / "SHA256SUMS"] + attest]
    (state / "attested").write_text("\n".join(digests) + "\n")
    env = dict(SANDBOX_ENV, STUB_STATE=str(state))
    return state, env


def cells_verify_release() -> None:
    d = scratch("v")
    kit = scratch_kit(d, bins=True)
    bins = sorted(kit.glob("bin/*/atx-verify"))
    commit = "0123456789abcdef0123456789abcdef01234567"
    state, env = stub_state("v-state", d, bins)
    env.update(KIT_REPO="opena2a-standards/atx-conformance", KIT_COMMIT=commit)
    r = run(["bash", KIT / "verify_release.sh", "candidate", state / "release", scratch("v-work1")], env=env, sandboxed=True)
    cell("v1 verify_release.sh candidate: every asset and binary attested, every one-byte copy refused",
         r.returncode == 0 and "every one-byte copy refused" in r.stdout, (r.stdout + r.stderr).strip().split("\n")[-1])
    log = (state / "gh.log").read_text()
    cell("v2 the attestation verify command, in full, for every file",
         log.count("--signer-workflow opena2a-standards/atx-conformance/.github/workflows/kit-release.yml "
                   f"--source-ref refs/heads/main --source-digest {commit} --deny-self-hosted-runners") == 2 * (2 + len(bins)),
         f"{log.count('attestation verify')} attestation verify calls")
    r = run(["bash", KIT / "verify_release.sh", "candidate", state / "release", scratch("v-work2")],
            env=dict(env, STUB_ATTEST_ALL="1"), sandboxed=True)
    cell("v3 double that attests any bytes: the one-byte control refuses", r.returncode == 1 and "proves nothing" in r.stderr,
         r.stderr.strip().split("\n")[-1])
    lone = scratch("v-lone")
    shutil.copy(state / "release" / "SHA256SUMS", lone)
    r = run(["bash", KIT / "verify_release.sh", "candidate", lone, scratch("v-work3")], env=env, sandboxed=True)
    cell("v4 a missing asset refuses", r.returncode != 0, r.stderr.strip().split("\n")[-1][:110])
    d2 = scratch("v-tamper")
    kit2 = scratch_kit(d2, bins=True)
    state2, env2 = stub_state("v-state2", d2, sorted(kit2.glob("bin/*/atx-verify")))
    lines = (state2 / "release" / "SHA256SUMS").read_text().splitlines()
    lines[0] = ("0" * 64) + lines[0][64:]
    (state2 / "release" / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    (state2 / "attested").open("a").write(hashlib.sha256((state2 / "release" / "SHA256SUMS").read_bytes()).hexdigest() + "\n")
    env2.update(KIT_REPO="opena2a-standards/atx-conformance", KIT_COMMIT=commit)
    r = run(["bash", KIT / "verify_release.sh", "candidate", state2 / "release", scratch("v-work4")], env=env2, sandboxed=True)
    cell("v5 SHA256SUMS that does not match the archive's files refuses", r.returncode != 0 and "sha256sum -c" in r.stderr,
         r.stderr.strip().split("\n")[-1][:110])


def cells_candidate() -> None:
    state = scratch("cand")
    mine = state / "SHA256SUMS"
    mine.write_text(("a" * 64) + "  fixtures/x.json\n")
    (state / "runs" / "4242").mkdir(parents=True)
    shutil.copy(mine, state / "runs" / "4242" / "SHA256SUMS")
    (state / "run-list").write_text("4242\n")
    env = dict(SANDBOX_ENV, STUB_STATE=str(state), GITHUB_SHA="0123456789abcdef0123456789abcdef01234567",
               GITHUB_REPOSITORY="opena2a-standards/atx-conformance")
    r = run(["bash", KIT / "candidate_equal.sh", mine], env=env, sandboxed=True)
    log = (state / "gh.log").read_text()
    cell("w1 candidate byte-equal: the tag run proceeds",
         r.returncode == 0 and "-w kit-release.yml -e workflow_dispatch -c 0123456789abcdef0123456789abcdef01234567 -s success -L 1" in log
         and "run download 4242" in log and "-n kit-sha256sums" in log, r.stdout.strip())
    other = state / "other"
    other.write_text(("b" * 64) + "  fixtures/x.json\n")
    r = run(["bash", KIT / "candidate_equal.sh", other], env=env, sandboxed=True)
    cell("w2 candidate differs by one SHA256SUMS line: refuses", r.returncode == 1 and "differs" in r.stderr,
         r.stderr.strip())
    (state / "run-list").write_text("")
    r = run(["bash", KIT / "candidate_equal.sh", mine], env=env, sandboxed=True)
    cell("w3 no successful dispatch run at the commit: refuses", r.returncode == 1 and "no successful" in r.stderr,
         r.stderr.strip()[:110])


def cells_stick() -> None:
    d = scratch("f-kit")
    kit = scratch_kit(d, bins=True)
    commit = "0123456789abcdef0123456789abcdef01234567"
    state, env = stub_state("f-state", d, sorted(kit.glob("bin/*/atx-verify")))
    env.update(STUB_COMMIT=commit, STUB_TAG="kit-2026-11-05", STUB_PROTOCOL="USB", STUB_REMOVABLE="Removable")

    def stick(name, volume, **over):
        e = dict(env, **over)
        return run(["bash", KIT / "write_stick.sh", "kit-2026-11-05", volume], env=e, sandboxed=True)

    def listing(p: Path):
        return sorted((str(q.relative_to(p)), q.stat().st_size) for q in p.rglob("*"))

    cases = [
        ("f1 refuses a volume diskutil does not report as USB", {"STUB_PROTOCOL": "SATA"}, None, "not USB"),
        ("f2 refuses a volume diskutil does not report as removable", {"STUB_REMOVABLE": "Fixed"}, None, "not Removable"),
        ("f3 refuses a path diskutil does not report as the mount point", {"STUB_MOUNT": "/Volumes/OTHER"}, None, "mount point"),
        ("f4 refuses a volume that holds a file, and leaves it as it was", {}, "photo.jpg", "not empty"),
    ]
    for name, over, existing, expect in cases:
        vol = scratch(name.split()[0] + "-vol")
        (vol / ".fseventsd").mkdir()
        if existing:
            (vol / existing).write_bytes(b"\xff\xd8 not ours")
        before = listing(vol)
        r = stick(name, vol, **over)
        after = listing(vol)
        cell(name, r.returncode == 1 and expect in r.stderr and before == after,
             r.stderr.strip().split("\n")[-1][:110])
    vol = scratch("f5-vol")
    (vol / ".fseventsd").mkdir()
    (vol / "System Volume Information").mkdir()
    r = stick("f5", vol)
    copied = vol / "interop-day-kit"
    kc = r.stdout.strip().split("\n")
    d7 = [l.rsplit(": ", 1)[-1] for l in kc if re.match(r"^[1-4] ", l)]
    cell("f5 a USB, removable, empty volume: copies the release's files and nothing else, kit check 1 1 1 1",
         r.returncode == 0 and copied.is_dir() and "PASS kit-2026-11-05" in r.stdout and d7 == ["1", "1", "1", "1"],
         (r.stdout + r.stderr).strip().split("\n")[-1][:120])
    dlog = (state / "diskutil.log").read_text().split("\n")
    cell("f6 diskutil was asked only info, never to erase, partition or format",
         all(l.startswith("info ") for l in dlog if l), f"{sum(1 for l in dlog if l)} calls, all info")
    vol = scratch("f7-vol")
    sums = (state / "release" / "SHA256SUMS").read_text().split("\n")
    sums[0] = ("0" * 64) + sums[0][64:]
    bad = scratch("f7-state")
    shutil.copytree(state / "release", bad / "release")
    (bad / "release" / "SHA256SUMS").write_text("\n".join(sums))
    attested = sorted((bad / "release").iterdir()) + sorted(kit.glob("bin/*/atx-verify"))
    (bad / "attested").write_text("\n".join(hashlib.sha256(p.read_bytes()).hexdigest() for p in attested) + "\n")
    r = stick("f7", vol, STUB_STATE=str(bad), STUB_ATTEST_ALL="")
    cell("f7 a release whose SHA256SUMS does not match its files: refused, nothing written to the volume",
         r.returncode != 0 and not any(vol.iterdir()), r.stderr.strip().split("\n")[-1][:110])


# --------------------------------------------------------------- --slow cell

def cell_reproducible() -> None:
    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True,
                            env=dict(os.environ, GOTOOLCHAIN="go1.27.3"), check=True).stdout.strip()
    runs = []
    for side in ("one", "two"):
        base = scratch(f"g-{side}")
        clone = base / "repo"
        subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(REPO), str(clone)], check=True)
        subprocess.run(["git", "-C", str(clone), "checkout", "-q", git("rev-parse", "HEAD")], check=True)
        env = dict(os.environ, KIT_COMMIT=git("rev-parse", "HEAD"), KIT_TAG="kit-2026-11-05",
                   KIT_REPO="opena2a-standards/atx-conformance", KIT_GO_VERSION="1.27.3",
                   GOCACHE=str(base / "gocache"), GOMODCACHE=str(base / "gomodcache"),
                   PIP_CACHE_DIR=str(base / "pipcache"), TMPDIR=str(scratch(f"g-{side}-tmp")),
                   GOTOOLCHAIN="local", PATH=f"{goroot}/bin:" + os.environ["PATH"])
        r = run(["bash", clone / "scripts" / "kit" / "assemble.sh", "local", base / "out"], cwd=clone, env=env)
        sums = base / "out" / "dist" / "SHA256SUMS"
        stop = (r.stdout + r.stderr).strip().split("\n")[-1]
        runs.append((sums.read_bytes() if sums.exists() else None, stop, r.returncode))
        print(f"      assembly {side}: exit {r.returncode}; last line: {stop[:140]}", flush=True)
    (a, _, _), (b, _, _) = runs
    cell("g1 two assemblies in separate folders and caches write byte-equal SHA256SUMS",
         a is not None and a == b, f"{len(a.splitlines()) if a else 0} lines, sha256 "
         f"{hashlib.sha256(a).hexdigest() if a else 'none'}")


def main(argv: list[str]) -> int:
    modes = set(argv)
    if not modes or not modes <= {"--ci", "--sandboxed", "--slow"}:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        if "--ci" in modes:
            cells_pins()
            cells_workflow()
            cells_unreadable_path()
            cells_sums()
            cells_census()
            cells_kit_check()
            cells_readme()
            cells_claims()
            cells_capture_in_the_unpacked_kit()
            cells_version_under_tags()
        if "--sandboxed" in modes:
            reason = sandbox_setup()
            if reason:
                cell("s0 guards", False, reason)
                print("test_kit: a guard did not hold; no sandboxed cell ran", file=sys.stderr)
            else:
                cells_verify_release()
                cells_candidate()
                cells_stick()
        if "--slow" in modes:
            cell_reproducible()
    finally:
        shutil.rmtree(SCRATCH, ignore_errors=True)
    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"test_kit: {len(RESULTS) - len(failed)} of {len(RESULTS)} cells passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
