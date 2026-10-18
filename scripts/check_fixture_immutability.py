#!/usr/bin/env python3
"""An existing fixture keeps the part that defines it.

README "Versioning and stability": a fixture's credential, its signatures, the
verifier state and the expected outcome are immutable, and a fixture that needs
a change in any of them ships under a new name. Its `description` and `spec`
citations are documentation and may be corrected in place.

WHAT HAPPENED. That rule stood in the README from the initial commit and
nothing checked it. e2f9dc4 (#26, 2026-09-09) rewrote `atx.capabilities` in 22
existing fixtures and re-signed every v1.1 fixture among them, keeping every
name. A consumer pinned to an earlier commit could not tell from the names
which fixtures had changed meaning. CHANGELOG.md lists them.

WHAT THIS ENFORCES. For every fixture `name` present both at a base commit and
in the tree under test, the `atx`, `verifierState` and `expected` members must
be equal. `atx` carries the signatures. Fixtures are matched by their `name`
member, not their path, so moving a file does not hide a change.

Equality is over the parsed JSON with three things kept that a plain
`json.loads` comparison loses: number spellings (`7` and `7.0` differ),
booleans against numbers (`false` and `0` differ), and repeated members (a
change to the first of two `"a"` members is a change even though the last one
wins). Member order is not compared between different member names, because
the signed form sorts members; the order of repeated members is compared.

WHAT THIS DOES NOT DO. A name that disappears is reported but does not fail:
a missing fixture is visible to a pinned consumer, a changed one is not. A new
name is not compared with anything. The base commit must be present in the
clone; when it is not, this exits 2 rather than passing on nothing.

Usage:
    python3 scripts/check_fixture_immutability.py              # vs merge base with origin/main
    python3 scripts/check_fixture_immutability.py --base REF   # vs REF
    python3 scripts/check_fixture_immutability.py --base A --head B   # commit B vs commit A
    python3 scripts/check_fixture_immutability.py --self-test
    python3 scripts/check_fixture_immutability.py --help
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = "fixtures"
DEFAULT_UPSTREAM = "origin/main"

# The members README "Versioning and stability" names as immutable. The
# signatures live inside `atx`.
MEMBERS = ("atx", "verifierState", "expected")

# Differing paths printed per member before the rest are counted.
MAX_PATHS = 5


class BaseError(Exception):
    """The base commit cannot be resolved in this clone."""


# --- strict JSON --------------------------------------------------------------

_OBJ = "{}"
_NUM = "#"


def _pairs(pairs):
    # Stable sort by member name: order between different names is ignored,
    # order among repeated names is kept.
    return (_OBJ, tuple(sorted(pairs, key=lambda kv: kv[0])))


def _num(lexeme):
    return (_NUM, lexeme)


def _load(text: str):
    """Parse JSON keeping number spellings and repeated members.

    Objects become ("{}", ((name, value), ...)), numbers ("#", "<lexeme>").
    Strings, booleans, null and arrays stay as Python str, bool, None, list,
    so `true` never equals `1` and `[]` never equals an object.
    """
    return json.loads(text, object_pairs_hook=_pairs, parse_int=_num,
                      parse_float=_num, parse_constant=_num)


def _diff_paths(a, b, path: str) -> list[str]:
    """The member paths at which a and b differ."""
    if a == b:
        return []
    if (isinstance(a, tuple) and isinstance(b, tuple)
            and a[0] == _OBJ and b[0] == _OBJ):
        out: list[str] = []
        names = list(dict.fromkeys([k for k, _ in a[1]] + [k for k, _ in b[1]]))
        for name in names:
            va = [v for k, v in a[1] if k == name]
            vb = [v for k, v in b[1] if k == name]
            sub = f"{path}.{name}"
            if va == vb:
                continue
            if len(va) == 1 and len(vb) == 1:
                out.extend(_diff_paths(va[0], vb[0], sub))
            elif not va:
                out.append(f"{sub} (added)")
            elif not vb:
                out.append(f"{sub} (removed)")
            else:
                out.append(f"{sub} (repeated member)")
        return out or [path]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out.extend(_diff_paths(x, y, f"{path}[{i}]"))
        return out or [path]
    return [path]


# --- reading fixtures ---------------------------------------------------------


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args],
                          capture_output=True, text=True)


def _rev(root: Path, ref: str) -> str | None:
    r = _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def resolve_base(root: Path, base: str | None) -> str:
    """The commit the tree is compared with.

    Explicit --base wins. Otherwise the merge base of HEAD and origin/main; on
    origin/main itself (a push to main) that is HEAD, so its first parent is
    used instead.
    """
    if base is not None:
        sha = _rev(root, base)
        if sha is None:
            raise BaseError(f"--base {base} is not a commit in this clone")
        return sha
    upstream = _rev(root, DEFAULT_UPSTREAM)
    if upstream is None:
        raise BaseError(
            f"{DEFAULT_UPSTREAM} is not in this clone; fetch it "
            f"(`git fetch origin main`, or a full-history checkout in CI) "
            f"or pass --base")
    mb = _git(root, "merge-base", "HEAD", upstream)
    if mb.returncode != 0 or not mb.stdout.strip():
        raise BaseError(
            f"HEAD and {DEFAULT_UPSTREAM} have no merge base in this clone; "
            f"a shallow clone needs more history, or pass --base")
    merge_base = mb.stdout.strip()
    if merge_base != _rev(root, "HEAD"):
        return merge_base
    parent = _rev(root, "HEAD^")
    if parent is None:
        raise BaseError(
            "HEAD is the merge base and its parent is not in this clone; "
            "fetch more history or pass --base")
    return parent


def _read_ref(root: Path, ref: str) -> dict[str, str]:
    """{path: text} for every fixtures/*.json at a commit."""
    r = _git(root, "ls-tree", "--name-only", ref, f"{FIXTURE_DIR}/")
    if r.returncode != 0:
        raise BaseError(f"cannot list {FIXTURE_DIR}/ at {ref}: {r.stderr.strip()}")
    out = {}
    for path in r.stdout.splitlines():
        if not path.endswith(".json"):
            continue
        show = _git(root, "show", f"{ref}:{path}")
        if show.returncode != 0:
            raise BaseError(f"cannot read {path} at {ref}: {show.stderr.strip()}")
        out[path] = show.stdout
    return out


def _read_tree(root: Path) -> dict[str, str]:
    """{path: text} for every fixtures/*.json in the working tree."""
    return {f"{FIXTURE_DIR}/{p.name}": p.read_text(encoding="utf-8")
            for p in sorted((root / FIXTURE_DIR).glob("*.json")) if p.is_file()}


def _key(path: str, doc) -> str:
    """A fixture's identity: its `name` member, or its path if it has none."""
    if isinstance(doc, tuple) and doc[0] == _OBJ:
        names = [v for k, v in doc[1] if k == "name"]
        if len(names) == 1 and isinstance(names[0], str):
            return names[0]
    return path


def _index(files: dict[str, str], side: str, failures: list[str]) -> dict:
    """{name: (path, parsed)}; unparseable and duplicated names are failures."""
    out: dict = {}
    for path, text in sorted(files.items()):
        try:
            doc = _load(text)
        except ValueError as e:
            failures.append(f"{path} ({side}): not valid JSON ({e}); its defining "
                            f"members cannot be compared")
            continue
        name = _key(path, doc)
        if name in out:
            failures.append(f"{path} ({side}): name '{name}' is also used by "
                            f"{out[name][0]}; a name must identify one fixture")
            continue
        out[name] = (path, doc)
    return out


def _member(doc, name: str):
    if isinstance(doc, tuple) and doc[0] == _OBJ:
        return [v for k, v in doc[1] if k == name]
    return []


def check(root: Path, base: str, head: str | None = None) -> tuple[list[str], list[str]]:
    """(failures, notes) comparing the tree (or commit `head`) with commit `base`."""
    failures: list[str] = []
    notes: list[str] = []
    before_files = _read_ref(root, base)
    after_files = _read_tree(root) if head is None else _read_ref(root, head)
    if not before_files:
        failures.append(f"no {FIXTURE_DIR}/*.json at the base commit; refusing to "
                        f"pass on nothing")
    if not after_files:
        failures.append(f"no {FIXTURE_DIR}/*.json in the tree under test; refusing "
                        f"to pass on nothing")
    before = _index(before_files, "base", failures)
    after = _index(after_files, "head", failures)

    for name, (old_path, old_doc) in before.items():
        if name not in after:
            notes.append(f"'{name}' ({old_path}) is no longer in {FIXTURE_DIR}/")
            continue
        new_path, new_doc = after[name]
        where = new_path if new_path == old_path else f"{old_path} -> {new_path}"
        for member in MEMBERS:
            old_v, new_v = _member(old_doc, member), _member(new_doc, member)
            if old_v == new_v:
                continue
            if len(old_v) == 1 and len(new_v) == 1:
                paths = _diff_paths(old_v[0], new_v[0], member)
            else:
                paths = [f"{member} (present {len(old_v)} -> {len(new_v)} times)"]
            shown = ", ".join(paths[:MAX_PATHS])
            if len(paths) > MAX_PATHS:
                shown += f", and {len(paths) - MAX_PATHS} more"
            failures.append(f"'{name}' ({where}): `{member}` changed at {shown}")
    return failures, notes


# --- self-test ----------------------------------------------------------------
#
# It drives the real check() against temporary git repositories: a base commit
# holding a real fixture from this repository, and a working tree changed the
# way a pull request would change it.

SEED = ROOT / FIXTURE_DIR / "v1_1-baseline-valid.json"
NAME = "atx-v1_1/baseline-valid"


def _seed() -> dict:
    return json.loads(SEED.read_text(encoding="utf-8"))


def _dump(doc: dict) -> str:
    return json.dumps(doc, indent=2) + "\n"


def _commit_all(root: Path, message: str) -> None:
    # The repository is a temporary one holding only fixtures/, so adding
    # everything in it adds exactly the fixtures (and stages their removal).
    for args in (("add", "--all"),
                 ("-c", "user.name=self-test", "-c", "user.email=self-test@example.invalid",
                  "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                  "commit", "-q", "--allow-empty", "-m", message)):
        r = _git(root, *args)
        if r.returncode != 0:
            raise RuntimeError(f"git {args[0]} failed in the self-test: {r.stderr.strip()}")


def _write(root: Path, files: dict[str, str]) -> None:
    d = root / FIXTURE_DIR
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    for name, text in files.items():
        (d / name).write_text(text, encoding="utf-8")


def _repo(base: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="fixture-immutability-"))
    r = _git(root, "-c", "init.defaultBranch=main", "init", "-q")
    if r.returncode != 0:
        raise RuntimeError(f"git init failed in the self-test: {r.stderr.strip()}")
    _write(root, base)
    _commit_all(root, "base")
    return root


def _probe(base: dict[str, str], head: dict[str, str]) -> tuple[list[str], list[str]]:
    root = _repo(base)
    try:
        _write(root, head)
        return check(root, "HEAD")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _seed_files() -> dict[str, str]:
    return {"v1_1-baseline-valid.json": _dump(_seed())}


def _mutated(edit) -> dict[str, str]:
    doc = _seed()
    edit(doc)
    return {"v1_1-baseline-valid.json": _dump(doc)}


def _replay_26(doc: dict) -> None:
    # The change e2f9dc4 made, run backwards on today's fixture.
    caps = doc["atx"]["capabilities"]
    caps[0] = "read:public" if caps[0] != "read:public" else "db:read"


def _resign(doc: dict) -> None:
    sig = doc["atx"]["signatures"][0]
    sig["value"] = sig["value"][::-1]


def _correct_docs(doc: dict) -> None:
    doc["description"] += " Corrected."
    doc["spec"] = list(doc["spec"])[:1]


def _seed_other() -> dict:
    doc = _seed()
    doc["name"] = "t/other"
    doc["description"] = "A different fixture."
    return doc


def _fires(result, *needles: str) -> bool:
    failures, _ = result
    return len(failures) == 1 and all(n in failures[0] for n in needles)


def _quiet(result) -> bool:
    failures, _ = result
    return not failures


def _set(path: tuple, value):
    def edit(doc):
        node = doc
        for p in path[:-1]:
            node = node[p]
        node[path[-1]] = value
    return edit


# Raw bodies for the cases a dict cannot express.
_DUP_BASE = '{"name": "t/dup", "atx": {"a": 1, "a": 2}, "verifierState": {}, "expected": {}}\n'
_DUP_HEAD = '{"name": "t/dup", "atx": {"a": 3, "a": 2}, "verifierState": {}, "expected": {}}\n'
_NUM_BASE = '{"name": "t/num", "atx": {"n": 7}, "verifierState": {}, "expected": {}}\n'
_NUM_HEAD = '{"name": "t/num", "atx": {"n": 7.0}, "verifierState": {}, "expected": {}}\n'
_BOOL_BASE = '{"name": "t/bool", "atx": {"revoked": false}, "verifierState": {}, "expected": {}}\n'
_BOOL_HEAD = '{"name": "t/bool", "atx": {"revoked": 0}, "verifierState": {}, "expected": {}}\n'
_ORDER_BASE = '{"name": "t/order", "atx": {"a": 1, "b": 2}, "verifierState": {}, "expected": {}}\n'
_ORDER_HEAD = '{"name": "t/order", "atx": {"b": 2, "a": 1}, "verifierState": {}, "expected": {}}\n'


def _rule_cases() -> list[tuple[bool, str, str]]:
    renamed = _seed()
    renamed["name"] = NAME + "-recut"
    _replay_26(renamed)
    moved = _mutated(_replay_26)["v1_1-baseline-valid.json"]
    return [
        (_quiet(_probe(_seed_files(), _seed_files())),
         "an unchanged fixture passes", "the check fails a tree that did not change"),
        (_quiet(_probe(_seed_files(), _mutated(_correct_docs))),
         "a corrected `description` and `spec` pass (documentation)",
         "the check fails a documentation edit the README allows in place"),
        (_fires(_probe(_seed_files(), _mutated(_replay_26)), NAME, "atx.capabilities[0]"),
         "the #26 change (atx.capabilities rewritten, name kept) fails by name and path",
         "the change this check exists for passes"),
        (_fires(_probe(_seed_files(), _mutated(_resign)), NAME, "atx.signatures[0].value"),
         "a changed `atx.signatures` fails", "re-signing in place passes"),
        (_fires(_probe(_seed_files(), _mutated(_set(("verifierState", "clockRfc3339"),
                                                    "2000-01-01T00:00:00Z"))),
                NAME, "verifierState.clockRfc3339"),
         "a changed `verifierState` fails", "the verifier state is not compared"),
        (_fires(_probe(_seed_files(), _mutated(_set(("expected", "verifyResult"),
                                                    "SELF-TEST-CHANGED"))),
                NAME, "expected.verifyResult"),
         "a changed `expected` fails", "the expected outcome is not compared"),
        (_quiet(_probe(_seed_files(), {**_seed_files(), "recut.json": _dump(renamed)})),
         "a changed credential under a new name, the old one kept, passes",
         "the remedy the README prescribes is refused"),
        (_fires(_probe(_seed_files(), {"moved.json": moved}), NAME,
                "fixtures/v1_1-baseline-valid.json -> fixtures/moved.json"),
         "a changed fixture moved to another path fails (matched by name)",
         "moving the file hides the change"),
        (_fires(_probe({"n.json": _NUM_BASE}, {"n.json": _NUM_HEAD}), "t/num", "atx.n"),
         "a number respelled (7 -> 7.0) fails", "number spellings are not compared"),
        (_fires(_probe({"b.json": _BOOL_BASE}, {"b.json": _BOOL_HEAD}), "t/bool", "atx.revoked"),
         "a boolean replaced by a number (false -> 0) fails", "false is compared equal to 0"),
        (_fires(_probe({"d.json": _DUP_BASE}, {"d.json": _DUP_HEAD}), "t/dup", "atx.a"),
         "a change to the first of two repeated members fails",
         "only the last of a repeated member is compared"),
        (_quiet(_probe({"o.json": _ORDER_BASE}, {"o.json": _ORDER_HEAD})),
         "members reordered with values kept pass", "member order between names is compared"),
    ]


def _guard_cases() -> list[tuple[bool, str, str]]:
    removed = _probe(_seed_files(), {"other.json": _dump(_seed_other())})
    return [
        (not removed[0] and any(NAME in n for n in removed[1]),
         "a removed name is reported as a note, not a failure",
         f"failures={removed[0]} notes={removed[1]}"),
        (_fires(_probe(_seed_files(), {"v1_1-baseline-valid.json": "{not json\n"}),
                "not valid JSON"),
         "an unparseable fixture fails", "an unparseable fixture is skipped"),
        (_fires(_probe(_seed_files(), {**_seed_files(), "copy.json": _dump(_seed())}),
                f"name '{NAME}' is also used by"),
         "two fixtures with one name fail", "a duplicated name is compared against one of them"),
        (_fires(_probe({}, _seed_files()), "at the base commit; refusing"),
         "a base commit with no fixtures fails", "the check passes on nothing"),
    ]


def _base_cases() -> list[tuple[bool, str, str]]:
    out = []
    root = _repo(_seed_files())
    try:
        first = _rev(root, "HEAD")
        try:
            resolve_base(root, None)
            out.append((False, "no origin/main exits as unresolved", "a base was invented"))
        except BaseError:
            out.append((True, "no origin/main exits as unresolved", ""))
        _git(root, "update-ref", "refs/remotes/origin/main", first)
        _write(root, _mutated(_replay_26))
        _commit_all(root, "branch work")
        got = resolve_base(root, None)
        out.append((got == first, "on a branch the base is the merge base with origin/main",
                    f"resolved {got}, expected {first}"))
        failures, _ = check(root, got)
        out.append((len(failures) == 1 and NAME in failures[0],
                    "the branch change fails against that merge base", f"{failures}"))
        second = _rev(root, "HEAD")
        _git(root, "update-ref", "refs/remotes/origin/main", second)
        got = resolve_base(root, None)
        out.append((got == first, "on origin/main itself the base is HEAD's parent",
                    f"resolved {got}, expected {first}"))
        try:
            resolve_base(root, "no-such-ref")
            out.append((False, "an unknown --base exits as unresolved", "a base was invented"))
        except BaseError:
            out.append((True, "an unknown --base exits as unresolved", ""))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return out


def _mutant_cases() -> list[tuple[bool, str, str]]:
    """A check that stopped looking must not read as a clean tree."""
    out = []
    probes = {
        "MEMBERS = ()": ("MEMBERS", (),
                         lambda: _probe(_seed_files(), _mutated(_replay_26))),
        "_load drops number spellings": (
            "_load", lambda text: json.loads(text, object_pairs_hook=_pairs),
            lambda: _probe({"n.json": _NUM_BASE}, {"n.json": _NUM_HEAD})),
        "_pairs keeps only the last repeated member": (
            "_pairs", lambda pairs: (_OBJ, tuple(sorted(dict(pairs).items()))),
            lambda: _probe({"d.json": _DUP_BASE}, {"d.json": _DUP_HEAD})),
        "_key -> path": ("_key", lambda path, _doc: path,
                         lambda: _probe(_seed_files(),
                                        {"moved.json": _mutated(_replay_26)["v1_1-baseline-valid.json"]})),
    }
    for label, (name, value, run) in probes.items():
        live = run()[0]
        original = globals()[name]
        globals()[name] = value
        try:
            try:
                mutated = run()[0]
            except Exception as e:  # a mutant that crashes is also observable
                mutated = [f"raised {type(e).__name__}"]
        finally:
            globals()[name] = original
        out.append((bool(live) and mutated != live, f"mutant KILLED: {label}",
                    f"SURVIVED: {mutated} same as unmutated {live}"))
    return out


def _report(cases: list[tuple[bool, str, str]]) -> int:
    failed = 0
    for ok, label, detail in cases:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        if not ok:
            print(f"          {detail}")
            failed += 1
    return failed


# A section that runs no cases would otherwise report success.
FLOORS = {"rule": 12, "guards": 4, "base": 5, "mutants": 4}


def self_test() -> int:
    failed = 0
    for key, heading, fn in (
        ("rule", "the defining members are compared, documentation is not", _rule_cases),
        ("guards", "nothing is skipped silently", _guard_cases),
        ("base", "the base commit is resolved, never invented", _base_cases),
        ("mutants", "a check that stopped looking must not read as clean", _mutant_cases),
    ):
        print(f"\n{heading}\n")
        cases = fn()
        failed += _report(cases)
        if len(cases) < FLOORS[key]:
            print(f"  [RED  ] section '{key}' ran {len(cases)} cases, floor is {FLOORS[key]}")
            failed += 1
    return failed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail when an existing fixture's atx, verifierState or "
                    "expected member changed since a base commit.")
    parser.add_argument("--base", help="commit to compare with (default: merge "
                        f"base of HEAD and {DEFAULT_UPSTREAM})")
    parser.add_argument("--head", help="commit to check (default: the working tree)")
    parser.add_argument("--self-test", action="store_true")
    args, unknown = parser.parse_known_args()
    if unknown:
        # In the words every script under scripts/ names one with.
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        parser.print_usage(sys.stderr)
        return 2

    if args.self_test:
        failed = self_test()
        if failed:
            print(f"\nself-test FAILED: {failed} case(s)", file=sys.stderr)
            return 1
        print("\nself-test passed: every defining member is compared, documentation "
              "is not,\nnothing is skipped silently, every mutant is killed")
        return 0

    try:
        base = resolve_base(ROOT, args.base)
        if args.head is not None and _rev(ROOT, args.head) is None:
            raise BaseError(f"--head {args.head} is not a commit in this clone")
        failures, notes = check(ROOT, base, args.head)
    except BaseError as e:
        print(f"fixture immutability check could not run: {e}", file=sys.stderr)
        return 2

    against = f"{base[:12]}" + ("" if args.head is None else f" -> {args.head}")
    for n in notes:
        print(f"  note: {n}")
    if failures:
        print(f"existing fixtures changed in the part that defines them ({against}):\n",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print("\nA fixture whose credential, signatures, verifier state or expected "
              "outcome\nchanges ships under a new name (README, Versioning and "
              "stability).", file=sys.stderr)
        return 1
    print(f"every existing fixture keeps its {', '.join(MEMBERS)} members ({against})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
