#!/usr/bin/env python3
"""Assert the README's sibling-repositories rows match the sibling repositories.

The rows stand in docs/sibling-repositories.md, which took the README's
Sibling repositories section and which the README links; this check reads
them there.

The atp-conformance and aip-conformance rows state counts and versions that
are measurements of other repositories, so check_readme_counts.py, which reads
only this tree, cannot hold them. They drifted: the atp-conformance row said
4 fixtures after that suite had grown to 14, and the aip-conformance row said
its verifiers "shipped at v0.2" while that repository had no tags and no
releases.

For each sibling row this check reads the sibling repository through the
GitHub API and holds the row to it:

  - every count listed in COUNT_SITES equals the matching fixtures/*.json
    files, or the verifiers/ directories, in that repository;
  - every verifier the row names as `A/B verifiers` is a verifiers/ directory
    there;
  - every release version (`vX.Y`) in the row's Status cell is a tag there;
  - the row's Spec cell names the spec id and version the repository's
    conformance.json declares in `spec.id` and `spec.version` ("AIP
    v1.0.0-draft" for `"id": "AIP", "version": "1.0.0-draft"`).

Every run starts with a self-test: each site is altered in memory, one at a
time, and the check must fail on it. The rows as published before this check
existed must fail too, and so must the aip-conformance row as published
before its Spec cell was checked, which named AIP v1.2.0-draft while that
repository declared AIP 1.0.0-draft, so the check keeps firing on the text it
was written for. The self-test checks the altered rows against sibling data
built from the rows themselves (offline_siblings), so it reads no repository.

The check needs network access. It reads through `gh api` when the GitHub CLI
is installed, so the CLI's login applies; otherwise it reads anonymously, or
with GH_TOKEN when that is set. When gh is installed and not logged in, the
run says so on one line that names both ways in: `gh auth login`, or GH_TOKEN.

Usage:
    python3 scripts/check_sibling_rows.py              # self-test, then the check
    python3 scripts/check_sibling_rows.py --self-test  # the self-test alone, per case
    python3 scripts/check_sibling_rows.py --help       # the usage line

Exit 0 when the self-test passes and every sibling row matches its
repository, 1 otherwise (including when a repository cannot be read), 2 on an
unknown argument.
"""

import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIBLINGS_PAGE_NAME = "docs/sibling-repositories.md"
SIBLINGS_PAGE = ROOT / SIBLINGS_PAGE_NAME
ORG = "opena2a-standards"
API = "https://api.github.com"
HEADING = "## Sibling repositories"

# A sibling row links its repository in the first cell.
SIBLING_ROW = re.compile(
    rf"^\| \[`([\w.-]+)`\]\(https://github\.com/{ORG}/\1\) \|.*$", re.M
)

# (repository, label, pattern on its row with group 1 the stated count,
#  what is counted, fixture-name prefix). The prefix "" counts every fixture.
COUNT_SITES = (
    ("atp-conformance", "fixture count", r"\|\s*(\d+) fixtures\b",
     "fixtures", ""),
    ("atp-conformance", "verifier count", r"\b(\d+)-verifier\b",
     "verifiers", None),
    ("aip-conformance", "§5.1 challenge-response fixture count",
     r"§5\.1 challenge-response covered by (\d+) ",
     "fixtures", "challenge-response-"),
    ("aip-conformance", "§6.1 trust-score fixture count",
     r"§6\.1 trust-score composition covered by (\d+) ",
     "fixtures", "trust-score-"),
)

NAMED_VERIFIERS = re.compile(r"\b([A-Z]\w*)/([A-Z]\w*) verifiers\b")
RELEASE = re.compile(r"\bv\d+(?:\.\d+)+\b")
# The spec a row's Spec cell names: an upper-case id, then `v` and a version
# with any pre-release suffix ("AIP v1.0.0-draft", "ATP v1.0.0-rc1").
SPEC_VERSION = re.compile(r"\b([A-Z][A-Z0-9]+) v(\d+(?:\.\d+)+(?:-[0-9A-Za-z.]+)?)(?![\w.-])")

# Rows published before a part of this check existed, each with that part and
# the failure it must still produce: the rows README.md published before this
# check, and the aip-conformance row this page published before the Spec cell
# was checked, which named AIP v1.2.0-draft while that repository declared AIP
# 1.0.0-draft.
RETRACTED_ROWS = (
    ("atp-conformance", "this check",
     "| [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) "
     "| ATP v1.0.0-rc1 protocol | 4 fixtures (discovery, trust-proof baseline, "
     "trust-proof hybrid, Signed Tree Head), same 2-verifier pair, "
     "`MANIFEST.sha256` pinned |",
     "atp-conformance row states 4 as its fixture count"),
    ("aip-conformance", "this check",
     "| [`aip-conformance`](https://github.com/opena2a-standards/aip-conformance) "
     "| AIP v1.0.0-draft identity protocol | §6.4 (VC `AgentTrustCredential`) "
     "covered by cross-linking this repo's fixtures; §5.1 challenge-response "
     "covered by 4 dedicated fixtures + Go/Python verifiers shipped at v0.2 "
     "(2026-05-28, Decision 3-C) |",
     "aip-conformance row names release v0.2"),
    ("aip-conformance", "the Spec cell check",
     "| [`aip-conformance`](https://github.com/opena2a-standards/aip-conformance) "
     "| AIP v1.2.0-draft identity protocol | §6.4 (VC `AgentTrustCredential`) "
     "covered by cross-linking this repo's fixtures; §5.1 challenge-response "
     "covered by 4 dedicated fixtures + Go/Python verifiers; §6.1 trust-score "
     "composition covered by 3 fixtures |",
     "aip-conformance row's Spec cell names AIP v1.2.0-draft, but"),
)


class SiblingError(Exception):
    pass


# gh's exit code for a command that needs authentication (`gh help exit-codes`).
GH_AUTH_REQUIRED = 4
NOT_LOGGED_IN = ("gh is not logged in to GitHub; run `gh auth login`, or set GH_TOKEN "
                 "to a GitHub token, then run this check again")


def fetch_json(path):
    """GET `path` (relative to the API root) through `gh api` when gh is
    installed, so its login applies; otherwise anonymously, or with GH_TOKEN."""
    if shutil.which("gh"):
        try:
            done = subprocess.run(["gh", "api", path], capture_output=True,
                                  text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SiblingError(f"could not read {path} through gh: {exc}") from exc
        if done.returncode == GH_AUTH_REQUIRED:
            raise SiblingError(NOT_LOGGED_IN)
        if done.returncode != 0:
            reason = (done.stderr.strip().splitlines() or ["no output"])[0]
            raise SiblingError(f"could not read {path} through gh: {reason}")
        body = done.stdout
    else:
        req = urllib.request.Request(f"{API}/{path}", headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "atx-conformance-check-sibling-rows",
        })
        token = os.environ.get("GH_TOKEN")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SiblingError(f"could not read {API}/{path}: {exc}") from exc
    try:
        return json.loads(body)
    except ValueError as exc:
        raise SiblingError(f"{path} did not return JSON: {exc}") from exc


def load_sibling(repo):
    """Return {"fixtures": [names], "verifiers": [dirs], "tags": [names]}."""
    tree = fetch_json(f"repos/{ORG}/{repo}/git/trees/HEAD?recursive=1")
    if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        raise SiblingError(f"{repo}: the tree response has no `tree` list")
    if tree.get("truncated"):
        raise SiblingError(f"{repo}: the tree response is truncated; counts would be short")
    fixtures, verifiers = [], []
    for entry in tree["tree"]:
        path = entry.get("path", "")
        if entry.get("type") == "blob" and re.fullmatch(r"fixtures/.+\.json", path):
            fixtures.append(path.rsplit("/", 1)[1])
        if entry.get("type") == "tree" and re.fullmatch(r"verifiers/[^/]+", path):
            verifiers.append(path.split("/", 1)[1])
    tags, page = [], 1
    while True:
        batch = fetch_json(f"repos/{ORG}/{repo}/tags?per_page=100&page={page}")
        if not isinstance(batch, list):
            raise SiblingError(f"{repo}: the tags response is not a list")
        tags += [t.get("name", "") for t in batch]
        if len(batch) < 100:
            break
        page += 1
    return {"fixtures": sorted(fixtures), "verifiers": sorted(verifiers), "tags": tags,
            "spec": load_declared_spec(repo)}


def load_declared_spec(repo):
    """The (spec.id, spec.version) the repository's conformance.json declares."""
    where = f"{ORG}/{repo} conformance.json"
    found = fetch_json(f"repos/{ORG}/{repo}/contents/conformance.json")
    if not isinstance(found, dict) or found.get("encoding") != "base64":
        raise SiblingError(f"{where}: the contents response carries no base64 content")
    try:
        profile = json.loads(base64.b64decode(found.get("content", "")).decode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise SiblingError(f"{where} is not JSON: {exc}") from exc
    spec = profile.get("spec") if isinstance(profile, dict) else None
    if not (isinstance(spec, dict) and isinstance(spec.get("id"), str)
            and isinstance(spec.get("version"), str)):
        raise SiblingError(f"{where} declares no spec.id and spec.version strings")
    return spec["id"], spec["version"]


def sibling_rows(readme):
    """Map each repository linked from a sibling-table row to that row."""
    lines = readme.splitlines()
    if HEADING not in lines:
        return {}
    start = lines.index(HEADING) + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")),
               len(lines))
    rows = {}
    for match in SIBLING_ROW.finditer("\n".join(lines[start:end])):
        rows.setdefault(match.group(1), match.group(0))
    return rows


def spec_cell(row):
    """The second cell of a table row, the Spec cell; "" when it has none."""
    cells = row.strip().strip("|").split("|")
    return cells[1].strip() if len(cells) > 1 else ""


def _version(name):
    """A numeric tag or release name as a tuple without trailing zeros."""
    found = re.fullmatch(r"v?(\d+(?:\.\d+)*)", name)
    if not found:
        return None
    parts = [int(p) for p in found.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def check(readme, siblings):
    """Return the failures for README text against `siblings`, a map of
    repository name to load_sibling() output."""
    rows = sibling_rows(readme)
    failures = []
    if not rows:
        return [f"no sibling rows found under `{HEADING}` in {SIBLINGS_PAGE_NAME}"]
    for repo in sorted({site[0] for site in COUNT_SITES} - set(rows)):
        failures.append(f"{SIBLINGS_PAGE_NAME} has no sibling-repositories row for {repo}")

    for repo, label, pattern, kind, prefix in COUNT_SITES:
        if repo not in rows:
            continue
        found = re.findall(pattern, rows[repo])
        if not found:
            failures.append(f"{repo} row states no {label}")
            continue
        data = siblings[repo]
        if kind == "verifiers":
            actual, where = len(data["verifiers"]), "verifiers/ directories"
        else:
            actual = sum(1 for n in data["fixtures"] if n.startswith(prefix))
            where = f"fixtures/{prefix}*.json files"
        for stated in found:
            if int(stated) != actual:
                failures.append(
                    f"{repo} row states {stated} as its {label}, but "
                    f"{ORG}/{repo} has {actual} {where}"
                )

    for repo, row in sorted(rows.items()):
        if repo not in siblings:
            failures.append(f"{repo} was not read; its row is unchecked")
            continue
        data = siblings[repo]
        for names in NAMED_VERIFIERS.findall(row):
            for name in names:
                if name.lower() not in data["verifiers"]:
                    failures.append(
                        f"{repo} row names a {name} verifier, but {ORG}/{repo} "
                        f"has no verifiers/{name.lower()}/"
                    )
        named = SPEC_VERSION.findall(spec_cell(row))
        declared = data.get("spec")
        if not named:
            failures.append(f"{repo} row's Spec cell names no spec version (`<ID> v<version>`)")
        elif declared is None:
            failures.append(f"{repo} declares no spec in its conformance.json; its Spec cell is unchecked")
        else:
            for spec_id, version in named:
                if (spec_id, version) != tuple(declared):
                    failures.append(
                        f"{repo} row's Spec cell names {spec_id} v{version}, but "
                        f"{ORG}/{repo} conformance.json declares {declared[0]} {declared[1]}"
                    )
        status = row.rstrip().rstrip("|").rsplit("|", 1)[-1]
        tagged = {_version(t) for t in data["tags"]} - {None}
        for release in RELEASE.findall(status):
            if _version(release) not in tagged:
                failures.append(
                    f"{repo} row names release {release}, but {ORG}/{repo} has "
                    f"no such tag (tags: {sorted(data['tags']) or 'none'})"
                )
    return failures


# --- self-test ---------------------------------------------------------------
#
# Each case alters one site of the published README and runs the real check()
# on it. A case is green only when the altered text yields a failure the
# unaltered text does not, so a README that is already stale does not make
# every case look red-as-expected. The sibling data the cases are checked
# against is built from the unaltered rows (offline_siblings), so the
# self-test needs no network and no GitHub login.

def offline_siblings(readme):
    """Sibling data, in load_sibling()'s form, under which each row of
    `readme` holds: the counts COUNT_SITES reads on it, the verifiers it names,
    the releases its Status cell names and the spec its Spec cell names.
    Stand-in names fill the counts."""
    rows = sibling_rows(readme)
    data = {repo: {"fixtures": [], "verifiers": [], "tags": [], "spec": None}
            for repo in set(rows) | {site[0] for site in COUNT_SITES}}
    for repo, row in rows.items():
        named = SPEC_VERSION.search(spec_cell(row))
        data[repo]["spec"] = named.groups() if named else None
        for names in NAMED_VERIFIERS.findall(row):
            data[repo]["verifiers"] += [n.lower() for n in names
                                        if n.lower() not in data[repo]["verifiers"]]
        status = row.rstrip().rstrip("|").rsplit("|", 1)[-1]
        data[repo]["tags"] += RELEASE.findall(status)
    # A count of every fixture ("" prefix) comes last, so it includes the
    # stand-ins the prefixed counts added.
    for repo, _label, pattern, kind, prefix in sorted(COUNT_SITES, key=lambda s: s[4] == ""):
        found = re.findall(pattern, rows.get(repo, ""))
        if not found:
            continue
        names = data[repo][kind]
        if kind == "verifiers":
            names += [f"stand-in-{i}" for i in range(len(names), int(found[0]))]
        else:
            have = sum(1 for n in names if n.startswith(prefix))
            names += [f"{prefix}stand-in-{i}.json" for i in range(have, int(found[0]))]
    return data


def _replace_row(readme, repo, new_row):
    old = sibling_rows(readme)[repo]
    return readme.replace(old, new_row, 1)


def self_test(readme, siblings, verbose):
    baseline = set(check(readme, siblings))

    def new_failures(text):
        return [f for f in check(text, siblings) if f not in baseline]

    rows = sibling_rows(readme)
    cases = []

    for i, (repo, label, pattern, _kind, _prefix) in enumerate(COUNT_SITES):
        case = f"{repo} {label}"
        match = re.search(pattern, rows.get(repo, ""))
        if match is None:
            cases.append((False, case, f"site not found in the {repo} row"))
            continue
        bad = str(9001 + i)
        row = rows[repo]
        altered = _replace_row(readme, repo, row[:match.start(1)] + bad + row[match.end(1):])
        new = new_failures(altered)
        cases.append((any(f"states {bad} " in f for f in new), case,
                      f"stating {bad} instead of {match.group(1)} still passes"))

    for repo, row in sorted(rows.items()):
        match = NAMED_VERIFIERS.search(row)
        if match is None:
            continue
        case = f"{repo} named verifier"
        altered = _replace_row(readme, repo,
                               row[:match.start(2)] + "Cobol" + row[match.end(2):])
        new = new_failures(altered)
        cases.append((any("verifiers/cobol/" in f for f in new), case,
                       f"naming a Cobol verifier still passes: {new}"))

    for repo, row in sorted(rows.items()):
        case = f"{repo} untagged release in Status"
        trimmed = row.rstrip()
        altered = _replace_row(readme, repo, trimmed[:-1].rstrip() + ", shipped at v99.0 |")
        new = new_failures(altered)
        cases.append((any("release v99.0" in f for f in new), case,
                       f"naming release v99.0 still passes: {new}"))

    for repo, row in sorted(rows.items()):
        cell = spec_cell(row)
        match = SPEC_VERSION.search(cell)
        case = f"{repo} Spec cell version"
        if match is None:
            cases.append((False, case, f"no `<ID> v<version>` in the {repo} Spec cell"))
            continue
        bad = "9.9.9-probe"
        altered = _replace_row(readme, repo, row.replace(
            cell, cell[:match.start(2)] + bad + cell[match.end(2):], 1))
        new = new_failures(altered)
        cases.append((any(f"Spec cell names {match.group(1)} v{bad}," in f for f in new), case,
                      f"naming {match.group(1)} v{bad} instead of v{match.group(2)} still passes: {new}"))

        case = f"{repo} Spec cell spec id"
        altered = _replace_row(readme, repo, row.replace(
            cell, cell[:match.start(1)] + "XYZ" + cell[match.end(1):], 1))
        new = new_failures(altered)
        cases.append((any(f"Spec cell names XYZ v{match.group(2)}," in f for f in new), case,
                      f"naming XYZ instead of {match.group(1)} still passes: {new}"))

        case = f"{repo} Spec cell with no version"
        altered = _replace_row(readme, repo, row.replace(
            cell, cell[:match.start(2) - 2] + cell[match.end(2):], 1))
        new = new_failures(altered)
        cases.append((any("Spec cell names no spec version" in f for f in new), case,
                      f"a Spec cell naming no version still passes: {new}"))

    for repo, before, retracted, expected in sorted(RETRACTED_ROWS):
        case = f"{repo} row as published before {before}"
        if repo not in rows:
            cases.append((False, case, f"no {repo} row to replace"))
            continue
        new = new_failures(_replace_row(readme, repo, retracted))
        cases.append((any(f.startswith(expected) for f in new), case,
                      f"the retracted row does not fail with {expected!r}: {new}"))

    for repo in sorted({site[0] for site in COUNT_SITES} & set(rows)):
        case = f"{repo} row removed"
        new = new_failures(readme.replace(rows[repo] + "\n", "", 1))
        expected = f"no sibling-repositories row for {repo}"
        cases.append((any(expected in f for f in new), case,
                      f"removing the row still passes: {new}"))

    failed = 0
    for ok, label, detail in cases:
        if verbose or not ok:
            print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        if not ok:
            print(f"          {detail}")
            failed += 1
    return failed, len(cases)


def main():
    usage = f"usage: {pathlib.Path(sys.argv[0]).name} [--self-test]"
    unknown = [a for a in sys.argv[1:] if a not in ("--self-test", "-h", "--help")]
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(usage, file=sys.stderr)
        return 2
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print(usage)
        return 0
    only_self_test = "--self-test" in sys.argv

    readme = SIBLINGS_PAGE.read_text(encoding="utf-8")
    failed, total = self_test(readme, offline_siblings(readme), only_self_test)
    if failed:
        print(f"self-test FAILED: {failed} of {total} case(s) not caught by the check",
              file=sys.stderr)
    else:
        print(f"self-test passed: the check fails on each of {total} altered sites")
    if only_self_test:
        return 1 if failed else 0

    repos = sorted(set(sibling_rows(readme)) | {site[0] for site in COUNT_SITES})
    siblings = {}
    try:
        for repo in repos:
            siblings[repo] = load_sibling(repo)
    except SiblingError as exc:
        sys.stdout.flush()
        print(f"cannot check the sibling rows: {exc}", file=sys.stderr)
        return 1

    failures = check(readme, siblings)
    if failures:
        sys.stdout.flush()
        print(f"{SIBLINGS_PAGE_NAME} sibling rows do not match the sibling "
              "repositories:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    if failed:
        return 1

    summary = ", ".join(
        f"{repo} ({len(siblings[repo]['fixtures'])} fixtures, "
        f"{len(siblings[repo]['verifiers'])} verifiers, "
        f"{len(siblings[repo]['tags'])} tags)"
        for repo in repos
    )
    print(f"{SIBLINGS_PAGE_NAME} sibling rows match the sibling repositories: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
