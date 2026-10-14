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
  - every release version (`vX.Y`) in the row's Status cell is a tag there.
    Spec versions belong in the Spec cell and are not checked.

Every run starts with a self-test: each site is altered in memory, one at a
time, and the check must fail on it. The rows as published before this check
existed must fail too, so the check keeps firing on the text it was written
for.

It needs network access. It reads through `gh api` when the GitHub CLI is
installed, so the CLI's login applies; otherwise it reads anonymously, or
with GH_TOKEN when that is set.

Usage:
    python3 scripts/check_sibling_rows.py              # self-test, then the check
    python3 scripts/check_sibling_rows.py --self-test  # the self-test alone, per case

Exit 0 when the self-test passes and every sibling row matches its
repository, 1 otherwise (including when a repository cannot be read), 2 on an
unknown argument.
"""

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

# The rows README.md published before this check existed, each with the
# failure it must still produce.
RETRACTED_ROWS = {
    "atp-conformance": (
        "| [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) "
        "| ATP v1.0.0-rc1 protocol | 4 fixtures (discovery, trust-proof baseline, "
        "trust-proof hybrid, Signed Tree Head), same 2-verifier pair, "
        "`MANIFEST.sha256` pinned |",
        "atp-conformance row states 4 as its fixture count",
    ),
    "aip-conformance": (
        "| [`aip-conformance`](https://github.com/opena2a-standards/aip-conformance) "
        "| AIP v1.0.0-draft identity protocol | §6.4 (VC `AgentTrustCredential`) "
        "covered by cross-linking this repo's fixtures; §5.1 challenge-response "
        "covered by 4 dedicated fixtures + Go/Python verifiers shipped at v0.2 "
        "(2026-05-28, Decision 3-C) |",
        "aip-conformance row names release v0.2",
    ),
}


class SiblingError(Exception):
    pass


def fetch_json(path):
    """GET `path` (relative to the API root) through `gh api` when gh is
    installed, so its login applies; otherwise anonymously, or with GH_TOKEN."""
    if shutil.which("gh"):
        try:
            done = subprocess.run(["gh", "api", path], capture_output=True,
                                  text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SiblingError(f"could not read {path} through gh: {exc}") from exc
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
    return {"fixtures": sorted(fixtures), "verifiers": sorted(verifiers), "tags": tags}


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
# every case look red-as-expected.

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

    for repo, (retracted, expected) in sorted(RETRACTED_ROWS.items()):
        case = f"{repo} row as published before this check"
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
    unknown = [a for a in sys.argv[1:] if a != "--self-test"]
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(f"usage: {pathlib.Path(sys.argv[0]).name} [--self-test]", file=sys.stderr)
        return 2
    only_self_test = "--self-test" in sys.argv

    readme = SIBLINGS_PAGE.read_text(encoding="utf-8")
    repos = sorted(set(sibling_rows(readme)) | {site[0] for site in COUNT_SITES})
    siblings = {}
    try:
        for repo in repos:
            siblings[repo] = load_sibling(repo)
    except SiblingError as exc:
        print(f"cannot check the sibling rows: {exc}", file=sys.stderr)
        return 1

    failed, total = self_test(readme, siblings, only_self_test)
    if failed:
        print(f"self-test FAILED: {failed} of {total} case(s) not caught by the check",
              file=sys.stderr)
    else:
        print(f"self-test passed: the check fails on each of {total} altered sites")
    if only_self_test:
        return 1 if failed else 0

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
