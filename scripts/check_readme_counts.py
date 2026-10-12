#!/usr/bin/env python3
"""Assert the counts stated in README.md and COSIGNERS.md match the tree.

The README states the expected verifier result in two places: the continuous
verification list ("N pass, 0 fail") and the implementations table ("N / N
PASS"). Both are measurements over fixtures/, so they are enforced here
rather than maintained by hand. They drifted apart once already: the table
still claimed 11 / 11 after the fixture set had grown to 20.

The same holds for every other count the README states about this tree: the
repository layout ("the N conformance fixtures"), the expected-output line
("summary: N pass, 0 fail (N fixtures)"), the per-version breakdown and JCS
vector count in this repository's sibling-repositories row, and the fixture
table, which must carry exactly one row per fixtures/*.json. Only the first
two were gated once, so the layout still said 8 fixtures after the set passed
20, the table had lost a row, and a sibling row reading "99 vectors" passed.

The README's expected-output section also says what a verifier result does
and does not measure, so it must name the MANIFEST.sha256 byte check.

Every run starts with a self-test: each count-bearing site in the published
README and COSIGNERS.md is altered in memory, one at a time, and the check
must fail on it. A site the check cannot see is reported by name instead of
silently passing.

Usage:
    python3 scripts/check_readme_counts.py              # self-test, then the check
    python3 scripts/check_readme_counts.py --self-test  # the self-test alone, per case

The Scope table may name a k-of-n signature threshold as covered only when a
fixture's verifierState declares the count it requires (THRESHOLD_FIELD).

It also holds the README's scope note on `behavioralProfile` to the fixtures.
That note said the field was omitted from the fixtures while every v1.1
fixture carried it inside its signed bytes.

It also gates the README's criterion (c) claim against the cosignature
registry in COSIGNERS.md. The README said the suite "closes criterion (c)"
(peer-cosigned conformance fixtures) while the registry's only row was the CI
self-cosignature. Criterion (c) is closed by a second-party row, so the README
may state it as closed only once such a row is recorded.

It also holds the README's trust-scoring note to what the suite contains. The
README called each fixture's trustScore composite output from the AIP-SPEC
§6.1 9-factor algorithm while no fixture carries factor inputs, so it must
call the value illustrative and must not call it the algorithm's output.

It also holds the README's statement of when the gates run to the `on:`
block of .github/workflows/conformance.yml. The README said "on each push and
pull request" while the workflow runs on pushes to main only.

Exit 0 when the self-test passes, every stated count matches the tree, the
byte check is named, the Scope table claims no threshold that no fixture
declares, the behavioralProfile note matches the fixtures, no criterion (c)
claim outruns the registry, the trustScore is called illustrative and the
trigger sentence matches the workflow, 1
otherwise, 2 on an unknown argument.
"""

import collections
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
FIXTURES = ROOT / "fixtures"
JCS_VECTORS = ROOT / "jcs-vectors" / "vectors"
# COSIGNERS.md tells an external cosigner what to observe before they sign.
# It stated 15 while fixtures/ held 20, because only README.md was gated here.
# A number a stranger is asked to verify against is exactly the number that
# must not be maintained by hand.
COSIGNERS = ROOT / "COSIGNERS.md"
# The verifiers compare verdicts, not bytes: an edit outside a fixture's signed
# payload still reports PASS. The expected-output section once said a modified
# fixture "shows up as one or more FAIL lines", which sent a reader to the
# verifiers for a check only MANIFEST.sha256 performs.
EXPECTED_OUTPUT = "### Expected output"
BYTE_CHECK = "shasum -a 256 -c MANIFEST.sha256"

# The Scope table listed "Threshold 2-of-3 cosignature path" as covered while
# no fixture states a required signature count and neither reference verifier
# reads one: both require every declared signature to verify and at least one
# to be present, so the threshold credential cut to one of its three
# signatures is accepted. A covered row that names a threshold is therefore a
# claim with no fixture behind it until some verifierState carries this field.
THRESHOLD_FIELD = "requiredSignatures"
THRESHOLD_CLAIM = re.compile(r"threshold|\b(?:\d+|k)-of-(?:\d+|n)\b", re.IGNORECASE)

# The "What this suite does NOT verify" bullet on behavioral profiles. It runs
# from its lead-in to the next bullet or blank line.
BEHAVIORAL_BULLET = re.compile(
    r"^- Behavioral profile validation\.(.*?)(?=\n- |\n\s*\n|\Z)",
    re.MULTILINE | re.DOTALL,
)
# The sentence that bullet must carry while exactly the v1.1 fixtures hold the
# field. v1.1 signs JCS(TBS), whose projection includes behavioralProfile.
BEHAVIORAL_V11_CLAIM = "carried and signed in the v1.1 fixtures"

# A present-tense statement that criterion (c) is closed, matched over
# whitespace-collapsed text so a line wrap cannot hide it. The conditional
# form ("designed to close criterion (c) ... once") does not match.
CRITERION_C_CLAIM = re.compile(
    r"\b(?:closes|closed|satisfies|meets)\s+criterion\s+\(c\)"
    r"|\bcriterion\s+\(c\)\s+(?:is|has\s+been)\s+(?:closed|satisfied|met)\b",
    re.IGNORECASE,
)
# The sentence README.md published before a second-party cosignature existed,
# with its original line wrap. The claim pattern must keep matching it, or the
# gate has stopped being able to fire on the text it was written for.
RETRACTED_CLAIM = "It closes criterion (c)\non the OpenA2A maturity bar"
REGISTRY_HEADING = "## Cosignature registry"

# The README called each fixture's `trustScore` (87.5) "composite output from
# the 9-factor algorithm specified in AIP-SPEC §6.1". No fixture carries the
# factor inputs that would produce it, and AIP-SPEC §6.1 states the composite
# on 0.0 to 1.0 while the fixtures use 0 to 100. The value is a placeholder,
# so the README may reproduce the weights but not call the value their output.
# Matched over whitespace-collapsed text so a line wrap cannot hide it.
TRUST_SCORE_CLAIM = re.compile(
    r"\b(?:output|result|computed|calculated|produced|derived)\s+"
    r"(?:from|of|by|with|using)\s+the\s+9-factor\s+(?:algorithm|formula|model)",
    re.IGNORECASE,
)
# The sentence README.md published, with its original line wrap. The claim
# pattern must keep matching it, or the gate cannot fire on the text it was
# written for.
RETRACTED_TRUST_CLAIM = (
    "is composite\noutput from the 9-factor algorithm specified in AIP-SPEC §6.1"
)
TRUST_HEADING = "### Trust scoring: 9-factor reference"
TRUST_PLACEHOLDER = "illustrative"

# The README's continuous-verification section says when the gates run. It said
# "on each push and pull request" while the workflow runs on pull requests and
# on pushes to main only, so a push to any other branch without a pull request
# ran no gate. The sentence is held to the workflow's `on:` block.
WORKFLOW = ROOT / ".github" / "workflows" / "conformance.yml"
WORKFLOW_NAME = ".github/workflows/conformance.yml"
CONTINUOUS = "## Continuous verification"
# The wording published before the triggers were gated.
RETRACTED_TRIGGERS = "on each push and pull request"
# A claim that every push runs the gates. Only true when push has no branch
# filter; "every push to `main`" does not match.
EVERY_PUSH_CLAIM = re.compile(r"\b(?:each|every|any|all)\s+push(?:es)?\b(?!\s+to\s)",
                              re.IGNORECASE)


def registry_cosigners(cosigners):
    """Return the Cosigner cell of every data row in the registry table, or
    None when the heading or the table header row cannot be found."""
    lines = cosigners.splitlines()
    try:
        start = [l.strip() for l in lines].index(REGISTRY_HEADING)
    except ValueError:
        return None
    rows = []
    in_table = False
    for line in lines[start + 1:]:
        if not line.startswith("|"):
            if in_table:
                break
            continue
        in_table = True
        rows.append(line)
    if not rows or rows[0].split("|")[1].strip() != "Cosigner":
        return None
    return [
        r.split("|")[1].strip()
        for r in rows[1:]
        if not re.match(r"^\|\s*:?-", r)
    ]


def is_self_cosignature(cosigner):
    name = cosigner.lower()
    return name.startswith("opena2a") or "self-cosigned" in name


def criterion_c_failures(readme, cosigners):
    failures = []
    if not CRITERION_C_CLAIM.search(" ".join(RETRACTED_CLAIM.split())):
        failures.append(
            "criterion (c) claim pattern no longer matches the sentence it was "
            "written for; the gate cannot fire"
        )
    rows = registry_cosigners(cosigners)
    if rows is None:
        failures.append(
            f"COSIGNERS.md has no `{REGISTRY_HEADING}` table with a Cosigner "
            "column; the criterion (c) claim cannot be checked"
        )
        return failures
    second_party = [r for r in rows if not is_self_cosignature(r)]
    claim = CRITERION_C_CLAIM.search(" ".join(readme.split()))
    if claim and not second_party:
        failures.append(
            f"README states \"{claim.group(0)}\" but the COSIGNERS.md registry "
            "records no second-party cosignature (self-cosignatures do not "
            "count); state it as designed to close criterion (c) once one is "
            "recorded"
        )
    return failures


def trust_score_failures(readme):
    """Check that the README calls the fixture trustScore a placeholder."""
    failures = []
    if not TRUST_SCORE_CLAIM.search(" ".join(RETRACTED_TRUST_CLAIM.split())):
        failures.append(
            "trustScore claim pattern no longer matches the sentence it was "
            "written for; the gate cannot fire"
        )
    claim = TRUST_SCORE_CLAIM.search(" ".join(readme.split()))
    if claim:
        failures.append(
            f"README states the fixture trustScore is \"{claim.group(0)}\", but "
            "no fixture carries factor inputs that produce it; call it an "
            "illustrative value"
        )
    body = section(readme, TRUST_HEADING)
    if body is None:
        failures.append(f"no `{TRUST_HEADING}` section found in README")
    elif TRUST_PLACEHOLDER not in body:
        failures.append(
            f"README `{TRUST_HEADING}` does not call the fixture trustScore "
            f"{TRUST_PLACEHOLDER}; nothing in this suite computes it"
        )
    return failures


def behavioral_profile_failures(readme, fixtures):
    """Check the README's behavioralProfile scope note against fixtures/."""
    carriers, v11 = set(), set()
    for path in fixtures:
        atx = json.loads(path.read_text(encoding="utf-8")).get("atx", {})
        if "behavioralProfile" in atx:
            carriers.add(path.name)
        if atx.get("atcVersion") == "1.1":
            v11.add(path.name)

    found = BEHAVIORAL_BULLET.search(readme)
    if not found:
        return ["no `- Behavioral profile validation.` scope note found in README"]
    note = re.sub(r"\s+", " ", found.group(1)).strip()

    failures = []
    if carriers and "omitted" in note:
        failures.append(
            f"README says behavioralProfile is omitted from the fixtures, but "
            f"{len(carriers)} of {len(fixtures)} carry it"
        )
    if not carriers:
        if "omitted" not in note:
            failures.append(
                "no fixture carries behavioralProfile, but the README scope note "
                "does not say it is omitted"
            )
    elif carriers == v11:
        if BEHAVIORAL_V11_CLAIM not in note:
            failures.append(
                f"exactly the {len(v11)} v1.1 fixtures carry behavioralProfile, "
                f"but the README scope note does not say "
                f"`{BEHAVIORAL_V11_CLAIM}`"
            )
    else:
        failures.append(
            "behavioralProfile is carried by a fixture set other than the v1.1 "
            "fixtures; restate the README scope note. Carried but not v1.1: "
            f"{sorted(carriers - v11)}; v1.1 but not carried: {sorted(v11 - carriers)}"
        )
    return failures


def declares_threshold(path):
    try:
        fx = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    state = fx.get("verifierState") if isinstance(fx, dict) else None
    return isinstance(state, dict) and THRESHOLD_FIELD in state


def threshold_claims(readme, fixtures):
    """Covered Scope-table rows that name a threshold no fixture declares."""
    if any(declares_threshold(p) for p in fixtures):
        return []
    scope = re.search(r"^## Scope\n(.*?)(?=^## )", readme, re.MULTILINE | re.DOTALL)
    if not scope:
        return ["no `## Scope` section found in README"]
    failures = []
    for line in scope.group(1).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|") or len(cells) < 2 or set(cells[0]) <= set("-"):
            continue
        if cells[1].lower().startswith("not covered"):
            continue
        if THRESHOLD_CLAIM.search(cells[0]):
            failures.append(
                f"README Scope table lists {cells[0]!r} as covered, but no "
                f"fixture's verifierState declares {THRESHOLD_FIELD}, so no "
                f"verifier is held to a threshold"
            )
    return failures


def _flow_list(value):
    """Parse a YAML scalar or flow sequence (`main`, `[main, dev]`)."""
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return [v.strip().strip("'\"") for v in value.split(",") if v.strip()]


def workflow_triggers(workflow):
    """Return {event: {filter: [value, ...]}} for the top-level `on:` key of
    the workflow text, or None when it has none. Covers the block form this
    repository uses and the inline `on: push` / `on: [push, pull_request]`
    forms; a filter listed as a block sequence is read item by item."""
    lines = workflow.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if re.match(r"""^(?:on|'on'|"on"):(?:\s|$)""", l)), None)
    if start is None:
        return None
    inline = lines[start].split(":", 1)[1].split("#", 1)[0].strip()
    if inline:
        return {event: {} for event in _flow_list(inline)}
    triggers = {}
    event = key = None
    event_indent = 0
    for line in lines[start + 1:]:
        text = line.split("#", 1)[0].rstrip()
        if not text.strip():
            continue
        if not line[0].isspace():
            break
        indent = len(text) - len(text.lstrip())
        body = text.strip()
        if body.startswith("- ") and event is not None and key is not None:
            triggers[event][key].append(body[2:].strip().strip("'\""))
            continue
        name, _, value = body.partition(":")
        if event is None or indent <= event_indent:
            event, event_indent, key = name.strip(), indent, None
            triggers[event] = {}
        else:
            key = name.strip()
            triggers[event][key] = _flow_list(value)
    return triggers


def trigger_phrase(triggers):
    """Return (phrase, problems): how the README must say when the gates run,
    e.g. "on every pull request and every push to `main`", or the triggers
    this check cannot phrase."""
    problems = [f"{WORKFLOW_NAME} triggers on `{e}`, which this check cannot "
                "phrase; extend trigger_phrase()"
                for e in sorted(set(triggers) - {"pull_request", "push"})]
    for event in ("pull_request", "push"):
        for key in sorted(set(triggers.get(event, {})) - {"branches"}):
            problems.append(f"{WORKFLOW_NAME} filters `{event}` by `{key}`, which "
                            "this check cannot phrase; extend trigger_phrase()")
    parts = []
    for event, noun, prep in (("pull_request", "pull request", "into"),
                              ("push", "push", "to")):
        if event not in triggers:
            continue
        branches = triggers[event].get("branches")
        if branches:
            parts.append(f"every {noun} {prep} "
                         + " or ".join(f"`{b}`" for b in branches))
        else:
            parts.append(f"every {noun}")
    if not parts:
        problems.append(f"{WORKFLOW_NAME} triggers on neither `push` nor "
                        "`pull_request`")
    return "on " + " and ".join(parts), problems


def ci_trigger_failures(readme, workflow):
    """Check the README's continuous-verification sentence against the
    workflow's triggers. `workflow` is the workflow text, None when missing."""
    if workflow is None:
        return [f"{WORKFLOW_NAME} is missing; the README's statement of when "
                "the gates run cannot be checked"]
    triggers = workflow_triggers(workflow)
    if not triggers:
        return [f"no `on:` triggers found in {WORKFLOW_NAME}"]
    phrase, problems = trigger_phrase(triggers)
    if problems:
        return problems
    body = section(readme, CONTINUOUS)
    if body is None:
        return [f"no `{CONTINUOUS}` section found in README"]
    text = " ".join(body.split())
    failures = []
    # The phrase must end where the clause ends, or "on every pull request and
    # every push" would be found inside "... every push to `main`".
    if not re.search(re.escape(phrase) + r"(?=[.,;:)]|$)", text):
        failures.append(
            f"README `{CONTINUOUS}` does not say the gates run \"{phrase}\", "
            f"which is what {WORKFLOW_NAME} triggers on"
        )
    if triggers.get("push", {}).get("branches"):
        for claim in EVERY_PUSH_CLAIM.finditer(text):
            failures.append(
                f"README `{CONTINUOUS}` says \"{claim.group(0)}\", but "
                f"{WORKFLOW_NAME} runs on pushes to "
                + " or ".join(f"`{b}`" for b in triggers["push"]["branches"])
                + " only"
            )
    return failures


def section(text, heading):
    """Return the body under `heading` up to the next heading, or None.

    Lines inside fenced code blocks are never headings, so a `# comment` in a
    shell example does not end the section early.
    """
    lines = text.splitlines()
    if heading not in lines:
        return None
    body = []
    fenced = False
    for line in lines[lines.index(heading) + 1:]:
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and re.match(r"#{1,6} ", line):
            break
        body.append(line)
    return "\n".join(body)

# The sibling-repositories table row that describes this repository.
THIS_REPO_ROW = re.compile(r"^\| `atx-conformance` \(this repo\) \|.*$", re.M)
# A row of the README fixture table: "| `fixtures/<name>` | <expected> | ...".
FIXTURE_ROW = re.compile(r"^\| `fixtures/([^`]+)` \|", re.M)
V1_1_PREFIX = "v1_1-"


def load_fixtures(root):
    """Map each fixtures/*.json name to whether its credential carries
    declaredPurpose. Returns (fixtures, failures)."""
    fixtures = {}
    failures = []
    for path in sorted((root / "fixtures").glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            failures.append(f"fixtures/{path.name} is not valid JSON ({exc})")
            fixtures[path.name] = False
            continue
        atx = doc.get("atx") if isinstance(doc, dict) else None
        fixtures[path.name] = isinstance(atx, dict) and "declaredPurpose" in atx
    return fixtures, failures


def count_vectors(root):
    return len(sorted((root / "jcs-vectors" / "vectors").glob("*.json")))


def _claims(failures, text, pattern, actual, missing, wrong):
    """Every number `pattern` captures in `text` must equal `actual`; at least
    one must be present. `wrong` formats the failure for a stated number."""
    found = re.findall(pattern, text)
    if not found:
        failures.append(missing)
    for stated in found:
        if int(stated) != actual:
            failures.append(wrong(stated))


def check(readme, cosigners, fixtures, vectors):
    """Return the failures for README text, COSIGNERS text (None when the
    file is missing), the fixture map from load_fixtures and the JCS vector
    count."""
    actual = len(fixtures)
    if actual == 0:
        return ["no fixtures found; refusing to pass vacuously"]
    v1_1 = [n for n in fixtures if n.startswith(V1_1_PREFIX)]
    v1_0 = actual - len(v1_1)
    purpose = sum(1 for n in v1_1 if fixtures[n])
    failures = []

    # Required, not optional. Guarding on existence meant deleting or renaming
    # the file made the whole block vanish while the success line still printed
    # "README and COSIGNERS counts match" -- a gate that reports on a file it
    # never opened.
    if cosigners is None:
        failures.append(
            "COSIGNERS.md is missing; it states the count an external cosigner "
            "is asked to observe and cannot go unchecked"
        )
    else:
        cos = re.findall(r"(\d+) pass, (\d+) fail", cosigners)
        if not cos:
            failures.append("no `N pass, 0 fail` claim found in COSIGNERS.md")
        for stated, failed in cos:
            if int(stated) != actual:
                failures.append(
                    f"COSIGNERS.md claims `{stated} pass` but fixtures/ holds {actual}"
                )
            if int(failed) != 0:
                failures.append(f"COSIGNERS.md claims `{failed} fail`, expected 0")
        for n in re.findall(r"\((\d+) fixtures\)", cosigners):
            if int(n) != actual:
                failures.append(
                    f"COSIGNERS.md claims ({n} fixtures) but fixtures/ holds {actual}"
                )
        failures.extend(criterion_c_failures(readme, cosigners))

    failures.extend(trust_score_failures(readme))

    # "must report `24 pass, 0 fail`" in the continuous-verification list and
    # "summary: 24 pass, 0 fail (24 fixtures)" under Expected output. Matching
    # only the backquoted form left the second one unchecked.
    pass_fail = re.findall(r"(\d+) pass, (\d+) fail", readme)
    if not pass_fail:
        failures.append("no `N pass, 0 fail` claim found in README")
    for stated, failed in pass_fail:
        if int(stated) != actual:
            failures.append(
                f"README claims `{stated} pass` but fixtures/ holds {actual}"
            )
        if int(failed) != 0:
            failures.append(f"README claims `{failed} fail`, expected 0")
    for n in re.findall(r"\((\d+) fixtures\)", readme):
        if int(n) != actual:
            failures.append(f"README claims ({n} fixtures) but fixtures/ holds {actual}")

    # "24 / 24 PASS" rows in the implementations table.
    table = re.findall(r"(\d+)\s*/\s*(\d+)\s+PASS", readme)
    if not table:
        failures.append("no `N / N PASS` row found in README")
    for got, total in table:
        if int(total) != actual:
            failures.append(
                f"README implementations table claims {got} / {total} PASS "
                f"but fixtures/ holds {actual}"
            )
        if got != total:
            failures.append(f"README table row {got} / {total} PASS is not a full pass")

    expected_output = section(readme, EXPECTED_OUTPUT)
    if expected_output is None:
        failures.append(f"no `{EXPECTED_OUTPUT}` section found in README")
    elif BYTE_CHECK not in expected_output:
        failures.append(
            f"README `{EXPECTED_OUTPUT}` does not name the byte check "
            f"`{BYTE_CHECK}`; the verifiers check verdicts, not bytes"
        )

    # "fixtures/   the 24 conformance fixtures" in the repository layout.
    _claims(
        failures, readme, r"\b(\d+) conformance fixtures\b", actual,
        "no `the N conformance fixtures` line found in the README repository layout",
        lambda n: f"README layout claims the {n} conformance fixtures "
                  f"but fixtures/ holds {actual}",
    )

    # "24 fixtures (10 v1.0, 14 v1.1 JCS incl. 6 declaredPurpose), ...
    # (8 vectors, Go/Python/TS)" in the sibling-repositories table.
    rows = THIS_REPO_ROW.findall(readme)
    if not rows:
        failures.append(
            "no `| `atx-conformance` (this repo) |` row found in the README "
            "sibling-repositories table"
        )
    where = "README sibling-repositories row for this repo"
    for row in rows:
        _claims(
            failures, row, r"\b(\d+) fixtures\b", actual,
            f"{where} states no `N fixtures` count",
            lambda n: f"{where} claims {n} fixtures but fixtures/ holds {actual}",
        )
        _claims(
            failures, row, r"\b(\d+) v1\.0\b", v1_0,
            f"{where} states no `N v1.0` count",
            lambda n: f"{where} claims {n} v1.0 fixtures but fixtures/ holds "
                      f"{v1_0} not named {V1_1_PREFIX}*.json",
        )
        _claims(
            failures, row, r"\b(\d+) v1\.1\b", len(v1_1),
            f"{where} states no `N v1.1` count",
            lambda n: f"{where} claims {n} v1.1 fixtures but fixtures/ holds "
                      f"{len(v1_1)} named {V1_1_PREFIX}*.json",
        )
        _claims(
            failures, row, r"\b(\d+) declaredPurpose\b", purpose,
            f"{where} states no `N declaredPurpose` count",
            lambda n: f"{where} claims {n} declaredPurpose fixtures but {purpose} "
                      f"v1.1 fixtures carry a declaredPurpose member",
        )
        _claims(
            failures, row, r"\b(\d+) vectors\b", vectors,
            f"{where} states no `N vectors` count",
            lambda n: f"{where} claims {n} vectors but jcs-vectors/vectors/ "
                      f"holds {vectors}",
        )

    # The fixture table: exactly one row per fixtures/*.json.
    listed = FIXTURE_ROW.findall(readme)
    if not listed:
        failures.append("no `| `fixtures/<name>` |` row found in the README fixture table")
    for name, times in sorted(collections.Counter(listed).items()):
        if times > 1:
            failures.append(f"README fixture table lists fixtures/{name} {times} times")
        if name not in fixtures:
            failures.append(
                f"README fixture table has a row for fixtures/{name}, "
                f"which is not in fixtures/"
            )
    for name in sorted(set(fixtures) - set(listed)):
        failures.append(f"README fixture table has no row for fixtures/{name}")

    return failures


# --- self-test ---------------------------------------------------------------
#
# Each case alters one site of the published text and runs the real check() on
# it. The sites are located by how a reader finds them, not by the patterns
# check() uses, so a count the check cannot see fails its case instead of
# passing unnoticed. A case is green only when the altered text yields a
# failure the unaltered text does not, so a README that is already stale does
# not make every case look red-as-expected.

# (label, file, pattern locating the site; group 1 is the number to alter)
NUMBER_SITES = (
    ("continuous verification `N pass, 0 fail`", "README.md",
     r"must report\s+`(\d+) pass"),
    ("expected output `summary: N pass`", "README.md", r"summary: (\d+) pass"),
    ("expected output `(N fixtures)`", "README.md", r"0 fail \((\d+) fixtures\)"),
    ("implementations table passed count", "README.md", r"\| (\d+) / \d+ PASS"),
    ("implementations table total", "README.md", r"\| \d+ / (\d+) PASS"),
    ("repository layout fixture count", "README.md", r"^fixtures/\s+the (\d+) "),
    ("sibling row fixture count", "README.md",
     r"^\| `atx-conformance` \(this repo\) \|[^|\n]*\| (\d+) "),
    ("sibling row v1.0 count", "README.md", r"\((\d+) v1\.0, "),
    ("sibling row v1.1 count", "README.md", r", (\d+) v1\.1 JCS"),
    ("sibling row declaredPurpose count", "README.md", r"incl\. (\d+) declaredPurpose"),
    ("sibling row JCS vector count", "README.md", r"\((\d+) vectors"),
    ("COSIGNERS observed `summary: N pass`", "COSIGNERS.md", r"summary: (\d+) pass"),
    ("COSIGNERS observed `(N fixtures)`", "COSIGNERS.md", r"0 fail \((\d+) fixtures\)"),
    ("COSIGNERS log `N pass, 0 fail`", "COSIGNERS.md", r"\| `(\d+) pass, 0 fail` \|"),
)


def _number_case(index, label, name, pattern, texts, run):
    match = re.search(pattern, texts[name], re.M)
    if match is None:
        return False, label, (f"site not found in {name}: a count stated there "
                              f"is not covered by this self-test")
    bad = str(9001 + index)
    altered = dict(texts)
    altered[name] = texts[name][:match.start(1)] + bad + texts[name][match.end(1):]
    new = run(altered)
    if any(bad in f for f in new):
        return True, label, ""
    return False, label, f"{name} stating {bad} instead of {match.group(1)} still passes"


def _row_case(label, texts, run, edit, expect):
    rows = list(FIXTURE_ROW.finditer(texts["README.md"]))
    if not rows:
        return False, label, "no fixture-table row found in README.md"
    readme = texts["README.md"]
    start = rows[0].start()
    end = readme.index("\n", start) + 1
    name = rows[0].group(1)
    altered = dict(texts)
    altered["README.md"] = readme[:start] + edit(readme[start:end], name) + readme[end:]
    new = run(altered)
    want = expect(name)
    if any(want in f for f in new):
        return True, label, ""
    return False, label, f"expected a failure containing {want!r}, got {new}"


def _trigger_cases(readme, workflow):
    """Alter the README trigger sentence or the workflow's `on:` block in
    memory; ci_trigger_failures() must report each one."""
    baseline = set(ci_trigger_failures(readme, workflow))

    def case(label, altered_readme, altered_workflow, want):
        new = [f for f in ci_trigger_failures(altered_readme, altered_workflow)
               if f not in baseline]
        if any(want in f for f in new):
            return True, label, ""
        return False, label, f"expected a failure containing {want!r}, got {new}"

    cases = []
    label = "README trigger sentence restored to the retracted wording"
    phrase = None
    if workflow is not None and workflow_triggers(workflow):
        phrase = trigger_phrase(workflow_triggers(workflow))[0]
    site = phrase and re.search(r"\s+".join(map(re.escape, phrase.split())), readme)
    if not site:
        missing = f"no trigger sentence ({phrase!r}) found in README.md"
        cases.append((False, label, missing))
        cases.append((False, "README trigger sentence overclaiming beside the right one",
                      missing))
    else:
        altered = readme[:site.start()] + RETRACTED_TRIGGERS + readme[site.end():]
        cases.append(case(label, altered, workflow, "does not say the gates run"))
        # The same sentence with the correct phrase appended after it: the
        # overclaim alone must still fail.
        altered = readme[:site.end()] + ", and " + RETRACTED_TRIGGERS + readme[site.end():]
        cases.append(case("README trigger sentence overclaiming beside the right one",
                          altered, workflow, "says \"each push\""))

    label = "workflow push trigger without a branch filter"
    branches = workflow and re.search(r"^(\s+push:[ \t]*\n)\s+branches:.*\n", workflow, re.M)
    if not branches:
        cases.append((False, label, f"no `push:` branch filter found in {WORKFLOW_NAME}"))
    else:
        altered = workflow[:branches.start()] + branches.group(1) + workflow[branches.end():]
        cases.append(case(label, readme, altered, "does not say the gates run"))

    label = "workflow triggering on an event the check cannot phrase"
    on = workflow and re.search(r"^on:[ \t]*\n", workflow, re.M)
    if not on:
        cases.append((False, label, f"no block `on:` key found in {WORKFLOW_NAME}"))
    else:
        altered = workflow[:on.end()] + "  workflow_dispatch:\n" + workflow[on.end():]
        cases.append(case(label, readme, altered, "cannot phrase"))

    cases.append(case(f"{WORKFLOW_NAME} missing", readme, None, "is missing"))
    return cases


def self_test(readme, cosigners, fixtures, vectors, verbose, workflow):
    texts = {"README.md": readme, "COSIGNERS.md": cosigners or ""}
    baseline = set(check(readme, cosigners, fixtures, vectors))

    def run(altered, cos=True):
        cos_text = altered["COSIGNERS.md"] if cos and cosigners is not None else None
        got = check(altered["README.md"], cos_text, fixtures, vectors)
        return [f for f in got if f not in baseline]

    cases = [_number_case(i, label, name, pattern, texts, run)
             for i, (label, name, pattern) in enumerate(NUMBER_SITES)]

    cases.append(_row_case(
        "fixture table missing a row", texts, run,
        lambda row, name: "",
        lambda name: f"has no row for fixtures/{name}"))
    cases.append(_row_case(
        "fixture table listing a row twice", texts, run,
        lambda row, name: row + row,
        lambda name: f"lists fixtures/{name} 2 times"))
    cases.append(_row_case(
        "fixture table row for a fixture that does not exist", texts, run,
        lambda row, name: row.replace(f"`fixtures/{name}`", "`fixtures/not-a-fixture.json`", 1),
        lambda name: "row for fixtures/not-a-fixture.json, which is not in fixtures/"))

    row = THIS_REPO_ROW.search(readme)
    if row is None:
        cases.append((False, "sibling row removed", "no this-repo row found in README.md"))
    else:
        altered = dict(texts)
        altered["README.md"] = readme[:row.start()] + readme[row.end():]
        new = run(altered)
        cases.append((any("(this repo) |` row found" in f for f in new),
                      "sibling row removed", f"removing the row still passes: {new}"))

    layout = re.search(r"^fixtures/\s+.*\n", readme, re.M)
    if layout is None:
        cases.append((False, "layout count removed", "no `fixtures/` layout line in README.md"))
    else:
        altered = dict(texts)
        altered["README.md"] = (readme[:layout.start()] + "fixtures/  the fixtures\n"
                                + readme[layout.end():])
        new = run(altered)
        cases.append((any("conformance fixtures` line found" in f for f in new),
                      "layout count removed", f"a layout line with no count still passes: {new}"))

    new = run(texts, cos=False)
    cases.append((any("COSIGNERS.md is missing" in f for f in new),
                  "COSIGNERS.md missing", f"a missing COSIGNERS.md still passes: {new}"))

    if TRUST_HEADING not in readme:
        cases.append((False, "trustScore called algorithm output",
                      f"no `{TRUST_HEADING}` heading in README.md"))
        cases.append((False, "trustScore not called illustrative",
                      f"no `{TRUST_HEADING}` heading in README.md"))
    else:
        start = readme.index(TRUST_HEADING) + len(TRUST_HEADING)
        altered = dict(texts)
        altered["README.md"] = (readme[:start] + "\n\nThe value " + RETRACTED_TRUST_CLAIM
                                + ".\n" + readme[start:])
        new = run(altered)
        cases.append((any("trustScore is" in f for f in new),
                      "trustScore called algorithm output",
                      f"the retracted trustScore sentence still passes: {new}"))
        body = section(readme, TRUST_HEADING)
        altered = dict(texts)
        altered["README.md"] = readme.replace(
            body, body.replace(TRUST_PLACEHOLDER, "computed"), 1)
        new = run(altered)
        cases.append((any(f"trustScore {TRUST_PLACEHOLDER}" in f for f in new),
                      "trustScore not called illustrative",
                      f"a section that drops `{TRUST_PLACEHOLDER}` still passes: {new}"))

    cases.extend(_trigger_cases(readme, workflow))

    failed = 0
    for ok, label, detail in cases:
        if verbose or not ok:
            print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        if not ok:
            print(f"          {detail}")
            failed += 1
    return failed, len(cases)


def main():
    # An unrecognised flag must not fall through to the default check and exit 0.
    unknown = [a for a in sys.argv[1:] if a != "--self-test"]
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(f"usage: {pathlib.Path(sys.argv[0]).name} [--self-test]", file=sys.stderr)
        return 2
    only_self_test = "--self-test" in sys.argv

    fixtures, failures = load_fixtures(ROOT)
    readme = README.read_text(encoding="utf-8")
    cosigners = COSIGNERS.read_text(encoding="utf-8") if COSIGNERS.exists() else None
    vectors = count_vectors(ROOT)
    workflow = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else None

    failed, total = self_test(readme, cosigners, fixtures, vectors, only_self_test,
                              workflow)
    if failed:
        print(f"self-test FAILED: {failed} of {total} case(s) not caught by the check",
              file=sys.stderr)
    else:
        print(f"self-test passed: the check fails on each of {total} altered count sites")
    if only_self_test:
        return 1 if failed else 0

    # The check runs even when the self-test failed: a site the self-test
    # cannot find is often a count the README dropped, and the check names it.
    failures += check(readme, cosigners, fixtures, vectors)
    fixture_paths = sorted(FIXTURES.glob("*.json"))
    failures.extend(threshold_claims(readme, fixture_paths))
    failures.extend(behavioral_profile_failures(readme, fixture_paths))
    failures.extend(ci_trigger_failures(readme, workflow))

    if failures:
        sys.stdout.flush()
        print("README counts do not match the tree:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    if failed:
        return 1

    print(f"README and COSIGNERS counts match the tree: {len(fixtures)} fixtures "
          f"(each with one fixture-table row), {vectors} JCS vectors, all stated "
          f"as passing; README names the MANIFEST.sha256 byte check; "
          f"behavioralProfile scope note matches; criterion (c) claim matches "
          f"the cosignature registry; trustScore is called illustrative; "
          f"CI trigger sentence matches {WORKFLOW_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
