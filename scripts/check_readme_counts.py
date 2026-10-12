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

It also holds the README's two Ed25519 key-source lists to vectors/. Both
named RFC 8032 Tests 1, 2, 3 and 1024 only, while the trusted partner.example
key two fixtures sign with is derived from a SHA-256 label. Every key id the
fixtures name must be a vector's keyId, every Ed25519 vector's source must be
named in both lists, and an RFC 8032 source must cite the section its own ref
links (issuer-untrusted.json cited Test 1024 under §7.3; it is in §7.1).

It also holds the ATX versions the README says the suite covers, in the intro
paragraph and the `ATX schema` row of the version-pinning table, to the
versions the fixtures expect to ACCEPT. Both said "v1.0" alone while most
fixtures were v1.1 and the vendored schema was the v1.1 schema.

It also holds the Go verifier's stated dependencies to the direct requirements
of verifiers/go/go.mod, in the three places that state them: the dependency
list under the README's Go heading, the version-pinning table and the header
comment of verifiers/go/verify.go. All three named cloudflare/circl alone
while go.mod also required gowebpki/jcs.

It also holds what jcs-vectors/README.md and both copies of the vendored RFC
8785 serializer say about the Python verifier's dependencies to
verifiers/python/requirements.txt. All three called the verifier
zero-dependency while that file names cryptography and dilithium-py; the
serializer adds no dependency, but the verifier is not dependency-free.

It also holds every link to an opena2a-standards document in the README's
Version pinning table to a commit. The AIP row linked the repository and the
did:opena2a row linked the document on its default branch, so both stated
versions the documents had moved past: v1.0 while AIP-SPEC.md read
1.2.0-draft, and v0.1 with registration "filed" after the method reached 0.2
and was registered. A link at a commit names the bytes the stated version is
read from.

It also holds the README's "Reproducing the fixtures" steps to the generator
in scripts/generate-fixtures/main.go. The steps described only the v1.0
pipe-delimited payload while the v1.1 fixtures are signed over JCS(TBS), and
they never mentioned the generator's cross-check of those bytes against
jcs-vectors. The section must name every canonicalPayload* function the
generator defines and every jcs-vectors file it cross-checks against, and no
other.

It also holds what jcs-vectors/README.md, jcs-vectors/ts/package.json and
jcs-vectors/ts/check.mjs say about the TypeScript leg's library to RFC 8785.
All three called erdtman/canonicalize the RFC 8785 reference implementation,
while RFC 8785 designates none and lists canonicalize in Appendix G among the
open-source implementations verified to be compatible with JCS. Each must cite
Appendix G and must not call the library the reference implementation.

It also holds where README.md and COSIGNERS.md send readers to coordinate.
Both kept naming a2aproject/A2A#1876 as the place second-party
implementations and coordination are tracked after that issue was closed as
not planned; its re-file #1885 is closed too. A closed upstream issue may be
cited only with `(closed` written right after it and never in a sentence that
says something is tracked or coordinated there, and the implementations
section must link this repository's issue tracker.

It also holds what jcs-vectors/README.md, verifiers/python/verify.py and
jcs-vectors/pin/main.go say about the JSON numbers left in the v1.1 TBS to
the vectors' canonical strings. All three said `trustLevel` was the only one
while every vector also carries scanSummary.criticalFindings and
scanSummary.highFindings, and five carry behavioralProfile.observationDays.
None may name one member as the only JSON number while the vectors carry
another, the README must state that every JSON number left in the TBS is an
integer, and every number in every vector must be one.

It also holds what jcs-vectors/README.md says v1.1 signs to the explicit TBS
projection. It said "every future field" becomes integrity-protected while a
member the projection does not name stays unsigned: added after signing, it
leaves the signature valid and both verifiers report ACCEPT. The README must
not claim future fields are signed and must say a field is signed once the
spec adds it to the TBS projection.

Exit 0 when the self-test passes, every stated count matches the tree, the
byte check is named, the Scope table claims no threshold that no fixture
declares, the behavioralProfile note matches the fixtures, no criterion (c)
claim outruns the registry, the trustScore is called illustrative, the
trigger sentence matches the workflow, both key-source lists name every
Ed25519 key, both version labels name exactly the accepted versions, each
Go dependency site names every direct requirement (the two README sites at
its pinned version; the verify.go header states no versions, so it is held
to module names alone), no Python dependency site calls the Python verifier
zero-dependency while requirements.txt names a package, each jcs-vectors
file describing canonicalize cites RFC 8785 Appendix G and calls it no
reference implementation, every Version pinning link names a commit, the
reproduction steps match the generator, no coordination link points at a
closed issue, every statement of the TBS numbers matches the vectors and
the jcs-vectors README scopes signing to the TBS projection, 1 otherwise,
2 on an unknown argument.
"""

import collections
import json
import pathlib
import re
import sys
import time

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

# jcs-vectors/README.md said v1.1 signing makes "every future field"
# integrity-protected. The TBS is an explicit projection: a member it does not
# name is unsigned, so a field added after signing leaves the signature valid
# and both verifiers report ACCEPT. A field is signed only once the spec adds it
# to the projection. Matched over whitespace-collapsed text.
JCS_README = ROOT / "jcs-vectors" / "README.md"
JCS_README_NAME = "jcs-vectors/README.md"
FUTURE_FIELD_CLAIM = re.compile(
    r"\b(?:every|any|all)\s+(?:future|new|later|unknown|added)\s+fields?\b",
    re.IGNORECASE,
)
# The sentence jcs-vectors/README.md published, with its original line wrap.
RETRACTED_FUTURE_CLAIM = (
    "`publisher`, and every future field become integrity-protected"
)
JCS_PROJECTION_RULE = re.compile(
    r"\bfield the spec adds to the TBS\s+projection\b", re.IGNORECASE
)

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

# Each Ed25519 keypair the generator signs with is a vectors/*.json file whose
# `provenance.source` says where its seed comes from, and the README restates
# those sources in two places. Both listed RFC 8032 Tests 1, 2, 3 and 1024 only,
# while the trusted `partner.example` key two fixtures sign with is derived from
# a SHA-256 label. Each site must name every vector's source: an RFC 8032
# vector by its section and test number, any other vector by its source string.
VECTORS = ROOT / "vectors"
KEY_SOURCE_SITES = (
    ("README fixture conventions list",
     re.compile(r"^- Ed25519 keypair sources?:.*$", re.M)),
    ("README version-pinning table",
     re.compile(r"^\| Ed25519 keypair sources? \|.*$", re.M)),
)
RFC8032_SOURCE = re.compile(r"^RFC 8032 §(\d+(?:\.\d+)*)\b.*?\bTest (\d+)\b")
RFC8032_REF = re.compile(r"/rfc8032#section-(\d+(?:\.\d+)*)$")
# "Test 1", "Tests 2 / 3", "Tests 2 and 3", "Tests 1, 2, 3, 1024".
TEST_LIST = re.compile(r"\bTests?\s+(\d+(?:\s*(?:,|/|and)\s*\d+)*)")
# issuer-untrusted.json cited Test 1024 under §7.3, which holds the Ed25519ph
# vectors, while its own `ref` linked §7.1, where Test 1024 is. A source is
# held to the section its ref links.
RETRACTED_KEY_SOURCE = "RFC 8032 §7.3 Abbreviated Test 1024 (first 32 bytes)"
AUTHORITY_KEY_ID = re.compile(r"did:opena2a:authority:[\w.-]+#[\w-]+")


def load_key_vectors(root):
    """Return (vectors, failures): one dict per vectors/*.json file with its
    name, algorithm, keyId and provenance source and ref."""
    vectors, failures = [], []
    for path in sorted((root / "vectors").glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            failures.append(f"vectors/{path.name} cannot be read as JSON ({exc})")
            continue
        if not isinstance(doc, dict):
            failures.append(f"vectors/{path.name} is not a JSON object")
            continue
        prov = doc.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        vectors.append({
            "name": path.name,
            "algorithm": doc.get("algorithm"),
            "keyId": doc.get("keyId"),
            "source": prov.get("source"),
            "ref": prov.get("ref"),
        })
    return vectors, failures


def fixture_key_ids(paths):
    """Every authority key id named anywhere in the given fixture files."""
    ids = set()
    for path in paths:
        ids.update(AUTHORITY_KEY_ID.findall(path.read_text(encoding="utf-8")))
    return ids


def key_source_failures(readme, vectors, used_key_ids):
    """Check every Ed25519 vector's provenance, and that both README key-source
    sites name it. `used_key_ids` are the key ids the fixtures name; each must
    be the keyId of a vector, or the key it names has no listed source."""
    failures = []
    known = {v["keyId"] for v in vectors}
    for key_id in sorted(used_key_ids - known):
        failures.append(f"fixtures name key {key_id}, which no vectors/*.json "
                        "provides, so its source is listed nowhere")
    ed25519 = [v for v in vectors if v["algorithm"] == "Ed25519"]
    if not ed25519:
        return failures + ["no Ed25519 keypair found in vectors/; refusing to "
                           "pass vacuously"]

    sites = []
    for label, pattern in KEY_SOURCE_SITES:
        found = pattern.findall(readme)
        if not found:
            failures.append(f"no {label} row found in README (pattern "
                            f"{pattern.pattern!r})")
        sites.extend((label, line) for line in found)

    for v in ed25519:
        where = f"vectors/{v['name']}"
        source = v["source"]
        if not isinstance(source, str) or not source.strip():
            failures.append(f"{where} has no provenance.source")
            continue
        rfc = RFC8032_SOURCE.match(source)
        if source.startswith("RFC 8032") and not rfc:
            failures.append(f"{where} source {source!r} names no `§N Test N`")
            continue
        if rfc:
            section, test = rfc.groups()
            link = RFC8032_REF.search(v["ref"] or "")
            if not link:
                failures.append(f"{where} cites RFC 8032 §{section} but its ref "
                                "links no RFC 8032 section")
            elif link.group(1) != section:
                failures.append(f"{where} cites RFC 8032 §{section} but its ref "
                                f"links §{link.group(1)}")
        for label, line in sites:
            if rfc:
                tests = {n for group in TEST_LIST.findall(line)
                         for n in re.findall(r"\d+", group)}
                named = f"RFC 8032 §{section}" in line and test in tests
                want = f"RFC 8032 §{section} Test {test}"
            else:
                named = source in line
                want = source
            if not named:
                failures.append(f"{label} does not name the key source of "
                                f"{where} ({v['keyId']}): {want}")
    return failures


# The two places a reader learns which ATX versions this suite covers. Both
# read "v1.0" while the fixtures, the vendored schema and the pinned spec were
# also v1.1. A version is covered when some fixture expects a credential of
# that atcVersion to ACCEPT: malformed-schema.json carries "2.0" only so that
# it is rejected as unsupported.
VERSION_PINNING = "## Version pinning"
SCHEMA_PIN_ROW = re.compile(r"^\| ATX schema \| ([^|\n]*) \|", re.M)
INTRO_SITE = "README intro paragraph"
PIN_SITE = f"README `{VERSION_PINNING}` `ATX schema` row"
ATX_VERSION = re.compile(r"\bv(\d+\.\d+)\b")

# The three places a reader learns what the Go verifier depends on. Each named
# cloudflare/circl alone after go.mod had come to require gowebpki/jcs for the
# v1.1 signed payload, so each is held to the direct requirements of go.mod.
GO_MOD = ROOT / "verifiers" / "go" / "go.mod"
VERIFY_GO = ROOT / "verifiers" / "go" / "verify.go"
GO_MOD_NAME = "verifiers/go/go.mod"
GO_HEADING = re.compile(r"^### Go\b.*$", re.M)
# A dependency-list item naming a module at a version: "- `<module> <version>`".
GO_MODULE_ITEM = re.compile(r"^- `([^`\s]+/[^`\s]+) (v[^`\s]+)`", re.M)
GO_PACKAGE_CLAUSE = re.compile(r"^package \w+", re.M)
GO_LIST_SITE = "README Go verifier dependency list"
GO_PIN_SITE = f"README `{VERSION_PINNING}` table"
GO_HEADER_SITE = "verifiers/go/verify.go header comment"


def accepted_versions(paths):
    """The atcVersion of every fixture whose expected verifyResult is ACCEPT."""
    versions = set()
    for path in paths:
        try:
            fx = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        atx = fx.get("atx") if isinstance(fx, dict) else None
        expected = fx.get("expected") if isinstance(fx, dict) else None
        if (isinstance(atx, dict) and isinstance(expected, dict)
                and expected.get("verifyResult") == "ACCEPT"
                and isinstance(atx.get("atcVersion"), str)):
            versions.add(atx["atcVersion"])
    return versions


def intro_paragraph(readme):
    """The first paragraph after the title, whitespace-collapsed, or None."""
    lines = readme.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("# ")]
    if not starts:
        return None
    para = []
    for line in lines[starts[0] + 1:]:
        if not line.strip():
            if para:
                break
            continue
        if line.startswith("#"):
            break
        para.append(line.strip())
    return " ".join(para) or None


def _versions(names):
    return " and ".join(f"v{v}" for v in sorted(names))


def version_label_failures(readme, versions):
    """Each README version label must name exactly the accepted versions."""
    if not versions:
        return ["no fixture expects a credential to ACCEPT; refusing to pass "
                "the README version labels vacuously"]
    pinning = section(readme, VERSION_PINNING)
    row = SCHEMA_PIN_ROW.search(pinning) if pinning is not None else None
    sites = ((INTRO_SITE, intro_paragraph(readme)),
             (PIN_SITE, row.group(1) if row else None))
    failures = []
    for where, text in sites:
        if text is None:
            failures.append(f"{where} not found; the ATX versions it names "
                            f"cannot be checked")
            continue
        named = set(ATX_VERSION.findall(text))
        problems = []
        if versions - named:
            problems.append(f"omits {_versions(versions - named)}")
        if named - versions:
            problems.append(f"names {_versions(named - versions)}, which no "
                            f"fixture expects to ACCEPT")
        if problems:
            failures.append(f"{where} {' and '.join(problems)}; the fixtures "
                            f"accept ATX {_versions(versions)}")
    return failures


def direct_requirements(go_mod):
    """Map each module a go.mod requires directly to its pinned version."""
    required = {}
    block = False
    for line in go_mod.splitlines():
        code, _, comment = line.partition("//")
        words = code.split()
        if words == ["require", "("]:
            block = True
            continue
        if words == [")"]:
            block = False
            continue
        if words[:1] == ["require"]:
            words = words[1:]
        elif not block:
            continue
        if len(words) == 2 and "indirect" not in comment:
            required[words[0]] = words[1]
    return required


def go_header(source):
    """The comment above a Go file's package clause."""
    clause = GO_PACKAGE_CLAUSE.search(source)
    return source[:clause.start()] if clause else ""


def _names(text, module):
    """Whether `text` names `module`, not a longer module name starting with it."""
    return re.search(re.escape(module) + r"(?![\w-])", text) is not None


def go_dependency_failures(readme, go_mod, verify_go):
    """Each place that states the Go verifier's dependencies must name every
    direct requirement of go.mod (None when a file is missing). The README
    sites state versions, so those must be the pinned ones; the verify.go
    header is prose, so it is checked for omissions only."""
    if go_mod is None:
        return [f"{GO_MOD_NAME} is missing; the Go verifier's stated "
                f"dependencies cannot be checked"]
    required = direct_requirements(go_mod)
    if not required:
        return [f"{GO_MOD_NAME} states no direct requirement; refusing to pass "
                f"the Go verifier's stated dependencies vacuously"]
    failures = []

    heading = GO_HEADING.search(readme)
    body = section(readme, heading.group(0)) if heading else None
    if body is None:
        failures.append(f"{GO_LIST_SITE} not found: README has no `### Go` section")
    else:
        listed = dict(GO_MODULE_ITEM.findall(body))
        for module, version in sorted(required.items()):
            if module not in listed:
                failures.append(f"{GO_LIST_SITE} omits `{module} {version}`, "
                                f"which {GO_MOD_NAME} requires")
            elif listed[module] != version:
                failures.append(f"{GO_LIST_SITE} states `{module} {listed[module]}` "
                                f"but {GO_MOD_NAME} pins {version}")
        for module in sorted(set(listed) - set(required)):
            failures.append(f"{GO_LIST_SITE} lists `{module}`, which "
                            f"{GO_MOD_NAME} does not require directly")

    pinning = section(readme, VERSION_PINNING)
    if pinning is None:
        failures.append(f"{GO_PIN_SITE} not found; the Go module versions it "
                        f"states cannot be checked")
    else:
        rows = [[c.strip() for c in line.strip().strip("|").split("|")]
                for line in pinning.splitlines() if line.startswith("|")]
        for module, version in sorted(required.items()):
            stated = [r[1] for r in rows if len(r) >= 3 and _names(r[2], module)]
            if not stated:
                failures.append(f"{GO_PIN_SITE} has no row for {module}, which "
                                f"{GO_MOD_NAME} pins at {version}")
            for found in stated:
                if found != version:
                    failures.append(f"{GO_PIN_SITE} states {module} {found} but "
                                    f"{GO_MOD_NAME} pins {version}")

    if verify_go is None:
        failures.append(f"{GO_HEADER_SITE} not found: verifiers/go/verify.go "
                        f"is missing")
    else:
        header = go_header(verify_go)
        for module in sorted(required):
            if not _names(header, module):
                failures.append(f"{GO_HEADER_SITE} does not name {module}, "
                                f"which {GO_MOD_NAME} requires")
    return failures


# The places that say what the vendored RFC 8785 serializer means for the
# Python verifier's dependencies: the jcs-vectors README's Python row and the
# docstring of each copy of the serializer. All three called the verifier
# zero-dependency while requirements.txt names cryptography and dilithium-py.
# The serializer adds no dependency; the verifier still has those two.
PY_REQUIREMENTS = ROOT / "verifiers" / "python" / "requirements.txt"
PY_REQUIREMENTS_NAME = "verifiers/python/requirements.txt"
PY_DEPENDENCY_SITES = (
    "jcs-vectors/README.md",
    "verifiers/python/rfc8785.py",
    "jcs-vectors/python/rfc8785.py",
)
# A requirement line opens with the package name; comments and `-r`-style
# options open with another character.
PY_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", re.M)
ZERO_DEPENDENCY = re.compile(r"\bzero[- ]dep", re.I)


def python_requirements(requirements):
    """The package names a requirements.txt lists, in order."""
    return PY_REQUIREMENT.findall(requirements)


def statements(text):
    """Each sentence of `text` on one line, and each table row as one."""
    for block in re.split(r"\n\s*\n", text):
        if block.lstrip().startswith("|"):
            yield from (line.strip() for line in block.splitlines())
        else:
            yield from re.split(r"(?<=[.!?])\s+", " ".join(block.split()))


def python_dependency_failures(requirements, texts):
    """No site may call the Python verifier zero-dependency while
    requirements.txt (None when missing) names a package. `texts` maps each of
    PY_DEPENDENCY_SITES to its text, None when the file is missing. A
    zero-dependency statement about the serializer alone is true and passes."""
    if requirements is None:
        return [f"{PY_REQUIREMENTS_NAME} is missing; the Python verifier's "
                f"stated dependencies cannot be checked"]
    packages = python_requirements(requirements)
    failures = []
    for site in PY_DEPENDENCY_SITES:
        text = texts.get(site)
        if text is None:
            failures.append(f"{site} is missing; what it says about the Python "
                            f"verifier's dependencies cannot be checked")
            continue
        for claim in statements(text):
            if (packages and ZERO_DEPENDENCY.search(claim)
                    and re.search(r"\bPython\b", claim)
                    and re.search(r"\bverifiers?\b", claim, re.I)):
                failures.append(f"{site} calls the Python verifier zero-dependency "
                                f"(\"{claim}\"), but {PY_REQUIREMENTS_NAME} requires "
                                f"{', '.join(packages)}")
    return failures


# The TypeScript leg of the JCS byte-agreement gate runs erdtman/canonicalize,
# and the three files that describe it called it the RFC 8785 reference
# implementation. RFC 8785 designates none: Appendix G lists canonicalize among
# the open-source implementations verified to be compatible with JCS. Each file
# is paired with the wording it published, with its original line wrap; the
# claim pattern must keep matching each, or the gate cannot fire on it.
JCS_LIBRARY_SITES = (
    ("jcs-vectors/README.md", "(erdtman, RFC 8785 reference impl)"),
    ("jcs-vectors/ts/package.json",
     "(erdtman/canonicalize, the RFC 8785 reference implementation)."),
    ("jcs-vectors/ts/check.mjs",
     "// from the vector's `tbs` object using erdtman/canonicalize (the RFC 8785\n"
     "// reference implementation, the same library the Secretless broker ATX verifier"),
)
JCS_REFERENCE_CLAIM = re.compile(
    r"\bRFC\s*8785(?:'s)?\s+reference\s+impl(?:ementation)?\b"
    r"|\breference\s+impl(?:ementation)?\s+(?:of|for)\s+RFC\s*8785\b",
    re.IGNORECASE,
)
JCS_APPENDIX_G = "RFC 8785 Appendix G"


def _flat_prose(text):
    """`text` with line-leading `//` and `#` markers removed and whitespace
    collapsed, so neither a line wrap nor a comment continuation splits a
    phrase."""
    return " ".join(re.sub(r"^\s*(?://+|#+)", "", text, flags=re.M).split())


def jcs_library_failures(sites):
    """Each file that describes the TypeScript leg's library (missing from
    `sites` when the file is) must say RFC 8785 Appendix G lists it, and must
    not call it the RFC 8785 reference implementation."""
    failures = []
    for path, retracted in JCS_LIBRARY_SITES:
        if not JCS_REFERENCE_CLAIM.search(_flat_prose(retracted)):
            failures.append(f"RFC 8785 reference claim pattern no longer matches "
                            f"the wording {path} published; the gate cannot fire")
        if path not in sites:
            failures.append(f"{path} is missing; what it says about canonicalize "
                            f"and RFC 8785 cannot be checked")
            continue
        flat = _flat_prose(sites[path])
        claim = JCS_REFERENCE_CLAIM.search(flat)
        if claim:
            failures.append(f"{path} calls canonicalize \"{claim.group(0)}\", but "
                            f"RFC 8785 designates no reference implementation; say "
                            f"it is listed in {JCS_APPENDIX_G}")
        if JCS_APPENDIX_G not in flat:
            failures.append(f"{path} does not say canonicalize is listed in "
                            f"{JCS_APPENDIX_G}")
    return failures


# Upstream A2A issues this suite once named as the place where second-party
# implementations and coordination are tracked. Both are closed: 1876 as not
# planned on 2026-06-15, and 1885, its re-file, on 2026-06-23. The README kept
# sending readers to 1876 for both after it closed. A mention may stay as a
# citation of where criterion (c) was stated, but only with `(closed` written
# right after it, and never in a sentence that says something is tracked,
# coordinated or happening there.
CLOSED_TRACKERS = ("1876", "1885")
_CLOSED = "|".join(CLOSED_TRACKERS)
# The link text is bounded: unbounded, every `[` in a run of them scanned to
# the end of the run, so a paragraph of 40,000 `[` took seconds.
LINK_TEXT_MAX = 200
CLOSED_TRACKER_REF = re.compile(
    rf"\[[^\]\n]{{0,{LINK_TEXT_MAX}}}\]\(https://github\.com/a2aproject/A2A/issues/({_CLOSED})\)"
    rf"|https://github\.com/a2aproject/A2A/issues/({_CLOSED})\b"
    rf"|`?(?:a2aproject/)?A2A#({_CLOSED})\b`?"
)
CLOSED_NOTE = re.compile(r"\s*\(closed\b", re.IGNORECASE)
TRACKING_CLAIM = re.compile(r"\b(?:tracked|tracking|coordinated|happens)\b", re.IGNORECASE)
# The two sentences README.md published after 1876 closed, with their original
# line wraps. The gate must keep failing each of them.
RETRACTED_TRACKING = (
    "Independent second-party implementations are tracked on the sibling issue\n"
    "[a2aproject/A2A#1876](https://github.com/a2aproject/A2A/issues/1876)."
)
RETRACTED_COORDINATION = (
    "Substantive coordination on the\n"
    "ATX wire format itself happens in "
    "[`opena2a-org/atx-spec`](https://github.com/opena2a-standards/atx-spec)\n"
    "and in the A2A coordination map on\n"
    "[a2aproject/A2A#1876](https://github.com/a2aproject/A2A/issues/1876)."
)
# The open location the implementations section must send readers to instead.
OPEN_TRACKER = "https://github.com/opena2a-standards/atx-conformance/issues"
IMPLEMENTATIONS = "## Implementations that validate against this suite"


def registry_cosigners(cosigners):
    """Return the Cosigner cell of every data row in the registry table, or
    None when the heading or the table header row cannot be found."""
    lines = cosigners.splitlines()
    try:
        start = [line.strip() for line in lines].index(REGISTRY_HEADING)
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


def jcs_scope_failures(jcs_readme):
    """Check that jcs-vectors/README.md scopes v1.1 signing to the TBS
    projection (None when the file is missing)."""
    if jcs_readme is None:
        return [f"{JCS_README_NAME} is missing; it states what v1.1 signs"]
    failures = []
    if not FUTURE_FIELD_CLAIM.search(" ".join(RETRACTED_FUTURE_CLAIM.split())):
        failures.append(
            "future-field claim pattern no longer matches the sentence it was "
            "written for; the gate cannot fire"
        )
    text = " ".join(jcs_readme.split())
    claim = FUTURE_FIELD_CLAIM.search(text)
    if claim:
        failures.append(
            f"{JCS_README_NAME} says \"{claim.group(0)}\" is signed, but the "
            "TBS is an explicit projection and a member it does not name stays "
            "unsigned; say \"any field the spec adds to the TBS projection\""
        )
    if not JCS_PROJECTION_RULE.search(text):
        failures.append(
            f"{JCS_README_NAME} does not say a field is signed once the spec "
            "adds it to the TBS projection"
        )
    return failures


def closed_tracker_mentions(name, text):
    """Mentions of a closed upstream issue in `text` that sit in a sentence
    sending the reader there to track or coordinate something, or that do not
    say the issue is closed. Matched per paragraph over whitespace-collapsed
    text so a line wrap cannot hide either."""
    failures = []
    for para in re.split(r"\n\s*\n", text):
        flat = " ".join(para.split())
        for ref in CLOSED_TRACKER_REF.finditer(flat):
            issue = f"a2aproject/A2A#{next(g for g in ref.groups() if g)}"
            start = flat.rfind(". ", 0, ref.start())
            end = flat.find(". ", ref.end())
            sentence = flat[start + 2 if start >= 0 else 0:end if end >= 0 else len(flat)]
            claim = TRACKING_CLAIM.search(sentence)
            if claim:
                failures.append(
                    f"{name} sends readers to {issue}, which is closed (the "
                    f"sentence says \"{claim.group(0)}\"); point them to this "
                    f"repository's issue tracker ({OPEN_TRACKER}) instead"
                )
            elif not CLOSED_NOTE.match(flat, ref.end()):
                failures.append(
                    f"{name} cites {issue} without saying it is closed; write "
                    f"`(closed ...)` right after it so no reader takes it for a "
                    f"live tracking location"
                )
    return failures


def tracker_failures(readme, cosigners):
    """Check README.md and COSIGNERS.md (None when missing) for coordination
    links that point at a closed upstream issue, and the README
    implementations section for a link to an open one."""
    failures = []
    for retracted in (RETRACTED_TRACKING, RETRACTED_COORDINATION):
        if not closed_tracker_mentions("x", retracted):
            failures.append(
                "closed-tracker pattern no longer matches a sentence it was "
                "written for; the gate cannot fire"
            )
    failures.extend(closed_tracker_mentions("README.md", readme))
    if cosigners is not None:
        failures.extend(closed_tracker_mentions("COSIGNERS.md", cosigners))
    implementations = section(readme, IMPLEMENTATIONS)
    if implementations is None:
        failures.append(f"no `{IMPLEMENTATIONS}` section found in README")
    elif OPEN_TRACKER not in implementations:
        failures.append(
            f"README `{IMPLEMENTATIONS}` does not link this repository's issue "
            f"tracker ({OPEN_TRACKER}), the open place to report a second-party "
            f"implementation or arrange a cosignature"
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
    start = next((i for i, line in enumerate(lines)
                  if re.match(r"""^(?:on|'on'|"on"):(?:\s|$)""", line)), None)
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


# A link to anything in an opena2a-standards repository, and the same link
# naming a file at a full commit id, optionally with a #fragment.
STANDARDS_LINK = re.compile(r"https://github\.com/opena2a-standards/[^\s()<>\[\]|]*")
PINNED_LINK = re.compile(
    r"https://github\.com/opena2a-standards/[^/\s]+/blob/[0-9a-f]{40}/[^\s()<>\[\]|#?]+"
    r"(?:#[^\s()<>\[\]|]*)?"
)


def version_pin_failures(readme):
    """Every opena2a-standards link in the Version pinning table that does
    not name a file at a commit, and the table missing or carrying no such
    link at all."""
    body = section(readme, VERSION_PINNING)
    if body is None:
        return [f"no `{VERSION_PINNING}` section found in README"]
    failures = []
    linked = 0
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        component = line.strip("|").split("|")[0].strip()
        for url in STANDARDS_LINK.findall(line):
            linked += 1
            if not PINNED_LINK.fullmatch(url):
                failures.append(
                    f"README Version pinning row {component!r} links {url} at no "
                    f"commit; link the document at the commit whose text states the "
                    f"version (.../blob/<40-hex commit>/<file>)"
                )
    if not linked:
        failures.append(
            f"README `{VERSION_PINNING}` links no opena2a-standards document; "
            f"refusing to pass vacuously"
        )
    return failures


# The README's account of how the generator signs. It described only the v1.0
# pipe-delimited payload while every v1.1 fixture is signed over JCS(TBS) by
# canonicalPayloadV11, and it never mentioned that the generator panics unless
# those bytes equal two jcs-vectors vectors. Both lists are read from the
# generator, so a new signing form or cross-check cannot go undocumented.
REPRODUCING = "## Reproducing the fixtures"
GENERATOR = pathlib.Path("scripts") / "generate-fixtures" / "main.go"
# A signing form the generator defines, and a canonical-bytes constant it
# compares a v1.1 credential against before it builds any fixture.
PAYLOAD_FUNC = re.compile(r"^func (canonicalPayload\w*)\(", re.M)
CROSS_CHECK_HEX = re.compile(r'^const (jcs\w*CanonicalHex) = "([0-9a-f]+)"', re.M)
NAMED_FUNC = re.compile(r"`(canonicalPayload\w*)`")
NAMED_VECTOR = re.compile(r"jcs-vectors/vectors/[\w.-]+\.json")


def generator_signing(root):
    """Read the fixture generator. Return (the canonicalPayload* functions it
    defines, the jcs-vectors file each jcs*CanonicalHex constant equals the
    expected.canonicalHex of, failures)."""
    try:
        src = (root / GENERATOR).read_text(encoding="utf-8")
    except OSError as exc:
        return [], [], [f"{GENERATOR.as_posix()} cannot be read ({exc})"]
    pinned = {}
    for path in sorted((root / "jcs-vectors" / "vectors").glob("*.json")):
        try:
            hex_ = json.loads(path.read_text(encoding="utf-8"))["expected"]["canonicalHex"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        pinned.setdefault(hex_, path.relative_to(root).as_posix())
    failures = []
    vectors = []
    for name, hex_ in CROSS_CHECK_HEX.findall(src):
        if hex_ in pinned:
            vectors.append(pinned[hex_])
        else:
            failures.append(
                f"{GENERATOR.as_posix()} constant {name} equals the "
                f"expected.canonicalHex of no jcs-vectors/vectors/*.json"
            )
    funcs = PAYLOAD_FUNC.findall(src)
    if not funcs:
        failures.append(
            f"{GENERATOR.as_posix()} defines no canonicalPayload* function; "
            f"refusing to pass vacuously"
        )
    return funcs, vectors, failures


def reproduction_failures(readme, signing):
    """The Reproducing the fixtures section must name every signing form the
    generator defines and every jcs-vectors vector it cross-checks against,
    and name no form or vector the generator does not have."""
    funcs, vectors, failures = signing
    failures = list(failures)
    body = section(readme, REPRODUCING)
    if body is None:
        return failures + [f"no `{REPRODUCING}` section found in README"]
    where = f"README `{REPRODUCING}`"
    for name in funcs:
        if f"`{name}`" not in body:
            failures.append(
                f"{where} does not name `{name}`, a canonical payload "
                f"{GENERATOR.as_posix()} signs fixtures over"
            )
    for name in sorted(set(NAMED_FUNC.findall(body)) - set(funcs)):
        failures.append(f"{where} names `{name}`, which {GENERATOR.as_posix()} does not define")
    for path in vectors:
        if path not in body:
            failures.append(
                f"{where} does not name {path}, a vector "
                f"{GENERATOR.as_posix()} cross-checks its v1.1 bytes against"
            )
    for path in sorted(set(NAMED_VECTOR.findall(body)) - set(vectors)):
        failures.append(
            f"{where} names {path}, which {GENERATOR.as_posix()} does not "
            f"cross-check against"
        )
    return failures


# jcs-vectors/README.md said `trustLevel` was the only JSON number left in the
# TBS, and the Python verifier and the vector pinner said the same in comments,
# while every vector also carries scanSummary.criticalFindings and
# scanSummary.highFindings as JSON numbers and five carry
# behavioralProfile.observationDays. The agreement argument rests on every one
# of them being an integer, so that is what the README must state, and no site
# may name one member as the only number unless the vectors carry no other.
# Each site is paired with the wording it published, with its original wrap.
TBS_NUMBER_SITES = (
    ("jcs-vectors/README.md",
     "`trustLevel` (an integer) is\n  the only JSON number left in the TBS"),
    ("verifiers/python/verify.py",
     "        # trustScore is string-encoded %.6f so trustLevel is the only JSON number."),
    ("jcs-vectors/pin/main.go",
     "// the float -> JCS-number cross-language hazard never arises). trustLevel is the\n"
     "// only JSON number in the TBS and is always an integer."),
)
INTEGER_SITE = "jcs-vectors/README.md"
INTEGER_CLAIM = "every JSON number left in the TBS is an integer"
# "`trustLevel` (an integer) is the only JSON number", matched over prose with
# comment markers and line wraps removed; group 1 is the member named.
ONLY_NUMBER_CLAIM = re.compile(
    r"`?(\w+)`?(?:\s+\([^)]*\))?\s+(?:is\s+)?the\s+only\s+JSON\s+number\b",
    re.IGNORECASE,
)


class _NonInteger(str):
    """A JSON number token with a fraction or an exponent."""


def _prose(text):
    """Collapse whitespace and drop line-leading `//` and `#` comment markers,
    so a claim wrapped across comment lines reads as one sentence."""
    return " ".join(re.sub(r"(?m)^\s*(?://+|#+)", " ", text).split())


def _tbs_numbers(value, path="", member=""):
    """Yield (path, member name, value) for every JSON number in a parsed TBS."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _tbs_numbers(item, f"{path}.{key}" if path else key, key)
    elif isinstance(value, list):
        for item in value:
            yield from _tbs_numbers(item, f"{path}[]", member)
    elif isinstance(value, _NonInteger) or (
            isinstance(value, int) and not isinstance(value, bool)):
        yield path, member, value


def load_canonical_strings(root):
    """Map each jcs-vectors/vectors/*.json name to its expected.canonicalString,
    or to None when the file has none."""
    canonical = {}
    for path in sorted((root / "jcs-vectors" / "vectors").glob("*.json")):
        try:
            text = json.loads(path.read_text(encoding="utf-8"))["expected"]["canonicalString"]
        except (OSError, ValueError, KeyError, TypeError):
            text = None
        canonical[path.name] = text if isinstance(text, str) else None
    return canonical


def tbs_number_failures(sites, canonical):
    """Hold each statement of which JSON numbers the TBS carries to the
    vectors' canonical strings. `sites` maps a TBS_NUMBER_SITES path to its
    text (None when missing); `canonical` is from load_canonical_strings."""
    if not canonical:
        return ["no jcs-vectors/vectors/*.json found; refusing to pass vacuously"]
    failures = []
    carriers = collections.defaultdict(set)
    members = set()
    for name, text in sorted(canonical.items()):
        try:
            tbs = json.loads(text, parse_float=_NonInteger)
        except (TypeError, ValueError):
            failures.append(f"jcs-vectors/vectors/{name} has no parseable "
                            f"expected.canonicalString")
            continue
        for path, member, value in _tbs_numbers(tbs):
            carriers[path].add(name)
            members.add(member)
            if isinstance(value, _NonInteger):
                failures.append(
                    f"jcs-vectors/vectors/{name}: TBS member {path} is the JSON "
                    f"number {value}, not an integer; {INTEGER_SITE} states "
                    f"{INTEGER_CLAIM}"
                )
    carried = ", ".join(f"{p} ({len(carriers[p])} of {len(canonical)})"
                        for p in sorted(carriers))
    for site, text in sites.items():
        if text is None:
            failures.append(f"{site} is missing; it states which JSON numbers "
                            f"the TBS carries")
            continue
        for claim in ONLY_NUMBER_CLAIM.finditer(_prose(text)):
            if members != {claim.group(1)}:
                failures.append(
                    f"{site} says `{claim.group(1)}` is the only JSON number in "
                    f"the TBS, but the vectors carry {len(carriers)}: {carried}; "
                    f"say {INTEGER_CLAIM}"
                )
    readme = sites.get(INTEGER_SITE)
    if readme is not None and INTEGER_CLAIM not in _prose(readme):
        failures.append(
            f"{INTEGER_SITE} does not state that {INTEGER_CLAIM}; it is what "
            f"cross-language agreement on the TBS numbers rests on"
        )
    return failures


def _tbs_number_cases(sites, canonical):
    """Restate each site's published only-number wording, drop the README's
    integer statement, and give one vector a fractional number; each must add
    a failure."""
    baseline = set(tbs_number_failures(sites, canonical))
    cases = []

    def new(altered_sites=sites, altered_canonical=canonical):
        return [f for f in tbs_number_failures(altered_sites, altered_canonical)
                if f not in baseline]

    for site, retracted in TBS_NUMBER_SITES:
        label = f"{site} naming `trustLevel` the only JSON number in the TBS"
        if sites.get(site) is None:
            cases.append((False, label, f"{site} not found"))
            continue
        altered = dict(sites)
        altered[site] = sites[site] + "\n" + retracted + "\n"
        got = new(altered_sites=altered)
        cases.append((any(f.startswith(f"{site} says `trustLevel`") for f in got),
                      label, f"appending its published wording still passes: {got}"))

    label = f"{INTEGER_SITE} not stating that {INTEGER_CLAIM}"
    readme = sites.get(INTEGER_SITE)
    if readme is None or INTEGER_CLAIM not in _prose(readme):
        cases.append((False, label, f"the statement is not in {INTEGER_SITE}"))
    else:
        altered = dict(sites)
        altered[INTEGER_SITE] = _prose(readme).replace(
            INTEGER_CLAIM, "every JSON number left in the TBS is small")
        got = new(altered_sites=altered)
        cases.append((any(f.startswith(f"{INTEGER_SITE} does not state") for f in got),
                      label, f"a README without it still passes: {got}"))

    label = "a vector whose TBS carries a fractional JSON number"
    name = next((n for n, t in sorted(canonical.items())
                 if t and re.search(r'"trustLevel":\d+', t)), None)
    if name is None:
        cases.append((False, label, "no vector carries an integer trustLevel"))
    else:
        altered = dict(canonical)
        altered[name] = re.sub(r'("trustLevel":\d+)', r"\g<1>.5", canonical[name], count=1)
        got = new(altered_canonical=altered)
        cases.append((any("not an integer" in f for f in got),
                      label, f"trustLevel 3.5 in {name} still passes: {got}"))
    return cases


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


def check(readme, cosigners, fixtures, vectors, signing):
    """Return the failures for README text, COSIGNERS text (None when the
    file is missing), the fixture map from load_fixtures, the JCS vector
    count and the generator reading from generator_signing."""
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

    failures.extend(version_pin_failures(readme))
    failures.extend(reproduction_failures(readme, signing))
    failures.extend(tracker_failures(readme, cosigners))
    return failures


# Everything the check reads from the tree, so one altered input can be run
# through the same checks main() runs.
Tree = collections.namedtuple("Tree", (
    "readme cosigners fixtures vectors signing fixture_paths workflow "
    "key_vectors used_key_ids versions go_mod verify_go py_requirements "
    "py_dependency_texts jcs_sites tbs_sites tbs_canonical jcs_readme"))


def tree_failures(tree):
    """Every failure the check reports for `tree`: check() and the checks run
    beside it. main() and the self-test's wiring cases both call this, so a
    check dropped from here fails a case instead of going unrun."""
    failures = check(tree.readme, tree.cosigners, tree.fixtures, tree.vectors, tree.signing)
    failures.extend(threshold_claims(tree.readme, tree.fixture_paths))
    failures.extend(behavioral_profile_failures(tree.readme, tree.fixture_paths))
    failures.extend(ci_trigger_failures(tree.readme, tree.workflow))
    failures.extend(key_source_failures(tree.readme, tree.key_vectors, tree.used_key_ids))
    failures.extend(version_label_failures(tree.readme, tree.versions))
    failures.extend(go_dependency_failures(tree.readme, tree.go_mod, tree.verify_go))
    failures.extend(python_dependency_failures(tree.py_requirements,
                                               tree.py_dependency_texts))
    failures.extend(jcs_library_failures(tree.jcs_sites))
    failures.extend(tbs_number_failures(tree.tbs_sites, tree.tbs_canonical))
    failures.extend(jcs_scope_failures(tree.jcs_readme))
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


def _key_source_cases(readme, vectors, used_key_ids):
    """Drop a key source from each README site, restore the retracted §7.3
    label, name an unknown key and empty vectors/ in memory;
    key_source_failures() must report each one."""
    baseline = set(key_source_failures(readme, vectors, used_key_ids))

    def case(label, altered_readme, altered_vectors, altered_ids, want):
        new = [f for f in key_source_failures(altered_readme, altered_vectors,
                                              altered_ids) if f not in baseline]
        if any(want in f for f in new):
            return True, label, ""
        return False, label, f"expected a failure containing {want!r}, got {new}"

    ed25519 = [v for v in vectors if v["algorithm"] == "Ed25519"
               and isinstance(v["source"], str)]
    derived = next((v for v in ed25519 if not RFC8032_SOURCE.match(v["source"])), None)
    rfc = max((v for v in ed25519 if RFC8032_SOURCE.match(v["source"])),
              key=lambda v: int(RFC8032_SOURCE.match(v["source"]).group(2)),
              default=None)

    cases = []
    for site_label, pattern in KEY_SOURCE_SITES:
        site = pattern.search(readme)
        for kind, v in (("derived", derived), ("RFC 8032", rfc)):
            label = f"{site_label} omitting the {kind} key source"
            if site is None or v is None:
                cases.append((False, label, f"no {site_label} row in README.md"
                              if site is None else f"no {kind} Ed25519 vector in vectors/"))
                continue
            line = site.group(0)
            if v is derived:
                cut = line.replace(v["source"], "")
            else:
                cut = re.sub(rf"\b{RFC8032_SOURCE.match(v['source']).group(2)}\b", "", line)
            altered = readme[:site.start()] + cut + readme[site.end():]
            cases.append(case(label, altered, vectors, used_key_ids,
                              f"{site_label} does not name the key source of "
                              f"vectors/{v['name']}"))

    label = "Test 1024 vector restored to the retracted §7.3 label"
    target = next((v for v in ed25519 if v["source"].startswith("RFC 8032")
                   and " Test 1024" in v["source"]), None)
    if target is None:
        cases.append((False, label, "no RFC 8032 Test 1024 vector in vectors/"))
    else:
        altered = [dict(v, source=RETRACTED_KEY_SOURCE) if v is target else v
                   for v in vectors]
        cases.append(case(label, readme, altered, used_key_ids,
                          f"vectors/{target['name']} cites RFC 8032 §7.3 but its "
                          "ref links §7.1"))

    cases.append(case("fixture naming a key no vector provides", readme, vectors,
                      used_key_ids | {"did:opena2a:authority:nobody.example#key-1"},
                      "nobody.example#key-1, which no vectors/*.json provides"))
    cases.append(case("vectors/ holding no Ed25519 keypair", readme,
                      [v for v in vectors if v["algorithm"] != "Ed25519"],
                      set(), "no Ed25519 keypair found in vectors/"))
    return cases


# (site name, pattern locating the site; group 1 is the text naming versions)
VERSION_SITES = (
    (INTRO_SITE, r"\A# [^\n]*\n+(.+?)(?=\n\s*\n)"),
    (PIN_SITE, r"^\| ATX schema \| ([^|\n]*) \|"),
)


def _version_cases(readme, versions):
    """Narrow each version label to its first version, then widen it with a
    version no fixture accepts; each must add a failure naming the site."""
    baseline = set(version_label_failures(readme, versions))
    cases = []
    for where, pattern in VERSION_SITES:
        match = re.search(pattern, readme, re.M | re.S)
        tokens = list(ATX_VERSION.finditer(match.group(1))) if match else []
        edits = (
            ("names only its first version",
             lambda s, t: s[:t[0].end()] + s[t[-1].end():]),
            ("names a version no fixture accepts",
             lambda s, t: s[:t[-1].end()] + ", v9.9" + s[t[-1].end():]),
        )
        for what, edit in edits:
            label = f"{where} {what}"
            if not tokens:
                cases.append((False, label, "site not found in README.md, or "
                              "it names no ATX version"))
                continue
            site = edit(match.group(1), tokens)
            altered = readme[:match.start(1)] + site + readme[match.end(1):]
            new = [f for f in version_label_failures(altered, versions)
                   if f not in baseline]
            cases.append((any(f.startswith(where) for f in new), label,
                          f"README.md reading {site!r} there still passes"))
    return cases


# A module and a version no go.mod here states, for the cases that invent one.
GO_INVENTED = "example.com/not/required"
GO_ALTERED_VERSION = "v9.9.9"


def _go_dependency_cases(readme, go_mod, verify_go):
    """Drop and restate each direct requirement at each site that states the
    Go verifier's dependencies, list a module go.mod does not require, and add
    a requirement no site names; each must add a failure naming the site."""
    if go_mod is None or verify_go is None:
        return [(False, "Go verifier dependency sites",
                 f"{GO_MOD_NAME} or verifiers/go/verify.go is missing")]
    baseline = set(go_dependency_failures(readme, go_mod, verify_go))
    cases = []

    def case(label, where, needle, readme=readme, go_mod=go_mod, verify_go=verify_go):
        new = [f for f in go_dependency_failures(readme, go_mod, verify_go)
               if f not in baseline]
        cases.append((any(f.startswith(where) and needle in f for f in new), label,
                      f"expected a {where} failure naming {needle}, got {new}"))

    def missing(label, name):
        cases.append((False, label, f"site not found in {name}: a dependency "
                                    f"stated there is not covered by this self-test"))

    parsed = direct_requirements(
        "require (\n\ta.example/m v1.0.0\n\tb.example/n v2.0.0 // indirect\n)\n"
        "require c.example/o v3.0.0\nrequire d.example/p v4.0.0 // indirect\n")
    cases.append((parsed == {"a.example/m": "v1.0.0", "c.example/o": "v3.0.0"},
                  "go.mod direct requirements, block and single-line forms",
                  f"read {parsed}"))

    go_at = readme.find("\n### Go")
    pin_at = readme.find(f"\n{VERSION_PINNING}\n")
    header = verify_go.partition("\npackage ")[0]
    for module in sorted(direct_requirements(go_mod)):
        name = re.escape(module)

        item = re.search(rf"^- `{name} ([^`\n]*)`[^\n]*\n", readme, re.M)
        if item is None:
            missing(f"{GO_LIST_SITE} entry for {module}", "README.md")
        else:
            case(f"{GO_LIST_SITE} without {module}", GO_LIST_SITE, module,
                 readme=readme[:item.start()] + readme[item.end():])
            case(f"{GO_LIST_SITE} stating another {module} version",
                 GO_LIST_SITE, GO_ALTERED_VERSION,
                 readme=readme[:item.start(1)] + GO_ALTERED_VERSION + readme[item.end(1):])

        row = re.compile(rf"^\|[^|\n]*\| ([^|\n]*) \|[^\n]*{name}[^\n]*\n", re.M)
        row = row.search(readme, pin_at + 1) if pin_at >= 0 else None
        if row is None:
            missing(f"{GO_PIN_SITE} row for {module}", "README.md")
        else:
            case(f"{GO_PIN_SITE} without the {module} row", GO_PIN_SITE, module,
                 readme=readme[:row.start()] + readme[row.end():])
            case(f"{GO_PIN_SITE} stating another {module} version",
                 GO_PIN_SITE, GO_ALTERED_VERSION,
                 readme=readme[:row.start(1)] + GO_ALTERED_VERSION + readme[row.end(1):])

        if module not in header:
            missing(f"{GO_HEADER_SITE} naming {module}", "verifiers/go/verify.go")
        else:
            case(f"{GO_HEADER_SITE} without {module}", GO_HEADER_SITE, module,
                 verify_go=verify_go.replace(module, "a module", 1))

    first = (re.compile(r"^- `[^\n]*\n", re.M).search(readme, go_at + 1)
             if go_at >= 0 else None)
    if first is None:
        missing(f"{GO_LIST_SITE}", "README.md")
    else:
        case(f"{GO_LIST_SITE} listing a module go.mod does not require",
             GO_LIST_SITE, GO_INVENTED,
             readme=(readme[:first.start()] + f"- `{GO_INVENTED} {GO_ALTERED_VERSION}`\n"
                     + readme[first.start():]))

    grown = go_mod + f"\nrequire {GO_INVENTED} {GO_ALTERED_VERSION}\n"
    for where in (GO_LIST_SITE, GO_PIN_SITE, GO_HEADER_SITE):
        case(f"{where} when go.mod gains a requirement", where, GO_INVENTED,
             go_mod=grown)
    return cases


# The two forms the zero-dependency claim was published in, with their
# original line wraps: the jcs-vectors README row and the serializer docstring.
RETRACTED_PY_CLAIMS = (
    "| Python | vendored `python/rfc8785.py` (stdlib only) | keeps the Python "
    "verifier zero-dependency |",
    "Standard-library only, so the Python ATX verifier keeps its zero-dependency\n"
    "offline promise.",
)


def _python_dependency_cases(requirements, texts):
    """Append each retracted zero-dependency claim to each site; each must add
    a failure naming the site. The same claim must pass when requirements.txt
    names no package, and a zero-dependency statement about the serializer
    alone must pass, so the check holds the claim to the file."""
    missing = [PY_REQUIREMENTS_NAME] if requirements is None else []
    missing += [s for s in PY_DEPENDENCY_SITES if texts.get(s) is None]
    if missing:
        return [(False, "Python verifier dependency sites",
                 f"{', '.join(missing)} missing")]
    baseline = collections.Counter(python_dependency_failures(requirements, texts))
    cases = []

    def appended(site, sentence):
        altered = dict(texts)
        altered[site] = texts[site] + "\n\n" + sentence + "\n"
        return altered

    def added(failures):
        # A multiset difference: a site that already states the claim reports
        # the appended copy as a second, identical failure.
        return list((collections.Counter(failures) - baseline).elements())

    parsed = python_requirements(
        "# pinned\ncryptography>=42.0.0\n\n-r more.txt\ndilithium-py>=1.1.0  # FIPS 204\n")
    cases.append((parsed == ["cryptography", "dilithium-py"],
                  "requirements.txt package names, comments and options aside",
                  f"read {parsed}"))

    for site in PY_DEPENDENCY_SITES:
        for claim in RETRACTED_PY_CLAIMS:
            new = added(python_dependency_failures(requirements, appended(site, claim)))
            cases.append((any(f.startswith(f"{site} calls the Python verifier") for f in new),
                          f"{site} calling the Python verifier zero-dependency: "
                          f"{claim.splitlines()[0][:40]}...",
                          f"appending the claim still passes: {new}"))

    site = PY_DEPENDENCY_SITES[0]
    for claim in RETRACTED_PY_CLAIMS:
        new = python_dependency_failures("# no packages\n", appended(site, claim))
        cases.append((not new, f"{site} zero-dependency claim with no package required: "
                               f"{claim.splitlines()[0][:40]}...",
                      f"expected no failure when {PY_REQUIREMENTS_NAME} names no "
                      f"package, got {new}"))
    serializer = "The vendored serializer itself is zero-dependency."
    new = added(python_dependency_failures(requirements, appended(site, serializer)))
    cases.append((not new, f"{site} calling the serializer alone zero-dependency",
                  f"a true statement about the serializer fails: {new}"))

    new = python_dependency_failures(None, texts)
    cases.append((any(f.startswith(f"{PY_REQUIREMENTS_NAME} is missing") for f in new),
                  f"{PY_REQUIREMENTS_NAME} missing",
                  f"a missing {PY_REQUIREMENTS_NAME} still passes: {new}"))
    return cases


def _jcs_library_cases(sites):
    """Restore each file's retracted reference claim beside its Appendix G
    citation, drop the citation, and remove the file; each must add a failure
    naming the file."""
    baseline = set(jcs_library_failures(sites))
    cases = []

    def case(label, altered, needle):
        new = [f for f in jcs_library_failures(altered) if f not in baseline]
        cases.append((any(needle in f for f in new), label,
                      f"expected a failure containing {needle!r}, got {new}"))

    for path, retracted in JCS_LIBRARY_SITES:
        text = sites.get(path)
        if text is None or JCS_APPENDIX_G not in text:
            cases.append((False, f"{path} citing {JCS_APPENDIX_G}",
                          f"no `{JCS_APPENDIX_G}` found in {path}"))
            continue
        case(f"{path} restored to the retracted reference claim",
             dict(sites, **{path: text + "\n" + retracted + "\n"}),
             f"{path} calls canonicalize")
        case(f"{path} not citing {JCS_APPENDIX_G}",
             dict(sites, **{path: text.replace(JCS_APPENDIX_G, "RFC 8785")}),
             f"{path} does not say canonicalize is listed in")
        case(f"{path} missing",
             {p: t for p, t in sites.items() if p != path},
             f"{path} is missing")
    return cases


def _pin_case(label, texts, run, edit, expect):
    """Alter the first link at a commit in the Version pinning table."""
    readme = texts["README.md"]
    start = readme.find(VERSION_PINNING + "\n")
    if start < 0:
        return False, label, f"no `{VERSION_PINNING}` section found in README.md"
    end = re.compile(r"^#{1,6} ", re.M).search(readme, start + len(VERSION_PINNING))
    link = PINNED_LINK.search(readme, start, end.start() if end else len(readme))
    if link is None:
        return False, label, f"no link at a commit found under `{VERSION_PINNING}` in README.md"
    url = edit(link.group(0))
    altered = dict(texts)
    altered["README.md"] = readme[:link.start()] + url + readme[link.end():]
    new = run(altered)
    want = expect(url)
    if any(want in f for f in new):
        return True, label, ""
    return False, label, f"expected a failure containing {want!r}, got {new}"


def _repro_case(label, texts, run, edit, expect):
    """Alter the body of the Reproducing the fixtures section."""
    readme = texts["README.md"]
    start = readme.find(REPRODUCING + "\n")
    if start < 0:
        return False, label, f"no `{REPRODUCING}` section found in README.md"
    start += len(REPRODUCING) + 1
    end = re.compile(r"^#{1,6} ", re.M).search(readme, start)
    end = end.start() if end else len(readme)
    body = edit(readme[start:end])
    if body == readme[start:end]:
        return False, label, f"nothing to alter under `{REPRODUCING}` in README.md"
    altered = dict(texts)
    altered["README.md"] = readme[:start] + body + readme[end:]
    new = run(altered)
    if any(expect in f for f in new):
        return True, label, ""
    return False, label, f"expected a failure containing {expect!r}, got {new}"


def _wiring_cases(tree):
    """Alter one input per check that tree_failures() runs and run it whole.
    The cases above call each check directly, so they stay green when main()
    stops running one; these fail instead."""
    baseline = set(tree_failures(tree))
    readme = tree.readme
    cases = []

    def case(label, want, **altered):
        new = [f for f in tree_failures(tree._replace(**altered)) if f not in baseline]
        cases.append((any(want in f for f in new), f"main() running the {label} check",
                      f"expected a failure containing {want!r}, got {new}"))

    row = FIXTURE_ROW.search(readme)
    if row is None:
        cases.append((False, "main() running the count check",
                      "no fixture-table row found in README.md"))
    else:
        end = readme.index("\n", row.start()) + 1
        case("count", f"has no row for fixtures/{row.group(1)}",
             readme=readme[:row.start()] + readme[end:])

    scope = re.search(r"^## Scope\n.*?^\|[-| ]+\|\n", readme, re.M | re.S)
    if scope is None:
        cases.append((False, "main() running the threshold check",
                      "no `## Scope` table found in README.md"))
    else:
        claim = "Threshold 2-of-3 cosignature path"
        case("threshold", f"lists {claim!r} as covered",
             readme=(readme[:scope.end()] + f"| {claim} | every fixture |\n"
                     + readme[scope.end():]),
             fixture_paths=[p for p in tree.fixture_paths if not declares_threshold(p)])

    case("behavioralProfile", "behavioralProfile is omitted",
         readme=readme.replace("- Behavioral profile validation.",
                               "- Behavioral profile validation. It is omitted.", 1))
    case("CI trigger", f"{WORKFLOW_NAME} is missing", workflow=None)
    case("key source", "nobody.example#key-1, which no vectors/*.json provides",
         used_key_ids=tree.used_key_ids | {"did:opena2a:authority:nobody.example#key-1"})
    case("version label", f"{INTRO_SITE} omits v9.9",
         versions=set(tree.versions) | {"9.9"})
    if tree.go_mod is None:
        cases.append((False, "main() running the Go dependency check",
                      f"{GO_MOD_NAME} is missing"))
    else:
        case("Go dependency", GO_INVENTED,
             go_mod=tree.go_mod + f"\nrequire {GO_INVENTED} {GO_ALTERED_VERSION}\n")
    site = PY_DEPENDENCY_SITES[0]
    if tree.py_dependency_texts.get(site) is None:
        cases.append((False, "main() running the Python dependency check",
                      f"{site} is missing"))
    else:
        case("Python dependency", f"{site} calls the Python verifier zero-dependency",
             py_requirements=(tree.py_requirements or "") + "\ncryptography\n",
             py_dependency_texts={**tree.py_dependency_texts,
                                  site: (tree.py_dependency_texts[site]
                                         + "\n\nThe Python verifier is zero-dependency.\n")})
    path, retracted = JCS_LIBRARY_SITES[0]
    case("RFC 8785 library", f"{path} calls canonicalize",
         jcs_sites={**tree.jcs_sites,
                    path: tree.jcs_sites.get(path, "") + "\n" + retracted + "\n"})
    site, retracted = TBS_NUMBER_SITES[0]
    case("TBS number", f"{site} says `trustLevel` is the only JSON number",
         tbs_sites={**tree.tbs_sites,
                    site: (tree.tbs_sites.get(site) or "") + "\n" + retracted + "\n"})
    case("signing scope", "is signed, but the TBS is an explicit projection",
         jcs_readme=(tree.jcs_readme or "") + "\n" + RETRACTED_FUTURE_CLAIM + ".\n")
    return cases


def self_test(tree, verbose):
    readme, cosigners, fixtures, vectors, signing = (
        tree.readme, tree.cosigners, tree.fixtures, tree.vectors, tree.signing)
    texts = {"README.md": readme, "COSIGNERS.md": cosigners or ""}
    baseline = set(check(readme, cosigners, fixtures, vectors, signing))

    def run(altered, cos=True, sig=signing):
        cos_text = altered["COSIGNERS.md"] if cos and cosigners is not None else None
        got = check(altered["README.md"], cos_text, fixtures, vectors, sig)
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

    cases.extend(_trigger_cases(readme, tree.workflow))
    cases.extend(_key_source_cases(readme, tree.key_vectors, tree.used_key_ids))
    cases.extend(_version_cases(readme, tree.versions))
    cases.extend(_go_dependency_cases(readme, tree.go_mod, tree.verify_go))
    cases.extend(_python_dependency_cases(tree.py_requirements, tree.py_dependency_texts))
    cases.extend(_jcs_library_cases(tree.jcs_sites))
    cases.extend(_wiring_cases(tree))

    cases.append(_pin_case(
        "version pinning link on a branch instead of a commit", texts, run,
        lambda url: re.sub(r"/blob/[0-9a-f]{40}/", "/blob/main/", url),
        lambda url: f"links {url} at no commit"))
    cases.append(_pin_case(
        "version pinning link to a repository instead of a document", texts, run,
        lambda url: url.split("/blob/")[0],
        lambda url: f"links {url} at no commit"))
    altered = dict(texts)
    altered["README.md"] = readme.replace(VERSION_PINNING + "\n", "## Versions\n", 1)
    new = run(altered)
    cases.append((any(f"no `{VERSION_PINNING}` section" in f for f in new),
                  "version pinning section removed",
                  f"a README without the section still passes: {new}"))

    funcs, vecs, _ = signing
    for name in funcs:
        cases.append(_repro_case(
            f"reproduction steps not naming `{name}`", texts, run,
            lambda body, n=name: body.replace(f"`{n}`", "the payload function"),
            f"does not name `{name}`"))
    for path in vecs:
        cases.append(_repro_case(
            f"reproduction steps not naming {path}", texts, run,
            lambda body, p=path: body.replace(p, "a jcs-vectors vector"),
            f"does not name {path}"))
    if vecs:
        cases.append(_repro_case(
            "reproduction steps naming a vector the generator does not cross-check",
            texts, run,
            lambda body: body.replace(vecs[0], "jcs-vectors/vectors/99-not-a-vector.json"),
            "names jcs-vectors/vectors/99-not-a-vector.json, which"))
    else:
        cases.append((False, "reproduction steps naming a vector the generator does not cross-check",
                      f"{GENERATOR.as_posix()} cross-checks against no jcs-vectors vector"))
    new = run(texts, sig=(funcs + ["canonicalPayloadV12"], vecs, []))
    cases.append((any("does not name `canonicalPayloadV12`" in f for f in new),
                  "generator signing form missing from the reproduction steps",
                  f"a generator form the README does not name still passes: {new}"))
    cases.append(_repro_case(
        "reproduction steps naming a signing form the generator does not define",
        texts, run,
        lambda body: body + "\nThe generator also signs over `canonicalPayloadV99`.\n",
        "names `canonicalPayloadV99`, which"))
    altered = dict(texts)
    altered["README.md"] = readme.replace(REPRODUCING + "\n", "## Regenerating\n", 1)
    new = run(altered)
    cases.append((any(f"no `{REPRODUCING}` section" in f for f in new),
                  "reproduction section removed",
                  f"a README without the section still passes: {new}"))

    label = "implementations section with no open tracker link"
    impl = readme.find(IMPLEMENTATIONS)
    nxt = readme.find("\n## ", impl + 1) if impl >= 0 else -1
    if impl < 0 or nxt < 0 or OPEN_TRACKER not in readme[impl:nxt]:
        cases.append((False, label, f"no `{OPEN_TRACKER}` link in the README "
                                    f"`{IMPLEMENTATIONS}` section"))
    else:
        altered = dict(texts)
        altered["README.md"] = (readme[:impl]
                                + readme[impl:nxt].replace(OPEN_TRACKER, "https://example.invalid/")
                                + readme[nxt:])
        new = run(altered)
        cases.append((any("does not link this repository's issue tracker" in f for f in new),
                      label, f"removing the link still passes: {new}"))

    for label, sentence in (
            ("README sending readers to closed A2A#1876 to track implementations",
             RETRACTED_TRACKING),
            ("README sending readers to closed A2A#1876 for coordination",
             RETRACTED_COORDINATION),
            ("README saying implementations are tracked on A2A#1876 while noting it closed",
             "Second-party implementations are tracked on\n"
             "[a2aproject/A2A#1876](https://github.com/a2aproject/A2A/issues/1876)\n"
             "(closed as not planned on 2026-06-15).")):
        altered = dict(texts)
        altered["README.md"] = readme + "\n" + sentence + "\n"
        new = run(altered)
        cases.append((any("sends readers to a2aproject/A2A#1876, which is closed" in f
                          for f in new),
                      label, f"appending it to README.md still passes: {new}"))

    citation = ("Criterion (c) was stated on\n"
                "[a2aproject/A2A#1885](https://github.com/a2aproject/A2A/issues/1885).")
    for name in ("README.md", "COSIGNERS.md"):
        altered = dict(texts)
        altered[name] = texts[name] + "\n" + citation + "\n"
        new = run(altered)
        cases.append((any(f"{name} cites a2aproject/A2A#1885 without saying it is closed" in f
                          for f in new),
                      f"{name} citing closed A2A#1885 with no `(closed` note",
                      f"appending the citation to {name} still passes: {new}"))

    # Linear in the run: about 0.2 s. Unbounded link text took 3.5 s or more.
    started = time.perf_counter()
    closed_tracker_mentions("README.md", "[" * 40000)
    took = time.perf_counter() - started
    cases.append((took < 1.5, "closed-tracker scan over a 40,000-character run of `[`",
                  f"took {took:.1f} s; the link-text match backtracks over the run"))
    cases.extend(_tbs_number_cases(tree.tbs_sites, tree.tbs_canonical))

    jcs_readme = tree.jcs_readme
    jcs_text = jcs_readme or ""
    jcs_baseline = set(jcs_scope_failures(jcs_readme))
    rule = JCS_PROJECTION_RULE.search(jcs_text)
    for label, altered, want in (
            (f"{JCS_README_NAME} saying every future field is signed",
             jcs_text + "\n" + RETRACTED_FUTURE_CLAIM + ".\n",
             "is signed, but the TBS is an explicit projection"),
            (f"{JCS_README_NAME} dropping the TBS projection rule",
             jcs_text[:rule.start()] + "field" + jcs_text[rule.end():] if rule else None,
             "does not say a field is signed once the spec adds it")):
        if altered is None:
            cases.append((False, label, f"no projection rule found in {JCS_README_NAME}"))
            continue
        new = [f for f in jcs_scope_failures(altered) if f not in jcs_baseline]
        cases.append((any(want in f for f in new), label,
                      f"the altered {JCS_README_NAME} still passes: {new}"))

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
    key_vectors, vector_failures = load_key_vectors(ROOT)
    failures += vector_failures
    fixture_paths = sorted(FIXTURES.glob("*.json"))
    tree = Tree(
        readme=README.read_text(encoding="utf-8"),
        cosigners=COSIGNERS.read_text(encoding="utf-8") if COSIGNERS.exists() else None,
        fixtures=fixtures,
        vectors=count_vectors(ROOT),
        signing=generator_signing(ROOT),
        fixture_paths=fixture_paths,
        workflow=WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else None,
        key_vectors=key_vectors,
        used_key_ids=fixture_key_ids(fixture_paths),
        versions=accepted_versions(fixture_paths),
        go_mod=GO_MOD.read_text(encoding="utf-8") if GO_MOD.exists() else None,
        verify_go=VERIFY_GO.read_text(encoding="utf-8") if VERIFY_GO.exists() else None,
        py_requirements=(PY_REQUIREMENTS.read_text(encoding="utf-8")
                         if PY_REQUIREMENTS.exists() else None),
        py_dependency_texts={
            site: (ROOT / site).read_text(encoding="utf-8") if (ROOT / site).exists() else None
            for site in PY_DEPENDENCY_SITES},
        jcs_sites={path: (ROOT / path).read_text(encoding="utf-8")
                   for path, _ in JCS_LIBRARY_SITES if (ROOT / path).exists()},
        tbs_sites={site: (ROOT / site).read_text(encoding="utf-8")
                   if (ROOT / site).exists() else None
                   for site, _ in TBS_NUMBER_SITES},
        tbs_canonical=load_canonical_strings(ROOT),
        jcs_readme=JCS_README.read_text(encoding="utf-8") if JCS_README.exists() else None,
    )

    failed, total = self_test(tree, only_self_test)
    if failed:
        print(f"self-test FAILED: {failed} of {total} case(s) not caught by the check",
              file=sys.stderr)
    else:
        print(f"self-test passed: the check fails on each of {total} altered count sites")
    if only_self_test:
        return 1 if failed else 0

    # The check runs even when the self-test failed: a site the self-test
    # cannot find is often a count the README dropped, and the check names it.
    failures += tree_failures(tree)

    if failures:
        sys.stdout.flush()
        print("README counts do not match the tree:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    if failed:
        return 1

    print(f"README and COSIGNERS counts match the tree: {len(fixtures)} fixtures "
          f"(each with one fixture-table row), {tree.vectors} JCS vectors, all stated "
          f"as passing; README names the MANIFEST.sha256 byte check; "
          f"behavioralProfile scope note matches; criterion (c) claim matches "
          f"the cosignature registry; trustScore is called illustrative; "
          f"CI trigger sentence matches {WORKFLOW_NAME}; "
          f"both README key-source lists name every Ed25519 key in vectors/; "
          f"intro and version-pinning row name ATX {_versions(tree.versions)}; "
          f"Go verifier dependency list, version-pinning rows and verify.go "
          f"header name every direct requirement of {GO_MOD_NAME}; "
          f"no jcs-vectors README or RFC 8785 serializer docstring calls the "
          f"Python verifier zero-dependency; "
          f"each jcs-vectors file describing canonicalize cites "
          f"{JCS_APPENDIX_G} and calls it no reference implementation; "
          f"every Version pinning link names a commit; "
          f"the reproduction steps name every signing form and jcs-vectors "
          f"cross-check in the generator; coordination links point at an open "
          f"issue tracker; every statement of the JSON numbers in the TBS "
          f"matches the {len(tree.tbs_canonical)} JCS vectors, all of them integers; "
          f"{JCS_README_NAME} scopes v1.1 signing to the TBS projection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
