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

The README's reference sections (the scope table and notes, the gates, the
fixture table, the dependency lists, the reproduction steps, the version
pins, the sibling rows and the repository layout) moved to the pages it
links, listed in README_PAGES. Every count and claim below is read from
README.md and those pages as one text, README.md first, so a passage that
moved is held where it now stands; "README" in a failure means that text.
The start-block capture in README.md states the expected result too, and is
checked with the other sites.

Every run starts with a self-test: each count-bearing site in the published
README and COSIGNERS.md is altered in memory, one at a time, and the check
must fail on it. A site the check cannot see is reported by name instead of
silently passing.

Those cases call the checks directly, so the self-test also runs this whole
script in a child process on a copy of the tree with one README count
altered, and that run must exit 1 naming the count: a main() that stopped
running the checks would exit 0 there. The child skips that one case
(CHECK_README_COUNTS_CHILD is set for it), so the runs do not nest.

Usage:
    python3 scripts/check_readme_counts.py              # self-test, then the check
    python3 scripts/check_readme_counts.py --self-test  # the self-test alone, per case
    python3 scripts/check_readme_counts.py --help       # the usage line

The Scope table may name a k-of-n signature threshold as covered only when a
fixture's verifierState declares the count it requires (THRESHOLD_FIELD).

A covered Scope row for signature verification that claims a set of fixtures
("every fixture", or "N of M") must state as "N of M" the count of fixtures
that reach signature verification (step 5); "every fixture" alone holds only
while no fixture rejects at steps 0 to 4.

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
of go.mod at the repository root (the module whose package
verifiers/go/verifier is the verifier), in the three places that state them:
the dependency list under the README's Go heading, the version-pinning table
and the header comment of verifiers/go/verifier/verify.go. All three named cloudflare/circl alone while go.mod
also required gowebpki/jcs.

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
jcs-vectors/README.md and jcs-vectors/pin/main.go called gowebpki/jcs, the Go
leg's library, a reference port in the same way; neither may.

It also holds what jcs-vectors/README.md and jcs-vectors/run-agreement.sh say
the byte-agreement gate runs. Both said it runs no code from another
repository while its Go and TypeScript legs run the modules
jcs-vectors/go.mod requires and the package jcs-vectors/ts/package.json
depends on. What both meant is that it runs no issuer, offline-verifier or
broker code.

It also holds how README.md and conformance.json describe that gate to the
legs jcs-vectors/run-agreement.sh runs. Both described it as agreement across
three canonicalizers after it began running each conformance verifier's own
v1.1 path over the vectors. Each description must name every verifiers/
directory the script runs a leg in.

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
scanSummary.highFindings, and four carry behavioralProfile.observationDays.
None may name one member as the only JSON number while the vectors carry
another, the README must state that every JSON number left in the TBS is an
integer, and every number in every vector must be one.

It also holds what jcs-vectors/README.md says v1.1 signs to the explicit TBS
projection. It said "every future field" becomes integrity-protected while a
member the projection does not name stays unsigned: added after signing, it
leaves the signature valid and both verifiers report ACCEPT. The README must
not claim future fields are signed and must say a field is signed once the
spec adds it to the TBS projection.

It also holds the scope page's count of ACCEPT fixtures that carry Ed25519
signatures only ("6 of its 8 ACCEPT fixtures") to the fixtures' expected
verifyResult and signature algorithms. Changed to "5 of its 9", it passed.

It also holds the repository layout's label of the scripts/*.py glob as CI
gates to the workflow. The layout called check_fixture_immutability.py a CI
gate while no workflow step ran it. A script the workflow runs neither by
name nor through a script it runs that imports it must have its own layout
line, and that line must not call it a CI gate. Only a name in the command of
a `run:` step, outside a shell comment, counts as run: a name anywhere in the
workflow file counted, so a YAML comment naming a script made it pass.

The criterion (c) claim is matched in more wordings than the one the README
used ("fulfils criterion (c)", "closes criterion c"), and a failure is
reported under a header that names claims as well as counts.

It also reads README.md alone, apart from the pages it links, and fails on
each line that states a three-part version or an ISO date (VERSION_OR_DATE).
README.md cited the day a2aproject/A2A#1876 closed above its first section
heading; that paragraph moved to docs/scope.md, as the version pins moved to
docs/version-pinning.md and the toolchain minimums to
docs/running-the-verifiers.md.

It also holds the README's `@<commit>` sentence to the history. The README
said `go run <module>/verifiers/go@<commit>` runs the verifier of "that
commit" while the form resolves only from the first commit whose go.mod at
the root declares the module; at the commit before it, `go run` exited 1.
Each sentence offering `@<commit>` must name its first commit ("for
`<commit>` or a later commit"). Where the checkout has full history, that
commit must be the oldest in HEAD's history whose go.mod declares the module
go.mod declares; a shallow clone, or a tree with no repository, is held to
the first half alone, and the closing line says so.

It also holds each `go run <module>/<dir>@latest` command in a fenced block
of the README and its pages to the history. README.md opened with
`go run <module>/verifiers/go@latest`, which exited 1 through the default
module proxy: before go.mod moved to the root, verifiers/go held a go.mod of
its own declaring another module path, the proxy answers
`<module>/verifiers/go@latest` with a version of that module it stored, and
the path mismatch stops `go run`. A stored version cannot be removed, so the
package such a command names must lie under no directory other than the root
whose go.mod appears in HEAD's history. A shallow clone, or a tree with no
repository, is not held to it, and the closing line says so. A README that
fails it is reported as this check's failure: the self-test's `@latest`
cases run on the README less each fenced line the check fails.

It also holds what CHANGELOG.md's Unreleased section names as README.md's
first command to README.md. That section said `go run
<module>/verifiers/go@latest` runs the Go verifier with nothing cloned and is
README.md's first command after README.md came to open with `go run
<module>/cmd/atx-verify@latest`, and the older command exits 1 through the
module proxy. Each `go run` code span in a sentence of that section that
names README.md's first command must be the first line of README.md's first
fenced block, with or without its `cd <dir> && ` prefix; `<module>` reads as
the module go.mod declares, and a span with another placeholder (`go run
<import path>@<version>`) names a form of command and is not held. The
sections below Unreleased record past commits and are not held to it.

Exit 0 when the self-test passes, every stated count matches the tree, the
byte check is named, the Scope table claims no threshold that no fixture
declares, each signature-verification Scope row that claims a set of fixtures
states the count that reach step 5, the behavioralProfile note matches the
fixtures, no criterion (c)
claim outruns the registry, the trustScore is called illustrative, the
trigger sentence matches the workflow, both key-source lists name every
Ed25519 key, both version labels name exactly the accepted versions, each
Go dependency site names every direct requirement (the two README sites at
its pinned version; the verify.go header states no versions, so it is held
to module names alone), each sentence offering `@<commit>` names its first
commit (the first with the module's go.mod at the root, where the history
can be read), each fenced `go run <module>/<dir>@latest` command names a
package under no directory that held a go.mod in HEAD's history (where the
history can be read), each `go run` command CHANGELOG.md's Unreleased section
names as README.md's first command is the one README.md opens with, no
Python dependency site calls the Python verifier
zero-dependency while requirements.txt names a package, each jcs-vectors
file describing canonicalize cites RFC 8785 Appendix G, none calls an RFC
8785 library a reference implementation or port, neither description of what
the byte-agreement gate runs says it runs no code from another repository,
every description of that gate names each verifier leg, every Version
pinning link names a commit, the reproduction steps match the generator, no
coordination link points at a closed issue, every statement of the TBS
numbers matches the vectors, the jcs-vectors README scopes signing to the
TBS projection, the Ed25519-only ACCEPT count matches the fixtures, the
workflow runs every script the layout calls a CI gate and README.md states no
version or date, 1 otherwise, 2 on an
unknown argument.
"""

import collections
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
# The pages README.md links that took its reference sections, read after it.
README_PAGES = tuple(pathlib.Path(p) for p in (
    "docs/scope.md",
    "docs/continuous-verification.md",
    "docs/fixtures.md",
    "docs/running-the-verifiers.md",
    "docs/reproducing-the-fixtures.md",
    "docs/version-pinning.md",
    "docs/versioning.md",
    "docs/sibling-repositories.md",
    "CONTRIBUTING.md",
))
# README.md read alone states no version or date; the pages above hold them.
# A three-part version (1.22.0, v0.4.1) or an ISO date (2026-10-01) matches.
# A two-part label such as "ATX v1.0" does not.
VERSION_OR_DATE = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+|20[0-9]{2}-[0-9]{2}-[0-9]{2}")
# The README.md line the pattern was written for, as it was wrapped. The
# pattern must keep matching it, or the gate cannot fire on that text.
RETRACTED_DATE_LINE = ('not planned on 2026-06-15), "peer-cosigned conformance '
                       'fixtures comparable to')
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

# The Scope table listed Ed25519 signature verification as covered by "every
# fixture" while some fixtures reject at steps 0 to 4 (strict parse, schema
# version, expiry, revocation, trusted issuer), so neither reference verifier
# checks their signatures. Which fixtures reach step 5 follows from each
# fixture's expected outcome: ACCEPT, or a reject category from step 5 on. A
# category placed in neither map fails the check rather than being guessed.
EARLY_REJECT_STEP = {
    "PARSE_ERROR": 0,
    "UNSUPPORTED_VERSION": 1,
    "EXPIRED": 2,
    "REVOKED": 3,
    "UNTRUSTED_ISSUER": 4,
}
SIGNATURE_STEP_REJECTS = {"SIGNATURE_INVALID"}
SIGNATURE_ROW = re.compile(r"signature verification", re.IGNORECASE)
EVERY_FIXTURE = re.compile(r"\b(?:every|all|each)\s+fixtures?\b", re.IGNORECASE)
N_OF_M = re.compile(r"\b(\d+) of (\d+)\b")

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
# whitespace-collapsed text so a line wrap cannot hide it. The criterion may
# be written with or without its parentheses. The conditional form ("designed
# to close criterion (c) ... once") does not match.
_CRITERION_C = r"criterion\s+(?:\(c\)|c\b)"
CRITERION_C_CLAIM = re.compile(
    r"\b(?:closes|closed|satisfies|satisfied|meets|met|fulfils|fulfills|fulfilled)\s+"
    + _CRITERION_C
    + r"|\b" + _CRITERION_C
    + r"\s+(?:is|has\s+been)\s+(?:closed|satisfied|met|fulfilled)\b",
    re.IGNORECASE,
)
# The sentence README.md published before a second-party cosignature existed,
# with its original line wrap. The claim pattern must keep matching it, or the
# gate has stopped being able to fire on the text it was written for.
RETRACTED_CLAIM = "It closes criterion (c)\non the OpenA2A maturity bar"
# Other wordings of the same claim. The pattern missed the first two.
CRITERION_C_SYNONYMS = (
    "It fulfils criterion (c) on the OpenA2A maturity bar",
    "It closes criterion c on the OpenA2A maturity bar",
    "It fulfills\ncriterion (c)",
    "Criterion (c) has been met",
)
# The README's own wording, which states the claim as conditional.
CRITERION_C_CONDITIONAL = "It is designed to close\ncriterion (c) on the OpenA2A maturity bar"
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
GO_MOD = ROOT / "go.mod"
VERIFY_GO = ROOT / "verifiers" / "go" / "verifier" / "verify.go"
GO_MOD_NAME = "go.mod"
GO_HEADING = re.compile(r"^### Go\b.*$", re.M)
# A dependency-list item naming a module at a version: "- `<module> <version>`".
GO_MODULE_ITEM = re.compile(r"^- `([^`\s]+/[^`\s]+) (v[^`\s]+)`", re.M)
GO_PACKAGE_CLAUSE = re.compile(r"^package \w+", re.M)
GO_LIST_SITE = "README Go verifier dependency list"
GO_PIN_SITE = f"README `{VERSION_PINNING}` table"
GO_HEADER_SITE = "verifiers/go/verifier/verify.go header comment"


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
        failures.append(f"{GO_HEADER_SITE} not found: verifiers/go/verifier/verify.go "
                        f"is missing")
    else:
        header = go_header(verify_go)
        for module in sorted(required):
            if not _names(header, module):
                failures.append(f"{GO_HEADER_SITE} does not name {module}, "
                                f"which {GO_MOD_NAME} requires")
    return failures


# The README offers `go run <module>/verifiers/go@<commit>`. That form resolves
# only at a commit whose go.mod at the repository root declares the module;
# before that commit verifiers/go was a module of its own, and `go run` of
# `@d8887e6` exited 1. The README said `@<commit>` runs the verifier of "that
# commit" with no first commit named, so each sentence offering it must name
# one ("for `<commit>` or a later commit"), and that commit is held to the
# history when the checkout has it.
COMMIT_FORM = "`@<commit>`"
START_CLAIM = re.compile(r"\bfor\s+`([0-9a-f]{7,40})`\s+or\s+(?:a|any)\s+later\s+commit\b")
GO_MODULE = re.compile(r"^module[ \t]+(\S+)", re.M)
START_SITE = f"README {COMMIT_FORM} sentence"


def _history_git(root):
    """A function running one git command in `root` with every GIT_*
    variable removed and git not let look for a repository above `root`, so
    a copy of the tree outside the repository reads as having no history."""
    env = {name: value for name, value in os.environ.items()
           if not name.startswith("GIT_")}
    env["GIT_CEILING_DIRECTORIES"] = str(pathlib.Path(root).resolve().parent)

    def git(*args):
        return subprocess.run(["git", *args], cwd=root, env=env,
                              capture_output=True, text=True, check=False)
    return git


def first_module_commit(root, go_mod):
    """The id of the oldest commit in HEAD's history whose go.mod at the root
    declares the module `go_mod` declares, or None when it cannot be read: no
    module line, git cannot run, `root` is not a repository's top level, or
    the clone is shallow (its oldest commit is where the clone was cut).

    git runs with every GIT_* variable removed and is not let look for a
    repository above `root`, so a copy of the tree outside the repository
    reads as having no history."""
    module = GO_MODULE.search(go_mod or "")
    if module is None:
        return None
    git = _history_git(root)
    try:
        shallow = git("rev-parse", "--is-shallow-repository")
        if shallow.returncode != 0 or shallow.stdout.strip() != "false":
            return None
        listed = git("rev-list", "--reverse", "HEAD", "--", GO_MOD_NAME)
        if listed.returncode != 0:
            return None
        for commit in listed.stdout.split():
            shown = git("show", f"{commit}:{GO_MOD_NAME}")
            found = GO_MODULE.search(shown.stdout) if shown.returncode == 0 else None
            if found is not None and found.group(1) == module.group(1):
                return commit
    except OSError:
        return None
    return None


def module_start_failures(readme, start):
    """Each sentence of the README that offers `@<commit>` must name the first
    commit the form runs from; when `start` (first_module_commit()) is known,
    the commit named must be that one."""
    failures = []
    for sentence in statements(readme):
        if COMMIT_FORM not in sentence:
            continue
        named = START_CLAIM.search(sentence)
        if named is None:
            failures.append(
                f"{START_SITE} names no first commit the form runs from "
                f"(\"for `<commit>` or a later commit\"); before the first "
                f"commit whose {GO_MOD_NAME} at the root declares the module, "
                f"`go run` cannot resolve the verifier: {sentence!r}")
        elif start is not None and not start.startswith(named.group(1)):
            failures.append(
                f"{START_SITE} names `{named.group(1)}` as the first commit the "
                f"form runs from, but the first commit in HEAD's history whose "
                f"{GO_MOD_NAME} at the root declares the module is {start[:7]} "
                f"({start})")
    return failures


# README.md opened with `go run <module>/verifiers/go@latest`, which exited 1
# through the default module proxy: before go.mod moved to the root,
# verifiers/go held a go.mod of its own declaring another module path, and the
# proxy answers `<module>/verifiers/go@latest` with a version of that module it
# stored. go run tries the longest module path first and stops on the path
# mismatch. A stored version cannot be removed, so the package a fenced
# `go run <module>/<dir>@latest` command names must lie under no directory that
# held a go.mod.
FENCED = re.compile(r"^```[^\n]*\n(.*?)^```", re.M | re.S)
LATEST_RUN = re.compile(r"\bgo run (\S+?)@latest\b")
LATEST_SITE = "README `go run <module>/<dir>@latest` command"


def nested_module_dirs(root):
    """Each directory other than the root whose go.mod appears in HEAD's
    history, sorted, or None when it cannot be read: git cannot run, `root` is
    not a repository's top level, or the clone is shallow (a go.mod removed
    before the commit the clone was cut at is not in it)."""
    git = _history_git(root)
    try:
        shallow = git("rev-parse", "--is-shallow-repository")
        if shallow.returncode != 0 or shallow.stdout.strip() != "false":
            return None
        listed = git("log", "--format=", "--name-only", "HEAD", "--",
                     f":(glob)**/{GO_MOD_NAME}")
        if listed.returncode != 0:
            return None
    except OSError:
        return None
    return sorted({str(pathlib.PurePosixPath(p).parent)
                   for p in listed.stdout.split() if p != GO_MOD_NAME})


def latest_run_failures(readme, go_mod, nested):
    """Each `go run <import path>@latest` in a fenced block of the README and
    its pages that names a package of the module go.mod declares must name
    one under no directory of `nested` (nested_module_dirs()). With no module
    line, or `nested` None, nothing is checked."""
    module = GO_MODULE.search(go_mod or "")
    if module is None or nested is None:
        return []
    module = module.group(1)
    failures = []
    commands = [path for block in FENCED.findall(readme)
                for path in LATEST_RUN.findall(block)]
    for path in dict.fromkeys(commands):
        if not path.startswith(module + "/"):
            continue
        rel = path[len(module) + 1:]
        for directory in nested:
            if rel == directory or rel.startswith(directory + "/"):
                failures.append(
                    f"{LATEST_SITE} `go run {path}@latest` names a package under "
                    f"{directory}, which held a {GO_MOD_NAME} of its own in HEAD's "
                    f"history; the module proxy can answer "
                    f"`{module}/{directory}@latest` with that module, and go run "
                    f"exits 1 when its {GO_MOD_NAME} declares another path")
    return failures


# CHANGELOG.md's Unreleased section still said `go run
# <module>/verifiers/go@latest` "runs the Go verifier with nothing cloned, and
# is README.md's first command" once README.md opened with `go run
# <module>/cmd/atx-verify@latest`, and the older command exits 1 through the
# module proxy (LATEST_SITE above). Each `go run` command a sentence of that
# section names as README.md's first command must be the one README.md opens
# with. The sections below it record past commits and are not held to it.
CHANGELOG = ROOT / "CHANGELOG.md"
CHANGELOG_NAME = "CHANGELOG.md"
UNRELEASED = "## Unreleased"
FIRST_COMMAND_CLAIM = re.compile(r"\bREADME(?:\.md)?['’]s\s+first\s+command\b")
CODE_SPAN = re.compile(r"`([^`]*)`")
# A code span holding a `go run` command, with or without a `cd <dir> && `
# prefix. One holding a placeholder other than <module>, such as `go run
# <import path>@<version>`, names a form of command and is not held.
GO_RUN_COMMAND = re.compile(r"(?:cd [^\s&;|]+ && )?go run \S.*")
CD_PREFIX = re.compile(r"cd [^\s&;|]+ && (.+)")
PLACEHOLDER = re.compile(r"<(?!module>)[^<>\s][^<>]*>")
# A sentence ends at `.`, `!` or `?` and a blank outside a code span: a span
# is matched whole and passed over, so `go run . ../../fixtures` is not split.
SENTENCE_BREAK = re.compile(r"`[^`]*`|(?<=[.!?])\s+")
# A paragraph ends at a blank line, and a list item where the next one opens.
ITEM_BREAK = re.compile(r"\n[ \t]*\n|\n(?=[ \t]*[-*+][ \t])")
FIRST_COMMAND_SITE = f"{CHANGELOG_NAME} Unreleased sentence"
# The sentence the check was written for, as it was wrapped. The check must
# keep failing it while README.md opens with another command.
RETRACTED_FIRST_COMMAND = (
    "- `go run github.com/opena2a-standards/atx-conformance/verifiers/go@latest`\n"
    "  runs the Go verifier with nothing cloned, and is README.md's first\n"
    "  command.")


def first_command(front_page):
    """The command README.md, read alone, opens with: the first line of its
    first fenced block that is not blank, or None when there is none."""
    block = FENCED.search(front_page or "")
    lines = block.group(1).split("\n") if block else []
    return next((line.strip() for line in lines if line.strip()), None)


def unreleased_sentences(changelog):
    """Each sentence of the section of `changelog` under UNRELEASED, up to the
    next heading of level 1 or 2, on one line; none when it has no such
    section. A paragraph or list item never shares a sentence with the next,
    and a code span is never split."""
    lines = changelog.split("\n")
    at = next((i for i, line in enumerate(lines) if line.rstrip() == UNRELEASED), None)
    if at is None:
        return []
    body = []
    for line in lines[at + 1:]:
        if re.match(r"#{1,2} ", line):
            break
        body.append(line)
    sentences = []
    for item in ITEM_BREAK.split("\n".join(body)):
        flat = " ".join(item.split())
        start = 0
        for found in SENTENCE_BREAK.finditer(flat):
            if not found.group(0).startswith("`"):
                sentences.append(flat[start:found.start()])
                start = found.end()
        if flat[start:]:
            sentences.append(flat[start:])
    return sentences


def changelog_first_command_failures(changelog, front_page, go_mod):
    """Each `go run` code span in a sentence of CHANGELOG.md's Unreleased
    section that names README.md's first command must be the command
    first_command() reads from README.md, with or without its `cd <dir> && `
    prefix; `<module>` in a span reads as the module go.mod declares, and a
    span holding another placeholder is passed over. `changelog` is None when
    the file is missing."""
    if changelog is None:
        return [f"{CHANGELOG_NAME} is missing; the commands its Unreleased section "
                f"names as README.md's first command cannot be checked"]
    first = first_command(front_page)
    named = set()
    if first is not None:
        bare = CD_PREFIX.fullmatch(first)
        named = {first, bare.group(1)} if bare else {first}
    module = GO_MODULE.search(go_mod or "")
    failures = []
    for sentence in unreleased_sentences(changelog):
        if not FIRST_COMMAND_CLAIM.search(sentence):
            continue
        for span in CODE_SPAN.findall(sentence):
            if not GO_RUN_COMMAND.fullmatch(span) or PLACEHOLDER.search(span):
                continue
            command = span.replace("<module>", module.group(1)) if module else span
            if command not in named:
                failures.append(
                    f"{FIRST_COMMAND_SITE} names `{span}` as README.md's first "
                    f"command, but README.md opens with "
                    + (f"`{first}`" if first is not None else "no fenced block")
                    + f": {sentence!r}")
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
# options open with another character. The indent is `[ \t]*`: `\s*` also
# matches newlines, so under re.M every line start in a run of blank lines
# rescanned the rest of the run, and 20,000 blank lines took 2 s.
PY_REQUIREMENT = re.compile(r"^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)", re.M)
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
# The Go leg runs github.com/gowebpki/jcs, which the jcs-vectors README and the
# vector pinner called a reference port in the same way. Each is paired with
# the wording it published.
JCS_PORT_SITES = (
    ("jcs-vectors/README.md", "(webpki.org reference port)"),
    ("jcs-vectors/pin/main.go", "//     (the webpki.org RFC 8785 reference port)."),
)
JCS_REFERENCE_CLAIM = re.compile(
    r"\bRFC\s*8785(?:'s)?\s+reference\s+impl(?:ementation)?\b"
    r"|\breference\s+impl(?:ementation)?\s+(?:of|for)\s+RFC\s*8785\b"
    r"|\b(?:RFC\s*8785(?:'s)?\s+)?reference\s+port\b",
    re.IGNORECASE,
)
JCS_APPENDIX_G = "RFC 8785 Appendix G"
# A line-leading `//` or `#` comment marker and its indent. The indent is
# `[ \t]*`: `\s*` also matches newlines, so under re.M every line start in a
# run of blank lines rescanned the rest of the run, and 20,000 blank lines
# took 2 s.
COMMENT_MARKER = re.compile(r"^[ \t]*(?://+|#+)", re.M)


def _flat_prose(text):
    """`text` with line-leading `//` and `#` markers removed and whitespace
    collapsed, so neither a line wrap nor a comment continuation splits a
    phrase."""
    return " ".join(COMMENT_MARKER.sub("", text).split())


def jcs_library_failures(sites):
    """No file that describes an RFC 8785 library the gate runs (missing from
    `sites` when the file is) may call it a reference implementation or a
    reference port, and each file that describes the TypeScript leg's library
    must say RFC 8785 Appendix G lists it."""
    failures = []
    cited = [path for path, _ in JCS_LIBRARY_SITES]
    paths = []
    for path, retracted in JCS_LIBRARY_SITES + JCS_PORT_SITES:
        if not JCS_REFERENCE_CLAIM.search(_flat_prose(retracted)):
            failures.append(f"RFC 8785 reference claim pattern no longer matches "
                            f"the wording {path} published; the gate cannot fire")
        if path not in paths:
            paths.append(path)
    for path in paths:
        if path not in sites:
            failures.append(f"{path} is missing; what it says about an RFC 8785 "
                            f"library cannot be checked")
            continue
        flat = _flat_prose(sites[path])
        for claim in JCS_REFERENCE_CLAIM.finditer(flat):
            failures.append(f"{path} calls an RFC 8785 library \"{claim.group(0)}\", "
                            f"but RFC 8785 designates no reference implementation")
        if path in cited and JCS_APPENDIX_G not in flat:
            failures.append(f"{path} does not say canonicalize is listed in "
                            f"{JCS_APPENDIX_G}")
    return failures


# jcs-vectors/README.md and the header of jcs-vectors/run-agreement.sh said the
# gate runs no code from another repository, while its Go and TypeScript legs
# run the modules jcs-vectors/go.mod requires and the package
# jcs-vectors/ts/package.json depends on. What both meant is that the gate runs
# no issuer, offline-verifier or broker code. Each file is paired with the
# wording it published, with its original line wrap.
GATE_SCRIPT_NAME = "jcs-vectors/run-agreement.sh"
GATE_GO_MOD_NAME = "jcs-vectors/go.mod"
GATE_PACKAGE_NAME = "jcs-vectors/ts/package.json"
OUTSIDE_CODE_SITES = (
    ("jcs-vectors/README.md", "It runs no code from another repository."),
    (GATE_SCRIPT_NAME,
     "# script exits 0. It runs no code outside this repository: an issuer, offline\n"
     "# verifier or broker is held to these bytes only by running vectors/ in its own"),
)
OUTSIDE_CODE_CLAIM = re.compile(
    r"\bruns?\s+no\s+code\s+(?:from\s+(?:another|any\s+other|other)|outside\s+(?:this|the))"
    r"\s+repositor(?:y|ies)\b",
    re.IGNORECASE,
)


def gate_libraries(go_mod, package):
    """The third-party libraries the gate's Go and TypeScript legs run: the
    direct requirements of jcs-vectors/go.mod and the dependencies of
    jcs-vectors/ts/package.json (each the file's text, None when missing)."""
    try:
        dependencies = json.loads(package or "{}").get("dependencies", {})
    except (ValueError, AttributeError):
        dependencies = {}
    return (sorted(direct_requirements(go_mod or ""))
            + sorted(dependencies if isinstance(dependencies, dict) else ()))


def outside_code_failures(sites, libraries):
    """Neither file that says what the gate runs (missing from `sites` when
    the file is) may say it runs no code from another repository while its
    legs run `libraries`, from gate_libraries."""
    failures = []
    for path, retracted in OUTSIDE_CODE_SITES:
        if not OUTSIDE_CODE_CLAIM.search(_flat_prose(retracted)):
            failures.append(f"outside-code claim pattern no longer matches the "
                            f"wording {path} published; the gate cannot fire")
        if path not in sites:
            failures.append(f"{path} is missing; what it says the byte-agreement "
                            f"gate runs cannot be checked")
            continue
        claim = OUTSIDE_CODE_CLAIM.search(_flat_prose(sites[path]))
        if claim and libraries:
            failures.append(f"{path} says the gate \"{claim.group(0)}\", but its "
                            f"legs run {', '.join(libraries)}; say it runs no "
                            f"issuer, offline-verifier or broker code")
    return failures


# The gate also runs each conformance verifier's own v1.1 path over the
# vectors. README.md, in the continuous-verification list and the v1.1 section,
# and the profile's description of the gate kept calling it agreement across
# three canonicalizers. Each must name every directory the gate script runs a
# verifier leg in, read from the leg's banner line.
VERIFIER_LEG = re.compile(r'^echo "=== \[verifier/\w+\] (verifiers/[\w-]+) ', re.M)
PROFILE = ROOT / "conformance.json"
PROFILE_NAME = "conformance.json"
README_GATE_SITE = "README description of the JCS byte-agreement gate"
PROFILE_GATE_SITE = f"{PROFILE_NAME} description of {GATE_SCRIPT_NAME}"
CANONICALIZERS = re.compile(r"\bcanonicalizers\b", re.IGNORECASE)
# The two sentences README.md published, with their original line wraps, and
# the description the profile carried.
RETRACTED_GATE_CLAIMS = (
    "The JCS byte-agreement gate\n"
    "   ([`jcs-vectors/run-agreement.sh`](./jcs-vectors/run-agreement.sh)) must\n"
    "   pass across the independent Go, Python, and TypeScript canonicalizers,\n"
    "   and every Go module in the repository must pin one `cloudflare/circl`\n"
    "   version ([`scripts/check_circl_pin.sh`](./scripts/check_circl_pin.sh)),\n"
    "   so the vectors and the verifier share one crypto tree.",
    "Cross-language byte agreement on `JCS(TBS)` is proven by\n"
    "[`jcs-vectors/`](jcs-vectors/) (Go, Python, and TypeScript canonicalizers must\n"
    "agree byte-for-byte).",
)
RETRACTED_PROFILE_GATE = (
    "three independent canonicalizers (Go gowebpki/jcs, vendored Python RFC 8785, "
    "TypeScript erdtman/canonicalize) must reproduce each vector's pinned "
    "canonical bytes exactly"
)


def verifier_legs(gate_script):
    """The directories jcs-vectors/run-agreement.sh runs a verifier leg in."""
    return VERIFIER_LEG.findall(gate_script)


def gate_descriptions(readme, profile):
    """(site, text) for each description of the byte-agreement gate: every
    README statement that names jcs-vectors/ and its canonicalizers, and the
    description of each additionalGates entry of conformance.json (its text,
    None when missing) whose path is the gate script. The repository layout,
    a fenced block, lists what the directory holds and is not one."""
    found = [(README_GATE_SITE, claim) for claim in statements(readme)
             if "jcs-vectors/" in claim and CANONICALIZERS.search(claim)
             and not claim.startswith("```")]
    try:
        gates = json.loads(profile or "{}").get("additionalGates", [])
    except (ValueError, AttributeError):
        gates = []
    for gate in gates if isinstance(gates, list) else []:
        if isinstance(gate, dict) and gate.get("path") == GATE_SCRIPT_NAME:
            found.append((PROFILE_GATE_SITE, str(gate.get("description", ""))))
    return found


def gate_leg_failures(readme, profile, gate_script):
    """Each description of the byte-agreement gate must name every directory
    jcs-vectors/run-agreement.sh (its text, None when missing) runs a verifier
    leg in. `profile` is conformance.json's text, None when missing."""
    if gate_script is None:
        return [f"{GATE_SCRIPT_NAME} is missing; the legs its descriptions must "
                f"name cannot be read"]
    failures = []
    if profile is None:
        failures.append(f"{PROFILE_NAME} is missing; its description of "
                        f"{GATE_SCRIPT_NAME} cannot be checked")
    for site, text in gate_descriptions(readme, profile):
        for leg in verifier_legs(gate_script):
            if not _names(text, leg):
                failures.append(f"{site} (\"{text[:60]}...\") does not name {leg}, "
                                f"whose own v1.1 path {GATE_SCRIPT_NAME} also runs "
                                f"over the vectors")
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
    for wording in CRITERION_C_SYNONYMS:
        if not CRITERION_C_CLAIM.search(" ".join(wording.split())):
            failures.append(
                f"criterion (c) claim pattern does not match {wording!r}; the "
                f"gate cannot fire on that wording"
            )
    if CRITERION_C_CLAIM.search(" ".join(CRITERION_C_CONDITIONAL.split())):
        failures.append(
            f"criterion (c) claim pattern matches the conditional "
            f"{CRITERION_C_CONDITIONAL!r}, which states no claim"
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


def scope_rows(readme):
    """(item, covered-by) cells of the README Scope table; None without one."""
    scope = re.search(r"^## Scope\n(.*?)(?=^## )", readme, re.MULTILINE | re.DOTALL)
    if not scope:
        return None
    rows = []
    for line in scope.group(1).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|") or len(cells) < 2 or set(cells[0]) <= set("-"):
            continue
        rows.append((cells[0], cells[1]))
    return rows


def threshold_claims(readme, fixtures):
    """Covered Scope-table rows that name a threshold no fixture declares."""
    if any(declares_threshold(p) for p in fixtures):
        return []
    rows = scope_rows(readme)
    if rows is None:
        return ["no `## Scope` section found in README"]
    failures = []
    for item, covered_by in rows:
        if covered_by.lower().startswith("not covered"):
            continue
        if THRESHOLD_CLAIM.search(item):
            failures.append(
                f"README Scope table lists {item!r} as covered, but no "
                f"fixture's verifierState declares {THRESHOLD_FIELD}, so no "
                f"verifier is held to a threshold"
            )
    return failures


def expected_outcomes(paths):
    """Map each fixture name to its expected (verifyResult, rejectCategory),
    or to None when the file states no `expected` object."""
    outcomes = {}
    for path in paths:
        try:
            fx = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            fx = None
        expected = fx.get("expected") if isinstance(fx, dict) else None
        outcomes[path.name] = (
            (expected.get("verifyResult"), expected.get("rejectCategory"))
            if isinstance(expected, dict) else None)
    return outcomes


def reaches_signature_step(outcome):
    """True if a fixture with this expected outcome reaches step 5, False if
    it rejects at steps 0 to 4, None if the outcome cannot be placed."""
    if outcome is None:
        return None
    result, category = outcome
    if result == "ACCEPT":
        return True
    if not isinstance(category, str):
        return None
    if category in EARLY_REJECT_STEP:
        return False
    if category in SIGNATURE_STEP_REJECTS:
        return True
    return None


def signature_coverage_failures(readme, outcomes):
    """Covered signature-verification Scope rows whose fixture count is wrong.
    `outcomes` is the map expected_outcomes() returns."""
    rows = scope_rows(readme)
    if rows is None:
        return ["no `## Scope` section found in README; its signature-"
                "verification row cannot be held to the fixtures"]
    claims = [
        (item, covered_by)
        for item, covered_by in rows
        if SIGNATURE_ROW.search(item)
        and not covered_by.lower().startswith("not covered")
        and (EVERY_FIXTURE.search(covered_by) or N_OF_M.search(covered_by))
    ]
    if not claims:
        return []
    failures, reached, early = [], [], []
    for name in sorted(outcomes):
        step = reaches_signature_step(outcomes[name])
        if step is None:
            failures.append(
                f"fixtures/{name}: expected outcome is neither ACCEPT nor "
                f"a reject category placed before or at step 5, so the "
                f"fixtures that reach signature verification cannot be counted"
            )
        elif step:
            reached.append(name)
        else:
            early.append(name)
    if failures:
        return failures
    total = len(outcomes)
    for item, covered_by in claims:
        stated = N_OF_M.findall(covered_by)
        for n, m in stated:
            if (int(n), int(m)) != (len(reached), total):
                failures.append(
                    f"README Scope table states {item!r} is covered by {n} of "
                    f"{m} fixtures, but {len(reached)} of {total} reach "
                    f"signature verification (step 5)"
                )
        if not stated and early:
            failures.append(
                f"README Scope table lists {item!r} as covered by every "
                f"fixture, but {len(early)} of {total} reject before signature "
                f"verification (step 5): {', '.join(early)}; state the count "
                f"as `{len(reached)} of {total}`"
            )
    return failures


# docs/scope.md says how many of the fixtures expected to ACCEPT carry Ed25519
# signatures only ("6 of its 8 ACCEPT fixtures"). Matched over the raw text
# with `\s+`, so a line wrap inside it cannot hide it.
ED25519_ONLY_CLAIM = re.compile(r"\b(\d+)\s+of\s+its\s+(\d+)\s+ACCEPT\s+fixtures\b")
ED25519 = "Ed25519"


def signature_suites(paths):
    """Map each fixture name to (expected verifyResult, the `algorithm` of each
    atx.signatures entry), or to None when the file states neither."""
    suites = {}
    for path in paths:
        try:
            fx = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            fx = None
        expected = fx.get("expected") if isinstance(fx, dict) else None
        atx = fx.get("atx") if isinstance(fx, dict) else None
        sigs = atx.get("signatures") if isinstance(atx, dict) else None
        if (not isinstance(expected, dict) or not isinstance(sigs, list)
                or not all(isinstance(s, dict) for s in sigs)):
            suites[path.name] = None
            continue
        suites[path.name] = (expected.get("verifyResult"),
                             tuple(s.get("algorithm") for s in sigs))
    return suites


def ed25519_only_failures(readme, suites):
    """Statements of how many ACCEPT fixtures carry Ed25519 signatures only
    that do not match the fixtures. `suites` is the map signature_suites()
    returns."""
    claims = ED25519_ONLY_CLAIM.findall(readme)
    if not claims:
        return []
    unread = sorted(n for n in suites if suites[n] is None)
    if unread:
        return [f"fixtures/{n}: no expected object or atx.signatures list, so "
                f"the ACCEPT fixtures that carry Ed25519 signatures only cannot "
                f"be counted" for n in unread]
    accept = [n for n in suites if suites[n][0] == "ACCEPT"]
    only = [n for n in accept if set(suites[n][1]) == {ED25519}]
    return [
        f"README states {n} of its {m} ACCEPT fixtures carry Ed25519 signatures "
        f"only, but {len(only)} of the {len(accept)} fixtures expected to "
        f"ACCEPT do"
        for n, m in claims if (int(n), int(m)) != (len(only), len(accept))
    ]


# The repository layout labels the scripts/*.py glob "CI gates". A script the
# workflow does not run, either by name in the command of a `run:` step or
# through a script it runs that imports it, must have its own layout line, and
# that line must not call it a CI gate. The layout called
# check_fixture_immutability.py a CI gate while no workflow step ran it, and a
# name the workflow held only in a comment counted as run.
SCRIPTS = ROOT / "scripts"
CI_GATE_GLOB = re.compile(r"^scripts/\*\.py[ \t]+CI gates\b", re.M)
# A layout line naming one script, with the indented lines that continue it.
SCRIPT_LINE = re.compile(r"^scripts/([\w-]+\.py)\b(.*(?:\n[ \t]+\S.*)*)", re.M)
SCRIPT_IMPORT = re.compile(r"^[ \t]*(?:import[ \t]+(\w+)|from[ \t]+(\w+)[ \t]+import\b)", re.M)
# A block-style YAML line holding a key: its indentation, an optional
# sequence dash, the key, plain, single-quoted or double-quoted, any spaces
# before its `:` (`run : x` holds the key `run`), and the value written on the
# same line.
WORKFLOW_KEY = re.compile(
    r"^( *)(-[ ]+)?([\w-]+|'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\")[ ]*:(?:[ \t]+(.*))?$")
# A double-quoted YAML scalar's escapes: `\x`, `\u` or `\U` and its hex
# digits, or the one character after the backslash, which YAML_ESCAPES maps.
YAML_ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|(.))", re.S)
YAML_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n",
    "v": "\v", "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"',
    "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": " ",
    "P": " ",
}
WORKFLOW_ITEM = re.compile(r"^( *)-(?:[ ]+|$)")
BLOCK_SCALAR = re.compile(r"^[|>][-+0-9]*[ \t]*(?:#.*)?$")
SHELL_COMMENT = re.compile(r"(?:^|(?<=\s))#.*$", re.M)
# Flow-style YAML: the spaces, line breaks and comments between tokens, and a
# single-quoted, double-quoted or plain scalar. A plain scalar ends at a flow
# indicator, at a `:` before a space or a flow indicator, and before a comment.
FLOW_SPACE = re.compile(r"(?:\s+|(?<=\s)#[^\n]*)*")
FLOW_SCALAR = re.compile(
    r"'(?:[^']|'')*'(?!')|\"(?:[^\"\\]|\\.)*\""
    r"|(?:[^\s,\[\]{}:'\"]|:(?=[^\s,\[\]{}]))"
    r"(?:[^\s,\[\]{}:]|:(?=[^\s,\[\]{}])|\s+(?=[^\s#,\[\]{}:]|:[^\s,\[\]{}]))*",
    re.S)


def yaml_key(scalar):
    """The key a mapping key's scalar text names: a single-quoted key without
    its quotes and with each `''` read as `'`, a double-quoted key without
    its quotes and with its backslash escapes undone, and a plain key as it
    is written. A double-quoted key holding an escape YAML does not define
    is returned with its quotes, so it names no plain key."""
    if scalar[:1] == "'":
        return scalar[1:-1].replace("''", "'")
    if scalar[:1] != '"':
        return scalar

    def unescape(match):
        code = match.group(1) or match.group(2) or match.group(3)
        return chr(int(code, 16)) if code else YAML_ESCAPES[match.group(4)]

    try:
        return YAML_ESCAPE.sub(unescape, scalar[1:-1])
    except (KeyError, ValueError):
        return scalar


def flow_node(text, pos):
    """The flow-style YAML node at text[pos], after the spaces, line breaks
    and comments before it, and the index past it: a mapping as a dict, a
    sequence as a list and a scalar as its source text, quotes kept, as the
    block-style lines are read. A mapping key is read by yaml_key(). A node
    left empty before `,`, `:`, `]` or `}` is None. Raises EOFError when the
    text ends inside the node and ValueError when it is not flow-style
    YAML."""
    pos = FLOW_SPACE.match(text, pos).end()
    if pos == len(text):
        raise EOFError
    opener = text[pos]
    if opener not in "{[":
        scalar = FLOW_SCALAR.match(text, pos)
        if scalar:
            return scalar.group(), scalar.end()
        if opener in "'\"":
            raise EOFError
        return None, pos
    close = "}" if opener == "{" else "]"
    mapping, sequence = {}, []
    pos += 1
    while True:
        pos = FLOW_SPACE.match(text, pos).end()
        if pos == len(text):
            raise EOFError
        if text[pos] == close:
            return (mapping if opener == "{" else sequence), pos + 1
        key, pos = flow_node(text, pos)
        pos = FLOW_SPACE.match(text, pos).end()
        pair = text.startswith(":", pos)
        value = None
        if isinstance(key, str) and (pair or opener == "{"):
            key = yaml_key(key)
        if pair:
            value, pos = flow_node(text, pos + 1)
            pos = FLOW_SPACE.match(text, pos).end()
        if opener == "[":
            sequence.append({key: value} if pair and isinstance(key, str) else key)
        elif isinstance(key, str):
            mapping[key] = value
        if pos == len(text):
            raise EOFError
        if text[pos] == ",":
            pos += 1
        elif text[pos] != close:
            raise ValueError(f"expected `,` or `{close}` at offset {pos}")


def flow_node_lines(lines, i, text):
    """The flow-style node `text`, the rest of a line, opens, read on through
    lines[i:] until it closes, and the index of the line after it; None and
    i when it does not close or is not flow-style YAML."""
    for end in range(i, len(lines) + 1):
        try:
            return flow_node("\n".join([text] + lines[i:end]), 0)[0], end
        except EOFError:
            continue
        except ValueError:
            break
    return None, i


def workflow_run_commands(workflow):
    """The command text of each `run:` key of an item in a `steps:` sequence
    of the workflow text, read as block-style YAML, with the text from a `#`
    that starts a word to the end of its line removed, as the shell drops a
    comment. The command may start on the key's line or on a later line
    indented past it, and a step may be a flow mapping on one line or more
    (`- {name: a, run: python3 scripts/a.py}`). A key may be quoted
    (`- "run": python3 scripts/a.py`) and is read by yaml_key(), and spaces
    may stand between a block-style key and its `:`
    (`- run : python3 scripts/a.py`). A script named in a YAML comment, a
    step `name:` or an action's `with:` input is in none of them."""
    lines = (workflow or "").splitlines()
    commands = []
    # Open nodes, innermost last: (column, "-") for a sequence item and
    # (column, key) for a mapping key.
    stack = []
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key = WORKFLOW_KEY.match(line)
        item = WORKFLOW_ITEM.match(line)
        indent = len(line) - len(line.lstrip(" "))
        # A sequence may sit at its parent key's own indentation, so an item
        # closes only the items and keys indented past it, and earlier items
        # at its own column.
        while stack and (stack[-1][0] > indent or (
                stack[-1][0] == indent and (not item or stack[-1][1] == "-"))):
            stack.pop()
        if item:
            stack.append((indent, "-"))
        is_step = (len(stack) >= 2 and stack[-1][1] == "-"
                   and stack[-2][1] == "steps")
        if item and line.startswith("{", item.end()):
            # A sequence item written as a flow mapping, on as many lines as
            # it takes to close.
            step, i = flow_node_lines(lines, i, line[item.end():])
            if is_step and isinstance(step, dict) and isinstance(step.get("run"), str):
                commands.append(SHELL_COMMENT.sub("", step["run"]))
            continue
        if not key:
            continue
        column = key.start(3)
        name, value = yaml_key(key.group(3)), (key.group(4) or "").strip()
        # A step's command may start on a later line than its `run:` key,
        # indented past it, after any YAML comment lines.
        if not value and name == "run" and is_step:
            j = i
            while j < len(lines) and (not lines[j].strip()
                                      or lines[j].lstrip().startswith("#")):
                j += 1
            if j < len(lines) and len(lines[j]) - len(lines[j].lstrip(" ")) > column:
                value, i = lines[j].strip(), j + 1
        # Lines indented past the key carry its value: a block scalar's body,
        # or the continuation of a value begun on the key's line.
        body = []
        if value:
            while i < len(lines) and (not lines[i].strip()
                                      or len(lines[i]) - len(lines[i].lstrip(" ")) > column):
                body.append(lines[i])
                i += 1
            if BLOCK_SCALAR.match(value):
                value = ""
        stack.append((column, name))
        if name == "run" and is_step:
            commands.append(SHELL_COMMENT.sub("", "\n".join([value] + body)))
    return commands


def ci_run_scripts(workflow, scripts):
    """The scripts/*.py names the workflow runs: those named in the command of
    a `run:` step, and those a script it runs imports. `scripts` maps each
    name to its source text."""
    named = "\n".join(workflow_run_commands(workflow))
    run = {name for name in re.findall(r"\bscripts/([\w-]+\.py)\b", named)
           if name in scripts}
    todo = list(run)
    while todo:
        source = scripts.get(todo.pop()) or ""
        for match in SCRIPT_IMPORT.finditer(source):
            name = f"{match.group(1) or match.group(2)}.py"
            if name in scripts and name not in run:
                run.add(name)
                todo.append(name)
    return run


def ci_gate_label_failures(readme, workflow, scripts):
    """scripts/*.py files the README layout calls CI gates that the workflow
    does not run."""
    if not CI_GATE_GLOB.search(readme):
        return []
    run = ci_run_scripts(workflow, scripts)
    own_line = {m.group(1): m.group(2) for m in SCRIPT_LINE.finditer(readme)}
    failures = []
    for name in sorted(set(scripts) - run):
        if name not in own_line:
            failures.append(
                f"README layout calls every scripts/*.py a CI gate, but "
                f"{WORKFLOW_NAME} does not run scripts/{name}; give it its own "
                f"layout line saying how it is run")
        elif "CI gate" in own_line[name]:
            failures.append(
                f"README layout calls scripts/{name} a CI gate, but "
                f"{WORKFLOW_NAME} does not run it")
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
# scanSummary.highFindings as JSON numbers and four carry
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
# comment markers and line wraps removed; group 1 is the member named. The
# member name and the parenthesis after it are bounded: unbounded, each was
# rescanned from every position in one long word or in a run of unclosed
# parentheses, and a 16,000-character word took 4 s.
MEMBER_NAME_MAX = 64
ASIDE_MAX = 200
ONLY_NUMBER_CLAIM = re.compile(
    rf"`?(\w{{1,{MEMBER_NAME_MAX}}})`?(?:\s+\([^)]{{0,{ASIDE_MAX}}}\))?"
    r"\s+(?:is\s+)?the\s+only\s+JSON\s+number\b",
    re.IGNORECASE,
)
# This file says, in its docstring and above TBS_NUMBER_SITES, how many of the
# vectors have the observationDays member. Both said five while four do, so
# the self-test holds the count to the vectors.
OBSERVATION_DAYS = "behavioralProfile.observationDays"
COUNT_WORDS = ("zero", "one", "two", "three", "four", "five", "six", "seven",
               "eight", "nine", "ten", "eleven", "twelve")
CARRIER_COUNT = re.compile(
    rf"\b({'|'.join(COUNT_WORDS)}|\d+)\s+carry\s+{re.escape(OBSERVATION_DAYS)}",
    re.IGNORECASE,
)


class _NonInteger(str):
    """A JSON number token with a fraction or an exponent."""


def _prose(text):
    """Collapse whitespace and drop line-leading `//` and `#` comment markers,
    so a claim wrapped across comment lines reads as one sentence."""
    return " ".join(COMMENT_MARKER.sub(" ", text).split())


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

    label = f"this script's count of the vectors that carry {OBSERVATION_DAYS}"
    carrying = sum(1 for text in canonical.values()
                   if any(path == OBSERVATION_DAYS
                          for path, _, _ in _tbs_numbers(_parsed(text))))
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    stated = [word.lower() for word in CARRIER_COUNT.findall(_prose(source))]
    counts = [COUNT_WORDS.index(word) if word in COUNT_WORDS else int(word)
              for word in stated]
    cases.append((bool(counts) and all(n == carrying for n in counts), label,
                  f"it says {', '.join(stated) or 'nothing'}, and {carrying} of "
                  f"the {len(canonical)} vectors carry it"))
    return cases


def _parsed(text):
    """A vector's canonical string as a parsed TBS, or None when it has none."""
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


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


def read_readme(root):
    """README.md and then each of README_PAGES, joined into one text. A page
    that is missing is left out, so each section it held is reported as not
    found."""
    texts = [(root / README.relative_to(ROOT)).read_text(encoding="utf-8")]
    texts += [(root / rel).read_text(encoding="utf-8")
              for rel in README_PAGES if (root / rel).exists()]
    return "\n".join(texts)


def front_page_failures(front_page):
    """One failure per line of README.md, read alone, that states a version or
    a date."""
    failures = []
    if not VERSION_OR_DATE.search(RETRACTED_DATE_LINE):
        failures.append(
            "version-or-date pattern no longer matches the README.md line it "
            "was written for; the gate cannot fire"
        )
    for number, line in enumerate(front_page.splitlines(), 1):
        found = VERSION_OR_DATE.search(line)
        if found:
            failures.append(
                f"README.md:{number} states {found.group(0)!r}; move the "
                f"passage to the page README.md links for it, or to "
                f"CHANGELOG.md, and keep the link"
            )
    return failures


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
    "py_dependency_texts jcs_sites tbs_sites tbs_canonical jcs_readme "
    "gate_sites gate_libraries profile outcomes suites scripts front_page "
    "module_start nested_modules changelog"))

# One check tree_failures() runs: its name, the call (`run(tree)` returns
# failures) and the alteration the self-test makes to prove the call is still
# made. `wiring(tree)` returns the text a new failure must contain and the
# Tree fields to replace, or a sentence saying why the site to alter was not
# found. Both halves sit in one CHECKS entry, below the alterations, so a
# check cannot be added without a wiring case or lose its case and then its
# call: the case list once fell three checks behind the calls.
Check = collections.namedtuple("Check", "name run wiring")


def tree_failures(tree, checks=None):
    """Every failure the check reports for `tree`: one call per entry of
    `checks`, CHECKS unless the self-test passes an altered list. main() and
    the self-test's wiring cases both call this, so a check dropped from
    CHECKS fails a case instead of going unrun."""
    failures = []
    for entry in CHECKS if checks is None else checks:
        failures.extend(entry.run(tree))
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
    ("expected output `summary: N pass`", "README.md", r"report\s+`summary: (\d+) pass"),
    ("expected output `(N fixtures)`", "README.md", r"0 fail \((\d+) fixtures\)`"),
    ("start-block capture `summary: N pass`", "README.md", r"^summary: (\d+) pass"),
    ("start-block capture `(N fixtures)`", "README.md",
     r"^summary: \d+ pass, 0 fail \((\d+) fixtures\)$"),
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
                 f"{GO_MOD_NAME} or verifiers/go/verifier/verify.go is missing")]
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
            missing(f"{GO_HEADER_SITE} naming {module}", "verifiers/go/verifier/verify.go")
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


# The sentence as the README published it, with its line wrap: no first commit.
RETRACTED_START = ("`@<commit>` in its place runs the verifier and fixtures of\n"
                   "that commit.")
INVENTED_START = "0" * 40


def _module_start_cases(readme):
    """Restate the retracted sentence, drop the first commit from the live
    one, and hold the live one to a first commit other than the one it names;
    each must add a failure naming the README `@<commit>` sentence. Then read
    first_module_commit() off temporary repositories."""
    sentences = [s for s in statements(readme) if COMMIT_FORM in s]
    named = [m.group(1) for m in map(START_CLAIM.search, sentences) if m]
    if not named:
        return [(False, f"{START_SITE} naming its first commit",
                 f"no sentence offering {COMMIT_FORM} with \"for `<commit>` or a "
                 f"later commit\" found in README.md or its pages")]
    held = named[0] + "0" * (40 - len(named[0]))
    baseline = set(module_start_failures(readme, held))
    cases = [(not baseline, f"{START_SITE} held to the commit it names",
              f"it fails against {held}: {sorted(baseline)}")]

    def case(label, needle, text=readme, start=held):
        new = [f for f in module_start_failures(text, start) if f not in baseline]
        cases.append((any(f.startswith(START_SITE) and needle in f for f in new),
                      label, f"expected a {START_SITE} failure naming {needle!r}, "
                             f"got {new}"))

    case("README restating `@<commit>` with no first commit",
         "names no first commit", text=readme + "\n\n" + RETRACTED_START + "\n")
    site = START_CLAIM.search(readme)
    case(f"{START_SITE} with its first commit dropped", "names no first commit",
         text=readme[:site.start()] + "for a commit" + readme[site.end():])
    case(f"{START_SITE} naming a commit other than the first with go.mod at the root",
         f"is {INVENTED_START[:7]}", start=INVENTED_START)
    cases.extend(_first_module_commit_cases())
    return cases


def _passing_latest_runs(readme, go_mod, nested):
    """`readme` with each line of a fenced block that latest_run_failures()
    fails against `nested` removed, and the lines removed. A command sits on
    one line (`go run` holds a space, the path none), so what is left
    passes."""
    removed = []

    def keep(block):
        kept = []
        for line in block.group(0).split("\n"):
            failing = latest_run_failures(f"```\n{line}\n```\n", go_mod, nested)
            (removed if failing else kept).append(line)
        return "\n".join(kept)
    return FENCED.sub(keep, readme), removed


def _latest_run_cases(readme, go_mod, nested):
    """The published README passes against the directories whose go.mod is in
    the history (verifiers/go where none can be read). Held to verifiers/go,
    the retracted first command `go run <module>/verifiers/go@latest` and a
    package below verifiers/go, each in a fenced block, add a failure naming
    it; the retracted command in prose adds none. _first_module_commit_cases()
    reads nested_module_dirs() off temporary repositories.

    The cases run on the README less each fenced line the check fails against
    those directories and verifiers/go, and when any was removed the first
    case's label says how many: a README that fails the check is reported by
    the check, and not as cases that fail for its reason."""
    module = GO_MODULE.search(go_mod or "")
    if module is None:
        return [(False, f"{LATEST_SITE} cases", f"{GO_MOD_NAME} declares no module")]
    go_mod_module = module.group(1)
    held = nested if nested is not None else ["verifiers/go"]
    readme, removed = _passing_latest_runs(readme, go_mod,
                                           sorted({*held, "verifiers/go"}))
    baseline = latest_run_failures(readme, go_mod, held)
    cases = [(not baseline,
              f"{LATEST_SITE}s held to the directories whose {GO_MOD_NAME} is in "
              f"the history ({', '.join(held)})"
              + (f"; the cases below run without the {len(removed)} fenced "
                 f"line(s) the check fails" if removed else ""),
              f"they fail: {baseline}")]

    def case(label, text, want):
        new = latest_run_failures(text, go_mod, ["verifiers/go"])
        named = any(f.startswith(LATEST_SITE) and "under verifiers/go," in f for f in new)
        cases.append((named == want, label,
                      f"expected {'a' if want else 'no'} {LATEST_SITE} failure "
                      f"naming verifiers/go, got {new}"))

    def fenced(command):
        return f"\n\n```bash\n{command}\n```\n"

    retracted = f"go run {go_mod_module}/verifiers/go@latest"
    case(f"README restating the retracted first command `{retracted}` in a fenced block",
         readme + fenced(retracted), True)
    case("a fenced `go run ...@latest` of a package below verifiers/go",
         readme + fenced(f"go run {go_mod_module}/verifiers/go/cmd/x@latest path/to/fixtures"),
         True)
    case(f"`{retracted}` in prose, outside a fenced block",
         readme + f"\n\n`{retracted}` exits 1.\n", False)
    return cases


def _failing_latest_run_cases(tree):
    """The README of 265c96b opened with the retracted command in a fenced
    block. The check failed it, and so did three self-test cases, for the
    README's reason and not their own: the cases above appended to it, and
    the `@latest` wiring case held it to verifiers/go, which it already
    failed on. Over the published README with a fenced block holding that
    command before its first line, the check must name the command and
    verifiers/go, and every case above and the wiring case must stay
    green."""
    module = GO_MODULE.search(tree.go_mod or "")
    if module is None:
        return [(False, f"{LATEST_SITE} cases over a README the check fails",
                 f"{GO_MOD_NAME} declares no module")]
    retracted = f"go run {module.group(1)}/verifiers/go@latest"
    readme = f"```bash\n{retracted}\n```\n\n" + tree.readme
    held = sorted({*(tree.nested_modules or []), "verifiers/go"})
    label = f"a README opening with `{retracted}` in a fenced block"
    failures = latest_run_failures(readme, tree.go_mod, held)
    cases = [(any(f"`{retracted}` names a package under verifiers/go," in f
                  for f in failures),
              f"{label} fails the check, naming the command and verifiers/go",
              f"got {failures}")]
    red = [case_label for ok, case_label, _ in
           _latest_run_cases(readme, tree.go_mod, held) if not ok]
    cases.append((not red, f"{LATEST_SITE} cases over {label}",
                  f"red for the README's failure, not their own: {red}"))
    entry = next((e for e in CHECKS if e.wiring is _wire_latest_run), None)
    if entry is None:
        cases.append((False, f"the `@latest` wiring case over {label}",
                      "no entry of CHECKS has the `@latest` wiring"))
    else:
        ok, _, detail = _wiring_case(tree._replace(readme=readme, nested_modules=held),
                                     entry)
        cases.append((ok, f"the {entry.name} wiring case over {label}", detail))
    return cases


# A command no README.md here opens with.
INVENTED_FIRST_COMMAND = "go run example.invalid/not-the-first-command@latest"


def _unreleased_with(changelog, text):
    """`changelog` with `text` as a paragraph opening its Unreleased section,
    which is added at the top when it has none."""
    lines = changelog.split("\n")
    at = next((i for i, line in enumerate(lines) if line.rstrip() == UNRELEASED), None)
    if at is None:
        return f"{UNRELEASED}\n\n{text}\n\n{changelog}"
    return "\n".join(lines[:at + 1] + ["", text, ""] + lines[at + 1:])


def _changelog_first_command_cases(tree):
    """Sentences added to the Unreleased section of the published
    CHANGELOG.md. Against the published README.md, the retracted sentence and
    one naming an invented command as README's first command each add a
    failure naming the command; one naming README.md's first command adds
    none, nor does it in the list item after one naming another command with
    no closing period, and it adds a failure once README.md opens with another
    command. The retracted sentence below the Unreleased section adds none,
    nor does a form of command (`go run <import path>@<version>`). Against a
    README.md opening with `cd verifiers/go && go run . ../../fixtures`, that
    command with or without its `cd` prefix adds none, and the command with
    another path adds a failure naming the span whole; `<module>` reads as the
    module go.mod declares. A missing CHANGELOG.md is reported. Each case
    counts only the failures the text it adds brings, so over the
    CHANGELOG.md of 20799e3, which the check fails, each case stays green."""
    changelog = tree.changelog or ""
    first = first_command(tree.front_page)
    if first is None:
        return [(False, f"{FIRST_COMMAND_SITE} cases", "README.md has no fenced block")]
    cases = []

    def case(label, text, want, page=tree.front_page, go_mod=tree.go_mod):
        before = collections.Counter(
            changelog_first_command_failures(changelog, page, go_mod))
        after = collections.Counter(changelog_first_command_failures(text, page, go_mod))
        new = list((after - before).elements())
        if want is None:
            cases.append((not new, label, f"it adds {new}"))
        else:
            want = f"names `{want}` as README.md's first command"
            cases.append((any(f.startswith(FIRST_COMMAND_SITE) and want in f for f in new),
                          label, f"expected a {FIRST_COMMAND_SITE} failure that "
                                 f"{want}, got {new}"))

    def opening(sentence):
        return _unreleased_with(changelog, sentence)

    retracted = CODE_SPAN.search(RETRACTED_FIRST_COMMAND).group(1)
    case(f"CHANGELOG.md restoring the retracted sentence on `{retracted}`",
         opening(RETRACTED_FIRST_COMMAND), retracted)
    case(f"CHANGELOG.md naming `{INVENTED_FIRST_COMMAND}` as README's first command",
         opening(f"`{INVENTED_FIRST_COMMAND}` is README's first command."),
         INVENTED_FIRST_COMMAND)
    holds = f"README.md's first command is `{first}`."
    case(f"CHANGELOG.md naming `{first}` as README.md's first command",
         opening(holds), None)
    case("CHANGELOG.md naming README.md's first command in the list item after "
         "one naming another command with no closing period",
         opening(f"- `{INVENTED_FIRST_COMMAND}` exits 1\n- {holds}"), None)
    block = FENCED.search(tree.front_page)
    other = (tree.front_page[:block.start(1)]
             + block.group(1).replace(first, INVENTED_FIRST_COMMAND, 1)
             + tree.front_page[block.end(1):])
    case(f"README.md opening with `{INVENTED_FIRST_COMMAND}` under a CHANGELOG.md "
         f"naming `{first}` as its first command", opening(holds), first, page=other)
    case("the retracted sentence in a CHANGELOG.md section below Unreleased",
         f"{changelog}\n## 0000000: a past commit\n\n{RETRACTED_FIRST_COMMAND}\n", None)
    case("a form of command, `go run <import path>@<version>`, in a sentence on "
         "README.md's first command",
         opening("`scripts/capture_go_verifier.py` reads README.md's first command and "
                 "runs `go run <import path>@<version>` as `go run ./<dir>`."), None)
    cd_page = "```bash\ncd verifiers/go && go run . ../../fixtures\n```\n"
    for label, sentence, want in (
            ("that command",
             "README.md's first command is `cd verifiers/go && go run . ../../fixtures`.",
             None),
            ("`go run . ../../fixtures` in `verifiers/go`",
             "README.md's first command, `go run . ../../fixtures` in `verifiers/go`, "
             "writes 93 lines.", None),
            ("`cd verifiers/go && go run . ../../other`, a span holding `. `",
             "README.md's first command is `cd verifiers/go && go run . ../../other`.",
             "cd verifiers/go && go run . ../../other")):
        case(f"README.md opening with `cd verifiers/go && go run . ../../fixtures`: "
             f"CHANGELOG.md naming {label} as its first command", opening(sentence), want,
             page=cd_page)
    case("CHANGELOG.md naming `go run <module>/cmd/x@latest` as README.md's first "
         "command, which is `go run example.invalid/m/cmd/x@latest` in module "
         "example.invalid/m",
         opening("README.md's first command is `go run <module>/cmd/x@latest`."), None,
         page="```bash\ngo run example.invalid/m/cmd/x@latest\n```\n",
         go_mod="module example.invalid/m\n")
    missing = changelog_first_command_failures(None, tree.front_page, tree.go_mod)
    cases.append((any(f"{CHANGELOG_NAME} is missing" in f for f in missing),
                  "CHANGELOG.md missing", f"got {missing}"))
    return cases


def _first_module_commit_cases():
    """first_module_commit() over a repository whose first commit holds a
    nested verifiers/go module, whose second adds go.mod at the root and whose
    third edits it: the second commit, or None for another module, a shallow
    clone and a directory that is no repository. A git command that fails is a
    red case."""
    label = "first_module_commit() over a temporary repository"
    env = {name: value for name, value in os.environ.items()
           if not name.startswith("GIT_")}
    config = ("-c", "user.name=self-test", "-c", "user.email=self-test@example.invalid",
              "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null")

    def git(cwd, *args):
        return subprocess.run(["git", *config, *args], cwd=cwd, env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(repo, files, message):
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text, encoding="utf-8")
        git(repo, "add", "--", *files)
        git(repo, "commit", "-q", "-m", message)
        return git(repo, "rev-parse", "HEAD")

    module = "module example.com/m\n\ngo 1.22.0\n"
    with tempfile.TemporaryDirectory(prefix="readme-counts-git-") as tmp:
        repo = pathlib.Path(tmp) / "repo"
        repo.mkdir()
        try:
            git(repo, "-c", "init.defaultBranch=main", "init", "-q")
            commit(repo, {"verifiers/go/go.mod": "module example.com/m/verifiers/go\n"},
                   "nested module")
            first = commit(repo, {GO_MOD_NAME: module}, "go.mod at the root")
            commit(repo, {GO_MOD_NAME: module + "\nrequire a.example/x v1.0.0\n"},
                   "edit go.mod")
            shallow = pathlib.Path(tmp) / "shallow"
            git(tmp, "clone", "-q", "--depth", "1", repo.resolve().as_uri(), str(shallow))
            plain = pathlib.Path(tmp) / "plain"
            plain.mkdir()
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = getattr(exc, "stderr", None) or exc
            return [(False, label, f"git failed building the repository: {detail}")]
        return [
            (first_module_commit(repo, module) == first,
             f"{label}: the commit that added go.mod at the root",
             f"expected {first}, got {first_module_commit(repo, module)}"),
            (first_module_commit(repo, "module example.com/other\n") is None,
             f"{label}: a module no commit's go.mod declares",
             "expected None"),
            (first_module_commit(shallow, module) is None,
             f"{label}: a shallow clone of it",
             f"expected None, got {first_module_commit(shallow, module)}"),
            (first_module_commit(plain, module) is None,
             f"{label}: a directory that is no repository",
             f"expected None, got {first_module_commit(plain, module)}"),
            (nested_module_dirs(repo) == ["verifiers/go"],
             "nested_module_dirs() over the same repository: verifiers/go, whose "
             "go.mod is in the history, and not the root",
             f"expected ['verifiers/go'], got {nested_module_dirs(repo)}"),
            (nested_module_dirs(shallow) is None,
             "nested_module_dirs() over a shallow clone of it",
             f"expected None, got {nested_module_dirs(shallow)}"),
            (nested_module_dirs(plain) is None,
             "nested_module_dirs() over a directory that is no repository",
             f"expected None, got {nested_module_dirs(plain)}"),
        ]


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
    other = "The TypeScript verifier is zero-dependency."
    new = added(python_dependency_failures(requirements, appended(site, other)))
    cases.append((not new, f"{site} calling a verifier other than the Python one "
                           f"zero-dependency",
                  f"a statement that does not name the Python verifier fails: {new}"))

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
             f"{path} calls an RFC 8785 library")
        case(f"{path} not citing {JCS_APPENDIX_G}",
             dict(sites, **{path: text.replace(JCS_APPENDIX_G, "RFC 8785")}),
             f"{path} does not say canonicalize is listed in")
        case(f"{path} missing",
             {p: t for p, t in sites.items() if p != path},
             f"{path} is missing")

    cited = [path for path, _ in JCS_LIBRARY_SITES]
    for path, retracted in JCS_PORT_SITES:
        label = f"{path} restored to the retracted reference-port claim"
        if path not in sites:
            cases.append((False, label, f"{path} not found"))
            continue
        case(label, dict(sites, **{path: sites[path] + "\n" + retracted + "\n"}),
             f"{path} calls an RFC 8785 library")
        if path not in cited:
            case(f"{path} missing",
                 {p: t for p, t in sites.items() if p != path},
                 f"{path} is missing")
    return cases


def _outside_code_cases(sites, libraries):
    """Restore each file's retracted claim and remove the file; each must add
    a failure naming the file. The same claim must pass when the legs run no
    third-party library, so the check holds the claim to what they run."""
    baseline = set(outside_code_failures(sites, libraries))
    cases = [(bool(libraries),
              "libraries the gate's Go and TypeScript legs run can be read",
              f"read none from {GATE_GO_MOD_NAME} and {GATE_PACKAGE_NAME}")]
    for path, retracted in OUTSIDE_CODE_SITES:
        label = f"{path} restored to the retracted no-outside-code claim"
        if path not in sites:
            cases.append((False, label, f"{path} not found"))
            continue
        restored = dict(sites, **{path: sites[path] + "\n" + retracted + "\n"})
        new = [f for f in outside_code_failures(restored, libraries) if f not in baseline]
        cases.append((any(f.startswith(f"{path} says the gate") for f in new), label,
                      f"appending its published wording still passes: {new}"))
        new = outside_code_failures(restored, [])
        cases.append((not any(f.startswith(f"{path} says the gate") for f in new),
                      f"{path} no-outside-code claim when the legs run no library",
                      f"expected no failure with no library to run, got {new}"))
        new = [f for f in outside_code_failures(
            {p: t for p, t in sites.items() if p != path}, libraries) if f not in baseline]
        cases.append((any(f.startswith(f"{path} is missing") for f in new),
                      f"{path} missing, where it says what the gate runs",
                      f"a missing {path} still passes: {new}"))
    return cases


# A verifier leg banner no gate script here carries, for the cases that add one.
INVENTED_LEG = "verifiers/invented"


def _gate_leg_cases(readme, profile, gate_script):
    """Restore each retracted description of the gate, give the gate script a
    verifier leg no description names, and remove the script and the profile;
    each must add a failure naming the site."""
    if gate_script is None or profile is None:
        return [(False, "byte-agreement gate descriptions",
                 f"{GATE_SCRIPT_NAME} or {PROFILE_NAME} is missing")]
    baseline = set(gate_leg_failures(readme, profile, gate_script))
    legs = verifier_legs(gate_script)
    sites = [site for site, _ in gate_descriptions(readme, profile)]
    cases = [(bool(legs), f"{GATE_SCRIPT_NAME} verifier leg banners can be read",
              "no `=== [verifier/<name>] verifiers/<dir> ` banner found")]
    for site in (README_GATE_SITE, PROFILE_GATE_SITE):
        cases.append((site in sites, f"{site} found",
                      "site not found: a description of the gate is not covered "
                      "by this self-test"))

    def case(label, where, needle, readme=readme, profile=profile, gate_script=gate_script):
        new = [f for f in gate_leg_failures(readme, profile, gate_script)
               if f not in baseline]
        cases.append((any(f.startswith(where) and needle in f for f in new), label,
                      f"expected a failure opening {where!r} and naming {needle!r}, "
                      f"got {new}"))

    first = legs[0] if legs else INVENTED_LEG
    for claim in RETRACTED_GATE_CLAIMS:
        case(f"README describing the gate as canonicalizers alone: "
             f"{claim.splitlines()[0][:40]}...",
             README_GATE_SITE, f"does not name {first}",
             readme=readme + "\n\n" + claim + "\n")
    label = f"{PROFILE_NAME} describing the gate as canonicalizers alone"
    try:
        doc = json.loads(profile)
        for gate in doc["additionalGates"]:
            if gate["path"] == GATE_SCRIPT_NAME:
                gate["description"] = RETRACTED_PROFILE_GATE
    except (ValueError, KeyError, TypeError):
        cases.append((False, label, f"{PROFILE_NAME} has no additionalGates entry to alter"))
    else:
        case(label, PROFILE_GATE_SITE, f"does not name {first}", profile=json.dumps(doc))
    grown = gate_script + f'\necho "=== [verifier/invented] {INVENTED_LEG} check ==="\n'
    for site in (README_GATE_SITE, PROFILE_GATE_SITE):
        case(f"{site} when the gate script gains a verifier leg",
             site, f"does not name {INVENTED_LEG}", gate_script=grown)
    case(f"{GATE_SCRIPT_NAME} missing, where its legs are read",
         GATE_SCRIPT_NAME, "is missing", gate_script=None)
    case(f"{PROFILE_NAME} missing, where it describes the gate",
         PROFILE_NAME, "is missing", profile=None)
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


# The Scope row that states how many fixtures reach signature verification, as
# a reader finds it: group 1 is its covered-by cell, group 2 the count that
# reach step 5 and group 3 the fixture total.
SIGNATURE_COUNT_SITE = re.compile(
    r"^\| [^|\n]*signature verification[^|\n]*\| ([^|\n]*?\b(\d+) of (\d+)\b[^|\n]*?) \|$",
    re.M | re.I)
# Counts no fixture set here holds, and not ones the other cases write.
SIGNATURE_BAD_REACHED = "9101"
SIGNATURE_BAD_TOTAL = "9102"


def _signature_coverage_cases(readme, outcomes):
    """Alter each count in the Scope row that states how many fixtures reach
    signature verification, put the row back to "every fixture", and change
    one fixture's expected outcome in memory; each must add a failure. With
    no fixture rejecting before step 5, "every fixture" must pass."""
    labels = (
        "Scope signature row count of fixtures that reach step 5",
        "Scope signature row fixture total",
        "Scope signature row saying every fixture while one rejects before step 5",
        "Scope signature row saying every fixture while none rejects before step 5",
        "fixture expected to reject before step 5 where it was expected to reach it",
        "fixture whose reject category is placed at no step",
    )
    site = SIGNATURE_COUNT_SITE.search(readme)
    names = sorted(outcomes)
    if site is None or not names:
        why = ("no fixture found, so no expected outcome can be altered"
               if site is not None else
               "no Scope row stating `N of M` for signature verification found "
               "in README.md: a count stated there is not covered by this "
               "self-test")
        return [(False, label, why) for label in labels]
    baseline = set(signature_coverage_failures(readme, outcomes))

    def new(text, altered):
        return [f for f in signature_coverage_failures(text, altered)
                if f not in baseline]

    def stating(group, text):
        return readme[:site.start(group)] + text + readme[site.end(group):]

    cases = []
    for label, group, bad, want in (
            (labels[0], 2, SIGNATURE_BAD_REACHED,
             f"covered by {SIGNATURE_BAD_REACHED} of"),
            (labels[1], 3, SIGNATURE_BAD_TOTAL,
             f"of {SIGNATURE_BAD_TOTAL} fixtures, but")):
        got = new(stating(group, bad), outcomes)
        cases.append((any(want in f for f in got), label,
                      f"README.md stating {bad} instead of {site.group(group)} "
                      f"still passes: {got}"))

    every = stating(1, "every fixture")
    early = {**outcomes, names[0]: ("REJECT", "EXPIRED")}
    got = new(every, early)
    cases.append((any("as covered by every fixture, but" in f for f in got),
                  labels[2], f"the row reading `every fixture` still passes: {got}"))
    got = signature_coverage_failures(every, {n: ("ACCEPT", None) for n in names})
    cases.append((not got, labels[3],
                  f"the row reading `every fixture` fails with every fixture "
                  f"expected to ACCEPT: {got}"))

    reaching = [n for n in names if reaches_signature_step(outcomes[n])]
    if not reaching:
        cases.append((False, labels[4], "no fixture is expected to reach step 5"))
    else:
        want = f"but {len(reaching) - 1} of {len(names)} reach signature verification"
        got = new(readme, {**outcomes, reaching[0]: ("REJECT", "EXPIRED")})
        cases.append((any(want in f for f in got), labels[4],
                      f"expected a failure containing {want!r}, got {got}"))

    want = f"fixtures/{names[0]}: expected outcome is neither ACCEPT"
    got = new(readme, {**outcomes, names[0]: ("REJECT", "NOT_A_CATEGORY")})
    cases.append((any(want in f for f in got), labels[5],
                  f"expected a failure containing {want!r}, got {got}"))
    return cases


# Counts no fixture set here holds, and not ones the other cases write.
ED25519_BAD_ONLY = "9201"
ED25519_BAD_ACCEPT = "9202"


def _ed25519_only_cases(readme, suites):
    """Alter each count in the statement of how many ACCEPT fixtures carry
    Ed25519 signatures only, then change the fixtures in memory: one
    Ed25519-only ACCEPT fixture given an ML-DSA-65 signature, one REJECT
    fixture expected to ACCEPT, one fixture that cannot be read. Each must
    add a failure."""
    labels = (
        "scope count of ACCEPT fixtures that carry Ed25519 signatures only",
        "scope count of ACCEPT fixtures",
        "Ed25519-only ACCEPT fixture given an ML-DSA-65 signature",
        "REJECT fixture expected to ACCEPT",
        "fixture whose expected object or signatures cannot be read",
    )
    site = ED25519_ONLY_CLAIM.search(readme)
    names = sorted(n for n in suites if suites[n] is not None)
    if site is None or not names:
        why = ("no fixture found whose expected outcome and signatures can be read"
               if site is not None else
               "no `N of its M ACCEPT fixtures` statement found in README.md or "
               "its pages: a count stated there is not covered by this self-test")
        return [(False, label, why) for label in labels]
    baseline = set(ed25519_only_failures(readme, suites))

    def new(text, altered):
        return [f for f in ed25519_only_failures(text, altered) if f not in baseline]

    cases = []
    for label, group, bad, want in (
            (labels[0], 1, ED25519_BAD_ONLY, f"states {ED25519_BAD_ONLY} of its"),
            (labels[1], 2, ED25519_BAD_ACCEPT, f"of its {ED25519_BAD_ACCEPT} ACCEPT")):
        got = new(readme[:site.start(group)] + bad + readme[site.end(group):], suites)
        cases.append((any(want in f for f in got), label,
                      f"README stating {bad} instead of {site.group(group)} "
                      f"still passes: {got}"))

    accept = [n for n in names if suites[n][0] == "ACCEPT"]
    only = [n for n in accept if set(suites[n][1]) == {ED25519}]
    rejected = [n for n in names if suites[n][0] != "ACCEPT"]
    for label, pool, altered, want in (
            (labels[2], only,
             lambda n: (suites[n][0], suites[n][1] + ("ML-DSA-65",)),
             f"but {len(only) - 1} of the {len(accept)} fixtures expected"),
            (labels[3], rejected,
             lambda n: ("ACCEPT", suites[n][1]),
             f"of the {len(accept) + 1} fixtures expected to ACCEPT")):
        if not pool:
            cases.append((False, label, "no fixture found to alter"))
            continue
        got = new(readme, {**suites, pool[0]: altered(pool[0])})
        cases.append((any(want in f for f in got), label,
                      f"expected a failure containing {want!r}, got {got}"))

    want = f"fixtures/{names[0]}: no expected object or atx.signatures list"
    got = new(readme, {**suites, names[0]: None})
    cases.append((any(want in f for f in got), labels[4],
                  f"expected a failure containing {want!r}, got {got}"))
    return cases


INVENTED_SCRIPT = "check_invented.py"


def _ci_gate_label_cases(readme, workflow, scripts):
    """Add a script no workflow step runs, stop the workflow naming this
    script, then name it again only in a YAML comment, only in shell comments
    of a `run:` step, only in a step name and an action input, only in the
    name of a step written as a flow mapping, and only in a YAML comment
    between a step's `run:` key and the command on the lines after it, run an
    invented helper only through an import and then cut the import, and give
    a script that is not run its own layout line, once calling it a CI gate
    and once not. Each but the last must add a failure. Then run this script
    from a step whose command starts on the line after `run:`, from a step
    written as a flow mapping on one line, from one whose command is on its
    second line, from steps whose `run:` key is double-quoted, single-quoted
    or double-quoted with a `\\x` escape, from a flow-mapping step whose
    keys are double-quoted, and from steps whose `run` key, plain or
    double-quoted, has a space before its `:`: none of the nine may add a
    failure. Last, name
    it under the single-quoted key `'ru''n'`, which reads as `ru'n`: that
    must add a failure."""
    labels = (
        "scripts/*.py script that no workflow step runs",
        "script the workflow stops naming",
        "script the workflow names only in a YAML comment",
        "script named only in shell comments of a run: step",
        "script named only in a step name and an action input",
        "script run only through an import, with the import cut",
        "own layout line calling a script that is not run a CI gate",
        "own layout line saying a script that is not run is run by hand",
        "script named only in the name of a flow-mapping step",
        "script named only in a YAML comment after a run: key",
        "script run by a step whose command starts on the line after run:",
        "script run by a step written as a flow mapping",
        "script run by a flow-mapping step whose command is on its second line",
        "script run by a step whose run: key is double-quoted",
        "script run by a step whose run: key is single-quoted",
        "script run by a step whose double-quoted run: key holds an escape",
        "script run by a flow-mapping step whose keys are double-quoted",
        "script named only under a quoted key that reads as ru'n",
        "script run by a step with a space between its run key and the colon",
        "script run by a step with a space after its double-quoted run key",
    )
    if not CI_GATE_GLOB.search(readme):
        why = ("no `scripts/*.py  CI gates` layout line found in README.md or its "
               "pages: the label is not covered by this self-test")
        return [(False, label, why) for label in labels]
    baseline = set(ci_gate_label_failures(readme, workflow, scripts))

    def new(text, flow, files):
        return [f for f in ci_gate_label_failures(text, flow, files) if f not in baseline]

    cases = []
    want = f"does not run scripts/{INVENTED_SCRIPT}"
    got = new(readme, workflow, {**scripts, INVENTED_SCRIPT: ""})
    cases.append((any(want in f for f in got), labels[0],
                  f"expected a failure containing {want!r}, got {got}"))

    this = pathlib.Path(__file__).name
    if f"scripts/{this}" not in (workflow or ""):
        why = f"{WORKFLOW_NAME} does not name scripts/{this}"
        cases.extend((False, label, why) for label in labels[1:5] + labels[8:])
    else:
        want = f"does not run scripts/{this}"
        renamed = workflow.replace(f"scripts/{this}", "scripts/renamed.py")
        # Each text is appended after the workflow's last step.
        named_not_run = (
            (labels[1], ""),
            (labels[2], f"\n# scripts/{this} is not run here\n"),
            (labels[3], f"\n      - run: |\n          # python3 scripts/{this}\n"
                        f"          echo done # scripts/{this}\n"),
            (labels[4], f"\n      - name: python3 scripts/{this}\n"
                        f"        uses: actions/checkout@v4\n"
                        f"        with:\n          run: python3 scripts/{this}\n"),
            (labels[8], f"\n      - {{name: python3 scripts/{this}, "
                        f"uses: actions/checkout@v4}}\n"),
            (labels[9], f"\n      - run:\n          # python3 scripts/{this}\n"
                        f"          echo done\n"),
            (labels[17], f"\n      - 'ru''n': python3 scripts/{this}\n"),
        )
        for label, text in named_not_run:
            got = new(readme, renamed + text, scripts)
            cases.append((any(want in f for f in got), label,
                          f"expected a failure containing {want!r}, got {got}"))
        run = (
            (labels[10], f"\n      - run:\n          python3 scripts/{this}\n"),
            (labels[11], f"\n      - {{name: a, run: python3 scripts/{this}}}\n"),
            (labels[12], f"\n      - {{name: a, run:\n          "
                         f"'python3 scripts/{this}'}}\n"),
            (labels[13], f"\n      - \"run\": python3 scripts/{this}\n"),
            (labels[14], f"\n      - 'run': python3 scripts/{this}\n"),
            (labels[15], f"\n      - \"r\\x75n\": python3 scripts/{this}\n"),
            (labels[16], f"\n      - {{\"name\": a, \"run\": \"python3 scripts/{this}\"}}\n"),
            (labels[18], f"\n      - run : python3 scripts/{this}\n"),
            (labels[19], f"\n      - \"run\" : python3 scripts/{this}\n"),
        )
        for label, text in run:
            got = new(readme, renamed + text, scripts)
            cases.append((not any(want in f for f in got), label,
                          f"the step is not read as running it: {got}"))

    flow = (workflow or "") + "\n        run: python3 scripts/invented_runner.py\n"
    files = {**scripts, "invented_runner.py": "import invented_helper  # noqa\n",
             "invented_helper.py": ""}
    want = "does not run scripts/invented_helper.py"
    reached = not any(want in f for f in new(readme, flow, files))
    cut = new(readme, flow, {**files, "invented_runner.py": ""})
    cases.append((reached and any(want in f for f in cut), labels[5],
                  f"with the import: {'not ' if reached else ''}reported; "
                  f"with it cut: {cut}"))

    line = f"\nscripts/{INVENTED_SCRIPT}            CI gate: an invented check\n"
    want = f"calls scripts/{INVENTED_SCRIPT} a CI gate"
    got = new(readme + line, workflow, {**scripts, INVENTED_SCRIPT: ""})
    cases.append((any(want in f for f in got), labels[6],
                  f"expected a failure containing {want!r}, got {got}"))
    line = f"\nscripts/{INVENTED_SCRIPT}\n                       an invented check (run by hand)\n"
    got = new(readme + line, workflow, {**scripts, INVENTED_SCRIPT: ""})
    cases.append((not got, labels[7], f"the line still fails: {got}"))
    return cases


def _front_page_cases(front_page):
    """Append one line to README.md alone: the line the version-or-date gate
    was written for, a version and a date must each fail it on that line
    number, and the two-part ATX labels the intro names must not."""
    baseline = set(front_page_failures(front_page))
    cases = []
    for label, line, value in (
            ("README.md restoring the date A2A#1876 closed", RETRACTED_DATE_LINE,
             "2026-06-15"),
            ("README.md stating a toolchain minimum", "Requires Go 1.22.0 or later.",
             "1.22.0"),
            ("README.md stating a pinned release", "Pin the suite at v0.4.1.",
             "v0.4.1"),
            ("README.md stating a date", "Last checked 2026-10-01.", "2026-10-01"),
            ("README.md naming ATX v1.0 and v1.1", "Fixtures for ATX v1.0 and v1.1.",
             None)):
        altered = front_page + "\n" + line + "\n"
        new = [f for f in front_page_failures(altered) if f not in baseline]
        if value is None:
            cases.append((not new, label, f"the gate fired on it: {new}"))
            continue
        want = f"README.md:{len(altered.splitlines())} states {value!r}"
        cases.append((any(f.startswith(want) for f in new), label,
                       f"expected a failure starting {want!r}, got {new}"))
    return cases


def _wire_count(tree):
    row = FIXTURE_ROW.search(tree.readme)
    if row is None:
        return "no fixture-table row found in README.md"
    end = tree.readme.index("\n", row.start()) + 1
    return (f"has no row for fixtures/{row.group(1)}",
            {"readme": tree.readme[:row.start()] + tree.readme[end:]})


def _wire_threshold(tree):
    scope = re.search(r"^## Scope\n.*?^\|[-| ]+\|\n", tree.readme, re.M | re.S)
    if scope is None:
        return "no `## Scope` table found in README.md"
    claim = "Threshold 2-of-3 cosignature path"
    return (f"lists {claim!r} as covered",
            {"readme": (tree.readme[:scope.end()] + f"| {claim} | every fixture |\n"
                        + tree.readme[scope.end():]),
             "fixture_paths": [p for p in tree.fixture_paths
                               if not declares_threshold(p)]})


def _wire_signature_coverage(tree):
    scope = re.search(r"^## Scope\n.*?^\|[-| ]+\|\n", tree.readme, re.M | re.S)
    if scope is None:
        return "no `## Scope` table found in README.md"
    stated = f"{SIGNATURE_BAD_REACHED} of {SIGNATURE_BAD_TOTAL}"
    return (f"covered by {stated} fixtures",
            {"readme": (tree.readme[:scope.end()]
                        + f"| Ed25519 signature verification | {stated} |\n"
                        + tree.readme[scope.end():])})


def _wire_behavioral_profile(tree):
    return ("behavioralProfile is omitted",
            {"readme": tree.readme.replace(
                "- Behavioral profile validation.",
                "- Behavioral profile validation. It is omitted.", 1)})


def _wire_ci_trigger(tree):
    return f"{WORKFLOW_NAME} is missing", {"workflow": None}


def _wire_key_source(tree):
    return ("nobody.example#key-1, which no vectors/*.json provides",
            {"used_key_ids": tree.used_key_ids
             | {"did:opena2a:authority:nobody.example#key-1"}})


def _wire_version_label(tree):
    return f"{INTRO_SITE} omits v9.9", {"versions": set(tree.versions) | {"9.9"}}


def _wire_go_dependency(tree):
    if tree.go_mod is None:
        return f"{GO_MOD_NAME} is missing"
    return GO_INVENTED, {"go_mod": (tree.go_mod
                                    + f"\nrequire {GO_INVENTED} {GO_ALTERED_VERSION}\n")}


def _wire_module_start(tree):
    if not any(COMMIT_FORM in s for s in statements(tree.readme)):
        return f"no sentence offering {COMMIT_FORM} found in README.md or its pages"
    return f"is {INVENTED_START[:7]}", {"module_start": INVENTED_START}


def _wire_latest_run(tree):
    module = GO_MODULE.search(tree.go_mod or "")
    paths = [path for block in FENCED.findall(tree.readme)
             for path in LATEST_RUN.findall(block)
             if module is not None and path.startswith(module.group(1) + "/")]
    if not paths:
        return (f"no fenced `go run <module>/<dir>@latest` command found in "
                f"README.md or its pages")
    # A directory already listed adds no failure, so a command the check
    # already fails (verifiers/go@latest under verifiers/go) is held to a
    # directory above its package (verifiers) instead.
    nested = tree.nested_modules or []
    for path in paths:
        parts = path[len(module.group(1)) + 1:].split("/")
        for directory in ("/".join(parts[:i]) for i in range(len(parts), 0, -1)):
            if directory and directory not in nested:
                return (f"names a package under {directory},",
                        {"nested_modules": [*nested, directory]})
    return (f"each directory holding the package of a fenced `go run "
            f"<module>/<dir>@latest` command is already listed as one whose "
            f"{GO_MOD_NAME} is in HEAD's history")


def _wire_changelog_first_command(tree):
    return (f"names `{INVENTED_FIRST_COMMAND}` as README.md's first command",
            {"changelog": _unreleased_with(
                tree.changelog or "",
                f"`{INVENTED_FIRST_COMMAND}` is README.md's first command.")})


def _wire_python_dependency(tree):
    site = PY_DEPENDENCY_SITES[0]
    if tree.py_dependency_texts.get(site) is None:
        return f"{site} is missing"
    return (f"{site} calls the Python verifier zero-dependency",
            {"py_requirements": (tree.py_requirements or "") + "\ncryptography\n",
             "py_dependency_texts": {
                 **tree.py_dependency_texts,
                 site: (tree.py_dependency_texts[site]
                        + "\n\nThe Python verifier is zero-dependency.\n")}})


def _wire_jcs_library(tree):
    path, retracted = JCS_LIBRARY_SITES[0]
    return (f"{path} calls an RFC 8785 library",
            {"jcs_sites": {**tree.jcs_sites,
                           path: tree.jcs_sites.get(path, "") + "\n" + retracted + "\n"}})


def _wire_tbs_number(tree):
    site, retracted = TBS_NUMBER_SITES[0]
    return (f"{site} says `trustLevel` is the only JSON number",
            {"tbs_sites": {**tree.tbs_sites,
                           site: (tree.tbs_sites.get(site) or "") + "\n" + retracted + "\n"}})


def _wire_signing_scope(tree):
    return ("is signed, but the TBS is an explicit projection",
            {"jcs_readme": (tree.jcs_readme or "") + "\n" + RETRACTED_FUTURE_CLAIM + ".\n"})


def _wire_outside_code(tree):
    path, retracted = OUTSIDE_CODE_SITES[0]
    if not tree.gate_libraries:
        return f"no library read from {GATE_GO_MOD_NAME} or {GATE_PACKAGE_NAME}"
    return (f"{path} says the gate",
            {"gate_sites": {**tree.gate_sites,
                            path: tree.gate_sites.get(path, "") + "\n" + retracted + "\n"}})


def _wire_gate_leg(tree):
    script = tree.gate_sites.get(GATE_SCRIPT_NAME)
    if script is None:
        return f"{GATE_SCRIPT_NAME} is missing"
    banner = f'\necho "=== [verifier/invented] {INVENTED_LEG} check ==="\n'
    return (f"does not name {INVENTED_LEG}",
            {"gate_sites": {**tree.gate_sites, GATE_SCRIPT_NAME: script + banner}})


def _wire_ed25519_only(tree):
    site = ED25519_ONLY_CLAIM.search(tree.readme)
    if site is None:
        return "no `N of its M ACCEPT fixtures` statement found in README.md or its pages"
    return (f"states {ED25519_BAD_ONLY} of its",
            {"readme": (tree.readme[:site.start(1)] + ED25519_BAD_ONLY
                        + tree.readme[site.end(1):])})


def _wire_ci_gate_label(tree):
    return (f"does not run scripts/{INVENTED_SCRIPT}",
            {"scripts": {**tree.scripts, INVENTED_SCRIPT: ""}})


def _wire_front_page(tree):
    return ("README.md:1 states '9.9.9'",
            {"front_page": "Requires Go 9.9.9 or later.\n" + tree.front_page})


CHECKS = (
    Check("count",
          lambda t: check(t.readme, t.cosigners, t.fixtures, t.vectors, t.signing),
          _wire_count),
    Check("threshold", lambda t: threshold_claims(t.readme, t.fixture_paths),
          _wire_threshold),
    Check("signature coverage",
          lambda t: signature_coverage_failures(t.readme, t.outcomes),
          _wire_signature_coverage),
    Check("behavioralProfile",
          lambda t: behavioral_profile_failures(t.readme, t.fixture_paths),
          _wire_behavioral_profile),
    Check("CI trigger", lambda t: ci_trigger_failures(t.readme, t.workflow),
          _wire_ci_trigger),
    Check("key source",
          lambda t: key_source_failures(t.readme, t.key_vectors, t.used_key_ids),
          _wire_key_source),
    Check("version label", lambda t: version_label_failures(t.readme, t.versions),
          _wire_version_label),
    Check("Go dependency",
          lambda t: go_dependency_failures(t.readme, t.go_mod, t.verify_go),
          _wire_go_dependency),
    Check("`@<commit>` first commit",
          lambda t: module_start_failures(t.readme, t.module_start),
          _wire_module_start),
    Check("`@latest` package path",
          lambda t: latest_run_failures(t.readme, t.go_mod, t.nested_modules),
          _wire_latest_run),
    Check("CHANGELOG.md first command",
          lambda t: changelog_first_command_failures(t.changelog, t.front_page, t.go_mod),
          _wire_changelog_first_command),
    Check("Python dependency",
          lambda t: python_dependency_failures(t.py_requirements, t.py_dependency_texts),
          _wire_python_dependency),
    Check("RFC 8785 library", lambda t: jcs_library_failures(t.jcs_sites),
          _wire_jcs_library),
    Check("TBS number", lambda t: tbs_number_failures(t.tbs_sites, t.tbs_canonical),
          _wire_tbs_number),
    Check("signing scope", lambda t: jcs_scope_failures(t.jcs_readme),
          _wire_signing_scope),
    Check("outside code",
          lambda t: outside_code_failures(t.gate_sites, t.gate_libraries),
          _wire_outside_code),
    Check("gate leg",
          lambda t: gate_leg_failures(t.readme, t.profile,
                                      t.gate_sites.get(GATE_SCRIPT_NAME)),
          _wire_gate_leg),
    Check("Ed25519-only count", lambda t: ed25519_only_failures(t.readme, t.suites),
          _wire_ed25519_only),
    Check("CI gate label",
          lambda t: ci_gate_label_failures(t.readme, t.workflow, t.scripts),
          _wire_ci_gate_label),
    Check("README.md version or date", lambda t: front_page_failures(t.front_page),
          _wire_front_page),
)


def _wiring_case(tree, entry, checks=None):
    """Make `entry`'s alteration and run tree_failures() whole over `checks`
    (CHECKS when None); the altered tree must add the failure that check
    reports."""
    label = f"tree_failures() running the {entry.name} check"
    if entry.wiring is None:
        return False, label, f"the {entry.name} check has no wiring case"
    wired = entry.wiring(tree)
    if isinstance(wired, str):
        return False, label, wired
    want, altered = wired
    baseline = set(tree_failures(tree, checks))
    new = [f for f in tree_failures(tree._replace(**altered), checks)
           if f not in baseline]
    return (any(want in f for f in new), label,
            f"expected a failure containing {want!r}, got {new}")


def _wiring_cases(tree):
    """One case per entry of CHECKS: alter the one input the check reads and
    run tree_failures() whole. The cases above call each check directly, so
    they stay green when tree_failures() stops running one; these fail
    instead. Then each case is run again with its own check's call replaced
    by one that reports nothing, and must go red: a case that stays green
    there does not hold the call it is named for. An entry with no alteration
    is itself a red case."""
    cases = [_wiring_case(tree, entry) for entry in CHECKS]
    for index, entry in enumerate(CHECKS):
        silent = (CHECKS[:index] + (entry._replace(run=lambda t: []),)
                  + CHECKS[index + 1:])
        green, _, _ = _wiring_case(tree, entry, silent)
        cases.append((not green,
                      f"the {entry.name} wiring case is red once tree_failures() "
                      f"stops running that check",
                      "it stays green with the check's call replaced by one "
                      "that reports nothing"))
    green, _, detail = _wiring_case(tree, Check("unwired", lambda t: [], None))
    cases.append((not green and "has no wiring case" in detail,
                  "a check listed with no wiring case is reported",
                  f"got {detail!r}"))
    unrun = _unrun_checks(CHECKS)
    cases.append((not unrun, "every function that reports failures is run from CHECKS",
                  f"no entry of CHECKS, nor check(), calls {', '.join(unrun)}"))
    cases.append((bool(_unrun_checks(CHECKS[:-1])),
                  "an entry dropped from CHECKS leaves its function reported as unrun",
                  f"CHECKS without its {CHECKS[-1].name} entry still calls every function"))
    return cases


def _unrun_checks(checks):
    """The functions of this module that report failures (check(),
    threshold_claims() and every `*_failures`) and that neither an entry of
    `checks` nor check() calls. An entry carries its own wiring case, so one
    deleted whole takes its case with it; this is what still names it."""
    called = set(check.__code__.co_names)
    for entry in checks:
        called.update(entry.run.__code__.co_names)
    reporting = {"check", "threshold_claims"} | {
        name for name, value in globals().items()
        if name.endswith("_failures") and callable(value)}
    return sorted(reporting - called - {"tree_failures"})


# Set for the child run below, which skips that one case so the runs do not nest.
CHILD_ENV = "CHECK_README_COUNTS_CHILD"
CHILD_TIMEOUT = 120
# A count no fixture set here holds, and not one the self-test writes itself.
CHILD_COUNT = "7777"
# Left out of the copy: nothing the script reads, and the bulk of a checkout.
UNCOPIED = (".git", "node_modules", "__pycache__", ".venv", "venv")
# The line main() prints above the failures. Most checks hold a claim, not a
# count: the header read "README counts do not match the tree" for a criterion
# (c), threshold or behavioralProfile failure too.
FAILURE_HEADER = "Counts and claims stated in the README and the files it describes do not match the tree:"


def _whole_script_case(tree):
    """Run this script in a child process on a copy of the tree whose README
    states one wrong count; it must exit 1 and name that count. Every other
    case calls the checks directly, so they hold tree_failures() to each check
    and only this run holds main() to tree_failures()."""
    label = "main() exiting 1 on a copy of the tree with one README count altered"
    pattern = re.compile(r"must report\s+`(\d+) pass")
    if pattern.search(tree.readme) is None:
        return False, label, "no `must report `N pass`` site found in README.md or its pages"
    want = f"README claims `{CHILD_COUNT} pass` but fixtures/ holds {len(tree.fixtures)}"
    with tempfile.TemporaryDirectory(prefix="readme-counts-") as tmp:
        copy = pathlib.Path(tmp) / "tree"
        try:
            # The temporary directory is left out by name too, so a TMPDIR
            # inside the repository is not copied into itself.
            shutil.copytree(
                ROOT, copy, ignore_dangling_symlinks=True,
                ignore=shutil.ignore_patterns(*UNCOPIED, pathlib.Path(tmp).name))
            # The count is altered in the file that states it.
            for rel in (pathlib.Path("README.md"), *README_PAGES):
                page = copy / rel
                text = page.read_text(encoding="utf-8") if page.exists() else ""
                site = pattern.search(text)
                if site is not None:
                    page.write_text(text[:site.start(1)] + CHILD_COUNT + text[site.end(1):],
                                    encoding="utf-8")
                    break
            else:
                return False, label, "the copied tree states no `must report `N pass`` site"
        except (OSError, shutil.Error) as exc:
            return False, label, f"could not copy the tree to run it: {exc}"
        script = copy / pathlib.Path(__file__).resolve().relative_to(ROOT)
        try:
            child = subprocess.run(
                [sys.executable, str(script)], capture_output=True, text=True,
                timeout=CHILD_TIMEOUT, check=False, env={**os.environ, CHILD_ENV: "1"})
        except subprocess.TimeoutExpired:
            return False, label, f"the child run did not end within {CHILD_TIMEOUT} s"
    return (child.returncode == 1 and want in child.stderr
            and FAILURE_HEADER in child.stderr, label,
            f"expected exit 1 and {want!r} under {FAILURE_HEADER!r} on stderr, got "
            f"exit {child.returncode} and {child.stderr.strip()[-300:]!r}")


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

    for wording in (RETRACTED_CLAIM,) + CRITERION_C_SYNONYMS:
        altered = dict(texts)
        altered["README.md"] = readme + "\n" + wording + ".\n"
        new = run(altered)
        cases.append((any(f.startswith("README states \"") and "criterion" in f
                          for f in new),
                      f"README stating {' '.join(wording.split())!r} with no "
                      f"second-party cosignature",
                      f"appending it to README.md still passes: {new}"))

    cases.extend(_signature_coverage_cases(readme, tree.outcomes))
    cases.extend(_ed25519_only_cases(readme, tree.suites))
    cases.extend(_ci_gate_label_cases(readme, tree.workflow, tree.scripts))
    cases.extend(_trigger_cases(readme, tree.workflow))
    cases.extend(_key_source_cases(readme, tree.key_vectors, tree.used_key_ids))
    cases.extend(_version_cases(readme, tree.versions))
    cases.extend(_go_dependency_cases(readme, tree.go_mod, tree.verify_go))
    cases.extend(_module_start_cases(readme))
    cases.extend(_latest_run_cases(readme, tree.go_mod, tree.nested_modules))
    cases.extend(_failing_latest_run_cases(tree))
    cases.extend(_changelog_first_command_cases(tree))
    cases.extend(_python_dependency_cases(tree.py_requirements, tree.py_dependency_texts))
    cases.extend(_jcs_library_cases(tree.jcs_sites))
    cases.extend(_outside_code_cases(tree.gate_sites, tree.gate_libraries))
    cases.extend(_gate_leg_cases(readme, tree.profile,
                                 tree.gate_sites.get(GATE_SCRIPT_NAME)))
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
    # Each of these took 1.5 s or more while its pattern rescanned the run from
    # every position in it; bounded, each takes under 0.05 s.
    blank = "\n" * 20000
    for label, scan in (
            ("line-leading comment markers stripped from 20,000 blank lines (_flat_prose)",
             lambda: _flat_prose(blank)),
            ("line-leading comment markers stripped from 20,000 blank lines (_prose)",
             lambda: _prose(blank)),
            ("requirements.txt package names read from 20,000 blank lines",
             lambda: python_requirements(blank)),
            ("only-number claim scan over one 16,000-character word",
             lambda: list(ONLY_NUMBER_CLAIM.finditer("a" * 16000))),
            ("only-number claim scan over 40,000 unclosed parentheses",
             lambda: list(ONLY_NUMBER_CLAIM.finditer("a (" * 40000)))):
        started = time.perf_counter()
        scan()
        took = time.perf_counter() - started
        cases.append((took < 0.5, label,
                      f"took {took:.1f} s; the pattern rescans the run from every "
                      f"position in it"))
    cases.extend(_tbs_number_cases(tree.tbs_sites, tree.tbs_canonical))
    cases.extend(_front_page_cases(tree.front_page))

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

    if not os.environ.get(CHILD_ENV):
        cases.append(_whole_script_case(tree))

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
    # An unrecognised flag must not fall through to the default check and exit 0.
    unknown = [a for a in sys.argv[1:] if a not in ("--self-test", "-h", "--help")]
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(usage, file=sys.stderr)
        return 2
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print(usage)
        return 0
    only_self_test = "--self-test" in sys.argv

    fixtures, failures = load_fixtures(ROOT)
    key_vectors, vector_failures = load_key_vectors(ROOT)
    failures += vector_failures
    fixture_paths = sorted(FIXTURES.glob("*.json"))
    go_mod = GO_MOD.read_text(encoding="utf-8") if GO_MOD.exists() else None
    tree = Tree(
        readme=read_readme(ROOT),
        cosigners=COSIGNERS.read_text(encoding="utf-8") if COSIGNERS.exists() else None,
        fixtures=fixtures,
        vectors=count_vectors(ROOT),
        signing=generator_signing(ROOT),
        fixture_paths=fixture_paths,
        workflow=WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else None,
        key_vectors=key_vectors,
        used_key_ids=fixture_key_ids(fixture_paths),
        versions=accepted_versions(fixture_paths),
        go_mod=go_mod,
        verify_go=VERIFY_GO.read_text(encoding="utf-8") if VERIFY_GO.exists() else None,
        py_requirements=(PY_REQUIREMENTS.read_text(encoding="utf-8")
                         if PY_REQUIREMENTS.exists() else None),
        py_dependency_texts={
            site: (ROOT / site).read_text(encoding="utf-8") if (ROOT / site).exists() else None
            for site in PY_DEPENDENCY_SITES},
        jcs_sites={path: (ROOT / path).read_text(encoding="utf-8")
                   for path, _ in JCS_LIBRARY_SITES + JCS_PORT_SITES
                   if (ROOT / path).exists()},
        tbs_sites={site: (ROOT / site).read_text(encoding="utf-8")
                   if (ROOT / site).exists() else None
                   for site, _ in TBS_NUMBER_SITES},
        tbs_canonical=load_canonical_strings(ROOT),
        jcs_readme=JCS_README.read_text(encoding="utf-8") if JCS_README.exists() else None,
        gate_sites={path: (ROOT / path).read_text(encoding="utf-8")
                    for path, _ in OUTSIDE_CODE_SITES if (ROOT / path).exists()},
        gate_libraries=gate_libraries(*(
            (ROOT / name).read_text(encoding="utf-8") if (ROOT / name).exists() else None
            for name in (GATE_GO_MOD_NAME, GATE_PACKAGE_NAME))),
        profile=PROFILE.read_text(encoding="utf-8") if PROFILE.exists() else None,
        outcomes=expected_outcomes(fixture_paths),
        suites=signature_suites(fixture_paths),
        scripts={path.name: path.read_text(encoding="utf-8")
                 for path in sorted(SCRIPTS.glob("*.py"))},
        front_page=README.read_text(encoding="utf-8"),
        module_start=first_module_commit(ROOT, go_mod),
        nested_modules=nested_module_dirs(ROOT),
        changelog=CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.exists() else None,
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
        print(f"{FAILURE_HEADER}\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    if failed:
        return 1

    first = first_command(tree.front_page)
    print(f"README and COSIGNERS counts match the tree: {len(fixtures)} fixtures "
          f"(each with one fixture-table row), {tree.vectors} JCS vectors, all stated "
          f"as passing; README names the MANIFEST.sha256 byte check; "
          f"each signature-verification Scope row that claims a set of "
          f"fixtures states the count that reach step 5; "
          f"behavioralProfile scope note matches; criterion (c) claim matches "
          f"the cosignature registry; trustScore is called illustrative; "
          f"CI trigger sentence matches {WORKFLOW_NAME}; "
          f"both README key-source lists name every Ed25519 key in vectors/; "
          f"intro and version-pinning row name ATX {_versions(tree.versions)}; "
          f"Go verifier dependency list, version-pinning rows and verify.go "
          f"header name every direct requirement of {GO_MOD_NAME}; "
          f"each sentence offering {COMMIT_FORM} names its first commit"
          + (f", {tree.module_start[:7]}, the first in HEAD's history whose "
             f"{GO_MOD_NAME} at the root declares the module; "
             if tree.module_start else
             f" (not held to the history: none could be read in this checkout); ")
          + (f"each fenced `go run <module>/<dir>@latest` command names a package "
             f"under none of the {len(tree.nested_modules)} directories whose "
             f"{GO_MOD_NAME} is in HEAD's history; "
             if tree.nested_modules is not None else
             f"fenced `go run <module>/<dir>@latest` commands not held to the "
             f"history: none could be read in this checkout; ")
          + (f"each `go run` command the {CHANGELOG_NAME} Unreleased section "
             f"names as README.md's first command is `{first}`; "
             if first is not None else
             f"the {CHANGELOG_NAME} Unreleased section names no `go run` command "
             f"as README.md's first command; ")
          + f"no jcs-vectors README or RFC 8785 serializer docstring calls the "
          f"Python verifier zero-dependency; "
          f"each jcs-vectors file describing canonicalize cites "
          f"{JCS_APPENDIX_G} and none calls an RFC 8785 library a reference "
          f"implementation or port; "
          f"neither {JCS_README_NAME} nor {GATE_SCRIPT_NAME} says the gate runs "
          f"no code from another repository; "
          f"every description of the byte-agreement gate names each verifier "
          f"leg {GATE_SCRIPT_NAME} runs; "
          f"every Version pinning link names a commit; "
          f"the reproduction steps name every signing form and jcs-vectors "
          f"cross-check in the generator; coordination links point at an open "
          f"issue tracker; every statement of the JSON numbers in the TBS "
          f"matches the {len(tree.tbs_canonical)} JCS vectors, all of them integers; "
          f"{JCS_README_NAME} scopes v1.1 signing to the TBS projection; "
          f"the Ed25519-only ACCEPT count matches the fixtures; "
          f"{WORKFLOW_NAME} runs each scripts/*.py the layout calls a CI gate; "
          f"README.md states no version or date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
