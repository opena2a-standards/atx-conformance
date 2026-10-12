#!/usr/bin/env python3
"""Validate every fixture, and conformance.json, against the schemas they rely on.

Two passes.

FORMAT. Each fixture and conformance.json names its file format in a `$schema`
member. That name MUST be the `$id` of a schema this repository ships under
schemas/*.schema.json (fixture-v1.schema.json, conformance-profile-v1.schema.json),
and the whole document MUST validate against it. The `$id` is an identifier;
the host it names does not serve the file, so the tracked file is the
definition. A `$schema` no tracked file defines fails, as does any document that
breaks its format.

CREDENTIAL. The atx-spec schema is the machine-readable model published by
atx-spec (schemas/atx-credential-v1.1.schema.json), vendored under
schemas/vendor/atx-spec/ and byte-drift-gated in CI against the pinned
ATX_SPEC_REF.

Contract:
- every fixture's `atx` member MUST validate against the schema, EXCEPT
- fixtures whose expected.rejectCategory is UNSUPPORTED_VERSION, which MUST
  fail validation and MUST fail on exactly the `atcVersion` enum (they carry
  an unregistered version by design), and
- the declared-purpose injection fixtures (issue #11), which carry an
  attacker-appended NON-OBJECT declaredPurpose by design and MUST fail
  validation on exactly the `declaredPurpose` member, and
- the case-variant fixture (atx-conformance#16), which carries a decoy
  top-level member whose name folds to a real field, and MUST fail validation
  on exactly one root `additionalProperties` error.

Any other schema error means fixture and schema have drifted apart.
Exit 0 only if the whole contract holds.

Note: the two strict-parse fixtures behave DIFFERENTLY here, and both are
correct. The duplicate-member fixture (v1_1-duplicate-purpose-member) validates
CLEANLY — json.loads collapses same-name duplicate members last-wins before
jsonschema sees them, and the collapsed credential is schema-valid. The
case-variant fixture (v1_1-case-variant-member) does NOT validate cleanly —
json.loads is case-sensitive, so the folded decoy (e.g. TRUSTLEVEL alongside
trustLevel) is kept as a distinct member and surfaces as a forbidden root
additional property. In both, the strict-parse rejection proper is pinned by
the verifiers (PARSE_ERROR via foldKey), not by this parse-semantics-agnostic
schema layer; the case-variant fixture's schema failure is just the same
case-fold ambiguity seen from the schema side.

Every run starts with a self-test: altered copies of a tracked fixture and of
conformance.json must each fail the format pass, and the tracked documents
must pass it. A case whose tracked document lacks the member it alters is
reported red by that member's name, and the format pass still runs.

Usage:
    python3 scripts/schema_validation.py              # self-test, then both passes
    python3 scripts/schema_validation.py --self-test  # the self-test alone
"""

import contextlib
import copy
import io
import json
import pathlib
import sys

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("error: the 'jsonschema' package is required (pip install jsonschema)")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas" / "vendor" / "atx-spec" / "atx-credential-v1.1.schema.json"
FORMAT_GLOB = "schemas/*.schema.json"
PROFILE = ROOT / "conformance.json"

# The members every v1 fixture carries, as the generator writes them. Listed
# here rather than read from the schema, so a schema that stops requiring one
# fails the self-test instead of shrinking it.
FIXTURE_MEMBERS = (
    "$schema", "name", "description", "requirement", "spec",
    "keypairRefs", "verifierState", "expected", "atx",
)


def load_formats(root: pathlib.Path = ROOT) -> tuple[dict, list[str]]:
    """Each tracked format schema keyed by its `$id`, and what is wrong with any
    that cannot be used. A schema whose `$schema` const differs from its `$id`
    would hold documents to a format name it does not define."""
    formats, problems = {}, []
    for path in sorted(root.glob(FORMAT_GLOB)):
        rel = path.relative_to(root)
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        sid = schema.get("$id")
        const = schema.get("properties", {}).get("$schema", {}).get("const")
        if not isinstance(sid, str) or const != sid:
            problems.append(f"{rel}: `$schema` const {const!r} is not its `$id` {sid!r}")
        elif sid in formats:
            problems.append(f"{rel}: `$id` {sid} is already defined by another file")
        else:
            formats[sid] = Draft202012Validator(schema)
    return formats, problems


def format_errors(doc: object, formats: dict) -> list[str]:
    """Why a document does not conform to the format its `$schema` names;
    empty when it does."""
    if not isinstance(doc, dict):
        return ["is not a JSON object"]
    named = doc.get("$schema")
    if not isinstance(named, str) or named not in formats:
        return [f"`$schema` {named!r} is not the `$id` of any {FORMAT_GLOB} file"]
    errors = sorted(formats[named].iter_errors(doc), key=lambda e: e.json_path)
    return [f"{e.json_path}: {e.message}" for e in errors]


def check_formats(formats: dict, problems: list[str]) -> int:
    """Print the format pass and return how many things failed it. A schema
    file that cannot be used is reported and counted apart from the documents:
    it is not one of them, so it does not come out of the pass count."""
    for problem in problems:
        print(f"FAIL  {problem}")
    docs = sorted((ROOT / "fixtures").glob("*.json")) + [PROFILE]
    failed = 0
    for path in docs:
        errors = format_errors(json.loads(path.read_text(encoding="utf-8")), formats)
        rel = path.relative_to(ROOT)
        if errors:
            print(f"FAIL  {rel}:")
            for err in errors:
                print(f"      {err}")
            failed += 1
        else:
            print(f"PASS  {rel}")
    unusable = ""
    if problems:
        unusable = (f", {len(problems)} schema file{'' if len(problems) == 1 else 's'} "
                    f"unusable")
    print(f"\nformat summary: {len(docs) - failed} pass, {failed} fail "
          f"({len(docs)} documents, {len(formats)} format schemas{unusable})\n")
    return failed + len(problems)


class _Unalterable(str):
    """Stands in for an altered copy when the tracked document lacks the member
    the case alters. The text names the member."""


def _altered(doc: object, change) -> object:
    """A deep copy of `doc` with `change` applied. A tracked document that has
    lost the member `change` reaches for yields an _Unalterable instead, so the
    case is reported red by name; the lookup once ended the run in a traceback
    before the format pass had named the problem."""
    out = copy.deepcopy(doc)
    try:
        change(out)
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        return _Unalterable(f"the tracked document has no member for this case "
                            f"to alter ({type(exc).__name__}: {exc})")
    return out


def _tracked_documents() -> tuple[object, object, object]:
    """The REJECT fixture, the ACCEPT fixture and the profile the cases alter."""
    fixtures = ROOT / "fixtures"
    return (json.loads((fixtures / "revoked.json").read_text(encoding="utf-8")),
            json.loads((fixtures / "baseline-valid.json").read_text(encoding="utf-8")),
            json.loads(PROFILE.read_text(encoding="utf-8")))


def _self_test_cases(reject: object, accept: object,
                     profile: object) -> list[tuple[str, object, bool]]:
    """(label, document, conforms) for the tracked documents and altered copies.
    Every altered copy is built by _altered, so none can raise."""
    untracked = "https://example.invalid/schemas/fixture-v1.json"
    cases = [
        ("tracked REJECT fixture (with a CRL) conforms", reject, True),
        ("tracked ACCEPT fixture conforms", accept, True),
        ("tracked conformance.json conforms", profile, True),
        ("a document that is not an object", [reject], False),
        ("fixture naming an untracked format",
         _altered(reject, lambda d: d.update({"$schema": untracked})), False),
        ("fixture naming the profile format",
         _altered(reject, lambda d: d.update({"$schema": profile["$schema"]})), False),
        ("fixture with an unknown member",
         _altered(reject, lambda d: d.update(verdict="ACCEPT")), False),
    ]
    cases += [(f"fixture with no {m!r} member", _altered(reject, lambda d, m=m: d.pop(m)), False)
              for m in FIXTURE_MEMBERS]
    cases += [
        ("fixture name outside the `atx-v<N>/<slug>` form",
         _altered(reject, lambda d: d.update(name="Revoked")), False),
        ("fixture requirement that opens with no § number",
         _altered(reject, lambda d: d.update(requirement="step 4: a revoked agent is rejected")), False),
        ("keypair path outside vectors/",
         _altered(reject, lambda d: d["keypairRefs"][0].update(path="keys/issuer-primary.json")), False),
        ("verifierState with an unknown member",
         _altered(reject, lambda d: d["verifierState"].update(mode="strict")), False),
        ("REJECT with no rejectCategory",
         _altered(reject, lambda d: d["expected"].pop("rejectCategory")), False),
        ("REJECT with no reasonContains",
         _altered(reject, lambda d: d["expected"].pop("reasonContains")), False),
        ("ACCEPT that names a rejectCategory",
         _altered(accept, lambda d: d["expected"].update(rejectCategory="REVOKED")), False),
        ("verifyResult other than ACCEPT or REJECT",
         _altered(accept, lambda d: d["expected"].update(verifyResult="PASS")), False),
        ("rejectCategory no verifier reports",
         _altered(reject, lambda d: d["expected"].update(rejectCategory="DENIED")), False),
        ("keypair with an unregistered algorithm",
         _altered(reject, lambda d: d["keypairRefs"][0].update(algorithm="RSA")), False),
        ("public key that is not lowercase hex",
         _altered(reject, lambda d: d["verifierState"]["publicKeys"][0].update(publicKeyHex="not-hex")), False),
        ("verifier clock that is not RFC 3339",
         _altered(reject, lambda d: d["verifierState"].update(clockRfc3339="2026-05-23")), False),
        ("CRL entry with no agentId",
         _altered(reject, lambda d: d["verifierState"]["crl"]["entries"][0].pop("agentId")), False),
        ("spec citation with no section",
         _altered(reject, lambda d: d["spec"][0].pop("section")), False),
        ("atx that is not an object",
         _altered(reject, lambda d: d.update(atx="credential")), False),
        ("profile naming an untracked format",
         _altered(profile, lambda d: d.update(
             {"$schema": "https://example.invalid/schemas/conformance-profile-v1.json"})), False),
        ("profile naming the fixture format",
         _altered(profile, lambda d: d.update({"$schema": reject["$schema"]})), False),
        ("profile with an unknown member",
         _altered(profile, lambda d: d.update(verdict="PASS")), False),
        ("profile with no requirements",
         _altered(profile, lambda d: d.pop("requirements")), False),
        ("profile requirement with a malformed expected",
         _altered(profile, lambda d: d["requirements"][0].update(expected="REJECTED")), False),
        ("profile requirement with no fixture path",
         _altered(profile, lambda d: d["requirements"][0].pop("fixture")), False),
        ("profile requirement with an unregistered level",
         _altered(profile, lambda d: d["requirements"][0].update(level="OPTIONAL")), False),
    ]
    return cases


def _case_results(cases: list[tuple[str, object, bool]],
                  formats: dict) -> list[tuple[bool, str, str]]:
    """(green, label, detail) for each case run through the format pass."""
    results = []
    for label, doc, conforms in cases:
        if isinstance(doc, _Unalterable):
            results.append((False, label, str(doc)))
            continue
        errors = format_errors(doc, formats)
        ok = not errors if conforms else bool(errors)
        detail = "" if ok else errors[0] if errors else "passed the format check"
        results.append((ok, label, detail))
    return results


def _missing_member_case(label: str, member: str, built: list[tuple[str, object, bool]],
                         reject: object, accept: object,
                         profile: object) -> tuple[bool, str, str]:
    """Building the cases from a tracked document that lacks `member` must turn
    the cases that alter it red by name, not raise. `built` is the cases from
    the tracked documents as they are; a case already unbuilt there is theirs."""
    try:
        cases = _self_test_cases(reject, accept, profile)
    except Exception as exc:  # a traceback is the defect this case holds
        return False, label, f"building the cases raised {type(exc).__name__}: {exc}"
    already = {name for name, doc, _ in built if isinstance(doc, _Unalterable)}
    unbuilt = [(name, str(doc)) for name, doc, _ in cases if isinstance(doc, _Unalterable)]
    named = [text for _, text in unbuilt if repr(member) in text]
    other = [text for name, text in unbuilt
             if repr(member) not in text and name not in already]
    return (bool(named) and not other, label,
            f"expected each case that could not be built to name {member!r}, "
            f"got {named + other}")


def _summary_case(formats: dict) -> tuple[bool, str, str]:
    """A schema file that cannot be used must not come out of the format
    summary's pass count: the documents' counts stay as they are without it."""
    label = "format summary counting an unusable schema file apart from the documents"

    def summary(problems: list[str]) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            failures = check_formats(formats, problems)
        lines = [line for line in out.getvalue().splitlines()
                 if line.startswith("format summary:")]
        return failures, lines[0] if lines else ""

    failures, line = summary([])
    more, with_problem = summary(["schemas/made-up.schema.json: cannot be used"])
    counts = line.partition(" (")[0]
    ok = (bool(counts) and with_problem.startswith(counts + " (")
          and "1 schema file unusable" in with_problem and more == failures + 1)
    return ok, label, f"read {line!r} without it and {with_problem!r} with it"


def self_test() -> tuple[int, int]:
    formats, problems = load_formats()
    results = [(False, f"format schema unusable: {problem}", "") for problem in problems]
    reject, accept, profile = _tracked_documents()
    cases = _self_test_cases(reject, accept, profile)
    results += _case_results(cases, formats)
    results.append(_missing_member_case(
        "conformance.json with no 'requirements' member is reported by name",
        "requirements", cases, reject, accept,
        _altered(profile, lambda d: d.pop("requirements", None))))
    results.append(_missing_member_case(
        "REJECT fixture with no 'expected' member is reported by name",
        "expected", cases, _altered(reject, lambda d: d.pop("expected", None)), accept, profile))
    results.append(_summary_case(formats))
    failed = 0
    for ok, label, detail in results:
        print(f"  [{'GREEN' if ok else 'RED  '}] {label}")
        if not ok:
            if detail:
                print(f"          {detail}")
            failed += 1
    return failed, len(results)


def check_credentials() -> int:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    failures = 0
    fixtures = sorted((ROOT / "fixtures").glob("*.json"))
    if not fixtures:
        print("error: no fixtures found")
        return 1

    for path in fixtures:
        doc = json.loads(path.read_text(encoding="utf-8"))
        atx = doc.get("atx")
        if atx is None:
            print(f"FAIL  {path.name}: no atx member")
            failures += 1
            continue
        errors = sorted(validator.iter_errors(atx), key=lambda e: e.json_path)
        expect_version_invalid = doc.get("expected", {}).get("rejectCategory") == "UNSUPPORTED_VERSION"
        expect_purpose_invalid = path.name in (
            "v1_1-declared-purpose-array-injected.json",
            "v1_1-declared-purpose-string-injected.json",
        )
        expect_case_variant_invalid = path.name == "v1_1-case-variant-member.json"
        if expect_version_invalid:
            only_version_enum = len(errors) == 1 and list(errors[0].absolute_path) == ["atcVersion"]
            if only_version_enum:
                print(f"PASS  {path.name}: schema-invalid on exactly atcVersion (as pinned)")
            else:
                print(f"FAIL  {path.name}: expected exactly one atcVersion enum error, got:")
                for err in errors or []:
                    print(f"      {err.json_path}: {err.message}")
                if not errors:
                    print("      (validated cleanly - fixture no longer exercises the version registry)")
                failures += 1
        elif expect_purpose_invalid:
            only_purpose = bool(errors) and all(
                list(e.absolute_path)[:1] == ["declaredPurpose"] for e in errors
            )
            if only_purpose:
                print(f"PASS  {path.name}: schema-invalid on exactly declaredPurpose (as pinned)")
            else:
                print(f"FAIL  {path.name}: expected errors only under declaredPurpose, got:")
                for err in errors or []:
                    print(f"      {err.json_path}: {err.message}")
                if not errors:
                    print("      (validated cleanly - fixture no longer carries an injected non-object)")
                failures += 1
        elif expect_case_variant_invalid:
            # The decoy case-variant member (e.g. TRUSTLEVEL alongside
            # trustLevel) is kept distinct by case-sensitive json.loads and
            # surfaces as a forbidden root additional property — exactly one
            # error, at the root, from additionalProperties. Anything else means
            # the fixture no longer carries the decoy or the schema drifted.
            only_root_addprops = (
                len(errors) == 1
                and errors[0].validator == "additionalProperties"
                and list(errors[0].absolute_path) == []
                # The offending property must be the case-variant decoy itself
                # (folds to a real field), not some unrelated extra member — so a
                # fixture that lost the decoy but gained a different stray member
                # cannot slip through this exception.
                and "TRUSTLEVEL" in errors[0].message
            )
            if only_root_addprops:
                print(f"PASS  {path.name}: schema-invalid on exactly the case-variant decoy at root (additionalProperties, as pinned)")
            else:
                print(f"FAIL  {path.name}: expected exactly one root additionalProperties error, got:")
                for err in errors or []:
                    print(f"      {err.json_path}: {err.message}")
                if not errors:
                    print("      (validated cleanly - fixture no longer carries the case-variant decoy)")
                failures += 1
        elif errors:
            print(f"FAIL  {path.name}:")
            for err in errors:
                print(f"      {err.json_path}: {err.message}")
            failures += 1
        else:
            print(f"PASS  {path.name}")

    print(f"\nsummary: {len(fixtures) - failures} pass, {failures} fail ({len(fixtures)} fixtures)")
    return failures


def main() -> int:
    # An unrecognised flag must not fall through to the default run and exit 0.
    unknown = [a for a in sys.argv[1:] if a != "--self-test"]
    if unknown:
        print(f"unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(f"usage: {pathlib.Path(sys.argv[0]).name} [--self-test]", file=sys.stderr)
        return 2

    print("self-test: the format pass fails on each altered document\n")
    failed, total = self_test()
    if failed:
        print(f"\nself-test FAILED: {failed} of {total} case(s)\n", file=sys.stderr)
    else:
        print(f"\nself-test passed: {total} cases\n")
    if "--self-test" in sys.argv:
        return 1 if failed else 0

    formats, problems = load_formats()
    format_failures = check_formats(formats, problems)
    credential_failures = check_credentials()
    return 1 if failed or format_failures or credential_failures else 0


if __name__ == "__main__":
    sys.exit(main())
