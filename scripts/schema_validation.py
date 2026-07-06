#!/usr/bin/env python3
"""Validate every fixture's embedded ATX credential against the vendored spec schema.

The schema is the machine-readable model published by atx-spec
(schemas/atx-credential-v1.1.schema.json), vendored under
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
"""

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


def main() -> int:
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
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
