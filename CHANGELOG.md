# Changelog

This repository has no tags or releases. A consumer pins it at a commit, so
entries name the commit that made the change. Changes to an existing fixture's
credential, signatures, verifier state or expected outcome are listed here
whenever one lands; README "Versioning and stability" says they should not.

## Unreleased

### Added

- `scripts/check_fixture_immutability.py` fails when the `atx`,
  `verifierState` or `expected` member of an existing fixture name differs
  from the merge base of `HEAD` and `origin/main`. Run it with `--base A
  --head B` to audit a past commit range, and with `--self-test` to see it
  fail on each kind of change it covers.
- Every fixture carries a `requirement` member naming the step or rule it
  tests, opening with the number of the `core.md` section it comes from
  (`atx-v1/expired`: `§1.3 step 2`), and each `conformance.json` entry
  copies it. `scripts/conformance_profile.py --check` fails on a fixture
  with no `requirement`, one whose section is not among the fixture's ATX
  `spec` citations, or one that two fixtures share (#140).
- `schemas/fixture-v1.schema.json` and
  `schemas/conformance-profile-v1.schema.json` define the two file formats
  whose `$schema` URIs the fixtures and `conformance.json` carry; neither URI
  is served. `scripts/schema_validation.py` fails when a document's
  `$schema` is not the `$id` of a tracked schema or the document does not
  validate against it, and starts every run with a self-test that alters a
  fixture and the profile and requires each copy to fail (#154). No fixture
  changes.

### Changed

- FIPS 204 is cited only by the four fixtures whose credential carries an
  ML-DSA-65 signature, where every fixture cited it before, and
  `atx-v1/wrong-issuer` also cites `core.md` section 13, which holds the
  issuer-trust rule it tests (#140). Every fixture's bytes and
  `MANIFEST.sha256` line change; no `atx`, `verifierState` or `expected`
  member does.
- README calls the fixture `trustScore` (87.5) an illustrative value and
  reproduces the AIP-SPEC §6.1 9-factor weights for reference, where it said
  the value was composite output from that algorithm: no fixture carries
  factor inputs, and AIP-SPEC §6.1 states the composite on 0.0 to 1.0.
  `scripts/check_readme_counts.py` fails when the README calls the value the
  algorithm's output or stops calling it illustrative (#146). No fixture
  changes.
- `scripts/check_readme_counts.py` runs its checks through one function that
  its self-test also runs, so the self-test fails when a check stops being
  run; it passed with the version-label check removed. Its self-test also
  covers a README naming a `canonicalPayload*` function the generator does
  not define, and `scripts/conformance_profile.py --check` covers a
  requirement whose § number does not open it (#153). No fixture changes.
- `jcs-vectors/README.md` and the docstring of both copies of the vendored
  RFC 8785 serializer say it adds no dependency to the Python verifier,
  where they called the verifier zero-dependency:
  `verifiers/python/requirements.txt` names `cryptography` and
  `dilithium-py`. `scripts/check_readme_counts.py` fails when any of the
  three calls the Python verifier zero-dependency while that file names a
  package (#159). No fixture changes.
- `jcs-vectors/README.md` says every JSON number left in the v1.1 TBS is an
  integer, where it said `trustLevel` was the only one; the comments in
  `verifiers/python/verify.py` and `jcs-vectors/pin/main.go` said the same.
  Every vector also carries `scanSummary.criticalFindings` and
  `scanSummary.highFindings`, and four of the eight carry
  `behavioralProfile.observationDays`, all integers.
  `scripts/check_readme_counts.py` fails when any of the three names one
  member as the only JSON number while the vectors carry another, when the
  README stops stating the integer rule, or when a vector's TBS carries a
  non-integer number (#155). No fixture or vector changes.
- `jcs-vectors/run-agreement.sh` also runs both conformance verifiers' own
  v1.1 projection and JCS call (`canonicalPayloadV11`,
  `canonical_payload_v11`) over every vector and fails unless each reproduces
  `expected.canonicalHex`; before, it ran only three standalone RFC 8785
  libraries. The gate now needs the Python verifier's dependencies.
  `jcs-vectors/README.md` says the gate runs no issuer, offline-verifier or
  broker code, where it said the directory proved agreement for all of them
  (#156). No fixture or vector changes.

## e2f9dc4 (#26, 2026-09-09): capabilities rewritten in 22 existing fixtures

Commit e2f9dc4 changed `atx.capabilities` to the AIP `namespace:action`
grammar in 22 fixtures and kept their names, contrary to the immutability
rule. A consumer pinned to a commit before e2f9dc4 holds different credential
bytes under these names. `verifierState` and `expected` did not change in any
of them, so each fixture's expected outcome is the same before and after.

Measured with
`python3 scripts/check_fixture_immutability.py --base e2f9dc4^ --head e2f9dc4`:

- In every one of the 22, the first two entries of `atx.capabilities`
  changed from `read:public`, `write:owned` to `db:read`, `db:write`.
  `atx-v1_1/tampered-capabilities` carries a third entry, which changed from
  `admin:all` to `system:exec`.
- The 13 v1.1 fixtures were re-signed, so their `atx.signatures` values
  changed too. The 9 v1.0 fixtures kept their signature values, because the
  v1.0 signed form does not include `capabilities`.
- In `atx-v1_1/declared-purpose-valid`, `atx-v1_1/duplicate-purpose-member`
  and `atx-v1_1/tampered-declared-purpose`, the
  `atx.declaredPurpose.capabilityJustification` members were renamed to
  match (`read:public` to `db:read`, `write:owned` to `db:write`).

Fixtures changed in place:

- v1.0: `atx-v1/baseline-valid`, `atx-v1/baseline-valid-hybrid`,
  `atx-v1/cross-issuer-key`, `atx-v1/expired`, `atx-v1/malformed-schema`,
  `atx-v1/revoked`, `atx-v1/tampered-signature`,
  `atx-v1/threshold-2of3-cosignature`, `atx-v1/wrong-issuer`
- v1.1: `atx-v1_1/baseline-valid`, `atx-v1_1/baseline-valid-hybrid`,
  `atx-v1_1/case-variant-member`, `atx-v1_1/cross-issuer-key`,
  `atx-v1_1/declared-purpose-array-injected`,
  `atx-v1_1/declared-purpose-empty-whitespace`,
  `atx-v1_1/declared-purpose-string-injected`,
  `atx-v1_1/declared-purpose-valid`, `atx-v1_1/duplicate-purpose-member`,
  `atx-v1_1/hybrid-mldsa-tampered`, `atx-v1_1/tampered-capabilities`,
  `atx-v1_1/tampered-declared-purpose`, `atx-v1_1/untrusted-chain-authority`
