# Changelog

This repository has no tags or releases. A consumer pins it at a commit, so
entries name the commit that made the change. Changes to an existing fixture's
credential, signatures, verifier state or expected outcome are listed here
whenever one lands; [`docs/versioning.md`](docs/versioning.md) "Versioning
and stability" says they should not.

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

- `verifiers/python/verify.py` rejects a v1.1 credential whose
  `declaredPurpose` holds a number outside the float64 range (`1e400`,
  `-1e400`, `1.7976931348623159e308`, an integer of 401 digits, one nested
  in an object or array) as `VERIFIER_CONFIG_ERROR`, the category the Go
  verifier reports, where it reported `SIGNATURE_INVALID`. A number inside
  the range (`1e308`, `1.7976931348623158e308`, `1e-400`) stays
  `SIGNATURE_INVALID` in both verifiers (#151). No fixture changes.
- `scripts/check_readme_counts.py` holds the `docs/scope.md` count of ACCEPT
  fixtures that carry Ed25519 signatures only ("6 of its 8") to the
  fixtures; changed to "5 of its 9", it passed. It fails when the
  repository layout in `CONTRIBUTING.md` calls a `scripts/*.py` file a CI
  gate that `.github/workflows/conformance.yml` does not run, and the
  layout gives `scripts/check_fixture_immutability.py`, which no workflow
  step runs, its own line saying it is run by hand. Its criterion (c) claim
  pattern also matches "fulfils criterion (c)" and "closes criterion c",
  and it prints its failures under "Counts and claims stated in the README
  and the files it describes do not match the tree", where the header read
  "README counts do not match the tree" for every failure (#151). No
  fixture changes.
- README.md is shortened to what the suite is, the command that runs the Go
  verifier and its output, how to run both verifiers and check the fixture
  bytes, the implementations table and one list of documentation links. Its
  reference sections moved as written to `docs/scope.md` (Scope and Honest
  scope notes), `docs/continuous-verification.md`, `docs/fixtures.md`,
  `docs/running-the-verifiers.md` (the Go and Python dependency lists),
  `docs/reproducing-the-fixtures.md`, `docs/version-pinning.md`,
  `docs/versioning.md`, `docs/sibling-repositories.md` and `CONTRIBUTING.md`
  (Contributing and Repository layout), and the full output of the README's
  Go run is `docs/captures/go-verifier.txt`. `scripts/check_readme_counts.py`
  reads README.md and those pages as one text and also holds the counts the
  README's capture prints, `scripts/check_spec_refs.py` holds every `core.md`
  link in those pages to the pin, `scripts/check_sibling_rows.py` reads
  `docs/sibling-repositories.md`, and the verifiers and the generator cite
  `docs/scope.md`, which `verify_test.go` and `test_verify.py` resolve in the
  file cited. No fixture changes.
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
- `jcs-vectors/README.md` says v1.1 signs `capabilities`, `scanSummary`,
  `issuerChain`, `publisher` and any field the spec adds to the TBS
  projection, where it said every future field: a member the projection does
  not name is unsigned, so one added after signing leaves the signature valid
  and both verifiers report ACCEPT. `scripts/check_readme_counts.py` fails
  when that README claims future fields are signed or stops stating the
  projection rule (#158). No fixture changes.
- `jcs-vectors/README.md`, `jcs-vectors/ts/package.json` and
  `jcs-vectors/ts/check.mjs` say `canonicalize` is listed in RFC 8785
  Appendix G, where they called it the RFC 8785 reference implementation:
  the RFC designates none. `scripts/check_readme_counts.py` fails when any
  of the three calls it the reference implementation or stops citing
  Appendix G (#160). No fixture or vector changes.
- `jcs-vectors/run-agreement.sh` fails its Go verifier leg unless
  `TestJCSVectorsThroughVerifierProjection` ran and passed. `go test -run`
  exits 0 when no test matches, so with that test renamed the gate still
  printed PASS. The leg also runs a name no test has and fails if that is
  reported as run (#165). No fixture or vector changes.
- README.md and the `jcs-byte-agreement` description in `conformance.json`
  name the two verifier legs of the byte-agreement gate (`verifiers/go`,
  `verifiers/python`) and say it needs the Python verifier's dependencies,
  where they described three canonicalizers only. `jcs-vectors/README.md`
  and the header of `jcs-vectors/run-agreement.sh` say the gate runs no
  issuer, offline-verifier or broker code, where they said it runs no code
  from another repository: its legs run `gowebpki/jcs`, `cloudflare/circl`
  and `canonicalize`. `jcs-vectors/README.md` and `jcs-vectors/pin/main.go`
  call `gowebpki/jcs` a Go implementation of RFC 8785, where they called it
  a reference port. `scripts/check_readme_counts.py` fails on each of the
  three earlier wordings (#165). `conformance.json` changes in that one
  description; no fixture or vector changes.
- `scripts/check_readme_counts.py` runs its checks from one list in which
  each check carries its own wiring case, and its self-test fails when a
  listed check has no case, when a case stays green with its check's call
  removed, or when a function that reports failures is run by no entry. The
  self-test also runs the whole script in a child process on a copy of the
  tree with one README count altered and requires exit 1; before, it passed
  with `main()` running no check. Four patterns that took about 2 to 4
  seconds on 20,000 blank lines or one 16,000-character word are bounded,
  with a timing case each; the zero-dependency check's restriction to
  statements that name the Python verifier has a case; and the script's own
  statement of how many vectors carry `behavioralProfile.observationDays`
  says four, where it said five (#165). No fixture changes.
- `scripts/schema_validation.py` reports a tracked document that lacks a
  member its self-test alters as a red case naming the member, and goes on
  to the format pass; it ended in a `KeyError` traceback before that pass
  ran. Its format summary counts a schema file that cannot be used apart
  from the documents, where one such file was subtracted from the documents
  that pass. Its self-test covers six more constraints of the two format
  schemas, one altered document each (#165). No fixture changes.
- `verifiers/python/verify.py` no longer imports `os` and
  `dataclasses.field`, which it did not use (#165). No fixture changes.
- README's dependency list for the Go verifier says the Go release can change
  a fixture's result when one of its timestamps has a time zone offset with
  an hour above 24 or a minute above 60 (`+25:00`, `+23:61`), where it said
  only "Go 1.22 or later". Go 1.22, which CI builds the verifier with and
  which the Python verifier follows, decodes such a timestamp. Go 1.23 and
  later reject it where the Go verifier decodes it: a CRL's `issuedAt` or
  `nextUpdate`, a CRL entry's `revokedAt`, the credential's `issuedAt` or
  `expiresAt`, the verifier clock `clockRfc3339`, and a v1.1 credential's
  `behavioralProfile.generatedAt`. No fixture carries such a timestamp
  (#167). No fixture changes.
- README.md's Scope table states how many fixtures reach Ed25519 signature
  verification (step 5), where it said every fixture: a fixture that rejects
  at steps 0 to 4 never has its signature checked when a verifier runs over
  `fixtures/`. `scripts/check_readme_counts.py` fails when that row states
  another count, or says "every fixture" while a fixture rejects before step
  5. `TestEarlyRejectFixturesCarryValidSignatures` in `verifiers/go` runs
  each such fixture through steps 5 to 8 with its gate lifted and requires
  its signatures to verify (#138). No fixture changes.
- The header of `verifiers/python/verify.py` no longer lists a trust level
  3+ chain check, which never ran; it lists v1.1 (`JCS(TBS)`) beside v1.0 and
  says the distinct signer-authority count (core.md §1.3 step 7) is not
  performed. The Go verifier's header says the same. `verifiers/go/verify.go`
  and `scripts/generate-fixtures/main.go` cited README §"Signed vs unsigned
  fields.", which README does not have; they now cite §"Canonicalization: v1.0
  signs 11 fields; v1.1 signs JCS(TBS)". `test_verify.py` fails when the
  Python header claims the step 7 check or omits a supported version, and it
  and `verify_test.go` fail when a verifier or the generator cites a README
  heading that does not exist (#161). No verdict or fixture changes.
- `jcs-vectors/run-agreement.sh` installs the TS/JS leg's dependency with
  `npm ci`, which installs exactly `ts/package-lock.json`, where it ran
  `npm install`. A failed install prints npm's error and a `[ts] FAIL` line,
  fails the gate, and the remaining legs and the `BYTE-AGREEMENT GATE` line
  still run; before, the script exited 1 straight after the install line with
  npm's output discarded and no summary. `jcs-vectors/test_run_agreement.py`
  runs the script with stub commands and checks both outcomes of the
  install (#170). No fixture or vector changes.
- `verifiers/python/verify.py` reaches the Go verifier's verdict, where it
  reached another or stopped with an error, on six inputs: a credential
  member whose name differs from its field's only in case (`Revoked` is read
  as `revoked`), an `issuedAt` or `expiresAt` written with a JSON escape (a
  `PARSE_ERROR`), an unpaired UTF-16 surrogate escape in a string member
  (decoded to U+FFFD), a `trustScore` of `-0` (signed as `-0.000000`), a
  signature value with a character outside the base64 alphabet
  (`SIGNATURE_INVALID`; `base64.b64decode` discarded the character), and a
  `behavioralProfile` or `scanSummary` member outside its Go type (projected
  into the v1.1 signed payload as the Go verifier projects it) (#167). No
  fixture changes.
- The Go verifier decodes every timestamp with `time.Time`'s own
  `UnmarshalJSON`, so one written with a JSON escape fails to decode under
  every Go release. Built with Go 1.27, it reported ACCEPT on a credential
  whose `issuedAt` or v1.1 `behavioralProfile.generatedAt` was written with
  one and loaded such a CRL entry `revokedAt`, where Go 1.22 through 1.26 and
  the Python verifier report `PARSE_ERROR`, `SIGNATURE_INVALID` and a load
  error; it now reports those too. Its result under Go 1.22, which CI uses,
  does not change (#173). No fixture changes.
- README's dependency lists say the Go or Python release sets the Unicode
  version of the case folding the duplicate-member check applies to a
  non-ASCII member name: U+1C89 and U+1C8A are a duplicate, and the
  credential a `PARSE_ERROR`, under Go 1.27 and Python 3.14 and not under
  Go 1.22 through 1.26 or Python 3.12. The Go list also says a timestamp
  written with a JSON escape fails to decode under every release (#173). No
  fixture changes.
- `verifiers/python/verify.py` decodes the fixture wrapper as the Go
  verifier's fixture struct does. A fixture member outside its Go type fails
  to load (a `name` of `{"a": 1}` reported PASS), and so does a CRL time
  outside the timestamp grammar. A `verifierState` member name in another
  case names the member (`TrustedIssuers` reported `UNTRUSTED_ISSUER`, now
  ACCEPT). Of two names in the wrapper that differ only in case, the last in
  the document wins (an `expected` of `{"verifyResult": "ACCEPT",
  "VerifyResult": "REJECT", "verifyResult": "ACCEPT"}` was read as REJECT). A
  public key whose `publicKeyHex` is not an even run of hex digits is
  skipped, where `"zz"` ended the fixture in a verify error and hex with a
  space inside it was used. A fixture with no `atx` is a `PARSE_ERROR`,
  where it was a verify error (#173). No fixture changes.
- `verifiers/python/verify.py` reads a fixture file as Go's
  `encoding/json` does: a byte that is not UTF-8 inside a string decodes to
  U+FFFD, one for each byte of the invalid sequence, where the file failed to
  load; arrays and objects nested up to 10000 levels deep, the fixture
  object included, load, where 5000 under one member failed to load, and
  deeper ones fail to load as they do in Go. Its string-literal scan now
  runs before the file is parsed, where it can meet an unterminated string
  literal, so it is a single pass, linear in that literal's length. The
  regular expression it replaces ran only after `json.loads` had accepted
  the file, so never on an unterminated literal (#173). No fixture changes.
- `python3 verify.py --help` (or `-h`) prints the usage line and exits 0,
  where it reported `--help` as a missing path and exited 2 (#173). No
  fixture changes.
- The vendored RFC 8785 serializer (`verifiers/python/rfc8785.py` and its
  copy in `jcs-vectors/python/`) serializes arrays and objects without
  recursion. A v1.1 credential whose `declaredPurpose` nested 497 or more
  levels of arrays or objects (331 or more on Python 3.11) ended in a
  `RecursionError` verify error, where the Go verifier reports
  `SIGNATURE_INVALID`; the Python verifier now reports that too, up to the
  10000 levels Go's decoder accepts. Its canonical bytes for every other
  value do not change (#175). No fixture changes.
- `test_verify.py` bounds how the string-literal scan's time grows from
  2,500 to 40,000 escaped quotes, each length timed at its fastest of five
  runs, where it bounded one scan of 200,000 at 2 seconds of wall-clock
  time, which a loaded host could exceed with no code change. It also
  checks that the regular expression the scan replaced exceeds the bound,
  and that the scan stays within it on a clock that runs 3,600 times fast,
  as it would read on a host that much slower (#177). No fixture changes.
- `verifiers/python/verify.py` writes a member's value into its decode error
  to 8 levels of arrays and objects, then `[...]` or `{...}`, where it wrote
  out the whole value. A credential, or a member Go decodes into a typed
  field (`capabilities`, `publisher`, `trustScore`, `signatures`, among
  others), holding deeply nested arrays now reports `PARSE_ERROR`, and one
  of `scanSummary` or `behavioralProfile` `SIGNATURE_INVALID`, as the Go
  verifier does, up to Go's 10000-level limit. Before, where `repr()` of
  the value raised `RecursionError`, these ended in a `RecursionError`
  verify error: from about 1000 levels on Python 3.11 and about 1500 on
  3.12.0 to 3.12.2, and on 3.12.3 to 3.12.12 only the credential did, at
  9999 levels. Where it did not, the `PARSE_ERROR` reason carried the whole
  value, about 20,000 characters at Go's limit; `scanSummary` and
  `behavioralProfile` members reported `SIGNATURE_INVALID` there, as they do
  now. A fixture wrapper member nested that deep, such as
  `expected.verifyResult`, still fails to load, and the load error now names
  the member where on Python 3.11 and 3.12.0 to 3.12.2 it gave only the
  `RecursionError` message. The depths are as measured on macOS; CPython's C
  recursion limit, which sets the 3.12 ones, is lower on some platforms
  (#179). No fixture changes.
- `verifiers/python/verify.py` loads a fixture that holds a JSON integer of
  more than 4300 digits, where the file failed with the load error `Exceeds
  the limit (4300 digits) for integer string conversion`: from Python 3.11
  `int()` refuses a literal that long unless the interpreter's limit is
  raised, and the Go verifier loads it. The number is no longer converted.
  In a member no Go struct declares (`atx.unknownMember`) the fixture
  verifies as it does without the member; in a member Go decodes into a
  typed field (`trustLevel`, `trustScore`, `publisher`, `capabilities`,
  among others) the credential is a `PARSE_ERROR` whose reason writes the
  number out; in `scanSummary.hma` or `behavioralProfile.observationDays` it
  is `SIGNATURE_INVALID`; and in a fixture wrapper member such as
  `expected.verifyResult` the file fails to load, with an error that names
  the member. The Go verifier reports the same for each. In
  `declaredPurpose` the credential is `SIGNATURE_INVALID`, as it is for a
  shorter integer outside float64 range, where the Go verifier reports
  `VERIFIER_CONFIG_ERROR` for both (#181). No fixture changes.
- `test_verify.py` nests objects as well as arrays to Go's depth limit, so
  it covers the decode error of a slice member (`capabilities`,
  `issuerChain`, `signatures`, `verifierState.trustedIssuers`) that holds an
  object, and it compares the whole reason of a decode error on a value ten
  levels deep, so the 8 levels stated above are tested. Before, it passed
  with that error writing out the whole value, and with the 8 changed to 7
  or 60 (#181). No fixture changes.
- `verifiers/python/verify.py` fails to load a fixture that writes a wrapper
  member twice, under one name or in two cases, with a first value outside
  the member's Go type, as the Go verifier does: `"clockRfc3339": 5` before
  the `verifierState` clock, `"NAME": 5` before `name`, an integer of 401 or
  5001 digits in place of the 5, or a CRL `issuedAt` or entry `revokedAt`
  written with a JSON escape before an unescaped one. Only the last value
  was decoded before, so the v1.1 baseline with the first or second insert
  printed `observed: ACCEPT`, and the CRL baseline with an escaped
  `issuedAt` first reported `REVOKED`, as each does without the insert. A
  first value inside its type, null included, still loads, and the last
  value is the one verified. Go decodes each value into the same field, so
  a repeat whose last value is null or an object can still reach a
  different verdict here; the module docstring names the two cases measured
  (#183). No fixture changes.

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
