# Changelog

This repository carries no tag yet: the section `v0.1.0` lists the changes
its first tag, `v0.1.0`, is to carry, and the section below it, named for
commit `e2f9dc4`, lists the fixtures that commit changed. Until that tag
exists, a consumer pins this repository at a commit. Changes to an existing
fixture's credential, signatures, verifier state or expected outcome are
listed here whenever one lands;
[`docs/versioning.md`](docs/versioning.md) "Versioning and stability" says
they should not.

## v0.1.0

### Added

- A MUST-REJECT fixture built by the generator, `fixtures/hybrid-pq-only.json`,
  holds the Ed25519 companion rule under `atcVersion` 1.0 (#151). It is the
  credential of `fixtures/baseline-valid-hybrid.json` with its Ed25519
  signature removed: one ML-DSA-65 signature that verifies over the legacy
  canonical bytes, and no Ed25519 signature. core.md §13, Cryptographic
  agility, says "a credential that declares an ML-DSA-65 entry MUST also
  carry a verifying Ed25519 entry" and names no `atcVersion`, while
  `fixtures/v1_1-hybrid-pq-only.json` was the one fixture for the rule, so
  a verifier that applies it to v1.1 alone passed the suite. The fixture
  expects `REJECT [SIGNATURE_INVALID]` with a reason containing
  `signature`, and both reference verifiers report
  `REJECT[SIGNATURE_INVALID: ML-DSA-65 signature declared without a
  verifying Ed25519 signature (an ML-DSA-65 entry requires an Ed25519
  companion)]` on it; `verify.go` and `verify.py` do not change. In the Go
  verifier, `TestSuitePinsEd25519CompanionUnderEachVersion` requires, for
  `atcVersion` 1.0 and for 1.1, a shipped fixture that the verifier rejects
  for the missing companion as that fixture pins; on the fixtures of the
  commit before this change it names `atcVersion` 1.0 and fails. The other
  27 existing fixtures and their `MANIFEST.sha256` lines are
  byte-identical, `fixtures/revoked.json` changing in its description alone
  (under Fixed); the manifest gains one line. `conformance.json` and the
  capture under `docs/captures/` are regenerated; the capture gains the
  fixture's three lines, and its summary line counts 29. The fixture
  counts in README.md, COSIGNERS.md, CONTRIBUTING.md,
  `docs/continuous-verification.md` and `docs/sibling-repositories.md` go
  from 28 to 29 (the sibling row's v1.0 count from 11 to 12), and
  `docs/scope.md` counts 22 of 29 fixtures that reach signature
  verification, where it counted 21 of 28. `docs/fixtures.md` lists the
  fixture, and `docs/scope.md`, `docs/reproducing-the-fixtures.md` and
  COSIGNERS.md name it beside `fixtures/v1_1-hybrid-pq-only.json`.
- A verifier state can set a k-of-n signature threshold, and a MUST-REJECT
  fixture built by the generator, `fixtures/threshold-1of3-cosignature.json`,
  holds both reference verifiers to it (#132). The fixture is the
  credential of `fixtures/threshold-2of3-cosignature.json` cut to its first
  signature, the primary's, under the same verifier state with
  `"requiredSignatures": 2`, and expects `REJECT [SIGNATURE_INVALID]` with a
  reason containing `threshold`. `schemas/fixture-v1.schema.json` gives the
  verifier state an optional `requiredSignatures` member, an integer of at
  least 1: the least number of distinct Ed25519 keys under which the
  credential's declared signatures must verify (core.md §3.1 step 8,
  cosignatures from 2 of 3 key holders). A key counts once however many
  signatures verify under it, whatever `keyId` they carry, and an ML-DSA-65
  signature does not count, as core.md §1.3a.2 names the Ed25519 signatures
  the threshold signatures and the ML-DSA-65 one the hybrid signature. Both
  verifiers write `signature threshold not met: requiredSignatures is 2,
  distinct Ed25519 keys that verified a declared signature: 1` on the
  fixture, and report a `requiredSignatures` below 1 as
  `VERIFIER_CONFIG_ERROR` (`bad requiredSignatures: 0 is not a positive
  integer`) before step 1, as they report a bad clock. With the member
  absent or null no threshold applies, and none of the 27 fixtures before
  it sets one. The verifiers of `ba3fc6c` read no threshold: on the
  fixture each reports `observed: ACCEPT`, a FAIL line. The fixture cites
  AIP-SPEC.md at the commit `docs/version-pinning.md` pins as the other
  Ed25519-only fixtures do, §3.1 "Cryptographic Identity" (Ed25519
  signing) and then §6.1 "Multi-Factor Algorithm", so 24 fixtures carry
  the Ed25519 signing citation. In the Go
  verifier, `TestRequiredSignaturesThreshold`,
  `TestRequiredSignaturesCountsKeysNotKeyIDs`,
  `TestRequiredSignaturesCountsEd25519Only`,
  `TestRequiredSignaturesBelowOneIsAConfigError`,
  `TestRequiredSignaturesDecode` and `TestSuiteCatchesThresholdBlindVerifier`
  pin it; in the Python verifier, the `RequiredSignaturesThreshold` class,
  whose decode tables were recorded from the Go verifier. The parity gate
  reports `go=PASS:REJECT[SIGNATURE_INVALID]
  python=PASS:REJECT[SIGNATURE_INVALID]` on the fixture. The 27 existing
  fixtures and their `MANIFEST.sha256` lines are byte-identical; the
  manifest gains one line. `conformance.json` and the capture under
  `docs/captures/` are regenerated; the capture gains the fixture's three
  lines, and its summary line counts 28. The `notCovered` entry for k-of-n
  threshold issuance now names what no fixture covers: a threshold the
  credential meets, so a verifier that rejects every credential whose
  verifier state sets `requiredSignatures` passes the suite. The fixture
  counts in
  README.md, COSIGNERS.md, CONTRIBUTING.md,
  `docs/continuous-verification.md` and `docs/sibling-repositories.md` go
  from 27 to 28 (the sibling row's v1.0 count from 10 to 11), and
  `docs/scope.md` counts 21 of 28 fixtures that reach signature
  verification, where it counted 20 of 27, and lists the threshold as
  covered by the fixture, where it listed it as not covered.
  `docs/fixtures.md` lists the fixture, and says the 2-of-3 fixture's
  verifier state sets no `requiredSignatures`, where it said no verifier
  reads a threshold.
- `scripts/check_sibling_rows.py` holds the Spec cell of each sibling row
  in `docs/sibling-repositories.md` to the `spec.id` and `spec.version` that
  repository's `conformance.json` declares, where it left that cell
  unchecked (#153). Its self-test alters the version and the id in each
  row's Spec cell, and removes the version, and requires each to fail; it
  runs 17 cases, from 11. Run against the sibling repositories, it reports
  that the `aip-conformance` row names AIP v1.2.0-draft while
  `opena2a-standards/aip-conformance` declares AIP 1.0.0-draft, and exits 1.
- A MUST-REJECT fixture, `fixtures/v1_1-declared-purpose-number-injected.json`,
  built by the generator (#130): the v1.1 baseline signed with no
  `declaredPurpose`, carrying `"declaredPurpose": 1.5` added after signing.
  §1.3a.2 rule 5 puts a present non-object value into the TBS verbatim, so
  it expects `REJECT [SIGNATURE_INVALID]` with a reason containing
  `signature`. The Go verifier canonicalizes the number and its Ed25519
  signature does not verify. The Python verifier's serializer refuses a
  number that is not an integer, so it has no bytes to verify a signature
  over; it now runs its signature loop with no key to verify against and
  writes the reason the Go verifier writes, `Ed25519 signature
  did:opena2a:authority:opena2a.org#key-1 did not verify against any
  configured public key`, where it wrote `no signature can be verified: the
  to-be-signed object cannot be canonicalized (...)`. The category is
  `SIGNATURE_INVALID` either way, and `test_verify.GoReportText` holds the
  Python report over `fixtures/` to the Go capture byte for byte, so with
  the old reason it failed on this fixture. `InjectedNumberPurpose` pins
  the reason for `1.5`, `{"autonomy": 0.5}` and `["billing:inquiry", 0.25]`.
  The Python verifier of `b0e094b`, the commit before its fix for #130,
  ends with `TypeError: not enough arguments for format string` on this
  fixture. None of the 25 fixtures before it carried a number that is not
  an integer in `declaredPurpose`, so the parity gate ran no such input; it
  now reports `go=PASS:REJECT[SIGNATURE_INVALID]
  python=PASS:REJECT[SIGNATURE_INVALID]` on this fixture.
  `scripts/schema_validation.py` holds it, with the array and string
  injections, to schema errors under `declaredPurpose` only. The 25
  existing fixtures and their `MANIFEST.sha256` lines are byte-identical;
  the manifest gains one line. `conformance.json` and the capture under
  `docs/captures/` are regenerated, the fixture counts in README.md,
  COSIGNERS.md, CONTRIBUTING.md, `docs/continuous-verification.md` and
  `docs/sibling-repositories.md` go from 25 to 26 (the sibling row's v1.1
  count from 15 to 16, its declaredPurpose count from 6 to 7), and
  `docs/scope.md` counts 19 of 26 fixtures that reach signature
  verification, where it counted 18 of 25. `docs/fixtures.md` and
  `docs/scope.md` list the fixture.
- Both reference verifiers read the first `--` as the end of the options
  (#224): each argument after it is a path, one that starts with `-`
  included, and `--` itself names nothing. `atx-verify -- -h.json` and
  `python3 verify.py -- -h.json` verify a fixture file named `-h.json`,
  where both named `--` an unknown option and exited 2, and the file could
  be named only with a directory in front, as `./-h.json`. An option before
  `--` is still read, and `--` alone is no path argument. Both usages have
  a `--` line. `TestDoubleDashEndsOptions` and the Python verifier's
  `ArgumentContract` class pin it. No fixture changes.
- Both reference verifiers take `--version`, and name an unknown option on
  stderr above their usage lines, exit 2 (#208): `verify --json` wrote
  `error: stat --json: no such file or directory`, and writes
  `unknown option: --json`. The Go verifier's `--version` writes the module
  path and version the binary records and the Go release that built it;
  through a module proxy holding this tree at a pseudo-version,
  `go run <module>/verifiers/go@latest --version` wrote that pseudo-version.
  The Python verifier's writes the commit git names as HEAD for its
  directory. Every script under `scripts/` takes `-h` and `--help`, and names
  an unknown argument as `unknown argument(s): <argument>` on the line above
  its usage, exit 2; `scripts/test_script_options.py` holds the ten scripts
  to that. `check_sibling_rows.py --self-test` checks its altered rows
  against sibling data built from the rows, so it reads no repository, and
  when gh is not logged in the plain run says so on one line naming
  `gh auth login` and `GH_TOKEN`.
- `go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest`
  runs the Go verifier with nothing cloned, and is README.md's first
  command. With no argument the verifier walks the fixture set built into
  the module version `go run` fetched, `fixtures/*.json` of that commit,
  names each fixture `fixtures/<name>` and exits 0 on the shipped set,
  where it wrote `usage: verify <fixture.json|dir>...` and exited 2. For
  that, `go.mod` moved from `verifiers/go` to the repository root and
  declares the module `github.com/opena2a-standards/atx-conformance`, the
  repository's path, where it declared
  `github.com/opena2a-org/atx-conformance/verifiers/go`. `go run
  github.com/opena2a-standards/atx-conformance/verifiers/go@latest` exits 1
  through the default module proxy, which answers it with the former
  nested module it stored for `d8887e6`. `fixtures.go` at the root embeds
  `fixtures/*.json`, `cmd/atx-verify` and `verifiers/go` are the module's
  main packages, and `cd verifiers/go && go run . ../../fixtures` writes
  the 93 lines it wrote before. `-h` and `--help` write the usage lines to
  stdout and exit 0. `TestEmbeddedFixturesAreTheFixtureDirectory` holds the
  embedded set to `fixtures/*.json` on disk, name by name and byte for
  byte, and `TestNoArgumentVerifiesEmbeddedFixtures` holds the no-argument
  report to the report for the `fixtures/` directory with each path
  rewritten. No fixture changes.
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
- `scripts/capture_go_verifier.py` runs the command README.md opens with,
  `go run . ../../fixtures` in `verifiers/go`, writes its standard output to
  `docs/captures/go-verifier.txt` and writes `docs/captures/go-verifier.json`
  beside it: the command, the Go release and platform, the commit, the
  uncommitted files under `verifiers/go` and `fixtures`, the time, the exit
  code and the capture's SHA-256. A run that exits non-zero writes nothing.
  `--check` needs no Go toolchain and fails when the sidecar does not
  describe the committed capture or README.md's command, or when the
  README's trimmed excerpt is not the capture's lines in order. The
  capture's bytes are unchanged. No fixture changes.
- `TestCaptureIsVerifierOutput` in `verifiers/go` fails when
  `docs/captures/go-verifier.txt` is not, byte for byte, what the Go
  verifier writes for the command its sidecar names, and names the first
  line that differs. CI runs it with `go test ./...`. The verifier's
  `main` now calls `run`, which takes the arguments and the two output
  streams and returns the exit code; its output and exit codes on the
  fixtures, on no argument, on a missing path and on a file that is not a
  fixture are unchanged. No fixture changes.
- `docs/demo/atx-verify.tape` records README.md's first command,
  `go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest`,
  typed in an empty directory with nothing cloned, then `echo $?`.
  `docs/demo/record-atx-verify.sh` builds the render image from
  `docs/demo/docker/Dockerfile` (VHS 0.12.0 with its encoder patched, and a
  Go toolchain), renders the tape with an empty home directory and writes
  `docs/demo/atx-verify.gif`, one frame per step, the text version
  `docs/demo/atx-verify-capture.txt` and the sidecar
  `docs/demo/atx-verify.json` (schema `demo-sidecar/2`): the module version
  `@latest` resolved to and its commit, the hashes of the script and the
  outputs, the pace measured from the tape, and `prerelease: true` unless
  HEAD carries the tag of that version. A render whose command does not exit
  0 with a `summary:` line last, or whose typing speed, holds, length,
  framing or size fall outside the limits the script names, writes no
  sidecar and exits 3. `docs/demo/atx-verify.narration.json` holds the words
  each hold is sized for. The MP4 a render writes goes to `docs/demo/out/`,
  which is not committed. No fixture changes.
- `fixtures/v1_1-scan-summary-member-outside-type.json`, a MUST-REJECT
  fixture (#173): the v1.1 baseline, which signs
  `scanSummary.criticalFindings` 0, with that member written as the string
  `"3"` after signing. It expects `REJECT[SIGNATURE_INVALID]` with
  `reasonContains` "signature"; both reference verifiers reported ACCEPT
  on it before the change to them below. The 26 existing fixtures and their
  `MANIFEST.sha256` lines are byte-identical; the manifest gains one line.
  `conformance.json` and the capture under `docs/captures/` are
  regenerated, the fixture counts in README.md, COSIGNERS.md,
  CONTRIBUTING.md, `docs/continuous-verification.md` and
  `docs/sibling-repositories.md` go from 26 to 27 (the sibling row's v1.1
  count from 16 to 17), and `docs/scope.md` counts 20 of 27 fixtures that
  reach signature verification, where it counted 19 of 26.
  `docs/fixtures.md` and `docs/scope.md` list the fixture, and
  `scripts/schema_validation.py` holds it to one schema error, the `type`
  of `scanSummary.criticalFindings`.

### Changed

- Six kinds of line in the two reference verifiers' output change wording
  (#276).
  The summary line counts `(1 fixture)` for one fixture, where it read
  `(1 fixtures)`; the shipped set's line, `(29 fixtures)`, is unchanged. An
  argument `help` or `version` that names no file adds the option meant to
  its line, `error: help: no such file or directory (--help prints the usage)`
  and `error: version: no such file or directory (--version prints the version line)`.
  Directories holding no `*.json` at their top level are reported as
  `no fixture *.json files found in <dirs> (subdirectories are not walked)`,
  naming each directory listed, where the line named none. A fixture with
  no `atx` member, such as one of another conformance suite, rejects with
  `PARSE_ERROR: the fixture has no atx member`, adding
  ` (its $schema is "<value>")` when its `$schema` is a string, where the Go
  verifier wrote `unexpected end of JSON input` and the Python verifier
  added that phrase in parentheses. A file that is not JSON, one whose
  value is not a JSON object and one nested deeper than 10000 levels are
  load errors with one reason each in both verifiers,
  `fixture is not valid JSON`, `fixture is not a JSON object` and
  `arrays and objects nested deeper than 10000 levels (the limit of Go's encoding/json)`,
  where each verifier wrote its JSON decoder's own error, the Go one naming
  the type `verifier.fixture`. A REJECT fixture that fails on its
  `expected.reasonContains` alone adds `reason does not contain "<substring>"`
  under its `observed:` line. Exit codes, verdicts and categories do not
  change, and both verifiers report `29 pass, 0 fail (29 fixtures)` on the
  shipped set. The argument table of `scripts/parity/parity.py` adds five
  cases, 46 from 41: the bare `help` and `version` words, and a file that is
  not a JSON object, one that is not JSON and one nested 10001 levels deep;
  run with the verifiers of the commit before, the gate fails on the last
  three. `docs/running-the-verifiers.md` says what each line reads.
- The `$schema` member of the 26 fixtures and of `conformance.json` names
  the address GitHub serves the schema of its format from on `main`,
  `https://raw.githubusercontent.com/opena2a-standards/atx-conformance/main/schemas/fixture-v1.schema.json`
  and
  `https://raw.githubusercontent.com/opena2a-standards/atx-conformance/main/schemas/conformance-profile-v1.schema.json`,
  and so do the `$id` and `$schema` const of each schema (#154). They
  named `https://atx.opena2a.org/schemas/fixture-v1.json`, whose host did
  not resolve, and
  `https://specs.opena2a.org/schemas/conformance-profile-v1.json`, which
  answered 404. When the change was made, each new address answered 200
  with the bytes of that schema file on `main`.
  `scripts/schema_validation.py` reports a format schema whose `$id` is not
  that prefix followed by the schema's path, and does not use it. Its
  self-test adds six cases (47 cases green, from 41): each tracked schema
  names its own address, and copies of the fixture schema identified on
  `atx.opena2a.org`, by the profile schema's address and by
  `schemas/fixture-v1.json`, a path no file has, and a copy of the profile
  schema identified on `specs.opena2a.org`, are each reported. Run over the
  schemas and documents of the commit before, the script exits 1, seven of
  its 49 self-test cases red. The generator writes the new URI, so each
  fixture changes in its `$schema` line alone and each of the 26
  `MANIFEST.sha256` lines changes; `scripts/check_fixture_immutability.py`
  passes, as the `atx`, `verifierState` and `expected` members are
  unchanged, and both verifiers report `26 pass, 0 fail`.
  `docs/captures/go-verifier.txt` is unchanged byte for byte; its sidecar
  records the new tree id of `fixtures`, so
  `scripts/capture_go_verifier.py --check` passes. A consumer that
  matches a `$schema` value must match the new one; the formats keep their
  members, and every rule but the `$schema` value, so both stay v1. The
  eight JCS vectors under
  `jcs-vectors/vectors/` still name
  `https://atx.opena2a.org/schemas/jcs-vector-v1.json`, a format no file
  under `schemas/` defines.
- Every fixture cites AIP-SPEC.md at the commit `docs/version-pinning.md`
  pins, `80db7b2304b2f37bddf1c82e788c27e1ab874b3d` of
  `opena2a-standards/agent-identity-protocol` (1.2.0-draft), where all 26
  cited `opena2a-org/agent-identity-protocol` on `main` with the section
  "§3 Hybrid Ed25519 + ML-DSA-65 signing, §6.1 9-factor trust scoring",
  Ed25519-only fixtures included (#153). Each fixture now carries two AIP
  citations: §3.1 "Cryptographic Identity" scoped to the signatures its
  credential carries (Ed25519 signing in 22 fixtures, hybrid Ed25519 +
  ML-DSA-65 signing in 3, an ML-DSA-65 signature with no Ed25519 signature
  in `v1_1-hybrid-pq-only.json`), then §6.1 "Multi-Factor Algorithm".
  `scripts/conformance_profile.py --check` fails, by fixture name, on a
  fixture whose AIP citations are not those two at that commit, and when
  `docs/version-pinning.md` does not link that commit; on the fixtures of
  the previous commit it names all 26.
- No fixture's `atx`, `verifierState` or `expected` member changes; every
  fixture's bytes, its `MANIFEST.sha256` line and `conformance.json` do, and
  `docs/captures/go-verifier.json` records the new tree of `fixtures/`. The
  Go verifier's output, `docs/captures/go-verifier.txt`, is unchanged.
- Both reference verifiers reject a v1.1 credential whose `scanSummary`
  holds a member outside its type, or is not an object, as
  `SIGNATURE_INVALID` with a reason naming `scanSummary` (#173). The signed
  payload holds each of its six members typed (core.md §1.3a.2 rule 2), so
  no signature covers such a value. Both verifiers left the member at its
  zero value: the v1.1 baseline, which signs `criticalFindings` 0, verified
  carrying `criticalFindings` `"3"` or `3.5`, and a credential signed with a
  zero `scanSummary` verified carrying a `scanSummary` of `7`. An absent or
  null `scanSummary`, or member, is still the zero value, and the check does
  not run under `atcVersion` 1.0, which signs no `scanSummary`.
  `TestScanSummaryOutsideItsType` and the Python verifier's
  `GoScanSummaryOutsideItsType` class pin it.
- The Go verifier rejects a v1.1 `declaredPurpose` holding an unpaired
  UTF-16 surrogate escape as `VERIFIER_CONFIG_ERROR`, naming the escape,
  where the Python verifier rejects it too (#173). Its JCS library read
  such an escape followed directly by a `\u` escape that does not complete
  the pair, `\ud800\ud800` for one, as a single U+FFFD: the Go verifier
  reported `SIGNATURE_INVALID` on the v1.1 baseline with one, and a
  credential signed with U+FFFD in `declaredPurpose` verified with such a
  pair written in its place. RFC 8785 §3.2.2.2 requires a canonicalizer to
  refuse a lone surrogate. A lone escape, `\ud800`, was refused already; its
  reason names the escape, where it read `Missing surrogate`.
  `TestDeclaredPurposeUnpairedSurrogateEscape` pins it. No fixture changes.
- The argument table of `scripts/parity/parity.py` runs twelve argument
  shapes that the "Arguments" section of `docs/running-the-verifiers.md`
  describes, whose closing sentence says the parity gate runs both
  verifiers on each shape it describes (#249). Its `--json` report listed
  29 argument lists, none of them one of these: `--` alone, which the
  section answers as it answers no argument; `-` alone, which is no
  unknown option; `-` followed by the byte 0xff, an unknown option that is
  not UTF-8; a directory holding a symbolic link named `*.json` to a
  fixture, and one holding such a link to a directory; a repository root
  whose `fixtures` directory has mode 000; a directory holding a file of
  mode 000, and that file named with `./` and `//`; a file spelled with
  `..`; a directory spelled with `./` and `//`; a `..` after a symbolic
  link with a trailing `/`; and an absolute path with a `..` after a
  symbolic link. The table runs 41 argument lists, from 29, and holds `--`
  alone to the answer it holds no argument to: the Go verifier verifies
  its embedded fixture set, each fixture passing, exit 0, and the Python
  verifier writes its usage, exit 2. Run on macOS, both verifiers agree on
  each new case and the gate passes, the three cases that need a file name
  that is not UTF-8 skipped, as APFS refuses one. Stand-in verifiers that
  diverge on eleven of the new argument lists pass the previous commit's
  argument table, 29 cases, with no divergence, and fail this one on those
  eleven. The section's closing sentence names `--` alone beside no
  argument, and `docs/continuous-verification.md` lists the new cases. The
  self-test adds twelve cases (63 cases green, from 51). No verifier or
  fixture changes.
- `docs/running-the-verifiers.md` says the file of a directory argument
  that names another directory once cleaned, as `d/link/..` can with
  `d/link` a symbolic link, is named and read as the argument spells the
  directory, then the file name, with a `/` between the two unless the
  directory as spelled ends in `/` (#233). It said "then a `/` and the file
  name", which gives `d/link/..//other.json` for `d/link/../`, while both
  verifiers print `PASS  d/link/../other.json` for it, exit 0, as they do
  for `d/link/..`. Its example quotes `d/link/../` beside `d/link/..`. The
  #231 entry under Fixed, which said the same, says "then the file name,
  with a `/` between the two unless the argument ends in `/`".
  `test_verify.py` adds
  `test_arguments_section_names_the_file_of_a_dotdot_after_a_link_as_printed`,
  which fails unless that section quotes `d/link/..` and `d/link/../` and
  the `PASS` line the Python verifier prints for each; on the previous
  commit's page it fails for `d/link/../`. No fixture changes.
- README.md says that `go run` resolves `@<commit>` to the commit's release
  tag, or to a pseudo-version when the commit has no tag. It said
  `@latest` resolves to the highest release tag of this repository that
  the Go module proxy reports, and this file's opening paragraph named
  `v0.1.0` as the first tag, until both were found to describe a tag the
  repository did not carry (#255, under Fixed). Two entries under
  `v0.1.0` are amended: the #165 entry says `verify.py` imports `os`
  again, and the #181 entry says the #151 change made a long integer in
  `declaredPurpose` `VERIFIER_CONFIG_ERROR` in both verifiers.
  `scripts/generate-fixtures/go.sum` carries the four `h1:` lines
  `go mod tidy` adds there, and `go run .` in that directory rewrites
  `fixtures/` and `MANIFEST.sha256` with no byte changed.
  `docs/captures/go-verifier.txt` is unchanged byte for byte; its sidecar
  records the new tree id of `verifiers/go/verifier`, whose `--version`
  comment changed (#223). No fixture changes.
- The Go verifier's usage and `--version` lines name the program
  `atx-verify`, the published entry point `cmd/atx-verify` (#224). They
  named `verify`, the name of neither main package's binary (`atx-verify`,
  `go`): `--help` wrote `usage: verify [fixture.json|dir]...` and writes
  `usage: atx-verify [fixture.json|dir]...`, and `--version` writes
  `atx-verify: <module> <version>, built with <Go release>`. The parity
  gate builds its Go binary as `atx-verify` and strips that name. No
  fixture changes.
- `scripts/parity/parity.py` runs twenty-one argument lists, from fifteen
  (#224): no argument; `-- -h.json` and `-- -h.json --help`; and an
  absolute path through a symbolic link to the working directory, through
  the link's target and outside the working directory. Every list runs from
  a symbolic link to the scratch directory, with `PWD` naming the link, as
  a shell names a directory it changed into through one; run on the
  verifiers before this change, the gate fails on the two paths under the
  link. No argument is held to the difference the verifiers document
  rather than to agreement: the Go verifier must report the fixture set its
  module embeds, each fixture `PASS  fixtures/<name>`, and exit 0, and the
  Python verifier, which has no embedded set, must write its usage and
  exit 2. A table row with more than five verdict lines names their count
  and last line. The self-test adds five cases (39 cases green, from 34).
  `docs/running-the-verifiers.md` names the no-argument difference and
  `docs/continuous-verification.md` the new lists. No fixture changes.
- `jcs-vectors/go.mod` declares `go 1.22.0`, as the root module and
  `scripts/generate-fixtures` do, where it declared `go 1.24` (#224): under
  `GOTOOLCHAIN=go1.22.12`, `go mod tidy` there stopped with
  `go: go.mod requires go >= 1.24`, and CI sets up Go 1.22. Under go1.22.12
  and go1.26.3 the module builds and vets, `go run ./check` passes its 8
  vectors and `go mod tidy` changes nothing; under go1.22.12 `go run ./pin`
  writes the vectors and `MANIFEST.sha256` byte for byte and
  `run-agreement.sh` ends `BYTE-AGREEMENT GATE: PASS`.
  `scripts/generate-fixtures/go.sum` holds the four `h1:` lines
  `go mod tidy` adds there (go-spew, go-difflib, testify, yaml.v3), which
  makes it the root module's `go.sum` byte for byte; the generator under
  go1.22.12 rewrites the 25 fixtures and `MANIFEST.sha256` byte for byte.
  `run-agreement.sh` installs the TS dependency with
  `npm ci --ignore-scripts`, which tells npm not to run package scripts
  inside the gate; `test_run_agreement.py` checks the flag. No fixture
  changes.
- README.md, `docs/running-the-verifiers.md` and `COSIGNERS.md` run the
  Python verifier in a virtual environment, `python3 -m venv .venv` and
  `. .venv/bin/activate`, then `python3 -m pip install -r requirements.txt`
  and `python3 verify.py ../../fixtures`, and say one is expected (#224).
  They ran `pip install` and `python verify.py`, and on a macOS host
  outside a virtual environment `command -v pip` and `command -v python`
  print nothing while `pip3` and `python3` exist. The Python verifier's
  missing-dependency line names
  `python3 -m pip install -r requirements.txt`, as `jcs-vectors/README.md`
  does.
  `docs/running-the-verifiers.md` says under "Which commit a run verified"
  what `--version` names for each way of running a verifier, as measured:
  the Go verifier run through the module proxy names the commit's
  pseudo-version; built from a git clone it names it under Go 1.24.0 and
  1.26.3 and `(devel)` under 1.22.12 and 1.23.0; built from a `git archive`
  copy it names `(devel)`, and the Python verifier run from that copy names
  no commit. `docs/scope.md` says both reference verifiers check the CRL,
  §1.3 step 6, at their step 3, before any signature, so the count of
  fixtures that reach signature verification follows their order. No
  fixture changes.
- The two reference verifiers read their arguments alike, and
  `scripts/parity/parity.py` holds them to it. An empty argument is a usage
  error on both, `error: an empty argument names no fixture file or
  directory` with exit 2, read after the options as any path is, where the
  Go verifier wrote `error: stat : no such file or directory` and the Python
  verifier walked the current directory. The Go verifier walks a directory
  whose `fixtures` entry is a file for its own `*.json`, as the Python
  verifier does, where it stopped with `open <dir>/fixtures: not a
  directory`; and it writes the Python verifier's line for a path that does
  not exist (`error: <path>: no such file or directory`, where it wrote
  `error: stat <path>: no such file or directory`) and for a directory with
  no `*.json` (`no fixture *.json files found`, where it added `in supplied
  args`). After the fixture table, `parity.py` runs both verifiers on eight
  argument lists from a scratch directory (an empty argument, `-h` and
  `--help` at several positions, a directory whose `fixtures` entry is a
  file, a path that does not exist, a directory with no `*.json`), the Go
  verifier as a binary it builds there since `go run` reports a program's
  exit 2 as its own exit 1, fails when their exit codes, first stderr lines
  or verdict lines differ, and writes the table under `arguments` in the
  `--json` report. Its self-test adds ten cases (27 cases green, from 17).
  `TestEmptyArgumentIsAUsageError`, `TestFixturesFileEntryWalksTheDirectory`
  and the Python verifier's `ArgumentContract` class pin the rules, and
  `docs/running-the-verifiers.md` states them under "Arguments". No fixture
  changes.
- Both reference verifiers refuse to load a file that is not a fixture: one
  whose `expected` member or `expected.verifyResult` is absent or null, or
  whose `verifyResult` is any string but `ACCEPT` or `REJECT`, the values
  `schemas/fixture-v1.schema.json` allows (`accept` included). Each such
  file gets one line, `FAIL  <file>  (load error: <reason>)`, with the
  reason `no expected member`, `no expected.verifyResult` or
  `expected.verifyResult "MAYBE" is not ACCEPT or REJECT`; it counts as a
  fail, the run goes on to the next file and exits 1. Before, such a value
  read as "expect REJECT": `{}`, an npm `package.json` or any other JSON
  object with no `atx` member rejected at parse and passed, so a run over
  `jcs-vectors/ts` wrote `summary: 2 pass, 0 fail (2 fixtures)` and exited
  0, a fixture with no `expected` member failed with a blank `expected:`
  line, and `accept` read as `ACCEPT`. Both verifiers read the last
  `expected` member and the last `verifyResult` in it, and the Python
  verifier quotes the value as Go's `%q` does. `verify_test.go` adds
  `TestNonFixtureIsALoadError` (seven files that are not fixtures, then the
  shipped set); in `test_verify.py`, `ExpectedMember` adds
  `test_unknown_verify_result_is_a_load_error`, and the three tests that
  held the old reading hold the new one, two of them renamed. The shipped
  set still verifies: `summary: 25 pass, 0 fail (25 fixtures)`, exit 0. No
  fixture changes.
- `scripts/check_readme_counts.py` reports a README that fails its
  `@latest` check as that check's failure. With a fenced block holding `go
  run github.com/opena2a-standards/atx-conformance/verifiers/go@latest`
  appended to README.md, its first line was `self-test FAILED: 2 of 225
  case(s) not caught by the check`, and 3 of 225 on the README of
  `265c96b`; on both it now prints `self-test passed`, then the check's
  failure naming that command and `verifiers/go`, and exits 1 as before.
  The `@latest` cases run on the README less each fenced line the check
  fails, and with `--self-test` the first case's label says how many lines
  were removed; the `@latest` wiring case holds a command the check
  already fails to a directory above its package. The self-test adds three
  cases over a README opening with that command in a fenced block: the
  check names the command and `verifiers/go`, and the `@latest` cases and
  the wiring case stay green (228 altered sites, from 225). No fixture
  changes.
- The Python verifier writes the signatures line's booleans as `true` and
  `false`, and quotes an unsupported `atcVersion` or a duplicate member name
  as Go's `%q` does, so its report over `fixtures/` from the repository root
  is `docs/captures/go-verifier.txt` byte for byte; 9 of the 93 lines of the
  two reports differed (#208). The Go verifier names a fixture given by an
  absolute path outside the working directory by that path, as the Python
  verifier does, where it wrote a climb of `..` elements. `docs/scope.md` and
  `docs/fixtures.md` carry no em dash.
- README.md names the first commit `@<commit>` works from: in place of
  `@latest`, it runs the verifier and fixtures of `ea4b485` or a later
  commit on `main`, the first commit with `go.mod` at the repository root.
  The sentence named no first commit, while `go run
  github.com/opena2a-standards/atx-conformance/verifiers/go@d8887e6`, the
  commit before it, exits 1. `scripts/check_readme_counts.py` fails when a
  sentence offering `@<commit>` names no first commit ("for `<commit>` or a
  later commit") and, in a checkout with full history, when the commit it
  names is not the oldest in `HEAD`'s history whose `go.mod` at the root
  declares the module `go.mod` declares. In a shallow clone its closing
  line says the commit was not held to the history. The self-test adds ten
  cases (216 altered sites, from 206), four of them reading the first
  commit off temporary git repositories. No fixture changes.
- `scripts/capture_go_verifier.py` reads README.md's first command with or
  without a `cd <dir> && ` prefix; without one, the command runs in the
  repository root. It runs `go run <import path>@<version>` of a package of
  this repository's module (`go.mod` at the root) as `go run ./<dir>` from
  the tree, so the capture is of the tree and not of a published version,
  and the sidecar records that command in a new `ranAs` member after
  `command`; `--check` fails when the sidecar's `ranAs` is another. For
  such a command, `inputs` and `inputTrees` list the package directory,
  `go.mod`, `go.sum`, the Go files at the module root and the directory
  they embed (`verifiers/go`, `go.mod`, `go.sum`, `fixtures.go`,
  `fixtures`). `TestCaptureIsVerifierOutput` runs the sidecar's `ranAs` in
  its working directory. `docs/captures/go-verifier.txt` is the output of
  the new first command: its 93 lines name each fixture `fixtures/<name>`
  where they named `../../fixtures/<name>`. The self-test adds eight cases:
  a first command with no `cd` runs in the root and names this module's
  package, the `cd` form reads as before, `run_argv()` maps the command to
  `go run ./verifiers/go`, and the check fails on a sidecar with no `ranAs`
  member or another `ranAs`, on a `go.mod` changed after the capture, on a
  first command naming a package outside this module and on a `go.mod`
  declaring no module (67 cases green, from 59). No fixture changes.
- The module paths of `jcs-vectors/go.mod` and
  `scripts/generate-fixtures/go.mod` are under the repository's path,
  `github.com/opena2a-standards/atx-conformance/jcs-vectors` and
  `github.com/opena2a-standards/atx-conformance/scripts/generate-fixtures`,
  where they named `github.com/opena2a-org/atx-conformance`. No fixture
  changes.
- `scripts/check_readme_counts.py` reads the Go verifier's direct
  requirements from `go.mod` at the repository root, where it read
  `verifiers/go/go.mod`. No fixture changes.
- README.md is shorter: the verifiers' exit-code sentence moved as written to
  `docs/running-the-verifiers.md` (Exit code), and the Documentation list has
  nine lines, the `CONTRIBUTING.md` line linking `conformance.json`,
  `COSIGNERS.md` and `CHANGELOG.md`. No fixture changes.
- `scripts/check_readme_counts.py` reads a block-style key of the workflow
  written with spaces before its `:` as the same key, as YAML does. With the
  step that runs it replaced by `run : python3 scripts/check_readme_counts.py`
  or `"run" : python3 scripts/check_readme_counts.py`, the check exited 1
  saying the workflow does not run that script; both now exit 0, as `run:`
  does. Its self-test adds two cases, a step whose plain `run` key and one
  whose double-quoted `"run"` key has a space before the colon, each of which
  must count as running the script (#198). No fixture changes.
- `scripts/check_readme_counts.py` reads a quoted key of the workflow, in a
  block-style line or a flow mapping, as the key it names: a single-quoted
  key without its quotes and with each `''` read as `'`, a double-quoted key
  without its quotes and with its backslash escapes undone. With the step
  that runs it replaced by `- "run": python3 scripts/check_readme_counts.py`
  or `- {"name": a, "run": "python3 scripts/check_readme_counts.py"}`, the
  check exited 1 saying the workflow does not run that script; both now exit
  0, as the unquoted forms do. Its self-test adds five cases: a step whose
  `run:` key is double-quoted, one whose key is single-quoted, one whose
  double-quoted key is written `"r\x75n"`, and a flow-mapping step whose keys
  are double-quoted, each of which must count as running the script, and the
  script named only under the key `'ru''n'`, which must not (#196). No
  fixture changes.
- `scripts/capture_go_verifier.py --check` and `--self-test` report a
  self-test case that cannot run git as a red case. With `PATH` holding
  `python3` and no `git`, or with every git command exiting 128 (as git
  does when it cannot read its configuration), both ended in a Python
  traceback (`FileNotFoundError` for `git`, or `CalledProcessError` from
  `git init`) before printing a case line or the summary. Each case now runs
  when it is reported: one that raises because git cannot be started or a
  git command exits non-zero prints `[RED  ]` and then the error under its
  label (the missing `git`, or the git command, its exit code and its
  standard error), the cases after it still run, and the run ends in its
  `N/N cases green` summary and exits 1. Two self-test cases build and run
  the other cases with no git on `PATH` and with a `git` on `PATH` that
  exits 128, whatever environment it is run with, and require exit code 1,
  the summary line last and an error line under each red case (#195). No
  fixture changes.
- `docs/captures/go-verifier.json` records `inputTrees`, the git tree id of
  each path the Go command reads (`verifiers/go`, `fixtures`), in place of
  `commit`. The commit it held, `48b49a8`, was the one the capture was taken
  on, on a branch the squash merge left off `main`: it is not an ancestor of
  `main`. A tree id hashes only the names, modes and bytes of the files
  under the path, so after a squash merge `git rev-parse HEAD:verifiers/go`
  on `main` gives the recorded id.
  `scripts/capture_go_verifier.py --check` runs git and fails when a
  recorded tree id is not the one that path has in the working tree, or
  when the sidecar lists other input paths than README.md's command reads.
  Its self-test squash-merges a branch holding a capture into `main` and
  requires a fresh clone of `main` to pass the check and to resolve each
  object id the sidecar records (#190). The capture's bytes are unchanged.
  No fixture changes.
- `scripts/capture_go_verifier.py` runs each git command with every `GIT_*`
  variable removed from its environment and with `GIT_CEILING_DIRECTORIES`
  set to the directory above the repository the command targets. With
  `GIT_DIR` naming another repository, as git exports it to a hook,
  `--self-test` (which `--check` runs first) wrote its temporary commits
  into that repository: one holding a single commit gained a `capture`
  branch and ten commits, and the run ended with a `CalledProcessError`
  from `git clone`. That repository now keeps its single commit and the
  self-test passes. The self-test adds two cases: the squash-merge case run
  with `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` naming another
  repository, and the not-a-git-work-tree case with the copy made inside
  another repository's work tree. The first must pass and the second must
  fail as it names, and each must leave every file of the other repository
  unchanged (#194). No fixture changes.
- `scripts/check_readme_counts.py` reads the command of a `run:` step that
  starts on a line after the key, indented past it, and of a step written as
  a flow mapping on one line or more. With the
  `scripts/check_fixture_immutability.py` entry removed from the
  `CONTRIBUTING.md` layout, a step `- run:` with
  `python3 scripts/check_fixture_immutability.py` on the next line, or
  `- {name: a, run: python3 scripts/check_fixture_immutability.py}`, made the
  check exit 1 saying the workflow does not run that script; both now exit
  0, as the one-line form did. Its self-test adds five cases: a step whose
  command starts on the line after `run:`, a flow-mapping step on one line
  and one whose command is on its second line, each of which must count as
  running the script, and the script named only in the name of a
  flow-mapping step and only in a YAML comment after a `run:` key, each of
  which must not (#192). No fixture changes.
- `verifiers/go/verify.go` reports a duplicate member that comes after a
  number outside the float64 range (`1e400`, `-1e400`, an integer of 401
  digits, one nested in an object or array, one between the two members)
  as `PARSE_ERROR`, as the Python verifier does. Its duplicate-member scan
  read numbers as float64, stopped at such a number and reported no
  duplicate: `v1_1-baseline-valid.json` with `"zzz": 1e400, "trustLevel": 1`
  at the start of its credential, and `baseline-valid.json` with
  `"declaredPurpose": 1e400, "trustLevel": 1`, were accepted. The scan now
  reads numbers without converting them (#187). No fixture changes.
- `scripts/check_readme_counts.py` counts a `scripts/*.py` file as run by
  `.github/workflows/conformance.yml` only when the command of a `run:` step
  names it outside a shell comment, or a script so run imports it. It
  counted a name anywhere in the workflow file: with the
  `scripts/check_fixture_immutability.py` entry removed from the
  `CONTRIBUTING.md` layout, a YAML comment naming that script made the check
  exit 0, and it now exits 1 and names the script. Its self-test adds three
  cases, the name only in a YAML comment, only in shell comments of a `run:`
  step, and only in a step `name:` and an action's `with:` input (#188). No
  fixture changes.
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
- The README paragraph on the `a2a-idf-conformance` pattern the suite mirrors
  and the second-party cosignature criterion (c) waits on moved as written to
  `docs/scope.md`, taking with it the date a2aproject/A2A#1876 closed.
  `scripts/check_readme_counts.py` reads README.md alone and fails on each
  line that states a three-part version or an ISO date. No fixture changes.
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
- `verifiers/python/verify.py` dropped its imports of `os` and
  `dataclasses.field`, which it did not use (#165); it imports `os` again
  for `--version`, which reads `os.environ` (#208). No fixture changes.
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
  `declaredPurpose` the credential was `SIGNATURE_INVALID`, as it was for a
  shorter integer outside float64 range, where the Go verifier reports
  `VERIFIER_CONFIG_ERROR` for both (#181); the `declaredPurpose` entry for
  #151 above makes it `VERIFIER_CONFIG_ERROR` in both verifiers, as each
  reports for an integer of 401 or 5000 digits there. No fixture changes.
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

### Fixed

- Both verifiers fold a credential member name by a fixed table, ASCII
  `A-Z` to `a-z`, U+212A (Kelvin sign) to `k` and U+017F (long s) to `s`,
  and leave every other character unchanged, where they lowercased every
  other character by the Unicode tables of the release they ran under
  (`unicode.ToLower` in `verify.go`, `str.lower()` in `verify.py`), so
  which names were a duplicate member depended on the Go and Python release
  (#173). The credential of `fixtures/v1_1-baseline-valid.json` with two
  unsigned members added, named U+1C89 followed by `x` and U+1C8A followed
  by `x` (a case pair from Unicode 16.0), was ACCEPT built with Go 1.26.3
  and under Python 3.13.12 and a `PARSE_ERROR` built with Go 1.27.2 and
  under Python 3.14.3; it is ACCEPT under all four. Members named `É`
  and `é` are two members, ACCEPT on both, where both reported
  `PARSE_ERROR`; `É` written twice stays a `PARSE_ERROR`, as do
  `TRUSTLEVEL` beside `trustLevel`, the Kelvin sign beside `k` and the long
  s beside `s`. With Go 1.26.3 and Python 3.14.3 the two verifiers also
  split on U+0130, which `unicode.ToLower` maps to `i` and `str.lower()` to
  `i` followed by U+0307: a member named U+0130 followed by `d` beside the
  credential's `id` was a `PARSE_ERROR` in the Go verifier and ACCEPT in
  the Python one, and members named U+0130 followed by `x` and `i`, U+0307,
  `x` the reverse; each is ACCEPT on both. Go's `encoding/json` matches a
  name to an ASCII struct field through no non-ASCII letter but the Kelvin
  sign and the long s, and RFC 8259 §8.3 compares names code unit by code
  unit, so neither reference verifier's decoder joins the names the fold no
  longer joins.
  `docs/running-the-verifiers.md` says the fold is fixed where it said each
  release set its Unicode version. `TestFoldKey` and
  `TestRawDuplicateMember` hold the table in the Go verifier, and
  `GoMemberNameFolding.test_non_ascii_names_fold_only_through_the_fixed_table`,
  which replaces `test_non_ascii_names_fold_through_lowercase`, holds it in
  the Python one. No fixture changes.
- Both reference verifiers reject a v1.1 credential whose signed payload
  holds an integer of magnitude above 2^53-1, outside the I-JSON exact
  range (RFC 7493 §2.2), as `SIGNATURE_INVALID`, with one reason naming the
  member and the integer: `trustLevel`, `scanSummary.criticalFindings`,
  `scanSummary.highFindings`, `behavioralProfile.observationDays` or an
  integer in `declaredPurpose` (#278). The Go verifier's JCS library reads
  each number as an IEEE 754 double and writes 9007199254740993 as
  9007199254740992, so it accepted a credential carrying 9007199254740993
  under a signature over those bytes, which the Python verifier, writing
  the digits, rejected because the signature did not verify. The check
  runs once the payload canonicalizes, so a `declaredPurpose` number
  outside the float64 range or an unpaired surrogate escape still rejects
  as `VERIFIER_CONFIG_ERROR`. The vendored RFC 8785 serializer
  (`verifiers/python/rfc8785.py` and `jcs-vectors/python/rfc8785.py`)
  refuses such an integer where it wrote its digits, as it refuses a
  float. A MUST-REJECT fixture built by the generator,
  `fixtures/v1_1-integer-outside-exact-range.json`, carries
  `scanSummary.criticalFindings` 9007199254740993 signed over the bytes the
  JCS library writes for it; the Go verifier reported ACCEPT on it before
  this change. The 29 existing fixtures and their `MANIFEST.sha256` lines
  are byte-identical, the manifest gains one line, the stated counts go
  from 29 to 30, and `conformance.json` and the Go verifier capture are
  regenerated.
- `scripts/parity/parity.py` checks a `--json` symbolic link whose target
  ends in `/` or `/.` at the directory that target names, where it checked
  the directory of a file of that name, as pathlib drops that `/` or `/.`
  in joining the target (#274). Run with Python 3.12 and with Python 3.14
  on macOS from a directory holding `file`, a regular file, and symbolic
  links `tsl` to `newdir/`, `dot` to `newdir/.`, `fsl` to `file/` and
  `via` to `b/`, with `b` a symbolic link to `newdir` and no `newdir`:
  `--json tsl`, `--json dot` and `--json via` are refused as `no such
  directory: newdir` and `--json fsl` as `not a directory: file`, exit 2
  and one line naming the path and why, before any verifier runs, where
  the check accepted each and writing the report to it, as the gate does,
  raised `FileNotFoundError`, and `NotADirectoryError` for `fsl`. A link
  to `missing/x/` with no `missing` and one to `file/x/`, refused before
  as `no such directory: missing` and `not a directory: file`, are refused
  as `no such directory: missing/x` and `no such directory: file/x`, as
  `--json missing/x/y.json` and `--json file/x/y.json` are. The self-test
  adds one case (79, from 78): links to `newdir/` and `newdir/.` with no
  `newdir`, to a file's name followed by `/`, and to the name of a link it
  accepts followed by `/`. No fixture changes.
- `scripts/parity/parity.py` refuses a `--json` path the report cannot be
  written to as a usage error, exit 2 and one line naming the path and why,
  before any verifier runs, and its self-test holds the docstring's Report
  keys block exactly (#271). Run with Python 3.12 and with Python 3.14 from
  a directory holding `ro/` of mode 555, `ro/existing.json` of mode 444,
  `locked/sub/` under `locked/` of mode 000, and `dangling`, a symbolic
  link to `missing/parity-report.json`, with no `missing/`: `--json
  ro/parity-report.json` is
  refused as `directory not writable: ro`, `--json ro/existing.json` as
  `not writable` and `--json dangling` as `no such directory: missing`,
  where on both releases the check accepted each and writing the report
  raised `PermissionError` or `FileNotFoundError`. `--json
  locked/parity-report.json`, `--json locked/sub` and `--json
  locked/sub/parity-report.json` are refused as `Permission denied`, and a
  path through a missing directory with a 300-character name as `File name
  too long`, where with Python 3.12 the check raised `PermissionError` or
  `OSError`, and with Python 3.14 it accepted the first two, said `no such
  directory: locked/sub` for the third, a directory that exists, and `no
  such directory` for the fourth. The check reads each path with
  `os.stat`, whose error, other than a missing path, is the reason, where
  `Path.is_dir` and `Path.exists` return False for a permission error on
  Python 3.14 and raise it on Python 3.12. The self-test's case holding the Report keys
  block equal to `REPORT_KEYS` now needs the block on lines of its own and
  followed by a blank line, so a key line appended after its last entry
  turns the case red, where it stayed green. The Report keys entry for
  `unreported`, and the docstrings of `build_report` and `render_table`,
  say a verifier is listed when it exited non-zero before reporting any
  fixture, as `compare` lists it; one that exits 0 without reporting any
  fixture is a fixture set mismatch. The self-test adds four cases (78,
  from 74): the refusals above, under stand-ins for the permission errors
  that deny access whatever user the self-test runs as, paths it accepts,
  the appended key line, and a verifier exiting 0 without reporting any
  fixture absent from `unreported`. No fixture changes.
- The description of `fixtures/revoked.json` says that the credential's
  revoked flag is what rejects it in both reference verifiers, which read
  the flag before the CRL and return on it, and that
  `fixtures/revoked-crl-only.json` is the fixture whose verdict depends on
  the CRL, where it ended "Both rejection paths are exercised." (#151).
  Both verifiers report `REJECT[REVOKED: credential revoked field is true]`
  on it and never read its CRL entry, as `docs/fixtures.md` says. Only the
  description changes, at its source in the generator:
  `scripts/check_fixture_immutability.py` finds the fixture's `atx`,
  `verifierState` and `expected` members unchanged, and its
  `MANIFEST.sha256` line and its `conformance.json` entry change with the
  description, as `docs/versioning.md` allows for documentation.
- `scripts/parity/parity.py` ends with an exit code, not a traceback, on two
  paths, and documents its `--json` report's keys (#126). A `--json` path
  that is a directory or whose directory does not exist is a usage error:
  exit 2 and one line naming the path, before any verifier runs, where the
  gate ran both verifiers and the argument table and then raised an
  `OSError` writing the report. A verifier that cannot start is reported as
  `[parity] <name> verifier could not start: <reason>`, exiting 127 before
  reporting any fixture and named in `unreported`, and the argument table's
  `go build` that cannot start is a build error; run with no `go` on PATH,
  the gate ends `PARITY: FAIL` naming both and exits 1, where it raised
  `FileNotFoundError`. The module docstring lists the six keys of the
  report under `Report keys:`, held equal to `REPORT_KEYS`, whose names the
  self-test holds equal to the keys `build_report` returns. The self-test's
  no-fixtures case now runs stand-ins that exit 1, so a gate that ran a
  verifier before finding no fixture would leave that exit on stderr and
  turn the case red; a control shows the same stand-ins leave it when run
  over a fixture. The self-test adds six cases (74, from 68). No fixture
  changes.
- The #259 entry below says that outside the RFC 3339 layout the Go
  verifier's error still differed by release, and that the #266 entry above
  it makes the Go 1.22.12 build name the offset too, where it said the error
  can still differ (#268). Built with Go 1.22.0, 1.22.12, 1.23.0 or 1.26.3,
  the Go verifier rejects `fixtures/baseline-valid.json` with an `issuedAt`
  of `2099-12-31T23:59:59+25:00x` as `PARSE_ERROR: parsing time
  "2099-12-31T23:59:59+25:00x": time zone offset hour out of range`; on the
  commit before #266, built with Go 1.22.12, it named the extra text
  (`extra text: "x"`). `scripts/check_readme_counts.py` fails when a
  sentence of this file's top section says a result can still differ by
  release, or still differs between Go releases, and quotes as a code span
  a timestamp that `verifiers/go/verifier/verify_test.go` writes as a
  string literal: what those tests expect of a timestamp does not depend on
  the Go release that runs them. On this file as the previous commit left
  it, the check names the #259 sentence and exits 1. The self-test adds
  eleven cases (272 altered sites, from 261). No fixture changes.
- The Go verifier names the time zone offset, as Go 1.23 and later do, when
  a timestamp outside the RFC 3339 layout has an offset hour above 24 or
  minute above 60 and text follows the offset or the offset's sign or
  minute is malformed (#266). Built with Go 1.22.12, it rejected a
  credential whose `issuedAt` was `2099-12-31T23:59:59+25:00x` with
  `PARSE_ERROR: parsing time "2099-12-31T23:59:59+25:00x": extra text:
  "x"`, and one whose `issuedAt` was `2026-02-30T00:00:00+25:0a` for an
  offset it could not parse (`cannot parse "+25:0a" as "Z07:00"`); built
  with Go 1.26.3 it named `time zone offset hour out of range` in each. The
  Python verifier rejects both as a `PARSE_ERROR`, as not in the RFC 3339
  layout, so the verdict category did not differ. Go 1.23 and later check
  the offset's range before the text after it, its sign and its minute's
  digits; the verifier now gives their error under Go 1.22 too
  (`offsetFirst`, which replaces `offsetBeforeDay` and still names the
  offset before a day out of range). `TestTimestampDecode` adds nine such
  timestamps and eight controls whose error does not change, and
  `TestOffsetOutsideLayoutVerdict` pins the two values above as an
  `issuedAt` on the v1.0 and v1.1 baselines, as a clock and as a CRL
  `issuedAt`. Built with Go 1.22.0 and Go 1.22.12, both tests fail without
  the change; with it they pass built with each of Go 1.22.0, 1.22.12,
  1.23.0, 1.24.0, 1.25.0, 1.25.3, 1.25.7, 1.26.0, 1.26.3, 1.26.5, 1.26.7,
  1.26.8, 1.27.2 and 1.27.3. `docs/running-the-verifiers.md` states the
  case, and the sidecar `docs/captures/go-verifier.json`, re-taken with
  `scripts/capture_go_verifier.py`, records the new tree of
  `verifiers/go/verifier`; `docs/captures/go-verifier.txt` is unchanged
  byte for byte. No fixture changes.
- The Go verifier names the time zone offset, as Go 1.23 and later and the
  Python verifier do, when a timestamp's day is out of range and its offset
  has an hour above 24 or a minute above 60 (#259). Built with Go 1.22.12,
  it rejected a credential whose `issuedAt` was `2026-02-30T00:00:00+25:00`
  with `PARSE_ERROR: parsing time "2026-02-30T00:00:00+25:00": day out of
  range`, and named the day for that value in `clockRfc3339` and in a CRL's
  `issuedAt` too; built with Go 1.23.0 or Go 1.26.3 it named `time zone
  offset hour out of range` in each, as the Python verifier does. The
  verdict category did not differ between them. Go 1.22's time package
  refuses such a timestamp for the day, and `checkOffset` ran only on a
  timestamp Go had decoded; the verifier now checks the offset before it
  reports a day out of range (`offsetBeforeDay`), and built with Go 1.22.12
  and with Go 1.26.3 it names the offset in each of the three. The offsets
  table in `TestTimestampDecode` adds `2099-02-30T23:59:59+25:00` and
  `1900-02-29T00:00:00+23:61`, with three controls whose offset is in range
  and whose error names the day, and `TestOffsetOutOfRangeVerdict` adds
  `2026-02-30T00:00:00+25:00` as an `issuedAt`, a clock and a CRL
  `issuedAt`. Built with Go 1.22.12, both tests fail without the change;
  with it they pass built with each of Go 1.22.0, 1.22.12, 1.23.0, 1.24.0,
  1.25.0, 1.25.3, 1.25.7, 1.26.0, 1.26.3, 1.26.5, 1.26.7, 1.26.8, 1.27.2
  and 1.27.3. `GO_OFFSET_OUT_OF_RANGE`, `GO_OFFSET_VERDICTS`,
  `GO_UNLOADABLE_OFFSETS` and the clock test in
  `verifiers/python/test_verify.py` carry the new rows, and
  `docs/running-the-verifiers.md` says Go 1.22 refuses such a timestamp for
  the day when its day is out of range. Outside the RFC 3339 layout the
  error still differed by release: built with Go 1.22.12 the verifier
  named the extra text in an `issuedAt` of `2099-12-31T23:59:59+25:00x`,
  and built with Go 1.23.0 or Go 1.26.3 the offset; the #266 entry above
  makes it name the offset built with Go 1.22.12 too. The sidecar
  `docs/captures/go-verifier.json`, re-taken with
  `scripts/capture_go_verifier.py`, records the new tree of
  `verifiers/go/verifier`; `docs/captures/go-verifier.txt` is unchanged
  byte for byte. No fixture changes.
- The Python verifier rejects a v1.1 credential whose `declaredPurpose`
  holds an unpaired UTF-16 surrogate escape as `VERIFIER_CONFIG_ERROR` when
  it also holds a number its JCS serializer cannot write, `1.5` for one, as
  the Go verifier does (#173). It refused an escape in a string only as it
  encoded the payload, after the number had stopped it and left no
  payload, so it reported `SIGNATURE_INVALID`: on
  `{"a": 1.5, "b": "\ud800"}`, and on
  `{"a": 1.5, "b": "\ud800\ud800"}` once the Go verifier refused that
  escape too (above). It now refuses the escape before it canonicalizes the
  payload, so an escape beside a number outside the float64 range is named
  in place of the number, as in the Go verifier. Its reason, which quoted
  the encoder's error, is the one the Go verifier writes, naming the first
  unpaired escape, with its hex digits in lower case.
  `GO_SURROGATE_VERDICTS_V11` and
  `test_declared_purpose_escape_is_refused_before_a_number` in
  `verifiers/python/test_verify.py` pin it. No fixture changes.
- The `aip-conformance` row in `docs/sibling-repositories.md` names AIP
  v1.0.0-draft, the `spec.id` and `spec.version` that
  `opena2a-standards/aip-conformance` declares in its `conformance.json`,
  where it named AIP v1.2.0-draft (#261). Run against the sibling
  repositories, `scripts/check_sibling_rows.py` exits 0, where it reported
  that the row's Spec cell names AIP v1.2.0-draft and exited 1. Its
  self-test keeps the row that named AIP v1.2.0-draft among the retracted
  rows the check must still fail on, checked against sibling data built
  from the published rows: put in place of this commit's row, it fails
  with `aip-conformance row's Spec cell names AIP v1.2.0-draft, but`, and
  on the page of the previous commit, which publishes that row, the case
  is red and the self-test exits 1. The self-test runs 18 cases, from 17.
  No fixture changes.
- Both reference verifiers refuse a timestamp whose time zone offset has an
  hour above 24 or a minute above 60 (`+25:00`, `+23:61`), and the Go
  verifier's verdict on one no longer depends on the Go release that built it
  (#167). Built with Go 1.22.12, the Go verifier reached `SIGNATURE_INVALID`
  on a baseline whose `expiresAt` was `2099-12-31T23:59:59+25:00` and
  `ACCEPT` on one whose `clockRfc3339` was `2026-06-01T00:00:00+23:61`, as
  the Python verifier did; built with Go 1.23.0 or Go 1.26.0, it reached
  `PARSE_ERROR` and `VERIFIER_CONFIG_ERROR`. The Go verifier checks the
  offset after Go's time package decodes a timestamp (`checkOffset`) and
  refuses it with the error Go 1.23 and later give, and the Python verifier
  refuses it with a reason that names the same error text. Measured with Go 1.22.12 and Go 1.26.3: a
  credential `issuedAt` or `expiresAt` with such an offset is a
  `PARSE_ERROR`, a `clockRfc3339` a `VERIFIER_CONFIG_ERROR`, a CRL
  `issuedAt`, `nextUpdate` or entry `revokedAt` fails to load the fixture,
  and a `behavioralProfile.generatedAt` projects the profile as null, so
  the signature rejects. An offset of `+24:00` or `+23:60` still decodes.
  `TestOffsetOutOfRangeVerdict` and the offsets table in
  `TestTimestampDecode` in `verifiers/go`, and `GO_OFFSET_OUT_OF_RANGE`,
  `GO_OFFSET_VERDICTS` and `GO_UNLOADABLE_OFFSETS` in
  `verifiers/python/test_verify.py`, pin it. No fixture changes.
- README.md and this file's opening paragraph describe the repository as
  carrying no tag, where both described a `v0.1.0` tag it does not carry
  (#255). README.md said `@latest` resolves to the highest release tag of
  this repository that the Go module proxy reports, and this file said
  `v0.1.0` is this repository's first tag, while the tags API of
  `opena2a-standards/atx-conformance` returned an empty list and
  `go list -m -json github.com/opena2a-standards/atx-conformance@latest`
  resolved to `v0.0.0-20261020031110-014aa2e7700c`, a pseudo-version of
  commit `014aa2e` on `main`. README.md says the repository has no release
  tag, so `@latest` resolves to a pseudo-version of a commit on `main`, the
  one the Go module proxy reports as latest; this file says the repository
  carries no tag yet and that the `v0.1.0` section lists the changes its
  first tag is to carry. `scripts/check_readme_counts.py` holds the README
  and this file's opening paragraph to the version tags the checkout
  carries, where they can be read: a sentence naming a tag as this
  repository's must name one it carries; while it carries none, a sentence
  saying what `@latest` resolves to must name the pseudo-version; once it
  carries one, no sentence may say it has no tag. On the README.md and
  CHANGELOG.md of the previous commit it names both sentences and exits 1.
  Held to a `v0.1.0` tag, it names the three sentences that say the
  repository has no tag: README.md's, the `--version` item of
  `docs/running-the-verifiers.md` and this file's opening. A shallow
  clone, or a tree with no repository, is not held to it, and the closing
  line says so; the workflow's checkout of this repository sets no
  `fetch-depth`, whose default fetches one commit, so in CI the self-test's
  cases are what hold the check. The self-test adds sixteen cases (261
  altered sites, from 245). No fixture changes.
- `docs/captures/go-verifier.json` lists no file in `inputsUncommitted`, and
  `scripts/capture_go_verifier.py --check` fails on a sidecar that lists one
  (#208). The sidecar is the provenance README.md's excerpt is published
  with, and it listed `fixtures/v1_1-declared-purpose-number-injected.json`,
  a file the #130 change, which last rewrote it, also added: it named as
  uncommitted a file committed beside it, and `--check` passed on it.
  Before the #130 change it listed `verifiers/go/verifier/verify.go` and
  `verifiers/go/verifier/verify_test.go`, two files the #231 change, which
  rewrote it then, also changed. A capture is taken once the inputs it
  reads are committed. `--check` names the files a sidecar lists in
  `inputsUncommitted` and says to commit the changes and run the script,
  and the script, after writing a sidecar that lists one, names the files
  on a line saying `--check` fails on it. The `$schema` change (#154,
  under Changed) re-took the sidecar, and the time zone offset change
  (#167) re-took it again, each recording `inputsUncommitted` as `[]`;
  this change does not rewrite the sidecar, and
  `docs/captures/go-verifier.txt` is unchanged byte for byte. The
  self-test adds three cases: a sidecar listing an input file fails, a run
  with a change to an input uncommitted names the file on its last line,
  and a capture taken that way and committed with the change fails on
  `inputsUncommitted` alone (71 cases green, from 68). No fixture changes.
- `scripts/parity/parity.py` skips the six argument cases that need a path
  of mode 000 (`locked`, `lockedroot`, `noread/x.json`, `./noread//x.json`,
  `noread` and `noread/{xff}.json`) where that mode does not deny the gate
  access, rather than running them on paths the verifiers can open (#252).
  Mode 000 does not deny root access: run as root in a `python:3.12-slim`
  container, stand-in verifiers that list or open their argument opened all
  six paths, and the rows read `agree: exit 0` with no word that the cases
  tested nothing they are named for. The gate now lists `locked` and
  `lockedroot/fixtures` and opens `noread/x.json` before the cases run;
  where one opens, each of the six rows reads `skipped: mode 000 does not
  deny this process access: it opened locked (effective uid 0)`, naming the
  path and the effective uid, the PASS line counts them, and the `--json`
  report marks them, as it does the cases the file system refuses a name
  that is not UTF-8 for. Run as root in a `python:3.12` container with Go
  1.26 and both verifiers, the gate exits 0 with `PARITY: PASS (... and on
  every argument case but the 6 skipped)`. In the `python:3.12-slim`
  container run as uid 1000, or as root with `DAC_OVERRIDE` and
  `DAC_READ_SEARCH` dropped, the stand-ins were denied those paths and the
  cases ran. The self-test adds four cases (68 cases green, from 64). No
  fixture changes.
- `scripts/parity/parity.py` reads the fixture it copies to the two scratch
  files whose name is not UTF-8, `xff/{xff}.json` and `noread/{xff}.json`,
  once, before the `try` that classifies their writes, so an `EILSEQ` or
  `EINVAL` raised by that read is raised rather than taken for the file
  system refusing the name (#246). With the read for `xff/{xff}.json`
  raising `EINVAL`, `_argument_scratch` returned `the file system refuses a
  name that is not UTF-8 (Invalid argument)` and wrote neither file; with
  the name standing in as `ff`, which any file system takes, and the read
  for `noread/{xff}.json` raising `EINVAL`, it returned the same, that file
  unwritten. It now raises `EINVAL` from the one read. The self-test adds
  one case (64 cases green, from 63). No fixture changes.
- The Python reference verifier words the load error of a fixture file it
  cannot read as the Go reference verifier does, naming the path as spelled
  and, where it is not UTF-8, by its bytes (#244). The error was Python's
  `OSError`, the path quoted through `repr` as a `Path` holds it: run on
  Linux as a user other than root, for `d`, a directory holding a copy of
  `fixtures/baseline-valid.json` of mode 000 named by the byte 0xff then
  `.json`, `python3 verify.py d` wrote `FAIL  d/`, that byte, then
  `.json  (load error: [Errno 13] Permission denied: 'd/\udcff.json')`,
  naming the file once by its byte and once by the six characters
  `\udcff`, where `atx-verify d` wrote `(load error: open d/`, that byte,
  then `.json: permission denied)`, both exit 1; both now write the Go
  verifier's line. A file of mode 000 named as `./d//x.json` was named
  `d/x.json` in the error, and is named `./d//x.json`, and for `l`, a
  directory holding `link.json`, a symbolic link to a directory, the error
  `[Errno 21] Is a directory: 'l/link.json'` is
  `read l/link.json: is a directory`. `verify.py` reads the file with
  `_read_file`, which words the error of `open` or of the read after it as
  Go's `os.ReadFile` does. The Python verifier's `UnreadableFixture` class
  and two tests of
  `NonUTF8FixtureName` pin it; the test that runs the verifier on such a
  file needs a user other than root and a file system that takes the name,
  which APFS refuses. The "Arguments" section of
  `docs/running-the-verifiers.md` says so. The argument table of
  `scripts/parity/parity.py` runs 29 argument lists, from 27, adding a
  file of mode 000 named `x.json` and one named by the byte 0xff then
  `.json`, which `docs/continuous-verification.md` lists; where the file
  system refuses that name, the second is skipped with the two cases that
  already need one. The verdict lines the table compares carry the load
  error a FAIL line names, which they dropped. With the Python verifier of
  the previous commit, the gate fails on the two new cases alone, run on
  Linux as a user other than root. The self-test adds three cases (51
  cases green, from 48). No fixture changes.
- `scripts/parity/parity.py` takes only `EILSEQ` or `EINVAL`, raised writing
  the scratch file whose name is not UTF-8, for the file system refusing
  that name (#243). Its `except OSError` took `ENOSPC` there for a refusal:
  run on stand-in verifiers with that write raising `ENOSPC`, the gate
  skipped the two cases that need the name, each row reading `skipped: the
  file system refuses a name that is not UTF-8 (No space left on device)`,
  and wrote `PARITY: PASS (all implementations agree on gate, verdict, and
  category, and on every argument case but the 2 skipped)`, exit 0;
  `EACCES`, `EROFS` and `EIO` were taken for refusals too. Those four are
  now raised, as an error writing another scratch file is, and on the same
  stand-ins the gate stops with `ENOSPC`, exit 1. APFS refuses the name with
  `EILSEQ`, and exFAT on macOS with `EINVAL`.
  `docs/continuous-verification.md` says which errors are a refusal. The
  self-test adds two cases (48 cases green, from 46). No fixture changes.
- The Python reference verifier names a fixture whose path is not UTF-8 by
  the path's bytes in its report, as the Go reference verifier names it
  (#241). `sys.argv` and `os.scandir` hold a byte of a path that does not
  decode as a surrogate escape, which the report line wrote as a backslash
  escape: for `d`, a directory holding a copy of
  `fixtures/baseline-valid.json` named by the byte 0xff then `.json`,
  `python3 verify.py d` wrote `PASS  d/\udcff.json`, the six characters
  `\udcff` where `atx-verify d` wrote the byte, both exit 0, and naming the
  file as the argument gave the same two lines; both now write the byte.
  The verifier sets standard output to write each surrogate escape as the
  byte it stands for before the first report line. An unpaired surrogate
  outside the escapes, U+D800 in a verify error for one, is still written
  as a backslash escape. The Python verifier's `NonUTF8FixtureName` class
  pins it; its test that runs the verifier on such a file is skipped where
  the file system refuses the name, as APFS does. The "Arguments" section
  of `docs/running-the-verifiers.md` says so. The argument table of
  `scripts/parity/parity.py` runs 27 argument lists, from 25, adding that
  file named as a file and found in a directory, which
  `docs/continuous-verification.md` lists; where the file system refuses
  the name, the two cases are skipped, each row saying why, and the PASS
  line counts them. Each row of the `--json` report's `arguments` holds
  `skipped`, null for a case that ran. With the Python verifier of the
  previous commit, the gate fails on those two cases alone, run on Linux.
  The self-test adds three cases (46 cases green, from 43). No fixture
  changes.
- `verifiers/python/test_verify.py` imports where Python's `os` has no
  `geteuid`, as on Windows (#240). `NonUTF8Argument`'s test of a directory
  that cannot be listed was decorated with `skipIf(os.geteuid() == 0, ...)`,
  which is evaluated when the class body runs, at import, before the
  class's `skipIf(os.name != "posix", ...)` applies: run with an `os`
  stand-in whose `name` is `"nt"` and which has no `geteuid`, the module
  raised `AttributeError: module 'os' has no attribute 'geteuid'` there, so
  it did not import. That guard reads `os.name` first, as
  `ArgumentContract`'s does, and the module imports with that stand-in,
  `NonUTF8Argument` skipped. The new `OsWithoutGeteuid` class imports the
  file with the stand-in in place of `os`, and checks that
  `NonUTF8Argument` and `ArgumentContract`'s test of a directory that
  cannot be listed are skipped; run on the file as it was before this
  change, it raises that `AttributeError`. No fixture changes.
- The Python reference verifier writes an argument that is not UTF-8 on
  stderr as the bytes it was given, as the Go reference verifier writes it
  (#238). `sys.argv` holds a byte that does not decode as a surrogate
  escape, which `sys.stderr` wrote as a backslash escape: for the one byte
  0xff, `python3 verify.py $'\xff'` wrote
  `error: \udcff: no such file or directory`, the six characters `\udcff`
  where `atx-verify $'\xff'` wrote the byte, both exit 2; both now write
  the byte. The line naming an unknown option goes through the same write:
  for `-` followed by that byte, both write `unknown option: -` and the
  byte. The Python verifier's `NonUTF8Argument` class pins it; its test of
  a directory that cannot be listed, named by that byte, is skipped where
  the file system refuses such a name, as APFS does. The "Arguments"
  section of `docs/running-the-verifiers.md` says so. The argument table
  of `scripts/parity/parity.py` runs 25 argument lists, from 24, adding
  `{xff}`, the byte 0xff, and reads a byte of a verifier's output that is
  not UTF-8 as a surrogate escape, where the byte the Go verifier writes
  raised `UnicodeDecodeError`; with the Python verifier of the previous
  commit, the gate fails on that case alone. The self-test adds one case
  (43 cases green, from 42): a verifier that writes the six characters
  `\udcff` for that byte is reported as a divergence. No fixture changes.
- The Python reference verifier refuses a directory it cannot list as the
  Go reference verifier refuses it (#236). It gave no name for a directory
  `os.scandir` could not open: with `locked/` holding a copy of
  `fixtures/baseline-valid.json` as `x.json` and mode 000, run as a user
  other than root, `python3 verify.py locked` wrote
  `no fixture *.json files found` where `atx-verify locked` wrote
  `error: open locked: permission denied`, both exit 2; both now write
  the latter, and name `locked/` and `./locked` as spelled. A repository
  root whose `fixtures/` cannot be listed is refused naming it,
  `error: open r/fixtures: permission denied` for `r`.
  `test_a_directory_that_cannot_be_listed_is_refused` pins it. The
  "Arguments" section of `docs/running-the-verifiers.md` says so. The
  argument table of `scripts/parity/parity.py` runs 24 argument lists,
  from 23, adding `locked`, a directory of mode 000 while the cases run;
  with the Python verifier of the previous commit, the gate fails on that
  case alone. The self-test adds one case (42 cases green, from 41): a
  verifier that writes `no fixture *.json files found` for that directory
  is reported as a divergence. No fixture changes.
- The Python reference verifier skips a subdirectory named `*.json` when
  it walks a directory, as the Go reference verifier skips it (#234). It
  listed a directory with `Path.glob("*.json")`, which gives
  subdirectories too: with `g/` holding a copy of
  `fixtures/baseline-valid.json` as `x.json` and a subdirectory
  `sub.json`, `python3 verify.py g` wrote
  `FAIL  g/sub.json  (load error: [Errno 21] Is a directory: 'g/sub.json')`
  above `PASS  g/x.json` and `summary: 1 pass, 1 fail (2 fixtures)`,
  exit 1, where `atx-verify g` wrote `PASS  g/x.json` and
  `summary: 1 pass, 0 fail (1 fixtures)`, exit 0; both now write the
  latter. A subdirectory named `*.json` in a repository root's `fixtures/`
  is skipped too. It now keeps the `*.json` entries the Go verifier keeps,
  those `os.ReadDir` does not type as a directory, so a symbolic link
  named `*.json` is kept whatever it links to, as before, and a link to a
  directory is still a load error in both.
  `test_a_subdirectory_named_json_is_skipped` pins it. The "Arguments"
  section of `docs/running-the-verifiers.md` says which entries a walk
  skips. The argument table of `scripts/parity/parity.py` runs 23
  argument lists, from 22, adding `subdir`, a directory holding a
  subdirectory named `sub.json`; with the Python verifier of the previous
  commit, the gate fails on that case alone. The self-test adds one case
  (41 cases green, from 40): a verifier that reports `subdir/sub.json` as a
  fixture that fails to load is reported as a divergence. No fixture
  changes.
- Both reference verifiers read and name the file the operating system
  resolves a path to when a `..` follows a symbolic link (#231). A
  directory argument was listed by the operating system, which resolves the
  link before it applies the `..`, and each file listed was joined onto the
  argument as Go's `filepath.Join` joins it, which removes the `..` with the
  link. With `d/link` a link to `elsewhere/deep` and `elsewhere/other.json`
  a copy of `fixtures/expired.json`, `atx-verify d/link/..` and
  `python3 verify.py d/link/..` wrote `FAIL  d/other.json` with a load
  error, exit 1; both write `PASS  d/link/../other.json`, exit 0, having
  verified that copy. Where a directory argument, cleaned as
  `filepath.Clean` cleans it, names another directory than it does, its
  files are named and read as the argument spells it, then the file name,
  with a `/` between the two unless the argument ends in `/`, and its
  `fixtures` entry is looked up there: `r/link/..`,
  which resolves to a directory holding `fixtures/`, was walked for its own
  `*.json` and is walked for `fixtures/*.json`. A directory argument that
  names the same directory cleaned keeps the names `filepath.Join` gives:
  `fixfile/../fixfile` names `fixfile/x.json`. The directory of an absolute
  path is resolved as the path spells it, each `..` applied after the
  element before it is resolved: with `elsewhere/x.json` a copy of
  `fixtures/expired.json`, `$PWD/d/link/../x.json` was named `d/x.json`
  while `elsewhere/x.json` was read, and is named by its whole path, since
  `elsewhere` is outside the working directory. Both verifiers removed a
  `..` from that directory with the element before it before resolving its
  links, as `filepath.Dir` removes it, which the #224 entry below says of
  the Python verifier; each now resolves the directory as spelled.
  `TestDotDotAfterALinkIsAppliedWhereTheLinkLeads` and the Python
  verifier's `test_dotdot_after_a_link_is_applied_where_the_link_leads`
  pin it; the latter replaces
  `test_directory_is_cleaned_before_its_links_are_resolved`, which held the
  name `sub/x.json` for `$PWD/sub/link/../x.json`. The "Arguments" section
  of `docs/running-the-verifiers.md` says how such a directory's files are
  named. The argument table of `scripts/parity/parity.py` runs 22 argument
  lists, from 21, adding `hop/link/..`; with this commit's Go verifier and
  the Python verifier of the previous commit, the gate fails on that case
  alone. The self-test adds one case (40 cases green, from 39): a verifier
  that names the files of `hop/link/..` with the `..` removed is reported
  as a divergence. No fixture changes.
- `scripts/check_readme_counts.py` reads CHANGELOG.md's top section, its
  first `## ` section whatever the heading says, for the `go run` commands
  it names as README.md's first command, where it read the section headed
  `## Unreleased` alone (#229). Once that section was retitled `## v0.1.0`
  it read no sentence of CHANGELOG.md, so a sentence under `## v0.1.0`
  naming an invented `go run` command as README.md's first command left it
  exiting 0, while its closing line still named the Unreleased section. On
  the CHANGELOG.md of `602ba90` it reads 279 sentences under `## v0.1.0`,
  where it read none, and with that sentence added it names the sentence
  and exits 1. A CHANGELOG.md with no `## ` heading fails it, exit 1, where
  it passed, and the closing line names the heading of the section read.
  The self-test's cases add their sentences to the published top section,
  where they added a `## Unreleased` section at the top of a CHANGELOG.md
  that had none, and it adds three cases (245 altered sites, from 242): an
  invented command named in a top section retitled `## v9.9.9`, the same
  under `### Added` in a CHANGELOG.md whose one section is `## v0.1.0`, and
  a CHANGELOG.md with each `## ` heading made `### `. No fixture changes.
- Both reference verifiers name a fixture given by an absolute path under
  the working directory alike when the working directory was entered
  through a symbolic link (#224): each compares the working directory and
  the directory holding the fixture with their links resolved. Run from a
  link to a directory holding `fixtures/`, with `PWD` naming the link as a
  shell sets it, the Go verifier wrote `PASS  fixtures/baseline-valid.json`
  for the path through the link and the whole path for the same file
  through the link's target, and the Python verifier the reverse; both
  write `PASS  fixtures/baseline-valid.json` for each. The Python verifier
  removes a `..` from that directory with the element before it before it
  resolves the directory's links, as Go's `filepath.Dir` does.
  `TestPathUnderLinkedWorkingDirectory` and the Python verifier's
  `ArgumentContract` class pin it. No fixture changes.
- The Python verifier names a fixture in its report as the Go verifier
  does, however its argument is spelled (#220). It made each argument a
  `pathlib.Path`, which drops `./` and a trailing `/`, collapses `//` and
  keeps a `..` that Go's `filepath.Join` removes: from `verifiers/python`,
  `python verify.py ../../fixtures/./baseline-valid.json` wrote
  `PASS  ../../fixtures/baseline-valid.json`, and writes
  `PASS  ../../fixtures/./baseline-valid.json`, the Go verifier's line;
  `../../fixtures//baseline-valid.json` likewise. It now reads each argument
  as the string it is: a file keeps its spelling in its PASS or FAIL line, a
  file of a walked directory is named as `filepath.Join` writes it
  (`fixfile/../fixfile` names `fixfile/x.json`, not
  `fixfile/../fixfile/x.json`), an absolute path under the working directory
  is named relative to it with its `..` removed, the names sort byte by
  byte, as the Go verifier sorts them, and a file named with a trailing `/`
  is refused, `error: stat fixfile/x.json/: not a directory` with exit 2,
  where it was verified. The "Arguments" section of
  `docs/running-the-verifiers.md` says how a file and the files of a walked
  directory are named, and that a trailing `/` is refused. The Go verifier's
  behavior does not change. The argument table of `scripts/parity/parity.py`
  runs fifteen argument lists, from twelve: `fixfile//x.json
  ./fixfile/./x.json`, `fixfile/../fixfile` and `fixfile/x.json/`; with the
  Python verifier of the previous commit the gate fails on those three and
  agrees on the other twelve. The self-test adds three cases (34 cases
  green, from 31): a verifier that reads each of those argument lists as a
  `pathlib.Path` reads it is reported as a divergence. `test_verify.py` adds
  `PathSpelling`. No fixture changes.
- The Added entry on running the Go verifier with nothing cloned names
  `go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest`
  as README.md's first command; through the default module proxy it
  printed `summary: 25 pass, 0 fail (25 fixtures)` and exited 0 (#222). The
  entry named `go run
  github.com/opena2a-standards/atx-conformance/verifiers/go@latest`, which
  exits 1 there, and called `verifiers/go` the module's main package, while
  `cmd/atx-verify` is one too. `scripts/check_readme_counts.py` fails when
  a sentence of CHANGELOG.md's Unreleased section names as README.md's
  first command a `go run` command other than the first line of README.md's
  first fenced block, with or without its `cd <dir> && ` prefix and with
  `<module>` read as the module `go.mod` declares. A command holding another
  placeholder, such as `go run <import path>@<version>`, and the sections
  below Unreleased are not held to it. On the CHANGELOG.md of `20799e3` it
  names that entry's sentence and exits 1. The self-test adds fourteen
  cases (242 altered sites, from 228), among them the sentence this entry
  corrects, the same sentence in a section below Unreleased, and a
  README.md opening with `cd verifiers/go && go run . ../../fixtures`, a
  code span holding `. ` that the check reads whole. No fixture changes.
- The Python verifier verifies a fixture path named twice twice, as the Go
  verifier does (#218): `python verify.py ../../fixtures/baseline-valid.json
  ../../fixtures/baseline-valid.json` wrote one PASS block and
  `summary: 1 pass, 0 fail (1 fixtures)`, and writes two PASS blocks and
  `summary: 2 pass, 0 fail (2 fixtures)`, the Go verifier's report.
  `docs/running-the-verifiers.md` says so. The argument table of
  `scripts/parity/parity.py` runs twelve argument lists, from eleven:
  `fixfile/x.json fixfile/x.json`, on which both verifiers exit 0 and write
  two PASS lines and that summary. The self-test adds one case (31 cases
  green, from 30): a verifier that verifies a path named twice once is
  reported as a divergence. `test_verify.py` adds `RepeatedPath`. No fixture
  changes.
- `docs/running-the-verifiers.md` says the parity gate runs both verifiers
  on each argument shape its "Arguments" section names, and the argument
  table of `scripts/parity/parity.py` ran none of `--version`, an unknown
  option or a repository root (#216). The table runs eleven argument lists,
  from eight: `fixfile --version`, `fixfile --bogus` and `root`, a scratch
  directory holding `baseline-valid.json` as `fixtures/x.json` beside a
  `conformance.json` that is not a fixture, as a repository root does. On
  this tree both verifiers exit 0 on `fixfile --version` and write no
  verdict line, exit 2 on `fixfile --bogus` with `unknown option: --bogus`
  as the first stderr line, and on `root` verify `root/fixtures/x.json`
  alone. The self-test adds three cases (30 cases green, from 27): a
  verifier that takes `--version` after a path for a path, one that reports
  an unknown option as a missing path, and one that walks a repository root
  for its own `*.json` are each reported as a divergence.
  `docs/continuous-verification.md` names the new argument lists; the
  sentence in `docs/running-the-verifiers.md` is unchanged. No fixture
  changes.
- README.md's first command is `go run
  github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest`.
  `go run github.com/opena2a-standards/atx-conformance/verifiers/go@latest`,
  the command it opened with, exits 1 through the default module proxy
  with `module declares its path as:
  github.com/opena2a-org/atx-conformance/verifiers/go but was required as:
  github.com/opena2a-standards/atx-conformance/verifiers/go`: the proxy
  answers `verifiers/go@latest` with the version of the former nested
  module it stored for `d8887e6`, and a stored version cannot be removed.
  No directory on the path `cmd/atx-verify` has held a `go.mod`. Through a
  local file proxy holding that stored module and this tree as the root
  module, `cmd/atx-verify@latest` printed `summary: 25 pass, 0 fail (25
  fixtures)` and exited 0, and `verifiers/go@latest` exited 1 with the
  error above. The verifier moved to the package `verifiers/go/verifier`,
  whose `Run` takes the arguments and the two output streams;
  `cmd/atx-verify` and `verifiers/go` are main packages that call it, so
  `cd verifiers/go && go run . ../../fixtures` and `go test ./...` there run
  as before, and `TestEntryPointsPassArgsToRun` holds both to the call.
  `docs/captures/go-verifier.txt` is unchanged byte for byte; its sidecar
  records `ranAs` `go run ./cmd/atx-verify` and lists
  `verifiers/go/verifier` among its inputs, which
  `scripts/capture_go_verifier.py` reads off the package's imports of the
  module (self-test 68 cases, from 67). README.md says `@latest` resolves
  to the commit the module proxy reports as latest, where it said the
  newest commit on `main`, and that `verifiers/go@<commit>` runs for
  `ea4b485` or a later commit. `scripts/check_readme_counts.py` fails when
  a fenced `go run <module>/<dir>@latest` command names a package under a
  directory whose `go.mod` is in `HEAD`'s history (self-test 225 altered
  sites, from 216); on the README of `265c96b` it names `verifiers/go`. No
  fixture changes.

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
