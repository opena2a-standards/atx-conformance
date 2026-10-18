# Changelog

This repository has no tags or releases. A consumer pins it at a commit, so
entries name the commit that made the change. Changes to an existing fixture's
credential, signatures, verifier state or expected outcome are listed here
whenever one lands; [`docs/versioning.md`](docs/versioning.md) "Versioning
and stability" says they should not.

## Unreleased

### Added

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
- `go run github.com/opena2a-standards/atx-conformance/verifiers/go@latest`
  runs the Go verifier with nothing cloned, and is README.md's first
  command. With no argument the verifier walks the fixture set built into
  the module version `go run` fetched, `fixtures/*.json` of that commit,
  names each fixture `fixtures/<name>` and exits 0 on the shipped set,
  where it wrote `usage: verify <fixture.json|dir>...` and exited 2. For
  that, `go.mod` moved from `verifiers/go` to the repository root and
  declares the module `github.com/opena2a-standards/atx-conformance`, the
  repository's path: declared as
  `github.com/opena2a-org/atx-conformance/verifiers/go`, the command above
  fetched the newest commit and stopped at `module declares its path as:
  github.com/opena2a-org/atx-conformance/verifiers/go but was required as:
  github.com/opena2a-standards/atx-conformance/verifiers/go`. `fixtures.go`
  at the root embeds `fixtures/*.json`, `verifiers/go` is the module's main
  package, and `cd verifiers/go && go run . ../../fixtures` writes the 93
  lines it wrote before. `-h` and `--help` write the usage lines to stdout
  and exit 0. `TestEmbeddedFixturesAreTheFixtureDirectory` holds the
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

### Changed

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

### Fixed

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
