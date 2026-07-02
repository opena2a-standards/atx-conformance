# atx-conformance

Conformance fixtures and reference verifiers for the
[ATX v1.0 credential schema](https://github.com/opena2a-org/atx-spec).

Each fixture is a byte-stable JSON file that bundles an Agent Trust Credential
with verifier configuration and an expected outcome (ACCEPT or REJECT). Two
SDK-independent reference verifiers (Go and Python) walk the fixture set and
report PASS or FAIL per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

This suite mirrors the pattern set by
[`a2a-idf-conformance/fixtures/composition/aim-did-rfc9421/`](https://github.com/opena2a-org/a2a-idf-conformance/tree/main/fixtures/composition/aim-did-rfc9421)
(APS interop conformance for A2A-IDF wire signatures). It closes criterion (c)
on the OpenA2A maturity bar tracked in [a2aproject/A2A#1876](https://github.com/a2aproject/A2A/issues/1876):
"peer-cosigned conformance fixtures comparable to APS's `aim-did-rfc9421/*`
set."

License: Apache 2.0. All keypairs, seeds, and credential identifiers in this
repository are TEST-ONLY.

## Scope

What this suite verifies:

| Item | Covered by |
|---|---|
| ATX v1.0 schema-version gate | `fixtures/malformed-schema.json` |
| Expiry gate against a pinned verifier clock | `fixtures/expired.json` |
| Revocation via credential `revoked` flag AND CRL membership | `fixtures/revoked.json` |
| Trusted-issuer DID set | `fixtures/wrong-issuer.json` |
| Ed25519 signature verification over the canonical payload | every fixture |
| Hybrid Ed25519 + ML-DSA-65 signature verification (FIPS 204) | `fixtures/baseline-valid-hybrid.json` |
| Threshold 2-of-3 cosignature path | `fixtures/threshold-2of3-cosignature.json` |
| Tampered-signature rejection | `fixtures/tampered-signature.json` |
| Key-to-issuer binding (a trusted authority cannot sign for another) | `fixtures/cross-issuer-key.json`, `fixtures/v1_1-cross-issuer-key.json` |
| ATX v1.1 JCS(TBS) signing, signed-field integrity | `fixtures/v1_1-baseline-valid.json`, `fixtures/v1_1-tampered-capabilities.json` |
| ATX v1.1 declaredPurpose carried under the signature (§1.5) | `fixtures/v1_1-declared-purpose-valid.json`, `fixtures/v1_1-tampered-declared-purpose.json` |
| Issuer-chain depth requirement for trust level 3 and above | implicit in every ACCEPT fixture (all use trust level 4 with a 2-link chain) |

What this suite does NOT verify:

- Content hash matching the agent binary. The `contentHash` field is in every
  fixture for byte-stability, but no agent binary is shipped; verifiers stop
  at step 5 (signature) without consulting content.
- Transparency log inclusion proofs. The `transparencyLogIndex` is populated
  for byte-stability; the conformance verifiers do not consult a log.
- Build attestation predicate verification. `buildAttestation` is a string
  field in ATX v1.0 (not a structured SLSA v1 predicate inline); verifiers
  do not parse it.
- Behavioral profile validation. Field is omitted from these fixtures.

The full requirement-to-fixture mapping is machine-readable in
[`conformance.json`](./conformance.json), regenerated from the fixtures by
[`scripts/conformance_profile.py`](./scripts/conformance_profile.py) and
CI-checked against drift.

## Continuous verification

[`.github/workflows/conformance.yml`](./.github/workflows/conformance.yml)
enforces every claim in this README on each push and pull request:

1. Both reference verifiers run against `fixtures/` and must report
   `15 pass, 0 fail`.
2. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
3. The JCS byte-agreement gate
   ([`jcs-vectors/run-agreement.sh`](./jcs-vectors/run-agreement.sh)) must
   pass across the independent Go, Python, and TypeScript canonicalizers.
4. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](./scripts/parity/parity.py)) asserts the Go
   and Python verifiers agree per fixture on gate status, verdict, and
   reject category, and publishes `parity-report.json` as a CI artifact.
5. `conformance.json` must match the fixture set.

## Honest scope notes

This is the section that future reviewers, second-implementation authors, and
A2A coordination-map readers should read before forming judgments.

### Canonicalization: v1.0 signs 11 fields; v1.1 signs JCS(TBS)

ATX v1.0 signs a pipe-delimited canonical string, not the JSON body. The
signature covers exactly 11 fields, defined verbatim in
[`opena2a-registry/pkg/atcverify/verify.go`](https://github.com/opena2a-org/opena2a-registry/blob/main/pkg/atcverify/verify.go)
`canonicalPayload()`:

```
agentId | agentDid | version | contentHash | buildAttestation | issuerDid |
trustLevel | trustScore (%.6f) | issuedAt (RFC 3339) | expiresAt (RFC 3339) |
atcVersion (hardcoded "1.0")
```

Fields NOT covered by the v1.0 signature include `capabilities`, `scanSummary`,
`behavioralProfile`, `publisher`, `publisherDid`, `transparencyLogIndex`,
`signatures`, `revoked`, `revokedAt`, `revocationReason`, `createdAt`, `id`,
`issuerChain`. A consequence is that an attacker who can write to a stored v1.0
credential could modify `capabilities` or `scanSummary` without breaking
signature verification.

**ATX v1.1 closes this.** A v1.1 credential (`atcVersion: "1.1"`) signs
`JCS(TBS)`: the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical form
of a projected to-be-signed object that includes `capabilities`, `scanSummary`,
`issuerChain`, `publisher`, and `behavioralProfile`, so those fields become
integrity-protected. The normative projection and determinism rules are in
[`atx-spec/core.md`](https://github.com/opena2a-org/atx-spec/blob/main/core.md)
§1.3a.2. The verifiers dispatch on `atcVersion`; the v1.0 pipe form is frozen and
unchanged. Cross-language byte agreement on `JCS(TBS)` is proven by
[`jcs-vectors/`](jcs-vectors/) (Go, Python, and TypeScript canonicalizers must
agree byte-for-byte). The `fixtures/v1_1-*.json` fixtures exercise the v1.1 path,
including `v1_1-tampered-capabilities.json`, which is REJECTED precisely because
capabilities are now signed.

### Hybrid signing: production status

ATX v1.0 mandates hybrid Ed25519 + ML-DSA-65 signing at the wire format.
The registry-side issuance path (`opena2a-registry/internal/application/atc_service.go` `IssueATC()`)
emits hybrid signatures in production: threshold Ed25519 signatures from
the multi-key signing set, plus one ML-DSA-65 signature from the hybrid
keypair wired in at `cmd/server/main.go:682-685`. Issued ATX credentials
in production today therefore carry both algorithms, matching the
`baseline-valid-hybrid.json` fixture in this repository.

The standalone offline verifier (`opena2a-registry/pkg/atcverify`)
verifies both algorithms as of opena2a-registry PR #214: when a
credential declares an ML-DSA-65 signature, at least one ML-DSA-65
signature must verify in addition to at least one Ed25519 signature.
The wire-format alignment between the issuer's emitted ML-DSA-65
signature `Value` (raw 3309-byte `mldsa65.SignatureSize` blob) and the
spec / conformance-fixture format was closed by opena2a-registry PR #215.
Credentials issued before PR #215 carry a legacy combined-blob encoding
that the new verifier rejects; ATC TTL is 7 days so the rollover is
naturally complete one week after PR #215 ships.

A separate AIM-side credential format (`RealATCIssuer.Issue()` in
`agent-identity-management/apps/backend/internal/infrastructure/atc/atc_issuer.go`)
produces CBOR-encoded credentials and signs Ed25519 only. That issuer has
no active callers in the AIM backend today; whether it ships as a future
artifact or gets removed is tracked separately. It is not the credential
this conformance suite tests.

The Go reference verifier in this repository ([`verifiers/go`](./verifiers/go))
DOES verify ML-DSA-65 signatures per the spec mandate. The Python reference
verifier ([`verifiers/python`](./verifiers/python)) treats ML-DSA-65 as
present but out-of-scope (the post-quantum Python library landscape is
fragmented; no stdlib support). The hybrid fixture is annotated to be
ACCEPTed on the Ed25519 path alone in Python, with a banner. For full
hybrid verification end to end, run the Go verifier.

### Trusted-issuer DID drift between this suite and the production verifier

This suite uses the canonical post-consolidation DID method
`did:opena2a:<type>:<id>` with type prefix `authority` for issuers, matching
the 2026-05-23 unification across AIP-SPEC and ATX-SPEC. The `did:opena2a`
method itself is formally documented at
[`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a)
(Apache-2.0) and is filed for registration with the W3C DID Extensions
registry on
[`w3c/did-extensions#717`](https://github.com/w3c/did-extensions/pull/717).
The production offline verifier in `opena2a-registry/pkg/atcverify/verify.go`
still hardcodes `did:opena2a:registry:opena2a.org` (note the `registry`
type prefix) and a legacy `did:atp:registry:opena2a`. The conformance
verifiers configure trusted issuers from the fixture, so they do not
rely on the production verifier's hardcoded list. The drift is a separate
reconciliation item against the ATC to ATX code rename.

### Trust scoring: 9-factor reference

The `trustScore` field in each fixture (87.5 on the baseline) is composite
output from the 9-factor algorithm specified in AIP-SPEC §6.1 with the
audited weights:

| Factor | Weight |
|---|---|
| Verification status | 25 |
| Uptime and availability | 15 |
| Action success rate | 15 |
| Security alerts | 15 |
| Compliance | 10 |
| Execution isolation | 10 |
| Age and history | 5 |
| Drift detection | 3 |
| User feedback | 2 |
| Total | 100 |

The fixture value is illustrative; this suite does not verify the
trust-score computation itself.

## Fixtures

All fixtures use:

- Trusted issuer DID: `did:opena2a:authority:opena2a.org`
- Test agent: `agent_conformance_test_001` (DID `did:opena2a:agent:agent_conformance_test_001`)
- Pinned verifier clock: `2026-05-24T00:00:00Z`
- Ed25519 keypair source: [RFC 8032 §7.1 Test 1](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1) (primary) and Tests 2 / 3 (cosigners)
- ML-DSA-65 keypair source: fixed test seed (incrementing bytes `00..1f`), public key pinned in [`vectors/mldsa65-seed.json`](./vectors/mldsa65-seed.json)

| Fixture | Expected | Exercises |
|---|---|---|
| `fixtures/baseline-valid.json` | ACCEPT | Single Ed25519 signature from primary issuer, trust level 4 with 2-link chain. The minimum viable accepted credential. |
| `fixtures/baseline-valid-hybrid.json` | ACCEPT | Ed25519 plus ML-DSA-65 signatures from the same primary issuer over the same canonical payload. Go verifier validates both; Python validates Ed25519 only and reports ML-DSA-65 as out of scope. |
| `fixtures/revoked.json` | REJECT (REVOKED) | Credential `revoked: true` AND CRL entry for the agent. Both rejection paths exercised. |
| `fixtures/threshold-2of3-cosignature.json` | ACCEPT | Three Ed25519 signatures from three distinct keys (primary plus two cosigners). All three verify. |
| `fixtures/expired.json` | REJECT (EXPIRED) | `expiresAt: 2025-01-01T00:00:00Z`, earlier than the pinned clock. Otherwise valid. |
| `fixtures/wrong-issuer.json` | REJECT (UNTRUSTED_ISSUER) | Real Ed25519 signature from an untrusted-issuer keypair (RFC 8032 §7.1 Test 1024 first 32 bytes), `issuerDid: did:opena2a:authority:attacker.example`. Signature is mathematically valid; issuer is not in trusted set. |
| `fixtures/tampered-signature.json` | REJECT (SIGNATURE_INVALID) | One bit of the signature value flipped after signing. All other fields unchanged. |
| `fixtures/malformed-schema.json` | REJECT (UNSUPPORTED_VERSION) | `atcVersion: "2.0"`. Verifier rejects at step 1 before any signature check. |
| `fixtures/v1_1-baseline-valid.json` | ACCEPT | ATX v1.1. Single Ed25519 signature over `JCS(TBS)` (atx-spec §1.3a.2). Canonical bytes equal the `jcs-vectors` baseline. |
| `fixtures/v1_1-baseline-valid-hybrid.json` | ACCEPT | ATX v1.1 with Ed25519 plus ML-DSA-65 over the same `JCS(TBS)` bytes. Go validates both; Python validates Ed25519 only. |
| `fixtures/v1_1-tampered-capabilities.json` | REJECT (SIGNATURE_INVALID) | ATX v1.1 whose `capabilities` were escalated to `admin:all` after signing. Rejected because v1.1 signs capabilities; the v1.0 form would have accepted it. |
| `fixtures/v1_1-declared-purpose-valid.json` | ACCEPT | ATX v1.1 carrying a populated `declaredPurpose` (§1.5: vocabVersion, statement, category, taskScopes, capabilityJustification, autonomy, dataScopes, egressScopes). The presence-based member is signed as part of `JCS(TBS)`; canonical bytes equal the `jcs-vectors` `08-declared-purpose` vector. |
| `fixtures/v1_1-tampered-declared-purpose.json` | REJECT (SIGNATURE_INVALID) | ATX v1.1 whose `declaredPurpose.category` was rewritten from `financial-operations` to `agent-orchestration` after signing. Rejected because v1.1 signs declaredPurpose; this is the integrity that makes a declared purpose binding and non-repudiable (no post-issuance purpose-laundering). |

## Running the verifiers

Both verifiers walk every `*.json` file in the directory you point them at
(or you may pass individual fixture files). Exit code is 0 if every
fixture's observed result matches the expected result and the rejection
category matches (when declared).

### Go (full hybrid Ed25519 plus ML-DSA-65)

```bash
cd verifiers/go
go run . ../../fixtures
```

Depends on:

- Go 1.22 or later
- `github.com/cloudflare/circl v1.6.2` (resolved by `go mod tidy`)

### Python (Ed25519, ML-DSA-65 out of scope)

```bash
cd verifiers/python
pip install -r requirements.txt
python verify.py ../../fixtures
```

Depends on:

- Python 3.11 or later
- `cryptography >= 42.0.0`

For full hybrid verification end to end, use the Go verifier.

### Expected output

Both verifiers report `summary: 15 pass, 0 fail (15 fixtures)` against the
shipped fixture set. Any divergence on bytes (the fixture file was modified)
or on verifier semantics (the verifier has drifted from the spec) shows up
as one or more FAIL lines.

## Reproducing the fixtures

The fixtures in this repository are deterministic. To regenerate them from
the keypair vectors in [`vectors/`](./vectors):

```bash
cd scripts/generate-fixtures
go run .
```

The generator:

1. Loads each Ed25519 keypair vector. Verifies that the seed-derived public
   key matches the vector's `publicKeyHex`. Panics on drift.
2. Resolves the ML-DSA-65 public key from the seed (using CIRCL's
   `mldsa65.NewKeyFromSeed`). Pins the resolved public key into
   `vectors/mldsa65-seed.json` on first run; on subsequent runs, verifies
   that the pinned value still matches.
3. Builds each ATX credential from a shared template (`newBaselineATX`),
   then per-fixture mutates exactly the fields needed to exercise that
   fixture's path (revoke, expire, swap issuer, tamper signature, change
   schema version, add cosigners or ML-DSA-65 sig).
4. Computes the pipe-delimited canonical payload (the same 11-field
   function the production verifier in `pkg/atcverify` uses, duplicated
   verbatim in the generator and in each reference verifier).
5. Ed25519-signs (and ML-DSA-65-signs where applicable) the canonical
   payload.
6. Marshals each fixture to byte-stable JSON (`encoding/json` with 2-space
   indent, fields in struct-declaration order).
7. Writes the fixture file. Recomputes its SHA-256. Updates
   `MANIFEST.sha256` in path-sorted order.

Re-running the generator MUST produce byte-identical fixtures. If the bytes
change, either (a) the generator changed, (b) the canonicalization shifted,
or (c) the CIRCL ML-DSA-65 implementation changed. Any of those is a
breaking change for downstream verifiers.

## Version pinning

| Component | Version | Source |
|---|---|---|
| ATX schema | v1.0 | [`opena2a-org/atx-spec/core.md`](https://github.com/opena2a-org/atx-spec/blob/main/core.md) |
| AIP spec | v1.0 (in flight on PR 1496) | [`opena2a-org/agent-identity-protocol`](https://github.com/opena2a-org/agent-identity-protocol) |
| `did:opena2a` method | v0.1 (W3C registration filed, PR `w3c/did-extensions#717`) | [`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a/blob/main/did-method-opena2a.md) |
| Ed25519 test vector source | RFC 8032 §7.1 Tests 1, 2, 3, 1024 | [datatracker.ietf.org/doc/html/rfc8032](https://datatracker.ietf.org/doc/html/rfc8032) |
| ML-DSA-65 | FIPS 204 final | [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final) |
| CIRCL (ML-DSA-65 implementation) | v1.6.2 | [github.com/cloudflare/circl](https://github.com/cloudflare/circl) |
| cryptography (Python Ed25519) | >= 42.0.0 | [pyca/cryptography](https://github.com/pyca/cryptography) |
| Conformance fixture format | v1 (this repo) | [`fixtures/baseline-valid.json#$schema`](./fixtures/baseline-valid.json) |

## Implementations that validate against this suite

| Implementation | Verifier | Status |
|---|---|---|
| `opena2a-standards/atx-conformance/verifiers/go` (this repo) | Go, full Ed25519 plus ML-DSA-65, v1.0 + v1.1 | 11 / 11 PASS |
| `opena2a-standards/atx-conformance/verifiers/python` (this repo) | Python, Ed25519, ML-DSA-65 out of scope, v1.0 + v1.1 | 11 / 11 PASS |
| `opena2a-org/opena2a-registry/pkg/atcverify` (production offline verifier) | Go, full Ed25519 plus ML-DSA-65 | passes the hybrid fixture as of opena2a-registry PR #214 + PR #215; integration via vendored fixture or `go get` import open as a follow-up |

Independent second-party implementations are tracked on the sibling issue
[a2aproject/A2A#1876](https://github.com/a2aproject/A2A/issues/1876).

## Sibling repositories

Two peer conformance suites cover the other OpenA2A specs in scope of the
A2A coordination map's criterion (c) thread
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885):

| Repo | Spec | Status |
|---|---|---|
| `atx-conformance` (this repo) | ATX v1.0 + v1.1 credential schema | 13 fixtures (8 v1.0, 5 v1.1 JCS incl. 2 declaredPurpose), 2 verifiers (Go full hybrid, Python Ed25519), `jcs-vectors/` byte-agreement gate (8 vectors, Go/Python/TS), `MANIFEST.sha256` pinned |
| [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) | ATP v1.0.0-rc1 protocol | 4 fixtures (discovery, trust-proof baseline, trust-proof hybrid, Signed Tree Head), same 2-verifier pair, `MANIFEST.sha256` pinned |
| [`aip-conformance`](https://github.com/opena2a-standards/aip-conformance) | AIP v1.0.0-draft identity protocol | §6.4 (VC `AgentTrustCredential`) covered by cross-linking this repo's fixtures; §5.1 challenge-response covered by 4 dedicated fixtures + Go/Python verifiers shipped at v0.2 (2026-05-28, Decision 3-C) |

The three suites share the same MANIFEST-pinned byte-stable shape and are
structurally comparable to A2A-IDF's
[`aim-did-rfc9421/*`](https://github.com/opena2a-org/a2a-idf-conformance/tree/main/fixtures/composition/aim-did-rfc9421)
set.

## Repository layout

```
LICENSE                          Apache 2.0
README.md                        this file
MANIFEST.sha256                  per-fixture SHA-256 (path-sorted)
fixtures/                        the 8 conformance fixtures (byte-stable JSON)
vectors/                         test keypair vectors (TEST-ONLY)
verifiers/go/                    Go reference verifier (full hybrid)
verifiers/python/                Python reference verifier (Ed25519)
scripts/generate-fixtures/       deterministic fixture generator (Go)
```

## Versioning and stability

- The conformance fixture file format (`$schema: fixture-v1`) is stable
  across patch revisions of this repository. Adding new fixture fields is
  a minor version bump; renaming or removing fields is a major version
  bump.
- The set of fixtures may grow. New fixtures are additive and do not
  invalidate prior `MANIFEST.sha256` entries; each new fixture appears as
  a new line in the manifest.
- Existing fixtures are immutable once published. If a fixture needs to
  change semantically, it ships under a new name. This is what makes
  `MANIFEST.sha256` a useful regression check.

## Contributing

Issues and PRs welcome on this repository. Substantive coordination on the
ATX wire format itself happens in [`opena2a-org/atx-spec`](https://github.com/opena2a-org/atx-spec)
and in the A2A coordination map on
[a2aproject/A2A#1876](https://github.com/a2aproject/A2A/issues/1876).

## License

Apache 2.0, see [`LICENSE`](./LICENSE).
