# atx-conformance: scope

What the suite verifies, what it does not, and the notes to read before
relying on it. The commands that run it are in the [README](../README.md).

This suite mirrors the pattern set by
[`a2a-idf-conformance/fixtures/composition/aim-did-rfc9421/`](https://github.com/opena2a-standards/a2a-idf-conformance/tree/main/fixtures/composition/aim-did-rfc9421)
(APS interop conformance for A2A-IDF wire signatures). It is designed to close
criterion (c) on the OpenA2A maturity bar stated in
[a2aproject/A2A#1876](https://github.com/a2aproject/A2A/issues/1876) (closed as
not planned on 2026-06-15), "peer-cosigned conformance fixtures comparable to
APS's `aim-did-rfc9421/*` set", once a second-party cosignature is recorded in
the [cosignature registry](../COSIGNERS.md#cosignature-registry). The CI
self-cosignature anchors the baseline and does not count toward it.

## Scope

What this suite verifies:

| Item | Covered by |
|---|---|
| ATX v1.0 schema-version gate | `fixtures/malformed-schema.json` |
| Expiry gate against a pinned verifier clock | `fixtures/expired.json` |
| Revocation via the credential `revoked` flag | `fixtures/revoked.json` |
| Revocation via CRL membership alone, the credential's own flag being false (§1.3 step 6, which both reference verifiers perform at their step 3, before any signature) | `fixtures/revoked-crl-only.json` |
| Trusted-issuer DID set | `fixtures/wrong-issuer.json` |
| Ed25519 signature verification over the canonical payload | every fixture that passes steps 0 to 4 of the reference verifiers (strict parse, schema version, expiry, revocation by the flag or the CRL, trusted issuer): 19 of 26. The others reject before step 5; `go test` in `verifiers/go` checks that their signatures verify once that gate is lifted. The count follows the reference verifiers' order, which checks the CRL (§1.3 step 6) before the signatures (§1.3 steps 4 and 5), so `fixtures/revoked-crl-only.json` is among the others. Both fixtures whose CRL lists their agent carry valid signatures, so in the spec's order they reject as `REVOKED` too |
| Hybrid Ed25519 + ML-DSA-65 signature verification (FIPS 204) | `fixtures/baseline-valid-hybrid.json` |
| Multi-signature: every declared signature must verify (three Ed25519 signatures from three distinct keys) | `fixtures/threshold-2of3-cosignature.json` |
| Tampered-signature rejection | `fixtures/tampered-signature.json` |
| Key-to-issuer binding (a trusted authority cannot sign for another; a chain DID that is not a trusted issuer contributes no eligible key) | `fixtures/cross-issuer-key.json`, `fixtures/v1_1-cross-issuer-key.json`, `fixtures/v1_1-untrusted-chain-authority.json` |
| ATX v1.1 JCS(TBS) signing, signed-field integrity | `fixtures/v1_1-baseline-valid.json`, `fixtures/v1_1-tampered-capabilities.json` |
| ATX v1.1 declaredPurpose carried under the signature (§1.5) | `fixtures/v1_1-declared-purpose-valid.json`, `fixtures/v1_1-tampered-declared-purpose.json` |
| Degenerate declaredPurpose (§1.3a.2 rule 5, issue #11): parse-level emptiness, verbatim non-object inclusion | `fixtures/v1_1-declared-purpose-empty-whitespace.json`, `fixtures/v1_1-declared-purpose-array-injected.json`, `fixtures/v1_1-declared-purpose-string-injected.json`, `fixtures/v1_1-declared-purpose-number-injected.json` |
| Strict credential parse: duplicate object members reject at any depth (RFC 8259 §4 parser-divergence smuggling) | `fixtures/v1_1-duplicate-purpose-member.json` |
| Fold-aware strict parse: case-variant members that `encoding/json` collapses last-wins (e.g. `TRUSTLEVEL`/`trustLevel`) reject as PARSE_ERROR | `fixtures/v1_1-case-variant-member.json` |
| Distinct signer-authority count for trust level 3 and above (§1.3 step 7) | not covered; see conformance.json notCovered |
| k-of-n threshold issuance, such as 2-of-3 (§3.1 step 8): a credential with fewer valid signatures than the threshold rejects | not covered; see conformance.json notCovered |

What this suite does NOT verify:

- Content hash matching the agent binary. The `contentHash` field is in every
  fixture for byte-stability, but no agent binary is shipped; verifiers stop
  at step 5 (signature) without consulting content.
- Transparency log inclusion proofs. The `transparencyLogIndex` is populated
  for byte-stability; the conformance verifiers do not consult a log.
- Build attestation predicate verification. `buildAttestation` is a string
  field in ATX v1.0 (not a structured SLSA v1 predicate inline); verifiers
  do not parse it.
- Behavioral profile validation. The `behavioralProfile` field is carried and
  signed in the v1.1 fixtures, but not validated.

The full requirement-to-fixture mapping is machine-readable in
[`conformance.json`](../conformance.json), regenerated from the fixtures by
[`scripts/conformance_profile.py`](../scripts/conformance_profile.py) and
CI-checked against drift. Each entry's `requirement`, copied from its
fixture, names the step or rule that fixture tests and opens with the
number of the `core.md` section it comes from: `atx-v1/expired` tests
`§1.3 step 2`, the expiry check. The drift check fails when a fixture has
no `requirement`, when its section is not one of the fixture's ATX `spec`
citations, or when two fixtures name the same requirement. A fixture
cites FIPS 204 only when its credential carries an ML-DSA-65 signature.

## Honest scope notes

This is the section that future reviewers, second-implementation authors, and
A2A coordination-map readers should read before forming judgments.

### Canonicalization: v1.0 signs 11 fields; v1.1 signs JCS(TBS)

ATX v1.0 signs a pipe-delimited canonical string, not the JSON body. The
signature covers exactly 11 fields, defined normatively in
[`atx-spec/core.md`](https://github.com/opena2a-standards/atx-spec/blob/e89bed94ca0a7308e2d6915e384be4c89d3a67df/core.md)
§1.3a.1:

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
[`atx-spec/core.md`](https://github.com/opena2a-standards/atx-spec/blob/e89bed94ca0a7308e2d6915e384be4c89d3a67df/core.md)
§1.3a.2. The verifiers dispatch on `atcVersion`; the v1.0 pipe form is frozen and
unchanged. Cross-language byte agreement on `JCS(TBS)` is proven by
[`jcs-vectors/`](../jcs-vectors/) (the Go, Python, and TypeScript canonicalizers
and the v1.1 projection of both reference verifiers, `verifiers/go` and
`verifiers/python`, must agree byte-for-byte). The `fixtures/v1_1-*.json`
fixtures exercise the v1.1 path, including `v1_1-tampered-capabilities.json`,
which is REJECTED precisely because capabilities are now signed.

### Hybrid signing: what this suite requires

The ATX spec has every credential carry an Ed25519 and an ML-DSA-65
signature (core.md §1.1). This suite does not require both: it accepts
single-suite Ed25519 credentials, and 6 of its 8 ACCEPT fixtures
(`baseline-valid.json` among them) carry Ed25519 signatures only. What it
requires is that every declared signature verifies, and that a credential
which declares an ML-DSA-65 entry also carries a verifying Ed25519 entry
(core.md §13, Cryptographic agility).
`baseline-valid-hybrid.json` and `v1_1-baseline-valid-hybrid.json` each
carry an Ed25519 signature and an ML-DSA-65 signature over the same signed
payload. In both, the ML-DSA-65 `value` is the base64 of a raw FIPS 204
ML-DSA-65 signature (3309 bytes decoded); no container or combined-blob
framing is used.

Both reference verifiers verify both declared signature suites per the spec
mandate: the Go verifier ([`verifiers/go`](../verifiers/go)) via
`cloudflare/circl`, and the Python verifier
([`verifiers/python`](../verifiers/python)) via `dilithium-py` (FIPS 204).
Each verifies the ML-DSA-65 signature cryptographically over the same
canonical payload the Ed25519 signature signs. The MUST-REJECT control
`fixtures/v1_1-hybrid-mldsa-tampered.json`, the hybrid baseline with the
Ed25519 entry intact and the ML-DSA-65 value flipped by one bit, pins that
a forged post-quantum signature cannot ride an intact classical one. The
MUST-REJECT control `fixtures/v1_1-hybrid-pq-only.json`, the hybrid
baseline with the Ed25519 entry removed and one ML-DSA-65 signature left
that verifies, pins that a post-quantum signature cannot verify a
credential without its Ed25519 companion.

### Trusted-issuer DID method used by this suite

This suite uses the canonical post-consolidation DID method
`did:opena2a:<type>:<id>` with type prefix `authority` for issuers, matching
the 2026-05-23 unification across AIP-SPEC and ATX-SPEC. The `did:opena2a`
method itself is formally documented at
[`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a)
(Apache-2.0) and is registered in the W3C DID Extensions registry
([`w3c/did-extensions#717`](https://github.com/w3c/did-extensions/pull/717),
merged 2026-07-04).
Because the suite must run without any external trust configuration, the
conformance verifiers take their trusted-issuer set from each fixture's
`verifierState.trustedIssuers`; running the suite requires no issuer
configuration outside the fixture files.

### Trust scoring: 9-factor reference

The `trustScore` field in each fixture (87.5 on the baseline) is an
illustrative value; the 9-factor weights specified in AIP-SPEC §6.1 are
reproduced for reference:

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

No factor inputs in this suite produce the fixture value, and it is stated
on a 0 to 100 scale, while AIP-SPEC §6.1 states the composite score on 0.0
to 1.0. This suite does not verify the trust-score computation itself.
