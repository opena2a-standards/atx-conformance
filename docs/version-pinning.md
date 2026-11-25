# atx-conformance: version pinning

The specification, method and library versions the fixtures and the
reference verifiers are pinned to. What may change between commits of this
repository is in [versioning.md](versioning.md).

## Version pinning

| Component | Version | Source |
|---|---|---|
| ATX schema | v1.0 and v1.1 | [`opena2a-standards/atx-spec/core.md`](https://github.com/opena2a-standards/atx-spec/blob/e89bed94ca0a7308e2d6915e384be4c89d3a67df/core.md) |
| AIP spec | v1.2.0-draft | [`opena2a-standards/agent-identity-protocol/AIP-SPEC.md`](https://github.com/opena2a-standards/agent-identity-protocol/blob/80db7b2304b2f37bddf1c82e788c27e1ab874b3d/AIP-SPEC.md) |
| ATP spec | v1.1.0-draft; `fixtures/expired-beyond-skew.json` cites its §10.2 clock-skew bound | [`opena2a-standards/agent-trust-protocol/ATP-SPEC.md`](https://github.com/opena2a-standards/agent-trust-protocol/blob/e6b4e29f037469133683482bc9ab923f5704aa85/ATP-SPEC.md) |
| `did:opena2a` method | v0.2 (draft), registered in the W3C DID Extensions registry (`w3c/did-extensions#717`, merged 2026-07-04) | [`opena2a-standards/did-method-opena2a/did-method-opena2a.md`](https://github.com/opena2a-standards/did-method-opena2a/blob/c160d50d0f90d809bb60ccfae0b5ca9d7fda2ab2/did-method-opena2a.md) |
| Ed25519 keypair sources | RFC 8032 §7.1 Tests 1, 2, 3, 1024; secondary issuer seed `SHA-256("opena2a-atx-conformance/issuer-secondary/key-1/v1")` (not an RFC vector) | [datatracker.ietf.org/doc/html/rfc8032](https://datatracker.ietf.org/doc/html/rfc8032) |
| ML-DSA-65 | FIPS 204 final | [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final) |
| CIRCL (ML-DSA-65 implementation) | v1.6.2 | [github.com/cloudflare/circl](https://github.com/cloudflare/circl) |
| gowebpki/jcs (Go RFC 8785 canonicalization) | v1.0.1 | [github.com/gowebpki/jcs](https://github.com/gowebpki/jcs) |
| cryptography (Python Ed25519) | >= 42.0.0 | [pyca/cryptography](https://github.com/pyca/cryptography) |
| dilithium-py (Python ML-DSA-65) | >= 1.1.0 | [GiacomoPope/dilithium-py](https://github.com/GiacomoPope/dilithium-py) |
| Conformance fixture format | v1 (this repo) | [`schemas/fixture-v1.schema.json`](../schemas/fixture-v1.schema.json) |

Until this suite re-pins, atx-spec `main` governs where the two differ. The Coverage paragraph of §12 (Conformance) in `main`'s `core.md` names five fixtures that declare `atcVersion` 1.1, carry Ed25519 signatures only and pin ACCEPT: `v1_1-baseline-valid`, `v1_1-declared-purpose-empty-whitespace`, `v1_1-declared-purpose-integer-signed`, `v1_1-declared-purpose-valid` and `v1_1-no-transparency-log-index`. A verifier that follows `main` rejects each of the five as `SIGNATURE_INVALID` under the required-suites rule of §1.3 step 5, since none declares an ML-DSA-65 entry, and §12 excepts them from the pinned-verdict requirement, so that rejection is not a conformance failure. The same rule rejects `v1_1-two-authority-cosignature`, which declares `atcVersion` 1.1, carries Ed25519 signatures only and pins ACCEPT; it was added to this suite after §12 named the five, and §12 does not except it, so a verifier that follows `main` does not produce its pinned verdict and no exception covers that. The rule also rejects the four fixtures that pin `INSUFFICIENT_SIGNER_AUTHORITIES` (`v1_1-cosigner-named-not-signed`, `v1_1-one-authority-threshold-keys`, `v1_1-one-key-under-two-dids` and `v1_1-own-key-labelled-as-cosigner`), each `atcVersion` 1.1 with no ML-DSA-65 entry, as `SIGNATURE_INVALID` at step 5, before step 7 runs: a category other than the one they pin. On a revocation response in the ATP-SPEC v1.0.0-rc1 §8.1 shape, a verifier looks the agent up by `agentDid`, as §1.3 step 6 says, whatever key the suite's fixture lists carry.
