# atx-conformance: reproducing the fixtures

How the fixture generator builds and signs every fixture, so a reader can
regenerate them and compare the bytes. The fixture set itself is described in
[fixtures.md](fixtures.md).

## Reproducing the fixtures

The fixtures in this repository are deterministic. To regenerate them from
the keypair vectors in [`vectors/`](../vectors):

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
3. Cross-checks the v1.1 signing form against the byte-agreement gate in
   [`jcs-vectors/`](../jcs-vectors) before it builds any fixture. The v1.1
   baseline credential (`newBaselineV11ATX`) must canonicalize to the
   `expected.canonicalHex` of `jcs-vectors/vectors/01-baseline.json`, and
   the same credential carrying the present-case `declaredPurpose` to the
   one in `jcs-vectors/vectors/08-declared-purpose.json`. Panics on
   divergence, so the v1.1 fixtures cannot drift from the bytes the Go,
   Python and TypeScript legs of that gate agree on.
4. Builds each ATX credential from a shared template (`newBaselineATX` for
   v1.0, `newBaselineV11ATX` for v1.1), then per-fixture mutates exactly
   the fields needed to exercise that fixture's path (revoke, expire, swap
   issuer, tamper signature, change schema version, set `declaredPurpose`,
   add cosigners or ML-DSA-65 sig).
5. Computes the canonical payload in the form the credential's version
   signs:
   - Every fixture not named `v1_1-*.json`, including
     `malformed-schema.json` with `atcVersion` "2.0": the pipe-delimited
     11-field form defined normatively in `atx-spec` `core.md` §1.3a.1
     (`canonicalPayload`), duplicated verbatim in the generator and in each
     reference verifier.
   - Every `v1_1-*.json` fixture: `JCS(TBS)` per `core.md` §1.3a.2
     (`canonicalPayloadV11`). The generator projects the credential into
     the v1.1 to-be-signed object, which adds `publisher`, `publisherDid`,
     `capabilities`, `behavioralProfile`, `scanSummary`, `issuerChain` and,
     when present, `declaredPurpose` to the signed fields, and canonicalizes
     it per RFC 8785 with `github.com/gowebpki/jcs`.
6. Ed25519-signs and ML-DSA-65-signs that payload, as each fixture carries
   those signatures (`hybrid-pq-only.json` and `v1_1-hybrid-pq-only.json`
   carry the ML-DSA-65 signature alone). A fixture that tests tampering
   changes the field or signature it tampers with after this step, so its
   signature covers the original bytes.
7. Marshals each fixture to byte-stable JSON (`encoding/json` with 2-space
   indent, fields in struct-declaration order).
8. Writes the fixture file. Recomputes its SHA-256. Updates
   `MANIFEST.sha256` in path-sorted order.

Re-running the generator MUST produce byte-identical fixtures. If the bytes
change, either (a) the generator changed, (b) the canonicalization shifted,
or (c) the CIRCL ML-DSA-65 implementation changed. Any of those is a
breaking change for downstream verifiers.
