# ATX v1.1 JCS / RFC 8785 byte-agreement vectors

ATX v1.1 signs a canonicalized JSON to-be-signed (TBS) object instead of the
v1.0 11-field pipe string, so `capabilities`, `scanSummary`, `issuerChain`,
`publisher`, and every future field become integrity-protected. The signature is
computed over `JCS(TBS)` where JCS is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
JSON Canonicalization.

The single hard requirement of that design is **cross-language byte agreement**:
the registry issuer (Go), the offline verifier (Go), the conformance verifiers
(Go + Python), and the Secretless broker (TypeScript) must each canonicalize the
same TBS to the same bytes, or a credential signed by one fails to verify under
another. This directory is the gate that proves it.

## What the gate proves

`run-agreement.sh` runs three INDEPENDENT RFC 8785 implementations over every
vector and fails unless all three reproduce the vector's pinned
`expected.canonicalHex` byte-for-byte:

| Leg | Library | Also checks |
|-----|---------|-------------|
| Go | [`github.com/gowebpki/jcs`](https://github.com/gowebpki/jcs) (webpki.org reference port) | re-verifies the pinned Ed25519 + ML-DSA-65 signatures over the recomputed bytes |
| Python | vendored `python/rfc8785.py` (stdlib only) | keeps the Python verifier zero-dependency |
| TS/JS | [`canonicalize`](https://www.npmjs.com/package/canonicalize) (erdtman, RFC 8785 reference impl) | the library the Secretless broker verifier uses |

The libraries are an implementation detail behind the vectors. The vectors are
the guarantee. **The jcs-vectors set may merge only when `run-agreement.sh`
exits 0.**

```bash
./run-agreement.sh
```

Requires Go, Python 3, and Node (the script installs the pinned `canonicalize`
into `ts/node_modules` on first run).

## The TBS construction rule (normative)

The normative definition lives in `atx-spec/core.md` §1.3a. Summary, because the
vectors encode it:

TBS is an **explicit projection** of the credential into a fully-populated
object. Never rely on a language's `omitempty`. Included keys (JCS sorts them; the
authored order in each vector is irrelevant):

```
atcVersion, agentId, agentDid, publisher, publisherDid, version, contentHash,
buildAttestation, capabilities, behavioralProfile, scanSummary, trustScore,
trustLevel, issuedAt, expiresAt, issuerDid, issuerChain
```

Excluded: `id`, `transparencyLogIndex` (dead field), `signatures` (the
envelope), `revoked`/`revokedAt`/`revocationReason` (mutated post-issuance via
CRL/DB), `createdAt`.

`declaredPurpose` (atx-spec §1.5) is the one **presence-based** member: when a
publisher declares a purpose it is included and JCS sorts it (recursively,
including the nested `capabilityJustification` map) into position between
`contentHash` and `expiresAt`; when absent it is omitted entirely, so a
no-purpose TBS is byte-identical to one from before the field existed. Every
vector except `08-declared-purpose` exercises the absent case (no key); the
omission rule itself lives in each verifier's projection, not here.

Determinism rules (the part that bites cross-language):

- **Canonical empties, always present.** Optional strings (`publisherDid`,
  `buildAttestation`) absent -> `""`. `behavioralProfile` absent -> JSON `null`.
  `capabilities` / `issuerChain` absent -> `[]` (never `null`).
- **`scanSummary` is always a full object**, all six fields present and
  zero-valued where unknown (`hma`, `criticalFindings`, `highFindings`,
  `secretless`, `cryptoServe`, `oasbLevel`); never `null`.
- **`trustScore` is string-encoded `%.6f`** in the TBS (e.g. `"87.500000"`),
  even though the wire field stays a JSON number. This removes the
  float -> JCS-number formatting hazard entirely: `trustLevel` (an integer) is
  the only JSON number left in the TBS, and integers serialize identically
  everywhere.
- **`issuerChain` order is root-first** and significant: JCS preserves array
  order, it never sorts arrays.
- The ML-DSA-65 hybrid leg signs the **same** `JCS(TBS)` bytes as Ed25519.

## The vectors

| File | What it pins |
|------|--------------|
| `01-baseline.json` | fully populated TBS, authored with unsorted keys |
| `02-unicode-and-escaping.json` | `"`, `\`, newline, U+0001, CJK, emoji, and a tab inside an array element — RFC 8785 minimal escaping |
| `03-canonical-empties.json` | optional-string `""`, `behavioralProfile` `null`, empty `[]`, zero-valued `scanSummary` |
| `04-key-order-scramble.json` | byte-identical content to baseline, keys scrambled at every level; MUST equal baseline's bytes |
| `05-issuer-chain-order.json` | three-authority root-first chain; array order is significant |
| `06-trustscore-string.json` | `trustScore` as the `%.6f` string `"66.666667"`, never a JSON number |
| `07-nested-and-unicode-arrays.json` | nested `behavioralProfile` + non-zero `scanSummary` + unicode array elements together |
| `08-declared-purpose.json` | present-case `declaredPurpose` (§1.5) authored after `issuerChain` with scrambled own + nested `capabilityJustification` keys and a multi-byte statement; JCS must reposition and recursively sort it |

Each vector file carries the authored `tbs`, plus the pinned
`expected.canonicalString`, `expected.canonicalHex`, `expected.canonicalSha256`,
and known-answer `ed25519` / `mldsa65` signatures. The signing keys are the
suite's existing test vectors: Ed25519 from `vectors/issuer-primary.json`
(RFC 8032 §7.1 Test 1) and ML-DSA-65 from `vectors/mldsa65-seed.json`. Both
signing paths are deterministic, so the signatures are reproducible.

## Regenerating the pinned values

The vectors are produced by one Go tool. Edit a TBS in `pin/main.go`, then:

```bash
go run ./pin            # rewrites vectors/*.json and MANIFEST.sha256
./run-agreement.sh      # must stay green
```

`pin` is the only writer of `vectors/`. The three checkers never derive anything
from `expected.*`; they recompute from `tbs` and compare, so a bad pin cannot
hide behind itself.

## Scope

This directory proves canonicalization byte-agreement and provides signing
known-answer tests. It does not exercise the credential-to-TBS projection (that
lives in each verifier and is tested by the v1.1 conformance fixtures) or the
verification algorithm (the fixtures cover that). It is the foundation the
Phase 1 verifier work is built on.
