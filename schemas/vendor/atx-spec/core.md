# ATX core architecture

**Certificate authority infrastructure for AI agents**

**Document version:** 1.1.0-final (July 2026; first published as "Version 1.0", May 2026)
**Credential format status:** ATX 1.1 is the current, normative wire format (§1.3a.2) and is what production issuance emits; ATX 1.0 is frozen legacy (§1.3a.1), accepted per the transition rule in §1.3a.5.
**Protocol status:** the ATP wire protocol (§2) is normatively specified in [ATP-SPEC v1.0.0-rc1](https://github.com/opena2a-standards/agent-trust-protocol); this document defines the architecture it implements. Identity (AIP) and authorization (AAP) layers beneath this document carry their own, earlier maturity levels — a claim in this document never upgrades theirs.

Defines the Agent Trust eXtension credential format, the Agent Trust Protocol that issues and verifies it, and the architectural commitments that make the system survive at planetary scale.

This document replaces the prior ATC architecture v2.0 (March 2026). The credential is now ATX. The protocol around it is ATP. Everything else continues forward.

## Conventions and terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

Normative requirements in this document are concentrated in §1 (credential format, canonical signing forms, verification algorithm) and §12–§14 (conformance, security, registries). Sections 0 and 2–11 are architectural: they explain the system the requirements produce and constrain implementations only where they use BCP 14 key words.

---

## 0. The reframe

Every prior trust architecture for AI agents made the same mistake. It treated a central database as the trust authority. Consumers query the database, the database returns a verdict, the database is on the critical path of every interaction.

That is a database pretending to be infrastructure. It does not scale. It puts a single party in the hot path of every agent call. It creates a single point of failure that no enterprise will accept. And it cannot become a standard because no organization will make a competitor's database the gatekeeper for their own agents.

The correct model already exists. It has operated at planetary scale for thirty years. It is called public key infrastructure.

When the internet needed certificate infrastructure, nobody built a database that every HTTPS connection queried. They built a credential system. Certificate authorities issue signed credentials. The credential travels with the entity. Any verifier checks it locally in milliseconds. CA infrastructure handles revocation and audit in the background. No CA is in the hot path for any connection.

ATX is the same model for AI agents. The Agent Trust Protocol (ATP) is how nodes communicate. The Agent Trust eXtension (ATX) is the signed credential every agent carries. The protocol is the standard. The credential is the artifact. Everything in this document follows from that distinction.

| Dimension | Database model | ATX model |
|---|---|---|
| Verification | Network query per interaction | Local check, zero network calls |
| Scalability | O(n) on query volume | O(1) on verifier path |
| Single point of failure | Registry down breaks trust | Registry down does not break verification |
| Adoption barrier | Every verifier integrates Registry API | Verify locally with any Ed25519 library |
| Posture toward Google | Compete or be ignored | Federate and cosign |
| Regulatory posture | SaaS product that regulators evaluate | Infrastructure that regulators can mandate |

---

## 1. The Agent Trust eXtension (ATX)

The ATX is the foundational artifact of the entire architecture. It is a signed, self contained credential analogous to a TLS certificate. Every AI agent carries one. Every counterparty verifies it locally before honoring a request.

The ATX travels with the agent. When agent A calls agent B, A presents its ATX in the request. B verifies it locally. No network call. No Registry lookup. No latency. This is the property that makes the architecture scale to a billion agents.

### 1.1 ATX schema

```json
{
  "id":               "b3d0a7e2-4f6c-4b9e-9a2d-8c1e5f7a9b3c",
  "atcVersion":       "1.1",
  "agentId":          "aim_7f3a9c2e",
  "agentDid":         "did:opena2a:agent:acme-corp/billing-agent",
  "publisher":        "acme-corp",
  "publisherDid":     "did:opena2a:publisher:acme-corp",
  "version":          "2.1.4",
  "contentHash":      "3f8a1c5d9e2b7f4a6c0d8e1b5a9f3c7e2d6b0a4f8c1e5d9b3a7f0c4e8d2b6a1f",
  "buildAttestation": "https://slsa.dev/provenance/v1#acme-corp/billing-agent",
  "transparencyLogIndex": 1847293,
  "capabilities":     ["db:read", "api:call"],
  "declaredPurpose": {
    "vocabVersion": "1",
    "statement":    "Processes customer billing inquiries and issues refunds up to a supervisor-set limit.",
    "category":     "financial-operations",
    "taskScopes":   ["billing:inquiry", "billing:refund"],
    "capabilityJustification": {
      "db:read":  ["billing:inquiry"],
      "api:call": ["billing:refund"]
    },
    "autonomy":     "supervised",
    "dataScopes":   ["customer.billing", "customer.contact"],
    "egressScopes": ["api.stripe.com", "hooks.internal.acme.com"]
  },
  "behavioralProfile": {
    "checksum":       "sha256:1c5d9e2b7f4a6c0d",
    "generatedAt":    "2026-05-19T00:00:00Z",
    "observationDays": 14
  },
  "scanSummary": {
    "hma":              "passed",
    "criticalFindings": 0,
    "highFindings":     0,
    "secretless":       "clean",
    "cryptoServe":      "no-weak-crypto",
    "oasbLevel":        "L2"
  },
  "trustScore":   87.5,
  "trustLevel":   3,
  "issuedAt":     "2026-05-19T00:00:00Z",
  "expiresAt":    "2026-05-26T00:00:00Z",
  "issuerDid":    "did:opena2a:authority:opena2a.org",
  "issuerChain": [
    "did:opena2a:authority:opena2a.org"
  ],
  "signatures": [
    { "keyId": "did:opena2a:authority:opena2a.org#key-v3", "algorithm": "Ed25519",   "value": "sfxSAtxm3TwrzodrXyjph5dEBGePWAot8lz96WdlCrCDYGlHvuAYhgWF/GCzwsFDxjWXUFYTUX0DN+0ofCvRAw==" },
    { "keyId": "did:opena2a:authority:opena2a.org#pqc-v1", "algorithm": "ML-DSA-65", "value": "m5oAcs2LqmMNQmvUeQdCzXh0nBhTsFhkNCJmQeXwqUvVbTgKdRz3l" }
  ],
  "revoked":   false,
  "createdAt": "2026-05-19T00:00:00Z"
}
```

The illustration is wire-shape-accurate but its hash, signature and log-index values are placeholders — it does not verify. The machine-readable definition of this shape is [`schemas/atx-credential-v1.1.schema.json`](./schemas/atx-credential-v1.1.schema.json); the atx-conformance fixtures are the byte ground truth.

Every field is mandatory unless explicitly marked optional in the ATP spec or in this document. `transparencyLogIndex` is optional: it is the index the issuer's transparency log assigned to this credential's issuance entry (§6), set after signing and outside both signing forms (§1.3a.1, §1.3a.2). An issuer MUST NOT emit it with any value other than the one the log assigned to this credential's entry, and an issuer that recorded no inclusion omits it. Verifiers MUST NOT treat its value as evidence of log inclusion; inclusion is established only by the log's own proofs (§6), for which a present index is the lookup key (ATP verification step 6). The signature block carries at minimum one Ed25519 signature and one ML-DSA-65 signature. Quantum resistance is not deferred. It ships on day one.

The version field is named `atcVersion` on the wire (earlier revisions of this document illustrated it under the alias `atxVersion`). Its value selects the canonical form the signatures cover: see §1.3a. `"1.0"` is the legacy eleven-field form; `"1.1"` signs the JCS (RFC 8785) canonicalization of a projected to-be-signed object, which brings `capabilities`, `scanSummary`, `issuerChain`, and `publisher` under the signature. `trustScore` rides the wire as a 0-100 JSON number; the v1.1 to-be-signed projection string-encodes it (§1.3a.2 rule 3). The issuance envelope fields `id`, `revoked`, and `createdAt` (plus `revokedAt`/`revocationReason` once revoked) accompany every issued credential and are excluded from the signed bytes (§1.3a.2).

`declaredPurpose` is an **optional** ATX 1.1 field (additive in 1.1; a 1.0 verifier ignores it). It is the publisher's signed, structured declaration of what the agent is *for* — an identity and attestation property, never an authorization input. Its semantics, sub-fields, and vocabulary are defined in §1.5; its treatment under the signature is defined in §1.3a.2.

### 1.2 ATX lifecycle

| Stage | Trigger | What happens |
|---|---|---|
| Issuance | Build plugin runs on CI merge | Issuing node mints ATX bound to this content hash and build attestation. Threshold signed. Logged to transparency log. |
| Delivery | Build completes | ATX written to build artifact. Embedded in agent container or package. No separate retrieval at runtime. |
| Presentation | Agent makes any request | ATX presented in Agent-Trust-Credential HTTP header. Inline in A2A agent card. Part of MCP server manifest. |
| Verification | Counterparty receives request | Local verification only. Signature check. Expiry check. Revocation cache check. Content hash check if deep verification. |
| Renewal | 7 days or new build | Build plugin runs again. Fresh ATX issued. Old ATX expires. Short lifetime forces rescan as a hygiene primitive. |
| Revocation | Compromise detected | Issuing node publishes to CRL. Federated push to all nodes within 60 seconds. Local verifiers refresh within 5 minutes. |

### 1.3 Local verification algorithm
<!-- opena2a-definition: atx-verification-steps -->

Any party verifying an ATX runs this sequence locally. Steps 1 through 5 require zero network calls. Step 6 uses a locally cached revocation list refreshed every 5 minutes.

1. Parse ATX. Validate schema version is supported.
2. Check `expiresAt` is in the future, evaluated within the family clock-skew bound of ATP §10.2, which never extends the credential TTL of §1.2 or the revocation cache window of §3.3. Expired ATX rejects immediately.
3. Resolve issuerDid to public key using locally cached DID document. TTL is one hour. Cache miss triggers a single fetch.
4. Verify the Ed25519 signature against the cached public key. Sub millisecond on any modern CPU.
   - Key eligibility. The key a signature is verified against MUST have been resolved, as in step 3, for an authority the verifier trusts for this credential: the authority named by `issuerDid`, or, under `atcVersion` 1.1 only, an authority that the signed `issuerChain` names and that is a trusted issuer under the verifier's federation trust list (§7). A chain DID that is not a trusted issuer contributes no eligible key: the chain is signed by the very key whose eligibility is in question, so it cannot vouch for that key (§13, Delegation and chain abuse). Under `atcVersion` 1.0 `issuerChain` is unsigned (§1.3a.1) and contributes no eligible key. A signature that verifies only against some other key the verifier holds is a signature failure (`SIGNATURE_INVALID`), not an issuer failure.
5. Verify every remaining declared signature, the ML-DSA-65 signature included, under the family signature gate (§13, Cryptographic agility; AAP §9.4): a declared signature that does not verify, or whose suite this verifier does not implement, is a signature failure. ML-DSA-65 adds three to five milliseconds.
6. Check agentId against locally cached CRL. If listed, reject. If cache is stale beyond 5 minutes, refresh asynchronously but allow this request using the cached version.
7. Count distinct signer authorities. If trust level 3 or higher is required, the verifier MUST reject the credential unless at least two distinct authorities have each produced a signature that this verifier has itself verified over the credential's canonical signed bytes (the form selected in step 1).
   - The authority behind a signature is the DID its `keyId` names: the `keyId` up to the first `#`, or the whole value if it contains none. A signature counts only after the verifier has resolved that DID as in step 3, confirmed the verifying key is published in the resulting DID document, and confirmed the authority is one it accepts under its federation trust list (§7).
   - Distinctness is over keys as well as names. Each authority counts once however many of its keys signed, so an Ed25519 and an ML-DSA-65 signature from one authority are one authority, and a threshold key set held by one authority is one authority. Two signatures that verify under the same public key count once, whatever `keyId` values they carry.
   - Only verified signatures count. The length of `issuerChain` MUST NOT be counted, and presence in `issuerChain` MUST NOT substitute for a verified signature. The chain is a signed declaration of intended delegation order (§1.3a.2 rule 4), not evidence that the authorities it names signed anything.
8. Accept. Attach the ATX to the request context for downstream use, together with the number of distinct signer authorities this verifier itself verified in step 7 and whether it performed that count at all.

A verifier that did not perform the step 7 count MUST NOT present `trustLevel` to downstream consumers as a value it has verified: it has verified the signature over the level, not the multi-authority property the level asserts at 3 and above. Before presenting a `trustLevel` of 3 or higher it MUST either perform the count of step 7, or present the level together with an explicit marker that the multi-authority property was not checked. It MUST NOT lower the level and MUST NOT omit the field: lowering asserts a level no issuer signed, and omitting removes a signed field the consumer may need. A verifier that did not perform the count reports it as not performed and MUST NOT report a count of zero or one in its place; an absent measurement is not a measured result. A consumer that receives a `trustLevel` of 3 or higher with no such marker MAY assume the verifier performed the count.

Total verification time on warm cache is under 2 milliseconds. Cold cache is under 10 milliseconds. The Registry is never on this path.

In step 1 the verifier dispatches on the credential's version field (`atcVersion`
on the wire): `"1.0"` selects the legacy canonical form of §1.3a.1; `"1.1"`
selects the JCS canonical form of §1.3a.2. Steps 4 and 5 verify the signature
over the bytes that form produces.

### 1.3a Canonical signing form

The signature in `signatures[]` does not cover the raw JSON body. It covers a
deterministic byte string derived from the credential. Two forms exist. A
verifier selects the form by the credential's version field; the two are never
mixed.

#### 1.3a.1 Legacy form (`atcVersion` = "1.0")

ATX v1.0 signs a pipe-delimited string of exactly eleven fields, in this order:

```
agentId | agentDid | version | contentHash | buildAttestation | issuerDid |
trustLevel | trustScore (formatted %.6f) | issuedAt (RFC 3339, UTC) |
expiresAt (RFC 3339, UTC) | "1.0"
```

The eleventh field is the literal string `1.0`, independent of any other field.
This form is **frozen**: existing v1.0 signatures depend on its exact bytes, so
it MUST NOT change. It signs neither `capabilities`, nor `scanSummary`, nor
`behavioralProfile`, nor `publisher`, nor `publisherDid`, nor `issuerChain`, nor
`transparencyLogIndex`. A holder of a valid v1.0 credential can therefore alter
any of those fields and the signature still verifies. Consumers MUST treat those
fields as unauthenticated when `atcVersion` is `1.0` (see §1.3a.4).

#### 1.3a.2 JCS form (`atcVersion` = "1.1")
<!-- opena2a-definition: atx-tbs-exclusions -->

ATX v1.1 signs `JCS(TBS)`: the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
JSON Canonicalization of a to-be-signed (TBS) object projected from the
credential. This brings `capabilities`, `scanSummary`, `issuerChain`,
`publisher`, and every field added in future versions under the signature
automatically.

The TBS is an **explicit projection**. An implementation MUST construct it by
setting every key below to a fully determined value; it MUST NOT rely on a
serializer's omit-empty behavior, because an omitted key and a present empty key
canonicalize to different bytes. The included keys are exactly:

```
atcVersion, agentId, agentDid, publisher, publisherDid, version, contentHash,
buildAttestation, capabilities, declaredPurpose (optional, see rule 5),
behavioralProfile, scanSummary, trustScore, trustLevel, issuedAt, expiresAt,
issuerDid, issuerChain
```

Excluded, and MUST NOT appear in the TBS: `id`; `transparencyLogIndex` (unsigned inclusion metadata, assigned by the log and set after signing; §1.1); `signatures` (the envelope being produced); `revoked`,
`revokedAt`, `revocationReason` (mutated after issuance via the CRL and the
database, so they cannot be signed at issuance); and `createdAt`.

Determinism rules. These are normative; they are the difference between a
credential that verifies across implementations and one that does not:

1. **Canonical empties are always present.** An absent optional string
   (`publisherDid`, `buildAttestation`) MUST be the empty string `""`. An absent
   `behavioralProfile` MUST be JSON `null`. An absent `capabilities` or
   `issuerChain` MUST be the empty array `[]`, never `null`.
2. **`scanSummary` is always a full object.** All six members
   (`hma`, `criticalFindings`, `highFindings`, `secretless`, `cryptoServe`,
   `oasbLevel`) MUST be present, zero-valued where unknown (`""` for the string
   members, `0` for the integer members). `scanSummary` MUST NOT be `null`.
3. **`trustScore` is string-encoded.** In the TBS, `trustScore` MUST be the
   string produced by formatting the numeric score with six fractional digits
   (printf `%.6f`), e.g. `"87.500000"`. The wire credential keeps `trustScore`
   as a JSON number; the projection performs the conversion. This makes
   `trustLevel` (an integer) the only JSON number in the TBS, which removes the
   RFC 8785 ECMAScript number-formatting path from cross-language scope entirely.
4. **`issuerChain` is root-first and order-significant.** Element 0 is the root
   authority. JCS preserves array order and never sorts arrays, so reordering the
   chain changes the signed bytes.
5. **`declaredPurpose` is presence-based (the one optional member).** Unlike every
   other member, an absent `declaredPurpose` is **omitted from the TBS entirely**,
   not emitted as a canonical empty. A credential MUST emit the key only when the
   publisher declared a purpose, and then as a fully-populated object (§1.5); a
   credential with no declared purpose produces the exact bytes it would have
   produced before this field existed, so every previously pinned v1.1 vector and
   signature stays valid. The JSON literal `null` and an empty object `{}` are
   both treated as "absent" and MUST also be omitted, so there is no
   present-but-empty form to disagree on. Emptiness is decided at the JSON
   parse level: any serialization that parses to the empty object (including
   whitespace variants such as `{ }`) is the empty object. A present value
   that is **anything else — including a non-object value (array, string,
   number, boolean) — MUST be included in the TBS verbatim**; a verifier MUST
   NOT normalize an unexpected value away, because silently omitting it would
   let unsigned purpose content ride a valid signature (the injection the
   conformance suite pins with its `v1_1-declared-purpose-*-injected`
   fixtures). This is a deliberate, documented
   exception to the "canonical empties are always present" rule above; it is the
   pattern every future *optional* additive field follows. When the key is
   present, JCS sorts its member names like any other nested object and it sits
   between `contentHash` and `expiresAt` in the canonical output.

The Ed25519 threshold signatures and the ML-DSA-65 hybrid signature are all
computed over the **same** `JCS(TBS)` bytes. JCS itself sorts object member names
by UTF-16 code unit, preserves array order, applies minimal JSON string escaping
(only `"`, `\`, and the control range below U+0020 are escaped; every other code
point, including all non-ASCII, is emitted as raw UTF-8), and emits no
insignificant whitespace.

#### 1.3a.3 Cross-implementation byte agreement is mandatory

Because issuance (Go), the offline verifier (Go), the conformance verifiers
(Go and Python), and the Secretless broker (TypeScript) each canonicalize
independently, a v1.1 credential is only interoperable if all of them produce
identical `JCS(TBS)` bytes. The normative byte vectors and the cross-language
agreement gate live in
[`atx-conformance/jcs-vectors`](https://github.com/opena2a-org/atx-conformance/tree/main/jcs-vectors).
A conformant implementation MUST reproduce, byte-for-byte, the
`expected.canonicalHex` of every vector there.

#### 1.3a.4 Authorization on signed fields requires v1.1

A consumer that makes an authorization or trust decision on `capabilities`,
`scanSummary`, `issuerChain`, or `publisher` MUST require `atcVersion` to be
`1.1` or later. Under `1.0` those fields are not covered by the signature
(§1.3a.1) and a credential holder can forge them. This binds the Secretless AAP
grant path, which gates on the verified `capabilities`: once issuance is v1.1, a
forged `capabilities` value changes `JCS(TBS)` and fails signature verification,
so the grant policy never sees it.

#### 1.3a.5 Version transition

When issuance moves from `1.0` to `1.1`, verifiers MUST accept both forms for one
credential TTL (seven days), after which all live credentials are v1.1 and
verifiers MAY reject `1.0` for capability-gated decisions per §1.3a.4. The
`atcVersion` value is itself inside the v1.1 TBS, so an attacker cannot strip a
`1.1` credential down to the `1.0` form: the legacy verifier would recompute a
pipe string the v1.1 signature never covered, and verification fails closed.

### 1.4 ATX versus TLS certificate

| Property | TLS certificate | ATX |
|---|---|---|
| What it identifies | A domain or server | An AI agent, its build, its behavior |
| Who issues | Certificate authority (DigiCert, Let's Encrypt) | ATP authority (OpenA2A root, enterprise nodes, sovereign nodes) |
| How it verifies | Local chain validation, OCSP | Local signature check, cached CRL |
| Revocation | CRL or OCSP stapling | Federated CRL with push propagation under 60 seconds |
| Transparency | Certificate Transparency log | ATP transparency log (RFC 6962 compatible) |
| Expiry | 90 days to 1 year | 7 days (forces rescan as hygiene) |
| Contains behavior | No, identity only | Yes. Scan results, capabilities, behavioral profile |

### 1.5 Declared purpose (optional)

`declaredPurpose` is the publisher's structured, signed declaration of what an
agent is *for*. `capabilities` bounds an agent's *reach* — which operations it may
touch. `declaredPurpose` declares its *objective* — what those operations are
meant to accomplish. The two are independent axes: capability scope answers "is
this action permitted?"; declared purpose lets an offline observer ask the
separate question "does this permitted action serve the declared objective?".

The field is **optional and additive** in ATX 1.1. It is signed as part of the
v1.1 TBS when present (§1.3a.2, rule 5), which makes a declaration **binding,
attributable, and non-repudiable**: a publisher cannot later deny what its agent
claimed to be for. The issuing authority attests *that this is what was declared*,
not that it is true — the same trust split as a TLS certificate's Subject fields.

#### 1.5.1 What it is not

- **Never an authorization input.** The local verification algorithm (§1.3)
  gains no purpose gate. Acceptance stays signature + expiry + revocation + chain.
  A verifier MAY attach `declaredPurpose` to the request context (step 8) for its
  own out-of-band policy, but OpenA2A's accept/reject path is purpose-blind.
- **Never inferred.** `declaredPurpose` is publisher-declared and stable. It is
  not a model's judgment of what an agent is doing; that is detection output and
  lives in a separate plane (§3, Intelligence). Declared purpose is identity;
  inferred intent is detection. The two are never conflated, and inferred intent
  is never written into a credential or a DID document.

#### 1.5.2 Sub-fields

| Sub-field | Req? | Type / rule |
|---|---|---|
| `vocabVersion` | core | the purpose-vocabulary version this declaration was issued against (currently `"1"`), so a later vocabulary revision never silently re-interprets an old credential. |
| `statement` | core | string, ≤ 280 chars. Human- and audit-readable intent. Secondary: it is attacker-controllable content, so it is judged only by a non-generative classifier and is never the sole basis for a machine judgment. |
| `category` | core | one value from the closed core vocabulary (§1.5.3) or an org-namespaced custom value (`<org>.<name>`). |
| `taskScopes` | core | array of `namespace:objective` tokens, grammar `^[a-z][a-z0-9]*:[a-z][a-z0-9_]*$`, at the *objective* level. The primary machine-comparable anchor. |
| `capabilityJustification` | core | map of each granted `capability` → the `taskScope(s)` it serves. Keys MUST be a subset of `capabilities`. Ties reach to objective and drives the breadth measure (§1.5.4). |
| `autonomy` | optional | enum `supervised` \| `human_in_loop` \| `autonomous`. |
| `dataScopes` | optional | array of declared data domains the agent operates over. An in-scope action touching an undeclared data domain is a detectable tell. |
| `egressScopes` | optional | array of declared external destinations (hostnames/domains; no paths, no secrets). An in-scope action egressing to an undeclared destination is the covert-exfiltration tell — the degree of freedom a faithfully-declared action type can still be abused in. |

No sub-field carries PII or secrets: the object is signed, travels with every
request, and may be written to the transparency log.

#### 1.5.3 Vocabulary

`category` and the `taskScope` namespaces are **governed, versioned vocabularies**
— closed core plus org-namespaced custom — managed like the capability registry.
The core `category` values (vocab v1), each with a breadth class and a
sensitivity class, are: `customer-support`, `financial-operations`,
`data-analysis`, `data-engineering`, `software-development`, `devops-automation`,
`security-operations`, `content-generation`, `research-assistant`,
`sales-marketing`, `hr-people-ops`, `legal-compliance`, `healthcare-clinical`,
`device-control`, `agent-orchestration`. There is deliberately no catch-all
category. Custom categories (`<org>.<name>`) default to the broadest, most
sensitive class until reviewed, so custom is never a cheap way to claim a narrow
profile. The reserved core `taskScope` namespaces (vocab v1) are: `support`,
`billing`, `accounting`, `analytics`, `dataops`, `dev`, `ci`, `infra`, `secops`,
`content`, `research`, `crm`, `people`, `legal`, `clinical`, `device`,
`orchestrate`. A non-reserved namespace is a custom org taskScope.

`security-operations` and `device-control` are legitimately dual-use (a security
agent's behavior resembles an attacker's; device control has physical-world
impact). They may not be declared with a narrow breadth, and their
`capabilityJustification` must enumerate each sensitive capability explicitly —
no wildcard.

#### 1.5.4 Breadth is measured, not claimed

Purpose breadth is computed from `capabilityJustification`, not from how
taskScope tokens are named (which an adversary could craft to sound narrow). The
measure is the count of distinct capability *namespaces* across all
justification entries; a "narrow" declaration that justifies `secrets:read`,
`network:connect`, and `system:exec` scores broad regardless of its token names.
A computed breadth above the category's class raises the floor; it never lowers
it. An over-broad declaration is therefore a visible, scoreable downgrade rather
than a free pass — the property that makes a vague "cover everything" purpose
useless as cover.

#### 1.5.5 Verifier and trust guidance

- **Absence MUST NOT cause rejection.** During the optional phase a verifier that
  refuses credentials lacking `declaredPurpose` fragments the network. Absence is
  at most a weak telemetry signal ("an agent executing a sensitive sequence
  without a declared purpose"), never a hard gate.
- **A declared purpose does not buy trust.** Purpose specificity sets *detection
  sensitivity* — a narrow declaration is held to a tighter consistency test — but
  it MUST NOT raise an agent's trust prior. Otherwise a signed, coherent-looking
  purpose becomes an alibi that suppresses scrutiny while the agent covertly does
  something else. The declaration tightens the test; it does not vouch for intent.

---

## 2. The Agent Trust Protocol (ATP)

ATX is the artifact. ATP is the protocol that issues, verifies, revokes, and federates ATX credentials.

ATP defines five things:

1. **The ATX format itself.** Schema, signature suite, encoding rules. Published as an open standard.
2. **The DID method `did:opena2a`.** How publishers, agents, and authorities are named. How keys are bound to identities. How key rotation works without breaking existing credentials. Type prefixes registered: `registry`, `authority`, `publisher`, `agent`, `mcp_server`, `ai_tool`, `llm`, `skill` (`a2a_agent` is a deprecated legacy alias of `agent`, not a registered type). Shared with AIP (Agent Identity Protocol) and ATP-SPEC v1.0.0-rc1.
3. **The transparency log format.** RFC 6962 binary Merkle tree. Signed Tree Head schema. Inclusion and consistency proof formats.
4. **The federation protocol.** How nodes register with each other, exchange public keys, cosign credentials, propagate revocations, and maintain trust lists.
5. **The revocation list format.** Delta CRLs, signed CRL endpoints, push notification format, cache semantics.

ATP is the standards play. ATX is the wedge. We push ATP into A2A spec as the trust binding A2A is missing today (PR 1496 already in flight). We push ATP into IETF as a Working Group draft. We push the transparency log conformance criteria into the same model the WebPKI uses for CA acceptance.

The credential is the wedge because every agent carries one. The protocol is the moat because once it is in the spec, every implementer is using ours.

---

## 3. The five planes

The architecture operates across five planes. Each has a clear owner. Each can be understood independently.

| Plane | Owner | What it does |
|---|---|---|
| Issuance | Issuing node CA service | Receives build attestations from CI. Mints ATX. Threshold signs. Logs to transparency log. This is the only plane where a node sits in the request path. |
| Verification | Any verifier, locally | Signature check, expiry check, CRL check. All local. Issuing node never queried during verification. Sub 5ms. |
| Revocation | Issuing node plus federation | Federated CRL published and pushed to all nodes within 60 seconds. Verifiers cache locally, refresh every 5 minutes. |
| Transparency | Issuing node plus monitors | Append only RFC 6962 Merkle tree. STH published every 5 minutes. Independent monitors verify consistency. Anyone can run a monitor. |
| Intelligence | ARIA plus NanoMind | Semantic anomaly detection, behavioral twin aggregation, NanoMind routing for natural language queries, UNAUTHORIZED_CHANGE detection. Async. Never on any critical path. |

### 3.1 Issuance flow

This is the only flow where the issuing node is synchronously required. It happens once per build, not per agent interaction.

1. Developer merges PR. CI triggers build.
2. Build plugin exchanges GitHub OIDC token for short lived ATP build token. 15 minute TTL, scoped to this repo and run ID, replay protected via jti table.
3. Build plugin verifies HMA and Secretless tool binaries against their own ATX credentials. If either fails, the build aborts. Compromised security tools never execute.
4. Build plugin runs HMA, Secretless, CryptoServe scans. Collects JSON results.
5. Build plugin computes content hash of the build artifact.
6. Build plugin constructs build attestation JSON. Signs with ephemeral OIDC derived key. Posts to issuing node.
7. Issuing node verifies attestation signature. Writes attestation to transparency log. Receives log index.
8. Issuing node constructs ATX. Requests threshold cosignatures from 2 of 3 key holders. Adds transparency log index.
9. If an enterprise or sovereign node is in the issuerChain, the issuing node requests cosignature from that node's API.
10. Issuing node returns signed ATX to build plugin.
11. Build plugin embeds ATX in the deployment artifact. Writes to build outputs.

Total time under 90 seconds. The developer merges a PR and the agent has a fresh, signed, transparency log backed credential before the deployment pipeline finishes.

### 3.2 Verification flow

This flow has zero issuing node involvement. It runs thousands of times per second across the ecosystem.

1. Verifier receives request. Extracts Agent-Trust-Credential header or the atx field from an A2A agent card or MCP manifest.
2. Parse ATX. Check atxVersion is supported. Check expiresAt is in the future. Under 0.1ms.
3. Look up issuerDid in local DID document cache. TTL one hour. Cache hit proceeds. Cache miss does a single fetch and caches the result. Under 1ms on hit.
4. Verify Ed25519 signature against cached issuer public key. Under 1ms.
5. If ML-DSA-65 signature is present, verify it too. Under 5ms.
6. Check agentId against locally cached CRL. TTL 5 minutes. If listed, reject. If cache miss, queue async refresh and allow this request on the cached version. Under 0.1ms.
7. Optionally verify contentHash against the known artifact for deep verification.
8. Accept. Warm cache total: under 2ms. Cold cache total: under 10ms with one network fetch for the DID document.

### 3.3 Revocation flow

Revocation speed is the measure of how quickly a compromised agent stops being trusted. Target: under 60 seconds from revocation event to rejection at all subscribed verifiers. Hard upper bound: 5 minutes for any verifier still on its cached CRL.

1. Revocation trigger fires. Examples: CONTENT_HASH_VIOLATION, manual revocation, security incident, ATX expiry with failed reissuance.
2. Issuing node marks ATX as revoked. Adds REVOCATION entry to transparency log. Increments CRL version.
3. Issuing node pushes updated CRL delta to all active federation nodes via HTTP POST with HMAC signature. Under 5 seconds.
4. Federation nodes receive delta, update local CRL, acknowledge. Nodes failing to acknowledge within 30 seconds are flagged offline.
5. CDN cached CRL endpoint invalidated. Fresh CRL available immediately.
6. SSE event published to all subscribers as a trust_changed event for this agentId.
7. Verifiers detect the revocation on next request from this agent. Reject.

---

## 4. Developer reported trust

The old architecture had OpenA2A monitoring packages for changes. Wrong frame. It made OpenA2A reactive, polling the ecosystem to discover changes the developer already caused.

The right model: developers report changes through the build plugin. The system monitors for changes that bypassed developer reporting. Those bypasses are the attacks.

| Scenario | Architecture response |
|---|---|
| Developer pushes code and builds | Build plugin reports the change. ATX issued immediately. Registry updated. No polling. Developer is the reporter. |
| Attacker force pushes a tag, no build | New content hash exists in npm or GitHub with no corresponding ATX. Global webhook feed catches the version event. Issuing node asks: does a valid ATX exist for this content hash? No equals UNAUTHORIZED_CHANGE. Trust drops immediately. |
| Incomplete credential rotation | AIM revocation is cryptographic. All federation nodes notified via push within 60 seconds. No manual rotation process to miss vectors. |
| Legitimate version with no build plugin yet | Treated as trust level 2 (Listed). No ATX, no higher trust. Developer is incentivized to adopt the build plugin to lift their agents to level 3 or higher. |

### 4.1 Why this scales O(1) not O(n)

The old webhook model required one subscription per package. 1.1 million packages equals 1.1 million subscriptions to manage. That does not scale and it is operationally fragile.

The new model uses exactly two global subscriptions regardless of package count:

* One npm registry level webhook feed. Receives all npm publish and unpublish events globally.
* One GitHub org level webhook. Receives all push and tag events for linked repositories.

For each event received, the issuing node asks one question. Does a valid ATX exist for this content hash? Single indexed lookup. Under 1 millisecond regardless of whether the system contains 1 million or 1 billion packages.

### 4.2 The build plugin as trust anchor

The build plugin is not a convenience feature. It is the cryptographic anchor that makes the entire trust model work. Without it, the issuing node is guessing about package integrity from the outside. With it, the developer is making a verifiable attestation from the inside.

The build plugin produces four things in sequence:

1. **Tool integrity verification.** Before running HMA or Secretless, verify their content hashes against their own ATX credentials. The security tools verify themselves before they run. This is the exact defense against the Trivy attack. If HMA were compromised and its binary changed, its ATX would not verify and the build would fail before the compromised tool ran.
2. **Security scans.** HMA, Secretless, CryptoServe. Results embedded in the ATX.
3. **Build attestation.** Signed record of this build. Commit hash, content hash, tool versions, scan results, builder identity, OIDC derived ephemeral key. Written to transparency log before the ATX is issued.
4. **ATX issuance request.** Issuing node receives the build attestation, issues the ATX, signs with threshold keys, logs issuance, returns ATX to the build environment.

---

## 5. Runtime self attestation

This closes the gap prior architectures missed entirely. Build time attestation proves what was built. Runtime self attestation proves what is actually running.

When an agent process starts, ARP executes the following before the agent handles any request:

1. Compute SHA-256 of the running binary.
2. Extract embedded ATX from the binary, written there by the build plugin.
3. Verify ATX signature. Verify not expired. Verify not revoked via CRL check.
4. Verify that the running binary's content hash matches the ATX contentHash field. If mismatch, the binary has been modified after attestation. ARP kills the process and logs a RUNTIME_INTEGRITY_VIOLATION event.
5. Begin behavioral twin observation. L0 rules active immediately. L1 model loads from fleet baseline.

This prevents the Trivy scenario at the runtime level. Even if an attacker substitutes a modified binary, the content hash mismatch is caught at process start before the agent handles a single request.

Runtime self attestation also enables the agent to prove what it is. When a counterparty asks for proof, the agent presents its ATX. The ATX binds the running binary to the build attestation to the transparency log. The chain is complete.

---

## 6. Transparency log

The transparency log is the mechanism that makes the trust infrastructure itself uncompromisable. Any modification to trust data produces immediately detectable evidence.

### 6.1 Binary Merkle tree, not sequential chain

Sequential hash chaining requires checking the entire chain from genesis to detect tampering. At 10 million entries, that becomes operationally impractical for external monitors.

RFC 6962 binary Merkle tree gives O(log n) inclusion proofs. A monitor can verify any entry in a log of 10 million entries by checking approximately 23 hashes. An auditor can verify any single ATX issuance without downloading the full log.

### 6.2 Hash construction

```
leaf_hash(entry) = SHA256(0x00 || timestamp_bytes || entry_type_byte || entry_data_bytes)
node_hash(left, right) = SHA256(0x01 || left_hash || right_hash)
MTH({d0}) = SHA256(0x00 || d0)
MTH(D[n]) = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))   where k is the largest power of two less than n
```

### 6.3 Signed Tree Head

Published every 5 minutes maximum. Any gap greater than 10 minutes is a monitor alert. The STH is the anchor that external parties verify against.

The transparency log is ATP's domain, and the STH wire shape is normatively
pinned there: ATP-SPEC §5.6 with
[`signed-tree-head-v1.schema.json`](https://github.com/opena2a-standards/agent-trust-protocol/blob/main/schemas/signed-tree-head-v1.schema.json),
byte-pinned by the atp-conformance `transparency-log-sth` fixture. The
Ed25519 signature is computed over the 32 raw bytes decoded from `rootHash`:

```json
{
  "treeSize": 1847294,
  "timestamp": "2026-05-23T00:00:00Z",
  "rootHash": "SHA256:111cc6504a7f35183bef35aa9d647cc3c799278325354d4446bb0157079b1602",
  "signedBy": "did:opena2a:authority:opena2a.org#key-1",
  "signature": "egu1YqeoHIW9w7e7fmaFUECdMv6HbOABUDwi6BHQMZn7vkPveBg34g3e3Jptlkw5GqipnytIKmLUs7W4xoCjCQ=="
}
```

An earlier revision of this section illustrated a hybrid variant
(`logId` + a `signatures[]` array carrying Ed25519 and ML-DSA-65 entries).
That shape is NOT the pinned wire format; a multi-signature STH — the
natural carrier for a post-quantum leg and for §7 cross-org cosigning —
is a possible future ATP extension, not something a verifier should accept
today.

### 6.4 Monitors

OpenA2A operates minimum 3 monitors in geographically separate regions. But the architecture requires external monitors to be credible. The monitor binary is open source, documented, and designed to be run by anyone with 5 minutes of setup.

Monitor verification cycle (every 5 minutes):

1. Fetch current STH.
2. Verify STH signature against the published public key.
3. Fetch consistency proof between last verified size and current size.
4. Verify the log has only grown. No entries modified or deleted.
5. Spot check 5 random recent entries. Fetch inclusion proofs. Verify each against the current STH root.
6. Verify no trust level 3 or higher entry exists without a corresponding federation cosign entry.
7. If any check fails, publish MONITOR_ALERT to the public endpoint and send to configured webhooks.

The monitor alert endpoint is public. Any party can subscribe and receive alerts. This is the mechanism that makes OpenA2A itself accountable.

---

## 7. Cross org cosigning

When agent A (issued by enterprise node X) calls agent B (issued by enterprise node Y), the trust decision requires cross node verification.

The protocol:

1. Agent A presents ATX issued by node X. ATX includes issuerChain field.
2. Agent B's verifier checks: is node X in B's trusted federation list? If yes, verify signature against X's public key (cached from X's DID document). Accept if valid.
3. If node X is not in B's trusted list, B queries the root node (OpenA2A) for a cosignature. Root node verifies X's ATX and issues a cross org attestation.
4. For trust level 4 (Verified), both issuing nodes AND the root node must have cosigned. No single organization can unilaterally grant the highest trust level.

This is the cryptographic mechanism that lets independent organizations interoperate without either having to be the gatekeeper. The trust list is local. The cosignature is the bridge. The transparency log makes the whole thing auditable.

The deeper architectural treatment of multi org and sovereign deployments lives in the ATX sovereign federation architecture doc.

---

## 8. Product integration map

Every OpenA2A product gains a specific role in the ATX architecture. Nothing is standalone.

| Product | Role | What it contributes |
|---|---|---|
| OpenA2A Registry | The root CA node | Issues ATX for community packages. Runs transparency log. Maintains CRL. Operates root federation node. Runs global webhook feeds. |
| HackMyAgent | The scanner at issuance | Scan results embedded in ATX at build time. HMA's own binary carries an ATX and verifies itself before running. 209 static plus 29 semantic plus 164 adversarial checks gate trust level. |
| Build plugin | The CA interface | Translates every CI build into a build attestation and ATX request. The developer's voice in the trust system. |
| AIM | Identity issuance and runtime enforcement | Issues agent keypairs bound to ATX. Enforces capabilities at runtime. 8 factor trust feeds into ATX trust score. Fleet dashboard shows ATX status across all agents. |
| ARP (part of HMA) | Runtime self attestation and L1 behavioral twin | At agent startup verifies own binary hash matches ATX contentHash. L1 behavioral model learns normal behavior. Anomaly events push to the behavioral gradient endpoint. |
| Secretless AI | Credential surface elimination | Removes all persistent credentials from CI and runtime. Nothing to steal equals no cascade after an ATX compromise attempt. |
| NanoMind | ATX intelligence layer | Routes natural language queries to ATX verification, scan results, revocation status. Answers "why is my agent trust level 2" conversationally from ATX data. |
| AI Browser Guard | User facing ATX verification | Extracts ATX from the Agent-Trust-Credential header. Displays trust level and scan summary to the user. Red warning on revoked or no ATX agents. |
| CryptoServe | PQC hygiene at issuance | Scan results embedded in ATX. ML-DSA-65 signature on every ATX makes them quantum resistant from day one. CryptoServe census feeds ecosystem level PQC adoption signal. |
| OASB | Compliance evidence from ATX | OASB compliance level (L1, L2, L3) embedded in ATX. The ATX is the compliance artifact for SOC 2, NIST AI RMF, EU AI Act. Every auditor gets the ATX plus the transparency log inclusion proof. |
| ARIA | Threat intelligence feeder | New attack patterns discovered by ARIA trigger HMA check additions. New checks gate ATX issuance. Zero day to HMA check to ATX requirement within hours. |
| TrapMyAgent and AgentPwn | Behavioral telemetry source | Real attack signatures feed the L0 rules and L1 baselines that ARP enforces at runtime. The honeypot fleet is the ground truth for what attacks actually look like. |

---

## 9. The one rule

**The issuing node must never be on the hot path of ATX verification.**

This rule supersedes everything else. If any code path causes an ATX verification to require a network call to the issuing node, that code must be reverted. Verification is local. Always. The issuing node handles issuance, revocation publication, and transparency logging. It does not handle verification.

This is the architectural property that makes ATX scale to a billion agents. It is also the property that makes Zero Failures real. The issuing node can be down for an hour and verification continues uninterrupted across the entire ecosystem. Do not compromise it.

---

## 10. What ATX is not

These boundaries are as important as the capabilities.

* **ATX is not an identity system.** AIM is, and AIM implements AIP §3 Agent Identity (see [`opena2a-org/agent-identity-protocol`](https://github.com/opena2a-org/agent-identity-protocol)). ATX binds an AIM-issued, AIP-conformant identity to a build and a behavioral profile. The identity itself comes from AIM.
* **ATX is not a runtime authorization system.** ARC is. ATX presents the credential. ARC enforces the policy.
* **ATX is not a centralized database.** It is a credential format. The issuing nodes are infrastructure. The credential travels with the agent.
* **ATX is not proprietary.** ATP is published as an open standard. Any organization can issue ATX credentials using the same format. Compatibility is the goal.
* **ATX does not bind to a single cryptographic suite.** Ed25519 and ML-DSA-65 are mandatory today. Additional suites can be added via ATP version negotiation.
* **ATX is not a substitute for code review.** Scans embedded in the ATX are signals, not absolution. A trust level 4 ATX on a malicious agent is a bug in the scanners, not a property of the credential.

---

## 11. Architectural commitments

The non negotiable properties that must hold across every implementation:

1. **Zero Failures.** No issuing node is ever a runtime dependency for customers. Local enforcement continues during any outage. Cloud is coordination, never critical path.
2. **One taxonomy, one ID.** All attack classifications resolve to Threat Matrix technique IDs (T-NNNN) at threats.opena2a.org. Scan results embedded in ATX reference those IDs. No parallel classifiers.
3. **Append only transparency.** Every ATX issuance and revocation is logged to the RFC 6962 Merkle tree before it takes effect. No retroactive modification is possible.
4. **Federation by default.** A single ATP node is a demonstration environment, not the architecture. Production deployments assume multiple cosigning nodes.
5. **Open standard.** ATP and ATX are published openly. Reference implementations are Apache 2.0. The protocol does not depend on OpenA2A as a vendor.
6. **Local verification, always.** The verifier never queries an issuing node during the verification path. Caching, CRL refresh, and DID document lookup happen out of band.

These six commitments are how the system survives at scale, how governments are willing to deploy it, and how Google and other enterprises can federate without conceding control. The rest of the architecture is engineering. The commitments are not.

---

## 12. Conformance
<!-- opena2a-definition: atx-conformance-coverage -->

Three conformance targets exist. An implementation claims conformance for one or more of them; the claims are independent.

**Credential (an ATX instance).** A conforming ATX carries every mandatory field of §1.1, selects exactly one canonical signing form by its version field (§1.3a), and its signatures verify over the bytes that form produces. A v1.1 credential MUST satisfy the determinism rules of §1.3a.2.

**Issuer.** A conforming issuer emits only conforming credentials, signs `JCS(TBS)` bytes that are byte-identical to what the conformance vectors pin (§1.3a.3), logs every issuance and revocation to the transparency log before it takes effect (§11 commitment 3), and never requires a verifier to contact it on the verification path (§9). A conforming issuer MUST NOT assert `trustLevel` 3 or higher on a credential that does not carry signatures from at least two distinct authorities as §1.3 step 7 counts them, and MUST NOT assert `trustLevel` 4 without the root cosignature §7 rule 4 requires. This binds issuance from the point an issuer claims conformance to it; it is not retroactive and it does not reclassify credentials already issued. The conformance suite's fixtures are not conforming issuer output under this rule and are not a model of issuance: they assert `trustLevel` 4 while carrying signatures from a single authority, and all but the two hybrid fixtures carry Ed25519 signatures only (see Coverage below), because they exist to pin signing bytes and verdicts rather than issuance policy.

**Verifier.** A conforming verifier implements the local verification algorithm of §1.3, dispatching on the credential's version field, and rejects on the failure of any step. It MUST treat the §1.3a.1 unsigned fields as unauthenticated under `atcVersion` `1.0` (§1.3a.4), and it MUST NOT add a network dependency on the issuing node to the acceptance path.

**Conformance suite.** The executable definition of these claims is the byte-pinned fixture set and SDK-independent reference verifiers at [`opena2a-standards/atx-conformance`](https://github.com/opena2a-standards/atx-conformance): 21 fixtures (baseline, hybrid, threshold cosignature, revocation, expiry, issuer binding, tamper rejection, malformed schema, and the `v1_1-*` family covering JCS signing, signed-field integrity, the untrusted chain authority of §1.3 step 4 that contributes no eligible key even when named in the signed `issuerChain`, `declaredPurpose`, the rule-5 degenerate inputs — whitespace-empty object accepted as absent, injected non-object values rejected — and strict credential parse: duplicate object members rejected at any depth per RFC 8259 §4, and case-variant members that a last-wins JSON decoder would collapse rejected as `PARSE_ERROR`), each pinned by SHA-256 in its `MANIFEST.sha256`, plus the `jcs-vectors` cross-language byte-agreement gate. An implementation claiming issuer or verifier conformance MUST produce the pinned verdict on every fixture and, for v1.1 issuance, MUST reproduce every `jcs-vectors` `expected.canonicalHex` byte-for-byte.

**Coverage.** The suite is the executable definition of the requirements it has fixtures for, and no more. It is not a complete test of this specification, and a requirement's absence from the suite is not evidence that an implementation satisfies it. Requirements stated normatively in this document that no fixture exercises include the distinct-signer-authority count of §1.3 step 7, the cosignature requirements of §7 (federation cosigning, and the root cosignature at trust level 4), revocation propagation timing (§3.3), and transparency-log monitor behavior (§6.4). No fixture carries signatures from more than one distinct authority, and the fixture format has no field for the required trust level that step 7's condition reads, so a verifier that omits step 7 entirely passes the suite. An implementation MUST self-attest these requirements against §1.3 step 7, §3.3, §6.4, and §7 until fixtures exist for them. The profile in `conformance.json` does not identify which requirement a given fixture exercises: every entry in it cites the same specification sections. Where this section and the suite's `notCovered` list disagree, both are incomplete; the requirement text in this document governs.

---

## 13. Security considerations

Attack techniques are cited by agent-threat-matrix ID ([threats.opena2a.org](https://threats.opena2a.org)) per architectural commitment 2.

**Unsigned v1.0 fields are forgeable (T-4001 Capability Override).** The legacy form signs eleven fields (§1.3a.1); `capabilities`, `scanSummary`, `issuerChain`, and `publisher` are not among them. A holder can rewrite any of these in a v1.0 credential without breaking its signature. Every consumer making decisions on those fields MUST enforce §1.3a.4 (require v1.1). This is the single most important verifier-side rule in this document.

**Stolen credentials replay (T-5004 Credential Reuse).** An ATX is a bearer artifact: presenting it proves what was attested about an agent build, not that the presenter is that agent. Exfiltrated credentials replay until expiry — the 7-day TTL (§1.2) and the CRL (§3.3) bound the window, and deep verification (`contentHash` check, §3.2 step 7; runtime self-attestation, §5), where performed, binds the credential to the running artifact. Deployments where impersonation matters MUST pair ATX presentation with a proof-of-possession channel (AIP identity keys); ATX alone does not provide one.

**Compromised build tooling (T-9006 Supply Chain Compromise, T-9003 Malicious Code Deployment).** The build plugin verifies scanner binaries against their own ATX credentials before executing them (§4.2) precisely because the scanners are the trust bootstrap: a compromised scanner otherwise attests a clean build of malicious code. The residual risk is a compromise of the build environment itself (OIDC token theft within the 15-minute TTL, §3.1); transparency-log monitoring (§6.4) is the detection layer for issuances that should not exist.

**Key substitution at resolution (T-4007 Tool Impersonation and Squatting).** Verification resolves `issuerDid` to a key through a cached DID document (§1.3 step 3). An attacker who can serve a substituted DID document controls which key verifies. Resolvers MUST fetch DID documents over authenticated channels, and the federation trust list (§7) bounds which issuers are accepted at all — an unknown issuer with a valid self-signature is still rejected.

**Delegation and chain abuse (T-4004 Delegation Abuse).** `issuerChain` is order-significant and signed under v1.1 (§1.3a.2 rule 4), but the signer writes it: it records which authorities were meant to endorse a credential, not which ones did. The evidence that two authorities endorsed one is two signatures the verifier itself verified under keys published by two distinct authorities, which is what §1.3 step 7 requires at trust level 3 and above; §7 requires a root cosignature in addition at trust level 4. A verifier that instead tests the length of `issuerChain`, or the presence of a name in it, enforces nothing, because one authority can write any chain it likes and sign alone. This is a gap between what the trust levels are specified to mean and what a verifier delivers until it implements step 7 as a count of distinct verified signer authorities: on a verifier that does not, trust levels 3 and 4 carry no multi-authority property, and relying parties MUST NOT read them as evidence that more than one authority signed.

**Revocation staleness.** A verifier on a stale CRL accepts a revoked agent for up to the cache TTL (5 minutes, §3.3). This is a deliberate availability trade (fail-open on cache, never on signature): the bound MUST be documented to relying parties, and verifiers MUST NOT extend the CRL TTL beyond 5 minutes for trust-level-3+ decisions.

**Purpose as alibi.** `declaredPurpose` is attacker-authored content under a valid signature. It MUST NOT raise a trust prior (§1.5.5) — a coherent declared purpose is a tightened detection baseline, never evidence of benign intent. The `statement` free-text sub-field is judged only by non-generative classifiers (§1.5.2) to keep prompt-injection payloads inside it from reaching a generative evaluator.

**Downgrade resistance.** `atcVersion` sits inside the v1.1 TBS, so stripping a v1.1 credential to the legacy form fails closed (§1.3a.5). Verifiers MUST NOT accept a credential whose version field selects a form its signatures do not verify under.

**Cryptographic agility.** Every credential carries Ed25519 and ML-DSA-65 signatures (§1.1); signature acceptance follows the family signature gate of AAP §9.4: every signature entry the credential declares MUST verify, a verifier MUST NOT accept a credential on a subset of its declared signatures, and a credential that declares an ML-DSA-65 entry MUST also carry a verifying Ed25519 entry. A verifier that does not implement a declared suite MUST reject the credential rather than accept it on the suites it does implement (AAP §8.2); the rejection is a signature failure (`SIGNATURE_INVALID`). A verifier that verifies only the Ed25519 entry has not performed post-quantum verification and MUST NOT claim it.

---

## 14. Registry considerations

This specification is not (yet) under IANA administration; the registries below are governed by the OpenA2A standards organization ([`opena2a-standards`](https://github.com/opena2a-standards)) with the same discipline an IANA section would impose: closed sets change only by specification revision, namespaced sets accept registrations by pull request against the governing repository.

| Registry | Governed set | Change policy |
|---|---|---|
| ATX version numbers | `1.0` (frozen legacy), `1.1` (current) | Specification revision only. A new version number is REQUIRED whenever the canonical signing form changes (§1.3a); reusing a version for different bytes is forbidden. |
| Signature algorithm suites | `Ed25519`, `ML-DSA-65` | Specification revision via ATP version negotiation (§10). |
| DID type prefixes (`did:opena2a`) | `registry`, `authority`, `publisher`, `agent`, `mcp_server`, `ai_tool`, `llm`, `skill` (`a2a_agent`: deprecated legacy alias of `agent`) | Registered in the [did:opena2a method specification](https://github.com/opena2a-standards/did-method-opena2a); additions by PR there, mirrored into §2 here. |
| `declaredPurpose` category vocabulary | 15 core values (§1.5.3), versioned via `vocabVersion` | Core set changes by specification revision with a `vocabVersion` bump; `<org>.<name>` custom values need no registration but default to the broadest class until reviewed (§1.5.3). |
| `taskScope` namespaces | 17 reserved core namespaces (§1.5.3) | Same policy as categories; non-reserved namespaces are org-custom. |
| Capability tokens | `namespace:operation` grammar | Governed with the capability registry in AIM; `capabilityJustification` keys MUST be a subset of the granted set (§1.5.2). |
| Transparency-log entry types | issuance, revocation, build attestation (§6) | ATP-SPEC revision. |

If ATP enters IETF process (§2), these registries are the candidates for genuine IANA sections; their change policies are written so that transition is a renaming, not a redesign.

---

*ATX core architecture v1.1.0. July 2026 (first published May 2026). OpenA2A. Apache 2.0. Successor to ATC v2.0.*
