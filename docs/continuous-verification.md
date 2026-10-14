# atx-conformance: continuous verification

The gates CI runs on this repository. The commands that run the verifiers
by hand are in the [README](../README.md#running-the-verifiers).

## Continuous verification

[`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml)
runs the following gates on every pull request and every push to `main`.
They cover the counts, the verifier results, the fixture bytes and the
claims the README and its pages under `docs/` make about them -- not every
sentence below:

1. Both reference verifiers run against `fixtures/` and must report
   `25 pass, 0 fail`.
2. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
3. The JCS byte-agreement gate
   ([`jcs-vectors/run-agreement.sh`](../jcs-vectors/run-agreement.sh)) must
   pass across the independent Go, Python, and TypeScript canonicalizers
   and across both reference verifiers' own v1.1 projection
   (`verifiers/go`, `verifiers/python`; the gate needs the Python
   verifier's dependencies), and every Go module in the repository must pin
   one `cloudflare/circl` version
   ([`scripts/check_circl_pin.sh`](../scripts/check_circl_pin.sh)), so the
   vectors and the verifier share one crypto tree.
4. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](../scripts/parity/parity.py)) asserts the Go
   and Python verifiers agree per fixture on gate status, verdict, and
   reject category, and publishes `parity-report.json` as a CI artifact.
5. `conformance.json` must match the fixture set, and every ATX citation in
   each fixture's `spec` list, each JCS vector's `spec` member and the
   `requirements[].specRefs` of `conformance.json` must link to atx-spec
   `core.md` at the pinned atx-spec commit and name one of its headings
   exactly ([`scripts/check_spec_refs.py`](../scripts/check_spec_refs.py)).
   A citation id must be a string, and one that differs from `ATX` only in
   case or surrounding blanks fails rather than being skipped. Every link to
   atx-spec `core.md` in the README, in its pages under `docs/` and in
   `verifiers/go/verify.go` must be the same pinned link. The top-level
   `spec.ref` of
   `conformance.json` is written from that link, so the staleness check holds
   it to the pin; the prose of `notCovered[].item` is not checked. Headings
   are read from the copy vendored at `schemas/vendor/atx-spec/core.md` from
   the same pinned atx-spec ref as the schema. That copy must carry the
   SHA-256 of `core.md` at that ref, and the ref recorded with it must be the
   one the schema drift gate checks out, so the copy cannot gain a heading by
   being edited or fall behind a moved pin.
6. Schema validation
   ([`scripts/schema_validation.py`](../scripts/schema_validation.py)): every
   fixture's `atx` member must validate against the atx-spec machine-readable
   credential schema, vendored under `schemas/vendor/atx-spec/` and
   byte-drift-gated against a pinned atx-spec ref; the `malformed-schema`
   fixture must fail on exactly the `atcVersion` registry enum. Before that,
   every fixture and `conformance.json` must name in `$schema` the `$id` of a
   schema under `schemas/` and validate against it in full
   (`schemas/fixture-v1.schema.json`,
   `schemas/conformance-profile-v1.schema.json`); a self-test first proves the
   check fails on altered copies of each.
