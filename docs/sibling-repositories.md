# atx-conformance: sibling repositories

The conformance suites for the other OpenA2A specifications, and how this
repository's row in their table is checked.

## Sibling repositories

Two peer conformance suites cover the other OpenA2A specs in scope of the
A2A coordination map's criterion (c) thread
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885) (closed on 2026-06-23):

| Repo | Spec | Status |
|---|---|---|
| `atx-conformance` (this repo) | ATX v1.0 + v1.1 credential schema | 27 fixtures (10 v1.0, 17 v1.1 JCS incl. 7 declaredPurpose), 2 verifiers (Go and Python, both full hybrid), `jcs-vectors/` byte-agreement gate (8 vectors, Go/Python/TS), `MANIFEST.sha256` pinned |
| [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) | ATP v1.0.0-rc1 protocol | 14 fixtures (discovery, trust proof, Signed Tree Head, inclusion and consistency proof, revocation list, with must-reject controls), same 2-verifier pair, `MANIFEST.sha256` pinned |
| [`aip-conformance`](https://github.com/opena2a-standards/aip-conformance) | AIP v1.2.0-draft identity protocol | §6.4 (VC `AgentTrustCredential`) covered by cross-linking this repo's fixtures; §5.1 challenge-response covered by 4 dedicated fixtures + Go/Python verifiers; §6.1 trust-score composition covered by 3 fixtures |

The three suites share the same MANIFEST-pinned byte-stable shape and are
structurally comparable to A2A-IDF's
[`aim-did-rfc9421/*`](https://github.com/opena2a-standards/a2a-idf-conformance/tree/main/fixtures/composition/aim-did-rfc9421)
set.

The fixture and verifier counts in the two sibling rows, any release
version a sibling row names, and the spec version its Spec cell names, are
measurements of those repositories, not of this one; the Spec cell is held
to the `spec.id` and `spec.version` the repository's `conformance.json`
declares. [`scripts/check_sibling_rows.py`](../scripts/check_sibling_rows.py)
reads both repositories through the GitHub API and fails when a row no
longer matches them. It needs network access and is run by hand, not by the
[continuous-verification gates](continuous-verification.md).
