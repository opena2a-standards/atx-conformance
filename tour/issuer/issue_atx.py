#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Issue one ATX v1.1 credential with throwaway keys and write four fixtures.

The guided tour (cmd/atx-tour, step 4) runs this, then both reference
verifiers over the directory it writes. It is a separate issuer: it is
written from ATX core.md section 1.3a.2 (the JCS signing form) and imports
nothing from verifiers/go or verifiers/python, so a PASS means two pieces of
code written apart agree on the signed bytes.

Throwaway keys only: a new Ed25519 key and a new ML-DSA-65 key are made on
every run, held in memory and never written anywhere. Nothing this script
issues comes from OpenA2A or any registry.

usage:  python3 tour/issuer/issue_atx.py <output-directory>
needs:  the Python verifier's packages (cryptography, dilithium-py), as
        installed from verifiers/python/requirements.lock.

The four fixtures, each with the verdict both verifiers must reach:
  1-issued.json            the credential as issued         ACCEPT
  2-one-byte-changed.json  trustScore 50 edited to 90       REJECT SIGNATURE_INVALID
  3-revoked.json           the agent on the verifier's CRL  REJECT REVOKED
  4-untrusted-issuer.json  the issuer not trusted           REJECT UNTRUSTED_ISSUER
"""
import base64
import copy
import hashlib
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dilithium_py.ml_dsa import ML_DSA_65

# core.md 1.3a.2: the members of the to-be-signed (TBS) projection, exactly.
# declaredPurpose is optional and this credential declares none, so it is
# omitted (rule 5).
TBS_MEMBERS = (
    "atcVersion", "agentId", "agentDid", "publisher", "publisherDid",
    "version", "contentHash", "buildAttestation", "capabilities",
    "behavioralProfile", "scanSummary", "trustScore", "trustLevel",
    "issuedAt", "expiresAt", "issuerDid", "issuerChain",
)


def canonical(value):
    """RFC 8785 for the JSON values this script builds: objects, arrays,
    strings, integers, booleans and null. A float never reaches it: rule 3
    turns trustScore into a string before signing."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        out = ['"']
        for ch in value:
            code = ord(ch)
            if ch == '"':
                out.append('\\"')
            elif ch == "\\":
                out.append("\\\\")
            elif code < 0x20:
                named = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
                out.append(named.get(code, "\\u%04x" % code))
            else:
                out.append(ch)
        out.append('"')
        return "".join(out)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        # Member names sort by UTF-16 code unit.
        names = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(canonical(k) + ":" + canonical(value[k]) for k in names) + "}"
    raise TypeError("no canonical form for %r in this issuer" % (value,))


def rfc3339(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: python3 tour/issuer/issue_atx.py <output-directory>\n")
        return 2
    out_dir = argv[1]

    tag = secrets.token_hex(4)
    issuer = "did:opena2a:authority:throwaway-%s.example" % tag
    agent_id = "agent_throwaway_%s" % tag
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # Two fresh key pairs, in memory only.
    ed_private = Ed25519PrivateKey.generate()
    ed_public = ed_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pq_public, pq_private = ML_DSA_65.keygen()

    credential = {
        "id": str(uuid.uuid4()),
        "atcVersion": "1.1",
        "agentId": agent_id,
        "agentDid": "did:opena2a:agent:" + agent_id,
        "publisher": "throwaway-tour",
        "publisherDid": "did:opena2a:publisher:throwaway-tour",
        "version": "1.0.0",
        # A stand-in: this tour has no agent binary to hash.
        "contentHash": hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        "buildAttestation": "",
        "capabilities": ["db:read"],
        "behavioralProfile": None,
        "scanSummary": {"hma": "", "criticalFindings": 0, "highFindings": 0,
                        "secretless": "", "cryptoServe": "", "oasbLevel": ""},
        "trustScore": 50,
        "trustLevel": 2,
        "issuedAt": rfc3339(now),
        "expiresAt": rfc3339(now + timedelta(days=1)),
        "issuerDid": issuer,
        "issuerChain": [issuer],
        "revoked": False,
        "createdAt": rfc3339(now),
    }

    tbs = {name: credential[name] for name in TBS_MEMBERS}
    tbs["trustScore"] = "%.6f" % float(credential["trustScore"])  # rule 3
    payload = canonical(tbs).encode("utf-8")

    # Both signatures cover the same JCS(TBS) bytes.
    credential["signatures"] = [
        {"keyId": issuer + "#key-1", "algorithm": "Ed25519",
         "value": base64.b64encode(ed_private.sign(payload)).decode("ascii")},
        {"keyId": issuer + "#key-1-pqc", "algorithm": "ML-DSA-65",
         "value": base64.b64encode(ML_DSA_65.sign(pq_private, payload)).decode("ascii")},
    ]

    keys = [
        {"role": "throwaway-ed25519", "path": "(held in memory, not saved)",
         "algorithm": "Ed25519", "publicKeyHex": ed_public.hex(),
         "keyId": issuer + "#key-1"},
        {"role": "throwaway-ml-dsa-65", "path": "(held in memory, not saved)",
         "algorithm": "ML-DSA-65", "publicKeyHex": pq_public.hex(),
         "keyId": issuer + "#key-1-pqc"},
    ]
    clock = rfc3339(now + timedelta(minutes=1))

    def fixture(slug, description, expected, atx, **state):
        verifier_state = {"clockRfc3339": clock, "trustedIssuers": [issuer],
                          "publicKeys": keys}
        verifier_state.update(state)
        return {
            "name": "atx-tour/" + slug,
            "description": description,
            "requirement": "ATX core.md 1.3 local verification of a credential issued by this tour",
            "spec": [{"id": "ATX", "section": "1.3a.2 JCS form",
                      "ref": "schemas/vendor/atx-spec/core.md"}],
            "keypairRefs": keys,
            "verifierState": verifier_state,
            "expected": expected,
            "atx": atx,
        }

    changed = copy.deepcopy(credential)
    changed["trustScore"] = 90  # one byte of the file, 5 to 9, after signing

    revocation_list = {
        "version": 1,
        "issuedAt": rfc3339(now),
        "nextUpdate": rfc3339(now + timedelta(hours=1)),
        "entries": [{"agentId": agent_id, "revokedAt": rfc3339(now),
                     "reason": "revoked by the tour"}],
        "signature": "unsigned: a tour test list",
    }

    fixtures = [
        ("1-issued", fixture("issued", "The credential as issued.",
                             {"verifyResult": "ACCEPT"}, credential)),
        ("2-one-byte-changed", fixture(
            "one-byte-changed", "trustScore edited from 50 to 90 after signing.",
            {"verifyResult": "REJECT", "rejectCategory": "SIGNATURE_INVALID"}, changed)),
        ("3-revoked", fixture(
            "revoked", "The agent is on the verifier's revocation list.",
            {"verifyResult": "REJECT", "rejectCategory": "REVOKED"}, credential,
            crl=revocation_list)),
        ("4-untrusted-issuer", fixture(
            "untrusted-issuer", "The verifier does not trust this issuer.",
            {"verifyResult": "REJECT", "rejectCategory": "UNTRUSTED_ISSUER"}, credential,
            trustedIssuers=["did:opena2a:authority:someone-else.example"])),
    ]

    os.makedirs(out_dir, exist_ok=True)
    for slug, body in fixtures:
        path = os.path.join(out_dir, slug + ".json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(body, handle, indent=2)
            handle.write("\n")
        want = body["expected"]["verifyResult"]
        category = body["expected"].get("rejectCategory")
        print("wrote %s.json  expect %s%s" % (slug, want, " " + category if category else ""))
    print("issuer %s" % issuer)
    print("signed bytes %d, sha256 %s" % (len(payload), hashlib.sha256(payload).hexdigest()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
