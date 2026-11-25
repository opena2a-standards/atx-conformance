#!/usr/bin/env python3
"""The suite pins an explicit k-of-n signature threshold from both sides
(atx-spec core.md section 3.1 step 8, atx-conformance#409), and
conformance.json's notCovered says no more than that.

A threshold is set by a fixture's verifierState.requiredSignatures. The
pair is two fixtures under the same verifier state that sets it: one whose
declared signatures verify under at least that many distinct Ed25519 keys and
which expects ACCEPT, and one whose signatures verify under fewer and which
expects REJECT SIGNATURE_INVALID with a reason containing "threshold". The
REJECT alone passes a verifier that rejects every credential whose verifier
state sets requiredSignatures; the ACCEPT alone passes one that reads no
threshold.

Before the change this test came with, threshold-1of3-cosignature.json was
the only fixture that set requiredSignatures, and notCovered listed "a
threshold the credential meets". Both reference verifiers are run on the
pair here and must pass each fixture and print the same bytes.

Needs Go and the Python verifier's dependencies. Run from the repository
root:

    python3 scripts/test_threshold_pair.py
"""

import json
import pathlib
import subprocess
import sys
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
FIXTURES = ROOT / "fixtures"
PROFILE = ROOT / "conformance.json"
FIELD = "requiredSignatures"
MET = "fixtures/threshold-2of3-required-met.json"
NOT_MET = "fixtures/threshold-1of3-cosignature.json"


def load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def threshold_fixtures():
    """Every fixture whose verifier state sets requiredSignatures, by path."""
    found = {}
    for path in sorted(FIXTURES.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        if FIELD in fixture.get("verifierState", {}):
            found[path.relative_to(ROOT).as_posix()] = fixture
    return found


def distinct_ed25519_keys(fixture):
    """The public keys of the verifier state that a declared Ed25519
    signature names by keyId: the most keys the signatures can verify under."""
    keys = {k["keyId"]: k["publicKeyHex"] for k in fixture["verifierState"]["publicKeys"]
            if k["algorithm"] == "Ed25519"}
    return {keys[s["keyId"]] for s in fixture["atx"]["signatures"]
            if s["algorithm"] == "Ed25519" and s["keyId"] in keys}


class ThresholdPair(unittest.TestCase):
    def test_a_threshold_is_both_met_and_not_met(self):
        fixtures = threshold_fixtures()
        accept = [p for p, f in fixtures.items() if f["expected"]["verifyResult"] == "ACCEPT"]
        reject = [p for p, f in fixtures.items()
                  if f["expected"] == {"verifyResult": "REJECT", "rejectCategory": "SIGNATURE_INVALID",
                                       "reasonContains": "threshold"}]
        self.assertIn(MET, accept, f"no fixture sets {FIELD} and expects ACCEPT: {sorted(fixtures)}")
        self.assertIn(NOT_MET, reject, f"no fixture sets {FIELD} and expects a threshold REJECT")

    def test_the_pair_shares_its_verifier_state_and_credential(self):
        met, not_met = load(MET), load(NOT_MET)
        self.assertEqual(met["verifierState"], not_met["verifierState"])
        self.assertEqual(met["verifierState"][FIELD], 2)
        self.assertEqual(len(met["verifierState"]["publicKeys"]), 3)
        strip = lambda atx: {k: v for k, v in atx.items() if k != "signatures"}
        self.assertEqual(strip(met["atx"]), strip(not_met["atx"]))
        # Case B's one signature is case A's first, byte for byte.
        self.assertEqual(not_met["atx"]["signatures"], met["atx"]["signatures"][:1])

    def test_the_met_fixture_has_two_distinct_keys_and_the_other_one(self):
        met, not_met = load(MET), load(NOT_MET)
        required = met["verifierState"][FIELD]
        self.assertEqual(len(met["atx"]["signatures"]), 2)
        self.assertEqual(len(distinct_ed25519_keys(met)), required)
        self.assertEqual(len(distinct_ed25519_keys(not_met)), required - 1)

    def test_not_covered_no_longer_lists_a_threshold_the_credential_meets(self):
        items = [e["item"] for e in json.loads(PROFILE.read_text(encoding="utf-8"))["notCovered"]]
        self.assertFalse([i for i in items if "a threshold the credential meets" in i], items)
        step8 = [i for i in items if "section 3.1 step 8" in i]
        self.assertEqual(len(step8), 1, items)
        self.assertIn("repeat signatures from one key", step8[0])

    def test_both_reference_verifiers_pass_the_pair_and_print_the_same_bytes(self):
        args = [MET, NOT_MET]
        go = subprocess.run(["go", "run", "./cmd/atx-verify", *args], cwd=ROOT,
                            capture_output=True, text=True, timeout=600)
        py = subprocess.run([sys.executable, "verifiers/python/verify.py", *args], cwd=ROOT,
                            capture_output=True, text=True, timeout=600)
        self.assertEqual(go.returncode, 0, go.stdout + go.stderr)
        self.assertEqual(py.returncode, 0, py.stdout + py.stderr)
        self.assertEqual(go.stdout, py.stdout)
        for rel in args:
            self.assertIn(f"PASS  {rel}\n", go.stdout)
        self.assertIn("summary: 2 pass, 0 fail (2 fixtures)", go.stdout)


if __name__ == "__main__":
    unittest.main()
