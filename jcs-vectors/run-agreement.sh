#!/usr/bin/env bash
# ATX v1.1 JCS / RFC 8785 cross-language byte-agreement gate.
#
# Runs three INDEPENDENT canonicalizers over every vector in vectors/ and fails
# unless all three reproduce each vector's pinned expected.canonicalHex
# byte-for-byte:
#
#   Go      github.com/gowebpki/jcs       (also re-verifies Ed25519 + ML-DSA-65)
#   Python  vendored RFC 8785 (zero-dep)  python/rfc8785.py
#   TS/JS   erdtman/canonicalize          ts/check.mjs
#
# It then runs both conformance verifiers' own v1.1 path (credential -> TBS
# projection -> JCS) over the same vectors and requires the same bytes:
#
#   Go      verifiers/go      TestJCSVectorsThroughVerifierProjection
#   Python  verifiers/python  test_verify.JCSVectorsThroughVerifierProjection
#
# This is the Phase 0 MERGE GATE: the jcs-vectors set may only merge when this
# script exits 0. It runs no issuer, offline-verifier or broker code: each is
# held to these bytes only by running vectors/ in its own CI.
set -euo pipefail

cd "$(dirname "$0")"

fail=0

# Run one named test of verifiers/go. `go test -run` exits 0 with "no tests to
# run" when the pattern matches no test, so a renamed test left this leg green
# without running. It passes only when the -v output carries the test's own
# PASS line.
go_verifier_test() {
  local out
  if ! out=$( cd ../verifiers/go && go test -count=1 -v -run "^$1\$" . 2>&1 ); then
    echo "$out"
    return 1
  fi
  echo "$out"
  if ! grep -q "^--- PASS: $1 (" <<<"$out"; then
    echo "[verifier/go] FAIL  $1 did not run: verifiers/go has no test of that name"
    return 1
  fi
}

echo "=== [go] github.com/gowebpki/jcs ==="
if ! go run ./check; then fail=1; fi
echo

echo "=== [py] vendored RFC 8785 (stdlib only) ==="
if ! python3 python/check.py; then fail=1; fi
echo

echo "=== [ts] erdtman/canonicalize ==="
if [ ! -d ts/node_modules ]; then
  echo "[ts] installing pinned dependency (canonicalize) ..."
  ( cd ts && npm install --no-audit --no-fund >/dev/null 2>&1 )
fi
if ! node ts/check.mjs; then fail=1; fi
echo

echo "=== [verifier/go] verifiers/go canonicalPayloadV11 ==="
if ! go_verifier_test TestJCSVectorsThroughVerifierProjection; then fail=1; fi
# The leg must be able to fail: a name no test has is not reported as run.
if go_verifier_test TestNoSuchVerifierTest >/dev/null; then
  echo "[verifier/go] FAIL  a test name that matches no test was reported as run"; fail=1
fi
echo

echo "=== [verifier/py] verifiers/python canonical_payload_v11 ==="
if ! ( cd ../verifiers/python && python3 -m unittest test_verify.JCSVectorsThroughVerifierProjection ); then fail=1; fi
echo

echo "=== verifying jcs-vectors/MANIFEST.sha256 ==="
manifest_ok=1
while read -r sha path; do
  [ -z "$sha" ] && continue
  full="../$path"
  if [ ! -f "$full" ]; then
    echo "MANIFEST FAIL: missing $path"; manifest_ok=0; continue
  fi
  got=$(shasum -a 256 "$full" | awk '{print $1}')
  if [ "$got" != "$sha" ]; then
    echo "MANIFEST FAIL: $path"; echo "   want $sha"; echo "   got  $got"; manifest_ok=0
  fi
done < MANIFEST.sha256
if [ "$manifest_ok" -eq 1 ]; then echo "MANIFEST.sha256 OK"; else fail=1; fi
echo

if [ "$fail" -eq 0 ]; then
  echo "BYTE-AGREEMENT GATE: PASS (go == py == ts == both verifiers == pinned, manifest intact)"
else
  echo "BYTE-AGREEMENT GATE: FAIL"
fi
exit "$fail"
