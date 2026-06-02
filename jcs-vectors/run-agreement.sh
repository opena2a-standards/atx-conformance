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
# This is the Phase 0 MERGE GATE: the jcs-vectors set may only merge when this
# script exits 0. Cross-language agreement on the canonical bytes is the actual
# guarantee that the registry, conformance, and Secretless verifiers will all
# sign and verify the same payload; the JCS libraries are an implementation
# detail behind it.
set -euo pipefail

cd "$(dirname "$0")"

fail=0

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
  echo "BYTE-AGREEMENT GATE: PASS (go == py == ts == pinned, manifest intact)"
else
  echo "BYTE-AGREEMENT GATE: FAIL"
fi
exit "$fail"
