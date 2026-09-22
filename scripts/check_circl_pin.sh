#!/usr/bin/env bash
# One cloudflare/circl version across every Go module in this repository.
#
# The vectors (jcs-vectors), the fixture generator (scripts/generate-fixtures)
# and the Go verifier (verifiers/go) all sign and verify ML-DSA-65 through
# github.com/cloudflare/circl. When they resolve different versions the
# vectors and the verifier do not share one crypto tree, and a pinned digest
# can hold under one version and move under the other without any gate
# noticing. This script lists the pin per go.mod and exits non-zero when
# they differ. It runs in CI beside the byte-agreement gate.
#
# Usage: scripts/check_circl_pin.sh            # from the repository root
#        scripts/check_circl_pin.sh <root>     # another checkout
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
module="github.com/cloudflare/circl"

pins=()
rc=0
while IFS= read -r gomod; do
  rel="${gomod#"$root"/}"
  version="$(awk -v m="$module" '$1 == m { print $2; exit } $1 == "require" && $2 == m { print $3; exit }' "$gomod")"
  if [ -z "$version" ]; then
    echo "SKIP  $rel: does not require $module"
    continue
  fi
  echo "PIN   $rel: $module $version"
  pins+=("$version")
done < <(find "$root" -name go.mod -not -path '*/node_modules/*' -not -path '*/.git/*' | sort)

if [ "${#pins[@]}" -eq 0 ]; then
  echo "FAIL  no go.mod requires $module"
  exit 1
fi

distinct="$(printf '%s\n' "${pins[@]}" | sort -u | wc -l | tr -d ' ')"
if [ "$distinct" -ne 1 ]; then
  echo "FAIL  $distinct distinct $module versions across ${#pins[@]} modules; pin one"
  rc=1
else
  echo "PASS  one $module version (${pins[0]}) across ${#pins[@]} modules"
fi
exit "$rc"
