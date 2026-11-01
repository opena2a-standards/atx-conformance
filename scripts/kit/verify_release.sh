#!/usr/bin/env bash
# Verifies the interop day kit as published, or as a candidate:
#
#   verify_release.sh release <tag> <work-dir>
#       Downloads the release <tag> into <work-dir>/assets.
#   verify_release.sh candidate <asset-dir> <work-dir>
#       Takes the assets of a dispatch run on main from <asset-dir>.
#
# The assets are exactly interop-day-kit.tar.gz and SHA256SUMS. For each of
# them, and for each binary in the unpacked kit, the build provenance
# attestation must verify:
#   gh attestation verify <file> -R <owner/repo>
#     --signer-workflow <owner/repo>/.github/workflows/kit-release.yml
#     --source-ref <ref> --source-digest <commit> --deny-self-hosted-runners
# and the same command must fail on a copy of the file with one byte changed.
# Then sha256sum -c SHA256SUMS must pass inside the unpacked kit, and the
# kit's files must be exactly the files SHA256SUMS names. For a release,
# gh release verify <tag> must pass too. The unpacked kit is left in
# <work-dir>/kit/interop-day-kit.
#
# The ref is refs/tags/<tag> for a release and refs/heads/main for a
# candidate. Environment: KIT_REPO (owner/repo), KIT_COMMIT (the full commit),
# and GH_TOKEN where gh is not signed in.
set -euo pipefail
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1

here=$(cd "$(dirname "$0")" && pwd)
py=${KIT_PYTHON:-python3}
workflow_file=.github/workflows/kit-release.yml

die() { echo "verify: $*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

[ $# -eq 3 ] || die "usage: verify_release.sh release <tag> <work-dir> | candidate <asset-dir> <work-dir>"
mode=$1 arg=$2 work=$3
[[ "${KIT_REPO:-}" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || die "KIT_REPO is not owner/repo"
[[ "${KIT_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || die "KIT_COMMIT is not a full commit id"
mkdir -p "$work"
[ -z "$(ls -A "$work")" ] || die "$work is not empty"
assets="$work/assets"
mkdir "$assets"

case "$mode" in
  release)
    [[ "$arg" =~ ^kit-[0-9]{4}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?$ ]] || die "not a kit tag: $arg"
    ref="refs/tags/$arg"
    gh release download "$arg" -R "$KIT_REPO" -D "$assets"
    ;;
  candidate)
    ref="refs/heads/main"
    cp "$arg/interop-day-kit.tar.gz" "$arg/SHA256SUMS" "$assets/"
    ;;
  *) die "unknown mode: $mode" ;;
esac

found=$(cd "$assets" && ls -A | tr '\n' ' ')
[ "$found" = "SHA256SUMS interop-day-kit.tar.gz " ] || die "the assets are '$found', not exactly SHA256SUMS and interop-day-kit.tar.gz"

attested() {
  gh attestation verify "$1" -R "$KIT_REPO" --signer-workflow "$KIT_REPO/$workflow_file" \
    --source-ref "$ref" --source-digest "$KIT_COMMIT" --deny-self-hosted-runners >/dev/null
}
# An attestation written seconds before may not be readable yet, so the check
# on the file itself is tried up to KIT_ATTEST_TRIES times, 15 seconds apart.
# The check on the copy with one byte changed is tried once and must fail.
attested_file() {
  local i tries=${KIT_ATTEST_TRIES:-3}
  for ((i = 1; i <= tries; i++)); do
    attested "$1" && return 0
    [ "$i" -lt "$tries" ] && sleep 15
  done
  return 1
}

"$py" -I "$here/kit_files.py" extract "$assets/interop-day-kit.tar.gz" "$work/kit"
kit="$work/kit/interop-day-kit"
flips="$work/one-byte-changed"
mkdir "$flips"
n=0
for f in "$assets/interop-day-kit.tar.gz" "$assets/SHA256SUMS" "$kit"/bin/*/atx-verify*; do
  [ -f "$f" ] || die "no file $f"
  name=${f#"$work/"}
  attested_file "$f" || die "the attestation of $name does not verify"
  n=$((n + 1))
  flip="$flips/$n-$(basename "$f")"
  "$py" -I "$here/kit_files.py" flip "$f" "$flip"
  if attested "$flip"; then die "a copy of $name with one byte changed verified: the check proves nothing"; fi
  echo "verify: $name: attestation verifies ($ref, $KIT_COMMIT); one byte changed: refused"
done
[ "$n" -ge 3 ] || die "only $n files checked"

lines=$(wc -l <"$assets/SHA256SUMS" | tr -d ' ')
ok=$(cd "$kit" && sha256 -c "$assets/SHA256SUMS" | grep -c ': OK$') || die "sha256sum -c failed on the unpacked kit"
[ "$ok" = "$lines" ] || die "sha256sum -c: $ok of $lines OK"
echo "verify: sha256sum -c SHA256SUMS: $ok of $lines OK"
"$py" -I "$here/kit_files.py" listcheck "$kit" "$assets/SHA256SUMS"

if [ "$mode" = release ]; then
  gh release verify "$arg" -R "$KIT_REPO" >/dev/null || die "gh release verify $arg failed"
  echo "verify: gh release verify $arg: passed"
fi
echo "verify: $mode $arg: $n attested files, every one-byte copy refused, $lines files checked"
