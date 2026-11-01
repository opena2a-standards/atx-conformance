#!/usr/bin/env bash
# Writes the interop day kit onto one USB stick, from the published release.
#
#   write_stick.sh <tag> <volume-path>
#
# 1. Refuses unless diskutil info reports the volume as USB and removable,
#    mounted at <volume-path>, and the volume holds no files.
# 2. Downloads the release into a new folder and verifies it with
#    verify_release.sh: every asset's attestation (and a copy with one byte
#    changed refused), sha256sum -c SHA256SUMS and the file list.
# 3. Checks the volume again, then copies interop-day-kit/ onto it.
# 4. Checks the copy on the stick with this repository's scripts, never with
#    one read from the stick: sha256sum -c against the downloaded SHA256SUMS,
#    the stick's files equal to the files SHA256SUMS names (nothing else),
#    and the data protection kit check, which must print 1 on each line.
#
# It never formats, deletes or overwrites: it writes only a new
# interop-day-kit/ onto an empty volume. A volume that holds anything but the
# operating system's own volume folders is refused, and so is any other disk.
# Needs: macOS diskutil, gh signed in, git and python3, run from a clone of
# the repository. Environment: KIT_REPO (default
# opena2a-standards/atx-conformance).
set -euo pipefail
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1

here=$(cd "$(dirname "$0")" && pwd)
py=${KIT_PYTHON:-python3}
repo=${KIT_REPO:-opena2a-standards/atx-conformance}

die() { echo "stick: REFUSED: $*" >&2; exit 1; }
say() { echo "stick: $*"; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

[ $# -eq 2 ] || die "usage: write_stick.sh <tag> <volume-path>"
tag=$1 vol=$2
[[ "$tag" =~ ^kit-[0-9]{4}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?$ ]] || die "not a kit tag: $tag"
[[ "$repo" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || die "KIT_REPO is not owner/repo"
case "$vol" in /*) ;; *) die "give the volume as an absolute path, as /Volumes/<name>" ;; esac
[ -d "$vol" ] && [ ! -L "$vol" ] || die "not a directory: $vol"
vol=$(cd "$vol" && pwd -P)

# The operating system writes these onto a volume when it mounts it; anything
# else at the top of the volume means the volume is not empty.
os_volume_entry() {
  case "$1" in
    .fseventsd | .Spotlight-V100 | .Trashes | .TemporaryItems | "System Volume Information") [ -d "$vol/$1" ] ;;
    ._.Trashes) [ -f "$vol/$1" ] ;;
    *) return 1 ;;
  esac
}

check_volume() {
  local info protocol removable mount entry
  info=$(diskutil info "$vol") || die "diskutil info $vol failed"
  protocol=$(printf '%s\n' "$info" | awk -F': *' '$1 ~ /^ *Protocol$/ { print $2; exit }')
  removable=$(printf '%s\n' "$info" | awk -F': *' '$1 ~ /^ *Removable Media$/ { print $2; exit }')
  mount=$(printf '%s\n' "$info" | awk -F': *' '$1 ~ /^ *Mount Point$/ { print $2; exit }')
  [ "$protocol" = USB ] || die "diskutil reports the protocol of $vol as '${protocol:-none}', not USB"
  [ "$removable" = Removable ] || die "diskutil reports $vol as '${removable:-not removable}', not Removable"
  [ "$mount" = "$vol" ] || die "diskutil reports the mount point as '${mount:-none}', not $vol"
  while IFS= read -r entry; do
    os_volume_entry "$entry" && continue
    die "the volume is not empty: it holds $entry"
  done < <(cd "$vol" && ls -A)
}

check_volume
say "$vol: USB, removable, mounted there, empty"

[[ "$(command -v gh || true)" = /* ]] || die "gh is not installed"
commit=$(git ls-remote "https://github.com/$repo.git" "refs/tags/$tag" "refs/tags/$tag^{}" \
  | awk '{ c[$2] = $1 } END { t = "refs/tags/'"$tag"'"; if (t "^{}" in c) print c[t "^{}"]; else print c[t] }')
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "the tag $tag does not resolve to a commit on $repo"
say "$tag is commit $commit"

work=$(mktemp -d)
KIT_REPO=$repo KIT_COMMIT=$commit bash "$here/verify_release.sh" release "$tag" "$work/release"
sums="$work/release/assets/SHA256SUMS"
src="$work/release/kit/interop-day-kit"

check_volume
cp -R -X -n "$src" "$vol/interop-day-kit"
say "copied interop-day-kit/ onto $vol"

dst="$vol/interop-day-kit"
lines=$(wc -l <"$sums" | tr -d ' ')
ok=$(cd "$dst" && sha256 -c "$sums" | grep -c ': OK$') || die "sha256sum -c failed on the stick"
[ "$ok" = "$lines" ] || die "sha256sum -c on the stick: $ok of $lines OK"
"$py" -I "$here/kit_files.py" listcheck "$dst" "$sums" || die "the stick's interop-day-kit/ is not exactly the release's files"
d7=$(bash "$here/kit-check.sh" "$dst")
printf '%s\n' "$d7"
[ "$(printf '%s\n' "$d7" | awk -F': ' '{ printf "%s ", $NF }')" = "1 1 1 1 " ] || die "the data protection kit check on the stick did not print 1 on each of its four lines"
say "PASS $tag on $vol: sha256sum -c $ok of $lines OK, the release's files and nothing else, kit check 1 1 1 1"
