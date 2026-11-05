#!/usr/bin/env bash
# Assembles the interop day kit: atx-conformance at one commit, its Go verifier
# built for six platforms, the Python verifier's pinned wheels, and the text a
# first-time reader needs, with one SHA256SUMS over every file.
#
#   assemble.sh stage <out-dir>
#       In a clean clone at KIT_COMMIT, builds the six binaries with
#       CGO_ENABLED=0 go build -trimpath before anything else is written, and
#       writes nothing into the checkout. Checks that each binary records the
#       commit, no uncommitted change and the pinned Go. Then writes
#       <out-dir>/kit-stage.tar: git archive of the commit, the binaries under
#       bin/<os>-<arch>/, the launchers verify and verify.cmd, and the Python
#       verifier's wheels, downloaded with --require-hashes against the lock.
#   assemble.sh check-capture <kit-dir> <capture> <exit-code-file> <os>-<arch> <out-dir>
#       Checks one platform's run of the launcher (exit 0, last line
#       "summary: N pass, 0 fail (N fixtures)" with N the fixture count, no
#       absolute path), and the binary's --version line, and writes
#       <out-dir>/<os>-<arch>.txt, .version and .sha256.
#   assemble.sh kit <kit-stage.tar> <captures-dir> <out-dir>
#       Writes <out-dir>/interop-day-kit from the stage and the captures, with
#       captures/<os>-<arch>.txt, README-START-HERE.md, CONTACT.txt and
#       PYTHON.md; installs the Python verifier offline from the kit and runs
#       it; runs the label census; writes <out-dir>/SHA256SUMS over every file
#       and checks it with sha256sum -c and the file-list check; runs the data
#       protection kit check; writes the release notes and title, and
#       <out-dir>/interop-day-kit.tar.gz, checked the same way.
#   assemble.sh claims <out-dir> <captures-dir>
#       Refuses when the release notes name a --version form a binary does not
#       print.
#   assemble.sh local <out-dir>
#       stage, a run of the launcher on this machine, check-capture, and kit.
#
# Environment: KIT_TAG (kit-YYYY-MM-DD or kit-YYYY-MM-DD.N), KIT_REPO
# (owner/repo), KIT_COMMIT (a full commit id), KIT_GO_VERSION (as 1.22.12).
set -euo pipefail
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1

usage='usage: assemble.sh stage <out-dir>
       assemble.sh check-capture <kit-dir> <capture> <exit-code-file> <os>-<arch> <out-dir>
       assemble.sh kit <kit-stage.tar> <captures-dir> <out-dir>
       assemble.sh claims <out-dir> <captures-dir>
       assemble.sh local <out-dir>
       assemble.sh -h | --help'
# -h or --help prints the usage on stdout. An option other than those, or a
# first argument that names no command, is named on stderr above the usage,
# and the script exits 2 before it reads or writes anything.
want_help=0 unknown=
case "${1:-}" in ''|-?*|stage|check-capture|kit|claims|local) ;; *) unknown=$1 ;; esac
for opt in "$@"; do
  case "$opt" in
    -h|--help) want_help=1 ;;
    -?*) unknown="${unknown:+$unknown }$opt" ;;
  esac
done
if [ -n "$unknown" ]; then printf 'unknown argument(s): %s\n%s\n' "$unknown" "$usage" >&2; exit 2; fi
if [ "$want_help" = 1 ]; then printf '%s\n' "$usage"; exit 0; fi

here=$(cd "$(dirname "$0")" && pwd)
py=${KIT_PYTHON:-python3}
workflow_file=.github/workflows/kit-release.yml

die() { echo "assemble: $*" >&2; exit 1; }
say() { echo "assemble: $*"; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
hash_of() { sha256 "$1" | cut -d' ' -f1; }
need_env() { local v; for v in "$@"; do [ -n "${!v:-}" ] || die "$v is not set"; done; }
check_tag() {
  # A kit tag is kit-YYYY-MM-DD or kit-YYYY-MM-DD.N: never a v prefix, never a slash.
  [[ "$1" =~ ^kit-[0-9]{4}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?$ ]] || die "not a kit tag: $1"
}
check_commit() { [[ "$1" =~ ^[0-9a-f]{40}$ ]] || die "not a full commit id: $1"; }
check_repo() { [[ "$1" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || die "not owner/repo: $1"; }
targets() { grep -v -E '^[[:space:]]*(#|$)' "$here/targets.txt"; }
ext_of() { [ "$1" = windows ] && echo .exe || true; }
empty_dir() { mkdir -p "$1"; [ -z "$(ls -A "$1")" ] || die "$1 is not empty"; }
checkout_root() { git -C "$here" rev-parse --show-toplevel; }
outside_checkout() {
  local p r
  p=$(cd "$1" && pwd -P); r=$(cd "$2" && pwd -P)
  case "$p/" in "$r/"*) die "$1 is inside the checkout; the kit is written outside it" ;; esac
}
version_line() { # <module> <commit>
  # Go stamps a build from a clean clone of an untagged commit with the version
  # v0.0.0-<committer time, UTC, %Y%m%d%H%M%S>-<first 12 hex of the commit>.
  # The time is the commit's, read with git; never this machine's clock.
  local line ct date
  ct=$(git -C "$here" show -s --format=%ct "$2") || die "cannot read the committer time of $2 with git in $here"
  [[ "$ct" =~ ^[0-9]+$ ]] || die "the committer time of $2 reads '$ct', not a count of seconds"
  date=$("$py" -I -c 'import datetime, sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y%m%d%H%M%S"))' "$ct")
  [[ "$date" =~ ^[0-9]{14}$ ]] || die "the committer time $ct of $2 renders as '$date'"
  line=$(cat "$here/version-line.txt.in")
  line=${line//<module>/$1}; line=${line//<date>/$date}; line=${line//<sha12>/${2:0:12}}
  line=${line//<go version>/$KIT_GO_VERSION}
  printf '%s\n' "$line"
}

stage() {
  local out=$1 root kit os arch ext bin info gov
  need_env KIT_COMMIT KIT_GO_VERSION
  check_commit "$KIT_COMMIT"
  root=$(checkout_root)
  [ -d "$root/.git" ] || die "$root is not a clone: in a worktree, whose .git is a file, go build records no commit"
  [ "$(git -C "$root" rev-parse HEAD)" = "$KIT_COMMIT" ] || die "HEAD is $(git -C "$root" rev-parse HEAD), not $KIT_COMMIT"
  [ -z "$(git -C "$root" status --porcelain)" ] || die "the checkout has uncommitted or untracked files"
  gov=$(cd "$root" && go env GOVERSION)
  [ "$gov" = "go$KIT_GO_VERSION" ] || die "go is $gov, not go$KIT_GO_VERSION"
  empty_dir "$out"
  outside_checkout "$out" "$root"
  kit="$out/interop-day-kit"

  # The binaries come first, from the checkout as cloned.
  while read -r os arch; do
    ext=$(ext_of "$os")
    (cd "$root" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
      go build -trimpath -buildvcs=true -o "$kit/bin/$os-$arch/atx-verify$ext" ./cmd/atx-verify)
    say "built bin/$os-$arch/atx-verify$ext"
  done < <(targets)
  [ -z "$(git -C "$root" status --porcelain)" ] || die "the builds wrote into the checkout"
  while read -r os arch; do
    bin="$kit/bin/$os-$arch/atx-verify$(ext_of "$os")"
    info=$(cd "$root" && go version -m "$bin")
    [ "$(printf '%s\n' "$info" | head -n 1)" = "$bin: go$KIT_GO_VERSION" ] || die "$bin was not built with go$KIT_GO_VERSION"
    for want in "vcs.revision=$KIT_COMMIT" "vcs.modified=false" "-trimpath=true" "CGO_ENABLED=0" "GOOS=$os" "GOARCH=$arch"; do
      printf '%s\n' "$info" | grep -q -x -F "$(printf '\tbuild\t%s' "$want")" || die "$bin does not record $want"
    done
  done < <(targets)
  say "every binary records commit $KIT_COMMIT, no uncommitted change, go$KIT_GO_VERSION, -trimpath, CGO_ENABLED=0"

  # The tree at the commit, and nothing in it that the kit writes itself.
  if git -C "$root" ls-tree -r "$KIT_COMMIT" | awk '$1 == "120000" || $1 == "160000" { found = 1 } END { exit !found }'; then
    die "the tree holds a link or a submodule"
  fi
  for name in README-START-HERE.md CONTACT.txt PYTHON.md verify verify.cmd captures bin verifiers/python/wheels; do
    if git -C "$root" cat-file -e "$KIT_COMMIT:$name" 2>/dev/null; then die "the tree already holds $name, which the kit writes"; fi
  done
  git -C "$root" archive --format=tar "$KIT_COMMIT" | tar -x -C "$kit"
  cp "$here/launchers/verify" "$kit/verify"
  chmod 0755 "$kit/verify"
  "$py" -I -c 'import sys; d = open(sys.argv[1], "rb").read(); assert b"\r" not in d; open(sys.argv[2], "wb").write(d.replace(b"\n", b"\r\n"))' \
    "$here/launchers/verify.cmd" "$kit/verify.cmd"
  bash "$here/python_wheels.sh" fetch "$root/verifiers/python/requirements.lock" "$kit/verifiers/python/wheels"
  "$py" -I "$here/kit_files.py" archive "$kit" "$out/kit-stage.tar" --mtime 0 --plain
}

check_capture() {
  local kit=$1 capture=$2 rc_file=$3 target=$4 out=$5 os n expected bin module version prefix suffix stamp rc path
  need_env KIT_COMMIT KIT_GO_VERSION
  check_commit "$KIT_COMMIT"
  os=${target%-*}
  rc=$(tr -d ' \r\n' <"$rc_file")
  [ "$rc" = 0 ] || die "$target: the launcher exited $rc"
  n=$(find "$kit/fixtures" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')
  [ "$n" -gt 0 ] || die "no fixtures in $kit/fixtures"
  expected="summary: $n pass, 0 fail ($n fixtures)"
  [ -s "$capture" ] && [ "$(tail -c 1 "$capture" | od -An -c | tr -d ' ')" = '\n' ] || die "$target: the capture is empty or does not end with a newline"
  [ "$(tail -n 1 "$capture")" = "$expected" ] || die "$target: last line is '$(tail -n 1 "$capture")', not '$expected'"
  if grep -q '^FAIL' "$capture"; then die "$target: a FAIL line"; fi
  for path in "$(cd "$kit" && pwd -P)" "$(cd "$kit" && pwd -W 2>/dev/null || true)" "${HOME:-}" "${USERPROFILE:-}"; do
    [ ${#path} -gt 1 ] || continue
    if grep -q -F "$path" "$capture"; then die "$target: the capture holds the absolute path $path"; fi
  done
  bin="$kit/bin/$target/atx-verify$(ext_of "$os")"
  module=$(awk '$1 == "module" { print $2; exit }' "$kit/go.mod")
  version=$("$bin" --version | tr -d '\r')
  # check-capture runs in the unpacked kit, which is not a repository, and runs
  # no Python, so it does not read the commit's time: the line must be the one
  # Go stamps for a clean build of KIT_COMMIT with go$KIT_GO_VERSION, with 14
  # ASCII digits where the time goes and every other character compared as a
  # fixed string. kit() compares the whole line, the time included, where the
  # checkout is.
  prefix="atx-verify: $module v0.0.0-"
  suffix="-${KIT_COMMIT:0:12}, built with go$KIT_GO_VERSION"
  stamp=${version#"$prefix"}
  stamp=${stamp%"$suffix"}
  [[ "$stamp" =~ ^[0123456789]{14}$ ]] && [ "$prefix$stamp$suffix" = "$version" ] ||
    die "$target: --version prints '$version', not '${prefix}<14 digits>${suffix}'"
  mkdir -p "$out"
  cp "$capture" "$out/$target.txt"
  printf '%s\n' "$version" >"$out/$target.version"
  hash_of "$bin" >"$out/$target.sha256"
  say "$target: exit 0, $expected, $version"
}

kit() {
  local stage_tar=$1 caps=$2 out=$3 root kit work n expected module want os arch target bin
  local tested=() not_tested=() all=() f5=false commit_time vpy python_last d7 lines
  need_env KIT_TAG KIT_REPO KIT_COMMIT KIT_GO_VERSION
  check_tag "$KIT_TAG"; check_repo "$KIT_REPO"; check_commit "$KIT_COMMIT"
  root=$(checkout_root)
  [ "$(git -C "$root" rev-parse HEAD)" = "$KIT_COMMIT" ] || die "HEAD is $(git -C "$root" rev-parse HEAD), not $KIT_COMMIT"
  empty_dir "$out"
  outside_checkout "$out" "$root"
  kit="$out/interop-day-kit"
  work=$(mktemp -d)
  KIT_WORK=$work
  trap 'rm -rf "$KIT_WORK"' EXIT
  "$py" -I "$here/kit_files.py" extract "$stage_tar" "$out"

  n=$(find "$kit/fixtures" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')
  expected="summary: $n pass, 0 fail ($n fixtures)"
  module=$(awk '$1 == "module" { print $2; exit }' "$kit/go.mod")
  want=$(version_line "$module" "$KIT_COMMIT")
  mkdir "$kit/captures"
  for f in "$caps"/*; do
    [ -e "$f" ] || continue
    target=$(basename "$f"); target=${target%.*}
    targets | awk -v t="$target" '$1 "-" $2 == t { found = 1 } END { exit !found }' || die "a capture for $target, which is not a kit platform"
  done
  while read -r os arch; do
    target="$os-$arch"
    all+=("$os/$arch")
    bin="$kit/bin/$target/atx-verify$(ext_of "$os")"
    if [ -f "$caps/$target.txt" ]; then
      [ "$(cat "$caps/$target.sha256")" = "$(hash_of "$bin")" ] || die "$target: the binary that ran is not the binary in the kit"
      [ "$(tail -n 1 "$caps/$target.txt")" = "$expected" ] || die "$target: the capture's last line is not '$expected'"
      [ "$(cat "$caps/$target.version")" = "$want" ] || die "$target: the version line is not '$want'"
      cp "$caps/$target.txt" "$kit/captures/$target.txt"
      tested+=("$os/$arch")
    else
      not_tested+=("$os/$arch")
    fi
  done < <(targets)
  [ "${#tested[@]}" -gt 0 ] || die "no platform ran the fixtures"
  say "captures: ${#tested[@]} platforms ran all $n fixtures; not tested: ${not_tested[*]:-none}"

  # The Python verifier, installed offline from the kit's own wheels.
  "$py" -m venv "$work/venv"
  vpy="$work/venv/bin/python"
  "$vpy" -I -m pip install --disable-pip-version-check --quiet --no-index \
    --find-links "$kit/verifiers/python/wheels" --only-binary=:all: --require-hashes \
    -r "$kit/verifiers/python/requirements.lock"
  (cd "$kit" && "$vpy" -B verifiers/python/verify.py fixtures) >"$work/python.txt" || die "the Python verifier failed on the kit's fixtures"
  python_last=$(tail -n 1 "$work/python.txt")
  [ "$python_last" = "$expected" ] || die "the Python verifier's last line is '$python_last', not '$expected'"
  say "Python verifier, installed offline from the kit: $python_last"

  # Whether the verifiers print raw control characters from the files they read.
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) target=darwin-arm64 ;; Darwin-x86_64) target=darwin-amd64 ;;
    Linux-x86_64) target=linux-amd64 ;; Linux-aarch64|Linux-arm64) target=linux-arm64 ;;
    *) die "no kit binary runs on $(uname -s)-$(uname -m)" ;;
  esac
  if "$py" -I "$here/terminal_probe.py" "$kit/fixtures/wrong-issuer.json" "$kit/bin/$target/atx-verify" \
      "$vpy" "$kit/verifiers/python/verify.py"; then
    f5=false
  else
    [ $? -eq 1 ] || die "the terminal-safety probe did not run"
    f5=true
    say "the verifiers print raw control characters: the README and the notes carry the warning"
  fi

  commit_time=$(git -C "$root" show -s --format=%ct "$KIT_COMMIT")
  "$py" -I - "$work/facts.json" "$KIT_COMMIT" "$KIT_TAG" "$KIT_REPO" "$workflow_file" "$n" "$expected" \
    "$python_last" "$commit_time" "$f5" "${#all[@]}" "${all[@]}" "${#tested[@]}" "${tested[@]}" \
    "${not_tested[@]+"${not_tested[@]}"}" <<'PY'
import json, sys
a = sys.argv[1:]
out, sha, tag, repo, wf, n, expected, py_last, ctime, f5 = a[:10]
rest = a[10:]
k = int(rest[0]); targets = rest[1:1 + k]; rest = rest[1 + k:]
k = int(rest[0]); tested = rest[1:1 + k]; not_tested = rest[1 + k:]
json.dump({"sha": sha, "tag": tag, "repo": repo, "workflow": wf, "n": int(n), "expected": expected,
           "pythonExpected": py_last, "commitTime": int(ctime), "f5": f5 == "true",
           "targets": targets, "tested": tested, "notTested": not_tested},
          open(out, "w"), indent=2)
PY
  "$py" -I "$here/render.py" texts "$work/facts.json" "$here/templates" "$kit" "$out"

  "$py" -I "$here/label_census.py" "$kit"

  "$py" -I "$here/kit_files.py" sums "$kit" >"$out/SHA256SUMS"
  (cd "$kit" && sha256 -c "$out/SHA256SUMS") >"$work/check.txt" || die "sha256sum -c failed on the kit"
  lines=$(wc -l <"$out/SHA256SUMS" | tr -d ' ')
  [ "$(grep -c ': OK$' "$work/check.txt")" = "$lines" ] || die "sha256sum -c did not say OK on every line"
  say "sha256sum -c: $lines of $lines OK"
  "$py" -I "$here/kit_files.py" listcheck "$kit" "$out/SHA256SUMS"

  d7=$(bash "$here/kit-check.sh" "$kit")
  printf '%s\n' "$d7"
  [ "$(printf '%s\n' "$d7" | awk -F': ' '{ printf "%s ", $NF }')" = "1 1 1 1 " ] || die "the data protection kit check did not print 1 on each of its four lines"

  "$py" -I "$here/kit_files.py" archive "$kit" "$out/interop-day-kit.tar.gz" --mtime "$commit_time"
  "$py" -I "$here/kit_files.py" extract "$out/interop-day-kit.tar.gz" "$work/unpacked"
  (cd "$work/unpacked/interop-day-kit" && sha256 -c "$out/SHA256SUMS") >/dev/null || die "sha256sum -c failed on the archive"
  "$py" -I "$here/kit_files.py" listcheck "$work/unpacked/interop-day-kit" "$out/SHA256SUMS"
  for f in "$work/unpacked/interop-day-kit/verify" "$work/unpacked/interop-day-kit"/bin/*/atx-verify*; do
    [ -x "$f" ] || die "the archive drops the execute bit of ${f#"$work/unpacked/"}"
  done
  say "kit: $lines files; SHA256SUMS $(hash_of "$out/SHA256SUMS"); interop-day-kit.tar.gz $(hash_of "$out/interop-day-kit.tar.gz")"
}

claims() {
  local out=$1 caps=$2 files=()
  for f in "$caps"/*.version; do [ -e "$f" ] && files+=("$f"); done
  "$py" -I "$here/render.py" check-claims "$out/release-notes.md" ${files[@]+"${files[@]}"}
}

host_target() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) echo darwin-arm64 ;; Darwin-x86_64) echo darwin-amd64 ;;
    Linux-x86_64) echo linux-amd64 ;; Linux-aarch64|Linux-arm64) echo linux-arm64 ;;
    *) die "no kit binary runs on $(uname -s)-$(uname -m)" ;;
  esac
}

local_run() {
  local out=$1 host
  empty_dir "$out"
  host=$(host_target)
  stage "$out/stage"
  "$py" -I "$here/kit_files.py" extract "$out/stage/kit-stage.tar" "$out/run"
  (cd "$out/run/interop-day-kit" || exit 1; set +e; ./verify >"$out/run/capture.txt"; echo $? >"$out/run/capture.rc")
  check_capture "$out/run/interop-day-kit" "$out/run/capture.txt" "$out/run/capture.rc" "$host" "$out/captures"
  kit "$out/stage/kit-stage.tar" "$out/captures" "$out/dist"
}

case "${1:-}" in
  stage) [ $# -eq 2 ] || die "usage: assemble.sh stage <out-dir>"; stage "$2" ;;
  check-capture) [ $# -eq 6 ] || die "usage: assemble.sh check-capture <kit-dir> <capture> <exit-code-file> <os>-<arch> <out-dir>"; check_capture "$2" "$3" "$4" "$5" "$6" ;;
  kit) [ $# -eq 4 ] || die "usage: assemble.sh kit <kit-stage.tar> <captures-dir> <out-dir>"; kit "$2" "$3" "$4" ;;
  claims) [ $# -eq 3 ] || die "usage: assemble.sh claims <out-dir> <captures-dir>"; claims "$2" "$3" ;;
  local) [ $# -eq 2 ] || die "usage: assemble.sh local <out-dir>"; local_run "$2" ;;
  *) die "usage: assemble.sh stage|check-capture|kit|claims|local ..." ;;
esac
