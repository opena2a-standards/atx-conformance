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
#       bin/<os>-<arch>/, the line their --version prints in
#       bin/version-line.txt (as version-line prints it, from this checkout),
#       the launchers verify and verify.cmd, and the Python verifier's
#       wheels, downloaded with --require-hashes against the lock.
#   assemble.sh check-capture <kit-dir> <capture> <exit-code-file> <os>-<arch> <out-dir>
#       Checks one platform's run of the launcher (exit 0, last line
#       "summary: N pass, 0 fail (N fixtures)" with N the fixture count, no
#       absolute path), and that the binary's --version line is the whole
#       line in bin/version-line.txt, and writes <out-dir>/<os>-<arch>.txt,
#       .version and .sha256.
#   assemble.sh kit <kit-stage.tar> <captures-dir> <out-dir>
#       Writes <out-dir>/interop-day-kit from the stage and the captures, with
#       captures/<os>-<arch>.txt, README-START-HERE.md, CONTACT.txt and
#       PYTHON.md, and without the stage's bin/version-line.txt, the line each
#       capture's version file must hold; installs the Python verifier
#       offline from the kit and runs it; runs the label census; writes
#       <out-dir>/SHA256SUMS over every file and checks it with sha256sum -c
#       and the file-list check; runs the data protection kit check; writes
#       the release notes and title, and <out-dir>/interop-day-kit.tar.gz,
#       checked the same way.
#   assemble.sh claims <out-dir> <captures-dir>
#       Refuses when the release notes name a --version form a binary does not
#       print.
#   assemble.sh local <out-dir>
#       stage, a run of the launcher on this machine, check-capture, and kit.
#   assemble.sh version-line
#       Prints the --version line Go stamps into a clean build of KIT_COMMIT
#       with go$KIT_GO_VERSION in this checkout, from the tags it holds: the
#       line stage writes into the kit.
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
       assemble.sh version-line
       assemble.sh -h | --help'
# -h or --help prints the usage on stdout. An option other than those, or a
# first argument that names no command, is named on stderr above the usage,
# and the script exits 2 before it reads or writes anything.
want_help=0 unknown=
case "${1:-}" in ''|-?*|stage|check-capture|kit|claims|local|version-line) ;; *) unknown=$1 ;; esac
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
utc_stamp() { # <seconds>: the time as %Y%m%d%H%M%S in UTC
  local stamp
  stamp=$("$py" -I -c 'import datetime, sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y%m%d%H%M%S"))' "$1")
  [[ "$stamp" =~ ^[0-9]{14}$ ]] || die "the time $1 renders as '$stamp'"
  printf '%s\n' "$stamp"
}
version_line() { # <module>
  # The --version line Go stamps into a clean build of KIT_COMMIT in this
  # checkout, with the version Go derives from the tags the checkout holds
  # (render.py go-version): vX.Y.Z when the highest version tag on the
  # commit is vX.Y.Z; vX.Y.(Z+1)-0.<time>-<sha12> when the highest version
  # tag on the commit or an ancestor is vX.Y.Z; v0.0.0-<time>-<sha12> while
  # the commit and its ancestors carry no Go version tag. <time> is the
  # committer time of the commit, UTC, %Y%m%d%H%M%S, read with git; never
  # this machine's clock. <sha12> is the first 12 hex of the commit. Run it
  # in the checkout the binaries are built from, so that it reads the tags
  # the Go build read.
  local ct at history version line
  ct=$(git -C "$here" show -s --format=%ct "$KIT_COMMIT") || die "cannot read the committer time of $KIT_COMMIT with git in $here"
  [[ "$ct" =~ ^[0-9]+$ ]] || die "the committer time of $KIT_COMMIT reads '$ct', not a count of seconds"
  at=$(git -C "$here" for-each-ref --points-at="$KIT_COMMIT" --format='%(refname)' refs/tags) ||
    die "cannot list the tags on $KIT_COMMIT with git in $here"
  history=$(git -C "$here" for-each-ref --merged="$KIT_COMMIT" --format='%(refname)' refs/tags) ||
    die "cannot list the tags on $KIT_COMMIT and its ancestors with git in $here"
  version=$("$py" -I "$here/render.py" go-version "$KIT_COMMIT" "$ct" "$at" "$history") ||
    die "no version line for $KIT_COMMIT"
  line=$(cat "$here/version-line.txt.in")
  line=${line//<module>/$1}; line=${line//<version>/$version}; line=${line//<go version>/$KIT_GO_VERSION}
  version_form "$line" "$1" || die "the version line for $KIT_COMMIT is not in a form check-capture takes: '$line'"
  printf '%s\n' "$line"
}
version_file=bin/version-line.txt
version_form() { # <line> <module>
  # Whether <line> is a --version line of <module> built with
  # go$KIT_GO_VERSION whose version is in one of the three forms
  # version_line writes. The two pseudo-version forms must end in the first
  # 12 hex of KIT_COMMIT. The form vX.Y.Z names no commit, so this check
  # does not tie it to KIT_COMMIT. Bash only: check-capture runs it with no
  # git and no Python.
  local v sha12=${KIT_COMMIT:0:12} n='(0|[123456789][0123456789]*)' t='[0123456789]{14}' untagged tagged after
  v=${1#"atx-verify: $2 "}
  v=${v%", built with go$KIT_GO_VERSION"}
  [ "atx-verify: $2 $v, built with go$KIT_GO_VERSION" = "$1" ] || return 1
  untagged="^v0\\.0\\.0-$t-$sha12\$"
  tagged="^v[01]\\.$n\\.$n\$"
  after="^v[01]\\.$n\\.[123456789][0123456789]*-0\\.$t-$sha12\$"
  [[ "$v" =~ $untagged ]] || [[ "$v" =~ $tagged ]] || [[ "$v" =~ $after ]]
}
stage_line() { # <kit-dir> <module>
  # The line stage wrote into the kit, which every binary's --version must
  # print, once version_form has checked it: go$KIT_GO_VERSION, a version
  # in a form version_line writes and, in the two pseudo-version forms, the
  # first 12 hex of KIT_COMMIT.
  local line
  [ -f "$1/$version_file" ] || die "the kit holds no $version_file: stage writes there the line every binary's --version prints"
  line=$(cat "$1/$version_file")
  version_form "$line" "$2" ||
    die "$version_file holds '$line', not a --version line of ${KIT_COMMIT:0:12} with go$KIT_GO_VERSION in a form stage writes"
  printf '%s\n' "$line"
}

stage() {
  local out=$1 root kit os arch ext bin info gov module want
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

  # The line every binary's --version prints, derived once, here, from the
  # tags of the checkout the binaries were built from; check-capture and kit()
  # compare with it where no tag can be read.
  module=$(awk '$1 == "module" { print $2; exit }' "$root/go.mod")
  want=$(version_line "$module")
  printf '%s\n' "$want" >"$kit/$version_file"
  say "every binary's --version must print: $want"

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
  local kit=$1 capture=$2 rc_file=$3 target=$4 out=$5 os n expected bin module want version rc path
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
  # check-capture runs in the unpacked kit, which is not a repository, and runs
  # no Python, so it reads no tag and no commit time: the binary's --version
  # line must be the whole line stage derived where the checkout and its tags
  # were and wrote into the kit, once stage_line has checked that line. That
  # check holds the line to go$KIT_GO_VERSION and, in the two pseudo-version
  # forms, to the first 12 hex of KIT_COMMIT. The form vX.Y.Z names no
  # commit: stage tied the binaries to the commit with go version -m, and
  # kit() ties each capture to its binary's sha256.
  want=$(stage_line "$kit" "$module")
  version=$("$bin" --version | tr -d '\r')
  [ "$version" = "$want" ] || die "$target: --version prints '$version', not '$want'"
  mkdir -p "$out"
  cp "$capture" "$out/$target.txt"
  printf '%s\n' "$version" >"$out/$target.version"
  hash_of "$bin" >"$out/$target.sha256"
  say "$target: exit 0, $expected, $version"
}

kit() {
  local stage_tar=$1 caps=$2 out=$3 root kit work n expected module want version stamp os arch target bin
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
  # The line every capture must hold is the one stage derived from the tags
  # of the checkout the binaries were built from; this checkout may hold no
  # tag, so the version is never derived here. The commit time in it, where
  # it names one, is read again here. The file is the stage's, not a kit
  # file.
  want=$(stage_line "$kit" "$module")
  version=${want#"atx-verify: $module "}
  version=${version%", built with go$KIT_GO_VERSION"}
  commit_time=$(git -C "$root" show -s --format=%ct "$KIT_COMMIT") || die "cannot read the committer time of $KIT_COMMIT with git in $root"
  [[ "$commit_time" =~ ^[0-9]+$ ]] || die "the committer time of $KIT_COMMIT reads '$commit_time', not a count of seconds"
  stamp=$(utc_stamp "$commit_time")
  if [[ "$version" == *"-${KIT_COMMIT:0:12}" && "$version" != *[-.]"$stamp-${KIT_COMMIT:0:12}" ]]; then
    die "$version_file names $version, whose time is not $stamp, the committer time of $KIT_COMMIT"
  fi
  rm "$kit/$version_file"
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

  "$py" -I - "$work/facts.json" "$KIT_COMMIT" "$KIT_TAG" "$KIT_REPO" "$workflow_file" "$n" "$expected" \
    "$python_last" "$commit_time" "$f5" "$version" "${#all[@]}" "${all[@]}" "${#tested[@]}" "${tested[@]}" \
    "${not_tested[@]+"${not_tested[@]}"}" <<'PY'
import json, sys
a = sys.argv[1:]
out, sha, tag, repo, wf, n, expected, py_last, ctime, f5, version = a[:11]
rest = a[11:]
k = int(rest[0]); targets = rest[1:1 + k]; rest = rest[1 + k:]
k = int(rest[0]); tested = rest[1:1 + k]; not_tested = rest[1 + k:]
json.dump({"sha": sha, "tag": tag, "repo": repo, "workflow": wf, "n": int(n), "expected": expected,
           "pythonExpected": py_last, "commitTime": int(ctime), "version": version, "f5": f5 == "true",
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

print_version_line() {
  local module
  need_env KIT_COMMIT KIT_GO_VERSION
  check_commit "$KIT_COMMIT"
  module=$(awk '$1 == "module" { print $2; exit }' "$(checkout_root)/go.mod")
  [ -n "$module" ] || die "no module line in go.mod"
  version_line "$module"
}

case "${1:-}" in
  stage) [ $# -eq 2 ] || die "usage: assemble.sh stage <out-dir>"; stage "$2" ;;
  check-capture) [ $# -eq 6 ] || die "usage: assemble.sh check-capture <kit-dir> <capture> <exit-code-file> <os>-<arch> <out-dir>"; check_capture "$2" "$3" "$4" "$5" "$6" ;;
  kit) [ $# -eq 4 ] || die "usage: assemble.sh kit <kit-stage.tar> <captures-dir> <out-dir>"; kit "$2" "$3" "$4" ;;
  claims) [ $# -eq 3 ] || die "usage: assemble.sh claims <out-dir> <captures-dir>"; claims "$2" "$3" ;;
  local) [ $# -eq 2 ] || die "usage: assemble.sh local <out-dir>"; local_run "$2" ;;
  version-line) [ $# -eq 1 ] || die "usage: assemble.sh version-line"; print_version_line ;;
  *) die "usage: assemble.sh stage|check-capture|kit|claims|local|version-line ..." ;;
esac
