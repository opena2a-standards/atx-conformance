#!/usr/bin/env bash
# The Python verifier's dependencies for the interop day kit: wheels only,
# for every platform and CPython version in python-targets.txt, each pinned
# by exact version and SHA-256 in verifiers/python/requirements.lock.
#
#   python_wheels.sh lock  <out-lock> <name==version>...
#       Downloads, with no hashes, the wheels of exactly these pins for every
#       target and writes the lock: one line per package, every wheel's hash.
#   python_wheels.sh fetch <lock> <dest-dir>
#       Downloads every target's wheels with --require-hashes against the
#       lock, then runs check.
#   python_wheels.sh check <lock> <wheel-dir>
#       Refuses unless the directory holds wheels only (0 source
#       distributions) and the set of their SHA-256 values equals the set the
#       lock lists, each under the package its file name names.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
targets="$here/python-targets.txt"
py=${KIT_PYTHON:-python3}

die() { echo "python_wheels: $*" >&2; exit 1; }

# The interpreter that runs pip evaluates the dependency markers: on CPython
# 3.10 or older, cryptography asks for typing-extensions, which the targets
# (3.11 and newer) never need.
"$py" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "run with CPython 3.11 or newer (set KIT_PYTHON)"

versions=()
plat_names=()
plat_tags=()
while read -r first rest; do
  case "$first" in ''|'#'*) continue ;; esac
  if [ "$first" = versions ]; then
    read -r -a versions <<<"$rest"
  else
    plat_names+=("$first")
    plat_tags+=("$rest")
  fi
done <"$targets"
[ "${#versions[@]}" -gt 0 ] || die "no versions line in $targets"
[ "${#plat_names[@]}" -gt 0 ] || die "no platform lines in $targets"

# download <dest> <extra pip args...>: one pip download per target.
download() {
  local dest=$1; shift
  local i v tags args
  for i in "${!plat_names[@]}"; do
    read -r -a tags <<<"${plat_tags[$i]}"
    args=()
    for t in "${tags[@]}"; do args+=(--platform "$t"); done
    for v in "${versions[@]}"; do
      echo "python_wheels: ${plat_names[$i]} CPython $v" >&2
      "$py" -I -m pip download --disable-pip-version-check --quiet \
        --only-binary=:all: --implementation cp --python-version "$v" \
        --abi "cp${v/./}" "${args[@]}" --dest "$dest" "$@"
    done
  done
}

check() {
  "$py" -I - "$1" "$2" <<'PY'
import hashlib, pathlib, re, sys

lock_path, wheel_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

pins, hashes, current = {}, {}, None
for raw in lock_path.read_text(encoding="utf-8").splitlines():
    line = raw.split("#", 1)[0].strip().rstrip("\\").strip()
    if not line:
        continue
    for token in line.split():
        if token.startswith("--hash="):
            algo, _, value = token[len("--hash="):].partition(":")
            if algo != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", value) or current is None:
                sys.exit(f"python_wheels: malformed hash in the lock: {token}")
            hashes.setdefault(current, set()).add(value)
        else:
            m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.]+)", token)
            if not m:
                sys.exit(f"python_wheels: the lock pins every line with ==: {token}")
            current = norm(m.group(1))
            if current in pins:
                sys.exit(f"python_wheels: {current} is pinned twice")
            pins[current] = m.group(2)
if not pins:
    sys.exit("python_wheels: the lock pins nothing")
for name in pins:
    if not hashes.get(name):
        sys.exit(f"python_wheels: {name} has no --hash in the lock")

files = sorted(p for p in wheel_dir.iterdir())
not_wheels = [p.name for p in files if not (p.is_file() and p.name.endswith(".whl"))]
if not_wheels:
    sys.exit("python_wheels: not a wheel (source distributions and other files refuse): " + ", ".join(not_wheels))
seen = {}
for p in files:
    name, version = p.name.split("-")[:2]
    name = norm(name)
    if pins.get(name) != version:
        sys.exit(f"python_wheels: {p.name} is not the version the lock pins ({name}=={pins.get(name)})")
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    if digest not in hashes[name]:
        sys.exit(f"python_wheels: {p.name} has a SHA-256 the lock does not list")
    seen.setdefault(name, set()).add(digest)
for name, want in hashes.items():
    missing = want - seen.get(name, set())
    if missing:
        sys.exit(f"python_wheels: the lock lists {len(missing)} hash(es) of {name} that no wheel here has")
print(f"python_wheels: {len(files)} wheels, {len(pins)} packages, 0 source distributions, "
      f"every SHA-256 equal to the lock")
PY
}

cmd=${1:-}
case "$cmd" in
  lock)
    [ $# -ge 3 ] || die "usage: python_wheels.sh lock <out-lock> <name==version>..."
    out=$2; shift 2
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    download "$tmp/w" --no-deps "$@"
    "$py" -I - "$tmp/w" "$out" "$@" <<'PY'
import hashlib, pathlib, re, sys
wheel_dir, out, pins = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3:]
def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()
by_name = {}
for p in sorted(wheel_dir.iterdir()):
    if not p.name.endswith(".whl"):
        sys.exit(f"python_wheels: not a wheel: {p.name}")
    by_name.setdefault(norm(p.name.split("-")[0]), set()).add(hashlib.sha256(p.read_bytes()).hexdigest())
lines = [
    "# The Python verifier's dependencies as the interop day kit ships them:",
    "# wheels only, for CPython 3.11 to 3.15 on macOS, Linux and Windows (arm64",
    "# and amd64), each pinned by exact version and the SHA-256 of every wheel.",
    "# Written by: bash scripts/kit/python_wheels.sh lock verifiers/python/requirements.lock "
    + " ".join(pins),
    "# The kit installs them offline as its PYTHON.md says.",
]
for pin in sorted(pins, key=lambda s: norm(s.split("==")[0])):
    name = norm(pin.split("==")[0])
    if name not in by_name:
        sys.exit(f"python_wheels: no wheel was downloaded for {pin}")
    lines.append(pin + " \\")
    hs = sorted(by_name[name])
    for i, h in enumerate(hs):
        lines.append(f"    --hash=sha256:{h}" + (" \\" if i < len(hs) - 1 else ""))
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"python_wheels: wrote {out} ({sum(len(v) for v in by_name.values())} wheels, {len(by_name)} packages)")
PY
    ;;
  fetch)
    [ $# -eq 3 ] || die "usage: python_wheels.sh fetch <lock> <dest-dir>"
    mkdir -p "$3"
    download "$3" --require-hashes -r "$2"
    check "$2" "$3"
    ;;
  check)
    [ $# -eq 3 ] || die "usage: python_wheels.sh check <lock> <wheel-dir>"
    check "$2" "$3"
    ;;
  *)
    die "usage: python_wheels.sh lock|fetch|check ..."
    ;;
esac
