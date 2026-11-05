#!/bin/bash
# Data protection check for the interop day kit. Usage: kit-check.sh <path to interop-day-kit>
# Run it on the machine that built the kit. Each line must print exactly 1: the witness's own hit.
# More than 1 is a finding; 0 means the instrument is broken.
usage='usage: kit-check.sh <path to interop-day-kit>
       kit-check.sh -h | --help'
# -h or --help prints the usage on stdout. Any other option is named on stderr
# above the usage, and the script exits 2 before it reads anything else.
want_help=0 unknown=
for opt in "$@"; do
  case "$opt" in
    -h|--help) want_help=1 ;;
    -?*) unknown="${unknown:+$unknown }$opt" ;;
  esac
done
if [ -n "$unknown" ]; then printf 'unknown argument(s): %s\n%s\n' "$unknown" "$usage" >&2; exit 2; fi
if [ "$want_help" = 1 ]; then printf '%s\n' "$usage"; exit 0; fi
K="$1"; W=$(mktemp -d)
mkdir "$W/.git"; printf '%s\n' "$HOME" > "$W/h.txt"
printf 'witness@kit-check-control.org\nhttps://example.org/?witness=1\n' > "$W/w.txt"
echo "1 metadata entries: $(find "$K" "$W" \( -name .git -o -name '*.pyc' -o -name __pycache__ -o -name pyvenv.cfg -o -name .DS_Store -o -name '._*' \) | wc -l | tr -d ' ')"
echo "2 files with the builder home path: $(grep -r -a -l -F "$HOME" "$K" "$W/h.txt" | wc -l | tr -d ' ')"
echo "3 addresses outside the contact and example domains: $(grep -r -a -h -o -E --exclude-dir='*.dist-info' --exclude-dir='*.egg-info' '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$K" "$W/w.txt" | tr 'A-Z' 'a-z' | sort -u | grep -c -v -x -E 'info@opena2a\.org|[^@]+@([a-z0-9-]+\.)*(example|invalid)|[^@]+@example\.(com|org|net)')"
echo "4 links with a query or another host: $(cat "$K/CONTACT.txt" "$K/README-START-HERE.md" "$W/w.txt" 2>/dev/null | grep -o -E 'https?://[^] )>"`]+' | grep -c -v -x -E 'https://(github\.com/opena2a-(standards|org)/[A-Za-z0-9._/-]+|datatracker\.ietf\.org/doc/[A-Za-z0-9._/-]+|opena2a\.org/[A-Za-z0-9._/-]*)(#[A-Za-z0-9._-]+)?')"
rm -rf "$W"
