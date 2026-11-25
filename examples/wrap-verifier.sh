#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Puts a verifier that prints its verdict as text behind the kit's command contract: exit 0 ACCEPT, exit 1 REJECT, exit 2 couldn't read.
# Run: atx-verify --verifier "sh wrap-verifier.sh {file} <your verifier command>" (- for {file} passes stdin), with ACCEPT_TEXT and REJECT_TEXT set to what it prints.
file=$1; shift
accept=${ACCEPT_TEXT:-"observed: ACCEPT"}; reject=${REJECT_TEXT:-"observed: REJECT"}
if [ "$file" = - ]; then out=$("$@" 2>&1); else out=$("$@" "$file" 2>&1); fi
line=$(printf '%s\n' "$out" | grep -F -m 1 -e "$reject" -e "$accept" | tr -d '\000-\037' | sed 's/^ *//')
reason=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
case "$line" in
  *"$reject"*) printf '{"verdict":"REJECT","reason":"%s"}\n' "$reason"; exit 1 ;;
  *"$accept"*) printf '{"verdict":"ACCEPT","reason":"%s"}\n' "$reason"; exit 0 ;;
esac
printf '%s\n' "$out"; exit 2
