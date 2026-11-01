#!/usr/bin/env bash
# A tag run publishes only the kit the release test passed: its SHA256SUMS
# must be byte-equal to the SHA256SUMS of the newest successful
# workflow_dispatch run of the release workflow at the same commit. No such
# run at the commit refuses.
#
#   candidate_equal.sh <SHA256SUMS>
#
# Environment: GH_TOKEN (the job's token, with actions: read),
# GITHUB_REPOSITORY, GITHUB_SHA, KIT_WORKFLOW_NAME (kit-release.yml).
set -euo pipefail

die() { echo "candidate: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: candidate_equal.sh <SHA256SUMS>"
mine=$1
[ -f "$mine" ] || die "no file $mine"
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || die "GITHUB_SHA is not a full commit id"
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || die "GITHUB_REPOSITORY is not owner/repo"
wf=${KIT_WORKFLOW_NAME:-kit-release.yml}
[[ "$wf" =~ ^[A-Za-z0-9._-]+\.ya?ml$ ]] || die "not a workflow file name: $wf"

id=$(gh run list -R "$GITHUB_REPOSITORY" -w "$wf" -e workflow_dispatch -c "$GITHUB_SHA" -s success -L 1 \
  --json databaseId --jq '.[0].databaseId // empty')
[ -n "$id" ] || die "no successful workflow_dispatch run of $wf at $GITHUB_SHA: build the candidate first"
[[ "$id" =~ ^[0-9]+$ ]] || die "not a run id: $id"

dir=$(mktemp -d)
gh run download "$id" -R "$GITHUB_REPOSITORY" -n kit-sha256sums -D "$dir"
[ -f "$dir/SHA256SUMS" ] || die "run $id has no SHA256SUMS in its kit-sha256sums artifact"
cmp -s "$dir/SHA256SUMS" "$mine" || die "SHA256SUMS differs from the candidate's (run $id at $GITHUB_SHA)"
echo "candidate: SHA256SUMS byte-equal to the candidate's, run $id at $GITHUB_SHA"
