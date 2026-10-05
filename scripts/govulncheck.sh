#!/usr/bin/env bash
# Runs govulncheck and fails on any vulnerability the code calls unless its
# OSV ID is listed in govulncheck-allow.txt. govulncheck has no ignore flag,
# so this reads its JSON output. Module- and package-level findings (code that
# is never called) don't fail, the same as govulncheck's own default.
#
#   scripts/govulncheck.sh                # scan ./...
#   scripts/govulncheck.sh findings.json  # filter a saved -format json run
#
# GOVULNCHECK names the binary (default: govulncheck on PATH).
set -euo pipefail
cd "$(dirname "$0")/.."

allowed="$(sed -e 's/#.*//' -e 's/[[:space:]]//g' govulncheck-allow.txt | grep -v '^$' || true)"

if [ "$#" -gt 0 ]; then
  json="$(cat "$1")"
else
  json="$("${GOVULNCHECK:-govulncheck}" -format json ./...)"
fi

called="$(printf '%s' "$json" | jq -r 'select(.finding != null) | .finding | select(.trace[0].function != null) | .osv' | sort -u)"

fail=0
for id in $called; do
  if printf '%s\n' "$allowed" | grep -qxF "$id"; then
    echo "govulncheck: $id is called but allowed (see govulncheck-allow.txt)"
  else
    echo "govulncheck: $id is called and not allowed: https://pkg.go.dev/vuln/$id"
    fail=1
  fi
done
for id in $allowed; do
  if ! printf '%s\n' "$called" | grep -qxF "$id"; then
    echo "govulncheck: $id is allowed but no longer found; remove it from govulncheck-allow.txt"
  fi
done
if [ "$fail" -ne 0 ]; then
  echo "govulncheck: FAILED"
  exit 1
fi
echo "govulncheck: no disallowed findings"
