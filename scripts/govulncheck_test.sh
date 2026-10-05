#!/usr/bin/env bash
# Checks scripts/govulncheck.sh against saved govulncheck JSON: the allowed ID
# passes, any other called finding fails, and an uncalled finding passes.
set -euo pipefail
cd "$(dirname "$0")/.."
dir=scripts/testdata/govulncheck
fail=0
expect() {
  local want=$1 file=$2
  if scripts/govulncheck.sh "$dir/$file" >/dev/null; then got=pass; else got=fail; fi
  if [ "$got" = "$want" ]; then
    echo "ok   $file: $got"
  else
    echo "FAIL $file: got $got, want $want"
    fail=1
  fi
}
expect pass allowed-only.json
expect fail other-called.json
expect pass other-uncalled.json
exit "$fail"
