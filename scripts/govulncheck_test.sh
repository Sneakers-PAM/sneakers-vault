#!/usr/bin/env bash
# Checks scripts/govulncheck.sh against saved govulncheck JSON with an empty
# allow list: any called finding fails (GO-2026-6443 included, now that it is no
# longer allowed), and an uncalled finding passes.
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
expect fail allowed-only.json
expect fail other-called.json
expect pass other-uncalled.json
exit "$fail"
