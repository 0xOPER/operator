#!/usr/bin/env bash
# pilot-export.sh -- the pilots' export: a fresh copy of exactly the public
# keep list, with R2's private-only rows stripped and the R6 strip applied.
# Pilots get the archive and NO repo access, by decision 9.
#
# The R6 strip (private-only rows that joined during R2): test/waves/R2.sh and
# its neuter patches, the closure tables (closure.tsv, protected.tsv,
# audit-map.tsv), keep-list.private, and the receipts. None of them are in the
# keep list, so the export never contains them -- this script proves it.
#
# usage: pilot-export.sh <export-dir>     exit: 0 exported, 1 a private row leaked, 2 VOID
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
if [ "${1:-}" = --selftest ]; then
  exec "$ROOT/test/lib/pilot-export-selftest.sh"
fi
DEST=${1:?usage: pilot-export.sh <export-dir>}
[ -f "$ROOT/keep-list" ] || { echo "pilot-export: VOID, no keep-list" >&2; exit 2; }
[ -e "$DEST" ] && { echo "pilot-export: VOID, $DEST exists; give a fresh dir" >&2; exit 2; }
mkdir -p "$DEST"
# the export carries exactly the keep list
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ -f "$ROOT/$f" ] || { echo "pilot-export: VOID, keep-list names missing $f" >&2; exit 2; }
  mkdir -p "$DEST/$(dirname "$f")"
  cp "$ROOT/$f" "$DEST/$f"
done < "$ROOT/keep-list"
# the private-only rows can never appear -- prove it via explicit pattern AND keep-list.private intersection
EXPORTED=$(cd "$DEST" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
LEAKS=$(printf '%s\n' "$EXPORTED" | grep -E \
  '^(forward-port\.tsv|keep-list\.private|test/agent-rules\.md|test/closure-check\.sh|test/neuters_private\.py|test/waves/R[1-9]\.sh|test/waves/neuters/|test/(closure|protected|audit-map)\.tsv)' || true)
if [ -f "$ROOT/keep-list.private" ]; then
  PRIV_HIT=$(LC_ALL=C comm -12 <(printf '%s\n' "$EXPORTED") <(LC_ALL=C sort "$ROOT/keep-list.private") || true)
  if [ -n "$PRIV_HIT" ]; then
    LEAKS=$(printf '%s\n%s\n' "$LEAKS" "$PRIV_HIT" | sed '/^$/d' | LC_ALL=C sort -u)
  fi
fi
if [ -n "$LEAKS" ]; then
  echo "pilot-export: LEAKED private rows:" >&2
  printf '%s\n' "$LEAKS" >&2
  exit 1
fi
echo "pilot-export: $(find "$DEST" -type f | wc -l) files, the keep list exactly, private rows absent"
