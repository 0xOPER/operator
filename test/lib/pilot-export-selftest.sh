#!/usr/bin/env bash
# pilot-export's selftest: the export is exactly the keep list; a planted
# private row fails the leak check. Arm D never touches the real tree (the
# room is read-only): it runs the export from a scratch COPY.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
rc=0
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT
KL_BEFORE=$(sha256sum "$ROOT/keep-list" | cut -d" " -f1)

"$ROOT/scripts/pilot-export.sh" "$T/e1" >/dev/null 2>&1 || { echo "A export green: rc=$?"; rc=1; }
# A: exactly the keep list
n=$(find "$T/e1" -type f | wc -l)
k=$(grep -c . "$ROOT/keep-list")
[ "$n" = "$k" ] || { echo "A count: exported $n vs keep-list $k"; rc=1; }

# B: a second export to an existing dir refuses
"$ROOT/scripts/pilot-export.sh" "$T/e1" >/dev/null 2>&1 && { echo "B exists refuses"; rc=1; }

# C: the leak check fires -- simulate by planting a private row in a scratch root's keep-list
mkdir -p "$T/leakroot"
tar -cf - -C "$ROOT" --exclude=.git --exclude=__pycache__ . | tar -xf - -C "$T/leakroot"
mkdir -p "$T/leakroot/test/waves"
printf 'line new fake\n' > "$T/leakroot/test/waves/R2.sh"
printf 'test/waves/R2.sh\n' >> "$T/leakroot/keep-list"
"$T/leakroot/scripts/pilot-export.sh" "$T/e2" >/dev/null 2>&1 && { echo "C leak check must refuse R2.sh"; rc=1; }

# D: a keep-list entry missing from the tree is VOID -- proven on a scratch
# COPY of the tree (the room's tree is read-only; the real one stays clean).
# The real keep-list is hashed before and after: git-diff would false-fail on
# any tree with work in flight.
mkdir -p "$T/root/scripts" "$T/root/test/lib"
tar -cf - -C "$ROOT" --exclude=.git --exclude=__pycache__ . | tar -xf - -C "$T/root"
printf 'does/not/exist.py\n' >> "$T/root/keep-list"
"$T/root/scripts/pilot-export.sh" "$T/e3" >/dev/null 2>&1 && { echo "D missing entry refuses"; rc=1; }
# and a clean keep-list on the copy still exports (the copy isn't broken)
printf '%s\n' "$(grep -v 'does/not/exist.py' "$T/root/keep-list")" > "$T/root/keep-list.tmp"
mv "$T/root/keep-list.tmp" "$T/root/keep-list"
"$T/root/scripts/pilot-export.sh" "$T/e4" >/dev/null 2>&1 || { echo "D copy exports green"; rc=1; }
# the REAL tree's keep-list never moved
[ "$(sha256sum "$ROOT/keep-list" | cut -d" " -f1)" = "$KL_BEFORE" ] \
  || { echo "D real keep-list untouched"; rc=1; }

if [ $rc = 0 ]; then echo "selftest: OK (count, exists, leak, missing)"; else echo "selftest: FAIL"; fi
exit $rc
