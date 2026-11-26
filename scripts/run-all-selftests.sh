#!/usr/bin/env bash
# run-all-selftests -- runs each tool's --selftest and prints ran, skipped and exception per tool.
# A tool with no --selftest fails unless test/selftest-exceptions.tsv names it with a reason,
# an owner and an expiry wave. Fewer tools than the pinned floor, or none passing, is VOID.
# A tool that exits 0 without printing an OK line failed and swallowed it. Exceptions can't pass the pinned ceiling.
# Run it through test/cleanroom.sh. Exit: 0 all ok, 1 a tool failed, 2 VOID.
# usage: run-all-selftests.sh | --selftest
set -uo pipefail
# every tool this runner starts inherits an address-space ceiling: a suite that
# loses its bounds dies alone instead of eating the box
ulimit -v 1048576 2>/dev/null || true
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
FLOOR=${RUN_ALL_FLOOR:-30}
CEILING=${RUN_ALL_CEILING:-0}
EXC="$ROOT/test/selftest-exceptions.tsv"
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT

selftest() {
  local me rc=0 r out i
  me=$(readlink -f -- "$0")
  fx() { # a fresh tree holding this script and n passing tools
    rm -rf "${T:?}/fx"; mkdir -p "$T/fx/bin" "$T/fx/scripts" "$T/fx/test"; cp "$me" "$T/fx/scripts/run-all-selftests.sh"
    for i in $(seq 1 "$1"); do printf '#!/bin/sh\n# --selftest\necho "selftest: OK"\n' > "$T/fx/bin/t$i"; chmod +x "$T/fx/bin/t$i"; done
  }
  run() { out=$(RUN_ALL_FLOOR=2 RUN_ALL_CEILING=${1:-1} "$T/fx/scripts/run-all-selftests.sh" 2>&1); r=$?; }
  fx 2; run; { [ $r = 0 ] && printf '%s' "$out" | grep -q '^ran=2 ok=2 fail=0'; } || { echo "A green: rc=$r $out"; rc=1; }
  fx 1; run; [ $r = 2 ] || { echo "B below the floor isn't VOID: rc=$r"; rc=1; }
  fx 0; run; [ $r = 2 ] || { echo "C nothing ran isn't VOID: rc=$r"; rc=1; }
  fx 2; printf '#!/bin/sh\n# --selftest\nexit 1\n' > "$T/fx/bin/bad"; chmod +x "$T/fx/bin/bad"; run
  { [ $r = 1 ] && printf '%s' "$out" | grep -q '^FAIL bad'; } || { echo "D failing tool: rc=$r $out"; rc=1; }
  fx 2; printf '#!/bin/sh\n# --selftest\nexit 0\n' > "$T/fx/bin/mute"; chmod +x "$T/fx/bin/mute"; run
  [ $r = 1 ] || { echo "E a tool with no OK line passed: rc=$r"; rc=1; }
  fx 2; printf '#!/bin/sh\necho no\n' > "$T/fx/bin/none"; chmod +x "$T/fx/bin/none"; run
  [ $r = 1 ] || { echo "F no selftest and no exception passed: rc=$r"; rc=1; }
  printf 'none\twhy\twho\tR3\n' > "$T/fx/test/selftest-exceptions.tsv"; run
  { [ $r = 0 ] && printf '%s' "$out" | grep -q 'exceptions=1'; } || { echo "G exception: rc=$r $out"; rc=1; }
  printf 'none\twhy\twho\tR3\n' > "$T/fx/test/selftest-exceptions.tsv"; run 0
  [ $r = 1 ] || { echo "G2 exceptions past the ceiling passed: rc=$r"; rc=1; }
  printf 'none\n' > "$T/fx/test/selftest-exceptions.tsv"; run
  [ $r = 1 ] || { echo "H an exception with no reason passed: rc=$r"; rc=1; }
  fx 2; printf '#!/bin/sh\n# --selftest\necho "selftest: OK"\nexit 1\n' > "$T/fx/bin/liar"; chmod +x "$T/fx/bin/liar"; run
  [ $r = 1 ] || { echo "I an OK line with exit 1 passed: rc=$r"; rc=1; }
  fx 0; for i in 1 2; do printf '#!/bin/sh\n# --selftest\nexit 1\n' > "$T/fx/bin/f$i"; chmod +x "$T/fx/bin/f$i"; done; run
  [ $r = 2 ] || { echo "J nothing passing isn't VOID: rc=$r"; rc=1; }
  fx 2; ln -s nowhere "$T/fx/bin/ghost"; run
  [ $r = 1 ] || { echo "K a dangling link passed: rc=$r"; rc=1; }
  if [ $rc = 0 ]; then echo "selftest: OK (green, floor, none, failing, mute, no selftest, exceptions, liar, nothing passing, dangling link)"; else echo "selftest: FAIL"; fi
  exit $rc
}
[ "${1:-}" = --selftest ] && selftest

ok=0 fail=0 skipped=0 ran=0 failed=()
for f in "$ROOT"/bin/* "$ROOT"/scripts/*; do
  name=$(basename "$f")
  if [ -L "$f" ] && [ ! -e "$f" ]; then printf 'FAIL %s is a dangling link\n' "$name"; fail=$((fail+1)); failed+=("$name"); continue; fi
  [ -f "$f" ] || continue
  [ "$name" = run-all-selftests.sh ] && continue
  if ! grep -q -- '--selftest' "$f"; then
    if [ -f "$EXC" ] && awk -F'\t' -v n="$name" '$1==n && $2!="" && $3!="" && $4!="" {f=1} END{exit !f}' "$EXC"; then
      printf 'EXCEPTION %s\n' "$name"; skipped=$((skipped+1))
    else
      printf 'FAIL %s has no selftest and no exception\n' "$name"; fail=$((fail+1)); failed+=("$name")
    fi
    continue
  fi
  ran=$((ran+1))
  # To a file: a child left holding stdout must not outlast the timeout.
  timeout -k 5 300 "$f" --selftest >"$T/out" 2>&1 </dev/null; rc=$?
  if [ "$rc" = 0 ] && grep -q ': OK' "$T/out"; then
    printf 'OK   %-28s %s\n' "$name" "$(tail -1 "$T/out" | cut -c1-90)"; ok=$((ok+1))
  else
    printf 'FAIL %s rc=%s\n%s\n---\n' "$name" "$rc" "$(cat "$T/out")"; fail=$((fail+1)); failed+=("$name")
  fi
done
exceptions=0; [ -f "$EXC" ] && exceptions=$(grep -cv '^#\|^$' "$EXC")
printf 'ran=%d ok=%d fail=%d skipped=%d exceptions=%d floor=%d\n' "$ran" "$ok" "$fail" "$skipped" "$exceptions" "$FLOOR"
[ "$fail" -gt 0 ] && printf 'failed: %s\n' "${failed[*]}"
if [ "$ok" = 0 ] || [ "$ran" -lt "$FLOOR" ]; then echo "run-all-selftests: VOID, ran $ran with $ok ok, floor $FLOOR" >&2; exit 2; fi
[ "$exceptions" -le "$CEILING" ] || { echo "run-all-selftests: $exceptions exceptions, the pinned ceiling is $CEILING" >&2; exit 1; }
[ "$fail" = 0 ]
