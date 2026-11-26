#!/usr/bin/env bash
# run-first-level-selftests -- runs each tool's first-level selftest: the arms that need
# bwrap, which can't start inside test/cleanroom.sh on hosts with AppArmor's userns
# restriction. Decision 35: these lines need no login, so CI runs this outside the room,
# never in an agent's box and never as the production UID. The room's own proof lives
# here too, which is why this must not be wrapped in the room it tests.
# A tool that exits 0 without an OK line failed and swallowed it. Fewer tools than the
# pinned floor, or none passing, is VOID. Its own --selftest runs on fixtures and is
# room-safe, so the in-room battery covers it.
# usage: run-first-level-selftests.sh | --selftest     exit: 0 all ok, 1 a tool failed, 2 VOID
set -uo pipefail
# this runner works outside the room, so it carries its own ceiling down to every
# tool: nothing it starts can outgrow the host, whatever the tool forgets
ulimit -v 1048576 2>/dev/null || true
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
FLOOR=${FIRST_LEVEL_FLOOR:-7}
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT

selftest() {
  local me rc=0 i out r
  me=$(readlink -f -- "$0")
  fx() { # a fresh tree holding this script, a fake room and n passing tools
    rm -rf "${T:?}/fx"; mkdir -p "$T/fx/scripts" "$T/fx/test"; cp "$me" "$T/fx/scripts/run-first-level-selftests.sh"
    printf '#!/bin/sh\n# --first-level\necho "first-level: OK"\n' > "$T/fx/test/cleanroom.sh"; chmod +x "$T/fx/test/cleanroom.sh"
    for i in $(seq 1 "$1"); do printf '#!/bin/sh\n# --first-level\necho "first-level: OK"\n' > "$T/fx/scripts/t$i"; chmod +x "$T/fx/scripts/t$i"; done
  }
  run() { out=$(FIRST_LEVEL_FLOOR="${1:-2}" "$T/fx/scripts/run-first-level-selftests.sh" 2>&1); r=$?; }
  fx 0; run 1; { [ "$r" = 0 ] && printf '%s' "$out" | grep -q '^ran=1 ok=1 fail=0 floor=1$'; } || { echo "A green: rc=$r $out"; rc=1; }
  fx 0; run; [ "$r" = 2 ] || { echo "B below the floor isn't VOID: rc=$r"; rc=1; }
  fx 1; run; { [ "$r" = 0 ] && printf '%s' "$out" | grep -q '^ran=2 ok=2 fail=0 floor=2$'; } || { echo "C a listed tool joins the count: rc=$r $out"; rc=1; }
  printf '#!/bin/sh\n# --first-level\nexit 1\n' > "$T/fx/scripts/t1"; run; { [ "$r" = 1 ] && printf '%s' "$out" | grep -q '^FAIL scripts/t1'; } || { echo "D failing tool: rc=$r $out"; rc=1; }
  printf '#!/bin/sh\n# --first-level\nexit 0\n' > "$T/fx/scripts/t1"; run
  [ "$r" = 1 ] || { echo "E a tool with no OK line passed: rc=$r"; rc=1; }
  if [ $rc = 0 ]; then echo "selftest: OK (green, floor, listed tools, failing, mute)"; else echo "selftest: FAIL"; fi
  exit $rc
}
[ "${1:-}" = --selftest ] && selftest

ok=0 fail=0 ran=0 failed=()
tools=(test/cleanroom.sh)
for f in "$ROOT"/bin/* "$ROOT"/scripts/*; do
  name=$(basename "$f")
  [ "$name" = run-first-level-selftests.sh ] && continue
  if [ -f "$f" ] && grep -q -- '--first-level' "$f"; then tools+=("${f#"$ROOT"/}"); fi
done
for rel in "${tools[@]}"; do
  ran=$((ran+1))
  # To a file: a child left holding stdout must not outlast the timeout.
  timeout -k 5 300 "$ROOT/$rel" --first-level >"$T/out" 2>&1 </dev/null; rc=$?
  if [ "$rc" = 0 ] && grep -q ': OK' "$T/out"; then
    printf 'OK   %-28s %s\n' "$rel" "$(tail -1 "$T/out" | cut -c1-90)"; ok=$((ok+1))
  else
    printf 'FAIL %s rc=%s\n%s\n---\n' "$rel" "$rc" "$(cat "$T/out")"; fail=$((fail+1)); failed+=("$rel")
  fi
done
printf 'ran=%d ok=%d fail=%d floor=%d\n' "$ran" "$ok" "$fail" "$FLOOR"
[ "$fail" -gt 0 ] && printf 'failed: %s\n' "${failed[*]}"
if [ "$ok" = 0 ] || [ "$ran" -lt "$FLOOR" ]; then echo "run-first-level-selftests: VOID, ran $ran with $ok ok, floor $FLOOR" >&2; exit 2; fi
[ "$fail" = 0 ]
