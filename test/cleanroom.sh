#!/usr/bin/env bash
# Runs a command in this checkout with your home hidden, no network, and the tree read-only.
# Write to /tmp inside. Nothing written inside survives. It's a test wrapper, not a security boundary
# for hostile code. Nested bwrap fails on hosts with AppArmor's userns restriction, so a box can't call this.
# usage: test/cleanroom.sh <cmd> [args...]     (cwd inside is /work/operator)
#        test/cleanroom.sh --first-level       the room's own proof, run outside any room
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: test/cleanroom.sh <cmd> [args...]" >&2; exit 2; }
bw=$(PATH=/usr/bin:/bin command -v bwrap) || { echo "cleanroom: VOID, bwrap not found" >&2; exit 2; }
repo=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
if [ "${1:-}" = --first-level ]; then
  # The room can't test itself nested, so this runs at first level: CI's first-level
  # battery step, or scripts/run-first-level-selftests.sh by hand. Never inside the room.
  me=$(readlink -f -- "$0"); rc=0
  "$me" sh -c '[ "$(grep -c : /proc/net/dev)" = 1 ]' || rc=1
  [ "$(grep -c : /proc/net/dev)" -gt 1 ] || rc=1
  h=$HOME
  out=$("$me" sh -c "test ! -e \"$h\" && ! touch /work/operator/.w 2>/dev/null && echo inside") || rc=1
  [ "$out" = inside ] || rc=1
  [ -e "$h" ] || rc=1
  if [ "$rc" = 0 ]; then echo "first-level: OK (net hidden, home hidden, tree read-only)"; else echo "first-level: FAIL" >&2; fi
  exit "$rc"
fi
args=(--unshare-all --new-session --die-with-parent
  --ro-bind /usr /usr --ro-bind /etc /etc
  --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/sbin /sbin
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run --tmpfs /work
  --tmpfs /home --remount-ro /home --dir /tmp/home
  --ro-bind "$repo" /work/operator --chdir /work/operator
  --setenv HOME /tmp/home --setenv USER tester --setenv LOGNAME tester
  --setenv PATH /usr/bin:/bin --setenv TMPDIR /tmp
  --setenv GIT_CONFIG_NOSYSTEM 1
  --setenv GIT_AUTHOR_NAME tester --setenv GIT_AUTHOR_EMAIL tester@example.invalid
  --setenv GIT_COMMITTER_NAME tester --setenv GIT_COMMITTER_EMAIL tester@example.invalid)
[ -e /lib64 ] && args+=(--symlink usr/lib64 /lib64)
[ -d /usr/local ] && args+=(--tmpfs /usr/local)
# Inherited descriptors reach past the mount namespace, and a socket stdin talks to whatever started us.
for f in /proc/$$/fd/*; do n=${f##*/}; [ "$n" -gt 2 ] 2>/dev/null && eval "exec $n>&-" 2>/dev/null; done
[ -S /dev/stdin ] && exec </dev/null
# env -i: bwrap's PID 1 keeps its own environ, and every tool inside can read /proc/1/environ.
exec env -i "$bw" "${args[@]}" -- "$@"
