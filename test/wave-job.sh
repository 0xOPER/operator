#!/usr/bin/env bash
# wave-job -- runs a wave's acceptance script on the pre-wave commit, an empty tree and HEAD.
#   new lines:   red before the wave, red on empty, green on HEAD
#   guard lines: red on empty, green on HEAD, red under test/waves/neuters/<wave>/<id>.patch
#   lines marked local, owner, real-cli or first-level aren't run here. Each owes a receipt, so the job exits 3.
# A wave script names its pre-wave commit, then calls one row per line at column 0:
#   pre_wave <sha>
#   line <new|guard> <id> '<command>' [local|owner|real-cli|first-level]
# Commands run with cwd at the tree under test. The table goes to stdout, so tee it to keep a log.
# Exit: 0 all hold, 1 a line broke its rule, 2 VOID, 3 receipts owed or lines filtered out.
# It reads the wave script from HEAD, and refuses to run outside test/cleanroom.sh: an older tree can
# hold tools you wouldn't run on your own machine.
# usage: test/wave-job.sh <wave> <pre-wave-sha> [line-id ...] | --selftest
set -uo pipefail
if [ "${1:-}" = --selftest ]; then
  me=$(readlink -f -- "$0"); F=$(mktemp -d) || exit 2
  trap 'rm -rf "${F:?}"' EXIT
  git init -q "$F/r"; mkdir -p "$F/r/test/waves/neuters/W"; cp "$me" "$F/r/test/wave-job.sh"
  g() { git -C "$F/r" -c user.email=t@example.invalid -c user.name=t -c commit.gpgsign=false "$@"; }
  echo before > "$F/r/old"; g add -A; g commit -qm pre; p=$(git -C "$F/r" rev-parse HEAD)
  echo after > "$F/r/new"; printf 'keep\n' > "$F/r/target"
  w() { { printf 'pre_wave %s\n' "$p"; cat; } > "$F/r/test/waves/$1.sh"; }   # a wave script from stdin
  w W <<'WAVE'
line new good '[ -f new ]'
line new greenpre '[ -f old ]'
line new redhead '[ -f absent ]'
line guard greenempty '[ ! -f target ] || [ "$(cat target)" = keep ]'
line guard guarded '[ "$(cat target)" = keep ]'
line guard noneuter '[ -f new ]'
line guard survivor '[ -f new ]'
line new localonly 'false' local
WAVE
  printf -- '--- a/target\n+++ b/target\n@@ -1 +1 @@\n-keep\n+broken\n' > "$F/r/test/waves/neuters/W/guarded.patch"
  printf -- '--- a/target\n+++ b/target\n@@ -1 +1 @@\n-keep\n+broken\n' > "$F/r/test/waves/neuters/W/survivor.patch"
  cp "$F/r/test/waves/neuters/W/guarded.patch" "$F/r/test/waves/neuters/W/greenempty.patch"
  g add -A; g commit -qm wave
  export WAVE_JOB_FIXTURE=1
  out=$("$F/r/test/wave-job.sh" W "$p" 2>&1); r=$?
  st=0
  [ "$r" = 1 ] || { echo "selftest: job rc=$r, want 1"; st=1; }
  for want in 'good .* ok$' 'greenpre .* green-pre-wave$' 'redhead .* red-on-HEAD$' 'greenempty .* green-on-empty$' 'guarded .* ok$' 'noneuter .* guard-without-neuter$' 'survivor .* neuter-survived$' 'localonly .* owes a receipt'; do
    printf '%s\n' "$out" | grep -qE "$want" || { echo "selftest: missing verdict: $want"; st=1; }
  done
  printf '%s\n' "$out" | grep -qE 'ran=7 skipped=1 bad=5$' || { echo "selftest: wrong totals"; st=1; }
  "$F/r/test/wave-job.sh" nosuch "$p" >/dev/null 2>&1; [ $? = 2 ] || { echo "selftest: missing wave isn't VOID"; st=1; }
  # A clean wave with an open line is 3, and so is one with lines filtered out. With neither it's 0.
  printf "line new good '[ -f new ]'\nline new localonly 'false' local\n" | w X
  printf "line new good '[ -f new ]'\n" | w Y
  # A wave script that can't be read whole is VOID, never a verdict.
  printf "line new good '[ -f new ]'\nline new typo '[ -f new ]\nline new owed 'false' local\n" | w P
  printf "line new good '[ -f new ]'\nreturn 0\nline new owed 'false' local\n" | w Q
  printf "line new good '[ -f new ]'\nexit 0\nline new owed 'false' local\n" | w R
  printf "line new good '[ -f new ]'\ndone\n" | w T
  printf "line new redhead '[ -f absent ]'\nexit 0\n" | w S
  # So is a duplicate id, a bad tag, a wave with nothing to run, and a wrong or missing pre-wave commit.
  printf "line new a '[ -f new ]'\nline new a '[ -f new ]'\n" | w D
  printf "line bogus a '[ -f new ]'\n" | w U
  printf "line new a 'false' local\n" | w L
  : | w E
  { printf 'pre_wave %s\n' "$(git -C "$F/r" rev-parse HEAD)"; printf "line new good '[ -f new ]'\n"; } > "$F/r/test/waves/M.sh"
  printf "line new good '[ -f new ]'\n" > "$F/r/test/waves/N.sh"
  # A neuter that doesn't apply is a broken line, and a neuter only in the working copy doesn't count.
  printf "line guard nope '[ -f new ]'\n" | w A
  mkdir -p "$F/r/test/waves/neuters/A"; printf -- '--- a/gone\n+++ b/gone\n@@ -1 +1 @@\n-x\n+y\n' > "$F/r/test/waves/neuters/A/nope.patch"
  printf "line guard loose '[ \"\$(cat target)\" = keep ]'\n" | w B
  g add -A; g commit -qm more
  "$F/r/test/wave-job.sh" X "$p" >/dev/null 2>&1; [ $? = 3 ] || { echo "selftest: an open line isn't rc 3"; st=1; }
  "$F/r/test/wave-job.sh" Y "$p" >/dev/null 2>&1; [ $? = 0 ] || { echo "selftest: a clean wave isn't rc 0"; st=1; }
  "$F/r/test/wave-job.sh" X "$p" good >/dev/null 2>&1; [ $? = 3 ] || { echo "selftest: a filtered run isn't rc 3"; st=1; }
  for x in P Q R T D U L E M N; do "$F/r/test/wave-job.sh" "$x" "$p" >/dev/null 2>&1; [ $? = 2 ] || { echo "selftest: broken wave $x isn't VOID"; st=1; }; done
  "$F/r/test/wave-job.sh" S "$p" >/dev/null 2>&1; [ $? = 1 ] || { echo "selftest: an exit hid a red line"; st=1; }
  out=$("$F/r/test/wave-job.sh" A "$p" 2>&1); printf '%s\n' "$out" | grep -q 'nope .* neuter-does-not-apply$' || { echo "selftest: a neuter that doesn't apply"; st=1; }
  mkdir -p "$F/r/test/waves/neuters/B"; printf -- '--- a/target\n+++ b/target\n@@ -1 +1 @@\n-keep\n+broken\n' > "$F/r/test/waves/neuters/B/loose.patch"
  out=$("$F/r/test/wave-job.sh" B "$p" 2>&1); printf '%s\n' "$out" | grep -q 'loose .* guard-without-neuter$' || { echo "selftest: an uncommitted neuter counted"; st=1; }
  # A dirty wave script doesn't count: the job reads the commit.
  printf "line new good 'true'\n" | w Y
  out=$("$F/r/test/wave-job.sh" Y "$p" 2>&1); printf '%s\n' "$out" | grep -q 'good .* ok$' || { echo "selftest: the job read a dirty script"; st=1; }
  # Outside the wrapper it refuses to run.
  (cd "$F/r" && env -u WAVE_JOB_FIXTURE test/wave-job.sh Y "$p" >/dev/null 2>&1); [ $? = 2 ] || { echo "selftest: it ran outside the wrapper"; st=1; }
  "$F/r/test/wave-job.sh" Y >/dev/null 2>&1; [ $? = 2 ] || { echo "selftest: missing args aren't usage"; st=1; }
  [ "$st" = 0 ] && echo "selftest: OK (each rule breaks its own line, totals, VOID)"
  exit $st
fi
[ $# -ge 2 ] || { echo "usage: wave-job.sh <wave> <pre-wave-sha> [line-id ...] | --selftest" >&2; exit 2; }
wave=$1; pre=$2; shift 2
[ "${WAVE_JOB_FIXTURE:-}" = 1 ] || { [ "$PWD" = /work/operator ] && [ -z "$(ls -A /home)" ] && [ "$(grep -c : /proc/net/dev)" = 1 ]; } || { echo "wave-job: VOID, run it through test/cleanroom.sh" >&2; exit 2; }
only=" $* "
repo=$(git -C "$(dirname -- "$0")" rev-parse --show-toplevel)
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT
script=$T/wave.sh
git -C "$repo" show "HEAD:test/waves/$wave.sh" >"$script" 2>/dev/null || { echo "wave-job: VOID, no test/waves/$wave.sh at HEAD" >&2; exit 2; }
head=$(git -C "$repo" rev-parse HEAD); tree=$(git -C "$repo" rev-parse "HEAD^{tree}")
mkdir -p "$T/empty" "$T/pre" "$T/head"
git -C "$repo" archive "$pre" | tar -x -C "$T/pre" || { echo "wave-job: VOID, no pre-wave tree at $pre" >&2; exit 2; }
git -C "$repo" archive HEAD | tar -x -C "$T/head" || exit 2
LINES=$T/lines; : >"$LINES"
line() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "${4:-clean}" "$3" >>"$LINES"; }
pre_wave() {
  [ "$(git -C "$repo" rev-parse "$pre^{commit}" 2>/dev/null)" = "$(git -C "$repo" rev-parse "$1^{commit}" 2>/dev/null)" ] || { echo "wave-job: VOID, the pre-wave commit is $1, not $pre" >&2; return 1; }
  echo "$1" >"$T/predecl"
}
# In a subshell, so an exit or a return in the script can't end the job, and every line must register.
# shellcheck disable=SC1090
( . "$script" ) || { echo "wave-job: VOID, test/waves/$wave.sh failed" >&2; exit 2; }
[ -s "$T/predecl" ] || { echo "wave-job: VOID, test/waves/$wave.sh names no pre-wave commit" >&2; exit 2; }
[ "$(grep -c '^line ' "$script")" = "$(wc -l <"$LINES")" ] || { echo "wave-job: VOID, test/waves/$wave.sh registered $(wc -l <"$LINES") of $(grep -c '^line ' "$script") lines" >&2; exit 2; }
if [ "$(cut -f2 "$LINES" | sort | uniq -d | wc -l)" != 0 ]; then echo "wave-job: VOID, duplicate line ids" >&2; exit 2; fi

run_line() { # tree cmd -> rc. A fresh HOME per run, stdin closed.
  local home; home=$(mktemp -d "$T/home.XXXXXX")
  ( cd "$1" && HOME=$home timeout "${LINE_TIMEOUT:-600}" bash --noprofile --norc -c "$2" ) >"$T/out" 2>&1 </dev/null
}

bad=0 ran=0 skipped=0
printf '%-10s %-6s %-28s %-5s %-5s %-5s %s\n' WHERE TAG ID PRE EMPTY HEAD VERDICT
while IFS=$'\t' read -r tag id where cmd; do
  case "$tag" in new|guard) ;; *) echo "wave-job: VOID, line $id has tag $tag" >&2; exit 2;; esac
  if [ "$only" != "  " ] && [ "${only#* $id }" = "$only" ]; then skipped=$((skipped+1)); continue; fi
  if [ "$where" != clean ]; then
    printf '%-10s %-6s %-28s %-5s %-5s %-5s %s\n' "$where" "$tag" "$id" - - - "owes a receipt naming tree $tree"
    skipped=$((skipped+1)); continue
  fi
  ran=$((ran+1)); v=ok
  run_line "$T/pre" "$cmd"; p=$?
  run_line "$T/empty" "$cmd"; e=$?
  run_line "$T/head" "$cmd"; h=$?
  cp "$T/out" "$T/out.head"
  [ "$e" != 0 ] || v="green-on-empty"
  [ "$h" = 0 ] || v="red-on-HEAD"
  if [ "$tag" = new ]; then
    [ "$p" != 0 ] || v="green-pre-wave"
  else
    patch=$T/neuter.patch
    if ! git -C "$repo" show "HEAD:test/waves/neuters/$wave/$id.patch" >"$patch" 2>/dev/null; then v="guard-without-neuter"
    else
      rm -rf "$T/neutered"; mkdir "$T/neutered"; git -C "$repo" archive HEAD | tar -x -C "$T/neutered"
      if ! (cd "$T/neutered" && patch -sp1 <"$patch") >/dev/null 2>&1; then v="neuter-does-not-apply"
      else run_line "$T/neutered" "$cmd"; n=$?; [ "$n" != 0 ] || v="neuter-survived"; fi
    fi
  fi
  [ "$v" = ok ] || { bad=$((bad+1)); [ "$h" = 0 ] || tail -5 "$T/out.head" | cut -c1-200 | sed 's/^/    /'; }
  printf '%-10s %-6s %-28s %-5s %-5s %-5s %s\n' clean "$tag" "$id" "$p" "$e" "$h" "$v"
done <"$LINES"
echo "wave=$wave head=$head tree=$tree pre=$pre ran=$ran skipped=$skipped bad=$bad"
[ "$ran" -gt 0 ] || { echo "wave-job: VOID, nothing ran" >&2; exit 2; }
[ "$bad" = 0 ] || exit 1
[ "$skipped" = 0 ] || exit 3
