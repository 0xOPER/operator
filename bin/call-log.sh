#!/usr/bin/env bash
# call-log -- a hash-committed call log. Each row records only hashes of argv, stdout
# and stderr, plus the exit code, optional key fields and a link to the previous row,
# so editing any row breaks every later one. Payloads are never stored. A receipt cites
# a call id, and verify and bind show the machinery ran it.
#
# Key fields (v2) are how the engine files a check result: `record <label> --key row=<id>
# --key commit=<sha> --key arm=<sha> -- cmd...`, so a result is keyed by row id, commit
# and arm ruling hash and a re-run under a new key never matches a stored one. Rows are
# schema v2: ts id label keys argv_h out_h err_h rc prev row_sha, ten columns.
#
# A same-user process can rewrite the whole log and its chain, so this detects edits
# and doesn't prevent them. Cutting rows off the end can't be detected at all without an
# outside anchor. The append holds an exclusive flock, so parallel writers chain instead
# of racing; a writer that can't take the lock in 30 s is rc 3.
#
# usage:
#   call-log.sh record <label> [--key k=v]... -- <cmd...>   run and commit (prints call_id). Exits with
#                                                           the command's code, and no id on stdout means no row
#   call-log.sh verify                        chain integrity check (rc0)
#   call-log.sh bind <call_id>                rc0 if the id exists and the chain holds
#   call-log.sh show <call_id>                the row (hashes only)
#   call-log.sh --selftest
# env: CALL_LOG_FILE (default $OPERATOR_HOME/call-log.tsv)
# exit: 0 ok, 1 verify or bind failed, 2 usage, 3 lock busy
set -uo pipefail
PATH=/usr/bin:/bin:$PATH

HERE=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)
. "$ROOT/bin/lib/paths"
LOG="${CALL_LOG_FILE:-$OPERATOR_HOME/call-log.tsv}"

sha() { sha256sum | cut -d' ' -f1; }

_last_sha() { tail -1 "$LOG" 2>/dev/null | awk -F'\t' '{print $NF}'; }

cmd_record() { # label, then --key k=v pairs, then --, then argv
  local label="$1" keys="" k kv; shift
  while [ "${1:-}" = --key ]; do
    kv=$2; shift 2
    k=${kv%%=*}
    local val=${kv#*=}
    [[ $k =~ ^[a-z][a-z0-9_]{0,30}$ && $kv == *=* && $val =~ ^[A-Za-z0-9._-]{0,199}$ ]] \
      || { echo "call-log: a key pair must be name=value, name [a-z][a-z0-9_]*, value letters digits . _ - only: $kv" >&2; return 2; }
    keys+="${keys:+,}$kv"
  done
  [ $# -ge 2 ] && [ "$1" = "--" ] || { echo 'usage: call-log.sh record <label> [--key k=v]... -- <cmd...>' >&2; return 2; }
  shift
  case "$label" in *[[:cntrl:]]*) echo "call-log: a label can't hold control characters" >&2; return 2 ;; esac
  local rc id prev rowdir ts row   # out and err stay global: the EXIT trap outlives this function
  rowdir=$(dirname -- "$LOG"); mkdir -p "$rowdir"
  (umask 077; : >>"$LOG") 2>/dev/null || { echo "call-log: can't write $LOG, command not run" >&2; return 2; }
  if [ -s "$LOG" ] && [ -n "$(tail -c 1 "$LOG")" ]; then
    echo "call-log: the log's last row has no newline, refusing to glue a row onto it" >&2; return 2
  fi
  out=$(mktemp) || return 2; err=$(mktemp) || { rm -f -- "$out"; return 2; }
  trap 'rm -f -- "${out:-}" "${err:-}"' EXIT
  ( exec -- "$@" ) >"$out" 2>"$err"; rc=$?
  local argv_h out_h err_h
  argv_h=$(printf '%s\0' "$@" | sha)
  out_h=$(sha <"$out"); err_h=$(sha <"$err")
  [ -n "$keys" ] || keys=-
  # The read-append pair runs under one exclusive lock, so parallel records chain.
  exec 9>>"$LOG" || { echo "call-log: can't open $LOG, command rc=$rc" >&2; return 2; }
  if ! flock -w 30 9; then echo "call-log: the log is locked after 30 s, command rc=$rc" >&2; return 3; fi
  prev=$(tail -1 "$LOG" 2>/dev/null | awk -F'\t' '{print $NF}')
  id="c$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)   # once: a second boundary between two calls broke the row hash
  row=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$ts" "$id" "$label" "$keys" "$argv_h" "$out_h" "$err_h" "$rc" "$prev")
  # the row hash binds the run's token when one is set: a jailed worker that
  # somehow reached the log path still can't forge a row that verifies
  if [ -n "${CALL_LOG_TOKEN:-}" ]; then
    rh=$(printf '%s' "$row" | openssl dgst -sha256 -hmac "$CALL_LOG_TOKEN" | awk '{print $NF}')
  else
    rh=$(printf '%s' "$row" | sha)
  fi
  printf '%s\t%s\n' "$row" "$rh" >&9 || { echo "call-log: could not write $LOG, command rc=$rc" >&2; return 2; }
  exec 9>&-
  echo "$id"
  return "$rc"
}

cmd_verify() { # recompute every row hash; each row's row_sha must match and chain
  # TAB is IFS whitespace, so `read` would collapse the empty prev
  # field of a first row. Split on unit-separator (non-whitespace) instead.
  local ts id label keys ah oh eh rc prev rh line=0 bad=0 last="" fields raw
  [ -f "$LOG" ] && [ -r "$LOG" ] || { echo "call-log: no log to verify: $LOG" >&2; return 1; }
  exec 8<"$LOG"
  flock -s 8
  while IFS= read -r raw <&8 || [ -n "$raw" ]; do
    fields=$(printf '%s' "$raw" | tr '\t' '\037')
    IFS=$'\037' read -r ts id label keys ah oh eh rc prev rh <<<"$fields"
    line=$((line+1))
    _rowp=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$ts" "$id" "$label" "$keys" "$ah" "$oh" "$eh" "$rc" "$prev")
    _plain=$(printf '%s' "$_rowp" | sha)
    _ok=0
    [ "$rh" = "$_plain" ] && {
      if [ -n "${CALL_LOG_TOKEN:-}" ]; then
        echo "call-log: row $line is a PLAIN row in a token run (forged or pre-token)" >&2; bad=1
      else
        _ok=1
      fi
    }
    if [ "$_ok" = 0 ] && [ -n "${CALL_LOG_TOKEN:-}" ]; then
      _hmac=$(printf '%s' "$_rowp" | openssl dgst -sha256 -hmac "$CALL_LOG_TOKEN" | awk '{print $NF}')
      [ "$rh" = "$_hmac" ] || { echo "call-log: row $line hash mismatch" >&2; bad=1; }
    elif [ "$_ok" = 0 ]; then
      echo "call-log: row $line hash mismatch" >&2; bad=1
    fi
    [ "$prev" != "$last" ] \
      && { echo "call-log: row $line chain break (prev=$prev want=$last)" >&2; bad=1; }
    last="$rh"
  done
  exec 8<&-
  return "$bad"
}

_row() { ID="$1" awk -F'\t' '$2==ENVIRON["ID"]{print; exit}' "$LOG"; }

cmd_bind() {
  cmd_verify || return 1
  [ -n "$(_row "$1")" ] || { echo "call-log: no such call id: $1" >&2; return 1; }
}

selftest() {
  local rc=0 id1 id2 id3 id4
  # tmp is global, because the EXIT trap outlives this function
  tmp=$(mktemp -d) || exit 2
  trap 'rm -rf "${tmp:?}"' EXIT
  export CALL_LOG_FILE="$tmp/call.tsv"
  LOG="$CALL_LOG_FILE"
  self=$(readlink -f "$0")
  TMPDIR_PROBE="$tmp/tmpd"; mkdir -p "$TMPDIR_PROBE"; recordtmp() { TMPDIR="$TMPDIR_PROBE" "$self" "$@"; }
  # A record, show and bind. The row holds the real output hash and exit code.
  id1=$(recordtmp record test-label -- /bin/echo hello) || rc=1
  [ "$(cmd_show "$id1" | cut -f6)" = "$(echo hello | sha)" ] || { echo "A: output hash"; rc=1; }
  [ "$(cmd_show "$id1" | cut -f8)" = 0 ] || { echo "A: exit code"; rc=1; }
  cmd_bind "$id1" || { echo "A: bind"; rc=1; }
  [ "$(cmd_show "$id1" | cut -f3)" = test-label ] || { echo "A: label"; rc=1; }
  [ "$(cmd_show "$id1" | cut -f5)" = "$(printf '%s\0' /bin/echo hello | sha)" ] || { echo "A: argv hash"; rc=1; }
  [ "$(cmd_show "$id1" | cut -f7)" = "$(: | sha)" ] || { echo "A: stderr hash"; rc=1; }
  [ "$(cmd_show "$id1" | cut -f4)" = "-" ] || { echo "A: no keys reads as -"; rc=1; }
  [ "$(ls -A "$TMPDIR_PROBE" | wc -l)" = 0 ] || { echo "A: payload temp left behind"; rc=1; }
  # B a failing command is recorded with its exit code, and the chain still verifies
  id2=$("$self" record test-label -- /bin/false) && { echo "B: record hid the command's failure"; rc=1; }
  [ "$(cmd_show "$id2" | cut -f8)" = 1 ] || { echo "B: exit code"; rc=1; }
  cmd_verify || { echo "B: verify"; rc=1; }
  # C rows with the same command get different ids
  [ "$id1" != "$id2" ] || { echo "C: ids collide"; rc=1; }
  # D a fabricated id is refused on a log that verifies, so only the id check can refuse it
  cmd_bind "c-nope" 2>/dev/null && { echo "D: fabricated id passed"; rc=1; }
  # E a chain break is caught: dropping a middle row leaves each row's own hash intact
  id3=$("$self" record test-label -- /bin/echo third) || rc=1
  cp "$LOG" "$tmp/good.tsv"
  sed -i '2d' "$LOG"
  cmd_verify 2>/dev/null && { echo "E: chain break undetected"; rc=1; }
  # F an edited row is caught, and bind refuses on a log that doesn't verify
  cp "$tmp/good.tsv" "$LOG"
  sed -i '1s/\t[0-9a-f]\{64\}\t/\t0000000000000000000000000000000000000000000000000000000000000000\t/' "$LOG"
  cmd_verify 2>/dev/null && { echo "F: edit undetected"; rc=1; }
  cmd_bind "$id3" 2>/dev/null && { echo "F: bind passed on a broken log"; rc=1; }
  # F2 a forged last row with no newline, a deleted first row and a missing log all fail
  cp "$tmp/good.tsv" "$LOG"; printf 'x\tc-forged\tl\t0\t0\t0\t0\t0\t0' >> "$LOG"
  cmd_verify 2>/dev/null && { echo "F2: unterminated row passed"; rc=1; }
  cp "$tmp/good.tsv" "$LOG"; sed -i '1d' "$LOG"
  cmd_verify 2>/dev/null && { echo "F2: deleted first row passed"; rc=1; }
  rm -f "$LOG"
  cmd_verify 2>/dev/null && { echo "F2: missing log verified"; rc=1; }
  # F3 a control character in a label can't poison the log, and a command with no argv is usage
  "$self" record "$(printf 'a\tb')" -- /bin/true >/dev/null 2>&1; [ $? = 2 ] || { echo "F3: tab in a label"; rc=1; }
  "$self" record lbl -- >/dev/null 2>&1; [ $? = 2 ] || { echo "F3: record with no command"; rc=1; }
  "$self" bind >/dev/null 2>&1; [ $? = 2 ] || { echo "F3: bind with no id"; rc=1; }
  "$self" show >/dev/null 2>&1; [ $? = 2 ] || { echo "F3: show with no id"; rc=1; }
  # F4 a row that can't be written is rc 2, so no receipt cites a row that doesn't exist
  mkdir -p "$tmp/adir"; CALL_LOG_FILE="$tmp/adir" "$self" record lbl -- touch "$tmp/ran" >/dev/null 2>&1; { [ $? = 2 ] && [ ! -e "$tmp/ran" ]; } || { echo "F4: unwritable log, or the command ran anyway"; rc=1; }
  CALL_LOG_FILE="$tmp/gone.tsv" "$self" record lbl -- sh -c 'rm -f "$CALL_LOG_FILE"; mkdir "$CALL_LOG_FILE"' >/dev/null 2>&1; [ $? = 2 ] || { echo "F4: the command broke the log"; rc=1; }
  # F5 a builtin isn't a command, so no word can skip the row. The default path is used and created.
  [ "$("$self" record lbl -- return 0)" != "" ] || { echo "F5: return skipped the row"; rc=1; }
  # and no word is read as an assignment: that would be a row saying rc 0 for a command that never ran
  "$self" record lbl -- FOO=bar >/dev/null 2>&1; [ $? = 127 ] || { echo "F5: an assignment read as a command that passed"; rc=1; }
  "$self" record lbl -- -a x >/dev/null 2>&1; [ $? = 127 ] || { echo "F5: a leading dash read as an option"; rc=1; }
  mkdir -p "$tmp/a=b"; printf '#!/bin/sh\ntouch "$1"\n' > "$tmp/a=b/tool"; chmod +x "$tmp/a=b/tool"
  "$self" record lbl -- "$tmp/a=b/tool" "$tmp/ran2" >/dev/null 2>&1; [ -e "$tmp/ran2" ] || { echo "F5: a path holding = didn't run"; rc=1; }
  env -u CALL_LOG_FILE OPERATOR_HOME="$tmp/fresh/deep" "$self" record lbl -- /bin/true >/dev/null; [ -s "$tmp/fresh/deep/call-log.tsv" ] || { echo "F5: default path"; rc=1; }
  # F6 an unknown id and a bad verb, and an id spelled with an escape, are refused
  "$self" show c-nope >/dev/null 2>&1; [ $? = 1 ] || { echo "F6: show of an unknown id"; rc=1; }
  "$self" nosuch >/dev/null 2>&1; [ $? = 2 ] || { echo "F6: bad verb"; rc=1; }
  mkdir -p "$tmp/vdir"; verr=$(CALL_LOG_FILE="$tmp/vdir" "$self" verify 2>&1 >/dev/null); { [ $? = 1 ] && printf '%s' "$verr" | grep -q 'no log to verify'; } || { echo "F6: verify on a directory: $verr"; rc=1; }
  # H key pairs ride the row in order, a malformed pair is refused before the command runs, and v1 rows fail
  id5=$(recordtmp record test-label --key row=tests.frozen --key commit=0123abc --key arm=deadbee -- /bin/echo keyed) || rc=1
  [ "$(cmd_show "$id5" | cut -f4)" = "row=tests.frozen,commit=0123abc,arm=deadbee" ] || { echo "H: keys"; rc=1; }
  recordtmp record test-label --key row -- /bin/true >/dev/null 2>&1; [ $? = 2 ] || { echo "H: a pair without ="; rc=1; }
  recordtmp record test-label --key Row=x -- /bin/true >/dev/null 2>&1; [ $? = 2 ] || { echo "H: an uppercase name"; rc=1; }
  recordtmp record test-label --key "row=$(printf 'a\tb')" -- /bin/true >/dev/null 2>&1; [ $? = 2 ] || { echo "H: a control character"; rc=1; }
  [ -e "$TMPDIR_PROBE/ran" ] || true; recordtmp record test-label --key row=x -- touch "$TMPDIR_PROBE/ran" >/dev/null 2>&1; r=$?
  { [ "$r" = 0 ] && [ -e "$TMPDIR_PROBE/ran" ]; } || { echo "H: a refused key never ran its command, or a good one didn't run (rc=$r)"; rc=1; }
  cmd_verify || { echo "H: verify with keys"; rc=1; }
  cp "$LOG" "$tmp/v2.tsv"; printf 'x\tc-old\tl\t%s\t%s\t%s\t0\t%s\t%s' "$(printf x | sha)" "$(printf x | sha)" "$(printf x | sha)" "$(printf x | sha)" "$(printf x | sha)" >> "$LOG"
  cmd_verify 2>/dev/null && { echo "H: a v1 row passed as v2"; rc=1; }
  cp "$tmp/v2.tsv" "$LOG"
  # H2 an unterminated tail row refuses a new record, so no id ever cites a glued row
  cp "$LOG" "$tmp/term.tsv"; printf 'x' >> "$LOG"
  recordtmp record test-label -- /bin/true >/dev/null 2>&1; [ $? = 2 ] || { echo "H2: appended onto an unterminated log"; rc=1; }
  cp "$tmp/term.tsv" "$LOG"
  # I parallel records chain under the lock instead of racing
  PLOG=$tmp/par.tsv; export CALL_LOG_FILE="$PLOG"; LOG="$PLOG"; : >"$LOG"
  for i in 1 2 3 4 5 6 7 8; do "$self" record par -- /bin/echo "$i" >/dev/null & done; wait
  [ "$(grep -c . "$LOG")" = 8 ] || { echo "I: parallel rows lost"; rc=1; }
  cmd_verify || { echo "I: parallel chain"; rc=1; }
  export CALL_LOG_FILE="$tmp/call.tsv"; LOG="$CALL_LOG_FILE"
  # G a citation of a reset log's old row is refused, and an empty log binds nothing
  : >"$LOG"
  cmd_bind "$id1" 2>/dev/null && { echo "G: bind on an empty log"; rc=1; }
  id4=$("$self" record test-label -- /bin/echo fresh)
  cmd_bind "$id1" 2>/dev/null && { echo "G: stale id passed"; rc=1; }
  cmd_bind "\\143${id4#c}" 2>/dev/null && { echo "G: an escaped id passed"; rc=1; }
  # H the token law: rows HMAC-bind the run's token; a plain row in a token
  # run names itself forged, and a token row verifies
  tlog=$tmp/token.tsv; export CALL_LOG_FILE=$tlog CALL_LOG_TOKEN=run-secret-1
  LOG=$tlog
  "$self" record tok-label -- /bin/echo tok >/dev/null 2>&1 || { echo "H: token record" >&2; rc=1; }
  cmd_verify >/dev/null 2>&1 || { echo "H: token row verifies" >&2; rc=1; }
  # a correctly-CHAINED plain row (recorded with no token into a copy):
  # in a token run it must name itself and fail
  cp "$tlog" "$tmp/plain-copy.tsv"
  LOG="$tmp/plain-copy.tsv"
  export CALL_LOG_FILE="$tmp/plain-copy.tsv"
  unset CALL_LOG_TOKEN
  "$self" record plain-label -- /bin/echo p >/dev/null 2>&1 || { echo "H: plain record into the copy" >&2; rc=1; }
  export CALL_LOG_TOKEN=run-secret-1
  LOG="$tmp/plain-copy.tsv"
  vout=$(cmd_verify 2>&1; echo "rc=$?")
  printf '%s' "$vout" | grep -q "PLAIN row in a token run" \
    || { echo "H: a plain row in a token run passed ($vout)" >&2; rc=1; }
  cmd_verify >/dev/null 2>&1 && { echo "H: the plain copy verified under a token" >&2; rc=1; }
  LOG="$tlog"
  # without the token those rows CANNOT verify -- the binding is the point
  unset CALL_LOG_TOKEN
  cmd_verify >/dev/null 2>&1 && { echo "H: token rows verified with no token" >&2; rc=1; }
  # H2 the WRONG token names the mismatch: a row HMAC-bound to one secret
  # must not quietly pass under another
  export CALL_LOG_TOKEN=run-secret-2
  vout2=$(cmd_verify 2>&1; echo "rc=$?")
  printf '%s' "$vout2" | grep -q "hash mismatch" \
    || { echo "H2: a row bound to another token passed ($vout2)" >&2; rc=1; }
  cmd_verify >/dev/null 2>&1 && { echo "H2: the wrong token verified" >&2; rc=1; }
  unset CALL_LOG_TOKEN CALL_LOG_FILE
  if [ "$rc" -eq 0 ]; then
    echo "selftest: OK (record, exit code, ids, fabricated, chain break, edit, stale, keys, unterm, token, parallel)"
  else
    echo "selftest: FAIL (see above)" >&2
  fi
  return "$rc"
}

cmd_show() { local r; r=$(_row "$1"); [ -n "$r" ] || return 1; printf '%s\n' "$r"; }

case "${1:-}" in
  record) shift; cmd_record "$@" ;;
  verify) cmd_verify ;;
  bind|show) [ $# -ge 2 ] || { echo "usage: call-log.sh $1 <call_id>" >&2; exit 2; }; "cmd_$1" "$2" ;;
  --selftest) selftest; exit $? ;;
  *) sed -n '2,/^set -/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
