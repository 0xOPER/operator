#!/usr/bin/env bash
# ratchet -- shellcheck and ruff problem counts may only go down. test/ratchet.tsv holds the numbers,
# and a count below its number fails too, so the slack can't be spent again.
# A tool that's absent is a failure, never a pass. Exit: 0 holds, 1 a count moved, 2 VOID.
set -uo pipefail
cd -- "$(dirname -- "$0")/.." || exit 2
base() { awk -F'\t' -v k="$1" '$1==k{print $2}' test/ratchet.tsv; }
command -v pipx >/dev/null || { echo "ratchet: VOID, no pipx" >&2; exit 2; }
tracked=$(comm -12 <(git ls-files | sort) <(sort keep-list)) && [ -n "$tracked" ] || { echo "ratchet: VOID, no tracked files" >&2; exit 2; }
mapfile -t shells < <(printf '%s\n' "$tracked" | while IFS= read -r f; do [ -f "$f" ] && head -1 "$f" | grep -qE '^#!.*(ba)?sh' && printf '%s\n' "$f"; done; printf '%s\n' bin/lib/paths)
# Exit 1 with lines is findings. Anything else, or no verdict line, means the tool itself failed.
sc_out=$(pipx run --spec shellcheck-py==0.10.0.1 shellcheck -x -f gcc "${shells[@]}" 2>/dev/null); r=$?
sc=$(printf '%s\n' "$sc_out" | grep -cE '^[^ ]+:[0-9]+:[0-9]+:')
{ [ "$r" = 0 ] || { [ "$r" = 1 ] && [ "$sc" -gt 0 ]; }; } || { echo "ratchet: VOID, shellcheck rc=$r" >&2; exit 2; }
rf_out=$(pipx run ruff==0.14.0 check --output-format=concise . 2>/dev/null); r=$?
printf '%s\n' "$rf_out" | grep -qE '^(All checks passed|Found [0-9]+ error)' || { echo "ratchet: VOID, ruff rc=$r gave no verdict" >&2; exit 2; }
rf=$(printf '%s\n' "$rf_out" | grep -cE '^[^ ]+:[0-9]+:[0-9]+:')
echo "shellcheck=$sc baseline=$(base shellcheck)"
echo "ruff=$rf baseline=$(base ruff)"
rc=0
for pair in "shellcheck $sc" "ruff $rf"; do
  set -- $pair
  b=$(base "$1")
  case "$b" in
    ''|*[!0-9]*) echo "ratchet: $1 has no number in test/ratchet.tsv" >&2; rc=1 ;;
    *) if [ "$2" -gt "$b" ]; then echo "ratchet: $1 rose to $2 from $b" >&2; rc=1
       elif [ "$2" -lt "$b" ]; then echo "ratchet: $1 fell to $2, so lower test/ratchet.tsv from $b" >&2; rc=1; fi ;;
  esac
done
[ "$rc" = 0 ] || printf '%s\n' "$sc_out" "$rf_out"
exit $rc
