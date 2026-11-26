#!/usr/bin/env bash
# operator -- the one entry point over bin/.
# usage:
#   operator status [run] [--json]  the run ledger and task states
#   operator doctor [--json]        the front door: installed, configured, missing, next step
#   operator rules <dir> [--json]   what each seat may do right now, from the ruled team
#   operator help [<tool>]          this text, or a tool's own header
#   operator --version
#   operator <tool> [args...]       runs bin/<tool>, with or without its suffix. Bare names only.
#   operator --selftest
# exit: 0 ok, 1 refused or missing, 2 usage or VOID. A passthrough exits with the tool's code.
set -uo pipefail

HERE=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)
BINDIR="${OPERATOR_BIN_DIR:-$ROOT/bin}"
# shellcheck source=bin/lib/paths
. "$ROOT/bin/lib/paths"

usage() { sed -n '2,/^set -/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

resolve_tool() {  # $1 name -> path. Bare names only: no namespace escape.
  case "$1" in
    ''|*/*|.*) return 1 ;;
  esac
  local f
  for f in "$BINDIR/$1" "$BINDIR/$1.sh" "$BINDIR/$1.py"; do
    [ -f "$f" ] && [ -x "$f" ] && { printf '%s\n' "$f"; return 0; }
  done
  return 1
}

tool_help() {
  local f; f=$(resolve_tool "$1") || { echo "operator: no such tool: $1" >&2; return 2; }
  case "$f" in
    *.py) sed -n '/^"""/,/^"""$/p' "$f" | sed 's/^"""//' ;;
    *) sed -n '2,/^set -/p' "$f" | sed '$d' | sed 's/^# \{0,1\}//' ;;
  esac
}

selftest() {
  local rc=0 out r me tmp
  me=$(readlink -f -- "$0")
  tmp=$(mktemp -d) || exit 2
  trap 'rm -rf "${tmp:?}"' EXIT
  mkdir -p "$tmp/bin" "$tmp/oh/runs/r9"
  printf '#!/bin/sh\n# tool-x -- a fixture\nset -u\necho ran:"$*"\nexit 7\n' > "$tmp/bin/tool-x.sh"
  chmod +x "$tmp/bin/tool-x.sh"
  printf '#!/bin/sh\necho "status-args:$*"\nexit 0\n' > "$tmp/bin/run.py"
  chmod +x "$tmp/bin/run.py"
  cat > "$tmp/bin/check.py" <<'EOF'
#!/bin/sh
printf '{"check_args":"%s"}\n' "$*"
exit 0
EOF
  chmod +x "$tmp/bin/check.py"
  op() { OPERATOR_BIN_DIR="$tmp/bin" OPERATOR_WORKSPACES="$tmp/ws" OPERATOR_HOME="$tmp/oh" "$me" "$@"; }
  # A version comes from VERSION
  out=$("$me" --version); [ "$out" = "operator $(cat "$ROOT/VERSION")" ] || { echo "A version: [$out]"; rc=1; }
  # A2 an empty VERSION is refused, not printed
  mkdir -p "$tmp/vt/bin/lib"; cp "$me" "$tmp/vt/bin/operator.sh"; cp "$ROOT/bin/lib/paths" "$tmp/vt/bin/lib/"; : > "$tmp/vt/VERSION"
  "$tmp/vt/bin/operator.sh" --version >/dev/null 2>&1; [ $? = 2 ] || { echo "A2 empty VERSION"; rc=1; }
  # B status delegates all arguments (including --json) to run.py status
  out=$(op status r9 --json); r=$?
  { [ "$r" = 0 ] && [ "$out" = "status-args:status r9 --json" ]; } || { echo "B status args: rc=$r [$out]"; rc=1; }
  # C doctor forwards --json cleanly without trailing prose, and prints next step in text mode
  out=$(op doctor --json); r=$?
  { [ "$r" = 0 ] && [ "$out" = '{"check_args":"--json"}' ]; } || { echo "C doctor json: rc=$r [$out]"; rc=1; }
  out=$(op doctor); r=$?
  { [ "$r" = 0 ] && printf '%s\n' "$out" | grep -q '^next: operator init'; } || { echo "C2 doctor prose: rc=$r [$out]"; rc=1; }
  # D passthrough keeps the tool's args and exit code, with or without the suffix
  out=$(op tool-x a b); r=$?; { [ "$r" = 7 ] && [ "$out" = "ran:a b" ]; } || { echo "D passthrough: rc=$r [$out]"; rc=1; }
  out=$(op tool-x.sh c); r=$?; { [ "$r" = 7 ] && [ "$out" = "ran:c" ]; } || { echo "D suffix: rc=$r [$out]"; rc=1; }
  # E no namespace escape, and an unknown tool is rc2
  op ../bin/tool-x.sh >/dev/null 2>&1; [ $? = 2 ] || { echo "E traversal"; rc=1; }
  op nope >/dev/null 2>&1; [ $? = 2 ] || { echo "E unknown"; rc=1; }
  # E2 a .py tool passes through, and help reads its docstring
  printf '#!/usr/bin/env python3\n"""tool-p -- py fixture\n"""\nprint("ran-p")\n' > "$tmp/bin/tool-p.py"; chmod +x "$tmp/bin/tool-p.py"
  out=$(op tool-p); [ "$out" = ran-p ] || { echo "E2 py passthrough: [$out]"; rc=1; }
  out=$(op help tool-p); printf '%s' "$out" | grep -q 'py fixture' || { echo "E2 py help: [$out]"; rc=1; }
  out=$("$me" help); printf '%s' "$out" | grep -q 'operator status' || { echo "E2 help: [$out]"; rc=1; }
  # F help renders a tool's header, and rc2 when there is none
  out=$(op help tool-x); printf '%s' "$out" | grep -q 'a fixture' || { echo "F help: [$out]"; rc=1; }
  op help nope >/dev/null 2>&1; [ $? = 2 ] || { echo "F help unknown"; rc=1; }
  # H the state defaults keep a plain-shell run off anything else
  out=$(env -i PATH="$PATH" HOME=/h bash -c '. "$1"; printf "%s %s" "$OPERATOR_HOME" "$OPERATOR_WORKSPACES"' _ "$ROOT/bin/lib/paths")
  [ "$out" = "/h/.local/state/operator /h/.local/state/operator/workspaces" ] || { echo "H home default: [$out]"; rc=1; }
  out=$(env -i PATH="$PATH" HOME=/h XDG_STATE_HOME=/x bash -c '. "$1"; printf "%s" "$OPERATOR_HOME"' _ "$ROOT/bin/lib/paths")
  [ "$out" = /x/operator ] || { echo "H xdg default: [$out]"; rc=1; }
  out=$(env -i PATH="$PATH" HOME=/h XDG_STATE_HOME=rel bash -c '. "$1"; printf "%s" "$OPERATOR_HOME"' _ "$ROOT/bin/lib/paths")
  [ "$out" = /h/.local/state/operator ] || { echo "H relative xdg: [$out]"; rc=1; }
  out=$(env -i PATH="$PATH" bash -c '. "$1"; printf "%s" "$OPERATOR_HOME"' _ "$ROOT/bin/lib/paths")
  [ "$out" = /nonexistent/.local/state/operator ] || { echo "H no home: [$out]"; rc=1; }
  out=$(env -i PATH="$PATH" HOME=/h bash -c '. "$1"; bash -c "printf %s \"\$OPERATOR_HOME\""' _ "$ROOT/bin/lib/paths")
  [ "$out" = /h/.local/state/operator ] || { echo "H not exported: [$out]"; rc=1; }
  # I with no seam set, passthrough reads this tree's bin, and empty status is friendly rc0
  out=$(env -u OPERATOR_BIN_DIR "$me" operator.sh --version); [ "$out" = "operator $(cat "$ROOT/VERSION")" ] || { echo "I default bin: [$out]"; rc=1; }
  out=$(env -u OPERATOR_BIN_DIR -u OPERATOR_HOME -u XDG_STATE_HOME HOME="$tmp/fh" "$me" status); r=$?
  { [ "$r" = 0 ] && printf '%s' "$out" | grep -q "no runs under $tmp/fh/.local/state/operator/runs"; } || { echo "I0 paths default: rc=$r [$out]"; rc=1; }
  out=$(env -u OPERATOR_BIN_DIR OPERATOR_HOME="$tmp/dh" "$me" status); r=$?
  { [ "$r" = 0 ] && printf '%s' "$out" | grep -q "no runs under $tmp/dh/runs"; } || { echo "I empty status: rc=$r [$out]"; rc=1; }
  out=$(env -u OPERATOR_BIN_DIR OPERATOR_HOME="$tmp/dh" "$me" status --json); r=$?
  { [ "$r" = 0 ] && [ "$out" = '{"runs":[]}' ]; } || { echo "I2 empty status json: rc=$r [$out]"; rc=1; }
  if [ "$rc" = 0 ]; then echo "selftest: OK (version, status, doctor, passthrough, namespace, help, paths)"; else echo "selftest: FAIL"; fi
  exit "$rc"
}

case "${1:-help}" in
  status)
    shift
    if ls "$OPERATOR_HOME"/runs/*/run.json >/dev/null 2>&1 || { [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; }; then
      exec "$BINDIR/run.py" status "$@"
    fi
    case " $* " in
      *" --json "*) echo '{"runs":[]}' ;;
      *) echo "no runs under $OPERATOR_HOME/runs" ;;
    esac
    exit 0 ;;
  doctor)
    shift
    "$BINDIR/check.py" "$@"
    r=$?
    case " $* " in
      *" --json "*) ;;
      *) echo "next: operator init <dir> --template feature, or operator demo run" ;;
    esac
    exit "$r" ;;
  help) if [ -z "${2:-}" ]; then usage; else tool_help "$2"; fi; exit $? ;;
  --version) v=$(cat "$ROOT/VERSION" 2>/dev/null) && [ -n "$v" ] || { echo "operator: no VERSION" >&2; exit 2; }; printf 'operator %s\n' "$v"; exit 0 ;;
  --selftest) selftest ;;
  *)
    tool=$(resolve_tool "$1") || { echo "operator: no such tool: $1 (operator help)" >&2; exit 2; }
    shift
    exec "$tool" "$@" ;;
esac
