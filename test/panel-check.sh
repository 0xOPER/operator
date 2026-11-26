#!/usr/bin/env bash
# panel-check -- the C6 wave line: the panel renders a run the engine's own
# shapes describe, through the CLI verbs a human uses, and the served surface
# refuses what decision 18 keeps in the CLI.
#
# The fixture here is hand-built to the engine's file shapes (run.json,
# ledger.tsv, an escalation with its named fix, an attempt with hooks) because
# the wave line must not depend on the selftest's own fixture helpers: the
# ratchet neuters bin/panel.py, and this check must die on the same neuters
# from the outside, not by sharing code with what it checks.
#
# usage: panel-check.sh          exit: 0 the panel holds, 1 it broke, 2 VOID
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
T=$(mktemp -d) || exit 2
trap 'kill "${SRV:-0}" 2>/dev/null; rm -rf "${T:?}"' EXIT

export OPERATOR_HOME="$T/oph"
mkdir -p "$T/oph/runs/e1/attempts/a1" "$T/oph/runs/e1/escalations"
printf '%s\n' '{"schema":1,"run":"e1","state":"running","autonomy":"a2","notified":false}' \
  > "$T/oph/runs/e1/run.json"
# an empty ledger reads UNFIRED whatever run.json claims -- the header is the
# CLI's status doc, not the file
: > "$T/oph/runs/e1/ledger.tsv"
printf '%s\n' '{"schema":1,"kind":"reserve","ts":"2026-11-13T00:00:00Z"}' \
  > "$T/oph/runs/e1/events.jsonl"
printf '%s\n' '# escalation: needs_input' '' 'attempt a1 asks for input' '' \
  'fix: run.py reply e1 t1 --note F.md' \
  > "$T/oph/runs/e1/escalations/20261113T000000Z-episode.md"
printf '%s\n' '{"id":"a1","seat":"w","task":"build.check","grants":["src/**"],"ref":"integration/R","seats":[]}' \
  > "$T/oph/runs/e1/attempts/a1/attempt.json"
printf 'Bash <script>alert(1)</script> {"c":"a\033b"}\n' \
  > "$T/oph/runs/e1/attempts/a1/hook.jsonl"

rc=0
python3 -I "$ROOT/bin/panel.py" render --run e1 --out "$T/p.html" >/dev/null 2>&1 \
  || { echo "panel-check: render refused"; rc=1; }
grep -q 'run <b>e1</b>' "$T/p.html" 2>/dev/null \
  || { echo "panel-check: the header names the run"; rc=1; }
grep -q '>unfired<' "$T/p.html" 2>/dev/null \
  || { echo "panel-check: an empty ledger reads unfired (the doc, not the file)"; rc=1; }
grep -q 'run.py reply e1 t1 --note F.md' "$T/p.html" 2>/dev/null \
  || { echo "panel-check: the queue shows the named fix"; rc=1; }
grep -q '<script>alert(1)</script>' "$T/p.html" \
  && { echo "panel-check: a hostile hook line rode the page raw"; rc=1; }
# an ESC byte never rides the page raw either (the hook line carries one)
grep -q "$(printf '\033')" "$T/p.html" \
  && { echo "panel-check: an escape byte rode the page raw"; rc=1; }

# the served surface: boot it, then a signature-shaped verb refuses BY NAME
PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()
PY
) || exit 2
python3 -I "$ROOT/bin/panel.py" serve --run e1 --port "$PORT" >"$T/serve.log" 2>&1 &
SRV=$!
i=0; while [ $i -lt 40 ] && ! grep -q "panel: http" "$T/serve.log" 2>/dev/null; do
  sleep 0.25; i=$((i + 1))
done
grep -q "panel: http://127.0.0.1:$PORT/" "$T/serve.log" \
  || { echo "panel-check: serve never came up on loopback"; rc=1; }
TOKEN=$(python3 - "$PORT" <<'PY'
import re, sys, urllib.request
body = urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/", timeout=10).read().decode()
m = re.search(r'var TOKEN = "([0-9a-f]+)";', body)
print(m.group(1) if m else "")
PY
) || exit 2
[ -n "$TOKEN" ] || { echo "panel-check: the served page carries no token"; rc=1; }
code=$(curl -s -o "$T/verb.out" -w '%{http_code}' -X POST \
  -H "content-type: application/json" -H "x-panel-token: $TOKEN" \
  --data '{"verb":"verdict","run":"e1"}' "http://127.0.0.1:$PORT/verb") || rc=1
[ "$code" = 403 ] && grep -q "decision 18" "$T/verb.out" \
  || { echo "panel-check: a verdict verb must refuse by name (got $code)"; rc=1; }

if [ $rc = 0 ]; then echo "panel-check: OK (render, unfired law, named fix, escape, serve refusal)"; fi
exit $rc
