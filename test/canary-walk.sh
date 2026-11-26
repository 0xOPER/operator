#!/usr/bin/env bash
# canary-walk.sh -- C2: the acceptance walk for credential isolation, at the
# real bwrap tier. A FAKE user home beside the engine carries planted
# canaries (each CLI's login files: ssh, netrc, gh hosts and per-CLI
# credentials) with a
# random marker; a real worker jail -- the engine's own spawn.py worker
# seam, the same binds an adapter turn gets -- runs the walker over
# everything it can see (filesystem, /proc/*/environ, /proc/*/cmdline) and
# must find ZERO canaries. The egress law rides with it: a probe turn
# through the adapter jail reaches the broker (its row lands) and, with the
# broker stopped, the same call refuses -- the broker is the only door.
# After the runs, no canary exists anywhere under the engine's own home.
#
# usage: canary-walk.sh            (on-host: bwrap; first-level)
#        canary-walk.sh --selftest
# exit: 0 the walk held, 1 it didn't, 2 usage or VOID
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
ME="$ROOT/test/canary-walk.sh"
WALKER="$ROOT/test/lib/canary-walker.py"

die() { echo "canary-walk: $*" >&2; exit 2; }

selftest() {
  local rc=0 T out
  T=$(mktemp -d) || exit 2
  trap 'rm -rf "${T:?}"' EXIT
  # A the walker counts exactly: a planted marker is 1, a clean tree is 0,
  # and a marker in a fake /proc-style limb file is found the same way
  mkdir -p "$T/one" "$T/clean"
  printf 'CANARY-aa11bb22\n' > "$T/one/leak"
  out=$(WALK_ROOT="$T/one" WALK_PROC=0 CANARY_MARK="CANARY-aa11bb22" python3 "$WALKER" 2>&1)
  printf '%s' "$out" | grep -q "canary-hits=1" || { echo "A a planted marker counts 1: $out"; rc=1; }
  out=$(WALK_ROOT="$T/clean" WALK_PROC=0 CANARY_MARK="CANARY-aa11bb22" python3 "$WALKER" 2>&1)
  printf '%s' "$out" | grep -q "canary-hits=0" || { echo "A a clean tree is 0: $out"; rc=1; }
  # B usage: the walker refuses to run without its marker env
  out=$(WALK_ROOT="$T/clean" python3 "$WALKER" 2>&1); [ $? != 0 ] || { echo "B no marker env refuses: rc=0"; rc=1; }
  if [ $rc = 0 ]; then echo "selftest: OK (the walker counts exactly, env demanded)"; else echo "selftest: FAIL"; fi
  exit $rc
}
[ "${1:-}" = --selftest ] && selftest

command -v python3 >/dev/null 2>&1 || die "no python3"
command -v bwrap >/dev/null 2>&1 || die "canary-walk is a first-level test: bwrap must exist on the host"

MARK="CANARY-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
D=$(mktemp -d "${TMPDIR:-/tmp}/cw.XXXX") || die "no scratch"
[ -n "${CW_KEEP:-}" ] || trap 'rm -rf "${D:?}"' EXIT
mkdir -p "$D/oh"

# --- the fake user home: every CLI's login shape, all carrying the marker
FH="$D/fakehome"
mkdir -p "$FH/.ssh" "$FH/.config/gh" "$FH/.claude" "$FH/.codex" \
         "$FH/.config/opencode" "$FH/.local/share/opencode"
printf '%s\n' "-----BEGIN $(printf '%s%s' OPENSSH PRIVATE KEY)-----" "$MARK-agent-key" > "$FH/.ssh/id_ed25519"
printf 'machine api.example login agent password %s\n' "$MARK" > "$FH/.netrc"
printf 'github.com:\n  oauth_token: %s\n' "$MARK" > "$FH/.config/gh/hosts.yml"
printf '{"claudeApiKey":"%s"}\n' "$MARK" > "$FH/.claude/.credentials.json"
printf '{"OPENAI_API_KEY":"%s"}\n' "$MARK" > "$FH/.codex/auth.json"
printf '{"auth":{"token":"%s"}}\n' "$MARK" > "$FH/.config/opencode/opencode.json"
printf '{"apiKeys":{"operator":"%s"}}\n' "$MARK" > "$FH/.local/share/opencode/auth.json"
chmod -R go-rwx "$FH"

# --- the fixture: a program, a run, an attempt (the real engine verbs)
PROG="$D/prog"; mkdir -p "$PROG/roles"
printf 'schema = 1\nname = "cw"\nmax_parallel = 1\n[seat.w]\nrole = "roles/w.md"\nwrite = ["src/**"]\nadapter = "stub"\n[seat.w.budget]\nusd = 1.0\n' > "$PROG/team.toml"
printf 'Fixture worker.\n' > "$PROG/roles/w.md"
printf 'schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "walk"\nkind = "run"\nseat = "w"\nreviewer = "r"\ncmd = "true"\n' > "$PROG/contract.toml"
export OPERATOR_HOME="$D/oh"
RD="$D/oh/runs/cw1"
python3 "$ROOT/bin/spawn.py" init-run "$RD" >/dev/null || die "init-run refused"
echo base > "$RD/parent/base.txt"
git -C "$RD/parent" add -A >/dev/null 2>&1
git -C "$RD/parent" -c user.email=cw@x -c user.name=cw commit -qm base >/dev/null 2>&1
git -C "$RD/parent" branch -f integration/R HEAD >/dev/null 2>&1
ADIR=$(python3 "$ROOT/bin/spawn.py" attempt "$RD" --id walk --seat w \
  --grants "src/**" --task r1 --prog "$PROG") || die "the attempt refused to build"
python3 "$ROOT/bin/spawn.py" compose "$ADIR" >/dev/null || die "compose refused"
cp "$WALKER" "$ADIR/repo/walker.py"
printf '%s\n' "$MARK" > "$ADIR/repo/mark.txt"

# --- check 1: the jailed walker finds ZERO canaries (the fake home is
# never mounted; nothing the engine passes carries it)
export OPERATOR_PROGRAM="$PROG" OPERATOR_SEAT=w OPERATOR_RUN=cw1
# the marker rides ARGV: the worker jail drops the caller's env (its own
# isolation law, proven below), so an env-passed marker would never arrive
timeout -k 10 150 python3 "$ROOT/bin/spawn.py" worker "$ADIR" \
  --timeout 120 -- python3 -I /w/repo/walker.py /w/repo/mark.txt > "$D/walk.out" 2>&1 || true
grep -q "canary-hits=0" "$ADIR/transcript.out" 2>/dev/null || {
  echo "canary-walk: FAIL (the jail sees canaries or the walker never ran):"
  echo "    --- walk.out ---"
  sed 's/^/    /' "$D/walk.out" 2>/dev/null
  echo "    --- supervisor.json ---"
  sed 's/^/    /' "$ADIR/supervisor.json" 2>/dev/null
  echo "    --- transcript.out ---"
  tail -20 "$ADIR/transcript.out" 2>/dev/null | sed 's/^/    /'
  echo "    --- transcript.err ---"
  tail -20 "$ADIR/transcript.err" 2>/dev/null | sed 's/^/    /'
  exit 1; }
echo "  walker: zero canaries across the visible filesystem and /proc"

# --- checks 3+4: the egress law -- the broker is the only door. A probe
# turn through the ADAPTER jail (the relay the adapter leg starts) reaches
# the broker behind the scripted upstream; its row lands; with the broker
# stopped, the same call refuses
printf '%s' '{"name":"bash","input":{"command":"true"}}' > "$D/tool.json"
CELL_LOG="$D/req.log" CELL_TOOL="$D/tool.json" CELL_DIALECT=anthropic \
  python3 "$ROOT/test/lib/cell-stub.py" > "$D/port" 2>/dev/null &
STUB=$!
for _ in $(seq 50); do [ -s "$D/port" ] && break; sleep 0.1; done
[ -s "$D/port" ] || { kill $STUB 2>/dev/null; die "the cell stub never bound"; }
python3 "$ROOT/bin/broker.py" serve "$D/broker.sock" \
  "http://127.0.0.1:$(cat "$D/port")" cw-dummy "$D/broker.jsonl" >/dev/null 2>&1 &
BROKER=$!
for _ in $(seq 50); do [ -S "$D/broker.sock" ] && break; sleep 0.1; done
[ -S "$D/broker.sock" ] || { kill $STUB $BROKER 2>/dev/null; die "the broker never bound"; }
export OPERATOR_BROKER="$D/broker.sock"
cat > "$ADIR/repo/egress.py" <<'PYE'
import json, sys, urllib.request
try:
    r = urllib.request.urlopen(urllib.request.Request(
        "http://127.0.0.1:3128/v1/messages", method="POST",
        headers={"content-type": "application/json"},
        data=json.dumps({"model": "m", "messages": []}).encode()), timeout=10)
    print(f"egress=ok status={r.status}")
    sys.exit(0)
except Exception as e:
    print(f"egress=refused {type(e).__name__}")
    sys.exit(0)
PYE
mkdir -p "$D/adapters"
sed 's|^argv = .*|argv = ["python3", "-I", "/w/repo/egress.py"]|' \
  "$ROOT/config/adapters/stub.toml" > "$D/adapters/stub.toml"
probe_run() {
  OPERATOR_ADAPTERS="$D/adapters" OPERATOR_CREDENTIAL=cw-dummy \
    timeout -k 10 200 python3 "$ROOT/bin/spawn.py" adapter "$1" --timeout 150 \
    > "$D/probe.out" 2>&1
}
probe_run "$ADIR"
grep -q "egress=ok" "$ADIR/transcript.out" 2>/dev/null || {
  echo "canary-walk: FAIL (the broker-door probe never landed)";
  tail -3 "$D/probe.out" 2>/dev/null | sed 's/^/    /'; kill $STUB $BROKER 2>/dev/null; exit 1; }
[ -s "$D/broker.jsonl" ] || { echo "canary-walk: FAIL (no broker row for the allowed call)"; kill $STUB $BROKER 2>/dev/null; exit 1; }
echo "  egress: the allowed call lands through the broker (row recorded)"
kill $BROKER 2>/dev/null; sleep 0.5
ADIR2=$(python3 "$ROOT/bin/spawn.py" attempt "$RD" --id walk2 --seat w \
  --grants "src/**" --task r1 --prog "$PROG") || die "the control attempt refused"
python3 "$ROOT/bin/spawn.py" compose "$ADIR2" >/dev/null || die "compose refused"
cp "$ADIR/repo/egress.py" "$ADIR2/repo/egress.py"
probe_run "$ADIR2"
grep -q "egress=refused" "$ADIR2/transcript.out" 2>/dev/null || {
  echo "canary-walk: FAIL (the stopped-broker control did not refuse)";
  tail -3 "$D/probe.out" 2>/dev/null | sed 's/^/    /'; kill $STUB 2>/dev/null; exit 1; }
kill $STUB 2>/dev/null
echo "  egress control: the broker stopped, the same call refuses"

# --- checks 2+5: no canary in any channel the engine wrote, and none
# anywhere under the engine's own home
HITS=$(grep -rl "$MARK" "$ADIR" "$ADIR2" "$D/oh" "$D/broker.jsonl" 2>/dev/null | grep -v "repo/mark.txt" | head -3)
[ -z "$HITS" ] || { echo "canary-walk: FAIL (a canary reached the engine side: $HITS)"; exit 1; }
echo "  engine side: transcripts, hooks, run state -- zero canaries"
echo "canary-walk: OK (jail blind to the fake home, broker the only door, engine side clean)"
