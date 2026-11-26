#!/usr/bin/env bash
# topology-drill.sh -- C3: paired attacks at the bwrap tier, each with its
# allowed-path proof. NET leg: a probe turn through the ADAPTER jail (the
# netns whose only egress is the relay to the broker) must refuse every
# foreign shape -- IP literals, the metadata address, unlisted privates,
# outside DNS, UDP/443, proxy-style absolute URIs -- while the broker's own
# face answers. FS leg: the WORKER jail must not see another program's
# tree, the engine's own home, or the host's docker socket, while the repo
# stays writable and no marker from either hidden tree rides anywhere.
#
# usage: topology-drill.sh          (on-host: bwrap; first-level)
#        topology-drill.sh --selftest
# exit: 0 the drill held, 1 it didn't, 2 usage or VOID
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
ME="$ROOT/test/topology-drill.sh"
DRILL="$ROOT/test/lib/topology-drill.py"

die() { echo "topology-drill: $*" >&2; exit 2; }

selftest() {
  local rc=0 out
  # A usage: an unknown mode names itself a LEAK, the caller refuses
  out=$(python3 "$DRILL" no-such-mode 2>&1); printf '%s' "$out" | grep -q "probe usage LEAK" \
    || { echo "A unknown mode: $out"; rc=1; }
  out=$(python3 "$DRILL" 2>&1); [ $? != 0 ] || { echo "B no mode refuses"; rc=1; }
  # C the net verdicts PARSE, and the closed-port twin is honest: against a
  # dead broker the allowed twin reads LEAK. The ATTACK verdicts are
  # jail-properties and are NOT asserted here -- this host has real egress,
  # so ip-literal and dns-outside answer on the host by design; their
  # refusals are the first-level run's claims
  python3 - "$DRILL" <<'PY' || rc=1
import subprocess, sys
r = subprocess.run([sys.executable, sys.argv[1], "net", "127.0.0.1:1"],
                   capture_output=True, text=True, timeout=60)
lines = [l for l in r.stdout.splitlines() if l.startswith("probe ")]
names = ["direct-broker", "ip-literal", "metadata-169.254", "private-unlisted",
         "dns-outside", "udp-443", "proxy-bypass", "rebinding-host"]
assert len(lines) == len(names), f"one line per probe: {lines}"
for l in lines:
    assert l.endswith((" ok", " refused", " LEAK")), f"malformed: {l}"
assert any("direct-broker LEAK" in l for l in lines), f"closed port: {lines}"
print("verdicts parse")
PY
  if [ $rc = 0 ]; then echo "selftest: OK (usage, verdict shapes, closed-port twin)"; else echo "selftest: FAIL"; fi
  exit $rc
}
[ "${1:-}" = --selftest ] && selftest

command -v python3 >/dev/null 2>&1 || die "no python3"
command -v bwrap >/dev/null 2>&1 || die "topology-drill is a first-level test: bwrap must exist"

MARK_O="TD-O-$(tr -dc a-f0-9 </dev/urandom | head -c 10)"
MARK_H="TD-H-$(tr -dc a-f0-9 </dev/urandom | head -c 10)"
D=$(mktemp -d "${TMPDIR:-/tmp}/td.XXXX") || die "no scratch"
[ -n "${TD_KEEP:-}" ] || trap 'rm -rf "${D:?}"' EXIT
mkdir -p "$D/oh"

# the hidden trees the jail must never see: another program, engine state
mkdir -p "$D/otherprog/src" "$D/oh/keys"
printf 'other-program-secret %s\n' "$MARK_O" > "$D/otherprog/src/secret.py"
printf 'engine-key-material %s\n' "$MARK_H" > "$D/oh/keys/operator.key"

# --- the fixture: program, run, attempt (the real engine verbs)
PROG="$D/prog"; mkdir -p "$PROG/roles"
printf 'schema = 1\nname = "td"\nmax_parallel = 1\n[seat.w]\nrole = "roles/w.md"\nadapter = "stub"\nwrite = ["src/**"]\n[seat.w.budget]\nusd = 1.0\n' > "$PROG/team.toml"
printf 'Fixture worker.\n' > "$PROG/roles/w.md"
printf 'schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "drill"\nkind = "run"\nseat = "w"\nreviewer = "r"\ncmd = "true"\n' > "$PROG/contract.toml"
export OPERATOR_HOME="$D/oh"
RD="$D/oh/runs/td1"
python3 "$ROOT/bin/spawn.py" init-run "$RD" >/dev/null || die "init-run refused"
echo base > "$RD/parent/base.txt"
git -C "$RD/parent" add -A >/dev/null 2>&1
git -C "$RD/parent" -c user.email=td@x -c user.name=td commit -qm base >/dev/null 2>&1
git -C "$RD/parent" branch -f integration/R HEAD >/dev/null 2>&1
export OPERATOR_PROGRAM="$PROG" OPERATOR_SEAT=w OPERATOR_RUN=td1
ADIR=$(python3 "$ROOT/bin/spawn.py" attempt "$RD" --id drill --seat w \
  --grants "src/**" --task r1 --prog "$PROG") || die "the attempt refused to build"
python3 "$ROOT/bin/spawn.py" compose "$ADIR" >/dev/null || die "compose refused"

# --- the FS leg: the WORKER jail
cp "$DRILL" "$ADIR/repo/drill.py"
timeout -k 10 150 python3 "$ROOT/bin/spawn.py" worker "$ADIR" --timeout 120 -- \
  python3 -I /w/repo/drill.py fs "$MARK_O" "$MARK_H" /var/run/docker.sock \
  > "$D/fs.out" 2>&1 || true
FS_OUT=$(cat "$ADIR/transcript.out" 2>/dev/null)
check_fs() { printf '%s\n' "$FS_OUT" | grep -q "probe $1 $2"; }
check_fs repo-writable ok || { echo "topology-drill: FAIL (the repo is not writable): $(printf '%s' "$FS_OUT" | tail -3)"; exit 1; }
for p in other-tree engine-home markers-invisible docker-sock; do
  check_fs $p refused || { echo "topology-drill: FAIL (fs probe $p leaked or never ran)"; exit 1; }
done
echo "  fs: repo writable; other trees, engine home, docker.sock all invisible"

# --- the NET leg: the ADAPTER jail (relay -> broker -> stub)
printf '%s' '{"name":"bash","input":{"command":"true"}}' > "$D/tool.json"
CELL_LOG="$D/req.log" CELL_TOOL="$D/tool.json" CELL_DIALECT=anthropic \
  python3 "$ROOT/test/lib/cell-stub.py" > "$D/port" 2>/dev/null &
STUB=$!
for _ in $(seq 50); do [ -s "$D/port" ] && break; sleep 0.1; done
[ -s "$D/port" ] || { kill $STUB 2>/dev/null; die "the cell stub never bound"; }
python3 "$ROOT/bin/broker.py" serve "$D/broker.sock" \
  "http://127.0.0.1:$(cat "$D/port")" td-dummy "$D/broker.jsonl" >/dev/null 2>&1 &
BROKER=$!
for _ in $(seq 50); do [ -S "$D/broker.sock" ] && break; sleep 0.1; done
[ -S "$D/broker.sock" ] || { kill $STUB $BROKER 2>/dev/null; die "the broker never bound"; }
export OPERATOR_BROKER="$D/broker.sock"
cp "$DRILL" "$ADIR/repo/drill.py"
mkdir -p "$D/adapters"
sed 's|^argv = .*|argv = ["python3", "-I", "/w/repo/drill.py", "net", "127.0.0.1:3128"]|' \
  "$ROOT/config/adapters/stub.toml" > "$D/adapters/stub.toml"
OPERATOR_ADAPTERS="$D/adapters" OPERATOR_CREDENTIAL=td-dummy \
  timeout -k 10 200 python3 "$ROOT/bin/spawn.py" adapter "$ADIR" --timeout 150 \
  > "$D/net.out" 2>&1
kill $STUB $BROKER 2>/dev/null
NET_OUT=$(cat "$ADIR/transcript.out" 2>/dev/null)
check_net() { printf '%s\n' "$NET_OUT" | grep -q "probe $1 $2"; }
check_net direct-broker ok || { echo "topology-drill: FAIL (the broker's own face did not answer -- the netns is dead, not safe): $(printf '%s' "$NET_OUT" | tail -3)"; exit 1; }
for p in ip-literal metadata-169.254 private-unlisted dns-outside udp-443 proxy-bypass rebinding-host; do
  check_net $p refused || { echo "topology-drill: FAIL (net probe $p leaked or never ran)"; exit 1; }
done
echo "  net: the broker answers; literals, metadata, privates, DNS, UDP, proxy shapes all refuse"
echo "topology-drill: OK (every attack refused, every allowed twin landed)"
