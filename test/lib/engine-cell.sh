#!/usr/bin/env bash
# engine-cell.sh -- the conformance cells' engine leg, sourced by conformance.sh.
# claude's cells drive the bare CLI (its permission rules are the refusing
# layer); opencode and codex have NO config-level path scoping at their pins
# (opencode's pure mode runs every tool ungated -- probed; codex has no
# permission system in exec mode), so their refusing layers are the ENGINE's:
# the jail (ro binds, the netns) and the seal/gate (grants). A cell for those
# adapters is therefore a REAL engine attempt -- spawn.py adapter through the
# worker jail, the manifest's own planting, the broker relaying to the cell
# stub -- and the receipt names whichever layer refused.
#
# The caller sets: ROOT, ADAPTER (opencode|codex), D (scratch), CELL dialect.
# Functions below build the fixture, run one twin as an attempt, and leave
# $D/req.log (every raw request the stub saw) + the attempt dir in $ADIR.
engine_cell_setup() {
  mkdir -p "$D/oh"
  PROG="$D/prog"; mkdir -p "$PROG/roles"
  cat > "$PROG/team.toml" <<TOML
schema = 1
name = "cell"
max_parallel = 1
[seat.w]
role = "roles/w.md"
adapter = "$ADAPTER"
write = ["src/**"]
[seat.w.budget]
usd = 1.0
TOML
  printf 'You execute the next tool call exactly as instructed.\n' > "$PROG/roles/w.md"
  cat > "$PROG/contract.toml" <<'TOML'
schema = 2
[[row]]
id = "r1"
stage = "s"
desc = "the conformance fixture"
kind = "run"
seat = "w"
reviewer = "r"
cmd = "true"
TOML
  RD="$D/oh/runs/cell1"
  python3 "$ROOT/bin/spawn.py" init-run "$RD" >/dev/null || return 2
  PARENT="$RD/parent"
  echo base > "$PARENT/base.txt"
  git -C "$PARENT" add -A >/dev/null 2>&1
  git -C "$PARENT" -c user.email=c@x -c user.name=c commit -qm base >/dev/null 2>&1
  git -C "$PARENT" branch -f integration/R HEAD >/dev/null 2>&1
  # the scripted upstream behind the broker: the stub speaks the adapter's
  # dialect, the broker re-originates with its own credential
  python3 "$ROOT/bin/broker.py" serve "$D/broker.sock" \
    "http://127.0.0.1:$(cat "$D/port")" cell-dummy "$D/broker.jsonl" >/dev/null 2>&1 &
  ENGINE_BROKER=$!
  for _ in $(seq 50); do [ -S "$D/broker.sock" ] && break; sleep 0.1; done
  [ -S "$D/broker.sock" ] || { echo "  engine-cell: the broker never bound" >&2; return 2; }
  export OPERATOR_HOME="$D/oh" OPERATOR_ADAPTERS="$ROOT/config/adapters" \
         OPERATOR_CREDENTIAL=cell-dummy OPERATOR_BROKER="$D/broker.sock" \
         OPERATOR_PROGRAM="$PROG" OPERATOR_SEAT=w OPERATOR_RUN=cell1
  return 0
}

# engine_cell_run <id> [dir] -- one twin: tool.json carries THIS twin's tool
# call, the attempt runs through the real jail, $ADIR points at it afterwards.
# dir is a path under the attempt's repo, created before the turn: a fixture
# the command writes into.
engine_cell_run() {
  local id=$1 rc issued=0
  local pre_dir=${2:-}
  rm -f "$D/req.log"
  ADIR=$(python3 "$ROOT/bin/spawn.py" attempt "$RD" --id "$id" --seat w \
    --grants "src/**" --task r1 --prog "$PROG") || return 2
  [ -z "$pre_dir" ] || mkdir -p "$ADIR/repo/$pre_dir"
  python3 "$ROOT/bin/spawn.py" compose "$ADIR" >/dev/null || return 2
  timeout -k 10 240 python3 "$ROOT/bin/spawn.py" adapter "$ADIR" --timeout 200 \
    > "$D/drive-$id.out" 2> "$D/drive-$id.err"
  rc=$?
  # the twin ran if the tool was issued and ANSWERED: either the follow-up
  # request echoes the call id upstream, or the CLI's own permission layer
  # refused it -- an errored tool turn ends without an upstream echo, and
  # its receipt is the transcript's tool event (probed 2026-11-19:
  # opencode's pure mode turns the out-of-project "ask" into a reject)
  grep -q toolu_cell "$D/req.log" 2>/dev/null && issued=1
  grep -q 'toolu_cell' "$ADIR/transcript.out" 2>/dev/null && issued=1
  [ "$issued" = 1 ] || {
    echo "  $id: VOID (the tool was neither echoed upstream nor answered in the transcript; drive rc=$rc; requests seen: $(grep -c -- '--REQ--' "$D/req.log" 2>/dev/null || echo 0))";
    tail -2 "$D/drive-$id.err" 2>/dev/null | sed 's/^/    /';
    tail -3 "$D/drive-$id.out" 2>/dev/null | sed 's/^/    /'; return 1; }
  return 0
}

# engine_cell_result -- the tool_result text the upstream received for the
# issued call (the receipt channel: refusals ride it)
engine_cell_result() {
  python3 - "$D/req.log" <<'PY'
import sys
reqs = [r for r in open(sys.argv[1], errors="replace").read().split("\n--REQ--\n") if r.strip()]
res = next((r for r in reqs if "tool_result" in r or "function_call_output" in r
            or "toolResult" in r), None)
sys.stdout.write(res or "")
PY
}

# engine_cell_tool_error -- the CLI-side refusal: the transcript's tool event
# for the issued call in error state (opencode's permission reject ends the
# turn without an upstream echo -- the receipt is HERE)
engine_cell_tool_error() {
  python3 - "$ADIR/transcript.out" <<'PY'
import json, sys


def main():
    for ln in open(sys.argv[1], errors="replace"):
        try:
            d = json.loads(ln)
        except ValueError:
            continue
        p = d.get("part") or {}
        if p.get("callID") == "toolu_cell" or d.get("callID") == "toolu_cell":
            st = p.get("state") or {}
            if st.get("status") == "error":
                print(st.get("error") or "(error)")
            else:
                print("(the tool event is not an error)")
            return
    print("(no tool event for the call)")


main()
PY
}
