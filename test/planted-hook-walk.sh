#!/usr/bin/env bash
# planted-hook-walk.sh -- the acceptance walk for the delivery invariant: the
# engine never runs git inside an attempt after the worker starts. A worker
# whose .git is writable (a writable clone, when a grant asks for one) could
# plant hooks and config-driven commands. This walk plants them where the
# worker would have: in the attempt's .git, after a real turn. Three legs then
# run the engine, and nothing may fire on the host: the real delivery chain
# (seal, gate, collect, candidate); the engine's own verb on the already-turned
# attempt (spawn.py adapter, a re-drive: the verb whose adapter_prepare used to
# ask the attempt's repository, on the host, whether the adapter's config file
# is tracked); and the writable clone (a seat that asks with shell, on an
# adapter that earned the class), where the plants are written by the worker's
# own turn FROM INSIDE THE JAIL. A positive control proves the detection is
# live: git run in each repository ON THE HOST does fire the plants.
#
# --sabotage proves the walk can fail, once per leg: against a copy of the
# engine whose collector runs git inside the attempt on the host, against one
# whose adapter_prepare does, and against one whose seal does for a clone, the
# same walk reports it.
#
# usage: planted-hook-walk.sh            (on-host: bwrap, git; first-level)
#        planted-hook-walk.sh --selftest
#        planted-hook-walk.sh --sabotage
# env: PLANTED_HOOK_ENGINE (test seam: the tree the walk runs), PHW_KEEP
# exit: 0 the walk held, 1 it didn't, 2 usage or VOID
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
ME="$ROOT/test/planted-hook-walk.sh"
PLANT="$ROOT/test/lib/plant-hooks.sh"
ENGINE=${PLANTED_HOOK_ENGINE:-$ROOT}

die() { echo "planted-hook-walk: $*" >&2; exit 2; }
fail() { echo "planted-hook-walk: FAIL ($*)"; exit 1; }

fixture() {  # <dir>: a one-commit repository, or a non-zero code
  git init -q "$1" && echo x > "$1/f" && git -C "$1" add -A \
    && git -C "$1" -c user.email=a@x -c user.name=a commit -qm base
}

fire_control() {  # <repo>: git run in this repository on the host
  git -C "$1" add -A >/dev/null 2>&1            # the post-index-change hook
  printf 'protocol=https\nhost=x\n\n' | git -C "$1" credential fill >/dev/null 2>&1   # the helper
  git -C "$1" ls-files -- opencode.json >/dev/null 2>&1   # the fsmonitor (the re-drive's call)
}

selftest() {
  local rc=0 T
  T=$(mktemp -d) || exit 2
  trap 'rm -rf "${T:?}"' EXIT
  # A the plants are live where git runs in that repository: a hook and the
  # config-driven commands both leave their trace
  fixture "$T/a" || die "no git fixture"
  mkdir -p "$T/m"
  sh "$PLANT" "$T/a" "$T/m" || die "the plants didn't take"
  fire_control "$T/a"
  grep -q "post-index-change" "$T/m/HOOK-RAN" 2>/dev/null || { echo "A a planted hook fired: no trace"; rc=1; }
  grep -q "credential" "$T/m/CFG-RAN" 2>/dev/null || { echo "A a planted config command fired: no trace"; rc=1; }
  grep -q "fsmonitor" "$T/m/CFG-RAN" 2>/dev/null || { echo "A the planted fsmonitor fired: no trace"; rc=1; }
  # B a repository without the plants leaves nothing: the traces are the plants'
  fixture "$T/b" || die "no git fixture"
  mkdir -p "$T/m2"
  fire_control "$T/b"
  if [ -e "$T/m2/HOOK-RAN" ] || [ -e "$T/m2/CFG-RAN" ]; then echo "B a clean repository left a trace"; rc=1; fi
  # C the plant script runs where the marker directory cannot be made (a jail):
  # it plants, and nothing fires
  fixture "$T/c" || die "no git fixture"
  sh "$PLANT" "$T/c" "$T/no-such-dir/markers" || { echo "C the plants didn't take without a marker directory"; rc=1; }
  if ! grep -q "fsmonitor" "$T/c/.git/config" 2>/dev/null || [ ! -x "$T/c/.githooks/post-commit" ]; then
    echo "C the plants are not in the repository"; rc=1
  fi
  [ ! -e "$T/no-such-dir/markers/HOOK-RAN" ] || { echo "C a plant fired"; rc=1; }
  if [ $rc = 0 ]; then echo "selftest: OK (the plants fire where git runs, and only there)"; else echo "selftest: FAIL"; fi
  exit $rc
}

sabotage() {
  # the walk must be able to fail, once per leg. Each doctor puts a host-side
  # git call inside the attempt back into a copy of the engine -- exactly the
  # regression its leg stands for
  local name S rc_all=0 rc
  for name in collect reprepare sealclone; do
    S=$(mktemp -d "${TMPDIR:-/tmp}/phw-sab.XXXX") || die "no scratch"
    [ -n "${PHW_KEEP:-}" ] || trap 'rm -rf "${S:?}"' EXIT
    mkdir -p "$S/engine"
    (cd "$ROOT" && tar --exclude=.git -cf - .) | (cd "$S/engine" && tar -xf -)
    if ! python3 -I - "$S/engine/bin/spawn.py" "$name" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); t = p.read_text()
if sys.argv[2] == "collect":
    old = "def collect(attempt):\n"
    new = old + ("    import subprocess as _s  # SABOTAGE: git inside the attempt, on the host\n"
                 "    _s.run([\"git\", \"-C\", os.path.join(attempt, \"repo\"), \"status\", \"--short\"], capture_output=True)\n")
elif sys.argv[2] == "reprepare":
    old = "    body = manifest.get(\"repo_config_body\")\n"
    new = old + ("    import subprocess as _s  # SABOTAGE: git inside the attempt, on the host\n"
                 "    _s.run([\"git\", \"-C\", os.path.join(attempt, \"repo\"), \"ls-files\", \"--\", \"opencode.json\"],\n"
                 "           capture_output=True, env=engine_env())\n")
else:
    old = "    seal_dir = os.path.join(attempt, \"seal\")\n"
    new = ("    import subprocess as _s  # SABOTAGE: git inside a clone's attempt, on the host\n"
           "    if meta.get(\"shell\"):\n"
           "        _s.run([\"git\", \"-C\", os.path.join(attempt, \"repo\"), \"status\", \"--short\"],\n"
           "               capture_output=True, env=engine_env())\n"
           + old)
assert t.count(old) == 1, f"the walk's sabotage anchor moved: {old!r}"
p.write_text(t.replace(old, new))
PY
    then die "the doctoring didn't take"; fi
    PLANTED_HOOK_ENGINE="$S/engine" bash "$ME" > "$S/walk.out" 2>&1
    rc=$?
    if [ "$rc" = 0 ]; then
      echo "sabotage($name): FAIL (the walk passed against an engine whose $name runs git in the attempt on the host)"
      sed 's/^/    /' "$S/walk.out"; rc_all=1
    elif ! grep -q "ran host-side" "$S/walk.out"; then
      echo "sabotage($name): FAIL (the doctored tree failed the walk for another reason)"; sed 's/^/    /' "$S/walk.out"; rc_all=1
    else
      echo "sabotage($name): OK (the walk reports an engine whose $name runs git inside the attempt on the host)"
    fi
    [ -n "${PHW_KEEP:-}" ] || rm -rf -- "$S"
  done
  exit $rc_all
}

[ "${1:-}" = --selftest ] && selftest
[ "${1:-}" = --sabotage ] && sabotage
[ $# = 0 ] || die "usage: planted-hook-walk.sh | --selftest | --sabotage"
command -v python3 >/dev/null 2>&1 || die "no python3"
command -v bwrap >/dev/null 2>&1 || die "planted-hook-walk is a first-level test: bwrap must exist on the host"
[ -x "$ENGINE/bin/spawn.py" ] || die "no engine at $ENGINE (PLANTED_HOOK_ENGINE)"

D=$(mktemp -d "${TMPDIR:-/tmp}/phw.XXXX") || die "no scratch"
[ -n "${PHW_KEEP:-}" ] || trap 'rm -rf "${D:?}"' EXIT
spawn() { python3 "$ENGINE/bin/spawn.py" "$@"; }

# --- the fixture: a program, a run, an attempt (the real engine verbs)
PROG="$D/prog"; mkdir -p "$PROG/roles"
printf 'schema = 1\nname = "phw"\nmax_parallel = 1\n[seat.w]\nrole = "roles/w.md"\nwrite = ["src/**"]\nadapter = "stub"\n[seat.w.budget]\nusd = 1.0\n' > "$PROG/team.toml"
printf 'Fixture worker.\n' > "$PROG/roles/w.md"
printf 'schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "walk"\nkind = "run"\nseat = "w"\nreviewer = "r"\ncmd = "true"\n' > "$PROG/contract.toml"
export OPERATOR_HOME="$D/oh"
RD="$D/oh/runs/phw1"
spawn init-run "$RD" >/dev/null || die "init-run refused"
mkdir -p "$RD/parent/src"; echo "v=1" > "$RD/parent/src/a.py"
git -C "$RD/parent" add -A >/dev/null 2>&1
git -C "$RD/parent" -c user.email=phw@x -c user.name=phw commit -qm base >/dev/null 2>&1
git -C "$RD/parent" branch -f integration/R HEAD >/dev/null 2>&1
ADIR=$(spawn attempt "$RD" --id phw --seat w --grants "src/**" --task r1 --prog "$PROG") || die "the attempt refused to build"
spawn compose "$ADIR" >/dev/null || die "compose refused"
export OPERATOR_PROGRAM="$PROG" OPERATOR_SEAT=w OPERATOR_RUN=phw1

# --- 1 the worker's honest change, in the real jail
timeout -k 10 150 python3 "$ENGINE/bin/spawn.py" worker "$ADIR" --timeout 120 -- \
  /bin/sh -c 'echo v=2 > src/a.py' > "$D/turn.out" 2>&1
[ "$(cat "$ADIR/repo/src/a.py" 2>/dev/null)" = v=2 ] || fail "the worker turn never wrote its change"
echo "  turn: the worker wrote its change inside the jail"

# --- 2 the plants, where a writable .git would have let the worker put them
mkdir -p "$D/host"
rm -f -- "$D/host/HOOK-RAN" "$D/host/CFG-RAN"
sh "$PLANT" "$ADIR/repo" "$D/host" || die "the plants didn't take"

# --- 3 the real chain, on the host
spawn seal "$ADIR" > "$D/seal.out" 2>&1
[ "$(tail -n 1 "$D/seal.out")" = sealed ] || fail "the seal did not seal: $(tail -n 1 "$D/seal.out")"
spawn gate "$ADIR" > "$D/gate.out" 2>&1
[ "$(tail -n 1 "$D/gate.out")" = OK ] || fail "the gate did not pass: $(tail -n 1 "$D/gate.out")"
spawn collect "$ADIR" > "$D/collect.out" 2>&1
spawn candidate "$ADIR" --task r1 > "$D/candidate.out" 2>&1
[ "$(tail -n 1 "$D/candidate.out")" = candidate ] || fail "the candidate did not build: $(tail -n 1 "$D/candidate.out")"
[ "$(git -C "$RD/parent" show refs/heads/candidate/r1:src/a.py 2>/dev/null)" = v=2 ] || fail "the candidate isn't the worker's change"

# --- 4 nothing fired on the host
for m in HOOK-RAN CFG-RAN; do
  [ -e "$D/host/$m" ] && fail "a planted $m ran host-side through the chain: $(sort -u "$D/host/$m" | tr '\n' ' ')"
done
echo "  chain: seal, gate, collect, candidate -- no hook and no config command ran on the host"

# --- 4b the engine's own verb, on the attempt the worker already turned (a
# re-drive). Only an adapter whose manifest plants a repo config asks the
# attempt's repository anything (is the config file tracked?), so the seat's
# adapter is one that does; its turn is a shell that changes nothing. The
# config must land: a verb that refused before the question proves nothing
mkdir -p "$D/adapters"
cat > "$D/adapters/stub.toml" <<'TOML'
schema = 1
name = "stub"
tested_classes = ["write"]
tool_fencing = "unfenced"
argv = ["/bin/sh", "-c", "echo re-drive"]
repo_config = "opencode.json"
repo_config_body = '{ "model": "fixture" }'
engine_bins = ["bin/lib/stub-adapter.py"]
cost_stream = "jsonl"
TOML
OPERATOR_ADAPTERS="$D/adapters" timeout -k 10 150 python3 "$ENGINE/bin/spawn.py" adapter "$ADIR" --timeout 120 > "$D/redrive.out" 2>&1
grep -q "^rc=0" "$D/redrive.out" || fail "the re-drive never ran: $(tail -n 1 "$D/redrive.out")"
[ -f "$ADIR/repo/opencode.json" ] || fail "the re-drive never planted the config: the verb asked the repository nothing, so the leg proves nothing"
for m in HOOK-RAN CFG-RAN; do
  [ -e "$D/host/$m" ] && fail "a planted $m ran host-side through the engine's own verb on the turned attempt: $(sort -u "$D/host/$m" | tr '\n' ' ')"
done
echo "  re-drive: the engine's own verb on the turned attempt -- no hook and no config command ran on the host"

# --- 4c the writable clone: a seat that asks with shell, on an adapter whose
# manifest proves the class, writes its .git from inside the jail. The turn
# makes a branch and a worktree of its own and a side branch, THEN plants the
# zoo (a planted reference-transaction hook that cannot write its marker would
# abort the worker's own ref updates there). The real chain runs on that
# attempt, and nothing may fire on the host; .git is never delivered
printf 'schema = 1\nname = "phw"\nmax_parallel = 1\n[seat.w]\nrole = "roles/w.md"\nwrite = ["src/**"]\nadapter = "stub"\nshell = ["*"]\n[seat.w.budget]\nusd = 1.0\n' > "$PROG/team.toml"
mkdir -p "$D/cl-adapters"
sed 's/^tested_classes = .*/tested_classes = ["write", "shell"]/' "$ENGINE/config/adapters/stub.toml" > "$D/cl-adapters/stub.toml"
ADIR2=$(spawn attempt "$RD" --id phw-clone --seat w --grants "src/**" --task r1 --prog "$PROG") || die "the clone attempt refused to build"
TURN2=$(cat <<'TURN'
set -eu
git checkout -q -b feature/walk && echo BRANCH-OK
git worktree add -q -b walk-wt "$HOME/wt" && [ -f "$HOME/wt/.git" ] && echo WORKTREE-OK
echo side > "$HOME/side.txt"
b=$(git hash-object -w "$HOME/side.txt")
t=$(printf '100644 blob %s\tside-only.txt\n' "$b" | git mktree)
c=$(git -c user.email=a@x -c user.name=a commit-tree "$t" -m side)
git update-ref refs/heads/side "$c" && echo "$c" > src/side-sha.txt
echo clone-ok > src/clone-ok.txt
TURN
)
OPERATOR_ADAPTERS="$D/cl-adapters" timeout -k 10 150 python3 "$ENGINE/bin/spawn.py" worker "$ADIR2" --timeout 120 -- \
  /bin/sh -c "$TURN2
$(cat "$PLANT")" sh . "$D/host" > "$D/turn2.out" 2>&1
if ! grep -q "BRANCH-OK" "$ADIR2/transcript.out" 2>/dev/null || ! grep -q "WORKTREE-OK" "$ADIR2/transcript.out" 2>/dev/null; then
  fail "the clone turn could not branch or add a worktree: the jail gave no writable .git ($(tail -n 2 "$D/turn2.out" | tr '\n' '|'))"
fi
grep -q "fsmonitor" "$ADIR2/repo/.git/config" 2>/dev/null || fail "the clone turn planted nothing in .git from the jail: the leg proves nothing"
grep -q "^rc=0" "$D/turn2.out" || fail "the clone turn did not end clean: $(tail -n 1 "$D/turn2.out")"
spawn seal "$ADIR2" > "$D/seal2.out" 2>&1
[ "$(tail -n 1 "$D/seal2.out")" = sealed ] || fail "the clone's seal did not seal: $(tail -n 1 "$D/seal2.out")"
spawn gate "$ADIR2" > "$D/gate2.out" 2>&1
[ "$(tail -n 1 "$D/gate2.out")" = OK ] || fail "the clone's gate did not pass: $(tail -n 1 "$D/gate2.out")"
spawn candidate "$ADIR2" --task r1 > "$D/candidate2.out" 2>&1
[ "$(tail -n 1 "$D/candidate2.out")" = candidate ] || fail "the clone's candidate did not build: $(tail -n 1 "$D/candidate2.out")"
[ "$(git -C "$RD/parent" show refs/heads/candidate/r1:src/clone-ok.txt 2>/dev/null)" = clone-ok ] || fail "the clone's work is not the candidate"
if git -C "$RD/parent" ls-tree -r --name-only refs/attempts/phw-clone | grep -q '^\.git/'; then fail "the clone's .git was delivered"; fi
SIDE=$(cat "$ADIR2/repo/src/side-sha.txt" 2>/dev/null)
printf %s "$SIDE" | grep -qE '^[0-9a-f]{40}$' || fail "the clone turn recorded no side branch"
if git -C "$RD/parent" cat-file -e "${SIDE}^{commit}" 2>/dev/null; then fail "the parent learned the clone's side branch"; fi
for m in HOOK-RAN CFG-RAN; do
  [ -e "$D/host/$m" ] && fail "a planted $m, written by the worker in its clone, ran host-side through the chain: $(sort -u "$D/host/$m" | tr '\n' ' ')"
done
echo "  clone: a worker turn wrote its .git from the jail -- the chain delivered the work tree; no hook and no config command ran on the host; .git was not delivered"

# --- 5 the control: the same plants DO fire where git runs in those repositories on the host
fire_control "$ADIR/repo"
if [ ! -s "$D/host/HOOK-RAN" ] || [ ! -s "$D/host/CFG-RAN" ]; then fail "the control did not fire: the walk proves nothing"; fi
grep -q "fsmonitor" "$D/host/CFG-RAN" || fail "the control never fired the fsmonitor: the re-drive leg proves nothing"
rm -f -- "$D/host/HOOK-RAN" "$D/host/CFG-RAN"
fire_control "$ADIR2/repo"
if [ ! -s "$D/host/HOOK-RAN" ] || [ ! -s "$D/host/CFG-RAN" ]; then fail "the control did not fire on the clone: the clone leg proves nothing"; fi
grep -q "fsmonitor" "$D/host/CFG-RAN" || fail "the control never fired the clone's fsmonitor: the clone leg proves nothing"
echo "  control: git run in those repositories on the host fires the plants (the detection is live)"
echo "planted-hook-walk: OK (neither the chain, nor the engine's own verb, nor the seal of a clone runs git in the attempt; the plants are live)"
