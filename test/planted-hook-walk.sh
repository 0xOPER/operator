#!/usr/bin/env bash
# planted-hook-walk.sh -- the acceptance walk for the delivery invariant: the
# engine never runs git inside an attempt after the worker starts. A worker
# whose .git is writable (a writable clone, when a grant asks for one) could
# plant hooks and config-driven commands. This walk plants them where the
# worker would have: in the attempt's .git, after a real turn. The real
# delivery chain (seal, gate, collect, candidate) then runs, and nothing may
# fire on the host. A positive control proves the detection is live: git run
# in that repository ON THE HOST does fire the plants.
#
# --sabotage proves the walk can fail: against a copy of the engine whose
# collector runs git inside the attempt on the host, the same walk reports it.
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
}

selftest() {
  local rc=0 T
  T=$(mktemp -d) || exit 2
  trap 'rm -rf "${T:?}"' EXIT
  # A the plants are live where git runs in that repository: a hook and a
  # config-driven command both leave their trace
  fixture "$T/a" || die "no git fixture"
  sh "$PLANT" "$T/a" "$T/m" || die "the plants didn't take"
  fire_control "$T/a"
  grep -q "post-index-change" "$T/m/HOOK-RAN" 2>/dev/null || { echo "A a planted hook fired: no trace"; rc=1; }
  grep -q "credential" "$T/m/CFG-RAN" 2>/dev/null || { echo "A a planted config command fired: no trace"; rc=1; }
  # B a repository without the plants leaves nothing: the traces are the plants'
  fixture "$T/b" || die "no git fixture"
  mkdir -p "$T/m2"
  fire_control "$T/b"
  if [ -e "$T/m2/HOOK-RAN" ] || [ -e "$T/m2/CFG-RAN" ]; then echo "B a clean repository left a trace"; rc=1; fi
  if [ $rc = 0 ]; then echo "selftest: OK (the plants fire where git runs, and only there)"; else echo "selftest: FAIL"; fi
  exit $rc
}

sabotage() {
  # the walk must be able to fail: a collector that runs git inside the attempt
  # on the host is exactly the regression it stands for
  local S
  S=$(mktemp -d "${TMPDIR:-/tmp}/phw-sab.XXXX") || die "no scratch"
  [ -n "${PHW_KEEP:-}" ] || trap 'rm -rf "${S:?}"' EXIT
  mkdir -p "$S/engine"
  (cd "$ROOT" && tar --exclude=.git -cf - .) | (cd "$S/engine" && tar -xf -)
  if ! python3 -I - "$S/engine/bin/spawn.py" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); t = p.read_text()
old = "def collect(attempt):\n"
assert t.count(old) == 1
new = old + ("    import subprocess as _s  # SABOTAGE: git inside the attempt, on the host\n"
             "    _s.run([\"git\", \"-C\", os.path.join(attempt, \"repo\"), \"status\", \"--short\"], capture_output=True)\n")
p.write_text(t.replace(old, new))
PY
  then die "the doctoring didn't take"
  fi
  PLANTED_HOOK_ENGINE="$S/engine" bash "$ME" > "$S/walk.out" 2>&1
  local rc=$?
  if [ "$rc" = 0 ]; then
    echo "sabotage: FAIL (the walk passed against a collector that runs git in the attempt on the host)"
    sed 's/^/    /' "$S/walk.out"; exit 1
  fi
  grep -q "ran host-side" "$S/walk.out" || {
    echo "sabotage: FAIL (the doctored tree failed the walk for another reason)"; sed 's/^/    /' "$S/walk.out"; exit 1; }
  echo "sabotage: OK (the walk reports a collector that runs git inside the attempt on the host)"
  exit 0
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

# --- 5 the control: the same plants DO fire where git runs in that repository on the host
fire_control "$ADIR/repo"
if [ ! -s "$D/host/HOOK-RAN" ] || [ ! -s "$D/host/CFG-RAN" ]; then fail "the control did not fire: the walk proves nothing"; fi
echo "  control: git run in that repository on the host fires the plants (the detection is live)"
echo "planted-hook-walk: OK (the chain never runs git in the attempt; the plants are live)"
