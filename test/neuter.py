#!/usr/bin/env python3
"""neuter -- break each check on purpose and confirm its tool's selftest notices.

Each row of NEUTERS is a one-line patch to one tool. The job applies it to a copy
of the tree and runs that tool's --selftest, which must then fail. A neuter that
survives fails the build unless test/neuter-survivors.txt names it, and an entry
there that no longer survives fails too. NEUTER_FLOOR and SURVIVOR_CEILING are pinned
below, so shrinking the table or growing the baseline shows up as a diff to them. A
tool with a selftest and no neuter it kills isn't tested, and fails unless
test/selftest-exceptions.tsv names it. This covers only the rows in test/neuters.py.
Run it through test/cleanroom.sh.

usage: neuter.py [--only ID ...]
exit: 0 holds, 1 a new survivor or an untested tool, 2 VOID
"""
import argparse
import os
import concurrent.futures
import pathlib
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "test"))
from neuters import NEUTERS as PUBLIC_NEUTERS  # noqa: E402
try:
    from neuters_private import PRIVATE_NEUTERS  # noqa: E402
    _HAS_PRIVATE = True
except ImportError:
    PRIVATE_NEUTERS = []
    _HAS_PRIVATE = False

NEUTERS = list(PUBLIC_NEUTERS) + list(PRIVATE_NEUTERS)

# Gates with a selftest of their own.
GATES = ("test/wave-job.sh", "test/closure-check.sh")
SURVIVORS = ROOT / "test" / "neuter-survivors.txt"
EXCEPTIONS = ROOT / "test" / "selftest-exceptions.tsv"
TIMEOUT = 300
PUBLIC_NEUTER_FLOOR = 450
PRIVATE_NEUTER_FLOOR = 475
NEUTER_FLOOR = PRIVATE_NEUTER_FLOOR if _HAS_PRIVATE else PUBLIC_NEUTER_FLOOR
SURVIVOR_CEILING = 0    # the baseline's size; only ever lower it
WORKERS = min(8, os.cpu_count() or 4)


def listed(path, columns=1):
    if not path.exists():
        return set()
    rows = (ln.split("\t") for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#"))
    return {r[0].strip() for r in rows if len(r) >= columns and all(r[:columns])}


def tools_with_selftest():
    out = []
    for pat in ("bin/*", "scripts/*"):
        for p in sorted(ROOT.glob(pat)):
            if p.is_file() and "--selftest" in p.read_text(errors="replace"):
                out.append(p.relative_to(ROOT).as_posix())
    return out + [g for g in GATES if (ROOT / g).exists()]


def _force_rmtree(p):
    for root, dirs, files in os.walk(p):
        for n in dirs:
            try:
                os.chmod(os.path.join(root, n), 0o700)
            except OSError:
                pass
        for n in files:
            try:
                os.chmod(os.path.join(root, n), 0o600)
            except OSError:
                pass
    shutil.rmtree(p, ignore_errors=True)


def why(out):
    """The last lines of a test's output: what a row that did not die was saying."""
    lines = [ln.strip() for ln in out.decode("utf-8", "replace").splitlines() if ln.strip()]
    return " | ".join(ln[:200] for ln in lines[-3:])


def run_test(tree, tool, cmd, tmpdir=None):
    argv = [str(tree / cmd[0]), *cmd[1:]] if cmd else [str(tree / tool), "--selftest"]
    env = {**os.environ, "OPERATOR_AST_MUTANTS": "1"}
    if tmpdir:
        env["TMPDIR"] = str(tmpdir)
    try:
        r = subprocess.run(argv, cwd=tree, capture_output=True, timeout=TIMEOUT,
                           env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        return 124, False, "timed out; last output: " + why((e.stdout or b"") + (e.stderr or b""))
    out = (r.stdout or b"") + (r.stderr or b"")
    has_fail = any(m in out for m in (b"FAIL", b"AssertionError", b"Traceback"))
    # rc 0 with no OK line: the tool failed and swallowed it
    rc = r.returncode if r.returncode or b": OK" in r.stdout else 99
    return rc, has_fail, why(out)


def parses(path):
    if path.suffix == ".tsv":  # a rule file: its tool's selftest reads it
        return True
    cmd = [sys.executable, "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read())"] if path.suffix == ".py" else ["bash", "-n"]
    return subprocess.run([*cmd, str(path)], capture_output=True).returncode == 0


def copy_tree(d):
    tree = pathlib.Path(d, "tree")
    shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(".git", "__pycache__"), symlinks=True)
    return tree


def run_row(row):
    """Apply one row to its own copy of the tree. The test's rc, or None if the patch doesn't parse."""
    tool, old, new = row[1:4]
    cmd = row[4].split() if len(row) > 4 else None
    d = tempfile.mkdtemp(prefix="neuter.")
    try:
        sub_tmp = pathlib.Path(d, "tmp")
        sub_tmp.mkdir()
        tree = copy_tree(d)
        path = tree / tool
        mode = path.stat().st_mode
        path.write_text(path.read_text().replace(old, new))
        path.chmod(mode)
        return run_test(tree, tool, cmd, tmpdir=sub_tmp) if parses(path) else None
    finally:
        _force_rmtree(d)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--on-host", action="store_true",
                    help="run modified tools on the host (first-level rows need bwrap, "
                         "which the room cannot nest on this host); the room is the default")
    a = ap.parse_args()
    if not a.on_host and not os.environ.get("NEUTER_ROOM_OK"):
        in_room = os.path.isdir("/work/operator") and not [d for d in ("/home",) if os.listdir(d)]
        if not in_room:
            print("neuter: run me through test/cleanroom.sh (modified tools belong in the "
                  "room); pass --on-host ONLY for rows whose tests need bwrap, and know "
                  "that no row may weaken a guard whose break signals processes outside "
                  "its own children or outgrows its memory -- such a row re-arms the "
                  "incident class", file=sys.stderr)
            return 2
    if not NEUTERS:
        print("neuter: VOID, no neuters", file=sys.stderr)
        return 2
    # An exception needs its reason, owner and expiry wave, as in the battery.
    allowed_survivors, exceptions = listed(SURVIVORS), listed(EXCEPTIONS, 4)
    unknown = set(a.only or []) - {r[0] for r in NEUTERS}
    if unknown or len(NEUTERS) < NEUTER_FLOOR or len(allowed_survivors) > SURVIVOR_CEILING:
        print(f"neuter: VOID, unknown ids {sorted(unknown)}, or rows {len(NEUTERS)}<{NEUTER_FLOOR}, or baseline {len(allowed_survivors)}>{SURVIVOR_CEILING}", file=sys.stderr)
        return 2
    killed_by_tool, survivors, timeouts, voids, bad = {}, set(), set(), set(), 0
    rows = [r for r in NEUTERS if (not a.only or r[0] in a.only)]
    for id_, tool, old, *_ in rows:
        if not (ROOT / tool).is_file():
            print(f"neuter: VOID, {id_}: missing target {tool}", file=sys.stderr)
            return 2
        n = (ROOT / tool).read_text().count(old)
        if n != 1:
            print(f"neuter: VOID, {id_}: pattern found {n} times in {tool}", file=sys.stderr)
            return 2
    # Each test must be green on the untouched tree, or a kill proves nothing.
    tests = sorted({r[4] if len(r) > 4 else r[1]: (r[1], r[4].split() if len(r) > 4 else None) for r in rows}.items())

    def _check_base(item):
        key, (tool, cmd) = item
        d0 = tempfile.mkdtemp(prefix="neuter-base.")
        try:
            stmp = pathlib.Path(d0, "tmp")
            stmp.mkdir()
            rc = run_test(copy_tree(d0), tool, cmd, tmpdir=stmp)[0]
            return key, rc
        finally:
            _force_rmtree(d0)

    with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
        for key, rc in pool.map(_check_base, tests):
            if rc != 0:
                print(f"neuter: VOID, {key} is red before any neuter (rc={rc})", file=sys.stderr)
                return 2
        for row, res in zip(rows, pool.map(run_row, rows)):
            id_, tool = row[:2]
            if res is None:
                print(f"neuter: VOID, {id_} doesn't parse, so a failure would prove nothing", file=sys.stderr)
                return 2
            rc, has_fail, note = res
            if rc == 0:
                state = "SURVIVED"
                survivors.add(id_)
            elif rc == 124:
                state = "TIMEOUT"
                timeouts.add(id_)
            elif rc == 2:
                state = "VOID"
                voids.add(id_)
            elif rc == 1 or has_fail:
                state = "killed"
                killed_by_tool[tool] = killed_by_tool.get(tool, 0) + 1
            else:
                state = f"RC={rc}"
                voids.add(id_)
            # A row that did not die says why: the verdict line alone cannot be told
            # apart from an environment that broke the test (first-level rows in a
            # room that cannot nest bwrap) from a row that no longer sees its break
            line = f"{state:9} {id_:12} {tool}"
            print(line if state == "killed" else f"{line}\n          why: {note}", flush=True)
    new_survivors = survivors - allowed_survivors
    if a.only:
        print(f"only={len(a.only)} killed={sum(killed_by_tool.values())} survived={len(survivors)} timeout={len(timeouts)} void={len(voids)}")
        return 1 if (new_survivors or timeouts or voids) else 0
    stale = allowed_survivors - survivors
    untested = [t for t in tools_with_selftest() if t not in killed_by_tool and pathlib.Path(t).name not in exceptions]
    for s in sorted(new_survivors):
        print(f"NEW SURVIVOR {s}")
        bad += 1
    for t_id in sorted(timeouts):
        print(f"TIMEOUT {t_id}: timed out at {TIMEOUT}s (not counted as killed)")
        bad += 1
    for v_id in sorted(voids):
        print(f"VOID {v_id}: exited VOID or without failure marker (not counted as killed)")
        bad += 1
    for s in sorted(stale):
        print(f"STALE BASELINE {s}: it no longer survives, so remove it from {SURVIVORS.name}")
        bad += 1
    for t in untested:
        print(f"UNTESTED {t}: no neuter makes its selftest fail")
        bad += 1
    total = sum(killed_by_tool.values())
    print(f"neuters={len(NEUTERS)} killed={total} survived={len(survivors)} timeout={len(timeouts)} void={len(voids)} baseline={len(allowed_survivors)} tools_tested={len(killed_by_tool)}")
    if total == 0:
        print("neuter: VOID, nothing was killed", file=sys.stderr)
        return 2
    return 1 if bad else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as e:
        print(f"neuter: VOID, {e}", file=sys.stderr)
        sys.exit(2)
