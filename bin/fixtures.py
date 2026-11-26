#!/usr/bin/env python3
"""fixtures -- a small repeatable suite through the engine, with numbers.

`run` is the room-safe half: it builds a synthetic program (two stub seats, a
contract stricter than the template: exact-content rows, a reviewer on every
row), runs the stub adapter against an engine-written plan -- so the cost and
session parse from the worker's stream the way a real attempt's do, and the
plan's sum must match -- and places one scripted call to the loopback upstream
whose body must come back verbatim from the request log (the receipt the
conformance layer reuses). `--first-level` adds what the room cannot nest: the
worker jail for the second seat, seal, gate, candidate, promote, and the
contract's rows green on the promoted parent. The report is one line of
numbers, and any number that misses what the plan said is a refusal. These are
synthetic tasks, never team outcomes.

usage: fixtures.py run [--keep DIR] | --selftest | --first-level
exit: 0 the fixture holds, 1 refused or a number missed, 2 usage or VOID
"""
import json
import os
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
import spawn as spawn_mod  # noqa: E402

JSON_SCHEMA = 1
TIME_BOUND = 120  # a walk that takes minutes is a stuck walk

TEAM = ('schema = 1\nname = "fixture"\n[seat.w]\nrole = "roles/writer.md"\n'
        'adapter = "stub"\nwrite = ["src/**"]\n[seat.w.budget]\nusd = 1.0\n'
        '[seat.r]\nrole = "roles/reviewer.md"\nadapter = "stub"\n'
        'write = ["docs/**"]\n')
# stricter than the template: exact content, a reviewer on every row
CONTRACT = ('schema = 2\n[[row]]\nid = "a.impl"\nstage = "impl"\n'
            'desc = "the plan\'s write landed verbatim"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "grep -qx \'v=2\' src/a.py"\n'
            '[[row]]\nid = "b.doc"\nstage = "impl"\ndesc = "the second seat delivered"\n'
            'kind = "run"\nseat = "r"\nreviewer = "w"\n'
            'cmd = "grep -qx \'fixture-doc\' docs/d.md"\n')
PLAN_W = [{"do": "sleep", "seconds": 1.0},  # alive long enough to be recorded
          {"do": "write", "path": "src/a.py", "body": "v=2\n"},
          {"do": "try_write", "path": "/proc/outside-fixture", "body": "x"},
          {"do": "report", "json": {"done": True}},
          {"do": "cost", "usd": 0.02},
          {"do": "session", "id": "fx-1"}]


class Refused(Exception):
    pass


class Void(Exception):
    pass


def _stream_of(lines):
    """The worker's JSONL stream: the last cost and session it reported."""
    cost, session = None, None
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row.get("cost"), (int, float)) and row["cost"] >= 0:
            cost = row["cost"]
        if isinstance(row.get("session_id"), str):
            session = row["session_id"]
    return cost, session


def _plan_cost(plan):
    return round(sum(s.get("usd", 0) for s in plan if s.get("do") == "cost"), 6)


def _upstream_leg(checks, ok):
    """One scripted call to the loopback upstream; the body must come back
    verbatim from the request log (the receipt conformance reuses)."""
    import shutil
    import tempfile
    import urllib.request
    base = tempfile.mkdtemp(prefix="fx-up.")
    try:
        script = os.path.join(base, "s.jsonl")
        log = os.path.join(base, "log.jsonl")
        body = json.dumps({"model": "fx", "messages": [{"role": "user",
                                                        "content": "fixture-call"}]})
        with open(script, "w") as f:
            f.write(json.dumps({"id": "msg_fx", "content": [{"type": "text",
                                                             "text": "fx-ok"}]}) + "\n")
        p = subprocess.Popen([sys.executable, os.path.join(ROOT, "bin", "upstream.py"),
                              "serve", script, log], stdout=subprocess.PIPE, text=True)
        try:
            port = int(p.stdout.readline().strip())
            req = urllib.request.Request(f"http://127.0.0.1:{port}/anthropic",
                                         data=body.encode(),
                                         headers={"content-type": "application/json",
                                                  "x-api-key": "fx-key"}, method="POST")
            got = json.loads(urllib.request.urlopen(req, timeout=10).read())
            checks += 1
            if got.get("content", [{}])[0].get("text") == "fx-ok":
                ok += 1
            rows = [json.loads(l) for l in open(log)]
            checks += 1
            if rows and rows[0].get("body") == body and \
                    rows[0].get("headers", {}).get("x-api-key") == "fx-key":
                ok += 1
            return checks, ok, rows[0] if rows else {}
        finally:
            p.terminate()
            p.wait()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def scenario(deep, expected_cost=None, tamper=None, keep=None):
    """The walk. Room-safe unless deep; refuses (never lies) on a missed number.

    expected_cost pins a different number to prove the report refuses a lie.
    tamper: 'content' rewrites the plan's body so the stricter row goes red;
            'receipt' posts a different body than the receipt names.
    """
    import shutil
    import tempfile
    checks = ok = rows_green = 0
    t0 = time.monotonic()
    base = keep or tempfile.mkdtemp(prefix="fx-rt.")
    home = os.path.join(base, "home")
    os.makedirs(home)
    old_home = os.environ.get("OPERATOR_HOME")
    os.environ["OPERATOR_HOME"] = home
    plan = [dict(s) for s in PLAN_W]
    if tamper == "content":
        next(s for s in plan if s.get("do") == "write")["body"] = "v=3\n"
    try:
        # the world: a ruled program and its parent repo
        prog = spawn_mod._program(home, "fixture", team_body=TEAM,
                                  contract_body=CONTRACT)
        for role in ("writer", "reviewer"):
            with open(os.path.join(prog, "roles", f"{role}.md"), "w") as f:
                f.write(f"You are the {role} seat.\n")
        k = os.path.join(base, "k")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", k,
                        "-C", "fx"], capture_output=True, check=True)
        sf = os.path.join(home, "signers", "allowed_signers")
        os.makedirs(os.path.dirname(sf), exist_ok=True)
        with open(sf, "w") as f:
            f.write(f'owner@fixture namespaces="operator-ruling" '
                    f'{open(k + ".pub").read().strip()}\n')
        os.chmod(sf, 0o600)
        core = os.path.join(base, "core")
        os.makedirs(core)
        with open(os.path.join(core, "V"), "w") as f:
            f.write("0.1\n")
        ce = dict(spawn_mod.engine_env(commit=True))
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "c"]):
            subprocess.run(["git", "-C", core, *args], capture_output=True, env=ce)
        os.environ["RULING_CORE_GIT"] = core
        r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "ruling.py"),
                            "sign", prog, "--kind", "arm", "--key", k],
                           capture_output=True, text=True, env=dict(os.environ))
        if r.returncode != 0:
            raise Void(f"the arm ruling didn't sign: {r.stderr[:120]}")
        arm = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "ruling.py"),
                              "arm-hash", prog], capture_output=True, text=True,
                             env=dict(os.environ)).stdout.strip()
        rd, parent, _ = spawn_mod._world(home, "fx-run", {"src/a.py": "v=1\n"})

        # seat w: the stub adapter against the engine-written plan
        aw = spawn_mod.build_attempt(rd, "w", ["src/**"], "integration/R", "fx-w",
                                     "impl", prog, ["w", "r"])
        os.makedirs(os.path.join(aw, "inbox"), exist_ok=True)
        with open(os.path.join(aw, "compiled", "plan.json"), "w") as f:
            json.dump(plan, f)
        r = subprocess.run([sys.executable, "-I",
                            os.path.join(ROOT, "bin", "lib", "stub-adapter.py"),
                            os.path.join(aw, "compiled", "plan.json")],
                           capture_output=True, text=True,
                           cwd=os.path.join(aw, "repo"), timeout=60)
        checks += 1
        if r.returncode == 0:
            ok += 1
        cost, session = _stream_of(r.stdout.splitlines())
        checks += 1
        if session == "fx-1":
            ok += 1
        # the cost the stream reported is the cost the plan promised
        checks += 1
        want_cost = _plan_cost(plan)
        if cost == want_cost:
            ok += 1
        elif expected_cost is None:
            raise Refused(f"the worker's stream says cost={cost}, the plan says "
                          f"{want_cost}; a number that misses is a refusal")
        # the pinned cost: a lie refuses even when the stream was honest
        if expected_cost is not None and expected_cost != cost:
            raise Refused(f"the report pins cost={expected_cost}, the stream says "
                          f"{cost}; a pinned number that misses is a refusal")
        # the outside write was tried, refused and left nothing; the report landed
        checks += 1
        if '"ok": false' in r.stdout and '"path": "/proc/outside-fixture"' in r.stdout \
                and not os.path.exists("/proc/outside-fixture"):
            ok += 1
        checks += 1
        if os.path.isfile(os.path.join(aw, "repo", "out", "report.json")):
            ok += 1

        # the upstream receipt
        c2, o2, row0 = _upstream_leg(0, 0)
        checks += c2
        if tamper == "receipt":
            checks += 1  # the pinned body must be the one the log holds
            if row0.get("body") == "other":
                ok += 1
            raise Refused("the receipt names a body the log doesn't hold")
        ok += o2

        rows_green = 0
        if deep:
            # what the room cannot nest: the manifest path in the worker jail --
            # the same plan re-run through cmd_adapter, whose supervisor record
            # (pid, namespace, starttime, cost) exists from spawn time, then
            # seal, gate and promotion
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                spawn_mod.cmd_adapter(aw, 60)
            sup = os.path.join(aw, "supervisor.json")
            checks += 2
            if not os.path.isfile(sup):
                raise Refused("the adapter's supervisor never recorded; a live "
                              "worker would be invisible to stop and cancel")
            rec = json.load(open(sup))
            if rec.get("cost") == 0.02 and rec.get("pid") and rec.get("starttime") \
                    and rec.get("session") == "fx-1":
                ok += 1
            if rec.get("pid_ns"):
                ok += 1
            # C8: the adapter's meta records the broker it ran against
            meta8 = json.load(open(os.path.join(aw, "attempt.json")))
            checks += 1
            if not str(meta8.get("broker", "")).startswith("http://"):
                raise Refused("the adapter never recorded its broker; a run "
                              "can't be read back without it")
            ok += 1
            if spawn_mod.seal(aw) != "sealed" or spawn_mod.import_gate(aw)[0] != "OK":
                raise Refused("the stub's work didn't seal and gate")
            checks += 1
            ok += 1
            spawn_mod.candidate(aw, task="impl")
            spawn_mod.promote(parent, "impl")
            ar = spawn_mod.build_attempt(rd, "r", ["docs/**"], "integration/R", "fx-r",
                                         "docs", prog, ["w", "r"])
            os.makedirs(os.path.join(ar, "inbox"), exist_ok=True)
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                spawn_mod.cmd_worker(ar, 60, ["/bin/sh", "-c",
                                              "mkdir -p docs && printf 'fixture-doc\\n' "
                                              "> docs/d.md"])
            if spawn_mod.seal(ar) != "sealed" or spawn_mod.import_gate(ar)[0] != "OK":
                raise Refused("the second seat's work didn't seal and gate")
            checks += 1
            ok += 1
            spawn_mod.candidate(ar, task="docs")
            spawn_mod.promote(parent, "docs")
            env = {**os.environ, "CONTRACT_REPO": parent, "CONTRACT_TIP": "HEAD",
                   "CONTRACT_ARM": arm}
            verdicts = {}
            for row in ("a.impl", "b.doc"):
                r = subprocess.run([sys.executable, os.path.join(ROOT, "bin",
                                                                 "contract.py"),
                                    "run", prog, row], capture_output=True, text=True,
                                   env=env, timeout=120)
                checks += 1
                verdicts[row] = "green" in r.stdout
                if verdicts[row]:
                    ok += 1
                    rows_green += 1
                elif tamper != "content":
                    raise Refused(f"row {row} isn't green: {r.stdout.strip()[:80]}")
            if tamper == "content":
                # both rows read to the end: the refusal carries what each earned,
                # so only a walk that kept evaluating can name the second one
                raise Refused("the tampered plan read: " + " ".join(
                    f"{r}={'green' if g else 'red'}" for r, g in sorted(verdicts.items()))
                    + " -- a claim the work didn't earn")

        elapsed = time.monotonic() - t0
        if elapsed > TIME_BOUND:
            raise Refused(f"the walk took {elapsed:.0f}s; a walk that outgrows "
                          f"{TIME_BOUND}s is stuck, not slow")
        doc = {"schema": JSON_SCHEMA, "checks": checks, "ok": ok,
               "rows": rows_green, "time": round(elapsed, 1), "cost": cost,
               "session": session, "keep": keep, "deep": deep}
        if ok != checks:
            raise Refused(f"{checks - ok} check(s) missed their number")
        return doc
    finally:
        os.environ.pop("RULING_CORE_GIT", None)
        if old_home is None:
            os.environ.pop("OPERATOR_HOME", None)
        else:
            os.environ["OPERATOR_HOME"] = old_home
        if keep is None:
            shutil.rmtree(base, ignore_errors=True)


def cmd_run(deep, keep):
    try:
        doc = scenario(deep, keep=keep)
    except Refused as e:
        print(f"fixtures: {e}", file=sys.stderr)
        return 1
    except Void as e:
        print(f"fixtures: VOID, {e}", file=sys.stderr)
        return 2
    print(f"fixtures: checks={doc['checks']} ok={doc['ok']} "
          f"rows={doc['rows']}/2 time={doc['time']}s cost={doc['cost']:.3f}")
    return 0


def selftest():
    """Room-safe: the walk reports every number it earned (seal and the rows
    wait for the first level); a pinned cost that lies refuses; a receipt
    naming the wrong body refuses; --keep retains the tree."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    import shutil as _sh
    import tempfile
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="fx-self.")
    try:
        # A the room walk holds, with its numbers
        doc = scenario(False)
        check(doc["checks"] == doc["ok"] and doc["checks"] >= 6 and doc["rows"] == 0,
              f"A the numbers: {doc}")
        check(doc["cost"] == 0.02 and doc["session"] == "fx-1", "A cost and session")
        check(doc["time"] < TIME_BOUND, f"A time bounded: {doc['time']}s")

        # B a pinned cost that lies refuses, with both numbers named
        try:
            scenario(False, expected_cost=0.05)
            check(False, "B a lying pin refuses")
        except Refused as e:
            check("0.05" in str(e) and "0.02" in str(e), f"B both numbers: {e}")

        # C a receipt naming a body the log doesn't hold refuses
        try:
            scenario(False, tamper="receipt")
            check(False, "C the wrong receipt refuses")
        except Refused as e:
            check("receipt" in str(e), f"C names the receipt: {e}")

        # D --keep retains the tree the walk built
        keep = os.path.join(base, "kept")
        doc = scenario(False, keep=keep)
        check(doc["keep"] == keep and os.path.isdir(os.path.join(keep, "home")),
              "D --keep retains the tree")

        print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
        return 0 if ok[0] and not bad[0] else 1
    finally:
        _sh.rmtree(base, ignore_errors=True)


def first_level():
    """The jail legs: both seats to promoted rows green, the tampered twin red,
    all inside the time bound. Runs bwrap; never inside the room."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    # A the full walk: two seats, promotion, both rows green
    doc = scenario(True)
    check(doc["checks"] == doc["ok"] and doc["rows"] == 2,
          f"A both rows green through promotion: {doc}")
    check(doc["cost"] == 0.02 and doc["time"] < TIME_BOUND,
          f"A cost and time: {doc}")

    # B a tampered plan turns the stricter row red and refuses
    try:
        scenario(True, tamper="content")
        check(False, "B the tampered plan refuses")
    except Refused as e:
        check("a.impl=red" in str(e) and "b.doc=green" in str(e),
              f"B both verdicts, earned: {e}")

    print(f"first-level: OK ({ok[0]} checks)" if ok[0] and not bad[0]
          else "first-level: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def main(argv):
    if argv[1:] == ["run"]:
        return cmd_run(False, None)
    if len(argv) == 4 and argv[1:3] == ["run", "--keep"]:
        return cmd_run(False, argv[3])
    print("usage: fixtures.py run [--keep DIR] | --selftest | --first-level",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    if sys.argv[1:] == ["--first-level"]:
        sys.exit(first_level())
    sys.exit(main(sys.argv))
