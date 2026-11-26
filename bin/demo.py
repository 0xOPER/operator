#!/usr/bin/env python3
"""demo -- two seats to done in under a minute, and the three refusals.

The whole engine on one screen, first level: a ruled program with two stub
seats, a forged claim the contract refuses to honor (the row stays red until
honest evidence exists), both seats through worker, seal, gate and promotion to
green rows, an outside write refused while the same write inside the layout
lands, and the network fence end to end -- a listener behind the egress proxy
counts nothing for a denied host, one hit for an allowed host through the jail's
relay, one more for the same connect from the host. Without bubblewrap it says
sandbox=unavailable, says what that means, and exits non-zero.

usage: demo.py run [--keep DIR] | --selftest | --first-level
exit: 0 the demo holds, 1 refused or a number missed, 2 usage or VOID
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
import spawn as spawn_mod  # noqa: E402
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location(
    "egress_proxy", os.path.join(ROOT, "bin", "egress-proxy.py"))
_ep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ep)
_client_hello = _ep.hello  # the demo's probe speaks TLS-shaped bytes

TIME_BOUND = 60
TEAM = ('schema = 1\nname = "demo"\n[seat.w]\nrole = "roles/writer.md"\n'
        'adapter = "stub"\nwrite = ["src/**"]\n[seat.w.budget]\nusd = 1.0\n'
        '[seat.r]\nrole = "roles/reviewer.md"\nadapter = "stub"\n'
        'write = ["docs/**"]\n')
CONTRACT = ('schema = 2\n[[row]]\nid = "a.impl"\nstage = "impl"\n'
            'desc = "the plan\'s write landed verbatim"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "grep -qx \'v=2\' src/a.py"\n'
            '[[row]]\nid = "b.doc"\nstage = "impl"\ndesc = "the second seat delivered"\n'
            'kind = "run"\nseat = "r"\nreviewer = "w"\n'
            'cmd = "grep -qx \'fixture-doc\' docs/d.md"\n'
            '[[row]]\nid = "c.evidence"\nstage = "impl"\n'
            'desc = "honest evidence, not a claim"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "test -f src/evidence.txt"\n')
PLAN_W = [{"do": "sleep", "seconds": 1.0},  # alive long enough to be recorded
          {"do": "write", "path": "src/a.py", "body": "v=2\n"},
          {"do": "try_write", "path": "/proc/outside-demo", "body": "x"},
          {"do": "report", "json": {"done": True}},
          {"do": "cost", "usd": 0.02},
          {"do": "session", "id": "demo-1"}]


class Refused(Exception):
    pass


class Void(Exception):
    pass


def bwrap_missing():
    return shutil.which("bwrap") is None


def sandbox_unavailable():
    print("demo: sandbox=unavailable -- bubblewrap is missing, so no worker can "
          "run jailed and an unattended run refuses rather than run loose; "
          "install it (apt install bubblewrap) and run me again", file=sys.stderr)
    return 1


def _run_row(prog, row, parent, arm, want_green):
    env = {**os.environ, "CONTRACT_REPO": parent, "CONTRACT_TIP": "HEAD",
           "CONTRACT_ARM": arm}
    r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "contract.py"),
                        "run", prog, row], capture_output=True, text=True,
                       env=env, timeout=120)
    green = "green" in r.stdout
    return (green is want_green), r.stdout.strip()[:80]


def _listener():
    """A TCP listener that counts its hits and answers with a banner."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    hits = [0]

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            hits[0] += 1
            try:
                c.recv(1024)
                c.sendall(b"listener-ok")
            except OSError:
                pass
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv, hits


PROBE = r"""
import socket, sys
port = int(sys.argv[1])
def speak(req, wait_reply):
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
    c.sendall(req)
    if wait_reply is None:
        c.shutdown(socket.SHUT_WR)
    data = b""
    try:
        while True:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
            if wait_reply is not None and b"listener-ok" in data:
                break
    except OSError:
        pass
    c.close()
    return data
hello = bytes.fromhex(sys.argv[2])
out = []
d = speak(b"CONNECT denied.test:443 HTTP/1.1\r\n\r\n", None)
out.append(b"denied:" + d[:13])
d = speak(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n" + hello + b"payload", b"ok")
out.append(b"allowed:" + d[:13] + (b"-hit" if b"listener-ok" in d else b"-miss"))
print(b" ".join(out).decode("ascii", "replace"))
"""


def _network_leg(base):
    """The fence, end to end: a denied host never reaches the listener, an
    allowed host reaches it through the jail's relay, the host reaches it too."""
    srv, hits = _listener()
    lport = srv.getsockname()[1]
    sockdir = os.path.join(base, "socks")
    policy = os.path.join(base, "policy")
    log = os.path.join(base, "egress.log")
    future = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    with open(policy, "w") as f:
        f.write(f"* until {future}\n!denied.test\n"
                f"pin allowed.test 127.0.0.1 {lport}\n")
    px = subprocess.Popen([sys.executable, "-I",
                           os.path.join(ROOT, "bin", "egress-proxy.py"),
                           "serve", sockdir, policy, log],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    probe = os.path.join(base, "probe.py")
    with open(probe, "w") as f:
        f.write(PROBE)
    hello_hex = _client_hello("allowed.test").hex()
    try:
        for _ in range(100):
            if os.path.exists(os.path.join(sockdir, "proxy.sock")):
                break
            time.sleep(0.05)
        if not os.path.exists(os.path.join(sockdir, "proxy.sock")):
            raise Refused("the egress proxy never bound its socket")
        before = hits[0]
        jail = [shutil.which("bwrap"), "--die-with-parent", "--new-session",
                "--unshare-all", "--cap-drop", "ALL",
                "--ro-bind", "/usr", "/usr",
                "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
                "--symlink", "usr/lib64", "/lib64", "--ro-bind-try",
                "/etc/alternatives", "/etc/alternatives",
                "--proc", "/proc", "--dev", "/dev", "--size", "134217728",
                "--tmpfs", "/tmp",
                "--ro-bind", os.path.join(ROOT, "bin", "egress-proxy.py"),
                "/tmp/egress-proxy.py",
                "--ro-bind", probe, "/tmp/probe.py",
                "--bind", sockdir, "/run/socks",
                "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
                "--setenv", "HOME", "/tmp",
                "--setenv", "HTTPS_PROXY", "http://127.0.0.1:3128",
                "--setenv", "HTTP_PROXY", "http://127.0.0.1:3128",
                "--chdir", "/tmp", "--",
                "/bin/sh", "-c",
                "python3 -I /tmp/egress-proxy.py relay /run/socks/proxy.sock "
                "--port 3128 & sleep 0.5; python3 -I /tmp/probe.py 3128 "
                f"{hello_hex}"]
        r = subprocess.run(jail, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise Refused(f"the jailed probe failed: {r.stderr[-160:]}")
        denied_ok = "denied:HTTP/1.1 403" in r.stdout
        allowed_ok = "allowed:HTTP/1.1 200" in r.stdout and "-hit" in r.stdout
        through = hits[0] - before
        # the same connect, from the host, straight at the listener
        c = socket.create_connection(("127.0.0.1", lport), timeout=10)
        c.sendall(b"host-side")
        c.recv(64)
        c.close()
        host_side = hits[0] - before - through
        rows = open(log, encoding="ascii").read().splitlines()
        return {"denied_ok": denied_ok, "allowed_ok": allowed_ok,
                "through": through, "host_side": host_side, "rows": rows}
    finally:
        px.terminate()
        px.wait(10)
        srv.close()


def scenario(keep=None):
    """The whole demo. Returns its numbers; refuses on any miss."""
    checks = ok = 0
    t0 = time.monotonic()
    base = keep or tempfile.mkdtemp(prefix="demo-rt.")
    home = os.path.join(base, "home")
    os.makedirs(home, exist_ok=True)
    old_home = os.environ.get("OPERATOR_HOME")
    os.environ["OPERATOR_HOME"] = home
    try:
        import run as run_mod
        prog = spawn_mod._program(home, "demo", team_body=TEAM,
                                  contract_body=CONTRACT)
        for role in ("writer", "reviewer"):
            with open(os.path.join(prog, "roles", f"{role}.md"), "w") as f:
                f.write(f"You are the {role} seat.\n")
        k = os.path.join(base, "k")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", k,
                        "-C", "demo"], capture_output=True, check=True)
        sf = os.path.join(home, "signers", "allowed_signers")
        os.makedirs(os.path.dirname(sf), exist_ok=True)
        with open(sf, "w") as f:
            f.write(f'owner@fixture namespaces="operator-ruling" '
                    f'{open(k + ".pub").read().strip()}\n')
        os.chmod(sf, 0o600)
        core = os.path.join(base, "core")
        os.makedirs(core, exist_ok=True)
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
        rd, parent, base_sha = spawn_mod._world(home, "demo-run", {"src/a.py": "v=1\n"})
        now_ts = time.time()
        run_mod._save_run(rd, {
            "state": "running", "autonomy": "attended",
            "program": os.path.abspath(prog), "run": "demo-run",
            "started_at": now_ts, "base_commit": base_sha, "arm_hash": arm,
        })
        run_mod.log_event(rd, "start", run="demo-run", autonomy="attended",
                          seats=["r", "w"], program=os.path.abspath(prog))

        def _record_settled(aid, seat, task, usd):
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            with open(os.path.join(rd, "ledger.tsv"), "a", encoding="utf-8") as lf:
                lf.write(f"{aid}\t{seat}\t{task}\t{usd:.4f}\tsettled\t{stamp}\n")

        # the forgery: a claim the contract refuses to honor -- every row red
        # against the base, whatever the worker's report says
        forged = os.path.join(rd, "attempts", "forged", "out")
        os.makedirs(forged, exist_ok=True)
        with open(os.path.join(forged, "report.json"), "w") as f:
            json.dump({"done": True, "claim": "all rows pass"}, f)
        for row in ("a.impl", "b.doc", "c.evidence"):
            checks += 1
            held, _ = _run_row(prog, row, parent, arm, want_green=False)
            ok += 1 if held else 0

        # seat w: real jailed stub adapter turn; outside write refused by jail
        aw = spawn_mod.build_attempt(rd, "w", ["src/**"], "integration/R", "demo-w",
                                     "a.impl", prog, ["w", "r"])
        os.makedirs(os.path.join(aw, "inbox"), exist_ok=True)
        with open(os.path.join(aw, "compiled", "plan.json"), "w") as f:
            json.dump(PLAN_W, f)
        import contextlib
        import io
        run_mod.log_event(rd, "dispatch", attempt="demo-w", task="a.impl", seat="w")
        with contextlib.redirect_stdout(io.StringIO()):
            rc_w = spawn_mod.cmd_adapter(aw, 60)
        tx_w = open(os.path.join(aw, "transcript.out"), encoding="utf-8",
                    errors="replace").read() if os.path.isfile(os.path.join(aw, "transcript.out")) else ""
        checks += 2
        if rc_w == 0 and os.path.isfile(os.path.join(aw, "repo", "src", "a.py")):
            ok += 1
        if '"ok": false' in tx_w and '"path": "/proc/outside-demo"' in tx_w \
                and not os.path.exists("/proc/outside-demo"):
            ok += 1
        elif os.path.exists(os.path.join(aw, "repo", "src", "a.py")) is False:
            raise Refused("the stub's write never landed")
        else:
            raise Refused("the outside write wasn't refused and reported")
        if spawn_mod.seal(aw) != "sealed" or spawn_mod.import_gate(aw)[0] != "OK":
            raise Refused("the stub's work didn't seal and gate")
        with open(os.path.join(aw, "collected.json"), "w", encoding="utf-8") as f:
            json.dump(spawn_mod.collect(aw), f, ensure_ascii=True, indent=1)
        _record_settled("demo-w", "w", "a.impl", 0.02)
        spawn_mod.candidate(aw, task="impl")
        spawn_mod.promote(parent, "impl")
        run_mod.log_event(rd, "promote", attempt="demo-w", task="a.impl", result="promoted")

        # seat r: a plain jailed worker command through the same ladder
        ar = spawn_mod.build_attempt(rd, "r", ["docs/**"], "integration/R", "demo-r",
                                     "b.doc", prog, ["w", "r"])
        os.makedirs(os.path.join(ar, "inbox"), exist_ok=True)
        run_mod.log_event(rd, "dispatch", attempt="demo-r", task="b.doc", seat="r")
        with contextlib.redirect_stdout(io.StringIO()):
            spawn_mod.cmd_worker(ar, 60, ["/bin/sh", "-c",
                                          "mkdir -p docs && printf 'fixture-doc\\n' "
                                          "> docs/d.md"])
        if spawn_mod.seal(ar) != "sealed" or spawn_mod.import_gate(ar)[0] != "OK":
            raise Refused("the second seat's work didn't seal and gate")
        _record_settled("demo-r", "r", "b.doc", 0.01)
        spawn_mod.candidate(ar, task="docs")
        spawn_mod.promote(parent, "docs")
        with open(os.path.join(ar, "promoted"), "w", encoding="utf-8") as f:
            f.write("b.doc\n")
        run_mod.log_event(rd, "promote", attempt="demo-r", task="b.doc", result="promoted")

        # the rows: two green now, the evidence row honestly still red
        for row, want in (("a.impl", True), ("b.doc", True), ("c.evidence", False)):
            checks += 1
            held, out = _run_row(prog, row, parent, arm, want_green=want)
            if not held:
                raise Refused(f"row {row} read {'green' if want else 'red'} "
                              f"as {out!r}; the contract doesn't follow the plan")
            ok += 1

        # honest evidence: the work happens, the row turns green
        ae = spawn_mod.build_attempt(rd, "w", ["src/**"], "integration/R", "demo-e",
                                     "a.impl", prog, ["w", "r"])
        os.makedirs(os.path.join(ae, "inbox"), exist_ok=True)
        run_mod.log_event(rd, "dispatch", attempt="demo-e", task="a.impl", seat="w")
        with contextlib.redirect_stdout(io.StringIO()):
            spawn_mod.cmd_worker(ae, 60, ["/bin/sh", "-c",
                                          "printf 'honest\\n' > src/evidence.txt"])
        if spawn_mod.seal(ae) != "sealed" or spawn_mod.import_gate(ae)[0] != "OK":
            raise Refused("the evidence work didn't seal and gate")
        _record_settled("demo-e", "w", "a.impl", 0.01)
        spawn_mod.candidate(ae, task="evidence")
        spawn_mod.promote(parent, "evidence")
        with open(os.path.join(ae, "promoted"), "w", encoding="utf-8") as f:
            f.write("a.impl\n")
        run_mod.log_event(rd, "promote", attempt="demo-e", task="a.impl", result="promoted")
        checks += 1
        held, out = _run_row(prog, "c.evidence", parent, arm, want_green=True)
        if not held:
            raise Refused(f"the evidence row stayed red after the work: {out!r}")
        ok += 1
        shutil.rmtree(os.path.join(rd, "attempts", "forged"), ignore_errors=True)
        run_mod._save_run(rd, {
            "state": "done", "autonomy": "attended",
            "program": os.path.abspath(prog), "run": "demo-run",
            "started_at": now_ts, "finished_at": time.time(),
            "base_commit": base_sha, "arm_hash": arm,
        })
        run_mod.log_event(rd, "done", run="demo-run")

        # the network fence: +0 denied, +1 allowed through the jail, +1 host
        net = _network_leg(base)
        checks += 3
        if net["denied_ok"] and net["through"] == 1 and net["allowed_ok"]:
            ok += 1
        else:
            raise Refused(f"the fence missed: {net['denied_ok']} "
                          f"through={net['through']} {net['allowed_ok']}")
        if net["host_side"] == 1:
            ok += 1
        else:
            raise Refused(f"the host-side connect counted {net['host_side']}")
        if len(net["rows"]) == 2 and all("refused denied.test" in x or
                                         "allowed allowed.test" in x
                                         for x in net["rows"]):
            ok += 1
        else:
            raise Refused(f"the proxy log holds {net['rows']}")

        elapsed = time.monotonic() - t0
        if elapsed > TIME_BOUND:
            raise Refused(f"the demo took {elapsed:.0f}s; the promise is "
                          f"{TIME_BOUND}s")
        if ok != checks:
            raise Refused(f"{checks - ok} check(s) missed")
        return {"checks": checks, "ok": ok, "time": round(elapsed, 1),
                "keep": keep}
    finally:
        os.environ.pop("RULING_CORE_GIT", None)
        if old_home is None:
            os.environ.pop("OPERATOR_HOME", None)
        else:
            os.environ["OPERATOR_HOME"] = old_home
        if keep is None:
            shutil.rmtree(base, ignore_errors=True)


def cmd_run(keep):
    if bwrap_missing():
        return sandbox_unavailable()
    try:
        doc = scenario(keep)
    except Refused as e:
        print(f"demo: {e}", file=sys.stderr)
        return 1
    except Void as e:
        print(f"demo: VOID, {e}", file=sys.stderr)
        return 2
    print(f"demo: OK ({doc['checks']} checks, {doc['time']}s, "
          f"two seats done, three refusals held)")
    return 0


def selftest():
    """Room-safe: without bubblewrap the demo says sandbox=unavailable, says
    what that means, and exits non-zero; usage refuses; --keep is honoured."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="demo-self.")
    try:
        empty = os.path.join(base, "emptybin")
        os.makedirs(empty)
        env = {**os.environ, "PATH": empty}
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "run"],
                           capture_output=True, text=True, env=env, timeout=60)
        check(r.returncode == 1 and "sandbox=unavailable" in r.stderr
              and "unattended" in r.stderr and "apt install bubblewrap" in r.stderr,
              f"A the missing sandbox names itself and its fix: rc={r.returncode} "
              f"{r.stderr[:110]}")
        r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                           capture_output=True, text=True, timeout=60)
        check(r.returncode == 2 and "usage" in r.stderr, "A bare usage refuses")
        print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0]
              else "selftest: FAIL")
        return 0 if ok[0] and not bad[0] else 1
    finally:
        shutil.rmtree(base, ignore_errors=True)


def first_level():
    """The whole demo under its own clock."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    if bwrap_missing():
        print("first-level: FAIL (no bubblewrap on this host)", file=sys.stderr)
        return 1
    kdir = tempfile.mkdtemp(prefix="demo-keep.")
    try:
        doc = scenario(keep=kdir)
        check(doc["checks"] == doc["ok"] and doc["ok"] >= 11
              and doc["time"] < TIME_BOUND,
              f"A the demo holds: {doc}")
        rp = subprocess.run(
            [sys.executable, os.path.join(ROOT, "bin", "panel.py"), "render", "--run", "demo-run"],
            capture_output=True, text=True,
            env={**os.environ, "OPERATOR_HOME": os.path.join(kdir, "home")},
            timeout=30)
        phtml = os.path.join(kdir, "home", "runs", "demo-run", "panel.html")
        html_body = open(phtml, encoding="utf-8").read() if os.path.isfile(phtml) else ""
        check(rp.returncode == 0 and "demo-run" in html_body and "demo-w" in html_body
              and "passed" in html_body,
              f"B quickstart demo --keep -> panel render works verbatim: rc={rp.returncode}")
    finally:
        shutil.rmtree(kdir, ignore_errors=True)
    print(f"first-level: OK ({ok[0]} checks)" if ok[0] and not bad[0]
          else "first-level: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def main(argv):
    if argv[1:] == ["run"]:
        return cmd_run(None)
    if len(argv) == 4 and argv[1:3] == ["run", "--keep"]:
        return cmd_run(argv[3])
    print("usage: demo.py run [--keep DIR] | --selftest | --first-level",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    if sys.argv[1:] == ["--first-level"]:
        sys.exit(first_level())
    sys.exit(main(sys.argv))
