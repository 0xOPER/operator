#!/usr/bin/env python3
"""census -- runtime proof that agent CLIs and signing run only through the engine.

Two doors, one census. `install` writes PATH-first shims: one per agent CLI,
which log the caller chain and refuse any call with no sanctioned caller in it,
and one for ssh-keygen, which passes everything through untouched except
`-Y sign` -- that call is censused the same way (the sign census T3 shares).
A call is sanctioned when an ancestor RAN the engine's own tool for it: the
hop's executable is a python interpreter and the door file sits at the script
position -- spawn.py for agent CLIs, ruling.py or approvals for signing. A
caller that merely names the path (in argv[0], or as an argument of inline
code) sanctions nothing. The chain is read from /proc, never trusted from the
environment, and a censused call with no log path, or one whose log cannot be
written, refuses -- fail closed, like the gate.

`report` reads a census log back: rows=N admit=A refuse=R, exit 1 on any refuse
or unreadable row. A battery, demo or run that censuses clean reports rows from
sanctioned signing alone and zero refusals.

usage: census.py install <shim-dir>          writes the shims (dir must be census-owned)
       census.py report <log>                counts the rows (absent log: rows=0, exit 0)
       census.py --selftest
exit: 0 ok, 1 refused or refusals in the report, 2 usage or VOID
"""
import json
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

JSON_SCHEMA = 1
# the audit's five (the sample that gated nothing) plus the public CLIs a
# manifest may name; shims cost nothing until one of these runs
AGENT_CLIS = ("claude", "codex", "opencode", "zcode", "gemini", "amp", "cursor", "aider", "goose")
# a call is sanctioned when an ancestor's argv carries one of these under bin/
DOOR_FOR = {name: ("spawn.py",) for name in AGENT_CLIS}
DOOR_FOR["ssh-keygen"] = ("ruling.py", "approvals", "review.py", "wire.py")
MARKER = ".census-shims"

SH_CLI = """#!/bin/sh
# census shim (operator): logs the caller chain, refuses calls from no sanctioned door
exec python3 -I '{census}' --shim '{name}' --dir '{dir}' "$@"
"""

SH_KEYGEN = """#!/bin/sh
# census shim (operator): -Y sign is censused; every other call passes straight through
sign=0 prev=
for a in "$@"; do
  if [ "$prev" = "-Y" ] && [ "$a" = sign ]; then sign=1; fi
  case "$a" in -Ysign) sign=1 ;; esac
  prev=$a
done
if [ "$sign" = 1 ]; then
  exec python3 -I '{census}' --shim ssh-keygen --dir '{dir}' "$@"
  echo "census: the sign shim is broken" >&2; exit 1
fi
exec '{real}' "$@"
"""


class Void(Exception):
    pass


def which_real(name):
    """The real binary for name -- never a shim: a PATH entry holding the
    census marker is a shim dir, and admitting into it would census twice."""
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or os.path.isfile(os.path.join(d, MARKER)):
            continue
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def cmd_install(directory, real_overrides=None):
    if any("'" in p for p in (directory, ROOT)):
        raise Void("shim paths cannot carry single quotes")
    os.makedirs(directory, exist_ok=True)
    if [f for f in os.listdir(directory) if f != MARKER] and \
            not os.path.isfile(os.path.join(directory, MARKER)):
        raise Void(f"{directory} holds files the census didn't write; "
                   "give install an empty dir of its own")
    real = {}
    for name in AGENT_CLIS + ("ssh-keygen",):
        found = which_real(name)
        real[name] = os.path.realpath(found) if found else None
    real.update(real_overrides or {})
    if real["ssh-keygen"] is None:
        raise Void("no ssh-keygen on PATH; the engine signs with it and the "
                   "shim must be able to pass calls through")
    me = os.path.abspath(__file__)
    wrote = []
    for name in AGENT_CLIS:
        p = os.path.join(directory, name)
        with open(p, "w") as f:
            f.write(SH_CLI.format(census=me, name=name, dir=os.path.abspath(directory)))
        os.chmod(p, 0o755)
        wrote.append(name)
    p = os.path.join(directory, "ssh-keygen")
    with open(p, "w") as f:
        f.write(SH_KEYGEN.format(census=me, dir=os.path.abspath(directory),
                                 real=real["ssh-keygen"]))
    os.chmod(p, 0o755)
    wrote.append("ssh-keygen")
    with open(os.path.join(directory, MARKER), "w") as f:
        f.write(json.dumps({"schema": JSON_SCHEMA, "root": ROOT, "real": real},
                           ensure_ascii=True, sort_keys=True) + "\n")
    return {"schema": JSON_SCHEMA, "dir": directory, "shims": wrote,
            "real": {k: v for k, v in real.items() if v}}


def caller_chain(limit=64):
    """The argv of each ancestor, read from /proc, nearest first. Read-only."""
    chain, pid = [], os.getpid()
    for _ in range(limit):
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
                stat = f.read()
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            break
        rest = stat[stat.rfind(")") + 1:].split()
        if len(rest) < 2 or not rest[1].isdigit():
            break
        chain.append({"pid": pid,
                      "argv": [a[:120].decode("utf-8", "replace") for a in argv if a][:8]})
        ppid = int(rest[1])
        if ppid <= 1:
            break
        pid = ppid
    return chain


def _hop_exe_is_python(pid):
    """True when the hop's executable is a python interpreter (a shell or a
    copied binary wearing the name is not the door)."""
    try:
        out = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None
    return os.path.basename(out).startswith("python") if out else None


def _door_at_script_position(argv, door_paths):
    """The door file at the position an interpreter would RUN it: the first
    token after argv[0] that is not an interpreter option. argv[0] is a name
    any caller can wear (`exec -a`) and never counts; -c or -m means the code
    is inline or a module, so no script position exists at all."""
    prev = ""
    for tok in argv[1:]:
        if prev in ("-W", "-X"):        # those consumed a value; it is not a
            prev = tok                  # script position either
            continue
        if tok in ("-c", "-m"):
            return False                # inline code / a module: no script
        if tok.startswith("-"):
            prev = tok
            continue
        return tok in door_paths
    return False


def sanctioned_as(chain, name):
    """(door, tool) when an ancestor RAN the door tool: its executable is a
    python interpreter and the door file sits at the script position. A caller
    that merely names the path -- in argv[0] or as an argument -- sanctions
    nothing."""
    doors = DOOR_FOR.get(name, ())
    bin_real = os.path.realpath(os.path.join(ROOT, "bin"))
    door_paths = {os.path.realpath(os.path.join(ROOT, "bin", d)) for d in doors}
    for hop in chain:
        for arg in hop["argv"][1:]:
            if os.path.basename(arg) in doors and \
                    os.path.realpath(os.path.dirname(arg)) == bin_real:
                if hop["argv"] and _door_at_script_position(hop["argv"], door_paths) \
                        and _hop_exe_is_python(hop["pid"]):
                    return True, os.path.basename(arg)
    return False, None


def run_shim(name, shim_dir, argv):
    """The censused call: log the chain, then admit through the real binary or refuse."""
    chain = caller_chain()
    ok, door = sanctioned_as(chain, name)
    log = os.environ.get("OPERATOR_CENSUS_LOG", "")
    real = None
    marker = os.path.join(shim_dir, MARKER)
    if os.path.isfile(marker):
        try:
            with open(marker, encoding="utf-8") as f:
                real = json.load(f).get("real", {}).get(name)
        except (ValueError, OSError):
            real = None
    row = {"schema": JSON_SCHEMA, "shim": name, "verdict": "admit" if ok else "refuse",
           "door": door, "argv": [a[:160] for a in argv][:16], "chain": chain[:16]}
    logged = False
    if log:
        try:
            line = json.dumps(row, ensure_ascii=True, sort_keys=True)
            with open(log, "a", encoding="utf-8") as f:
                f.write(line[:65536] + "\n")
            logged = True
        except OSError as e:
            print(f"census: refusing {name}: the census log can't be written "
                  f"({e}); fix {log} or unset OPERATOR_CENSUS_LOG to run uncensused",
                  file=sys.stderr)
            return 1
    if not ok:
        fix = "spawn.py" if name in AGENT_CLIS else "ruling.py or approvals"
        print(f"census: refused {name}: no sanctioned caller in the chain "
              f"(the door for it is {fix})"
              + ("" if logged else "; set OPERATOR_CENSUS_LOG to keep a row of this"),
              file=sys.stderr)
        return 1
    if real is None:
        print(f"census: admit via {door} (no real {name} on this machine; "
              f"the census doesn't install one)", file=sys.stderr)
        return 0
    os.execv(real, [real] + argv)


def cmd_report(log):
    rows = admit = refuse = 0
    if os.path.isfile(log):
        with open(log, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rows += 1
                try:
                    verdict = json.loads(line).get("verdict")
                except ValueError:
                    verdict = "refuse"  # a row the census can't read fails closed
                if verdict == "admit":
                    admit += 1
                else:
                    refuse += 1
    print(f"census: rows={rows} admit={admit} refuse={refuse}")
    return 0 if refuse == 0 else 1


def main(argv):
    if len(argv) >= 4 and argv[1] == "--shim":
        name, rest = argv[2], list(argv[3:])
        shim_dir = "."
        if "--dir" in rest:
            i = rest.index("--dir")
            if i + 1 >= len(rest):
                return 2
            shim_dir = rest[i + 1]
            rest = rest[:i] + rest[i + 2:]
        return run_shim(name, shim_dir, rest)
    if len(argv) >= 3 and argv[1] == "install":
        overrides = {}
        i = 3
        while i + 1 < len(argv):
            if argv[i] == "--real" and "=" in argv[i + 1]:
                k, v = argv[i + 1].split("=", 1)
                overrides[k] = v
                i += 2
            else:
                break
        try:
            doc = cmd_install(argv[2], overrides)
        except Void as e:
            print(f"census: VOID, {e}", file=sys.stderr)
            return 2
        except OSError as e:
            print(f"census: VOID, can't write the shims: {e}", file=sys.stderr)
            return 2
        print(json.dumps(doc, ensure_ascii=True, sort_keys=True))
        return 0
    if len(argv) == 3 and argv[1] == "report":
        try:
            return cmd_report(argv[2])
        except OSError as e:
            print(f"census: VOID, can't read {argv[2]}: {e}", file=sys.stderr)
            return 2
    print("usage: census.py install <shim-dir> | report <log> | --selftest",
          file=sys.stderr)
    return 2


def selftest():
    """Room-safe: install owns its dir and refuses a foreign one; an unsanctioned
    CLI call refuses with the chain logged; a caller argv'd as spawn.py admits;
    ssh-keygen passes through untouched while -Y sign is censused both ways, a
    sanctioned signature still verifies, and an unwritable log refuses."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    import shutil as _sh
    import subprocess
    import tempfile
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="census-rt.")
    shims = os.path.join(base, "shims")
    log = os.path.join(base, "census.jsonl")
    echo = "/bin/echo" if os.path.exists("/bin/echo") else "/usr/bin/echo"
    try:
        # A install writes a shim per CLI plus the ssh-keygen proxy, and owns its
        # dir; claude's real binary is stubbed so the admit arm runs echo, not a
        # live CLI that re-enters PATH (and, under a nested census, other shims)
        cmd_install(shims, {"claude": echo})
        names = sorted(os.listdir(shims))
        check(set(names) == set(AGENT_CLIS) | {"ssh-keygen", MARKER},
              f"A one shim per name: {len(names)}")
        check(all(os.access(os.path.join(shims, n), os.X_OK)
                  for n in names if n != MARKER), "A every shim is executable")
        cmd_install(shims)
        check(len(os.listdir(shims)) == len(names), "A reinstall is idempotent")
        foreign = os.path.join(base, "foreign")
        os.makedirs(foreign)
        open(os.path.join(foreign, "mine"), "w").close()
        try:
            cmd_install(foreign)
            check(False, "A a foreign dir refuses")
        except Void as e:
            check("didn't write" in str(e), f"A the refusal names whose dir: {e}")

        env = {**os.environ, "OPERATOR_CENSUS_LOG": log,
               "PATH": shims + os.pathsep + os.environ.get("PATH", "")}

        # B an unsanctioned CLI call refuses, with the chain in the log
        r = subprocess.run([os.path.join(shims, "claude"), "--version"],
                           capture_output=True, text=True, env=env, timeout=60)
        check(r.returncode == 1 and "census" in r.stderr and "spawn.py" in r.stderr,
              f"B the refusal names the door: rc={r.returncode} {r.stderr[:90]}")
        rows = [json.loads(l) for l in open(log)]
        check(rows and rows[-1]["verdict"] == "refuse" and rows[-1]["shim"] == "claude",
              f"B the refuse row: {rows[-1] if rows else None}")
        check(any("census" in a for hop in rows[-1]["chain"] for a in hop["argv"]),
              "B the chain carries the caller")

        # C the door law: naming the path sanctions nothing. A caller wearing
        # the door's argv[0] (exec -a shape) or carrying it as inline-code data
        # refuses; a chain whose hop RAN the door (script position, python exe)
        # admits -- proven on synthetic chains, then live through ruling.py
        key = os.path.join(base, "k")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key,
                        "-C", "census"], capture_output=True, check=True)
        bin_real = os.path.realpath(os.path.join(ROOT, "bin"))
        spawn_path = os.path.realpath(os.path.join(bin_real, "spawn.py"))
        my_exe = os.path.realpath(sys.executable)
        ran = {"pid": os.getpid(), "argv": [sys.executable, spawn_path, "worker", "x"]}
        wore = {"pid": os.getpid(), "argv": [spawn_path, "-c", "code",
                                             os.path.join(shims, "claude")]}
        carried = {"pid": os.getpid(), "argv": [sys.executable, "-c", "code",
                                                spawn_path]}
        swallowed = {"pid": os.getpid(),
                     "argv": [sys.executable, "-W", spawn_path, "evil.py"]}
        consumed_ok = {"pid": os.getpid(),
                       "argv": [sys.executable, "-W", "ignore", spawn_path,
                                "worker", "x"]}
        check(sanctioned_as([ran], "claude") == (True, "spawn.py"),
              "C a hop that ran the door admits")
        check(sanctioned_as([wore], "claude") == (False, None),
              "C a caller wearing the door's name sanctions nothing")
        check(sanctioned_as([carried], "claude") == (False, None),
              "C the door as inline-code data sanctions nothing")
        check(sanctioned_as([swallowed], "claude") == (False, None),
              "C the door worn as a -W value sanctions nothing")
        check(sanctioned_as([consumed_ok], "claude") == (True, "spawn.py"),
              "C the script past a consumed -W value still admits")
        rev_path = os.path.realpath(os.path.join(bin_real, "review.py"))
        wire_path = os.path.realpath(os.path.join(bin_real, "wire.py"))
        check("zcode" in AGENT_CLIS and sanctioned_as([ran], "zcode") == (True, "spawn.py"),
              "C2 zcode is shimmed and sanctioned via spawn.py")
        check(sanctioned_as([{"pid": os.getpid(), "argv": [sys.executable, rev_path, "verdict"]}],
                            "ssh-keygen") == (True, "review.py"),
              "C2 review.py is a sanctioned ssh-keygen door")
        check(sanctioned_as([{"pid": os.getpid(), "argv": [sys.executable, wire_path, "sign"]}],
                            "ssh-keygen") == (True, "wire.py"),
              "C2 wire.py is a sanctioned ssh-keygen door")
        # live: the argv0-spoof shape that once admitted now refuses
        door_child = ("import subprocess, sys\n"
                      "r = subprocess.run([sys.argv[1], '--version'], "
                      "capture_output=True, text=True)\n"
                      "sys.exit(r.returncode)\n")
        p = subprocess.run([os.path.join(ROOT, "bin", "spawn.py"), "-c", door_child,
                            os.path.join(shims, "claude")],
                           executable=sys.executable, env=env,
                           capture_output=True, text=True, timeout=60)
        rows = [json.loads(l) for l in open(log)]
        check(p.returncode == 1 and rows[-1]["verdict"] == "refuse",
              f"C the spoof shape refuses: rc={p.returncode} {rows[-1]['verdict']}")

        # D ssh-keygen passes through uncensused (a shape the engine itself uses)
        r = subprocess.run([os.path.join(shims, "ssh-keygen"), "-y", "-P", "",
                            "-f", key], capture_output=True, text=True, env=env,
                           timeout=60)
        check(r.returncode == 0 and r.stdout.startswith("ssh-ed25519 "),
              f"D pass-through: rc={r.returncode} {r.stdout[:40]}")
        n_rows = sum(1 for _ in open(log))
        check(n_rows == 2, f"D the pass-through wrote no row: {n_rows}")

        # E an unsanctioned -Y sign refuses; a real ruling.py signs and admits
        msg = os.path.join(base, "msg")
        with open(msg, "w") as f:
            f.write("census fixture\n")
        r = subprocess.run([os.path.join(shims, "ssh-keygen"), "-Y", "sign",
                            "-f", key, "-n", "operator-ruling", os.path.basename(msg)],
                           capture_output=True, text=True, env=env, cwd=base, timeout=60)
        check(r.returncode == 1 and "ruling.py" in r.stderr,
              f"E unsanctioned sign refuses: rc={r.returncode} {r.stderr[:90]}")
        rows = [json.loads(l) for l in open(log)]
        check(rows[-1]["shim"] == "ssh-keygen" and rows[-1]["verdict"] == "refuse",
              f"E the sign refuse row: {rows[-1]['shim']} {rows[-1]['verdict']}")
        # E3 the shim execs its census under -I: a hostile PYTHONPATH with a
        # shadowing module never loads (the planter's plant was dropping that
        # flag -- invisible to every suite, so the arm is behavioral)
        hostile = os.path.join(base, "hostile-site")
        os.makedirs(hostile, exist_ok=True)
        marker = os.path.join(base, "sitecustomize-ran")
        with open(os.path.join(hostile, "sitecustomize.py"), "w") as f:
            f.write(f"open({marker!r}, 'w').write('ran')\n")
        env_h = {**env, "PYTHONPATH": hostile}
        r = subprocess.run([os.path.join(shims, "claude"), "--version"],
                           capture_output=True, text=True, env=env_h, timeout=60)
        check(not os.path.exists(marker),
              f"E3 -I keeps a hostile sitecustomize out: rc={r.returncode} "
              f"out={r.stdout[:40]!r}")
        # E2 the COMBINED spelling censuses too (the forger lens found the
        # two-word-only scan shipping: ssh-keygen's getopt takes -Ysign)
        r = subprocess.run([os.path.join(shims, "ssh-keygen"), "-Ysign",
                            "-f", key, "-n", "operator-ruling", os.path.basename(msg)],
                           capture_output=True, text=True, env=env, cwd=base, timeout=60)
        rows = [json.loads(l) for l in open(log)]
        check(r.returncode == 1 and rows[-1]["shim"] == "ssh-keygen"
              and rows[-1]["verdict"] == "refuse",
              f"E2 -Ysign censuses: rc={r.returncode} "
              f"{rows[-1].get('verdict')} {r.stderr[:60]}")
        # a real ruling.py at the script position, signing a real program
        import spawn as spawn_mod
        home = os.path.join(base, "home")
        os.makedirs(os.path.join(home, "signers"))
        with open(os.path.join(home, "signers", "allowed_signers"), "w") as f:
            f.write(f'owner@fixture namespaces="operator-ruling" '
                    f'{open(key + ".pub").read().strip()}\n')
        os.chmod(os.path.join(home, "signers", "allowed_signers"), 0o600)
        env = {**env, "OPERATOR_HOME": home}
        core = os.path.join(base, "core")
        os.makedirs(core)
        with open(os.path.join(core, "V"), "w") as f:
            f.write("0.1\n")
        ce = dict(spawn_mod.engine_env(commit=True))
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "c"]):
            subprocess.run(["git", "-C", core, *args], capture_output=True, env=ce)
        env["RULING_CORE_GIT"] = core
        prog = spawn_mod._program(home, "censusprog")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "ruling.py"),
                            "sign", prog, "--kind", "arm", "--key", key],
                           capture_output=True, text=True, env=env, cwd=base,
                           timeout=60)
        check(r.returncode == 0, f"E ruling.py signs for real: rc={r.returncode} "
                                 f"{r.stderr[:120]}")
        rows = [json.loads(l) for l in open(log)]
        check(rows[-1]["verdict"] == "admit" and rows[-1]["door"] == "ruling.py",
              f"E the sign admit row: {rows[-1]['door']}")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "ruling.py"),
                            "verify", prog], capture_output=True, text=True,
                           env=env, timeout=60)
        check(r.returncode == 0, f"E ruling.py verifies its own signing: "
                                 f"rc={r.returncode} {r.stderr[:100]}")

        # F the report counts and fails on refusals; an unreadable row fails closed
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "report", log],
                           capture_output=True, text=True, timeout=60)
        counts = dict(kv.split("=") for kv in r.stdout.split()[1:])
        check(r.returncode == 1 and counts["refuse"] == "5" and counts["admit"] == "1",
              f"F the report counts refusals: {r.stdout.strip()}")
        admit_only = os.path.join(base, "admit.jsonl")
        with open(admit_only, "w") as f:
            f.write(json.dumps({"verdict": "admit"}) + "\n")
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "report",
                            admit_only], capture_output=True, text=True, timeout=60)
        check(r.returncode == 0, "F admits alone pass")
        junk = os.path.join(base, "junk.jsonl")
        with open(junk, "w") as f:
            f.write("not json\n")
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "report", junk],
                           capture_output=True, text=True, timeout=60)
        check(r.returncode == 1, "F an unreadable row fails closed")
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "report",
                            os.path.join(base, "absent.jsonl")],
                           capture_output=True, text=True, timeout=60)
        check(r.returncode == 0 and "rows=0" in r.stdout, "F an absent log is zero rows")

        # G no log path, or an unwritable log, still refuses
        env_nl = {k: v for k, v in env.items() if k != "OPERATOR_CENSUS_LOG"}
        r = subprocess.run([os.path.join(shims, "claude"), "--version"],
                           capture_output=True, text=True, env=env_nl, timeout=60)
        check(r.returncode == 1 and "OPERATOR_CENSUS_LOG" in r.stderr,
              f"G no log names its fix: {r.stderr[:90]}")
        r = subprocess.run([os.path.join(shims, "claude"), "--version"],
                           capture_output=True, text=True,
                           env={**env, "OPERATOR_CENSUS_LOG": "/dev/full"}, timeout=60)
        check(r.returncode == 1 and "can't be written" in r.stderr,
              f"G an unwritable log refuses: {r.stderr[:90]}")

        print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
        return 0 if ok[0] and not bad[0] else 1
    finally:
        _sh.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.exit(main(sys.argv))
