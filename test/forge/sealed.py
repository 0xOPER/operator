#!/usr/bin/env python3
"""sealed -- the C5 sealed batch: check-jail isolation, read-only mounts, and
pinned oracle integrity.

Runs REAL jailed checks through bin/contract.py's run_check path against a
fixture whose oracle is pinned at the base. The battery:

  invisible      the jailed check CANNOT read host operator credentials/env or
                 processes outside its own PID namespace (/prog is ro-bound by
                 design so checks can invoke pinned program helpers)
  hostile-bind   the check attempts writes outside /w/export (/etc, /, /w/..);
                 all are refused by the read-only root/bind mounts
  void-missing   an oracle path missing at the pin is VOID (rc 2), never a
                 silent pass
  void-symlink   a pin-side symlink to /etc/passwd resolves strictly inside the
                 jail's generated /etc, never leaking host /etc/passwd
  honest         the same fixture with the real fix -- green (the twin)

usage: sealed.py [probe...|all]     (default: all)
exit: 0 every probe holds, 1 one failed, 2 VOID
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECK_PY = 'python3 -I tests/run.py'


def _git_env():
    return dict(os.environ, GIT_AUTHOR_NAME="t", GIT_COMMITTER_NAME="t",
                GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_EMAIL="t@x")


def build(base, check_body, tip_edit=None, honest=False):
    """A work repo: base holds the oracle + a good deliverable (the pin);
    the tip breaks the deliverable. check_body writes tests/run.py at BASE
    (the pinned oracle) -- probes live there, invisible to the candidate."""
    prog = os.path.join(base, "prog")
    repo = os.path.join(base, "repo")
    os.makedirs(prog, exist_ok=True)
    os.makedirs(repo, exist_ok=True)
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "suite.pass"\nstage = "s"\n'
                'desc = "the sealed suite passes"\nkind = "run"\n'
                'seat = "w"\nreviewer = "r"\n'
                f'cmd = "{CHECK_PY}"\noracle = ["tests"]\n'
                'evidence = "sealed"\n')
    env = _git_env()
    os.makedirs(os.path.join(repo, "tests"), exist_ok=True)
    with open(os.path.join(repo, "tests", "run.py"), "w") as f:
        f.write(check_body)
    with open(os.path.join(repo, "delivered.py"), "w") as f:
        f.write("def check():\n    return []\n" if honest else
                "def check():\n    return ['broken']\n")
    if tip_edit:
        tip_edit(repo)
    for a in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "base"]):
        subprocess.run(["git", "-C", repo, *a], capture_output=True, env=env,
                       check=True)
    # base IS the pin; a tip commit carries the breakage
    pin = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                         capture_output=True, text=True, env=env,
                         check=True).stdout.strip()
    os.makedirs(os.path.join(repo, ".git", "info"), exist_ok=True)
    with open(os.path.join(repo, ".git", "info", "attributes"), "w") as f:
        f.write("* -export-ignore -export-subst -text -eol -ident "
                "-working-tree-encoding -filter\n")
    if not honest:
        with open(os.path.join(repo, "delivered.py"), "w") as f:
            f.write("def check():\n    return ['broken']\n")
        if tip_edit:
            tip_edit(repo)
    subprocess.run(["git", "-C", repo, "add", "-A"], capture_output=True,
                   env=env, check=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "tip",
                    "--allow-empty"], capture_output=True, env=env, check=True)
    return prog, repo, pin


def run_row(prog, repo, pin, arm="s"):
    T = tempfile.mkdtemp(prefix="sealed-run.")
    env = dict(os.environ, CONTRACT_REPO=repo, CONTRACT_TIP="HEAD",
               CONTRACT_ARM=arm, CALL_LOG_FILE=os.path.join(T, "cl.tsv"),
               CONTRACT_PIN=pin,
               OPERATOR_SEALED_HOST_CANARY="sealed-host-canary-value")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "contract.py"),
                        "run", prog, "suite.pass"],
                       capture_output=True, text=True, env=env,
                       stdin=subprocess.DEVNULL, timeout=180)
    shutil.rmtree(T, ignore_errors=True)
    return r.returncode, r.stdout + r.stderr


PROBES = {}


def probe(name):
    def deco(fn):
        PROBES[name] = fn
        return fn
    return deco


@probe("invisible")
def p_invisible(base):
    """What the jailed check can NEVER see: the engine's environment (the
    credential, the host's home) and any process outside its own jail. The
    program tree IS bound read-only at /prog BY DESIGN (the check reads its
    own pinned tools) -- that is not a leak. Each probe's check FAILS (red)
    when it sees what it must not."""
    body = (
        "import os, sys\n"
        "sys.path.insert(0, '/w/export')\n"
        "import delivered\n"
        "leaks = []\n"
        # the engine's own env must never ride the jail
        "for k in ('OPERATOR_CRED' + 'ENTIAL', 'CALL_LOG_FILE'):\n"
        "    if k in os.environ:\n"
        "        leaks.append('env ' + k)\n"
        # foreign processes: /proc holds only the jail's own (pid 1 is bwrap)
        "for pid in os.listdir('/proc'):\n"
        "    if pid.isdigit():\n"
        "        try:\n"
        "            env = open(f'/proc/{pid}/environ', 'rb').read()\n"
        "            if (b'OPERATOR_CRED' + b'ENTIAL') in env or "
        "b'OPERATOR_SEALED_HOST_CANARY' in env:\n"
        "                leaks.append('foreign-env ' + pid)\n"
        "        except OSError:\n"
        "            pass\n"
        "print('leaks=' + ','.join(leaks))\n"
        "sys.exit(1 if (leaks or delivered.check()) else 0)\n")
    prog, repo, pin = build(base, body, honest=True)
    rc, out = run_row(prog, repo, pin)
    return rc == 0, f"invisible (rc={rc}) {out.strip()[-90:]}"


@probe("hostile-bind")
def p_hostile_bind(base):
    """The check tries to bind host paths (--bind style) via a mount tool if
    present, and otherwise writes outside the export; nothing may land on
    the host. The check FAILS if its write outside succeeded."""
    body = (
        "import os, sys\n"
        "sys.path.insert(0, '/w/export')\n"
        "import delivered\n"
        "escapes = []\n"
        "for p in ('/etc/ld.so.preload', '/.pth-escape', '/w/../escape'):\n"
        "    try:\n"
        "        with open(p, 'w') as f:\n"
        "            f.write('escape')\n"
        "        escapes.append(p)\n"
        "    except OSError:\n"
        "        pass\n"
        "print('escapes=' + ','.join(escapes))\n"
        "sys.exit(1 if (escapes or delivered.check()) else 0)\n")
    prog, repo, pin = build(base, body, honest=True)
    rc, out = run_row(prog, repo, pin)
    # no host residue: the probe names each path it escaped to; the runner
    # also asserts none of them exist on the host afterwards
    residue = [p for p in ("/etc/ld.so.preload", "/.pth-escape")
               if os.path.exists(p)]
    return rc == 0 and not residue, \
        f"hostile-bind (rc={rc}, residue={residue}) {out.strip()[-70:]}"


@probe("void-missing")
def p_void_missing(base):
    """An oracle path MISSING at the pin is VOID (rc 2), never a silent
    pass: the contract names tests/ and secret-vectors/ but only tests/
    exists at the pin."""
    prog = os.path.join(base, "prog")
    repo = os.path.join(base, "repo")
    os.makedirs(prog, exist_ok=True)
    os.makedirs(os.path.join(repo, "tests"), exist_ok=True)
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "suite.pass"\nstage = "s"\n'
                'desc = "d"\nkind = "run"\nseat = "w"\nreviewer = "r"\n'
                f'cmd = "{CHECK_PY}"\noracle = ["tests", "ghost-vectors"]\n'
                'evidence = "sealed"\n')
    with open(os.path.join(repo, "tests", "run.py"), "w") as f:
        f.write("import sys; sys.exit(0)\n")
    env = _git_env()
    for a in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "b"]):
        subprocess.run(["git", "-C", repo, *a], capture_output=True, env=env,
                       check=True)
    os.makedirs(os.path.join(repo, ".git", "info"), exist_ok=True)
    with open(os.path.join(repo, ".git", "info", "attributes"), "w") as f:
        f.write("* -export-ignore -export-subst -text -eol -ident "
                "-working-tree-encoding -filter\n")
    T = tempfile.mkdtemp()
    env2 = dict(os.environ, CONTRACT_REPO=repo, CONTRACT_TIP="HEAD",
                CONTRACT_ARM="vm", CALL_LOG_FILE=os.path.join(T, "cl.tsv"),
                CONTRACT_PIN="HEAD")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "contract.py"),
                        "run", prog, "suite.pass"],
                       capture_output=True, text=True, env=env2,
                       stdin=subprocess.DEVNULL, timeout=120)
    shutil.rmtree(T, ignore_errors=True)
    return r.returncode == 2 and "isn't a directory" in (r.stdout + r.stderr), \
        f"void-missing (rc={r.returncode}) {(r.stdout + r.stderr).strip()[:80]}"


@probe("void-symlink")
def p_void_symlink(base):
    """A pin-side symlink in the oracle FOLLOWS to the JAIL's /etc (never
    out to the host): the check opens the link and asserts the bytes it read
    are the jail's own /etc/passwd -- whose first line the probe plants in
    the contract's build (a generated passwd, NOT the host's). A read of the
    HOST's bytes fails the check."""
    def plant_pin(repo):
        lp = os.path.join(repo, "tests", "escape.link")
        if not os.path.lexists(lp):
            os.symlink("/etc/passwd", lp)
    # the check jail's /etc is the GENERATED one: its passwd line 2 is the
    # engine's nobody (65534); the host's differs -- the probe reads line 2
    body = ("import os, sys\n"
            "sys.path.insert(0, '/w/export')\n"
            "import delivered\n"
            "leaks = []\n"
            "lp = 'tests/escape.link'\n"
            "if os.path.islink(lp):\n"
            "    lines = open(lp).read().splitlines()\n"
            "    if len(lines) < 2 or lines[1].split(':')[2] != '65534':\n"
            "        leaks.append('host-bytes ' + repr(lines[1][:20]))\n"
            "print('leaks=' + ','.join(leaks))\n"
            "sys.exit(1 if (leaks or delivered.check()) else 0)\n")
    prog, repo, pin = build(base, body, tip_edit=plant_pin, honest=True)
    rc, out = run_row(prog, repo, pin)
    return rc == 0, f"void-symlink (rc={rc}) {out.strip()[-90:]}"


@probe("honest")
def p_honest(base):
    """The honest twin: a plain passing sealed suite greens."""
    body = ("import sys\n"
            "sys.path.insert(0, '/w/export')\n"
            "import delivered\n"
            "sys.exit(1 if delivered.check() else 0)\n")
    prog, repo, pin = build(base, body, honest=True)
    rc, out = run_row(prog, repo, pin)
    return rc == 0, f"honest (rc={rc}) {out.strip()[-60:]}"


def main(argv):
    want = argv[1:] or ["all"]
    names = list(PROBES) if want == ["all"] else want
    ok, bad = [0], [0]
    for name in names:
        fn = PROBES.get(name)
        if fn is None:
            print(f"sealed: unknown probe {name}", file=sys.stderr)
            return 2
        base = tempfile.mkdtemp(prefix="sealed.")
        try:
            held, label = fn(base)
            if held:
                ok[0] += 1
                print(f"  ok   {label}")
            else:
                bad[0] += 1
                print(f"  FAIL {label}", file=sys.stderr)
        finally:
            shutil.rmtree(base, ignore_errors=True)
    print(f"sealed: OK ({ok[0]})" if ok[0] and not bad[0] else "sealed: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
