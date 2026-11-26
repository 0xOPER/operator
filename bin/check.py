#!/usr/bin/env python3
"""check -- the engine's front door: installed, configured, missing, next step.

One screen says whether this machine can run the engine, and every missing piece
names its fix (the UX floor's first rule): the version it found, the version it
needs, and the command that resolves it. doctor composes this with the run state;
`operator check` is the README's second command.

The probes are cheap and read-only: version strings, module lookups, writable
paths, the signers hygiene (ruling.py check), and the adapter directory's
existence. Nothing here spawns a jail or spends anything.

usage: check.py [--json]
exit: 0 everything needed is present, 1 something is missing or short, 2 VOID
"""
import json
import os
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))

JSON_SCHEMA = 1
GIT_MIN = (2, 38)
GIT_FSCK_FULL = (2, 48)          # below this, bundles can't be forced to fsck
PY_MIN = (3, 11)                 # tomllib


class Void(Exception):
    pass


def probe_binary(name):
    """(path, first version line) or (None, None) when absent."""
    path = shutil.which(name)
    if not path:
        return None, None
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True,
                           timeout=10)
    except subprocess.TimeoutExpired:
        return path, "hung"  # a probe that never answers can't be trusted; the
        # row below names it missing with its fix
    line = (r.stdout or r.stderr).strip().splitlines()
    return path, (line[0] if line else "")


def version_tuple(text):
    m = re.search(r"([0-9]+(\.[0-9]+)+)", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def ge(t, minimum):
    return t is not None and (t[:len(minimum)] >= minimum if len(t) >= len(minimum)
                              else t + (0,) * (len(minimum) - len(t)) >= minimum)


def run_checks():
    checks = []

    def add(name, ok, found, need, fix):
        checks.append({"check": name, "ok": bool(ok), "found": found, "need": need, "fix": fix})

    def hung_row(name, path):
        add(name, False, "hung", "any",
            f"{path} --version never answered; a binary that hangs instead of "
            "answering is a broken install -- remove or fix it, then retry")

    path, ver = probe_binary("git")
    if ver == "hung":
        hung_row("git", path)
        checks.append({"check": "git-bundle-fsck", "ok": True, "found": "hung",
                       "need": "-", "fix": "unavailable while the probe hangs"})
        return checks
    t = version_tuple(ver)
    add("git", path and ge(t, GIT_MIN), ver or "absent", f">= {GIT_MIN[0]}.{GIT_MIN[1]}",
        "install git >= 2.38 (apt install git)")
    if t and t < GIT_FSCK_FULL:
        checks.append({"check": "git-bundle-fsck", "ok": True, "found": ver,
                       "need": f">= {GIT_FSCK_FULL[0]}.{GIT_FSCK_FULL[1]} for full bundle fsck",
                       "fix": f"below {GIT_FSCK_FULL[0]}.{GIT_FSCK_FULL[1]} the gate records bundle_fsck=off; "
                              "upgrade git when you can"})

    path, ver = probe_binary("bwrap")
    if ver == "hung":
        hung_row("bubblewrap", path)
    else:
        add("bubblewrap", path is not None, ver or "absent", "any",
            "install bubblewrap (apt install bubblewrap); without it every run is "
            "sandbox=unavailable and unattended refuses")

    path, ver = probe_binary("ssh-keygen")
    if ver == "hung":
        hung_row("openssh", path)
    else:
        add("openssh", path is not None, ver or "absent", "any",
            "install openssh-client (apt install openssh-client); rulings sign "
            "with ssh-keygen")

    t = sys.version_info[:2]
    add("python", ge(t, PY_MIN), f"{t[0]}.{t[1]}", f">= {PY_MIN[0]}.{PY_MIN[1]}",
        f"run me with python3 >= {PY_MIN[0]}.{PY_MIN[1]} (tomllib is stdlib there)")
    import importlib.util
    for mod, fix in (("venv", "install python3-venv (apt install python3-venv); [setup] rows need it"),
                     ("ensurepip", "install python3-venv (apt install python3-venv); pip bootstrapping needs it")):
        add(mod, importlib.util.find_spec(mod) is not None, "present" if
            importlib.util.find_spec(mod) else "absent", "any", fix)

    import ruling as ruling_mod
    home = ruling_mod.operator_home() if hasattr(ruling_mod, "operator_home") else None
    home = home or os.environ.get("OPERATOR_HOME") or os.path.join(ROOT, "state")
    writable = os.path.isdir(home) and os.access(home, os.W_OK)
    if not os.path.isdir(home):
        try:
            os.makedirs(home, exist_ok=True)
            writable = os.access(home, os.W_OK)
        except OSError:
            writable = False
    add("operator-home", writable, home, "a writable state root",
        f"create or fix permissions on {home} (or set OPERATOR_HOME)")

    r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "ruling.py"), "check"],
                       capture_output=True, text=True, timeout=30,
                       env={**os.environ})
    add("signers", r.returncode == 0, (r.stdout or r.stderr).strip().splitlines()[-1][:60]
        if (r.stdout or r.stderr).strip() else "no signers file",
        "one signer, namespace-restricted",
        "put an ed25519 signer in the signers file: operator init walks you there")

    adapters = os.environ.get("OPERATOR_ADAPTERS") or os.path.join(ROOT, "config", "adapters")
    n = len([f for f in os.listdir(adapters) if f.endswith(".toml")]) if os.path.isdir(adapters) else 0
    add("adapters", True, f"{n} manifest(s) in {adapters}", "the stub ships one",
        "none needed until a seat names an adapter; the stub manifest ships with the core")
    return checks


def main():
    as_json = "--json" in sys.argv[1:]
    try:
        checks = run_checks()
    except Void as e:
        print(f"check: VOID, {e}", file=sys.stderr)
        return 2
    bad = [c for c in checks if not c["ok"]]
    if as_json:
        print(json.dumps({"schema": JSON_SCHEMA, "ok": not bad, "checks": checks},
                         ensure_ascii=True, sort_keys=True))
    else:
        width = max(len(c["check"]) for c in checks)
        for c in checks:
            mark = "ok " if c["ok"] else "MISSING"
            print(f"{mark} {c['check']:{width}}  {c['found']}")
            if not c["ok"]:
                print(f"     {'':{width}}  need: {c['need']}")
                print(f"     {'':{width}}  fix:  {c['fix']}")
        notes = [c for c in checks if c["check"] == "git-bundle-fsck"]
        for c in notes:
            print(f"note {c['check']}  {c['fix']}")
        print(f"check: {'everything needed is present' if not bad else f'{len(bad)} missing'}")
    return 0 if not bad else 1


def selftest():
    """Room-safe: the probes parse, the floor refuses, the fix names itself, and
    --json carries what the screen does. Version probes run against the room's
    own binaries; the missing-binary shape runs against a stripped PATH."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    import tempfile
    import shutil as _sh
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="chk.")
    home = os.path.join(base, "home")
    os.makedirs(os.path.join(home, "signers"))
    k = os.path.join(base, "k")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", k, "-C", "t"],
                   capture_output=True)
    sf = os.path.join(home, "signers", "allowed_signers")
    with open(sf, "w") as f:
        f.write(f'owner@fixture namespaces="operator-ruling" {open(k + ".pub").read().strip()}\n')
    os.chmod(sf, 0o600)
    old = os.environ.get("OPERATOR_HOME")
    os.environ["OPERATOR_HOME"] = home
    try:
        # A the probes parse a real version line
        t = version_tuple("git version 2.53.0")
        check(t == (2, 53, 0), f"A version parse: {t}")
        check(ge((2, 38), GIT_MIN) and not ge((2, 37, 9), GIT_MIN), "A the floor compares")
        check(ge((2, 37, 9, 1), GIT_MIN) is False and ge((2, 48), GIT_FSCK_FULL), "A tuple shapes")

        # B the checks run and every missing one names its fix
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--json"],
                           capture_output=True, text=True, env=dict(os.environ), timeout=60)
        check(r.returncode in (0, 1), f"B check exits 0/1: {r.returncode}")
        doc = json.loads(r.stdout)
        check(doc["schema"] == 1 and isinstance(doc["checks"], list), "B the json schema")
        for c in doc["checks"]:
            if not c["ok"]:
                check(bool(c["fix"]) and bool(c["need"]), f"B {c['check']} names its fix")
        names = {c["check"] for c in doc["checks"]}
        check({"git", "bubblewrap", "openssh", "python", "venv", "ensurepip",
               "operator-home", "signers", "adapters"} <= names, f"B the surface: {sorted(names)}")

        # C a stripped PATH makes the binaries missing, each with its fix
        empty = os.path.join(base, "emptybin")
        os.makedirs(empty)
        env = {**os.environ, "PATH": empty}
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--json"],
                           capture_output=True, text=True, env=env, timeout=60)
        doc2 = json.loads(r.stdout)
        check(r.returncode == 1 and not doc2["ok"], "C missing binaries refuse")
        byname = {c["check"]: c for c in doc2["checks"]}
        check(byname["git"]["found"] == "absent" and "apt install git" in byname["git"]["fix"],
              f"C git names its fix: {byname['git']}")
        check(byname["bubblewrap"]["found"] == "absent" and
              "sandbox=unavailable" in byname["bubblewrap"]["fix"],
              "C bwrap names what its absence means")

        # D the screen and the json agree
        r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                           capture_output=True, text=True, env=dict(os.environ), timeout=60)
        check("MISSING" in r.stdout or "everything needed is present" in r.stdout,
              "D the human screen lands")
        # F the bundle-fsck note appears exactly under the short git
        oldbin = os.path.join(base, "oldbin")
        os.makedirs(oldbin)
        fake = os.path.join(oldbin, "git")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\n[ \"$1\" = --version ] && echo 'git version 2.40.0'\nexit 0\n")
        os.chmod(fake, 0o755)
        env = {**os.environ, "PATH": oldbin + os.pathsep + os.environ["PATH"]}
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--json"],
                           capture_output=True, text=True, env=env, timeout=60)
        note = [c for c in json.loads(r.stdout)["checks"] if c["check"] == "git-bundle-fsck"]
        check(note and "bundle_fsck=off" in note[0]["fix"], f"F the fsck note: {note}")

        # H a probe that hangs is a named miss, not a traceback
        hungbin = os.path.join(base, "hungbin")
        os.makedirs(hungbin)
        fake = os.path.join(hungbin, "git")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nsleep 60\n")
        os.chmod(fake, 0o755)
        env = {**os.environ, "PATH": hungbin + os.pathsep + os.environ["PATH"]}
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--json"],
                           capture_output=True, text=True, env=env, timeout=60)
        doc5 = json.loads(r.stdout)
        byname5 = {c["check"]: c for c in doc5["checks"]}
        check(r.returncode == 1 and byname5["git"]["ok"] is False
              and byname5["git"]["found"] == "hung"
              and "never answered" in byname5["git"]["fix"],
              f"H the hung probe names itself and its fix: {byname5['git']}")

        # G a too-old binary fails the floor, and a missing module is seen
        oldbin = os.path.join(base, "oldbin2")
        os.makedirs(oldbin)
        for name, ver in (("git", "git version 2.20.0"), ("bwrap", "bubblewrap 0.4.0")):
            fake = os.path.join(oldbin, name)
            with open(fake, "w") as f:
                f.write(f"#!/bin/sh\n[ \"$1\" = --version ] && echo '{ver}'\nexit 0\n")
            os.chmod(fake, 0o755)
        env = {**os.environ, "PATH": oldbin + os.pathsep + os.environ["PATH"]}
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--json"],
                           capture_output=True, text=True, env=env, timeout=60)
        byname4 = {c["check"]: c for c in json.loads(r.stdout)["checks"]}
        check(byname4["git"]["ok"] is False and ">= 2.38" in byname4["git"]["need"],
              f"G an old git fails the floor: {byname4['git']}")
        check(byname4["bubblewrap"]["ok"] is True, "G bwrap has no version floor yet")

        # E the signers hygiene rides along
        with open(sf, "a") as f:
            f.write(f"loose@fixture {open(k + '.pub').read().strip()}\n")
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--json"],
                           capture_output=True, text=True, env=dict(os.environ), timeout=60)
        doc3 = json.loads(r.stdout)
        byname3 = {c["check"]: c for c in doc3["checks"]}
        check(byname3["signers"]["ok"] is False, "E a loose signer fails check")
        os.chmod(sf, 0o600)
        with open(sf, "w") as f:
            f.write(f'owner@fixture namespaces="operator-ruling" {open(k + ".pub").read().strip()}\n')
        os.chmod(sf, 0o600)

        print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
        return 0 if ok[0] and not bad[0] else 1
    finally:
        if old is None:
            del os.environ["OPERATOR_HOME"]
        else:
            os.environ["OPERATOR_HOME"] = old
        _sh.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.exit(main())
