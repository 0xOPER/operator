#!/usr/bin/env python3
"""init -- a program's first door: scaffolding, the signer, the hook instance.

`operator init <dir> --template feature` writes team.toml, contract.toml and
roles/ from the shipped template so a stranger edits instead of blank-filing.
`--key` registers the signing key's public half in the signers file and REFUSES
a plain key: a signing key without a passphrase protects nothing that outlives
a session, and the refusal names how to make one. `--hook <log>` renders the
audit hook instance a CLI loads: two lines naming the run's log in the
environment and exec'ing the tracked source from the read-only core, so the
instance is never tracked and never writable by a run.

usage: init.py <dir> [--template feature|plan|research] [--key <keyfile>] [--hook <logfile>]
       init.py --selftest
exit: 0 done, 1 refused (each names its fix), 2 usage or VOID
"""
import json
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
import ruling as ruling_mod  # noqa: E402

JSON_SCHEMA = 1
NAMESPACE = "operator-ruling,operator-review"
HOOK_TEMPLATE = """#!/bin/sh
OPERATOR_HOOK_LOG={log} exec {core} "$@"
"""


class Void(Exception):
    pass


class Refused(Exception):
    pass


def key_is_plain(key):
    """True when the key decrypts with an empty passphrase. ssh-keygen only
    touches the private half; a passphrase-less key answers -y with no input."""
    r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", key],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=15)
    return r.returncode == 0


def cmd_init(directory, template, key, hook_log):
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            raise Void(f"can't create {directory}: {e}")
    wrote = []
    if template:
        import re as _re
        if not _re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", template):
            raise Refused(f"invalid template {template!r}; pick feature, plan, or research")
        src = os.path.join(ROOT, "profiles", "templates", template)
        if not os.path.isdir(src):
            raise Refused(f"no template {template!r} under profiles/templates; "
                          "pick feature, plan, or research, or run without --template to scaffold by hand")
        for name in sorted(os.listdir(src)):
            s = os.path.join(src, name)
            d = os.path.join(directory, name)
            if os.path.exists(d):
                continue
            if os.path.isdir(s):
                shutil_copytree(s, d)
            else:
                with open(s, "rb") as f, open(d, "wb") as g:
                    g.write(f.read())
            wrote.append(name)
    registered = False
    if key:
        if not os.path.isfile(key):
            raise Refused(f"no key at {key}; pass the private half's path "
                          "(the .pub must sit beside it)")
        if not os.path.isfile(key + ".pub"):
            raise Refused(f"no {key}.pub beside the key; generate the pair together")
        if key_is_plain(key):
            raise Refused("a plain key signs anything that steals it; make a "
                          "passphrase key: ssh-keygen -t ed25519 -f <key>, then "
                          "register it with ssh-agent or $SSH_ASKPASS")
        sf = ruling_mod.signers_file()
        os.makedirs(os.path.dirname(sf), exist_ok=True)
        pub = open(key + ".pub").read().strip()
        principal_host = os.path.basename(os.path.abspath(directory)) or "program"
        line = f'owner@{principal_host} namespaces="{NAMESPACE}" {pub}\n'
        existing = []
        if os.path.isfile(sf):
            existing = open(sf).read().splitlines(True)
        if not any(pub in l for l in existing):
            with open(sf, "a") as f:
                f.write(line)
        os.chmod(sf, 0o600)
        registered = True
    rendered = None
    if hook_log:
        core = os.path.join(ROOT, "bin", "audit-hook.py")
        rendered = os.path.join(directory, "hook-instance.sh")
        if os.path.exists(rendered):
            raise Refused(f"hook-instance.sh already exists in {directory}; an "
                          "edited instance is yours -- move it aside or delete "
                          "it to re-render")
        with open(rendered, "w") as f:
            f.write(HOOK_TEMPLATE.format(log=hook_log, core=core))
        os.chmod(rendered, 0o755)
        wrote.append("hook-instance.sh")
    return {"schema": JSON_SCHEMA, "dir": directory, "template": template,
            "wrote": wrote, "signer_registered": registered, "hook": rendered}


def shutil_copytree(src, dst):
    import shutil
    shutil.copytree(src, dst)


def main(argv):
    if len(argv) < 2 or argv[1].startswith("-"):
        print("usage: init.py <dir> [--template feature] [--key <keyfile>] "
              "[--hook <logfile>]", file=sys.stderr)
        return 2
    try:
        doc = cmd_init(argv[1], _flag(argv, "--template"), _flag(argv, "--key"),
                       _flag(argv, "--hook"))
    except Refused as e:
        print(f"init: {e}", file=sys.stderr)
        return 1
    except Void as e:
        print(f"init: VOID, {e}", file=sys.stderr)
        return 2
    print(json.dumps(doc, ensure_ascii=True, sort_keys=True))
    return 0


def _flag(argv, name):
    if name in argv and argv.index(name) + 1 < len(argv):
        return argv[argv.index(name) + 1]
    return None


def selftest():
    """Room-safe: the template lands and validates, a plain key refuses with the
    command that fixes it, a passphrase key registers once, and the rendered
    hook instance names the log and execs the tracked source."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    import shutil as _sh
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="init-rt.")
    home = os.path.join(base, "home")
    os.makedirs(home)
    old = os.environ.get("OPERATOR_HOME")
    os.environ["OPERATOR_HOME"] = home
    try:
        # A the feature template lands and validates through both loaders
        d = os.path.join(base, "prog")
        doc = cmd_init(d, "feature", None, None)
        check(sorted(doc["wrote"]) == ["contract.toml", "roles", "team.toml"],
              f"A template files: {doc['wrote']}")
        import team as team_mod
        import contract as contract_mod
        team_mod.load(d)
        contract_mod.load(d)
        rl_f = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "contract.py"), "lint", d],
                              capture_output=True, text=True)
        check(rl_f.returncode == 0,
              f"A the feature template validates and passes contract lint: {rl_f.stdout}{rl_f.stderr}")

        # B a second init over the same dir writes nothing, loses nothing
        doc2 = cmd_init(d, "feature", None, None)
        check(doc2["wrote"] == [], "B re-init over existing files writes nothing")

        # C a plain key refuses with the fix named; a passphrase key registers once
        plain = os.path.join(base, "plain")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", plain,
                        "-C", "plain"], capture_output=True)
        try:
            cmd_init(d, None, plain, None)
            check(False, "C a plain key refuses")
        except Refused as e:
            check("passphrase" in str(e) and "ssh-keygen -t ed25519" in str(e),
                  f"C the refusal names the fix: {e}")
        locked = os.path.join(base, "locked")
        askpass = os.path.join(base, "askpass.sh")
        with open(askpass, "w") as f:
            f.write("#!/bin/sh\necho open-sesame\n")
        os.chmod(askpass, 0o755)
        env = {**os.environ, "SSH_ASKPASS": askpass, "SSH_ASKPASS_REQUIRE": "force",
               "DISPLAY": ":0"}
        r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "open-sesame",
                            "-f", locked, "-C", "locked"], capture_output=True, env=env)
        check(r.returncode == 0, "C fixture passphrase key made")
        check(key_is_plain(plain) and not key_is_plain(locked),
              "C plainness probe discriminates")
        doc3 = cmd_init(d, None, locked, None)
        check(doc3["signer_registered"], "C a passphrase key registers")
        sf = ruling_mod.signers_file()
        body = open(sf).read()
        check(body.count("ssh-ed25519") == 1 and "operator-ruling" in body,
              f"C exactly one restricted signer: {body[:80]}")
        cmd_init(d, None, locked, None)
        check(open(sf).read() == body, "C a second registration doesn't duplicate")

        # D the rendered hook names the log and execs the tracked source
        doc4 = cmd_init(os.path.join(base, "p2"), None, None,
                        os.path.join(base, "p2", "run.log"))
        body = open(doc4["hook"]).read()
        core = os.path.join(ROOT, "bin", "audit-hook.py")
        check(f"OPERATOR_HOOK_LOG=" in body and core in body and "exec" in body,
              f"D the hook instance renders: {body!r}")
        r = subprocess.run(["/bin/sh", doc4["hook"], "post_tool_use"], input="{}",
                           capture_output=True, text=True,
                           env={**os.environ, "OPERATOR_HOOK_LOG":
                                os.path.join(base, "p2", "run.log")})
        check(r.returncode == 0 and
              os.path.exists(os.path.join(base, "p2", "run.log")),
              f"D the instance execs the tracked hook: {r.stderr[:80]}")

        # F a second --hook refuses rather than clobber the rendered instance
        try:
            cmd_init(os.path.join(base, "p2"), None, None,
                     os.path.join(base, "p2", "other.log"))
            check(False, "F a second --hook refuses")
        except Refused as e:
            check("hook-instance.sh already exists" in str(e) and "move it aside" in str(e),
                  f"F the refusal names the instance and its fix: {e}")
        check(open(doc4["hook"]).read() == body, "F the first instance is unchanged")

        # E an unknown or traversal template refuses with what exists; plan & research validate
        for bad_tpl in ("nope", "../migration"):
            try:
                cmd_init(os.path.join(base, "p3"), bad_tpl, None, None)
                check(False, f"E bad template {bad_tpl} refuses")
            except Refused as e:
                check("pick feature" in str(e), f"E names the choice ({bad_tpl}): {e}")
        for tpl in ("plan", "research"):
            dt = os.path.join(base, f"tpl-{tpl}")
            cmd_init(dt, tpl, None, None)
            team_mod.load(dt)
            contract_mod.load(dt)
            rl_t = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "contract.py"), "lint", dt],
                                  capture_output=True, text=True)
            check(rl_t.returncode == 0,
                  f"E2 {tpl} template scaffolds, validates, and passes contract lint: {rl_t.stdout}{rl_t.stderr}")

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
    sys.exit(main(sys.argv))
