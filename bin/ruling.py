#!/usr/bin/env python3
"""ruling -- the canonical closure of everything a run depends on, signed.

A closure names each component by the sha256 of its bytes, sorted by key and serialised
once, so the same program state yields byte-identical closures (the unit arm proves it)
and any one changed component changes its named hash. `sign` closes the program as it
stands and records an arm or row ruling under an ssh-keygen -Y signature in the
operator-ruling namespace; `verify` recomputes the closure, compares it byte for byte,
checks the signature against the signers file, and refuses when the signer has been
rotated out or the namespace isn't ours. Verifying the newest ruling of a kind is the
default; older ones are superseded, not lost.

The signers file lives under OPERATOR_HOME (signers/allowed_signers by default, or
OPERATOR_SIGNERS), outside every bind a run mounts. `check` holds its hygiene: every
entry must restrict itself to the operator-ruling namespace, and the file must not be
writable past its owner or sit under a bind. The v1 engine's $ROOT/allowed_signers is
untouched and stays with v1 until it leaves.

usage: ruling.py closure <program-dir>
       ruling.py sign <program-dir> [--kind arm|row] [--row <id>] [--key <keyfile>]
       ruling.py verify <program-dir> [ruling-file]
       ruling.py arm-hash <program-dir>            the newest arm ruling's hash, for CONTRACT_ARM
       ruling.py show <program-dir> [ruling-file]
       ruling.py check                             signers hygiene (T4)
       ruling.py --selftest
env: OPERATOR_SIGNERS, OPERATOR_HOME, CONTRACT_REPO, CONTRACT_TIP, CONTRACT_PIN
exit: 0 closed or verified, 1 refused, 2 usage or VOID
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CLOSURE_SCHEMA = 1
ENVELOPE_SCHEMA = 1
NAMESPACE = "operator-ruling"
ALLOWED_NAMESPACES = (NAMESPACE, "operator-review")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# allowed_signers: principals, then OPTIONS (where namespaces= belongs), then the key.
# Anything after the key blob is a comment ssh-keygen ignores, so a restriction there
# restricts nothing and check refuses the line.
SIGNER_KEY = re.compile(r"(?:ssh|sk-ssh|ecdsa|sk-ecdsa)-[A-Za-z0-9@._-]+\s+[A-Za-z0-9+/=]+")
NAMESPACES = re.compile(r"(?:^|\s)namespaces=(\"([^\"]*)\"|([^\"\s]+))")
BIND_PREFIXES = ("/work", "/w/", "/prog", "/env", "/tmp/contract.")


class Void(Exception):
    pass


class Refused(Exception):
    pass


def die(msg, code):
    print(f"ruling: {msg}", file=sys.stderr)
    sys.exit(code)


def sh(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)


def signers_file():
    return os.environ.get("OPERATOR_SIGNERS") or os.path.join(
        os.environ.get("OPERATOR_HOME", os.path.join(ROOT, "state")), "signers", "allowed_signers")


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_sha(path):
    """A directory's content hash: sorted relative paths and FULL bytes, links by
    target, no metadata, so a touched-but-unchanged tree closes identically and no
    byte of any file hides below a cap. Each entry is length-prefixed so distinct
    paths or boundaries can never collide. A non-regular file that isn't a link
    fails loud: a FIFO has no place in a ruled tree."""
    entries = []

    def walk(d, prefix):
        for entry in sorted(os.scandir(d), key=lambda e: e.name):
            rel = prefix + entry.name
            if entry.is_symlink():
                entries.append((rel.encode(), b"link", os.readlink(entry.path).encode()))
            elif entry.is_dir(follow_symlinks=False):
                walk(entry.path, rel + "/")
            elif entry.is_file(follow_symlinks=False):
                entries.append((rel.encode(), b"file", entry.path))
            else:
                raise Void(f"{entry.path} isn't a regular file or a link, so it can't be ruled")

    walk(path, "")
    h = hashlib.sha256()
    for rel_b, kind, source in entries:
        h.update(b"%s:%d:" % (kind, len(rel_b)))
        h.update(rel_b)
        if isinstance(source, bytes):
            h.update(b":%d:" % len(source))
            h.update(source)
        else:
            sz = os.lstat(source).st_size
            h.update(b":%d:" % sz)
            with open(source, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        h.update(b"\n")
    return h.hexdigest()


def core_state():
    tree = os.environ.get("RULING_CORE_GIT") or ROOT
    r = sh(["git", "-C", tree, "rev-parse", "HEAD"])
    if r.returncode != 0:
        raise Void(f"the core at {tree} isn't a git tree")
    dirty = bool(sh(["git", "-C", tree, "status", "--porcelain"]).stdout.strip())
    return r.stdout.strip(), dirty


def closure_of(prog):
    """The canonical closure: component name -> sha, plus the ruled base and core state.
    The signers file is deliberately not a component: it changes as signers rotate, and
    rotation is the signature check's business, not the closure's."""
    if not os.path.isfile(os.path.join(prog, "contract.toml")):
        raise Void(f"no contract.toml in {prog}, so nothing closes")
    comp = {"contract.toml": file_sha(os.path.join(prog, "contract.toml"))}
    for name in sorted(os.listdir(prog)):
        if name in ("rulings", "runs") or name == "contract.toml" or name.startswith("."):
            continue
        p = os.path.join(prog, name)
        if os.path.isdir(p) and not os.path.islink(p):
            comp[name] = tree_sha(p)
        else:
            comp[name] = file_sha(p)
    repo = os.environ.get("CONTRACT_REPO")
    tip = os.environ.get("CONTRACT_TIP") or "HEAD"
    base = os.environ.get("CONTRACT_PIN") or tip
    if not repo and os.environ.get("CONTRACT_PIN"):
        raise Void("CONTRACT_PIN is set but CONTRACT_REPO isn't, so the pin can't resolve")
    base_sha = ""
    if repo:
        if not os.path.isdir(os.path.join(repo, ".git")):
            raise Void("CONTRACT_REPO must be a git tree")
        r = sh(["git", "-C", repo, "rev-parse", base])
        if r.returncode != 0:
            raise Void(f"the ruled base {base} doesn't resolve in the work repo")
        base_sha = r.stdout.strip()
    core_sha, dirty = core_state()
    sf = signers_file()
    return {
        "schema": CLOSURE_SCHEMA,
        "components": comp,
        "base": base_sha,
        "core": core_sha,
        "core_dirty": dirty,
    }


def serialise(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def rulings_dir(prog):
    return os.path.join(prog, "rulings")


def list_rulings(prog):
    d = rulings_dir(prog)
    if not os.path.isdir(d):
        return []
    out = []
    for name in sorted(os.listdir(d)):
        if not re.fullmatch(r"\d{5}-(arm|row|stage)(?:\.[a-z0-9._-]+)?\.json", name):
            continue
        try:
            with open(os.path.join(d, name), encoding="utf-8") as f:
                doc = json.load(f)
            if not isinstance(doc, dict) or "sig" not in doc or "closure_bytes" not in doc:
                raise ValueError("not a ruling record")
        except (OSError, ValueError) as e:
            raise Void(f"ruling {name} doesn't parse: {e}")
        out.append((name, doc))
    return out


def newest(prog, kind):
    hits = [(n, d) for n, d in list_rulings(prog) if d.get("kind") == kind]
    return hits[-1] if hits else None


def cmd_closure(prog):
    print(serialise(closure_of(prog)).decode())


def sign(prog, kind, row, key, run=None, not_after=None, waivers=None):
    if kind not in ("arm", "row", "stage"):
        raise Refused("--kind is arm, row or stage")
    if row is not None and not ID_RE.fullmatch(row):
        raise Refused(f"--row {row!r} must match [a-z0-9][a-z0-9._-]{{0,63}}")
    if not_after:
        try:
            time.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise Refused("--not-after takes 2026-12-31T23:59:59Z, UTC")
    core_sha, dirty = core_state()
    if dirty:
        raise Refused("the core is dirty; a ruling over uncommitted bytes certifies nothing. "
                      "Commit or stash, then rule")
    if kind in ("row", "stage") and not row:
        raise Refused(f"a {kind} ruling names its --{kind}")
    sf = signers_file()
    if not os.path.isfile(sf):
        raise Void(f"no signers file at {sf}; nothing can be signed")
    if not key:
        raise Void("a signing key is required (--key); rulings are never made by the engine alone")
    try:
        with open(key + ".pub") as f:
            blob = f.read().split()[1]
    except (OSError, IndexError):
        raise Void("the signing key has no readable .pub beside it")
    with open(sf, encoding="utf-8") as f:
        if not any(not line.lstrip().startswith("#") and blob in line.split() for line in f):
            raise Refused("the signing key is not in the signers file, so its ruling could never verify")
    closure = closure_of(prog)
    payload = serialise(closure)
    signed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    waiver_list = sorted(set(waivers or ()))
    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "kind": kind,
        "row": row,
        "run": run,
        "not_after": not_after,
        "signed_at": signed_at,
        "waivers": waiver_list,
        "closure_sha": hashlib.sha256(payload).hexdigest(),
        "closure": closure,
    }
    envelope_bytes = serialise(envelope)
    with tempfile.TemporaryDirectory(prefix="ruling.") as t:
        p = os.path.join(t, "envelope")
        with open(p, "wb") as f:
            f.write(envelope_bytes)
        r = sh(["ssh-keygen", "-Y", "sign", "-f", key, "-n", NAMESPACE, p])
        sig_path = p + ".sig"
        if r.returncode != 0 or not os.path.isfile(sig_path):
            raise Void(f"the signer refused: {(r.stderr or r.stdout).strip()[:160]}")
        with open(sig_path, "rb") as f:
            sig = base64.b64encode(f.read()).decode()
    fp = sh(["ssh-keygen", "-lf", key])
    who = fp.stdout.split()[1] if fp.returncode == 0 else "unknown"
    d = rulings_dir(prog)
    os.makedirs(d, exist_ok=True)
    nums = [int(x[0].split("-")[0]) for x in list_rulings(prog)]
    n = (max(nums) + 1) if nums else 1
    record = {"kind": kind, "row": row, "signer": who, "signed_at": signed_at,
              "run": run, "not_after": not_after, "waivers": waiver_list,
              "closure": closure, "closure_bytes": payload.decode(),
              "envelope_bytes": envelope_bytes.decode(), "sig": sig}
    while True:
        path = os.path.join(d, f"{n:05d}-{kind}{('.' + row) if row else ''}.json")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            n += 1
            continue
        with os.fdopen(fd, "w") as f:
            json.dump(record, f, indent=1, sort_keys=True)
        break
    print(path)
    return path


def signers_history():
    """Rotation memory: <home>/signers/history.tsv holds fingerprint TAB from
    TAB to (UTC), and the retired key's bytes sit at signers/retired/<fp>.pub.
    A key rotated OUT of allowed_signers still verifies rulings SIGNED inside
    its recorded window and nothing after; rotation without a history row
    revokes retroactively, which is the point of rotating."""
    import datetime as _dt
    root = os.path.dirname(signers_file())
    sf = os.path.join(root, "history.tsv")
    out = []
    if os.path.isfile(sf):
        with open(sf, encoding="utf-8") as f:
            for ln in f:
                parts = ln.strip().split("\t")
                if len(parts) != 3:
                    continue
                fp, t0, t1 = parts
                try:
                    d0 = _dt.datetime.strptime(t0, "%Y-%m-%dT%H:%M:%SZ")
                    d1 = _dt.datetime.strptime(t1, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    continue
                pub = os.path.join(root, "retired", fp.replace("/", "_") + ".pub")
                if not os.path.isfile(pub):
                    continue  # a window with no key certifies nothing
                out.append((fp, d0, d1, pub))
    return out


def verify_one(prog, name, doc):
    sf = signers_file()
    if not os.path.isfile(sf):
        raise Void(f"no signers file at {sf}")
    closure = closure_of(prog)
    if serialise(closure) != doc["closure_bytes"].encode():
        raise Refused(f"{name}: the program no longer closes as it did when signed")
    env_raw = doc.get("envelope_bytes")
    if not isinstance(env_raw, str) or not env_raw:
        raise Refused(f"{name}: ruling carries no signed envelope (unsigned metadata is refused)")
    try:
        env = json.loads(env_raw)
    except ValueError:
        raise Refused(f"{name}: signed envelope doesn't parse")
    if (not isinstance(env, dict)
            or env.get("kind") != doc.get("kind")
            or env.get("row") != doc.get("row")
            or env.get("run") != doc.get("run")
            or env.get("not_after") != doc.get("not_after")
            or env.get("signed_at") != doc.get("signed_at")
            or env.get("waivers", []) != doc.get("waivers", [])
            or serialise(env.get("closure")) != doc["closure_bytes"].encode()
            or env.get("closure_sha") != hashlib.sha256(doc["closure_bytes"].encode()).hexdigest()):
        raise Refused(f"{name}: ruling envelope metadata does not match its signed bytes")
    with tempfile.TemporaryDirectory(prefix="ruling.") as t:
        s = os.path.join(t, "envelope.sig")
        try:
            sig_bytes = base64.b64decode(doc["sig"])
        except ValueError:
            raise Refused(f"{name}: malformed signature encoding")
        with open(s, "wb") as f:
            f.write(sig_bytes)
        principals = []
        with open(sf, encoding="utf-8") as sfh:
            for line in sfh:
                line = line.strip()
                if line and not line.startswith("#"):
                    principals.append(line.split()[0])
        ok = False
        # key rotation: a signer rotated out still verifies inside the window
        # history.tsv records for it -- the signed envelope's signed_at decides
        import datetime as _dt2
        hist_ok = False
        try:
            when = _dt2.datetime.strptime(env.get("signed_at", ""),
                                          "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            when = None
        signer_fp = doc.get("signer", "")
        for fp, d0, d1, pub in signers_history():
            if fp == signer_fp and when and d0 <= when <= d1:
                # the key is gone from allowed_signers; verify against the ONE
                # retired key by materialising a one-key signers file
                hs = os.path.join(t, "history-signers")
                with open(hs, "w") as h:
                    h.write(f'{signer_fp} namespaces="{NAMESPACE}" {open(pub).read().strip()}\n')
                r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", hs,
                                    "-I", signer_fp, "-n", NAMESPACE, "-s", s],
                                   input=env_raw, capture_output=True,
                                   text=True)
                if r.returncode == 0:
                    ok = True
                    hist_ok = True
                break
        for ident in ([] if hist_ok else principals + [doc.get("signer", "")]):
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", sf, "-I", ident,
                                "-n", NAMESPACE, "-s", s],
                               input=env_raw, capture_output=True, text=True)
            if r.returncode == 0:
                ok = True
                break
        if not ok:
            raise Refused(f"{name}: the signature doesn't verify, or its signer was rotated out")
    return doc


def cmd_verify(prog, named):
    hits = list_rulings(prog)
    if not hits:
        raise Void("no rulings to verify")
    if named:
        target = [(n, d) for n, d in hits if n == named or n == os.path.basename(named)]
        if not target:
            raise Refused(f"no ruling named {named}")
    else:
        target = [hits[-1]]
    verify_one(prog, target[0][0], target[0][1])
    d = target[0][1]
    print(f"verified: {target[0][0]} kind={d['kind']} row={d.get('row') or '-'} signer={d['signer']}")


def arm_hash_of(prog):
    """The newest arm ruling that still verifies, as a 16-hex closure hash, or None."""
    for name, doc in reversed(list_rulings(prog)):
        if doc.get("kind") != "arm":
            continue
        try:
            verify_one(prog, name, doc)
        except (Refused, Void):
            continue
        return hashlib.sha256(doc["closure_bytes"].encode()).hexdigest()[:16]
    return None


def cmd_arm_hash(prog):
    """The newest arm ruling that still verifies: an unverifiable one is never an arm."""
    h = arm_hash_of(prog)
    if h:
        print(h)
        return
    raise Void("no arm ruling verifies; CONTRACT_ARM stays '-'")


def cmd_show(prog, named):
    hits = list_rulings(prog)
    if not hits:
        raise Void("no rulings")
    for name, doc in hits:
        if not named or name == named or name == os.path.basename(named):
            print(f"{name} kind={doc['kind']} row={doc.get('row') or '-'} signer={doc['signer']} "
                  f"signed_at={doc['signed_at']}")


def cmd_check():
    sf = signers_file()
    if not os.path.isfile(sf):
        raise Void(f"no signers file at {sf}")
    bad = []
    with open(sf, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            m = SIGNER_KEY.search(line)
            if not m or m.start() < 1:
                bad.append(f"line {i}: not a signer entry")
                continue
            options = line[:m.start()]
            if "namespaces" in line[m.end():]:
                bad.append(f"line {i}: namespaces= after the key is a comment, not a restriction")
                continue
            hits = list(NAMESPACES.finditer(options))
            if len(hits) != 1:
                bad.append(f"line {i}: exactly one namespaces= restriction, in the options")
                continue
            got = [g for g in (hits[0].group(2) or hits[0].group(3) or "").split(",") if g]
            if not got or NAMESPACE not in got or any(ns not in ALLOWED_NAMESPACES for ns in got):
                bad.append(f"line {i}: namespaces must be exactly within {list(ALLOWED_NAMESPACES)}, not {got}")
    st = os.stat(sf)
    if st.st_mode & 0o022:
        bad.append(f"the signers file is writable past its owner ({oct(st.st_mode & 0o777)})")
    real_sf = os.path.realpath(sf)
    if any(real_sf == "/" or real_sf.startswith(p) for p in BIND_PREFIXES):
        bad.append(f"the signers file sits under a bind ({sf})")
    for b in bad:
        print(f"ruling: {b}", file=sys.stderr)
    if bad:
        sys.exit(1)
    print(f"check: {sf} holds ({sum(1 for l in open(sf) if l.strip() and not l.startswith('#'))} signers)")


USAGE = ("usage: ruling.py closure|sign|verify|arm-hash|show|check <program-dir> [args] | --selftest")


def selftest():
    import shutil as _shutil
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))  # the suite never eats the box

    ok = [0]
    bad = [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    def verb(*args, env=None):
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run([sys.executable, os.path.abspath(__file__), *args],
                              capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)

    base = tempfile.mkdtemp(prefix="rt.")
    home = os.path.join(base, "home")
    os.makedirs(os.path.join(home, "signers"))
    sf = os.path.join(home, "signers", "allowed_signers")
    k1 = os.path.join(base, "k1")
    k2 = os.path.join(base, "k2")
    for k in (k1, k2):
        r = sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", k, "-C", "test-signer"])
        if r.returncode != 0:
            die("ssh-keygen unavailable", 2)
    def signer_line(k):
        pub = open(k + ".pub").read().strip()
        return f'test@fixture namespaces="{NAMESPACE}" {pub}\n'
    with open(sf, "w") as f:
        f.write(signer_line(k1))
    os.chmod(sf, 0o600)
    core = os.path.join(base, "core")
    os.makedirs(core)
    with open(os.path.join(core, "VERSION"), "w") as f:
        f.write("0.1\n")
    e = dict(os.environ)
    e["GIT_AUTHOR_NAME"] = e["GIT_COMMITTER_NAME"] = "t"
    e["GIT_AUTHOR_EMAIL"] = e["GIT_COMMITTER_EMAIL"] = "t@x"
    subprocess.run(["git", "-C", core, "init", "-q"], capture_output=True, env=e)
    subprocess.run(["git", "-C", core, "add", "-A"], capture_output=True, env=e)
    subprocess.run(["git", "-C", core, "commit", "-qm", "core"], capture_output=True, env=e)
    env = {"OPERATOR_HOME": home, "RULING_CORE_GIT": core}
    prog = os.path.join(base, "prog")
    os.makedirs(prog)
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                'seat = "x"\nreviewer = "y"\ncmd = "true"\n')

    # A the same state closes byte-identically; one changed component changes its hash (T1)
    r1 = verb("closure", prog, env=env)
    r2 = verb("closure", prog, env=env)
    check(r1.returncode == 0 and r1.stdout == r2.stdout and r1.stdout.strip(), f"A determinism: {r1.stderr}")
    check(r1.stdout.startswith('{"base"'), "A the closure is sorted, whatever built it")
    first = json.loads(r1.stdout)
    with open(os.path.join(prog, "contract.toml"), "a") as f:
        f.write("\n")
    r3 = verb("closure", prog, env=env)
    check(json.loads(r3.stdout)["components"]["contract.toml"] != first["components"]["contract.toml"],
          "A a changed component changes its hash")
    with open(os.path.join(prog, "contract.toml"), "r+") as f:
        body = f.read().rstrip("\n")
        f.seek(0)
        f.write(body)
        f.truncate()

    # B sign and verify round-trip; a tampered closure refuses
    rs = verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    check(rs.returncode == 0 and os.path.isfile(rs.stdout.strip()), f"B sign: {rs.stderr}")
    ruling = rs.stdout.strip()
    rv = verb("verify", prog, env=env)
    check(rv.returncode == 0 and "kind=arm" in rv.stdout, f"B verify: {rv.stdout}{rv.stderr}")
    with open(ruling) as f:
        doc = json.load(f)
    doc["closure_bytes"] = doc["closure_bytes"].replace("schema", "schema ", 1)
    with open(ruling, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    rv = verb("verify", prog, env=env)
    check(rv.returncode == 1, f"B tamper: {rv.stdout}{rv.stderr}")
    with open(ruling) as f:
        doc = json.load(f)
    doc["closure_bytes"] = doc["closure_bytes"].replace("schema ", "schema", 1)
    with open(ruling, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)

    # B2 a program that changed under a good signature refuses: the closure isn't what was signed
    rs2 = verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    with open(os.path.join(prog, "contract.toml"), "a") as f:
        f.write("\n")
    rv = verb("verify", prog, env=env)
    check(rv.returncode == 1 and "no longer closes" in rv.stderr, f"B2 changed program: {rv.stderr}")
    with open(os.path.join(prog, "contract.toml"), "r+") as f:
        body = f.read().rstrip("\n")
        f.seek(0); f.write(body); f.truncate()

    # C a signature in the wrong namespace never verified, so a forged one refuses
    p = tempfile.NamedTemporaryFile(delete=False, suffix=".envelope")
    p.write(doc["envelope_bytes"].encode())
    p.close()
    sh(["ssh-keygen", "-Y", "sign", "-f", k1, "-n", "other-namespace", p.name])
    with open(p.name + ".sig", "rb") as f:
        doc["sig"] = base64.b64encode(f.read()).decode()
    with open(ruling, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    os.unlink(p.name)
    os.unlink(p.name + ".sig")
    rv = verb("verify", prog, ruling, env=env)
    check(rv.returncode == 1 and "rotated out" in rv.stderr, f"C wrong namespace: {rv.stderr}ERR:{rv.stdout}")
    # C2 tampering envelope metadata (not_after, run, kind, signed_at) after signing refuses
    rs_m = verb("sign", prog, "--kind", "arm", "--key", k1, "--run", "r1",
                "--not-after", "2099-01-01T00:00:00Z", env=env)
    check(rs_m.returncode == 0, f"C2 signed bound arm: {rs_m.stderr}")
    rm_path = rs_m.stdout.strip()
    orig_m = json.load(open(rm_path))
    for field, bogus in (("not_after", None), ("run", "r2"), ("kind", "row"),
                         ("signed_at", "2020-01-01T00:00:00Z")):
        tampered = dict(orig_m)
        tampered[field] = bogus
        with open(rm_path, "w") as f:
            json.dump(tampered, f, indent=1, sort_keys=True)
        rv_m = verb("verify", prog, rm_path, env=env)
        check(rv_m.returncode == 1 and "envelope" in rv_m.stderr,
              f"C2 tamper {field} refuses: rc={rv_m.returncode} {rv_m.stderr}")
    with open(rm_path, "w") as f:
        json.dump(orig_m, f, indent=1, sort_keys=True)
    check(verb("verify", prog, rm_path, env=env).returncode == 0, "C2 intact envelope verifies")
    # C3 tree_sha length-prefixes entries so ["ab","c"] vs ["a","bc"] never collide
    t_a, t_b = os.path.join(base, "ta"), os.path.join(base, "tb")
    os.makedirs(t_a)
    os.makedirs(t_b)
    open(os.path.join(t_a, "ab"), "w").write("1")
    open(os.path.join(t_a, "c"), "w").write("2")
    open(os.path.join(t_b, "a"), "w").write("1")
    open(os.path.join(t_b, "bc"), "w").write("2")
    check(tree_sha(t_a) != tree_sha(t_b), "C3 distinct trees never collide in tree_sha")
    t_c, t_d = os.path.join(base, "tc"), os.path.join(base, "td")
    os.makedirs(t_c)
    os.makedirs(t_d)
    open(os.path.join(t_c, "x"), "w").write("1\nfile:1:y:2")
    open(os.path.join(t_d, "x"), "w").write("1")
    open(os.path.join(t_d, "y"), "w").write("2")
    check(tree_sha(t_c) != tree_sha(t_d), "C3 length-prefixed data blocks framing collisions")
    # C4 row id traversal refuses
    check(verb("sign", prog, "--kind", "row", "--row", "../evil", "--key", k1, env=env).returncode == 1,
          "C4 path-traversal row id refuses")
    # restore a good signature
    rs = verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    check(rs.returncode == 0, "C restore")

    # D rotation: a signer removed from the file fails verify, and arm-hash tracks the newest arm
    with open(sf, "w") as f:
        f.write(signer_line(k2))
    rv = verb("verify", prog, env=env)
    check(rv.returncode == 1, f"D rotated out: {rv.stdout}{rv.stderr}")
    with open(sf, "w") as f:
        f.write(signer_line(k1))
    ra = verb("arm-hash", prog, env=env)
    check(ra.returncode == 0 and re.fullmatch(r"[0-9a-f]{16}", ra.stdout.strip()), f"D arm-hash: {ra.stdout}")
    h1 = ra.stdout.strip()
    verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    ra = verb("arm-hash", prog, env=env)
    check(ra.stdout.strip() == h1, "D unchanged state keeps its arm hash")
    with open(os.path.join(prog, "team.toml"), "w") as f:
        f.write('schema = 1\n')
    verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    ra = verb("arm-hash", prog, env=env)
    check(ra.stdout.strip() != h1, "D changed state changes the arm hash")
    os.unlink(os.path.join(prog, "team.toml"))

    # E row rulings name their row, and verify of the newest is the default
    rr = verb("sign", prog, "--kind", "row", "--row", "a", "--key", k1, env=env)
    check(rr.returncode == 0, f"E row sign: {rr.stderr}")
    rv = verb("verify", prog, env=env)
    check(rv.returncode == 0 and "kind=row" in rv.stdout, f"E newest verified: {rv.stdout}ERR:{rv.stderr}")
    rs2 = verb("sign", prog, "--kind", "row", "--key", k1, env=env)
    check(rs2.returncode == 1, "E a rowless row ruling refused at sign")

    # F signers hygiene: no namespaces, a wider namespace, and a loose mode all fail
    rc = verb("check", env=env)
    check(rc.returncode == 0, f"F clean: {rc.stderr}")
    with open(sf, "a") as f:
        f.write(f"loose@fixture {open(k2 + '.pub').read().strip()}\n")
    rc = verb("check", env=env)
    check(rc.returncode == 1 and "namespaces" in rc.stderr, f"F no restriction: {rc.stderr}")
    with open(sf, "w") as f:
        f.write(f"t@f namespaces={NAMESPACE},other {open(k1 + '.pub').read().strip()}\n")
    rc = verb("check", env=env)
    check(rc.returncode == 1 and "exactly" in rc.stderr, f"F wider: {rc.stderr}")
    with open(sf, "w") as f:
        f.write(f't@f namespaces="{NAMESPACE},operator-review" {open(k1 + ".pub").read().strip()}\n')
    rc = verb("check", env=env)
    check(rc.returncode == 0, f"F ruling+review allowed: {rc.stderr}")
    with open(sf, "w") as f:
        f.write(signer_line(k1))
    os.chmod(sf, 0o664)
    rc = verb("check", env=env)
    check(rc.returncode == 1 and "writable" in rc.stderr, f"F loose mode: {rc.stderr}")
    os.chmod(sf, 0o600)
    rc = verb("check", env=env)
    check(rc.returncode == 0, "F restored")

    # F2 the fold's own promises: a byte past any cap moves the closure, env closes,
    # a comment-position restriction fails check, a non-signer key can't sign, a dirty
    # core refuses, and a malformed ruling is VOID, not a traceback
    tools = os.path.join(prog, "tools")
    os.makedirs(tools)
    big = os.path.join(tools, "big.bin")
    with open(big, "wb") as f:
        f.write(b"A" * 76800)
    r4 = verb("closure", prog, env=env)
    with open(big, "r+b") as f:
        f.seek(70000)
        f.write(b"B" * 100)
    r5 = verb("closure", prog, env=env)
    check(r4.stdout != r5.stdout, "F2 a byte past 64KiB moves the closure")
    os.unlink(big)
    envd = os.path.join(prog, "env")
    os.makedirs(envd)
    with open(os.path.join(envd, "e.conf"), "w") as f:
        f.write("good\n")
    r6 = verb("closure", prog, env=env)
    with open(os.path.join(envd, "e.conf"), "w") as f:
        f.write("evil\n")
    r7 = verb("closure", prog, env=env)
    check(r6.stdout != r7.stdout, "F2 env content closes")
    os.unlink(os.path.join(envd, "e.conf"))
    os.rmdir(envd)
    with open(sf, "w") as f:
        pub = open(k1 + ".pub").read().strip()
        f.write(f"t@f {pub} namespaces={NAMESPACE}\n")
    os.chmod(sf, 0o600)
    rc = verb("check", env=env)
    check(rc.returncode == 1 and "comment" in rc.stderr, f"F2 comment position: {rc.stderr}")
    with open(sf, "w") as f:
        f.write(signer_line(k1))
    k3 = os.path.join(base, "k3")
    sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", k3, "-C", "outsider"])
    rs = verb("sign", prog, "--kind", "arm", "--key", k3, env=env)
    check(rs.returncode == 1 and "not in the signers file" in rs.stderr, f"F2 outsider key: {rs.stderr}")
    with open(os.path.join(core, "junk.txt"), "w") as f:
        f.write("uncommitted\n")
    rs = verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    check(rs.returncode == 1 and "dirty" in rs.stderr, f"F2 dirty core: {rs.stderr}")
    os.unlink(os.path.join(core, "junk.txt"))
    rs = verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    check(rs.returncode == 0, "F2 clean core signs again")
    d = os.path.join(prog, "rulings")
    with open(os.path.join(d, "99999-arm.json"), "w") as f:
        f.write("{not json")
    ra = verb("arm-hash", prog, env=env)
    check(ra.returncode == 2 and "doesn't parse" in ra.stderr, f"F2 malformed ruling: {ra.stderr}")
    os.unlink(os.path.join(d, "99999-arm.json"))
    ra = verb("arm-hash", prog, env=env)
    check(ra.returncode == 0, "F2 arm-hash recovers")

    # H key rotation: a ruling signed by a key later rotated OUT refuses
    # without a history row, and verifies inside the window history.tsv
    # records with the retired key's bytes beside it
    import datetime as _dt
    rh = verb("sign", prog, "--kind", "arm", "--key", k1, env=env)
    check(rh.returncode == 0, f"H sign for rotation: {rh.stderr[:80]}")
    # rotate k1 out; k2 signs going forward
    for _kp in (k2, k2 + ".pub"):
        if os.path.exists(_kp):
            os.unlink(_kp)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
                    k2, "-C", "next-signer"], capture_output=True, stdin=subprocess.DEVNULL)
    with open(sf, "w") as f:
        f.write(signer_line(k2))
    rr = verb("verify", prog, env=env)
    check(rr.returncode == 1 and "rotated out" in rr.stderr,
          f"H rotation refuses the old key: rc={rr.returncode} {rr.stderr[:80]}")
    fp1 = sh(["ssh-keygen", "-lf", k1]).stdout.split()[1]
    retired = os.path.join(home, "signers", "retired")
    os.makedirs(retired, exist_ok=True)
    _shutil.copy(k1 + ".pub", os.path.join(retired, fp1.replace("/", "_") + ".pub"))
    now = _dt.datetime.utcnow()
    with open(os.path.join(home, "signers", "history.tsv"), "w") as f:
        f.write(f"{fp1}\t2020-01-01T00:00:00Z\t"
                f"{(now + _dt.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
    rr2 = verb("verify", prog, env=env)
    check(rr2.returncode == 0, f"H the windowed retired key verifies: {rr2.stderr[:80]}")
    with open(os.path.join(home, "signers", "history.tsv"), "w") as f:
        f.write(f"{fp1}\t2020-01-01T00:00:00Z\t2020-01-02T00:00:00Z\n")
    rr3 = verb("verify", prog, env=env)
    check(rr3.returncode == 1, "H an expired window refuses")

    # G VOID shapes
    empty = tempfile.mkdtemp(prefix="rt.")
    check(verb("closure", empty, env=env).returncode == 2, "G empty program")
    check(verb("sign", prog, "--kind", "arm", env=env).returncode == 2, "G sign without a key")
    check(verb("verify", empty, env=env).returncode == 2, "G verify nothing")
    # H ID_RE traversal refusal on --row and newest() verified lookup
    r_trav = verb("sign", prog, "--kind", "row", "--row", "../escape", "--key", k2, env=env)
    check(r_trav.returncode == 1 and "must match" in (r_trav.stderr + r_trav.stdout),
          f"H --row traversal refused by ID_RE: {r_trav.stderr}")
    rs_k2 = verb("sign", prog, "--kind", "arm", "--key", k2, env=env)
    check(rs_k2.returncode == 0, f"H2 sign fresh arm with active k2: {rs_k2.stderr}")
    old_env_h = {ek: os.environ.get(ek) for ek in ("OPERATOR_HOME", "RULING_CORE_GIT")}
    os.environ["OPERATOR_HOME"] = env["OPERATOR_HOME"]
    os.environ["RULING_CORE_GIT"] = env["RULING_CORE_GIT"]
    try:
        nw_arm = newest(prog, "arm")
        nw_stage = newest(prog, "stage")
        check(nw_arm is not None and nw_arm[1].get("kind") == "arm" and nw_stage is None,
              f"H2 newest() returns verified arm and None for absent stage: {nw_arm is not None}/{nw_stage}")
    finally:
        for ek, ev in old_env_h.items():
            if ev is None:
                os.environ.pop(ek, None)
            else:
                os.environ[ek] = ev

    _shutil.rmtree(base, ignore_errors=True)
    _shutil.rmtree(empty, ignore_errors=True)
    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def main(argv):
    if len(argv) < 2 or argv[1] not in ("closure", "sign", "verify", "arm-hash", "show", "check", "approve"):
        die(USAGE, 2)
    verb = argv[1]
    if verb == "check":
        try:
            cmd_check()
        except Void as e:
            die(f"VOID, {e}", 2)
        return
    if len(argv) < 3:
        die(USAGE, 2)
    prog = argv[2]
    if not os.path.isdir(prog):
        die(f"no program directory {prog}", 2)
    try:
        if verb == "closure":
            cmd_closure(prog)
        elif verb in ("sign", "approve"):
            kind, row, key, run, not_after, waivers = "arm", None, None, None, None, []
            rest = argv[3:]
            i = 0
            while i < len(rest):
                if rest[i] == "--kind" and i + 1 < len(rest):
                    kind = rest[i + 1]
                    i += 2
                elif rest[i] == "--row" and i + 1 < len(rest):
                    row = rest[i + 1]
                    i += 2
                elif rest[i] == "--key" and i + 1 < len(rest):
                    key = rest[i + 1]
                    i += 2
                elif rest[i] == "--run" and i + 1 < len(rest):
                    run = rest[i + 1]
                    i += 2
                elif rest[i] == "--not-after" and i + 1 < len(rest):
                    not_after = rest[i + 1]
                    i += 2
                elif rest[i] == "--waive" and i + 1 < len(rest):
                    waivers.append(rest[i + 1])
                    i += 2
                else:
                    die(USAGE, 2)
            sign(prog, kind, row, key, run, not_after, waivers=waivers)
        elif verb == "verify":
            cmd_verify(prog, argv[3] if len(argv) > 3 else None)
        elif verb == "arm-hash":
            cmd_arm_hash(prog)
        elif verb == "show":
            cmd_show(prog, argv[3] if len(argv) > 3 else None)
    except Refused as e:
        die(str(e), 1)
    except Void as e:
        die(f"VOID, {e}", 2)
    except json.JSONDecodeError as e:
        die(f"a ruling doesn't parse: {e}", 2)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    main(sys.argv)
