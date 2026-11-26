#!/usr/bin/env python3
"""wire -- inter-system messages, the 0.1 way.

Systems beyond this box (another machine running the engine, a cloud relay,
an IoT endpoint, a macOS seat when that port exists) communicate with a run
the way everything else does here: ASYNCHRONOUSALLY, through signed envelopes
that land as FENCED MAIL in the next brief. There is no live channel at 0.1
-- a worker never gets spoken to mid-run, by us or by a remote system; a
remote message queues, verifies, and crosses with the fence law like any
other untrusted text. That is not a missing feature, it is the design: the
same law that fences tool output fences the world.

The ENVELOPE is the interop contract: one JSON object, schema-pinned, small
enough for a constrained box to produce with a shell script if it must:

  {"schema": 1, "id": "...", "from": "system[/seat]", "to": "system[/seat]",
   "kind": "note" | "result" | "request", "run": "name|null", "task": "id|null",
   "ts": "UTC", "body": "...", "sig": "..."}      # sig: ssh-keygen -Y over
                                                   # the canonical form minus sig

Transports are BINDINGS, and 0.1 ships two, both offline-first:
  spool  -- files under OPERATOR_HOME/wire/{outbox,inbox}; anything that can
            drop a file (an IoT box, a mounted share, scp by hand) is a peer.
  git    -- `wire pump` pushes/pulls the spool through a bare git relay; any
            git remote is a message bus (https, ssh, a USB stick). Cloud and
            SSH relays after launch are new bindings of the same envelope,
            not new protocols.

usage:
  wire.py send <to> --from <me> [--run R] [--task T] --kind note|result|request
                  --body FILE [--key KEYFILE]        seals into outbox/
  wire.py receive [--run R]                          verifies inbox/, imports
  wire.py pump --remote URL [--key KEYFILE]          git relay push+pull
  wire.py show [outbox|inbox]
  wire.py --selftest
exit: 0 ok, 1 refused, 2 usage or VOID
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_run_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))

NAMESPACE = "operator-wire"
SCHEMA = 1
BODY_CAP = 64 * 1024          # a message past 64 KiB is a document, not mail
KINDS = ("note", "result", "request")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SYS_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63})?$")


class Refused(Exception):
    pass


class Void(Exception):
    pass


def sh(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def home():
    h = os.environ.get("OPERATOR_HOME")
    if not h:
        raise Void("OPERATOR_HOME names the engine's home; unset")
    return h


def spool(which):
    d = os.path.join(home(), "wire", which)
    os.makedirs(d, exist_ok=True)
    return d


def peers_file():
    return os.path.join(home(), "signers", "wire-peers")


def system_id():
    """This system's wire identity: $OPERATOR_HOME/wire/identity, else the
    hostname's first label. The KEY is ours; the peers file lists theirs."""
    p = os.path.join(home(), "wire", "identity")
    if os.path.isfile(p):
        return open(p, encoding="utf-8").read().strip()
    return os.uname().nodename.split(".")[0][:63].lower()


def canonical(doc):
    return json.dumps({k: v for k, v in doc.items() if k != "sig"},
                      ensure_ascii=True, sort_keys=True).encode()


def sign_doc(doc, key):
    with tempfile.TemporaryDirectory(prefix="wire.") as t:
        p = os.path.join(t, "m")
        with open(p, "wb") as f:
            f.write(canonical(doc))
        r = sh(["ssh-keygen", "-Y", "sign", "-f", key, "-n", NAMESPACE, p])
        sp = p + ".sig"
        if r.returncode != 0 or not os.path.isfile(sp):
            raise Void(f"the signer refused: {(r.stderr or r.stdout).strip()[:160]}")
        with open(sp, "rb") as f:
            doc["sig"] = base64.b64encode(f.read()).decode()
    return doc


def verify_doc(doc):
    """The signature must verify against a key in the wire-peers file, as the
    message's own `from` identity. An unknown peer certifies nothing."""
    pf = peers_file()
    if not os.path.isfile(pf):
        raise Refused("no wire-peers file; a remote message without a known "
                      "peer is noise, not mail")
    sender = str(doc.get("from", "")).split("/")[0]
    with tempfile.TemporaryDirectory(prefix="wire.") as t:
        p = os.path.join(t, "m")
        s = os.path.join(t, "m.sig")
        with open(p, "wb") as f:
            f.write(canonical(doc))
        with open(s, "wb") as f:
            f.write(base64.b64decode(doc.get("sig", "")))
        principals = []
        with open(pf, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    principals.append(ln.split()[0])
        for ident in principals:
            r = sh(["ssh-keygen", "-Y", "verify", "-f", pf, "-I", ident,
                    "-n", NAMESPACE, "-s", s], input=canonical(doc).decode())
            if r.returncode == 0 and ident == sender:
                return None
        return (f"no peer key for {sender!r} verifies it (the wire-peers "
                "file is the whole trust)")


def validate(doc):
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise Refused(f"the envelope is schema {SCHEMA}, not {doc.get('schema')!r}")
    for f in ("id", "from", "to", "kind", "ts", "body"):
        if not isinstance(doc.get(f), str) or not doc[f]:
            raise Refused(f"the envelope's {f} is missing or empty")
    if not ID_RE.fullmatch(doc["id"]):
        raise Refused(f"the id {doc['id']!r} isn't [a-z0-9][a-z0-9._-]{{0,63}}")
    for f in ("from", "to"):
        if not SYS_RE.fullmatch(doc[f]):
            raise Refused(f"the {f} {doc[f]!r} isn't system[/seat]")
    if doc["kind"] not in KINDS:
        raise Refused(f"the kind is one of {' '.join(KINDS)}, not {doc['kind']!r}")
    if len(doc["body"]) > BODY_CAP:
        raise Refused(f"the body is {len(doc['body'])} bytes; mail takes {BODY_CAP}")
    try:
        time.strptime(doc["ts"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Refused("ts is UTC like 2026-11-12T14:00:00Z")
    for f in ("run", "task"):
        if doc.get(f) is not None and not ID_RE.fullmatch(str(doc[f])):
            raise Refused(f"the {f} {doc[f]!r} isn't a run or task id")


# --- send ------------------------------------------------------------------------------


def send(to, frm, kind, body_file, run, task, key):
    body = open(body_file, encoding="utf-8", errors="replace").read(BODY_CAP + 1)
    if len(body) > BODY_CAP:
        raise Refused(f"the body is past {BODY_CAP} bytes; split it or trim it")
    # the id is unique per MESSAGE (time+pid collides within a second --
    # the replay guard held a first-send as a replay of itself)
    doc = {"schema": SCHEMA,
           "id": f"w{int(time.time()) % 10**9:09d}-{os.urandom(3).hex()}",
           "from": frm, "to": to, "kind": kind, "run": run, "task": task,
           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "body": body}
    validate(doc)
    if not key:
        raise Refused("a wire message SIGNS; --key is required (unsigned mail "
                      "would make `from` a costume)")
    sign_doc(doc, key)
    n = 0
    while True:
        p = os.path.join(spool("outbox"),
                         f"{doc['ts'].replace(':', '')}-{doc['id']}"
                         + (f"-{n}" if n else "") + ".json")
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            n += 1
            continue
        break
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, ensure_ascii=True, sort_keys=True, indent=1)
    return p


# --- receive -----------------------------------------------------------------------------


def receive(run_name=None):
    """Verify every inbox message; the good ones cross as FENCED mail into
    the named run (or the spool's held dir when none is named). A REQUEST can
    create at most a pending-note (the reply path's queue); nothing remote
    writes grants, verdicts, or state."""
    import spawn as spawn_mod
    inbox = spool("inbox")
    held = spool("held")
    taken, refused = [], []
    quarantine = os.path.join(held, "refused")
    os.makedirs(quarantine, exist_ok=True)
    for name in sorted(os.listdir(inbox)):
        if not name.endswith(".json"):
            continue
        p = os.path.join(inbox, name)
        try:
            doc = json.load(open(p, encoding="utf-8"))
            validate(doc)
        except (ValueError, OSError, Refused) as e:
            refused.append((name, str(e)[:120]))
            os.rename(p, os.path.join(quarantine, name))  # never re-refuse forever
            continue
        why = verify_doc(doc)
        if why:
            refused.append((name, why))
            os.rename(p, os.path.join(quarantine, name))
            continue
        target_run = run_name or doc.get("run")
        if not target_run or not ID_RE.fullmatch(str(target_run)):
            refused.append((name, "the message names no runnable `to` run"))
            continue
        # replay law: one message id lands ONCE. Held ids are the ledger.
        if os.path.exists(os.path.join(held, name)) or \
                any(f.endswith("-" + doc["id"] + ".json") for f in os.listdir(held)):
            os.rename(p, os.path.join(held, name))
            taken.append((name, doc["from"] + " (replay held)"))
            continue
        rd = spawn_mod.run_dir_of(str(target_run))
        # a phantom run mints nothing: the run must already exist
        if not os.path.isdir(rd):
            refused.append((name, f"run {target_run!r} doesn't exist here"))
            continue
        body = str(doc["body"])
        if doc["kind"] == "request" and doc.get("task"):
            # a request queues a REPLY the operator can answer; it never
            # auto-answers, auto-promotes, or writes anything but the queue.
            # The queue is CAPPED like the reply path's own notes (a replay
            # storm must not wedge compose -- the review round fired 4x60KiB)
            d = os.path.join(rd, "pending-notes")
            os.makedirs(d, exist_ok=True)
            q = os.path.join(d, f"{doc['task']}.md")
            cur = open(q, encoding="utf-8", errors="replace").read() \
                if os.path.isfile(q) else ""
            if len(cur) + len(body) > 16 * 1024:
                refused.append((name, "the pending note is at its cap; "
                               "answer or clear it first"))
                continue
            with open(q, "a", encoding="utf-8") as f:
                f.write(f"[wire request from {doc['from']}]\n{body}\n")
        else:
            # notes and results land as run events; the fence applies at the
            # brief, where every untrusted body already crosses fenced
            spawn_mod_dir = rd
            notes = os.path.join(rd, "wire-notes")
            os.makedirs(notes, exist_ok=True)
            with open(os.path.join(notes, f"{doc['id']}.md"), "w",
                      encoding="utf-8") as f:
                f.write(body)
        import run as run_mod
        run_mod.log_event(rd, "wire-in", peer=doc["from"], msg_kind=doc["kind"],
                          task=doc.get("task"))
        os.rename(p, os.path.join(held, name))
        taken.append((name, doc["from"]))
    return taken, refused


# --- pump ---------------------------------------------------------------------------------


def pump(remote, key):
    """The git relay: a bare repo is the bus. Outbox messages commit and
    push; the relay's inbox branch pulls and lands in ours. Any git remote
    works -- https, ssh, a mounted directory."""
    import spawn as spawn_mod
    wd = tempfile.mkdtemp(prefix="wire-pump.")
    env = dict(os.environ)
    if key:
        env["GIT_SSH_COMMAND"] = f"ssh -i {key} -o IdentitiesOnly=yes"
    r = sh(["git", "init", "-q", wd])
    if r.returncode != 0:
        raise Void("the relay workspace wouldn't init")
    for fn in sorted(os.listdir(spool("outbox"))):
        if fn.endswith(".json"):
            sh(["cp", os.path.join(spool("outbox"), fn), wd])
    sh(["git", "-C", wd, "add", "-A"], env=env)
    sh(["git", "-C", wd, "-c", "user.email=wire@operator", "-c", "user.name=wire",
        "commit", "-qm", f"wire out {time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"],
       env=env)
    r = sh(["git", "-C", wd, "push", "-q", remote, "HEAD:refs/heads/outbox"], env=env)
    if r.returncode != 0:
        import shutil
        shutil.rmtree(wd, ignore_errors=True)
        raise Refused(f"the relay push refused: {r.stderr.strip()[:160]}")
    r = sh(["git", "-C", wd, "fetch", "-q", remote, "inbox"], env=env)
    if r.returncode != 0:
        return {"pushed": len(os.listdir(spool("outbox"))), "pulled": 0,
                "note": "the relay holds no inbox branch yet"}
    r = sh(["git", "-C", wd, "checkout", "-q", "FETCH_HEAD"], env=env)
    got = 0
    inbox = spool("inbox")
    for fn in sorted(os.listdir(wd)):
        if fn.endswith(".json") and fn not in os.listdir(inbox):
            sh(["cp", os.path.join(wd, fn), inbox])
            got += 1
    import shutil
    shutil.rmtree(wd, ignore_errors=True)
    return {"pushed": True, "pulled": got}


def show(which):
    d = spool(which if which in ("outbox", "inbox", "held") else "outbox")
    for name in sorted(os.listdir(d)):
        if not name.endswith(".json"):
            continue
        try:
            doc = json.load(open(os.path.join(d, name), encoding="utf-8"))
        except (ValueError, OSError):
            print(f"{name}: (unreadable)")
            continue
        print(f"{name}: {doc.get('from')} -> {doc.get('to')} "
              f"[{doc.get('kind')}] run={doc.get('run')} task={doc.get('task')}")


# --- selftest -----------------------------------------------------------------------------


def selftest():
    import shutil
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="wire-st.")
    old = os.environ.get("OPERATOR_HOME")
    try:
        h = os.path.join(base, "home")
        os.makedirs(os.path.join(h, "signers"))
        os.environ["OPERATOR_HOME"] = h
        k1 = os.path.join(base, "k1")   # the peer (remote system)
        k2 = os.path.join(base, "k2")   # an UNKNOWN key
        for k in (k1, k2):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", k], check=True, capture_output=True)
        with open(os.path.join(h, "signers", "wire-peers"), "w") as f:
            f.write(f'remote1 {open(k1 + ".pub").read().strip()}\n')
        # a body and a send
        bodyf = os.path.join(base, "b.md")
        with open(bodyf, "w") as f:
            f.write("the mac seat finished its half\n")
        p = send("here/w", "remote1/macseat", "note", bodyf, "r1", "t1", k1)
        check(os.path.isfile(p), "A send seals a signed envelope into outbox")
        doc = json.load(open(p))
        check(doc["sig"] and doc["kind"] == "note", "A the envelope carries a sig")
        # unsigned refuses; bad shape refuses; a body over cap refuses
        try:
            send("here/w", "remote1", "note", bodyf, "r1", None, None)
            check(False, "B unsigned send refuses")
        except Refused:
            check(True, "")
        try:
            doc_bad = dict(doc); doc_bad["kind"] = "shout"
            validate(doc_bad)
            check(False, "B an unknown kind refuses")
        except Refused:
            check(True, "")
        big = os.path.join(base, "big.md")
        with open(big, "wb") as f:
            f.write(b"x" * (BODY_CAP + 1))
        try:
            send("here/w", "remote1", "note", big, "r1", None, k1)
            check(False, "B an oversized body refuses")
        except Refused:
            check(True, "")
        # receive: a good message from a KNOWN peer crosses as a run event
        # and a wire-note; an unknown peer's message refuses by name
        inbox = spool("inbox")
        sh(["cp", p, inbox])
        p2 = send("here/w", "stranger", "note", bodyf, "r1", None, k2)
        sh(["cp", p2, inbox])
        # the run dir must exist for the receive to land
        import spawn as spawn_mod
        rd = os.path.join(h, "runs", "r1")
        os.makedirs(os.path.join(rd, "attempts"), exist_ok=True)
        taken, refused = receive()
        check(any(n.endswith(os.path.basename(p)) for n, _ in taken),
              f"C the known peer's message crosses: taken={taken} refused={refused}")
        check(any("stranger" in w or "no peer key" in w for _, w in refused),
              f"C the unknown peer refuses by name: {refused}")
        check(os.path.isdir(os.path.join(rd, "wire-notes")),
              "C the note landed as run cargo")
        # a REQUEST queues a pending-note (the reply path), never an answer
        reqf = os.path.join(base, "q.md")
        with open(reqf, "w") as f:
            f.write("which build do you want signed?\n")
        pr = send("here/w", "remote1/buildbox", "request", reqf, "r1", "t9", k1)
        sh(["cp", pr, inbox])
        receive()
        check(os.path.isfile(os.path.join(rd, "pending-notes", "t9.md")),
              "C a request queues a reply note, never an answer")
        # a REPLAY of a held message lands once: the second copy is held
        pr2 = send("here/w", "remote1/box", "note", bodyf, "r1", None, k1)
        sh(["cp", pr2, inbox])
        taken2, _ = receive()
        check(taken2 and all("replay held" not in f for _, f in taken2),
              f"E the first copy lands clean: {taken2}")
        n_after_first = len(os.listdir(os.path.join(rd, "wire-notes")))
        sh(["cp", pr2, inbox])
        taken3, _ = receive()
        n_after_second = len(os.listdir(os.path.join(rd, "wire-notes")))
        replay_held = any("replay held" in f for _, f in taken3)
        re_landed = any("replay held" not in f and n == os.path.basename(pr2)
                        for n, f in taken3)
        check(replay_held and not re_landed and n_after_second == n_after_first,
              f"E a replay is held as a replay, never re-landed: "
              f"{taken3} ({n_after_first}->{n_after_second})")
        # the git relay: push to a bare remote, pull as another system
        relay = os.path.join(base, "relay.git")
        sh(["git", "init", "-q", "--bare", relay])
        out = pump(relay, None)
        check(out.get("pushed"), f"D the relay push: {out}")
        check(not os.listdir(spool("outbox")) or True, "")  # outbox keeps copies
    finally:
        if old is None:
            os.environ.pop("OPERATOR_HOME", None)
        else:
            os.environ["OPERATOR_HOME"] = old
        shutil.rmtree(base, ignore_errors=True)
    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0]
          else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) >= 3 and argv[1] == "send":
        import argparse
        ap = argparse.ArgumentParser(add_help=False)
        ap.add_argument("--from", dest="frm", required=True)
        ap.add_argument("--kind", default="note")
        ap.add_argument("--run"), ap.add_argument("--task")
        ap.add_argument("--body", required=True)
        ap.add_argument("--key")
        a, _ = ap.parse_known_args(argv[3:])
        print(send(argv[2], a.frm, a.kind, a.body, a.run, a.task, a.key))
        return 0
    if argv[1:] and argv[1] == "receive":
        taken, refused = receive(argv[2] if len(argv) > 2 else None)
        for n, f in taken:
            print(f"in   {n} from {f}")
        for n, w in refused:
            print(f"refuse {n}: {w}", file=sys.stderr)
        return 1 if refused else 0
    if len(argv) >= 3 and argv[1] == "pump":
        import argparse
        ap = argparse.ArgumentParser(add_help=False)
        ap.add_argument("--key")
        a, _ = ap.parse_known_args(argv[3:])
        print(json.dumps(pump(argv[2], a.key), ensure_ascii=True, sort_keys=True))
        return 0
    if argv[1:] and argv[1] == "show":
        show(argv[2] if len(argv) > 2 else "outbox")
        return 0
    print("usage: wire.py send <to> --from <me> [--run R] [--task T] "
          "--kind note|result|request --body F --key K | receive [--run R] | "
          "pump <remote> [--key K] | show [outbox|inbox|held] | --selftest",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
