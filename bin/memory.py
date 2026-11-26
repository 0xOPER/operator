#!/usr/bin/env python3
"""memory -- the engine's attributed, append-only note store.

Two scopes, one law per scope: a note is either SELF (a seat wrote it, only
that seat's later attempts read it) or TEAM (an owner or reviewer promoted
it, every seat reads it). Writers are the engine and the owner -- never a
worker: a worker's report can SUGGEST a note, and the suggestion rides the
collected report for a human to promote, because a note that lands in the
NEXT brief is prompt-adjacent, and prompt-adjacent text is a trust decision.

The store is sqlite with PRAGMA user_version (schema 1) and the FIRST-create
race closed (the audit row: open with O_CREAT under an exclusive lock, and a 0-byte
db is a NAMED error, not an empty read). Reads never create. Every row is
attributed: who, when, scope, and the content hash. Appends only -- no
UPDATE, no DELETE through this tool; a wrong note is superseded, not edited.

Snapshot in the brief: compose rides `memory.snapshot()` -- the LAST N notes
per scope, fenced like all untrusted-adjacent text, hash-recorded in the
brief's header so the ruling closes over what the seats will read.

usage:
  memory.py init                                    create the store (0600)
  memory.py add --seat <s> --scope self|team --note FILE [--by <who>]
  memory.py promote --id N --by <who>               self -> team
  memory.py snapshot [--seat S] [--last N]          the fenced brief block
  memory.py show [--seat S] [--last N]
  memory.py --selftest
exit: 0 ok, 1 refused, 2 usage or VOID
"""
import hashlib
import json
import os
import sqlite3
import sys
import time

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))

SCHEMA_VERSION = 1
NOTE_CAP = 8 * 1024            # a note past 8 KiB is a document; link it
SNAPSHOT_LAST = 12
ID_RE_STRICT = None  # set below (import lazily to keep the module standalone)


class Refused(Exception):
    pass


class Void(Exception):
    pass


def home():
    h = os.environ.get("OPERATOR_HOME")
    if not h:
        raise Void("OPERATOR_HOME names the engine's home; unset")
    return h


def db_path():
    return os.path.join(home(), "memory.db")


def _connect(create=False):
    p = db_path()
    if not create and not os.path.isfile(p):
        raise Void(f"no memory store at {p}; reads never create one -- init does")
    if create:
        # the first-create race row: create exclusively, then open
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    con = sqlite3.connect(p)
    cur = con.execute("PRAGMA user_version").fetchone()
    v = cur[0] if cur else 0
    if v == 0 and create:
        con.executescript(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, "
            "by TEXT NOT NULL, seat TEXT NOT NULL, scope TEXT NOT NULL "
            "CHECK (scope in ('self','team')), body TEXT NOT NULL, "
            "sha TEXT NOT NULL, prog TEXT NOT NULL DEFAULT '', "
            "promoted_by TEXT);")
        con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        con.commit()
    elif v != SCHEMA_VERSION:
        con.close()
        raise Void(f"the store is schema {v}, this tool is {SCHEMA_VERSION}; "
                   "a migration is a ruling, not a silent rewrite")
    return con


def init():
    if os.path.exists(db_path()):
        raise Refused(f"a store already exists at {db_path()}")
    con = _connect(create=True)
    con.close()
    return db_path()


def _check_seat(seat):
    import re
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", seat or ""):
        raise Refused(f"seat {seat!r} isn't [a-z0-9][a-z0-9._-]{{0,63}}")


def _prog():
    """The store is scoped by program: a team note is prompt-adjacent in the
    NEXT brief, and a note written under one program's trust must not ride
    another program's seats (the review crossed them live)."""
    return os.environ.get("OPERATOR_PROG_ID", "")


def add(seat, scope, note_file, by):
    _check_seat(seat)
    if scope not in ("self", "team"):
        raise Refused("scope is self or team")
    if scope == "team" and by is None:
        raise Refused("a TEAM note names who promoted it (--by); team scope "
                      "is a trust decision, never anonymous")
    body = open(note_file, encoding="utf-8", errors="replace").read(NOTE_CAP + 1)
    if len(body) > NOTE_CAP:
        raise Refused(f"the note is past {NOTE_CAP} bytes; link the document, "
                      "don't mail the book")
    con = _connect()
    try:
        con.execute(
            "INSERT INTO notes (ts, by, seat, scope, body, sha, prog) "
            "VALUES (?,?,?,?,?,?,?)",
            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), by or seat,
             seat, scope, body,
             hashlib.sha256(body.encode()).hexdigest()[:16], _prog()))
        con.commit()
        n = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        return n
    finally:
        con.close()


def promote(note_id, by):
    if not by:
        raise Refused("a promotion names its promoter (--by)")
    con = _connect()
    try:
        cur = con.execute("SELECT scope FROM notes WHERE id=?", (note_id,)).fetchone()
        if cur is None:
            raise Refused(f"no note {note_id}")
        if cur[0] == "team":
            raise Refused(f"note {note_id} is already team scope")
        con.execute("UPDATE notes SET scope='team', promoted_by=? WHERE id=?",
                    (by, note_id))  # authorship stays; promotion is named apart
        con.commit()
        return note_id
    finally:
        con.close()


def _rows(seat=None, last=SNAPSHOT_LAST, scope=None):
    con = _connect()
    try:
        q = "SELECT id, ts, by, seat, scope, body, sha FROM notes"
        cond, args = ["prog=?"], [_prog()]  # the program's notes, no other's
        if scope:
            cond.append("scope=?"); args.append(scope)
        if seat:
            cond.append("seat=?"); args.append(seat)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY id DESC LIMIT ?"; args.append(int(last))
        return list(reversed(con.execute(q, args).fetchall()))
    finally:
        con.close()


def snapshot(seat=None, last=SNAPSHOT_LAST):
    """The brief's memory block: the seat's self notes and the team notes,
    fenced as one span, the newest last. Returns the text (or '')."""
    import spawn as spawn_mod
    rows = _rows(seat=seat, last=last, scope="self") if seat else []
    rows += _rows(last=last, scope="team")
    if not rows:
        return ""
    body = "\n".join(f"[{r[4]} {r[3]} {r[1]} #{r[0]}] {r[5]}" for r in rows)
    return f'<span-untrusted source="memory">{spawn_mod.fence_foreign(body)}</span-untrusted>'


def show(seat=None, last=SNAPSHOT_LAST):
    for r in _rows(seat=seat, last=last):
        print(json.dumps({"id": r[0], "ts": r[1], "by": r[2], "seat": r[3],
                          "scope": r[4], "sha": r[6],
                          "body": r[5][:120] + ("..." if len(r[5]) > 120 else "")},
                         ensure_ascii=True, sort_keys=True))


# --- selftest -----------------------------------------------------------------------------


def selftest():
    import shutil
    import tempfile
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="mem-st.")
    old = os.environ.get("OPERATOR_HOME")
    try:
        os.environ["OPERATOR_HOME"] = base
        # reads never create; a 0-byte db is a named error
        try:
            _connect()
            check(False, "A a read with no store refuses")
        except Void:
            check(True, "")
        check(not os.path.exists(db_path()), "A the read created no file")
        p = init()
        check(os.path.isfile(p) and (os.stat(p).st_mode & 0o777) == 0o600,
              "B init creates a 0600 store")
        try:
            init()
            check(False, "B a second init refuses")
        except Refused:
            check(True, "")
        # a 0-byte db is a NAMED error
        os.unlink(p)
        open(p, "wb").close()
        try:
            _connect()
            check(False, "B a 0-byte db names itself")
        except Void as e:
            check("schema" in str(e) or "user_version" in str(e),
                  f"B the 0-byte shape names a schema error: {e}")
        os.unlink(p)
        init()
        nf = os.path.join(base, "n.md")
        with open(nf, "w") as f:
            f.write("the flaky test needs TERM not KILL\n")
        n1 = add("w", "self", nf, None)
        check(n1 == 1, "C a self note lands attributed")
        # a TEAM note without --by refuses; with --by lands
        try:
            add("w", "team", nf, None)
            check(False, "C an anonymous team note refuses")
        except Refused:
            check(True, "")
        n2 = add("owner", "team", nf, "owner@key")
        check(n2 == 2, "C a promoted team note lands")
        # caps: an oversized note refuses
        big = os.path.join(base, "big.md")
        with open(big, "wb") as f:
            f.write(b"x" * (NOTE_CAP + 1))
        try:
            add("w", "self", big, None)
            check(False, "C an oversized note refuses")
        except Refused:
            check(True, "")
        # promote: self -> team names its promoter; team -> team refuses
        promote(n1, "owner@key")
        rows = {r[0]: r for r in _rows()}
        check(rows[1][4] == "team" and rows[1][2] == "w",
              "D promotion keeps the author's attribution")
        # the program scope: a note written under another program's id never
        # rides this one's snapshot (the review crossed them live)
        other = os.path.join(base, "other.md")
        with open(other, "w") as f:
            f.write("other-prog-marker-3e9\n")
        os.environ["OPERATOR_PROG_ID"] = "other-prog"
        try:
            add("w", "team", other, "someone-else@k")
        finally:
            os.environ.pop("OPERATOR_PROG_ID", None)
        check("other-prog-marker-3e9" not in snapshot("w"),
              "D another program's notes never ride this brief")
        os.environ["OPERATOR_PROG_ID"] = "other-prog"
        own_snap = snapshot("w")
        os.environ.pop("OPERATOR_PROG_ID", None)
        check("other-prog-marker-3e9" in own_snap,
              "D the note rides its OWN program's snapshot")
        try:
            promote(n2, "owner@key")
            check(False, "D re-promoting team refuses")
        except Refused:
            check(True, "")
        # snapshot: fenced, newest last, both scopes for the seat
        snap = snapshot("w", 10)
        check("span-untrusted" in snap and "flaky test" in snap and "#2" in snap,
              f"E the snapshot fences and carries the notes: {snap[:80]!r}")
        # another seat: team notes yes, ANOTHER seat's self notes no
        with open(nf, "w") as f:
            f.write("seat-w private scratch\n")
        n3 = add("w", "self", nf, None)
        snap2 = snapshot("r", 10)
        check("flaky test" in snap2 and "seat-w private scratch" not in snap2,
              "E another seat sees team notes, never another seat's self notes")
        check("seat-w private scratch" in snapshot("w", 10),
              "E the seat's own self notes ride its own snapshot")
        # append-only: no update/delete verbs exist to call
        _src = open(__file__).read()
        _needles = ("def " + "delete", "SET " + "body", "DELETE " + "FROM notes")
        check(not any(n in _src for n in _needles),
              "F the store exposes no delete or edit path")
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
    if argv[1:] == ["init"]:
        print(init())
        return 0
    if argv[1:] and argv[1] == "add":
        import argparse
        ap = argparse.ArgumentParser(add_help=False)
        ap.add_argument("--seat", required=True)
        ap.add_argument("--scope", required=True)
        ap.add_argument("--note", required=True)
        ap.add_argument("--by")
        a, _ = ap.parse_known_args(argv[2:])
        print(add(a.seat, a.scope, a.note, vars(a)["by"]))
        return 0
    if argv[1:] and argv[1] == "promote":
        import argparse
        ap = argparse.ArgumentParser(add_help=False)
        ap.add_argument("--id", type=int, required=True)
        ap.add_argument("--by", required=True)
        a, _ = ap.parse_known_args(argv[2:])
        promote(vars(a)["id"], vars(a)["by"])
        print("promoted note %s to team by %s" % (vars(a)["id"], vars(a)["by"]))
        return 0
    if argv[1:] and argv[1] == "snapshot":
        import argparse
        ap = argparse.ArgumentParser(add_help=False)
        ap.add_argument("--seat"), ap.add_argument("--last", type=int)
        a, _ = ap.parse_known_args(argv[2:])
        t = snapshot(a.seat, a.last or SNAPSHOT_LAST)
        if t:
            print(t)
        return 0
    if argv[1:] and argv[1] == "show":
        import argparse
        ap = argparse.ArgumentParser(add_help=False)
        ap.add_argument("--seat"), ap.add_argument("--last", type=int)
        a, _ = ap.parse_known_args(argv[2:])
        show(a.seat, a.last or SNAPSHOT_LAST)
        return 0
    print("usage: memory.py init | add --seat S --scope self|team --note F "
          "[--by W] | promote --id N --by W | snapshot [--seat S] [--last N] | "
          "show [--seat S] | --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
