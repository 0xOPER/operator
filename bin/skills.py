#!/usr/bin/env python3
"""skills -- the catalog: what a program's skills are, hash-bound.

The ruling already closes over the program tree, so the skills it ships are
content-pinned the moment the arm ruling signs. This tool LISTS them with
their hashes (the catalog a worker reports against), and verifies a copy
still matches -- `skills verify` recomputes and refuses on drift. Skills
land in attempts by spawn's copy (regular files only, one shared cap);
nothing here executes a skill or reads one into the engine's trust.

usage:
  skills.py catalog <program-dir> [--seat S]     name, SKILL.md path, sha256
  skills.py verify <program-dir> [--seat S]      rc 1 on any drift
  skills.py --selftest
exit: 0 ok/verified, 1 drift or refusal, 2 usage or VOID
"""
import hashlib
import os
import re
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))

PATH_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")


class Refused(Exception):
    pass


class Void(Exception):
    pass


def _seat_skills(prog, seat=None):
    import spawn as spawn_mod
    doc, seats, _ = spawn_mod.load_team(prog)
    if seat is not None and seat not in seats:
        raise Refused(f"seat {seat!r} isn't on the team")
    out = {}
    for sname, sdoc in seats.items():
        if seat is not None and sname != seat:
            continue
        for sk in (sdoc.get("skills") or []):
            if not PATH_OK.fullmatch(sk) or ".." in sk.split("/") or sk.startswith("/"):
                raise Refused(f"seat {sname}: skill {sk!r} isn't a program-relative path")
            d = os.path.join(prog, sk)
            # the skill ROOT itself may not be a link: the walk only sees what
            # it walks INTO, and a root link hashes and copies whatever the
            # target holds at that moment (the review fired it end to end)
            if os.path.islink(d):
                raise Refused(f"seat {sname}: skill {sk!r} is itself a link; "
                              "skills ship files")
            # a vanished dir records None: catalog refuses it, drift names it
            out[(sname, sk)] = d if os.path.isdir(d) else None
    return out


def _hash_dir(d):
    """Deterministic hash of a skill dir: every file, sorted by name."""
    h = hashlib.sha256()
    files = []
    for dirpath, dirnames, names in os.walk(d):
        for n in names:
            p = os.path.join(dirpath, n)
            st = os.lstat(p)
            import stat as _st
            if not _st.S_ISREG(st.st_mode):
                raise Refused(f"{p} isn't a regular file; skills are files "
                              "(a FIFO or device hangs or swallows the hash)")
            files.append((os.path.relpath(p, d), p, st.st_size))
    total = 0
    for rel, p, size in sorted(files):
        total += size
        if total > 4 * 1024 * 1024:
            raise Refused(f"the skills past 4 MiB total; link documents, "
                          "don't ship them")
        h.update(rel.encode())
        with open(p, "rb") as f:
            while True:
                chunk = f.read(1 << 16)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest()[:16], len(files)


def catalog(prog, seat=None):
    rows = []
    for (sname, sk), d in sorted(_seat_skills(prog, seat).items()):
        if d is None:
            raise Refused(f"seat {sname}: skill {sk!r} doesn't exist")
        sha, n = _hash_dir(d)
        m = os.path.join(d, "SKILL.md")
        if not os.path.isfile(m):
            raise Refused(f"seat {sname}: skill {sk} carries no SKILL.md")
        rows.append({"seat": sname, "skill": sk, "files": n, "sha": sha})
    return rows


def verify(prog, seat=None):
    """Drift check: the catalog recomputes; the caller compares against the
    ruling's recorded catalog (stored beside the ruling by `record`)."""
    return catalog(prog, seat)


def record(prog, ruling_id=None):
    """Write the catalog as a baseline, bound to the ruling that signs it
    when one is named: the filename carries the ruling id, and a pre-placed
    file at the predicted name must hold the SAME bytes or the record
    refuses (a lying baseline is the attack, not the accident)."""
    rows = catalog(prog)
    import json
    body = json.dumps(rows, ensure_ascii=True, sort_keys=True, indent=1)
    h = hashlib.sha256(body.encode()).hexdigest()[:16]
    tag = f"{ruling_id}-" if ruling_id else ""
    p = os.path.join(prog, f"skills-catalog-{tag}{h}.json")
    if os.path.exists(p):
        if open(p, encoding="utf-8").read() == body + "\n":
            return p
        raise Refused(f"a baseline sits at {os.path.basename(p)} holding "
                      "different bytes; baselines don't lie twice")
    with open(p, "w", encoding="utf-8") as f:
        f.write(body + "\n")
    return p


def _recorded(prog):
    """The ruling-BOUND baseline wins (a ruling id in the name is the claim);
    with none bound, a bare hash-named baseline serves -- but only ONE may
    exist, or the choice itself is drift nobody ruled."""
    import json
    bound = [n for n in sorted(os.listdir(prog))
             if re.fullmatch(r"skills-catalog-.+?-[0-9a-f]{16}\.json", n)]
    bare = [n for n in sorted(os.listdir(prog))
            if re.fullmatch(r"skills-catalog-[0-9a-f]{16}\.json", n)]
    if bound:
        name = bound[-1]
    elif len(bare) == 1:
        name = bare[0]
    elif len(bare) > 1:
        raise Refused("multiple unbound baselines exist; record with the "
                      "ruling's id so the choice is ruled, not lexicographic")
    else:
        return None
    return json.load(open(os.path.join(prog, name), encoding="utf-8")), name


def check_drift(prog):
    base, name = _recorded(prog) or (None, None)
    import spawn as _sp
    try:
        now = catalog(prog)  # also loads the team; both refuse on a vanished dir
    except (Refused, _sp.Refused):
        # a vanished dir refuses the walk -- even the team loader's own check;
        # the drift names it from the baseline
        if base is None:
            raise
        now = None
    if base is None:
        return None, now  # no baseline: verification is the ruling's closure
    if now == base:
        return None, now
    # name the drift honestly
    base_keys = {(r["seat"], r["skill"]): r for r in base}
    now_keys = {(r["seat"], r["skill"]): r for r in (now or [])}
    drift = []
    for k in sorted(set(base_keys) | set(now_keys)):
        if k not in now_keys:
            drift.append(f"{k[0]}/{k[1]} vanished")
        elif k not in base_keys:
            drift.append(f"{k[0]}/{k[1]} appeared")
        elif base_keys[k]["sha"] != now_keys[k]["sha"]:
            drift.append(f"{k[0]}/{k[1]} content drifted "
                         f"({base_keys[k]['sha']} -> {now_keys[k]['sha']})")
    return drift, now


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

    base = tempfile.mkdtemp(prefix="sk-st.")
    old = os.environ.get("OPERATOR_HOME")
    try:
        home = os.path.join(base, "home")
        os.makedirs(home)
        os.environ["OPERATOR_HOME"] = home
        prog = os.path.join(base, "prog")
        os.makedirs(os.path.join(prog, "roles"))
        os.makedirs(os.path.join(prog, "skills", "alpha"))
        with open(os.path.join(prog, "skills", "alpha", "SKILL.md"), "w") as f:
            f.write("---\nname: alpha\ndescription: test\n---\nbody\n")
        with open(os.path.join(prog, "roles", "w.md"), "w") as f:
            f.write("r\n")
        with open(os.path.join(prog, "contract.toml"), "w") as f:
            f.write('schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\n'
                    'kind = "run"\nseat = "w"\nreviewer = "r"\ncmd = "true"\n')
        with open(os.path.join(prog, "team.toml"), "w") as f:
            f.write('schema = 1\nname = "t"\nmax_parallel = 1\n[seat.w]\n'
                    'role = "roles/w.md"\nadapter = "stub"\n'
                    'skills = ["skills/alpha"]\n')
        rows = catalog(prog)
        check(len(rows) == 1 and rows[0]["skill"] == "skills/alpha"
              and rows[0]["sha"], f"A the catalog lists hash-bound: {rows}")
        # the baseline records, and clean verifies
        p = record(prog, None)
        check(os.path.isfile(p), "B the baseline records")
        drift, _ = check_drift(prog)
        check(drift is None, f"B a clean tree verifies: {drift}")
        # content drift names itself; a vanished skill names itself; an
        # appeared skill names itself
        with open(os.path.join(prog, "skills", "alpha", "SKILL.md"), "a") as f:
            f.write("edited\n")
        drift, _ = check_drift(prog)
        check(drift and any("drifted" in d for d in drift),
              f"C content drift names itself: {drift}")
        # re-record after the edit (bound to a ruling id), then vanish
        record(prog, "r00002")
        # a pre-placed baseline under the name record WILL predict, holding
        # other bytes, refuses (a lying baseline is the attack)
        import json as _json, hashlib as _hl
        _body = _json.dumps(catalog(prog), ensure_ascii=True, sort_keys=True,
                            indent=1)
        _h = _hl.sha256(_body.encode()).hexdigest()[:16]
        ghost = os.path.join(prog, f"skills-catalog-r00003-{_h}.json")
        with open(ghost, "w") as f:
            f.write(_body.replace('"files"', '"lies"') + "\n")
        try:
            record(prog, "r00003")
            check(False, "C a lying pre-placed baseline refuses")
        except Refused:
            check(True, "")
        os.unlink(ghost)
        shutil.rmtree(os.path.join(prog, "skills", "alpha"))
        drift, _ = check_drift(prog)
        check(drift and any("vanished" in d for d in drift),
              f"C a vanished skill names itself: {drift}")
        # restore + a NEW unlisted skill appears
        os.makedirs(os.path.join(prog, "skills", "alpha"))
        with open(os.path.join(prog, "skills", "alpha", "SKILL.md"), "w") as f:
            f.write("---\nname: alpha\ndescription: test\n---\nbody\n")
        os.makedirs(os.path.join(prog, "skills", "ghost"))
        with open(os.path.join(prog, "skills", "ghost", "SKILL.md"), "w") as f:
            f.write("x\n")
        tm = open(os.path.join(prog, "team.toml")).read()
        open(os.path.join(prog, "team.toml"), "w").write(
            tm.replace('skills = ["skills/alpha"]',
                       'skills = ["skills/alpha", "skills/ghost"]'))
        drift, _ = check_drift(prog)
        check(drift and any("appeared" in d for d in drift),
              f"C an appeared skill names itself: {drift}")
        # a skill ROOT that is a symlink refuses: the walk only rejects
        # links it walks INTO, and a root link's bytes are the target's
        # at hash and copy time (the review round shipped the payload)
        # ghost's SKILL.md was just deleted; restore it so the catalog
        # reaches the rootlink check (else ghost's missing file refuses
        # first and the arm proves nothing)
        os.makedirs(os.path.join(prog, "skills", "ghost"), exist_ok=True)
        with open(os.path.join(prog, "skills", "ghost", "SKILL.md"), "w") as f:
            f.write("g\n")
        _rl_target = os.path.join(base, "rl-target")
        os.makedirs(_rl_target, exist_ok=True)
        with open(os.path.join(_rl_target, "SKILL.md"), "w") as f:
            f.write("---\nname: rl\ndescription: d\n---\npayload\n")
        os.symlink(_rl_target, os.path.join(prog, "skills", "rootlink"))
        tm2 = open(os.path.join(prog, "team.toml")).read()
        _pair = (('skills = ["skills/alpha", "skills/ghost"]',
                  'skills = ["skills/alpha", "skills/ghost", "skills/rootlink"]')
                 if 'skills/ghost' in tm2 else
                 ('skills = ["skills/alpha"]',
                  'skills = ["skills/alpha", "skills/rootlink"]'))
        open(os.path.join(prog, "team.toml"), "w").write(tm2.replace(*_pair))
        try:
            catalog(prog)
            check(False, "D a root-link skill refuses the catalog")
        except Refused:
            check(True, "")
        open(os.path.join(prog, "team.toml"), "w").write(tm2)
        os.unlink(os.path.join(prog, "skills", "rootlink"))
        os.unlink(os.path.join(prog, "skills", "ghost", "SKILL.md"))
        try:
            catalog(prog)
            check(False, "D a skillless dir refuses")
        except Refused:
            check(True, "")
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
    if len(argv) >= 3 and argv[1] == "catalog":
        import json
        for r in catalog(argv[2], None if len(argv) < 5 or argv[3] != "--seat"
                         else argv[4]):
            print(json.dumps(r, ensure_ascii=True, sort_keys=True))
        return 0
    if len(argv) >= 3 and argv[1] == "verify":
        drift, now = check_drift(argv[2])
        if drift is None:
            print(f"verify: {len(now)} skill(s), no baseline -- the ruling's "
                  "closure is the pin")
            return 0
        if not drift:
            print(f"verify: {len(now)} skill(s), catalog holds")
            return 0
        for d in drift:
            print(f"drift: {d}", file=sys.stderr)
        return 1
    if len(argv) >= 3 and argv[1] == "record":
        print(record(argv[2], None))
        return 0
    print("usage: skills.py catalog <prog> [--seat S] | verify <prog> | "
          "record <prog> | --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
