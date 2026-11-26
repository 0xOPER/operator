#!/usr/bin/env python3
"""rules -- what may I do right now: one screen per seat, from the ruled team.

The grants a seat carries, the waivers the team owes, the autonomy it runs
under -- read from team.py's loaded state, never from persona text (authority
lives in the ruled manifest alone). The human screen is one line per seat with
the detail behind --json; every refusal names its fix.

usage: rules.py <program-dir> [--seat S] [--json]
exit: 0 printed, 1 refused, 2 usage or VOID
"""
import json
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
sys.path.insert(0, os.path.join(ROOT, "bin", "lib"))
import spawn as spawn_mod  # noqa: E402

JSON_SCHEMA = 1


def _waivers_of(prog):
    import team as team_mod
    doc, seats, contract = spawn_mod.load_team(prog)
    rows = contract[0]
    out = []
    if any(r.get("reviewer") is None for r in rows):
        out.append("unreviewed-rows")
    if len({r.get("seat") for r in rows}) < 2 and rows:
        out.append("rule-of-two")
    for r in rows:
        rev = r.get("reviewer")
        if rev and rev in seats and r.get("seat") in seats:
            fs = team_mod.model_family(seats.get(r["seat"]))
            fr = team_mod.model_family(seats.get(rev))
            if fs and fr and fs == fr and "same-family-review" not in out:
                out.append("same-family-review")
    for sname, seat in seats.items():
        if (seat.get("budget") or {}).get("usd") is not None:
            out.append(f"budget=advisory:{sname}")
    if (doc.get("budget") or {}).get("usd") is not None:
        out.append("budget=advisory:team")
    return out


def seat_rules(prog):
    """One row per seat: the grants, the budget, the autonomy."""
    doc, seats, contract = spawn_mod.load_team(prog)
    for sname, seat in seats.items():
        budget = seat.get("budget") or {}
        yield {
            "seat": sname,
            "human": seat.get("human") is True,
            "adapter": seat.get("adapter"),
            "role": seat.get("role"),
            "write": seat.get("write", []),
            "read": seat.get("read", []),
            "network": seat.get("network", []),
            "shell": seat.get("shell", []),
            "model": seat.get("model"),
            "repo_context": seat.get("repo_context", "hide"),
            "usd": budget.get("usd"),
            "minutes": budget.get("minutes"),
        }


def cmd_rules(prog, seat, as_json):
    doc, seats, _ = spawn_mod.load_team(prog)
    rows = [r for r in seat_rules(prog)]
    if seat:
        rows = [r for r in rows if r["seat"] == seat]
        if not rows:
            print(f"rules: seat {seat!r} isn't on the team; "
                  f"seats are {' '.join(sorted(seats))}", file=sys.stderr)
            return 1
    waivers = sorted(set(_waivers_of(prog)))
    doc_out = {"schema": JSON_SCHEMA, "team": doc.get("name"),
               "autonomy": doc.get("autonomy", "attended"),
               "max_parallel": doc.get("max_parallel", 1),
               "seats": rows, "waivers": waivers}
    if as_json:
        print(json.dumps(doc_out, ensure_ascii=True, sort_keys=True))
    else:
        print(f"team {doc.get('name')} autonomy={doc.get('autonomy', 'attended')} "
              f"max_parallel={doc.get('max_parallel', 1)}")
        for r in rows:
            if r["human"]:
                print(f"  {r['seat']:12} human")
                continue
            grants = ",".join(r["write"]) or "-"
            print(f"  {r['seat']:12} write={grants} net={','.join(r['network']) or '-'} "
                  f"usd={r['usd'] if r['usd'] is not None else '-'}")
        if waivers:
            print(f"  needs-waiver: {' '.join(waivers)}")
    return 0


def main(argv):
    if len(argv) < 2 or argv[1].startswith("-"):
        print("usage: rules.py <program-dir> [--seat S] [--json]", file=sys.stderr)
        return 2
    seat = None
    if "--seat" in argv:
        i = argv.index("--seat")
        if i + 1 >= len(argv):
            print("rules: --seat takes a name", file=sys.stderr)
            return 2
        seat = argv[i + 1]
    try:
        return cmd_rules(argv[1], seat, "--json" in argv)
    except spawn_mod.Refused as e:
        print(f"rules: {e}; fix what it names, then retry", file=sys.stderr)
        return 1
    except spawn_mod.Void as e:
        print(f"rules: VOID, {e}", file=sys.stderr)
        return 2


def selftest():
    """Room-safe: grants print per seat, waivers name themselves, --json carries
    what the screen does, an unknown seat refuses with the roster named."""
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

    base = tempfile.mkdtemp(prefix="rules-rt.")
    try:
        prog = spawn_mod._program(
            base, "p1",
            team_body='schema = 1\nname = "trio"\nmax_parallel = 2\n'
                      '[seat.w]\nrole = "roles/w.md"\nadapter = "stub"\nwrite = ["src/**"]\n'
                      '[seat.w.budget]\nusd = 4.0\n'
                      '[seat.r]\nrole = "roles/w.md"\nadapter = "stub"\n'
                      '[seat.h]\nhuman = true\n',
            contract_body='schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\n'
                          'kind = "run"\nseat = "w"\ncmd = "true"\n'
                          '[[row]]\nid = "b"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                          'seat = "r"\nreviewer = "w"\ncmd = "true"\n')
        check(cmd_rules(prog, None, False) == 0, "A the screen prints")
        doc = json.loads(_capture(lambda: cmd_rules(prog, None, True)))
        check(doc["schema"] == 1 and doc["team"] == "trio" and doc["max_parallel"] == 2,
              "A json shape")
        seats = {r["seat"]: r for r in doc["seats"]}
        check(seats["w"]["write"] == ["src/**"] and seats["w"]["usd"] == 4.0,
              f"A grants carry: {seats.get('w')}")
        check(seats["h"]["human"] is True, "A a human seat says so")
        check("budget=advisory:w" in doc["waivers"], f"A the advisory waiver: {doc['waivers']}")
        check("unreviewed-rows" in doc["waivers"], "A the unreviewed waiver")

        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            r = cmd_rules(prog, "w", False)
        check(r == 0 and "write=src/**" in buf.getvalue(), f"B one seat: {buf.getvalue()!r}")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            r = cmd_rules(prog, "nope", False)
        check(r == 1 and "seats are" in buf.getvalue(), f"B unknown seat: {buf.getvalue()!r}")

        print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
        return 0 if ok[0] and not bad[0] else 1
    finally:
        _sh.rmtree(base, ignore_errors=True)


def _capture(fn):
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue()


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.exit(main(sys.argv))
