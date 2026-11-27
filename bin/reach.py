#!/usr/bin/env python3
"""reach -- a seat's network, from the charter the owner signed.

A charter's [reach] is the network policy of a program (docs/charter.md): a
profile (closed, dev or research), extra hosts to allow, hosts to deny, pins,
and the declared rule: how many hosts may be declared for a while
(declared_max) and for how long (declared_ttl). A seat asks for its share
with `network = ["pypi.org", ...]` in team.toml, and the charter bounds it: a
host the charter does not cover refuses where the team loads, `*` is the
charter's whole reach and never more, and a deny beats every allow. Without a
charter a program is closed: no seat has a network.

`reach.py allow <program-dir> --seat <seat> --host <host>` is net.allow, the
operator seat's verb (the manager inherits it): one host on 443 for one seat
that already holds a network grant, for declared_ttl seconds while fewer than
declared_max are live. Never a denied host, never a grant the seat lacks. The
live declarations sit in <program>/runs/reach-declared.json, outside the
signed closure; every one is a row in the call log; it rides the seat's next
turn.

`reach.py policy <program-dir> --seat <seat>` prints the egress policy the
seat's jail runs. bin/egress-proxy.py re-reads the policy file on every
connection. The proxy serves port 443; another port is a pin in the charter.

usage: reach.py policy <program-dir> --seat <seat>
       reach.py allow <program-dir> --seat <seat> --host <host> [--by who]
       reach.py check <program-dir> --seat <seat>
       reach.py --selftest
exit: 0 ok, 1 refused or a finding, 2 usage or VOID
"""
import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
import environment as env_mod  # noqa: E402

PIN_RE = env_mod.PIN_RE

# a category is a list of hosts; a leading dot means its subdomains
CATEGORIES = {
    "registries": ("pypi.org", "files.pythonhosted.org"),
    "docs": ("github.com", ".githubusercontent.com"),
    "vcs": ("github.com",),
}
# `web` is not a list: any global address on 80 and 443
PROFILES = {"closed": (), "dev": ("registries", "docs", "vcs", "declared"),
            "research": ("registries", "docs", "vcs", "web", "declared")}
PROXY_PORT = 3129           # the egress face inside the jail
DEFAULT_TTL = 3600          # a declaration's life when the charter names none
DECLARED_FILE = os.path.join("runs", "reach-declared.json")   # outside the signed closure


class Void(Exception):
    pass


class Refused(Exception):
    pass


class Finding(Exception):
    pass


class Locked(Exception):
    pass


def die(msg, code):
    print(f"reach: {msg}", file=sys.stderr)
    sys.exit(code)


def rule_matches(host, rule):
    """`*`, exact, or a leading-dot subdomain rule (subdomains only), as the proxy reads it."""
    return rule == "*" or host == rule or (rule.startswith(".") and host.endswith(rule))


def reach_of(prog):
    """The charter's [reach] with its defaults. A program without a charter is closed."""
    doc = env_mod.charter(prog)
    reach = doc.get("reach") if doc is not None and isinstance(doc.get("reach"), dict) else {}
    max_, ttl = reach.get("declared_max", 0), reach.get("declared_ttl", DEFAULT_TTL)
    return {"profile": reach.get("profile", "closed"),
            "allow": [h for h in reach.get("allow", []) if isinstance(h, str)],
            "deny": [h for h in reach.get("deny", []) if isinstance(h, str)],
            "pins": [p for p in reach.get("pins", []) if isinstance(p, str)],
            "declared_max": max_ if type(max_) is int and max_ > 0 else 0,
            "declared_ttl": ttl if type(ttl) is int and ttl > 0 else DEFAULT_TTL}


def profile_hosts(reach):
    """The hosts a profile's named categories cover (`web` is not a list)."""
    out = []
    for cat in PROFILES.get(reach["profile"], ()):
        for h in CATEGORIES.get(cat, ()):
            if h not in out:
                out.append(h)
    return out


def covers(reach, host):
    """(covered, why): whether the charter's reach covers this host."""
    if any(rule_matches(host, d.lstrip("!")) for d in reach["deny"]):
        return False, f"{host} is on the charter's deny list"
    if "web" in PROFILES.get(reach["profile"], ()):
        return True, ""
    if any(rule_matches(host, r) for r in reach["allow"] + profile_hosts(reach)):
        return True, ""
    return False, (f"{host} is outside the charter's reach (profile {reach['profile']}, "
                   f"allowed: {', '.join(reach['allow']) or 'none'})")


def seat_hosts(hosts):
    """The seat's grant as bare hosts. A port other than 443 is a finding: the
    proxy serves 443, and another port is a pin in the charter, not a grant."""
    out = []
    for h in hosts:
        host, sep, port = h.rpartition(":")
        if sep and port.isdigit():
            if port != "443":
                raise Finding(f"network names {h!r} with a port other than 443: the egress proxy "
                              "serves 443 only; pin the port in the charter's [reach].pins instead")
            out.append(host)
        else:
            out.append(h)
    return out


def check_grant(prog, hosts):
    """Refuses a grant the charter doesn't cover. Finding names the fix."""
    reach = reach_of(prog)
    bare = seat_hosts(hosts)
    for h in bare:
        if h == "*":
            if reach["profile"] == "closed":
                raise Finding('network = ["*"] asks for the charter\'s whole reach and the charter is '
                              "closed (no profile): open a profile in [reach] (the owner signs), or "
                              "name the hosts")
            continue
        ok, why = covers(reach, h)
        if not ok:
            raise Finding(f"network: {why}; add the host to [reach].allow or widen the profile "
                          "(the owner signs), or drop it")


def policy(prog, hosts, seat=None):
    """The egress proxy's policy lines for one seat's jail. With a seat's name,
    its live declarations (allow) ride with their expiry."""
    reach = reach_of(prog)
    bare = seat_hosts(hosts)
    check_grant(prog, hosts)
    lines = ["# the boundary: the charter's reach, narrowed to this seat"]
    lines += [f"!{d}" for d in reach["deny"]]
    allowed = bare
    if "*" in bare:
        # the charter's whole reach: its categories and allow list, plus the
        # web when the profile has it. Never a bare star under a narrower profile
        allowed = sorted(set(reach["allow"]) | set(profile_hosts(reach)))
        if "web" in PROFILES.get(reach["profile"], ()):
            allowed.append("*")
    # the text says what the proxy does: a denied host is never also an allow line
    allowed = [h for h in allowed
               if h == "*" or not any(rule_matches(h, d.lstrip("!")) for d in reach["deny"])]
    lines += allowed
    for d in (declared_of(prog) if seat else []):
        if d["seat"] == seat:
            lines.append(f"{d['host']} until {d['until']}")
    allowed_set = set(allowed)
    lines += [f"pin {m.group(1)} {m.group(5)} {m.group(6)}" for p in reach["pins"]
              if env_mod.pin_ok(p) and (m := PIN_RE.fullmatch(p)) and m.group(1) in allowed_set]
    return lines


def stamp(ts):
    """The proxy's expiry stamp, strict: 2030-01-01T00:00:00Z, UTC."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _epoch(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def declared_of(prog, now=None):
    """The live declarations of a program, oldest first: host, seat, until, by
    and at. An expired one leaves the list; it never leaves the call log,
    where every one was a row."""
    try:
        with open(os.path.join(prog, DECLARED_FILE), encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return []
    now = time.time() if now is None else now
    out = []
    for d in (doc if isinstance(doc, list) else []):
        try:
            if isinstance(d, dict) and _epoch(d["until"]) > now:
                out.append(d)
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _is_address(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def allow(prog, seat, host, by="cli"):
    """net.allow (docs/charter.md): one host on 443 for one seat, for the
    charter's declared lifetime and inside its declared number. It widens a
    network grant the seat already holds and never opens one; it never touches
    the deny list. Every declaration is a row in the call log, or it is nothing.
    Returns the declaration, with its receipt."""
    import team as team_mod
    reach = reach_of(prog)
    if reach["declared_max"] <= 0:
        raise Refused("the charter's declared_max is 0, so nobody declares a host: the owner signs "
                      "a number in [reach] to open the rule")
    if "declared" not in PROFILES.get(reach["profile"], ()):
        raise Refused(f"the {reach['profile']} profile doesn't carry the declared rule")
    try:
        _, seats, _ = team_mod.load(prog)
    except (team_mod.Finding, team_mod.Void) as e:
        raise Void(str(e))
    if not ((seats.get(seat) or {}).get("network")):
        raise Refused(f"seat {seat!r} holds no network grant: net.allow widens a grant and never "
                      "opens one (network in team.toml, which the owner signs)")
    if not isinstance(host, str) or not team_mod.HOST_RE.fullmatch(host) or ":" in host \
            or host != host.lower() or _is_address(host):
        raise Refused(f"{host!r} isn't a bare host name: no port, no address (an address is a pin "
                      "in [reach].pins, which the owner signs)")
    if not isinstance(by, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", by):
        raise Refused("who declares must be a short lower-case name (--by)")
    ok, why = covers(reach, host)
    if "deny list" in why:
        raise Refused(f"{host} is on the charter's deny list: net.allow never touches it")
    if ok:
        raise Refused(f"{host} is already inside the charter's reach: nothing to declare")
    live = declared_of(prog)
    for d in live:
        if d["seat"] == seat and d["host"] == host:
            raise Refused(f"{host} is declared for seat {seat} until {d['until']}")
    if len(live) >= reach["declared_max"]:
        raise Refused(f"{len(live)} hosts are declared and the charter's declared_max is "
                      f"{reach['declared_max']}: the first expires at "
                      f"{min(d['until'] for d in live)}, or the owner raises declared_max")
    now = time.time()
    entry = {"host": host, "seat": seat, "until": stamp(now + reach["declared_ttl"]),
             "by": by, "at": stamp(now)}
    entry["receipt"] = _store(prog, live + [entry], entry)
    return entry


def _store(prog, entries, entry):
    """The declarations file and its log row land together or not at all.
    Returns the row's call id."""
    path = os.path.join(prog, DECLARED_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    before = open(path, encoding="utf-8").read() if os.path.exists(path) else None
    fd, tmp = tempfile.mkstemp(prefix=".reach-", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(entries, indent=1, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    argv = [os.path.join(ROOT, "bin", "call-log.sh"), "record", "net-allow",
            "--key", f"host={entry['host']}", "--key", f"seat={entry['seat']}",
            "--key", f"until={entry['until'].replace(':', '')}", "--key", f"by={entry['by']}",
            "--", "cat", path]
    r = env_mod.sh(argv)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    if before is None:
        os.unlink(path)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(before)
    if r.returncode == 3:
        raise Locked("the call log is locked")
    raise Void(f"the call log refused the declaration's row, so nothing was declared: "
               f"{r.stderr.strip()[:200]}")
def flag(argv, name, default=None):
    if name in argv and argv.index(name) + 1 < len(argv):
        return argv[argv.index(name) + 1]
    return default


def seat_grant(prog, seat):
    """The seat's network grant from team.toml: [] without one."""
    import team as team_mod
    try:
        _, seats, _ = team_mod.load(prog)
    except (team_mod.Finding, team_mod.Void) as e:
        raise Void(str(e))
    doc = seats.get(seat) or {}
    return list(doc.get("network") or [])


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) >= 4 and argv[1] == "policy" and flag(argv, "--seat"):
        prog, seat = argv[2], flag(argv, "--seat")
        try:
            print("\n".join(policy(prog, seat_grant(prog, seat), seat)))
        except (Refused, Finding) as e:
            die(str(e), 1)
        except Void as e:
            die(str(e), 2)
        return 0
    if len(argv) >= 4 and argv[1] == "allow" and flag(argv, "--seat") and flag(argv, "--host"):
        try:
            e = allow(argv[2], flag(argv, "--seat"), flag(argv, "--host"), by=flag(argv, "--by", "cli"))
        except Locked as e:
            die(str(e), 3)
        except (Refused, Finding) as e:
            die(str(e), 1)
        except Void as e:
            die(str(e), 2)
        print(f"reach: OK (net.allow {e['host']} for {e['seat']} until {e['until']})")
        return 0
    if len(argv) >= 4 and argv[1] == "check" and flag(argv, "--seat"):
        prog, seat = argv[2], flag(argv, "--seat")
        try:
            check_grant(prog, seat_grant(prog, seat))
        except (Refused, Finding) as e:
            die(str(e), 1)
        except Void as e:
            die(str(e), 2)
        print(f"reach: OK ({seat}: {', '.join(seat_grant(prog, seat)) or 'no network'})")
        return 0
    print("usage: reach.py policy <program-dir> --seat <seat> | "
          "allow <program-dir> --seat <seat> --host <host> [--by who] | "
          "check <program-dir> --seat <seat> | --selftest", file=sys.stderr)
    return 2


# --- selftest ----------------------------------------------------------------------------


def selftest():
    """The room suite: the cover law, the profile, deny, pins, ports, the policy text."""
    import tempfile
    import shutil
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    def refused(fn, needle, label):
        try:
            fn()
        except (Refused, Finding) as e:
            check(needle in str(e), f"{label}: {e}")
        except Void as e:
            check(False, f"{label} VOIDed instead of refusing: {e}")
        else:
            check(False, f"{label} was accepted")

    base = tempfile.mkdtemp(prefix="reach-st.")
    try:
        prog = os.path.join(base, "prog")
        os.makedirs(prog)
        with open(os.path.join(prog, "contract.toml"), "w") as f:
            f.write('schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                    'seat = "w"\nreviewer = "r"\ncmd = "true"\n')
        cpath = os.path.join(prog, "charter.toml")

        def charter(text):
            with open(cpath, "w") as f:
                f.write(text)

        # A no charter is closed: nothing is covered, and a seat's grant refuses
        check(reach_of(prog)["profile"] == "closed", "A no charter is the closed profile")
        refused(lambda: check_grant(prog, ["pypi.org"]), "closed",
                "A a closed program refuses any network")
        refused(lambda: policy(prog, ["*"]), "closed", "A `*` on a closed program refuses")
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "dev"\n')
        check(covers(reach_of(prog), "pypi.org")[0] and covers(reach_of(prog), "github.com")[0]
              and covers(reach_of(prog), "raw.githubusercontent.com")[0],
              "B the dev profile covers its registries, docs and forges")
        check(not covers(reach_of(prog), "outside.test")[0], "B a host outside the profile is not covered")
        refused(lambda: check_grant(prog, ["outside.test"]), "outside the charter's reach",
                "B a seat can't name a host the charter doesn't cover")
        check(policy(prog, ["pypi.org"]) == ["# the boundary: the charter's reach, narrowed to this seat",
                                             "pypi.org"],
              f"B the policy is the seat's hosts: {policy(prog, ['pypi.org'])}")
        # C an allow list widens the reach; a deny beats every allow
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "closed"\nallow = ["api.example.org", ".corp.example"]\n'
                'deny = ["bad.example.org"]\n')
        check(covers(reach_of(prog), "api.example.org")[0] and covers(reach_of(prog), "x.corp.example")[0],
              "C an allow list covers its hosts and subdomains")
        refused(lambda: check_grant(prog, ["bad.example.org"]), "deny list",
                "C a denied host is not covered")
        # D `*` is the charter's reach and never more
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "dev"\nallow = ["api.example.org"]\n'
                'deny = ["github.com"]\n')
        lines = policy(prog, ["*"])
        check("!github.com" in lines and "api.example.org" in lines and "pypi.org" in lines
              and "*" not in lines and "github.com" not in lines,
              f"D `*` becomes the charter's reach, deny first, never a star, a denied host dropped: {lines}")
        check(policy(prog, ["api.example.org"]) == ["# the boundary: the charter's reach, narrowed to this seat",
                                                    "!github.com", "api.example.org"],
              "D a narrowed seat keeps the charter's deny lines")
        # E pins ride for allowed hosts only
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "closed"\nallow = ["api.example.org", "other.example"]\n'
                'pins = ["api.example.org=192.0.2.10:8443", "other.example=192.0.2.11:8443"]\n')
        lines = policy(prog, ["api.example.org"])
        check(lines[-1] == "pin api.example.org 192.0.2.10 8443" and not any("other.example" in ln for ln in lines),
              f"E a pin rides for an allowed host only: {lines}")
        check("web" in PROFILES["research"], "F the research profile carries the web")
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "research"\n')
        check(covers(reach_of(prog), "anything.example")[0], "F research covers any host")
        check("*" in policy(prog, ["*"]), "F under research a `*` seat gets the web as a star line")
        check("*" not in policy(prog, ["api.example.org"]), "F a narrowed seat never gets the web")
        # G a port other than 443 is a finding; 443 is the host
        refused(lambda: policy(prog, ["api.example.org:8443"]), "serves 443 only",
                "G a grant with another port refuses")
        check(seat_hosts(["a.example:443", "b.example"]) == ["a.example", "b.example"],
              "G :443 is the bare host")
        # H the declared rule (docs/charter.md): net.allow widens a grant the
        # seat already holds, inside the charter's number and lifetime; every
        # one is a row in the call log; a denied host, an address, a port and
        # a seat without a grant refuse, naming the fix
        old_log = os.environ.get("CALL_LOG_FILE")
        os.environ["CALL_LOG_FILE"] = os.path.join(base, "call-log.tsv")

        def put(name, text):
            with open(os.path.join(prog, name), "w", encoding="utf-8") as f:
                f.write(text)

        def logged():
            p = os.environ["CALL_LOG_FILE"]
            return [ln.split("\t")[3] for ln in
                    (open(p, encoding="utf-8").read().splitlines() if os.path.exists(p) else [])
                    if len(ln.split("\t")) == 10 and ln.split("\t")[2] == "net-allow"]

        def bare(e):
            return {k: v for k, v in e.items() if k != "receipt"}

        os.makedirs(os.path.join(prog, "roles"), exist_ok=True)
        put("roles/w.md", "You are the worker seat.\n")
        put("team.toml", 'schema = 1\nname = "t"\nmax_parallel = 1\n[seat.w]\nrole = "roles/w.md"\n'
            'adapter = "stub"\nnetwork = ["api.example.org"]\n[seat.x]\nrole = "roles/w.md"\n'
            'adapter = "stub"\n')
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "closed"\nallow = ["api.example.org"]\n'
                'deny = ["bad.example.org"]\ndeclared_max = 2\ndeclared_ttl = 3600\n')
        refused(lambda: allow(prog, "w", "docs.example.net"), "doesn't carry the declared rule",
                "H a closed profile doesn't carry the declared rule")
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "dev"\ndeclared_max = 0\n')
        refused(lambda: allow(prog, "w", "docs.example.net"), "declared_max is 0",
                "H a charter with declared_max 0 lets nobody declare")
        charter('schema = 1\nname = "st"\n[reach]\nprofile = "dev"\nallow = ["api.example.org"]\n'
                'declared_max = 2\ndeclared_ttl = 3600\ndeny = ["bad.example.org"]\n')
        refused(lambda: allow(prog, "x", "docs.example.net"), "holds no network grant",
                "H a seat without a network grant is never opened by net.allow")
        refused(lambda: allow(prog, "nope", "docs.example.net"), "holds no network grant",
                "H a seat that isn't on the team refuses the same way")
        for shape in ("docs.example.net:8443", "192.0.2.10", "Docs.Example.net", "docs.example.net/x"):
            refused(lambda h=shape: allow(prog, "w", h), "bare host name",
                    f"H {shape} isn't a bare host name")
        refused(lambda: allow(prog, "w", "bad.example.org"), "deny list",
                "H a denied host is never declared")
        refused(lambda: allow(prog, "w", "pypi.org"), "already inside",
                "H a host the charter already covers is not declared again")
        check(not logged() and not os.path.exists(os.path.join(prog, DECLARED_FILE)),
              "H nothing refused left a row or a file")
        t0 = time.time()
        e1 = allow(prog, "w", "docs.example.net", by="op")
        check(e1["until"] in (stamp(t0 + 3600), stamp(t0 + 3601)) and e1["by"] == "op"
              and e1["receipt"] and json.load(open(os.path.join(prog, DECLARED_FILE))) == [bare(e1)],
              f"H a declaration names its host, seat, expiry and receipt: {e1}")
        check(logged() == [f"host=docs.example.net,seat=w,until={e1['until'].replace(':', '')},by=op"],
              f"H every declaration is a row in the call log: {logged()}")
        head = ["# the boundary: the charter's reach, narrowed to this seat", "!bad.example.org",
                "api.example.org"]
        check(policy(prog, ["api.example.org"], seat="w") == head + [f"docs.example.net until {e1['until']}"],
              f"H a live declaration rides its seat's policy, with its expiry: "
              f"{policy(prog, ['api.example.org'], seat='w')}")
        check(policy(prog, ["api.example.org"], seat="x") == head
              and policy(prog, ["api.example.org"]) == head,
              "H another seat's policy, and one asked without a seat, carry no declaration")
        refused(lambda: allow(prog, "w", "docs.example.net"), "is declared for seat w until",
                "H the same host for the same seat is refused while it is live")
        e2 = allow(prog, "w", "second.example.net")
        refused(lambda: allow(prog, "w", "third.example.net"), "declared_max is 2",
                "H the charter's number is the ceiling")
        check(len(logged()) == 2 and len(declared_of(prog)) == 2, "H two declarations, two rows")
        check(declared_of(prog, now=time.time() + 7200) == []
              and declared_of(prog, now=time.time() + 1800) == [bare(e1), bare(e2)],
              "H an expired declaration is not live; a live one is, oldest first")
        put(DECLARED_FILE, json.dumps([{"host": "old.example.net", "seat": "w", "until": stamp(time.time() - 10),
                                        "by": "op", "at": stamp(time.time() - 4000)}]))
        check(policy(prog, ["api.example.org"], seat="w") == head,
              "H an expired declaration is gone from the policy")
        allow(prog, "w", "fresh.example.net")
        check([d["host"] for d in declared_of(prog)] == ["fresh.example.net"],
              "H the next declaration writes the live ones only")
        me = os.path.abspath(__file__)

        def at_the_door(*args):
            return subprocess.run([sys.executable, "-I", me, *args], capture_output=True, text=True,
                                  env=dict(os.environ), stdin=subprocess.DEVNULL)

        r_c = at_the_door("allow", prog, "--seat", "w", "--host", "cli.example.net", "--by", "op")
        check(r_c.returncode == 0 and "net.allow cli.example.net for w until" in r_c.stdout,
              f"H the verb's own door: rc={r_c.returncode} {r_c.stdout!r} {r_c.stderr[-120:]!r}")
        r_c = at_the_door("allow", prog, "--seat", "x", "--host", "cli2.example.net")
        check(r_c.returncode == 1 and "holds no network grant" in r_c.stderr,
              f"H a refusal at the door names the fix and exits 1: rc={r_c.returncode} {r_c.stderr[-100:]!r}")
        r_c = at_the_door("policy", prog, "--seat", "w")
        check(r_c.returncode == 0 and any(ln.startswith("cli.example.net until ") for ln in r_c.stdout.splitlines()),
              f"H the policy door prints the declaration: {r_c.stdout!r}")
        if old_log is None:
            os.environ.pop("CALL_LOG_FILE", None)
        else:
            os.environ["CALL_LOG_FILE"] = old_log
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (Refused, Finding) as e:
        die(str(e), 1)
    except Locked as e:
        die(str(e), 3)
    except Void as e:
        print(f"reach: VOID, {e}", file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"reach: VOID, {e}", file=sys.stderr)
        sys.exit(2)
