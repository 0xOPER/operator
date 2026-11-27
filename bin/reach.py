#!/usr/bin/env python3
"""reach -- a seat's network, from the charter the owner signed.

A charter's [reach] is the network policy of a program (docs/charter.md): a
profile (closed, dev or research), extra hosts to allow, hosts to deny, pins,
and how many hosts the manager may declare. A seat asks for its share with
`network = ["pypi.org", ...]` in team.toml, and the charter bounds it: a host
the charter does not cover refuses where the team loads, `*` is the charter's
whole reach and never more, and a deny beats every allow. Without a charter a
program is closed: no seat has a network.

`reach.py policy <program-dir> --seat <seat>` prints the egress policy the
seat's jail runs. bin/egress-proxy.py re-reads it on every connection, so a
policy may gain a host while a turn runs (the manager's net.allow, a later
milestone). The proxy serves port 443; another port is a pin in the charter.

usage: reach.py policy <program-dir> --seat <seat>
       reach.py check <program-dir> --seat <seat>
       reach.py --selftest
exit: 0 ok, 1 refused or a finding, 2 usage or VOID
"""
import os
import sys

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
PROFILES = {"closed": (), "dev": ("registries", "docs", "vcs"),
            "research": ("registries", "docs", "vcs", "web")}
PROXY_PORT = 3129           # the egress face inside the jail


class Void(Exception):
    pass


class Refused(Exception):
    pass


class Finding(Exception):
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
    if doc is None:
        return {"profile": "closed", "allow": [], "deny": [], "pins": []}
    reach = doc.get("reach") if isinstance(doc.get("reach"), dict) else {}
    return {"profile": reach.get("profile", "closed"),
            "allow": [h for h in reach.get("allow", []) if isinstance(h, str)],
            "deny": [h for h in reach.get("deny", []) if isinstance(h, str)],
            "pins": [p for p in reach.get("pins", []) if isinstance(p, str)]}


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


def policy(prog, hosts):
    """The egress proxy's policy lines for one seat's jail."""
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
    allowed_set = set(allowed)
    lines += [f"pin {m.group(1)} {m.group(5)} {m.group(6)}" for p in reach["pins"]
              if env_mod.pin_ok(p) and (m := PIN_RE.fullmatch(p)) and m.group(1) in allowed_set]
    return lines


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
            print("\n".join(policy(prog, seat_grant(prog, seat))))
        except (Refused, Finding) as e:
            die(str(e), 1)
        except Void as e:
            die(str(e), 2)
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
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (Refused, Finding) as e:
        die(str(e), 1)
    except Void as e:
        print(f"reach: VOID, {e}", file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"reach: VOID, {e}", file=sys.stderr)
        sys.exit(2)
