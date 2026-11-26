#!/usr/bin/env python3
"""goals_lint -- a plan's goals can all FAIL.

A goal row that can't fail is a rubber stamp: trivial cmds, scaffold descs,
and checks that mirror the plan's own words all pass hollow. This lints the
plan's goal list (one '## <id>' section per goal, each naming its check
command) and refuses what contract.py's own lint would refuse.
"""
import re
import sys

TRIVIAL = {"true", "false", ":", "pass", "exit 0", "exit 1", "echo ok"}


def main(argv):
    if len(argv) != 2:
        print("usage: goals_lint.py <plan.md>", file=sys.stderr)
        return 2
    text = open(argv[1], encoding="utf-8", errors="replace").read()
    heads = list(re.finditer(r"^## ([a-z0-9][a-z0-9._-]{0,63})$", text, re.M))
    if not heads:
        print("goals_lint: no '## <id>' goal sections in the plan", file=sys.stderr)
        return 1
    bad = []
    for i, h in enumerate(heads):
        gid = h.group(1)
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        section = text[h.end():end]  # by header SPANS: a goal id that is a
        # prefix of another's can't shadow its section (the review fired it)
        m = re.search(r"check:\s*`(.+?)`", section)
        if not m:
            bad.append(f"{gid}: no check: `command` line")
            continue
        cmd = m.group(1).strip()
        low = cmd.lower()
        if low in TRIVIAL:
            bad.append(f"{gid}: check is trivial ({cmd!r})")
        # bypass shapes: an always-true tail, a trivial HEAD, or a test over
        # bare literals passes when the goal is unmet (the review ran all
        # three past) -- a path operand is meaningful, a bare word is not
        if re.search(r"(\|\||&&)\s*(true|:|exit 0)\s*$", low):
            bad.append(f"{gid}: check short-circuits true ({cmd!r})")
        if low.split() and low.split()[0].rstrip(";") in TRIVIAL:
            bad.append(f"{gid}: check begins trivial ({cmd!r})")
        _t = re.fullmatch(r"(test|\[)\s+(.*)", cmd)
        if _t:
            _ops = re.sub(r"^[A-Za-z]+\s+", "", _t.group(2))
            _ops = _ops.replace('"', "").replace("'", "")
            if "/" not in _ops and not re.search(r"[$`]", _ops):
                bad.append(f"{gid}: check tests only bare literals ({cmd!r})")
        if re.search(r"desc:\s*(todo|tbd|placeholder)\b", section, re.I):
            bad.append(f"{gid}: desc is scaffold")
    for b in bad:
        print(f"goals_lint: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
