#!/usr/bin/env python3
"""goals_forge -- the auditor's forge test.

--control runs the plan's honest goal checks and must PASS.
--plant-forge rewrites ONE goal's check into a known-forgeable shape (an
always-true assertion) and re-runs it: the planted goal must FAIL the row --
if the hollowed check still passes, the plan's checks prove nothing and this
row goes red. The oracle pins this script, so the author can't swap the
forge.
"""
import re
import subprocess
import sys
import tempfile
import os


def goal_sections(text):
    heads = list(re.finditer(r"^## ([a-z0-9][a-z0-9._-]{0,63})$", text, re.M))
    out = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        out.append((m.group(1), text[m.end():end]))
    return out


def run_check(cmd, workdir):
    r = subprocess.run(["/bin/sh", "-c", cmd], cwd=workdir,
                       capture_output=True, text=True, timeout=60)
    return r.returncode


def main(argv):
    if len(argv) not in (3, 4):
        print("usage: goals_forge.py <plan.md> --control|--plant-forge",
              file=sys.stderr)
        return 2
    plan, mode = argv[1], argv[2]
    text = open(plan, encoding="utf-8", errors="replace").read()
    goals = goal_sections(text)
    if not goals:
        print("goals_forge: no goals in the plan", file=sys.stderr)
        return 1
    work = tempfile.mkdtemp(prefix="forge.")
    if mode == "--control":
        # goal checks are repo-relative: they run where the plan lives
        repo = os.path.dirname(os.path.abspath(plan)) or "."
        for gid, body in goals:
            m = re.search(r"check:\s*`(.+?)`", body)
            if not m or run_check(m.group(1), repo) != 0:
                print(f"goals_forge: control: {gid} failed its own check",
                      file=sys.stderr)
                return 1
        print(f"goals_forge: control: {len(goals)} goal(s) hold")
        return 0
    if mode != "--plant-forge":
        print("usage: goals_forge.py <plan.md> --control|--plant-forge",
              file=sys.stderr)
        return 2
    # plant: hollow the FIRST goal's check into an always-true shape
    gid, body = goals[0]
    m = re.search(r"check:\s*`(.+?)`", body)
    if not m:
        print(f"goals_forge: {gid} carries no check to hollow", file=sys.stderr)
        return 1
    hollow = "true"  # the canonical hollow: passes when the goal is unmet
    forged = text.replace(f"check: `{m.group(1)}`", f"check: `{hollow}`", 1)
    fp = os.path.join(work, "plan.md")
    with open(fp, "w") as f:
        f.write(forged)
    # the forged plan is RE-LINTED: a hollow check must fail the lint
    r = subprocess.run([sys.executable, "-I", os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "goals_lint.py"), fp],
        capture_output=True, text=True, timeout=60)
    if r.returncode == 0:
        print(f"goals_forge: the hollowed check still passed the lint -- "
              "the plan's checks are hollow", file=sys.stderr)
        return 1
    print("goals_forge: the planted forge failed the lint, as it must")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
