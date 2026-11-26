#!/usr/bin/env python3
"""stub-adapter -- the fixture worker: does exactly what the engine's plan says.

The plan is engine-written (compiled/plan.json), never brief text: a worker that
obeyed its brief would be the confused deputy the whole engine exists to fence.
Each step is one of: write (inside the layout), try_write (attempted anywhere,
the jail decides), report (out/report.json), outbox, cost, session, sleep,
exit. Every step's outcome prints as one JSON line on stdout for the supervisor
to parse; a bad plan refuses named, never improvises.
"""
import json
import os
import sys
import time

sys.dont_write_bytecode = True
ALLOWED = ("write", "try_write", "report", "outbox", "cost", "session", "sleep")


def _out_dir():
    """The attempt's out dir: /w/out in the jail, beside the repo standalone
    (the fixture suite runs the plan without a jail)."""
    jail = "/w/out"
    if os.path.isdir("/w"):
        return jail
    return "out"


def main():
    if len(sys.argv) != 2:
        print("stub-adapter: usage: stub-adapter.py <plan.json>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            plan = json.load(f)
    except (OSError, ValueError) as e:
        print(f"stub-adapter: VOID, the plan won't load: {e}", file=sys.stderr)
        return 2
    if not isinstance(plan, list):
        print("stub-adapter: VOID, the plan is a list of steps", file=sys.stderr)
        return 2
    for i, step in enumerate(plan):
        if not isinstance(step, dict) or step.get("do") not in ALLOWED:
            print(f"stub-adapter: VOID, step {i} isn't one of {' '.join(ALLOWED)}",
                  file=sys.stderr)
            return 2
        do = step["do"]
        if do in ("write", "try_write"):
            path = step.get("path") or ""
            try:
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "w") as f:
                    f.write(step.get("body", ""))
                out = {"step": i, "do": do, "path": path, "ok": True}
            except OSError as e:
                out = {"step": i, "do": do, "path": path, "ok": False, "why": e.strerror}
        elif do == "report":
            od = _out_dir()
            os.makedirs(od, exist_ok=True)
            with open(os.path.join(od, "report.json"), "w") as f:
                json.dump(step.get("json", {}), f)
            out = {"step": i, "do": do, "ok": True}
        elif do == "outbox":
            od = os.path.join(_out_dir(), "outbox")
            os.makedirs(od, exist_ok=True)
            with open(os.path.join(od, f"{step.get('to', 'seat')}.md"), "w") as f:
                f.write(step.get("body", ""))
            out = {"step": i, "do": do, "ok": True}
        elif do == "cost":
            out = {"step": i, "cost": float(step.get("usd", 0))}
        elif do == "session":
            out = {"step": i, "session_id": str(step.get("id", "stub"))}
        elif do == "sleep":
            time.sleep(float(step.get("seconds", 0)))
            out = {"step": i, "do": do, "ok": True}
        print(json.dumps(out, ensure_ascii=True, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
