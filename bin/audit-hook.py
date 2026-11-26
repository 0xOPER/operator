#!/usr/bin/env python3
"""audit-hook -- log every tool call a CLI makes inside a run, capped and redacted.

This is the tracked source. `operator init` renders the instance a CLI actually loads:
a two-line wrapper that names the run's log file in the environment and execs this
file from the read-only core, so the instance itself is never tracked and never
writable by the run. hooks/ stays banned (R1's gone-tools line), which is why this
lives in bin/.

The 0.1 behaviour is logging, not blocking: matcher * over the CLI's tool calls, one
line each, tool name and a size-capped, control-stripped rendering of the input.
Blocking is the conformance layer's refusal, not this hook's. Nothing here follows
instructions from the payload: it is data, printed and dropped.

usage: audit-hook.py            (a hook event on stdin; OPERATOR_HOOK_LOG names the log)
       audit-hook.py --selftest
env: OPERATOR_HOOK_LOG   the log file (default: refuse; a rendered instance always sets it)
exit: 0 logged or ignored, 1 the log couldn't be written, 2 usage/VOID
"""
import json
import os
import re
import sys

sys.dont_write_bytecode = True

CAP = 4000
SAFE = re.compile(r"[^ -~\t]")


def render(value, budget):
    """A capped, control-stripped one-line rendering of any JSON value."""
    try:
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        text = repr(value)
    text = SAFE.sub("?", text[:budget])
    return text


def log_line(event):
    """One log line from a hook event, or None when the payload carries no call."""
    if not isinstance(event, dict):
        return "unparsed " + render(event, CAP - 10)
    # the tool name is capped first and the payload budgeted from it, so the render
    # slice is the one and only payload cap and the ratchet can see it break
    tool = str(event.get("tool_name") or event.get("tool") or "-")[:64]
    payload = event.get("tool_input", event.get("input", event.get("args")))
    return f"{tool} {render(payload, CAP - len(tool) - 1)}".strip()


def main():
    log = os.environ.get("OPERATOR_HOOK_LOG")
    if not log:
        print("audit-hook: VOID, OPERATOR_HOOK_LOG names the log; init renders it", file=sys.stderr)
        return 2
    raw = sys.stdin.read(65536)
    try:
        event = json.loads(raw)
    except (ValueError, RecursionError):
        event = {"tool_name": "unparsed", "tool_input": raw[:CAP - 10]}
    line = log_line(event)
    try:
        with open(log, "a", encoding="ascii", errors="replace") as f:
            f.write(line + "\n")
    except OSError as e:
        # exit 2 REFUSES the tool call: an audit trail that can't be written
        # never lets the call through (the fail-open lens caught exit 1 here)
        print(f"audit-hook: the log wouldn't open (refusing): {e}", file=sys.stderr)
        return 2
    return 0


def selftest():
    import subprocess
    import tempfile
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

    def hook(payload, env_extra=None):
        e = dict(os.environ)
        e.update(env_extra or {})
        return subprocess.run([sys.executable, os.path.abspath(__file__)],
                              input=payload, capture_output=True, text=True, env=e)

    d = tempfile.mkdtemp(prefix="ah.")
    log = os.path.join(d, "hook.log")
    env = {"OPERATOR_HOOK_LOG": log}
    # A a normal tool call logs one line, capped
    r = hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls -la"}}), env)
    check(r.returncode == 0 and open(log).read() == 'Bash {"command":"ls -la"}\n',
          f"A logged: {open(log).read()!r}")
    # B junk on stdin logs as unparsed, never crashes
    r = hook("not json at all", env)
    check(r.returncode == 0 and "unparsed" in open(log).read(), f"B unparsed: {r.stderr}")
    # C control characters never reach the log
    r = hook(json.dumps({"tool_name": "Write", "tool_input": {"c": "a\x1b[31mb\tc\nd"}}), env)
    check(r.returncode == 0 and "\x1b" not in open(log).read() and "\n" not in
          open(log).read().split('Write')[-1].rstrip("\n")[-10:], f"C stripped: {open(log).read()!r}")
    # D the cap holds
    r = hook(json.dumps({"tool_name": "X", "tool_input": {"p": "A" * 20000}}), env)
    lines = open(log).read().splitlines()
    check(r.returncode == 0 and len(lines[-1]) <= CAP, f"D capped: {len(lines[-1])}")
    # E no log named is VOID, and an unwritable log REFUSES the call (exit 2 --
    # an audit trail that can't be written never lets the call through)
    r = hook("{}")
    check(r.returncode == 2 and "OPERATOR_HOOK_LOG" in r.stderr, f"E no log: {r.stderr}")
    r = hook("{}", {"OPERATOR_HOOK_LOG": os.path.join(d, "no", "such", "dir", "l")})
    check(r.returncode == 2 and "refusing" in r.stderr, f"E unwritable: {r.stderr}")

    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.exit(main())
