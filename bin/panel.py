#!/usr/bin/env python3
"""panel -- the human view of a run. A VIEW, not a source of truth (decision 18).

The panel renders what the engine already wrote -- the same docs the CLI emits.
The run header IS `run.py status --json` (executed, not re-implemented); the
escalation queue IS `run.py approvals --json`; the matrix rides task_states,
the engine's own computation; the tool-call cards are audit-hook's own log
lines. Nothing on the page is state the panel computed. A region with nothing
to show SAYS so and names where it looked -- a dead panel is refused like a
dead control.

Two modes:

  render   one static HTML page, written into the run dir (panel.html) or
           stdout. Deterministic: no wall clock rides the output, so the same
           run renders to the same bytes. Verb buttons in this mode COPY the
           named fix -- the page is inert by itself.
  serve    the same page on 127.0.0.1 with a live tail: GET / re-renders per
           request, GET /tail streams events.jsonl as it grows, and POST /verb
           runs ONE of the whitelisted engine verbs (stop, resume, cancel,
           reply) through run.py itself -- the verb logs its own event; the
           panel adds no state and never signs anything. Signatures and
           verdicts stay in the CLI (decision 18); asking for them is refused
           BY NAME. A per-boot token (served inside the page, checked on every
           POST), a Host-header pin to the loopback origin and a CSP keep a
           foreign page from driving the verbs.

usage: panel.py render [--run R] [--out F]    (default: first run, panel.html)
       panel.py serve  [--run R] [--port N]   (default: port 8765)
       panel.py --selftest
env: OPERATOR_HOME (runs live under it)
exit: 0 ok, 1 refused or a check failed, 2 usage or VOID
"""
import html
import json
import math
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
import run as run_mod   # noqa: E402  the engine's own laws, called not copied
import spawn as spawn_mod  # noqa: E402

JSON_SCHEMA = 1
DEFAULT_PORT = 8765
HOOK_CARDS = 200        # tool-call cards per attempt, the newest kept
EVENT_ROWS = 200        # timeline rows, the newest kept
EGRESS_ROWS = 100       # broker rows, the newest kept
NOTE_CAP = run_mod.REPLY_CAP  # a reply answers a question, briefly
BODY_CAP = NOTE_CAP + 4096  # headroom past the note cap so the note's OWN
# refusal fires first-hand (a cap that always shadows the smaller cap makes
# the smaller cap's message a lie)

# the ONLY verbs the panel runs, each mapped to run.py with FIXED argv shapes
# (no shell ever; no verb composes strings into a command). A verdict or a
# signature here would move the ruling surface into whatever holds the page --
# decision 18 refuses that, and so does the whitelist.
VERB_ARGV = {
    "stop":    lambda b: ["stop", b["run"]],
    "resume":  lambda b: ["resume", b["run"]],
    "cancel":  lambda b: ["cancel", b["run"], b["attempt"]],
    "reply":   None,     # needs the note file law below
}


def die(msg, fix, code=2):
    print(f"panel: {msg}", file=sys.stderr)
    if fix:
        print(f"  fix: {fix}", file=sys.stderr)
    sys.exit(code)


def esc(s):
    """Every dynamic byte on the page goes through here first."""
    return html.escape(str(s), quote=True)


def jslit(obj):
    """A JSON island that can't close its own script tag."""
    return json.dumps(obj, ensure_ascii=True, sort_keys=True)\
        .replace("</", "<\\/")


def _clean(s):
    """Control bytes never ride the page, whatever a log line carried in."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(s))


# --- the doc the page renders ----------------------------------------------------------


def _cli(doc_verb, args):
    """Run an engine CLI verb and return (rc, doc_or_text). The panel's truth
    is the CLI's own output; a CLI that dies shows as itself, never hidden."""
    p = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "run.py"),
                        doc_verb, *args],
                       capture_output=True, text=True, timeout=60,
                       stdin=subprocess.DEVNULL)
    return p.returncode, (p.stdout + p.stderr).strip()


def run_doc(run_name):
    """The header doc: literally `run.py status <run> --json`."""
    rc, out = _cli("status", [run_name, "--json"])
    if rc != 0:
        return {"schema": JSON_SCHEMA, "run": run_name, "state": "unknown",
                "cli": f"run.py status exited {rc}: {_clean(out[:400])}"}
    try:
        return json.loads(out)
    except ValueError:
        return {"schema": JSON_SCHEMA, "run": run_name, "state": "unknown",
                "cli": "run.py status --json emitted a doc that won't parse"}


def approvals_doc():
    """The queue doc: literally `run.py approvals --json`."""
    rc, out = _cli("approvals", ["--json"])
    if rc != 0:
        return [{"run": "-", "state": "?", "waiting": [
            {"kind": "cli", "what": f"run.py approvals exited {rc}: "
                                   f"{_clean(out[:400])}", "fix": ""}]}]
    try:
        return json.loads(out)
    except ValueError:
        return [{"run": "-", "state": "?", "waiting": [
            {"kind": "cli", "what": "approvals --json won't parse",
             "fix": ""}]}]


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, RecursionError):
        return None


def matrix_rows(rd):
    """The task matrix, from task_states -- the engine's own computation over
    the contract and the ledger. A program dir that moved (or a run with no
    attempts to name it) is stated, not papered over."""
    try:
        prog = run_mod._prog_of(rd)
        if not prog or not os.path.isdir(prog):
            return None, prog
        return run_mod.task_states(prog, rd), prog
    except Exception as e:  # a contract that won't load shows as itself
        # no state is claimed for a row the engine never computed: the
        # truth rides the detail text, the state column stays '-'
        return [{"task": "-", "seat": "-", "stage": "-", "deps": [],
                 "state": "-",
                 "detail": f"the contract won't load: {_clean(e)}"}], None


def budget_rows(rd):
    """Reserved vs settled per seat, straight off the ledger, paired with
    each seat's ruled USD cap from team.toml when reachable."""
    caps = {}
    rj = _read_json(os.path.join(rd, "run.json")) or {}
    prog = rj.get("program") or run_mod._prog_of(rd)
    if prog and os.path.isdir(prog):
        try:
            _, seats_cfg, _ = spawn_mod.load_team(prog)
            for sname, scfg in seats_cfg.items():
                u = (scfg.get("budget") or {}).get("usd")
                if isinstance(u, (int, float)) and not isinstance(u, bool) \
                        and math.isfinite(u) and u > 0:
                    caps[sname] = float(u)
        except Exception:
            pass
    seats = {}
    for r in run_mod.read_ledger(rd):
        aid, seat, task, amount, st, ts = r
        s = seats.setdefault(seat, {"attempts": 0, "settled": 0.0,
                                    "reserved": 0.0, "released": 0,
                                    "cap": caps.get(seat)})
        s["attempts"] += 1
        try:
            amt = float(amount)
        except ValueError:
            amt = 0.0
        if st == "settled":
            s["settled"] += amt
        elif st == "open":
            s["reserved"] += amt
        elif st == "released":
            s["released"] += 1
    return seats


def _read_hook_tail(adir, limit=65536):
    """Safely read up to the last `limit` bytes of an attempt's hook log.
    Prefers the collector-jailed copy in collected.json; when reading a live
    or legacy hook.jsonl directly on host, refuses symlinks (O_NOFOLLOW),
    non-regular files (FIFO/device), and caps bytes read to prevent host file
    exfiltration or OOM."""
    coll = _read_json(os.path.join(adir, "collected.json"))
    if isinstance(coll, list):
        for d in coll:
            if isinstance(d, dict) and d.get("file") == "hook.jsonl" \
                    and isinstance(d.get("body"), str) and not d.get("refused"):
                return [ln for ln in d["body"][-limit:].splitlines() if ln.strip()][-HOOK_CARDS:]
    out_dir = os.path.join(adir, "out")
    cands = []
    if not os.path.islink(out_dir):
        hp = os.path.join(adir, "out", "hook.jsonl")
        cands.append(hp)
    cands.append(os.path.join(adir, "hook.jsonl"))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    for p in cands:
        if os.path.islink(p):
            continue
        fd = -1
        try:
            fd = os.open(p, flags)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                continue
            start = max(0, st.st_size - limit)
            if start:
                os.lseek(fd, start, os.SEEK_SET)
            raw = b""
            while len(raw) < limit:
                chunk = os.read(fd, min(16384, limit - len(raw)))
                if not chunk:
                    break
                raw += chunk
            lines = raw.decode("utf-8", "replace").splitlines()
            if start and lines:
                lines = lines[1:]  # drop partial leading line after tail seek
            return [ln for ln in lines if ln.strip()][-HOOK_CARDS:]
        except OSError:
            continue
        finally:
            if fd >= 0:
                os.close(fd)
    return []


def attempt_cards(rd):
    """One card per attempt: what the engine stored -- the meta, the
    supervisor's outcome, the delivery markers, the hook's tool calls, the
    settled-or-reserved row. Nothing recomputed."""
    out = []
    for adir in run_mod.attempt_dirs(rd):
        name = os.path.basename(adir)
        meta = _read_json(os.path.join(adir, "attempt.json")) or {}
        sup = _read_json(os.path.join(adir, "supervisor.json")) or {}
        state = run_mod.attempt_state(adir, rd)
        rep = run_mod.report_of(adir)
        # delivery chips: markers the engine itself wrote, in pipeline order
        # (the candidate stage has NO marker file -- candidacy lives in the
        # parent repo's refs/heads/candidate/<task>, read through the
        # engine's own egit_ok, never a panel invention)
        chips = []
        chips.append("ran" if os.path.isfile(os.path.join(adir,
                                                         "supervisor.json"))
                     else "reserved")
        if os.path.isfile(os.path.join(adir, "collected.json")):
            chips.append("collected")
        task_of_a = str(meta.get("task") or "")
        if task_of_a and spawn_mod.egit_ok(
                os.path.join(rd, "parent"), "rev-parse", "--verify",
                f"refs/heads/candidate/{task_of_a}")[0]:
            chips.append("candidate")
        if os.path.isfile(os.path.join(adir, "contract.json")):
            cdoc = _read_json(os.path.join(adir, "contract.json"))
            if isinstance(cdoc, dict) and "ok" in cdoc:
                chips.append("contract-ok" if cdoc.get("ok") else "contract-red")
        if os.path.isfile(os.path.join(adir, "promoted")):
            chips.append("promoted")
        hooks = _read_hook_tail(adir)
        # the transcript's last lines, tailed the same way cmd_tail tails
        # them: from the END of the file, so a huge transcript never loads
        tail = []
        tp = os.path.join(adir, "transcript.out")
        if os.path.isfile(tp):
            with open(tp, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 64 * 1024))
                tail = f.read().decode("utf-8", "replace").splitlines()[-40:]
        cost = ""
        for r in run_mod.read_ledger(rd):
            if r[0] == name:
                cost = f"{r[3]} {r[4]}"
        # the CLI session this turn rode, by shape (zcode/claude/opencode),
        # with the HOME-swap replay that opens the attempt's own store
        session = run_mod._session_of(adir)
        out.append({"name": name, "seat": meta.get("seat", "?"),
                    "task": meta.get("task", "?"), "state": state,
                    "rc": sup.get("rc"), "timed_out": bool(sup.get("timed_out")),
                    "chips": chips, "hooks": hooks, "cost": cost,
                    "tail": tail, "session": session,
                    "report_needs_input":
                        bool(rep.get("needs_input")) if rep else False})
    return out


def verdict_rows(rd):
    """The reviewers' own words: the LATEST recorded verdict per task from
    reviews/ (the note with it) -- the panel showed chips and states while
    the substance, the reviewer's evidence, sat unread on disk."""
    out = {}
    rdir = os.path.join(rd, "reviews")
    if not os.path.isdir(rdir):
        return []
    for n in sorted(os.listdir(rdir)):
        p = os.path.join(rdir, n)
        if not n.endswith(".json") or not os.path.isfile(p):
            continue
        try:
            d = json.load(open(p, encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if not isinstance(d, dict) or "task" not in d:
            continue
        prev = out.get(d["task"])
        if prev is None or str(d.get("signed_at", "")) > str(prev.get("signed_at", "")):
            out[d["task"]] = {"task": d["task"],
                              "verdict": d.get("verdict", "?"),
                              "note": str(d.get("note", ""))[:600],
                              "signed": bool(d.get("signed")),
                              "attempt": d.get("attempt", "-"),
                              "signed_at": d.get("signed_at", "-")}
    rows = sorted(out.values(), key=lambda r: str(r["task"]))
    return rows


def mail_rows(rd):
    """The op seat's queued mail, bodies whole: pending-notes/<task>.md is
    what the NEXT attempt of the task carries -- the inter-agent message
    the panel until now showed only as a byte count."""
    out = []
    pdir = os.path.join(rd, "pending-notes")
    if not os.path.isdir(pdir):
        return []
    for n in sorted(os.listdir(pdir)):
        p = os.path.join(pdir, n)
        if not n.endswith(".md") or not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8", errors="replace") as f:
            body = f.read(4096)
        out.append({"task": n[:-3], "body": body})
    return out


def census_view(rd):
    """The census, read back through census.py report ITSELF (the counting
    law is the CLI's, executed -- a copied loop would silently diverge the
    day the census law changes; the review round named that class). Rows
    live where the shims were installed -- the run's own dir first, then the
    engine home; absent logs are stated with the paths."""
    looked = []
    for base in (rd, spawn_mod.operator_home()):
        p = os.path.join(base, "census.jsonl")
        looked.append(p)
        if os.path.isfile(p):
            r = subprocess.run([sys.executable,
                                os.path.join(ROOT, "bin", "census.py"),
                                "report", p],
                               capture_output=True, text=True, timeout=30,
                               stdin=subprocess.DEVNULL)
            line = (r.stdout + r.stderr).strip().splitlines()
            m = re.search(r"rows=(\d+) admit=(\d+) refuse=(\d+)",
                          line[-1] if line else "")
            if not m:
                return {"log": p, "rows": 0, "admit": 0, "refuse": 0,
                        "cli": _clean((r.stdout + r.stderr)[:200])}
            return {"log": p, "rows": int(m.group(1)),
                    "admit": int(m.group(2)), "refuse": int(m.group(3))}
    return None


def egress_rows_view(rd):
    """The broker's own log rows, if this run recorded one. The broker's log
    path is chosen at serve time; a run without one says so."""
    p = os.path.join(rd, "broker.log")
    if not os.path.isfile(p):
        return None
    rows = []
    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                rows.append(line.rstrip("\n"))
    return {"log": p, "rows": rows[-EGRESS_ROWS:]}


def build_doc(run_name):
    """Everything the page shows, gathered. One subprocess pair for parity,
    module calls for the rest -- all engine laws, zero panel arithmetic."""
    rd = run_mod.run_dir_of(run_name)
    doc = {"schema": JSON_SCHEMA, "status": run_doc(run_name),
           "approvals": [r for r in approvals_doc() if r.get("run") == run_name]
                        or [{"run": run_name, "state": "?", "waiting": []}],
           "matrix": None, "prog": None, "budget": budget_rows(rd),
           "attempts": attempt_cards(rd), "census": census_view(rd),
           "verdicts": verdict_rows(rd), "mail": mail_rows(rd),
           "egress": egress_rows_view(rd),
           "events": run_mod.read_events(rd)[-EVENT_ROWS:]}
    m, prog = matrix_rows(rd)
    doc["matrix"], doc["prog"] = m, prog
    return doc


# --- the page ---------------------------------------------------------------------------


def _bar(settled, reserved, cap=None):
    """A two-tone bar: settled fills, reserved hatches. Scales against the
    seat's ruled USD cap when known, falling back to settled + reserved."""
    total = settled + reserved
    denom = max(float(cap), total) if (cap and cap > 0) else total
    sp = f"{settled / denom * 100:.1f}" if denom else "0"
    rp = f"{reserved / denom * 100:.1f}" if denom else "0"
    return (f'<div class=bar><i style="width:{sp}%"></i><b style="width:{rp}%">'
            f"</b></div>")


def _verb_button(fix, live):
    """The named fix as a button. Live (served) pages POST the whitelisted
    verb through run.py; a fix that maps to no verb, and every fix on a
    static render, COPIES the command instead -- the static page is inert.
    The mapping is the same whitelist POST /verb enforces. The run/task/
    attempt arguments are parsed HERE, server-side, and ride as data
    attributes -- the client never re-parses the fix line (a client-side
    word-split answered the wrong task: the review round fired it)."""
    m = re.match(r"^(run\.py|review\.py)\s+(\S+)\s+(\S+)(?:\s+(\S+))?", fix)
    verb = m.group(2) if m else ""
    args = m.groups()[2:] if m else ()
    task = attempt = ""
    if m and m.group(1) == "run.py":
        # run.py reply <run> <task> / run.py cancel <run> <attempt>
        if verb == "reply" and args[1]:
            task = args[1]
        elif verb == "cancel" and args[1]:
            attempt = args[1]
    if live and verb in VERB_ARGV:
        cmd = fix.replace("run.py", "python3 bin/run.py", 1) \
            if m.group(1) == "run.py" else fix
        return (f'<button class=verb data-verb="{esc(verb)}" '
                f'data-run="{esc(args[0] if args and args[0] else "")}" '
                f'data-task="{esc(task)}" '
                f'data-attempt="{esc(attempt)}" '
                f'data-fix="{esc(fix)}">{esc(verb)}</button>'
                f'<code class=fix>{esc(cmd)}</code>')
    return (f'<button class=copy data-fix="{esc(fix)}">copy</button>'
            f'<code class=fix>{esc(fix)}</code>')


def render_page(doc, token=None):
    """The static page. Inline CSS only; JS only for copy buttons, drawers and
    the live tail -- the page READS fine with JS off (details/summary)."""
    st = doc["status"]
    run_name = st.get("run", "?")
    state = esc(st.get("state", "?"))
    r = [f"""<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>operator panel -- {esc(run_name)}</title>
<style>
:root{{--bg:#101418;--fg:#d7dee6;--dim:#8b98a5;--line:#232b33;--acc:#4cc38a;
--warn:#e5a00d;--bad:#e5534b;--res:#2d5a88}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 ui-monospace,Menlo,Consolas,monospace}}
header{{padding:14px 18px;border-bottom:1px solid var(--line)}}
header .sub{{color:var(--dim);font-size:12px;margin-top:4px}}
h2{{font-size:13px;letter-spacing:.08em;color:var(--dim);margin:22px 18px 8px;
text-transform:uppercase}}
.chip{{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;
border:1px solid var(--line)}}
.chip.passed,.chip.promoted,.chip.settled,.chip.green,.chip.contract-ok,.chip.done{{color:var(--acc);
border-color:var(--acc)}}
.chip.escalated,.chip.unknown,.chip.refused,.chip.contract-red{{color:var(--bad);border-color:var(--bad)}}
.chip.running,.chip.reserved{{color:var(--warn);border-color:var(--warn)}}
.chip.ready{{color:var(--fg)}}
.chip.blocked,.chip.reviewing,.chip.collected,.chip.candidate{{color:#9ab}}
table{{border-collapse:collapse;margin:0 18px;max-width:calc(100% - 36px)}}
td,th{{border:1px solid var(--line);padding:4px 9px;text-align:left;
vertical-align:top;font-size:13px}}
th{{color:var(--dim);font-weight:400}}
.dock{{display:flex;gap:26px;flex-wrap:wrap;padding:10px 18px;
border-bottom:1px solid var(--line);font-size:13px}}
.dock .seat b{{color:var(--dim);font-weight:400}}
.bar{{display:inline-block;width:180px;height:9px;border:1px solid var(--line);
border-radius:5px;overflow:hidden;vertical-align:middle;margin:0 8px;
background:var(--line)}}
.bar i,.bar b{{display:inline-block;height:100%}}
.bar i{{background:var(--acc)}}.bar b{{background:var(--res)}}
.card{{border:1px solid var(--line);border-radius:6px;margin:8px 18px;
padding:10px 12px}}
.card .head{{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline}}
.card .meta{{color:var(--dim);font-size:12px}}
.meta{{color:var(--dim);font-size:12px;margin:4px 18px;display:block}}
.hooks{{margin-top:8px}}
.hook{{border-left:2px solid var(--line);padding:2px 8px;margin:3px 0;
font-size:12px;overflow-wrap:anywhere}}
.hook .tool{{color:var(--acc)}}
button{{background:#1a222b;color:var(--fg);border:1px solid var(--line);
border-radius:4px;padding:2px 10px;font:inherit;cursor:pointer}}
button:hover{{border-color:var(--acc)}}
code.fix{{color:var(--dim);font-size:12px;overflow-wrap:anywhere}}
details{{margin:8px 18px}}summary{{cursor:pointer;color:var(--dim)}}
.q{{border:1px solid var(--warn);border-radius:6px;margin:8px 18px;
padding:10px 12px}}
.q .what{{margin:2px 0}}
.empty{{color:var(--dim);margin:4px 18px;font-size:13px}}
.evt{{margin:0 18px;font-size:12px;color:var(--dim)}}
.evt b{{color:var(--fg);font-weight:400}}
#live{{margin:0 18px;font-size:12px;color:var(--acc);white-space:pre-wrap}}
footer{{color:var(--dim);font-size:11px;padding:16px 18px;
border-top:1px solid var(--line);margin-top:24px}}
</style></head><body>
<header><div>operator panel -- run <b>{esc(run_name)}</b>
<span class="chip {state}">{state}</span>
{('<span class="chip escalated">red: notified</span>') if st.get('red') else ''}
{('<span class="chip running">STOP set</span>') if st.get('stop') else ''}
{f'<span class="chip">autonomy {esc(st.get("autonomy"))}</span>' if st.get('autonomy') else ''}
</div>
<div class=sub>view not truth -- the header is run.py status --json, the queue
is approvals --json, the cards are audit-hook lines; nothing here is state the
panel computed.</div></header>"""]
    if st.get("cli"):
        r.append(f'<div class=q><div class=what>status CLI: {esc(st["cli"])}</div>'
                 f'<code class=fix>the header shows the failure itself</code></div>')
    # the budget dock: reserved vs settled per seat
    seats = doc["budget"]
    if seats:
        r.append('<div class=dock>')
        for seat, s in sorted(seats.items()):
            cap_txt = f' / cap ${s["cap"]:.2f}' if s.get("cap") else ""
            r.append(f'<div class=seat><b>{esc(seat)}</b> '
                     f'{_bar(s["settled"], s["reserved"], s.get("cap"))}'
                     f'settled ${s["settled"]:.4f} / reserved ${s["reserved"]:.4f}'
                     f'{cap_txt}'
                     f' &middot; attempts {s["attempts"]}'
                     + (f' &middot; released {s["released"]}'
                        if s["released"] else "")
                     + "</div>")
        r.append("</div>")
    else:
        r.append('<div class=empty>no ledger rows yet -- reservations appear '
                 "here when run.py reserve writes them</div>")
    # the escalation queue with named-fix verbs
    waiting = []
    for blk in doc["approvals"]:
        waiting.extend(blk.get("waiting") or [])
    r.append("<h2>escalation queue</h2>")
    if not waiting:
        r.append('<div class=empty>nothing waits on a human -- '
                 "run.py approvals --json returned no rows for this run</div>")
    else:
        for w in waiting:
            fix = w.get("fix") or ""
            what = w.get("what") or w.get("task") or ""
            r.append(f'<div class=q><span class="chip '
                     f'{esc(w.get("kind", ""))}">{esc(w.get("kind", "?"))}</span>'
                     f'<div class=what>{esc(_clean(what))}</div>'
                     + (_verb_button(fix, token is not None) if fix else "")
                     + "</div>")
    # the run matrix
    r.append("<h2>run matrix</h2>")
    if doc["matrix"] is None:
        r.append(f'<div class=empty>no matrix -- the program dir moved or is '
                 f"gone ({esc(doc['prog'] or 'unrecorded')}); task_states reads "
                 "it live, so pass --run on a host where it exists</div>")
    else:
        r.append("<table><tr><th>task</th><th>seat</th><th>stage</th>"
                 "<th>deps</th><th>state</th><th>detail</th></tr>")
        for t in doc["matrix"]:
            r.append(f'<tr><td>{esc(t["task"])}</td><td>{esc(t["seat"])}</td>'
                     f'<td>{esc(t["stage"])}</td>'
                     f'<td>{esc(" ".join(t["deps"]) or "-")}</td>'
                     f'<td><span class="chip {esc(t["state"])}">'
                     f'{esc(t["state"])}</span></td>'
                     f'<td>{esc(_clean(t["detail"]))}</td></tr>')
        r.append("</table>")
    # the attempts: delivery chips + tool-call cards
    r.append("<h2>attempts</h2>")
    if not doc["attempts"]:
        r.append('<div class=empty>no attempts yet -- run.py reserve and spawn '
                 "write them under runs/&lt;run&gt;/attempts/</div>")
    for a in doc["attempts"]:
        chips = " ".join(f'<span class="chip {esc(c)}">{esc(c)}</span>'
                         for c in a["chips"])
        extra = ""
        if a["timed_out"]:
            extra = '<span class="chip escalated">timed out</span>'
        if a["report_needs_input"]:
            extra += '<span class="chip blocked">asks for input</span>'
        r.append(f"""<details class=card{" open" if a["state"] in ("started",) else ""}><summary>
<span class="chip {esc(a["state"])}">{esc(a["state"])}</span>
<b>{esc(a["name"])}</b> seat={esc(a["seat"])} task={esc(a["task"])}
rc={esc(a["rc"]) if a["rc"] is not None else "?"} {chips} {extra}
<span class=meta>{esc(a["cost"])}</span></summary>
<div class=hooks>""")
        if a["hooks"]:
            r.append(f'<div class=meta>{len(a["hooks"])} tool call(s), '
                     "newest last, from hook.jsonl:</div>")
            for line in a["hooks"]:
                tool, _, payload = line.partition(" ")
                r.append(f'<div class=hook><span class=tool>{esc(tool)}</span> '
                         f"{esc(_clean(payload))}</div>")
        else:
            r.append('<div class=meta>no tool calls logged (hook.jsonl absent '
                     "or empty)</div>")
        if a.get("session"):
            s = a["session"]
            r.append(f'<div class=meta>session ({esc(s["cli"])}): '
                     f'<code>{esc(s["id"])}</code> &middot; replay: '
                     f'<code>{esc(s["replay"])}</code></div>')
        if a["tail"]:
            r.append('<div class=meta>transcript tail (last 40 lines of '
                     "transcript.out):</div>")
            for line in a["tail"]:
                r.append(f'<div class=hook>{esc(_clean(line))}</div>')
        else:
            r.append('<div class=meta>no transcript bytes (transcript.out '
                     "absent or empty)</div>")
        r.append("</div></details>")
    # the reviewers' own words: the latest verdict per task, note with it
    r.append("<h2>review verdicts</h2>")
    if doc.get("verdicts"):
        for v in doc["verdicts"]:
            cls = "promoted" if v["verdict"] == "green" else "escalated"
            sig = " signed" if v["signed"] else " unsigned"
            r.append(f'<details class=card><summary><span class="chip {cls}">'
                     f'{esc(v["verdict"])}</span> <b>{esc(v["task"])}</b>'
                     f'<span class=meta>{esc(str(v["attempt"]))}{sig} '
                     f'at {esc(str(v["signed_at"]))}</span></summary>'
                     f'<div class=hook>{esc(_clean(v["note"]))}</div>'
                     "</details>")
    else:
        r.append('<div class=empty>no recorded verdicts yet (reviews/)</div>')
    # the op seat's queued mail: bodies whole, fenced by esc
    r.append("<h2>queued mail (op replies)</h2>")
    if doc.get("mail"):
        for m in doc["mail"]:
            r.append(f'<details class=card><summary><b>{esc(m["task"])}</b>'
                     '<span class=meta>rides the next attempt</span></summary>'
                     f'<div class=hook>{esc(_clean(m["body"]))}</div></details>')
    else:
        r.append('<div class=empty>no pending notes (pending-notes/)</div>')
    # census and egress, read-only
    r.append("<h2>census</h2>")
    if doc["census"]:
        c = doc["census"]
        bad = ' escalated' if c["refuse"] else " green"
        r.append(f'<div class=dock><div><span class="chip{bad}">'
                 f'rows={c["rows"]} admit={c["admit"]} refuse={c["refuse"]}'
                 f'</span> <span class=meta>{esc(c["log"])}'
                 + (f' -- {esc(c["cli"])}' if c.get("cli") else "")
                 + "</span></div></div>")
    else:
        r.append('<div class=empty>no census log -- rows land where the shims '
                 "were installed (runs/&lt;run&gt;/census.jsonl or "
                 "$OPERATOR_HOME/census.jsonl); census.py report reads them"
                 "</div>")
    r.append("<h2>egress (broker log)</h2>")
    if doc["egress"]:
        e = doc["egress"]
        r.append(f'<div class=meta>{esc(e["log"])} -- newest {len(e["rows"])} '
                 "row(s):</div><table>")
        for row in e["rows"]:
            r.append(f"<tr><td>{esc(_clean(row))}</td></tr>")
        r.append("</table>")
    else:
        r.append('<div class=empty>no broker log in this run -- the broker\'s '
                 "log path is chosen at serve time (broker.py serve ... "
                 "&lt;log&gt;); point it at runs/&lt;run&gt;/broker.log to see "
                 "it here</div>")
    # the timeline
    r.append("<h2>events</h2>")
    if doc["events"]:
        for ev in doc["events"]:
            fields = {k: v for k, v in ev.items()
                      if k not in ("schema", "domain", "generation", "batch")}
            r.append('<div class=evt><b>' + esc(_clean(json.dumps(
                fields, ensure_ascii=True, sort_keys=True))) + "</b></div>")
    else:
        r.append('<div class=empty>no events yet -- log_event writes '
                 "events.jsonl as the run lives</div>")
    r.append('<div id=live></div>')
    # the tail hookup and the verbs; inert without a server
    r.append(f"""<script>
var TOKEN = {jslit(token)};
function copyText(t){{var ta=document.createElement('textarea');ta.value=t;
document.body.appendChild(ta);ta.select();document.execCommand('copy');
ta.remove();}}
document.addEventListener('click',function(e){{
 var b=e.target.closest('button');if(!b)return;
 if(b.classList.contains('copy')){{copyText(b.dataset.fix);b.textContent='copied';
  setTimeout(function(){{b.textContent='copy';}},1200);return;}}
 if(b.classList.contains('verb')){{
  var body={{verb:b.dataset.verb,run:b.dataset.run||{jslit(run_name)}}};
  if(b.dataset.verb==='cancel'&&b.dataset.attempt){{
   body.attempt=b.dataset.attempt;}}
  if(b.dataset.verb==='reply'){{
   body.task=b.dataset.task||'';
   var note=prompt('reply note (rides the next attempt\\'s mail):');
   if(note===null)return;body.note=note;}}
  fetch('/verb',{{method:'POST',headers:{{'content-type':'application/json',
   'x-panel-token':TOKEN}},body:JSON.stringify(body)}})
  .then(function(x){{return x.json();}})
  .then(function(j){{b.textContent=b.dataset.verb+' rc='+j.rc;
   setTimeout(function(){{location.reload();}},900);}})
  .catch(function(){{copyText(b.dataset.fix);b.textContent='copied (no server)';}});
 }});
if(TOKEN && window.EventSource){{
 var es=new EventSource('/tail');
 es.onmessage=function(e){{var d=document.getElementById('live');
  var l=document.createElement('div');l.textContent=e.data;
  d.appendChild(l);while(d.childNodes.length>50)d.removeChild(d.firstChild);}};
}}
</script><footer>operator panel v1 -- static render; every number came from an
engine file or CLI. Verbs: stop resume cancel reply only; signatures and
verdicts stay in the CLI (decision 18).</footer></body></html>""")
    return "\n".join(r)


# --- render -----------------------------------------------------------------------------


def cmd_render(run_name, out_path):
    home = spawn_mod.operator_home()
    if not run_name:
        runs = []
        root = os.path.join(home, "runs")
        if os.path.isdir(root):
            for n in sorted(os.listdir(root)):
                if os.path.isfile(os.path.join(root, n, "run.json")):
                    runs.append(n)
        if not runs:
            die("no runs exist under " + home,
                "start one: run.py start <program-dir> --run <name>")
        run_name = runs[0]
        if len(runs) > 1:
            print(f"runs: {' '.join(runs)} (showing {runs[0]}; pass --run "
                  "to pick another)", file=sys.stderr)
    doc = build_doc(run_name)
    page = render_page(doc)
    if out_path == "-":
        sys.stdout.write(page + "\n")
        return {"schema": JSON_SCHEMA, "run": run_name, "out": "-",
                "bytes": len(page)}
    if not out_path:
        out_path = os.path.join(spawn_mod.operator_home(), "runs", run_name,
                                "panel.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page + "\n")
    print(f"panel: {out_path} ({len(page)} bytes)")
    return {"schema": JSON_SCHEMA, "run": run_name, "out": out_path,
            "bytes": len(page)}


# --- serve ------------------------------------------------------------------------------


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, run_name, port):
        self.run_name = run_name
        self.token = secrets.token_hex(16)   # per boot; foreign pages can't read it
        baddr = os.environ.get("OPERATOR_PANEL_BIND", "127.0.0.1")
        if baddr not in ("127.0.0.1", "0.0.0.0"):
            raise ValueError(f"OPERATOR_PANEL_BIND must be 127.0.0.1 or 0.0.0.0, got {baddr!r}")
        if baddr == "0.0.0.0":
            super().__init__(("0.0.0.0", port), PanelHandler)
        else:
            super().__init__(("127.0.0.1", port), PanelHandler)


class PanelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "operator-panel/1"

    def log_message(self, *a):
        pass  # a view that narrates is a log, not a panel

    def _origin_ok(self):
        """A foreign page must not drive the verbs: the Host is pinned to the
        loopback origin this server answers on (a DNS-rebind or cross-site
        POST carries its own)."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return host in ("127.0.0.1", "localhost", "::1")

    def _reply(self, code, body, ctype="text/plain; charset=utf-8",
               extra=()):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'; "
                         "form-action 'none'; frame-ancestors 'none'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # the Host pin guards READS too: the page carries the per-boot token
        # and the tail streams events -- a rebind attacker's same-origin
        # fetch('/') must not read either (the review round fired it)
        if not self._origin_ok():
            self._reply(403, "panel: refused -- the Host header names a "
                             "foreign origin; this panel answers on "
                             "loopback only")
            return
        if self.path == "/":
            try:
                page = render_page(build_doc(self.server.run_name),
                                   token=self.server.token)
            except Exception as e:  # a run that won't read shows as itself
                self._reply(500, f"panel: the run won't render: {e}")
                return
            self._reply(200, page, "text/html; charset=utf-8")
            return
        if self.path == "/tail":
            self._tail()
            return
        self._reply(404, "panel: no such page; / and /tail only")

    def _tail(self):
        """The thin live tail: events.jsonl as it grows, one SSE line each.
        Read-only; it never writes run state."""
        rd = run_mod.run_dir_of(self.server.run_name)
        path = os.path.join(rd, "events.jsonl")
        # the connect point is snapshotted BEFORE the headers go out: the
        # stream begins at the size the file had the moment the client asked,
        # whatever the scheduler does between the flush and the first poll
        pos = os.path.getsize(path) if os.path.isfile(path) else 0
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.flush()
        except OSError:
            return
        deadline = time.time() + 3600
        while time.time() < deadline:
            got = False
            if os.path.isfile(path):
                with open(path, encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    for line in f:
                        if line.strip():
                            data = _clean(line.rstrip("\n"))
                            self.wfile.write(f"data: {data}\n\n".encode(
                                "utf-8", "replace"))
                            got = True
                    pos = f.tell()
            if got:
                try:
                    self.wfile.flush()
                except OSError:
                    return
            else:
                try:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                except OSError:
                    return
            time.sleep(1.0)

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reply(400, "panel: the Content-Length isn't a number")
            return
        if n > BODY_CAP:
            self._reply(413, "panel: the POST body is past the cap")
            return
        if not self._origin_ok():
            self._reply(403, "panel: refused -- the Host header names a "
                             "foreign origin; this panel answers on "
                             "loopback only")
            return
        if self.headers.get("X-Panel-Token") != self.server.token:
            self._reply(403, "panel: refused -- the panel token is missing or "
                             "wrong; the page served here carries it")
            return
        if self.path != "/verb":
            self._reply(404, "panel: no such page; / and /tail only")
            return
        try:
            body = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            self._reply(400, "panel: the POST body isn't JSON")
            return
        self._verb(body)

    def _verb(self, body):
        """Run ONE whitelisted engine verb through run.py, argv FIXED per
        verb (never a shell, never a composed string). Everything else --
        verdicts, signatures, gc, anything unnamed -- refuses BY NAME. Every
        field is type-checked BEFORE it touches argv: a JSON type is input,
        and input refuses, it never crashes the thread."""
        if not isinstance(body, dict):
            self._reply(400, "panel: the verb body isn't an object")
            return
        verb = body.get("verb")
        if not isinstance(verb, str):
            self._reply(400, "panel: the verb isn't a string")
            return
        if verb not in VERB_ARGV:
            self._reply(403, f"panel: {verb!r} is not a panel verb; the "
                             f"panel runs {sorted(VERB_ARGV)} through run.py, "
                             "and signatures and verdicts stay in the CLI "
                             "(decision 18)")
            return
        maker = VERB_ARGV.get(verb)  # reply's None rides its own note path
        run_name = body.get("run") or self.server.run_name
        # one panel serves ONE run: a body naming another run is a request
        # this panel never made (the verbs stay scoped to what's on screen)
        if run_name != self.server.run_name:
            self._reply(403, f"panel: this panel serves "
                             f"{self.server.run_name!r}, not {run_name!r}")
            return
        if not isinstance(run_name, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", run_name):
            self._reply(400, "panel: the run name isn't "
                             "[a-z0-9][a-z0-9._-]{0,63}")
            return
        if verb == "reply":
            task = body.get("task") or ""
            note = body.get("note")
            if not isinstance(task, str) or not re.fullmatch(
                    r"[a-z0-9][a-z0-9._-]{0,63}", task):
                self._reply(400, "panel: the reply names no valid task")
                return
            if not isinstance(note, str) or not note.strip():
                self._reply(400, "panel: the reply carries no note")
                return
            if len(note.encode("utf-8")) > NOTE_CAP:
                self._reply(413, f"panel: the note is past {NOTE_CAP} bytes")
                return
            fd, tmp = tempfile.mkstemp(prefix="panel-note.")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(note)
                argv = [sys.executable, os.path.join(ROOT, "bin", "run.py"),
                        "reply", run_name, task, "--note", tmp]
                p = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=60, stdin=subprocess.DEVNULL)
            finally:
                os.unlink(tmp)
            self._reply(200, json.dumps({"rc": p.returncode,
                                         "out": _clean(p.stdout + p.stderr)
                                         [:2000]}),
                        "application/json")
            return
        # only cancel names an attempt; stop and resume take none
        attempt = body.get("attempt") or "" if verb == "cancel" else ""
        if verb == "cancel" and (not isinstance(attempt, str) or not
                                 re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",
                                              attempt)):
            self._reply(400, "panel: the attempt name isn't a name "
                             "([a-z0-9][a-z0-9._-]{0,63})")
            return
        args = maker({"run": run_name, "attempt": attempt})
        if verb == "cancel" and not re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", args[2]):
            self._reply(400, "panel: cancel names no valid attempt")
            return
        argv = [sys.executable, os.path.join(ROOT, "bin", "run.py"), *args]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL)
        self._reply(200, json.dumps(
            {"rc": p.returncode, "out": _clean(p.stdout + p.stderr)[:2000]},
            ensure_ascii=True), "application/json")


def cmd_serve(run_name, port):
    srv = PanelServer(run_name or _first_run(), port)
    bound = srv.socket.getsockname()[1]
    # the address is a literal, not an interpolation: the bind law pins it
    print(f"panel: http://127.0.0.1:{bound}/  (token rides the page; verbs: "
          f"{sorted(VERB_ARGV)})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def _first_run():
    home = spawn_mod.operator_home()
    root = os.path.join(home, "runs")
    if os.path.isdir(root):
        for n in sorted(os.listdir(root)):
            if os.path.isfile(os.path.join(root, n, "run.json")):
                return n
    die("no runs exist under " + home,
        "start one: run.py start <program-dir> --run <name>")


# --- selftests ---------------------------------------------------------------------------


def _fixture_run(home, hostile=False, empty_ledger=False):
    """A run dir under a throwaway home: ledger, events, an escalation with a
    named fix, one attempt with hooks and markers. The shapes are the engine's
    own, exactly what run.py and spawn.py write."""
    rd = os.path.join(home, "runs", "rn1")
    os.makedirs(os.path.join(rd, "attempts", "a1"), exist_ok=True)
    run = {"schema": 1, "run": "rn1", "state": "running", "autonomy": "a2",
           "notified": False}
    with open(os.path.join(rd, "run.json"), "w") as f:
        json.dump(run, f)
    task = "t<script>alert(1)</script>" if hostile else "build.check"
    rows = ("a1\tw\t" + task + "\t4.0000\topen\t2026-11-13T00:00:00Z\n"
            "a0\tw\tdone.now\t0.1200\tsettled\t2026-11-13T00:01:00Z\n"
            "a9\tw\tgone.try\t2.0000\treleased\t2026-11-13T00:02:00Z\n")
    if empty_ledger:
        rows = ""
    with open(os.path.join(rd, "ledger.tsv"), "w") as f:
        f.write(rows)
    with open(os.path.join(rd, "events.jsonl"), "w") as f:
        f.write(json.dumps({"schema": 1, "kind": "reserve", "ts":
                            "2026-11-13T00:00:00Z", "attempt": "a1",
                            "domain": None, "generation": None,
                            "batch": None}) + "\n")
    esc = os.path.join(rd, "escalations")
    os.makedirs(esc, exist_ok=True)
    body = ("# escalation: needs_input\n\nattempt a1 asks for input\n\n"
            "fix: run.py reply rn1 " + ("t1" if not hostile else "t1") +
            " --note F.md\n")
    if hostile:
        # the ESC rides the FIRST line: approvals reads the head and the fix
        # lines only, so that is the channel a control byte really takes
        body = ("# escalation: <script>alert(2)</script>\x1b[31m\n\n"
                "what with an escape\n\n"
                "fix: run.py reply rn1 t1 --note F.md\n")
    with open(os.path.join(esc, "20261113T000000Z-episode.md"), "w") as f:
        f.write(body)
    adir = os.path.join(rd, "attempts", "a1")
    with open(os.path.join(adir, "attempt.json"), "w") as f:
        json.dump({"id": "a1", "seat": "w", "task": task, "grants": ["src/**"],
                   "ref": "integration/R", "seats": [],
                   "prog": os.path.join(home, "prog")}, f)
    with open(os.path.join(adir, "supervisor.json"), "w") as f:
        json.dump({"pid": None, "rc": 0, "timed_out": False}, f)
    with open(os.path.join(adir, "hook.jsonl"), "w") as f:
        f.write('Bash {"command":"ls -la"}\n'
                'Write {"path":"/w/out/report.json"}\n')
    with open(os.path.join(adir, "collected.json"), "w") as f:
        json.dump([{"file": "report.json",
                    "body": json.dumps({"needs_input": True,
                                        "summary": hostile and
                                        "<script>alert(3)</script>" or
                                        "did the thing"})}], f)
    return rd


def _fixture_prog(home):
    prog = os.path.join(home, "prog")
    os.makedirs(os.path.join(prog, "roles"), exist_ok=True)
    with open(os.path.join(prog, "roles", "w.md"), "w") as f:
        f.write("You are the w seat.\n")
    with open(os.path.join(prog, "team.toml"), "w") as f:
        f.write('schema = 1\nname = "t"\nmax_parallel = 1\n[seat.w]\n'
                'role = "roles/w.md"\nadapter = "stub"\n')
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "build.check"\nstage = "s"\n'
                'desc = "d"\nkind = "run"\ncmd = "true"\nseat = "w"\n'
                'reviewer = "r"\n')
    return prog


def selftest():
    import shutil
    import urllib.request
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="panel.")
    try:
        # ---- render: parity, bars, queue, cards -------------------------
        home = os.path.join(base, "h1")
        os.environ["OPERATOR_HOME"] = home
        os.makedirs(os.path.join(home, "runs"))
        _fixture_prog(home)
        rd = _fixture_run(home)
        doc = build_doc("rn1")
        page = render_page(doc)
        check(doc["status"].get("state") in ("running",)
              and "run.py" not in doc["status"].get("cli", ""),
              "A1 status parity: the header doc is run.py status --json")
        check("operator panel -- run <b>rn1</b>" in page,
              "A2 the header names the run")
        check("settled $0.1200 / reserved $4.0000" in page
              and "attempts 3" in page and "released 1" in page,
              "A3 reserved-vs-settled bars ride the ledger")
        check("run.py reply rn1 t1 --note F.md" in page
              and "class=copy" in page and "class=verb" not in page,
              "A4 the static queue copies the named fix (inert by design)")
        check("Bash" in page and "ls -la" in page and "Write" in page,
              "A5 tool-call cards render hook.jsonl")
        # A5b out/hook.jsonl takes precedence over legacy root hook.jsonl,
        # budget bar scales against ruled cap, and contract.json renders a chip
        os.makedirs(os.path.join(rd, "attempts", "a1", "out"), exist_ok=True)
        with open(os.path.join(rd, "attempts", "a1", "out", "hook.jsonl"), "w") as f:
            f.write('Read {"path":"src/live.py"}\n')
        with open(os.path.join(rd, "attempts", "a1", "contract.json"), "w") as f:
            json.dump({"ok": True, "receipts": []}, f)
        page_out = render_page(build_doc("rn1"))
        check("src/live.py" in page_out and "contract-ok" in page_out,
              "A5b panel reads out/hook.jsonl and renders contract-ok chip")
        check('width:10.0%' in _bar(1.0, 0.0, cap=10.0),
              "A5c budget bar scales against ruled cap instead of showing 100%")
        os.unlink(os.path.join(rd, "attempts", "a1", "out", "hook.jsonl"))
        os.unlink(os.path.join(rd, "attempts", "a1", "contract.json"))
        # A5d symlinked out/hook.jsonl pointing at a host secret MUST NOT be read
        host_sec = os.path.join(base, "host-secret.txt")
        with open(host_sec, "w") as f:
            f.write("TOP-SECRET-HOST-CANARY-991\n")
        os.symlink(host_sec, os.path.join(rd, "attempts", "a1", "out", "hook.jsonl"))
        page_sym = render_page(build_doc("rn1"))
        check("TOP-SECRET-HOST-CANARY-991" not in page_sym,
              "A5d symlinked out/hook.jsonl never leaks host files into panel")
        os.unlink(os.path.join(rd, "attempts", "a1", "out", "hook.jsonl"))
        check(page == render_page(build_doc("rn1")),
              "A6 deterministic: the same run renders to the same bytes")
        # G the observability reads: verdict notes, op mail bodies, and the
        # CLI session link ride the page -- the panel's own data, stated
        rd1 = os.path.join(home, "runs", "rn1")
        os.makedirs(os.path.join(rd1, "reviews"), exist_ok=True)
        with open(os.path.join(rd1, "reviews", "t1-001.json"), "w") as f:
            json.dump({"task": "t1", "verdict": "green", "signed": True,
                       "attempt": "rev-t1-1", "signed_at": "2026-11-18T00:00:00Z",
                       "note": "the reviewer's own words"}, f)
        os.makedirs(os.path.join(rd1, "pending-notes"), exist_ok=True)
        with open(os.path.join(rd1, "pending-notes", "t1.md"), "w") as f:
            f.write("the queued mail body")
        with open(os.path.join(rd1, "attempts", "a1", "transcript.out"), "a") as f:
            f.write('{"sessionId": "sess_g1", "usage": {}}\n')
        page_g = render_page(build_doc("rn1"))
        check("review verdicts" in page_g and "own words" in page_g
              and ">green</span>" in page_g,
              "G the latest verdict note rides the page")
        check("queued mail" in page_g and "the queued mail body" in page_g,
              "G the op mail body rides the page")
        check("session (zcode)" in page_g and "sess_g1" in page_g
              and "zcode tui" in page_g,
              "G the CLI session link and replay ride the attempt card")
        # B hostile bytes never ride the page raw
        home2 = os.path.join(base, "h2")
        os.environ["OPERATOR_HOME"] = home2
        os.makedirs(os.path.join(home2, "runs"))
        _fixture_prog(home2)
        _fixture_run(home2, hostile=True)
        page2 = render_page(build_doc("rn1"))
        check("<script>alert(1)</script>" not in page2
              and "&lt;script&gt;" in page2 and "\x1b" not in page2,
              "B hostile names and escapes render escaped, never raw")
        # C the state comes from the doc, never the file: an empty ledger
        # reads unfired whatever run.json claims
        home3 = os.path.join(base, "h3")
        os.environ["OPERATOR_HOME"] = home3
        os.makedirs(os.path.join(home3, "runs"))
        _fixture_prog(home3)
        _fixture_run(home3, empty_ledger=True)
        doc3 = build_doc("rn1")
        check(doc3["status"].get("state") == "unfired",
              "C an empty ledger reads unfired (the CLI's law, not the file's)")
        check("unfired" in render_page(doc3), "C the page carries it")
        # D dead panels refuse: every emptiness is stated and names its paths
        home4 = os.path.join(base, "h4")
        os.environ["OPERATOR_HOME"] = home4
        rd4 = os.path.join(home4, "runs", "fresh")
        os.makedirs(rd4)
        with open(os.path.join(rd4, "run.json"), "w") as f:
            json.dump({"schema": 1, "state": "running"}, f)
        page4 = render_page(build_doc("fresh"))
        for needle in ("no ledger rows yet", "no attempts yet",
                       "no census log", "no broker log", "no events yet"):
            check(needle in page4, f"D states its emptiness: {needle}")
        # E the server: whitelist, token, host pin, loopback bind, tail
        home5 = os.path.join(base, "h5")
        os.environ["OPERATOR_HOME"] = home5
        os.makedirs(os.path.join(home5, "runs"))
        _fixture_prog(home5)
        _fixture_run(home5)
        srv = PanelServer("rn1", 0)
        check(srv.socket.getsockname()[0] == "127.0.0.1",
              "E1 the server binds loopback only")
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        url = f"http://127.0.0.1:{srv.socket.getsockname()[1]}"

        def post(path, obj, token="x", host=None):
            req = urllib.request.Request(
                url + path, data=json.dumps(obj).encode(),
                headers={"Content-Type": "application/json",
                         "X-Panel-Token": token, "Host": host or
                         f"127.0.0.1:{srv.socket.getsockname()[1]}"})
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, resp.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode()
            except (urllib.error.URLError, OSError) as e:
                # a crashed request thread reads as rc 0 with the crash named:
                # the CHECK decides, never an uncaught traceback
                return 0, f"<crash: {e}>"

        import urllib.error
        code, body = post("/verb", {"verb": "verdict", "run": "rn1"},
                          token=srv.token)
        check(code == 403 and "decision 18" in body and "verdict" in body,
              "E2 a verdict verb refuses BY NAME (no signature surface)")
        code, _ = post("/verb", {"verb": "stop", "run": "rn1"})
        check(code == 403, "E3 a POST without the panel token refuses")
        code, _ = post("/verb", {"verb": "stop", "run": "rn1"},
                       token=srv.token, host="evil.example")
        check(code == 403, "E4 a foreign Host refuses (the rebind pin)")
        code, body = post("/verb", {"verb": "nonsense"}, token=srv.token)
        check(code == 403 and "not a panel verb" in body,
              "E5 an unnamed verb refuses by name")
        # gc IS an engine verb but not a PANEL verb: the whitelist names the
        # four, and a broader engine verb refuses the same way
        code, body = post("/verb", {"verb": "gc", "run": "rn1"},
                          token=srv.token)
        check(code == 403 and "not a panel verb" in body,
              "E5b an engine verb outside the four refuses by name")
        code, body = post("/verb", {"verb": "cancel", "run": "rn1",
                                    "attempt": "../evil"}, token=srv.token)
        check(code == 400, "E6 an attempt name that isn't a name refuses")
        # E6b a JSON type is input and REFUSES, never crashes the thread
        code, body = post("/verb", {"verb": "stop", "run": 5},
                          token=srv.token)
        check(code == 403 and "serves" in body,
              "E6b a run of another name (or type) refuses, no crash")
        code, body = post("/verb", {"verb": ["stop"]}, token=srv.token)
        check(code == 400, "E6c a non-string verb refuses, no crash")
        # the green path: resume on a stopped run logs its own event
        runp = os.path.join(home5, "runs", "rn1", "run.json")
        with open(runp) as f:
            rj = json.load(f)
        rj["state"] = "paused"
        with open(runp, "w") as f:
            json.dump(rj, f)
        open(os.path.join(home5, "runs", "rn1", "STOP"), "w").close()
        code, body = post("/verb", {"verb": "resume", "run": "rn1"},
                          token=srv.token)
        docj = json.loads(body)
        with open(runp) as f:
            rj2 = json.load(f)
        check(code == 200 and docj["rc"] == 0
              and rj2.get("state") == "running"
              and not os.path.exists(os.path.join(home5, "runs", "rn1",
                                                  "STOP")),
              "E7 resume runs THROUGH run.py: the verb, not the panel, moves state")
        check(any(e.get("kind") == "resume" for e in run_mod.read_events(
            os.path.join(home5, "runs", "rn1"))),
              "E7b the verb logged its own event")
        # the page carries the token; the tail streams events
        with urllib.request.urlopen(url + "/", timeout=10) as resp:
            served = resp.read().decode()
            csp = resp.headers.get("Content-Security-Policy") or ""
        check(srv.token in served and "class=verb" in served,
              "F1 the served page carries the token and live verb buttons")
        check("frame-ancestors 'none'" in csp and "connect-src 'self'" in csp,
              "F2 the CSP pins framing and connects to self")
        # F2b the Host pin guards READS too: the page (with its token) and
        # the tail never serve a foreign origin
        try:
            urllib.request.urlopen(urllib.request.Request(
                url + "/", headers={"Host": "evil.example"}), timeout=10)
            got = 200
        except urllib.error.HTTPError as e:
            got = e.code
        check(got == 403, "F2b a foreign Host never reads the page (rebind)")
        # F4 the reply button end to end: the button's OWN data attributes
        # (parsed server-side) name the task; POST exactly what the JS would
        # and the pending note lands for THAT task -- the fired proof of the
        # round's HIGH (a client-side word-split answered 'reply')
        m = re.search(r'data-verb="reply" data-run="([^"]*)" '
                      r'data-task="([^"]*)"', served)
        check(m is not None and m.group(1) == "rn1" and m.group(2) == "t1",
              "F4 the button's server-parsed attrs name run and task")
        if m:
            code, body = post("/verb", {"verb": "reply", "run": m.group(1),
                                        "task": m.group(2),
                                        "note": "the human's answer"},
                              token=srv.token)
            docj = json.loads(body)
            notes = os.path.join(home5, "runs", "rn1", "pending-notes")
            landed = sorted(os.listdir(notes)) if os.path.isdir(notes) else []
            check(code == 200 and docj["rc"] == 0 and landed == ["t1.md"]
                  and "the human's answer" in open(
                      os.path.join(notes, "t1.md")).read(),
                  f"F4b the reply lands for the RIGHT task (got {landed})")
        with urllib.request.urlopen(urllib.request.Request(
                url + "/tail", headers={"Accept": "text/event-stream"}),
                timeout=10) as resp:
            # the tail streams what arrives FROM NOW (append-only): let its
            # start-of-stream size snapshot settle, then write a fresh event
            # and it must come through framed as SSE. Read by line with a
            # deadline -- the stream never ends, so a sized read would wait
            # forever on the keepalives that keep it alive.
            time.sleep(0.5)
            with open(os.path.join(home5, "runs", "rn1", "events.jsonl"),
                      "a") as f:
                f.write(json.dumps({"schema": 1, "kind": "panel-tail-probe",
                                    "ts": "2026-11-13T00:09:00Z"}) + "\n")
            buf, deadline = "", time.time() + 10
            while "panel-tail-probe" not in buf and time.time() < deadline:
                line = resp.readline()
                if not line:
                    break
                buf += line.decode("utf-8", "replace")
        check("panel-tail-probe" in buf and "data:" in buf,
              "F3 the tail streams new events.jsonl lines as SSE")
        srv.shutdown()
        srv.server_close()
        os.environ["OPERATOR_HOME"] = ""
        if ok[0] and not bad[0]:
            print("selftest: OK (render parity, hostile bytes, doc-state law, "
                  "dead panels, whitelist/token/host/tail)")
        else:
            print("selftest: FAIL", file=sys.stderr)
        return 0 if ok[0] and not bad[0] else 1
    finally:
        shutil.rmtree(base, ignore_errors=True)


# --- CLI ---------------------------------------------------------------------------------


USAGE = ("usage: panel.py render [--run R] [--out F|-] | serve [--run R] "
         "[--port N] | --selftest")


def main(argv):
    if len(argv) < 2:
        print(USAGE, file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return selftest()
    verb = argv[1]
    run_name = out_path = None
    port = DEFAULT_PORT
    i = 2
    while i < len(argv):
        if argv[i] == "--run" and i + 1 < len(argv):
            run_name = argv[i + 1]
            i += 2
        elif argv[i] == "--out" and i + 1 < len(argv):
            out_path = argv[i + 1]
            i += 2
        elif argv[i] == "--port" and i + 1 < len(argv):
            try:
                port = int(argv[i + 1])
            except ValueError:
                die(f"the port {argv[i + 1]!r} isn't a number", USAGE)
            i += 2
        else:
            die(f"unknown argument {argv[i]!r}", USAGE)
    if verb == "render":
        cmd_render(run_name, out_path or "")
        return 0
    if verb == "serve":
        return cmd_serve(run_name, port)
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
