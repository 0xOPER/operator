#!/usr/bin/env python3
"""team -- loads team.toml and checks what a seat may do, with no LLM anywhere.

The default for every grant is nothing. Unknown keys refuse at every level, a seat
that isn't human names a role file that exists, and the contract's seats and reviewers
must all exist with the reviewer never the author. Enforceability is conservative by
construction: a grant class demands a verified adapter, and until the adapter manifests
name their tested range (P marks them, C8 writes them) any non-human seat demanding
shell, write, network, read, mcp or model refuses with the reason. Memory, skills and
mcp tables are carried inert this wave: shape-checked, printed as inert, granting
nothing, so the roadmap's own sample team loads without failing open.

Ruling rows must name a human seat. deps can't loop and can't point to a later stage.
A reviewer may hold no prefix that runs repo code. Waivable findings print as
`needs-waiver <name>` and refuse at approve time, not validate time: budget=advisory
(a usd cap the seat's adapter can't enforce), rule-of-two (sensitive access and
external effects in one seat), unreviewed-rows (a writing seat with only some rows
reviewed). Gitlinks and filter=lfs in the base tree refuse by name when the work repo
is named; unsupported at 0.1 either way.

usage: team.py validate <program-dir> [--waive <name>]...
       team.py --selftest
env: CONTRACT_REPO (for the base-tree checks; skipped with a note when unset)
exit: 0 holds, 1 a finding, 2 usage or VOID
"""
import os
import re
import subprocess
import sys
import tempfile
import tomllib

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCHEMA = 1
TOP_KEYS = {"schema", "name", "contract", "autonomy", "max_parallel", "budget", "seat", "mcp"}
SEAT_KEYS = {"role", "adapter", "human", "write", "read", "see", "network", "shell", "mcp",
             "memory", "skills", "budget", "model", "repo_context", "gpu", "ro", "env"}
GRANT_KEYS = {"write", "read", "network", "shell", "mcp", "model"}
INERT_KEYS = ("memory", "skills", "mcp")
AUTONOMY = ("attended", "unattended")
# mounts the jail itself owns: a seat's ro paths never land on or under these
JAIL_OWNED = ("/proc", "/sys", "/dev", "/usr", "/etc", "/bin", "/lib", "/lib64",
              "/sbin", "/tmp", "/run", "/var", "/w", "/work", "/engine", "/env",
              "/prog", "/opt", "/root")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$")
PATH_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/*-]*$")
GLOB_RE = re.compile(r"^[A-Za-z0-9.][A-Za-z0-9._*/-]*$")
REPO_CODE_PREFIXES = ("pytest", "python", "python3", "make", "bash", "sh", "zsh",
                      "node", "npm", "cargo", "go", "ruby", "perl", "git")
INDIRECT_PREFIXES = ("env", "xargs", "timeout", "nohup", "stdbuf", "sudo", "exec", "command")
WAIVERS = ("budget=advisory", "rule-of-two", "unreviewed-rows", "same-family-review")


def model_family(seat_doc):
    """Infer the commercial model family for cross-family review checks.
    Returns None for human seats or stub/test adapters; returns 'unknown' for
    unrecognized custom/gateway model IDs so cross-family enforcement fails closed."""
    if not isinstance(seat_doc, dict) or seat_doc.get("human") is True:
        return None
    adapter = str(seat_doc.get("adapter") or "")
    if not adapter or adapter == "stub" or adapter.startswith("stub"):
        return None
    m = str(seat_doc.get("model") or "").strip().lower()
    if not m:
        adir = os.environ.get("OPERATOR_ADAPTERS") or os.path.join(ROOT, "config", "adapters")
        mpath = os.path.join(adir, f"{adapter}.toml")
        if os.path.isfile(mpath):
            try:
                with open(mpath, "rb") as mf:
                    m = str(tomllib.load(mf).get("default_model") or "").strip().lower()
            except Exception:
                m = ""
    if not m:
        return {
            "claude-code": "anthropic",
            "opencode": "anthropic",
            "codex": "openai",
            "zcode": "glm",
        }.get(adapter, "unknown")
    toks = [t for t in re.split(r"[/._:-]+", m) if t]
    if any(t in ("anthropic", "claude", "sonnet", "opus", "haiku") or t.startswith("claude") for t in toks):
        return "anthropic"
    if any(t in ("openai", "codex", "o1", "o3", "o4") or t.startswith(("gpt", "codex")) for t in toks):
        return "openai"
    if any(t in ("zai", "zhipu", "glm") or t.startswith("glm") for t in toks):
        return "glm"
    if any(t in ("google", "gemini") or t.startswith("gemini") for t in toks):
        return "google"
    if any(t.startswith("deepseek") for t in toks):
        return "deepseek"
    if any(t in ("qwen", "alibaba") or t.startswith("qwen") for t in toks):
        return "qwen"
    if any(t in ("meta", "llama") or t.startswith("llama") for t in toks):
        return "llama"
    if any(t in ("mistral", "codestral", "ministral") or t.startswith(("mistral", "codestral", "ministral")) for t in toks):
        return "mistral"
    return "unknown"


class Void(Exception):
    pass


class Finding(Exception):
    pass


def sh(argv):
    return subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL)


def load(prog):
    """Parses and checks team.toml against contract.toml. Finding = refused (rc 1)."""
    path = os.path.join(prog, "team.toml")
    if not os.path.isfile(path):
        raise Void(f"no team.toml in {prog}")
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise Finding(f"team.toml doesn't parse: {e}")
    except OSError as e:
        raise Void(f"team.toml can't be read: {e}")
    if type(doc.get("schema")) is not int or doc["schema"] != SCHEMA:
        raise Finding(f"schema must be the integer {SCHEMA}, not {doc.get('schema')!r}")
    for k in doc:
        if k not in TOP_KEYS:
            raise Finding(f"unknown top-level key {k!r}")
    for k, how in (("name", str), ("contract", str), ("autonomy", str)):
        if k in doc and not isinstance(doc[k], how):
            raise Finding(f"{k} must be a string")
    if "name" not in doc or not NAME_RE.fullmatch(doc["name"]):
        raise Finding("the team needs a name: [a-z0-9][a-z0-9._-]{0,63}")
    if doc.get("autonomy", "attended") not in AUTONOMY:
        raise Finding(f"autonomy must be one of {' '.join(AUTONOMY)}")
    if "max_parallel" in doc and (not isinstance(doc["max_parallel"], int)
                                  or isinstance(doc["max_parallel"], bool) or doc["max_parallel"] < 1):
        raise Finding("max_parallel must be a positive integer")
    for mname, mtable in (doc.get("mcp") or {}).items():
        if not isinstance(mtable, dict):
            raise Finding(f"[mcp.{mname}] must be a table")
        for k in mtable:
            if k not in ("command", "url", "args"):
                raise Finding(f"[mcp.{mname}] has unknown key {k!r}")
    seats = doc.get("seat")
    if not isinstance(seats, dict) or not seats:
        raise Finding("the team names no seats")
    for sname, seat in seats.items():
        if not NAME_RE.fullmatch(sname):
            raise Finding(f"seat name {sname!r} must be [a-z0-9][a-z0-9._-]{{0,63}}")
        if not isinstance(seat, dict):
            raise Finding(f"seat {sname} isn't a table")
        for k in seat:
            if k not in SEAT_KEYS:
                raise Finding(f"seat {sname} has unknown key {k!r}")
        if seat.get("human") is True:
            for k in seat:
                if k not in ("human", "budget"):
                    raise Finding(f"seat {sname} is human and takes no {k}")
            check_budget(seat.get("budget", {}), f"seat {sname}")
            continue
        role = seat.get("role")
        if not isinstance(role, str) or not role:
            raise Finding(f"seat {sname}: a non-human seat names a role file")
        if not PATH_OK.fullmatch(role) or ".." in role.split("/"):
            raise Finding(f"seat {sname}: role {role!r} must be a program-relative path")
        if not os.path.isfile(os.path.join(prog, role)):
            raise Finding(f"seat {sname}: role file {role!r} doesn't exist")
        if not isinstance(seat.get("adapter"), str) or not seat["adapter"]:
            raise Finding(f"seat {sname}: a non-human seat names an adapter")
        for g in GRANT_KEYS:
            if g in seat:
                check_grant(sname, g, seat[g])
        if "see" in seat:
            # checkout VISIBILITY naming for instruction paths (`CLAUDE.md`,
            # `.github`, etc.) hidden by sparse-checkout unless named in `write`
            # or `see`. It grants no writes (the delivery gate ignores it) and
            # demands no adapter class -- unlike `read`, which is an enforced class.
            see = seat["see"]
            if not isinstance(see, list) or not all(isinstance(v, str) and v for v in see):
                raise Finding(f"seat {sname}: see must be a list of repo-relative path globs")
            for v in see:
                if not GLOB_RE.fullmatch(v) or v.startswith("/") or v.endswith("/") \
                        or ".." in v.split("/"):
                    raise Finding(f"seat {sname}: see {v!r} must be a repo-relative path glob")
        if "repo_context" in seat and seat["repo_context"] not in ("hide", "load"):
            raise Finding(f"seat {sname}: repo_context is hide or load")
        if "env" in seat:
            # the environments this seat may call through its jail's socket
            # (bin/environment.py Door); each one is declared in the charter
            ev = seat["env"]
            if not isinstance(ev, list) or not all(isinstance(v, str) and NAME_RE.fullmatch(v) for v in ev):
                raise Finding(f"seat {sname}: env must be a list of environment names, "
                              "[a-z0-9][a-z0-9._-]{0,63}")
        if "gpu" in seat and not isinstance(seat["gpu"], bool):
            raise Finding(f"seat {sname}: gpu is true or absent")
        if "ro" in seat:
            # read-only host paths the seat's jail mounts at their own paths
            # (the model tree, a dataset): the author's grant, the engine's
            # fence -- nothing the jail already mounts, and nothing that
            # touches the engine's own tree or state in EITHER direction
            # (inside it, or an ANCESTOR of it: /home would cross the engine,
            # its state and every key on the machine), ever crosses. The
            # literal AND its resolution both face the fence: the bind follows
            # the symlink, so the fence must too
            ros = seat["ro"]
            if not isinstance(ros, list) or not ros or \
                    not all(isinstance(v, str) and v for v in ros):
                raise Finding(f"seat {sname}: ro must be a non-empty list of "
                              f"absolute paths")
            eng = os.path.realpath(ROOT)
            default_oph = os.path.join(
                os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"),
                "operator")
            oph = os.path.realpath(os.environ.get("OPERATOR_HOME") or default_oph)
            resolved = [os.path.realpath(v) for v in ros]
            if len(set(resolved)) != len(resolved):
                raise Finding(f"seat {sname}: ro names the same path twice "
                              f"(after resolving); bind it once")
            for v, real in zip(ros, resolved):
                if v == "/" or not v.startswith("/") or ".." in v.split("/"):
                    raise Finding(f"seat {sname}: ro {v!r} must be an absolute host path")
                if real == os.sep or os.path.normpath(v) == os.sep:
                    raise Finding(f"seat {sname}: ro {v!r} resolves to the host "
                                  f"root; name the data path itself")
                for p in (v, real):
                    if any(p == q or p.startswith(q + "/") for q in JAIL_OWNED):
                        raise Finding(f"seat {sname}: ro {v!r} sits on one of the jail's "
                                      f"own mounts; bind a data path instead")
                if not os.path.exists(v):
                    raise Finding(f"seat {sname}: ro {v!r} doesn't exist on this host")
                for mine in (eng, oph):
                    if real == mine or real.startswith(mine + os.sep) or \
                            mine.startswith(real + os.sep):
                        raise Finding(f"seat {sname}: ro {v!r} touches the engine's own "
                                      f"tree or state (or names an ancestor of it); "
                                      f"bind a data path instead")
        if "memory" in seat:
            if not isinstance(seat["memory"], dict):
                raise Finding(f"seat {sname}: memory must be a table of r/w scopes")
            for scope, mode in seat["memory"].items():
                if scope not in ("self", "team") or not isinstance(mode, str) \
                        or set(mode) - set("rw"):
                    raise Finding(f"seat {sname}: memory {scope}={mode!r} isn't r/w scopes")
        if "skills" in seat:
            if not isinstance(seat["skills"], list) or not all(isinstance(x, str) for x in seat["skills"]):
                raise Finding(f"seat {sname}: skills must be a list of paths")
            for sk in seat["skills"]:
                if not PATH_OK.fullmatch(sk) or ".." in sk.split("/") or not sk:
                    raise Finding(f"seat {sname}: skill {sk!r} must be a program-relative path")
                if not os.path.isdir(os.path.join(prog, sk)):
                    raise Finding(f"seat {sname}: skill {sk!r} doesn't exist")
        check_budget(seat.get("budget", {}), f"seat {sname}")
    # a seat's environments are declared ones: the charter the owner signs names them
    declared = _charter_environments(prog)
    for sname, seat in seats.items():
        for n in seat.get("env") or []:
            if n not in declared:
                raise Finding(f"seat {sname}: env names {n!r}, which charter.toml doesn't "
                              f"declare; declare [[environment.{n}]] (docs/charter.md), or drop it")

    cname = doc.get("contract", "contract.toml")
    if not PATH_OK.fullmatch(cname) or ".." in cname.split("/"):
        raise Finding(f"contract {cname!r} must be a program-relative path")
    contract = load_contract(prog, cname)
    # the dep law at LOAD (the review round fired the holes): a dep naming no
    # row, a self-dep, or a cycle parks tasks blocked forever -- refuse the
    # team at the door, where every door (start, tick, next) reads it
    ids = [r.get("id") for r in contract[0]]
    for r in contract[0]:
        for d in r.get("deps") or []:
            if d == r.get("id"):
                raise Finding(f"row {r.get('id')}: a row cannot depend on itself")
            if d not in ids:
                raise Finding(f"row {r.get('id')}: dep {d!r} names no row")
    by_id = {r.get("id"): r for r in contract[0]}

    def reaches(start, cur, seen):
        for d in by_id.get(cur, {}).get("deps") or []:
            if d == start:
                return True
            if d in seen:
                continue
            seen.add(d)
            if reaches(start, d, seen):
                return True
        return False

    for r in contract[0]:
        if reaches(r.get("id"), r.get("id"), set()):
            raise Finding(f"row {r.get('id')}: its deps cycle")
    return doc, seats, contract


def _charter_environments(prog):
    """The environments the program's charter signs; {} without one."""
    if not os.path.isfile(os.path.join(prog, "charter.toml")):
        return {}
    import environment as env_mod
    try:
        return env_mod.specs(prog)
    except env_mod.Finding as e:
        raise Finding(str(e))


def check_budget(b, where):
    if not isinstance(b, dict):
        raise Finding(f"{where} budget must be a table")
    # the minutes a seat may spend inside its environments; the other budget
    # keys are checked below, by their own law
    if "env_minutes" in b and (not isinstance(b["env_minutes"], (int, float))
                               or isinstance(b["env_minutes"], bool)
                               or not (0 <= b["env_minutes"] < float("inf"))):
        raise Finding(f"{where} budget env_minutes must be a non-negative number")
    b = {k: v for k, v in b.items() if k != "env_minutes"}
    for k in b:
        if k not in ("usd", "minutes", "context"):
            raise Finding(f"{where} budget has unknown key {k!r}")
        if not isinstance(b[k], (int, float)) or isinstance(b[k], bool) \
                or b[k] != b[k] or b[k] in (float("inf"), float("-inf")) or b[k] < 0:
            raise Finding(f"{where} budget {k} must be a non-negative number")


def check_grant(sname, kind, value):
    shapes = {"write": "a repo path glob", "read": "a directory path", "network": "a host",
              "shell": "a command prefix", "model": "a model id", "mcp": "a server or tool name"}
    if kind == "model":
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value):
            raise Finding(f"seat {sname}: model must be one {shapes[kind]} ([A-Za-z0-9._:/-]{{1,128}})")
        return
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise Finding(f"seat {sname}: {kind} must be a list of {shapes[kind]}s")
    for v in value:
        if kind == "network":
            if v != "*" and (not HOST_RE.fullmatch(v)
                             or (":" in v and not 0 < int(v.rsplit(":", 1)[1]) < 65536)):
                raise Finding(f"seat {sname}: network {v!r} isn't a host or host:port (1-65535)")
        elif kind in ("write", "read"):
            if not GLOB_RE.fullmatch(v) or v.startswith("/") or v.endswith("/") \
                    or ".." in v.split("/"):
                raise Finding(f"seat {sname}: {kind} {v!r} must be a repo-relative path glob")


def load_contract(prog, name):
    """Loads contract.toml's rows for the cross-checks. Only what validate needs."""
    path = os.path.join(prog, name)
    if not os.path.isfile(path):
        raise Void(f"no {name} in {prog}")
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as e:
        raise Void(f"{name} can't be read: {e}")
    rows = doc.get("row", [])
    out, stages = [], []
    if not isinstance(rows, list):
        raise Void("the contract's rows aren't a list")
    for row in rows:
        if not isinstance(row, dict):
            raise Void("a contract row isn't a table")
        stage = row.get("stage")
        if not isinstance(stage, str):
            raise Void("a contract row has no stage string")
        if stage not in stages:
            stages.append(stage)
        for f in ("id", "seat", "reviewer"):
            if f in row and not isinstance(row[f], str):
                raise Void(f"a contract row's {f} isn't a string")
        if "deps" in row and not isinstance(row["deps"], list):
            raise Void("a contract row's deps aren't a list")
        out.append(row)
    return out, stages


def manifest_classes(prog, adapter):
    """The adapter manifest's tested classes, when it exists. None until P writes one.
    Manifests live in the ENGINE's adapter directory (OPERATOR_ADAPTERS, default the
    core's config/adapters), never in the program: a program author certifying their
    own seat's grants is the self-signature this check exists to refuse."""
    m = os.path.join(os.environ.get("OPERATOR_ADAPTERS") or os.path.join(ROOT, "config", "adapters"),
                     f"{adapter}.toml")
    if not os.path.isfile(m):
        return None
    try:
        with open(m, "rb") as f:
            doc = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError):
        return None
    tc = doc.get("tested_classes")
    if not isinstance(tc, list) or not all(isinstance(c, str) for c in tc) or not tc:
        return []
    return [c for c in tc if c in GRANT_KEYS]


def cmd_validate(prog, waivers):
    doc, seats, contract = load(prog)
    rows, stages = contract
    findings, waivables, notes = [], [], []

    for rid, row in [(r.get("id"), r) for r in rows]:
        seat = row.get("seat")
        rid = rid or "?"
        if seat not in seats:
            findings.append(f"row {rid}: seat {seat!r} isn't on the team")
        reviewer = row.get("reviewer")
        if reviewer is None:
            pass  # an unreviewed row is legal; it feeds the unreviewed-rows waiver below
        elif reviewer not in seats:
            findings.append(f"row {rid}: reviewer {reviewer!r} isn't on the team")
        elif reviewer == seat:
            findings.append(f"row {rid}: the reviewer is the author")
        elif seats[reviewer].get("human") is not True:
            shell = seats[reviewer].get("shell", [])
            for p in shell:
                base = p.split()[0] if p != "*" else "*"
                bad = (p == "*" or base in REPO_CODE_PREFIXES or base in INDIRECT_PREFIXES
                       or "/" in base or base.startswith("."))
                if bad:
                    findings.append(f"row {rid}: reviewer {reviewer} holds repo-code or "
                                    f"indirected prefix {p!r}")
            fam_s = model_family(seats.get(seat))
            fam_r = model_family(seats.get(reviewer))
            same_or_unk = bool(fam_s and fam_r and (
                fam_s == "unknown" or fam_r == "unknown" or fam_s == fam_r
            ))
            if same_or_unk and "same-family-review" not in waivers:
                if "same-family-review" not in waivables:
                    waivables.append("same-family-review")
                notes.append(f"needs-waiver same-family-review: row {rid} pairs {seat} ({fam_s}) and "
                             f"{reviewer} ({fam_r}) on the same or unclassified model family")
        if row.get("kind") == "ruling" and seats.get(seat, {}).get("human") is not True:
            findings.append(f"row {rid}: a ruling row names {seat!r}, which isn't a human seat")
    by_id = {r.get("id"): r for r in rows}
    for rid, row in by_id.items():
        for d in row.get("deps", []):
            if d not in by_id:
                findings.append(f"row {rid} depends on {d}, which doesn't exist")
            elif stages.index(row["stage"]) < stages.index(by_id[d]["stage"]):
                findings.append(f"row {rid} depends on {d}, which sits in a later stage")
    def loops(start, node, path):
        for d in by_id.get(node, {}).get("deps", []):
            if d == start or (d in path and not loops(d, d, set())) is None:
                return True
            if d in path:
                continue
            path.add(d)
            if loops(start, d, path):
                return True
            path.discard(d)
        return False
    for rid in by_id:
        if loops(rid, rid, {rid}):
            findings.append(f"row {rid} sits in a dependency loop")
            break

    for sname, seat in seats.items():
        if seat.get("human") is True:
            continue
        classes = manifest_classes(prog, seat["adapter"])
        # BYO `model` is a model identifier passed to the adapter/broker, not a
        # sandbox confinement grant class; still requires a real manifest.
        demands = [g for g in GRANT_KEYS if g != "model" and seat.get(g)]
        if demands and classes is None:
            findings.append(
                f"seat {sname}: demands {' '.join(sorted(demands))} on adapter "
                f"{seat['adapter']!r}, which has no verified manifest yet. P marks the "
                f"tested classes and C8 writes the manifest; until then nothing is enforceable")
        elif seat.get("model") and classes is None:
            findings.append(
                f"seat {sname}: names model on adapter {seat['adapter']!r}, "
                "which has no verified manifest")
        else:
            for g in demands:
                if g not in (classes or []):
                    findings.append(f"seat {sname}: {g} is outside adapter {seat['adapter']!r}'s tested range")
        if seat.get("network"):
            # the charter bounds every seat's reach (docs/charter.md): a host it
            # doesn't cover refuses here, where the author is looking
            import reach as reach_mod
            try:
                reach_mod.check_grant(prog, seat["network"])
            except reach_mod.Finding as e:
                findings.append(f"seat {sname}: {e}")
        for k in INERT_KEYS:
            if seat.get(k):
                notes.append(f"inert: seat {sname}.{k} is shape-checked only this wave; it grants nothing until its chunk lands")
        b = seat.get("budget", {})
        if "usd" in b and "budget=advisory" not in waivables:
            waivables.append("budget=advisory")
            notes.append(f"needs-waiver budget=advisory: seat {sname} has a usd cap nothing enforces before R4's broker")
        if seat.get("read") and seat.get("network"):
            waivables.append("rule-of-two")
            notes.append(f"needs-waiver rule-of-two: seat {sname} holds read grants and network effects together")
        if seat.get("write"):
            reviewed = [r for r in rows if r.get("seat") == sname and r.get("reviewer")]
            unreviewed = [r for r in rows if r.get("seat") == sname and not r.get("reviewer")]
            if reviewed and unreviewed:
                waivables.append("unreviewed-rows")
                notes.append(f"needs-waiver unreviewed-rows: seat {sname} writes and has rows without a reviewer")

    if "usd" in doc.get("budget", {}):
        waivables.append("budget=advisory")
        notes.append("needs-waiver budget=advisory: the team-level usd cap, nothing enforces it before R4's broker")

    repo = os.environ.get("CONTRACT_REPO")
    if repo and os.path.isdir(os.path.join(repo, ".git")):
        r = sh(["git", "-C", repo, "ls-tree", "-r", "HEAD"])
        if any(line.startswith("160000 ") for line in r.stdout.splitlines()):
            findings.append("the base tree holds a gitlink (embedded repo), unsupported at 0.1")
        a = sh(["git", "-C", repo, "show", "HEAD:.gitattributes"])
        if a.returncode == 0 and "filter=lfs" in a.stdout:
            findings.append("the base tree sets filter=lfs, unsupported at 0.1")
    else:
        why = "unset" if not repo else "not a git tree"
        notes.append(f"note: CONTRACT_REPO {why}, so the base tree's gitlink and lfs checks were skipped")

    for w in waivers:
        if w not in WAIVERS:
            raise Finding(f"unknown waiver {w!r}; the waivable names are {' '.join(WAIVERS)}")
    waived = set(waivers)
    for n in notes:
        print(n)
    for f in findings:
        print(f"team: {f}", file=sys.stderr)
    print(f"validate: seats={len(seats)} rows={len(rows)} findings={len(findings)} "
          f"needs-waiver={' '.join(sorted(set(waivables))) or '-'}")
    if findings:
        sys.exit(1)


def selftest():
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

    def prog(team, contract=None, roles=("reviewer.md",), skills=()):
        d = tempfile.mkdtemp(prefix="tm.")
        os.makedirs(os.path.join(d, "roles"))
        for r in roles:
            with open(os.path.join(d, "roles", r), "w") as f:
                f.write(f"---\nname: {r[:-3]}\ndescription: d\n---\nbody\n")
        for s in skills:
            os.makedirs(os.path.join(d, s), exist_ok=True)
        with open(os.path.join(d, "team.toml"), "w") as f:
            f.write(team)
        with open(os.path.join(d, "contract.toml"), "w") as f:
            f.write(contract or
                    'schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                    'seat = "worker"\nreviewer = "rev"\ncmd = "true"\n')
        return d

    engine_adapters = tempfile.mkdtemp(prefix="tma.")
    ALL = {"shell", "write", "network", "read", "mcp", "model"}
    def with_manifests(*classes):
        with open(os.path.join(engine_adapters, "claude-code.toml"), "w") as f:
            f.write("tested_classes = [" + ", ".join(f'"{c}"' for c in classes) + "]\n")
        return {"OPERATOR_ADAPTERS": engine_adapters}

    def run_(d, *extra, env=None):
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run([sys.executable, os.path.abspath(__file__), "validate", d, *extra],
                              capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)

    BASE = '''schema = 1
name = "feature"
[seat.worker]
role = "roles/worker.md"
adapter = "claude-code"
[seat.rev]
role = "roles/reviewer.md"
adapter = "claude-code"
[seat.owner]
human = true
'''
    # A a sound minimal team validates, inert keys carry, waivers are only the named ones
    d = prog(BASE, roles=("worker.md", "reviewer.md"))
    r = run_(d)
    check(r.returncode == 0 and "seats=3" in r.stdout and "findings=0" in r.stdout,
          f"A validate: {r.stdout}{r.stderr}")
    inert = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                         'adapter = "claude-code"\nmemory = { self = "rw" }\nskills = ["skills/tdd"]\n[seat.rev]', 1)
    d = prog(inert, roles=("worker.md", "reviewer.md"), skills=("skills/tdd",))
    r = run_(d)
    check(r.returncode == 0 and "inert: seat worker.memory" in r.stdout
          and "inert: seat worker.skills" in r.stdout, f"A inert: {r.stdout}")
    r = run_(d, "--waive", "nonsense")
    check(r.returncode == 1 and "unknown waiver" in r.stderr, f"A waiver names: {r.stderr}")
    # B unknown keys refuse at every level, and so do bad shapes
    for bad_doc, why in [
        (BASE.replace('name = "feature"', 'name = "feature"\nbogus = 1'), "top key"),
        (BASE.replace('[seat.rev]', '[seat.rev]\nweird = 1'), "seat key"),
        (BASE.replace('name = "feature"', 'name = "Feature X"'), "name shape"),
        (BASE.replace('[seat.owner]\nhuman = true', '[seat.owner]\nhuman = true\nshell = ["*"]'), "human grants"),
        (BASE.replace('role = "roles/worker.md"', 'role = "roles/gone.md"'), "role exists"),
        (BASE.replace('adapter = "claude-code"\n[seat.rev]', 'adapter = "claude-code"\nwrite = ["/abs"]\n[seat.rev]', 1), "write abs"),
        (BASE.replace('adapter = "claude-code"\n[seat.rev]', 'adapter = "claude-code"\nnetwork = ["not a host"]\n[seat.rev]', 1), "network"),
        (BASE.replace('autonomy = ', '') + 'autonomy = "wild"\n' if False else BASE.replace('name = "feature"\n', 'name = "feature"\nautonomy = "wild"\n'), "autonomy"),
    ]:
        r = run_(prog(bad_doc, roles=("worker.md", "reviewer.md")))
        check(r.returncode == 1, f"B {why}: rc={r.returncode} {r.stdout}{r.stderr}")
    # C the cross-checks: unknown seats, reviewer-is-author, repo-code reviewer, ruling seat
    def rows_doc(seat="worker", reviewer="rev", extra=""):
        return ('schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                f'seat = "{seat}"\nreviewer = "{reviewer}"\ncmd = "true"\n{extra}')
    r = run_(prog(BASE, contract=rows_doc(seat="ghost"), roles=("worker.md", "reviewer.md")))
    check(r.returncode == 1 and "isn't on the team" in r.stderr, f"C unknown seat: {r.stderr}")
    r = run_(prog(BASE, contract=rows_doc(reviewer="ghost"), roles=("worker.md", "reviewer.md")))
    check(r.returncode == 1 and "isn't on the team" in r.stderr, f"C unknown reviewer: {r.stderr}")
    r = run_(prog(BASE, contract=rows_doc(reviewer="worker"), roles=("worker.md", "reviewer.md")))
    check(r.returncode == 1 and "reviewer is the author" in r.stderr, f"C author: {r.stderr}")
    r = run_(prog(BASE, contract=rows_doc(reviewer="owner"), roles=("worker.md", "reviewer.md")))
    check(r.returncode == 0, f"C a human reviewer holds: {r.stdout}{r.stderr}")
    r = run_(prog(BASE, contract=rows_doc().replace('kind = "run"', 'kind = "ruling"').replace('cmd = "true"\n', ''),
                  roles=("worker.md", "reviewer.md")))
    check(r.returncode == 1 and "human seat" in r.stderr, f"C ruling seat: {r.stderr}")
    revcode = BASE.replace('[seat.rev]\nrole = "roles/reviewer.md"\nadapter = "claude-code"',
                           '[seat.rev]\nrole = "roles/reviewer.md"\nadapter = "claude-code"\nshell = ["pytest -q"]')
    d = prog(revcode, roles=("worker.md", "reviewer.md"))
    r = run_(d)
    check(r.returncode == 1 and "repo-code" in r.stderr, f"C reviewer prefix: {r.stderr}")
    # D deps: a dep on a later stage refuses, and a loop refuses
    fwd = (rows_doc(extra='deps = ["b"]\n') +
           '[[row]]\nid = "b"\nstage = "two"\ndesc = "d"\nkind = "run"\n'
           'seat = "worker"\nreviewer = "rev"\ncmd = "true"\n')
    r = run_(prog(BASE, contract=fwd, roles=("worker.md", "reviewer.md")))
    check(r.returncode == 1 and "later stage" in r.stderr, f"D forward dep: {r.stderr}")
    loop = (rows_doc(extra='deps = ["b"]\n') +
            '[[row]]\nid = "b"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
            'seat = "worker"\nreviewer = "rev"\ncmd = "true"\ndeps = ["a"]\n')
    r = run_(prog(BASE, contract=loop, roles=("worker.md", "reviewer.md")))
    check(r.returncode == 1 and ("loop" in r.stderr or "later stage" in r.stderr or "cycle" in r.stderr), f"D loop: {r.stderr}")

    # E enforceability: no manifest, no grants; a manifest opens only its
    # tested classes. C8 ships real manifests, so the no-manifest arms use an
    # adapter nothing ships, and the claude-code arms now measure against the
    # CORE's own manifest (P's tested range: write only).
    grants = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                          'adapter = "claude-code"\nshell = ["git diff"]\n[seat.rev]', 1)
    d = prog(grants, roles=("worker.md", "reviewer.md"))
    r = run_(d)
    check(r.returncode == 1 and "tested range" in r.stderr,
          f"E the core manifest gates: {r.stderr}")
    d = prog(grants, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests("shell"))
    check(r.returncode == 0, f"E manifest opens shell: {r.stdout}{r.stderr}")
    none = grants.replace('adapter = "claude-code"', 'adapter = "nothing-ships-this"', 1)
    d = prog(none, roles=("worker.md", "reviewer.md"))
    r = run_(d)
    check(r.returncode == 1 and "no verified manifest" in r.stderr, f"E no manifest: {r.stderr}")
    net = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                       'adapter = "claude-code"\nnetwork = ["pypi.org"]\n[seat.rev]', 1)
    d = prog(net, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests("shell"))
    check(r.returncode == 1 and "tested range" in r.stderr, f"E untested class: {r.stderr}")
    # the core's real manifest is present and opens exactly what P tested (including BYO model)
    byo = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                       'adapter = "claude-code"\nmodel = "claude-sonnet-4-5"\n[seat.rev]', 1)
    r = run_(prog(byo, roles=("worker.md", "reviewer.md")))
    check(r.returncode == 0, f"E the shipped claude-code manifest validates BYO seat.model: {r.stdout}{r.stderr}")
    bad_model = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                             'adapter = "claude-code"\nmodel = "bad quote\\"inject"\n[seat.rev]', 1)
    r = run_(prog(bad_model, roles=("worker.md", "reviewer.md")))
    check(r.returncode == 1 and "model must be" in r.stderr, f"E unsafe model id refuses: {r.stderr}")
    r = run_(prog(BASE, roles=("worker.md", "reviewer.md")))
    check(r.returncode == 0, f"E the shipped claude-code manifest validates a "
                             f"write-only seat: {r.stdout}{r.stderr}")
    # a program's own adapters/ dir certifies nothing (F03): even a generous
    # self-cert can't widen the core manifest's tested range
    d2 = prog(grants, roles=("worker.md", "reviewer.md"))
    os.makedirs(os.path.join(d2, "adapters"))
    with open(os.path.join(d2, "adapters", "claude-code.toml"), "w") as f:
        f.write('tested_classes = ["shell", "write", "network"]\n')
    r = run_(d2)
    check(r.returncode == 1 and "tested range" in r.stderr, f"E self-certification: {r.stderr}")
    # F waivables print as needs, never refuse at validate
    wv = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                      'adapter = "claude-code"\nbudget = { usd = 5 }\n[seat.rev]', 1)
    d = prog(wv, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests(*ALL))
    check(r.returncode == 0 and "needs-waiver budget=advisory" in r.stdout, f"F advisory prints: {r.stdout}")
    # F1d the context dimension is a budget key like usd: tokens, per seat or
    # team, enforced at reservation (the whole context a seat's turns saw)
    ok_ctx = BASE.replace('[seat.owner]',
                          '[seat.worker.budget]\nusd = 6.0\ncontext = 500000\n[seat.owner]', 1)
    d = prog(ok_ctx, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests("write"))
    check(r.returncode == 0, f"F1d a context budget validates: rc={r.returncode} {r.stderr[:80]}")
    bad_ctx = BASE.replace('[seat.owner]',
                           '[seat.worker.budget]\ncontext = "lots"\n[seat.owner]', 1)
    d = prog(bad_ctx, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests("write"))
    check(r.returncode == 1 and "context must be a non-negative number" in r.stderr,
          f"F1d a non-number context refuses: {r.stderr[:80]}")
    ro2 = BASE.replace('adapter = "claude-code"\n[seat.rev]', 'adapter = "claude-code"\nread = ["docs"]\nnetwork = ["pypi.org"]\n[seat.rev]', 1)
    d = prog(ro2, roles=("worker.md", "reviewer.md"))
    os.makedirs(os.path.join(d, "docs"), exist_ok=True)
    with open(os.path.join(d, "charter.toml"), "w") as f:
        f.write('schema = 1\nname = "st"\n[reach]\nprofile = "dev"\n')   # the charter covers the grant
    r = run_(d, env=with_manifests(*ALL))
    check(r.returncode == 0 and "needs-waiver rule-of-two" in r.stdout, f"F rule of two: {r.stdout}")
    # F-net the charter bounds a seat's reach: a host outside it refuses by name
    for hosts, why in ((['outside.test'], "outside the charter's reach"), (["*"], "closed")):
        netx = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                            f'adapter = "claude-code"\nnetwork = {hosts}\n[seat.rev]', 1)
        d = prog(netx, roles=("worker.md", "reviewer.md"))
        r = run_(d, env=with_manifests(*ALL))
        check(r.returncode == 1 and "seat worker: network" in r.stderr and why in r.stderr,
              f"F-net a grant beyond the charter refuses ({hosts}): {r.stderr[:160]}")
    netx = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                        'adapter = "claude-code"\nnetwork = ["*"]\n[seat.rev]', 1)
    d = prog(netx, roles=("worker.md", "reviewer.md"))
    with open(os.path.join(d, "charter.toml"), "w") as f:
        f.write('schema = 1\nname = "st"\n[reach]\nprofile = "dev"\n')
    r = run_(d, env=with_manifests(*ALL))
    check(r.returncode == 0, f"F-net `*` under an open profile validates: {r.stdout}{r.stderr}")
    # F1b `see` is shape-checked as visibility naming: good passes with NO
    # demand on the adapter's tested classes, a bad shape refuses
    ok_see = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                          'adapter = "claude-code"\nsee = [".github/**"]\n[seat.rev]', 1)
    d = prog(ok_see, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests("write"))
    check(r.returncode == 0 and "see" not in r.stdout,
          f"F1b see passes without demanding a class: rc={r.returncode} {r.stdout[:80]}")
    bad_see = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                           'adapter = "claude-code"\nsee = ["/abs/path"]\n[seat.rev]', 1)
    d = prog(bad_see, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests("write"))
    check(r.returncode == 1 and "see" in r.stderr,
          f"F1b a bad see shape refuses: rc={r.returncode} {r.stderr[:80]}")
    # F1c the seat's gpu/ro flags: gpu is true or absent; ro is absolute,
    # distinct, exists, never on a jail-owned mount, never resolving into the
    # engine's own tree or state (the model tree crosses; the engine never
    # does). The green shape needs a legal writable dir -- the room has none
    # (its whole world is the jail's own mounts), so the room proves the
    # refusals and the host's first-level arm proves the green path
    _ro_dir = tempfile.mkdtemp(prefix="tm-ro.")
    _legal_home = os.environ.get("HOME", "")
    _legal = _legal_home.startswith("/") and os.path.isdir(_legal_home) and \
        not any(_legal_home == p or _legal_home.startswith(p + "/") for p in JAIL_OWNED)
    if not _legal:
        print("skipped: F1c green leg (this host's HOME sits on a jail-owned mount)")
    if _legal:
        _ro_legal = tempfile.mkdtemp(prefix="tm-legal.", dir=_legal_home)
        ok_gpu = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                              'adapter = "claude-code"\ngpu = true\n'
                              f'ro = ["{_ro_legal}"]\n[seat.rev]', 1)
        d = prog(ok_gpu, roles=("worker.md", "reviewer.md"))
        r = run_(d, env=with_manifests("write"))
        check(r.returncode == 0, f"F1c gpu+ro validate: rc={r.returncode} {r.stderr[:100]}")
        import shutil as _sh1d
        _sh1d.rmtree(_ro_legal, ignore_errors=True)
    # the engine-tree refusal fires where the tree lives off the jail's own
    # mounts (the host's real tree); a copy under /tmp or /var/tmp hears the
    # jail-mount refusal first, which is the same law one branch earlier
    _rootwhy = "engine's own tree" if not any(
        ROOT == p or ROOT.startswith(p + "/") for p in JAIL_OWNED) \
        else "jail's own mounts"
    for badro, why in [
        ('gpu = "yes"', "gpu is true or absent"),
        (f'ro = ["{_ro_dir}", "{_ro_dir}"]', "names the same path twice"),
        ('ro = ["relative/models"]', "absolute host path"),
        ('ro = ["/usr/share/models"]', "jail's own mounts"),
        ('ro = ["/tmp/' 'models"]', "jail's own mounts"),
        ('ro = ["/no/such/dir"]', "doesn't exist"),
        (f'ro = ["{ROOT}"]', _rootwhy),
    ]:
        bad_gpu = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                               f'adapter = "claude-code"\n{badro}\n[seat.rev]', 1)
        d = prog(bad_gpu, roles=("worker.md", "reviewer.md"))
        r = run_(d, env=with_manifests("write"))
        check(r.returncode == 1 and why in r.stderr,
              f"F1c {why} refuses: rc={r.returncode} {r.stderr[:90]}")
    # the crown, on the host where a legal writable dir exists: an ANCESTOR
    # of the state dir crosses it just as surely as a path inside it --
    # proven with a controlled OPERATOR_HOME so it fires wherever the tree
    # lives (copies under /tmp hear the jail-owned branch first)
    if _legal:
        _anc = tempfile.mkdtemp(prefix="tm-anc.", dir=_legal_home)
        os.makedirs(os.path.join(_anc, "state"), exist_ok=True)
        _oh = os.environ.get("OPERATOR_HOME")
        os.environ["OPERATOR_HOME"] = os.path.join(_anc, "state")
        try:
            anc_team = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                                    'adapter = "claude-code"\n'
                                    f'ro = ["{_anc}"]\n[seat.rev]', 1)
            d = prog(anc_team, roles=("worker.md", "reviewer.md"))
            r = run_(d, env=with_manifests("write"))
            check(r.returncode == 1 and "touches the engine's own" in r.stderr,
                  f"F1c an ancestor of the state refuses: {r.stderr[:90]}")
        finally:
            if _oh is None:
                del os.environ["OPERATOR_HOME"]
            else:
                os.environ["OPERATOR_HOME"] = _oh
            import shutil as _sh1e
            _sh1e.rmtree(_anc, ignore_errors=True)
    else:
        print("skipped: F1c crown leg (no legal writable dir on this host)")
    import shutil as _sh1c
    _sh1c.rmtree(_ro_dir, ignore_errors=True)
    # F1d a seat's environments: a list of names, each one declared in the
    # charter the owner signs; env_minutes is what the seat may spend inside them
    def env_team(extra, budget=""):
        return BASE.replace('adapter = "claude-code"\n[seat.rev]',
                            f'adapter = "claude-code"\n{extra}\n{budget}\n[seat.rev]', 1)

    st_charer = ('schema = 1\nname = "st"\n\n[[environment.tests]]\n'
                 'image = "sha256:' + "b" * 64 + '"\nruntime = "docker"\nuser = "1000:1000"\n'
                 '\n  [environment.tests.limits]\n  memory = "64m"\n  cpus = 1\n  pids = 16\n  wall = 300\n')
    for badenv, why in [
        ('env = "tests"', "must be a list of environment names"),
        ('env = ["Tests"]', "must be a list of environment names"),
        ('env = ["tests"]', "which charter.toml doesn't declare"),
    ]:
        d = prog(env_team(badenv), roles=("worker.md", "reviewer.md"))
        r = run_(d, env=with_manifests("write"))
        check(r.returncode == 1 and why in r.stderr,
              f"F1d {why} refuses: rc={r.returncode} {r.stderr[:90]}")
    d = prog(env_team('env = ["tests"]', "[seat.worker.budget]\nenv_minutes = -1"),
             roles=("worker.md", "reviewer.md"))
    with open(os.path.join(d, "charter.toml"), "w") as f:
        f.write(st_charer)
    r = run_(d, env=with_manifests("write"))
    check(r.returncode == 1 and "env_minutes must be a non-negative number" in r.stderr,
          f"F1d a negative env_minutes refuses: rc={r.returncode} {r.stderr[:90]}")
    d = prog(env_team('env = ["tests"]', "[seat.worker.budget]\nenv_minutes = 5"),
             roles=("worker.md", "reviewer.md"))
    with open(os.path.join(d, "charter.toml"), "w") as f:
        f.write(st_charer)
    r = run_(d, env=with_manifests("write"))
    check(r.returncode == 0, f"F1d a declared environment and its budget validate: rc={r.returncode} {r.stderr[:100]}")
    # F2 a mixed reviewed/unreviewed writing seat waives, never refuses
    mixed = (rows_doc() + '[[row]]\nid = "b"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
             'seat = "worker"\ncmd = "true"\n')
    writing = BASE.replace('adapter = "claude-code"\n[seat.rev]',
                           'adapter = "claude-code"\nwrite = ["src/**"]\n[seat.rev]', 1)
    d = prog(writing, contract=mixed, roles=("worker.md", "reviewer.md"))
    r = run_(d, env=with_manifests(*ALL))
    check(r.returncode == 0 and "needs-waiver unreviewed-rows" in r.stdout, f"F2 unreviewed: {r.stdout}{r.stderr}")

    # G VOID shapes
    empty = tempfile.mkdtemp(prefix="tm.")
    check(run_(empty).returncode == 2, "G no team")
    d = prog(BASE, roles=("worker.md", "reviewer.md"))
    os.chmod(os.path.join(d, "team.toml"), 0)
    check(run_(d).returncode == 2, "G unreadable team")
    os.chmod(os.path.join(d, "team.toml"), 0o644)
    # H the dep door at load: a self-dep, a ghost dep and a cycle all refuse
    # (they parked tasks blocked forever when load stayed silent)
    base_t = open(os.path.join(d, "team.toml")).read()
    c_ok = open(os.path.join(d, "contract.toml")).read()

    def with_contract(body):
        open(os.path.join(d, "contract.toml"), "w").write(body)
        return run_(d)
    try:
        r = with_contract('schema = 2\n[[row]]\nid = "a"\nstage = "s"\n'
                          'desc = "d"\nkind = "run"\ncmd = "true"\n'
                          'seat = "w"\nreviewer = "r"\ndeps = ["a"]\n')
        check(r.returncode == 1 and "itself" in r.stdout + r.stderr,
              f"H a self-dep refuses: {(r.stdout + r.stderr)[:80]}")
        r = with_contract('schema = 2\n[[row]]\nid = "a"\nstage = "s"\n'
                          'desc = "d"\nkind = "run"\ncmd = "true"\n'
                          'seat = "w"\nreviewer = "r"\ndeps = ["ghost"]\n')
        check(r.returncode == 1 and "names no row" in r.stdout + r.stderr,
              f"H a ghost dep refuses: {(r.stdout + r.stderr)[:80]}")
        r = with_contract('schema = 2\n[[row]]\nid = "a"\nstage = "s"\n'
                          'desc = "d"\nkind = "run"\ncmd = "true"\n'
                          'seat = "w"\nreviewer = "r"\ndeps = ["b"]\n'
                          '[[row]]\nid = "b"\nstage = "s"\ndesc = "d"\n'
                          'kind = "run"\ncmd = "true"\nseat = "w"\n'
                          'reviewer = "r"\ndeps = ["a"]\n')
        check(r.returncode == 1 and "cycle" in r.stdout + r.stderr,
              f"H a dep cycle refuses: {(r.stdout + r.stderr)[:80]}")
        # I cross-family vs same-family review waiver
        r_role = "roles/w.md" if os.path.isfile(os.path.join(d, "roles", "w.md")) else "roles/worker.md"
        sf_team = ('schema = 1\nname = "sf"\n'
                   f'[seat.w]\nrole = "{r_role}"\nadapter = "claude-code"\n'
                   f'[seat.r]\nrole = "{r_role}"\nadapter = "opencode"\n'
                   f'[seat.rx]\nrole = "{r_role}"\nadapter = "codex"\n')
        open(os.path.join(d, "team.toml"), "w").write(sf_team)
        r = with_contract('schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\n'
                          'kind = "run"\ncmd = "true"\nseat = "w"\nreviewer = "r"\noracle = ["tests"]\n')
        check(r.returncode == 0 and "same-family-review" in r.stdout,
              f"I same-family review flags needs-waiver: {r.stdout}")
        r = with_contract('schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\n'
                          'kind = "run"\ncmd = "true"\nseat = "w"\nreviewer = "rx"\noracle = ["tests"]\n')
        check(r.returncode == 0 and "same-family-review" not in r.stdout,
              f"I cross-family review needs no waiver: {r.stdout}")
        check(model_family({"adapter": "claude-code", "model": "bedrock/us.anthropic.claude-sonnet-4-6"}) == "anthropic"
              and model_family({"adapter": "codex", "model": "openrouter/custom-unknown-70b"}) == "unknown",
              "I2 gateway multi-slash anthropic resolves and unknown custom IDs fail closed")
        unk_team = ('schema = 1\nname = "sf"\n'
                    f'[seat.w]\nrole = "{r_role}"\nadapter = "claude-code"\n'
                    f'[seat.r_unk]\nrole = "{r_role}"\nadapter = "codex"\nmodel = "custom-gw/mystery-model"\n')
        open(os.path.join(d, "team.toml"), "w").write(unk_team)
        r_unk = with_contract('schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\n'
                              'kind = "run"\ncmd = "true"\nseat = "w"\nreviewer = "r_unk"\noracle = ["tests"]\n')
        check(r_unk.returncode == 0 and "same-family-review" in r_unk.stdout,
              f"I2 unclassified model family requires same-family-review waiver: {r_unk.stdout}")
    finally:
        open(os.path.join(d, "contract.toml"), "w").write(c_ok)
        open(os.path.join(d, "team.toml"), "w").write(base_t)

    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def main(argv):
    if len(argv) < 2 or argv[1] != "validate":
        print("usage: team.py validate <program-dir> [--waive <name>]... | --selftest", file=sys.stderr)
        sys.exit(2)
    if len(argv) < 3:
        sys.exit(2)
    waivers = []
    rest = argv[3:]
    i = 0
    while i < len(rest):
        if rest[i] == "--waive" and i + 1 < len(rest):
            waivers.append(rest[i + 1])
            i += 2
        else:
            sys.exit(2)
    try:
        cmd_validate(argv[2], waivers)
    except Finding as e:
        print(f"team: {e}", file=sys.stderr)
        sys.exit(1)
    except Void as e:
        print(f"team: VOID, {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    main(sys.argv)
