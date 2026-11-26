#!/usr/bin/env python3
"""contract -- loads a program's contract.toml, runs every check through one run_check,
and files each result in the call log keyed by row id, commit and arm ruling hash.

The loader refuses what it doesn't name: unknown keys, kinds this wave doesn't run,
ids out of shape, deps that don't exist or loop, oracles that nest (a nested read-only
bind can be swapped by renaming its parent), and setups whose lock lines reach outside
their inputs. Whole-table validation runs before any evaluation, and a broken table is
VOID (rc 2), never a verdict. A green result matches only its own key: an amend or a
re-arm changes the key and the row re-runs. `advance` evaluates the first stage that
isn't green on the tip under one program lock (flock -n; busy is rc 3), `done` evaluates
every stage and prints the label mix.

run_check is the only way a check runs: a fresh jail, no network, no credentials, a
writable throwaway export of the row's commit (the repo's info/attributes must be the
pinned export line, so the export is the commit), the program tree read-only at $PROG,
oracle paths restored from the pinned commit and bound read-only over the export, listed
ro paths bound, generated passwd and hosts, a scrubbed env, stdin closed, the row's
timeout (at least 60), and output capped and drained so the check keeps its own exit
code. The capped output goes to a run file beside the program's call log.

[setup] runs inside a network-isolated bubblewrap jail containing only its declared
inputs and a fresh staging directory at /env; when setup.network is non-empty, its
lonely loopback is bridged exclusively through bin/egress-proxy.py enforcing the
declared host allowlist. On exit 0, the staged /env directory swaps into <prog>/env
and binds read-only at /env for every subsequent contract row.

usage: contract.py <validate|lint|doctor|run|advance|done|setup|amend|forge> <program-dir> [row-id]
       contract.py --selftest | --first-level
env: CONTRACT_REPO the work repo (export source), CONTRACT_TIP the commit to evaluate
     (default HEAD), CONTRACT_ARM the arm ruling hash (default -), CALL_LOG_FILE,
     OPERATOR_HOME (via bin/call-log.sh)
exit: 0 green, 1 a finding or a red check, 2 usage or VOID, 3 the program is locked
"""
import ast
import fnmatch
import hashlib
import hmac
import json
import os
import re
import resource
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
sys.path.insert(0, os.path.join(ROOT, "bin", "lib"))
from jail import bwrap_args, generated_etc, nvidia_nodes, run_capped  # noqa: E402

SCHEMA = 2
SETUP_KEYS = {"cmd": str, "inputs": list, "network": list, "timeout": int}
ROW_KEYS = {"id": str, "stage": str, "desc": str, "kind": str, "seat": str, "reviewer": str,
            "deps": list, "cmd": str, "timeout": int, "oracle": list, "oracle_from": str,
            "ro": list, "control": str, "driver": str, "evidence": str,
            "file": str, "columns": int, "rows_min": int,
            "require": list, "forbid": list, "gpu": bool,
            "expect_base_fail": bool, "mutable_configs": list,
            "runner": str, "min_tests": int, "test_paths": list,
            "diff_base": str, "env": str}
KINDS = ("run", "ruling", "tsv", "git")
EVIDENCE = ("sealed", "author-reachable", "human")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
STAGE_RE = re.compile(r"^[a-z][a-z0-9-]*$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
ORACLE_PAT_RE = re.compile(r"^[A-Za-z0-9._*][A-Za-z0-9._/*-]{0,255}$")
TIMEOUT_MIN, TIMEOUT_DEFAULT = 60, 600
OUT_CAP = 1024 * 1024
ATTRIBUTES = "* -export-ignore -export-subst -text -eol -ident -working-tree-encoding -filter"
FSIZE = 512 * 1024 * 1024         # RLIMIT_FSIZE outside the jail, as spawn's jails
NPROC = 64                        # prlimit --nproc inside, as spawn's jails
AS_FLOOR = 3 * 1024 * 1024 * 1024
TSV_MAX_BYTES = 16 * 1024 * 1024  # cap engine-side TSV reads so a bloated candidate cannot OOM
RUNNER_CONFIG_NAMES = (
    "pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml",
    "pyproject.toml", "setup.cfg", "setup.py", "tox.ini", "noxfile.py",
    "conftest.py", ".coveragerc", "sitecustomize.py", "usercustomize.py",
    "Makefile", "GNUmakefile", "Cargo.toml", "build.rs",
    "package.json", "tsconfig.json",
    "**/conftest.py", "**/*.pth", "jest.config.*", "vitest.config.*", ".mocharc.*",
)
TRIVIAL_CMDS = {"true", "false", ":", "pass", "exit 0", "exit 1", "echo ok"}


def as_cap():
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
    except (OSError, ValueError):
        return AS_FLOOR
    return AS_FLOOR if hard in (resource.RLIM_INFINITY, -1) else min(AS_FLOOR, hard)


def flag(argv, name, default=None):
    if name in argv and argv.index(name) + 1 < len(argv):
        return argv[argv.index(name) + 1]
    return default


class Void(Exception):
    pass


class Finding(Exception):
    pass


def die(msg, code):
    print(f"contract: {msg}", file=sys.stderr)
    sys.exit(code)


def sh(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)


# --- loading and validation ----------------------------------------------------------

def check_path_list(name, values, what):
    for v in values:
        if not isinstance(v, str) or not v or "\x00" in v or any(ord(c) < 0x20 for c in v):
            raise Finding(f"{name}: {what} must be non-empty strings without control characters")
        if v.startswith("/") or v.split("/")[0] in ("..", "-e", ".", "./") or "//" in v or "/../" in f"/{v}/":
            raise Finding(f"{name}: {what} can't name {v!r}: repo-relative only, no traversal, no -e . ./")
        if v.endswith("/") or v.endswith("/."):
            raise Finding(f"{name}: {what} can't name {v!r}: a trailing slash changes its bind")


def check_oracle_list(rid, oracle):
    for o in oracle:
        if not isinstance(o, str) or not o or "\x00" in o or any(ord(c) < 0x20 for c in o):
            raise Finding(f"row {rid}: oracle paths must be non-empty strings without control characters")
        if o.startswith("/") or o.startswith("-") or o.endswith("/") or "//" in o \
                or any(part in ("..", ".") for part in o.split("/")) \
                or not ORACLE_PAT_RE.fullmatch(o):
            raise Finding(f"row {rid}: invalid oracle pattern {o!r}")


def _disk_prog_key(prog):
    h = hashlib.sha256()
    skip_dirs = {"runs", "rulings", "env", "env.old", "__pycache__", ".git"}
    for root_d, dirs, files in os.walk(prog):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs)
        for fn in sorted(files):
            fp = os.path.join(root_d, fn)
            if os.path.islink(fp) or not os.path.isfile(fp):
                continue
            rel = os.path.relpath(fp, prog).replace(os.sep, "/")
            h.update(rel.encode("utf-8") + b"\0")
            with open(fp, "rb") as f:
                h.update(hashlib.sha256(f.read()).digest() + b"\n")
    return h.hexdigest()[:16]


def _charter_environments(prog):
    """The environments the program's charter signs (docs/charter.md); {} without one.
    A broken charter is a finding here, where the rows that name it are loaded."""
    if not os.path.isfile(os.path.join(prog, "charter.toml")):
        return {}
    import environment as env_mod
    try:
        return env_mod.specs(prog)
    except env_mod.Finding as e:
        raise Finding(str(e))


def load(prog):
    """Parse and whole-table-validate. Returns the contract dict. Finding = a refused
    table (rc 1); Void = the shape of the world is wrong (rc 2)."""
    path = os.path.join(prog, "contract.toml")
    if not os.path.isfile(path):
        raise Void(f"no contract.toml in {prog}")
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise Finding(f"contract.toml doesn't parse: {e}")
    except OSError as e:
        raise Void(f"contract.toml can't be read: {e}")
    if type(doc.get("schema")) is not int or doc["schema"] != SCHEMA:
        raise Finding(f"schema must be the integer {SCHEMA}, not {doc.get('schema')!r}")
    for k in doc:
        if k not in ("schema", "setup", "row"):
            raise Finding(f"unknown top-level key {k!r}")
    setup = doc.get("setup", {})
    if not isinstance(setup, dict):
        raise Finding("[setup] must be a table")
    for k, v in setup.items():
        if k not in SETUP_KEYS:
            raise Finding(f"[setup] has unknown key {k!r}")
        if SETUP_KEYS[k] is list:
            if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
                raise Finding(f"[setup] {k} must be a list of strings")
        elif SETUP_KEYS[k] is int:
            if type(v) is not int or v < TIMEOUT_MIN:
                raise Finding(f"[setup] {k} must be an integer >= {TIMEOUT_MIN}")
        elif not isinstance(v, SETUP_KEYS[k]) or not v:
            raise Finding(f"[setup] {k} must be a non-empty {SETUP_KEYS[k].__name__}")
    check_path_list("[setup]", setup.get("inputs", []), "an input")
    for h in setup.get("network", []):
        # '*' is the open-web research wildcard, and it rides ONLY the
        # template's own fetch command: a wildcard over an arbitrary shell
        # command is an unbounded hand (the review ran curl past it)
        if h == "*":
            if not str(setup.get("cmd", "")).startswith(
                    "python3 -I $PROG/checks/fetch_sources.py "):
                raise Finding("[setup] network '*' rides the research "
                              "template's fetch_sources command only -- any "
                              "other setup names its hosts")
            raw_scmd = str(setup.get("cmd", ""))
            if any(ch in raw_scmd for ch in (";", "|", "&", "`", "$(" , ">", "<", "\n", "\r")):
                raise Finding("[setup] network '*' forbids shell chaining or redirection")
            continue
        if not HOST_RE.fullmatch(h):
            raise Finding(f"[setup] network names {h!r}, which is not a host name")
    if "cmd" in setup:
        try:
            toks = shlex.split(setup["cmd"])
        except ValueError as e:
            raise Finding(f"[setup] cmd doesn't parse as a command: {e}")
        if "*" in setup.get("network", []) and toks[:3] == ["python3", "-I", "$PROG/checks/fetch_sources.py"]:
            if len(toks) != 5 or not all(re.fullmatch(r"[A-Za-z0-9._/-]+", t) for t in toks[3:]):
                raise Finding("[setup] network '*' requires exact 5-token fetch_sources invocation")
        inputs = set(setup.get("inputs", []))
        for i, t in enumerate(toks):
            if t in ("-e", "--editable"):
                raise Finding("[setup] cmd may not install editable: a lock line, not a tree")
            if t in ("-r", "--requirement"):
                if i + 1 >= len(toks):
                    raise Finding("[setup] cmd ends in a lock-line flag with no argument")
                lock = toks[i + 1]
                if lock not in inputs:
                    raise Finding(f"[setup] cmd names the lock line {lock!r}, which is outside inputs")
            if t in ("--index", "-i", "--index-url", "--extra-index-url") and i + 1 < len(toks) \
                    and not toks[i + 1].startswith(("https://", "http://")):
                raise Finding("[setup] cmd's package index must be a URL")
    rows = doc.get("row")
    if not isinstance(rows, list) or not rows:
        raise Finding("the contract names no rows: an empty contract gates nothing")
    seen, by_id = set(), {}
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise Finding(f"row {i} isn't a table")
        for k in row:
            if k not in ROW_KEYS:
                raise Finding(f"row {i} has unknown key {k!r}")
        rid = row.get("id")
        if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
            raise Finding(f"row {i} has id {rid!r}: [a-z0-9][a-z0-9._-]{{0,63}}")
        if rid == "setup":
            raise Finding("row id 'setup' is reserved for [setup]")
        if rid in seen:
            raise Finding(f"duplicate row id {rid}")
        seen.add(rid)
        kind = row.get("kind")
        if kind not in KINDS:
            raise Finding(f"row {rid}: kind must be one of {' '.join(KINDS)}, not {kind!r}")
        if row.get("driver") is not None and row["driver"] != "external":
            raise Finding(f"row {rid}: driver names how the check runs; only "
                          "'external' (the review path) exists")
        for f in ("stage", "seat", "desc"):
            if not isinstance(row.get(f), str) or not row[f]:
                raise Finding(f"row {rid}: {f} must be a non-empty string")
        if not STAGE_RE.fullmatch(row["stage"]) or row["stage"] == "done":
            raise Finding(f"row {rid}: stage {row['stage']!r} must be [a-z][a-z0-9-]* and not done")
        reviewer = row.get("reviewer")
        if not isinstance(reviewer, str) or not reviewer:
            raise Finding(f"row {rid}: reviewer is required")
        if reviewer == row["seat"]:
            raise Finding(f"row {rid}: the reviewer is the seat")
        deps = row.get("deps", [])
        if not isinstance(deps, list) or not all(isinstance(d, str) for d in deps):
            raise Finding(f"row {rid}: deps must be a list of row ids")
        row.setdefault("deps", [])
        oracle = row.get("oracle", [])
        if not isinstance(oracle, list) or not all(isinstance(o, str) for o in oracle):
            raise Finding(f"row {rid}: oracle must be a list of paths")
        check_oracle_list(rid, oracle)
        of = row.get("oracle_from")
        if of is not None and (not isinstance(of, str) or not ID_RE.fullmatch(of)):
            raise Finding(f"row {rid}: oracle_from must be a row id")
        ro = row.get("ro", [])
        if not isinstance(ro, list) or not all(isinstance(r, str) for r in ro):
            raise Finding(f"row {rid}: ro must be a list of paths")
        if "gpu" in row and not isinstance(row["gpu"], bool):
            raise Finding(f"row {rid}: gpu is true or absent")
        if "env" in row:
            if kind != "run" or row.get("driver") == "external":
                raise Finding(f"row {rid}: only a run row with its own cmd takes env")
            if not isinstance(row["env"], str) or not ID_RE.fullmatch(row["env"]):
                raise Finding(f"row {rid}: env must be an environment name: [a-z0-9][a-z0-9._-]{{0,63}}")
            if "gpu" in row:
                raise Finding(f"row {rid}: env and gpu name devices twice; an environment's "
                              "devices come from its signed spec")
        if "expect_base_fail" in row and not isinstance(row["expect_base_fail"], bool):
            raise Finding(f"row {rid}: expect_base_fail is true or absent")
        if ("expect_base_fail" in row and kind != "run") or (
                row.get("expect_base_fail") and row.get("driver") == "external"):
            raise Finding(f"row {rid}: only a runnable check row takes expect_base_fail")
        if "mutable_configs" in row:
            mc = row["mutable_configs"]
            if not isinstance(mc, list) or not all(isinstance(x, str) for x in mc):
                raise Finding(f"row {rid}: mutable_configs must be a list of paths")
            check_path_list(f"row {rid}", mc, "a mutable_configs path")
        if "runner" in row and row["runner"] not in ("pytest", "raw"):
            raise Finding(f"row {rid}: runner must be 'pytest' or 'raw'")
        if "min_tests" in row:
            mt = row["min_tests"]
            if not isinstance(mt, int) or isinstance(mt, bool) or mt < 0:
                raise Finding(f"row {rid}: min_tests must be a non-negative integer")
        if "test_paths" in row:
            tp = row["test_paths"]
            if not row.get("expect_base_fail"):
                raise Finding(f"row {rid}: test_paths requires expect_base_fail = true")
            if not isinstance(tp, list) or not tp or not all(isinstance(x, str) for x in tp):
                raise Finding(f"row {rid}: test_paths must be a non-empty list of paths")
            check_oracle_list(rid, tp)
        if "diff_base" in row:
            if kind != "git":
                raise Finding(f"row {rid}: only a git row takes diff_base")
            if row["diff_base"] not in ("step", "pin"):
                raise Finding(f"row {rid}: diff_base must be 'step' or 'pin'")
        if kind == "ruling":
            for f in ("cmd", "timeout", "oracle", "oracle_from", "control", "ro",
                      "file", "columns", "rows_min", "require", "forbid", "gpu"):
                if f in row:
                    raise Finding(f"row {rid}: a ruling row takes no {f}")
            for f in ("mutable_configs", "runner", "min_tests", "test_paths"):
                if f in row:
                    raise Finding(f"row {rid}: a ruling row takes no {f}")
        elif kind != "run" and "gpu" in row:
            raise Finding(f"row {rid}: only a run row takes gpu (its check is "
                          "the one place a device binds)")
        if kind == "tsv":
            # an engine-shaped check: the TSV's own shape is the claim
            if not isinstance(row.get("file"), str) or not row["file"] \
                    or "/" in row["file"] or row["file"].startswith("."):
                raise Finding(f"row {rid}: a tsv row names a top-level file")
            if not isinstance(row.get("columns"), int) or isinstance(row.get("columns"), bool) \
                    or not 1 <= row["columns"] <= 4096:
                raise Finding(f"row {rid}: columns must be an integer 1..4096")
            if "rows_min" in row and (not isinstance(row["rows_min"], int)
                                      or isinstance(row["rows_min"], bool)
                                      or row["rows_min"] < 0):
                raise Finding(f"row {rid}: rows_min must be a non-negative integer")
            for f in ("cmd", "oracle", "oracle_from", "require", "forbid"):
                if f in row:
                    raise Finding(f"row {rid}: a tsv row takes no {f} -- the engine "
                                  "generates the check")
        if kind == "git":
            # the DELIVERY's shape is the claim: required and forbidden paths
            # between the pin and the candidate, evaluated by the engine
            req = row.get("require", [])
            forb = row.get("forbid", [])
            for f, vals in (("require", req), ("forbid", forb)):
                if not isinstance(vals, list) or not all(isinstance(v, str) and v for v in vals):
                    raise Finding(f"row {rid}: {f} must be a list of path globs")
            if not req and not forb:
                raise Finding(f"row {rid}: a git row names require and/or forbid globs")
            for f in ("cmd", "oracle", "oracle_from", "file", "columns"):
                if f in row:
                    raise Finding(f"row {rid}: a git row takes no {f} -- the engine "
                                  "evaluates the delivery itself")
        # the evidence label: what the row's pass is WORTH. The DEFAULT
        # derives from the shape -- an oracle-pinned row IS sealed by
        # construction; an explicit label must match the shape or it's a lie.
        ev = row.get("evidence") or (
            "human" if kind == "ruling" else (
                "sealed" if (oracle or row.get("oracle_from") is not None)
                else "author-reachable"))
        row["evidence"] = ev
        if ev not in EVIDENCE:
            raise Finding(f"row {rid}: evidence must be one of {' '.join(EVIDENCE)}")
        if kind == "ruling" and ev != "human":
            raise Finding(f"row {rid}: a ruling row must carry human evidence")
        if ev == "sealed" and not oracle and row.get("oracle_from") is None:
            raise Finding(f"row {rid}: sealed evidence NEEDS an oracle -- a sealed "
                          "row with nothing pinned is a labeling lie")
        if ev == "author-reachable" and (oracle or row.get("oracle_from") is not None):
            raise Finding(f"row {rid}: an oracle-pinned row is SEALED evidence; "
                          "an author-reachable row ships its checks in the tree")
        if ev == "human" and kind != "ruling":
            raise Finding(f"row {rid}: human evidence completes by a ruling; "
                          "kind must be ruling")
        if "evidence" in row and row.get("oracle") and ev == "human":
            raise Finding(f"row {rid}: human evidence takes no oracle")
        row.setdefault("ro", [])
        row.setdefault("oracle", [])
        row.setdefault("timeout", TIMEOUT_DEFAULT)
        t = row.get("timeout", TIMEOUT_DEFAULT)
        if not isinstance(t, int) or isinstance(t, bool) or t < TIMEOUT_MIN:
            raise Finding(f"row {rid}: timeout must be an integer of at least {TIMEOUT_MIN}")
        if kind == "run" and row.get("driver") == "external":
            if "cmd" in row:
                raise Finding(f"row {rid}: driver=external runs through the review "
                              "path; it takes no cmd")
        elif kind == "run":
            cmd = row.get("cmd")
            if not isinstance(cmd, str) or not cmd.strip():
                raise Finding(f"row {rid}: a run row needs a cmd")
            check_path_list(f"row {rid}", ro, "an ro path")
        by_id[rid] = row
    env_specs = _charter_environments(prog)
    for rid, row in by_id.items():
        if row.get("env"):
            # the row's check leaves the jail only for an environment the owner signed
            if row["env"] not in env_specs:
                raise Finding(f"row {rid}: env {row['env']!r} names no environment in "
                              f"charter.toml; declare [[environment.{row['env']}]] "
                              "(docs/charter.md), or drop env")
            wall = env_specs[row["env"]]["limits"]["wall"]
            if row["timeout"] > wall:
                raise Finding(f"row {rid}: timeout {row['timeout']} exceeds environment "
                              f"{row['env']}'s wall of {wall}s; lower the timeout or raise "
                              "the signed wall")
    for rid, row in by_id.items():
        for d in row["deps"]:
            if d not in by_id:
                raise Finding(f"row {rid} depends on {d}, which doesn't exist")
        if row.get("oracle_from") is not None and row["oracle_from"] not in by_id:
            raise Finding(f"row {rid}: oracle_from names {row['oracle_from']}, which doesn't exist")
        # oracle_from RESOLVES at load: the borrowed oracle joins this row's
        # bound set (a validated-but-never-dereferenced key would make the
        # sealed label hollow -- the review round fired it), and a chain that
        # cycles refuses by name
        seen_of, src = {rid}, row.get("oracle_from")
        while src is not None:
            if src in seen_of:
                raise Finding(f"row {rid}: oracle_from chain cycles at {src}")
            seen_of.add(src)
            src_row = by_id.get(src)
            if src_row is None:
                raise Finding(f"row {rid}: oracle_from names {src}, which doesn't exist")
            for o in src_row.get("oracle", []):
                if o not in row["oracle"]:
                    row["oracle"] = row["oracle"] + [o]
            src = src_row.get("oracle_from")
        if row.get("evidence") == "sealed" and not row["oracle"]:
            raise Finding(f"row {rid}: sealed evidence via oracle_from resolved to an empty oracle")
        if row["kind"] == "run" and row.get("driver") != "external" \
                and row["oracle"] and row.get("runner") != "raw":
            cmd_pt = row["cmd"]
            if re.search(r"(?<![A-Za-z0-9_.-])pytest(?![A-Za-z0-9_])", cmd_pt) \
                    and _parse_pytest_cmd(cmd_pt, row.get("runner")) is None:
                raise Finding(
                    f"row {rid}: sealed pytest command {cmd_pt!r} uses shell syntax or "
                    "an unwrapped invocation that bypasses pytest-guard; write a direct "
                    "'[env K=V ...] [<python> -m] pytest ...' command (or set "
                    'runner = "raw" only if intentionally unguarded)')
        ctl = row.get("control")
        if ctl is not None:
            if not isinstance(ctl, str) or ctl not in by_id:
                raise Finding(f"row {rid}: control {ctl!r} doesn't exist")
            crow = by_id[ctl]
            if crow["kind"] != "run" or crow.get("driver") == "external":
                raise Finding(f"row {rid}: control {ctl!r} must be a runnable check row")
            cseen, ccur = {rid}, ctl
            while ccur is not None:
                if ccur in cseen:
                    raise Finding(f"row {rid}: control chain cycles at {ccur}")
                cseen.add(ccur)
                ccur = (by_id.get(ccur) or {}).get("control")
        colour, stack = {rid: 1}, [rid]
        while stack:
            for d in by_id[stack.pop()]["deps"]:
                if d not in colour:
                    colour[d] = 1
                    stack.append(d)
                elif colour.get(d) == 1 and d == rid:
                    raise Finding(f"row {rid} sits in a dependency loop")
    tgroups = {}
    for row in rows:
        gk = (row["seat"], row["stage"], tuple(row["deps"]))
        prev = tgroups.get(gk)
        if prev is not None and prev[1] != row.get("reviewer"):
            raise Finding(
                f"rows {prev[0]} and {row['id']} share ({row['seat']}, {row['stage']}, deps) "
                "and form one task, so they must name the same reviewer")
        tgroups.setdefault(gk, (row["id"], row.get("reviewer")))
    with open(path, "rb") as f:
        prog_key = hashlib.sha256(f.read()).hexdigest()[:16]
    return {"setup": setup, "rows": [by_id[r["id"]] for r in rows], "by_id": by_id, "prog_key": prog_key}


def stages_of(contract):
    out = []
    for row in contract["rows"]:
        if row["stage"] not in out:
            out.append(row["stage"])
    return out


def tasks_of(contract):
    """Rows with the same seat, stage and deps form one task."""
    out = {}
    for row in contract["rows"]:
        key = (row["seat"], row["stage"], tuple(row["deps"]))
        out.setdefault(key, []).append(row["id"])
    return out


def label_of(row):
    ev = row.get("evidence")
    if ev in EVIDENCE:
        return ev
    if row["kind"] == "ruling":
        return "human"
    return "sealed" if row.get("oracle") else "author-reachable"


_PROV_RANK = {"author-reachable": 0, "human": 1, "sealed": 2}
_RANK_PROV = {v: k for k, v in _PROV_RANK.items()}


def effective_label_of(contract, rid):
    """Weakest-link provenance across `rid` and all transitive `deps` (plus `control`)."""
    by_id = contract["by_id"]
    if rid not in by_id:
        return "author-reachable"
    seen = set()
    stack = [rid]
    weakest = _PROV_RANK.get(label_of(by_id[rid]), 0)
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in by_id:
            continue
        seen.add(cur)
        r = by_id[cur]
        rk = _PROV_RANK.get(label_of(r), 0)
        if rk < weakest:
            weakest = rk
        for d in r.get("deps") or ():
            if d not in seen:
                stack.append(d)
        ctl = r.get("control")
        if ctl and ctl not in seen:
            stack.append(ctl)
    return _RANK_PROV[weakest]


# --- results: call-log rows keyed by row, commit and arm -----------------------------

def call_log():
    return os.environ.get("CALL_LOG_FILE") or os.path.join(
        os.environ.get("OPERATOR_HOME", os.path.join(ROOT, "state")), "call-log.tsv")


def results_for(contract, commit, arm, pin=None):
    """Reads the call log and maps (row, commit, arm) -> (rc, call_id), only after the
    chain verifies, so an edited or lazily forged row never yields a kept green. A
    same-user forger who recomputes the whole chain can still plant a row: that limit
    is the call log's own, stated in its header, and the engine runs as a non-production
    UID in CI to keep the window narrow. A row whose keys don't parse is left out."""
    log = call_log()
    if not os.path.isfile(log):
        return {}
    v = sh([os.path.join(ROOT, "bin", "call-log.sh"), "verify"])
    if v.returncode != 0:
        raise Void("the call log doesn't verify, so no stored result can be trusted")
    out = {}
    with open(log, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 10 or not parts[2].startswith("check:") or parts[3] == "-":
                continue
            keys = dict(kv.split("=", 1) for kv in parts[3].split(",") if "=" in kv)
            if keys.get("overlay") == "off":
                continue  # an overlay-off vacuous-proof row never certifies a contract check
            if pin:
                rdef = contract["by_id"].get(keys.get("row")) or {}
                is_sealed = bool(rdef.get("oracle") or rdef.get("expect_base_fail"))
                if ("pin" in keys and keys["pin"] != pin) or (is_sealed and "pin" not in keys):
                    continue
            if set(keys) >= {"prog", "row", "commit", "arm", "rc"} \
                    and keys["prog"] == contract["prog_key"]:
                try:
                    out[(keys["row"], keys["commit"], keys["arm"])] = (int(keys["rc"]), parts[1])
                except ValueError:
                    continue
    return out


def record(row_id, commit, arm, rc, runfile, prog_key, pin=None, overlay_off=False, extra=()):
    """Files one result row. `extra` adds keys a row's own door carries (an environment)."""
    argv = [os.path.join(ROOT, "bin", "call-log.sh"), "record", f"check:{row_id}",
            "--key", f"prog={prog_key}", "--key", f"row={row_id}", "--key", f"commit={commit}",
            "--key", f"arm={arm}", "--key", f"rc={rc}"]
    if pin:
        argv += ["--key", f"pin={pin}"]
    if overlay_off:
        argv += ["--key", "overlay=off"]
    for k, v in extra:
        argv += ["--key", f"{k}={v}"]
    argv += ["--", "cat", runfile]
    r = sh(argv)
    if r.returncode != 0 or not r.stdout.strip():
        raise Void(f"the call log refused the result row for {row_id}: {r.stderr.strip()}")
    return r.stdout.strip()


def record_setup(commit, arm, rc, runfile, prog_key):
    argv = [os.path.join(ROOT, "bin", "call-log.sh"), "record", "setup:env",
            "--key", f"prog={prog_key}", "--key", "phase=setup",
            "--key", f"commit={commit}", "--key", f"arm={arm}",
            "--key", f"rc={rc}", "--", "cat", runfile]
    r = sh(argv)
    if r.returncode != 0 or not r.stdout.strip():
        raise Void(f"the call log refused the setup receipt: {r.stderr.strip()}")
    return r.stdout.strip()


# --- run_check ------------------------------------------------------------------------

def git(repo, *args):
    r = sh(["git", "-C", repo, *args])
    if r.returncode != 0:
        raise Void(f"git {' '.join(args[:2])} failed: {(r.stderr or r.stdout).strip()[:160]}")
    return r.stdout.strip()


def verify_export_attrs(repo):
    attrs = os.path.join(repo, ".git", "info", "attributes") if os.path.isdir(os.path.join(repo, ".git")) \
        else os.path.join(repo, "info", "attributes")
    try:
        with open(attrs, encoding="utf-8") as f:
            body = f.read().strip()
    except OSError:
        raise Void("the work repo has no info/attributes; the export wouldn't be the commit")
    if body != ATTRIBUTES:
        raise Void("the work repo's info/attributes must be exactly the pinned export line: "
                   "a later line would take precedence over it in git")


def resolve():
    """The repo with its export line verified, and the tip resolved to a commit, so a
    result key names a commit, never a ref that moved."""
    repo = repo_for()
    verify_export_attrs(repo)
    return repo, git(repo, "rev-parse", os.environ.get("CONTRACT_TIP") or "HEAD")


def export_commit(repo, commit, dest):
    verify_export_attrs(repo)
    p1 = subprocess.Popen(["git", "-C", repo, "archive", commit], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    p2 = subprocess.Popen(["tar", "-x", "-C", dest], stdin=p1.stdout, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    p1.stdout.close()
    if p2.wait() != 0 or p1.wait() != 0:
        raise Void(f"couldn't export {commit[:12]}")


def _step_parent_of(repo, pin, commit):
    """Return the promoted step parent `commit^1` when `pin` is a strict
    ancestor of `commit^1` (multi-step chain T0 -> C1 -> ... -> Ck);
    otherwise return `pin` (single-step run or root check)."""
    if not pin or not commit or commit == pin:
        return pin
    rp1 = sh(["git", "-C", repo, "rev-parse", "--verify", f"{commit}^1^{{commit}}"])
    if rp1.returncode != 0 or not rp1.stdout.strip():
        return pin
    p1 = rp1.stdout.strip()
    if p1 == pin:
        return pin
    anc = sh(["git", "-C", repo, "merge-base", "--is-ancestor", pin, p1])
    if anc.returncode == 0:
        return p1
    return pin


def git_check(row, prog, repo, commit):
    """The delivery's shape, evaluated by the engine against the diff between
    the step parent (or root pin when diff_base='pin') and the candidate:
    every require glob matches at least one changed path, no forbid glob
    matches any. No shell runs."""
    raw_pin = os.environ.get("CONTRACT_PIN") or commit
    rp = sh(["git", "-C", repo, "rev-parse", "--verify", f"{raw_pin}^{{commit}}"])
    pin = rp.stdout.strip() if (rp.returncode == 0 and rp.stdout.strip()) else raw_pin
    base_ref = pin if row.get("diff_base") == "pin" else _step_parent_of(repo, pin, commit)
    try:
        out = git(repo, "diff-tree", "-r", "--no-renames", "--name-only", base_ref, commit)
    except Void as e:
        return 1, f"the diff between the pin and the candidate didn't read: {e}"
    paths = [x for x in out.splitlines() if x.strip()]
    why = []
    ok = True
    for g in row.get("require", []):
        hit = [p for p in paths if fnmatch.fnmatch(p, g)]
        if not hit:
            ok = False
            why.append(f"require {g!r}: nothing changed under it")
        else:
            why.append(f"require {g!r}: {len(hit)} path(s)")
    for g in row.get("forbid", []):
        hit = [p for p in paths if fnmatch.fnmatch(p, g)]
        if hit:
            ok = False
            why.append(f"forbid {g!r}: {hit[:4]} changed under it")
        else:
            why.append(f"forbid {g!r}: clean")
    return (0 if ok else 1), "\n".join(why)


def tsv_check(row, prog, repo, commit):
    """The named TSV's own shape: N columns on every row, at least rows_min
    rows, utf-8. The engine reads the candidate's file directly -- no shell,
    no oracle; the file IS the claim. Refuses symlinks and caps file size."""
    import stat as _stat
    tmp = tempfile.mkdtemp(prefix="tsv.")
    try:
        export = os.path.join(tmp, "x")
        os.mkdir(export)
        export_commit(repo, commit, export)
        p = os.path.join(export, row["file"])
        if os.path.islink(p):
            return 1, f"{row['file']} is a symlink at the candidate; refusing to follow"
        if not os.path.isfile(p):
            return 1, f"{row['file']} doesn't exist at the candidate"
        try:
            flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
            fd = os.open(p, flags)
            try:
                st = os.fstat(fd)
                if not _stat.S_ISREG(st.st_mode):
                    return 1, f"{row['file']} is not a regular file at the candidate"
                if st.st_size > TSV_MAX_BYTES:
                    return 1, f"{row['file']} exceeds {TSV_MAX_BYTES} bytes"
                with os.fdopen(fd, "rb") as f:
                    raw = f.read(TSV_MAX_BYTES + 1)
                fd = -1
            finally:
                if fd >= 0:
                    os.close(fd)
            if len(raw) > TSV_MAX_BYTES:
                return 1, f"{row['file']} exceeds {TSV_MAX_BYTES} bytes"
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as e:
            return 1, f"{row['file']} won't read as utf-8: {e}"
        lines = [ln for ln in text.splitlines() if ln.strip()]
        floor = max(row.get("rows_min", 1), 1)  # an empty file is never green
        if len(lines) < floor:
            return 1, f"{len(lines)} rows < rows_min {floor}"
        n = row["columns"]
        for i, ln in enumerate(lines, 1):
            if ln.count("\t") + 1 != n:
                return 1, f"row {i} has {ln.count(chr(9)) + 1} columns, not {n}"
        return 0, f"{len(lines)} rows x {n} columns, utf-8"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


DISK_FLOOR = 512 * 1024 * 1024  # refuse check/setup jails when free disk < 512 MiB


def _assert_disk_floor(path):
    try:
        st = os.statvfs(path)
        if st.f_bavail * st.f_frsize < DISK_FLOOR:
            raise Void("free disk space is below 512 MiB; refusing to start check jail")
    except OSError:
        pass


def _match_repo_glob(rel_path, pat):
    """Match repo-relative path against `pat`, supporting `**/` zero-or-more segments."""
    if pat == "**":
        return True
    parts = pat.split("/")
    rx = ["^"]
    i = 0
    while i < len(parts):
        seg = parts[i]
        if seg == "**":
            if i + 1 < len(parts):
                rx.append("(?:.+/)?")
                i += 1
                continue
            rx.append(".*")
        else:
            s_rx = ""
            for ch in seg:
                if ch == "*":
                    s_rx += "[^/]*"
                elif ch == "?":
                    s_rx += "[^/]"
                else:
                    s_rx += re.escape(ch)
            rx.append(s_rx)
            if i + 1 < len(parts):
                rx.append("/")
        i += 1
    rx.append("$")
    return bool(re.match("".join(rx), rel_path))


def _assert_no_symlink_ancestors(root_dir, rel_path, ctx):
    cur = root_dir
    for part in rel_path.split("/")[:-1]:
        if not part:
            continue
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            raise Void(f"{ctx}: symlink ancestor at {rel_path!r} refused")


def _git_ls_entries(repo, rev):
    r = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-t", "-z", rev],
                       capture_output=True, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        raise Void(f"git ls-tree failed on {rev[:12]}")
    entries = {}
    for rec in r.stdout.split(b"\0"):
        if not rec:
            continue
        head, path_b = rec.split(b"\t", 1)
        mode, typ, oid = head.decode("ascii").split()
        p = path_b.decode("utf-8", "surrogateescape")
        entries[p] = (mode, typ, oid)
    return entries


def _resolve_oracle_at_pin(repo, pin, patterns, row_id):
    entries = _git_ls_entries(repo, pin)
    matched = []
    for pat in patterns:
        if any(c in pat for c in "*?["):
            hits = sorted(
                (p, info[1]) for p, info in entries.items()
                if info[1] in ("tree", "blob") and info[0] not in ("120000", "160000")
                and _match_repo_glob(p, pat)
            )
            if not hits:
                raise Void(f"row {row_id}: oracle {pat!r} isn't a directory at the pin (zero matches)")
            matched.extend(hits)
        else:
            info = entries.get(pat)
            if info is None or info[1] not in ("tree", "blob") or info[0] in ("120000", "160000"):
                raise Void(f"row {row_id}: oracle {pat!r} isn't a directory at the pin, so it can't bind")
            matched.append((pat, info[1]))
    # Deduplicate and drop paths nested inside an already-bound oracle directory
    trees = {p for p, t in matched if t == "tree"}
    dedup = []
    seen = set()
    for p, t in matched:
        if p in seen:
            continue
        if any(p != tr and p.startswith(tr + "/") for tr in trees):
            continue
        seen.add(p)
        dedup.append((p, t))
    return dedup


def _seat_allowed_writes(prog, row_id):
    tpath = os.path.join(prog, "team.toml")
    if not os.path.isfile(tpath):
        return None
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import team as team_mod
    try:
        _, seats_doc, _ = team_mod.load(prog)
    except Exception:
        return None
    contract = load(prog)
    by_id = contract["by_id"]
    row = by_id.get(row_id)
    if not row or row["seat"] not in seats_doc or "write" not in seats_doc[row["seat"]]:
        return None
    return list(seats_doc[row["seat"]].get("write") or [])


def _apply_candidate_diff(repo, pin, commit, export, allowed_writes, resolved_oracles, row_id):
    if pin == commit:
        return
    r = subprocess.run(["git", "-C", repo, "diff-tree", "-r", "--no-renames", "-z", pin, commit],
                       capture_output=True, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        raise Void(f"row {row_id}: git diff-tree {pin[:12]}..{commit[:12]} failed")
    tokens = [t for t in r.stdout.split(b"\0") if t]
    oracle_trees = [p for p, t in resolved_oracles if t == "tree"]
    oracle_blobs = {p for p, t in resolved_oracles if t == "blob"}
    i = 0
    while i + 1 < len(tokens):
        meta_s = tokens[i].decode("ascii", "replace")
        rel_path = tokens[i + 1].decode("utf-8", "surrogateescape")
        i += 2
        parts = meta_s.lstrip(":").split()
        if len(parts) < 5:
            continue
        new_mode, new_oid, status = parts[1], parts[3], parts[4][0]
        in_oracle = (rel_path in oracle_blobs) or any(
            rel_path == tr or rel_path.startswith(tr + "/") for tr in oracle_trees
        )
        if allowed_writes is not None and not in_oracle:
            if not any(_match_repo_glob(rel_path, g) for g in allowed_writes):
                raise Finding(f"row {row_id}: candidate modified {rel_path!r} outside seat write grants")
        dst = os.path.join(export, rel_path)
        if status == "D":
            if os.path.isdir(dst) and not os.path.islink(dst):
                shutil.rmtree(dst, ignore_errors=True)
            elif os.path.lexists(dst):
                os.unlink(dst)
            parent_d = os.path.dirname(dst)
            while parent_d and os.path.abspath(parent_d) != os.path.abspath(export):
                try:
                    os.rmdir(parent_d)
                except OSError:
                    break
                parent_d = os.path.dirname(parent_d)
        else:
            if new_mode in ("120000", "160000"):
                if not in_oracle:
                    raise Finding(f"row {row_id}: candidate planted forbidden mode {new_mode} at {rel_path!r}")
                # Oracle symlinks are overwritten when binds_ok is True; materialize for vacuous-proof mode
                blob = subprocess.run(["git", "-C", repo, "cat-file", "blob", new_oid],
                                      capture_output=True, stdin=subprocess.DEVNULL)
                _assert_no_symlink_ancestors(export, rel_path, f"row {row_id}")
                _mkdir_parent_or_finding(dst, f"row {row_id}")
                if os.path.isdir(dst) and not os.path.islink(dst):
                    shutil.rmtree(dst, ignore_errors=True)
                elif os.path.lexists(dst):
                    os.unlink(dst)
                if new_mode == "120000":
                    os.symlink(blob.stdout.decode("utf-8", "surrogateescape"), dst)
                continue
            _assert_no_symlink_ancestors(export, rel_path, f"row {row_id}")
            _mkdir_parent_or_finding(dst, f"row {row_id}")
            if os.path.isdir(dst) and not os.path.islink(dst):
                shutil.rmtree(dst, ignore_errors=True)
            elif os.path.lexists(dst):
                os.unlink(dst)
            blob = subprocess.run(["git", "-C", repo, "cat-file", "blob", new_oid],
                                  capture_output=True, stdin=subprocess.DEVNULL)
            if blob.returncode != 0:
                raise Void(f"row {row_id}: missing blob {new_oid[:12]} for {rel_path!r}")
            with open(dst, "wb") as wf:
                wf.write(blob.stdout)
            if new_mode == "100755":
                os.chmod(dst, 0o755)


_RESERVED_GUARD_ENV = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONINSPECT", "PYTHONSTARTUP",
    "PYTHONHOME", "HOME", "PATH", "PROG",
})


def _mkdir_parent_or_finding(dst, label):
    try:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
    except OSError as e:
        raise Finding(f"{label}: candidate obstructed parent directory ({e})")


def _parse_pytest_cmd(cmd_str, runner_override=None):
    if any(ch in cmd_str for ch in (";", "|", "&", "`", "$(", ">", "<", "\n", "\r")):
        return None
    try:
        toks = shlex.split(cmd_str)
    except ValueError:
        return None
    if not toks:
        return None
    env_pairs = []
    py_path = []
    if toks[0] == "env":
        toks = toks[1:]
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        k, v = toks[0].split("=", 1)
        if k == "PYTHONPATH":
            py_path = [p for p in v.split(":") if p]
        elif k not in _RESERVED_GUARD_ENV:
            env_pairs.append((k, v))
        toks = toks[1:]
    if not toks:
        return None
    base0 = os.path.basename(toks[0])
    if re.fullmatch(r"pytest(?:-\d+(?:\.\d+)*)?", base0):
        py_exe = os.path.join(os.path.dirname(toks[0]), "python") if "/" in toks[0] else "python3"
        return py_exe, ["-I"], toks[1:], tuple(env_pairs), tuple(py_path)
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", base0):
        py_flags = ["-I"]
        i = 1
        while i < len(toks) and toks[i] != "-m":
            fl = toks[i]
            if fl in ("-I", "-s", "-S", "-E", "-P"):
                i += 1
            elif fl in ("-B", "-O", "-OO", "-u", "-q", "-v", "-b", "-d"):
                if fl not in py_flags:
                    py_flags.append(fl)
                i += 1
            elif fl in ("-W", "-X") and i + 1 < len(toks):
                py_flags.extend((fl, toks[i + 1]))
                i += 2
            elif fl.startswith(("-W", "-X")) and len(fl) > 2:
                py_flags.append(fl)
                i += 1
            else:
                return None
        if i + 1 < len(toks) and toks[i] == "-m" and toks[i + 1] == "pytest":
            return toks[0], py_flags, toks[i + 2:], tuple(env_pairs), tuple(py_path)
    if runner_override == "pytest":
        return "python3", ["-I"], toks, tuple(env_pairs), tuple(py_path)
    return None


def _has_skip_decorator(node):
    for dec in getattr(node, "decorator_list", ()):
        txt = ast.unparse(dec)
        if any(k in txt for k in ("skip", "xfail")):
            return True
    return False


def _pin_unskipped_pytest_nodes(od_root, resolved_oracles):
    """Static AST discovery of unskipped test functions/methods under pinned oracle paths."""
    unskipped = set()
    for o_path, o_typ in resolved_oracles:
        base_p = os.path.join(od_root, o_path)
        py_files = []
        if o_typ == "blob" and base_p.endswith(".py") and os.path.isfile(base_p):
            py_files.append((o_path, base_p))
        elif os.path.isdir(base_p):
            for rd, _, fns in os.walk(base_p):
                for fn in sorted(fns):
                    if fn.endswith(".py") and (fn.startswith("test_") or fn.endswith("_test.py")):
                        fp = os.path.join(rd, fn)
                        rel = os.path.relpath(fp, od_root).replace(os.sep, "/")
                        py_files.append((rel, fp))
        for rel, fp in py_files:
            try:
                tree = ast.parse(open(fp, encoding="utf-8").read(), filename=rel)
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                    if not _has_skip_decorator(node):
                        unskipped.add(f"{rel}::{node.name}")
                elif isinstance(node, ast.ClassDef) and node.name.startswith("Test") and not _has_skip_decorator(node):
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                            if not _has_skip_decorator(item):
                                unskipped.add(f"{rel}::{node.name}::{item.name}")
    return unskipped


def _verify_pytest_receipt(rec_path, guard_key, min_tests, pin_unskipped):
    if not os.path.isfile(rec_path):
        return False, "missing pytest-guard receipt (process exited before sessionfinish)"
    try:
        doc = json.load(open(rec_path, encoding="utf-8"))
        payload = doc["payload"]
        got_mac = str(doc["hmac"])
    except Exception as e:
        return False, f"invalid pytest-guard receipt JSON: {e}"
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    want_mac = hmac.new(guard_key, canon, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want_mac, got_mac):
        return False, "forged pytest-guard HMAC receipt"
    if not payload.get("runner_intact"):
        return False, "pytest/unittest runner hooks or assertions were monkey-patched"
    if int(payload.get("failed", 0)) > 0 or int(payload.get("errors", 0)) > 0:
        return False, f"pytest reported failed={payload.get('failed')} errors={payload.get('errors')}"
    if int(payload.get("exitstatus", 1)) != 0:
        return False, f"pytest exitstatus={payload.get('exitstatus')}"
    floor = max(1, int(min_tests or 0))
    if int(payload.get("passed", 0)) < floor:
        return False, f"pytest passed={payload.get('passed')} < required floor {floor}"
    if pin_unskipped:
        passed_bases = {nid.split("[", 1)[0] for nid in (payload.get("passed_ids") or ())}
        skipped_bases = {nid.split("[", 1)[0] for nid in (payload.get("skipped_ids") or ())}
        newly_skipped = sorted(pin_unskipped & skipped_bases)
        if newly_skipped:
            return False, f"pinned test(s) skipped at runtime: {newly_skipped[:3]}"
        missing = sorted(pin_unskipped - passed_bases)
        if missing:
            return False, f"pinned test(s) deselected or unexecuted: {missing[:3]}"
    return True, ""


def run_check(row, prog, repo, commit, arm, results, prog_key, record_log=True, transplant=None, check_seat_writes=True):
    """Runs one row's check through the jail. Returns (rc, runfile_path, call_id).
    Oracle paths pin at CONTRACT_PIN (the ruled base commit), never at the moving tip,
    so the overlay holds what the ruling froze."""
    raw_pin = os.environ.get("CONTRACT_PIN")
    if row["oracle"] and not raw_pin:
        raise Void(f"row {row['id']}: sealed row requires CONTRACT_PIN; refusing to pin candidate tip")
    if row.get("expect_base_fail") and not raw_pin:
        raise Void(f"row {row['id']}: expect_base_fail row requires CONTRACT_PIN; refusing to pin candidate tip")
    if raw_pin:
        rp = sh(["git", "-C", repo, "rev-parse", "--verify", f"{raw_pin}^{{commit}}"])
        if rp.returncode != 0:
            raise Void(f"row {row['id']}: CONTRACT_PIN {raw_pin!r} isn't a commit in {repo}")
        pin = rp.stdout.strip()
    else:
        pin = commit
    tmp = tempfile.mkdtemp(prefix="contract.")
    _assert_disk_floor(tmp)
    binds_ok = os.environ.get("OPERATOR_OVERLAY_OFF") != "1"
    if not binds_ok and os.environ.get("OPERATOR_HOLLOW_VACUOUS_PROOF") != "1":
        raise Void("OPERATOR_OVERLAY_OFF is refused outside the vacuous-proof test seam")
    runfile = None
    try:
        export = os.path.join(tmp, "x")
        os.mkdir(export)
        binds = []
        od = os.path.join(tmp, "o")
        os.makedirs(od, exist_ok=True)
        resolved_oracles = _resolve_oracle_at_pin(repo, pin, row["oracle"], row["id"]) if row["oracle"] else []
        if row["oracle"] and binds_ok:
            step_base = _step_parent_of(repo, pin, commit) if check_seat_writes else commit
            export_commit(repo, step_base, export)
            allowed_writes = (
                _seat_allowed_writes(prog, row["id"])
                if (transplant is None and check_seat_writes)
                else None
            )
            _apply_candidate_diff(repo, step_base, commit, export, allowed_writes, resolved_oracles, row["id"])
        else:
            export_commit(repo, commit, export)
        if transplant is not None:
            cand_sha, test_patterns = transplant
            try:
                tp_resolved = _resolve_oracle_at_pin(repo, cand_sha, test_patterns, row["id"])
            except Void:
                return 0, None, "transplant-missing"
            td_arch = os.path.join(tmp, "tp")
            os.makedirs(td_arch, exist_ok=True)
            for tp_path, tp_typ in tp_resolved:
                arch = subprocess.Popen(["git", "-C", repo, "archive", cand_sha, "--", tp_path],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
                untar = subprocess.Popen(["tar", "-x", "-C", td_arch], stdin=arch.stdout,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                arch.stdout.close()
                if untar.wait() != 0 or arch.wait() != 0:
                    return 0, None, "transplant-failed"
                src_tp = os.path.join(td_arch, tp_path)
                dst_tp = os.path.join(export, tp_path)
                _assert_no_symlink_ancestors(export, tp_path, f"row {row['id']}")
                os.makedirs(os.path.dirname(dst_tp), exist_ok=True)
                if os.path.isdir(dst_tp) and not os.path.islink(dst_tp):
                    shutil.rmtree(dst_tp, ignore_errors=True)
                elif os.path.lexists(dst_tp):
                    os.unlink(dst_tp)
                if tp_typ == "tree":
                    shutil.copytree(src_tp, dst_tp, symlinks=False)
                else:
                    shutil.copy2(src_tp, dst_tp)
        for o_path, o_typ in resolved_oracles:
            arch = subprocess.Popen(["git", "-C", repo, "archive", pin, "--", o_path],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            untar = subprocess.Popen(["tar", "-x", "-C", od], stdin=arch.stdout,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            arch.stdout.close()
            if untar.wait() != 0 or arch.wait() != 0:
                raise Void(f"row {row['id']}: oracle {o_path!r} didn't export from the pin")
            gone = os.path.join(export, o_path)
            if binds_ok:
                if o_typ == "tree" and (os.path.islink(gone) or os.path.isfile(gone)):
                    raise Void(f"row {row['id']}: oracle {o_path!r} is a file at the candidate; refusing the swap")
                if o_typ == "blob" and (os.path.islink(gone) or os.path.isdir(gone)):
                    raise Void(f"row {row['id']}: oracle {o_path!r} is a directory or link at the candidate; refusing the swap")
                # the pin lands OVER the candidate's copy: the candidate's
                # version of the oracle never runs (the overlay's whole point)
                _assert_no_symlink_ancestors(export, o_path, f"row {row['id']}")
                if o_typ == "tree":
                    shutil.rmtree(gone, ignore_errors=True)
                    os.makedirs(gone, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(gone), exist_ok=True)
                    if os.path.lexists(gone):
                        os.unlink(gone)
                    open(gone, "wb").close()
                binds += ["--ro-bind", os.path.join(od, o_path),
                          os.path.join("/w/export", o_path)]
        if row["oracle"] and binds_ok:
            # Seal root and nested test-runner config files against candidate tampering:
            # restore pinned blob read-only or remove candidate-planted copy.
            rcfg_dir = os.path.join(tmp, "rcfg")
            os.makedirs(rcfg_dir, exist_ok=True)
            pin_entries = _git_ls_entries(repo, pin)
            exp_files = []
            for rd_e, _, fns_e in os.walk(export):
                for fn_e in fns_e:
                    fp_e = os.path.join(rd_e, fn_e)
                    exp_files.append(os.path.relpath(fp_e, export).replace(os.sep, "/"))
            mutable_set = set(row.get("mutable_configs") or ())
            oracle_trees = [p for p, t in resolved_oracles if t == "tree"]
            oracle_blobs = {p for p, t in resolved_oracles if t == "blob"}
            seen_rcfg = set()
            rcfg_idx = 0
            for cfg in RUNNER_CONFIG_NAMES:
                if any(c in cfg for c in "*?["):
                    targets = sorted(
                        p for p in (set(pin_entries) | set(exp_files))
                        if _match_repo_glob(p, cfg)
                    )
                else:
                    targets = [cfg]
                for rel_cfg in targets:
                    if rel_cfg in seen_rcfg or rel_cfg in mutable_set or rel_cfg in oracle_blobs:
                        continue
                    if any(rel_cfg == tr or rel_cfg.startswith(tr + "/") for tr in oracle_trees):
                        continue
                    seen_rcfg.add(rel_cfg)
                    cand_cfg = os.path.join(export, rel_cfg)
                    pinfo = pin_entries.get(rel_cfg)
                    if pinfo and pinfo[1] == "blob" and pinfo[0] not in ("120000", "160000"):
                        blob = subprocess.run(["git", "-C", repo, "cat-file", "blob", pinfo[2]],
                                              capture_output=True, stdin=subprocess.DEVNULL)
                        if blob.returncode == 0:
                            _assert_no_symlink_ancestors(export, rel_cfg, f"row {row['id']}")
                            _mkdir_parent_or_finding(cand_cfg, f"row {row['id']}")
                            if os.path.isdir(cand_cfg) and not os.path.islink(cand_cfg):
                                shutil.rmtree(cand_cfg, ignore_errors=True)
                            elif os.path.lexists(cand_cfg):
                                os.unlink(cand_cfg)
                            open(cand_cfg, "wb").close()
                            rcfg_idx += 1
                            pin_file = os.path.join(rcfg_dir, f"rcfg_{rcfg_idx}")
                            with open(pin_file, "wb") as f:
                                f.write(blob.stdout)
                            binds += ["--ro-bind", pin_file, os.path.join("/w/export", rel_cfg)]
                    else:
                        if os.path.isdir(cand_cfg) and not os.path.islink(cand_cfg):
                            shutil.rmtree(cand_cfg, ignore_errors=True)
                        elif os.path.lexists(cand_cfg):
                            os.unlink(cand_cfg)
        prog_real = os.path.realpath(prog)
        for r in row["ro"]:
            src = r if os.path.isabs(r) else os.path.join(prog, r)
            if not os.path.exists(src):
                raise Void(f"row {row['id']}: ro path {r!r} doesn't exist")
            if not os.path.isabs(r):
                sreal = os.path.realpath(src)
                if sreal != prog_real and not sreal.startswith(prog_real + os.sep):
                    raise Void(f"row {row['id']}: ro path {r!r} escapes program dir via symlink")
            binds += ["--ro-bind", src, os.path.join("/w/ro", r)]
        if row.get("gpu"):
            nodes = nvidia_nodes()
            if not nodes:
                raise Void(f"row {row['id']}: gpu=true but this host has no nvidia "
                           "devices (want /dev/nvidiactl, /dev/nvidia[0-9]*, "
                           "/dev/nvidia-uvm); run it on the GPU host, or drop gpu")
            binds += [x for n in nodes for x in ("--dev-bind", n, n)]
        guard_key = None
        rec_host = None
        pin_unskipped = set()
        inner_cmd = ["/bin/sh", "-c", row["cmd"]]
        pt_parsed = (
            _parse_pytest_cmd(row["cmd"], row.get("runner"))
            if (row["oracle"] and binds_ok
                and row.get("runner") != "raw")
            else None
        )
        guard_env = ()
        if pt_parsed is not None:
            py_exe, py_flags, pt_args, guard_env, py_path = pt_parsed
            guard_key = os.urandom(32).hex().encode("ascii")
            g_in = os.path.join(tmp, "g_in")
            g_meta = os.path.join(tmp, "g_meta")
            rec_host = os.path.join(tmp, "g_out")
            with open(g_in, "wb") as kf:
                kf.write(guard_key + b"\n")
            with open(g_meta, "w", encoding="utf-8") as mf:
                json.dump({
                    "oracle_roots": [os.path.join("/w/export", o) for o, _ in resolved_oracles],
                    "pythonpath": list(py_path),
                }, mf)
            open(rec_host, "wb").close()
            os.chmod(g_in, 0o600)
            os.chmod(rec_host, 0o600)
            pin_unskipped = _pin_unskipped_pytest_nodes(od, resolved_oracles)
            binds += [
                "--ro-bind", os.path.join(ROOT, "bin", "lib", "pytest-guard.py"), "/engine/pytest-guard.py",
                "--bind", g_in, "/w/.op-key",
                "--bind", g_meta, "/w/.op-meta",
                "--bind", rec_host, "/w/.op-receipt",
            ]
            inner_cmd = [py_exe, *py_flags, "/engine/pytest-guard.py", *pt_args]
        etc = generated_etc(tmp)
        env_dir = os.path.join(prog, "env") if os.path.isdir(os.path.join(prog, "env")) else None
        extra = list(binds)
        for f in ("passwd", "hosts", "machine-id", "hostname"):
            extra += ["--ro-bind", os.path.join(etc, f), f"/etc/{f}"]
        if env_dir:
            extra += ["--ro-bind", env_dir, "/env"]
        extra += ["--ro-bind", os.path.abspath(prog), "/prog"]
        inner_limits = ["prlimit", f"--nproc={NPROC}"]
        if not row.get("gpu"):
            inner_limits.append(f"--as={as_cap()}")
        base_setenvs = (
            ("HOME", "/tmp"), ("PATH", "/usr/bin:/bin"),
            ("PROG", "/prog"), ("NO_COLOR", "1"),
            ("TERM", "dumb"), ("PYTHONSAFEPATH", "1"),
            ("PYTHONNOUSERSITE", "1"),
            ("PYTHONDONTWRITEBYTECODE", "1"),
            *guard_env,
        )
        env_meta = None
        if row.get("env"):
            # The environment door: the same export, the same read-only overlays
            # (the pinned oracle, the runner configs, pytest-guard's files) at the
            # same paths, in a container the owner signed. bin/environment.py is
            # the only container client and verifies the ruling before every run.
            import environment as env_mod
            rc, kept, env_meta = env_mod.run_check_env(
                prog, row["env"], export, env_mod.overlays_of(binds), inner_cmd,
                base_setenvs, row["timeout"], OUT_CAP)
        else:
            argv = ["prlimit", f"--fsize={FSIZE}", "--core=0"] + \
                bwrap_args(binds=extra, setenvs=base_setenvs,
                           chdir="/w/export", export=export, export_dest="/w/export") + \
                inner_limits + inner_cmd
            rc, kept = run_capped(argv, row["timeout"], OUT_CAP)
        if guard_key is not None:
            g_ok, g_why = _verify_pytest_receipt(rec_host, guard_key, row.get("min_tests", 1), pin_unskipped)
            if not g_ok:
                rc = 1
                kept = (kept + f"\n[pytest-guard] {g_why}\n".encode("utf-8"))[-OUT_CAP:]
        if not record_log:
            return rc, None, "base-probe"
        runfile = os.path.join(prog, "runs", f"{row['id']}.{commit[:12]}.out")
        os.makedirs(os.path.dirname(runfile), exist_ok=True)
        with open(runfile, "wb") as f:
            f.write(kept)
        cid = record(row["id"], commit, arm, rc, runfile, prog_key,
                     pin=pin if (row["oracle"] or row.get("expect_base_fail")) else None,
                     overlay_off=not binds_ok,
                     extra=(("env", row["env"]), ("image", env_meta["image"])) if env_meta else ())
        return rc, runfile, cid
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_BASE_FAIL_CACHE = {}


def _verify_expect_base_fail(row, prog, repo, commit, arm, done, prog_key):
    """Negative differential control (FAIL_ON_BASE): when row.expect_base_fail is
    true, verify that row['cmd'] exits non-zero at CONTRACT_PIN (with optional
    candidate `test_paths` transplanted onto CONTRACT_PIN) before accepting a
    candidate pass. Returns (ok_bool, why_if_failed, pin_sha)."""
    raw_pin = os.environ.get("CONTRACT_PIN")
    if not raw_pin:
        raise Void(f"row {row['id']}: expect_base_fail requires CONTRACT_PIN")
    rp = sh(["git", "-C", repo, "rev-parse", "--verify", f"{raw_pin}^{{commit}}"])
    if rp.returncode != 0 or not rp.stdout.strip():
        raise Void(f"row {row['id']}: CONTRACT_PIN {raw_pin!r} isn't a commit in {repo}")
    pin_sha = rp.stdout.strip()
    if pin_sha == commit:
        return False, f"candidate {commit[:12]} equals CONTRACT_PIN; nothing changed from base", pin_sha
    tpaths = tuple(row.get("test_paths") or ())
    ck = (prog_key, row["id"], row["cmd"], pin_sha, tpaths, commit if tpaths else "")
    if ck not in _BASE_FAIL_CACHE:
        tp_arg = (commit, list(tpaths)) if tpaths else None
        brc, _, _ = run_check(row, prog, repo, pin_sha, arm, done, prog_key,
                              record_log=False, transplant=tp_arg, check_seat_writes=False)
        _BASE_FAIL_CACHE[ck] = brc
    if _BASE_FAIL_CACHE[ck] == 0:
        return False, f"expect_base_fail check exited 0 on base {pin_sha[:12]} (vacuous check)", pin_sha
    if tpaths and _BASE_FAIL_CACHE[ck] in (5, 126, 127):
        return False, f"transplanted test_paths exited rc={_BASE_FAIL_CACHE[ck]} on base {pin_sha[:12]} (no tests collected or missing runner)", pin_sha
    step_base = _step_parent_of(repo, pin_sha, commit)
    if row.get("deps") and step_base != pin_sha:
        sck = (prog_key, row["id"], row["cmd"], step_base, tpaths, commit if tpaths else "", "step")
        if sck not in _BASE_FAIL_CACHE:
            stp_arg = (commit, list(tpaths)) if tpaths else None
            src, _, _ = run_check(row, prog, repo, step_base, arm, done, prog_key,
                                  record_log=False, transplant=stp_arg, check_seat_writes=False)
            _BASE_FAIL_CACHE[sck] = src
        sbc = _BASE_FAIL_CACHE[sck]
        if sbc == 0:
            return False, f"expect_base_fail check exited 0 on step parent {step_base[:12]} (vacuous chained check)", pin_sha
        if tpaths and sbc in (5, 126, 127):
            return False, f"transplanted test_paths exited rc={sbc} on step parent {step_base[:12]} (no tests collected or missing runner)", pin_sha
    return True, "", pin_sha


def evaluate(contract, prog, repo, commit, arm, rows, results, quiet=False):
    """Runs the given rows' checks as needed, deps first. Returns (red, lines)."""
    lines, red = [], 0
    done = dict(results)
    order = []
    pending = list(rows)
    while pending:
        progressed = False
        for row in list(pending):
            if any(d not in [r["id"] for r in order] and d in pending_ids(pending) for d in row["deps"]):
                continue
            order.append(row)
            pending.remove(row)
            progressed = True
        if not progressed:
            raise Finding("deps among these rows loop, so none can run")
    for row in order:
        rid = row["id"]
        blocked = [d for d in row["deps"] if done.get((d, commit, arm), (1,))[0] != 0]
        if blocked:
            lines.append(f"BLOCK {rid}: waiting on {' '.join(blocked)}")
            red += 1
            continue
        if (rid, commit, arm) in done:
            rc = done[(rid, commit, arm)][0]
            lines.append(f"{'green' if rc == 0 else 'red':6} {rid} (kept: result key matches)")
            red += rc != 0
            continue
        ev = row.get("evidence", "author-reachable")
        if row["kind"] == "ruling":
            lines.append(f"{'-':6} {rid} human: a ruling row closes by signature, not by running")
            red += 1
            continue
        if row.get("driver") == "external":
            # the REVIEW path runs this row: its check IS the verdict law --
            # a green, provenanced, CURRENT verdict for this row's id
            import review as review_mod
            rd_run = os.environ.get("OPERATOR_HOME", "")
            repo_dir = os.environ.get("CONTRACT_REPO", "")
            why = review_mod.gate_for_row(repo_dir, rid)
            if why is None:
                lines.append(f"{'green':6} {rid} driver=external evidence={ev} "
                             "-- a verified verdict")
                continue
            lines.append(f"{'red':6} {rid} driver=external evidence={ev} -- {why}")
            red += 1
            continue
        if row["kind"] == "git":
            rc, why = git_check(row, prog, repo, commit)
            runfile = os.path.join(prog, "runs", f"{row['id']}.{commit[:12]}.out")
            os.makedirs(os.path.dirname(runfile), exist_ok=True)
            with open(runfile, "w", encoding="utf-8") as f:
                f.write(f"git row {rid} (evidence={ev})\n{why}\n")
            gpin = os.environ.get("CONTRACT_PIN")
            if gpin:
                rp_g = sh(["git", "-C", repo, "rev-parse", "--verify", f"{gpin}^{{commit}}"])
                gpin = rp_g.stdout.strip() if rp_g.returncode == 0 and rp_g.stdout.strip() else None
            cid = record(row["id"], commit, arm, rc, runfile, contract["prog_key"], pin=gpin)
            done[(rid, commit, arm)] = (rc, cid)
            short = next((ln for ln in why.splitlines() if "nothing changed"
                          in ln or "changed under it" in ln), why.splitlines()[0] if why else "")
            lines.append(f"{'green' if rc == 0 else 'red':6} {rid} git evidence={ev} "
                         f"-- {short} -- {os.path.basename(runfile)} {cid}")
            red += rc != 0
            continue
        if row["kind"] == "tsv":
            # the tsv shape IS the check: the engine reads the candidate's
            # file directly; no shell ever runs for a tsv row
            rc, why = tsv_check(row, prog, repo, commit)
            runfile = os.path.join(prog, "runs", f"{row['id']}.{commit[:12]}.out")
            os.makedirs(os.path.dirname(runfile), exist_ok=True)
            with open(runfile, "w", encoding="utf-8") as f:
                f.write(f"tsv row {rid} (evidence={ev})\n{why}\n")
            cid = record(row["id"], commit, arm, rc, runfile, contract["prog_key"])
            done[(rid, commit, arm)] = (rc, cid)
            lines.append(f"{'green' if rc == 0 else 'red':6} {rid} tsv evidence={ev} "
                         f"-- {why} -- {os.path.basename(runfile)} {cid}")
            red += rc != 0
            continue
        # the twin law: a row with a control runs its control at the same
        # commit, and the pair passes or the row does not
        ctl = row.get("control")
        if ctl:
            crow = contract["by_id"].get(ctl)
            if crow is None:
                lines.append(f"RED    {rid}: control {ctl!r} doesn't exist")
                red += 1
                continue
            crc, _, _ = run_check(crow, prog, repo, commit, arm, done,
                                  contract["prog_key"])
            done[(ctl, commit, arm)] = (crc, "control")
            if crc != 0:
                lines.append(f"RED    {rid}: its control {ctl} failed -- a pass "
                             "with a dead control proves nothing")
                red += 1
                continue
        if row.get("expect_base_fail"):
            bf_ok, bf_why, bf_pin = _verify_expect_base_fail(
                row, prog, repo, commit, arm, done, contract["prog_key"])
            if not bf_ok:
                runfile = os.path.join(prog, "runs", f"{rid}.{commit[:12]}.out")
                os.makedirs(os.path.dirname(runfile), exist_ok=True)
                with open(runfile, "w", encoding="utf-8") as f:
                    f.write(f"expect_base_fail row {rid}: {bf_why}\n")
                cid = record(rid, commit, arm, 1, runfile, contract["prog_key"], pin=bf_pin)
                done[(rid, commit, arm)] = (1, cid)
                lines.append(f"RED    {rid}: {bf_why} {cid}")
                red += 1
                continue
        rc, runfile, cid = run_check(row, prog, repo, commit, arm, done, contract["prog_key"])
        done[(rid, commit, arm)] = (rc, cid)
        lines.append(f"{'green' if rc == 0 else 'red':6} {rid} rc={rc} evidence={ev} "
                     f"{os.path.basename(runfile)} {cid}")
        red += rc != 0
    return red, lines


def pending_ids(rows):
    return [r["id"] for r in rows]


def task_rows_for(contract, task_id):
    """Return all rows belonging to the task group containing task_id."""
    for _, ids in tasks_of(contract).items():
        if task_id in ids:
            return [contract["by_id"][rid] for rid in ids]
    if task_id in contract["by_id"]:
        return [contract["by_id"][task_id]]
    return []


def machine_rows_for(contract, task_id):
    """Non-human-blocking machine-checkable rows for task_id (run/tsv/git;
    excludes ruling rows and driver=external review rows)."""
    return [r for r in task_rows_for(contract, task_id)
            if r["kind"] != "ruling" and r.get("driver") != "external"]


def evaluate_task_machine_rows(prog, repo, commit, pin, arm, task_id, call_log_path=None):
    """Run all machine-checkable contract rows for task_id against commit pinned
    at pin. Returns (all_green, receipts_list, summary_str). Runs BEFORE smart-head
    review so broken candidates fast-fail without burning reviewer spend."""
    contract = load(prog)
    mrows = machine_rows_for(contract, task_id)
    if not mrows:
        return True, [], "no machine-checkable rows"
    old_env = {k: os.environ.get(k) for k in
               ("CONTRACT_REPO", "CONTRACT_TIP", "CONTRACT_PIN",
                "CONTRACT_ARM", "CALL_LOG_FILE")}
    try:
        resolved_pin = pin or commit
        rp = sh(["git", "-C", repo, "rev-parse", "--verify", f"{resolved_pin}^{{commit}}"])
        if rp.returncode == 0 and rp.stdout.strip():
            resolved_pin = rp.stdout.strip()
        os.environ["CONTRACT_REPO"] = repo
        os.environ["CONTRACT_TIP"] = commit
        os.environ["CONTRACT_PIN"] = resolved_pin
        os.environ["CONTRACT_ARM"] = arm or "-"
        if call_log_path:
            os.environ["CALL_LOG_FILE"] = call_log_path
        done = results_for(contract, commit, arm or "-", pin=resolved_pin)
        receipts = []
        all_ok = True
        for row in mrows:
            rid = row["id"]
            ev = label_of(row)
            key = (rid, commit, arm or "-")
            if key in done:
                rc, cid = done[key]
                receipts.append({"id": rid, "kind": row["kind"], "evidence": ev,
                                 "rc": rc, "call_id": cid, "kept": True, "tail": ""})
                if rc != 0:
                    all_ok = False
                continue
            if row["kind"] == "git":
                rc, why = git_check(row, prog, repo, commit)
                runfile = os.path.join(prog, "runs", f"{rid}.{commit[:12]}.out")
                os.makedirs(os.path.dirname(runfile), exist_ok=True)
                with open(runfile, "w", encoding="utf-8") as f:
                    f.write(f"git row {rid} (evidence={ev})\n{why}\n")
                cid = record(rid, commit, arm or "-", rc, runfile, contract["prog_key"],
                             pin=resolved_pin)
                receipts.append({"id": rid, "kind": "git", "evidence": ev, "rc": rc,
                                 "call_id": cid, "tail": why[:400]})
                if rc != 0:
                    all_ok = False
                continue
            if row["kind"] == "tsv":
                rc, why = tsv_check(row, prog, repo, commit)
                runfile = os.path.join(prog, "runs", f"{rid}.{commit[:12]}.out")
                os.makedirs(os.path.dirname(runfile), exist_ok=True)
                with open(runfile, "w", encoding="utf-8") as f:
                    f.write(f"tsv row {rid} (evidence={ev})\n{why}\n")
                cid = record(rid, commit, arm or "-", rc, runfile, contract["prog_key"],
                             pin=resolved_pin)
                receipts.append({"id": rid, "kind": "tsv", "evidence": ev, "rc": rc,
                                 "call_id": cid, "tail": why[:400]})
                if rc != 0:
                    all_ok = False
                continue
            ctl = row.get("control")
            if ctl:
                crow = contract["by_id"].get(ctl)
                if crow is None:
                    receipts.append({"id": rid, "kind": "run", "evidence": ev, "rc": 1,
                                     "call_id": "-", "tail": f"control {ctl!r} missing"})
                    all_ok = False
                    continue
                crc, crf, _ = run_check(crow, prog, repo, commit, arm or "-", done,
                                        contract["prog_key"])
                if crc != 0:
                    ctail = open(crf, encoding="utf-8", errors="replace").read()[-400:] if crf and os.path.isfile(crf) else ""
                    receipts.append({"id": rid, "kind": "run", "evidence": ev, "rc": crc,
                                     "call_id": "control",
                                     "tail": f"control {ctl} failed (rc={crc}): {ctail}"[:400]})
                    all_ok = False
                    continue
            if row.get("expect_base_fail"):
                bf_ok, bf_why, bf_pin = _verify_expect_base_fail(
                    row, prog, repo, commit, arm or "-", done, contract["prog_key"])
                if not bf_ok:
                    rf_bf = os.path.join(prog, "runs", f"{rid}.{commit[:12]}.out")
                    os.makedirs(os.path.dirname(rf_bf), exist_ok=True)
                    with open(rf_bf, "w", encoding="utf-8") as f:
                        f.write(f"expect_base_fail row {rid}: {bf_why}\n")
                    cid_bf = record(rid, commit, arm or "-", 1, rf_bf,
                                    contract["prog_key"], pin=bf_pin)
                    receipts.append({"id": rid, "kind": "run", "evidence": ev, "rc": 1,
                                     "call_id": cid_bf, "tail": bf_why[:400]})
                    all_ok = False
                    continue
            rc, rf, cid = run_check(row, prog, repo, commit, arm or "-", done, contract["prog_key"])
            tail = ""
            if rf and os.path.isfile(rf):
                with open(rf, encoding="utf-8", errors="replace") as f:
                    tail = f.read()[-400:].strip()
            receipts.append({"id": rid, "kind": "run", "evidence": ev, "rc": rc,
                             "call_id": cid, "tail": tail})
            if rc != 0:
                all_ok = False
        summary = "; ".join(
            f"{r['id']}={('green' if r['rc'] == 0 else 'red(rc=' + str(r['rc']) + ')')}[{r['evidence']}]"
            for r in receipts)
        return all_ok, receipts, summary
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def gate_task_green(rd, parent, task_id, cand_sha):
    """Hard promote gate: for any engine-driven run (run.json present), verify
    that every machine-checkable row for task_id passed at cand_sha in the run's
    verified call-log.tsv. Returns None on pass, or a refusal string."""
    rj = os.path.join(rd, "run.json")
    if not os.path.isfile(rj):
        return None  # standalone unit/fixture promote outside run.py
    try:
        rdoc = json.load(open(rj, encoding="utf-8"))
    except (OSError, ValueError):
        return f"task {task_id!r}: unreadable run.json; refusing promotion"
    prog = rdoc.get("program")
    if not prog or not os.path.isfile(os.path.join(prog, "contract.toml")):
        return None
    contract = load(prog)
    mrows = machine_rows_for(contract, task_id)
    if not mrows:
        return None
    arm = rdoc.get("arm_hash") or "-"
    pin = rdoc.get("base_commit")
    if not pin:
        rp = sh(["git", "-C", parent, "rev-parse", "--verify", f"{cand_sha}^1"])
        pin = rp.stdout.strip() if rp.returncode == 0 and rp.stdout.strip() else cand_sha
    clog = os.path.join(rd, "call-log.tsv")
    old_cl = os.environ.get("CALL_LOG_FILE")
    try:
        os.environ["CALL_LOG_FILE"] = clog
        done = results_for(contract, cand_sha, arm, pin=pin)
    except Void as e:
        return f"task {task_id!r}: contract call-log void ({e}); refusing promotion"
    finally:
        if old_cl is None:
            os.environ.pop("CALL_LOG_FILE", None)
        else:
            os.environ["CALL_LOG_FILE"] = old_cl
    missing, failed = [], []
    for row in mrows:
        hit = done.get((row["id"], cand_sha, arm))
        if hit is None:
            missing.append(row["id"])
        elif hit[0] != 0:
            failed.append(f"{row['id']}(rc={hit[0]})")
        ctl = row.get("control")
        if ctl:
            chit = done.get((ctl, cand_sha, arm))
            if chit is None:
                missing.append(f"{row['id']}:control({ctl})")
            elif chit[0] != 0:
                failed.append(f"{row['id']}:control({ctl},rc={chit[0]})")
    if missing:
        return (f"task {task_id!r} has unverified contract row(s) {' '.join(missing)} "
                f"at candidate {cand_sha[:12]}; run contract checks before promote")
    if failed:
        return (f"task {task_id!r} failed contract row(s) {' '.join(failed)} "
                f"at candidate {cand_sha[:12]}; refusing promotion")
    return None


# --- verbs ---------------------------------------------------------------------------

def cmd_validate(prog):
    load(prog)
    print(f"validate: the contract holds")


def cmd_amend(prog, key):
    """The amend flow: a mid-run contract edit is LEGAL exactly one way --
    validate the changed program, then sign a fresh arm ruling. An amend over
    a broken program certifies nothing and refuses; a signed amend changes
    prog_key, so every kept result from the old program is void and every row
    re-runs (the reopen law rides the keying, and deleted artifacts re-check
    with the rows)."""
    pre_key = _disk_prog_key(prog)
    load(prog)  # validates, refuses on any finding
    if not key:
        die("amend signs the changed program; --key is required", 2)
    print("validate: the changed contract holds; signing the amend")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import ruling as ruling_mod
    if _disk_prog_key(prog) != pre_key:
        die("the program changed between validate and sign; an amend signs "
            "the tree it validated -- retry", 1)
    try:
        path = ruling_mod.sign(prog, "arm", None, key)
    except (ruling_mod.Refused, ruling_mod.Void) as e:
        die(f"the amend's ruling refused: {e}", 1)
    print(f"amend: {os.path.basename(path)}; kept results under the old "
          "program key are void -- every row re-runs at its next check")


def cmd_forge(repo_dir, out):
    """contract forge: a PROPOSAL, honestly labelled. Scans a repo's shapes
    (never executes anything, no network) and writes a contract skeleton the
    author must review: detected suites become oracle-backed rows, the
    evidence derives from what was actually found, and nothing ships unmarked.
    """
    if not os.path.isdir(repo_dir):
        die(f"{repo_dir!r} isn't a directory to scan", 2)
    rows, notes = [], []

    def has(*names):
        return any(os.path.exists(os.path.join(repo_dir, n)) for n in names)

    py_tdir = "tests" if os.path.isdir(os.path.join(repo_dir, "tests")) else (
        "test" if os.path.isdir(os.path.join(repo_dir, "test")) else None
    )
    if py_tdir:
        cmd = "python3 -m pytest -q" if has("pytest.ini", "setup.cfg", "pyproject.toml", "tox.ini") \
            else f"python3 -m unittest discover -s {py_tdir}"
        rows.append({"id": "tests.frozen", "stage": "design", "desc":
                     "PROPOSED: the existing suite passes (forge detected it)",
                     "kind": "run", "seat": "test-author", "reviewer": "reviewer",
                     "cmd": cmd, "oracle": [py_tdir]})
        notes.append(f"detected a python suite under {py_tdir}/")
    if has("package.json"):
        js_row = {"id": "js.tests", "stage": "design", "desc":
                  "PROPOSED: the javascript suite passes", "kind": "run",
                  "seat": "test-author", "reviewer": "reviewer",
                  "cmd": "npm test -- --silent"}
        if py_tdir:
            js_row["oracle"] = [py_tdir]
        else:
            js_row["expect_base_fail"] = True
        rows.append(js_row)
        notes.append("detected package.json; npm test proposed")
    if has("go.mod"):
        rows.append({"id": "go.tests", "stage": "design", "desc":
                     "PROPOSED: the go suite passes", "kind": "run",
                     "seat": "test-author", "reviewer": "reviewer",
                     "cmd": "go test ./...", "expect_base_fail": True})
        notes.append("detected go.mod")
    if has("Cargo.toml"):
        rows.append({"id": "rust.tests", "stage": "design", "desc":
                     "PROPOSED: the rust suite passes", "kind": "run",
                     "seat": "test-author", "reviewer": "reviewer",
                     "cmd": "cargo test --quiet",
                     **({"oracle": ["tests"]} if os.path.isdir(os.path.join(repo_dir, "tests"))
                        else {"expect_base_fail": True})})
        notes.append("detected Cargo.toml")
    rows.append({"id": "ship.signoff", "stage": "ship", "desc":
                 "Owner approves the delivery", "kind": "ruling",
                 "seat": "owner", "reviewer": "owner2", "deps": [r["id"] for r in rows]})
    if not any(r.get("oracle") for r in rows):
        notes.append("NO oracle detected: every row is author-reachable -- "
                     "write a hidden suite and pin it before trusting a green")
    body = ["schema = 2"]
    for r in rows:
        body.append("[[row]]")
        for k, v in r.items():
            if isinstance(v, list):
                body.append(f"{k} = [" + ", ".join(json.dumps(x) for x in v) + "]")
            elif isinstance(v, bool):
                body.append(f"{k} = {'true' if v else 'false'}")
            elif isinstance(v, int):
                body.append(f"{k} = {v}")
            else:
                body.append(f"{k} = {json.dumps(str(v))}")
        body.append("")
    text = ("# FORGED PROPOSAL -- review every row before signing; the scanner\n"
            "# reads shapes, it understands nothing\n"
            + ("# notes: " + "; ".join(notes) + "\n" if notes else "")
            + "\n".join(body) + "\n")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"forge: {out} ({len(rows)} proposed rows) -- REVIEW IT")
    else:
        sys.stdout.write(text)


def _is_unexercised_oracle_stat(cmd_s, oracle_list):
    """Detect dummy-oracle rows whose cmd is a bare `test`/`[` stat on a non-oracle path."""
    if any(ch in cmd_s for ch in (";", "|", "&", "`", "$(")):
        return False
    try:
        toks = shlex.split(cmd_s)
    except ValueError:
        return False
    if not toks or toks[0] not in ("test", "["):
        return False
    args = [t for t in toks[1:] if t != "]" and not t.startswith("-")]
    if not args:
        return True
    for a in args:
        if a.startswith(("$PROG", "${PROG}", "/prog", "/w/ro")):
            return False
        for o in oracle_list:
            if a == o or a.startswith(o + "/") or _match_repo_glob(a, o):
                return False
    return True


def cmd_lint(prog):
    contract = load(prog)
    bad = []
    rows = contract["rows"]
    by_id = contract["by_id"]
    if not rows:
        bad.append("the contract names no rows")
    scaffold = all(
        (row.get("desc", "").lower() in ("", "todo", "tbd", "placeholder") or
         row.get("cmd", "").strip() in TRIVIAL_CMDS) for row in rows if row["kind"] == "run")
    if scaffold and any(row["kind"] == "run" for row in rows):
        bad.append("every run row is scaffold: an empty desc or a trivial cmd")
    for row in rows:
        if row["kind"] != "run":
            continue
        if row["desc"].lower() in ("", "todo", "tbd", "placeholder"):
            bad.append(f"row {row['id']}: desc is scaffold")
        if row.get("driver") == "external":
            continue
        cmd_s = row["cmd"].strip()
        if cmd_s in TRIVIAL_CMDS:
            bad.append(f"row {row['id']}: cmd is trivial ({cmd_s!r})")
        elif re.search(r"\|\|\s*(?:true|:|exit\s+0)\s*$", cmd_s) or re.match(r"^(?:true|:)\s*\|\|", cmd_s):
            bad.append(f"row {row['id']}: cmd has an always-true short-circuit ({cmd_s!r})")
        if row["oracle"] and _is_unexercised_oracle_stat(cmd_s, row["oracle"]):
            bad.append(f"row {row['id']}: bare test/[ stat never exercises declared oracle {row['oracle']}")
        ctl = row.get("control")
        if ctl:
            crow = by_id.get(ctl)
            if crow and not crow.get("oracle") and not crow.get("expect_base_fail"):
                bad.append(f"row {row['id']}: control target {ctl!r} lacks oracle or expect_base_fail")
        if not row["oracle"] and not ctl and not row.get("expect_base_fail"):
            bad.append(f"row {row['id']}: author-reachable with neither oracle, control, nor expect_base_fail")
    tasks = tasks_of(contract)
    print(f"lint: rows={len(rows)} stages={len(stages_of(contract))} tasks={len(tasks)} "
          f"findings={len(bad)}")
    for b in bad:
        print(f"  {b}")
    if bad:
        sys.exit(1)


def _cli_pin(repo):
    raw = os.environ.get("CONTRACT_PIN")
    if not raw or not repo or not os.path.isdir(os.path.join(repo, ".git")):
        return None
    rp = sh(["git", "-C", repo, "rev-parse", "--verify", f"{raw}^{{commit}}"])
    return rp.stdout.strip() if rp.returncode == 0 and rp.stdout.strip() else raw


def cmd_doctor(prog):
    contract = load(prog)
    commit, arm = tip_and_arm()
    results = results_for(contract, commit, arm, pin=_cli_pin(os.environ.get("CONTRACT_REPO")))
    rows = contract["rows"]
    print(f"doctor: commit={commit[:12]} arm={arm}")
    for st in stages_of(contract):
        for row in [r for r in rows if r["stage"] == st]:
            rid = row["id"]
            pin = f" oracle=pinned:{','.join(row['oracle'])}" if row["oracle"] else ""
            if row["kind"] == "ruling":
                print(f"  {st:12} {rid:40} human{pin}")
            elif (rid, commit, arm) in results:
                rc = results[(rid, commit, arm)][0]
                print(f"  {st:12} {rid:40} {'green' if rc == 0 else 'red'} (rc={rc}){pin}")
            else:
                blocked = [d for d in row["deps"] if results.get((d, commit, arm), (1,))[0] != 0]
                why = f"BLOCK {' '.join(blocked)}" if blocked else "not run"
                print(f"  {st:12} {rid:40} {why}{pin}")
    counts = {}
    for row in rows:
        counts[label_of(row)] = counts.get(label_of(row), 0) + 1
    tasks = "; ".join("{} <- {}@{}".format("+".join(sorted(v)), k[0], k[1])
                      for k, v in tasks_of(contract).items())
    print(f"tasks: {tasks}")
    print("labels: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))


def _parse_setup_pins(pins, allowed_hosts):
    """Validate `--pin host=addr:port` operator vouches against [setup].network.
    A pin can never widen [setup].network: every pinned host must already be
    authorized by `allowed_hosts` (or `*`)."""
    import ipaddress
    out = []
    allow_set = {h.lower() for h in allowed_hosts}
    wildcard = "*" in allow_set
    for spec in pins or []:
        m = re.fullmatch(r"([A-Za-z0-9.-]+)=([0-9a-fA-F.:]+):(\d{1,5})", spec or "")
        if not m:
            raise Finding(f"invalid --pin {spec!r}; want host=addr:port")
        host, addr, port_s = m.group(1).lower(), m.group(2), m.group(3)
        port = int(port_s)
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            raise Finding(f"invalid --pin {spec!r}; {addr!r} is not an IP address")
        if not HOST_RE.fullmatch(host) or not (1 <= port <= 65535):
            raise Finding(f"invalid --pin {spec!r}; bad host or port")
        if not wildcard and host not in allow_set:
            raise Finding(f"--pin host {host!r} is outside [setup] network allowlist")
        out.append((host, addr, port))
    return out


def _rmtree_writable(path):
    if not os.path.lexists(path):
        return
    if os.path.islink(path) or os.path.isfile(path):
        try:
            os.unlink(path)
        except OSError:
            pass
        return
    for root_d, dirs, files in os.walk(path):
        try:
            os.chmod(root_d, 0o700)
        except OSError:
            pass
        for dn in dirs:
            p = os.path.join(root_d, dn)
            if not os.path.islink(p):
                try:
                    os.chmod(p, 0o700)
                except OSError:
                    pass
        for fn in files:
            p = os.path.join(root_d, fn)
            if not os.path.islink(p):
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
    shutil.rmtree(path, ignore_errors=True)


def cmd_setup(prog, pins=None):
    contract = load(prog)
    setup = contract["setup"]
    if not setup or "cmd" not in setup:
        raise Void("this contract has no [setup]")
    net_hosts = list(setup.get("network") or [])
    parsed_pins = _parse_setup_pins(pins, net_hosts)
    if "*" in net_hosts and os.environ.get("OPERATOR_ALLOW_CUSTOM_FETCH_SOURCES") != "1":
        prog_fs = os.path.join(prog, "checks", "fetch_sources.py")
        canon_fs = os.path.join(ROOT, "profiles", "templates", "research", "checks", "fetch_sources.py")
        if os.path.islink(prog_fs) or not os.path.isfile(prog_fs) or not os.path.isfile(canon_fs):
            raise Void("[setup] network '*' requires an unmodified regular checks/fetch_sources.py")
        fd_p = os.open(prog_fs, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd_p, "rb") as fp, open(canon_fs, "rb") as fc:
            if hashlib.sha256(fp.read()).digest() != hashlib.sha256(fc.read()).digest():
                raise Void("[setup] network '*' refused: checks/fetch_sources.py differs from shipped template")
    if shutil.which("bwrap") is None:
        raise Void("bubblewrap (bwrap) is missing; [setup] runs only inside a jail")
    repo, commit = resolve()
    arm = tip_and_arm()[1]
    timeout = setup.get("timeout", TIMEOUT_DEFAULT)
    tmp = tempfile.mkdtemp(prefix="setup-", dir="/tmp" if os.path.isdir("/tmp") else None)
    _assert_disk_floor(tmp)
    px = None
    try:
        full_export = os.path.join(tmp, "full")
        os.mkdir(full_export)
        export_commit(repo, commit, full_export)
        work_export = os.path.join(tmp, "x")
        os.mkdir(work_export)
        prog_real = os.path.realpath(prog)
        full_real = os.path.realpath(full_export)
        for rel in setup.get("inputs") or []:
            cand_repo = os.path.join(full_export, rel)
            cand_prog = os.path.join(prog, rel)
            if os.path.lexists(cand_repo):
                src, root_real = cand_repo, full_real
            elif os.path.lexists(cand_prog):
                src, root_real = cand_prog, prog_real
            else:
                raise Void(f"[setup] input {rel!r} is absent from both CONTRACT_REPO and {prog}")
            sreal = os.path.realpath(src)
            if os.path.islink(src) or not os.path.isfile(src) \
                    or (sreal != root_real and not sreal.startswith(root_real + os.sep)):
                raise Void(f"[setup] input {rel!r} must be a regular non-symlink file inside its root")
            dst = os.path.join(work_export, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            fd_in = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd_in, "rb") as f_in, open(dst, "wb") as f_out:
                f_out.write(f_in.read())
        stage_env = os.path.join(tmp, "env")
        os.mkdir(stage_env)
        etc = generated_etc(tmp)
        extra = ["--bind", stage_env, "/env",
                 "--ro-bind", os.path.abspath(prog), "/prog"]
        for f in ("passwd", "hosts", "machine-id", "hostname"):
            extra += ["--ro-bind", os.path.join(etc, f), f"/etc/{f}"]
        setenvs = [("HOME", "/tmp"), ("PATH", "/env/bin:/usr/bin:/bin"),
                   ("VIRTUAL_ENV", "/env"), ("PIP_CACHE_DIR", "/tmp/pip-cache"),
                   ("PROG", "/prog"), ("NO_COLOR", "1"), ("TERM", "dumb")]
        sh_argv = ["/bin/sh", "-c", setup["cmd"]]
        if net_hosts:
            sockdir = os.path.join(tmp, "socks")
            policy = os.path.join(tmp, "policy")
            eglog = os.path.join(prog, "runs", f"setup.{commit[:12]}.egress.log")
            os.makedirs(os.path.dirname(eglog), exist_ok=True)
            until_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                     time.gmtime(time.time() + max(timeout + 120, 900)))
            pol_lines = ["setup"]
            for h in net_hosts:
                pol_lines.append(f"{h} until {until_ts}")
            for ph, pa, pp in parsed_pins:
                pol_lines.append(f"pin {ph} {pa} {pp}")
            with open(policy, "w", encoding="ascii") as f:
                f.write("\n".join(pol_lines) + "\n")
            px = subprocess.Popen(
                [sys.executable, "-I", os.path.join(ROOT, "bin", "egress-proxy.py"),
                 "serve", sockdir, policy, eglog],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            for _ in range(100):
                if os.path.exists(os.path.join(sockdir, "proxy.sock")):
                    break
                if px.poll() is not None:
                    break
                time.sleep(0.05)
            if not os.path.exists(os.path.join(sockdir, "proxy.sock")):
                err_px = (px.stderr.read().decode("utf-8", "replace") if px.stderr else "").strip()
                raise Void(f"[setup] egress proxy failed to bind: {err_px[:160]}")
            extra += ["--ro-bind", os.path.join(ROOT, "bin", "egress-proxy.py"),
                      "/tmp/egress-proxy.py",
                      "--bind", sockdir, "/run/socks"]
            setenvs += [("HTTPS_PROXY", "http://127.0.0.1:3128"),
                        ("HTTP_PROXY", "http://127.0.0.1:3128")]
            relay_wrap = (
                "python3 -I /tmp/egress-proxy.py relay /run/socks/proxy.sock --port 3128 "
                ">/dev/null 2>&1 &\n"
                "RELAY_PID=$!\n"
                "python3 -I -c 'import socket,sys,time\n"
                "for _ in range(100):\n"
                "    try:\n"
                "        s = socket.create_connection((\"127.0.0.1\", 3128), 1)\n"
                "        s.close(); sys.exit(0)\n"
                "    except OSError:\n"
                "        time.sleep(0.05)\n"
                "sys.exit(1)' || { kill $RELAY_PID 2>/dev/null || true; "
                "echo 'setup: relay never answered on 3128' >&2; exit 2; }\n"
                '/bin/sh -c "$1"\n'
                "RC=$?\n"
                "kill $RELAY_PID 2>/dev/null || true\n"
                "exit $RC\n"
            )
            sh_argv = ["/bin/sh", "-c", relay_wrap, "setup", setup["cmd"]]
        argv = (["prlimit", f"--fsize={FSIZE}", "--core=0"] +
                bwrap_args(binds=extra, setenvs=tuple(setenvs),
                           chdir="/w/export", export=work_export, export_dest="/w/export") +
                ["prlimit", f"--nproc={NPROC}", *sh_argv])
        rc, kept = run_capped(argv, timeout, OUT_CAP)
        runfile = os.path.join(prog, "runs", f"setup.{commit[:12]}.out")
        os.makedirs(os.path.dirname(runfile), exist_ok=True)
        with open(runfile, "wb") as f:
            f.write(kept)
        record_setup(commit, arm, rc, runfile, contract["prog_key"])
        if rc != 0:
            tail = kept.decode("utf-8", "replace").strip()[-200:]
            print(f"setup: red (rc={rc}) {runfile}" + (f" -- {tail}" if tail else ""))
            sys.exit(1)
        env_dst = os.path.join(prog, "env")
        env_old = os.path.join(prog, "env.old")
        _rmtree_writable(env_old)
        if os.path.lexists(env_dst):
            os.rename(env_dst, env_old)
        shutil.move(stage_env, env_dst)
        _rmtree_writable(env_old)
        print(f"setup: green (rc=0) env={env_dst}")
    finally:
        if px is not None:
            px.terminate()
            try:
                px.wait(10)
            except subprocess.TimeoutExpired:
                px.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def cmd_run(prog, row_id):
    contract = load(prog)
    if row_id not in contract["by_id"]:
        die(f"no row {row_id} in {prog}", 2)
    repo, commit = resolve()
    arm = tip_and_arm()[1]
    red, lines = evaluate(contract, prog, repo, commit, arm,
                          [contract["by_id"][row_id]],
                          results_for(contract, commit, arm, pin=_cli_pin(repo)))
    print("\n".join(lines))
    sys.exit(1 if red else 0)


def cmd_advance(prog):
    contract = load(prog)
    repo, commit = resolve()
    arm = tip_and_arm()[1]
    results = results_for(contract, commit, arm, pin=_cli_pin(repo))
    target = None
    for st in stages_of(contract):
        stage_rows = [r for r in contract["rows"] if r["stage"] == st]
        if any(results.get((r["id"], commit, arm), (1,))[0] != 0 for r in stage_rows):
            target = st
            break
    if target is None:
        counts = {}
        for row in contract["rows"]:
            counts[label_of(row)] = counts.get(label_of(row), 0) + 1
        print("advance: every stage is green on the tip")
        print("labels: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
        return
    rows = [r for r in contract["rows"] if r["stage"] == target]
    print(f"advance: stage {target}")
    red, lines = evaluate(contract, prog, repo, commit, arm, rows, results)
    print("\n".join(lines))
    print(f"advance: stage={target} red={red}")
    sys.exit(1 if red else 0)


def cmd_done(prog):
    contract = load(prog)
    repo, commit = resolve()
    arm = tip_and_arm()[1]
    red, lines = evaluate(contract, prog, repo, commit, arm, contract["rows"],
                          results_for(contract, commit, arm, pin=_cli_pin(repo)))
    print("\n".join(lines))
    counts = {}
    eff_counts = {}
    for row in contract["rows"]:
        counts[label_of(row)] = counts.get(label_of(row), 0) + 1
        eff = effective_label_of(contract, row["id"])
        eff_counts[eff] = eff_counts.get(eff, 0) + 1
    reviewed = sum(1 for row in contract["rows"] if row.get("reviewer"))
    print(f"done: {counts.get('sealed', 0)} sealed, {counts.get('author-reachable', 0)} "
          f"author-reachable ({reviewed} reviewed), {counts.get('human', 0)} human "
          f"(effective: {eff_counts.get('sealed', 0)} sealed, "
          f"{eff_counts.get('author-reachable', 0)} author-reachable, "
          f"{eff_counts.get('human', 0)} human)")
    sys.exit(1 if red else 0)


def repo_for():
    repo = os.environ.get("CONTRACT_REPO")
    if not repo or not os.path.isdir(os.path.join(repo, ".git")):
        raise Void("CONTRACT_REPO must name the work repo (a git tree) the export comes from")
    return repo


def tip_and_arm():
    commit = os.environ.get("CONTRACT_TIP") or "HEAD"
    arm = os.environ.get("CONTRACT_ARM") or "-"
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", arm):
        raise Void(f"CONTRACT_ARM must be one identifier, not {arm!r}")
    return commit, arm


def with_lock(prog, fn):
    import fcntl
    os.makedirs(os.path.join(prog, "runs"), exist_ok=True)
    lf = os.path.join(prog, "runs", ".advance.lock")
    f = open(lf, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        die("another advance holds this program's lock", 3)
    try:
        fn()
    finally:
        fcntl.flock(f, fcntl.LOCK_UN)


def selftest():
    """Room-safe: loaders    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))  # the suite never eats the box
, validation, lint, doctor and the result key, on fixtures. No
    jail, so the battery can run this inside the clean room; the jail arms are at --first-level."""

    ok = [0]
    bad = [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    def prog(doc):
        d = tempfile.mkdtemp(prefix="ct.")
        with open(os.path.join(d, "contract.toml"), "w") as f:
            f.write(doc)
        return d

    def run_verb(verb, d, *extra, env=None):
        e = dict(os.environ)
        e.update(env or {})
        argv = [sys.executable, os.path.abspath(__file__), verb, d, *extra]
        return subprocess.run(argv, capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)

    SOUND = """schema = 2
[[row]]
id = "tests.frozen"
stage = "design"
desc = "Acceptance tests exist and fail on the base"
kind = "run"
seat = "test-author"
reviewer = "reviewer"
cmd = "python3 -I $PROG/tools/expect-red.py"
oracle = ["tests"]

[[row]]
id = "ship.signoff"
stage = "ship"
desc = "Owner approves"
kind = "ruling"
seat = "owner"
reviewer = "owner2"
deps = ["tests.frozen"]
"""
    # A a sound contract validates and lints
    d = prog(SOUND)
    r = run_verb("validate", d)
    check(r.returncode == 0 and "holds" in r.stdout, f"A validate: {r.stdout}{r.stderr}")
    r = run_verb("lint", d)
    check(r.returncode == 0 and "rows=2" in r.stdout and "tasks=" in r.stdout, f"A lint: {r.stdout}{r.stderr}")
    # B doctor names stages, labels and tasks without running anything
    r = run_verb("doctor", d, env={"CONTRACT_TIP": "HEAD", "CONTRACT_ARM": "-"})
    check(r.returncode == 0 and "human" in r.stdout and "not run" in r.stdout
          and "oracle=pinned:tests" in r.stdout and "labels:" in r.stdout
          and "1 sealed" in r.stdout and "1 human" in r.stdout,
          f"B doctor: {r.stdout}{r.stderr}")
    # C unknown keys refuse everywhere
    for bad_doc, label in [
        ('schema = 2\nextra = 1\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n', "top key"),
        ('schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\nbogus = 1\n', "row key"),
        ('schema = 2\n[setup]\ncmd = "x"\ninputs = []\nnetwork = []\nweird = 1\n[[row]]\nid = "a"\nstage = "s"\ndesc = "d"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n', "setup key"),
    ]:
        r = run_verb("validate", prog(bad_doc))
        check(r.returncode == 1 and "unknown" in r.stderr, f"C {label}: {r.stderr}")
    # D the typed kinds: legal shapes validate, mis-shapes refuse with the reason
    doc_tsv = SOUND.replace('kind = "run"', 'kind = "tsv"', 1) \
                    .replace('cmd = "python3 -I $PROG/tools/expect-red.py"',
                             'file = "out.tsv"\ncolumns = 3\nrows_min = 1', 1) \
                    .replace('oracle = ["tests"]\n', '', 1)
    r = run_verb("validate", prog(doc_tsv))
    check(r.returncode == 0, f"D kind tsv validates: {r.stderr}")
    r = run_verb("validate", prog(doc_tsv.replace("columns = 3", "columns = 0")))
    check(r.returncode == 1 and "columns" in r.stderr, f"D tsv shape refuses: {r.stderr}")
    doc_git = SOUND.replace('kind = "run"', 'kind = "git"', 1) \
                    .replace('cmd = "python3 -I $PROG/tools/expect-red.py"',
                             'require = ["out.tsv"]\nforbid = ["secrets/**"]', 1) \
                    .replace('oracle = ["tests"]\n', '', 1)
    r = run_verb("validate", prog(doc_git))
    check(r.returncode == 0, f"D kind git validates: {r.stderr}")
    r = run_verb("validate", prog(doc_git.replace('require = ["out.tsv"]\n', "")
                                   .replace('forbid = ["secrets/**"]\n', "")))
    check(r.returncode == 1 and "require and/or forbid" in r.stderr,
          f"D a git row names its globs: {r.stderr}")
    # driver=external: the review path's row -- no cmd
    r = run_verb("validate", prog(SOUND.replace(
        'cmd = "python3 -I $PROG/tools/expect-red.py"\n', 'driver = "external"\n', 1)))
    check(r.returncode == 0, f"D driver=external validates without cmd: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace(
        'cmd = "python3 -I $PROG/tools/expect-red.py"',
        'driver = "external"\ncmd = "x"', 1)))
    check(r.returncode == 1 and "review path" in r.stderr,
          f"D driver=external takes no cmd: {r.stderr}")
    # the evidence labels: the default derives from the shape; a lie refuses
    r = run_verb("validate", prog(SOUND))
    check(r.returncode == 0, "D an oracle row defaults to sealed")
    r = run_verb("validate", prog(SOUND.replace(
        'oracle = ["tests"]', 'oracle = ["tests"]\nevidence = "author-reachable"', 1)))
    check(r.returncode == 1 and "SEALED" in r.stderr,
          f"D mislabeling an oracle row refuses: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace(
        'kind = "run"', 'kind = "run"\nevidence = "human"', 1)))
    check(r.returncode == 1 and "ruling" in r.stderr,
          f"D human evidence is a ruling row: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace(
        'cmd = "python3 -I $PROG/tools/expect-red.py"\noracle = ["tests"]',
        'cmd = "true"\nevidence = "sealed"', 1)))
    check(r.returncode == 1 and "NEEDS an oracle" in r.stderr,
          f"D sealed without an oracle refuses: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace('deps = ["tests.frozen"]', 'deps = ["tests.frozen"]\ncmd = "x"', 1)))
    check(r.returncode == 1 and "ruling row takes no cmd" in r.stderr, f"D ruling cmd: {r.stderr}")
    # C2 the gpu row key: true validates, a non-bool refuses, a ruling row
    # takes none -- and nvidia_nodes is a pure read (a fixture dir decides;
    # the host's own /dev decides real rows at run time, never the room)
    r = run_verb("validate", prog(SOUND.replace('kind = "run"', 'kind = "run"\ngpu = true', 1)))
    check(r.returncode == 0, f"C2 gpu=true validates: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace('kind = "run"', 'kind = "run"\ngpu = "yes"', 1)))
    check(r.returncode == 1 and "gpu is true or absent" in r.stderr, f"C2 gpu shape: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace(
        'kind = "ruling"', 'kind = "ruling"\ngpu = true', 1)))
    check(r.returncode == 1 and "a ruling row takes no gpu" in r.stderr,
          f"C2 a ruling row takes no gpu: {r.stderr}")
    _tsv_gpu = SOUND.replace('kind = "run"', 'kind = "tsv"\ngpu = true', 1) \
                    .replace('cmd = "python3 -I $PROG/tools/expect-red.py"',
                             'file = "out.tsv"\ncolumns = 2\nrows_min = 1', 1) \
                    .replace('oracle = ["tests"]\n', '')
    r = run_verb("validate", prog(_tsv_gpu))
    check(r.returncode == 1 and "only a run row takes gpu" in r.stderr,
          f"C2 a tsv row takes no gpu: {r.stderr}")
    import tempfile as _tf2
    import shutil as _sh2
    _nd = _tf2.mkdtemp(prefix="ctn.")
    check(nvidia_nodes(_nd) == [], "C2 nvidia_nodes: an empty dir reads empty")
    for n in ("nvidiactl", "nvidia-uvm", "nvidia0"):
        open(os.path.join(_nd, n), "w").close()
    check(nvidia_nodes(_nd) == [os.path.join(_nd, "nvidiactl"),
                                os.path.join(_nd, "nvidia-uvm"),
                                os.path.join(_nd, "nvidia0")],
          "C2 nvidia_nodes: the control, uvm and card nodes, in that order")
    open(os.path.join(_nd, "nvidia1"), "w").close()
    os.unlink(os.path.join(_nd, "nvidia-uvm"))
    check(nvidia_nodes(_nd) == [], "C2 nvidia_nodes: no uvm, no CUDA -- reads empty")
    _sh2.rmtree(_nd, ignore_errors=True)
    # D6 oracle_from RESOLVES at load: the borrower's oracle gains the
    # lender's set, and a cycle refuses by name
    extra_row = ('\n[[row]]\nid = "borrower"\nstage = "s"\ndesc = "d"\n'
                 'kind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
                 'oracle_from = "tests.frozen"\n')
    d6 = prog(SOUND + extra_row)
    try:
        c6 = load(d6)
        b = c6["by_id"]["borrower"]
        check("tests" in b["oracle"],
              f"D6 the borrowed oracle joins the bound set: {b['oracle']}")
    except (Finding, Void) as e:
        check(False, f"D6 oracle_from resolves at load: {e}")
    cyc_rows = ('\n[[row]]\nid = "cyc1"\nstage = "s"\ndesc = "d"\n'
                'kind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
                'oracle_from = "cyc2"\n'
                '[[row]]\nid = "cyc2"\nstage = "s"\ndesc = "d"\n'
                'kind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
                'oracle_from = "cyc1"\n')
    try:
        load(prog(SOUND + cyc_rows))
        check(False, "D6 an oracle_from cycle refuses")
    except Finding as e:
        check("cycles" in str(e), f"D6 the cycle names itself: {e}")
    # D7 an EMPTY tsv is never green (rows_min floors at 1): engine-side,
    # no jail needed
    tmp7 = tempfile.mkdtemp(prefix="tsv7.")
    try:
        r7 = os.path.join(tmp7, "r.git")
        e7 = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_COMMITTER_NAME="t",
                  GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_EMAIL="t@x")
        os.makedirs(r7, exist_ok=True)
        subprocess.run(["git", "-C", r7, "init", "-q"], capture_output=True, env=e7)
        os.makedirs(os.path.join(r7, ".git", "info"), exist_ok=True)
        with open(os.path.join(r7, ".git", "info", "attributes"), "w") as f:
            f.write(ATTRIBUTES + "\n")
        with open(os.path.join(r7, "out.tsv"), "w") as f:
            f.write("\n \n")
        subprocess.run(["git", "-C", r7, "add", "-A"], capture_output=True, env=e7)
        subprocess.run(["git", "-C", r7, "commit", "-qm", "e"], capture_output=True, env=e7)
        head = subprocess.run(["git", "-C", r7, "rev-parse", "HEAD"],
                              capture_output=True, text=True, env=e7).stdout.strip()
        row7 = {"id": "a", "file": "out.tsv", "columns": 3}
        rc7, why7 = tsv_check(row7, tmp7, r7, head)
        check(rc7 == 1 and "rows_min 1" in why7,
              f"D7 an empty tsv is red: rc={rc7} {why7}")
        # D7b a symlinked tsv target is refused (O_NOFOLLOW)
        os.unlink(os.path.join(r7, "out.tsv"))
        os.symlink("/etc/passwd", os.path.join(r7, "out.tsv"))
        subprocess.run(["git", "-C", r7, "add", "-A"], capture_output=True, env=e7)
        subprocess.run(["git", "-C", r7, "commit", "-qm", "sym"], capture_output=True, env=e7)
        head_sym = subprocess.run(["git", "-C", r7, "rev-parse", "HEAD"],
                                  capture_output=True, text=True, env=e7).stdout.strip()
        rc7s, why7s = tsv_check(row7, tmp7, r7, head_sym)
        check(rc7s == 1 and "symlink" in why7s,
              f"D7b symlink tsv refused: rc={rc7s} {why7s}")
    finally:
        shutil.rmtree(tmp7, ignore_errors=True)
    # D6b control validation and hollow sealed oracle_from refusal
    r = run_verb("validate", prog(SOUND + '\n[[row]]\nid = "u"\nstage = "s"\ndesc = "d"\n'
                                  'kind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
                                  'control = "missing.ctl"\n'))
    check(r.returncode == 1 and "control" in r.stderr, f"D6b missing control refuses: {r.stderr}")
    r = run_verb("validate", prog(SOUND + '\n[[row]]\nid = "u"\nstage = "s"\ndesc = "d"\n'
                                  'kind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
                                  'control = "ship.signoff"\n'))
    check(r.returncode == 1 and "runnable check" in r.stderr, f"D6b ruling control refuses: {r.stderr}")
    r = run_verb("validate", prog(SOUND + '\n[[row]]\nid = "plain"\nstage = "s"\ndesc = "d"\n'
                                  'kind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
                                  '[[row]]\nid = "hseal"\nstage = "s"\ndesc = "d"\n'
                                  'kind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
                                  'oracle_from = "plain"\nevidence = "sealed"\n'))
    check(r.returncode == 1 and "empty oracle" in r.stderr, f"D6b hollow sealed oracle_from refuses: {r.stderr}")

    # D4 the amend flow: validate-then-sign; a broken program refuses; the
    # fresh ruling lands and the old program's results are void by key
    am_base = tempfile.mkdtemp(prefix="am.")
    am_home = os.path.join(am_base, "home")
    os.makedirs(os.path.join(am_home, "signers"))
    am_key = os.path.join(am_base, "k")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", am_key],
                   capture_output=True, check=True)
    with open(os.path.join(am_home, "signers", "allowed_signers"), "w") as f:
        f.write(f'own@x namespaces="operator-ruling" {open(am_key + ".pub").read().strip()}\n')
    os.chmod(os.path.join(am_home, "signers", "allowed_signers"), 0o600)
    am_core = os.path.join(am_base, "core")
    os.makedirs(am_core)
    with open(os.path.join(am_core, "VERSION"), "w") as f:
        f.write("0.1\n")
    am_env = {k: v for k, v in os.environ.items()}
    am_env.update({"GIT_AUTHOR_NAME": "t", "GIT_COMMITTER_NAME": "t",
                   "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_EMAIL": "t@x"})
    subprocess.run(["git", "-C", am_core, "init", "-q"], capture_output=True, env=am_env)
    subprocess.run(["git", "-C", am_core, "add", "-A"], capture_output=True, env=am_env)
    subprocess.run(["git", "-C", am_core, "commit", "-qm", "c"], capture_output=True, env=am_env)
    am_prog = prog(SOUND)
    am_e = {**os.environ, "OPERATOR_HOME": am_home, "RULING_CORE_GIT": am_core}
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "amend", am_prog,
                        "--key", am_key], capture_output=True, text=True, env=am_e,
                       stdin=subprocess.DEVNULL)
    check(r.returncode == 0 and "signing the amend" in r.stdout,
          f"D4 amend validates then signs: rc={r.returncode} {r.stdout}{r.stderr[:120]}")
    broken = prog(SOUND.replace('schema = 2', 'schema = 3'))
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "amend", broken,
                        "--key", am_key], capture_output=True, text=True, env=am_e,
                       stdin=subprocess.DEVNULL)
    check(r.returncode == 1 and "schema" in r.stderr,
          f"D4 an amend over a broken program refuses: rc={r.returncode} {r.stderr[:80]}")
    # D4b the amend signs the tree it validated: a program whose bytes moved
    # between pre_key and sign refuses (in-process: the second _disk_prog_key lies)
    _real_dpk = _disk_prog_key
    _calls = {"n": 0}
    def _lying_dpk(p):
        k = _real_dpk(p)
        _calls["n"] += 1
        if _calls["n"] >= 2:
            return "moved0123456789"
        return k
    am2 = prog(SOUND)
    _self_mod_g = globals()
    _saved_env = {k: os.environ.get(k) for k in
                  ("OPERATOR_HOME", "RULING_CORE_GIT")}
    os.environ["OPERATOR_HOME"] = am_home
    os.environ["RULING_CORE_GIT"] = am_core
    _self_mod_g["_disk_prog_key"] = _lying_dpk
    try:
        with open(os.devnull, "w") as _dn:
            _so, _se = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = _dn
            try:
                cmd_amend(am2, am_key)
                flipped_refused = False
            except SystemExit as _ex:
                flipped_refused = _ex.code == 1
            finally:
                sys.stdout, sys.stderr = _so, _se
        check(flipped_refused,
              "D4b an amend over bytes that moved between loads refuses")
    finally:
        _self_mod_g["_disk_prog_key"] = _real_dpk
        for k, v in _saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "amend", am2,
                        "--key", am_key], capture_output=True, text=True, env=am_e,
                       stdin=subprocess.DEVNULL)
    check(r.returncode == 0, f"D4b the honest amend still signs: {r.stdout}")
    shutil.rmtree(am_base, ignore_errors=True)
    # D5 forge's honesty: a repo with NO suite gets the no-oracle warning,
    # a repo with one gets a sealed oracle row -- and the header says PROPOSAL
    fr = tempfile.mkdtemp(prefix="forge.")
    out_f = os.path.join(fr, "c.toml")
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "forge", fr,
                        "--out", out_f], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    txt = open(out_f).read() if os.path.isfile(out_f) else ""
    check(r.returncode == 0 and "NO oracle detected" in txt
          and "FORGED PROPOSAL" in txt,
          f"D5 forge warns when no oracle exists: {txt[:80]!r}")
    os.makedirs(os.path.join(fr, "tests"))
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "forge", fr,
                        "--out", out_f], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    txt2 = open(out_f).read()
    check('oracle = ["tests"]' in txt2 and "NO oracle detected" not in txt2,
          f"D5 a detected suite pins its oracle: {txt2[:80]!r}")
    shutil.rmtree(fr, ignore_errors=True)
    # E deps that don't exist or loop
    r = run_verb("validate", prog(SOUND.replace('deps = ["tests.frozen"]', 'deps = ["nope"]')))
    check(r.returncode == 1 and "doesn't exist" in r.stderr, f"E missing dep: {r.stderr}")
    loopy = SOUND.replace('oracle = ["tests"]', 'oracle = ["tests"]\ndeps = ["ship.signoff"]')
    r = run_verb("validate", prog(loopy))
    check(r.returncode == 1 and "loop" in r.stderr, f"E loop: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace('cmd = "python3 -I $PROG/tools/expect-red.py"',
                                               'cmd = "python3 -I $PROG/tools/expect-red.py"\ndeps = ["tests.frozen"]')))
    check(r.returncode == 1 and "loop" in r.stderr, f"E self-dep: {r.stderr}")
    # F nested/file/glob oracles validate; absolute/traversal/trailing-slash oracles refuse; timeouts floor
    r_nest = run_verb("validate", prog(SOUND.replace('oracle = ["tests"]', 'oracle = ["src/x", "sympy/**/tests", "scope.txt"]')))
    check(r_nest.returncode == 0, f"F nested/file/glob oracle validates: {r_nest.stderr}")
    r = run_verb("validate", prog(SOUND.replace('oracle = ["tests"]', 'oracle = ["../escape"]')))
    check(r.returncode == 1 and "invalid oracle pattern" in r.stderr, f"F traversal oracle refuses: {r.stderr}")
    r_ts = run_verb("validate", prog(SOUND.replace('oracle = ["tests"]', 'oracle = ["tests/"]')))
    check(r_ts.returncode == 1 and "invalid oracle pattern" in r_ts.stderr, f"F trailing-slash oracle refuses: {r_ts.stderr}")
    r = run_verb("validate", prog(SOUND.replace('oracle = ["tests"]', 'timeout = 30')))
    check(r.returncode == 1 and "at least 60" in r.stderr, f"F timeout: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace('reviewer = "reviewer"', 'reviewer = "test-author"')))
    check(r.returncode == 1 and "reviewer is the seat" in r.stderr, f"F reviewer: {r.stderr}")
    # G the empty contract gates nothing
    r = run_verb("validate", prog('schema = 2\n'))
    check(r.returncode == 1 and "no rows" in r.stderr, f"G empty: {r.stderr}")
    # H lint flags scaffold, trivial arms, short-circuits, mutual-vacuity control_targets, and dummy-oracle stat
    scaffold = 'schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "todo"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "true"\n'
    r = run_verb("lint", prog(scaffold))
    check(r.returncode == 1 and "scaffold" in r.stdout and "trivial" in r.stdout, f"H scaffold: {r.stdout}")
    sc_bypass = 'schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "real check"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "pytest -q || true"\nexpect_base_fail = true\n'
    r_sc = run_verb("lint", prog(sc_bypass))
    check(r_sc.returncode == 1 and "short-circuit" in r_sc.stdout, f"H2 short-circuit lint: {r_sc.stdout}")
    mut_vac = (
        'schema = 2\n'
        '[[row]]\nid = "r1"\nstage = "s"\ndesc = "check"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "python3 check.py"\ncontrol = "c1"\n'
        '[[row]]\nid = "c1"\nstage = "s"\ndesc = "ctl"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "python3 ctl.py"\n'
    )
    r_mv = run_verb("lint", prog(mut_vac))
    check(r_mv.returncode == 1 and "lacks oracle or expect_base_fail" in r_mv.stdout,
          f"H2b mutual-vacuity control target rejected by lint: {r_mv.stdout}")
    dummy_or = (
        'schema = 2\n'
        '[[row]]\nid = "r1"\nstage = "s"\ndesc = "dummy"\nkind = "run"\nseat = "x"\nreviewer = "y"\n'
        'cmd = "test -f reports/out.md"\noracle = ["checks"]\n'
    )
    r_do = run_verb("lint", prog(dummy_or))
    check(r_do.returncode == 1 and "never exercises declared oracle" in r_do.stdout,
          f"H2c dummy oracle with bare test -f rejected by lint: {r_do.stdout}")
    eff_c = load(prog(
        'schema = 2\n'
        '[[row]]\nid = "ar"\nstage = "s"\ndesc = "d"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "test -f a"\nexpect_base_fail = true\n'
        '[[row]]\nid = "sl"\nstage = "s"\ndesc = "d"\nkind = "run"\nseat = "x"\nreviewer = "y"\ndeps = ["ar"]\ncmd = "pytest -q"\noracle = ["tests"]\n'
    ))
    check(label_of(eff_c["by_id"]["sl"]) == "sealed"
          and effective_label_of(eff_c, "sl") == "author-reachable",
          "H2d effective_label_of computes weakest-link provenance across deps")
    ok_ebf = 'schema = 2\n[[row]]\nid = "a"\nstage = "s"\ndesc = "real check"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "test -f src/new.py"\nexpect_base_fail = true\n[[row]]\nid = "ext"\nstage = "s"\ndesc = "external review row"\nkind = "run"\ndriver = "external"\nseat = "x"\nreviewer = "y"\n'
    r_ebf = run_verb("lint", prog(ok_ebf))
    check(r_ebf.returncode == 0 and "findings=0" in r_ebf.stdout, f"H3 expect_base_fail and driver=external pass lint: {r_ebf.stdout}{r_ebf.stderr}")
    # H4 merged task rows with mismatched reviewers refuse at load
    mismatch_rev = (
        'schema = 2\n'
        '[[row]]\nid = "a1"\nstage = "s"\ndesc = "d1"\nkind = "run"\nseat = "x"\nreviewer = "y"\ncmd = "test -f a"\nexpect_base_fail = true\n'
        '[[row]]\nid = "a2"\nstage = "s"\ndesc = "d2"\nkind = "run"\nseat = "x"\nreviewer = "z"\ncmd = "test -f b"\nexpect_base_fail = true\n'
    )
    r_mr = run_verb("validate", prog(mismatch_rev))
    check(r_mr.returncode == 1 and "same reviewer" in r_mr.stderr, f"H4 task group reviewer mismatch: {r_mr.stderr}")
    # I the result key: a filed result matches only its own key
    d = prog(SOUND)
    log = tempfile.mkdtemp(prefix="ctlog.")
    logf = os.path.join(log, "cl.tsv")
    os.environ["CALL_LOG_FILE"] = logf
    pk = load(d)["prog_key"]
    cid = subprocess.run([os.path.join(ROOT, "bin", "call-log.sh"), "record", "check:tests.frozen",
                          "--key", f"prog={pk}", "--key", "row=tests.frozen", "--key", "commit=abc123",
                          "--key", "arm=-", "--key", "rc=0", "--", "cat", "/dev/null"],
                         capture_output=True, text=True).stdout.strip()
    results = results_for(load(d), "abc123", "-")
    check(results.get(("tests.frozen", "abc123", "-")) == (0, cid), f"I result key: {results}")
    check(("tests.frozen", "abc123", "-") not in results_for(load(d), "abc123", "-", pin="deadbeef"),
          "I sealed row without pin= never matches a pinned lookup")
    check(("tests.frozen", "abc123", "deadbeef") not in results, "I a new arm key misses")
    check(("tests.frozen", "def456", "-") not in results, "I a new commit key misses")
    # I2 the key binds the contract: another program with the same row id keeps nothing
    d2 = prog(SOUND.replace("Acceptance tests exist and fail on the base", "A different description"))
    check(not results_for(load(d2), "abc123", "-"), "I2 another contract shares no result")
    # I3 a row whose rc doesn't parse is left out, not a crash
    subprocess.run([os.path.join(ROOT, "bin", "call-log.sh"), "record", "check:tests.frozen",
                    "--key", f"prog={pk}", "--key", "row=odd", "--key", "commit=abc123",
                    "--key", "arm=-", "--key", "rc=abc", "--", "cat", "/dev/null"],
                   capture_output=True, text=True)
    check(("odd", "abc123", "-") not in results_for(load(d), "abc123", "-"), "I3 an unparseable rc is skipped")
    # I4 a forged row voids trust: no stored result answers on a broken chain
    with open(logf, "a") as f:
        f.write("forged\tc-x\tcheck:tests.frozen\trow=tests.frozen,commit=abc123,arm=-\t0\t0\t0\t0\t0\t0\n")
    try:
        results_for(load(d), "abc123", "-")
        check(False, "I4 a forged log still answered")
    except Exception:
        check(True, "I4 a forged log voids results")
    del os.environ["CALL_LOG_FILE"]
    # J VOID shapes: no contract, and run without a repo
    empty = tempfile.mkdtemp(prefix="ct.")
    r = run_verb("validate", empty)
    check(r.returncode == 2 and "no contract.toml" in r.stderr, f"J no contract: {r.stderr}")
    r = run_verb("run", d, "tests.frozen")
    check(r.returncode == 2 and "CONTRACT_REPO" in r.stderr, f"J no repo: {r.stderr}")
    r = run_verb("nosuch", d)
    check(r.returncode == 2, "J usage")
    # J2 shapes the review found: float schema, option-shaped oracles, ghost oracle_from,
    # a setup cmd whose lock line reaches outside inputs, and an arm that isn't one name
    r = run_verb("validate", prog(SOUND.replace("schema = 2", "schema = 2.0")))
    check(r.returncode == 1 and "integer" in r.stderr, f"J2 float schema: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace('oracle = ["tests"]', 'oracle = ["-e"]')))
    check(r.returncode == 1 and "invalid oracle pattern" in r.stderr, f"J2 oracle shape: {r.stderr}")
    r = run_verb("validate", prog(SOUND.replace('oracle = ["tests"]', 'oracle = ["tests"]\noracle_from = "ghost.row"')))
    check(r.returncode == 1 and "doesn't exist" in r.stderr, f"J2 oracle_from: {r.stderr}")
    setupdoc = SOUND + '\n[setup]\ncmd = "pip install -r evil.lock"\ninputs = ["requirements.lock"]\nnetwork = []\n'
    r = run_verb("validate", prog(setupdoc))
    check(r.returncode == 1 and "outside inputs" in r.stderr, f"J2 setup lock line: {r.stderr}")
    r = run_verb("validate", prog(SOUND + '\n[setup]\ncmd = "pip install -e ."\ninputs = ["requirements.lock"]\nnetwork = []\n'))
    check(r.returncode == 1 and "editable" in r.stderr, f"J2 setup editable: {r.stderr}")
    d = prog(SOUND)
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "doctor", d],
                       capture_output=True, text=True, env={**os.environ, "CONTRACT_ARM": "x,rc=0"},
                       stdin=subprocess.DEVNULL)
    check(r.returncode == 2 and "one identifier" in r.stderr, f"J2 arm shape: {r.stderr}")
    os.chmod(os.path.join(d, "contract.toml"), 0)
    r = run_verb("validate", d)
    check(r.returncode == 2 and "can't be read" in r.stderr, f"J2 unreadable contract: {r.stderr}")
    os.chmod(os.path.join(d, "contract.toml"), 0o644)

    # K setup validates its lock lines and defers its run
    doc = SOUND + '\n[setup]\ncmd = "pip install"\ninputs = ["requirements.lock"]\nnetwork = ["pypi.org"]\n'
    r = run_verb("validate", prog(doc))
    check(r.returncode == 0, f"K setup validates: {r.stderr}")
    r = run_verb("validate", prog(doc.replace(
        'cmd = "pip install"', 'cmd = "python3 -I $PROG/checks/fetch_sources.py '
        'reports/report.md /env/sources"').replace(
        'network = ["pypi.org"]', 'network = ["*"]')))
    check(r.returncode == 0, "K the open-web wildcard validates on the fetch "
          f"command: {r.stderr[:80]}")
    r = run_verb("validate", prog(doc.replace(
        'network = ["pypi.org"]', 'network = ["*"]')))
    check(r.returncode == 1 and "fetch_sources" in r.stderr,
          "K a wildcard over any other command refuses")
    r = run_verb("validate", prog(doc.replace('inputs = ["requirements.lock"]', 'inputs = ["requirements.lock", "-e"]')))
    check(r.returncode == 1 and "repo-relative only" in r.stderr, f"K lock line: {r.stderr}")
    d = prog(doc)
    r = run_verb("setup", d)
    check(r.returncode == 2 and ("bubblewrap" in r.stderr or "CONTRACT_REPO" in r.stderr),
          f"K setup requires bwrap + CONTRACT_REPO: {r.stderr}")
    r_nosetup = run_verb("setup", prog(SOUND))
    check(r_nosetup.returncode == 2 and "no [setup]" in r_nosetup.stderr,
          f"K2 contract without [setup] Voids named: {r_nosetup.stderr}")
    r_badpin = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "setup", d, "--pin", "evil.test=127.0.0.1:9999"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL)
    check(r_badpin.returncode == 1 and "outside [setup] network" in r_badpin.stderr,
          f"K3 --pin outside [setup].network refuses: {r_badpin.stderr}")
    r_badip = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "setup", d, "--pin", "pypi.org=999.999.999.999:80"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL)
    check(r_badip.returncode == 1 and "not an IP address" in r_badip.stderr,
          f"K3b --pin invalid IP refuses: {r_badip.stderr}")
    r_badflag = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "setup", d, "--bogus"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL)
    check(r_badflag.returncode == 2, f"K3c unknown flag on setup refuses: {r_badflag.stderr}")
    r_wcchain = run_verb("validate", prog(
        SOUND + '\n[setup]\ncmd = "python3 -I $PROG/checks/fetch_sources.py reports/report.md /env/sources; echo x"\n'
        'inputs = ["checks/fetch_sources.py", "reports/report.md"]\nnetwork = ["*"]\n'))
    check(r_wcchain.returncode == 1, f"K3d wildcard fetch_sources chaining refuses: {r_wcchain.stderr}")
    r_resrow = run_verb("validate", prog(SOUND.replace('id = "tests.frozen"', 'id = "setup"')))
    check(r_resrow.returncode == 1 and "reserved for [setup]" in r_resrow.stderr,
          f"K3e row id 'setup' is reserved: {r_resrow.stderr}")
    # K4 advance re-evaluates on tip (red tsv row exits 1), and missing contract.toml is VOID (rc 2)
    adv_base = tempfile.mkdtemp(prefix="adv.")
    try:
        adv_repo = os.path.join(adv_base, "repo")
        os.makedirs(adv_repo)
        adv_ge = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_COMMITTER_NAME": "t",
                  "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_EMAIL": "t@x"}
        subprocess.run(["git", "-C", adv_repo, "init", "-q"], capture_output=True, env=adv_ge)
        os.makedirs(os.path.join(adv_repo, ".git", "info"), exist_ok=True)
        with open(os.path.join(adv_repo, ".git", "info", "attributes"), "w") as f:
            f.write(ATTRIBUTES + "\n")
        subprocess.run(["git", "-C", adv_repo, "commit", "--allow-empty", "-qm", "c"],
                       capture_output=True, env=adv_ge)
        adv_prog = prog('schema = 2\n[[row]]\nid = "t.row"\nstage = "s"\ndesc = "d"\n'
                        'kind = "tsv"\nseat = "w"\nreviewer = "r"\nfile = "missing.tsv"\n'
                        'columns = 2\nrows_min = 1\n')
        r_adv = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "advance", adv_prog],
            capture_output=True, text=True,
            env={**os.environ, "CONTRACT_REPO": adv_repo, "CONTRACT_TIP": "HEAD",
                 "CALL_LOG_FILE": os.path.join(adv_base, "adv.cl")},
            stdin=subprocess.DEVNULL)
        check(r_adv.returncode == 1 and "red=1" in r_adv.stdout,
              f"K4 advance re-evaluates and refuses red stage: {r_adv.stdout}{r_adv.stderr}")
        empty_dir = os.path.join(adv_base, "nocont")
        os.makedirs(empty_dir)
        r_vadv = run_verb("advance", empty_dir)
        r_vdoc = run_verb("doctor", empty_dir)
        check(r_vadv.returncode == 2 and r_vdoc.returncode == 2 and "VOID" in r_vdoc.stderr,
              f"K5 missing contract is VOID on advance/doctor: {r_vadv.returncode}/{r_vdoc.returncode}")
        # K6 wildcard [setup] refuses a tampered checks/fetch_sources.py before opening bwrap
        wc_prog = prog(
            'schema = 2\n[setup]\n'
            'cmd = "python3 -I $PROG/checks/fetch_sources.py reports/r.md /env/sources"\n'
            'inputs = ["checks/fetch_sources.py"]\nnetwork = ["*"]\n'
            '[[row]]\nid = "r1"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "test -f reports/r.md"\nexpect_base_fail = true\n'
        )
        os.makedirs(os.path.join(wc_prog, "checks"), exist_ok=True)
        with open(os.path.join(wc_prog, "checks", "fetch_sources.py"), "w") as f:
            f.write("# tampered wildcard setup script\n")
        r_wc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "setup", wc_prog],
            capture_output=True, text=True,
            env={**os.environ, "CONTRACT_REPO": adv_repo, "CONTRACT_TIP": "HEAD"},
            stdin=subprocess.DEVNULL)
        check(r_wc.returncode == 2 and "differs from shipped template" in r_wc.stderr,
              f"K6 tampered fetch_sources refused on network '*': {r_wc.stderr}")
        # K7 check_path_list NUL/trailing-slash, [setup] HOST_RE, and results_for pin mismatch
        got_nul = got_ts = False
        try:
            check_path_list("row r1", ["ok\x00bad"], "a ro path")
        except Finding:
            got_nul = True
        try:
            check_path_list("row r1", ["tools/"], "a ro path")
        except Finding:
            got_ts = True
        check(got_nul and got_ts, f"K7a check_path_list rejects NUL and trailing slash: {got_nul}/{got_ts}")
        r_badhost = run_verb("validate", prog(
            'schema = 2\n[setup]\ncmd = "true"\ninputs = ["a.txt"]\nnetwork = ["bad_host!"]\n'
            '[[row]]\nid = "r1"\nstage = "s"\ndesc = "d"\nkind = "run"\nseat = "w"\nreviewer = "r"\ncmd = "true"\n'
        ))
        check(r_badhost.returncode == 1 and "network" in r_badhost.stderr,
              f"K7b invalid [setup].network host refused: {r_badhost.stderr}")
        r_baddb1 = run_verb("validate", prog(
            'schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "true"\ndiff_base = "step"\n'
        ))
        r_baddb2 = run_verb("validate", prog(
            'schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "d"\nkind = "git"\n'
            'seat = "w"\nreviewer = "r"\nrequire = ["src/**"]\ndiff_base = "bogus"\n'
        ))
        check(r_baddb1.returncode == 1 and r_baddb2.returncode == 1,
              f"K7d diff_base rejects non-git row and invalid mode: {r_baddb1.returncode}/{r_baddb2.returncode}")
        pin_cl = os.path.join(adv_base, "pin.cl")
        old_clf = os.environ.get("CALL_LOG_FILE")
        os.environ["CALL_LOG_FILE"] = pin_cl
        try:
            ct_pin = load(adv_prog)
            rf_tmp = os.path.join(adv_base, "rf.out")
            open(rf_tmp, "w").write("ok\n")
            record("t.row", "a" * 40, "arm1", 0, rf_tmp, ct_pin["prog_key"], pin="b" * 40)
            hit_match = results_for(ct_pin, "a" * 40, "arm1", pin="b" * 40)
            hit_mismatch = results_for(ct_pin, "a" * 40, "arm1", pin="c" * 40)
            check(("t.row", "a" * 40, "arm1") in hit_match and ("t.row", "a" * 40, "arm1") not in hit_mismatch,
                  f"K7c results_for rejects mismatched pin: match={len(hit_match)} mismatch={len(hit_mismatch)}")
        finally:
            if old_clf is None:
                os.environ.pop("CALL_LOG_FILE", None)
            else:
                os.environ["CALL_LOG_FILE"] = old_clf
        # K8 (H3) _parse_pytest_cmd wraps interpreter paths, python3.N, /env/bin/pytest, and env vars;
        # load() refuses unwrapped sealed pytest commands (e.g. 'pytest -q ; true')
        mig_doc = load(os.path.join(ROOT, "profiles", "migration"))
        mig_pt = _parse_pytest_cmd(mig_doc["by_id"]["tests.pass"]["cmd"])
        p_full = _parse_pytest_cmd("env FOO=bar PYTHONPATH=custom_lib python3.12 -B -m pytest -q tests")
        p_bin = _parse_pytest_cmd("/env/bin/pytest -q")
        check(mig_pt is not None and mig_pt[0] == "/env/bin/python"
              and p_full is not None and p_full[0] == "python3.12" and "-B" in p_full[1]
              and p_full[3] == (("FOO", "bar"),) and p_full[4] == ("custom_lib",)
              and p_bin is not None and p_bin[0] == "/env/bin/python",
              f"K8a _parse_pytest_cmd handles interpreter paths, flags, and env: mig={mig_pt} full={p_full} bin={p_bin}")
        r_unwrapped = run_verb("validate", prog(
            'schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "pytest -q ; true"\noracle = ["tests"]\n'
        ))
        r_raw_opt = run_verb("validate", prog(
            'schema = 2\n[[row]]\nid = "r1"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "pytest -q ; true"\noracle = ["tests"]\nrunner = "raw"\n'
        ))
        check(r_unwrapped.returncode == 1 and "bypasses pytest-guard" in r_unwrapped.stderr
              and r_raw_opt.returncode == 0,
              f"K8b unwrapped sealed pytest refused at validate unless runner='raw': rc={r_unwrapped.returncode}/{r_raw_opt.returncode}")
        blk_file = os.path.join(adv_base, "blocker_file")
        open(blk_file, "w").write("x")
        got_obst = False
        try:
            _mkdir_parent_or_finding(os.path.join(blk_file, "conftest.py"), "row r1")
        except Finding:
            got_obst = True
        check(got_obst, "K8c obstructed parent directory raises Finding instead of raw OSError")
    finally:
        shutil.rmtree(adv_base, ignore_errors=True)

    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def first_level():
    """The jail arms: a real repo, a real export, a real bwrap. Runs outside the room,
    where nested bwrap can't start (decision 35)."""
    ok = [0]
    bad = [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    def git(*args, cwd):
        r = sh(["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
                "-c", "commit.gpgsign=false", "-C", cwd, *args])
        if r.returncode != 0:
            raise Void(f"fixture git {args[0]} failed: {r.stderr}")
        return r.stdout.strip()

    base = tempfile.mkdtemp(prefix="ctfl.")
    repo = os.path.join(base, "repo")
    os.makedirs(os.path.join(repo, "src"))
    os.makedirs(os.path.join(repo, "tests"))
    os.makedirs(os.path.join(repo, ".git", "info"))
    with open(os.path.join(repo, ".git", "info", "attributes"), "w") as f:
        f.write(ATTRIBUTES + "\n")
    with open(os.path.join(repo, "src", "a.py"), "w") as f:
        f.write("v = 1\n")
    with open(os.path.join(repo, "tests", "t.txt"), "w") as f:
        f.write("suite\n")
    git("init", "-q", cwd=repo)
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "base", cwd=repo)
    base_sha = git("rev-parse", "HEAD", cwd=repo)
    prog = os.path.join(base, "prog")
    os.makedirs(os.path.join(prog, "tools"))
    with open(os.path.join(prog, "tools", "x.txt"), "w") as f:
        f.write("tool\n")

    def prog_with(row_cmd, extra=""):
        with open(os.path.join(prog, "contract.toml"), "w") as f:
            f.write(f'schema = 2\n[[row]]\nid = "a.check"\nstage = "s"\ndesc = "one check"\n'
                    f'kind = "run"\nseat = "w"\nreviewer = "r"\ncmd = {json_str(row_cmd)}\n{extra}')

    def json_str(s):
        return json.dumps(s)

    def run_row(env_extra=None, arm="a"):
        logf = os.path.join(base, "cl.tsv")
        e = {**os.environ, "CONTRACT_REPO": repo, "CONTRACT_TIP": "HEAD", "CONTRACT_ARM": arm,
             "CALL_LOG_FILE": logf}
        e.update(env_extra or {})
        return subprocess.run([sys.executable, os.path.abspath(__file__), "run", prog, "a.check"],
                              capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)

    # D8 the research citation law, live: a saved source greens an honest
    # quote; a fabricated quote and an unfetched URL each stay red (the
    # template ships its checks in the repo and its sources under env/)
    import shutil as _sh8
    base8 = tempfile.mkdtemp(prefix="cite8.")
    rt_repo = os.path.join(base8, "rt.git")
    e8v = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_COMMITTER_NAME="t",
               GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_EMAIL="t@x")
    os.makedirs(os.path.join(rt_repo, "reports"), exist_ok=True)
    os.makedirs(rt_repo, exist_ok=True)
    subprocess.run(["git", "-C", rt_repo, "init", "-q"],
                   capture_output=True, env=e8v)
    os.makedirs(os.path.join(rt_repo, ".git", "info"), exist_ok=True)
    with open(os.path.join(rt_repo, ".git", "info", "attributes"), "w") as f:
        f.write(ATTRIBUTES + "\n")
    _sh8.copytree(os.path.join(ROOT, "profiles", "templates", "research",
                               "checks"),
                  os.path.join(rt_repo, "checks"))
    prog8 = os.path.join(base8, "research-prog")
    _sh8.copytree(os.path.join(ROOT, "profiles", "templates", "research"),
                  prog8, ignore=_sh8.ignore_patterns("runs", "env"))
    os.makedirs(os.path.join(prog8, "env", "sources"), exist_ok=True)
    import hashlib as _hl8
    _u = "https://example.com/page"
    _h = _hl8.sha256(_u.encode()).hexdigest()[:16]
    with open(os.path.join(prog8, "env", "sources", _h + ".url"), "w") as f:
        f.write(_u + "\n")
    _body8 = b"<html>quoted text here</html>"
    with open(os.path.join(prog8, "env", "sources", _h + ".body"), "wb") as f:
        f.write(_body8)
    # the manifest seals the saved body (hash of the BYTES, not the URL)
    _bh = _hl8.sha256(_body8).hexdigest()[:16]
    with open(os.path.join(prog8, "env", "sources", "sources.manifest"), "w") as f:
        f.write(f"{_bh}\t{_u}\n")

    def rt_commit(report_body, msg):
        with open(os.path.join(rt_repo, "reports", "report.md"), "w") as f:
            f.write(report_body)
        subprocess.run(["git", "-C", rt_repo, "add", "-A"],
                       capture_output=True, env=e8v)
        c = subprocess.run(["git", "-C", rt_repo, "commit", "-qm", msg],
                           capture_output=True, text=True, env=e8v)
        if c.returncode != 0:
            check(False, f"D8 the fixture commit refused: {c.stderr.strip()[:120]}")

    def rt_run(row):
        log8 = os.path.join(base8, "cl8.tsv")
        e9 = dict(os.environ, CONTRACT_REPO=rt_repo, CONTRACT_TIP="HEAD",
                  CONTRACT_PIN="HEAD", CONTRACT_ARM="z8", CALL_LOG_FILE=log8)
        return subprocess.run([sys.executable, os.path.abspath(__file__),
                               "run", prog8, row],
                              capture_output=True, text=True, env=e9,
                              stdin=subprocess.DEVNULL)

    rt_commit("H\n\n> quoted text here [1]\n\n1. " + _u + "\n", "honest")
    r = rt_run("report.write")
    _rf8 = os.path.join(prog8, "runs")
    _rf8_txt = ""
    if os.path.isdir(_rf8):
        _f8 = sorted(os.listdir(_rf8))[-1]
        _rf8_txt = open(os.path.join(_rf8, _f8), errors="replace").read()[:120]
    check(r.returncode == 0, f"D8 report.write greens first: rc={r.returncode} "
          f"runfile={_rf8_txt!r}")
    r2 = rt_run("citations.check")
    check(r2.returncode == 0 and "green" in r2.stdout,
          f"D8 an honest quote greens: rc={r2.returncode} "
          f"err={r2.stderr.strip()[:200]} out={r2.stdout.strip()[:120]}")
    rt_commit("L\n\n> words never written [1]\n\n1. " + _u + "\n", "lie")
    rt_run("report.write")
    r3 = rt_run("citations.check")
    check(r3.returncode == 1, "D8 a fabricated quote stays red")
    _ghost_host = "never-fetched-9x" + ".example"
    rt_commit("U\n\n> quoted text here [1]\n\n1. https://" + _ghost_host + "/x\n",
              "unfetched")
    rt_run("report.write")
    r4 = rt_run("citations.check")
    _rf9 = os.path.join(prog8, "runs")
    _f9 = ""
    if os.path.isdir(_rf9):
        _cands = [f for f in os.listdir(_rf9)
                  if f.startswith("citations.check.")]
        _f9 = max(_cands, key=lambda f: os.path.getmtime(
            os.path.join(_rf9, f))) if _cands else ""
    _rf9_txt = open(os.path.join(_rf9, _f9), errors="replace").read()[:200] \
        if _f9 else ""
    check(r4.returncode == 1 and "no saved source" in _rf9_txt,
          f"D8 an unfetched URL stays red with the reason: {_rf9_txt[:80]!r} "
          f"report={open(os.path.join(rt_repo, 'reports', 'report.md'), errors='replace').read()[:80]!r}")
    # the seal: a hand-planted .url/.body pair with no manifest entry reds
    # (the review planted one and a fabricated quote verified against it)
    import hashlib as _hl8b
    _fake_u = "https://planted.example.com/x"
    _fake_h = _hl8b.sha256(_fake_u.encode()).hexdigest()[:16]
    with open(os.path.join(prog8, "env", "sources", _fake_h + ".url"), "w") as f:
        f.write(_fake_u + "\n")
    with open(os.path.join(prog8, "env", "sources", _fake_h + ".body"), "wb") as f:
        f.write(b"planted words")
    rt_commit("P\n\n> planted words [1]\n\n1. " + _fake_u + "\n", "planted")
    rt_run("report.write")
    r5 = rt_run("citations.check")
    check(r5.returncode == 1, "D8 a hand-planted source with no manifest reds")
    for _f in (_fake_h + ".url", _fake_h + ".body"):
        os.unlink(os.path.join(prog8, "env", "sources", _f))
    _sh8.rmtree(rt_repo, ignore_errors=True)
    _sh8.rmtree(prog8, ignore_errors=True)
    _sh8.rmtree(base8, ignore_errors=True)
    # D9 the plan template's forge test, live through the jail: the control
    # greens on met goals, the planted hollow FAILS the lint (so the forge row
    # greens), and a hollow plan reds the lint row outright
    import shutil as _sh9
    base9 = tempfile.mkdtemp(prefix="plan9.")
    p_repo = os.path.join(base9, "p.git")
    e9v = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_COMMITTER_NAME="t",
               GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_EMAIL="t@x")
    os.makedirs(os.path.join(p_repo, "src"), exist_ok=True)
    subprocess.run(["git", "-C", p_repo, "init", "-q"],
                   capture_output=True, env=e9v)
    os.makedirs(os.path.join(p_repo, ".git", "info"), exist_ok=True)
    with open(os.path.join(p_repo, ".git", "info", "attributes"), "w") as f:
        f.write(ATTRIBUTES + "\n")
    with open(os.path.join(p_repo, "src", "a.py"), "w") as f:
        f.write("v=1\n")
    with open(os.path.join(p_repo, "src", "b.py"), "w") as f:
        f.write("v=1\n")
    with open(os.path.join(p_repo, "plan.md"), "w") as f:
        f.write("# Plan\n\n## g.one\n\ndesc: first\ncheck: `test -f src/a.py`\n"
                "\n## g.two\n\ndesc: second\ncheck: `test -f src/b.py`\n")
    _sh9.copytree(os.path.join(ROOT, "profiles", "templates", "plan",
                               "checks"),
                  os.path.join(p_repo, "checks"))
    subprocess.run(["git", "-C", p_repo, "add", "-A"],
                   capture_output=True, env=e9v)
    subprocess.run(["git", "-C", p_repo, "commit", "-qm", "plan"],
                   capture_output=True, env=e9v)
    prog9 = os.path.join(base9, "plan-prog")
    _sh9.copytree(os.path.join(ROOT, "profiles", "templates", "plan"), prog9,
                  ignore=_sh9.ignore_patterns("runs"))

    def plan_run(row):
        log9 = os.path.join(base9, "cl9.tsv")
        e10 = dict(os.environ, CONTRACT_REPO=p_repo, CONTRACT_TIP="HEAD",
                   CONTRACT_PIN="HEAD", CONTRACT_ARM="z9", CALL_LOG_FILE=log9)
        return subprocess.run([sys.executable, os.path.abspath(__file__),
                               "run", prog9, row],
                              capture_output=True, text=True, env=e10,
                              stdin=subprocess.DEVNULL)

    r = plan_run("goals.lint")
    check(r.returncode == 0 and "green" in r.stdout,
          f"D9 the lint row greens on real goals: {r.stdout.strip()[:90]}")
    r = plan_run("goals.forge")
    check(r.returncode == 0 and "green" in r.stdout,
          f"D9 the forge row greens when the hollow is caught: "
          f"{r.stdout.strip()[:260]}")
    # a hollow plan reds the lint row
    with open(os.path.join(p_repo, "plan.md"), "w") as f:
        f.write("# Plan\n\n## x\n\ndesc: hollow\ncheck: `true`\n")
    subprocess.run(["git", "-C", p_repo, "add", "-A"],
                   capture_output=True, env=e9v)
    subprocess.run(["git", "-C", p_repo, "commit", "-qm", "hollow"],
                   capture_output=True, env=e9v)
    r = plan_run("goals.lint")
    check(r.returncode == 1, "D9 a hollow plan reds the lint row")
    _sh9.rmtree(base9, ignore_errors=True)
    # A the export is the commit: no .git, the file is there, output capped, result keyed
    prog_with("test -f src/a.py && test ! -e .git && echo ran")
    r = run_row(arm="a")
    runfile = os.path.join(prog, "runs")
    check(r.returncode == 0 and "green" in r.stdout and os.path.isdir(runfile) and
          any(f.startswith("a.check.") and f.endswith(".out") for f in os.listdir(runfile)),
          f"A green through the jail: {r.stdout}{r.stderr}")
    with open(os.path.join(base, "cl.tsv")) as f:
        logtext = f.read()
    check("row=a.check" in logtext and "arm=a" in logtext and "rc=0" in logtext, f"A result row: {logtext}")
    # G the gpu row: on a GPU host the nodes land inside the check jail (their
    # own dev mounts past the fresh /dev); on a gpu-less host the row Voids
    # with the fix named -- never a mysterious CUDA init failure
    nodes_here = nvidia_nodes()
    prog_with("test -c /dev/nvidiactl && test -c /dev/nvidia-uvm && "
              "test -c /dev/nvidia0 && echo GPU-NODES-OK", 'gpu = true')
    r = run_row(arm="g")
    if nodes_here:
        gout = ""
        gf = [os.path.join(runfile, f) for f in os.listdir(runfile)
              if f.startswith("a.check.")]
        if gf:
            with open(sorted(gf)[-1], encoding="utf-8", errors="replace") as f:
                gout = f.read()
        check(r.returncode == 0 and "GPU-NODES-OK" in gout,
              f"G the gpu row runs green through the jail: {r.stdout}{r.stderr}")
    else:
        check(r.returncode == 2 and "no nvidia devices" in r.stdout + r.stderr,
              f"G the gpu row names its fix on a gpu-less host: {r.stdout}{r.stderr}")
    # B a red check is red, and its rc rides the key
    prog_with("exit 3")
    r = run_row(arm="b")
    check(r.returncode == 1 and "rc=3" in r.stdout, f"B red keeps its rc: {r.stdout}{r.stderr}")
    # C the cap drains past the limit and keeps the exit code
    prog_with("awk 'BEGIN{for(i=0;i<300000;i++) print \"aaaaaaaaaa\"; exit 0}'")
    r = run_row(arm="c")
    rf = [os.path.join(runfile, f) for f in os.listdir(runfile) if f.startswith("a.check.")][0]
    check(r.returncode == 0 and os.path.getsize(rf) == OUT_CAP, f"C cap: rc={r.returncode} size={os.path.getsize(rf)}")
    # D ro paths and $PROG bind read-only
    prog_with('test -f /w/ro/tools/x.txt && test -f "$PROG/tools/x.txt"', extra='ro = ["tools"]\n')
    r = run_row(arm="d")
    check(r.returncode == 0, f"D ro and PROG: {r.stdout}{r.stderr}")
    # D3 a driver=external row consults the verdict law: no verdict, red with
    # the reason named
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "a.check"\nstage = "s"\ndesc = "one check"\n'
                'kind = "run"\nseat = "w"\nreviewer = "r"\ndriver = "external"\n')
    logd = os.path.join(base, "cl3.tsv")
    e = {**os.environ, "CONTRACT_REPO": repo, "CONTRACT_TIP": "HEAD",
         "CONTRACT_ARM": "q", "CALL_LOG_FILE": logd,
         "OPERATOR_HOME": os.path.join(base, "nohome")}
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "run", prog, "a.check"],
                       capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)
    check(r.returncode == 1 and "no verdict" in r.stdout,
          f"D3 a driver row without a verdict is red and names why: {r.stdout}")
    # D2 the typed kinds, LIVE: a tsv row shape-checks the candidate's file,
    # a git row shape-checks the delivery, and the twin law holds
    with open(os.path.join(repo, "out.tsv"), "w") as f:
        f.write("host\tport\tver\na.example\t443\t1\nb.example\t80\t2\n")
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "add the tsv", cwd=repo)
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "a.check"\nstage = "s"\ndesc = "one check"\n'
                'kind = "tsv"\nseat = "w"\nreviewer = "r"\nfile = "out.tsv"\n'
                'columns = 3\nrows_min = 2\n')
    r = run_row(arm="t1")
    check(r.returncode == 0 and "tsv" not in r.stderr,
          f"D2 a tsv row runs green live: {r.stdout}{r.stderr}")
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "a.check"\nstage = "s"\ndesc = "one check"\n'
                'kind = "tsv"\nseat = "w"\nreviewer = "r"\nfile = "out.tsv"\n'
                'columns = 4\nrows_min = 2\n')
    r = run_row(arm="t2")
    check(r.returncode == 1 and "columns" in r.stdout,
          f"D2 a mis-shaped tsv is red and names why: {r.stdout}")
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "a.check"\nstage = "s"\ndesc = "one check"\n'
                'kind = "git"\nseat = "w"\nreviewer = "r"\n'
                'require = ["out.tsv"]\nforbid = ["secrets/**"]\n')
    r = run_row(env_extra={"CONTRACT_PIN": "HEAD~1"}, arm="g1")
    check(r.returncode == 0, f"D2 a git row runs green live: {r.stdout}{r.stderr}")
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "a.check"\nstage = "s"\ndesc = "one check"\n'
                'kind = "git"\nseat = "w"\nreviewer = "r"\n'
                'require = ["docs/**"]\n')
    r = run_row(env_extra={"CONTRACT_PIN": "HEAD~1"}, arm="g2")
    check(r.returncode == 1 and "nothing changed" in r.stdout,
          f"D2 an unmet require is red: {r.stdout}")
    # the twin law: the control runs and its failure fails the row
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "ctl"\nstage = "s"\ndesc = "control"\n'
                'kind = "run"\nseat = "w"\nreviewer = "r"\ncmd = "exit 1"\n'
                '[[row]]\nid = "a.check"\nstage = "s"\ndesc = "one check"\n'
                'kind = "run"\nseat = "w"\nreviewer = "r"\ncmd = "true"\n'
                'control = "ctl"\n')
    logc = os.path.join(base, "cl2.tsv")
    e = {**os.environ, "CONTRACT_REPO": repo, "CONTRACT_TIP": "HEAD",
         "CONTRACT_ARM": "z", "CALL_LOG_FILE": logc}
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "run", prog, "a.check"],
                       capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)
    check(r.returncode == 1 and "control" in r.stdout and "ctl" in r.stdout,
          f"D2 a dead control fails its row: {r.stdout}")
    # E the oracle restores the pinned directory over a candidate that deleted it
    git("rm", "-q", "-r", "tests", cwd=repo)
    git("commit", "-qm", "drop tests", cwd=repo)
    prog_with("test -f tests/t.txt", extra='oracle = ["tests"]\n')
    r = run_row(env_extra={"CONTRACT_TIP": "HEAD", "CONTRACT_PIN": "HEAD~1"}, arm="e")
    check(r.returncode == 0, f"E oracle restores: {r.stdout}{r.stderr}")
    prog_with("test -f tests/t.txt", extra='oracle = ["tests"]\n')
    r = run_row(env_extra={"CONTRACT_TIP": "HEAD~1", "CONTRACT_PIN": "HEAD~1"}, arm="f")
    check(r.returncode == 0, f"E oracle pins the base: {r.stdout}{r.stderr}")
    # F an oracle missing at the pin is VOID, and so is a repo without the export line
    prog_with("true", extra='oracle = ["nowhere"]\n')
    r = run_row(env_extra={"CONTRACT_PIN": "HEAD"}, arm="g")
    check(r.returncode == 2 and "isn't a directory at the pin" in r.stderr, f"F oracle void: {r.stderr}")
    # F2 a sealed row with CONTRACT_PIN unset refuses VOID (never falls back to candidate tip)
    r_nopin = run_row(arm="g2np")
    check(r_nopin.returncode == 2 and "CONTRACT_PIN" in r_nopin.stderr,
          f"F2 sealed row without CONTRACT_PIN voids: rc={r_nopin.returncode} {r_nopin.stderr}")
    bare = os.path.join(base, "bare")
    os.makedirs(bare)
    sh(["git", "-C", bare, "init", "-q"])
    prog_with("true")
    r = run_row(env_extra={"CONTRACT_REPO": bare}, arm="h")
    check(r.returncode == 2 and "info/attributes" in r.stderr, f"F attributes void: {r.stderr}")
    # G the jail's network, PID and user namespaces are isolated: lonely loopback,
    # parent loopback listener unreachable, and parent contract.py absent from /proc
    import socket as _sock
    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as _srv:
        _srv.bind(("127.0.0.1", 0))
        _srv.listen(4)
        _port = _srv.getsockname()[1]
        prog_with(
            'test "$(grep -c : /proc/net/dev)" = 1 '
            '&& ! grep -qa "[c]ontract.py" /proc/[0-9]*/cmdline '
            '&& python3 -I -c '
            f'"import socket,sys; s=socket.socket(); s.settimeout(1.0); '
            f'rc=s.connect_ex((\'127.0.0.1\',{_port})); s.close(); sys.exit(0 if rc!=0 else 1)"'
        )
        r = run_row(arm="i")
    check(r.returncode == 0, f"G a lonely loopback and isolated namespaces: {r.stdout}{r.stderr}")
    # G2 the scrubbed env: the operator's variables never reach the check, the setenvs do
    prog_with('! env | grep -q CONTRACT_ARM && env | grep -q "PROG=/prog"')
    r = run_row(arm="p")
    check(r.returncode == 0, f"G2 scrubbed env: {r.stdout}{r.stderr}")
    # G3 the host's identifiers and live /usr/local never reach the check
    prog_with('test "$(cat /etc/machine-id)" = engine-jail && { test ! -e /usr/local || test -z "$(ls -A /usr/local)"; }')
    r = run_row(arm="q")
    check(r.returncode == 0, f"G3 hidden host: {r.stdout}{r.stderr}")
    # G4 a check past its deadline is TERMd and KILLed: rc 124, not a hang
    if os.environ.get("OPERATOR_AST_MUTANTS") != "1":
        with open(os.path.join(prog, "contract.toml")) as f:
            saved = f.read()
        with open(os.path.join(prog, "contract.toml"), "w") as f:
            f.write('schema = 2\n[[row]]\nid = "a.check"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                    'seat = "w"\nreviewer = "r"\ncmd = "sleep 200"\ntimeout = 60\n')
        r = run_row(arm="s")
        check(r.returncode == 1 and "rc=124" in r.stdout, f"G4 the deadline kills: {r.stdout}{r.stderr}")
        with open(os.path.join(prog, "contract.toml"), "w") as f:
            f.write(saved)
    # H a result key matches: the same row, commit and arm is kept, a new arm re-runs
    logf = os.path.join(base, "cl.tsv")
    e = {**os.environ, "CONTRACT_REPO": repo, "CONTRACT_TIP": base_sha, "CONTRACT_PIN": base_sha, "CONTRACT_ARM": "j", "CALL_LOG_FILE": logf}
    prog_with("test -f tests/t.txt", extra='oracle = ["tests"]\n')
    r1 = subprocess.run([sys.executable, os.path.abspath(__file__), "run", prog, "a.check"],
                        capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)
    r2 = subprocess.run([sys.executable, os.path.abspath(__file__), "run", prog, "a.check"],
                        capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL)
    check(r1.returncode == 0 and r2.returncode == 0 and "kept" in r2.stdout,
          f"H kept: {r2.stdout}{r2.stderr}")

    # I a result key that changed re-runs instead of keeping: same row and commit, new arm
    e2 = {**e, "CONTRACT_ARM": "k"}
    r3 = subprocess.run([sys.executable, os.path.abspath(__file__), "run", prog, "a.check"],
                        capture_output=True, text=True, env=e2, stdin=subprocess.DEVNULL)
    check(r3.returncode == 0 and "kept" not in r3.stdout and "green" in r3.stdout,
          f"I re-run on a new arm: {r3.stdout}{r3.stderr}")
    # J the export is the commit even against an in-tree .gitattributes: info/attributes wins
    with open(os.path.join(repo, ".gitattributes"), "w") as f:
        f.write("tests/ export-ignore\n")
    os.makedirs(os.path.join(repo, "tests"), exist_ok=True)
    open(os.path.join(repo, "tests", "t.txt"), "w").write("suite\n")
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "attrs", cwd=repo)
    prog_with("test -f tests/t.txt && test -f .gitattributes")
    r = run_row(arm="l")
    check(r.returncode == 0, f"J export-ignore overridden: {r.stdout}{r.stderr}")
    # K writes inside the jail leave nothing on the host: /tmp is a tmpfs, / is read-only,
    # and the export's throwaway directory is gone when the check ends
    before = sorted(os.listdir(prog))
    prog_with("sh -c 'echo c > /tmp/canary; echo c > /canary 2>/dev/null; echo c > /w/export/canary; exit 0'")
    r = run_row(arm="m")
    stray = [f for f in os.listdir(prog) if f not in before and f != "runs"]
    canary = []
    for root, dirs, files in os.walk(prog):
        canary += [os.path.join(root, f) for f in files if f == "canary"]
    check(r.returncode == 0 and not stray and not canary, f"K no canary on the host: {r.stdout}{r.stderr}")
    # L /env binds read-only when it exists, and an unlisted ro path is absent, not readable
    envd = os.path.join(prog, "env")
    os.makedirs(envd)
    with open(os.path.join(envd, "tool"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(os.path.join(envd, "tool"), 0o755)
    prog_with('test -x /env/tool && test ! -e /w/ro/absent.txt', extra='ro = ["tools"]\n')
    r = run_row(arm="n")
    check(r.returncode == 0, f"L env and absence: {r.stdout}{r.stderr}")
    shutil.rmtree(envd)
    # M a 60-second passing check goes green under the floor's default ceiling
    if os.environ.get("OPERATOR_AST_MUTANTS") != "1":
        prog_with("sleep 60 && test -f src/a.py")
        r = run_row(arm="o")
        check(r.returncode == 0 and "green" in r.stdout, f"M 60-second check: {r.stdout}{r.stderr}")

    # N [setup] runs jailed through egress-proxy.py: denied host fails without
    # populating env/, allowed pinned host populates env/ and subsequent row reads /env
    import http.server
    import threading

    class _SetupH(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "17")
            self.end_headers()
            self.wfile.write(b"setup-fetched-ok\n")

        def log_message(self, *a):
            pass

    srv_s = http.server.HTTPServer(("127.0.0.1", 0), _SetupH)
    sport = srv_s.server_address[1]
    threading.Thread(target=srv_s.serve_forever, daemon=True).start()
    try:
        shutil.rmtree(os.path.join(prog, "env"), ignore_errors=True)
        with open(os.path.join(prog, "contract.toml"), "w") as f:
            f.write(
                'schema = 2\n'
                '[setup]\n'
                'cmd = "python3 -I -c \\"import urllib.request; '
                'urllib.request.urlopen(\'http://denied.test/x\').read()\\""\n'
                'inputs = ["src/a.py"]\n'
                'network = ["allowed.test"]\n'
                '[[row]]\nid = "a.check"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                'seat = "w"\nreviewer = "r"\ncmd = "grep -qx setup-fetched-ok /env/fetched.txt"\n'
            )
        r_den = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "setup", prog,
             "--pin", f"allowed.test=127.0.0.1:{sport}"],
            capture_output=True, text=True,
            env={**os.environ, "CONTRACT_REPO": repo, "CONTRACT_TIP": "HEAD",
                 "CONTRACT_ARM": "setup1", "CALL_LOG_FILE": logf},
            stdin=subprocess.DEVNULL)
        check(r_den.returncode == 1 and not os.path.exists(os.path.join(prog, "env")),
              f"N1 [setup] denied host refuses and leaves no env/: {r_den.stdout}{r_den.stderr}")
        with open(os.path.join(prog, "contract.toml"), "w") as f:
            f.write(
                'schema = 2\n'
                '[setup]\n'
                'cmd = "test -f src/a.py && python3 -I -c \\"import urllib.request; '
                'd=urllib.request.urlopen(\'http://allowed.test/x\').read(); '
                'open(\'/env/fetched.txt\',\'wb\').write(d)\\""\n'
                'inputs = ["src/a.py"]\n'
                'network = ["allowed.test"]\n'
                '[[row]]\nid = "a.check"\nstage = "s"\ndesc = "d"\nkind = "run"\n'
                'seat = "w"\nreviewer = "r"\ncmd = "grep -qx setup-fetched-ok /env/fetched.txt"\n'
            )
        r_ok = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "setup", prog,
             "--pin", f"allowed.test=127.0.0.1:{sport}"],
            capture_output=True, text=True,
            env={**os.environ, "CONTRACT_REPO": repo, "CONTRACT_TIP": "HEAD",
                 "CONTRACT_ARM": "setup1", "CALL_LOG_FILE": logf},
            stdin=subprocess.DEVNULL)
        check(r_ok.returncode == 0 and os.path.isfile(os.path.join(prog, "env", "fetched.txt")),
              f"N2 [setup] allowed host populates env/ via egress-proxy: {r_ok.stdout}{r_ok.stderr}")
        r_envrow = run_row(arm="setup1")
        check(r_envrow.returncode == 0 and "green" in r_envrow.stdout,
              f"N3 contract row reads /env populated by [setup]: {r_envrow.stdout}{r_envrow.stderr}")
    finally:
        srv_s.shutdown()
        srv_s.server_close()

    # N4 live expect_base_fail: vacuous base-passing check reds; differential check greens
    ebf_base = git("rev-parse", "HEAD", cwd=repo)
    with open(os.path.join(repo, "src", "diff_feature.py"), "w") as f:
        f.write("ok = 1\n")
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "add diff_feature", cwd=repo)
    ebf_cand = git("rev-parse", "HEAD", cwd=repo)
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write(
            'schema = 2\n'
            '[[row]]\nid = "vac.check"\nstage = "s"\ndesc = "vacuous"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "test -f src/a.py"\nexpect_base_fail = true\n'
            '[[row]]\nid = "diff.check"\nstage = "s"\ndesc = "differential"\nkind = "run"\n'
            'seat = "w"\nreviewer = "r"\ncmd = "test -f src/diff_feature.py"\nexpect_base_fail = true\n'
        )
    ok_ebf_all, recs_ebf, sum_ebf = evaluate_task_machine_rows(
        prog, repo, ebf_cand, ebf_base, "ebf1", "vac.check", call_log_path=logf)
    by_rid = {r["id"]: r for r in recs_ebf}
    check(not ok_ebf_all and by_rid["vac.check"]["rc"] == 1
          and "vacuous" in by_rid["vac.check"]["tail"]
          and by_rid["diff.check"]["rc"] == 0,
          f"N4 expect_base_fail rejects vacuous base-pass and passes true differential: {sum_ebf} {by_rid}")

    # N5 pytest-guard in-process sabotage rejection (os._exit(0), atexit, monkeypatch, runtime skip,
    # sys._getframe / oracle-read audit hook), nested/file/glob oracle, & test_paths transplantation
    pg_base_dir = tempfile.mkdtemp(prefix="pguard.")
    try:
        pg_repo = os.path.join(pg_base_dir, "repo")
        pg_prog = os.path.join(pg_base_dir, "prog")
        os.makedirs(os.path.join(pg_repo, "src"), exist_ok=True)
        os.makedirs(os.path.join(pg_repo, "pkg", "tests"), exist_ok=True)
        os.makedirs(pg_prog, exist_ok=True)
        with open(os.path.join(pg_repo, "src", "calc.py"), "w") as f:
            f.write("def add(a, b):\n    return a - b\n")
        with open(os.path.join(pg_repo, "scope.txt"), "w") as f:
            f.write("PINNED-SCOPE\n")
        with open(os.path.join(pg_repo, "pkg", "tests", "test_calc.py"), "w") as f:
            f.write("from src.calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
        git("init", "-q", cwd=pg_repo)
        os.makedirs(os.path.join(pg_repo, ".git", "info"), exist_ok=True)
        with open(os.path.join(pg_repo, ".git", "info", "attributes"), "w") as f:
            f.write(ATTRIBUTES + "\n")
        git("add", "-A", cwd=pg_repo)
        git("commit", "-qm", "pin", cwd=pg_repo)
        pg_pin = git("rev-parse", "HEAD", cwd=pg_repo)
        with open(os.path.join(pg_prog, "contract.toml"), "w") as f:
            f.write(
                'schema = 2\n'
                '[[row]]\nid = "pg"\nstage = "s"\ndesc = "sealed pytest"\nkind = "run"\n'
                'seat = "w"\nreviewer = "r"\ncmd = "pytest -q pkg/tests"\n'
                'oracle = ["pkg/**/tests", "scope.txt"]\n'
            )
        pg_log = os.path.join(pg_base_dir, "cl.tsv")

        def _pg_try(calc_body, tag):
            with open(os.path.join(pg_repo, "src", "calc.py"), "w") as wf:
                wf.write(calc_body)
            with open(os.path.join(pg_repo, "scope.txt"), "w") as wf:
                wf.write("TAMPERED-SCOPE\n")
            git("add", "-A", cwd=pg_repo)
            git("commit", "-qm", tag, cwd=pg_repo)
            cand_s = git("rev-parse", "HEAD", cwd=pg_repo)
            ok_pg, recs_pg, _ = evaluate_task_machine_rows(
                pg_prog, pg_repo, cand_s, pg_pin, f"arm-{tag}", "pg", call_log_path=pg_log)
            return ok_pg, recs_pg[0]

        ok1, rec1 = _pg_try("import os\nos._exit(0)\n", "osexit")
        check(not ok1 and rec1["rc"] == 1 and "pytest-guard" in rec1["tail"],
              f"N5a os._exit(0) defeated by pytest-guard HMAC receipt: {rec1}")
        ok2, rec2 = _pg_try("import atexit, os\natexit.register(os._exit, 0)\ndef add(a, b): return 0\n", "atexit")
        check(not ok2 and rec2["rc"] == 1,
              f"N5b atexit(os._exit, 0) defeated by pytest-guard: {rec2}")
        ok3, rec3 = _pg_try("import pytest\ndef add(a, b):\n    pytest.skip('bypass')\n", "rtskip")
        check(not ok3 and rec3["rc"] == 1 and "pytest-guard" in rec3["tail"],
              f"N5c runtime pytest.skip on pinned unskipped test defeated: {rec3}")
        ok4, rec4 = _pg_try("import sys\ndef add(a, b):\n    sys._getframe(1)\n    return a + b\n", "getframe")
        check(not ok4 and rec4["rc"] == 1,
              f"N5d candidate sys._getframe blocked by audit hook: {rec4}")
        ok5, rec5 = _pg_try(
            "def add(a, b):\n"
            "    assert open('scope.txt').read().strip() == 'PINNED-SCOPE'\n"
            "    return a + b\n", "honest")
        # Wait: scope.txt IS in oracle_roots so candidate reading scope.txt is blocked by audit hook!
        check(not ok5 and rec5["rc"] == 1,
              f"N5e candidate reading sealed oracle file directly is blocked by audit hook: {rec5}")
        ok6, rec6 = _pg_try("def add(a, b):\n    return a + b\n", "cleanfix")
        check(ok6 and rec6["rc"] == 0,
              f"N5f honest fix passes under pytest-guard + nested glob oracle: {rec6}")

        # N5g test_paths transplantation: vacuous candidate test passing on base is rejected;
        # genuine test failing on base and passing on candidate is accepted
        tp_prog = os.path.join(pg_base_dir, "tp-prog")
        os.makedirs(tp_prog, exist_ok=True)
        with open(os.path.join(tp_prog, "contract.toml"), "w") as f:
            f.write(
                'schema = 2\n'
                '[[row]]\nid = "feat"\nstage = "s"\ndesc = "feature"\nkind = "run"\n'
                'seat = "w"\nreviewer = "r"\ncmd = "env PYTHONPATH=. python3 -B -m unittest discover -s newtests"\n'
                'expect_base_fail = true\ntest_paths = ["newtests"]\n'
            )
        os.makedirs(os.path.join(pg_repo, "newtests"), exist_ok=True)
        with open(os.path.join(pg_repo, "newtests", "test_vac.py"), "w") as f:
            f.write("import unittest\nclass T(unittest.TestCase):\n    def test_vac(self): self.assertTrue(True)\n")
        git("add", "-A", cwd=pg_repo)
        git("commit", "-qm", "vac-tp", cwd=pg_repo)
        tp_vac_cand = git("rev-parse", "HEAD", cwd=pg_repo)
        ok_tv, recs_tv, _ = evaluate_task_machine_rows(
            tp_prog, pg_repo, tp_vac_cand, pg_pin, "tp1", "feat", call_log_path=pg_log)
        check(not ok_tv and recs_tv[0]["rc"] == 1 and "vacuous" in recs_tv[0]["tail"],
              f"N5g vacuous transplanted test rejected: {recs_tv}")
        os.unlink(os.path.join(pg_repo, "newtests", "test_vac.py"))
        with open(os.path.join(pg_repo, "src", "feat_mod.py"), "w") as f:
            f.write("def mul(a, b):\n    return a * b\n")
        with open(os.path.join(pg_repo, "newtests", "test_real.py"), "w") as f:
            f.write("import unittest\nfrom src.feat_mod import mul\n"
                    "class T(unittest.TestCase):\n    def test_mul(self): self.assertEqual(mul(3, 4), 12)\n")
        git("add", "-A", cwd=pg_repo)
        git("commit", "-qm", "real-tp", cwd=pg_repo)
        tp_real_cand = git("rev-parse", "HEAD", cwd=pg_repo)
        ok_tr, recs_tr, _ = evaluate_task_machine_rows(
            tp_prog, pg_repo, tp_real_cand, pg_pin, "tp2", "feat", call_log_path=pg_log)
        check(ok_tr and recs_tr[0]["rc"] == 0,
              f"N5h real transplanted test fails on base and greens on candidate: {recs_tr}")

        # N6 (AUTO-5A) multi-step chain T0 -> C1 -> C2: _step_parent_of isolates
        # cross-seat sequential promotions, per-step git_check, and chained expect_base_fail
        ms_dir = os.path.join(pg_base_dir, "ms")
        ms_repo = os.path.join(ms_dir, "repo")
        ms_prog = os.path.join(ms_dir, "prog")
        os.makedirs(os.path.join(ms_repo, "tests"), exist_ok=True)
        os.makedirs(os.path.join(ms_prog, "roles"), exist_ok=True)
        for rn in ("a", "b", "r"):
            with open(os.path.join(ms_prog, "roles", f"{rn}.md"), "w") as f:
                f.write(f"role {rn}\n")
        with open(os.path.join(ms_prog, "team.toml"), "w") as f:
            f.write(
                'schema = 1\nname = "ms"\n'
                '[seat.a]\nrole = "roles/a.md"\nadapter = "stub"\nwrite = ["src/a/**"]\n[seat.a.budget]\nusd = 1.0\n'
                '[seat.b]\nrole = "roles/b.md"\nadapter = "stub"\nwrite = ["src/b/**"]\n[seat.b.budget]\nusd = 1.0\n'
                '[seat.r]\nrole = "roles/r.md"\nadapter = "stub"\n[seat.r.budget]\nusd = 1.0\n'
            )
        with open(os.path.join(ms_prog, "contract.toml"), "w") as f:
            f.write(
                'schema = 2\n'
                '[[row]]\nid = "s1"\nstage = "s1"\ndesc = "step 1"\nkind = "run"\n'
                'seat = "a"\nreviewer = "r"\ncmd = "env PYTHONPATH=. python3 -I -m pytest -q tests/test_s1.py"\n'
                'oracle = ["tests/test_s1.py"]\nexpect_base_fail = true\n'
                '[[row]]\nid = "s2.test"\nstage = "s2"\ndesc = "step 2 independent"\nkind = "run"\n'
                'seat = "b"\nreviewer = "r"\ncmd = "env PYTHONPATH=. python3 -I -m pytest -q tests/test_s2.py"\n'
                'oracle = ["tests/test_s2.py"]\n'
                '[[row]]\nid = "s2.git"\nstage = "s2"\ndesc = "step 2 git shape"\nkind = "git"\n'
                'seat = "b"\nreviewer = "r"\nrequire = ["src/b/**"]\nforbid = ["src/a/**"]\n'
                '[[row]]\nid = "s2.vac"\nstage = "s2v"\ndesc = "vacuous chained"\nkind = "run"\n'
                'deps = ["s1"]\nseat = "b"\nreviewer = "r"\n'
                'cmd = "env PYTHONPATH=. python3 -I -m pytest -q tests/test_s1.py"\n'
                'oracle = ["tests/test_s1.py"]\nexpect_base_fail = true\n'
                '[[row]]\nid = "s2.chain"\nstage = "s2c"\ndesc = "real chained"\nkind = "run"\n'
                'deps = ["s1"]\nseat = "b"\nreviewer = "r"\n'
                'cmd = "env PYTHONPATH=. python3 -I -m pytest -q tests/test_s2.py"\n'
                'oracle = ["tests/test_s2.py"]\nexpect_base_fail = true\n'
            )
        with open(os.path.join(ms_repo, "tests", "test_s1.py"), "w") as f:
            f.write("from src.a.m import v1\ndef test_s1():\n    assert v1() == 10\n")
        with open(os.path.join(ms_repo, "tests", "test_s2.py"), "w") as f:
            f.write("from src.a.m import v1\nfrom src.b.n import v2\ndef test_s2():\n    assert v2() == v1() + 5\n")
        git("init", "-q", cwd=ms_repo)
        os.makedirs(os.path.join(ms_repo, ".git", "info"), exist_ok=True)
        with open(os.path.join(ms_repo, ".git", "info", "attributes"), "w") as f:
            f.write(ATTRIBUTES + "\n")
        git("add", "-A", cwd=ms_repo)
        git("commit", "-qm", "t0", cwd=ms_repo)
        ms_t0 = git("rev-parse", "HEAD", cwd=ms_repo)
        os.makedirs(os.path.join(ms_repo, "src", "a"), exist_ok=True)
        open(os.path.join(ms_repo, "src", "__init__.py"), "w").close()
        open(os.path.join(ms_repo, "src", "a", "__init__.py"), "w").close()
        with open(os.path.join(ms_repo, "src", "a", "m.py"), "w") as f:
            f.write("def v1():\n    return 10\n")
        git("add", "-A", cwd=ms_repo)
        git("commit", "-qm", "c1", cwd=ms_repo)
        ms_c1 = git("rev-parse", "HEAD", cwd=ms_repo)
        os.makedirs(os.path.join(ms_repo, "src", "b"), exist_ok=True)
        open(os.path.join(ms_repo, "src", "b", "__init__.py"), "w").close()
        with open(os.path.join(ms_repo, "src", "b", "n.py"), "w") as f:
            f.write("from src.a.m import v1\ndef v2():\n    return v1() + 5\n")
        git("add", "-A", cwd=ms_repo)
        git("commit", "-qm", "c2", cwd=ms_repo)
        ms_c2 = git("rev-parse", "HEAD", cwd=ms_repo)
        check(_step_parent_of(ms_repo, ms_t0, ms_c2) == ms_c1
              and _step_parent_of(ms_repo, ms_t0, ms_c1) == ms_t0,
              "N6_0 _step_parent_of resolves C2^1=C1 and C1^1=T0")
        ms_log = os.path.join(ms_dir, "cl.tsv")
        ok_s2, recs_s2, _ = evaluate_task_machine_rows(
            ms_prog, ms_repo, ms_c2, ms_t0, "ms1", "s2.test", call_log_path=ms_log)
        check(ok_s2 and len(recs_s2) == 2 and all(r["rc"] == 0 for r in recs_s2),
              f"N6a cross-seat sequential promotion and step git_check pass on C2: {recs_s2}")
        ok_vac_ch, recs_vac_ch, _ = evaluate_task_machine_rows(
            ms_prog, ms_repo, ms_c2, ms_t0, "ms2", "s2.vac", call_log_path=ms_log)
        check(not ok_vac_ch and "step parent" in recs_vac_ch[0]["tail"],
              f"N6b chained expect_base_fail rejects check already green at step parent C1: {recs_vac_ch}")
        ok_real_ch, recs_real_ch, _ = evaluate_task_machine_rows(
            ms_prog, ms_repo, ms_c2, ms_t0, "ms3", "s2.chain", call_log_path=ms_log)
        check(ok_real_ch and recs_real_ch[0]["rc"] == 0,
              f"N6c chained expect_base_fail passes when check fails on T0 and C1 and greens on C2: {recs_real_ch}")
        # And if seat b illegally touches src/a/m.py in C1 -> C3, _seat_allowed_writes refuses!
        with open(os.path.join(ms_repo, "src", "a", "m.py"), "w") as f:
            f.write("def v1():\n    return 10  # touched by b\n")
        git("add", "-A", cwd=ms_repo)
        git("commit", "-qm", "c3-illegal", cwd=ms_repo)
        ms_c3 = git("rev-parse", "HEAD", cwd=ms_repo)
        got_grant_refusal = False
        try:
            evaluate_task_machine_rows(ms_prog, ms_repo, ms_c3, ms_t0, "ms4", "s2.test", call_log_path=ms_log)
        except Finding as e_gr:
            got_grant_refusal = "outside seat write grants" in str(e_gr)
        check(got_grant_refusal, "N6d step diff strictly enforces seat b write grants against upstream files")
    finally:
        shutil.rmtree(pg_base_dir, ignore_errors=True)

    # the hollow-suite battery rides the first-level suite (it jails)
    r9 = subprocess.run([sys.executable, "-I",
                         os.path.join(ROOT, "test", "forge", "hollow.py"), "all"],
                        capture_output=True, text=True, timeout=600,
                        stdin=subprocess.DEVNULL)
    check(r9.returncode == 0 and "hollow: OK" in r9.stdout,
          f"FL hollow-suite: {r9.stdout.strip()[-80:]} {r9.stderr.strip()[-80:]}")
    print(f"first-level: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "first-level: FAIL")
    return 0 if ok[0] and not bad[0] else 1





USAGE = ("usage: contract.py <validate|lint|doctor|run|advance|done|setup|amend|forge> "
         "<dir> [row-id] [--key K] [--out F] [--pin host=addr:port]")


def _parse_setup_flags(extra_argv):
    pins = []
    i = 0
    while i < len(extra_argv):
        if extra_argv[i] == "--pin":
            if i + 1 >= len(extra_argv):
                die("setup --pin requires host=addr:port", 2)
            pins.append(extra_argv[i + 1])
            i += 2
        else:
            die(f"unknown setup argument {extra_argv[i]!r}", 2)
    return pins


def main(argv):
    if len(argv) < 3 or argv[1] not in ("validate", "lint", "doctor", "run",
                                        "advance", "done", "setup", "amend",
                                        "forge"):
        die(USAGE, 2)
    verb, prog = argv[1], argv[2]
    if not os.path.isdir(prog):
        die(f"no directory {prog}", 2)
    try:
        if verb == "validate":
            cmd_validate(prog)
        elif verb == "lint":
            cmd_lint(prog)
        elif verb == "doctor":
            cmd_doctor(prog)
        elif verb == "setup":
            pins = _parse_setup_flags(argv[3:])
            with_lock(prog, lambda: cmd_setup(prog, pins=pins))
        elif verb == "run":
            if len(argv) != 4:
                die("usage: contract.py run <program-dir> <row-id>", 2)
            cmd_run(prog, argv[3])
        elif verb in ("advance", "done"):
            with_lock(prog, lambda: (cmd_advance if verb == "advance" else cmd_done)(prog))
        elif verb == "amend":
            cmd_amend(prog, flag(argv, "--key"))
        elif verb == "forge":
            cmd_forge(prog, flag(argv, "--out"))
    except Finding as e:
        die(str(e), 1)
    except Void as e:
        die(f"VOID, {e}", 2)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    if sys.argv[1:] == ["--first-level"]:
        sys.exit(first_level())
    main(sys.argv)
