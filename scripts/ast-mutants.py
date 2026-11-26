#!/usr/bin/env python3
"""ast-mutants -- deterministic AST mutation generator and scorer for CLAIMS.md.

Generates and scores syntactic AST mutants over the 11 TCB control-plane files
named in CLAIMS.md (`TCB_TARGETS`):
  bin/lib/jail.py, bin/spawn.py, bin/run.py, bin/contract.py, bin/review.py,
  bin/team.py, bin/ruling.py, bin/broker.py, bin/egress-proxy.py,
  bin/compose-fence.py, bin/untrusted-span-fence.py
plus optional developer release-tooling (`DEV_TARGETS`: scripts/release-lint.py).

Test harnesses (`selftest`, `first_level`) and namespace process-kill sweeps
(`_stop_namespace`, per test/neuters.py ROW POLICY) are excluded from mutation.
When `bwrap` is functional on the host, mutants surviving `--selftest` are
subsequently tested against first-level jail suites. Reports `killed`, `crashed`,
`timeout`, and `survived` separately, with `strict_kill_pct = killed / total`
(timeouts and signal crashes are never counted as test kills).

usage:
  ast-mutants.py list [--file REL] [--include-dev] [--limit N] [--json]
  ast-mutants.py score [--file REL] [--include-dev] [--limit N] [--workers W] [--fail-on-survivor] [--json]
  ast-mutants.py --selftest
exit: 0 ok, 1 selftest failed (or --fail-on-survivor had survivors), 2 usage or VOID
"""
import argparse
import ast
import concurrent.futures
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parent.parent

TCB_TARGETS = (
    "bin/lib/jail.py",
    "bin/spawn.py",
    "bin/run.py",
    "bin/contract.py",
    "bin/review.py",
    "bin/team.py",
    "bin/ruling.py",
    "bin/broker.py",
    "bin/egress-proxy.py",
    "bin/compose-fence.py",
    "bin/untrusted-span-fence.py",
)
DEV_TARGETS = (
    "scripts/release-lint.py",
)
CLAIMS_TARGETS = TCB_TARGETS + DEV_TARGETS
HARNESS_FOR = {
    "bin/lib/jail.py": ("bin/contract.py", "bin/spawn.py"),
}
SKIP_FUNCS = frozenset({"selftest", "first_level", "_stop_namespace"})
CMP_FLIP = {
    ast.Eq: "!=",
    ast.NotEq: "==",
    ast.Lt: ">=",
    ast.LtE: ">",
    ast.Gt: "<=",
    ast.GtE: "<",
    ast.Is: "is not",
    ast.IsNot: "is",
    ast.In: "not in",
    ast.NotIn: "in",
}
CMP_SYMBOL = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
}
DIE_NAMES = frozenset({"die", "_void", "exit"})
TIMEOUT_S = 60
FIRST_LEVEL_TIMEOUT_S = 180


def _line_offsets(src):
    offs = [0]
    for ln in re.findall(r"[^\r\n]*(?:\r\n|\r|\n)|.+$", src):
        offs.append(offs[-1] + len(ln.encode("utf-8")))
    return offs


def _span_bytes(offs, lineno, col, end_lineno, end_col):
    return offs[lineno - 1] + col, offs[end_lineno - 1] + end_col


def _excluded_ranges(tree):
    ranges = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in SKIP_FUNCS:
            if node.end_lineno is not None:
                ranges.append((node.lineno, node.end_lineno))
    for node in getattr(tree, "body", ()):
        if isinstance(node, ast.If) and node.end_lineno is not None and "__main__" in ast.unparse(node.test):
            ranges.append((node.lineno, node.end_lineno))
    return ranges


def _in_excluded(lineno, ranges):
    return any(lo <= lineno <= hi for lo, hi in ranges)


def _is_terminating_stmt(stmt):
    if isinstance(stmt, (ast.Raise, ast.Return)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        fn = stmt.value.func
        if isinstance(fn, ast.Name) and fn.id in DIE_NAMES:
            return True
        if isinstance(fn, ast.Attribute) and fn.attr in DIE_NAMES:
            return True
    return False


def generate_for_source(rel, src, limit=0):
    """Return deterministic list of AST-valid mutant dicts for `src`."""
    tree = ast.parse(src, filename=rel)
    raw = src.encode("utf-8")
    offs = _line_offsets(src)
    excl = _excluded_ranges(tree)
    top_spans = []
    for stmt in getattr(tree, "body", ()):
        if getattr(stmt, "col_offset", -1) == 0 and getattr(stmt, "end_lineno", None) is not None:
            ts_b = offs[stmt.lineno - 1]
            te_b = offs[stmt.end_lineno] if stmt.end_lineno < len(offs) else len(raw)
            top_spans.append((ts_b, te_b))
    candidates = []

    for node in ast.walk(tree):
        ln = getattr(node, "lineno", None)
        if ln is None or _in_excluded(ln, excl):
            continue
        # 1. Single and chained comparisons: flip each operator individually
        if isinstance(node, ast.Compare) and node.ops and len(node.ops) == len(node.comparators) \
                and node.end_lineno is not None:
            s_b, e_b = _span_bytes(offs, node.lineno, node.col_offset,
                                   node.end_lineno, node.end_col_offset)
            terms = [ast.unparse(node.left)] + [ast.unparse(c) for c in node.comparators]
            if all(type(op) in CMP_SYMBOL for op in node.ops):
                for idx_op, op_node in enumerate(node.ops):
                    op_t = type(op_node)
                    if op_t not in CMP_FLIP:
                        continue
                    ops_str = [
                        CMP_FLIP[op_t] if j == idx_op else CMP_SYMBOL[type(o)]
                        for j, o in enumerate(node.ops)
                    ]
                    pieces = [f"({terms[0]})"]
                    for op_s, rhs_s in zip(ops_str, terms[1:]):
                        pieces.append(f"{op_s} ({rhs_s})")
                    repl = "(" + " ".join(pieces) + ")"
                    kind = "cmp" if len(node.ops) == 1 else f"cmp_chain_{idx_op}"
                    candidates.append((node.lineno, node.col_offset, kind, s_b, e_b, repl))
        # 2. Unary `not x` -> `(x)`
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and node.end_lineno is not None:
            s_b, e_b = _span_bytes(offs, node.lineno, node.col_offset,
                                   node.end_lineno, node.end_col_offset)
            repl = f"({ast.unparse(node.operand)})"
            candidates.append((node.lineno, node.col_offset, "not", s_b, e_b, repl))
        # 3. Boolean conjunctions/disjunctions: `and` <-> `or`
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)) \
                and len(node.values) >= 2 and node.end_lineno is not None:
            s_b, e_b = _span_bytes(offs, node.lineno, node.col_offset,
                                   node.end_lineno, node.end_col_offset)
            joiner = " or " if isinstance(node.op, ast.And) else " and "
            repl = "(" + joiner.join(f"({ast.unparse(v)})" for v in node.values) + ")"
            candidates.append((node.lineno, node.col_offset, "boolop", s_b, e_b, repl))
        # 4. Boolean Constant return: `return True` <-> `return False`
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, bool) and node.value.end_lineno is not None:
            v = node.value
            s_b, e_b = _span_bytes(offs, v.lineno, v.col_offset, v.end_lineno, v.end_col_offset)
            repl = "False" if v.value is True else "True"
            candidates.append((v.lineno, v.col_offset, "ret_bool", s_b, e_b, repl))
        # 5. Guard `if cond:` whose body immediately raises, returns, or calls die/_void/exit
        elif isinstance(node, ast.If) and not node.orelse and node.body \
                and _is_terminating_stmt(node.body[0]) and node.test.end_lineno is not None:
            t = node.test
            if not (isinstance(t, ast.Constant) and t.value is False):
                s_b, e_b = _span_bytes(offs, t.lineno, t.col_offset, t.end_lineno, t.end_col_offset)
                candidates.append((t.lineno, t.col_offset, "guard_off", s_b, e_b, "False"))

    candidates.sort(key=lambda x: (x[0], x[1], x[2], x[5]))
    short = pathlib.Path(rel).stem
    mutants = []
    seen_spans = set()
    idx = 0
    for lineno, col, kind, s_b, e_b, repl in candidates:
        key = (s_b, e_b, repl)
        if key in seen_spans:
            continue
        seen_spans.add(key)
        orig = raw[s_b:e_b].decode("utf-8", "replace")
        if orig == repl:
            continue
        chk_bytes = None
        for ts_b, te_b in top_spans:
            if ts_b <= s_b and e_b <= te_b:
                chk_bytes = raw[ts_b:s_b] + repl.encode("utf-8") + raw[e_b:te_b]
                break
        if chk_bytes is None:
            chk_bytes = raw[:s_b] + repl.encode("utf-8") + raw[e_b:]
        try:
            ast.parse(chk_bytes.decode("utf-8"), filename=rel)
        except (UnicodeDecodeError, SyntaxError):
            continue
        idx += 1
        sha = hashlib.sha256(f"{rel}:{s_b}:{e_b}:{repl}".encode("utf-8")).hexdigest()[:12]
        mutants.append({
            "id": f"AM-{short}-{idx:04d}",
            "sha": sha,
            "file": rel,
            "line": lineno,
            "col": col,
            "kind": kind,
            "start_byte": s_b,
            "end_byte": e_b,
            "orig": orig,
            "repl": repl,
        })
        if limit > 0 and idx >= limit:
            break
    return mutants


def collect_mutants(root=ROOT, only_file=None, limit=0, include_dev=False):
    default_list = list(TCB_TARGETS) + (list(DEV_TARGETS) if include_dev else [])
    targets = [only_file] if only_file else default_list
    for rel in targets:
        if rel not in CLAIMS_TARGETS:
            raise ValueError(f"{rel!r} is not in CLAIMS_TARGETS: {CLAIMS_TARGETS}")
        if not (root / rel).is_file():
            raise FileNotFoundError(f"missing target file {root / rel}")
    out = []
    for rel in targets:
        src = (root / rel).read_text(encoding="utf-8")
        ms = generate_for_source(rel, src, limit=limit)
        out.extend(ms)
    return out


def _probe_bwrap():
    if not shutil.which("bwrap"):
        return False
    try:
        r = subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"],
                           capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False


def _force_rmtree(path):
    p = str(path)
    if not os.path.lexists(p):
        return
    for rd, dirs, files in os.walk(p):
        try:
            os.chmod(rd, 0o700)
        except OSError:
            pass
        for dn in dirs:
            dp = os.path.join(rd, dn)
            if not os.path.islink(dp):
                try:
                    os.chmod(dp, 0o700)
                except OSError:
                    pass
        for fn in files:
            fp = os.path.join(rd, fn)
            if not os.path.islink(fp):
                try:
                    os.chmod(fp, 0o600)
                except OSError:
                    pass
    shutil.rmtree(p, ignore_errors=True)


def _run_harness_cmd(tree, harness_rel, flag, timeout_s, as_bytes, sub_tmp):
    hpath = tree / harness_rel
    if not hpath.is_file():
        return "survived"
    argv = [sys.executable, str(hpath), flag]
    if shutil.which("prlimit"):
        argv = ["prlimit", f"--as={as_bytes}", *argv]
    child_env = dict(os.environ, TMPDIR=str(sub_tmp), TMP=str(sub_tmp), TEMP=str(sub_tmp),
                     OPERATOR_AST_MUTANTS="1")
    proc = subprocess.Popen(argv, cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, env=child_env, start_new_session=True)
    timed_out = False
    out_b = b""
    try:
        out_b, _ = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    if timed_out:
        return "timeout"
    if proc.returncode is not None and proc.returncode < 0:
        return "crashed"
    if proc.returncode != 0 or b": OK" not in out_b:
        return "killed"
    return "survived"


def _eval_phase(root, m, phase):
    rel = m["file"]
    raw = (root / rel).read_bytes()
    mut_bytes = raw[:m["start_byte"]] + m["repl"].encode("utf-8") + raw[m["end_byte"]:]
    harnesses = HARNESS_FOR.get(rel, (rel,))
    td = tempfile.mkdtemp(prefix="amut.")
    try:
        tree = pathlib.Path(td, "tree")
        sub_tmp = pathlib.Path(td, "t")
        sub_tmp.mkdir(parents=True, exist_ok=True)
        shutil.copytree(root, tree, ignore=shutil.ignore_patterns(".git", "__pycache__"), symlinks=True)
        target = tree / rel
        mode = target.stat().st_mode
        target.write_bytes(mut_bytes)
        target.chmod(mode)
        if phase == "selftest":
            for h_rel in harnesses:
                st = _run_harness_cmd(tree, h_rel, "--selftest", TIMEOUT_S, 1073741824, sub_tmp)
                if st != "survived":
                    return m["id"], st
            return m["id"], "survived"
        fl_flag = "-" + "-first-level"
        for h_rel in harnesses:
            h_path = tree / h_rel
            if h_path.is_file() and fl_flag in h_path.read_text(encoding="utf-8", errors="replace"):
                st_fl = _run_harness_cmd(tree, h_rel, fl_flag, FIRST_LEVEL_TIMEOUT_S, 4294967296, sub_tmp)
                if st_fl != "survived":
                    return m["id"], st_fl
        return m["id"], "survived"
    finally:
        _force_rmtree(td)


def score_mutants(root, mutants, workers=4):
    bwrap_ok = _probe_bwrap()
    results = {}
    w_st = max(1, workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=w_st) as ex:
        futs = [ex.submit(_eval_phase, root, m, "selftest") for m in mutants]
        for f in concurrent.futures.as_completed(futs):
            mid, status = f.result()
            results[mid] = status
    if bwrap_ok:
        fl_flag = "-" + "-first-level"
        fl_candidates = []
        for m in mutants:
            if results.get(m["id"]) != "survived":
                continue
            harnesses = HARNESS_FOR.get(m["file"], (m["file"],))
            if any((root / h).is_file() and fl_flag in (root / h).read_text(encoding="utf-8", errors="replace")
                   for h in harnesses):
                fl_candidates.append(m)
        if fl_candidates:
            w_fl = max(1, min(w_st, 6))
            with concurrent.futures.ThreadPoolExecutor(max_workers=w_fl) as ex:
                futs = [ex.submit(_eval_phase, root, m, "first_level") for m in fl_candidates]
                for f in concurrent.futures.as_completed(futs):
                    mid, status = f.result()
                    results[mid] = status
    killed = sum(1 for v in results.values() if v == "killed")
    crashed = sum(1 for v in results.values() if v == "crashed")
    timeout = sum(1 for v in results.values() if v == "timeout")
    survived_muts = [m for m in mutants if results.get(m["id"]) == "survived"]
    survived_ids = [m["id"] for m in survived_muts]
    denom = len(mutants)
    strict_pct = round(100.0 * killed / denom, 2) if denom else 100.0
    per_file = {}
    for m in mutants:
        fn = m["file"]
        rec = per_file.setdefault(fn, {"total": 0, "killed": 0, "crashed": 0, "timeout": 0, "survived": 0})
        rec["total"] += 1
        st = results.get(m["id"], "survived")
        rec[st] = rec.get(st, 0) + 1
    for fn, rec in per_file.items():
        rec["strict_kill_pct"] = round(100.0 * rec["killed"] / rec["total"], 2) if rec["total"] else 100.0
    return {
        "bwrap_first_level": bwrap_ok,
        "total": denom,
        "killed": killed,
        "crashed": crashed,
        "timeout": timeout,
        "survived": len(survived_ids),
        "strict_kill_pct": strict_pct,
        "score_pct": strict_pct,
        "per_file": per_file,
        "survivor_ids": survived_ids,
        "survivors_detail": [
            {"id": m["id"], "file": m["file"], "line": m["line"], "kind": m["kind"],
             "orig": m["orig"][:80], "repl": m["repl"][:80]}
            for m in survived_muts[:200]
        ],
    }


def selftest():
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    # A all 11 TCB modules + DEV_TARGETS generate deterministic AST-valid mutants
    m1 = collect_mutants(ROOT, limit=15, include_dev=True)
    m2 = collect_mutants(ROOT, limit=15, include_dev=True)
    by_file = {t: [m for m in m1 if m["file"] == t] for t in CLAIMS_TARGETS}
    check(len(TCB_TARGETS) == 11 and len(CLAIMS_TARGETS) == 12
          and all(len(v) >= 5 for v in by_file.values()),
          f"A all 12 TCB+DEV files produce AST mutants: { {k: len(v) for k, v in by_file.items()} }")
    check([m["sha"] for m in m1] == [m["sha"] for m in m2],
          "A2 mutant generation is deterministic")

    # B selftest / first_level / _stop_namespace are never mutated; BoolOp, chained Compare, and die() ARE mutated
    sample_src = (
        "def guard(x, y):\n"
        "    if x < 0 or y < 0:\n"
        "        die('neg')\n"
        "    if 0 <= x <= 10:\n"
        "        return True\n"
        "    return False\n\n"
        "def _stop_namespace(p):\n"
        "    if p < 0:\n"
        "        raise ValueError('skip')\n"
        "    return p == 1\n\n"
        "def selftest():\n"
        "    return 1 == 1\n"
    )
    ms_s = generate_for_source("bin/fx.py", sample_src)
    kinds_s = {m["kind"] for m in ms_s}
    check(ms_s and all(m["line"] <= 6 for m in ms_s)
          and "boolop" in kinds_s and "guard_off" in kinds_s and "cmp_chain_0" in kinds_s,
          f"B excluded functions skipped; BoolOp/chained-Compare/die mutated: {kinds_s}")

    # C scorer distinguishes killed guard mutants from surviving dead-code mutants and never inflates strict_kill_pct
    with tempfile.TemporaryDirectory(prefix="amut-st.") as td:
        troot = pathlib.Path(td)
        (troot / "bin").mkdir()
        fx_code = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "def live_check(x):\n"
            "    if x < 0:\n"
            "        raise ValueError('bad')\n"
            "    return True\n"
            "def dead_helper():\n"
            "    return True\n"
            "def selftest():\n"
            "    try:\n"
            "        live_check(-1)\n"
            "        return 1\n"
            "    except ValueError:\n"
            "        pass\n"
            "    if not live_check(1):\n"
            "        return 1\n"
            "    print('selftest: OK')\n"
            "    return 0\n"
            "if __name__ == '__main__' and '--selftest' in sys.argv:\n"
            "    sys.exit(selftest())\n"
        )
        fx_p = troot / "bin" / "spawn.py"
        fx_p.write_text(fx_code, encoding="utf-8")
        fx_p.chmod(0o755)
        fx_ms = generate_for_source("bin/spawn.py", fx_code)
        sc = score_mutants(troot, fx_ms, workers=2)
        check(sc["killed"] >= 2 and sc["survived"] >= 1
              and sc["strict_kill_pct"] == round(100.0 * sc["killed"] / sc["total"], 2),
              f"C scorer kills tested mutants and reports strict_kill_pct: {sc}")

    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("verb", nargs="?")
    ap.add_argument("--file", dest="only_file", default=None)
    ap.add_argument("--include-dev", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--fail-on-survivor", action="store_true")
    ap.add_argument("--json", action="store_true")
    a, extra = ap.parse_known_args(argv[1:])
    if extra or a.verb not in ("list", "score") or a.limit < 0 or a.workers < 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        mutants = collect_mutants(ROOT, only_file=a.only_file, limit=a.limit,
                                  include_dev=a.include_dev)
    except (ValueError, OSError) as e:
        print(f"ast-mutants: VOID, {e}", file=sys.stderr)
        return 2
    if a.verb == "list":
        counts = {}
        for m in mutants:
            counts[m["file"]] = counts.get(m["file"], 0) + 1
        digest = hashlib.sha256(
            "\n".join(m["sha"] for m in mutants).encode("utf-8")
        ).hexdigest()[:16]
        if a.json:
            print(json.dumps({"total": len(mutants), "digest": digest,
                              "by_file": counts, "mutants": mutants},
                             ensure_ascii=True, indent=1))
        else:
            for rel, cnt in counts.items():
                print(f"  {rel:28} {cnt:5d} mutants")
            print(f"ast-mutants: total={len(mutants)} files={len(counts)} digest={digest}")
        return 0
    rep = score_mutants(ROOT, mutants, workers=a.workers)
    if a.json:
        print(json.dumps(rep, ensure_ascii=True, sort_keys=True, indent=1))
    else:
        print(f"ast-mutants: total={rep['total']} killed={rep['killed']} "
              f"crashed={rep['crashed']} timeout={rep['timeout']} "
              f"survived={rep['survived']} strict_kill_pct={rep['strict_kill_pct']}%")
    if a.fail_on_survivor and rep["survived"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
