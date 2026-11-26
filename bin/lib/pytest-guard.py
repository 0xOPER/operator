#!/usr/bin/env python3
"""pytest-guard -- in-process integrity wrapper for sealed pytest checks.

Defeats candidate-code process-exit short-circuits (os._exit(0), atexit),
runner monkey-patching, runtime test-node skipping/deselection, and memory
introspection inside the shared Python interpreter:
  1. Reads the one-time 32-byte host key from /w/.op-key into a private closure
     and zeroes + truncates /w/.op-key before any candidate path enters sys.path.
  2. Imports pytest and unittest from trusted system paths first and snapshots
     core outcome classes, assertion methods, and code objects.
  3. Installs an irremovable CPython sys.addaudithook blocking candidate frames
     under /w/export (outside sealed oracle paths) from calling sys._getframe,
     gc.get_objects/get_referrers, ctypes.*, or opening /w/.op-*, /prog/*, or
     sealed oracle files directly.
  4. Emits an HMAC-SHA256 receipt to /w/.op-receipt inside pytest_sessionfinish
     carrying collected/passed/failed/errors/skipped counts, node IDs, and
     runner_intact status.
"""
import gc
import hashlib
import hmac
import json
import os
import sys


def _bootstrap():
    key_path = "/w/.op-key"
    meta_path = "/w/.op-meta"
    receipt_path = "/w/.op-receipt"

    with open(key_path, "rb") as kf:
        secret_key = kf.read().strip()
    with open(key_path, "r+b") as kf:
        kf.seek(0)
        kf.write(b"\x00" * 64)
        kf.flush()
        kf.truncate(0)

    oracle_roots = ()
    extra_pythonpath = ()
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as mf:
                mdoc = json.load(mf)
            oracle_roots = tuple(
                os.path.normpath(p) for p in (mdoc.get("oracle_roots") or ()) if isinstance(p, str)
            )
            extra_pythonpath = tuple(
                p for p in (mdoc.get("pythonpath") or ()) if isinstance(p, str) and p
            )
        finally:
            try:
                os.unlink(meta_path)
            except OSError:
                pass

    # Strip any candidate directory from sys.path before importing runner modules
    sys.path[:] = [
        p for p in sys.path
        if p and not os.path.abspath(p).startswith("/w/export")
    ]

    import pytest
    import unittest.case as _uc
    import _pytest.outcomes as _outcomes

    def _sig(obj):
        code = getattr(obj, "__code__", None)
        return (id(obj), id(code) if code is not None else None)

    snapshots = (
        (pytest, "fail", _sig(pytest.fail)),
        (pytest, "skip", _sig(pytest.skip)),
        (pytest, "xfail", _sig(pytest.xfail)),
        (_outcomes, "OutcomeException", _sig(_outcomes.OutcomeException)),
        (_outcomes, "Failed", _sig(_outcomes.Failed)),
        (_outcomes, "Skipped", _sig(_outcomes.Skipped)),
        (_uc.TestCase, "assertEqual", _sig(_uc.TestCase.assertEqual)),
        (_uc.TestCase, "assertTrue", _sig(_uc.TestCase.assertTrue)),
        (_uc.TestCase, "fail", _sig(_uc.TestCase.fail)),
    )

    getframe = sys._getframe
    in_hook = [False]
    writing_receipt = [False]

    def _is_candidate_file(fname):
        if not fname or fname.startswith("<"):
            return False
        norm = os.path.normpath(os.path.abspath(fname))
        if norm != "/w/export" and not norm.startswith("/w/export/"):
            return False
        for oro in oracle_roots:
            if norm == oro or norm.startswith(oro + "/"):
                return False
        return True

    def _caller_is_candidate():
        depth = 2  # skip _caller_is_candidate (0) and _audit (1)
        while True:
            try:
                fr = getframe(depth)
            except ValueError:
                return False
            fn = fr.f_code.co_filename or ""
            if fn.startswith("<") and not fn.startswith("<frozen "):
                depth += 1
                continue
            return _is_candidate_file(fn)

    def _stack_has_candidate():
        depth = 1
        while True:
            try:
                fr = getframe(depth)
            except ValueError:
                return False
            if _is_candidate_file(fr.f_code.co_filename):
                return True
            depth += 1

    def _audit(event, args):
        if in_hook[0]:
            return
        in_hook[0] = True
        try:
            if event == "open":
                target = args[0] if args else None
                if isinstance(target, (str, bytes)):
                    t_str = target.decode("utf-8", "surrogateescape") if isinstance(target, bytes) else target
                    norm_t = os.path.normpath(os.path.abspath(t_str))
                    if norm_t in (key_path, meta_path) or norm_t.startswith("/w/.op-"):
                        if not (writing_receipt[0] and norm_t == receipt_path):
                            raise PermissionError(f"pytest-guard: access to {norm_t} is denied")
                    if _stack_has_candidate():
                        if norm_t == "/prog" or norm_t.startswith("/prog/"):
                            raise PermissionError("pytest-guard: candidate access to /prog is denied")
                        for oro in oracle_roots:
                            if norm_t == oro or norm_t.startswith(oro + "/"):
                                raise PermissionError("pytest-guard: candidate read of sealed oracle is denied")
            elif event in ("sys._getframe", "gc.get_objects", "gc.get_referrers"):
                if _caller_is_candidate():
                    raise PermissionError(f"pytest-guard: {event} is denied in candidate code")
            elif event.startswith("ctypes.") or (event == "import" and args and str(args[0]).startswith(("ctypes", "_ctypes"))):
                if _stack_has_candidate():
                    raise PermissionError(f"pytest-guard: {event} is denied in candidate code")
        finally:
            in_hook[0] = False

    class _GuardPlugin:
        def __init__(self):
            self.collected = []
            self.passed_ids = []
            self.failed_ids = []
            self.skipped_ids = []
            self.errors = 0

        def pytest_collection_modifyitems(self, session, config, items):
            self.collected = [it.nodeid for it in items]

        def pytest_collectreport(self, report):
            if report.failed:
                self.errors += 1

        def pytest_runtest_logreport(self, report):
            if report.when == "call":
                if report.passed:
                    self.passed_ids.append(report.nodeid)
                elif report.failed:
                    self.failed_ids.append(report.nodeid)
                elif report.skipped:
                    self.skipped_ids.append(report.nodeid)
            elif report.when in ("setup", "teardown"):
                if report.failed:
                    self.errors += 1
                elif report.skipped and report.when == "setup":
                    self.skipped_ids.append(report.nodeid)

        def pytest_internalerror(self, excrepr, excinfo):
            self.errors += 1

        def pytest_sessionfinish(self, session, exitstatus):
            intact = all(_sig(getattr(holder, attr, None)) == want for holder, attr, want in snapshots)
            payload = {
                "collected": self.collected,
                "errors": self.errors,
                "exitstatus": int(exitstatus),
                "failed": len(self.failed_ids),
                "passed": len(self.passed_ids),
                "passed_ids": self.passed_ids,
                "runner_intact": bool(intact),
                "skipped": len(self.skipped_ids),
                "skipped_ids": self.skipped_ids,
            }
            canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            mac = hmac.new(secret_key, canon, hashlib.sha256).hexdigest()
            doc = json.dumps({"hmac": mac, "payload": payload}, sort_keys=True)
            writing_receipt[0] = True
            try:
                with open(receipt_path, "w", encoding="utf-8") as rf:
                    rf.write(doc + "\n")
            finally:
                writing_receipt[0] = False

    plugin = _GuardPlugin()
    gc.collect()
    sys.addaudithook(_audit)
    # Prepend /w/export (and any authored PYTHONPATH entries) only after runner snapshot and audit hook are active
    sys.path.insert(0, "/w/export")
    for pp in reversed(extra_pythonpath):
        full_pp = pp if os.path.isabs(pp) else os.path.normpath(os.path.join("/w/export", pp))
        if full_pp not in sys.path:
            sys.path.insert(0, full_pp)
    rc = pytest.main(["--rootdir=/w/export", *sys.argv[1:]], plugins=[plugin])
    return int(rc) if isinstance(rc, int) else int(getattr(rc, "value", 1))


if __name__ == "__main__":
    sys.exit(_bootstrap())
