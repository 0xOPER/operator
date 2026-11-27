#!/usr/bin/env python3
"""derive -- a sealed baseline for a repository, found rather than written.

`derive.py rows <work-repo>` reads the tree at a commit (no checkout) and names
the runners it knows how to find: pytest and unittest, the test, check and
lint targets of a Makefile, the test, lint and typecheck scripts of a
package.json, cargo and go. For each it writes a contract row whose oracle
pins what the runner reads, so a worker cannot weaken the check it is held to.

`derive.py pin <program-dir> <run-parent> --at <commit>` runs every derived row
once at the commit, through the same jail every check runs in, and says which
are red there. Those are the known-red baseline: done then means no new red.

A derived row is a starting point. One that needs what the jail does not have
(an installed tree, a toolchain) is red at the pin and says so.

usage: derive.py rows <work-repo> [--at <commit>] --seat <seat> --reviewer <seat> [--json]
       derive.py pin <program-dir> <run-parent> --at <commit> [--json]
       derive.py --selftest | --first-level
exit: 0 ok, 1 a finding, 2 usage or VOID
"""
import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))

PYTEST_CONFIGS = ("pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "conftest.py")
TEST_FILE_RE = re.compile(r"(?:^|/)test_[^/]*\.py$")
MAKE_TARGET_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*):")
MAKE_TARGETS = ("test", "check", "lint")
NPM_SCRIPTS = ("test", "lint", "typecheck")
STAGE = "verify"
TIMEOUT = 600


class Void(Exception):
    pass


class Finding(Exception):
    pass


def sh(argv, cwd=None):
    return subprocess.run(argv, capture_output=True, text=True, cwd=cwd, stdin=subprocess.DEVNULL)


def _git(repo, *args, binary=False):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        raise Void(f"git {' '.join(args[:2])} refused in {repo}: "
                   f"{(r.stderr or b'').decode('utf-8', 'replace').strip()[:160]}")
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def tree_of(repo, at=None):
    """(the files at the commit, a reader of one file's bytes at the commit)."""
    commit = _git(repo, "rev-parse", "--verify", f"{at or 'HEAD'}^{{commit}}").strip()
    names = [ln for ln in _git(repo, "ls-tree", "-r", "--name-only", "-z", commit).split("\0") if ln]

    def read(path):
        try:
            return _git(repo, "show", f"{commit}:{path}")
        except Void:
            return ""

    return commit, set(names), read


def _tests_dir(files):
    """The Python test directory, by its files: `tests` before `test`."""
    for d in ("tests", "test"):
        if any(f.startswith(d + "/") and TEST_FILE_RE.search(f) for f in files):
            return d
    return None


def detect(files, read):
    """The rows a tree carries. Each: id, cmd, oracle, what (a word for people)."""
    found = []
    tdir = _tests_dir(files)
    if tdir:
        cfg = [c for c in PYTEST_CONFIGS if c in files]
        pyproject = read("pyproject.toml")
        if cfg or "[tool.pytest" in pyproject:
            oracle = [tdir] + cfg + (["pyproject.toml"] if "[tool.pytest" in pyproject else [])
            found.append({"id": "tests.pytest", "cmd": f"python3 -m pytest -q {tdir}",
                          "oracle": oracle, "what": "the pytest suite"})
        else:
            found.append({"id": "tests.unittest",
                          "cmd": f"python3 -m unittest discover -s {tdir} -p 'test_*.py'",
                          "oracle": [tdir], "what": "the unittest suite"})
    if "Makefile" in files:
        targets = []
        for ln in read("Makefile").splitlines():
            m = MAKE_TARGET_RE.match(ln)
            if m and m.group(1) not in targets:
                targets.append(m.group(1))
        for t in MAKE_TARGETS:
            if t in targets:
                found.append({"id": f"make.{t}", "cmd": f"make {t}", "oracle": ["Makefile"],
                              "what": f"the Makefile's {t} target"})
    if "package.json" in files:
        try:
            scripts = (json.loads(read("package.json")) or {}).get("scripts") or {}
        except ValueError:
            scripts = {}
        if isinstance(scripts, dict):
            lock = [lk for lk in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
                                  "yarn.lock") if lk in files]
            for s in NPM_SCRIPTS:
                if isinstance(scripts.get(s), str) and scripts[s].strip():
                    found.append({"id": f"npm.{s}", "cmd": f"npm run {s}",
                                  "oracle": ["package.json"] + lock, "what": f"the package's {s} script"})
    if "Cargo.toml" in files:
        found.append({"id": "cargo.test", "cmd": "cargo test",
                      "oracle": ["Cargo.toml"] + (["Cargo.lock"] if "Cargo.lock" in files else []),
                      "what": "the cargo suite"})
    if "go.mod" in files:
        found.append({"id": "go.test", "cmd": "go test ./...",
                      "oracle": ["go.mod"] + (["go.sum"] if "go.sum" in files else []),
                      "what": "the go suite"})
    return found


def rows_of(found, seat, reviewer):
    """Derived rows as contract rows (the shape bin/contract.py validates)."""
    return [{"id": r["id"], "stage": STAGE, "desc": f"derived: {r['what']}", "kind": "run",
             "seat": seat, "reviewer": reviewer, "deps": [], "cmd": r["cmd"],
             "timeout": TIMEOUT, "oracle": list(r["oracle"]), "ro": []} for r in found]


def to_toml(rows):
    out = []
    for r in rows:
        out.append("[[row]]")
        out.append(f'id = "{r["id"]}"')
        out.append(f'stage = "{r["stage"]}"')
        out.append(f'desc = "{r["desc"]}"')
        out.append('kind = "run"')
        out.append(f'seat = "{r["seat"]}"')
        out.append(f'reviewer = "{r["reviewer"]}"')
        out.append(f'cmd = {json.dumps(r["cmd"])}')
        out.append(f"timeout = {r['timeout']}")
        out.append("oracle = [" + ", ".join(json.dumps(o) for o in r["oracle"]) + "]")
        out.append("")
    return "\n".join(out)


def pin(prog, parent, at=None):
    """Every derived row, run once at the commit through the check jail.
    Returns [{id, rc, known_red}] and never files a result."""
    import contract as contract_mod
    doc = contract_mod.load(prog)   # a broken table is a finding before any row runs
    commit, _files, _read = tree_of(parent, at)
    derived = [r["id"] for r in detect(_files, _read)]
    saved = {k: os.environ.get(k) for k in ("CONTRACT_PIN", "CONTRACT_REPO")}
    os.environ["CONTRACT_PIN"] = commit
    os.environ["CONTRACT_REPO"] = parent
    out = []
    try:
        for rid in derived:
            row = doc["by_id"].get(rid)
            if row is None:
                out.append({"id": rid, "rc": None, "known_red": None, "why": "not in the contract"})
                continue
            try:
                rc, _runfile, _cid = contract_mod.run_check(row, prog, parent, commit, "derive", {},
                                                           "derive", record_log=False)
                out.append({"id": rid, "rc": rc, "known_red": rc != 0})
            except (contract_mod.Void, contract_mod.Finding) as e:
                out.append({"id": rid, "rc": None, "known_red": None, "why": str(e)[:200]})
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return out


def flag(argv, name, default=None):
    if name in argv and argv.index(name) + 1 < len(argv):
        return argv[argv.index(name) + 1]
    return default


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if argv[1:] == ["--first-level"]:
        return first_level()
    if len(argv) >= 2 and argv[1] == "rows" and argv[2:]:
        repo, at = argv[2], flag(argv, "--at")
        seat, reviewer = flag(argv, "--seat"), flag(argv, "--reviewer")
        if not seat or not reviewer:
            print("derive: --seat and --reviewer name who a derived row holds and who judges it",
                  file=sys.stderr)
            return 2
        try:
            _commit, files, read = tree_of(repo, at)
        except Void as e:
            print(f"derive: VOID, {e}", file=sys.stderr)
            return 2
        rows = rows_of(detect(files, read), seat, reviewer)
        if "--json" in argv:
            print(json.dumps({"rows": rows}, sort_keys=True))
        else:
            print(to_toml(rows) if rows else "# derive: no runner this tool knows was found")
        return 0
    if len(argv) >= 3 and argv[1] == "pin" and argv[2:]:
        prog, parent, at = argv[2], argv[3], flag(argv, "--at")
        if not os.path.isdir(os.path.join(parent, ".git")):
            print("derive: VOID, the run parent must be an engine-initialized git tree", file=sys.stderr)
            return 2
        try:
            out = pin(prog, parent, at)
        except Void as e:
            print(f"derive: VOID, {e}", file=sys.stderr)
            return 2
        if "--json" in argv:
            print(json.dumps({"pin": out}, sort_keys=True))
        else:
            if not out:
                print("  (no derived row in this contract)")
            for r in out:
                state = "red at the pin" if r.get("known_red") else (
                    "green at the pin" if r.get("known_red") is False else f"couldn't speak: {r.get('why')}")
                print(f"  {r['id']}: {state}")
        return 0
    print("usage: derive.py rows <work-repo> [--at <commit>] --seat <seat> --reviewer <seat> [--json] |\n"
          "       derive.py pin <program-dir> <run-parent> --at <commit> [--json] | "
          "--selftest | --first-level", file=sys.stderr)
    return 2


# --- selftest ----------------------------------------------------------------------------


def _commit_all(repo, msg, env):
    for a in (["add", "-A"], ["commit", "-qm", msg]):
        subprocess.run(["git", "-C", repo, *a], capture_output=True, env=env, check=True)


def _git_env():
    return {**os.environ, "GIT_AUTHOR_NAME": "d", "GIT_COMMITTER_NAME": "d",
            "GIT_AUTHOR_EMAIL": "d@x", "GIT_COMMITTER_EMAIL": "d@x"}


def selftest():
    """The room suite: what a tree carries, the rows it becomes, and that
    those rows load and lint as a contract."""
    import shutil
    import tempfile
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    def write(repo, path, text):
        full = os.path.join(repo, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)

    base = tempfile.mkdtemp(prefix="derive-st.")
    try:
        def repo_of(files):
            r = os.path.join(base, f"r{len(os.listdir(base))}")
            os.makedirs(r)
            subprocess.run(["git", "init", "-q", r], capture_output=True, check=True)
            for p, t in files.items():
                write(r, p, t)
            _commit_all(r, "base", _git_env())
            return r

        def ids(repo):
            return [r["id"] for r in detect(*tree_of(repo)[1:])]

        # A pytest by its config, with its test directory and config pinned
        r = repo_of({"pytest.ini": "[pytest]\n", "tests/test_a.py": "def test_a():\n    pass\n",
                     "src/a.py": "x = 1\n"})
        got = detect(*tree_of(r)[1:])
        check([g["id"] for g in got] == ["tests.pytest"] and got[0]["cmd"] == "python3 -m pytest -q tests"
              and got[0]["oracle"] == ["tests", "pytest.ini"],
              f"A a pytest tree is one row, its suite and config pinned: {got}")
        # unittest when nothing names pytest
        r = repo_of({"tests/test_a.py": "import unittest\n", "test/test_b.py": "import unittest\n"})
        got = detect(*tree_of(r)[1:])
        check([g["id"] for g in got] == ["tests.unittest"] and "unittest discover -s tests" in got[0]["cmd"]
              and got[0]["oracle"] == ["tests"], f"B a tree with tests and no pytest config is unittest: {got}")
        # pyproject's table counts as pytest config
        r = repo_of({"pyproject.toml": "[tool.pytest.ini_options]\nx = 1\n", "tests/test_a.py": "x = 1\n"})
        got = detect(*tree_of(r)[1:])
        check(got and got[0]["id"] == "tests.pytest" and "pyproject.toml" in got[0]["oracle"],
              f"B a pyproject table is pytest config: {got}")
        # Makefile targets
        r = repo_of({"Makefile": ".PHONY: test lint\nall: build\n\ntest:\n\tpython3 -m pytest\n\nlint:\n\truff check .\n"})
        check(ids(r) == ["make.test", "make.lint"], f"C the Makefile's test and lint targets: {ids(r)}")
        # package.json scripts
        r = repo_of({"package.json": json.dumps({"scripts": {"test": "jest", "build": "tsc", "lint": "eslint ."}}),
                     "package-lock.json": "{}\n"})
        got = detect(*tree_of(r)[1:])
        check([g["id"] for g in got] == ["npm.test", "npm.lint"]
              and got[0]["oracle"] == ["package.json", "package-lock.json"],
              f"D the package's test and lint scripts, its manifest and lockfile pinned: {got}")
        # a broken package.json is no finding: nothing is derived from it
        r = repo_of({"package.json": "{not json"})
        check(ids(r) == [], "D a package.json that doesn't parse derives nothing")
        # cargo and go
        r = repo_of({"Cargo.toml": "[package]\nname = 'x'\n"})
        check(ids(r) == ["cargo.test"], f"E a cargo tree: {ids(r)}")
        r = repo_of({"go.mod": "module x\n", "go.sum": ""})
        got = detect(*tree_of(r)[1:])
        check([g["id"] for g in got] == ["go.test"] and got[0]["oracle"] == ["go.mod", "go.sum"],
              f"E a go tree with its sum: {got}")
        # nothing
        r = repo_of({"README.md": "hi\n"})
        check(ids(r) == [], "F a tree with no runner derives no row")
        # --at reads that commit, not the working tree
        r = repo_of({"pytest.ini": "[pytest]\n", "tests/test_a.py": "x = 1\n"})
        write(r, "pytest.ini", "[pytest]\naddopts = -x\n")
        check(tree_of(r, "HEAD")[1] == {"pytest.ini", "tests/test_a.py"} and ids(r) == ["tests.pytest"],
              "G a commit is read, never the working tree")
        # the rows load and lint as a contract
        import contract as contract_mod
        r = repo_of({"pytest.ini": "[pytest]\n", "tests/test_a.py": "x = 1\n",
                     "Makefile": "test:\n\ttrue\n"})
        prog = os.path.join(base, "prog")
        os.makedirs(os.path.join(prog, "roles"))
        rows = rows_of(detect(*tree_of(r)[1:]), "writer", "reviewer")
        with open(os.path.join(prog, "contract.toml"), "w", encoding="utf-8") as f:
            f.write("schema = 2\n\n" + to_toml(rows))
        with open(os.path.join(prog, "team.toml"), "w", encoding="utf-8") as f:
            f.write('schema = 1\nname = "d"\n[seat.writer]\nrole = "roles/w.md"\nadapter = "stub"\n'
                    'write = ["src/**"]\n[seat.reviewer]\nrole = "roles/w.md"\nadapter = "stub"\n')
        with open(os.path.join(prog, "roles", "w.md"), "w", encoding="utf-8") as f:
            f.write("w\n")
        try:
            doc = contract_mod.load(prog)
            check(sorted(doc["by_id"]) == ["make.test", "tests.pytest"]
                  and all(doc["by_id"][k]["evidence"] == "sealed" for k in doc["by_id"]),
                  f"H the derived rows load as a contract, every one sealed: {sorted(doc['by_id'])}")
        except (contract_mod.Finding, contract_mod.Void) as e:
            check(False, f"H the derived rows load as a contract: {e}")
        out = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "contract.py"), "lint", prog],
                             capture_output=True, text=True, stdin=subprocess.DEVNULL)
        check(out.returncode == 0 and "findings=0" in out.stdout,
              f"H the derived rows lint clean: rc={out.returncode} {out.stdout.strip()[-120:]}")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def first_level():
    """The pin, through the real check jail: a suite that passes is green at
    the commit, a suite with a failing test is the known-red baseline, and
    nothing is filed."""
    import shutil
    import tempfile
    import contract as contract_mod
    import spawn as spawn_mod
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="derive-fl.")
    old = os.environ.get("OPERATOR_HOME")
    try:
        home = os.path.join(base, "home")
        os.makedirs(home)
        os.environ["OPERATOR_HOME"] = home
        prog = os.path.join(base, "prog")
        os.makedirs(os.path.join(prog, "roles"))
        with open(os.path.join(prog, "team.toml"), "w", encoding="utf-8") as f:
            f.write('schema = 1\nname = "d"\n[seat.writer]\nrole = "roles/w.md"\nadapter = "stub"\n'
                    'write = ["src/**"]\n[seat.reviewer]\nrole = "roles/w.md"\nadapter = "stub"\n')
        with open(os.path.join(prog, "roles", "w.md"), "w", encoding="utf-8") as f:
            f.write("w\n")
        # unittest only: pytest is not a dependency of this suite
        rd, parent, sha = spawn_mod._world(home, "d1", {
            "src/a.py": "def add(a, b):\n    return a + b\n",
            "tests/test_add.py": "import os, sys, unittest\n"
                                 "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
                                 "from src.a import add\n\n"
                                 "class T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n",
            "tests/test_bad.py": "import unittest\n\n"
                                 "class T(unittest.TestCase):\n    def test_bad(self):\n        self.fail('known red')\n"})
        # the world's base commit carries everything; a second commit adds the red test
        subprocess.run(["git", "-C", parent, "rm", "-q", "tests/test_bad.py"], capture_output=True, check=True)
        subprocess.run(["git", "-C", parent, "add", "-A"], capture_output=True, check=True)
        ge = {**os.environ, "GIT_AUTHOR_NAME": "d", "GIT_COMMITTER_NAME": "d",
              "GIT_AUTHOR_EMAIL": "d@x", "GIT_COMMITTER_EMAIL": "d@x"}
        subprocess.run(["git", "-C", parent, "commit", "-qm", "green first"], capture_output=True, env=ge,
                       check=True)
        green_sha = subprocess.run(["git", "-C", parent, "rev-parse", "HEAD"], capture_output=True,
                                   text=True).stdout.strip()
        with open(os.path.join(parent, "tests", "test_bad.py"), "w", encoding="utf-8") as f:
            f.write("import unittest\n\n\nclass T(unittest.TestCase):\n    def test_bad(self):\n        self.fail('known red')\n")
        subprocess.run(["git", "-C", parent, "add", "-A"], capture_output=True, check=True)
        subprocess.run(["git", "-C", parent, "commit", "-qm", "red second"], capture_output=True, env=ge,
                       check=True)
        with open(os.path.join(prog, "contract.toml"), "w", encoding="utf-8") as f:
            f.write("schema = 2\n\n" + to_toml(rows_of(detect(*tree_of(parent)[1:]), "writer", "reviewer")))
        try:
            doc = contract_mod.load(prog)
            check(sorted(doc["by_id"]) == ["tests.unittest"], f"L0 the tree derives its unittest row: {sorted(doc['by_id'])}")
            at_green = pin(prog, parent, green_sha)
            check(at_green and at_green[0]["id"] == "tests.unittest" and at_green[0]["known_red"] is False,
                  f"L1 a passing suite is green at the commit: {at_green}")
            at_red = pin(prog, parent)
            check(at_red and at_red[0]["known_red"] is True,
                  f"L2 a failing test is the known-red baseline, said not hidden: {at_red}")
            log = os.path.join(home, "call-log.tsv")
            check(not os.path.exists(log) or "check:tests.unittest" not in open(log).read(),
                  "L3 the pin files no result: the baseline is reported, never recorded as a check")
        finally:
            for k in ("CONTRACT_PIN", "CONTRACT_REPO"):
                os.environ.pop(k, None)
    finally:
        if old is None:
            os.environ.pop("OPERATOR_HOME", None)
        else:
            os.environ["OPERATOR_HOME"] = old
        shutil.rmtree(base, ignore_errors=True)
    print(f"first-level: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "first-level: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Finding as e:
        print(f"derive: {e}", file=sys.stderr)
        sys.exit(1)
    except Void as e:
        print(f"derive: VOID, {e}", file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"derive: VOID, {e}", file=sys.stderr)
        sys.exit(2)
