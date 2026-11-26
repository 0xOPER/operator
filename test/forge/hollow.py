#!/usr/bin/env python3
"""hollow -- the C5 hollow-suite battery against the real pytest + contract engine.

A fixture program whose oracle (`tests/`) is PINNED at a base commit and invoked
through the real `python3 -I -m pytest -q tests` runner (wrapped automatically
by `pytest-guard.py`). Each RECIPE is an adversarial candidate-side sabotage
edit; every recipe must fail (`rc != 0`) under the sealed overlay, the HONEST
twin must pass (`rc == 0`), and under `_vacuous_proof` (`OPERATOR_OVERLAY_OFF=1`)
every recipe passes (or fails on missing deleted file without executing the
broken deliverable), proving causal non-vacuity of the sealed overlay + runner
config guard + pytest-guard.

usage: hollow.py [recipe...|all]      (default: all)
exit: 0 every recipe blocked + honest green + vacuous-proof holds, 1 forgery passed, 2 VOID
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEST_SUITE = (
    "import os, sys\n"
    "sys.path.insert(0, os.getcwd())\n"
    "import delivered\n\n"
    "def test_delivered():\n"
    "    assert delivered.check() == []\n"
)
DELIVERED_GOOD = "def check():\n    return []\n"
DELIVERED_BAD = "def check():\n    return ['the deliverable is broken: audit fails']\n"
CHECK = "python3 -I -m pytest -q tests"


def build(base, edit=None, honest=False):
    prog = os.path.join(base, "prog")
    repo = os.path.join(base, "repo")
    os.makedirs(prog, exist_ok=True)
    os.makedirs(os.path.join(repo, "tests"), exist_ok=True)
    with open(os.path.join(prog, "contract.toml"), "w") as f:
        f.write('schema = 2\n[[row]]\nid = "suite.pass"\nstage = "s"\n'
                'desc = "the suite passes on its vectors"\nkind = "run"\n'
                'seat = "w"\nreviewer = "r"\n'
                f'cmd = "{CHECK}"\noracle = ["tests"]\n')
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_COMMITTER_NAME="t",
               GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_EMAIL="t@x")
    with open(os.path.join(repo, "tests", "test_suite.py"), "w") as f:
        f.write(TEST_SUITE)
    with open(os.path.join(repo, "delivered.py"), "w") as f:
        f.write(DELIVERED_GOOD)
    subprocess.run(["git", "-C", repo, "init", "-q"], capture_output=True, env=env, check=True)
    subprocess.run(["git", "-C", repo, "add", "-A"], capture_output=True, env=env, check=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "base"], capture_output=True, env=env, check=True)
    pin = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                         capture_output=True, text=True, env=env, check=True).stdout.strip()
    os.makedirs(os.path.join(repo, ".git", "info"), exist_ok=True)
    with open(os.path.join(repo, ".git", "info", "attributes"), "w") as f:
        f.write("* -export-ignore -export-subst -text -eol -ident -working-tree-encoding -filter\n")
    with open(os.path.join(repo, "delivered.py"), "w") as f:
        f.write(DELIVERED_BAD if not honest else DELIVERED_GOOD)
    if edit:
        edit(repo, prog)
    subprocess.run(["git", "-C", repo, "add", "-A"], capture_output=True, env=env, check=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "tip", "--allow-empty"],
                   capture_output=True, env=env, check=True)
    return prog, repo, pin


def run_row(prog, repo, pin, arm="a"):
    t_dir = tempfile.mkdtemp(prefix="hollow-run.")
    log = os.path.join(t_dir, "cl.tsv")
    env = dict(os.environ, CONTRACT_REPO=repo, CONTRACT_TIP="HEAD",
               CONTRACT_ARM=arm, CALL_LOG_FILE=log, CONTRACT_PIN=pin)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "contract.py"),
                        "run", prog, "suite.pass"],
                       capture_output=True, text=True, env=env,
                       stdin=subprocess.DEVNULL, timeout=120)
    shutil.rmtree(t_dir, ignore_errors=True)
    return r.returncode, r.stdout + r.stderr


def r_delete(repo, prog):
    os.unlink(os.path.join(repo, "tests", "test_suite.py"))


def r_skip(repo, prog):
    with open(os.path.join(repo, "tests", "test_suite.py"), "w") as f:
        f.write("import pytest\n\ndef test_delivered():\n    pytest.skip('marked flaky')\n")


def r_assert_true(repo, prog):
    with open(os.path.join(repo, "tests", "test_suite.py"), "w") as f:
        f.write("def test_delivered():\n    assert True\n")


def r_conftest(repo, prog):
    with open(os.path.join(repo, "tests", "conftest.py"), "w") as f:
        f.write("import sys, types\nm = types.ModuleType('delivered')\nm.check = lambda: []\nsys.modules['delivered'] = m\n")


def r_root_conftest(repo, prog):
    # Root conftest.py outside tests/ -- defeated specifically by RUNNER_CONFIG_NAMES sealing!
    with open(os.path.join(repo, "conftest.py"), "w") as f:
        f.write("import sys, types\nm = types.ModuleType('delivered')\nm.check = lambda: []\nsys.modules['delivered'] = m\n")


def r_init_patch(repo, prog):
    with open(os.path.join(repo, "tests", "__init__.py"), "w") as f:
        f.write("import sys, types\nm = types.ModuleType('delivered')\nm.check = lambda: []\nsys.modules['delivered'] = m\n")


def r_addopts(repo, prog):
    # Root pytest.ini deselecting test_delivered and pointing at a fake passing suite
    os.makedirs(os.path.join(repo, "fake_ok"), exist_ok=True)
    with open(os.path.join(repo, "fake_ok", "test_ok.py"), "w") as f:
        f.write("def test_ok():\n    assert True\n")
    with open(os.path.join(repo, "pytest.ini"), "w") as f:
        f.write('[pytest]\naddopts = -k "not test_delivered" fake_ok\n')


def r_pyproject(repo, prog):
    os.makedirs(os.path.join(repo, "fake_py"), exist_ok=True)
    with open(os.path.join(repo, "fake_py", "test_ok.py"), "w") as f:
        f.write("def test_ok():\n    assert True\n")
    with open(os.path.join(repo, "pyproject.toml"), "w") as f:
        f.write('[tool.pytest.ini_options]\naddopts = "-k not_a_real_match_or_ok fake_py"\n')
    with open(os.path.join(repo, "fake_py", "test_ok.py"), "w") as f:
        f.write("def test_not_a_real_match_or_ok():\n    assert True\n")


def r_setup_cfg(repo, prog):
    os.makedirs(os.path.join(repo, "fake_sc"), exist_ok=True)
    with open(os.path.join(repo, "fake_sc", "test_ok.py"), "w") as f:
        f.write("def test_sc_pass():\n    assert True\n")
    with open(os.path.join(repo, "setup.cfg"), "w") as f:
        f.write("[tool:pytest]\naddopts = -k test_sc_pass fake_sc\n")


def r_tox_ini(repo, prog):
    os.makedirs(os.path.join(repo, "fake_tx"), exist_ok=True)
    with open(os.path.join(repo, "fake_tx", "test_ok.py"), "w") as f:
        f.write("def test_tx_pass():\n    assert True\n")
    with open(os.path.join(repo, "tox.ini"), "w") as f:
        f.write("[pytest]\naddopts = -k test_tx_pass fake_tx\n")


def r_swap_check(repo, prog):
    with open(os.path.join(repo, "tests", "test_suite.py"), "w") as f:
        f.write("def test_delivered():\n    assert 1 == 1\n")


def r_symlink_swap(repo, prog):
    shutil.rmtree(os.path.join(repo, "tests"))
    os.makedirs(os.path.join(repo, "fake_sym"), exist_ok=True)
    with open(os.path.join(repo, "fake_sym", "test_suite.py"), "w") as f:
        f.write("def test_delivered():\n    assert True\n")
    os.symlink("fake_sym", os.path.join(repo, "tests"))


RECIPES = [
    ("delete", r_delete),
    ("skip", r_skip),
    ("assert-true", r_assert_true),
    ("conftest", r_conftest),
    ("root-conftest", r_root_conftest),
    ("init-patch", r_init_patch),
    ("addopts", r_addopts),
    ("pyproject", r_pyproject),
    ("setup-cfg", r_setup_cfg),
    ("tox-ini", r_tox_ini),
    ("swap-check", r_swap_check),
    ("symlink-swap", r_symlink_swap),
]


def _vacuous_proof():
    """With OPERATOR_OVERLAY_OFF=1, candidate sabotage edits take effect:
    passing recipes exit 0 (and delete/skip exit 5 'no tests collected' / 0
    without running the broken assertion), proving causal non-vacuity."""
    env = dict(os.environ, OPERATOR_OVERLAY_OFF="1",
               OPERATOR_HOLLOW_VACUOUS_PROOF="1")
    greens = []
    for name, edit in RECIPES:
        base = tempfile.mkdtemp(prefix="hollow-off.")
        try:
            prog, repo, pin = build(base, edit, honest=False)
            r = subprocess.run(
                [sys.executable, os.path.join(ROOT, "bin", "contract.py"),
                 "run", prog, "suite.pass"],
                capture_output=True, text=True,
                env=dict(env, CONTRACT_REPO=repo, CONTRACT_TIP="HEAD",
                         CONTRACT_ARM="v", CALL_LOG_FILE=os.path.join(base, "cl.tsv"),
                         CONTRACT_PIN=pin),
                stdin=subprocess.DEVNULL, timeout=120)
            ok = r.returncode == 0 or (
                name == "delete" and r.returncode == 1
                and "the deliverable is broken" not in (r.stdout + r.stderr)
            )
            greens.append((name, ok))
        finally:
            shutil.rmtree(base, ignore_errors=True)
    return greens


def main(argv):
    want = argv[1:] or ["all"]
    if want == ["all"]:
        want = [r[0] for r in RECIPES] + ["honest"]
    base = tempfile.mkdtemp(prefix="hollow.")
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
            print(f"  ok   {label}")
        else:
            bad[0] += 1
            print(f"  FAIL {label}", file=sys.stderr)

    try:
        prog, repo, pin = build(base, honest=True)
        rc, out = run_row(prog, repo, pin)
        check(rc == 0, f"honest twin green (rc={rc}) {out.strip()[:60]}")
        for name, edit in RECIPES:
            if name not in want:
                continue
            pb = os.path.join(base, "x-" + name)
            prog2, repo2, pin2 = build(pb, edit)
            rc, out = run_row(prog2, repo2, pin2, arm=name[:8])
            want_rc = (1, 2) if name == "symlink-swap" else (1,)
            check(rc in want_rc, f"{name} blocked (rc={rc}) {out.strip()[:70]}")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    greens = _vacuous_proof()
    for name, green in greens:
        check(green, f"vacuous-proof {name} greens without the pin")
    print(f"hollow: OK ({ok[0]})" if ok[0] and not bad[0] else "hollow: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
