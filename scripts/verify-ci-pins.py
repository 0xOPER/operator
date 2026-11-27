#!/usr/bin/env python3
"""verify-ci-pins -- what CI installs, it installs by hash.

The workflows used to name vendor CLIs by version and trust whatever the registry
served that day: installed as root, with every script a package called a
postinstall. Now test/cli-pins holds a lockfile whose every entry carries a
sha512 and its registry URL, the workflows install it with `npm ci
--ignore-scripts` as the runner's own user, and the Dockerfile builds FROM a
digest. This reads those files and refuses a tree that drifts: an npm command
in a workflow that is not `npm ci --ignore-scripts`, a lockfile entry with no
hash or no registry URL, a root dependency at anything but an exact version, a
package.json that carries scripts, a FROM without a digest. It never talks to
the network: the hashes were checked against the registry's own bytes before
they were committed, and npm checks them again at every install.

usage:
  verify-ci-pins.py [--root DIR]
  verify-ci-pins.py --selftest
exit: 0 pinned, 1 a pin drifted, 2 usage or VOID
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

PINS = pathlib.Path("test", "cli-pins")
WORKFLOWS = pathlib.Path(".github", "workflows")
REGISTRY = "https://registry.npmjs.org/"
# a sha512 is 64 bytes: 88 base64 characters, the last two pads
INTEGRITY = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
EXACT = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
# name[:tag]@sha256:<64 hex>, as a FROM line names it
DIGEST = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
                    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]*)?@sha256:[0-9a-f]{64}")
# a package manager in command position, after a separator, through a path
NPM = re.compile(r"(?:^|[\s;|&(])(?:\S*/)?(?P<tool>npm|npx|pnpm|yarn)\s+(?P<rest>[^\n]*)")
SEP = re.compile(r"\s*(?:&&|\|\||[;|&])\s*")


class Void(Exception):
    pass


def lock_findings(text):
    """package-lock.json: every entry by hash, from the registry."""
    try:
        lock = json.loads(text)
    except ValueError:
        return ["package-lock.json: not JSON"]
    out = []
    if lock.get("lockfileVersion") != 3:
        out.append(f"package-lock.json: lockfileVersion {lock.get('lockfileVersion')!r}, not 3")
    entries = {p: e for p, e in (lock.get("packages") or {}).items() if p}
    if not entries:
        out.append("package-lock.json: no package entry")
    for path, e in entries.items():
        if not INTEGRITY.fullmatch(e.get("integrity") or ""):
            out.append(f"package-lock.json: {path} carries no sha512 integrity")
        if not (e.get("resolved") or "").startswith(REGISTRY):
            out.append(f"package-lock.json: {path} is not resolved from the registry")
    return out


def manifest_findings(text):
    """package.json: exact versions, and nothing a root install would run."""
    try:
        doc = json.loads(text)
    except ValueError:
        return ["package.json: not JSON"]
    out = []
    deps = doc.get("dependencies") or {}
    if not deps:
        out.append("package.json: no dependency")
    for name, spec in deps.items():
        if not EXACT.fullmatch(str(spec)):
            out.append(f"package.json: {name} at {spec!r}, not an exact version")
    for key in ("scripts", "devDependencies", "optionalDependencies", "peerDependencies", "bundleDependencies"):
        if doc.get(key):
            out.append(f"package.json: carries {key}")
    return out


def workflow_findings(text, name):
    """A workflow's package-manager commands: `npm ci --ignore-scripts`, and nothing
    else. A comment line installs nothing; every other line is read whole."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in NPM.finditer(line):
            argv = SEP.split(m.group("rest"))[0].split()
            if m.group("tool") == "npm" and argv[:1] == ["ci"] and "--ignore-scripts" in argv[1:]:
                continue
            out.append(f"{name}:{n}: {m.group('tool')} {' '.join(argv)}: "
                       "only npm ci --ignore-scripts installs, from the lockfile")
    return out


def dockerfile_findings(text):
    """Dockerfile: every FROM names a digest."""
    out = []
    for n, line in enumerate(text.replace("\\\n", " ").splitlines(), 1):
        m = re.match(r"\s*FROM\s+(\S+)", line, re.I)
        if m and not DIGEST.fullmatch(m.group(1)):
            out.append(f"Dockerfile:{n}: {m.group(1)} is not pinned by digest")
    return out


def verify(root):
    """The findings of one tree, sorted. A file that isn't there is VOID, not clean."""
    root = pathlib.Path(root)
    out = []
    try:
        for f, read in ((PINS / "package-lock.json", lock_findings),
                        (PINS / "package.json", manifest_findings),
                        (pathlib.Path("Dockerfile"), dockerfile_findings)):
            out += read((root / f).read_text(encoding="utf-8"))
        flows = sorted(p for p in (root / WORKFLOWS).glob("*.y*ml") if p.is_file())
        if not flows:
            raise OSError(f"no workflow under {WORKFLOWS}")
        for p in flows:
            out += workflow_findings(p.read_text(encoding="utf-8"), p.relative_to(root).as_posix())
    except (OSError, ValueError) as e:
        raise Void(str(e)) from e
    return sorted(out)


def selftest():
    rc = 0

    def check(ok, label):
        nonlocal rc
        if not ok:
            print(f"FAIL {label}", file=sys.stderr)
            rc = 1

    h1, h2 = "sha512-" + "A" * 86 + "==", "sha512-" + "B" * 86 + "=="
    digest = "@sha256:" + "a" * 64
    one = {"version": "1.2.3", "resolved": REGISTRY + "one/-/one-1.2.3.tgz", "integrity": h1}
    manifest = {"name": "pins-selftest", "private": True, "dependencies": {"one": "1.2.3", "@two/three": "0.166.0"}}
    lock = {"name": "pins-selftest", "lockfileVersion": 3, "packages": {
        "": {"name": "pins-selftest", "dependencies": manifest["dependencies"]},
        "node_modules/one": one,
        "node_modules/@two/three": {"version": "0.166.0", "resolved": REGISTRY + "@two/three/-/three-0.166.0.tgz",
                                    "integrity": h2}}}
    flow = ("jobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: |\n"
            "          sudo apt-get install -y -qq bubblewrap\n"
            "          npm ci --ignore-scripts --no-fund --no-audit\n"
            "          # a comment may say npm install; it installs nothing\n"
            "      - run: cd x && npm ci --ignore-scripts && node -v\n"
            "      - run: echo \"${{ github.sha }} npm_config_cache=/x\"\n")
    docker = "FROM ubuntu:24.04" + digest + "\n\nRUN apt-get update -qq\n"
    flow_b = WORKFLOWS / "b.yml"
    flow_p, lock_p, manifest_p, docker_p = WORKFLOWS / "ci.yml", PINS / "package-lock.json", PINS / "package.json", pathlib.Path("Dockerfile")
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        good = {}

        def tree(over=None):
            """The pinned fixture, with the named files replaced."""
            for f in root.rglob("*"):
                if f.is_file():
                    f.unlink()
            for f, text in {**good, **(over or {})}.items():
                p = root / f
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            return root

        good.update({manifest_p: json.dumps(manifest), lock_p: json.dumps(lock), flow_p: flow, docker_p: docker})
        check(verify(tree()) == [], "a tree pinned by hash has no finding")

        def bad_one(**e):
            return json.dumps({**lock, "packages": {**lock["packages"], "node_modules/one": {**one, **e}}})

        def bad_dep(spec):
            return json.dumps({**manifest, "dependencies": {**manifest["dependencies"], "one": spec}})

        def ran(cmd):
            return {flow_p: flow + "      - run: " + cmd + "\n"}

        only = ": only npm ci --ignore-scripts installs, from the lockfile"
        at = ".github/workflows/ci.yml:11: "
        # one plant per guard, each naming its file
        for label, over, want in (
                ("npm install by version", ran("sudo npm install -g one@1.2.3"), at + "npm install -g one@1.2.3" + only),
                ("npm ci that runs scripts", ran("npm ci --no-fund"), at + "npm ci --no-fund" + only),
                ("npx", ran("npx one"), at + "npx one" + only),
                ("yarn", ran("yarn add one"), at + "yarn add one" + only),
                ("npm i", ran("npm i --ignore-scripts"), at + "npm i --ignore-scripts" + only),
                ("ignore-scripts=false", ran("npm ci --ignore-scripts=false"), at + "npm ci --ignore-scripts=false" + only),
                ("a path to npm", ran("/usr/bin/npm install one"), at + "npm install one" + only),
                ("a second workflow", {flow_b: "jobs:\n  b:\n    steps:\n      - run: npm install one\n"},
                 ".github/workflows/b.yml:4: npm install one" + only),
                ("an entry with no hash", {lock_p: bad_one(integrity=None)},
                 "package-lock.json: node_modules/one carries no sha512 integrity"),
                ("an entry with a sha1", {lock_p: bad_one(integrity="sha1-abc")},
                 "package-lock.json: node_modules/one carries no sha512 integrity"),
                ("an entry with a short hash", {lock_p: bad_one(integrity="sha512-abc")},
                 "package-lock.json: node_modules/one carries no sha512 integrity"),
                ("an entry from elsewhere", {lock_p: bad_one(resolved="https://evil.example.org/one.tgz")},
                 "package-lock.json: node_modules/one is not resolved from the registry"),
                ("an entry from a git URL", {lock_p: bad_one(resolved="git+ssh://git@example.org/one.git")},
                 "package-lock.json: node_modules/one is not resolved from the registry"),
                ("an older lockfile", {lock_p: json.dumps({**lock, "lockfileVersion": 2})},
                 "package-lock.json: lockfileVersion 2, not 3"),
                ("a lockfile with no entry", {lock_p: json.dumps({**lock, "packages": {"": lock["packages"][""]}})},
                 "package-lock.json: no package entry"),
                ("a manifest with no dependency", {manifest_p: json.dumps({**manifest, "dependencies": {}})},
                 "package.json: no dependency"),
                ("a range", {manifest_p: bad_dep("^1.2.3")}, "package.json: one at '^1.2.3', not an exact version"),
                ("a tag", {manifest_p: bad_dep("latest")}, "package.json: one at 'latest', not an exact version"),
                ("a root script", {manifest_p: json.dumps({**manifest, "scripts": {"postinstall": "x"}})},
                 "package.json: carries scripts"),
                ("a dev dependency", {manifest_p: json.dumps({**manifest, "devDependencies": {"one": "1.0.0"}})},
                 "package.json: carries devDependencies"),
                ("FROM by tag", {docker_p: docker.replace(digest, "")}, "Dockerfile:1: ubuntu:24.04 is not pinned by digest"),
                ("FROM a short digest", {docker_p: docker.replace("a" * 64, "a" * 63)},
                 "Dockerfile:1: ubuntu:24.04@sha256:" + "a" * 63 + " is not pinned by digest"),
                ("a second FROM", {docker_p: docker + "FROM alpine:3\n"}, "Dockerfile:4: alpine:3 is not pinned by digest")):
            hits = verify(tree(over))
            check(any(h.startswith(want) for h in hits), f"{label}: {hits}")
        check(verify(tree({docker_p: "FROM ubuntu@sha256:" + "0" * 64 + "\n"})) == [], "a digest with no tag rides")
        check(verify(tree({flow_p: flow, flow_b: "jobs: {}\n"})) == [], "a workflow with no npm command rides")
        check(verify(tree({lock_p: "{"}))[0] == "package-lock.json: not JSON", "a lockfile that isn't JSON is a finding")
        # A file that isn't there is VOID, never a clean tree
        for missing in (manifest_p, lock_p, flow_p, docker_p):
            t = tree()
            (t / missing).unlink()
            try:
                verify(t)
                check(False, f"no {missing.name} is VOID")
            except Void:
                pass
        try:
            verify(root / "nowhere")
            check(False, "no tree at all is VOID")
        except Void:
            pass
        # The CLI: rc 1 with each finding named, rc 0 when pinned, rc 2 on a missing tree
        me = pathlib.Path(__file__).resolve()
        def cli(*a):
            return subprocess.run([sys.executable, "-I", str(me), *a], capture_output=True, text=True)

        r = cli("--root", str(tree({docker_p: "FROM ubuntu:24.04\n"})))
        check(r.returncode == 1 and r.stdout.splitlines()[:1] == ["HIT Dockerfile:1: ubuntu:24.04 is not pinned by digest"]
              and "hits=1" in r.stdout, "CLI names the finding and counts it")
        r = cli("--root", str(tree()))
        check(r.returncode == 0 and "hits=0" in r.stdout, "CLI clean is rc 0")
        r = cli("--root", "")
        check(r.returncode == 2 and "VOID" in r.stderr, "CLI empty --root is rc 2")
        r = cli("--root", str(root / "nowhere"))
        check(r.returncode == 2 and "VOID" in r.stderr, "CLI missing --root is rc 2")
    if rc == 0:
        print("selftest: OK (lock by sha512 from the registry, exact versions, no script, "
              "npm ci --ignore-scripts only, FROM by digest, VOID)")
    return rc


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--root", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.root == "":
        print("verify-ci-pins: VOID -- empty --root", file=sys.stderr)
        return 2
    repo = pathlib.Path(__file__).resolve().parent.parent
    try:
        hits = verify(pathlib.Path(a.root).resolve() if a.root else repo)
    except Void as e:
        print(f"verify-ci-pins: VOID -- {e}", file=sys.stderr)
        return 2
    for where in hits:
        print(f"HIT {where}")
    print(f"hits={len(hits)}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
