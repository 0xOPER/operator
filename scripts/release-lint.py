#!/usr/bin/env python3
"""release-lint -- refuse a tree that carries private names or credential-shaped files.

A git tree is judged by what its HEAD ships, and the run names that SHA. Anything else
is judged file by file. Each file's name and bytes are scanned, and a binary is refused.
Tier A rules ship in test/lint/tier-a.tsv. Tier B is a private denylist kept outside the
repo and passed with --tier-b. A rule finds only what it names, so a person still reads
what ships.

A rule file holds rows of: name TAB regex TAB sample, with the sample reversed so the
file itself holds no live hit. A content hit prints rule, path and line, never the text,
because CI logs may be read by others. A name hit prints the path, so it carries what
matched. Paths on keep-list.private are skipped, and the run says how many. Tier A skips
its own rule file, which therefore can't hold comments.

usage:
  release-lint.py [--root DIR] [--tier-b FILE]
  release-lint.py --selftest [--tier-b FILE]
exit: 0 clean, 1 hits, 2 a rule file is missing, empty, short or broken
"""
import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

TIER_A_MIN = 11
TIER_B_MIN = 17
TIER_A = "test/lint/tier-a.tsv"
PRIVATE_LIST = "keep-list.private"

# What a hook hands its children: its own repository. A git call that means some
# other repository (the scratch one the selftest builds, or the tree the git mode
# reads) must not inherit it: under an absolute GIT_DIR, `git -C elsewhere init`
# re-initialises the caller's repository instead, and turns it bare.
GIT_DISCOVERY = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
                 "GIT_CEILING_DIRECTORIES", "GIT_PREFIX", "GIT_IMPLICIT_WORK_TREE")


def git_env():
    """The environment for a git call that must find its repository by its
    working directory, and nowhere else."""
    return {k: v for k, v in os.environ.items() if k not in GIT_DISCOVERY}

CREDENTIAL_NAME = re.compile(
    r"(?:^|/)\.(?:ssh|aws|kube|docker|gnupg|claude|codex)/|(?:^|/)\.config/gh/"
    r"|(?:^|/)(?:[^/]*_(?:rsa|dsa|ecdsa|ed25519)[^/]*|\.env(?:\..+)?|[^/]+\.env|env\.(?:local|prod\w*|staging|dev\w*|test)|\.envrc|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf|\.dockercfg|\.vault-token"
    r"|\.git-credentials|\.htpasswd|authorized_keys|known_hosts|allowed_signers|\.\w*_history|wg\d*\.conf"
    r"|auth\.json|hosts\.yml|\.claude\.json|storage_state\.json|cookies\.txt|[^/]*credentials(?:\.\w+)*|[^/]*client_secret[^/]*|service[-_]account[^/]*"
    r"|\.?(?:\w+[-_])?(?:token|api_?key)(?:\.\w+)?|(?:[\w-]+[-_])?secrets?(?:\.\w+)?"
    r"|[^/]*\.(?:pem|key|crt|cer|p12|pfx|p8|asc|keystore|kdbx|enc|gpg|age|ppk|ovpn|jks|tfstate|tfvars|har|db|sqlite3?)(?:[-.]\w+)?|gh[pousr]_[^/]*)$", re.I)


class Void(Exception):
    pass


def load_rules(path, minimum, tier):
    try:
        lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise Void(f"tier {tier} rules unreadable: {path}: {e}") from e
    rules = []
    for n, line in enumerate(lines, 1):
        if tier == "A" and line.startswith("#"):
            raise Void(f"tier A {path}:{n}: it's exempt from tier A, so it can't hold comments")
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3 or not all(parts):
            raise Void(f"tier {tier} {path}:{n}: want name, regex, sample")
        try:
            # re.ASCII: bytes above 127 decode to latin-1 letters, and \b must not treat them as word characters.
            rx = re.compile(parts[1], re.ASCII)
        except re.error as e:
            raise Void(f"tier {tier} {path}:{n}: bad regex: {e}") from e
        if not rx.search(parts[2][::-1]):
            raise Void(f"tier {tier} {path}:{n}: {parts[0]} doesn't match its own sample")
        rules.append((parts[0], rx, parts[2][::-1]))
    if len(rules) < minimum:
        raise Void(f"tier {tier} has {len(rules)} rules, the pinned minimum is {minimum}")
    return rules


def tree_files(root):
    names = [p.relative_to(root).as_posix() for p in pathlib.Path(root).rglob("*")
             if p.is_file() or p.is_symlink()]
    skip = set()
    private = pathlib.Path(root, PRIVATE_LIST)
    if private.is_file():
        skip = set(private.read_text(encoding="utf-8").splitlines()) | {PRIVATE_LIST}
    return [n for n in names if n not in skip]


def scan(root, tiers):
    """Return sorted hits as (rule, path, line). tiers is [(tier-name, rules)]."""
    hits = set()
    for name in tree_files(root):
        if CREDENTIAL_NAME.search(name):
            hits.add(("credential-file", name, 0))
        p = pathlib.Path(root, name)
        # A link's target ships as its blob, so it's scanned as the link's bytes.
        raw = os.readlink(p).encode() if p.is_symlink() else p.read_bytes() if p.is_file() else b""
        try:
            raw.decode("utf-8")
            if b"\0" in raw:
                hits.add(("binary-file", name, 0))
        except UnicodeDecodeError:
            hits.add(("binary-file", name, 0))
        # Binary stays searchable: latin-1 maps every byte, and the rules are ASCII.
        data = raw.decode("latin-1")
        for tier, rules in tiers:
            for rule, rx, _ in rules:
                if rx.search(name):
                    hits.add((rule, name, 0))
                if tier == "A" and name == TIER_A:
                    continue  # the rules themselves; tier B still reads this file
                for m in rx.finditer(data):
                    hits.add((rule, name, data.count("\n", 0, m.start()) + 1))
    return sorted(hits)


def selftest(tiers):
    rc = 0

    def check(ok, label):
        nonlocal rc
        if not ok:
            print(f"FAIL {label}", file=sys.stderr)
            rc = 1

    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        (root / "clean.txt").write_text("nothing to see\n")
        check(scan(root, tiers) == [], "clean tree has no hits")
        for tier, rules in tiers:
            for rule, _, sample in rules:
                for label, name, body in (
                        ("text", "plant.txt", sample.encode() + b"\n"),
                        ("binary", "plant.bin", b"\x00\xff" + sample.encode() + b"\x00\xfe")):
                    (root / name).write_bytes(body)
                    check(any(h[0] == rule for h in scan(root, tiers)), f"{tier}/{rule} in {label}")
                    (root / name).unlink()
                if "/" not in sample:
                    (root / sample).write_text("clean\n")
                    check(any(h[0] == rule and h[2] == 0 for h in scan(root, tiers)),
                          f"{tier}/{rule} in a file name")
                    (root / sample).unlink()
        for bad in ("id_rsa", "id_ed25519", "sub/dir/id_rsa", "ID_RSA", "x.pem", "x.key", ".env", ".env.local", "y.enc", "credentials",
                    "credentials.json", ".netrc", ".npmrc", ".pypirc", "ghs_x", "acme_prod_ed25519", ".credentials.json", "client_secret.json", "prod.env",
                    ".pgpass", ".aws/config", ".kube/config", ".docker/config.json", "credentials.json.bak", ".vault-token", "token.txt", "auth.json", "x.pem.bak",
                    "env" + ".local", "x.crt", "x.cer"):
            (root / bad).parent.mkdir(parents=True, exist_ok=True)
            (root / bad).write_text("clean\n")
            check(any(h[0] == "credential-file" and h[1] == bad for h in scan(root, tiers)), f"credential file {bad}")
            (root / bad).unlink()
        shutil.rmtree(root / "sub")
        # Each shape a rule's sample doesn't show, reversed here for the same reason as the samples
        for want, probe in (("home-path", "asu/ecila/aidem/"), ("home-path", "asr_di/hss./toor/"), ("home-path", "atad/ppa/vrs/"), ("home-path", "ved\\ecila\\sresU\\:C"),
                            ("email", "moc.buhtig.ylperon.sresu@ecila"), ("real-hostname", "lp.tneilc.ipa"), ("real-hostname", "ua.moc.tneilc"), ("real-hostname", "noino.tneilc"),
                            ("url-host", "oper-etavirp/gro-tneilc/moc.buhtig"), ("url-host", "x/niam/oper-etavirp/gro-tneilc/moc.tnetnocresubuhtig.war")):
            (root / "plant.txt").write_text(probe[::-1] + "\n")
            check(any(h[0] == want for h in scan(root, tiers[:1])), f"{want} shape {probe}")
            (root / "plant.txt").unlink()
        for quiet in ('"$d/root/programs/fx"', "x@example.com", "6432677+HashedViking@users.noreply.github.com", "351411109+0xOPER@users.noreply.github.com", "bin/tool.sh and test/run.py", "src/media/logo.png"):
            (root / "plant.txt").write_text(quiet + "\n")
            check(not scan(root, tiers[:1]), f"quiet on {quiet}")
            (root / "plant.txt").unlink()
        rule, _, sample = tiers[0][1][0]
        word = next(r for r in tiers[0][1] if "/" not in r[2])
        # Deep in a hidden directory, past line 1 and past 64 KB
        deep = root / "a" / ".b" / "deep.txt"
        deep.parent.mkdir(parents=True)
        deep.write_bytes(b"x\n" * 40000 + sample.encode() + b"\n")
        check((rule, "a/.b/deep.txt", 40001) in scan(root, tiers), "a hit deep in the tree, with its line number")
        shutil.rmtree(root / "a")
        # A directory name, and a link target
        (root / word[2]).mkdir()
        (root / word[2] / "f.txt").write_text("clean\n")
        check(any(h[0] == word[0] and h[2] == 0 for h in scan(root, tiers)), "a directory name")
        shutil.rmtree(root / word[2])
        os.symlink(word[2], root / "link")
        check(any(h[0] == word[0] and h[1] == "link" for h in scan(root, tiers)), "a link target")
        (root / "link").unlink()
        # The tier-A file is exempt from tier A only, and only that path
        (root / TIER_A).parent.mkdir(parents=True)
        (root / TIER_A).write_text(sample + "\n")
        check(scan(root, tiers[:1]) == [], "tier A skips its own file")
        check(any(h[1] == TIER_A for h in scan(root, [("B", tiers[0][1])])), "tier B reads the tier-A file")
        (root / TIER_A).rename(root / "other.tsv")
        check(any(h[1] == "other.tsv" for h in scan(root, tiers[:1])), "only that path is exempt")
        (root / "other.tsv").unlink()
        shutil.rmtree(root / "test")
        # UTF-16 and gzip don't get a pass
        (root / "w.txt").write_bytes(word[2].encode("utf-16"))
        check(any(h[0] == "binary-file" for h in scan(root, tiers)), "UTF-16 is flagged")
        (root / "w.txt").unlink()
        # Either sign of a binary is enough: a NUL in valid UTF-8, or bytes that aren't UTF-8.
        for label, raw in (("a NUL", b"a\0b\n"), ("bad UTF-8", b"a\xffb\n")):
            (root / "w.bin").write_bytes(raw)
            check(any(h[0] == "binary-file" for h in scan(root, tiers)), f"{label} is flagged")
            (root / "w.bin").unlink()
        check(scan(root, tiers) == [], "tree clean again after plants")
        # A hit must never echo the matched text.
        (root / "plant.txt").write_text(tiers[0][1][0][2] + "\n")
        check(tiers[0][1][0][2] not in "\n".join(map(str, scan(root, tiers))), "hit doesn't echo the match")
        (root / "plant.txt").unlink()
        # The private list skips only what it names.
        (root / "keep-list.private").write_text("private.txt\n")
        sample = tiers[0][1][0][2]
        (root / "private.txt").write_text(sample + "\n")
        check(scan(root, tiers) == [], "paths on the private list are skipped")
        (root / "other.txt").write_text(sample + "\n")
        check([h[1] for h in scan(root, tiers)] == ["other.txt"], "only listed paths are skipped")
        (root / "other.txt").unlink()
        (root / "private.txt.bak").write_text(sample + "\n")
        check([h[1] for h in scan(root, tiers)] == ["private.txt.bak"], "the private list matches whole paths")
        (root / "private.txt.bak").unlink()
        (root / "private.txt").unlink()
        (root / "keep-list.private").unlink()
        # The CLI: rc 1 and no echo on a hit, rc 0 clean, rc 2 on a missing tier B
        me = pathlib.Path(__file__).resolve()
        sample = tiers[0][1][0][2]
        (root / "other.txt").write_text(sample + "\n")
        r = subprocess.run([sys.executable, "-I", str(me), "--root", str(root)], capture_output=True, text=True)
        check(r.returncode == 1 and "HIT" in r.stdout and "other.txt" in r.stdout and sample not in r.stdout, "CLI hit is rc 1 with no echo")
        (root / "other.txt").unlink()
        r = subprocess.run([sys.executable, "-I", str(me), "--root", str(root)], capture_output=True, text=True)
        check(r.returncode == 0 and "hits=0" in r.stdout, "CLI clean is rc 0")
        r = subprocess.run([sys.executable, "-I", str(me), "--root", str(root), "--tier-b", str(root / "none.tsv")],
                           capture_output=True, text=True)
        check(r.returncode == 2 and "unreadable" in r.stderr, "CLI missing tier B is rc 2, and named")
        cli = lambda *a: subprocess.run([sys.executable, "-I", str(me), *a], capture_output=True, text=True)
        check(cli("--root", str(root), "--tier-b", "").returncode == 2, "CLI empty --tier-b is rc 2")
        check(cli("--root", "").returncode == 2, "CLI empty --root is rc 2")
        check(cli("--root", str(root / "none")).returncode == 2, "CLI missing --root is rc 2")
        check(len(tiers[0][1]) == TIER_A_MIN, "tier A count is its pin")
        with tempfile.TemporaryDirectory() as e:
            tb = pathlib.Path(e, "b.tsv")
            tb.write_text("".join(f"r{i}\tplantb{i}\t{str(i)[::-1]}btnalp\n" for i in range(TIER_B_MIN)))
            (root / "other.txt").write_text("plantb0\n")
            r = cli("--root", str(root), "--tier-b", str(tb))
            check(r.returncode == 1 and f"rules_loaded tier=B {TIER_B_MIN}" in r.stdout, "CLI applies tier B")
            (root / "other.txt").unlink()
            tb.write_text("".join(f"r{i}\tplantb{i}\t{str(i)[::-1]}btnalp\n" for i in range(TIER_B_MIN - 1)))
            check(cli("--root", str(root), "--tier-b", str(tb)).returncode == 2, "CLI short tier B is rc 2")
            tb.write_text("")
            check(cli("--root", str(root), "--tier-b", str(tb)).returncode == 2, "CLI empty tier B is rc 2")
            # Git mode reads HEAD, not the working copy. The working copy lies by being clean.
            # A hook would hand this process its own repository as GIT_DIR: stand one up and
            # point the variable at it, so the scratch repository is proven to be its own.
            decoy = pathlib.Path(e, "decoy")
            decoy.mkdir()
            held = {k: os.environ.get(k) for k in GIT_DISCOVERY}
            subprocess.run(["git", "-C", str(decoy), "init", "-q"], capture_output=True, env=git_env())
            os.environ["GIT_DIR"] = str(decoy / ".git")
            try:
                g = pathlib.Path(e, "g")
                g.mkdir()
                (g / "leak.txt").write_text(sample + "\n")
                scratch = ["git", "-C", str(g), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
                           "-c", "commit.gpgsign=false"]
                for a in (("init", "-q"), ("add", "-A"), ("commit", "-qm", "x")):
                    subprocess.run([*scratch, *a], capture_output=True, env=git_env())
                own = subprocess.run(["git", "-C", str(g), "log", "--format=%s"], capture_output=True, text=True, env=git_env())
                stray = subprocess.run(["git", "-C", str(decoy), "log", "--format=%s"], capture_output=True, text=True, env=git_env())
                check(own.returncode == 0 and own.stdout.splitlines() == ["x"] and stray.returncode != 0,
                      f"the scratch repository is its own under a caller's GIT_DIR: own={own.stdout!r} stray={stray.stdout!r}")
            finally:
                for k, v in held.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            (g / "leak.txt").write_text("clean\n")
            r = cli("--root", str(g))
            check(r.returncode == 1 and "HIT" in r.stdout and "head=" in r.stdout, "git mode reads HEAD and names it")
            (g / ".gitattributes").write_text("leak.txt export-ignore\n")
            for a in (("add", "-A"), ("commit", "-qm", "y")):
                subprocess.run(["git", "-C", str(g), "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", *a],
                               capture_output=True, env=git_env())
            check(cli("--root", str(g)).returncode == 2, "git mode refuses a tracked file the archive drops")
            # A tier A sample that holds a tier B name is refused at load.
            s0 = tiers[0][1][0][2]
            tb.write_text(f"r\t{re.escape(s0)}\t{s0[::-1]}\n" + "".join(f"r{i}\tplantb{i}\t{str(i)[::-1]}btnalp\n" for i in range(TIER_B_MIN)))
            check(cli("--root", str(root), "--tier-b", str(tb)).returncode == 2, "tier A samples can't hold tier B names")
            # A tree that can't be read is VOID, not a hit.
            bad = root / "locked.txt"
            bad.write_text("clean\n")
            bad.chmod(0)
            check(cli("--root", str(root)).returncode == 2, "an unreadable file is rc 2")
            bad.chmod(0o644)
            bad.unlink()
        # A rule file that is missing, empty, short or broken is VOID.
        for label, text in (("empty", ""), ("short", "a\tx\tx\n"), ("broken", "a\t(\tx\nb\tx\tx\nc\tx\tx\n"), ("columns", "a\tx\nb\tx\tx\n"), ("empty column", "a\t\tx\nb\tx\tx\nc\tx\tx\n"), ("sample mismatch", "a\tx\tq\nb\tx\tx\nc\tx\tx\n")):
            p = pathlib.Path(d, "rules.tsv")
            p.write_text(text)
            try:
                load_rules(p, 2, "T")
                check(False, f"{label} rule file refused")
            except Void:
                pass
        # A comment could hide text in the one file tier A skips.
        p.write_text("# a comment\na\tx\tx\nb\tx\tx\n")
        load_rules(p, 2, "T")
        try:
            load_rules(p, 2, "A")
            check(False, "tier A refuses comments")
        except Void:
            pass
        try:
            load_rules(pathlib.Path(d, "missing.tsv"), 1, "T")
            check(False, "missing rule file refused")
        except Void:
            pass
    if rc == 0:
        n = sum(len(r) for _, r in tiers)
        print(f"selftest: OK ({n} rules, plants in text, binary and names, credential files, private list, VOID)")
    return rc


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--root", default=None)
    ap.add_argument("--tier-b", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    repo = pathlib.Path(__file__).resolve().parent.parent
    if a.root == "":
        print("release-lint: VOID -- empty --root", file=sys.stderr)
        return 2
    root = pathlib.Path(a.root).resolve() if a.root else repo
    try:
        tiers = [("A", load_rules(repo / TIER_A, TIER_A_MIN, "A"))]
        if a.tier_b is not None:
            tiers.append(("B", load_rules(a.tier_b, TIER_B_MIN, "B")))
    except Void as e:
        print(f"release-lint: VOID -- {e}", file=sys.stderr)
        return 2
    for tier, rules in tiers:
        print(f"rules_loaded tier={tier} {len(rules)}")
    # A rule's sample is the obvious place for a leak just found, and tier A skips its own file.
    if len(tiers) > 1:
        held = [n for n, _, s in tiers[0][1] for _, rx, _ in tiers[1][1] if rx.search(s)]
        if held:
            print(f"release-lint: VOID -- tier A samples hold tier B names: {held}", file=sys.stderr)
            return 2
    if a.selftest:
        return selftest(tiers)
    # A git tree is judged by what its HEAD ships, not by the working copy.
    with tempfile.TemporaryDirectory() as t:
        if (root / ".git").exists():
            sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, env=git_env())
            arc = subprocess.run(["git", "-C", str(root), "archive", sha.stdout.strip()], capture_output=True, env=git_env())
            if sha.returncode or arc.returncode or subprocess.run(["tar", "-x", "-C", t], input=arc.stdout).returncode:
                print(f"release-lint: VOID -- can't export HEAD of {root}", file=sys.stderr)
                return 2
            # An export-ignore line or a gitlink drops a tracked path from the archive.
            ls = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "-z", "--name-only", sha.stdout.strip()], capture_output=True, env=git_env())
            got = {x.relative_to(t).as_posix() for x in pathlib.Path(t).rglob("*") if x.is_file() or x.is_symlink()}
            if ls.returncode or set(filter(None, ls.stdout.decode(errors="surrogateescape").split("\0"))) != got:
                print("release-lint: VOID -- HEAD tracks paths the archive doesn't hold (export-ignore or a gitlink)", file=sys.stderr)
                return 2
            print(f"head={sha.stdout.strip()}")
            root = pathlib.Path(t)
        try:
            files = tree_files(root)
            if not files:
                print(f"release-lint: VOID -- nothing to scan in {root}", file=sys.stderr)
                return 2
            hits = scan(root, tiers)
        except (OSError, UnicodeDecodeError) as e:
            print(f"release-lint: VOID -- {e}", file=sys.stderr)
            return 2
        for rule, path, line in hits:
            print(f"HIT {rule} {path}" + (f":{line}" if line else ""))
        total = sum(1 for p in pathlib.Path(root).rglob("*") if p.is_file() or p.is_symlink())
        print(f"files={len(files)} skipped={total - len(files)} hits={len(hits)}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
