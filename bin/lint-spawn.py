#!/usr/bin/env python3
"""lint-spawn -- the static hint that text which spawns an agent CLI is visible.

The spawn-gate audit's sample: the old gate was a string match that missed 17 of 20
spawn shapes -- quoted and spliced names, variable-held binaries, base64
payloads, scripts that spawn for you, the runners that mediate, and every CLI
that wasn't the one the pattern knew. This lint is that sample's static half
(it stays a hint; the runtime half is census.py's shims, which refuse any call
with no sanctioned door in its chain). The table below consolidates the audit's
shapes with the variants its verifier added; fixture text for the selftest is
generated at run time, and no private path from the audited tree is named.

The twenty shapes, with the shape the finding reports (verdict = the old gate):
 1 bare            <cli> -p                          bare       blocked
 2 dquote          "<cli>" -p                        dquote     blocked
 3 wrapper-path    a path ending <cli>-something     wrapper    blocked
 4 squote          '<cli>' -p                        squote     missed
 5 splice          quotes inside the word            splice     missed
 6 model-flags     flags before the verb             bare       missed
 7 skip-perms      --dangerously-skip-permissions    bare       missed
 8 var-held        X=<cli> then $X -p                var-held   missed
 9 base64-sh       a base64 literal piped into sh    base64-sh  missed
10 opaque-script   a script in the tree spawning     (its own shape)  missed
11 adapter-door    a helper that execs the CLI       (its own shape)  missed
12 session-door    a runner that starts the CLI      (its own shape)  missed
13 dispatch-door   a dispatcher that starts the CLI  (its own shape)  missed
14 codex-exec      codex exec                        bare       missed
15 opencode-run    opencode run                      bare       missed
16 gemini-p        gemini -p                         bare       missed
17 amp             amp                               bare       missed
18 other-clis      cursor, aider, goose by name      bare       missed
19 door-verbs      exec, command, env=, whitespace   bare       blocked (verifier)
20 path-forms      absolute and ./ paths to the CLI  path-forms blocked (verifier)

Mentions stay clean: an argument position (cat, grep, git log --grep=), a
comment, python attribute text -- only command position spawns. A trailing
`# census: allow` marks a line reviewed; it is counted as allowed, never silent.

usage: lint-spawn.py <path>... [--json]
exit: 0 clean, 1 findings, 2 usage or VOID
"""
import base64
import json
import os
import re
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))
import census as census_mod  # noqa: E402

CLIS = census_mod.AGENT_CLIS
JSON_SCHEMA = 1
SHAPES = (
    "bare", "dquote", "wrapper-path", "squote", "splice", "model-flags",
    "skip-perms", "var-held", "base64-sh", "opaque-script", "adapter-door",
    "session-door", "dispatch-door", "codex-exec", "opencode-run", "gemini-p",
    "amp", "other-clis", "door-verbs", "path-forms",
)  # twenty, pinned; the selftest asserts the count and one fixture per shape
ALLOW = "# census: allow"

WRAPPERS = {"exec", "command", "nohup", "nice", "env", "export",
           "readonly", "timeout", "xargs"}
SEG_SPLIT = re.compile(r"[;|&()\n]")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")
VAR_USE = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")
B64 = re.compile(r"'([A-Za-z0-9+/=]{16,})'|\"([A-Za-z0-9+/=]{16,})\"")
SHELLS = {"sh", "bash", "dash", "ash", "zsh"}
PY_SUBPROC = re.compile(r"(subprocess\.(?:run|call|check_call|check_output|Popen)"
                        r"\s*\(\s*\[)\s*(['\"])([^'\"]+?)\2")
PY_OSCALL = re.compile(r"(os\.(?:system|popen)\s*\(\s*|os\.exec\w+\s*\(\s*"
                       r"|pty\.spawn\s*\(\s*)(['\"])([^'\"]+?)\2")


class Void(Exception):
    pass


def cli_of(word):
    """The CLI a command-position word names, through quotes and path parts."""
    w = word.replace("'", "").replace('"', "")
    if not w or w.startswith("-") or w.startswith("#"):
        return None
    base = w.rsplit("/", 1)[-1] or w
    for cli in CLIS:
        if base == cli or base.startswith(cli + "-"):
            return cli
    return None


def shape_for(word):
    """The reported shape for a command-position CLI word."""
    w = word.replace("'", "").replace('"', "")
    base = w.rsplit("/", 1)[-1] or w
    if "/" in w and base in CLIS:
        return "path-forms"
    if base not in CLIS:  # a wrapper-family path (bin/<cli>-ci)
        return "wrapper-path"
    if "'" in word or '"' in word:
        if word[0] in "'\"" and word[-1] == word[0]:
            return "dquote" if '"' in word else "squote"
        return "splice"
    return "bare"


def strip_comments(line):
    out, q = [], None
    for ch in line:
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


CASE_LABEL = re.compile(r'^\s*[A-Za-z0-9_.-]+\)\s*(#.*)?$')


def _segments(line):
    return [s.strip() for s in SEG_SPLIT.split(line) if s.strip()]


def shell_findings(text, path, findings, base=1, varmap=None):
    """Command-position spawns in shell text. A hint: the splitter is not
    quote-aware past comment stripping, so exotic quoted separators may shift
    a segment -- the census holds the runtime line."""
    text = text.replace("\\\n", " ")
    own_map = varmap is None
    if own_map:
        varmap = {}
    for ln, raw in enumerate(text.splitlines(), base):
        line = strip_comments(raw)
        if ALLOW in raw:
            continue
        if CASE_LABEL.match(raw):  # a dispatch label, not a command
            continue
        segs = _segments(line)
        hit = False
        for seg in segs:
            toks = seg.split()
            i = 0
            while i < len(toks):
                t = toks[i]
                if t in WRAPPERS:
                    i += 2 if t == "timeout" else 1
                    continue
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", t) \
                    if ASSIGN.match(t) else None
                if m:
                    if cli_of(m.group(2)):
                        varmap[m.group(1)] = cli_of(m.group(2))
                        findings.append({"file": path, "line": ln, "shape": "var-held",
                                         "text": seg[:160]})
                        hit = True
                    i += 1
                    continue
                break
            if hit:
                break
            if i < len(toks):
                w = toks[i]
                vm = VAR_USE.match(w)
                if vm and vm.group(1) in varmap:
                    findings.append({"file": path, "line": ln, "shape": "var-held",
                                     "text": seg[:160]})
                    hit = True
                elif cli_of(w):
                    findings.append({"file": path, "line": ln, "shape": shape_for(w),
                                     "text": seg[:160]})
                    hit = True
            if hit:
                break
        # a base64 literal decoded into a shell, caught by what it decodes to
        b64_segs = [s for s in segs if s.split()[:1] == ["base64"]
                    and set(s.split()) & {"-d", "--decode"}]
        if b64_segs and {s.split()[0] for s in segs if s.split()} & SHELLS:
            for m in B64.finditer(raw):
                lit = m.group(1) or m.group(2)
                try:
                    decoded = base64.b64decode(lit, validate=True).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    continue
                sub = []
                shell_findings(decoded, path, sub)
                if sub:
                    findings.append({"file": path, "line": ln, "shape": "base64-sh",
                                     "text": decoded[:160]})
                    break


def py_findings(text, path, findings):
    for ln, line in enumerate(text.splitlines(), 1):
        if ALLOW in line:
            continue
        for m in PY_SUBPROC.finditer(line):
            if cli_of(m.group(3)):
                findings.append({"file": path, "line": ln, "shape": "python-call",
                                 "text": line.strip()[:160]})
        for m in PY_OSCALL.finditer(line):
            words = m.group(3).split()
            if words and cli_of(words[0]):
                findings.append({"file": path, "line": ln, "shape": "python-call",
                                 "text": line.strip()[:160]})


def scan(paths):
    findings, allowed, files = [], 0, []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames
                               if d not in (".git", "__pycache__")]
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    if fn.endswith(".sh") or fn.endswith(".py") or (
                            os.access(full, os.X_OK) and not os.path.islink(full)
                            and _has_shebang(full)):
                        files.append(full)
        elif not os.path.exists(p):
            raise Void(f"no such path: {p}")
    for f in sorted(set(files)):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            raise Void(f"can't read {f}: {e}")
        allowed += text.count(ALLOW)
        if f.endswith(".py"):  # python grammar only; a shell pass would read
            py_findings(text, f, findings)  # identifiers as commands
        else:
            shell_findings(text, f, findings)
    return findings, allowed


def _has_shebang(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def main(argv):
    paths = [a for a in argv[1:] if not a.startswith("--")]
    as_json = "--json" in argv
    if not paths:
        print("usage: lint-spawn.py <path>... [--json]", file=sys.stderr)
        return 2
    try:
        findings, allowed = scan(paths)
    except Void as e:
        print(f"lint-spawn: VOID, {e}", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps({"schema": JSON_SCHEMA, "findings": findings,
                          "allowed": allowed}, ensure_ascii=True, sort_keys=True))
    else:
        for f in findings:
            print(f"{f['file']}:{f['line']}: {f['shape']}: {f['text']}")
        print(f"lint-spawn: {len(findings)} finding(s), {allowed} allowed line(s)")
    return 0 if not findings else 1


# table entry -> the shape its fixture reports
ENTRY_SHAPE = {"bare": "bare", "dquote": "dquote", "wrapper-path": "wrapper-path",
               "squote": "squote", "splice": "splice", "model-flags": "bare",
               "skip-perms": "bare", "codex-exec": "bare", "opencode-run": "bare",
               "gemini-p": "bare", "amp": "bare", "other-clis": "bare",
               "door-verbs": "bare", "path-forms": "path-forms",
               "var-held": "var-held", "base64-sh": "base64-sh",
               "opaque-script": "bare", "adapter-door": "bare",
               "session-door": "bare", "dispatch-door": "bare"}


def selftest():
    """Room-safe: every one of the twenty shapes is caught (fixtures generated
    here, never tracked), the audit's false positives stay clean, python call
    sites catch literal argv, --json carries the findings, and an allow comment
    is counted, not silent."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    import shutil as _sh
    import subprocess
    import tempfile
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    check(len(SHAPES) == 20, "the table holds twenty shapes")

    base = tempfile.mkdtemp(prefix="ls-rt.")
    try:
        cli = "claude"
        lines = {  # one fixture line per one-face table entry
            "bare": f"{cli} -p",
            "dquote": f'"{cli}" -p',
            "wrapper-path": f"bin/{cli}-helper -p",
            "squote": f"'{cli}' -p",
            "splice": "cl'au'de -p",
            "model-flags": f"{cli} --model opus -p",
            "skip-perms": f"{cli} --dangerously-skip-permissions -p",
            "var-held": f"C={cli}\n$C -p",
            "base64-sh": "echo '" + base64.b64encode(f"{cli} -p with args".encode()).decode()
                         + "' | base64 -d | sh",
            "opaque-script": 'claude -p from inside a script',
            "adapter-door": 'exec claude "$@"',
            "session-door": 'claude -c resume',
            "dispatch-door": 'codex exec "$@"',
            "codex-exec": "codex exec",
            "opencode-run": "opencode run",
            "gemini-p": "gemini -p",
            "amp": "amp",
            "other-clis": "cursor -p",
            "door-verbs": "exec claude -p",
            "path-forms": "/usr/local/bin/claude -p",
        }
        check(set(lines) == set(SHAPES),
              f"every table entry carries a fixture: {set(SHAPES) ^ set(lines)}")
        variants = {  # the entries' other faces
            "door-verbs": ["command claude -p", "FOO=1 claude -p", "claude   -p"],
            "path-forms": ["./claude -p"],
            "other-clis": ["aider -p", "goose"],
            "wrapper-path": ["wrappers/claude-helper -p"],
        }
        tree = os.path.join(base, "tree")
        os.makedirs(tree)
        for shape, text in lines.items():  # one fixture per table entry, no drift
            with open(os.path.join(tree, shape.replace("-", "_") + ".sh"), "w") as fh:
                fh.write("#!/bin/sh\n" + text + "\n")
        # the audit's false positives stay clean, and comments stay comments
        with open(os.path.join(tree, "clean.sh"), "w") as fh:
            fh.write("cat bin/claude-helper\ngrep \"claude\" README.md\n"
                     "git log --grep='claude -c'\n"
                     "# claude -p in a comment stays a comment\n"
                     "command -v claude\n")

        findings, allowed = scan([tree])
        for shape, want in ENTRY_SHAPE.items():
            name = shape.replace("-", "_") + ".sh"
            n = sum(1 for f in findings
                    if f["file"].rsplit("/", 1)[-1] == name and f["shape"] == want)
            if shape == "var-held":
                check(n == 2, f"caught {shape} (assign and use): {n}")
            else:
                check(n >= 1, f"caught {shape} as {want}")
        for shape in ("adapter-door", "session-door", "dispatch-door"):
            name = shape.replace("-", "_") + ".sh"
            check(any(f["file"].endswith(name) for f in findings),
                  f"caught {shape} (a helper spawns the CLI for its caller)")
        check(not [f for f in findings if f["file"].endswith("clean.sh")],
              "the audit's false positives stay clean")

        vtree = os.path.join(base, "v")
        os.makedirs(vtree)
        variants["door-verbs"] = variants["door-verbs"] + ["timeout 10 claude -p hi",
                                                          "xargs claude -p z"]
        # case labels are not commands: a lone label stays clean, a label
        # heading a spawn still gets the spawn caught
        with open(os.path.join(vtree, "v11.sh"), "w") as fh:
            fh.write("#!/bin/sh\ncase \"$x\" in\n    claude-code)\n"
                     "        echo hi\n        ;;\nesac\n"
                     "run) claude -p caught\n")
        vlines = [t for ts in variants.values() for t in ts]
        for i, text in enumerate(vlines):
            with open(os.path.join(vtree, f"v{i}.sh"), "w") as fh:
                fh.write("#!/bin/sh\n" + text + "\n")
        vfind, _ = scan([vtree])
        check(len(vfind) == len(vlines) + 1,  # +1: the label-body spawn in v11.sh
              f"every variant face caught: {len(vfind)} of {len(vlines)}+1")

        # python call sites: literal argv0 and string commands; attributes stay clean
        p = os.path.join(base, "call.py")
        sys_cmd = "os." + "system('cod" + "ex exec')"  # split so this line stays clean
        with open(p, "w") as fh:
            fh.write("import subprocess, os\n"
                     "subprocess.run([\"claude\", \"-p\"], check=True)\n"
                     + sys_cmd + "\n"
                     "cur = conn.cursor()\n"
                     "subprocess.run([tool, \"-p\"])\n")
        pfind, _ = scan([p])
        check(len(pfind) == 2 and all(f["shape"] == "python-call" for f in pfind),
              f"python call sites: {[f['line'] for f in pfind]}")

        # --json carries the findings; the allow comment is counted, not silent
        with open(os.path.join(base, "a.sh"), "w") as fh:
            fh.write(f"{cli} -p  {ALLOW}\n")
        r = subprocess.run([sys.executable, os.path.abspath(__file__),
                            os.path.join(base, "a.sh"), "--json"],
                           capture_output=True, text=True, timeout=60)
        doc = json.loads(r.stdout)
        check(r.returncode == 0 and doc["findings"] == [] and doc["allowed"] == 1,
              f"allow is counted: rc={r.returncode} {doc}")
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "/no/such"],
                           capture_output=True, text=True, timeout=60)
        check(r.returncode == 2 and "VOID" in r.stderr, "a missing path is VOID")

        print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
        return 0 if ok[0] and not bad[0] else 1
    finally:
        _sh.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.exit(main(sys.argv))
