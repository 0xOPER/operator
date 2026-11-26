#!/usr/bin/env python3
"""fake-container -- the container runtime's protocol, for the room.

The cleanroom hides the container daemon and bwrap cannot nest in the room on
every host, so bin/environment.py's room selftest drives this shape of the
protocol instead: `image inspect`, `run -d`, `inspect --format`, `logs`, `kill`
and `rm -f`. It records the argv it was given, runs the command with NO
isolation at all, and answers from its records. It isolates nothing and
enforces nothing: a pass here proves the engine built the right argv, never
that a container held. bin/environment.py --first-level proves the real daemon.

records: $FAKE_CONTAINER_DIR (the caller names it; without it nothing runs)
special command text: __fake_oom__ marks the run as killed by its memory limit
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

ZERO_DIGEST = "0" * 64


def rec(name, ext):
    return os.path.join(os.environ["FAKE_CONTAINER_DIR"], name + ext)


def out(*a, **kw):
    print(*a, **kw)


def parse_run(argv):
    d = {"mounts": [], "env": {}, "tmpfs": [], "devices": [], "log_opt": [], "gpus": None}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            d["image"], d["cmd"] = argv[i + 1], argv[i + 2:]
            return d
        if a == "-d":
            d["detach"] = True
        elif a in ("-v",):
            src, dst, mode = argv[i + 1].rsplit(":", 2)
            d["mounts"].append([src, dst, mode])
            i += 1
        elif a.startswith("-e"):
            if a == "-e":
                k, _, v = argv[i + 1].partition("=")
                i += 1
            else:
                k, _, v = a[2:].partition("=")
            d["env"][k] = v
        elif a in ("--tmpfs",):
            d["tmpfs"].append(argv[i + 1])
            i += 1
        elif a in ("--log-opt",):
            d["log_opt"].append(argv[i + 1])
            i += 1
        elif a in ("--device",):
            d["devices"].append(argv[i + 1])
            i += 1
        elif a in ("--name", "--label", "--network", "--user", "--memory", "--memory-swap",
                   "--cpus", "--pids-limit", "--log-driver", "--cap-drop", "--security-opt",
                   "--workdir", "-w"):
            d[a] = argv[i + 1]
            i += 1
        elif a in ("--read-only",):
            d["--read-only"] = True
        elif a == "--gpus":
            d["gpus"] = argv[i + 1]
            i += 1
        else:
            out(f"fake-container: unknown flag {a}", file=sys.stderr)
            sys.exit(125)
        i += 1
    out("fake-container: no command after --", file=sys.stderr)
    sys.exit(125)


def host_cwd(d):
    """The directory the command runs in: the source of the bind its -w names."""
    for src, dst, _ in d["mounts"]:
        if dst == d.get("-w", "/work"):
            return src
    return tempfile.gettempdir()


def main(argv):
    if len(argv) < 2 or not os.environ.get("FAKE_CONTAINER_DIR"):
        out("fake-container: FAKE_CONTAINER_DIR names where I keep my records", file=sys.stderr)
        return 2
    if argv[1] == "image" and len(argv) >= 6 and argv[2] == "inspect":
        if argv[-1].endswith(ZERO_DIGEST):
            out(f"Error response from daemon: No such image: {argv[-1]}", file=sys.stderr)
            return 1
        out("sha256:" + argv[-1].rsplit(":", 1)[-1])
        return 0
    if argv[1] == "run":
        d = parse_run(argv[2:])
        name = d["--name"]
        with open(rec(name, ".argv.json"), "w") as f:
            json.dump(d, f, sort_keys=True)
        env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", **d["env"]}
        rcf, oom = rec(name, ".rc"), rec(name, ".oom")
        # a shell stays behind the command to write its exit code down
        wrap = '"$@"; r=$?; echo "$r" > "$RC"; exit "$r"'
        with open(rec(name, ".out"), "wb") as of:
            p = subprocess.Popen(["/bin/sh", "-c", wrap, "fake", *d["cmd"]], cwd=host_cwd(d),
                                 env=dict(env, RC=rcf), stdin=subprocess.DEVNULL,
                                 stdout=of, stderr=subprocess.STDOUT, start_new_session=True)
        with open(rec(name, ".pid"), "w") as f:
            f.write(str(p.pid))
        if any("__fake_oom__" in c for c in d["cmd"]):
            open(oom, "w").close()
        time.sleep(0.3)
        out("fake-" + name)
        return 0
    name = argv[-1]   # inspect, logs, kill and rm all end with the container's name
    if argv[1] == "inspect":
        if not os.path.exists(rec(name, ".argv.json")):
            out("Error: No such object", file=sys.stderr)
            return 1
        if os.path.exists(rec(name, ".rc")):
            with open(rec(name, ".rc")) as f:
                rc, status = f.read().strip() or "0", "exited"
        else:
            rc, status = "0", "running"
        oom = "true" if os.path.exists(rec(name, ".oom")) else "false"
        out(argv[argv.index("--format") + 1]
            .replace("{{.State.Status}}", status)
            .replace("{{.State.ExitCode}}", rc)
            .replace("{{.State.OOMKilled}}", oom))
        return 0
    if argv[1] == "logs":
        if os.path.exists(rec(name, ".out")):
            with open(rec(name, ".out"), "rb") as f:
                sys.stdout.buffer.write(f.read())
        return 0
    if argv[1] == "kill":
        try:
            with open(rec(name, ".pid")) as f:
                os.killpg(int(f.read()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
        if not os.path.exists(rec(name, ".rc")):
            with open(rec(name, ".rc"), "w") as f:
                f.write("137")
        out(name)
        return 0
    if argv[1] == "rm":
        keep = (".argv.json",) if os.environ.get("FAKE_NO_RM") == "1" else ()  # a selftest reads the argv back
        for ext in (e for e in (".argv.json", ".out", ".rc", ".oom", ".pid") if e not in keep):
            try:
                os.unlink(rec(name, ext))
            except OSError:
                pass
        return 0
    out(f"fake-container: unknown verb {argv[1:]}", file=sys.stderr)
    return 125


if __name__ == "__main__":
    sys.exit(main(sys.argv))
