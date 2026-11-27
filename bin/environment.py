#!/usr/bin/env python3
"""environment -- signed environments: where a program's work may run besides the jail.

A program declares its environments in charter.toml as [[environment.<name>]]
blocks (docs/charter.md): an image pinned by digest, the runtime, devices, host
mounts, the network, limits, the user and its writable scratch. The block sits
inside the signed closure like every other program file, so an edited
environment is an edited program: the arm ruling no longer verifies.

This tool is the only container client. A caller brings an environment name, a
command and a work directory; everything else comes from the signed spec: no
network, a read-only rootfs, every capability dropped, no new privileges, the
spec's user (never root, and the engine's own uid, so the files it writes stay
the engine's), memory, CPU, process and wall limits. The image is never pulled:
it must be present locally under exactly that digest. The arm ruling is
verified before every run.

Every run leaves a receipt in the hash-chained call log: environment, image,
argv hash, exit code, duration, runtime. A contract row with env = "<name>"
runs its check through the same door, with the pinned oracle and runner
configs mounted read-only over the export exactly as the jail binds them.

A seat with env = ["<name>"] gets the door inside its jail as a socket
(Door here, bin/lib/op-env.py there): the engine serves it, one request at a
time, grants and budget checked on this side. The turn's end is the run's end.

usage: environment.py validate <program-dir> [--json]
       environment.py run <program-dir> --env NAME [--work DIR] [--timeout S] [--json] -- <cmd...>
       environment.py --selftest | --first-level
env: OPERATOR_HOME, CALL_LOG_FILE, CONTRACT_REPO and CONTRACT_PIN when the arm
     ruling closes over a base commit, OPERATOR_CONTAINER_CLI (test seam: a
     fixture under test/ in the runtime's shape)
exit: 0 the command's own code, 1 refused or a finding, 2 usage or VOID,
      3 the call log is locked
"""
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bin"))

CHARTER = "charter.toml"
SCHEMA = 1
CHARTER_KEYS = ("schema", "name", "standing", "purse", "reach", "evidence",
                "reserved", "environment")
ENV_REQUIRED = ("image", "runtime", "user", "limits")
ENV_KEYS = {"image": str, "runtime": str, "devices": list, "mounts": list,
            "network": str, "rootfs": str, "writable": list, "user": str,
            "limits": dict}
LIMIT_KEYS = {"memory": str, "cpus": (int, float), "pids": int, "wall": int}
# podman follows a rootless-identity probe: its uid mapping is not the engine's
RUNTIMES = ("docker",)
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DIGEST_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._/-]{0,255}@)?sha256:([0-9a-f]{64})$")
SIZE_RE = re.compile(r"^[0-9]+[kmg]$")
STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
USER_RE = re.compile(r"^([1-9][0-9]{0,9}):([1-9][0-9]{0,9})$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
MOUNT_RE = re.compile(r"^(/[A-Za-z0-9._+/-]*):(ro|rw)$")
WRITABLE_RE = re.compile(r"^(/[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*):([0-9]+[kmg])$")
# the operator's vouch for a reach host: host=address:port (bin/reach.py reads it)
PIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*"
                    r")=((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$")
# a host path an environment may never mount: the roots of the host itself and
# the daemon's sockets. The engine's own tree and state join at validate time.
SYSTEM_PATHS = ("/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32",
                "/lib64", "/proc", "/root", "/run", "/sbin", "/sys", "/usr",
                "/var", "/var/lib", "/var/lib/containers", "/var/lib/docker",
                "/var/lib/podman", "/var/run", "/run/docker", "/run/podman",
                "/run/user", "/snap")
SYSTEM_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/var/run", "/var/lib/docker",
                   "/var/lib/containers", "/var/lib/podman", "/var/lib/kubelet")
SOCKETS = ("docker.sock", "podman.sock", "containerd.sock", "crio.sock",
           "containers.sock")
RESERVED = ("/work", "/tmp", "/w", "/prog", "/env", "/engine")  # the door's own container paths
LOG_CAP = 1024 * 1024     # the first bytes kept, as the jail's run_capped keeps them
LOG_MAX = "4m"            # the daemon's log rotation: a printing runaway costs disk, not the host
POLL = 0.25
KILL_GRACE = 30           # seconds a killed run gets to die before the door gives up on it
FAKE = os.path.join(ROOT, "test", "lib", "fake-container.py")
# the worker's door: the environment socket a jail may carry when its seat holds env grants
ENV_SOCK = "/op-envd.sock"        # the socket inside the jail
ENV_WORK = "/w/envwork"           # the seat's staged directory in the jail; /work inside the environment
ENV_CLIENT = "/engine/op-env.py"  # the jailed client (bin/lib/op-env.py), read-only
DOOR_OUT = 16 * 1024              # what one answer carries back to the jail
DOOR_IN = 512 * 1024              # the largest request the door reads
MAX_ARGS, MAX_ARG = 64, 4096


class Void(Exception):
    pass


class Refused(Exception):
    pass


class Finding(Exception):
    pass


class Locked(Exception):
    pass


def die(msg, code):
    print(f"environment: {msg}", file=sys.stderr)
    sys.exit(code)


def sh(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)


def short_dir():
    """Where an AF_UNIX socket may live: the shortest writable of /tmp and the
    temp dir. A socket path is capped at 108 bytes; an attempt's is not short."""
    return min((c for c in ("/tmp", tempfile.gettempdir())
                if os.path.isdir(c) and os.access(c, os.W_OK)), key=len)


def extra_roots():
    home = os.environ.get("OPERATOR_HOME")
    return (ROOT,) + ((os.path.realpath(home),) if home else ())


# --- the charter ------------------------------------------------------------------------


def charter(prog):
    """The parsed charter.toml, or None for a program that declares none (the
    degenerate charter: no reach, no environments)."""
    path = os.path.join(prog, CHARTER)
    if not os.path.lexists(path):
        return None
    if os.path.islink(path) or not os.path.isfile(path):
        raise Finding(f"{CHARTER} must be a regular file")
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise Finding(f"{CHARTER} doesn't parse: {e}")
    except OSError as e:
        raise Void(f"{CHARTER} can't be read: {e}")
    return doc


def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _intext(v):
    return isinstance(v, str) and bool(v) and "\x00" not in v and not any(ord(c) < 32 for c in v)


def _hosts(v):
    return isinstance(v, list) and all(isinstance(h, str) and HOST_RE.fullmatch(h) for h in v)


def charter_findings(doc):
    """Every finding of one charter; an empty list is a valid charter. The sections
    later milestones enforce (purse, reach, evidence, reserved) are shape-checked
    here and nothing more."""
    out = []
    if type(doc.get("schema")) is not int or doc["schema"] != SCHEMA:
        out.append(f"schema must be the integer {SCHEMA}, not {doc.get('schema')!r}")
    for k in doc:
        if k not in CHARTER_KEYS:
            out.append(f"unknown key {k!r}: the charter names {', '.join(CHARTER_KEYS)}")
    if not isinstance(doc.get("name"), str) or not ID_RE.fullmatch(doc["name"]):
        out.append(f"name must be [a-z0-9][a-z0-9._-]{{0,63}}, not {doc.get('name')!r}")
    sections = (("standing", ("not_after",)),
                ("purse", ("usd", "minutes", "context", "concurrency")),
                ("reach", ("profile", "declared_max", "declared_ttl", "allow", "deny", "pins")),
                ("evidence", ("min_mutation_kill",)),
                ("reserved", ("extra",)))
    body_of = {}
    for sec, keys in sections:
        if sec not in doc:
            continue
        body = doc[sec]
        if not isinstance(body, dict):
            out.append(f"[{sec}] must be a table")
            continue
        body_of[sec] = body
        for k in body:
            if k not in keys:
                out.append(f"[{sec}] takes {', '.join(keys)}, not {k!r}")
    standing, purse = body_of.get("standing", {}), body_of.get("purse", {})
    reach, evidence, reserved = body_of.get("reach", {}), body_of.get("evidence", {}), body_of.get("reserved", {})
    if "not_after" in standing and not (isinstance(standing["not_after"], str)
                                        and STAMP_RE.fullmatch(standing["not_after"])):
        out.append("[standing] not_after takes 2030-01-01T00:00:00Z, UTC")
    for k in ("usd", "minutes", "context"):
        if k in purse and not (_number(purse[k]) and purse[k] >= 0):
            out.append(f"[purse] {k} must be a non-negative number")
    if "concurrency" in purse and not (type(purse["concurrency"]) is int and purse["concurrency"] >= 1):
        out.append("[purse] concurrency must be an integer of at least 1")
    if "profile" in reach and reach["profile"] not in ("closed", "dev", "research"):
        out.append(f"[reach] profile is closed, dev or research, not {reach['profile']!r}")
    for k, low in (("declared_max", 0), ("declared_ttl", 1)):
        if k in reach and not (type(reach[k]) is int and reach[k] >= low):
            out.append(f"[reach] {k} must be an integer of at least {low}")
    for k in ("allow", "deny"):
        if k in reach and not _hosts(reach[k]):
            out.append(f"[reach] {k} must be a list of hosts")
    if "pins" in reach and not (isinstance(reach["pins"], list)
                                and all(pin_ok(p) for p in reach["pins"])):
        out.append("[reach] pins is a list of 'host=address:port' (an IPv4 address, a port below 65536)")
    if "min_mutation_kill" in evidence and not (
            _number(evidence["min_mutation_kill"]) and 0 <= evidence["min_mutation_kill"] <= 1):
        out.append("[evidence] min_mutation_kill is a share between 0 and 1")
    if "extra" in reserved and not (isinstance(reserved["extra"], list)
                                    and all(isinstance(x, str) and ID_RE.fullmatch(x)
                                            for x in reserved["extra"])):
        out.append("[reserved] extra must be a list of names, [a-z0-9][a-z0-9._-]{0,63}")
    out += environment_findings(doc)
    return out


def pin_ok(pin):
    """A charter pin is 'host=IPv4:port' with a real address and a real port."""
    m = isinstance(pin, str) and PIN_RE.fullmatch(pin)
    if not m:
        return False
    try:
        ipaddress.ip_address(m.group(5))
    except ValueError:
        return False
    return int(m.group(6)) <= 65535


def mount_refusal(host, roots=()):
    """Why an environment may not mount this host path, or None when it may."""
    p = os.path.normpath(host)
    if p != host or "//" in host:
        return f"{host!r}: write it as one clean absolute path"
    if p in SYSTEM_PATHS:
        return f"{host!r} is the host's own {p}: a spec mounts data, never the host"
    if p.rsplit("/", 1)[-1].endswith(".sock") or any(s in p for s in SOCKETS):
        return f"{host!r} is a container socket: the engine is the only container client"
    if p.startswith(SYSTEM_PREFIXES):
        return f"{host!r} is a system path: a spec mounts data, never the host"
    for root in roots:
        if p == root or p.startswith(root + "/"):
            return f"{host!r} is the engine's own tree or state"
    if p in RESERVED or p.startswith("/w/"):
        return f"{host!r} is a path the door uses inside the environment"
    return None


def environment_findings(doc):
    # TOML reads [[environment.<name>]] as environment = {name: [block, ...]}: one
    # block per environment, and a repeated header appends to the same name
    out = []
    envs = doc.get("environment", {})
    if not isinstance(envs, dict):
        return [f"[environment] holds one [[environment.<name>]] block per environment, "
                f"not {type(envs).__name__}"]
    for name, blocks in envs.items():
        w = f"environment {name!r}"
        if not ID_RE.fullmatch(name):
            out.append(f"environment names are [a-z0-9][a-z0-9._-]{{0,63}}, not {name!r}")
        if not isinstance(blocks, list) or not blocks or not all(isinstance(b, dict) for b in blocks):
            out.append(f"{w}: declare it as [[environment.{name}]]")
            continue
        if len(blocks) > 1:
            out.append(f"{w}: declared twice")
        spec = blocks[0]
        for k in spec:
            if k not in ENV_KEYS:
                out.append(f"{w}: unknown key {k!r}; the spec names {', '.join(sorted(ENV_KEYS))}")
        for k in ENV_REQUIRED:
            if k not in spec:
                out.append(f"{w}: {k} is required")
        if "image" in spec and not (isinstance(spec["image"], str) and DIGEST_RE.fullmatch(spec["image"])):
            out.append(f"{w}: image {spec['image']!r} must be pinned by digest: "
                       "`name@sha256:<64 hex>` or a local image id `sha256:<64 hex>`; "
                       "a tag moves, so it is refused")
        if "runtime" in spec and spec["runtime"] not in RUNTIMES:
            out.append(f"{w}: runtime is {' or '.join(RUNTIMES)}, not {spec['runtime']!r}"
                       + (" (podman follows a rootless-identity probe)"
                          if spec["runtime"] == "podman" else ""))
        if "devices" in spec:
            devs = spec["devices"]
            if not isinstance(devs, list) or not all(
                    isinstance(d, str) and (d == "gpu" or (d.startswith("/dev/") and ".." not in d
                                                           and _intext(d))) for d in devs):
                out.append(f"{w}: devices are 'gpu' or /dev paths, not {devs!r}")
        if "mounts" in spec:
            mounts = spec["mounts"]
            if not isinstance(mounts, list) or not all(isinstance(m, str) for m in mounts):
                out.append(f"{w}: mounts is a list of '/host/path:ro' or '/host/path:rw'")
            else:
                for m in mounts:
                    mt = MOUNT_RE.fullmatch(m)
                    if not mt:
                        out.append(f"{w}: mount {m!r} must be '/host/path:ro' or '/host/path:rw'")
                        continue
                    why = mount_refusal(mt.group(1), extra_roots())
                    if why:
                        out.append(f"{w}: mount {why}")
        if "network" in spec and spec["network"] != "none":
            out.append(f"{w}: network is 'none' in this build (reach is a later milestone), "
                       f"not {spec['network']!r}")
        if "rootfs" in spec and spec["rootfs"] != "ro":
            out.append(f"{w}: rootfs is 'ro'; scratch space is a writable tmpfs, not the rootfs")
        if "writable" in spec:
            wr = spec["writable"]
            if not isinstance(wr, list) or not all(isinstance(x, str) for x in wr):
                out.append(f"{w}: writable is a list of '/path:size'")
            else:
                for x in wr:
                    wt = WRITABLE_RE.fullmatch(x)
                    if not wt:
                        out.append(f"{w}: writable {x!r} must be '/path:size' with a size like 256m")
                    elif wt.group(1) in RESERVED or wt.group(1).startswith("/w/"):
                        out.append(f"{w}: writable {x!r} names a path the door uses; pick another")
        if "user" in spec and not (isinstance(spec["user"], str) and USER_RE.fullmatch(spec["user"])):
            out.append(f"{w}: user is 'uid:gid' with both above zero (never root), "
                       f"not {spec['user']!r}")
        if "limits" in spec:
            lim = spec["limits"]
            if not isinstance(lim, dict) or set(lim) != set(LIMIT_KEYS):
                out.append(f"{w}: limits names memory, cpus, pids and wall, all four")
            else:
                if not (isinstance(lim["memory"], str) and SIZE_RE.fullmatch(lim["memory"])):
                    out.append(f"{w}: limits.memory is a size like 512m or 4g")
                if not (_number(lim["cpus"]) and lim["cpus"] > 0):
                    out.append(f"{w}: limits.cpus is a positive number")
                if not (type(lim["pids"]) is int and lim["pids"] >= 1):
                    out.append(f"{w}: limits.pids is an integer of at least 1")
                if not (type(lim["wall"]) is int and lim["wall"] >= 1):
                    out.append(f"{w}: limits.wall is the ceiling of one run, in seconds")
    return out


def specs(prog):
    """name -> environment spec with its defaults filled. Finding names the first bad one."""
    doc = charter(prog)
    if doc is None:
        return {}
    bad = charter_findings(doc)
    if bad:
        raise Finding(f"{CHARTER}: {bad[0]}" + (f" (and {len(bad) - 1} more)" if len(bad) > 1 else ""))
    out = {}
    for name, blocks in doc.get("environment", {}).items():
        spec = blocks[0]
        out[name] = {**spec, "network": "none", "rootfs": "ro",
                     "devices": spec.get("devices", []), "mounts": spec.get("mounts", []),
                     "writable": spec.get("writable", [])}
    return out


def environment(prog, name):
    envs = specs(prog)
    if name not in envs:
        raise Refused(f"no environment {name!r} in {CHARTER}; declared here: "
                      f"{', '.join(sorted(envs)) or 'none'} (docs/charter.md)")
    return envs[name]


def require_signed(prog):
    """The arm ruling covers the program as it stands: an environment is signed
    with everything else in it, never on its own. Every run re-verifies it."""
    import ruling as ruling_mod
    newest = ruling_mod.newest(prog, "arm")
    if newest is None:
        raise Refused(f"no arm ruling exists for {prog}: sign the program first "
                      "(operator ruling sign <dir> --kind arm)")
    try:
        ruling_mod.verify_one(prog, newest[0], newest[1])
    except ruling_mod.Refused as e:
        raise Refused(f"the environment is not signed: {e}. Re-sign the program "
                      "(operator ruling sign <dir> --kind arm), with CONTRACT_REPO and "
                      "CONTRACT_PIN at the run's values when the ruling closes over a base")
    except ruling_mod.Void as e:
        raise Void(str(e))


# --- the door: the only container client ------------------------------------------------


def runtime_cli(spec):
    seam = os.environ.get("OPERATOR_CONTAINER_CLI")
    if seam:
        real = os.path.realpath(seam)
        if not real.startswith(os.path.join(ROOT, "test") + os.sep) or not os.access(real, os.X_OK):
            raise Refused("OPERATOR_CONTAINER_CLI names a fixture under test/ or stays unset: "
                          "it is a test seam, never a runtime of choice")
        return real
    exe = shutil.which(spec["runtime"])
    if not exe:
        raise Void(f"no {spec['runtime']} on PATH: run on the host that has the runtime "
                   "the signed spec names")
    return exe


def require_image(cli, spec):
    image = spec["image"]
    r = sh([cli, "image", "inspect", "--format", "{{.Id}}", image])
    if r.returncode != 0:
        raise Refused(f"image {image} isn't present locally and the engine never pulls; "
                      f"bring it yourself: {spec['runtime']} pull {image}")


def require_user(spec):
    uid = int(spec["user"].split(":")[0])
    if uid == os.getuid():
        return
    if os.getuid() == 0:
        raise Refused("the engine runs as root and an environment's user is never root: "
                      "run the engine as a plain user")
    raise Refused(f"the environment runs as uid {uid} but the engine is uid {os.getuid()}, "
                  f"so the files it writes would not be the engine's: set user = "
                  f"\"{os.getuid()}:{os.getgid()}\" in the signed spec, or run on the host "
                  f"whose uid is {uid}")


def _mount_flag(m):
    """A spec mount 'HOST:MODE' as the runtime's 'HOST:HOST:MODE': the same path inside."""
    host, mode = m.rsplit(":", 1)
    return f"{host}:{host}:{mode}"


def run_argv(cli, spec, name, cname, work, cmd, envs, mounts, cwd, work_mount=True):
    """The one argv shape. Everything the spec and the door decide is explicit here."""
    lim = spec["limits"]
    argv = [cli, "run", "-d", "--name", cname, "--label", f"operator.env={name}",
            "--network", spec["network"], "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", spec["user"],
            "--memory", lim["memory"], "--memory-swap", lim["memory"],
            "--cpus", str(lim["cpus"]), "--pids-limit", str(lim["pids"]),
            "--log-driver", "json-file", "--log-opt", f"max-size={LOG_MAX}",
            "--log-opt", "max-file=1",
            "--tmpfs", "/tmp:size=64m,mode=1777"]
    for w in spec["writable"]:
        path, size = w.rsplit(":", 1)
        argv += ["--tmpfs", f"{path}:size={size},mode=1777"]
    if work_mount:
        argv += ["-v", f"{work}:/work:rw"]
    for src, dst, mode in mounts:
        argv += ["-v", f"{src}:{dst}:{mode}"]
    for m in spec["mounts"]:
        argv += ["-v", _mount_flag(m)]
    if "gpu" in spec["devices"]:
        argv += ["--gpus", "all"]
    for d in spec["devices"]:
        if d != "gpu":
            argv += ["--device", f"{d}:{d}"]
    for k, v in envs:
        argv += ["-e", f"{k}={v}"]
    if cwd:
        argv += ["-w", cwd]
    return argv + ["--", spec["image"], *cmd]


def _binds_ok(src, dst, mode):
    return (os.path.isabs(src) and dst.startswith("/") and mode in ("ro", "rw")
            and ":" not in src and "," not in src and ":" not in dst and "," not in dst)


def run_env(prog, name, work, cmd, envs=(), mounts=(), cwd=None, timeout=None,
            cap=LOG_CAP, check=True, work_mount=True, abort=None):
    """One run in a signed environment. `work` is the caller's directory, writable
    at /work. `mounts` are (src, dst, mode) binds for a contract row's export and
    its read-only overlays. `abort` is an Event: set, it ends the run (rc 125).
    Returns (rc, out, meta)."""
    spec = environment(prog, name)
    if abort is not None and abort.is_set():
        raise Refused("the turn that asked for this run is over")
    if check:
        require_signed(prog)
    if not cmd or not all(isinstance(c, str) and "\x00" not in c for c in cmd):
        raise Refused("a command is required: -- <cmd...>")
    if not isinstance(work, str) or not os.path.isabs(work) or not os.path.isdir(work):
        raise Refused(f"the work directory must be an existing absolute path, not {work!r}")
    if ":" in work or "," in work:
        raise Refused("the work directory's path has a ':' or a ',': the runtime's "
                      "mount syntax can't name it")
    if any(not _binds_ok(*m) for m in mounts):
        raise Void(f"a bind of the door is malformed: {[m for m in mounts if not _binds_ok(*m)]}")
    cli = runtime_cli(spec)
    require_image(cli, spec)
    require_user(spec)
    for m in spec["mounts"]:
        host = m.rsplit(":", 1)[0]
        real = os.path.realpath(host)
        # a symlink into a refused root refuses too, socket before existence:
        # the daemon's socket may be absent in a room and is refused either way
        why = mount_refusal(real, extra_roots())
        if why:
            raise Refused(f"environment {name!r}: mount {host!r} resolves to {real!r}: {why}")
        if not os.path.exists(real):
            raise Refused(f"environment {name!r} mounts {host!r}, which doesn't exist on this host")
    for d in spec["devices"]:
        if d != "gpu" and not os.path.exists(d):
            raise Void(f"environment {name!r} names device {d}, which this host doesn't have; "
                       "run it on the host that does, or drop the device")
    if "gpu" in spec["devices"]:
        sys.path.insert(0, os.path.join(ROOT, "bin", "lib"))
        from jail import nvidia_nodes  # noqa: E402
        if not nvidia_nodes():
            raise Void(f"environment {name!r} names the gpu and this host has no nvidia devices; "
                       "run it on the GPU host, or drop the device")
    wall = spec["limits"]["wall"]
    limit = wall if timeout is None else min(timeout, wall)
    env_pairs = [("HOME", "/tmp"), ("PATH", "/usr/bin:/bin"), *envs]
    cname = "op-env-" + os.urandom(6).hex()
    argv = run_argv(cli, spec, name, cname, work, cmd, env_pairs, mounts, cwd, work_mount)
    t0 = time.monotonic()
    r = sh(argv)
    if r.returncode != 0:
        raise Void(f"{spec['runtime']} run refused: {(r.stderr or r.stdout).strip()[:300]}")
    timed_out, aborted, oom, gave_up, rc, out = False, False, False, False, None, b""
    floor = int(os.environ.get("OPERATOR_DISK_FLOOR") or 512 * 1024 * 1024)
    try:
        while rc is None:
            st = sh([cli, "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", cname])
            parts = st.stdout.split()
            if st.returncode == 0 and len(parts) == 3 and parts[0] != "running":
                rc, oom = int(parts[1]), parts[2] == "true"
                break
            if abort is not None and abort.is_set() and not aborted:
                aborted = True
                sh([cli, "kill", cname])
            left = time.monotonic() - t0
            if left > limit or shutil.disk_usage(work).free < floor:
                if not timed_out:
                    timed_out = True
                    sh([cli, "kill", cname])
                if left > limit + KILL_GRACE:
                    gave_up = True
                    break
            time.sleep(POLL)
        if rc is None:
            rc = 125 if gave_up else 124
        logs = subprocess.run([cli, "logs", cname], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        out = (logs.stdout or b"")[:cap]
    finally:
        sh([cli, "rm", "-f", cname])
    if timed_out:
        rc = 124
    if aborted:
        rc = 125
    meta = {"env": name, "image": DIGEST_RE.fullmatch(spec["image"]).group(1)[:16],
            "argv": hashlib.sha256(b"\0".join(c.encode("utf-8") for c in cmd)).hexdigest()[:16],
            "rc": rc, "secs": round(time.monotonic() - t0, 3), "runtime": spec["runtime"],
            "oom": oom, "timed_out": timed_out, "aborted": aborted}
    return rc, out, meta


def receipt(name, meta, runfile):
    """The run's receipt: a hash-chained row in the log that holds every check."""
    argv = [os.path.join(ROOT, "bin", "call-log.sh"), "record", f"env:{name}",
            "--key", f"env={name}", "--key", f"image={meta['image']}",
            "--key", f"argv={meta['argv']}", "--key", f"rc={meta['rc']}",
            "--key", f"secs={int(meta['secs'])}", "--key", f"runtime={meta['runtime']}",
            "--", "cat", runfile]
    r = sh(argv)
    if r.returncode == 3:
        raise Locked("the call log is locked")
    if r.returncode != 0 or not r.stdout.strip():
        raise Void(f"the call log refused the environment receipt: {r.stderr.strip()}")
    return r.stdout.strip()


def run_recorded(prog, name, work, cmd, envs=(), mounts=(), cwd=None, timeout=None,
                 cap=LOG_CAP, abort=None):
    """run_env plus its receipt. Returns (rc, out, meta, call_id)."""
    rc, out, meta = run_env(prog, name, work, cmd, envs, mounts, cwd, timeout, cap, True, True, abort)
    fd, runfile = tempfile.mkstemp(prefix="envrun.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(out)
        return rc, out, meta, receipt(name, meta, runfile)
    finally:
        os.unlink(runfile)


def overlays_of(binds):
    """The jail's flat bind list (--ro-bind SRC DST, --bind SRC DST) as (src, dst, mode)."""
    out = []
    for i in range(0, len(binds) - 2, 3):
        if binds[i] in ("--ro-bind", "--bind") and os.path.isabs(binds[i + 1]) \
                and binds[i + 2].startswith("/"):
            out.append((binds[i + 1], binds[i + 2], "ro" if binds[i] == "--ro-bind" else "rw"))
    return out


def run_check_env(prog, name, export, overlays, cmd, envs, timeout, cap=LOG_CAP):
    """A contract row's check in its environment: the export writable at /w/export,
    every read-only bind the jail would have (the pinned oracle, the runner
    configs, pytest-guard's files) mounted the same way at the same paths, an
    empty writable /w/out, the program read-only at /prog."""
    out = tempfile.mkdtemp(prefix="envout.")
    try:
        mounts = [(export, "/w/export", "rw"), *overlays, (out, "/w/out", "rw"),
                  (os.path.realpath(prog), "/prog", "ro")]
        return run_env(prog, name, out, cmd, envs, mounts, "/w/export", timeout, cap,
                       work_mount=False)
    finally:
        shutil.rmtree(out, ignore_errors=True)


# --- the worker's door: the environment socket a jail may carry --------------------------


class Door:
    """The engine's side of a worker's environment socket. One thread, one
    request at a time: a jailed seat asks with an environment name, a command
    and an optional timeout; everything else stays the door's. The arm ruling
    is verified on every run, the seat's grants and budget bound it, and the
    turn's end is the door's end: a run in flight is killed, nothing new runs."""

    def __init__(self, attempt, prog, grants, budget_secs=None):
        self.dir = os.path.join(attempt, "envd")
        self.work = os.path.join(self.dir, "work")
        self.record = os.path.join(self.dir, "sock")   # where the socket is, for the jail's binds
        self.sock = None
        self._room = None
        self.prog = prog
        self.grants = sorted(set(grants or ()))
        self.budget_secs = budget_secs
        self.abort = threading.Event()
        self.used = 0.0
        self._srv = None
        self._thread = None

    def start(self):
        os.makedirs(self.work, mode=0o700, exist_ok=True)
        # an AF_UNIX path is capped at 108 bytes and an attempt's path is not
        # the engine's to shorten: the socket lives in a short private directory
        self._room = tempfile.mkdtemp(prefix="op-envd-", dir=short_dir())
        self.sock = os.path.join(self._room, "s.sock")
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.sock)
        os.chmod(self.sock, 0o600)
        with open(self.record, "w", encoding="utf-8") as f:
            f.write(self.sock + "\n")
        self._srv.listen(8)
        self._thread = threading.Thread(target=self._serve, args=(self._srv,), daemon=True,
                                        name="environment-door")
        self._thread.start()
        return self

    def close(self):
        """The turn is over: no new request is served and a run in flight is killed."""
        self.abort.set()
        srv, self._srv = self._srv, None
        # closing the socket from here does not wake a thread blocked in accept():
        # one connection of our own brings it back, and the abort ends its loop
        if self.sock:
            wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            wake.settimeout(2)
            try:
                wake.connect(self.sock)
            except OSError:
                pass
            wake.close()
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=KILL_GRACE + 15)
        if self._room is not None:
            shutil.rmtree(self._room, ignore_errors=True)

    def _serve(self, srv):
        while not self.abort.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            with conn:
                data = b""
                try:
                    while len(data) <= DOOR_IN:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    data = b""
                try:
                    req = json.loads(data.decode("utf-8") or b"null")
                except (ValueError, UnicodeDecodeError):
                    req = None
                try:
                    conn.sendall(json.dumps(self._handle(req), sort_keys=True).encode("utf-8") + b"\n")
                except OSError:
                    pass

    @staticmethod
    def _refuse(why, fix):
        return {"rc": None, "refused": f"{why}. {fix}"}

    def _handle(self, req):
        if self.abort.is_set():
            return self._refuse("the turn is over", "the door closes with its turn")
        if not isinstance(req, dict):
            return self._refuse("a request is one JSON object: env, argv and an optional timeout",
                                "python3 -I /engine/op-env.py --env NAME -- <cmd...>")
        name = req.get("env")
        if not isinstance(name, str) or name not in self.grants:
            return self._refuse(f"environment {name!r} isn't granted to this seat",
                                f"granted here: {', '.join(self.grants) or 'none'}; a grant is the "
                                "seat's env in team.toml, which the owner signs")
        cmd = req.get("argv")
        if not isinstance(cmd, list) or not cmd or len(cmd) > MAX_ARGS \
                or not all(isinstance(c, str) and c and "\x00" not in c and len(c) <= MAX_ARG
                           for c in cmd):
            return self._refuse("argv must be a non-empty list of strings",
                                f"at most {MAX_ARGS} arguments of {MAX_ARG} bytes each")
        t = req.get("timeout")
        if t is not None and not (_number(t) and 0 < t <= 86400):
            return self._refuse("timeout is a number of seconds, at most a day",
                                "drop it to run for the environment's wall")
        if self.budget_secs is not None:
            left = self.budget_secs - self.used
            if left <= 0:
                return self._refuse("this seat's environment budget is spent",
                                    f"{self.budget_secs / 60:g} minutes were granted (env_minutes in "
                                    "team.toml); the owner raises it")
            t = left if t is None else min(t, left)
        try:
            rc, out, meta, cid = run_recorded(self.prog, name, self.work, cmd, timeout=t,
                                              cap=DOOR_OUT, abort=self.abort)
        except Locked as e:
            return {"rc": None, "void": str(e)}
        except (Refused, Finding) as e:
            return {"rc": None, "refused": str(e)}
        except Void as e:
            return {"rc": None, "void": str(e)}
        self.used += float(meta["secs"])
        return {"rc": rc, "out": out.decode("utf-8", "replace"), "secs": meta["secs"],
                "env": name, "image": meta["image"], "receipt": cid,
                "aborted": meta.get("aborted", False)}


def door_binds(attempt):
    """The jail's binds for a seat's environment socket. The socket exists only
    once Door.start() has run, so a jail is built only after its door."""
    envd = os.path.join(attempt, "envd")
    with open(os.path.join(envd, "sock"), encoding="utf-8") as f:
        sock = f.read().strip()
    return ["--bind", os.path.join(envd, "work"), ENV_WORK,
            "--bind", sock, ENV_SOCK,
            "--ro-bind", os.path.join(ROOT, "bin", "lib", "op-env.py"), ENV_CLIENT]


# --- the front door ---------------------------------------------------------------------


def flag(argv, name, default=None):
    if name in argv and argv.index(name) + 1 < len(argv):
        return argv[argv.index(name) + 1]
    return default


def cmd_validate(prog, as_json=False):
    doc = charter(prog)
    if doc is None:
        names, bad = [], []
    else:
        bad = charter_findings(doc)
        names = [] if bad else sorted(specs(prog))
    if as_json:
        print(json.dumps({"ok": not bad, "charter": doc is not None, "environments": names,
                          "findings": bad}, sort_keys=True))
    else:
        for b in bad:
            print(f"validate: {b}", file=sys.stderr)
        if bad:
            print(f"validate: {len(bad)} finding{'s' if len(bad) > 1 else ''}; fix {CHARTER} "
                  "(docs/charter.md)", file=sys.stderr)
        else:
            print(f"validate: OK ({len(names)} environments: "
                  f"{' '.join(names) or 'none declared, the degenerate charter'})")
    return 1 if bad else 0


def cmd_run(argv):
    prog = argv[0]
    name = flag(argv, "--env")
    as_json = "--json" in argv
    if not name or "--" not in argv:
        print("usage: environment.py run <program-dir> --env NAME [--work DIR] [--timeout S] "
              "[--json] -- <cmd...>", file=sys.stderr)
        return 2
    cmd = argv[argv.index("--") + 1:]
    try:
        timeout = float(flag(argv, "--timeout") or 0)
    except ValueError:
        print("environment: --timeout is seconds", file=sys.stderr)
        return 2
    if timeout < 0:
        print("environment: --timeout is a non-negative number of seconds", file=sys.stderr)
        return 2
    work = flag(argv, "--work") or os.getcwd()
    rc, out, meta, cid = run_recorded(prog, name, work, cmd, timeout=timeout or None)
    if as_json:
        print(json.dumps({**meta, "call_id": cid,
                          "out": out[:4096].decode("utf-8", "replace")}, sort_keys=True))
    else:
        sys.stdout.buffer.write(out)
        if out and not out.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        note = ("killed by its memory limit" if meta["oom"] else
                "killed at its wall clock" if meta["timed_out"] else "")
        print(f"environment: {name} rc={rc} secs={meta['secs']} receipt={cid}"
              + (f" ({note})" if note else ""), file=sys.stderr)
    return rc


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if argv[1:] == ["--first-level"]:
        return first_level()
    if len(argv) >= 3 and argv[1] == "validate":
        return cmd_validate(argv[2], "--json" in argv[3:])
    if len(argv) >= 3 and argv[1] == "run":
        return cmd_run(argv[2:])
    print("usage: environment.py validate <program-dir> [--json]\n"
          "       environment.py run <program-dir> --env NAME [--work DIR] [--timeout S] "
          "[--json] -- <cmd...>\n"
          "       environment.py --selftest | --first-level", file=sys.stderr)
    return 2


# --- fixtures of both suites -------------------------------------------------------------


IMAGE = "sha256:" + "a" * 64          # the fake runtime accepts any digest but the all-zero one
ABSENT = "sha256:" + "0" * 64
LIMITS = 'memory = "64m"\n  cpus = 1\n  pids = 16\n  wall = 300'
ROW = 'schema = 2\n[[row]]\nid = "e1"\nstage = "s"\ndesc = "d"\nkind = "run"\nseat = "w"\n' \
      'reviewer = "r"\ncmd = "true"\ntimeout = 120\n'
TEAM = 'schema = 1\nname = "t"\nmax_parallel = 1\n[seat.w]\nrole = "roles/w.md"\n' \
       'adapter = "stub"\nwrite = ["src/**"]\n[seat.r]\nrole = "roles/w.md"\nadapter = "stub"\n'


def charter_text(env="t", **over):
    """A one-environment charter; `over` replaces or adds keys of its block."""
    base = {"image": f'"{IMAGE}"', "runtime": '"docker"',
            "user": f'"{os.getuid()}:{os.getgid()}"', "writable": '["/scratch:8m"]'}
    base.update(over)
    limits = base.pop("limits", LIMITS)
    lines = [f"[[environment.{env}]]"] + [f"{k} = {v}" for k, v in base.items()] \
        + [f"  [environment.{env}.limits]", "  " + limits.replace("\n", "\n  ")]
    return "schema = 1\nname = \"st\"\n\n" + "\n".join(lines) + "\n"


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _git_env():
    return {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_COMMITTER_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_EMAIL": "t@x"}


def _signed_world(base):
    """A home with a signer, a committed core, and a program dir with contract and
    team. Returns (home, key, prog). The caller sets the env and signs."""
    home = os.path.join(base, "home")
    os.makedirs(os.path.join(home, "signers"))
    core = os.path.join(base, "core")
    os.makedirs(core)
    write(os.path.join(core, "VERSION"), "0.1\n")
    for a in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "core"]):
        subprocess.run(["git", "-C", core, *a], capture_output=True, env=_git_env())
    key = os.path.join(base, "k")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "env", "-f", key],
                   check=True, capture_output=True)
    sf = write(os.path.join(home, "signers", "allowed_signers"),
               f'owner@fixture namespaces="operator-ruling" {open(key + ".pub").read().strip()}\n')
    os.chmod(sf, 0o600)
    prog = os.path.join(base, "prog")
    os.makedirs(prog)
    write(os.path.join(prog, "contract.toml"), ROW)
    write(os.path.join(prog, "team.toml"), TEAM)
    os.makedirs(os.path.join(prog, "roles"))
    write(os.path.join(prog, "roles", "w.md"), "You are the fixture seat.\n")
    return home, key, prog, core


ENV_KEYS_OF_SUITES = ("OPERATOR_HOME", "RULING_CORE_GIT", "CALL_LOG_FILE",
                      "OPERATOR_CONTAINER_CLI", "FAKE_CONTAINER_DIR", "OPERATOR_DISK_FLOOR",
                      "CONTRACT_REPO", "CONTRACT_PIN")


# --- selftest: the room -----------------------------------------------------------------


def selftest():
    """The room suite: the charter's laws, the contract row's laws, and the argv the
    door builds, all against test/lib/fake-container.py. The real daemon is the
    first-level suite's."""
    import ruling as ruling_mod
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    def sign():
        with contextlib.redirect_stdout(sys.stderr):   # sign() names the record it wrote
            ruling_mod.sign(prog, "arm", None, key)

    def refused(fn, needle, label, void=False):
        want, other = (Void, (Refused, Finding)) if void else ((Refused, Finding), Void)
        try:
            fn()
        except want as e:
            check(needle in str(e), f"{label}: {e}")
        except other as e:
            check(False, f"{label} {'VOIDed' if not void else 'refused'} instead: {e}")
        else:
            check(False, f"{label} was accepted")

    old = {k: os.environ.get(k) for k in ENV_KEYS_OF_SUITES}
    base = tempfile.mkdtemp(prefix="environment-st.")
    try:
        home, key, prog, core = _signed_world(base)
        rec = os.path.join(base, "records")
        os.makedirs(rec)
        os.environ.update({"OPERATOR_HOME": home, "RULING_CORE_GIT": core,
                           "FAKE_CONTAINER_DIR": rec, "OPERATOR_CONTAINER_CLI": FAKE,
                           "OPERATOR_DISK_FLOOR": "0",
                           "CALL_LOG_FILE": os.path.join(home, "call-log.tsv")})
        os.environ.pop("CONTRACT_REPO", None)
        os.environ.pop("CONTRACT_PIN", None)
        cpath = os.path.join(prog, CHARTER)
        work = os.path.join(base, "work")
        os.makedirs(work)

        def validates(needle, label, text=None):
            write(cpath, text if text is not None else charter_text())
            got = charter_findings(charter(prog))
            check(any(needle in g for g in got), f"{label}: {got}")

        def clean(text, label):
            write(cpath, text)
            check(not charter_findings(charter(prog)), f"{label}: {charter_findings(charter(prog))}")

        # V the charter's laws (the program starts without one)
        check(charter(prog) is None and specs(prog) == {}, "V0 no charter is the degenerate charter")
        clean(charter_text(), "V1 a digest-pinned environment validates")
        validates("pinned by digest", "V2 a tag is refused", charter_text(image='"tests:latest"'))
        validates("never the host", "V3 the host root is refused", charter_text(mounts='["/:ro"]'))
        validates("container socket", "V4 a container socket is refused",
                  charter_text(mounts='["/var/run/docker.sock:ro"]'))
        validates("system path", "V5 /proc is refused", charter_text(mounts='["/proc/x:ro"]'))
        validates("engine's own tree", "V6 the engine's tree is refused",
                  charter_text(mounts=f'["{ROOT}/bin:ro"]'))
        validates("engine's own tree", "V7 the engine's state is refused",
                  charter_text(mounts=f'["{home}/signers:ro"]'))
        validates("never root", "V8 root is refused", charter_text(user='"0:0"'))
        validates("limits names memory", "V9 a missing memory limit is refused",
                  charter_text(limits="cpus = 1\n  pids = 16\n  wall = 30"))
        validates("network is 'none'", "V10 a network is refused", charter_text(network='"dev"'))
        validates("rootfs is 'ro'", "V11 a writable rootfs is refused", charter_text(rootfs='"rw"'))
        validates("the door uses", "V12 a writable path of the door's own is refused",
                  charter_text(writable='["/w/out:8m"]'))
        validates("unknown key", "V13 an unknown key is refused", charter_text(shell="true"))
        validates("runtime is docker", "V14 an unbuilt runtime is refused", charter_text(runtime='"podman"'))
        validates("devices are", "V15 a path that isn't a /dev device is refused",
                  charter_text(devices='["/etc/passwd"]'))
        validates("declared twice", "V16 an environment declared twice is refused",
                  charter_text() + "[[environment.t]]\nimage = \"" + IMAGE + "\"\nruntime = \"docker\"\n"
                  "user = \"1000:1000\"\n[environment.t.limits]\n" + LIMITS + "\n")
        write(cpath, "schema = 1\nname = \"x\"\n[[environment")
        try:
            specs(prog)
            check(False, "V17 an unparsable charter was accepted")
        except Finding as e:
            check("doesn't parse" in str(e), f"V17 an unparsable charter refuses: {e}")
        validates("declare it as", "V17b a plain [environment] table is refused",
                  "schema = 1\nname = \"x\"\n[environment]\nt = {}\n")
        validates("is required", "V17c a spec without a user is refused",
                  "schema = 1\nname = \"x\"\n[[environment.t]]\nimage = \"" + IMAGE
                  + "\"\nruntime = \"docker\"\n[environment.t.limits]\n" + LIMITS + "\n")
        # V18 the later milestones' sections are shape-checked and nothing more
        clean(charter_text() + "\n[standing]\nnot_after = \"2030-01-01T00:00:00Z\"\n"
              "[purse]\nusd = 10.0\nconcurrency = 2\n[reach]\nprofile = \"dev\"\n"
              "declared_max = 10\ndeclared_ttl = 3600\n[evidence]\nmin_mutation_kill = 0.3\n"
              "[reserved]\nextra = [\"ship\"]\n",
              "V18 the later milestones' sections hold their shape")
        validates("takes not_after", "V18b an unknown standing key is refused",
                  charter_text() + "\n[standing]\nuntil = \"x\"\n")
        validates("profile is closed, dev or research", "V18c an unknown reach profile is refused",
                  charter_text() + "\n[reach]\nprofile = \"open\"\n")
        validates("must be a non-negative number", "V18d a negative purse is refused",
                  charter_text() + "\n[purse]\nusd = -1\n")
        for badpin in ("a.example=999.1.1.1:1", "a.example=192.0.2.1:99999", "a.example", "a=b:1"):
            validates("pins is a list", f"V19 a reach pin that isn't host=address:port refuses ({badpin})",
                      charter_text() + f'\n[reach]\npins = ["{badpin}"]\n')
        clean(charter_text() + '\n[reach]\npins = ["a.example=192.0.2.1:8443"]\n',
              "V19 a well-formed reach pin validates")

        # C a contract row's laws
        import contract as contract_mod
        write(cpath, charter_text())

        def row_finding(row_text, needle, label):
            write(os.path.join(prog, "contract.toml"), row_text)
            try:
                contract_mod.load(prog)
                check(False, f"{label} was accepted")
            except contract_mod.Finding as e:
                check(needle in str(e), f"{label}: {e}")
            except contract_mod.Void as e:
                check(False, f"{label} VOIDed instead of refusing: {e}")

        row_finding(ROW + 'env = "nope"\n', "names no environment",
                    "C1 a row naming an undeclared environment")
        row_finding(ROW + 'env = "t"\ngpu = true\n', "devices twice", "C2 env and gpu together")
        row_finding(ROW + 'env = "t"\ndriver = "external"\n', "cmd takes env",
                    "C5 an external row takes no env")
        row_finding(ROW.replace("timeout = 120", "timeout = 600") + 'env = "t"\n', "exceeds",
                    "C4 a row timeout over the environment's wall")
        row_finding('schema = 2\n[[row]]\nid = "h1"\nstage = "s"\ndesc = "d"\nkind = "ruling"\n'
                    'seat = "o"\nreviewer = "r"\nenv = "t"\n', "run row", "C3 a ruling row takes no env")
        row_finding(ROW + 'env = "T"\n', "must be an environment name",
                    "C6 an environment name keeps its shape (and so is exact)")
        write(os.path.join(prog, "contract.toml"), ROW + 'env = "t"\n')
        try:
            check(contract_mod.load(prog)["by_id"]["e1"]["env"] == "t", "C7 a row naming a declared environment loads")
        except (contract_mod.Finding, contract_mod.Void) as e:
            check(False, f"C7 a declared environment refused the row: {e}")
        write(os.path.join(prog, "contract.toml"), ROW)

        def run(cmd, **kw):
            return run_recorded(prog, "t", work, cmd, **kw)

        def recorded(cmd, **kw):
            """Runs and returns (result, what the fake runtime was given for it)."""
            for n in os.listdir(rec):
                os.unlink(os.path.join(rec, n))
            os.environ["FAKE_NO_RM"] = "1"   # the fake keeps its argv record across `rm`
            try:
                res = run(cmd, **kw)
                names = [n for n in os.listdir(rec) if n.endswith(".argv.json")]
                return res, (json.load(open(os.path.join(rec, names[0]))) if names else {})
            finally:
                os.environ.pop("FAKE_NO_RM", None)

        # D the door
        refused(lambda: run(["true"]), "no arm ruling", "D0 an unsigned program refuses")
        sign()
        rc, out, meta, cid = run(["sh", "-c", "echo hello; pwd; echo $HOME $PATH"])
        check(rc == 0 and out.startswith(b"hello\n") and out.rstrip().endswith(b"/tmp /usr/bin:/bin"),
              f"D1 a signed environment runs: rc={rc} out={out!r}")
        (rc, out, meta, cid), d = recorded(["sh", "-c", "exit 0"])
        for k, v in (("--network", "none"), ("--read-only", True), ("--cap-drop", "ALL"),
                     ("--security-opt", "no-new-privileges"), ("--user", f"{os.getuid()}:{os.getgid()}"),
                     ("--memory", "64m"), ("--memory-swap", "64m"), ("--cpus", "1"),
                     ("--pids-limit", "16"), ("--label", "operator.env=t"),
                     ("--log-driver", "json-file"), ("image", IMAGE)):
            check(d.get(k) == v, f"D2 the argv carries {k}={v}: got {d.get(k)!r}")
        check(d.get("tmpfs") == ["/tmp:size=64m,mode=1777", "/scratch:size=8m,mode=1777"],
              f"D2b scratch space is size-capped tmpfs: {d.get('tmpfs')}")
        check(d.get("log_opt") == ["max-size=4m", "max-file=1"],
              f"D2c the daemon's log is capped: {d.get('log_opt')}")
        check(d.get("env") == {"HOME": "/tmp", "PATH": "/usr/bin:/bin"},
              f"D2d only the door's env reaches the command: {d.get('env')}")
        check(d.get("mounts") == [[work, "/work", "rw"]], f"D2e the work directory is /work: {d.get('mounts')}")
        check(d.get("cmd") == ["sh", "-c", "exit 0"] and d.get("detach") is True,
              f"D2f the command rides whole and detached: {d.get('cmd')}")
        (rc, out, meta, cid), d = recorded(["sh", "-c", "exit 7"])
        check(rc == 7, f"D3 the command's own exit code comes back: {rc}")
        (rc, out, meta, cid), d = recorded(["sh", "-c", "echo __fake_oom__; exit 137"])
        check(rc == 137 and meta["oom"] is True, f"D3b a run killed by its memory limit says so: {meta}")
        t0 = time.monotonic()
        (rc, out, meta, cid), d = recorded(["sh", "-c", "sleep 20"], timeout=1)
        check(rc == 124 and meta["timed_out"] is True and time.monotonic() - t0 < 12,
              f"D4 the wall clock kills a runaway: rc={rc} meta={meta}")
        rc5, out5, _meta5 = run_env(prog, "t", work, ["sh", "-c", "head -c 5000 /dev/zero | tr '\\0' x"], cap=100)
        check(rc5 == 0 and len(out5) == 100, f"D5 the output keeps its first bytes only: {len(out5)}")
        log = os.environ["CALL_LOG_FILE"]
        erows = [[kv.split("=", 1) for kv in ln.split("\t")[3].split(",")]
                 for ln in (open(log, encoding="utf-8").read().splitlines() if os.path.exists(log) else [])
                 if len(ln.split("\t")) == 10 and ln.split("\t")[2] == "env:t"]
        as_keys = [dict(r) for r in erows]
        keys = next((k for k in as_keys if k.get("rc") == "0"), {})
        check(len(as_keys) >= 4 and keys.get("env") == "t" and keys.get("image") == "a" * 16
              and keys.get("runtime") == "docker" and len(keys.get("argv", "")) == 16
              and keys.get("secs", "").isdigit()
              and {k.get("rc") for k in as_keys} >= {"0", "7", "137", "124"},
              f"D6 every run leaves a receipt: {as_keys[-1] if as_keys else None}")
        v = sh([os.path.join(ROOT, "bin", "call-log.sh"), "verify"])
        check(v.returncode == 0, f"D6b the receipts sit in a verifying chain: {v.stderr}")
        refused(lambda: run_recorded(prog, "nope", work, ["true"]), "no environment 'nope'",
                "D6c an undeclared environment refuses")
        good = open(cpath, encoding="utf-8").read()

        def swap(text):
            write(cpath, text)
            sign()

        swap(charter_text(image=f'"{ABSENT}"'))
        refused(lambda: run(["true"]), "never pulls", "D7 an absent digest refuses without a pull")
        swap(charter_text(user=f'"{os.getuid() + 1}:{os.getgid()}"'))
        refused(lambda: run(["true"]), "the engine is uid", "D8 another uid refuses")
        swap(charter_text(mounts='["/definitely/absent/dir:ro"]'))
        refused(lambda: run(["true"]), "doesn't exist on this host", "D9 a mount that isn't there refuses")
        link = os.path.join(base, "link")
        os.symlink("/run/docker.sock", link)
        swap(charter_text(mounts=f'["{link}:ro"]'))
        refused(lambda: run(["true"]), "container socket",
                "D10 a symlink to a container socket refuses at run")
        swap(good)
        os.environ["OPERATOR_CONTAINER_CLI"] = "/bin/echo"
        refused(lambda: run(["true"], timeout=1), "test seam",
                "D11 the runtime seam stays under test/")
        os.environ["OPERATOR_CONTAINER_CLI"] = FAKE
        write(cpath, charter_text(limits=LIMITS.replace('"64m"', '"32m"')))
        refused(lambda: run(["true"]), "no longer closes as it did when signed",
                "D12 an edited environment is an unsigned program")
        sign()
        (rc, out, meta, cid), d = recorded(["sh", "-c", "exit 0"])
        check(d.get("--memory") == "32m", "D13 the re-signed spec is the one that runs")
        sys.path.insert(0, os.path.join(ROOT, "bin", "lib"))
        from jail import nvidia_nodes  # noqa: E402
        swap(charter_text(devices='["gpu", "/dev/null"]'))
        if nvidia_nodes():
            (rc, out, meta, cid), d = recorded(["true"])
            check(d.get("gpus") == "all" and d.get("devices") == ["/dev/null:/dev/null"],
                  f"D14 devices ride from the signed spec: {d.get('gpus')} {d.get('devices')}")
        else:
            refused(lambda: run(["true"]), "no nvidia devices",
                    "D14 a gpu environment on a GPU-less host", void=True)
        swap(charter_text(mounts=f'["{base}/work:ro"]'))
        (rc, out, meta, cid), d = recorded(["true"])
        check([f"{base}/work", f"{base}/work", "ro"] in d.get("mounts", []),
              f"D15 a signed host mount lands at its own path, read-only: {d.get('mounts')}")
        # E a contract row's check: the export writable, every jail overlay read-only at its path
        swap(charter_text())
        export = os.path.join(base, "export")
        os.makedirs(os.path.join(export, "oracle"), exist_ok=True)
        pinned = os.path.join(base, "pin", "oracle")
        os.makedirs(pinned, exist_ok=True)
        for n in os.listdir(rec):
            os.unlink(os.path.join(rec, n))
        os.environ["FAKE_NO_RM"] = "1"
        try:
            rc, out, meta = run_check_env(prog, "t", export, overlays_of(
                ["--ro-bind", pinned, "/w/export/oracle", "--bind", base, "/w/.op-key"]),
                ["sh", "-c", "pwd"], (("PROG", "/prog"),), 30)
            names = [n for n in os.listdir(rec) if n.endswith(".argv.json")]
            rd = json.load(open(os.path.join(rec, names[0]))) if names else {}
        finally:
            os.environ.pop("FAKE_NO_RM", None)
        mounts = [tuple(m) for m in rd.get("mounts", [])]
        check((export, "/w/export", "rw") in mounts and (pinned, "/w/export/oracle", "ro") in mounts
              and (base, "/w/.op-key", "rw") in mounts
              and sum(1 for m in mounts if m[1:] == ("/w/out", "rw")) == 1
              and (os.path.realpath(prog), "/prog", "ro") in mounts
              and not any(m[1] == "/work" for m in mounts) and rd.get("-w") == "/w/export",
              f"E1 a row's check mounts the export and its overlays the way the jail does: {mounts}")
        check(rc == 0 and out.strip().endswith(b"/export") and rd.get("env", {}).get("PROG") == "/prog",
              f"E1b the check runs in the export with the door's env: rc={rc} out={out!r}")
        v = sh([os.path.join(ROOT, "bin", "call-log.sh"), "verify"])
        check(v.returncode == 0, f"E1c the chain still verifies: {v.stderr}")
        # E2 the whole way: a contract row's check leaves the jail only for its
        # environment, and its receipt says so
        import spawn as spawn_mod
        write(os.path.join(prog, "contract.toml"),
              ROW.replace('cmd = "true"', 'cmd = "echo ran-in-export"') + 'env = "t"\n')
        sign()
        e_rd, e_parent, e_sha = spawn_mod._world(home, "w1", {"src/a.py": "v=1\n"})
        try:
            e_row = contract_mod.load(prog)["by_id"]["e1"]
            e_rc, e_file, e_cid = contract_mod.run_check(e_row, prog, e_parent, e_sha, "arm-st", {}, "prog-st")
            e_out = open(e_file, "rb").read() if e_file else b""
        except (contract_mod.Finding, contract_mod.Void, OSError) as e:
            e_rc, e_out = None, repr(e).encode()
        check(e_rc == 0 and e_out.strip() == b"ran-in-export",
              f"E2 a row's check runs in its environment: rc={e_rc} out={e_out!r}")
        krows = [dict(kv.split("=", 1) for kv in ln.split("\t")[3].split(","))
                 for ln in (open(log, encoding="utf-8").read().splitlines() if os.path.exists(log) else [])
                 if len(ln.split("\t")) == 10 and ln.split("\t")[2] == "check:e1"]
        check(krows and krows[-1].get("env") == "t" and krows[-1].get("image") == "a" * 16,
              f"E2b the check's receipt names its environment and image: {krows[-1] if krows else None}")
        # F the worker's door: the socket a jail carries. bin/lib/op-env.py is
        # the client, run here as a process against the served socket
        adir_f = spawn_mod.build_attempt(e_rd, "w", ["src/**"], "integration/R", "a-door", "t1",
                                         prog, ["w"])
        client = os.path.join(ROOT, "bin", "lib", "op-env.py")

        def ask(sock_path, *args):
            return subprocess.run([sys.executable, "-I", client, *args], capture_output=True,
                                  text=True, stdin=subprocess.DEVNULL, timeout=240,
                                  env={**os.environ, "OPERATOR_ENV_SOCKET": sock_path})

        door = Door(adir_f, prog, ["t"]).start()
        check(os.path.exists(door.sock) and os.path.isdir(door.work),
              "F0 the door starts with its socket and the seat's staged directory")
        a = ask(door.sock, "--env", "t", "--", "sh", "-c", "echo from-door; pwd")
        check(a.returncode == 0 and a.stdout.startswith("from-door\n")
              and a.stdout.strip().endswith("/work") and "receipt=" in a.stderr,
              f"F1 a jailed client runs a command through the door: rc={a.returncode} out={a.stdout!r} "
              f"err={a.stderr[-160:]!r}")
        write(os.path.join(door.work, "note.txt"), "staged\n")
        a = ask(door.sock, "--env", "t", "--", "sh", "-c", "cat note.txt")
        check(a.returncode == 0 and a.stdout == "staged\n",
              f"F2 what the seat stages under /w/envwork is /work inside: {a.stdout!r}")
        a = ask(door.sock, "--env", "nope", "--", "true")
        check(a.returncode == 1 and "isn't granted to this seat" in a.stderr,
              f"F3 an environment not granted to the seat refuses by name: {a.stderr[-120:]!r}")
        a = ask(door.sock, "--env", "t", "--")
        check(a.returncode == 2, "F3b an empty command is a bad ask")

        def raw(sock_path, obj):
            """Asks the door without the client, so the door's own laws are what answer."""
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(120)
            s.connect(sock_path)
            s.sendall(json.dumps(obj).encode("utf-8"))
            s.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            s.close()
            return json.loads(data.decode("utf-8"))
        a = ask(door.sock, "--env", "t", "--timeout", "x", "--", "true")
        check(a.returncode == 2, "F3c a timeout that isn't seconds is a bad ask")
        r1 = raw(door.sock, {"env": "t", "argv": []})
        r2 = raw(door.sock, {"env": "t", "argv": ["true", 7]})
        r3 = raw(door.sock, {"env": "t", "argv": ["true"] * (MAX_ARGS + 1)})
        check(all("refused" in r and "argv must be" in r["refused"] for r in (r1, r2, r3)),
              f"F3e the door refuses an empty, mixed or overlong argv by name: {[r.get('refused', r)[:40] if isinstance(r.get('refused', r), str) else r for r in (r1, r2, r3)]}")
        a = ask(os.path.join(adir_f, "no.sock"), "--env", "t", "--", "true")
        check(a.returncode == 2 and "no environment socket" in a.stderr,
              "F3d a jail without the socket says so")
        door.close()
        a = ask(door.sock, "--env", "t", "--", "true")
        check(a.returncode == 2, "F4 the door's socket goes with the turn")
        # F5 the seat's budget: spent is refused, and a run is cut to what is left
        door_b = Door(adir_f, prog, ["t"], budget_secs=0.000001).start()
        a = ask(door_b.sock, "--env", "t", "--", "sh", "-c", "sleep 30")
        check(a.returncode == 124, f"F5 a run is cut to the budget that is left: rc={a.returncode}")
        a = ask(door_b.sock, "--env", "t", "--", "true")
        check(a.returncode == 1 and "environment budget is spent" in a.stderr,
              f"F5b a spent budget refuses by name: {a.stderr[-120:]!r}")
        t0b = time.monotonic()
        door_b.close()
        check(time.monotonic() - t0b < 10 and not door_b._thread.is_alive(),
              f"F5c the turn's end is prompt and its thread is gone: {time.monotonic() - t0b:.1f}s")
        # F6 the turn's end is a run's end: an in-flight run is killed
        door_c = Door(adir_f, prog, ["t"]).start()
        box = {}

        def slow():
            box["r"] = ask(door_c.sock, "--env", "t", "--", "sh", "-c", "sleep 40; echo late")

        th = threading.Thread(target=slow)
        th.start()
        time.sleep(1.5)
        t0c = time.monotonic()
        door_c.abort.set()
        th.join(timeout=40)
        a = box.get("r")
        check(a is not None and a.returncode == 125 and "aborted" in a.stderr
              and time.monotonic() - t0c < 25,
              f"F6 a run in flight dies with the turn: rc={getattr(a, 'returncode', None)} "
              f"err={getattr(a, 'stderr', '')[-120:]!r}")
        door_c.close()
        # F7 the door verifies the ruling on every run: an edited environment is
        # an unsigned program, whichever way it is asked for
        write(cpath, charter_text(limits=LIMITS.replace('"64m"', '"32m"')))
        door_d = Door(adir_f, prog, ["t"]).start()
        a = ask(door_d.sock, "--env", "t", "--", "true")
        check(a.returncode == 1 and "not signed" in a.stderr,
              f"F7 an edited environment refuses at the door: {a.stderr[-160:]!r}")
        door_d.close()
        sign()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(base, ignore_errors=True)
    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


# --- first level: the real daemon -------------------------------------------------------


def scratch_image(cli):
    """A local image from the host's static busybox: no registry, no pull."""
    bb = "/bin/busybox"
    ldd = shutil.which("ldd")
    if not (os.path.isfile(bb) and os.access(bb, os.X_OK) and ldd):
        return None
    ldd_out = subprocess.run([ldd, bb], capture_output=True)   # says so on either stream
    if b"not a dynamic executable" not in ldd_out.stdout + ldd_out.stderr:
        return None
    ctx = tempfile.mkdtemp(prefix="envimg.")
    try:
        os.makedirs(os.path.join(ctx, "bin"))
        shutil.copy2(bb, os.path.join(ctx, "bin", "busybox"))
        os.symlink("busybox", os.path.join(ctx, "bin", "sh"))
        with open(os.path.join(ctx, "Dockerfile"), "w") as f:
            f.write("FROM scratch\nCOPY bin /bin\n")
        r = sh([cli, "build", "-q", "-t", "op-env-selftest:local", ctx])
        return r.stdout.strip().splitlines()[-1] if r.returncode == 0 and r.stdout.strip() else None
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


def first_level():
    """The real daemon: the flags hold, the limits kill, the sealed overlay is the
    pin's, and a worker's jail sees no container socket."""
    import ruling as ruling_mod
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    cli = shutil.which("docker")
    if not cli:
        print("first-level: OK (live container arms skipped: no container runtime on this host)")
        return 0
    image = scratch_image(cli)
    if not image or not DIGEST_RE.fullmatch(image):
        print("first-level: OK (live container arms skipped: no static busybox to build a "
              "scratch image from)")
        return 0
    BB = "/bin/busybox"
    old = {k: os.environ.get(k) for k in ENV_KEYS_OF_SUITES}
    base = tempfile.mkdtemp(prefix="environment-fl.")
    try:
        home, key, prog, core = _signed_world(base)
        os.environ.update({"OPERATOR_HOME": home, "RULING_CORE_GIT": core,
                           "OPERATOR_DISK_FLOOR": "0",
                           "CALL_LOG_FILE": os.path.join(home, "call-log.tsv")})
        os.environ.pop("OPERATOR_CONTAINER_CLI", None)
        os.environ.pop("CONTRACT_REPO", None)
        os.environ.pop("CONTRACT_PIN", None)
        work = os.path.join(base, "work")
        os.makedirs(work)
        cpath = os.path.join(prog, CHARTER)

        def sign():
            with contextlib.redirect_stdout(sys.stderr):   # sign() names the record it wrote
                ruling_mod.sign(prog, "arm", None, key)

        def charter_of(ref, **over):
            write(cpath, charter_text(limits='memory = "64m"\n  cpus = 1\n  pids = 32\n  wall = 60',
                                      **over).replace(IMAGE, ref))

        def bb(*steps):
            """busybox applets, each spelled out: a scratch image has no PATH to search."""
            return [BB, "sh", "-c", "; ".join(f"{BB} {s}" for s in steps)]

        charter_of(image)
        try:
            run_env(prog, "t", work, [BB, "true"])
            check(False, "L0 an unsigned program ran")
        except Refused as e:
            check("no arm ruling" in str(e), f"L0 an unsigned program refuses: {e}")
        sign()
        rc, out, meta = run_env(prog, "t", work, bb("id -u > /work/uid", "cat /proc/net/dev > /work/dev",
                                                    "echo hello-from-container"))
        check(rc == 0 and b"hello-from-container" in out, f"L1 the real daemon ran it: rc={rc} out={out!r}")
        check(os.path.exists(os.path.join(work, "uid"))
              and open(os.path.join(work, "uid")).read().strip() == str(os.getuid()),
              "L1b it ran as the spec's user, the engine's own uid, and wrote into the work dir")
        ifs = [ln for ln in open(os.path.join(work, "dev")) if ":" in ln] if os.path.exists(os.path.join(work, "dev")) else []
        check(len(ifs) == 1 and ifs[0].strip().startswith("lo:"), f"L2 no network but loopback: {ifs}")
        rc, out, _ = run_env(prog, "t", work, bb("touch /x 2>/dev/null && echo WRITABLE || echo ro"))
        check(rc == 0 and out.strip() == b"ro", f"L3 the rootfs is read-only: {out!r}")
        rc, out, meta = run_env(prog, "t", work, [BB, "sh", "-c",
                                                  'x=aaaaaaaaaa; while :; do x="$x$x"; done; echo alive'])
        check(rc == 137 and meta["oom"] is True, f"L4 the memory limit kills a runaway: rc={rc} meta={meta}")
        t0 = time.monotonic()
        rc, out, meta = run_env(prog, "t", work, [BB, "sleep", "60"], timeout=2)
        check(rc == 124 and meta["timed_out"] is True and time.monotonic() - t0 < 20,
              f"L5 the wall clock kills a long run: rc={rc} secs={time.monotonic() - t0:.0f}")
        charter_of(ABSENT)
        sign()
        try:
            run_env(prog, "t", work, [BB, "true"])
            check(False, "L6 an absent digest ran")
        except Refused as e:
            check("never pulls" in str(e), f"L6 an absent digest refuses without a pull: {e}")
        # L7 a sealed row's overlay is the pin's, read-only, inside the container
        charter_of(image)
        import contract as contract_mod
        import spawn as spawn_mod
        cmd = f"{BB} cat /w/export/oracle/f; {BB} touch /w/export/oracle/x 2>/dev/null && echo WRITABLE || echo ro"
        write(os.path.join(prog, "contract.toml"),
              "schema = 2\n[[row]]\nid = \"e1\"\nstage = \"s\"\ndesc = \"d\"\nkind = \"run\"\n"
              "seat = \"w\"\nreviewer = \"r\"\ncmd = '" + cmd + "'\noracle = [\"oracle\"]\n"
              "env = \"t\"\nrunner = \"raw\"\ntimeout = 60\n")
        rd, parent, base_sha = spawn_mod._world(home, "w1", {"src/a.py": "v=1\n", "oracle/f": "PIN\n"})
        write(os.path.join(parent, "oracle", "f"), "CANDIDATE\n")
        subprocess.run(["git", "-C", parent, "add", "-A"], capture_output=True, env=_git_env())
        subprocess.run(["git", "-C", parent, "commit", "-qm", "cand"], capture_output=True, env=_git_env())
        cand = subprocess.run(["git", "-C", parent, "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip()
        os.environ.update({"CONTRACT_REPO": parent, "CONTRACT_PIN": base_sha})
        sign()   # as a run's own arm ruling is signed
        try:
            row = contract_mod.load(prog)["by_id"]["e1"]
            r_rc, r_file, _cid = contract_mod.run_check(row, prog, parent, cand, "arm-fl", {}, "prog-fl")
        finally:
            os.environ.pop("CONTRACT_REPO", None)
            os.environ.pop("CONTRACT_PIN", None)
        tail = open(r_file, "rb").read() if r_file and os.path.exists(r_file) else b""
        check(r_rc == 0 and tail.split() == [b"PIN", b"ro"],
              f"L7 the sealed overlay is the pin's and read-only: rc={r_rc} out={tail!r}")
        with open(os.environ["CALL_LOG_FILE"], encoding="utf-8") as f:
            krows = [dict(kv.split("=", 1) for kv in ln.split("\t")[3].split(","))
                     for ln in f.read().splitlines() if ln.split("\t")[2] == "check:e1"]
        check(krows and krows[-1].get("env") == "t" and krows[-1].get("image") == image.rsplit(":", 1)[-1][:16],
              f"L7b the check's receipt names its environment and image: {krows[-1] if krows else None}")
        # L8 a worker's jail sees no container socket
        sys.path.insert(0, os.path.join(ROOT, "bin", "lib"))
        from jail import bwrap_args  # noqa: E402
        probe = ('for p in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock; '
                 'do [ -e "$p" ] && exit 3; done; exit 0')
        r8 = subprocess.run(bwrap_args(chdir="/", etc=False) + ["/bin/sh", "-c", probe],
                            capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
        check(r8.returncode == 0,
              f"L8 a worker-shaped jail sees no container socket: rc={r8.returncode} {r8.stderr[-200:]!r}")
        # L9 the whole way: a jailed seat's client -> the door -> the real daemon
        write(os.path.join(prog, "team.toml"),
              TEAM.replace('write = ["src/**"]\n', 'write = ["src/**"]\nenv = ["t"]\n', 1))
        sign()
        rd9, _p9, _ = spawn_mod._world(home, "w9", {"src/a.py": "v=1\n"})
        adir9 = spawn_mod.build_attempt(rd9, "w", ["src/**"], "integration/R", "a9", "t1", prog, ["w"])
        write(os.path.join(adir9, "repo", "ask.py"),
              "import subprocess, sys\n"
              "r = subprocess.run([sys.executable, '-I', '/engine/op-env.py', '--env', 't', '--', "
              "'/bin/busybox', 'echo', 'from-a-jailed-seat'])\n"
              "open('/w/envwork/staged.txt', 'w').write('staged by the worker\\n')\n"
              "r2 = subprocess.run([sys.executable, '-I', '/engine/op-env.py', '--env', 't', '--', "
              "'/bin/busybox', 'cat', '/work/staged.txt'])\n"
              "r3 = subprocess.run([sys.executable, '-I', '/engine/op-env.py', '--env', 'nope', '--', "
              "'/bin/busybox', 'true'], capture_output=True, text=True)\n"
              "print('GRANT-REFUSED' if r3.returncode == 1 and \"isn't granted\" in r3.stderr\n"
              "      else 'GRANT-LEAK rc=%s %r' % (r3.returncode, r3.stderr[-120:]))\n"
              "sys.exit(max(r.returncode, r2.returncode))\n")
        with contextlib.redirect_stdout(sys.stderr):
            spawn_mod.compose_brief(adir9)
            spawn_mod.cmd_worker(adir9, 240, ["python3", "-I", "/w/repo/ask.py"])
        t9 = open(os.path.join(adir9, "transcript.out"), encoding="utf-8", errors="replace").read()
        check("from-a-jailed-seat" in t9 and "staged by the worker" in t9 and "GRANT-REFUSED" in t9,
              f"L9 a jailed seat reached its environment through the door: {t9[-300:]!r}")
        check(not os.path.exists(open(os.path.join(adir9, "envd", "sock")).read().strip()),
              "L9b the turn's end closed the door")
    finally:
        sh([cli, "rmi", "-f", "op-env-selftest:local"])
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(base, ignore_errors=True)
    print(f"first-level: OK ({ok[0]} checks, live container arms)" if ok[0] and not bad[0]
          else "first-level: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (Finding, Refused) as e:
        die(str(e), 1)
    except Locked as e:
        die(str(e), 3)
    except Void as e:
        die(str(e), 2)
    except OSError as e:
        print(f"environment: VOID: {e}", file=sys.stderr)
        sys.exit(2)
