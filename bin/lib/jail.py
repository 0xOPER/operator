"""jail -- the one bwrap builder every jail in the engine uses.

contract.py's run_check and spawn.py's worker jails both build on this, so the jail's
promises live in exactly one place:

- The environment is CLEARED before the setenvs, so nothing of the operator's —
  credentials included — reaches jailed code.
- The jail is a new session with every capability dropped, so the jailed command is
  detached from the spawner's process group and holds no privilege it could grow into.
- Binds that need mountpoints come before the remounts; the remounts touch only the
  mounts they name, so the export stays writable and the ro binds stay read-only.
  etc=False drops the wholesale /etc bind for jails that bind generated files over the
  identifiers instead (the worker jail: the host's /etc never enters it at all).
- /usr/local is a tmpfs when it exists, and machine-id and hostname are generated, so
  the host's live tooling and identifiers never leak.
- The network namespace is unshared; /proc shows the jail its own lonely loopback.
- The jailed process dies with its parent (--die-with-parent).
- Output is capped and drained past the cap, so the jailed command keeps its own exit
  code no matter how much it writes; the deadline is enforced here, TERM then KILL.

This is a library, not a tool: its arms are the first-level suites of the tools that
use it (contract.py --first-level, and spawn's when it lands).

usage: from jail import bwrap_args, run_capped        (importable; no __main__ behaviour)
"""
import os
import re
import select
import subprocess
import sys
import tempfile
import time

TMPFS_SIZE = "67108864"  # 64 MiB: the same bound the prototypes ran under


def nvidia_nodes(dev="/dev"):
    """The nvidia device nodes a CUDA workload needs, or [] when the host has
    none (the caller refuses, naming the fix -- never a mysterious CUDA init
    failure). The cards, the control and uvm nodes are required; the caps
    directory (NVENC/NVDEC sessions open its nodes) and the aux nodes ride when
    they exist. Binds made from these land as their own mounts inside the
    jail's fresh /dev, past its read-only remount -- a device node a jailed
    CUDA runtime can actually open."""
    if not os.path.isdir(dev):
        return []
    cards = sorted(n for n in os.listdir(dev) if re.fullmatch(r"nvidia\d+", n))
    if not cards or not (os.path.exists(os.path.join(dev, "nvidiactl"))
                         and os.path.exists(os.path.join(dev, "nvidia-uvm"))):
        return []
    out = [os.path.join(dev, "nvidiactl"), os.path.join(dev, "nvidia-uvm")]
    out += [os.path.join(dev, c) for c in cards]
    for opt in ("nvidia-uvm-tools", "nvidia-modeset", "nvidia-caps"):
        if os.path.exists(os.path.join(dev, opt)):
            out.append(os.path.join(dev, opt))
    return out


def bwrap_args(binds=(), setenvs=(("HOME", "/tmp"), ("PATH", "/usr/bin:/bin")),
               chdir="/w/export", export=None, export_dest="/w/export", etc=True):
    """The standard jail argv, up to the command. binds are flat bwrap pairs.
    export (a host path) is mounted writable at export_dest; chdir lands inside it.
    etc=False leaves /etc to the caller's binds (the worker jail binds generated files
    over the identifiers, and nothing else of the host's /etc enters)."""
    args = ["bwrap", "--clearenv", "--die-with-parent", "--new-session",
            "--cap-drop", "ALL"]
    if etc:
        args += ["--ro-bind", "/etc", "/etc"]
    else:
        args += ["--ro-bind-try", "/etc/alternatives", "/etc/alternatives"]
    has_usr_local = os.path.isdir("/usr/local")
    args += ["--ro-bind", "/usr", "/usr",
             "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
             "--symlink", "usr/lib", "/lib", "--proc", "/proc", "--dev", "/dev",
             "--size", TMPFS_SIZE, "--tmpfs", "/tmp", "--size", TMPFS_SIZE, "--tmpfs", "/dev/shm",
             *(["--symlink", "usr/lib64", "/lib64"] if os.path.exists("/lib64") else []),
             *(["--size", TMPFS_SIZE, "--tmpfs", "/usr/local"] if has_usr_local else []),
             "--unshare-user", "--disable-userns",
             "--unshare-ipc", "--unshare-uts", "--hostname", "engine-jail",
             "--unshare-pid", "--unshare-cgroup-try", "--unshare-net"]
    if export is not None:
        args += ["--bind", export, export_dest]
    args += list(binds)
    args += ["--remount-ro", "/dev", "--remount-ro", "/"]
    if has_usr_local:
        args += ["--remount-ro", "/usr/local"]
    for k, v in setenvs:
        args += ["--setenv", k, v]
    if chdir:
        args += ["--chdir", chdir]
    args += ["--"]
    return args


def generated_etc(tmp):
    """passwd, hosts, machine-id and hostname written into tmp; the caller binds each
    read-only over the jail's /etc so the host's never leak."""
    d = os.path.join(tmp, "etc")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "passwd"), "w") as f:
        f.write("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n")
    with open(os.path.join(d, "hosts"), "w") as f:
        f.write("127.0.0.1 localhost\n")
    with open(os.path.join(d, "machine-id"), "w") as f:
        f.write("engine-jail\n")
    with open(os.path.join(d, "hostname"), "w") as f:
        f.write("engine-jail\n")
    return d


def run_capped(argv, timeout, cap):
    """Runs argv with stdout and stderr merged, keeping the first cap bytes and draining
    the rest so the writer never blocks. Past the deadline: TERM, then KILL five
    seconds later, rc 124. Returns (rc, kept)."""
    try:
        # pid-1 environ law (the C1 fold, now reaching the check jail):
        # bwrap IS pid 1 in the jail and its /proc/1/environ is readable from
        # inside, so the engine's own env never rides it -- a minimal env
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             env={"PATH": "/usr/bin:/bin", "HOME": "/tmp",
                                  "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    except FileNotFoundError:
        raise SystemExit("jail: bwrap not found; nothing runs without its sandbox")
    deadline = time.monotonic() + timeout
    kept = bytearray()
    fd = p.stdout.fileno()
    timed_out = False
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            timed_out = True
            break
        ready, _, _ = select.select([fd], [], [], min(left, 5))
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        if len(kept) < cap:
            kept.extend(chunk[: cap - len(kept)])
    if timed_out:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        return 124, bytes(kept)
    rem = max(5.0, deadline - time.monotonic())
    try:
        return p.wait(timeout=rem), bytes(kept)
    except subprocess.TimeoutExpired:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        return 124, bytes(kept)
