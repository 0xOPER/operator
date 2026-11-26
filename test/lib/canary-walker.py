#!/usr/bin/env python3
"""canary-walker -- count canary markers across everything a jail can see.

Walks the filesystem (bounded files, /proc /sys /dev excluded from the walk
and covered explicitly), then every process's environ and cmdline. Prints
one counter line and up to five hit paths. Used host-side by the selftest
and jailed by test/canary-walk.sh; it only ever READS.

usage: canary-walker.py <mark-file>  (or env CANARY_MARK; WALK_ROOT default /)
exit: 0 always -- the caller reads the counter
"""
import os
import signal
import sys

sys.dont_write_bytecode = True

root = os.environ.get("WALK_ROOT", "/")
src = sys.argv[1] if len(sys.argv) > 1 else None
if src and os.path.isfile(src):
    with open(src, "rb") as f:
        mark = f.read().strip()
    SKIP = {os.path.abspath(src)}  # the marker's own carrier is not a leak
else:
    mark = os.environ["CANARY_MARK"].encode()
    SKIP = set()
hits = []
scanned = [0]
cur_dir = [root]


def _on_term(_signum, _frame):
    print(f"canary-timeout dir={cur_dir[0]} scanned={scanned[0]} hits={len(hits)}", flush=True)
    sys.exit(124)


signal.signal(signal.SIGTERM, _on_term)


def scan(path):
    if os.path.abspath(path) in SKIP:
        return
    scanned[0] += 1
    try:
        with open(path, "rb") as f:
            if mark in f.read(1 << 16):
                hits.append(path)
    except OSError:
        pass


for dirpath, dirnames, files in os.walk(root):
    cur_dir[0] = dirpath
    if dirpath.startswith(("/proc", "/sys", "/dev")):
        dirnames[:] = []
        continue
    if root == "/" and dirpath == "/usr":
        # /usr is the read-only OS package tree (750k+ SDK files on CI runners);
        # still descend into /usr/local while skipping static OS package dirs.
        dirnames[:] = [d for d in dirnames if d == "local"]
    for fn in files:
        p = os.path.join(dirpath, fn)
        try:
            if os.path.getsize(p) > (1 << 16):
                continue
        except OSError:
            continue
        scan(p)
if os.environ.get("WALK_PROC", "1") != "0":
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        for limb in ("environ", "cmdline"):
            scan(f"/proc/{pid}/{limb}")

print(f"canary-scanned={scanned[0]}", flush=True)
print(f"canary-hits={len(hits)}", flush=True)
for p in hits[:5]:
    print("HIT", p, flush=True)
