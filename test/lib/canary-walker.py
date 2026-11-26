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


def scan(path):
    if os.path.abspath(path) in SKIP:
        return
    try:
        with open(path, "rb") as f:
            if mark in f.read(1 << 16):
                hits.append(path)
    except OSError:
        pass


for dirpath, dirnames, files in os.walk(root):
    if dirpath.startswith(("/proc", "/sys", "/dev")):
        dirnames[:] = []
        continue
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

print(f"canary-hits={len(hits)}")
for p in hits[:5]:
    print("HIT", p)
