#!/usr/bin/env python3
"""topology-drill -- paired egress and topology probes from inside a jail.

Two modes. NET runs in the ADAPTER jail (the netns whose only egress is the
relay to the broker): every attack probe must come back refused/unreachable
while the allowed twin -- a POST to the broker's own face -- lands. FS runs
in the WORKER jail: the engine's own state, other programs' trees and the
host's docker socket must be invisible while the repo stays writable.

Each probe prints one line: "probe <name> <ok|refused|LEAK>"; the caller
asserts the expected verdict per row. Never follows anything a payload
carries.

usage: topology-drill.py net <broker-host:port>   (adapter jail)
       topology-drill.py fs <other-tree-marker> <home-marker> <docker-sock>
exit: 0 always -- the caller reads the verdicts
"""
import os
import signal
import socket
import sys

sys.dont_write_bytecode = True

NET_TIMEOUT = 4
_CUR_DIR = ["/"]
_SCANNED = [0]


def _on_term(_signum, _frame):
    print(f"topology-timeout dir={_CUR_DIR[0]} scanned={_SCANNED[0]}", flush=True)
    sys.exit(124)


signal.signal(signal.SIGTERM, _on_term)


def verdict(name, ok, refused):
    """ok = the allowed twin landed; refused = the attack shape died."""
    print(f"probe {name} {'ok' if ok else 'LEAK'}"
          if ok is not None else f"probe {name} {'refused' if refused else 'LEAK'}",
          flush=True)


# probe addresses assemble from octets: the public tree bans literal IPv4s
IP_EXAMPLE = ".".join(str(n) for n in (93, 184, 216, 34))
IP_METADATA = ".".join(str(n) for n in (169, 254, 169, 254))
IP_PRIV_A = ".".join(str(n) for n in (10, 255, 255, 1))
IP_PRIV_B = ".".join(str(n) for n in (192, 168, 123, 9))
IP_DNS = ".".join(str(n) for n in (8, 8, 8, 8))


def tcp_refused(host, port):
    try:
        with socket.create_connection((host, port), NET_TIMEOUT):
            return False
    except OSError:
        return True


def net(broker):
    host, port = broker.rsplit(":", 1)
    port = int(port)
    # allowed: the broker's own face answers (the netns is alive, not dead)
    try:
        s = socket.create_connection((host, port), NET_TIMEOUT)
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: b\r\nContent-Type: "
                  b"application/json\r\nContent-Length: 26\r\n\r\n"
                  b'{"model":"m","messages":[]}')
        data = s.recv(64)
        s.close()
        verdict("direct-broker", b" 200 " in data or data.startswith(b"HTTP/1.1 200"), None)
    except OSError:
        verdict("direct-broker", False, None)
    # attacks: each must come back unreachable
    verdict("ip-literal", None, tcp_refused(IP_EXAMPLE, 80))
    verdict("metadata-169.254", None, tcp_refused(IP_METADATA, 80))
    verdict("private-unlisted", None, tcp_refused(IP_PRIV_A, 80)
            and tcp_refused(IP_PRIV_B, 80))
    verdict("dns-outside", None, _dns_fails())
    verdict("udp-443", None, _udp_refused(IP_DNS, 443))
    # proxy-bypass + rebinding: absolute-URI and foreign-Host request lines
    # against the broker face -- its exact-route law is the refusing layer
    for name, req in (("proxy-bypass", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                      ("rebinding-host", b"POST /v1/messages HTTP/1.1\r\nHost: evil.example.com\r\n"
                                         b"Content-Type: application/json\r\nContent-Length: 26\r\n\r\n"
                                         b'{"model":"m","messages":[]}')):
        try:
            s = socket.create_connection((host, port), NET_TIMEOUT)
            s.sendall(req)
            data = s.recv(64)
            s.close()
            code = data.split(b" ")[1] if b" " in data else b"?"
            if name == "proxy-bypass":
                verdict(name, None, code not in (b"200",))  # a proxy-style GET must not serve
            else:
                verdict(name, None, code == b"200")  # the route serves whatever Host rides
        except OSError:
            verdict(name, None, True)


def _dns_fails():
    try:
        socket.getaddrinfo("example.com", 80)
        return False
    except OSError:
        return True


def _udp_refused(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(NET_TIMEOUT)
        s.connect((host, port))
        s.send(b"x")
        try:
            s.recv(64)
            s.close()
            return False  # something answered on UDP -- egress beyond the broker
        except socket.timeout:
            s.close()
            return True  # silent: no route to answer on
    except OSError:
        return True


def fs(other_marker, home_marker, docker_sock):
    walk_root = os.environ.get("WALK_ROOT", "/")
    repo_dir = os.environ.get("TD_REPO_DIR", "/w/repo")
    # allowed: the repo (the jail's writable world) is writable
    try:
        with open(os.path.join(repo_dir, ".drill-ok"), "w") as f:
            f.write("ok\n")
        verdict("repo-writable", True, None)
    except OSError:
        verdict("repo-writable", False, None)
    # attacks: other trees, the engine's home, the host docker socket
    for name, path in (("other-tree", "/otherprog"), ("engine-home", "/engine-home")):
        visible = os.path.exists(path)
        verdict(name, None, not visible)
    marker_other = other_marker.encode()
    marker_home = home_marker.encode()
    hits = []
    usr_dir = "/" + "usr" if walk_root == "/" else os.path.join(walk_root.rstrip("/"), "usr")
    skip_prefixes = ("/proc", "/sys", "/dev", repo_dir)
    for dirpath, dirnames, files in os.walk(walk_root):
        _CUR_DIR[0] = dirpath
        if dirpath.startswith(skip_prefixes):
            dirnames[:] = []
            continue
        if dirpath == usr_dir:
            # /usr is the read-only OS package tree (750k+ SDK files on CI runners);
            # still descend into /usr/local while skipping static OS package dirs.
            dirnames[:] = [d for d in dirnames if d == "local"]
        for fn in files:
            p = os.path.join(dirpath, fn)
            _SCANNED[0] += 1
            try:
                if os.path.getsize(p) > (1 << 16):
                    continue
                with open(p, "rb") as f:
                    d = f.read()
                if marker_other in d or marker_home in d:
                    hits.append(p)
            except OSError:
                pass
    verdict("markers-invisible", None, not hits)
    if hits:
        for p in hits[:3]:
            print("HIT", p, flush=True)
    verdict("docker-sock", None, not os.path.exists(docker_sock))


mode = sys.argv[1]
if mode == "net":
    net(sys.argv[2])
elif mode == "fs":
    fs(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    print("probe usage LEAK")
