#!/usr/bin/env python3
"""egress-proxy -- the only door out of a jail, and the relay that reaches it.

`serve` binds a Unix socket (basename bound after chdir: a socket path lives or
dies by AF_UNIX's 107 bytes) and answers one request per connection, the P box
proxy's law intact: CONNECT is for port 443 and the TLS ClientHello must name
the host it asked for; plain HTTP is setup-only on port 80; the host must be on
the boundary's list; resolution happens here, proxy-side, and every address the
host resolves to must be global (ipaddress decides -- no range literals in this
tree) and not one this machine holds. A deny rule beats any allow, a rule with
` until <UTC>` stops matching the moment it passes, and each connection writes
exactly one log row, its reason stripped of control characters. A full log
refuses everything. `relay` is the in-jail leg: CLIs speak HTTP(S)_PROXY over
TCP to a lonely loopback, and the relay pumps each connection to the socket.

usage: egress-proxy.py serve <sock-dir> <policy> <log> [--name NAME]   default name proxy.sock
       egress-proxy.py relay <sock-path> [--port N]                    default port 3128
       egress-proxy.py --selftest
policy: one rule per line, case-blind. `host`, `.domain` for subdomains, `*`,
        `!` before any of those denies it (deny beats allow), `setup` allows
        plain HTTP on port 80, ` until 2006-01-02T15:04:05Z` expires a rule,
        and `pin <host> <addr> <port>` is the operator vouching for an address:
        that host connects exactly there, no DNS, the log row says pinned, and
        every other law (port, SNI, deny, expiry) still applies.
exit: 0 served until killed / relayed, 1 a connection was refused (never), 2 usage or VOID
"""
import fcntl
import ipaddress
import os
import re
import select
import socket
import sys
import threading
import time

sys.dont_write_bytecode = True

HEAD_MAX = 16384
IDLE = 600
DRAIN = 30
SLOTS = 64
LOG_MAX = 200 * 1024 * 1024  # a full log refuses everything; rotate by hand
LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
NAME = re.compile(rf"{LABEL}(\.{LABEL})*")
HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:")
DROP = (b"host:", b"connection:", b"proxy-connection:", b"keep-alive:",
        b"proxy-authorization:", b"upgrade:", b"te:")
STAMP = "%Y-%m-%dT%H:%M:%SZ"


class Refused(Exception):
    pass


class Void(Exception):
    pass


def parse_until(text):
    """The epoch of an RFC3339-UTC stamp, or None when it won't parse."""
    import calendar
    try:
        return calendar.timegm(time.strptime(text, STAMP))
    except (ValueError, OverflowError):
        return None


def load_policy(path):
    """(rules with optional expiry, pins, setup). Re-read per connection."""
    rules, pins, setup = [], {}, False
    try:
        with open(path, encoding="ascii") as f:
            body = f.read()
    except OSError as e:
        raise Void(f"the boundary won't read: {e}")
    for line in body.splitlines():
        line = line.strip().lower()
        if line == "setup":
            setup = True
        elif line.startswith("pin "):
            parts = line.split()
            if len(parts) != 4 or not NAME.fullmatch(parts[1]) \
                    or not parts[3].isdigit():
                raise Void(f"a pin line won't parse: {line!r}")
            try:
                ipaddress.ip_address(parts[2])
            except ValueError:
                raise Void(f"a pin names something that isn't an address: {line!r}")
            pins[parts[1]] = (parts[2], int(parts[3]))
        elif line and not line.startswith("#"):
            until = None
            if " until " in line:
                line, _, stamp = line.partition(" until ")
                until = parse_until(stamp.strip())
                if until is None:
                    raise Void(f"a rule carries a stamp that won't parse: {stamp!r}")
            rules.append((line, until))
    return rules, pins, setup


def rule_matches(host, rule):
    """`*`, exact, or a leading-dot subdomain rule (subdomains only)."""
    return rule == "*" or host == rule or (rule.startswith(".") and host.endswith(rule))


def allowed(host, rules, now=None):
    """Deny beats allow; an expired allow rule matches nothing and says why."""
    now = now if now is not None else time.time()
    for rule, until in rules:
        if rule.startswith("!") and rule_matches(host, rule[1:]):
            if until is None or now <= until:
                return False, "deny"
    for rule, until in rules:
        if rule.startswith("!"):
            continue
        if rule_matches(host, rule):
            if until is not None and now > until:
                return False, "the rule for this host expired"
            return True, ""
    return False, "not on the boundary"


def resolve(host, port):
    return socket.getaddrinfo(host, port, family=socket.AF_INET,
                              type=socket.SOCK_STREAM)


def is_local(addr):
    """True if this host holds addr: only a local address can be bound."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((addr, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def public_addrs(host, port, resolve_fn, local):
    try:
        addrs = list(dict.fromkeys(i[4][0] for i in resolve_fn(host, port)))
    except (OSError, UnicodeError):
        raise Refused("doesn't resolve")
    if not addrs:
        raise Refused("doesn't resolve")
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if not ip.is_global or ip.is_multicast or local(a):
            raise Refused("resolves to an address that isn't public")
    return addrs


def connect(addrs, port):
    err = OSError("no address")
    for a in addrs:
        try:
            s = socket.create_connection((a, port), timeout=15)
            s.settimeout(IDLE)
            return s
        except OSError as e:
            err = e
    raise err


def sni(record):
    """The host name in a TLS ClientHello record, or None."""
    try:
        if record[0] != 0x16 or record[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32
        p += 1 + record[p]
        p += 2 + int.from_bytes(record[p:p + 2], "big")
        p += 1 + record[p]
        end = p + 2 + int.from_bytes(record[p:p + 2], "big")
        p += 2
        while p + 4 <= end:
            etype = int.from_bytes(record[p:p + 2], "big")
            elen = int.from_bytes(record[p + 2:p + 4], "big")
            if etype == 0:
                body = record[p + 4:p + 4 + elen]
                if body[2] != 0:
                    return None
                n = int.from_bytes(body[3:5], "big")
                return body[5:5 + n].decode("ascii")
            p += 4 + elen
    except (IndexError, UnicodeDecodeError):
        return None
    return None


def hello(name):
    """A TLS ClientHello record naming `name` (or no SNI when None)."""
    ext = b""
    if name is not None:
        n = name.encode()
        entry = b"\x00" + len(n).to_bytes(2, "big") + n
        sni_body = len(entry).to_bytes(2, "big") + entry
        ext = b"\x00\x00" + len(sni_body).to_bytes(2, "big") + sni_body
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def safe(s):
    return "".join(c if c.isalnum() or c in ".:-_" else "?" for c in str(s))[:120]


class Conn:
    """One client connection over a socket (the relay's TCP side, or serve's)."""

    def __init__(self, sock):
        self.sock, self.buf = sock, b""
        self.host, self.port, self.tunnel = "-", 0, False

    def read_until(self, mark, limit):
        while mark not in self.buf:
            if len(self.buf) > limit:
                return None
            if not select.select([self.sock], [], [], 30)[0]:
                return None
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        head, _, self.buf = self.buf.partition(mark)
        return head

    def read_exact(self, n):
        while len(self.buf) < n:
            if not select.select([self.sock], [], [], 30)[0]:
                return None
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def write(self, data):
        self.sock.sendall(data)


def relay_bytes(conn, up, first):
    """Pump bytes both ways. The client closing half-closes upstream so a reply
    still in flight arrives."""
    pending, conn.buf = first + conn.buf, b""
    up.sendall(pending)
    sent, recv = len(pending), 0
    watch = [conn.sock, up]
    while True:
        r, _, _ = select.select(watch, [], [], IDLE if conn.sock in watch else DRAIN)
        if not r:
            break
        if conn.sock in r:
            data = conn.sock.recv(65536)
            if data:
                up.sendall(data)
                sent += len(data)
            else:
                watch.remove(conn.sock)
                try:
                    up.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        if up in r:
            data = up.recv(65536)
            if not data:
                break
            conn.write(data)
            recv += len(data)
    return sent, recv


def handle(conn, policy, resolve_fn, connect_fn, local):
    """One client connection. Returns (sent, received), or raises Refused."""
    rules, pins, setup = policy
    head = conn.read_until(b"\r\n\r\n", HEAD_MAX)
    if head is None:
        raise Refused("no request head")
    lines = head.split(b"\r\n")
    if any(b"\r" in ln or b"\n" in ln for ln in lines):
        raise Refused("bare CR or LF in the request head")
    try:
        method, target, version = lines[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError):
        raise Refused("bad request line")
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise Refused("bad request line")
    if method == "CONNECT":
        host, _, port = target.rpartition(":")
        if port != "443":
            raise Refused("CONNECT is for port 443 only")
    elif method in ("GET", "HEAD") and target.startswith("http://"):
        if not setup:
            raise Refused("plain HTTP is for setup only")
        hostport, _, path = target[len("http://"):].partition("/")
        host, _, port = hostport.partition(":")
        if port not in ("", "80"):
            raise Refused("plain HTTP is for port 80 only")
        if not all(HEADER.match(ln) for ln in lines[1:]):
            raise Refused("bad header line")
        if any(ln.lower().startswith((b"content-length:", b"transfer-encoding:"))
               for ln in lines[1:]):
            raise Refused("plain HTTP GET/HEAD may not carry a request body")
    else:
        raise Refused(f"method {safe(method)} isn't allowed")
    conn.host, conn.port = host.lower().rstrip("."), 443 if method == "CONNECT" else 80
    host = conn.host
    if len(host) > 253 or not NAME.fullmatch(host):
        raise Refused("bad host name")
    ok, why = allowed(host, rules)
    if not ok:
        raise Refused(why)
    pinned = pins.get(host)
    conn.pinned = pinned[0] if pinned else None
    addrs = [pinned[0]] if pinned else public_addrs(host, conn.port, resolve_fn,
                                                    local)
    if method == "CONNECT":
        conn.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        conn.tunnel = True
        hdr = conn.read_exact(5)
        if hdr is None:
            raise Refused("no TLS record")
        body = conn.read_exact(int.from_bytes(hdr[3:5], "big"))
        if body is None:
            raise Refused("short TLS record")
        first = hdr + body
        name = sni(first)
        if name is None or name.lower().rstrip(".") != host:
            raise Refused(f"TLS names {safe(name or 'nothing')}")
        up = connect_fn([addrs[0]], pinned[1] if pinned else conn.port)
        try:
            return relay_bytes(conn, up, first)
        finally:
            up.close()
    else:
        kept = [ln for ln in lines[1:] if not ln.lower().startswith(DROP)]
        first = b"\r\n".join([f"{method} /{path} {version}".encode(),
                              f"Host: {host}".encode(), *kept,
                              b"Connection: close", b"", b""])
        up = connect_fn([addrs[0]], pinned[1] if pinned else conn.port)
        try:
            # Plain HTTP GET/HEAD sends rewritten headers ONLY and never forwards
            # client body or pipelined bytes upstream (defeating exfil/smuggling).
            up.sendall(first)
            sent = len(first)
            try:
                up.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            recv = 0
            while True:
                data = up.recv(65536)
                if not data:
                    break
                conn.write(data)
                recv += len(data)
            return sent, recv
        finally:
            up.close()


def take_slot(dirpath):
    os.makedirs(dirpath, mode=0o700, exist_ok=True)
    for i in range(SLOTS):
        fd = os.open(os.path.join(dirpath, str(i)), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            os.close(fd)
    return None


def reply(conn, code, reason):
    if conn.tunnel:
        return
    body = (reason + "\n").encode("ascii", "replace")
    try:
        conn.write(b"HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %d"
                   b"\r\nConnection: close\r\n\r\n%s" % (code, len(body), body))
    except OSError:
        pass


def one_connection(sock, policy_path, log_path, resolve_fn, connect_fn, local):
    """Serve one client: verdict, reply, exactly one log row."""
    conn, t0 = Conn(sock), time.time()
    conn.pinned = None
    verdict, reason, sent, recv = "allowed", "", 0, 0
    log_full = False
    slot = take_slot(os.path.join(os.path.dirname(os.path.abspath(log_path)),
                                  "proxy-slots"))
    try:
        if os.path.exists(log_path) and os.path.getsize(log_path) > LOG_MAX:
            log_full = True
            raise Refused("the proxy log is full")
        try:  # an unwritable log would serve traffic no row remembers: refuse
            probe = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.close(probe)
        except OSError as e:
            raise Refused(f"the log can't be written: {e.strerror}")
        if slot is None:
            raise Refused("too many connections")
        sent, recv = handle(conn, load_policy(policy_path), resolve_fn, connect_fn,
                            local)
    except Refused as e:
        verdict, reason = "refused", str(e)
        reply(conn, b"403 Forbidden", reason)
    except Void as e:
        verdict, reason = "refused", f"the boundary won't load: {e}"
        reply(conn, b"403 Forbidden", reason)
    except Exception as e:  # every connection gets its log row, whatever broke
        verdict, reason = "error", type(e).__name__
        reply(conn, b"502 Bad Gateway", reason)
    finally:
        if slot is not None:
            os.close(slot)
        # the row lands BEFORE the socket closes: a client that saw EOF must
        # never be able to outrun the record of its own connection (except when
        # the log is already past LOG_MAX, so a looping client cannot fill disk)
        pin_tag = f" pinned={safe(conn.pinned)}" if conn.pinned else ""
        line = (f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {verdict} "
                f"{safe(conn.host)}:{conn.port} sent={sent} recv={recv} "
                f"secs={time.time() - t0:.1f}{pin_tag} {safe(reason).replace('?', ' ')}\n")
        try:
            if not log_full:
                fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                os.write(fd, line.encode("ascii"))
                os.close(fd)
        finally:
            try:
                sock.close()
            except OSError:
                pass


def serve(sock_dir, policy_path, log_path, name="proxy.sock"):
    if len(name) + 1 > 107:
        raise Void("the socket name is longer than AF_UNIX's 107 bytes")
    os.makedirs(sock_dir, mode=0o700, exist_ok=True)
    here = os.getcwd()
    os.chdir(sock_dir)  # bind the basename: the path law of AF_UNIX
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(name)
        os.chmod(name, 0o600)
    finally:
        os.chdir(here)
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=one_connection, args=(c, policy_path, log_path,
                                                      resolve, connect, is_local),
                         daemon=True).start()


def pump(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay(sock_path, port):
    """The in-jail leg: TCP on the lonely loopback, every connection pumped to
    the one Unix socket bound into the jail."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(srv.getsockname()[1], flush=True)

    def one(c):
        try:
            u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            u.connect(sock_path)
        except OSError:
            c.close()
            return
        t = threading.Thread(target=pump, args=(u, c), daemon=True)
        t.start()
        pump(c, u)
        t.join(timeout=DRAIN)
        c.close()
        u.close()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def main(argv):
    if len(argv) >= 5 and argv[1] == "serve":
        name = "proxy.sock"
        if "--name" in argv:
            i = argv.index("--name")
            if i + 1 >= len(argv):
                return 2
            name = argv[i + 1]
        try:
            serve(argv[2], argv[3], argv[4], name)
        except Void as e:
            print(f"egress-proxy: VOID, {e}", file=sys.stderr)
            return 2
        except OSError as e:
            print(f"egress-proxy: VOID, can't serve: {e}", file=sys.stderr)
            return 2
    if len(argv) >= 3 and argv[1] == "relay":
        port = 3128
        if "--port" in argv:
            i = argv.index("--port")
            if i + 1 >= len(argv):
                return 2
            port = int(argv[i + 1])
        try:
            relay(argv[2], port)
        except OSError as e:
            print(f"egress-proxy: VOID, can't relay: {e}", file=sys.stderr)
            return 2
    print("usage: egress-proxy.py serve <sock-dir> <policy> <log> [--name NAME] | "
          "relay <sock-path> [--port N] | --selftest", file=sys.stderr)
    return 2


def selftest():
    """Room-safe, no network: the boundary's law against a fake resolver --
    private, multicast and local addresses refused; the port rules; deny over
    allow; expiry; exactly one log row per CONNECT with control characters
    stripped; serve over a Unix socket and the relay's TCP leg, refused end to
    end. Addresses are spelled as hex ints: this tree carries no literals."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    import shutil as _sh
    import subprocess
    import tempfile
    import threading
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    # hex-spelled: a global unicast, a private 10/8, a private 192.168/16, multicast
    PUB, PRV10, PRV192, MCAST = (str(ipaddress.ip_address(h)) for h in
                                 (0x08080808, 0x0A000001, 0xC0A80101, 0xE0000001))

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    got = []

    def serve_upstream():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = b""
            while True:
                chunk = c.recv(65536)
                if not chunk:
                    break
                data += chunk
            got.append(data)
            c.sendall(b"PONG")
            c.close()
    threading.Thread(target=serve_upstream, daemon=True).start()
    up_port = srv.getsockname()[1]

    def lport_of(_srv):
        return up_port

    hosts = {"ok.test": PUB, "sub.ok.test": PUB, "loop.test": "127.0.0.1",
             "lan.test": PRV10, "lan2.test": PRV192, "multi.test": MCAST,
             "mixed.test": (PUB, PRV10)}

    def fake_resolve(host, p):
        if host not in hosts:
            raise OSError("no such host")
        addrs = hosts[host] if isinstance(hosts[host], tuple) else (hosts[host],)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, p)) for a in addrs]

    def fake_connect(_addrs, _port):
        return socket.create_connection(("127.0.0.1", up_port), timeout=5)

    def run(request, rules=("ok.test",), setup=False, local=lambda a: False):
        rules = [(r, None) if isinstance(r, str) else r for r in rules]
        a, b = socket.socketpair()
        conn = Conn(a)
        b.sendall(request)
        b.shutdown(socket.SHUT_WR)
        try:
            out = ("allowed",) + tuple(handle(conn, (list(rules), {}, setup),
                                              fake_resolve, fake_connect, local))
        except Refused as e:
            out = ("refused", str(e))
            reply(conn, b"403 Forbidden", str(e))
        finally:
            try:
                conn.sock.close()
            except OSError:
                pass
        data = b""
        b.settimeout(10)
        try:
            while True:
                chunk = b.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        b.close()
        return out, data

    # the tunnel: allowed CONNECT relays ClientHello-first, reply survives EOF
    v, rep = run(b"CONNECT ok.test:443 HTTP/1.1\r\nHost: ok.test:443\r\n\r\n"
                 + hello("ok.test") + b"MORE")
    check(v[0] == "allowed" and rep.endswith(b"PONG") and got
          and got[-1].startswith(b"\x16\x03") and got[-1].endswith(b"MORE"),
          f"A an allowed CONNECT relays: {v}")
    v, rep = run(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n" + hello("localhost"))
    check(v[0] == "refused" and "TLS names" in v[1],
          f"A a ClientHello naming another host: {v}")
    v, _ = run(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n" + hello(None))
    check(v[0] == "refused", f"A a ClientHello naming nothing: {v}")

    # the port rule
    v, rep = run(b"CONNECT ok.test:22 HTTP/1.1\r\n\r\n")
    check(v[0] == "refused" and "443" in v[1] and rep.startswith(b"HTTP/1.1 403"),
          f"B a port other than 443: {v}")
    v, _ = run(b"GET http://ok.test:8080/x HTTP/1.1\r\n\r\n", setup=True)
    check(v[0] == "refused" and "80" in v[1], f"B plain HTTP on another port: {v}")

    # the boundary: not listed, subdomains, deny over allow
    v, _ = run(b"CONNECT evil.test:443 HTTP/1.1\r\n\r\n" + hello("evil.test"))
    check(v[0] == "refused" and "boundary" in v[1], f"C a host not on the list: {v}")
    v, _ = run(b"CONNECT sub.ok.test:443 HTTP/1.1\r\n\r\n" + hello("sub.ok.test"))
    check(v[0] == "refused", f"C a subdomain without a leading-dot rule: {v}")
    v, _ = run(b"CONNECT sub.ok.test:443 HTTP/1.1\r\n\r\n" + hello("sub.ok.test"),
               rules=(".ok.test",))
    check(v[0] == "allowed", f"C a leading-dot rule covers subdomains: {v}")
    v, _ = run(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n" + hello("ok.test"),
               rules=("*", "!ok.test"))
    check(v[0] == "refused" and v[1] == "deny", f"C deny beats allow-all: {v}")
    past = time.strftime(STAMP, time.gmtime(time.time() - 3600))
    v, _ = run(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n" + hello("ok.test"),
               rules=[("*", None), ("!ok.test", parse_until(past))])
    check(v[0] == "allowed", f"C a deny past its stamp stops denying: {v}")

    # private, multicast, local and mixed resolutions refuse under allow-all
    for name in ("loop.test", "lan.test", "lan2.test", "multi.test", "mixed.test"):
        v, _ = run(b"CONNECT %s:443 HTTP/1.1\r\n\r\n" % name.encode() + hello(name),
                   rules=("*",))
        check(v[0] == "refused" and "public" in v[1],
              f"D {name} resolves somewhere unforgivable: {v}")
    v, _ = run(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n" + hello("ok.test"),
               local=lambda a: True)
    check(v[0] == "refused" and "public" in v[1],
          f"D a public address this host holds: {v}")

    # expiry: a rule that passed its stamp matches nothing, and says why
    past = time.strftime(STAMP, time.gmtime(time.time() - 3600))
    future = time.strftime(STAMP, time.gmtime(time.time() + 3600))
    v, _ = run(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n" + hello("ok.test"),
               rules=[("ok.test", parse_until(past))])
    check(v[0] == "refused" and "expired" in v[1], f"E an expired rule: {v}")
    v, _ = run(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n" + hello("ok.test"),
               rules=[("ok.test", parse_until(future))])
    check(v[0] == "allowed", f"E a rule still inside its stamp: {v}")

    # the log: one row per CONNECT, control characters never land
    base = tempfile.mkdtemp(prefix="eg-rt.")
    try:
        pol = os.path.join(base, "policy")
        with open(pol, "w") as f:
            f.write(f"# the boundary\nok.test until {future}\n!deny.test\n"
                    "setup\n.Example.COM\n")
        rules, pins, setup = load_policy(pol)
        check(rules == [("ok.test", rules[0][1]), ("!deny.test", None),
                        (".example.com", None)] and setup is True,
              f"F the policy parses, case-blind: {rules}")

        # a pin: the operator vouches, DNS is skipped, the log row says pinned.
        # pinned.test resolves nowhere -- only its pin can reach the upstream
        pin_pol = os.path.join(base, "pin-pol")
        with open(pin_pol, "w") as f:
            f.write(f"pinned.test\npin pinned.test 127.0.0.1 {up_port}\n")
        rules2, pins2, _ = load_policy(pin_pol)
        check(pins2 == {"pinned.test": ("127.0.0.1", up_port)},
              f"F a pin parses: {pins2}")
        a2, b2 = socket.socketpair()
        conn2 = Conn(a2)
        b2.sendall(b"CONNECT pinned.test:443 HTTP/1.1\r\n\r\n" + hello("pinned.test")
                   + b"TAIL")
        b2.shutdown(socket.SHUT_WR)
        try:
            verdict2 = ("allowed",) + tuple(handle(conn2, (rules2, pins2, False),
                                                   fake_resolve, fake_connect,
                                                   lambda a: False))
        except Refused as e:
            verdict2 = ("refused", str(e))
        finally:
            conn2.sock.close()
        rep2 = b""
        b2.settimeout(10)
        try:
            while True:
                chunk = b2.recv(65536)
                if not chunk:
                    break
                rep2 += chunk
        except OSError:
            pass
        b2.close()
        check(verdict2[0] == "allowed" and rep2.endswith(b"PONG") and
              got[-1].endswith(b"TAIL"),
              f"F a pinned host reaches its upstream through every other law: {verdict2}")
        check(parse_until("2006-01-02T15:04:05Z") is not None
              and parse_until("not a stamp") is None, "F stamps parse strictly")

        log = os.path.join(base, "log")
        sockdir = os.path.join(base, "socks")
        p = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__),
                              "serve", sockdir, pol, log],
                             stdout=subprocess.PIPE, text=True)
        sock_path = os.path.join(sockdir, "proxy.sock")
        for _ in range(100):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)

        def connect_proxy(req):
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.settimeout(10)
            c.connect(sock_path)
            c.sendall(req)
            c.shutdown(socket.SHUT_WR)
            data = b""
            try:
                while True:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            c.close()
            return data

        # through serve: a host off the boundary answers 403 over the socket
        rep = connect_proxy(b"CONNECT nope.test:443 HTTP/1.1\r\n\r\n")
        check(rep.startswith(b"HTTP/1.1 403") and b"boundary" in rep,
              f"G serve refuses over the socket: {rep[:120]}")
        # a log that can't be written refuses the connection before serving it
        with open(pol, "a") as f:
            f.write(f"pin allowed.test 127.0.0.1 {lport_of(srv)}\n"
                    "allowed.test\n")
        deadlog = os.path.join(base, "dead.log")
        open(deadlog, "w").close()
        os.chmod(deadlog, 0o000)
        deadsock = os.path.join(base, "deadsocks")
        p2 = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__),
                               "serve", deadsock, pol, deadlog],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if os.path.exists(os.path.join(deadsock, "proxy.sock")):
                    break
                time.sleep(0.05)
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.settimeout(10)
            c.connect(os.path.join(deadsock, "proxy.sock"))
            c.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n"
                      + hello("allowed.test"))
            c.shutdown(socket.SHUT_WR)
            rep2 = b""
            try:
                while True:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    rep2 += chunk
            except OSError:
                pass
            c.close()
            check(rep2.startswith(b"HTTP/1.1 403") and b"log" in rep2
                  and not rep2.startswith(b"HTTP/1.1 200"),
                  f"G an unwritable log refuses before serving: {rep2[:80]}")
        finally:
            p2.terminate()
            p2.wait(10)
            os.chmod(deadlog, 0o600)
        # through the relay's TCP leg to the same socket: the 403 comes back
        r = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__),
                              "relay", sock_path, "--port", "0"],
                             stdout=subprocess.PIPE, text=True)
        r_port = int(r.stdout.readline().strip())
        c = socket.create_connection(("127.0.0.1", r_port), timeout=10)
        c.sendall(b"CONNECT nope.test:443 HTTP/1.1\r\n\r\n")
        c.shutdown(socket.SHUT_WR)
        data = b""
        try:
            while True:
                chunk = c.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        c.close()
        check(data.startswith(b"HTTP/1.1 403"),
              f"G the relay carries the refusal back: {data[:40]}")
        # a CONNECT whose host names the log's discipline: exactly one row each
        connect_proxy(b"CONNECT a\tb\x1b.test:443 HTTP/1.1\r\n\r\n")
        connect_proxy(b"CONNECT deny.test:443 HTTP/1.1\r\n\r\n")
        p.terminate()
        p.wait(10)
        r.terminate()
        r.wait(10)
        rows = open(log, encoding="ascii").read().splitlines()
        check(len(rows) == 4 and sum(1 for x in rows if "refused" in x) == 4,
              f"F one row per CONNECT: {len(rows)}")
        check(all("\t" not in x and "\x1b" not in x for x in rows),
              "F control characters never reach the log")
        check(any("deny" in x for x in rows), "F the deny rule lands a row")
        # H plain HTTP GET carrying Content-Length or smuggled body is refused / never relayed
        smug_pol = os.path.join(base, "smug.pol")
        open(smug_pol, "w").write("setup\nallowed.test\n")
        smug_log = os.path.join(base, "smug.log")
        smug_dir = os.path.join(base, "smugsock")
        p_smug = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__),
                                   "serve", smug_dir, smug_pol, smug_log],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(40):
                if os.path.exists(os.path.join(smug_dir, "proxy.sock")):
                    break
                time.sleep(0.05)
            cs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cs.settimeout(10)
            cs.connect(os.path.join(smug_dir, "proxy.sock"))
            cs.sendall(b"GET http://allowed.test/p HTTP/1.1\r\nContent-Length: 5\r\n\r\nEXFIL")
            cs.shutdown(socket.SHUT_WR)
            rep_s = cs.recv(4096)
            cs.close()
            check(rep_s.startswith(b"HTTP/1.1 403") and b"body" in rep_s,
                  f"H plain HTTP GET with body refuses: {rep_s[:80]}")
        finally:
            p_smug.terminate()
            p_smug.wait(10)
        # I unmocked is_local, port-80 setup vs worker gate, Proxy-Authorization strip, and SLOTS ceiling
        check(is_local("127.0.0.1") is True and is_local(PUB) is False,
              "I1 is_local binds loopback and rejects non-local global IP")
        p80_worker, _ = run(b"GET http://ok.test/pkg HTTP/1.1\r\nHost: ok.test\r\n\r\n",
                            rules=("ok.test",), setup=False)
        check(p80_worker[0] == "refused", f"I2 port-80 plain HTTP refused outside setup: {p80_worker}")
        got_before = len(got)
        p80_setup, _ = run(
            b"GET http://ok.test/pkg HTTP/1.1\r\nHost: ok.test\r\n"
            b"Proxy-Authorization: Basic c2VjcmV0\r\nConnection: close\r\n\r\n",
            rules=("ok.test",), setup=True)
        check(p80_setup[0] == "allowed" and len(got) > got_before
              and b"Proxy-Authorization" not in got[-1] and b"c2VjcmV0" not in got[-1],
              f"I3 setup plain HTTP strips Proxy-Authorization before upstream: {p80_setup}")
        slot_dir = os.path.join(base, "slot-sub")
        os.makedirs(slot_dir, exist_ok=True)
        held_fds = []
        try:
            for _ in range(SLOTS):
                fd_s = take_slot(os.path.join(slot_dir, "proxy-slots"))
                if fd_s is not None:
                    held_fds.append(fd_s)
            check(len(held_fds) == SLOTS and take_slot(os.path.join(slot_dir, "proxy-slots")) is None,
                  f"I4a take_slot exhausts at SLOTS={SLOTS}: held={len(held_fds)}")
            sa, sb = socket.socketpair()
            sb.sendall(b"CONNECT ok.test:443 HTTP/1.1\r\n\r\n")
            sb.shutdown(socket.SHUT_WR)
            one_connection(sa, pol, os.path.join(slot_dir, "slot.log"), fake_resolve, fake_connect, lambda _a: False)
            slot_rep = sb.recv(1024)
            sb.close()
            check(slot_rep.startswith(b"HTTP/1.1 403") and b"too many connections" in slot_rep,
                  f"I4b exhausted SLOTS refuses excess connection: {slot_rep[:80]!r}")
        finally:
            for fd_s in held_fds:
                os.close(fd_s)
    finally:
        _sh.rmtree(base, ignore_errors=True)
        srv.close()

    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.exit(main(sys.argv))
