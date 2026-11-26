#!/usr/bin/env python3
"""fetch_sources -- save a copy of every URL a report cites.

Runs ONCE in [setup] with network; each cited URL is fetched into the named
sources dir as <hash>.url + <hash>.body (mode 600, size-capped). The citation
check then runs OFFLINE against these copies -- the saved bytes are the only
truth a quote is checked against.

usage: fetch_sources.py <report.md> <sources-dir>
exit: 0 fetched (or all previously saved), 1 a citation refused, 2 usage
"""
import hashlib
import ipaddress
import os
import re
import socket
import sys
import urllib.parse
import urllib.request

CAP = 2 * 1024 * 1024      # a source past 2 MiB isn't a citable page
URL_RE = re.compile(r"https?://[^\s\)\]\"']+")


def urls_of(report):
    seen = []
    for m in URL_RE.finditer(open(report, encoding="utf-8",
                                  errors="replace").read()):
        u = m.group(0).rstrip(".,;")
        if u not in seen:
            seen.append(u)
    return seen


def _proxy_covers_scheme(scheme):
    """True only when an explicit HTTP(S) proxy for `scheme` is active and not
    bypassed by NO_PROXY, meaning egress-proxy.py enforces DNS/IP checks."""
    if os.environ.get("NO_PROXY") or os.environ.get("no_proxy"):
        return False
    if scheme == "https":
        return bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"))
    if scheme == "http":
        return bool(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    return False


def _validate_public_url(u):
    """Refuse non-http(s) schemes and any literal or resolved non-global IP
    (including loopback, RFC 1918, link-local, RFC 6598 CGNAT, multicast)."""
    parsed = urllib.parse.urlsplit(u)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise OSError(f"scheme {scheme!r} is not allowed")
    host = parsed.hostname or ""
    if not host:
        raise OSError("missing host")
    try:
        lit_ip = ipaddress.ip_address(host)
    except ValueError:
        lit_ip = None
    if lit_ip is not None:
        if not lit_ip.is_global or lit_ip.is_multicast:
            raise OSError(f"{host} is a non-public address")
    elif not _proxy_covers_scheme(scheme):
        for ai in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(ai[4][0])
            if not ip.is_global or ip.is_multicast:
                raise OSError(f"{host} resolves to a non-public address")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        full_new = urllib.parse.urljoin(req.full_url, newurl)
        _validate_public_url(full_new)
        return super().redirect_request(req, fp, code, msg, headers, full_new)


def main(argv):
    if len(argv) != 3:
        print("usage: fetch_sources.py <report.md> <sources-dir>", file=sys.stderr)
        return 2
    report, out = argv[1], argv[2]
    if not os.path.isfile(report):
        print(f"fetch_sources: no report at {report}", file=sys.stderr)
        return 1
    os.makedirs(out, exist_ok=True)
    opener = urllib.request.build_opener(_SafeRedirectHandler)
    bad = 0
    manifest = []
    for u in urls_of(report):
        h = hashlib.sha256(u.encode()).hexdigest()[:16]
        url_p, body_p = os.path.join(out, h + ".url"), os.path.join(out, h + ".body")
        if os.path.isfile(body_p):
            continue  # already saved: the fetch is once (the manifest pins it)
        try:
            _validate_public_url(u)
        except OSError as e:
            print(f"fetch_sources: {u} refused: {e}", file=sys.stderr)
            bad += 1
            continue
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "operator-cite/1"})
            with opener.open(req, timeout=30) as r:
                body = r.read(CAP + 1)
                final = r.geturl()  # record where a redirect actually landed
            _validate_public_url(final)
        except Exception as e:
            print(f"fetch_sources: {u} refused: {type(e).__name__}", file=sys.stderr)
            bad += 1
            continue
        if len(body) > CAP:
            print(f"fetch_sources: {u} past {CAP} bytes", file=sys.stderr)
            bad += 1
            continue
        with open(url_p, "w", encoding="utf-8") as f:
            f.write((final if final != u else u) + "\n")
        with open(body_p, "wb") as f:
            f.write(body)
        os.chmod(url_p, 0o600)
        os.chmod(body_p, 0o600)
        manifest.append((u, hashlib.sha256(body).hexdigest()[:16]))
    # the manifest is the seal: only bodies it names are citable truth
    mp = os.path.join(out, "sources.manifest")
    known = {}
    if os.path.isfile(mp):
        for ln in open(mp, encoding="utf-8"):
            parts = ln.strip().split("\t")
            if len(parts) == 2:
                known[parts[1]] = parts[0]
    with open(mp, "w", encoding="utf-8") as f:
        for u, h in manifest:
            known[h] = u  # a refetch of changed bytes re-pins the manifest
        for h, u in sorted(known.items()):
            f.write(f"{h}\t{u}\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
