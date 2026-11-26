#!/usr/bin/env bash
# The citation seal, as the ratchet's 5th-column test: an UNSEALED .body
# (no manifest entry) must leave citations rc 1; a sealed one greens.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
export ROOT
T=$(mktemp -d); trap 'rm -rf "${T:?}"' EXIT
python3 -I - "$T" <<'PY' || exit 1
import hashlib, json, os, subprocess, sys
T = sys.argv[1]
body = b"<html>planted words</html>"
h = hashlib.sha256(body).hexdigest()[:16]
src = os.path.join(T, "sources"); os.makedirs(src)
open(os.path.join(src, h + ".body"), "wb").write(body)
open(os.path.join(src, h + ".url"), "w").write("https://planted.example.com/x\n")
open(os.path.join(T, "report.md"), "w").write(
    "T\n\n> planted words [1]\n\n1. https://planted.example.com/x\n")
r = subprocess.run([sys.executable, "-I",
                    os.path.join(os.environ["ROOT"],
                                 "profiles/templates/research/checks/citations.py"),
                    os.path.join(T, "report.md"), src],
                   capture_output=True, text=True)
assert r.returncode == 1, f"unsealed body verified: {r.stdout} {r.stderr}"
# sealed: same body, now in the manifest, greens
open(os.path.join(src, "sources.manifest"), "w").write(f"{h}\thttps://planted.example.com/x\n")
r2 = subprocess.run([sys.executable, "-I",
                     os.path.join(os.environ["ROOT"],
                                  "profiles/templates/research/checks/citations.py"),
                     os.path.join(T, "report.md"), src],
                    capture_output=True, text=True)
assert r2.returncode == 0, f"sealed body refused: {r2.stderr}"
print("citation-seal: OK (unsealed red, sealed green)")
PY
# an unparseable quote line (trailing text the regex can't hold) reds
T2=$(mktemp -d)
python3 -I - "$T2" <<'PY2' || { rm -rf "$T2"; exit 1; }
import hashlib, os, subprocess, sys
T = sys.argv[1]
body = b"<html>real words</html>"
h = hashlib.sha256(body).hexdigest()[:16]
src = os.path.join(T, "sources")
os.makedirs(src)
open(os.path.join(src, h + ".body"), "wb").write(body)
with open(os.path.join(src, "sources.manifest"), "w") as f:
    f.write(h + "\thttps://real.example.com/s\n")
open(os.path.join(T, "report.md"), "w").write(
    "T\n\n> real words [1] trailing after the marker\n\n1. https://real.example.com/s\n")
r = subprocess.run([sys.executable, "-I",
                    os.path.join(os.environ["ROOT"],
                                 "profiles/templates/research/checks/citations.py"),
                    os.path.join(T, "report.md"), src],
                   capture_output=True, text=True)
assert r.returncode == 1 and "unparseable" in r.stderr, \
    "trailing quote verified: " + r.stdout + r.stderr
print("citation-trailing: OK (unparseable quote reds)")
PY2
rm -rf "$T2"

# SSRF guard: fetch_sources refuses literal loopback/CGNAT, non-http(s), and 30x redirects to loopback
T3=$(mktemp -d)
python3 -I - "$T3" <<'PY3' || { rm -rf "$T3"; exit 1; }
import importlib.util, io, os, sys, urllib.request
spec = importlib.util.spec_from_file_location(
    "fetch_sources",
    os.path.join(os.environ["ROOT"], "profiles/templates/research/checks/fetch_sources.py"))
fs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fs)
cgnat = "http://" + "100.64" + ".0.1/cgnat"
for bad_u in ("http://127.0.0.1:8080/secret", cgnat, "ftp://example.com/f"):
    try:
        fs._validate_public_url(bad_u)
        raise AssertionError(f"accepted non-public URL {bad_u}")
    except OSError:
        pass
h = fs._SafeRedirectHandler()
req = urllib.request.Request("https://example.com/start")
try:
    h.redirect_request(req, io.BytesIO(), 302, "Found", {}, "http://127.0.0.1:8080/secret")
    raise AssertionError("accepted 302 redirect to loopback")
except OSError:
    pass
print("citation-ssrf: OK (loopback, CGNAT, non-http, and 302 redirect refused)")
PY3
rm -rf "$T3"
