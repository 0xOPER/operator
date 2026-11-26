#!/usr/bin/env python3
"""upstream -- a scripted provider on loopback, for demos, fixtures and conformance.

One server, three faces: /anthropic speaks the messages format, /openai speaks
the Responses format (no websockets), /compat speaks an OpenAI-compatible chat
completions endpoint. Every request body lands verbatim in the request log a
test reads -- a pass needs the log to show the call was issued -- and responses
come from a script file (one JSON response per line, served in order, a default
text completion when the script runs dry). It binds 127.0.0.1 only, refuses to
serve any other path, and never follows anything a request carries.

usage: upstream.py serve <script.jsonl> <request-log> [--port N]   prints the port, serves until killed
       upstream.py --selftest
exit: 0 served/ok, 1 refused, 2 usage or VOID
"""
import json
import os
import sys
import threading

_LOG_LOCK = threading.Lock()  # one row per write: concurrent posts never interleave
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True

ROUTES = ("/anthropic", "/openai", "/compat")
MAX_BODY = 1 << 20  # a request body past 1 MiB is a broken client, not a probe


class Script:
    """Responses in file order; the default when the script runs dry."""

    def __init__(self, path):
        self.rows = []
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.rows.append(line)
        self.i = 0

    def next(self, route):
        if self.i < len(self.rows):
            row = self.rows[self.i]
            self.i += 1
            return row
        if route == "/anthropic":
            return json.dumps({"id": "msg_default", "type": "message", "role": "assistant",
                               "content": [{"type": "text", "text": "ok"}],
                               "stop_reason": "end_turn", "usage": {"input_tokens": 1,
                                                                    "output_tokens": 1}})
        if route == "/openai":
            return json.dumps({"id": "resp_default", "object": "response", "status": "completed",
                               "output": [{"type": "message", "role": "assistant",
                                           "content": [{"type": "output_text", "text": "ok"}]}],
                               "usage": {"input_tokens": 1, "output_tokens": 1}})
        return json.dumps({"id": "cmpl_default", "object": "chat.completion",
                           "choices": [{"index": 0, "message": {"role": "assistant",
                                                                "content": "ok"}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1}})


def make_handler(script, log_path):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # the request log is ours, not stderr's
            pass

        def do_POST(self):
            route = self.path.split("?")[0].rstrip("/") or "/"
            if route not in ROUTES:
                self.send_error(404, "no such face")
                return
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self.close_connection = True
                self.send_error(413, "body too large")
                rem = min(n, MAX_BODY + 65536)
                while rem > 0:
                    chunk = self.rfile.read(min(65536, rem))
                    if not chunk:
                        break
                    rem -= len(chunk)
                return
            body = self.rfile.read(n)
            row = json.dumps({"route": route, "headers": {
                        k.lower(): v for k, v in self.headers.items()
                        if k.lower() in ("authorization", "x-api-key", "content-type")},
                    "body": body.decode("utf-8", "replace")}, ensure_ascii=True,
                sort_keys=True) + "\n"
            with _LOG_LOCK:  # a single append write; a torn row is a lost receipt
                fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
                os.write(fd, row.encode("utf-8"))
                os.close(fd)
            out = script.next(route).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    return Handler


def serve(script_path, log_path, port=0):
    script = Script(script_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(script, log_path))
    print(httpd.server_address[1], flush=True)
    httpd.serve_forever()


def main(argv):
    if len(argv) >= 4 and argv[1] == "serve":
        port = 0
        if "--port" in argv and argv.index("--port") + 1 < len(argv):
            port = int(argv[argv.index("--port") + 1])
        try:
            serve(argv[2], argv[3], port)
        except OSError as e:
            print(f"upstream: VOID, can't bind 127.0.0.1:{port}: {e}", file=sys.stderr)
            return 2
    print("usage: upstream.py serve <script.jsonl> <request-log> [--port N] | --selftest",
          file=sys.stderr)
    return 2


def selftest():
    """Room-safe: three faces answer their formats, the log holds the bodies
    verbatim, scripted rows serve in order, the default answers when dry, a
    body past the cap refuses, and an unknown path is 404."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, (1 << 30)))
    import shutil as _sh
    import subprocess
    import tempfile
    import urllib.request
    import urllib.error
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    base = tempfile.mkdtemp(prefix="up-rt.")
    log = os.path.join(base, "requests.jsonl")
    script = os.path.join(base, "script.jsonl")
    with open(script, "w") as f:
        f.write(json.dumps({"id": "msg_1", "content": [{"type": "text", "text": "first"}]}) + "\n")
    p = subprocess.Popen([sys.executable, os.path.abspath(__file__), "serve", script, log],
                         stdout=subprocess.PIPE, text=True)
    try:
        port = int(p.stdout.readline().strip())
        base_url = f"http://127.0.0.1:{port}"

        def post(path, body, key="sk-test"):
            req = urllib.request.Request(base_url + path, data=body.encode(),
                                         headers={"Content-Type": "application/json",
                                                  "x-api-key": key}, method="POST")
            return json.loads(urllib.request.urlopen(req, timeout=10).read())

        # A the three faces answer their shapes
        r = post("/anthropic", json.dumps({"model": "any", "messages": [{"role": "user",
                                                                         "content": "hi"}]}))
        check(r["content"][0]["text"] == "first", f"A the scripted row serves first: {r}")
        r = post("/openai", json.dumps({"model": "any", "input": "hi"}))
        check(r["output"][0]["content"][0]["text"] == "ok", "A the responses face defaults")
        r = post("/compat", json.dumps({"model": "any", "messages": [{"role": "user",
                                                                      "content": "hi"}]}))
        check(r["choices"][0]["message"]["content"] == "ok", "A the compat face defaults")

        # B the log holds the bodies verbatim, keys masked by name only
        rows = [json.loads(l) for l in open(log)]
        check(len(rows) == 3 and rows[0]["route"] == "/anthropic" and
              rows[2]["route"] == "/compat", f"B routes logged: {[r['route'] for r in rows]}")
        check(json.loads(rows[0]["body"])["messages"][0]["content"] == "hi",
              "B the body is verbatim")
        check(rows[0]["headers"].get("x-api-key") == "sk-test", "B the auth header is on the row")

        # C an unknown path is 404, and an oversized body is 413
        try:
            post("/nope", "{}")
            check(False, "C unknown path 404s")
        except urllib.error.HTTPError as e:
            check(e.code == 404, f"C unknown path: {e.code}")
        try:
            post("/anthropic", "{" + "x" * (MAX_BODY + 10) + "}")
            check(False, "C oversized body 413s")
        except urllib.error.HTTPError as e:
            check(e.code == 413, f"C oversized: {e.code}")

        print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0] else "selftest: FAIL")
        return 0 if ok[0] and not bad[0] else 1
    finally:
        p.terminate()
        p.wait()
        _sh.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.exit(main(sys.argv))
