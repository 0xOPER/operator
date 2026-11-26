#!/usr/bin/env python3
"""broker -- the engine's own wire to a real provider endpoint.

The worker jails have no network. The CLIs inside them speak to THIS broker
through the relay: the broker's Unix socket is bound into the jail, the relay
gives it a loopback TCP face, and every request the CLI sends is re-originated
here -- the broker parses the request line, enforces the route and the body
cap, strips whatever authorization the client carried, adds the engine's own
credential, and streams the provider's SSE answer straight back. The jail never
holds a usable key and never names a host; the broker is the only thing that
does (the ruling: broker, not proxy -- control stays engine-side).

One row per completed request lands in the broker log: time, route, status,
upstream bytes, and the usage tokens the stream itself reported.

usage:
  broker.py serve <sock-path> <origin-base> <credential> <log> [--max-body N]
  broker.py --selftest
exit: 0 served until killed / ok, 1 refused, 2 usage or VOID
"""
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_BODY = 8 << 20          # a request past 8 MiB is a broken client
MAX_CONNS = 32              # cap concurrent client threads against worker floods
CLIENT_TIMEOUT = 60         # cap slowloris client request reads
ROUTES = ("/v1/messages", "/v1/responses")
# the anthropic wire the claude adapter speaks, and the responses wire the
# codex adapter speaks (its broker_contract: response.completed.usage)
IDLE = 900                  # a streamed answer may take minutes; the wire stays

_LOG = threading.Lock()
_SLOTS = threading.Semaphore(MAX_CONNS)


def _extract_usage(d):
    """Extract token usage across Anthropic (message_start nests under
    message.usage; message_delta carries top-level usage), OpenAI Responses
    (response.completed nests under response.usage), and non-streaming JSON."""
    if not isinstance(d, dict):
        return None
    u = (d.get("usage")
         or (d.get("message") or {}).get("usage")
         or (d.get("response") or {}).get("usage"))
    return u if isinstance(u, dict) else None


def _merge_usage(cur, nxt):
    if not isinstance(nxt, dict):
        return cur
    merged = dict(cur) if isinstance(cur, dict) else {}
    merged.update(nxt)
    return merged


def _input_tokens_of(usage):
    if not isinstance(usage, dict):
        return 0
    return sum(
        int(usage.get(k) or 0) for k in (
            "input_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens")
        if isinstance(usage.get(k), (int, float))
    )


def _output_tokens_of(usage):
    if not isinstance(usage, dict):
        return 0
    v = usage.get("output_tokens")
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


# Deterministic conservative per-1M-token USD table: (uncached_in, cache_read, cache_write, out)
MODEL_PRICING_PER_MTOK = (
    ("opus-4-5", (5.0, 0.50, 6.25, 25.0)),
    ("opus-4-6", (5.0, 0.50, 6.25, 25.0)),
    ("opus-4.5", (5.0, 0.50, 6.25, 25.0)),
    ("opus-4.6", (5.0, 0.50, 6.25, 25.0)),
    ("opus", (15.0, 1.50, 18.75, 75.0)),
    ("haiku", (1.0, 0.10, 1.25, 5.0)),
    ("sonnet", (3.0, 0.30, 3.75, 15.0)),
    ("claude", (3.0, 0.30, 3.75, 15.0)),
    ("gpt-5-mini", (1.10, 0.275, 1.10, 4.40)),
    ("gpt-4o-mini", (0.60, 0.15, 0.60, 2.40)),
    ("o4-mini", (1.10, 0.275, 1.10, 4.40)),
    ("o3-mini", (1.10, 0.275, 1.10, 4.40)),
    ("gpt-5", (2.50, 0.625, 2.50, 10.0)),
    ("codex", (2.50, 0.625, 2.50, 10.0)),
    ("o3", (2.50, 0.625, 2.50, 10.0)),
    ("o1", (15.0, 7.50, 15.0, 60.0)),
    ("glm-5.3-flash", (0.10, 0.025, 0.10, 0.40)),
    ("flash", (0.30, 0.075, 0.30, 1.20)),
    ("glm", (1.00, 0.25, 1.00, 4.00)),
)
FALLBACK_PRICING_PER_MTOK = (5.0, 0.50, 6.25, 25.0)


def _compute_cost_usd(model_name, usage):
    if not isinstance(usage, dict):
        return None
    m = str(model_name or "").lower()
    rates = FALLBACK_PRICING_PER_MTOK
    for needle, r_tuple in MODEL_PRICING_PER_MTOK:
        if needle in m:
            rates = r_tuple
            break
    p_in, p_cr, p_cw, p_out = rates
    raw_in = int(usage.get("input_tokens") or 0) if isinstance(usage.get("input_tokens"), (int, float)) else 0
    cr = int(usage.get("cache_read_input_tokens") or 0) if isinstance(usage.get("cache_read_input_tokens"), (int, float)) else 0
    cw = int(usage.get("cache_creation_input_tokens") or 0) if isinstance(usage.get("cache_creation_input_tokens"), (int, float)) else 0
    details = usage.get("input_tokens_details")
    if isinstance(details, dict) and isinstance(details.get("cached_tokens"), (int, float)):
        oai_cached = int(details.get("cached_tokens") or 0)
        cr = max(cr, oai_cached)
        uncached_in = max(0, raw_in - oai_cached)
    else:
        uncached_in = max(0, raw_in)
    out_tok = _output_tokens_of(usage)
    usd = (uncached_in * p_in + cr * p_cr + cw * p_cw + out_tok * p_out) / 1_000_000.0
    return round(max(0.0, usd), 6)


SEAT_TOKEN_3_RE = re.compile(r"^op-seat:([a-z0-9][a-z0-9._-]{0,63}):([0-9a-f]{16})$")
SEAT_TOKEN_4_RE = re.compile(r"^op-seat:([a-z0-9][a-z0-9._-]{0,63}):([a-z0-9][a-z0-9._-]{0,63}):([0-9a-f]{16})$")


def _verify_client_token(headers, seat_key):
    """Verify `op-seat:<seat>:<aid>:<mac>` or legacy `op-seat:<seat>:<mac>`.
    Returns (ok_bool, seat_or_none, attempt_or_none)."""
    if not seat_key:
        return True, None, None
    raw = headers.get("x-api-key") or ""
    if not raw:
        auth = headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            raw = auth[7:].strip()
    tok = raw.strip()
    m4 = SEAT_TOKEN_4_RE.fullmatch(tok)
    if m4:
        seat, aid, mac = m4.group(1), m4.group(2), m4.group(3)
        msg = f"{seat}:{aid}".encode("utf-8")
    else:
        m3 = SEAT_TOKEN_3_RE.fullmatch(tok)
        if not m3:
            return False, None, None
        seat, aid, mac = m3.group(1), None, m3.group(2)
        msg = seat.encode("utf-8")
    want = hmac.new(seat_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(want, mac):
        return False, None, None
    return True, seat, aid


def _verify_client_seat(headers, seat_key):
    ok_s, seat_s, _ = _verify_client_token(headers, seat_key)
    return ok_s, seat_s


def log_row(path, log, **kv):
    for opt_k in ("seat", "attempt", "model", "cost_usd", "client_gone"):
        if kv.get(opt_k) is None:
            kv.pop(opt_k, None)
    row = {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "route": path, **kv}
    with _LOG:
        with open(log, "a", encoding="ascii", errors="replace") as f:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")


class UnixHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        sock = self.server_address
        if os.path.lexists(sock):
            os.unlink(sock)  # a stale socket from a killed run never blocks
        old = os.umask(0o177)
        try:
            super().server_bind()
        finally:
            os.umask(old)    # the socket answers only its own user


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = CLIENT_TIMEOUT
    origin = ("", "", "")   # (host, base-path, credential) set by serve()

    def log_message(self, *a):
        pass

    def handle(self):
        # Acquire concurrency slot BEFORE reading request headers so pre-header
        # slowloris connections cannot spawn unbounded threads past MAX_CONNS.
        if not _SLOTS.acquire(blocking=False):
            try:
                body = json.dumps({"error": "the broker concurrency ceiling is reached"}).encode()
                self.connection.settimeout(5)
                self.connection.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Connection: close\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body)
            except OSError:
                pass
            return
        try:
            super().handle()
        finally:
            _SLOTS.release()

    def _refuse(self, code, why):
        body = json.dumps({"error": why}).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            self.close_connection = True
        return None

    def do_POST(self):
        try:
            self._handle_post()
        finally:
            try:
                self.connection.settimeout(CLIENT_TIMEOUT)
            except OSError:
                pass

    def _handle_post(self):
        self.connection.settimeout(CLIENT_TIMEOUT)
        path = self.path.split("?")[0]
        if path not in ROUTES:  # exact: a suffix trick admitted traversal shapes
            self._refuse(404, "the broker serves the engine's routes only")
            log_row(path, self.server.log, status=404)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._refuse(400, "invalid Content-Length")
            log_row(path, self.server.log, status=400)
            return
        if n <= 0 or n > self.server.max_body:
            self._refuse(413 if n > 0 else 400, "the broker carries real turns, not dumps")
            log_row(path, self.server.log, status=413 if n > 0 else 400)
            return
        try:
            body = self.rfile.read(n)
        except OSError:
            self._refuse(408, "client body timed out")
            log_row(path, self.server.log, status=408)
            return
        self.connection.settimeout(IDLE)
        seat_ok, client_seat, client_attempt = _verify_client_token(
            self.headers, getattr(self.server, "seat_key", ""))
        if not seat_ok:
            self._refuse(401, "invalid or missing broker seat token")
            log_row(path, self.server.log, status=401)
            return
        req_model = ""
        try:
            req_doc = json.loads(body.decode("utf-8", "replace"))
            if isinstance(req_doc, dict) and isinstance(req_doc.get("model"), str):
                req_model = req_doc["model"][:128]
        except ValueError:
            req_model = ""
        cap = getattr(self.server, "turn_cap", 0)
        out_cap = getattr(self.server, "turn_output_cap", 0)
        usd_cap = getattr(self.server, "turn_usd_cap", 0.0)
        cap_scope = client_attempt or client_seat
        prev_in, prev_out, prev_usd = (0, 0, 0.0)
        if cap_scope:
            prev_in, prev_out, prev_usd = self.server.get_totals(cap_scope)
            if (cap and prev_in >= cap) or (out_cap and prev_out >= out_cap) or (usd_cap > 0 and prev_usd >= usd_cap):
                self._refuse(429, "attempt cumulative ceiling exceeded")
                log_row(path, self.server.log, status=429, out_bytes=0,
                        capped=True, seat=client_seat, attempt=client_attempt,
                        model=req_model or None, cost_usd=0.0)
                return
        up_entry = self.server.select_upstream(path, req_model)
        if up_entry is None:
            self._refuse(502, "no upstream configured for route/model")
            log_row(path, self.server.log, status=502, seat=client_seat,
                    attempt=client_attempt, model=req_model or None)
            return
        host, base, cred, scheme = up_entry
        # strip the client's authorization (both Bearer and mixed-case x-api-key)
        # and Accept-Encoding (compressed upstream bodies would blind SSE/JSON
        # usage metering and turn-cap enforcement)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("authorization", "x-api-key",
                                        "accept-encoding", "proxy-authorization",
                                        "host", "content-length",
                                        "connection", "transfer-encoding")}
        # BOTH spellings: the anthropic wire's own header is x-api-key (what
        # claude sends; some origins' edges REQUIRE it and 404 Bearer-only),
        # and Bearer rides along for the origins that prefer it
        headers["Authorization"] = f"Bearer {cred}"
        headers["x-api-key"] = cred
        headers["Accept-Encoding"] = "identity"
        headers["Content-Length"] = str(len(body))
        try:
            up = (http.client.HTTPSConnection if scheme == "https"
                  else http.client.HTTPConnection)(host, timeout=IDLE)
            up.request("POST", base + path + ("?" + self.path.split("?")[1]
                                              if "?" in self.path else ""),
                       body=body, headers=headers)
            resp = up.getresponse()
        except (OSError, http.client.HTTPException) as e:
            self._refuse(502, f"the origin refused: {type(e).__name__}")
            log_row(path, self.server.log, status=502, seat=client_seat,
                    attempt=client_attempt, model=req_model or None)
            return
        ctype = (resp.getheader("Content-Type") or "").lower()
        is_json = "application/json" in ctype and "text/event-stream" not in ctype
        sent = 0
        usage = None
        capped = False
        client_gone = False
        if is_json:
            # Non-streaming JSON response (stream: false): buffer up to max_body
            # so usage metering and turn_cap apply identically to SSE turns.
            try:
                raw = resp.read(self.server.max_body + 1)
            except (OSError, http.client.HTTPException) as e:
                up.close()
                self._refuse(502, f"origin JSON read failed: {type(e).__name__}")
                log_row(path, self.server.log, status=502, out_bytes=0,
                        seat=client_seat, attempt=client_attempt, model=req_model or None)
                return
            up.close()
            if len(raw) > self.server.max_body:
                self._refuse(502, "origin JSON response exceeds broker cap")
                log_row(path, self.server.log, status=502, out_bytes=0,
                        seat=client_seat, attempt=client_attempt, model=req_model or None)
                return
            try:
                jdoc = json.loads(raw.decode("utf-8", "replace"))
                if not req_model and isinstance(jdoc, dict) and isinstance(jdoc.get("model"), str):
                    req_model = jdoc["model"][:128]
                u = _extract_usage(jdoc)
                if isinstance(u, dict):
                    usage = u
            except ValueError:
                pass
            cost_usd = _compute_cost_usd(req_model, usage)
            if isinstance(usage, dict):
                cur_in = _input_tokens_of(usage)
                cur_out = _output_tokens_of(usage)
                cur_usd = cost_usd or 0.0
                if cap_scope:
                    self.server.add_totals(cap_scope, cur_in, cur_out, cur_usd)
                if (cap and (prev_in + cur_in) > cap) \
                        or (out_cap and (prev_out + cur_out) > out_cap) \
                        or (usd_cap > 0 and (prev_usd + cur_usd) > usd_cap):
                    capped = True
            if capped:
                log_row(path, self.server.log, status=429, out_bytes=0,
                        usage=usage, capped=True, seat=client_seat,
                        attempt=client_attempt, model=req_model or None,
                        cost_usd=cost_usd)
                self._refuse(429, "turn ceiling exceeded")
                return
            # Log BEFORE writing to the client so an early client disconnect
            # never drops a billed JSON turn row.
            try:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() in ("transfer-encoding", "connection", "content-length"):
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except OSError:
                client_gone = True
                self.close_connection = True
            log_row(path, self.server.log, status=resp.status, out_bytes=0 if client_gone else len(raw),
                    usage=usage, capped=None,
                    client_gone=True if client_gone else None,
                    seat=client_seat, attempt=client_attempt,
                    model=req_model or None, cost_usd=cost_usd)
            return
        chunked = False
        length = None
        for k, v in resp.getheaders():
            lk = k.lower()
            if lk in ("transfer-encoding", "connection", "content-length"):
                if lk == "transfer-encoding" and "chunked" in v.lower():
                    chunked = True
                elif lk == "content-length":
                    length = v
                continue
        try:
            try:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() in ("transfer-encoding", "connection", "content-length"):
                        continue
                    self.send_header(k, v)
                if chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                elif length:
                    # the origin framed it with a length: the client gets the same
                    # frame, or it would wait on the wire for a body that already ended
                    self.send_header("Content-Length", length)
                self.end_headers()
            except OSError:
                client_gone = True
                self.close_connection = True
                if getattr(up, "sock", None) is not None:
                    try:
                        up.sock.settimeout(1.0)
                    except OSError:
                        pass
            tail = b""   # incomplete trailing SSE line carried across chunks (never frozen at 64 KiB)
            read_fn = getattr(resp, "read1", resp.read)
            drain_deadline = (time.monotonic() + 1.0) if client_gone else None
            while True:
                if drain_deadline is not None and time.monotonic() >= drain_deadline:
                    break
                try:
                    data = read_fn(16384)
                except (OSError, http.client.HTTPException):
                    self.close_connection = True
                    break
                if not data:
                    break
                # incremental SSE line scan over the ENTIRE stream (even past 64 KiB):
                # the last usage-bearing event merges totals, while early message_start
                # cuts mid-stream the instant turn_cap is crossed.
                buf = tail + data
                lines = buf.split(b"\n")
                tail = lines.pop()
                if len(tail) > 1 << 20:
                    tail = tail[-(1 << 20):]
                if b'"usage"' in buf:
                    for ln in lines:
                        if b'"usage"' in ln and b"data:" in ln \
                                and (b"message_delta" in ln or b"message_start" in ln
                                     or b"response.completed" in ln):
                            try:
                                d = json.loads(ln.split(b"data:", 1)[1].strip())
                                if not req_model and isinstance(d, dict):
                                    rm_c = (d.get("model")
                                            or (d.get("message") or {}).get("model")
                                            or (d.get("response") or {}).get("model"))
                                    if isinstance(rm_c, str):
                                        req_model = rm_c[:128]
                                u = _extract_usage(d)
                                if isinstance(u, dict):
                                    usage = _merge_usage(usage, u)
                                    if cap and sum([
                                            prev_in,
                                            *(int(usage.get(k) or 0) for k in (
                                                "input_tokens",
                                                "cache_read_input_tokens",
                                                "cache_creation_input_tokens")
                                              if isinstance(usage.get(k), (int, float)))
                                    ]) > cap:
                                        # the turn's context crossed the
                                        # ceiling: CUT the stream here -- the
                                        # triggering chunk never reaches the
                                        # client, the turn fails, the row says
                                        # so (a clip would lie about what the
                                        # model sent)
                                        capped = True
                                        break
                                    if out_cap and (prev_out + _output_tokens_of(usage)) > out_cap:
                                        capped = True
                                        break
                                    if usd_cap > 0 and (prev_usd + (_compute_cost_usd(req_model, usage) or 0.0)) > usd_cap:
                                        capped = True
                                        break
                            except (ValueError, IndexError, AttributeError):
                                pass
                if capped:
                    break
                if not client_gone:
                    try:
                        if chunked:
                            self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                        else:
                            self.wfile.write(data)
                        sent += len(data)
                    except OSError:
                        client_gone = True
                        self.close_connection = True
                        drain_deadline = time.monotonic() + 1.0
                        if getattr(up, "sock", None) is not None:
                            try:
                                up.sock.settimeout(1.0)
                            except OSError:
                                pass
            if not capped and tail and b'"usage"' in tail and b"data:" in tail \
                    and (b"message_delta" in tail or b"message_start" in tail
                         or b"response.completed" in tail):
                try:
                    dt = json.loads(tail.split(b"data:", 1)[1].strip())
                    if not req_model and isinstance(dt, dict):
                        rm_t = (dt.get("model")
                                or (dt.get("message") or {}).get("model")
                                or (dt.get("response") or {}).get("model"))
                        if isinstance(rm_t, str):
                            req_model = rm_t[:128]
                    u = _extract_usage(dt)
                    if isinstance(u, dict):
                        usage = _merge_usage(usage, u)
                        if cap and (prev_in + _input_tokens_of(usage)) > cap:
                            capped = True
                        if out_cap and (prev_out + _output_tokens_of(usage)) > out_cap:
                            capped = True
                        if usd_cap > 0 and (prev_usd + (_compute_cost_usd(req_model, usage) or 0.0)) > usd_cap:
                            capped = True
                except (ValueError, IndexError, AttributeError):
                    pass
            if chunked and not capped and not client_gone:
                try:
                    self.wfile.write(b"0\r\n\r\n")
                except OSError:
                    client_gone = True
                    self.close_connection = True
        finally:
            try:
                up.close()
            except Exception:
                pass
            cost_usd = _compute_cost_usd(req_model, usage)
            if isinstance(usage, dict) and cap_scope:
                self.server.add_totals(cap_scope, _input_tokens_of(usage),
                                       _output_tokens_of(usage), cost_usd or 0.0)
            if capped or client_gone:
                # a hard abort: the connection ends mid-body, the client's read
                # fails, and the turn reports failure -- exactly the escalation
                # the ceiling exists to force
                self.close_connection = True
            log_row(path, self.server.log, status=resp.status, out_bytes=sent,
                    usage=usage, capped=True if capped else None,
                    client_gone=True if client_gone else None,
                    seat=client_seat, attempt=client_attempt,
                    model=req_model or None, cost_usd=cost_usd)


def _parse_origin_pair(origin_base, credential):
    parsed = urlsplit(origin_base)
    scheme = parsed.scheme if parsed.scheme in ("https", "http") else None
    if scheme is None or not parsed.netloc or not parsed.hostname:
        print("broker: VOID, the origin must name a scheme", file=sys.stderr)
        return None
    host = parsed.netloc
    if scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        print("broker: VOID, a non-loopback origin must be https", file=sys.stderr)
        return None
    base = parsed.path or ""
    if credential == "-":
        credential = os.environ.get("OPERATOR_BROKER_CREDENTIAL", "")
        if not credential:
            print("broker: VOID, credential '-' requires OPERATOR_BROKER_CREDENTIAL",
                  file=sys.stderr)
            return None
    elif credential.startswith("env:"):
        var = credential[4:]
        credential = os.environ.get(var, "")
        if not credential:
            print(f"broker: VOID, env var {var!r} is empty", file=sys.stderr)
            return None
    elif not credential:
        print("broker: VOID, upstream credential cannot be empty", file=sys.stderr)
        return None
    return (host, base, credential, scheme)


def serve(sock, origin_base, credential, log, max_body=MAX_BODY, turn_cap=0,
          turn_output_cap=0, turn_usd_cap=0.0, upstreams=None):
    """origin_base like https://api.example.com/api/anthropic (or '-' when
    --upstream entries provide the provider table). Supports cumulative per-attempt
    input/output/USD ceilings and route+model multi-provider upstream selection."""
    default_up = None
    if origin_base != "-":
        default_up = _parse_origin_pair(origin_base, credential)
        if default_up is None:
            return 2
    up_map = {}
    for prov, (ob, cr) in (upstreams or {}).items():
        if prov not in ("anthropic", "openai", "zai"):
            print(f"broker: VOID, unknown upstream provider {prov!r}", file=sys.stderr)
            return 2
        parsed_up = _parse_origin_pair(ob, cr)
        if parsed_up is None:
            return 2
        up_map[prov] = parsed_up
    if default_up is None and not up_map:
        print("broker: VOID, specify <origin-base> or at least one --upstream", file=sys.stderr)
        return 2
    d = os.path.dirname(sock)
    if d and not os.path.isdir(d):
        print(f"broker: VOID, no dir {d} for the socket", file=sys.stderr)
        return 2
    Handler.origin = default_up or next(iter(up_map.values()))
    srv = UnixHTTPServer(sock, Handler)
    srv.log, srv.max_body, srv.turn_cap = log, max_body, int(turn_cap or 0)
    srv.turn_output_cap = int(turn_output_cap or 0)
    srv.turn_usd_cap = float(turn_usd_cap or 0.0)
    srv.seat_key = os.environ.get("OPERATOR_BROKER_SEAT_KEY", "")
    srv._totals_lock = threading.Lock()
    srv._totals = {}

    def _get_totals(scope):
        with srv._totals_lock:
            rec = srv._totals.get(scope) or (0, 0, 0.0)
            return rec

    def _add_totals(scope, d_in, d_out, d_usd):
        with srv._totals_lock:
            p_in, p_out, p_usd = srv._totals.get(scope) or (0, 0, 0.0)
            srv._totals[scope] = (p_in + int(d_in), p_out + int(d_out), p_usd + float(d_usd))

    def _select_upstream(route_path, model_s):
        ml = (model_s or "").lower()
        if route_path == "/v1/responses":
            return up_map.get("openai") or default_up
        if route_path == "/v1/messages":
            if "glm" in ml:
                return up_map.get("zai") or default_up
            return up_map.get("anthropic") or default_up
        return default_up

    srv.get_totals = _get_totals
    srv.add_totals = _add_totals
    srv.select_upstream = _select_upstream
    print(sock, flush=True)
    srv.serve_forever()
    return 0


def selftest():
    """The broker re-originates one scripted turn against a loopback origin,
    refuses the routes it doesn't serve, and never forwards the client's own
    authorization. The origin is upstream.py speaking the anthropic wire."""
    import subprocess
    import tempfile
    import shutil
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 4 << 30)
                       if resource.getrlimit(resource.RLIMIT_AS)[1] in (-1,) or
                       resource.getrlimit(resource.RLIMIT_AS)[1] >= 4 << 30
                       else resource.getrlimit(resource.RLIMIT_AS))
    ok, bad = [0], [0]

    def check(cond, label):
        if cond:
            ok[0] += 1
        else:
            bad[0] += 1
            print(f"FAIL {label}", file=sys.stderr)

    here = os.path.dirname(os.path.abspath(__file__))
    upstream = os.path.join(here, "upstream.py")
    broker = os.path.abspath(__file__)
    T = tempfile.mkdtemp(prefix="broker-st.")
    try:
        # a loopback origin speaking the anthropic SSE wire (staging face:
        # loopback http is the one plain scheme the broker accepts)
        origin_srv = os.path.join(T, "origin.py")
        with open(origin_srv, "w") as f:
            f.write(
                "import json, ssl, sys, threading\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "seen = []\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    protocol_version = 'HTTP/1.1'\n"
                "    def log_message(self, *a): pass\n"
                "    def do_POST(self):\n"
                "        n = int(self.headers.get('Content-Length') or 0)\n"
                "        body = self.rfile.read(n)\n"
                "        seen.append((self.path, dict(self.headers), body))\n"
                "        auth = self.headers.get('Authorization', '')\n"
                "        xak = self.headers.get('x-api-key', '')\n"
                "        if auth != 'Bearer engine-secret' or xak != 'engine-secret':\n"
                "            self.send_response(401); self.send_header('Content-Length','0')\n"
                "            self.end_headers(); return\n"
                "        if self.path.split('?')[0].endswith('/v1/messages'):\n"
                "            data = ('data: ' + json.dumps({'type':'message_delta',"
                "'delta':{},'usage':{'input_tokens':7,'output_tokens':3}}) + chr(10) + chr(10)).encode()\n"
                "            self.send_response(200)\n"
                "            self.send_header('Content-Type','text/event-stream')\n"
                "            self.send_header('Content-Length', str(len(data)))\n"
                "            self.end_headers(); self.wfile.write(data)\n"
                "        else:\n"
                "            self.send_response(404); self.send_header('Content-Length','0')\n"
                "            self.end_headers()\n"
                "srv = HTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n")
        p_org = subprocess.Popen([sys.executable, origin_srv],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        port = int(p_org.stdout.readline().strip())
        # the origin is plain http on loopback; the broker demands https, so the
        # selftest rides the https law through a local shim: the broker's origin
        # parse takes https only -- for the test we run the REAL https shape by
        # pointing at the loopback with a scheme the broker accepts. The broker
        # is engine-side; the origin in production is a real https host. Here we
        # verify the RE-ORIGINATION, not TLS itself: run the broker's handler
        # against the loopback by overriding the connection class for the test.
        sock = os.path.join(T, "b.sock")
        logf = os.path.join(T, "b.jsonl")
        p_br = subprocess.Popen([sys.executable, broker, "serve", sock,
                                 f"http://127.0.0.1:{port}/api/anthropic",
                                 "engine-secret", logf],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        sock_out = p_br.stdout.readline().strip().decode()
        check(sock_out == sock, f"A the broker binds its socket: {sock_out!r}")
        import http.client as _hc

        class Unix(_hc.HTTPConnection):
            def __init__(self):
                super().__init__("localhost")

            def connect(self):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(sock)
                self.sock = s

        # a real turn: the client carries a WRONG token; the broker's own must win
        c = Unix()
        c.request("POST", "/v1/messages?beta=true",
                  body=json.dumps({"model": "m", "messages": []}),
                  headers={"Authorization": "Bearer client-guess",
                           "Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        check(r.status == 200, f"B the turn forwards: {r.status}")
        check(b"message_delta" in data, f"B the SSE streams back: {data[:60]!r}")
        import time as _t
        _t.sleep(0.3)  # the handler's log row lands just after the client's read
        rows = [json.loads(x) for x in open(logf)]
        check(rows and rows[0]["status"] == 200 and
              rows[0].get("usage") == {"input_tokens": 7, "output_tokens": 3},
              f"C the log row carries the stream's own usage: {rows}")
        # F a stream that splits the usage line across chunk boundaries still
        # logs its usage (the walk's one null row: the line straddled a read)
        import socket as _s
        origin2 = os.path.join(T, "origin2.py")
        with open(origin2, "w") as f:
            f.write(
                "import json, socket, threading\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    protocol_version = 'HTTP/1.1'\n"
                "    def log_message(self, *a): pass\n"
                "    def do_POST(self):\n"
                "        n = int(self.headers.get('Content-Length') or 0)\n"
                "        self.rfile.read(n)\n"
                "        if not self.path.split('?')[0].endswith('/v1/messages'):\n"
                "            self.send_response(404); self.send_header('Content-Length','0')\n"
                "            self.end_headers(); return\n"
                "        line = (b'data: ' + json.dumps({'type':'message_delta',"
                "'delta':{},'usage':{'input_tokens':11,'output_tokens':5}}).encode()"
                " + b'\\n\\n')\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Type','text/event-stream')\n"
                "        self.send_header('Content-Length', str(len(line)))\n"
                "        self.end_headers()\n"
                "        self.wfile.write(line[:20]); self.wfile.flush()\n"  # split mid-JSON
                "        import time as _t; _t.sleep(0.05)\n"
                "        self.wfile.write(line[20:]); self.wfile.flush()\n"
                "srv = HTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n")
        p_o2 = subprocess.Popen([sys.executable, origin2], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        port2 = int(p_o2.stdout.readline().strip())
        sock2 = os.path.join(T, "b2.sock"); log2 = os.path.join(T, "b2.jsonl")
        p_b2 = subprocess.Popen([sys.executable, broker, "serve", sock2,
                                 f"http://127.0.0.1:{port2}/api/anthropic",
                                 "engine-secret", log2],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p_b2.stdout.readline()

        class Unix2(_hc.HTTPConnection):
            def __init__(self):
                super().__init__("localhost")

            def connect(self):
                sk = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                sk.connect(sock2)
                self.sock = sk
        c4 = Unix2()
        c4.request("POST", "/v1/messages", body="{}",
                   headers={"Content-Type": "application/json"})
        r4 = c4.getresponse()
        r4.read()
        time.sleep(0.3)
        rows2 = [json.loads(x) for x in open(log2)]
        check(rows2 and rows2[0].get("usage") == {"input_tokens": 11, "output_tokens": 5},
              f"F a straddled usage line still lands: {rows2}")
        p_b2.terminate(); p_o2.terminate(); p_b2.wait(timeout=10); p_o2.wait(timeout=10)
        # G the RESPONSES wire: codex speaks it; the usage rides NESTED in
        # response.completed's response object, and the route serves it
        origin3 = os.path.join(T, "origin3.py")
        with open(origin3, "w") as f:
            f.write(
                "import json\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    protocol_version = 'HTTP/1.1'\n"
                "    def log_message(self, *a): pass\n"
                "    def do_POST(self):\n"
                "        n = int(self.headers.get('Content-Length') or 0)\n"
                "        self.rfile.read(n)\n"
                "        if not self.path.split('?')[0].endswith('/v1/responses'):\n"
                "            self.send_response(404); "
                "self.send_header('Content-Length','0')\n"
                "            self.end_headers(); return\n"
                "        line = (b'data: ' + json.dumps({'type':'response.completed',"
                "'response':{'usage':{'input_tokens':21,'output_tokens':9,"
                "'total_tokens':30}}}).encode() + b'\\n\\n')\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Type','text/event-stream')\n"
                "        self.send_header('Content-Length', str(len(line)))\n"
                "        self.end_headers()\n"
                "        self.wfile.write(line)\n"
                "srv = HTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n")
        p_o3 = subprocess.Popen([sys.executable, origin3], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        port3 = int(p_o3.stdout.readline().strip())
        sock3 = os.path.join(T, "b3.sock"); log3 = os.path.join(T, "b3.jsonl")
        p_b3 = subprocess.Popen([sys.executable, broker, "serve", sock3,
                                 f"http://127.0.0.1:{port3}", "engine-secret",
                                 log3],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p_b3.stdout.readline()

        class Unix3(_hc.HTTPConnection):
            def __init__(self):
                super().__init__("localhost")

            def connect(self):
                sk = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                sk.connect(sock3)
                self.sock = sk
        c5 = Unix3()
        c5.request("POST", "/v1/responses", body=json.dumps({"model": "m"}),
                   headers={"Authorization": "Bearer client-guess",
                            "Content-Type": "application/json"})
        r5 = c5.getresponse()
        data5 = r5.read()
        check(r5.status == 200 and b"response.completed" in data5,
              f"G the responses wire forwards: {r5.status} {data5[:60]!r}")
        time.sleep(0.3)
        rows3 = [json.loads(x) for x in open(log3)]
        check(rows3 and rows3[0].get("usage") ==
              {"input_tokens": 21, "output_tokens": 9, "total_tokens": 30},
              f"G the nested usage lands in the row: {rows3}")
        p_b3.terminate(); p_o3.terminate(); p_b3.wait(timeout=10); p_o3.wait(timeout=10)
        # H the turn cap: a wire that reports its usage EARLY is cut mid-stream
        # the moment the input ceiling (fresh + cache-read) is crossed -- the
        # tail never reaches the client and the row records capped; the same
        # stream under a higher cap flows whole
        origin_h = os.path.join(T, "origin_h.py")
        with open(origin_h, "w") as f:
            f.write(
                "import json\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    protocol_version = 'HTTP/1.1'\n"
                "    def log_message(self, *a): pass\n"
                "    def do_POST(self):\n"
                "        n = int(self.headers.get('Content-Length') or 0)\n"
                "        self.rfile.read(n)\n"
                "        ev1 = b'data: ' + json.dumps({'type':'message_start','usage':"
                "{'input_tokens': 900, 'cache_read_input_tokens': 100}}).encode() + b'\\n\\n'\n"
                "        ev2 = b'data: ' + json.dumps({'type':'message_delta','delta':{}})"
                ".encode() + b'\\n\\n'\n"
                "        body = ev1 + ev2\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Type', 'text/event-stream')\n"
                "        self.send_header('Content-Length', str(len(body)))\n"
                "        self.end_headers()\n"
                "        self.wfile.write(body)\n"
                "srv = HTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n")
        p_oh = subprocess.Popen([sys.executable, origin_h], stdout=subprocess.PIPE)
        port_h = int(p_oh.stdout.readline().strip())
        for cap_v, want_tail, want_capped in ((50, False, True), (5000, True, False)):
            sock_h = os.path.join(T, f"bh{cap_v}.sock")
            log_h = os.path.join(T, f"bh{cap_v}.jsonl")
            p_bh = subprocess.Popen([sys.executable, broker, "serve", sock_h,
                                     f"http://127.0.0.1:{port_h}", "engine-secret",
                                     log_h, "--turn-input-cap", str(cap_v)],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p_bh.stdout.readline()

            class UnixH(_hc.HTTPConnection):
                def __init__(self):
                    super().__init__("localhost")

                def connect(self):
                    sk = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                    sk.connect(sock_h)
                    self.sock = sk
            ch = UnixH()
            ch.request("POST", "/v1/messages", body="{}",
                       headers={"Content-Type": "application/json"})
            rh = ch.getresponse()
            try:
                data_h = rh.read()
            except (_hc.IncompleteRead, OSError):
                data_h = b""
            time.sleep(0.3)
            rows_h = [json.loads(x) for x in open(log_h)]
            check((b"message_delta" in data_h) == want_tail
                  and bool(rows_h[0].get("capped")) == want_capped,
                  f"H the turn cap cuts at the ceiling (cap={cap_v}): "
                  f"tail={want_tail} rows={rows_h}")
            p_bh.terminate(); p_bh.wait(timeout=10)
        p_oh.terminate(); p_oh.wait(timeout=10)
        # H2 real Anthropic nested message.usage + usage past 64 KiB + non-streaming JSON
        origin_h2 = os.path.join(T, "origin_h2.py")
        with open(origin_h2, "w") as f:
            f.write(
                "import json\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    protocol_version = 'HTTP/1.1'\n"
                "    def log_message(self, *a): pass\n"
                "    def do_POST(self):\n"
                "        n = int(self.headers.get('Content-Length') or 0)\n"
                "        req = json.loads(self.rfile.read(n).decode() or '{}')\n"
                "        mode = req.get('mode', 'nested')\n"
                "        if mode == 'json':\n"
                "            body = json.dumps({'id':'m1','usage':{'input_tokens':800,'output_tokens':12}}).encode()\n"
                "            self.send_response(200)\n"
                "            self.send_header('Content-Type', 'application/json')\n"
                "            self.send_header('Content-Length', str(len(body)))\n"
                "            self.end_headers(); self.wfile.write(body); return\n"
                "        if mode == 'json_big':\n"
                "            body = b'{\"pad\":\"' + b'A' * 2048 + b'\",\"usage\":{\"input_tokens\":999}}'\n"
                "            self.send_response(200)\n"
                "            self.send_header('Content-Type', 'application/json')\n"
                "            self.send_header('Content-Length', str(len(body)))\n"
                "            self.end_headers(); self.wfile.write(body); return\n"
                "        if mode == 'big':\n"
                "            pad = b'data: ' + json.dumps({'type':'content_block_delta','text':'x'*70000}).encode() + b'\\n\\n'\n"
                "            ev = b'data: ' + json.dumps({'type':'response.completed','response':{'usage':{'input_tokens':700,'output_tokens':5}}}).encode() + b'\\n\\n'\n"
                "            body = pad + ev\n"
                "        else:\n"
                "            ev1 = b'data: ' + json.dumps({'type':'message_start','message':{'usage':{'input_tokens':600,'cache_read_input_tokens':50}}}).encode() + b'\\n\\n'\n"
                "            ev2 = b'data: ' + json.dumps({'type':'message_delta','usage':{'output_tokens':9}}).encode() + b'\\n\\n'\n"
                "            body = ev1 + ev2\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Type', 'text/event-stream')\n"
                "        self.send_header('Content-Length', str(len(body)))\n"
                "        self.end_headers(); self.wfile.write(body)\n"
                "srv = HTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n")
        p_oh2 = subprocess.Popen([sys.executable, origin_h2], stdout=subprocess.PIPE)
        port_h2 = int(p_oh2.stdout.readline().strip())
        sock_h2 = os.path.join(T, "bh2.sock")
        log_h2 = os.path.join(T, "bh2.jsonl")
        p_bh2 = subprocess.Popen([sys.executable, broker, "serve", sock_h2,
                                  f"http://127.0.0.1:{port_h2}", "-",
                                  log_h2, "--turn-input-cap", "500", "--max-body", "1024"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 env=dict(os.environ, OPERATOR_BROKER_CREDENTIAL="env-secret"))
        p_bh2.stdout.readline()

        class UnixH2(_hc.HTTPConnection):
            def __init__(self):
                super().__init__("localhost")

            def connect(self):
                sk = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                sk.connect(sock_h2)
                self.sock = sk

        for mode_v in ("nested", "big", "json"):
            c_h2 = UnixH2()
            c_h2.request("POST", "/v1/messages", body=json.dumps({"mode": mode_v}),
                         headers={"Content-Type": "application/json",
                                  "X-Api-Key": "client-bogus",
                                  "Accept-Encoding": "gzip"})
            r_h2 = c_h2.getresponse()
            try:
                r_h2.read()
            except (_hc.IncompleteRead, OSError):
                pass
        time.sleep(0.3)
        rows_h2 = [json.loads(x) for x in open(log_h2)]
        check(len(rows_h2) == 3 and all(r.get("capped") for r in rows_h2),
              f"H2 nested Anthropic, >64KiB SSE, and stream:false JSON all cap: {rows_h2}")
        c_hb = UnixH2()
        c_hb.request("POST", "/v1/messages", body=json.dumps({"mode": "json_big"}),
                     headers={"Content-Type": "application/json"})
        r_hb = c_hb.getresponse()
        r_hb.read()
        check(r_hb.status == 502,
              f"H2b oversized non-streaming JSON response refuses 502: {r_hb.status}")
        p_bh2.terminate()
        p_oh2.terminate()
        p_bh2.wait(timeout=10)
        p_oh2.wait(timeout=10)
        # H3 http://localhost.evil.test must refuse as non-loopback
        bad_orig = subprocess.run([sys.executable, broker, "serve", os.path.join(T, "bad.sock"),
                                   "http://localhost.evil.test", "k", os.devnull],
                                  capture_output=True, text=True)
        check(bad_orig.returncode == 2, f"H3 prefix-spoofed http origin refuses: {bad_orig.returncode}")
        # a route the broker doesn't serve
        c2 = Unix()
        c2.request("POST", "/v1/other", body="{}",
                   headers={"Content-Type": "application/json"})
        r2 = c2.getresponse()
        r2.read()
        check(r2.status == 404, f"D unknown routes refuse: {r2.status}")
        c2t = Unix()
        c2t.request("POST", "/v1/extra/../v1/messages", body="{}",
                    headers={"Content-Type": "application/json"})
        r2t = c2t.getresponse()
        r2t.read()
        check(r2t.status == 404,
              f"D traversal-shaped routes refuse the exact law: {r2t.status}")
        # a bodyless request refuses
        c3 = Unix()
        c3.request("POST", "/v1/messages", body="",
                   headers={"Content-Type": "application/json"})
        r3 = c3.getresponse()
        r3.read()
        check(r3.status in (400, 413), f"E an empty body refuses: {r3.status}")
        # F HMAC seat authentication helper verifies valid op-seat token and rejects forgery
        sk = "test-seat-key-01"
        good_mac = hmac.new(sk.encode(), b"writer", hashlib.sha256).hexdigest()[:16]
        check(_verify_client_seat({"x-api-key": f"op-seat:writer:{good_mac}"}, sk) == (True, "writer"),
              "F valid op-seat token verifies")
        check(_verify_client_seat({"x-api-key": f"op-seat:reviewer:{good_mac}"}, sk) == (False, None),
              "F cross-seat forged token rejected")
        good_m4 = hmac.new(sk.encode(), b"writer:att-01", hashlib.sha256).hexdigest()[:16]
        check(_verify_client_token({"x-api-key": f"op-seat:writer:att-01:{good_m4}"}, sk) == (True, "writer", "att-01"),
              "F2 valid 4-part attempt-bound token verifies")
        check(_verify_client_token({"x-api-key": f"op-seat:writer:att-02:{good_m4}"}, sk) == (False, None, None),
              "F2 cross-attempt forged token rejected")
        check((_compute_cost_usd("claude-sonnet-4-6", {"input_tokens": 1000, "output_tokens": 200}) or 0) > 0,
              "F3 deterministic model USD pricing computes positive cost")
        # I cumulative per-attempt pre-flight 429 + multi-provider routing
        origin_mp = os.path.join(T, "origin_mp.py")
        with open(origin_mp, "w") as f:
            f.write(
                "import json, time\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    protocol_version = 'HTTP/1.1'\n"
                "    def log_message(self, *a): pass\n"
                "    def do_POST(self):\n"
                "        n = int(self.headers.get('Content-Length') or 0)\n"
                "        raw = self.rfile.read(n)\n"
                "        auth = self.headers.get('Authorization', '')\n"
                "        if b'\"stream\": true' in raw or b'\"stream\":true' in raw:\n"
                "            ev1 = b'data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":300}}}\\n\\n'\n"
                "            pad = b': ' + (b'x' * 262144) + b'\\n\\n'\n"
                "            ev2 = b'data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":50}}\\n\\n'\n"
                "            out = ev1 + pad + ev2\n"
                "            self.send_response(200)\n"
                "            self.send_header('Content-Type','text/event-stream')\n"
                "            self.send_header('Content-Length', str(len(out)))\n"
                "            self.end_headers()\n"
                "            self.wfile.write(ev1 + pad); self.wfile.flush()\n"
                "            time.sleep(0.05)\n"
                "            self.wfile.write(ev2); self.wfile.flush()\n"
                "            return\n"
                "        body = json.dumps({'id':'x','auth':auth,'usage':{'input_tokens':300,'output_tokens':50}}).encode()\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Type','application/json')\n"
                "        self.send_header('Content-Length', str(len(body)))\n"
                "        self.end_headers(); self.wfile.write(body)\n"
                "srv = HTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n")
        p_omp = subprocess.Popen([sys.executable, origin_mp], stdout=subprocess.PIPE)
        port_mp = int(p_omp.stdout.readline().strip())
        sock_mp = os.path.join(T, "bmp.sock")
        log_mp = os.path.join(T, "bmp.jsonl")
        p_bmp = subprocess.Popen(
            [sys.executable, broker, "serve", sock_mp, "-", "-", log_mp,
             "--turn-input-cap", "250",
             "--upstream", f"anthropic=http://127.0.0.1:{port_mp},env:TEST_ANTH_CRED",
             "--upstream", f"openai=http://127.0.0.1:{port_mp},env:TEST_OAI_CRED",
             "--upstream", f"zai=http://127.0.0.1:{port_mp},env:TEST_ZAI_CRED"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, OPERATOR_BROKER_SEAT_KEY=sk,
                     TEST_ANTH_CRED="anth-k", TEST_OAI_CRED="oai-k", TEST_ZAI_CRED="zai-k"))
        p_bmp.stdout.readline()

        class UnixMP(_hc.HTTPConnection):
            def __init__(self):
                super().__init__("localhost")

            def connect(self):
                sk_s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                sk_s.connect(sock_mp)
                self.sock = sk_s

        tok_a1 = f"op-seat:writer:a1:{hmac.new(sk.encode(), b'writer:a1', hashlib.sha256).hexdigest()[:16]}"
        tok_a2 = f"op-seat:writer:a2:{hmac.new(sk.encode(), b'writer:a2', hashlib.sha256).hexdigest()[:16]}"
        # Call 1 on a1 consumes 300 > 250 -> 429; pre-flight call 2 on a1 also 429 without hitting upstream
        for _ in range(2):
            cmp1 = UnixMP()
            cmp1.request("POST", "/v1/messages", body=json.dumps({"model": "claude-sonnet-4-6"}),
                         headers={"Content-Type": "application/json", "x-api-key": tok_a1})
            rmp1 = cmp1.getresponse()
            rmp1.read()
            check(rmp1.status == 429, f"I cumulative cap rejects attempt a1: {rmp1.status}")
        time.sleep(0.2)
        rows_mp1 = [json.loads(x) for x in open(log_mp)]
        check(len(rows_mp1) == 2 and "usage" in rows_mp1[0] and "usage" not in rows_mp1[1],
              f"I1b second call blocked pre-flight before hitting upstream: {rows_mp1}")
        # Separate attempt a2 with higher cap exercises multi-provider routing
        p_bmp.terminate()
        p_bmp.wait(timeout=10)
        sock_mp2 = os.path.join(T, "bmp2.sock")
        log_mp2 = os.path.join(T, "bmp2.jsonl")
        p_bmp2 = subprocess.Popen(
            [sys.executable, broker, "serve", sock_mp2, "-", "-", log_mp2,
             "--turn-input-cap", "500",
             "--upstream", f"anthropic=http://127.0.0.1:{port_mp},env:TEST_ANTH_CRED",
             "--upstream", f"openai=http://127.0.0.1:{port_mp},env:TEST_OAI_CRED",
             "--upstream", f"zai=http://127.0.0.1:{port_mp},env:TEST_ZAI_CRED"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, OPERATOR_BROKER_SEAT_KEY=sk,
                     TEST_ANTH_CRED="anth-k", TEST_OAI_CRED="oai-k", TEST_ZAI_CRED="zai-k"))
        p_bmp2.stdout.readline()

        class UnixMP2(_hc.HTTPConnection):
            def __init__(self):
                super().__init__("localhost")

            def connect(self):
                sk_s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                sk_s.connect(sock_mp2)
                self.sock = sk_s

        # Multi-provider routing: /v1/responses -> oai-k, /v1/messages glm -> zai-k
        c_oai = UnixMP2()
        c_oai.request("POST", "/v1/responses", body=json.dumps({"model": "gpt-5-codex"}),
                      headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok_a1}"})
        r_oai = c_oai.getresponse()
        d_oai = json.loads(r_oai.read().decode())
        # Second call on same attempt a1 (300 + 300 = 600 > 500) hits cumulative cap 429!
        c_oai2 = UnixMP2()
        c_oai2.request("POST", "/v1/responses", body=json.dumps({"model": "gpt-5-codex"}),
                       headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok_a1}"})
        r_oai2 = c_oai2.getresponse()
        r_oai2.read()
        # Separate attempt a2 with GLM model routes to zai-k cleanly!
        c_zai = UnixMP2()
        c_zai.request("POST", "/v1/messages", body=json.dumps({"model": "GLM-5.3-Flash"}),
                      headers={"Content-Type": "application/json", "x-api-key": tok_a2})
        r_zai = c_zai.getresponse()
        d_zai = json.loads(r_zai.read().decode())
        check(r_oai.status == 200 and d_oai.get("auth") == "Bearer oai-k"
              and r_oai2.status == 429
              and r_zai.status == 200 and d_zai.get("auth") == "Bearer zai-k",
              f"I2 multi-provider routing and cumulative sub-cap multi-call cap: oai={d_oai} r2={r_oai2.status} zai={d_zai}")
        # I3 (G1) early client disconnect on SSE stream still logs usage + client_gone and charges attempt cap
        tok_g1 = f"op-seat:writer:g1:{hmac.new(sk.encode(), b'writer:g1', hashlib.sha256).hexdigest()[:16]}"
        for _ in range(2):
            cs_g1 = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            cs_g1.connect(sock_mp2)
            req_b = json.dumps({"model": "claude-sonnet-4-6", "stream": True}).encode()
            cs_g1.sendall(
                b"POST /v1/messages HTTP/1.1\r\nHost: localhost\r\n"
                + f"x-api-key: {tok_g1}\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(req_b)}\r\n\r\n".encode()
                + req_b
            )
            cs_g1.recv(32)
            cs_g1.close()
            time.sleep(0.2)
        c_g1_3 = UnixMP2()
        c_g1_3.request("POST", "/v1/messages", body=json.dumps({"model": "claude-sonnet-4-6"}),
                       headers={"Content-Type": "application/json", "x-api-key": tok_g1})
        r_g1_3 = c_g1_3.getresponse()
        r_g1_3.read()
        rows_g1 = [json.loads(x) for x in open(log_mp2) if json.loads(x).get("attempt") == "g1"]
        check(len(rows_g1) == 3
              and rows_g1[0].get("client_gone") is True
              and (rows_g1[0].get("usage") or {}).get("input_tokens") == 300
              and (rows_g1[0].get("usage") or {}).get("output_tokens") == 50
              and (rows_g1[0].get("cost_usd") or 0) > 0
              and r_g1_3.status == 429,
              f"I3 early client disconnect still logs usage/cost and enforces attempt cap: rows={rows_g1} r3={r_g1_3.status}")
        p_bmp2.terminate()
        p_omp.terminate()
        p_bmp2.wait(timeout=10)
        p_omp.wait(timeout=10)
        p_br.terminate()
        p_org.terminate()
        p_br.wait(timeout=10)
        p_org.wait(timeout=10)
    finally:
        shutil.rmtree(T, ignore_errors=True)
    print(f"selftest: OK ({ok[0]} checks)" if ok[0] and not bad[0]
          else "selftest: FAIL")
    return 0 if ok[0] and not bad[0] else 1


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) >= 5 and argv[1] == "serve":
        cap = 0
        out_cap = 0
        usd_cap = 0.0
        max_body = MAX_BODY
        upstreams = {}
        i = 6
        while i < len(argv):
            if argv[i] == "--turn-input-cap":
                if i + 1 >= len(argv) or not argv[i + 1].isdigit():
                    print("broker: usage: --turn-input-cap <tokens>", file=sys.stderr)
                    return 2
                cap = int(argv[i + 1])
                i += 2
            elif argv[i] == "--turn-output-cap":
                if i + 1 >= len(argv) or not argv[i + 1].isdigit():
                    print("broker: usage: --turn-output-cap <tokens>", file=sys.stderr)
                    return 2
                out_cap = int(argv[i + 1])
                i += 2
            elif argv[i] == "--turn-usd-cap":
                if i + 1 >= len(argv):
                    print("broker: usage: --turn-usd-cap <usd>", file=sys.stderr)
                    return 2
                try:
                    usd_cap = float(argv[i + 1])
                except ValueError:
                    print("broker: usage: --turn-usd-cap <usd>", file=sys.stderr)
                    return 2
                if usd_cap < 0:
                    return 2
                i += 2
            elif argv[i] == "--upstream":
                if i + 1 >= len(argv) or "=" not in argv[i + 1] or "," not in argv[i + 1].split("=", 1)[1]:
                    print("broker: usage: --upstream <anthropic|openai|zai>=<origin>,<cred>", file=sys.stderr)
                    return 2
                prov, rest = argv[i + 1].split("=", 1)
                ob, cr = rest.split(",", 1)
                upstreams[prov.strip()] = (ob.strip(), cr.strip())
                i += 2
            elif argv[i] == "--max-body":
                if i + 1 >= len(argv) or not argv[i + 1].isdigit():
                    print("broker: usage: --max-body <bytes>", file=sys.stderr)
                    return 2
                max_body = int(argv[i + 1])
                i += 2
            else:
                print(f"broker: unknown flag {argv[i]!r}", file=sys.stderr)
                return 2
        try:
            return serve(argv[2], argv[3], argv[4],
                         argv[5] if len(argv) > 5 else os.devnull,
                         max_body=max_body, turn_cap=cap,
                         turn_output_cap=out_cap, turn_usd_cap=usd_cap,
                         upstreams=upstreams)
        except KeyboardInterrupt:
            return 0
    print(__doc__.strip().splitlines()[-2] if False else
          "usage: broker.py serve <sock> <origin-base> <credential> <log> [--upstream P=URL,CRED]... | --selftest",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
