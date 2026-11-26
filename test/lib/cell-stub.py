#!/usr/bin/env python3
"""cell-stub -- the conformance upstream: speaks the three CLIs' wire dialects
and ISSUES the exact tool call each cell names, then records the tool_result
that flows back. The denied call's receipt is that tool_result -- the refusal
text the CLI returns to the model, visible here in the next request's body.

Content-addressed, never turn-counted: a request carrying a tool_result gets
the done response; every other request gets the tool call. A CLI's incidental
first request (model metadata, token counting) can never steal the tool turn.

dialects (CELL_DIALECT env): anthropic (claude; tool_use blocks over SSE),
codex (responses wire: function_call items, total_tokens present),
opencode (chat completions: tool-call chunks then finish).

usage: cell-stub.py <log> <tool_json_file>     prints the port, serves until killed
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True

DIALECT = os.environ.get("CELL_DIALECT", "anthropic")


def sse(events):
    return "".join(f"event: {e[0]}\ndata: {json.dumps(e[1])}\n\n" for e in events).encode()


def anthropic_tool_events(tool):
    return [
        ("message_start", {"type": "message_start", "message": {
            "id": "m_cell", "type": "message", "role": "assistant",
            "content": [], "usage": {"input_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "tool_use",
                                                   "id": "toolu_cell",
                                                   "name": tool["name"],
                                                   "input": {}}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "input_json_delta",
                                           "partial_json": json.dumps(tool["input"])}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta",
                           "delta": {"stop_reason": "tool_use"},
                           "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]


def anthropic_done_events():
    return [
        ("message_start", {"type": "message_start", "message": {
            "id": "m_done", "type": "message", "role": "assistant",
            "content": [], "usage": {"input_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": "cell-done"}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                           "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]


def codex_tool_events(tool):
    # the responses wire: a function_call item; usage carries total_tokens
    # (P7: codex's parser requires it)
    return [
        ("response.created", {"type": "response.created"}),
        ("response.output_item.added", {
            "type": "response.output_item.added", "output_index": 0,
            "item": {"type": "function_call", "id": "toolu_cell", "call_id": "toolu_cell",
                     "name": tool["name"], "arguments": "", "status": "in_progress"}}),
        ("response.function_call_arguments.delta", {
            "type": "response.function_call_arguments.delta", "item_id": "toolu_cell",
            "output_index": 0, "delta": json.dumps(tool["input"])}),
        ("response.output_item.done", {
            "type": "response.output_item.done", "output_index": 0,
            "item": {"type": "function_call", "id": "toolu_cell", "call_id": "toolu_cell",
                     "name": tool["name"], "arguments": json.dumps(tool["input"]),
                     "status": "completed"}}),
        ("response.completed", {
            "type": "response.completed",
            "response": {"id": "r_cell", "status": "completed",
                         "usage": {"input_tokens": 1, "output_tokens": 1,
                                   "total_tokens": 2}}}),
    ]


def codex_done_events():
    return [
        ("response.created", {"type": "response.created"}),
        ("response.output_item.added", {
            "type": "response.output_item.added", "output_index": 0,
            "item": {"type": "message", "id": "msg_done", "role": "assistant",
                     "status": "in_progress", "content": []}}),
        ("response.output_text.delta", {
            "type": "response.output_text.delta", "item_id": "msg_done",
            "output_index": 0, "content_index": 0, "delta": "cell-done"}),
        ("response.output_item.done", {
            "type": "response.output_item.done",
            "item": {"type": "message", "id": "msg_done", "role": "assistant",
                     "status": "completed",
                     "content": [{"type": "output_text", "text": "cell-done"}]}}),
        ("response.completed", {
            "type": "response.completed",
            "response": {"id": "r_done", "status": "completed",
                         "usage": {"input_tokens": 1, "output_tokens": 1,
                                   "total_tokens": 2}}}),
    ]


def opencode_tool_events(tool):
    return [
        ("response.chunk", {"type": "tool_call_chunk", "id": "c1",
                            "toolCallId": "toolu_cell", "toolName": tool["name"],
                            "args": tool["input"]}),
        ("response.chunk", {"type": "finish", "toolCallId": "toolu_cell",
                            "args": tool["input"]}),
    ]


def opencode_done_events():
    return [
        ("response.chunk", {"type": "text", "text": "cell-done"}),
        ("response.chunk", {"type": "finish", "reason": "stop",
                            "usage": {"total": 2, "input": 1, "output": 1,
                                      "reasoning": 0, "cache": {"write": 0, "read": 0}}}),
    ]


TOOL_EVENTS = {"anthropic": anthropic_tool_events, "codex": codex_tool_events,
                "opencode": opencode_tool_events}
DONE_EVENTS = {"anthropic": anthropic_done_events, "codex": codex_done_events,
               "opencode": opencode_done_events}
# how each dialect spells "the tool result came back"
MARKERS = {"anthropic": b"tool_result", "codex": b"function_call_output",
           "opencode": b"toolResult"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(0, len(payload), 512):
            c = payload[i:i + 512]
            self.wfile.write(f"{len(c):x}\r\n".encode() + c + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n if n else 0)
        with open(os.environ["CELL_LOG"], "a", encoding="utf-8") as f:
            f.write(raw.decode("utf-8", "replace") + "\n--REQ--\n")
        # content-addressed: a tool result in the body means the work is done
        if MARKERS[DIALECT] in raw:
            self._send(sse(DONE_EVENTS[DIALECT]()))
            return
        with open(os.environ["CELL_TOOL"]) as f:
            tool = json.load(f)
        self._send(sse(TOOL_EVENTS[DIALECT](tool)))


srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(srv.server_address[1], flush=True)
srv.serve_forever()
