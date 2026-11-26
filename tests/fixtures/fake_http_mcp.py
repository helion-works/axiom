"""
Fake remote MCP servers for transport tests — standard library only.

    with FakeStreamableHTTP(sse_replies=True) as srv:   # POST /mcp, replies as SSE (FastMCP default)
        url = srv.url                                   # http://127.0.0.1:<port>/mcp
    with FakeStreamableHTTP(sse_replies=False) as srv:  # replies as application/json
    with FakeLegacySSE() as srv:                        # GET /sse -> endpoint event; POST /messages -> 202

Both serve one tool, one text resource (note://hello) plus one http resource and one
image resource that must be skipped, and two prompts (one with a required argument).
`srv.calls` records every JSON-RPC method received; `tools/call` is answered with an
error and recorded so a test can assert it never happened.
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INSTRUCTIONS = os.environ.get("FAKE_MCP_INSTRUCTIONS", "A fake remote server.")
RESOURCE_TEXT = os.environ.get("FAKE_RESOURCE_TEXT", "Hello from the fake remote server.")
PROMPT_TEXT = os.environ.get("FAKE_PROMPT_TEXT", "Say hello.")


def _result(method, params):
    if method == "initialize":
        return {"protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "fake-remote", "version": "0.0.1"},
                "instructions": INSTRUCTIONS}
    if method == "tools/list":
        return {"tools": [{"name": "echo", "description": "Echo the text back.",
                           "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
    if method == "resources/list":
        return {"resources": [
            {"uri": "note://hello", "name": "hello", "mimeType": "text/plain"},
            {"uri": "https://example.com/remote", "name": "remote", "mimeType": "text/plain"},
            {"uri": "img://logo", "name": "logo", "mimeType": "image/png"},
        ]}
    if method == "resources/read":
        if params.get("uri") == "note://hello":
            return {"contents": [{"uri": "note://hello", "mimeType": "text/plain", "text": RESOURCE_TEXT}]}
        raise KeyError("must not read " + str(params.get("uri")))
    if method == "prompts/list":
        return {"prompts": [{"name": "free", "arguments": []},
                            {"name": "needs_arg", "arguments": [{"name": "topic", "required": True}]}]}
    if method == "prompts/get":
        if params.get("name") == "free":
            return {"messages": [{"role": "user", "content": {"type": "text", "text": PROMPT_TEXT}}]}
        raise KeyError("must not fetch " + str(params.get("name")))
    raise KeyError(method)


class _Base(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, handler):
        super().__init__(("127.0.0.1", 0), handler)
        self.calls = []
        self.lock = threading.Lock()

    def record(self, method):
        with self.lock:
            self.calls.append(method)

    def __enter__(self):
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.shutdown()
        self.server_close()


# ---------------------------------------------------------------------------
class FakeStreamableHTTP(_Base):
    def __init__(self, sse_replies=True, require_accept=True):
        self.sse_replies = sse_replies
        self.require_accept = require_accept
        self.session_id = "sess-" + os.urandom(4).hex()
        super().__init__(_StreamableHandler)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"


class _StreamableHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        srv = self.server
        if self.path != "/mcp":
            self.send_error(404)
            return
        accept = self.headers.get("Accept", "")
        if srv.require_accept and ("text/event-stream" not in accept or "application/json" not in accept):
            self.send_error(406, "Not Acceptable: Client must accept both application/json and text/event-stream")
            return
        length = int(self.headers.get("Content-Length", 0))
        msg = json.loads(self.rfile.read(length) or b"{}")
        method = msg.get("method", "")
        srv.record(method)
        if "id" not in msg:  # notification
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method != "initialize" and self.headers.get("Mcp-Session-Id") != srv.session_id:
            self.send_error(400, "missing or wrong Mcp-Session-Id")
            return
        try:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": _result(method, msg.get("params") or {})}
        except KeyError as e:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": str(e)}}
        body = json.dumps(reply).encode()
        self.send_response(200)
        if method == "initialize":
            self.send_header("Mcp-Session-Id", srv.session_id)
        if srv.sse_replies:
            payload = b"event: message\r\ndata: " + body + b"\r\n\r\n"
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_DELETE(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


# ---------------------------------------------------------------------------
class FakeLegacySSE(_Base):
    def __init__(self):
        self.streams = {}  # session id -> list of pending (bytes) + condition
        super().__init__(_LegacyHandler)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/sse"


class _LegacyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        srv = self.server
        if self.path != "/sse":
            self.send_error(404)
            return
        sid = "s" + os.urandom(4).hex()
        queue, cond = [], threading.Condition()
        srv.streams[sid] = (queue, cond)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(f"event: endpoint\r\ndata: /messages/?session_id={sid}\r\n\r\n".encode())
        self.wfile.flush()
        deadline = time.time() + 30
        try:
            while time.time() < deadline:
                with cond:
                    if not queue:
                        cond.wait(0.5)
                    pending, queue[:] = list(queue), []
                for chunk in pending:
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            srv.streams.pop(sid, None)

    def do_POST(self):
        srv = self.server
        if not self.path.startswith("/messages/"):
            self.send_error(404)
            return
        sid = self.path.split("session_id=")[-1]
        length = int(self.headers.get("Content-Length", 0))
        msg = json.loads(self.rfile.read(length) or b"{}")
        method = msg.get("method", "")
        srv.record(method)
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()
        if "id" not in msg:
            return
        try:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": _result(method, msg.get("params") or {})}
        except KeyError as e:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": str(e)}}
        stream = srv.streams.get(sid)
        if stream:
            queue, cond = stream
            with cond:
                queue.append(b"event: message\r\ndata: " + json.dumps(reply).encode() + b"\r\n\r\n")
                cond.notify()
