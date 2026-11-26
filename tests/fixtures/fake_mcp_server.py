"""
A tiny stdio MCP server for tests — standard library only, no `mcp` package.

Speaks newline-delimited JSON-RPC 2.0 on stdin/stdout. Behaviour is driven by env vars
so a test can plant text where the scanner must look:

  FAKE_MCP_INSTRUCTIONS   text returned as initialize.instructions
  FAKE_RESOURCE_TEXT      text served for the resource note://hello
  FAKE_PROMPT_TEXT        text of the single message of prompt "free"
  FAKE_LISTCHANGED=1      advertise tools.listChanged = true
  FAKE_TOOLS              JSON list of extra tools [{"name","description"}]

It exits with status 3 if it ever receives tools/call: the scanner must never
invoke a tool.
"""

import json
import os
import sys


def _tools():
    tools = [{
        "name": "echo", "description": "Echo the text back.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
    }]
    extra = os.environ.get("FAKE_TOOLS")
    if extra:
        for t in json.loads(extra):
            t.setdefault("inputSchema", {"type": "object", "properties": {}})
            tools.append(t)
    return tools


def _handle(method, params):
    if method == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": os.environ.get("FAKE_LISTCHANGED") == "1"},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {"name": "fake-mcp", "version": "0.0.1"},
            "instructions": os.environ.get("FAKE_MCP_INSTRUCTIONS", "A fake server."),
        }
    if method == "tools/list":
        return {"tools": _tools()}
    if method == "resources/list":
        return {"resources": [
            {"uri": "note://hello", "name": "hello", "mimeType": "text/plain"},
            {"uri": "https://example.com/remote", "name": "remote", "mimeType": "text/plain"},
            {"uri": "img://logo", "name": "logo", "mimeType": "image/png"},
        ]}
    if method == "resources/read":
        uri = params.get("uri")
        if uri == "note://hello":
            return {"contents": [{"uri": uri, "mimeType": "text/plain",
                                  "text": os.environ.get("FAKE_RESOURCE_TEXT", "Hello from the fake server.")}]}
        if uri in ("https://example.com/remote", "img://logo"):
            # Reaching here means the scanner read something it should have skipped.
            sys.exit(4)
        raise KeyError(uri)
    if method == "prompts/list":
        return {"prompts": [
            {"name": "free", "description": "No arguments.", "arguments": []},
            {"name": "needs_arg", "description": "Needs one.",
             "arguments": [{"name": "topic", "required": True}]},
        ]}
    if method == "prompts/get":
        name = params.get("name")
        if name == "free":
            return {"messages": [{"role": "user", "content": {
                "type": "text", "text": os.environ.get("FAKE_PROMPT_TEXT", "Say hello.")}}]}
        if name == "needs_arg":
            sys.exit(5)  # the scanner must skip prompts with required arguments
        raise KeyError(name)
    if method == "tools/call":
        sys.exit(3)
    raise KeyError(method)


def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    for raw in stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        method = msg.get("method", "")
        if "id" not in msg:
            continue  # notification
        try:
            result = _handle(method, msg.get("params") or {})
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        except KeyError as e:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": f"unknown: {e}"}}
        stdout.write((json.dumps(reply) + "\n").encode("utf-8"))
        stdout.flush()


if __name__ == "__main__":
    main()
