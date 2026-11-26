"""
A healthy, boring MCP server over Streamable HTTP on 127.0.0.1 with no auth.

Used for the Part A.3 live false-positive check (what `axiom live --url` says about a
benign localhost server). It is deliberately ordinary: three harmless tools, one static
resource, one prompt, no instructions. Nothing here reads files, runs commands, or
talks to the network.

Run:  python healthy_http_server.py [port]      (default 127.0.0.1:3010, endpoint /mcp)
Requires the MCP Python SDK 2.x (``mcp>=2``) and uvicorn.
"""

from __future__ import annotations

import sys

import uvicorn
from mcp.server.mcpserver import MCPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 3010

mcp = MCPServer("healthy-notes")


@mcp.tool()
def word_count(text: str) -> int:
    """Count the words in a piece of text."""
    return len(text.split())


@mcp.tool()
def ping() -> str:
    """Return pong."""
    return "pong"


@mcp.tool()
def to_upper(text: str) -> str:
    """Upper-case a piece of text."""
    return text.upper()


@mcp.resource("notes://readme")
def readme() -> str:
    return "healthy-notes is a demonstration server. It stores nothing and calls nothing."


@mcp.prompt()
def summarise(text: str) -> str:
    """Ask for a one-paragraph summary of the given text."""
    return f"Summarise the following text in one paragraph:\n\n{text}"


if __name__ == "__main__":
    uvicorn.run(mcp.streamable_http_app(), host="127.0.0.1", port=PORT, log_level="warning")
