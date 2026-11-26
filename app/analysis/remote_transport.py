"""
Remote MCP transports for live scanning: Streamable HTTP and legacy HTTP+SSE.

Both clients expose the same surface the stdio client has, so the live scanner
treats them alike:

    init = await client.connect()          # the initialize result
    await client.list_tools() / list_resources() / list_prompts()
    await client.read_resource(uri) / get_prompt(name, args)
    await client.shutdown()

Streamable HTTP (MCP 2025-03-26 and later): every request is a POST to the MCP
endpoint; the response is either one JSON document or a text/event-stream whose
``message`` events carry JSON-RPC messages. The initialize response sets
``Mcp-Session-Id``, which later requests echo. Notifications return 202.

Legacy HTTP+SSE (MCP 2024-11-05): a GET on the SSE endpoint opens a stream whose
first ``endpoint`` event names the URL to POST messages to; every response comes
back on the stream, so a reader task dispatches them to waiting futures by id.

``connect_remote(url)`` tries the transport the URL suggests first and falls back
to the other. Nothing here ever calls ``tools/call``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import urljoin

MCP_PROTOCOL_VERSION = "2025-06-18"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "axiom", "version": "0.6.0"}
REQUEST_TIMEOUT = 15
CONNECT_TIMEOUT = 20


class RemoteTransportError(ConnectionError):
    pass


def _httpx():
    try:
        import httpx
    except ImportError:  # pragma: no cover
        raise ImportError("httpx is required for remote scanning. Install: pip install httpx")
    return httpx


async def _iter_sse(lines: AsyncIterator[str]) -> AsyncIterator[Tuple[str, str]]:
    """Yield (event, data) pairs from a text/event-stream line iterator."""
    event, data = "message", []
    async for raw in lines:
        line = raw.rstrip("\r")
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data = "message", []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field == "event":
            event = value
        elif field == "data":
            data.append(value)
    if data:
        yield event, "\n".join(data)


class _BaseRemoteClient:
    transport = "remote"

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.extra_headers = dict(headers or {})
        self._id = 0
        self._session = None
        self.server_info: Dict[str, Any] = {}

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _request(self, method: str, params: Optional[dict] = None) -> dict:
        return {"jsonrpc": "2.0", "id": self._next_id(), "method": method, "params": params or {}}

    async def _rpc_call(self, method: str, params: Optional[dict] = None) -> dict:  # pragma: no cover - abstract
        raise NotImplementedError

    async def list_tools(self) -> List[Dict[str, Any]]:
        try:
            return (await self._rpc_call("tools/list")).get("tools", [])
        except Exception:
            return []

    async def list_resources(self) -> List[Dict[str, Any]]:
        try:
            return (await self._rpc_call("resources/list")).get("resources", [])
        except Exception:
            return []

    async def list_prompts(self) -> List[Dict[str, Any]]:
        try:
            return (await self._rpc_call("prompts/list")).get("prompts", [])
        except Exception:
            return []

    async def read_resource(self, uri: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._rpc_call("resources/read", {"uri": uri})
        except Exception:
            return None

    async def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        try:
            return await self._rpc_call("prompts/get", {"name": name, "arguments": arguments or {}})
        except Exception:
            return None

    @staticmethod
    def _unwrap(data: dict) -> dict:
        if "error" in data:
            err = data["error"] or {}
            raise RuntimeError(f"MCP error {err.get('code', '?')}: {err.get('message', 'Unknown')}")
        return data.get("result", {})


# ---------------------------------------------------------------------------
class MCPStreamableHTTPClient(_BaseRemoteClient):
    """Streamable HTTP transport: POST to one endpoint, JSON or SSE replies."""
    transport = "streamable-http"

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        super().__init__(url, headers)
        self.session_id: Optional[str] = None
        self.protocol_version: str = MCP_PROTOCOL_VERSION

    def _headers(self) -> Dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.extra_headers,
        }
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
            h["MCP-Protocol-Version"] = self.protocol_version
        return h

    async def connect(self) -> Dict[str, Any]:
        httpx = _httpx()
        self._session = httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT))
        init = await self._post_and_wait(self._request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"roots": {"listChanged": False}},
            "clientInfo": CLIENT_INFO,
        }), capture_session=True)
        result = self._unwrap(init)
        self.protocol_version = result.get("protocolVersion") or self.protocol_version
        self.server_info = result.get("serverInfo", {})
        await self._notify("notifications/initialized")
        return result

    async def _rpc_call(self, method: str, params: Optional[dict] = None) -> dict:
        return self._unwrap(await self._post_and_wait(self._request(method, params)))

    async def _notify(self, method: str, params: Optional[dict] = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        try:
            await self._session.post(self.url, json=msg, headers=self._headers())
        except Exception:
            pass

    async def _post_and_wait(self, message: dict, capture_session: bool = False) -> dict:
        """POST one request and return its JSON-RPC response (JSON body or SSE stream)."""
        httpx = _httpx()
        want_id = message["id"]
        try:
            async with self._session.stream("POST", self.url, json=message, headers=self._headers()) as resp:
                if capture_session:
                    sid = resp.headers.get("mcp-session-id")
                    if sid:
                        self.session_id = sid
                if resp.status_code >= 400:
                    body = (await resp.aread())[:300].decode(errors="replace")
                    raise RemoteTransportError(f"HTTP {resp.status_code} from {self.url}: {body}")
                ctype = resp.headers.get("content-type", "").lower()
                if ctype.startswith("application/json"):
                    data = json.loads((await resp.aread()).decode("utf-8", errors="replace") or "{}")
                    if isinstance(data, list):
                        for item in data:
                            if item.get("id") == want_id:
                                return item
                        return data[0] if data else {}
                    return data
                if "text/event-stream" in ctype:
                    async for _event, data in _iter_sse(resp.aiter_lines()):
                        try:
                            msg = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(msg, dict) and msg.get("id") == want_id and ("result" in msg or "error" in msg):
                            return msg
                    raise RemoteTransportError("event stream ended without a response")
                body = (await resp.aread())[:300].decode(errors="replace")
                raise RemoteTransportError(f"unexpected content-type {ctype or 'none'} from {self.url}: {body}")
        except httpx.HTTPError as e:
            raise RemoteTransportError(f"streamable HTTP request failed: {e}")

    async def shutdown(self) -> None:
        if self._session:
            try:
                if self.session_id:
                    await self._session.delete(self.url, headers=self._headers(), timeout=5)
            except Exception:
                pass
            await self._session.aclose()
            self._session = None


# ---------------------------------------------------------------------------
class MCPSSEClient(_BaseRemoteClient):
    """Legacy HTTP+SSE transport: GET stream for replies, POST to the announced endpoint."""
    transport = "sse"

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        super().__init__(url, headers)
        self.base_url = url.rstrip("/")
        self.post_url: Optional[str] = None
        self._pending: Dict[int, asyncio.Future] = {}
        self._reader: Optional[asyncio.Task] = None
        self._endpoint_ready: Optional[asyncio.Future] = None
        self._stream_cm = None

    async def connect(self) -> Dict[str, Any]:
        httpx = _httpx()
        self._session = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=CONNECT_TIMEOUT))
        loop = asyncio.get_running_loop()
        self._endpoint_ready = loop.create_future()
        self._reader = asyncio.create_task(self._read_stream())
        try:
            await asyncio.wait_for(self._endpoint_ready, timeout=CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            await self.shutdown()
            raise RemoteTransportError(f"no 'endpoint' event from {self.url} within {CONNECT_TIMEOUT}s")
        result = self._unwrap(await self._send(self._request("initialize", {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })))
        self.server_info = result.get("serverInfo", {})
        try:
            await self._session.post(self.post_url, json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                                     headers=self.extra_headers, timeout=5)
        except Exception:
            pass
        return result

    async def _read_stream(self) -> None:
        httpx = _httpx()
        try:
            async with self._session.stream("GET", self.url, headers={"Accept": "text/event-stream", **self.extra_headers}) as resp:
                if resp.status_code >= 400 or "text/event-stream" not in resp.headers.get("content-type", "").lower():
                    body = (await resp.aread())[:200].decode(errors="replace")
                    raise RemoteTransportError(f"HTTP {resp.status_code} / {resp.headers.get('content-type')} from {self.url}: {body}")
                async for event, data in _iter_sse(resp.aiter_lines()):
                    if event == "endpoint":
                        self.post_url = urljoin(self.url, data.strip())
                        if self._endpoint_ready and not self._endpoint_ready.done():
                            self._endpoint_ready.set_result(True)
                        continue
                    try:
                        msg = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(msg, dict) and msg.get("id") in self._pending:
                        fut = self._pending.pop(msg["id"])
                        if not fut.done():
                            fut.set_result(msg)
        except Exception as e:  # propagate to whoever is waiting
            if self._endpoint_ready and not self._endpoint_ready.done():
                self._endpoint_ready.set_exception(e if isinstance(e, RemoteTransportError) else RemoteTransportError(str(e)))
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RemoteTransportError(f"SSE stream closed: {e}"))
            self._pending.clear()

    async def _send(self, message: dict) -> dict:
        if not self.post_url:
            raise RemoteTransportError("SSE endpoint not announced")
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._pending[message["id"]] = fut
        try:
            resp = await self._session.post(self.post_url, json=message, headers=self.extra_headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code >= 400:
                raise RemoteTransportError(f"HTTP {resp.status_code} posting to {self.post_url}")
            # Some servers answer inline instead of over the stream.
            if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/json"):
                data = resp.json()
                if isinstance(data, dict) and data.get("id") == message["id"]:
                    self._pending.pop(message["id"], None)
                    return data
            return await asyncio.wait_for(fut, timeout=REQUEST_TIMEOUT)
        except asyncio.TimeoutError:
            self._pending.pop(message["id"], None)
            raise RemoteTransportError(f"no response to {message['method']} within {REQUEST_TIMEOUT}s")

    async def _rpc_call(self, method: str, params: Optional[dict] = None) -> dict:
        return self._unwrap(await self._send(self._request(method, params)))

    async def shutdown(self) -> None:
        if self._reader:
            self._reader.cancel()
            try:
                await self._reader
            except (asyncio.CancelledError, Exception):
                pass
            self._reader = None
        if self._session:
            await self._session.aclose()
            self._session = None


# ---------------------------------------------------------------------------
async def connect_remote(url: str, headers: Optional[Dict[str, str]] = None,
                         transport: str = "auto") -> Tuple[_BaseRemoteClient, Dict[str, Any]]:
    """Connect with the right transport. Returns (client, initialize_result)."""
    order = {
        "streamable-http": [MCPStreamableHTTPClient],
        "sse": [MCPSSEClient],
    }.get(transport)
    if order is None:
        order = [MCPSSEClient, MCPStreamableHTTPClient] if url.rstrip("/").endswith("/sse") \
            else [MCPStreamableHTTPClient, MCPSSEClient]
    errors = []
    for cls in order:
        client = cls(url, headers)
        try:
            init = await asyncio.wait_for(client.connect(), timeout=CONNECT_TIMEOUT + REQUEST_TIMEOUT)
            return client, init
        except Exception as e:
            errors.append(f"{cls.transport}: {e}")
            try:
                await client.shutdown()
            except Exception:
                pass
    raise RemoteTransportError("; ".join(errors))
