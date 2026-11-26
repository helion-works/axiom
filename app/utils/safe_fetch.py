"""
SSRF-safe HTTP GET for fetching untrusted URLs (A2A agent cards, JWKS, ...).

Guarantees, for every request including each redirect hop:
  * only http/https URLs are fetched;
  * hostnames such as "localhost" and cloud metadata names are refused;
  * the hostname is resolved first and the request is refused if ANY resolved
    address is private, loopback, link-local (incl. 169.254.169.254), unique-local,
    multicast, unspecified, reserved or otherwise non-global (unless
    allow_private=True);
  * the connection is pinned to the vetted IP address (Host header and TLS SNI
    keep the original hostname), so a second DNS answer cannot rebind the
    request to an internal address;
  * redirects are never followed automatically: each Location is re-validated;
  * environment proxies are ignored (trust_env=False);
  * the body is streamed and the download aborted once max_bytes is exceeded.

DNS resolution goes through the module-level ``resolve_host`` function (or the
``resolver`` argument) and the HTTP transport through ``transport`` /
``_default_transport`` so tests can run fully offline.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

__all__ = [
    "SafeFetchError",
    "UnsafeURLError",
    "ResponseTooLargeError",
    "TooManyRedirectsError",
    "safe_get",
    "check_url",
    "is_disallowed_ip",
    "resolve_host",
]

USER_AGENT = "axiom-a2a-scanner (+https://github.com/helion-works/axiom; passive agent card analysis)"

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Exact hostnames that always point at the local machine or a cloud metadata service.
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
}
BLOCKED_SUFFIXES = (".localhost", ".metadata.google.internal")

# Tests may replace this with an httpx.MockTransport.
_default_transport: Optional[httpx.BaseTransport] = None


class SafeFetchError(Exception):
    """Base class for safe_get failures."""


class UnsafeURLError(SafeFetchError):
    """The URL (or a redirect target) is not allowed to be fetched."""


class ResponseTooLargeError(SafeFetchError):
    """The response body exceeded max_bytes."""


class TooManyRedirectsError(SafeFetchError):
    """More than max_redirects redirects were returned."""


Resolver = Callable[[str, int], List[str]]


def resolve_host(host: str, port: int) -> List[str]:
    """Resolve ``host`` to every IPv4/IPv6 address the system resolver returns."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeURLError(f"could not resolve host '{host}': {e}") from e
    addrs: List[str] = []
    for info in infos:
        addr = info[4][0]
        if "%" in addr:  # strip IPv6 zone id
            addr = addr.split("%", 1)[0]
        if addr not in addrs:
            addrs.append(addr)
    return addrs


def is_disallowed_ip(ip_str: str) -> bool:
    """True if the address is anything other than a public unicast address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        # Judge embedded IPv4 addresses (::ffff:127.0.0.1, 6to4, NAT64-ish) by the IPv4 rules too.
        if ip.ipv4_mapped is not None and is_disallowed_ip(str(ip.ipv4_mapped)):
            return True
        if ip.sixtofour is not None and is_disallowed_ip(str(ip.sixtofour)):
            return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or getattr(ip, "is_site_local", False)
        or not ip.is_global
    )


def _ip_literal(host: str) -> Optional[str]:
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return None


def check_url(
    url: str,
    allow_private: bool = False,
    resolver: Optional[Resolver] = None,
) -> Tuple[httpx.URL, List[str]]:
    """Validate ``url`` and return (parsed URL, vetted IP addresses).

    Raises UnsafeURLError when the URL must not be fetched.
    """
    try:
        parsed = httpx.URL(url)
    except Exception as e:  # httpx.InvalidURL and friends
        raise UnsafeURLError(f"invalid URL: {e}") from e
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError(f"scheme '{parsed.scheme or '(none)'}' is not allowed; only http and https")
    host = (parsed.host or "").lower().rstrip(".")
    if not host:
        raise UnsafeURLError("URL has no host")
    if parsed.userinfo:
        raise UnsafeURLError("URLs with embedded credentials are not allowed")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    literal = _ip_literal(host)
    if literal is not None:
        addrs = [literal]
    else:
        if not allow_private and (host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES)):
            raise UnsafeURLError(f"host '{host}' refers to a local or metadata service")
        addrs = (resolver or resolve_host)(host, port)
        if not addrs:
            raise UnsafeURLError(f"host '{host}' did not resolve")

    if not allow_private:
        bad = [a for a in addrs if is_disallowed_ip(a)]
        if bad:
            raise UnsafeURLError(
                f"host '{host}' resolves to a non-public address ({', '.join(bad)}); "
                "refusing to fetch (SSRF protection)"
            )
    return parsed, addrs


def safe_get(
    url: str,
    allow_private: bool = False,
    max_bytes: int = 1_000_000,
    timeout: float = 10,
    max_redirects: int = 3,
    *,
    resolver: Optional[Resolver] = None,
    transport: Optional[httpx.BaseTransport] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, str], bytes, str]:
    """GET ``url`` with SSRF protections. Returns (status, headers, body, final_url).

    ``headers`` in the result are lower-cased. ``final_url`` is the logical URL of the
    last hop (hostname, not the pinned IP).
    """
    transport = transport or _default_transport
    current = url
    redirects = 0
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5"}
    if headers:
        req_headers.update(headers)

    with httpx.Client(
        transport=transport,
        follow_redirects=False,
        timeout=timeout,
        trust_env=False,
    ) as client:
        while True:
            parsed, addrs = check_url(current, allow_private=allow_private, resolver=resolver)
            host = parsed.host
            pinned = parsed.copy_with(host=addrs[0])
            hop_headers = dict(req_headers)
            netloc_host = f"[{host}]" if ":" in host else host
            hop_headers["Host"] = netloc_host if parsed.port is None else f"{netloc_host}:{parsed.port}"
            extensions = {"sni_hostname": host} if parsed.scheme == "https" and _ip_literal(host) is None else {}

            request = client.build_request("GET", pinned, headers=hop_headers, extensions=extensions)
            response = client.send(request, stream=True)
            try:
                status = response.status_code
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                if status in REDIRECT_STATUSES and "location" in resp_headers:
                    if redirects >= max_redirects:
                        raise TooManyRedirectsError(f"more than {max_redirects} redirects")
                    redirects += 1
                    current = urljoin(str(parsed), resp_headers["location"])
                    continue

                declared = resp_headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise ResponseTooLargeError(f"response declares {declared} bytes (limit {max_bytes})")
                chunks: List[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ResponseTooLargeError(f"response exceeded {max_bytes} bytes")
                    chunks.append(chunk)
                return status, resp_headers, b"".join(chunks), str(parsed)
            finally:
                response.close()
