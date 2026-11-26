"""Tests for A2A agent card scanning (Workstream D): scanner, SSRF-safe fetch, CLI and REST.

Fully offline: remote cards and JWKS are served by an injected fetch function or an
httpx.MockTransport, and DNS resolution is faked.
"""

import base64
import importlib.util
import json
import re
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner


def _runner() -> CliRunner:
    """CliRunner with stderr kept separate from stdout.

    typer < 0.16 (click < 8.2) needs mix_stderr=False; newer releases removed the
    argument and separate the streams by default.
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()

from app.analysis.a2a_scanner import (
    A2AScanError,
    LEGACY_WELL_KNOWN_PATH,
    WELL_KNOWN_PATH,
    scan_agent_card,
    validate_card_schema,
)
from app.models.schemas import FindingSeverity
from app.utils import safe_fetch
from app.utils.safe_fetch import ResponseTooLargeError, TooManyRedirectsError, UnsafeURLError, safe_get

FIX = Path(__file__).parent / "fixtures" / "a2a"
HOST = "agent.example.com"
CARD_URL = f"https://{HOST}{WELL_KNOWN_PATH}"
JWKS_URL = f"https://{HOST}/.well-known/jwks.json"
PUBLIC_IP = "93.184.216.34"

HAS_JWT = importlib.util.find_spec("jwt") is not None and importlib.util.find_spec("cryptography") is not None
needs_jwt = pytest.mark.skipif(not HAS_JWT, reason="PyJWT[crypto] not installed (axiom-scan[a2a])")


# ============================================================
# Helpers
# ============================================================

def load(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class FakeWeb:
    """Injectable fetch: url -> (status, headers, body, final_url); records every URL requested."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        status, body = self.routes.get(url, (404, b"not found"))
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        return status, {"content-type": "application/json"}, body, url


def scan_remote(card, url=CARD_URL, extra=None, source=None):
    web = FakeWeb({url: (200, card), **(extra or {})})
    return scan_agent_card(source or url, fetch=web), web


def by_prefix(result, prefix):
    return [f for f in result.findings if f.id.startswith(prefix)]


def high_or_worse(result):
    return [f for f in result.findings if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical(card: dict) -> bytes:
    """Independent RFC 8785-style canonicalisation (card minus `signatures`)."""
    body = {k: v for k, v in card.items() if k != "signatures"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_card(card: dict, alg: str = "ES256", kid: str = "key-1", jku: str = JWKS_URL):
    """Produce a real detached JWS over the canonical card plus the matching JWKS."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from jwt.algorithms import get_default_algorithms

    algo = get_default_algorithms()[alg]
    if alg.startswith("ES"):
        priv = ec.generate_private_key(ec.SECP256R1())
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    header = {"alg": alg, "typ": "JOSE", "kid": kid, "jku": jku}
    protected = b64url(json.dumps(header, separators=(",", ":")).encode())
    sig = algo.sign(f"{protected}.{b64url(canonical(card))}".encode("ascii"), priv)
    signed = dict(card)
    signed["signatures"] = [{"protected": protected, "signature": b64url(sig)}]
    jwk = json.loads(algo.to_jwk(priv.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": alg})
    return signed, {"keys": [jwk]}


def fake_resolver(mapping):
    def _resolve(host, port):
        if host not in mapping:
            raise AssertionError(f"unexpected DNS lookup for {host}")
        return list(mapping[host])
    return _resolve


# ============================================================
# Scanner: one fixture per check
# ============================================================

FILE_CASES = [
    ("insecure_transport_card.json", "a2a-transport-insecure:interface-0", FindingSeverity.HIGH),
    ("schema_invalid_card.json", "a2a-schema-invalid", FindingSeverity.MEDIUM),
    ("no_auth_card.json", "a2a-auth-missing", FindingSeverity.HIGH),
    ("weak_scheme_card.json", "a2a-auth-weak:", FindingSeverity.MEDIUM),
    ("unsigned_card.json", "a2a-card-unsigned", FindingSeverity.MEDIUM),
    ("skill_poisoning_card.json", "a2a-skill-poisoning:summarise", FindingSeverity.HIGH),
    ("dangerous_skill_noauth_card.json", "a2a-skill-dangerous-noauth:ops", FindingSeverity.HIGH),
    ("extended_card_card.json", "a2a-extended-card-unchecked", FindingSeverity.INFO),
    ("legacy_card.json", "a2a-legacy-protocol:version", FindingSeverity.LOW),
    ("provider_missing_card.json", "a2a-provider-missing", FindingSeverity.LOW),
]


class TestScannerFixtures:
    @pytest.mark.parametrize("fixture,prefix,severity", FILE_CASES)
    def test_file_fixture(self, fixture, prefix, severity):
        web = FakeWeb()
        res = scan_agent_card(str(FIX / fixture), fetch=web)
        hits = by_prefix(res, prefix)
        assert hits, f"{fixture}: expected {prefix}, got {[f.id for f in res.findings]}"
        assert all(h.severity == severity for h in hits)
        assert res.discovery_path_used == "file"
        assert res.final_url is None
        assert web.calls == []  # file scans touch no network unless a card names a JWKS

    def test_weak_schemes_each_reported(self):
        res = scan_agent_card(str(FIX / "weak_scheme_card.json"), fetch=FakeWeb())
        assert {f.id for f in by_prefix(res, "a2a-auth-weak:")} == {
            "a2a-auth-weak:queryKey", "a2a-auth-weak:basic", "a2a-auth-weak:legacyOauth"}

    def test_card_over_http(self):
        card = load("unsigned_card.json")
        url = f"http://{HOST}{WELL_KNOWN_PATH}"
        res, _ = scan_remote(card, url=url)
        hit = by_prefix(res, "a2a-transport-insecure:card")
        assert hit and hit[0].severity == FindingSeverity.HIGH
        assert hit[0].owasp_asi == ["ASI07"]
        assert hit[0].related == ["MCP07:2025"]
        assert hit[0].owasp_mcp is None

    def test_interface_host_mismatch_unsigned(self):
        res, _ = scan_remote(load("host_mismatch_card.json"))
        hit = by_prefix(res, "a2a-interface-host-mismatch")
        assert hit and hit[0].severity == FindingSeverity.MEDIUM

    def test_interface_host_mismatch_not_reported_for_file(self):
        res = scan_agent_card(str(FIX / "host_mismatch_card.json"), fetch=FakeWeb())
        assert not by_prefix(res, "a2a-interface-host-mismatch")

    def test_provider_host_mismatch(self):
        res, _ = scan_remote(load("provider_host_mismatch_card.json"))
        hit = by_prefix(res, "a2a-provider-host-mismatch")
        assert hit and hit[0].severity == FindingSeverity.LOW

    def test_legacy_discovery_path(self):
        card = load("legacy_card.json")
        web = FakeWeb({f"https://{HOST}{LEGACY_WELL_KNOWN_PATH}": (200, card)})
        res = scan_agent_card(f"https://{HOST}", fetch=web)
        assert web.calls == [CARD_URL, f"https://{HOST}{LEGACY_WELL_KNOWN_PATH}"]
        assert res.discovery_path_used == LEGACY_WELL_KNOWN_PATH
        hit = by_prefix(res, "a2a-legacy-protocol:discovery-path")
        assert hit and hit[0].severity == FindingSeverity.LOW
        assert res.protocol_version == "0.3.0"

    def test_standard_discovery_path_preferred(self):
        card = load("unsigned_card.json")
        web = FakeWeb({CARD_URL: (200, card)})
        res = scan_agent_card(f"https://{HOST}/", fetch=web)
        assert web.calls == [CARD_URL]
        assert res.discovery_path_used == WELL_KNOWN_PATH
        assert not by_prefix(res, "a2a-legacy-protocol")

    def test_no_card_found(self):
        with pytest.raises(A2AScanError):
            scan_agent_card(f"https://{HOST}", fetch=FakeWeb())

    def test_not_a_file_or_url(self, tmp_path):
        with pytest.raises(A2AScanError):
            scan_agent_card(str(tmp_path / "missing.json"))
        with pytest.raises(UnsafeURLError):
            scan_agent_card("ftp://agent.example.com/card.json")


class TestExtendedCard:
    EXT = f"https://{HOST}/rest/v1/extendedAgentCard"

    def test_exposed_extended_card(self):
        card = load("extended_card_card.json")
        res, web = scan_remote(card, extra={self.EXT: (200, {**card, "name": "Forecast Agent (extended)"})})
        hit = by_prefix(res, "a2a-extended-card-exposed")
        assert hit and hit[0].severity == FindingSeverity.HIGH
        assert web.calls == [CARD_URL, self.EXT]

    def test_protected_extended_card(self):
        card = load("extended_card_card.json")
        res, web = scan_remote(card, extra={self.EXT: (401, b'{"error":"unauthorized"}')})
        assert not by_prefix(res, "a2a-extended-card")
        assert web.calls == [CARD_URL, self.EXT]

    def test_legacy_extended_card_path(self):
        card = load("legacy_extended_card.json")
        legacy_ext = f"https://{HOST}/a2a/agent/authenticatedExtendedCard"
        res, web = scan_remote(card, extra={legacy_ext: (200, card)})
        assert by_prefix(res, "a2a-extended-card-exposed")
        assert web.calls == [CARD_URL, legacy_ext]

    def test_jsonrpc_only_not_probed(self):
        card = load("extended_card_card.json")
        card["supportedInterfaces"] = card["supportedInterfaces"][:1]  # JSONRPC only
        res, web = scan_remote(card)
        assert by_prefix(res, "a2a-extended-card-unchecked")
        assert web.calls == [CARD_URL]


# ============================================================
# Signatures
# ============================================================

class TestSignatures:
    @needs_jwt
    @pytest.mark.parametrize("alg", ["ES256", "RS256"])
    def test_good_signed_card_remote(self, alg):
        signed, jwks = sign_card(load("good_signed_card.json"), alg=alg)
        res, web = scan_remote(signed, extra={JWKS_URL: (200, jwks)})
        assert high_or_worse(res) == []
        assert [f.id for f in res.findings if f.severity == FindingSeverity.MEDIUM] == []
        assert res.card.signed is True and res.card.signature_verified is True
        # passive: exactly one card GET and one JWKS GET, no task/message endpoints
        assert web.calls == [CARD_URL, JWKS_URL]
        assert not any(re.search(r"message|task", u, re.I) for u in web.calls)

    @needs_jwt
    def test_good_signed_card_file(self, tmp_path):
        signed, jwks = sign_card(load("good_signed_card.json"))
        p = tmp_path / "good_signed_card.json"
        p.write_text(json.dumps(signed, indent=2), encoding="utf-8")
        res = scan_agent_card(str(p), fetch=FakeWeb({JWKS_URL: (200, jwks)}))
        assert high_or_worse(res) == []
        assert res.card.signature_verified is True

    @needs_jwt
    def test_tampered_card_fails(self):
        signed, jwks = sign_card(load("good_signed_card.json"))
        signed["supportedInterfaces"][0]["url"] = "https://evil.example.net/a2a/v1"
        res, _ = scan_remote(signed, extra={JWKS_URL: (200, jwks)})
        hit = by_prefix(res, "a2a-signature-invalid")
        assert hit and hit[0].severity == FindingSeverity.HIGH
        assert res.card.signature_verified is False

    @needs_jwt
    def test_bad_signature_fixture(self):
        _, jwks = sign_card(load("good_signed_card.json"))
        res = scan_agent_card(str(FIX / "bad_signature_card.json"), fetch=FakeWeb({JWKS_URL: (200, jwks)}))
        hit = by_prefix(res, "a2a-signature-invalid")
        assert hit and hit[0].severity == FindingSeverity.HIGH

    @needs_jwt
    def test_unresolvable_key(self):
        web = FakeWeb()
        res = scan_agent_card(str(FIX / "unresolvable_key_card.json"), fetch=web)
        hit = by_prefix(res, "a2a-signature-invalid")
        assert hit and hit[0].severity == FindingSeverity.HIGH
        assert "cannot be resolved" in hit[0].description
        assert web.calls == []

    @needs_jwt
    def test_jwks_unreachable(self):
        res = scan_agent_card(str(FIX / "bad_signature_card.json"), fetch=FakeWeb())
        assert by_prefix(res, "a2a-signature-invalid")

    def test_cannot_verify_without_pyjwt(self, monkeypatch):
        # Simulate an install without the optional extra.
        monkeypatch.setitem(sys.modules, "jwt", None)
        monkeypatch.setitem(sys.modules, "jwt.algorithms", None)
        res = scan_agent_card(str(FIX / "bad_signature_card.json"), fetch=FakeWeb())
        hit = by_prefix(res, "a2a-signature-unverified")
        assert hit and hit[0].severity == FindingSeverity.MEDIUM
        assert "install axiom-scan[a2a]" in hit[0].description
        assert not by_prefix(res, "a2a-signature-invalid")
        assert res.card.signed is True and res.card.signature_verified is None


# ============================================================
# Schema validation and result shape
# ============================================================

class TestSchemaAndResult:
    def test_schema_valid_cards(self):
        assert validate_card_schema(load("good_signed_card.json")) == []
        assert validate_card_schema(load("legacy_card.json")) == []

    @pytest.mark.parametrize("use_jsonschema", [True, False])
    def test_schema_invalid(self, use_jsonschema):
        errs = validate_card_schema(load("schema_invalid_card.json"), use_jsonschema=use_jsonschema)
        joined = " ".join(errs)
        assert "version" in joined and "tags" in joined

    def test_structural_fallback_agrees_on_good_card(self):
        assert validate_card_schema(load("good_signed_card.json"), use_jsonschema=False) == []

    def test_fallback_used_when_jsonschema_missing(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "jsonschema", None)
        res = scan_agent_card(str(FIX / "schema_invalid_card.json"), fetch=FakeWeb())
        assert by_prefix(res, "a2a-schema-invalid")

    def test_result_fields(self):
        res = scan_agent_card(str(FIX / "no_auth_card.json"), fetch=FakeWeb())
        assert res.schema_version == "0.5"
        assert "static" in res.scope_note.lower() and "remains a gap" in res.scope_note
        assert res.card.name == "Forecast Agent"
        assert res.card.skill_count == 1
        assert res.card.signed is False
        assert res.risk_score > 0
        for f in res.findings:
            assert f.owasp_asi, f.id
            assert f.owasp_mcp is None, f.id
        assert by_prefix(res, "a2a-auth-missing")[0].related == ["MCP07:2025"]
        # serialisable
        json.loads(res.model_dump_json())


# ============================================================
# SSRF-safe fetch
# ============================================================

def _no_dns(host, port):
    raise AssertionError(f"DNS should not be consulted for {host}")


class TestSafeFetch:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://0.0.0.0/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/",
    ])
    def test_refuses_internal_and_non_http(self, url):
        transport = httpx.MockTransport(lambda r: pytest.fail(f"request sent to {r.url}"))
        with pytest.raises(UnsafeURLError):
            safe_get(url, resolver=_no_dns, transport=transport)

    def test_refuses_hostname_resolving_private(self):
        transport = httpx.MockTransport(lambda r: pytest.fail("request should not be sent"))
        with pytest.raises(UnsafeURLError, match="10.0.0.5"):
            safe_get("https://internal.example.com/card.json",
                     resolver=fake_resolver({"internal.example.com": ["10.0.0.5"]}), transport=transport)

    def test_refuses_if_any_address_private(self):
        with pytest.raises(UnsafeURLError):
            safe_get("https://mixed.example.com/",
                     resolver=fake_resolver({"mixed.example.com": [PUBLIC_IP, "192.168.1.10"]}),
                     transport=httpx.MockTransport(lambda r: httpx.Response(200)))

    def test_refuses_redirect_to_loopback(self):
        seen = []

        def handler(request):
            seen.append(str(request.url))
            return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})

        with pytest.raises(UnsafeURLError):
            safe_get("https://public.example.com/start",
                     resolver=fake_resolver({"public.example.com": [PUBLIC_IP]}),
                     transport=httpx.MockTransport(handler))
        assert len(seen) == 1  # the loopback hop was never requested

    def test_follows_safe_redirect_and_pins_ip(self):
        seen = []

        def handler(request):
            seen.append((request.url.host, request.headers["host"]))
            if request.url.path == "/start":
                return httpx.Response(301, headers={"Location": "/card.json"})
            return httpx.Response(200, json={"ok": True})

        status, headers, body, final = safe_get(
            "https://public.example.com/start",
            resolver=fake_resolver({"public.example.com": [PUBLIC_IP]}),
            transport=httpx.MockTransport(handler))
        assert status == 200 and json.loads(body) == {"ok": True}
        assert final == "https://public.example.com/card.json"
        assert seen == [(PUBLIC_IP, "public.example.com")] * 2

    def test_too_many_redirects(self):
        handler = lambda r: httpx.Response(302, headers={"Location": "/again"})  # noqa: E731
        with pytest.raises(TooManyRedirectsError):
            safe_get("https://public.example.com/", max_redirects=2,
                     resolver=fake_resolver({"public.example.com": [PUBLIC_IP]}),
                     transport=httpx.MockTransport(handler))

    def test_max_bytes_enforced(self):
        def handler(request):
            return httpx.Response(200, content=iter([b"x" * 600, b"y" * 600]))

        with pytest.raises(ResponseTooLargeError):
            safe_get("https://public.example.com/big", max_bytes=1000,
                     resolver=fake_resolver({"public.example.com": [PUBLIC_IP]}),
                     transport=httpx.MockTransport(handler))

    def test_allow_private(self):
        transport = httpx.MockTransport(lambda r: httpx.Response(200, content=b"{}"))
        status, _, body, _ = safe_get("http://127.0.0.1:8000/x", allow_private=True, transport=transport)
        assert status == 200 and body == b"{}"

    def test_scanner_propagates_refusal(self):
        with pytest.raises(UnsafeURLError):
            scan_agent_card("http://169.254.169.254")


# ============================================================
# CLI
# ============================================================

def _cli():
    from cli.axiom_cli import app
    return app


class TestA2ACLI:
    @pytest.mark.parametrize("fmt", ["table", "json", "md"])
    def test_formats_on_file(self, fmt):
        res = _runner().invoke(
            _cli(), ["a2a", str(FIX / "unsigned_card.json"), "--format", fmt])
        assert res.exit_code == 0, res.output + (res.stderr or "")
        assert "a2a-card-unsigned" in res.output
        if fmt == "json":
            data = json.loads(res.output)
            assert data["schema_version"] == "0.5"
            assert data["discovery_path_used"] == "file"
            assert data["findings"][0]["id"] == "a2a-card-unsigned"
        if fmt == "md":
            assert res.output.startswith("# Axiom A2A Agent Card Scan")

    def test_exit_code_on_high(self):
        res = _runner().invoke(_cli(), ["a2a", str(FIX / "no_auth_card.json"), "-f", "json"])
        assert res.exit_code == 1
        assert any(f["id"] == "a2a-auth-missing" for f in json.loads(res.output)["findings"])

    def test_poisoned_card_table_does_not_crash(self):
        res = CliRunner().invoke(_cli(), ["a2a", str(FIX / "skill_poisoning_card.json")])
        assert res.exit_code == 1
        assert "a2a-skill-poisoning" in res.output

    def test_help_has_notices(self):
        res = CliRunner().invoke(_cli(), ["a2a", "--help"])
        text = " ".join(res.output.split())
        assert "Only scan agents you own or are authorised to assess" in text
        assert "Passive only" in text and "never sends tasks or messages" in text

    def test_bad_format(self):
        res = CliRunner().invoke(_cli(), ["a2a", str(FIX / "unsigned_card.json"), "-f", "xml"])
        assert res.exit_code == 2

    def test_private_refused_without_flag(self, monkeypatch):
        monkeypatch.setattr(safe_fetch, "_default_transport",
                            httpx.MockTransport(lambda r: pytest.fail("must not be requested")))
        res = CliRunner().invoke(_cli(), ["a2a", "http://127.0.0.1:8000"])
        assert res.exit_code == 2
        assert "Refused" in res.output

    def test_allow_private_with_mock_transport(self, monkeypatch):
        card = load("unsigned_card.json")
        seen = []

        def handler(request):
            seen.append(str(request.url))
            if request.url.path == WELL_KNOWN_PATH:
                return httpx.Response(200, json=card)
            return httpx.Response(404)

        monkeypatch.setattr(safe_fetch, "_default_transport", httpx.MockTransport(handler))
        res = _runner().invoke(
            _cli(), ["a2a", "http://127.0.0.1:8000", "--allow-private", "--format", "json"])
        data = json.loads(res.output)
        assert data["final_url"] == f"http://127.0.0.1:8000{WELL_KNOWN_PATH}"
        assert seen == [f"http://127.0.0.1:8000{WELL_KNOWN_PATH}"]
        # card served over plain HTTP -> HIGH -> exit 1
        assert any(f["id"] == "a2a-transport-insecure:card" for f in data["findings"])
        assert res.exit_code == 1


# ============================================================
# REST API
# ============================================================

class TestA2AAPI:
    @pytest.fixture
    def client(self, monkeypatch):
        from main import app
        from app.api.routes import limiter
        monkeypatch.setattr(limiter, "enabled", False)
        monkeypatch.setattr(safe_fetch, "resolve_host", _no_dns)
        monkeypatch.setattr(safe_fetch, "_default_transport",
                            httpx.MockTransport(lambda r: pytest.fail(f"unexpected request {r.url}")))
        return TestClient(app)

    @pytest.mark.parametrize("source", [
        str(FIX / "unsigned_card.json"),
        "tests/fixtures/a2a/unsigned_card.json",
        "file:///etc/passwd",
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080",
        "http://[::1]/",
    ])
    def test_rejects_unsafe_sources(self, client, source):
        resp = client.post("/api/v1/a2a", json={"source": source})
        assert resp.status_code in (400, 422), resp.text

    def test_rejects_hostname_resolving_private(self, client, monkeypatch):
        monkeypatch.setattr(safe_fetch, "resolve_host", fake_resolver({"internal.example.com": ["10.0.0.5"]}))
        resp = client.post("/api/v1/a2a", json={"source": "https://internal.example.com"})
        assert resp.status_code == 400
        assert "10.0.0.5" in resp.json()["detail"]

    def test_rejects_redirect_to_loopback(self, client, monkeypatch):
        monkeypatch.setattr(safe_fetch, "resolve_host", fake_resolver({HOST: [PUBLIC_IP]}))
        monkeypatch.setattr(safe_fetch, "_default_transport", httpx.MockTransport(
            lambda r: httpx.Response(302, headers={"Location": "http://127.0.0.1/card.json"})))
        resp = client.post("/api/v1/a2a", json={"source": f"https://{HOST}"})
        assert resp.status_code == 400

    def test_missing_source(self, client):
        assert client.post("/api/v1/a2a", json={}).status_code == 422

    def test_scan_public_card(self, client, monkeypatch):
        card = load("no_auth_card.json")
        monkeypatch.setattr(safe_fetch, "resolve_host", fake_resolver({HOST: [PUBLIC_IP]}))
        monkeypatch.setattr(safe_fetch, "_default_transport", httpx.MockTransport(
            lambda r: httpx.Response(200, json=card) if r.url.path == WELL_KNOWN_PATH else httpx.Response(404)))
        resp = client.post("/api/v1/a2a", json={"source": f"https://{HOST}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["schema_version"] == "0.5"
        assert data["discovery_path_used"] == WELL_KNOWN_PATH
        assert any(f["id"] == "a2a-auth-missing" and f["severity"] == "high" for f in data["findings"])
        assert data["scope_note"]

    def test_no_card_is_422(self, client, monkeypatch):
        monkeypatch.setattr(safe_fetch, "resolve_host", fake_resolver({HOST: [PUBLIC_IP]}))
        monkeypatch.setattr(safe_fetch, "_default_transport", httpx.MockTransport(lambda r: httpx.Response(404)))
        assert client.post("/api/v1/a2a", json={"source": f"https://{HOST}"}).status_code == 422
