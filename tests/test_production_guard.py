"""Production guard for endpoints that act on the API host's machine."""

import pytest
from fastapi.testclient import TestClient

ENDPOINTS = [
    ("/api/v1/scan/local", {}),
    ("/api/v1/discover", {}),
    ("/api/v1/scan/live/stdio", {"command": "echo", "args": []}),
    ("/api/v1/scan/live/sse", {"url": "http://127.0.0.1:9/sse"}),
    ("/api/v1/scan/live/local", None),
]


@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def _post(client, path, body):
    return client.post(path, json=body) if body is not None else client.post(path)


@pytest.mark.parametrize("path,body", ENDPOINTS)
def test_production_blocks(client, monkeypatch, path, body):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("AXIOM_ALLOW_HOST_ACCESS", raising=False)
    monkeypatch.delenv("MCPGUARD_ALLOW_HOST_ACCESS", raising=False)
    r = _post(client, path, body)
    assert r.status_code == 404
    assert r.json() == {"detail": "Not found"}


@pytest.mark.parametrize("value", ["1", "true", "YES"])
@pytest.mark.parametrize("path,body", ENDPOINTS)
def test_production_with_override(client, monkeypatch, path, body, value):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("AXIOM_ALLOW_HOST_ACCESS", value)
    assert _post(client, path, body).status_code != 404


@pytest.mark.parametrize("path,body", ENDPOINTS)
def test_default_env_reachable(client, monkeypatch, path, body):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("AXIOM_ALLOW_HOST_ACCESS", raising=False)
    monkeypatch.delenv("MCPGUARD_ALLOW_HOST_ACCESS", raising=False)
    assert _post(client, path, body).status_code != 404


def test_health_reports_env(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("AXIOM_ALLOW_HOST_ACCESS", "1")
    data = client.get("/health").json()
    assert data["status"] == "healthy"
    assert data["env"] == "production"
    assert data["host_access"] is True
    monkeypatch.delenv("AXIOM_ALLOW_HOST_ACCESS")
    assert client.get("/health").json()["host_access"] is False


def test_legacy_env_name_still_works(client, monkeypatch):
    """MCPGUARD_ALLOW_HOST_ACCESS is a deprecated fallback for AXIOM_ALLOW_HOST_ACCESS."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("AXIOM_ALLOW_HOST_ACCESS", raising=False)
    monkeypatch.setenv("MCPGUARD_ALLOW_HOST_ACCESS", "1")
    assert client.get("/health").json()["host_access"] is True
    # The new name takes precedence over the legacy one.
    monkeypatch.setenv("AXIOM_ALLOW_HOST_ACCESS", "0")
    assert client.get("/health").json()["host_access"] is False
