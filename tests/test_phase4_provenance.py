"""
Phase 4 / E.3 — provenance: registry identity, lookalike names, freshness.
The registry is mocked; the check must never block a scan.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis import provenance as prov  # noqa: E402
from app.analysis.provenance import identify, normalise_repo, provenance_check, short_name  # noqa: E402
from app.models.schemas import FindingSeverity  # noqa: E402


def _entry(name, repo, pkgs=(), days_ago=400):
    return {"name": name, "version": "1.0.0", "repository": normalise_repo(repo), "packages": list(pkgs),
            "publishedAt": (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z"),
            "status": "active"}


@pytest.fixture
def registry(monkeypatch):
    table = {}

    async def fake_search(term, cache_enabled=True):
        return [e for e in table.values() if term in e["name"].lower()]

    monkeypatch.setattr(prov, "search_registry", fake_search)
    return table


def _pkg(tmp_path, name, repo="https://github.com/acme/airtable-mcp-server.git"):
    (tmp_path / "package.json").write_text(json.dumps({"name": name, "repository": {"type": "git", "url": repo}}), encoding="utf-8")
    return str(tmp_path)


class TestIdentity:
    def test_normalise(self):
        assert normalise_repo("git+https://github.com/Acme/Repo.git") == "https://github.com/acme/repo"
        assert normalise_repo("git@github.com:acme/repo.git") == "https://github.com/acme/repo"
        assert short_name("io.github.acme/airtable-mcp-server") == "airtable-mcp-server"
        assert short_name("@acme/pkg") == "pkg"

    def test_identify_from_package_json(self, tmp_path):
        ident = identify(_pkg(tmp_path, "airtable-mcp-server"))
        assert ident["npm"] == "airtable-mcp-server"
        assert ident["repository"] == "https://github.com/acme/airtable-mcp-server"


class TestChecks:
    @pytest.mark.asyncio
    async def test_match(self, tmp_path, registry):
        registry["a"] = _entry("io.github.acme/airtable-mcp-server", "https://github.com/acme/airtable-mcp-server", ["npm:airtable-mcp-server"])
        report, findings = await provenance_check(_pkg(tmp_path, "airtable-mcp-server"), cache_enabled=False)
        assert report["registry"]["status"] == "match" and findings == []

    @pytest.mark.asyncio
    async def test_mismatch(self, tmp_path, registry):
        registry["a"] = _entry("io.github.acme/airtable-mcp-server", "https://github.com/acme/airtable-mcp-server", ["npm:airtable-mcp-server"])
        d = _pkg(tmp_path, "airtable-mcp-server", repo="https://github.com/evil/airtable-mcp-server")
        report, findings = await provenance_check(d, cache_enabled=False)
        assert report["registry"]["status"] == "mismatch"
        f = {x.id: x for x in findings}
        assert f["provenance_mismatch"].severity == FindingSeverity.HIGH
        assert "github.com/acme/airtable-mcp-server" in f["provenance_mismatch"].evidence

    @pytest.mark.asyncio
    async def test_typosquat(self, tmp_path, registry):
        registry["a"] = _entry("io.github.acme/airtable-mcp-server", "https://github.com/acme/airtable-mcp-server", ["npm:airtable-mcp-server"])
        registry["b"] = _entry("io.github.mallory/airtable-mcp-servar", "https://github.com/mallory/x", ["npm:airtable-mcp-servar"])
        report, findings = await provenance_check(_pkg(tmp_path, "airtable-mcp-server"), cache_enabled=False)
        ids = {x.id for x in findings}
        assert any(i.startswith("registry_typosquat_") for i in ids)
        assert report["lookalikes"][0]["name"] == "io.github.mallory/airtable-mcp-servar"

    @pytest.mark.asyncio
    async def test_same_publisher_variant_is_not_a_squat(self, tmp_path, registry):
        registry["a"] = _entry("io.github.acme/airtable-mcp-server", "https://github.com/acme/airtable-mcp-server", ["npm:airtable-mcp-server"])
        registry["b"] = _entry("io.github.acme/airtable-mcp-servers", "https://github.com/acme/airtable-mcp-server")
        _, findings = await provenance_check(_pkg(tmp_path, "airtable-mcp-server"), cache_enabled=False)
        assert not any(x.id.startswith("registry_typosquat_") for x in findings)

    @pytest.mark.asyncio
    async def test_fresh_publish(self, tmp_path, registry):
        registry["a"] = _entry("io.github.acme/airtable-mcp-server", "https://github.com/acme/airtable-mcp-server", ["npm:airtable-mcp-server"], days_ago=2)
        _, findings = await provenance_check(_pkg(tmp_path, "airtable-mcp-server"), cache_enabled=False)
        f = {x.id: x for x in findings}
        assert f["provenance_fresh_publish"].severity == FindingSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_not_in_registry(self, tmp_path, registry):
        report, findings = await provenance_check(_pkg(tmp_path, "totally-private-thing"), cache_enabled=False)
        assert report["registry"]["status"] == "not_in_registry" and findings == []

    @pytest.mark.asyncio
    async def test_network_failure_is_silent(self, monkeypatch):
        async def http_boom(term):
            raise ConnectionError("no network")
        monkeypatch.setattr(prov, "_search", http_boom)
        assert await prov.search_registry("airtable-mcp-server", cache_enabled=False) == []
