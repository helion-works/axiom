"""
The curated MCP CVE list: real identifiers, real package names, and version-aware matching.
A patched version is never reported; an affected version is reported at the advisory's
severity; an unpinned version gets one INFO note.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis.engine import MCPAnalysisEngine  # noqa: E402
from app.models.schemas import DependencyInfo, FindingSeverity  # noqa: E402
from data.threat_intel import (  # noqa: E402
    KNOWN_MCP_CVES, KNOWN_VULNERABLE_PACKAGES, version_affected, version_tuple,
)


@pytest.fixture
def engine():
    return MCPAnalysisEngine()


def dep(name, version, ecosystem="npm"):
    return DependencyInfo(name=name, version=version, ecosystem=ecosystem, source="package.json")


class TestListIsReal:
    def test_every_identifier_is_a_real_cve_shape(self):
        for cve_id in KNOWN_MCP_CVES:
            assert re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id), cve_id

    def test_every_entry_has_a_source_and_a_range(self):
        for cve_id, info in KNOWN_MCP_CVES.items():
            assert info["reference"].startswith("https://"), cve_id
            assert info["affected"] and info["fixed"] and info["package"], cve_id
            for introduced, fixed in info["affected"]:
                assert version_tuple(introduced) < version_tuple(fixed), cve_id

    def test_legitimate_packages_are_not_on_the_malicious_list(self):
        for info in KNOWN_MCP_CVES.values():
            assert info["package"] not in KNOWN_VULNERABLE_PACKAGES


class TestOwaspTableExamples:
    def test_every_published_example_has_a_checked_source(self):
        # The `axiom owasp` table may only name a CVE from the built-in list or a
        # disclosure / demonstration recorded with its source in KNOWN_INCIDENTS.
        from app.analysis.owasp_mapping import OWASP_AGENTIC_TOP_10
        from data.threat_intel import KNOWN_INCIDENTS

        sourced = list(KNOWN_MCP_CVES) + [i["name"] for i in KNOWN_INCIDENTS if i["reference"].startswith("https://")]
        for asi_id, info in OWASP_AGENTIC_TOP_10.items():
            assert "real_incidents" not in info, asi_id
            for example in info["published_examples"]:
                assert any(example.startswith(name) for name in sourced), (asi_id, example)


class TestVersionRanges:
    @pytest.mark.parametrize("version,expected", [
        ("0.0.4", False), ("0.0.5", True), ("0.1.15", True), ("0.1.16", False), ("0.1.17", False),
        ("0.1.16-beta.1", False), ("1.0.0", False), ("v0.1.15", True), ("unknown", None), ("", None),
    ])
    def test_mcp_remote(self, version, expected):
        assert version_affected(version, KNOWN_MCP_CVES["CVE-2025-6514"]["affected"]) is expected

    @pytest.mark.parametrize("version,expected", [
        ("0.6.2", True), ("0.6.3", False), ("2025.1.14", True), ("2025.3.28", True),
        ("2025.7.1", False), ("2025.8.21", False),
    ])
    def test_filesystem_has_two_ranges(self, version, expected):
        assert version_affected(version, KNOWN_MCP_CVES["CVE-2025-53109"]["affected"]) is expected

    @pytest.mark.parametrize("version,expected", [("0.13.0", True), ("0.14.0", True), ("0.14.1", False)])
    def test_inspector(self, version, expected):
        assert version_affected(version, KNOWN_MCP_CVES["CVE-2025-49596"]["affected"]) is expected


class TestEngineMatching:
    def test_patched_version_is_not_reported(self, engine):
        assert engine._check_known_cves("some-server", [dep("mcp-remote", "0.1.16")]) == []

    def test_affected_version_is_critical_with_source(self, engine):
        findings = engine._check_known_cves("some-server", [dep("mcp-remote", "0.1.15")])
        assert [f.id for f in findings] == ["CVE-2025-6514"]
        f = findings[0]
        assert f.severity == FindingSeverity.CRITICAL and f.cve_id == "CVE-2025-6514"
        assert "mcp-remote@0.1.15" in f.title and "0.1.16" in f.recommendation
        assert "jfrog.com" in f.description

    def test_unpinned_version_is_one_info_note(self, engine):
        findings = engine._check_known_cves("some-server", [dep("mcp-remote", "unknown"), dep("mcp-remote", "unknown")])
        assert [f.id for f in findings] == ["CVE-2025-6514_unversioned"]
        assert findings[0].severity == FindingSeverity.INFO

    def test_real_package_names_match(self, engine):
        findings = engine._check_known_cves("some-server", [
            dep("@modelcontextprotocol/inspector", "0.14.0"),
            dep("@modelcontextprotocol/server-filesystem", "2025.3.28"),
        ])
        assert sorted(f.id for f in findings) == ["CVE-2025-49596", "CVE-2025-53109"]
        by_id = {f.id: f.severity for f in findings}
        assert by_id["CVE-2025-49596"] == FindingSeverity.CRITICAL
        assert by_id["CVE-2025-53109"] == FindingSeverity.HIGH

    def test_other_ecosystem_with_the_same_name_is_not_matched(self, engine):
        assert engine._check_known_cves("some-server", [dep("mcp-remote", "0.1.15", ecosystem="pypi")]) == []

    def test_scanned_package_uses_its_resolved_version(self, engine):
        patched = engine._check_known_cves("mcp-remote", [], target_version="0.1.29", target_ecosystem="npm")
        assert patched == []
        affected = engine._check_known_cves("mcp-remote", [], target_version="0.1.10", target_ecosystem="npm")
        assert [f.id for f in affected] == ["CVE-2025-6514"]

    def test_target_name_alone_is_not_a_match(self, engine):
        # A local folder or server that merely shares the name is not the npm package.
        assert engine._check_known_cves("mcp-remote", []) == []

    @pytest.mark.asyncio
    async def test_patched_dependency_gets_no_curated_finding(self, engine):
        findings = await engine._check_known_vulnerable([dep("mcp-remote", "0.1.16")], check_osv=False)
        assert findings == []


def _project(tmp_path, spec, locked=None, transitive=None):
    """A package.json depending on mcp-remote with `spec`, and optionally a package-lock.json."""
    import json
    deps = {} if spec is None else {"mcp-remote": spec}
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo", "dependencies": deps}), encoding="utf-8")
    packages = {"": {"name": "demo"}}
    if locked:
        packages["node_modules/mcp-remote"] = {"version": locked}
    if transitive:
        packages["node_modules/mcp-remote"] = {"version": transitive}
    if locked or transitive:
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    from app.analysis.dependencies import extract_dependencies
    return extract_dependencies(str(tmp_path))


class TestDeclaredAndLockedVersions:
    """What a real project hands the check: a manifest spec and, usually, a lockfile."""

    def test_range_with_patched_lockfile_is_not_reported(self, engine, tmp_path):
        deps = _project(tmp_path, "^0.1.10", locked="0.1.38")
        assert engine._check_known_cves("demo", deps) == []

    def test_range_with_affected_lockfile_is_reported_at_the_locked_version(self, engine, tmp_path):
        findings = engine._check_known_cves("demo", _project(tmp_path, "^0.1.10", locked="0.1.12"))
        assert [f.id for f in findings] == ["CVE-2025-6514"]
        assert findings[0].severity == FindingSeverity.CRITICAL and "mcp-remote@0.1.12" in findings[0].title

    @pytest.mark.parametrize("spec", ["^0.1.10", "~0.1", ">=0.1.0 <0.2", "<0.1.16", "0.x", "^0", "*", "latest",
                                      "0.1.x", "^0.1.0 || ^0.2.0", "github:geelen/mcp-remote", ""])
    def test_range_without_lockfile_is_a_note_not_a_verdict(self, engine, tmp_path, spec):
        findings = engine._check_known_cves("demo", _project(tmp_path, spec))
        assert [(f.id, f.severity) for f in findings] == [("CVE-2025-6514_unversioned", FindingSeverity.INFO)]

    @pytest.mark.parametrize("spec,expected", [("0.1.15", ["CVE-2025-6514"]), ("=0.1.15", ["CVE-2025-6514"]),
                                                ("0.1.16", []), ("v0.1.16", [])])
    def test_exact_manifest_version_without_lockfile(self, engine, tmp_path, spec, expected):
        assert [f.id for f in engine._check_known_cves("demo", _project(tmp_path, spec))] == expected

    def test_transitive_dependency_is_never_critical(self, engine, tmp_path):
        deps = _project(tmp_path, None, transitive="0.1.10")
        findings = engine._check_known_cves("demo", deps)
        assert [(f.id, f.severity) for f in findings] == [("CVE-2025-6514", FindingSeverity.HIGH)]
        assert "transitive" in findings[0].description
        assert [d for d in deps if d.name == "mcp-remote"][0].has_vulnerabilities is True

    def test_text_where_a_version_belongs_does_not_stop_the_scan(self, engine, tmp_path):
        assert engine._check_known_cves("demo", _project(tmp_path, "9" * 5000)) == []
        assert version_tuple("9" * 5000) is not None

    def test_rule_ids_are_the_built_in_lists_own(self, engine):
        affected = engine._check_known_cves("demo", [dep("mcp-remote", "0.1.15")])
        unpinned = engine._check_known_cves("demo", [dep("mcp-remote", "unknown")])
        assert affected[0].rule_id == "known_mcp_cve" and unpinned[0].rule_id == "known_mcp_cve_unpinned"

    def test_extra_fields_are_not_serialised(self, tmp_path):
        d = _project(tmp_path, "^0.1.10", locked="0.1.38")[0]
        assert d.locked_version == "0.1.38" and d.declared_spec == "^0.1.10"
        assert set(d.model_dump()) == {"name", "version", "ecosystem", "has_vulnerabilities", "vulnerability_count",
                                       "vulns", "direct", "source"}


class TestAdvisoryText:
    def test_fixed_versions_exist(self):
        # 0.6.3 was never released; the Filesystem advisory's only fixed version is 2025.7.1.
        info = KNOWN_MCP_CVES["CVE-2025-53109"]
        assert info["fixed"] == "2025.7.1"
        assert "0.6.3" not in info["recommendation"] and "0.6.3" not in info["description"]

    def test_every_entry_names_its_ghsa_id(self):
        for cve_id, info in KNOWN_MCP_CVES.items():
            assert re.fullmatch(r"GHSA(-[0-9a-z]{4}){3}", info["ghsa"]), cve_id
            assert info["ghsa"].lower() in info["reference"].lower() or "jfrog.com" in info["reference"]


class TestCountedOnce:
    def _osv(self, advisory_id):
        from app.models.schemas import Finding, FindingCategory
        return Finding(id=advisory_id, severity=FindingSeverity.MEDIUM, category=FindingCategory.DEPENDENCY_VULN,
                       title="Advisory in dependency", description="from OSV")

    def test_osv_twin_is_dropped_when_the_built_in_list_reported_it(self, engine):
        cve = engine._check_known_cves("demo", [dep("mcp-remote", "0.1.15")])
        others = [self._osv("GHSA-6xpm-ggf7-wc3p"), self._osv("GHSA-aaaa-bbbb-cccc")]
        assert [f.id for f in engine._drop_osv_twins(others, cve)] == ["GHSA-aaaa-bbbb-cccc"]

    def test_osv_finding_stays_when_the_built_in_list_only_left_a_note(self, engine):
        note = engine._check_known_cves("demo", [dep("mcp-remote", "unknown")])
        others = [self._osv("GHSA-6xpm-ggf7-wc3p")]
        assert engine._drop_osv_twins(others, note) == others
