"""
Phase 4 / Part C — the severity policy (docs/SEVERITY.md) as regression tests.

Each class pins one calibration decision that Part A/B measured as a false positive or a
miss. If a rule drifts back, the test names the server it would mis-score.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis.severity_policy import host_class, risk_level, risk_score, transport_severity  # noqa: E402
from app.models.schemas import Finding, FindingCategory, FindingSeverity, RiskLevel  # noqa: E402


def _f(sev, i=0):
    return Finding(id=f"x{i}", severity=sev, category=FindingCategory.METADATA, title="t", description="d")


class TestHostClass:
    @pytest.mark.parametrize("target,cls", [
        ("http://127.0.0.1:3010/mcp", "loopback"),
        ("http://localhost:3000/sse", "loopback"),
        ("https://[::1]:8080/mcp", "loopback"),
        ("127.0.0.1:9001", "loopback"),
        ("http://10.0.0.5/mcp", "private"),
        ("http://192.168.1.10:9001/", "private"),
        ("http://172.16.4.4/mcp", "private"),
        ("http://mcp.internal/mcp", "private"),
        ("https://mcp.example.com/mcp", "public"),
        ("http://8.8.8.8/mcp", "public"),
        ("http://0.0.0.0:8000/mcp", "unknown"),
        (None, "unknown"),
        ("", "unknown"),
    ])
    def test_classes(self, target, cls):
        assert host_class(target) == cls

    def test_transport_severity_by_place(self):
        assert transport_severity("http://127.0.0.1:3010/mcp")[0] == FindingSeverity.INFO    # A.3: healthy localhost server
        assert transport_severity("http://192.168.1.10:9001")[0] == FindingSeverity.LOW
        assert transport_severity("http://mcp.example.com/mcp")[0] == FindingSeverity.HIGH
        assert transport_severity(None)[0] == FindingSeverity.LOW                           # static source, host unknown


class TestRiskScore:
    def test_empty(self):
        assert risk_score([]) == 0.0 and risk_level(0.0) == RiskLevel.SAFE

    def test_info_only_is_safe(self):
        assert risk_score([_f(FindingSeverity.INFO, i) for i in range(50)]) == 0.0

    def test_low_notes_never_reach_medium(self):
        # the reference filesystem server: many capability notes, nothing hostile
        s = risk_score([_f(FindingSeverity.LOW, i) for i in range(40)])
        assert s < 25 and risk_level(s) == RiskLevel.LOW

    def test_worst_finding_sets_the_band(self):
        assert risk_level(risk_score([_f(FindingSeverity.MEDIUM)])) == RiskLevel.MEDIUM
        assert risk_level(risk_score([_f(FindingSeverity.HIGH)])) == RiskLevel.HIGH
        assert risk_level(risk_score([_f(FindingSeverity.CRITICAL)])) == RiskLevel.CRITICAL
        assert risk_level(risk_score([_f(FindingSeverity.HIGH), *[_f(FindingSeverity.LOW, i) for i in range(1, 30)]])) == RiskLevel.HIGH

    def test_breadth_adds_inside_the_band(self):
        one = risk_score([_f(FindingSeverity.HIGH)])
        many = risk_score([_f(FindingSeverity.HIGH, i) for i in range(5)])
        assert one < many < 75
        assert risk_score([_f(FindingSeverity.CRITICAL, i) for i in range(20)]) == 99.0
