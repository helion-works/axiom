"""
Phase 4 / D.5 — the anonymous usage ping (README, "Usage ping").
Payload is exactly the documented shape; off/env/DNT mean zero network calls; 24 h throttle;
offline never breaks `check`; the first-run notice prints once.
"""

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis import telemetry as tm  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Client:
    calls = []

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, json=None, headers=None):
        _Client.calls.append((url, json, headers))


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    import app.analysis.scan_history as sh
    monkeypatch.setattr(sh, "MCPGUARD_DIR", str(tmp_path))
    for v in ("AXIOM_TELEMETRY", "AGENTAV_TELEMETRY", "MCPGUARD_TELEMETRY", "DO_NOT_TRACK", "AXIOM_TELEMETRY_ENDPOINT"):
        monkeypatch.delenv(v, raising=False)
    import types
    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))
    _Client.calls.clear()
    return tmp_path


COUNTS = {"clients_detected": 2, "servers_inventoried": 7, "findings_critical": 0, "findings_high": 1,
          "findings_medium": 3}


class TestPayload:
    def test_exact_shape_and_nothing_else(self, isolated):
        poisoned = dict(COUNTS, server_names=["github"], paths=["/home/x"], tool_names=["run_command"])
        p = tm.build_payload(poisoned)
        assert tuple(p.keys()) == tm.PAYLOAD_KEYS
        assert tuple(p["counts"].keys()) == tm.COUNT_KEYS
        assert p["schema"] == 1 and p["client_version"] == "0.6.0" and p["os"] in ("windows", "macos", "linux")
        assert "server_names" not in json.dumps(p) and "/home/x" not in json.dumps(p) and "run_command" not in json.dumps(p)
        import uuid
        uuid.UUID(p["install_id"])
        assert p["sent_at"].endswith("Z")

    def test_install_id_is_random_and_resettable(self, isolated):
        a = tm.install_id()
        assert tm.install_id() == a
        assert tm.install_id(regenerate=True) != a

    def test_counts_only_from_check_result(self, isolated):
        from app.models.schemas import Finding, FindingCategory, FindingSeverity
        res = {"config_files_found": ["/a", "/b"], "total_servers": 7, "findings": [
            Finding(id="x", severity=FindingSeverity.HIGH, category=FindingCategory.METADATA, title="t", description="d"),
            Finding(id="y", severity=FindingSeverity.MEDIUM, category=FindingCategory.METADATA, title="t", description="d")]}
        assert tm.counts_from_check(res) == {"clients_detected": 2, "servers_inventoried": 7, "findings_critical": 0,
                                             "findings_high": 1, "findings_medium": 1}


class TestSwitches:
    def test_off_means_no_network(self, isolated):
        tm.set_enabled(False)
        assert tm.maybe_send(COUNTS, blocking=True) is False and _Client.calls == []

    @pytest.mark.parametrize("var,val", [("AXIOM_TELEMETRY", "0"), ("MCPGUARD_TELEMETRY", "0"), ("DO_NOT_TRACK", "1")])
    def test_env_means_no_network(self, isolated, monkeypatch, var, val):
        monkeypatch.setenv(var, val)
        assert tm.enabled() is False
        assert tm.maybe_send(COUNTS, blocking=True) is False and _Client.calls == []

    def test_throttle_one_send_per_day(self, isolated):
        assert tm.maybe_send(COUNTS, blocking=True) is True
        assert tm.maybe_send(COUNTS, blocking=True) is False
        assert len(_Client.calls) == 1
        url, body, headers = _Client.calls[0]
        assert url == tm.DEFAULT_ENDPOINT and tuple(body.keys()) == tm.PAYLOAD_KEYS
        assert headers["User-Agent"].startswith("axiom/0.6.0 (")

    def test_first_ping_keeps_its_install_id(self, isolated):
        # The id sent in the very first ping must be the one stored for every later ping.
        assert tm.maybe_send(COUNTS, blocking=True) is True
        sent_id = _Client.calls[0][1]["install_id"]
        assert tm.load_state().get("install_id") == sent_id
        assert tm.install_id() == sent_id

    def test_offline_is_silent(self, isolated, monkeypatch):
        class Boom(_Client):
            def post(self, *a, **k):
                raise ConnectionError("offline")
        import types
        monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=Boom))
        assert tm.maybe_send(COUNTS, blocking=True) is True   # started, failed silently

    def test_background_send_is_delivered_before_exit(self, isolated, monkeypatch):
        # `axiom check` sends on a daemon thread and then exits. flush() is what makes the
        # ping arrive: without it the interpreter ends before the request is made.
        import threading
        import types
        started = threading.Event()

        class Slow(_Client):
            def post(self, url, json=None, headers=None):
                started.wait(2)
                _Client.calls.append((url, json, headers))
        monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=Slow))
        assert tm.maybe_send(COUNTS) is True
        assert _Client.calls == []            # still in flight
        started.set()
        tm.flush()
        assert len(_Client.calls) == 1
        tm.flush()                            # nothing pending: returns at once

    def test_unrecognised_platform_is_sent_as_other(self, isolated, monkeypatch):
        monkeypatch.setattr(tm.platform, "system", lambda: "CYGWIN_NT-10.0-19045")
        assert tm.build_payload(COUNTS)["os"] == "other"

    def test_first_run_notice_once(self, isolated):
        assert tm.first_run_notice_due() is True
        tm.mark_notice_shown()
        assert tm.first_run_notice_due() is False


class TestCli:
    def test_check_runs_offline_and_notice_prints_once(self, tmp_path):
        env = dict(os.environ, AXIOM_DATA_DIR=str(tmp_path), AXIOM_TELEMETRY_ENDPOINT="http://127.0.0.1:9/v1/ping",
                   PYTHONIOENCODING="utf-8")
        p1 = subprocess.run([sys.executable, "-m", "cli.axiom_cli", "check", "--output", "json"], capture_output=True,
                            text=True, encoding="utf-8", cwd=REPO, env=env)
        assert p1.returncode in (0, 1, 2), p1.stderr[-400:]
        doc = json.loads(p1.stdout)
        assert set(doc["counts"]) == set(tm.COUNT_KEYS)
        assert "anonymous usage ping" in p1.stderr
        p2 = subprocess.run([sys.executable, "-m", "cli.axiom_cli", "check", "--output", "json"], capture_output=True,
                            text=True, encoding="utf-8", cwd=REPO, env=env)
        assert "anonymous usage ping" not in p2.stderr
        p3 = subprocess.run([sys.executable, "-m", "cli.axiom_cli", "telemetry", "show"], capture_output=True,
                            text=True, encoding="utf-8", cwd=REPO, env=env)
        assert tuple(json.loads(p3.stdout).keys()) == tm.PAYLOAD_KEYS
        p4 = subprocess.run([sys.executable, "-m", "cli.axiom_cli", "telemetry", "off"], capture_output=True,
                            text=True, encoding="utf-8", cwd=REPO, env=env)
        assert "off" in p4.stdout.lower()
