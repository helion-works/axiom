"""
Regenerate docs/COVERAGE.md from the raw proofs under proofs/ (Phase 4, E.4).

    python tools/coverage_ledger.py            # writes docs/COVERAGE.md
    python tools/coverage_ledger.py --check    # exit 1 if docs/COVERAGE.md is stale

Every benchmark row records: score, date, the scanner commit the raw outputs were taken
with, and whether rules were tuned on it (tuned) or it was held out (held-out). The README
links here instead of quoting numbers that go stale.
"""

from __future__ import annotations

import collections
import glob
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROOFS = os.path.join(ROOT, "proofs")
OUT = os.path.join(ROOT, "docs", "COVERAGE.md")
SEVS = ["critical", "high", "medium", "low", "info"]

# Fixed facts about each harness (what it is, how rules relate to it, where the write-up is)
HARNESSES = {
    "in-house": {"name": "In-house test bed", "status": "tuned",
                 "note": "two deliberately vulnerable Python servers (20 planted findings), two benign controls; Phase 2 rules were written against it",
                 "doc": "in-house test bed (not in this repository)"},
    "dvmcp": {"name": "DVMCP (Damn Vulnerable MCP, 15 challenges)", "status": "tuned",
              "note": "Phase 3 rules were written while reading its source; not re-run in Phase 4 (third-party code could not be executed in this environment)",
              "doc": "Phase 3 DVMCP write-up (not in this repository)"},
    "reference-servers": {"name": "Official reference servers (modelcontextprotocol/servers, 7 servers)", "status": "tuned (held out until Phase 4 Part C)",
                          "note": "every HIGH/CRITICAL on these is a false positive by default; held out for the before column only. The after column is a fresh clone taken on 2026-11-11", "doc": "FP_BASELINE.md"},
    "registry-sample": {"name": "MCP Registry sample 1 (50 servers: 25 most-starred of a random pool + 25 random)", "status": "tuned (held out until Phase 4 Part C; Phase 5 rules were written against its false positives)",
                        "note": "seed 20261104; held out for the before column only. In Phase 4, 5 repositories could not be checked out on Windows (45 scanned; after Part C at `555cd41`: CRITICAL 30, HIGH 82). The Phase 5 after column is a fresh clone of all 50 on 2026-11-11 with `core.longpaths`, so the two after figures are not the same snapshot", "doc": "FP_BASELINE.md"},
    "registry-sample-2": {"name": "MCP Registry sample 2 (50 servers, same method, new seed, sample 1 excluded)", "status": "held-out (false-positive corpus)",
                          "note": "seed 20261105; drawn and scanned once, after the Phase 5 rules were frozen; no rule has been edited since", "doc": "LAUNCH_READINESS.md"},
    "mcpsecbench": {"name": "MCPSecBench (AIS2Lab, 17 attacks; 14 server-side cases in scope)", "status": "tuned (held out until Phase 4 Part C)",
                    "note": "scored static only; no live runs (third-party code was not executed). The before column is the held-out score; the after column shows the fixes written against it", "doc": "HELDOUT_RESULTS.md"},
    "live-localhost": {"name": "Healthy localhost server over Streamable HTTP, no auth (A.3)", "status": "held-out (false-positive)",
                       "note": "tests/fixtures/healthy_http_server.py", "doc": "FP_BASELINE.md"},
}

# MCPSecBench scoring: finding ids that count as 'caught' per in-scope case (after Part C)
MCPSECBENCH_CASES = {
    "#1 Tool poisoning (add, m_check)": ["poison_add_injection_marker", "poison_add_preference_override", "poison_m_check_preference_override"],
    "#2 Tool shadowing (aft_check)": ["poison_aft_check_tool_shadowing"],
    "#3 Server-name squatting (check_sig / check_sig_)": ["squat_server_check_sig__check_sig_"],
    "#4 Tool-name squatting (compute / compute_)": ["shadow_compute_near_duplicate", "shadow_compute__near_duplicate"],
    "#5 Data exfiltration (times.tools_list)": ["schema_times_context_param_tools_list"],
    "#6 Prompt injection (internal://credentials)": ["resource_internal_credentials_secret_exposure"],
    "#7 Rug pull (get_weather_forecast)": ["rugpull_counter_get_weather_forecast", "rugpull_docstring_get_weather_forecast_get_weather_forecast"],
    "#8 Indirect prompt injection (get_user_info)": ["response_injection_get_user_info_injection_marker"],
    "#9 Sandbox escape (sandbox_run)": ["cap_sandbox_run_shell_exec", "flow_sandbox_run_command_shell_exec"],
    "#10 Confused AI (modify)": ["poison_modify_preference_override"],
    "#11 Vulnerable server (download.py check/compute)": ["flow_check_file_mame_file_read", "flow_compute_file_mame_file_read"],
    "#12 Schema inconsistencies (sub, times, check)": ["schema_sub_doc_mismatch", "schema_check_undocumented_params"],
    "#13 Configuration drift (sse.py 0.0.0.0)": ["mcp07_bind_all_0001"],
    "#14 Malicious OAuth metadata (CVE-2025-6514)": ["oauth_metachar_cve-2025-6514.py_"],
}
MCPSECBENCH_PARTIAL_BEFORE = {"#8 Indirect prompt injection (get_user_info)", "#13 Configuration drift (sse.py 0.0.0.0)"}


def _git(*args):
    try:
        return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def _load(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _totals(dirpath):
    tot = collections.Counter()
    servers = 0
    crit_servers = 0
    for p in sorted(glob.glob(os.path.join(dirpath, "*.json"))):
        d = _load(p)
        if not d or "findings" not in d:
            continue
        servers += 1
        c = collections.Counter(f.get("severity", "info") for f in d["findings"])
        tot.update(c)
        if d.get("risk_level") == "critical":
            crit_servers += 1
    return servers, crit_servers, tot


def _mcpsecbench_score(dirpath):
    ids = set()
    for p in glob.glob(os.path.join(dirpath, "*.json")):
        d = _load(p)
        if d and "findings" in d:
            ids |= {f["id"] for f in d["findings"] if f.get("severity") != "info"}
    caught = partial = 0
    rows = []
    for case, wanted in MCPSECBENCH_CASES.items():
        hit = [w for w in wanted if any(i == w or i.startswith(w) for i in ids)]
        if hit:
            caught += 1
            rows.append((case, "caught", ", ".join(hit[:2])))
        elif case in MCPSECBENCH_PARTIAL_BEFORE and any(i.startswith(("trust_", "mcp07_bind_all")) for i in ids):
            partial += 1
            rows.append((case, "partial", "generic pattern only"))
        else:
            rows.append((case, "miss", "-"))
    return caught, partial, len(MCPSECBENCH_CASES), rows


# The scanner commits the raw outputs were taken with. These are fixed facts about the files
# under proofs/, not the current HEAD: a ledger that printed HEAD would go stale on every commit.
BEFORE_COMMIT = "5f3d93b"   # proofs/*/raw       (held-out starting commit)
AFTER_COMMIT = "fe6d5dc"    # proofs/*/raw_after and proofs/registry-sample-2/raw (frozen worktree, Phase 5 Part 1 end)
AFTER_DATE = "2026-11-11"


def _commit_of(dirname):
    """Commit recorded for a raw directory: raw = starting commit, raw_after = Part C end commit."""
    if dirname.endswith("raw_after"):
        return AFTER_COMMIT
    return BEFORE_COMMIT


def build():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    head = _git("rev-parse", "--short", "HEAD") or "unknown"
    lines = [
        "# Coverage ledger",
        "",
        f"Generated by `python tools/coverage_ledger.py` from the raw outputs under `proofs/` (regenerated by CI; last generated {now} at commit `{head}`).",
        "",
        "**Two numbers, never merged:** recall on benchmarks that plant findings, and false positives on corpora that should be clean. "
        "`tuned` means rules were written while looking at that corpus; `held-out` means the score was taken before any rule touched it, "
        "and the after column shows the same corpus after the rule changes. A corpus stops being held out the moment a rule is "
        "written against it: only its before column stays independent. Registry sample 2 has no before column because it was "
        "scanned once, with the rules already frozen.",
        "",
        "| harness | status | before (commit) | after (commit) | date | write-up |",
        "|---|---|---|---|---|---|",
    ]
    # in-house + dvmcp: fixed historical numbers (re-run of the in-house bed is recorded in LAUNCH_READINESS)
    lines.append(f"| {HARNESSES['in-house']['name']} | tuned | 12/12 + 8/8, controls clean (`a13333e`) | 12/12 + 8/8, proofs 6/6 (`{AFTER_COMMIT}`) | {AFTER_DATE} | {HARNESSES['in-house']['doc']} |")
    lines.append(f"| {HARNESSES['dvmcp']['name']} | tuned | 15/15 (`a13333e`) | not re-run | 2026-11-03 | {HARNESSES['dvmcp']['doc']} |")

    def fmt(t):
        n, cs, c = t
        return f"{n} servers, {cs} rated critical; CRITICAL {c['critical']}, HIGH {c['high']}, MEDIUM {c['medium']}, LOW {c['low']}, INFO {c['info']}"

    for key in ("reference-servers", "registry-sample"):
        before = _totals(os.path.join(PROOFS, key, "raw"))
        after = _totals(os.path.join(PROOFS, key, "raw_after"))
        lines.append(f"| {HARNESSES[key]['name']} | {HARNESSES[key]['status']} | {fmt(before)} (`{BEFORE_COMMIT}`) | {fmt(after) if after[0] else 'pending'} (`{AFTER_COMMIT}`) | {AFTER_DATE} | {HARNESSES[key]['doc']} |")

    fresh = _totals(os.path.join(PROOFS, "registry-sample-2", "raw"))
    lines.append(f"| {HARNESSES['registry-sample-2']['name']} | {HARNESSES['registry-sample-2']['status']} | not scanned before the rules were frozen | "
                 f"{fmt(fresh) if fresh[0] else 'pending'} (`{AFTER_COMMIT}`) | {AFTER_DATE} | {HARNESSES['registry-sample-2']['doc']} |")

    b = _mcpsecbench_score(os.path.join(PROOFS, "mcpsecbench", "raw"))
    a = _mcpsecbench_score(os.path.join(PROOFS, "mcpsecbench", "raw_after"))
    lines.append(f"| {HARNESSES['mcpsecbench']['name']} | {HARNESSES['mcpsecbench']['status']} | {b[0]}/{b[2]} caught, {b[1]} partial (`{BEFORE_COMMIT}`) | "
                 f"{a[0]}/{a[2]} caught, {a[1]} partial (`{AFTER_COMMIT}`) | {AFTER_DATE} | HELDOUT_RESULTS.md |")
    lb = _load(os.path.join(PROOFS, "live-localhost", "raw", "healthy_http_before.json")) or {}
    la = _load(os.path.join(PROOFS, "live-localhost", "raw_after", "healthy_http_after.json")) or {}
    def live_fmt(d):
        if not d:
            return "pending"
        return f"{d.get('risk_level')} / {d.get('risk_score')}; " + ", ".join(f"{f['severity']} {f['id'].rsplit('_', 1)[-1]}" for f in d.get("findings", []))
    lines.append(f"| {HARNESSES['live-localhost']['name']} | held-out (false-positive) | {live_fmt(lb)} (`{BEFORE_COMMIT}`) | {live_fmt(la)} (`{AFTER_COMMIT}`) | {AFTER_DATE} | FP_BASELINE.md |")

    lines += ["", "## MCPSecBench, case by case (after)", "", "| case | verdict | evidence (finding id) |", "|---|---|---|"]
    for case, verdict, ev in a[3]:
        lines.append(f"| {case} | {verdict} | `{ev}` |")
    lines += ["", "Out of scope for a scanner (client, browser or network attacks): #15 Slash command overlap, #16 MCP rebinding, #17 Man-in-the-middle.", ""]
    lines += ["## Notes", ""]
    for key, h in HARNESSES.items():
        lines.append(f"- **{h['name']}** — {h['note']}.")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    text = build()
    if "--check" in sys.argv:
        current = open(OUT, "r", encoding="utf-8").read() if os.path.exists(OUT) else ""
        # ignore the generation stamp line when comparing
        strip = lambda s: "\n".join(l for l in s.splitlines() if not l.startswith("Generated by"))  # noqa: E731
        if strip(current) != strip(text):
            print("docs/COVERAGE.md is stale; run python tools/coverage_ledger.py")
            sys.exit(1)
        print("docs/COVERAGE.md is current")
    else:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("wrote", OUT)
