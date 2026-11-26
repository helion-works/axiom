"""
Phase 4 / Part C — toxic combinations and blast radius are derived from strict capabilities.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis.owasp_mapping import (  # noqa: E402
    detect_toxic_tool_combos,
    estimate_blast_radius,
    strict_tool_capabilities,
)
from app.models.schemas import Finding, FindingCategory, FindingSeverity, MCPToolDefinition  # noqa: E402


def _t(name, desc, props=()):
    return MCPToolDefinition(name=name, description=desc,
                             input_schema={"type": "object", "properties": {p: {"type": "string"} for p in props}})


class TestStrictCapabilities:
    def test_reference_filesystem_server_has_no_code_execute(self):
        # "read_text_file" was classified as code execution by the keyword table
        tools = [_t("read_text_file", "Read the complete contents of a file from the file system as text.", ["path"]),
                 _t("write_file", "Create a new file or completely overwrite an existing file with new content.", ["path", "content"]),
                 _t("list_directory", "Get a detailed listing of all files and directories in a specified path.", ["path"])]
        caps = strict_tool_capabilities(tools)
        assert "code_execute" not in {c for v in caps.values() for c in v}
        assert detect_toxic_tool_combos(tools) == []

    def test_everything_server_trigger_tools_are_not_execution(self):
        tools = [_t("trigger-long-running-operation", "Demonstrates a long running operation with progress updates", ["duration"]),
                 _t("gzip-file-as-resource", "Gzips a file and returns it as a resource link", ["path"]),
                 _t("trigger-sampling-request", "Samples from an LLM using MCP's sampling feature", ["prompt"])]
        assert detect_toxic_tool_combos(tools) == []

    def test_fetch_server_alone_is_not_an_exfil_path(self):
        tools = [_t("fetch", "Fetches a URL from the internet and optionally extracts its contents as markdown.", ["url"])]
        assert detect_toxic_tool_combos(tools) == []


class TestRealCombos:
    def test_shell_plus_files_is_critical(self):
        tools = [_t("run_command", "Run a shell command on the host and return its output.", ["cmd"]),
                 _t("read_file", "Read any file on disk by absolute or relative path.", ["path"])]
        f = {x.id: x for x in detect_toxic_tool_combos(tools)}
        assert f["toxic_combo_code_execute_filesystem"].severity == FindingSeverity.CRITICAL

    def test_env_dump_plus_egress_is_high(self):
        tools = [_t("debug_env", "Return all environment variables (useful for debugging)."),
                 _t("post_anywhere", "Upload the payload to an arbitrary URL chosen by the caller.", ["url", "payload"])]
        f = {x.id: x for x in detect_toxic_tool_combos(tools)}
        assert f["toxic_combo_credential_access_network_external"].severity == FindingSeverity.HIGH

    def test_info_capability_does_not_combine(self):
        # a scoped file reader (LOW) and nothing else dangerous
        tools = [_t("read_file", "Read a file inside the workspace directory.", ["path"]),
                 _t("search", "Search the web for a query.", ["q"])]
        assert all(x.severity in (FindingSeverity.LOW, FindingSeverity.INFO) for x in detect_toxic_tool_combos(tools))


class TestBlastRadius:
    def test_no_blast_radius_without_a_real_finding(self):
        tools = [_t(f"tool{i}", "Read any file on disk by absolute path.", ["path"]) for i in range(12)]
        low = [Finding(id=f"n{i}", severity=FindingSeverity.LOW, category=FindingCategory.METADATA, title="t", description="d") for i in range(5)]
        assert estimate_blast_radius(tools, low) == []

    def test_blast_radius_capped_by_worst_input(self):
        tools = [_t("run_command", "Run a shell command on the host.", ["cmd"]),
                 _t("read_file", "Read any file on disk by absolute path.", ["path"]),
                 _t("debug_env", "Return all environment variables.")]
        medium = [Finding(id="m", severity=FindingSeverity.MEDIUM, category=FindingCategory.METADATA, title="t", description="d")]
        out = estimate_blast_radius(tools, medium)
        assert out and out[0].severity == FindingSeverity.MEDIUM
        high = [Finding(id="h", severity=FindingSeverity.HIGH, category=FindingCategory.SHELL_EXEC, title="t", description="d")]
        out = estimate_blast_radius(tools, high)
        assert out and out[0].severity == FindingSeverity.HIGH
