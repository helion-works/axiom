"""
Replayable findings (Phase 4, E.4).

Every finding Axiom emits carries four things a reviewer can check without trusting
Axiom:

* ``rule_id``  — the stable name of the rule that fired (``poison_instruction_injection``,
  ``cap_shell_exec``, ``flow_file_read``, ``dependency_advisory`` ...), independent of the
  tool or file it fired on;
* ``evidence`` — the exact text the rule matched (a quoted phrase, a URL, a parameter name,
  an advisory id), never a secret value;
* ``location`` — ``<file>:<line>`` for source, ``live:<method>:<item>`` for a live session,
  ``config:<file>:<server>`` for client configs, ``static:<target>:<item>`` when a rule looked
  at an extracted definition rather than one line;
* ``replay``   — the exact command (or JSON-RPC request) that reproduces it.

Detectors may set these explicitly; :func:`enrich_findings` fills whatever is missing
from the finding's id, description and context, and the unit test
``tests/test_phase4_replay.py`` enforces that nothing leaves a scan without all four.
"""

from __future__ import annotations

import json
import re
from typing import Iterable, List, Optional

from app.models.schemas import Finding

# (regex over the finding id, rule_id). First match wins; order matters.
_RULE_TABLE = [
    (r"^(GHSA|CVE|PYSEC|OSV|GO|RUSTSEC|MAL)-", "dependency_advisory"),
    (r"^osv_.*_unversioned$", "dependency_unpinned_advisories"),
    (r"^dep_known_", "known_malicious_package"),
    (r"^manifest_(preinstall|postinstall|preuninstall|prepublish)", "install_lifecycle_hook"),
    (r"^manifest_bin_", "manifest_bin"),
    (r"^manifest_py_cmdclass", "setup_cmdclass"),
    (r"^transport_session_url", "transport_session_in_url"),
    (r"^transport_no_auth", "transport_no_auth"),
    (r"^transport_plain_http", "transport_plain_http"),
    (r"^live_.*_plain_http$", "live_plain_http"),
    (r"^live_.*_no_auth$", "live_no_auth"),
    (r"^live_.*_tools_list_changed$", "live_tools_list_changed"),
    (r"^live_.*_excessive_tools$", "live_excessive_tools"),
    (r"^live_.*_no_desc$", "live_tool_no_description"),
    (r"^live_.*_code_input$", "live_code_input_param"),
    (r"^live_.*_unknown_caps$", "live_unknown_capabilities"),
    (r"^live_.*_experimental$", "live_experimental_capabilities"),
    (r"^diff_.*_runtime_only$", "runtime_only_tool"),
    (r"^diff_.*_source_only$", "source_only_tool"),
    (r"^diff_.*_desc_mutation$", "description_mutation"),
    (r"^diff_.*_schema_mutation$", "schema_mutation"),
    (r"^surface_mismatch_tool_added_", "surface_mismatch_tool_added"),
    (r"^surface_mismatch_tool_changed_", "surface_mismatch_tool_changed"),
    (r"^surface_mismatch_tool_missing_", "surface_mismatch_tool_missing"),
    (r"^surface_mismatch_instructions", "surface_mismatch_instructions"),
    (r"^surface_mismatch_resource_added_", "surface_mismatch_resource_added"),
    (r"^surface_mismatch_prompt_added_", "surface_mismatch_prompt_added"),
    (r"^config_squat_", "config_server_name_squatting"),
    (r"^config_.*_dangerous_cmd$", "config_dangerous_command"),
    (r"^config_.*_hardcoded_secret$", "config_hardcoded_secret"),
    (r"^config_.*_npx_unknown$", "config_unpinned_npx"),
    (r"^config_.*_uvx$", "config_uvx"),
    (r"^config_.*_no_auth$", "config_remote_no_auth"),
    (r"^config_.*_env_overexposed$", "config_env_overexposed"),
    (r"^config_.*_env_", "config_secret_env_var"),
    (r"^cross_env_", "config_shared_credential"),
    (r"^discover_unapproved_", "shadow_server"),
    (r"^mcp01_secret_", "hardcoded_secret"),
    (r"^mcp04_unpinned_", "unpinned_install_source"),
    (r"^mcp05_tool_sink_", "tool_input_sink"),
    (r"^mcp07_bind_all_", "bind_all_interfaces"),
    (r"^mcp08_no_tool_logging", "no_tool_logging"),
    (r"^mcp10_broad_exposure_", "broad_data_exposure"),
    (r"^cap_.*_shell_exec$", "cap_shell_exec"),
    (r"^cap_.*_file_read$", "cap_file_read"),
    (r"^cap_.*_file_write$", "cap_file_write"),
    (r"^cap_.*_env_dump$", "cap_env_dump"),
    (r"^cap_.*_network_egress$", "cap_network_egress"),
    (r"^flow_.*_file_read$", "flow_file_read"),
    (r"^flow_.*_file_write$", "flow_file_write"),
    (r"^flow_.*_shell_exec$", "flow_shell_exec"),
    (r"^flow_.*_network_egress$", "flow_network_egress"),
    (r"^toxic_combo_", "toxic_tool_combination"),
    (r"^blast_radius_estimate", "blast_radius"),
    (r"^codegen_", "code_generation_pattern"),
    (r"^memory_", "memory_poisoning_pattern"),
    (r"^interagent_", "inter_agent_pattern"),
    (r"^trust_", "trust_exploitation_pattern"),
    (r"^rogue_", "rogue_agent_pattern"),
    (r"^egress_.*_desc_\d+$", "egress_url_in_description"),
    (r"^egress_", "egress_url_in_tool_body"),
    (r"^rugpull_docstring_", "rugpull_description_rewrite"),
    (r"^rugpull_counter_", "rugpull_invocation_counter"),
    (r"^rugpull_listchanged_", "rugpull_list_changed"),
    (r"^rugpull_remove_tool_", "rugpull_remove_tool"),
    (r"^rugpull_add_tool_", "rugpull_runtime_registration"),
    (r"^rewritten_desc_.*_(injection_marker|instruction_injection|tool_shadowing|preference_override|exfil_instruction|tool_chaining|priv_escalation|invisible_unicode|egress_\d+|sensitive_path|secret_exposure|invokes_dangerous_tool|unicode_hiding|supply_chain_config)$", None),
    (r"^deputy_", "confused_deputy"),
    (r"^squat_server_", "server_name_squatting"),
    (r"^oauth_metachar_", "oauth_shell_metacharacters"),
    (r"^schema_.*_context_param_", "schema_context_parameter"),
    (r"^schema_.*_doc_mismatch$", "schema_doc_mismatch"),
    (r"^schema_.*_undocumented_params$", "schema_undocumented_params"),
    (r"^scope_.*_excessive$", "excessive_scope_default"),
    (r"^identity_override_", "identity_override_param"),
    (r"^authz_input_", "authz_input_param"),
    (r"^unpinned_runtime_install_", "unpinned_runtime_install"),
    (r"^poison_.*_injection_marker$", "poison_injection_marker"),
    (r"^poison_.*_instruction_injection$", "poison_instruction_injection"),
    (r"^poison_.*_tool_shadowing$", "poison_tool_shadowing"),
    (r"^poison_.*_preference_override$", "poison_preference_override"),
    (r"^poison_.*_exfil_instruction$", "poison_exfil_instruction"),
    (r"^poison_.*_tool_chaining$", "poison_tool_chaining"),
    (r"^poison_.*_priv_escalation$", "poison_priv_escalation"),
    (r"^poison_.*_invisible_unicode$", "poison_invisible_unicode"),
    (r"^poison_.*_unicode_hiding$", "poison_unicode_hiding"),
    (r"^poison_.*_sleeper_pattern$", "poison_sleeper_pattern"),
    (r"^poison_.*_homoglyph$", "homoglyph_tool_name"),
    (r"^poison_.*_long_desc$", "long_description"),
    (r"^poison_.*_mismatch$", "name_description_mismatch"),
    (r"^shadow_.*_near_duplicate$", "near_duplicate_tool_name"),
    (r"^cross_tool_", "cross_tool_reference"),
    (r"^inject_", "prompt_injection_pattern"),
    (r"^ast_\d+$", "code_pattern_ast"),
    (r"^code_\d+$", "code_pattern_regex"),
    (r"^semgrep_", "semgrep_rule"),
    (r"^no_source$", "no_source"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(injection_marker)$", "served_text_injection_marker"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(invisible_unicode)$", "served_text_invisible_unicode"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(secret_exposure)$", "served_text_secret_exposure"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(sensitive_path)$", "served_text_sensitive_path"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(egress_\d+)$", "served_text_egress_url"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(invokes_dangerous_tool)$", "served_text_invokes_dangerous_tool"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(supply_chain_config)$", "served_text_supply_chain_config"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(restricted_name)$", "restricted_resource_name"),
    (r"^(instructions|resource_.*|prompt_.*|response_injection_.*|stored_.*|live_.*)_(instruction_injection|tool_shadowing|preference_override|exfil_instruction|tool_chaining|priv_escalation|unicode_hiding|system_prompt_override|role_injection)$", None),
]
_SUFFIX_RULES = {
    "instruction_injection": "served_text_instruction_injection", "tool_shadowing": "served_text_tool_shadowing",
    "preference_override": "served_text_preference_override", "exfil_instruction": "served_text_exfil_instruction",
    "tool_chaining": "served_text_tool_chaining", "priv_escalation": "served_text_priv_escalation",
    "unicode_hiding": "served_text_unicode_hiding", "system_prompt_override": "served_text_system_prompt_override",
    "role_injection": "served_text_role_injection", "injection_marker": "rewritten_description_injection_marker",
    "invisible_unicode": "rewritten_description_invisible_unicode", "sensitive_path": "rewritten_description_sensitive_path",
    "secret_exposure": "rewritten_description_secret_exposure", "invokes_dangerous_tool": "rewritten_description_invokes_dangerous_tool",
    "supply_chain_config": "rewritten_description_supply_chain_config",
}

_EVIDENCE_PATTERNS = [
    r"Matched pattern in tool '[^']*': '(.+?)'(?:\.|$)",
    r"Matched '(.+?)' in ",
    r"Evidence: '(.+?)'",
    r"contains text meant for the model, not the user: '(.+?)'",
    r"contains (?:text meant for the model[^:]*: )?'(.+?)'\.",
    r"Pattern matched in [^:]+: `(.+?)`",
    r"Call to `(.+?)`",
    r"references '(.+?)'",
    r"points the agent at (\S+?)(?=\.(?:\s|$)|$)",
    r"sends to a fixed external endpoint (\S+?)(?=\.(?:\s|$))",
    r"names (?:an external endpoint )?\((.+?)\)",
    r"reaches `(.+?)`",
    r"assigns `(.+?)`",
    r"says '(.+?)'",
    r"describes itself as '(.+?)'",
    r"credential-shaped values: (.+?)\. Values",
    r"invisible character\(s\) \((.+?)\)",
    r"'(.+?)' is in the live tools/list",
    r"announce names [^:]*: '(.+?)' in",
    r"contains '(.+?)'",
    r"Full command: (.+)$",
    r"Parameter '(.+?)' of",
    r"'(.+?)' \(advisory severity",
]


def rule_id_for(finding_id: str) -> str:
    for rx, rule in _RULE_TABLE:
        m = re.match(rx, finding_id)
        if m:
            if rule is None:
                suffix = m.group(m.lastindex) if m.lastindex else finding_id.rsplit("_", 1)[-1]
                return _SUFFIX_RULES.get(suffix, "served_text_" + suffix)
            return rule
    # strip trailing numbering / names conservatively
    base = re.sub(r"_\d{2,}$", "", finding_id)
    return base.split("_")[0] + "_rule" if base else "unknown_rule"


def _extract_evidence(f: Finding) -> str:
    text = f.description or ""
    for rx in _EVIDENCE_PATTERNS:
        m = re.search(rx, text, re.S)
        if m:
            ev = m.group(1).strip()
            if ev:
                return ev[:300]
    if f.cve_id:
        return f.cve_id
    return (f.title or "")[:200]


_ITEM_PATTERNS = [
    r"^cap_(.+)_(?:shell_exec|file_read|file_write|env_dump|network_egress)$",
    r"^flow_(.+?)_\w+_(?:file_read|file_write|shell_exec|network_egress)$",
    r"^poison_(.+)_(?:injection_marker|instruction_injection|tool_shadowing|preference_override|exfil_instruction|tool_chaining|priv_escalation|invisible_unicode|unicode_hiding|sleeper_pattern|homoglyph|long_desc|mismatch)$",
    r"^scope_(.+?)_\w+_excessive$",
    r"^identity_override_(.+)$",
    r"^authz_input_(.+)$",
    r"^unpinned_runtime_install_(.+)$",
    r"^schema_(.+)_(?:context_param_.+|doc_mismatch|undocumented_params)$",
    r"^shadow_(.+)_near_duplicate$",
    r"^cross_tool_(.+)$",
    r"^egress_(.+)_(?:desc_)?\d+$",
    r"^deputy_(.+)$",
    r"^rugpull_(?:counter|docstring)_(.+)$",
    r"^rugpull_(?:add_tool|remove_tool)_(.+)$",
    r"^(?:resource|prompt|stored|response_injection)_(.+?)_(?:injection_marker|invisible_unicode|secret_exposure|sensitive_path|egress_\d+|invokes_dangerous_tool|supply_chain_config|restricted_name|instruction_injection|tool_shadowing|preference_override|exfil_instruction|tool_chaining|priv_escalation|unicode_hiding|system_prompt_override|role_injection)$",
]


def _item_from_id(fid: str) -> str:
    for rx in _ITEM_PATTERNS:
        m = re.match(rx, fid)
        if m:
            return m.group(1)
    return ""


def _location(f: Finding, mode: str, target: str) -> str:
    if f.file_path:
        if f.file_path.startswith(("live:", "config:", "static:")):
            return f.file_path
        if mode == "config":
            return f"config:{f.file_path}"
        return f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
    fid = f.id
    if mode == "live" or fid.startswith(("live_", "diff_", "surface_mismatch_")):
        if "_resource_" in fid or fid.startswith("surface_mismatch_resource"):
            return f"live:resources/read:{fid}"
        if "_prompt_" in fid or fid.startswith("surface_mismatch_prompt"):
            return f"live:prompts/get:{fid}"
        if "instructions" in fid or fid.endswith(("_no_auth", "_plain_http", "_unknown_caps", "_experimental", "_tools_list_changed")):
            return f"live:initialize:{target}"
        return f"live:tools/list:{fid}"
    if fid.startswith(("toxic_combo_", "blast_radius")):
        return f"static:{target}:tools"
    if fid.startswith(("GHSA-", "CVE-", "PYSEC-", "OSV", "osv_", "dep_known_")):
        return f"static:{target}:dependencies"
    item = _item_from_id(fid)
    return f"static:{target}:{item}" if item else f"static:{target}"


def _replay(f: Finding, mode: str, target: str, replay_cmd: Optional[str]) -> str:
    sel = f"| jq '.findings[] | select(.id==\"{f.id}\")'"
    if mode == "live":
        method = "tools/list"
        loc = f.location or ""
        for m in ("resources/read", "prompts/get", "initialize", "tools/list"):
            if m in loc:
                method = m
                break
        rpc = {"jsonrpc": "2.0", "id": 1, "method": method}
        if method == "initialize":
            rpc["params"] = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "axiom", "version": "0.6.0"}}
        elif method == "resources/read":
            rpc["params"] = {"uri": "<uri from the finding title>"}
        elif method == "prompts/get":
            rpc["params"] = {"name": "<prompt name from the finding title>"}
        cmd = replay_cmd or f"axiom live --url {target} --output json"
        return f"{cmd} {sel}  # on the wire: {json.dumps(rpc, separators=(',', ':'))}"
    if mode == "config":
        cmd = replay_cmd or f"axiom local --path {f.file_path or target} --output json"
        return f"{cmd} {sel}"
    cmd = replay_cmd or f"axiom scan {target} --output json --no-ai --no-history"
    return f"{cmd} {sel}"


def enrich_findings(findings: Iterable[Finding], *, mode: str = "static", target: str = "",
                    replay_cmd: Optional[str] = None) -> List[Finding]:
    """Fill rule_id / evidence / location / replay on every finding that lacks one."""
    out: List[Finding] = []
    for f in findings:
        if not f.rule_id:
            f.rule_id = rule_id_for(f.id)
        if not f.evidence:
            f.evidence = _extract_evidence(f)
        if not f.location:
            f.location = _location(f, mode, target or "<target>")
        if not f.replay:
            f.replay = _replay(f, mode, target or "<target>", replay_cmd)
        out.append(f)
    return out


def explain(f: Finding) -> str:
    """Human-readable four-field explanation for `axiom explain`."""
    return (f"{f.id}  [{f.severity.value.upper()}] {f.category.value}\n"
            f"  rule:      {f.rule_id}\n"
            f"  evidence:  {f.evidence}\n"
            f"  location:  {f.location}\n"
            f"  replay:    {f.replay}\n"
            f"  title:     {f.title}\n"
            f"  why:       {f.description}\n"
            f"  owasp:     ASI {', '.join(f.owasp_asi or []) or '-'}; MCP {', '.join(f.owasp_mcp or []) or '-'}\n")
