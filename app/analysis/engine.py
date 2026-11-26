"""
Axiom Core Analysis Engine
Orchestrates all MCP-specific security scanning modules:
  - Source code pattern analysis
  - Tool definition extraction & poisoning detection
  - Dependency vulnerability checking
  - Transport security assessment
  - Known CVE matching
  - Repository health analysis
"""

import os
import re
import json
import shutil
import tempfile
import time
import subprocess
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime, timezone

from app.models.schemas import (
    Finding, FindingSeverity, FindingCategory, DependencyInfo, RepoHealth,
    MCPToolDefinition, MCPResourceDefinition, MCPPromptDefinition,
    MCPServerProfile, TransportType, RiskLevel
)
from app.analysis.tool_poisoning import tool_poisoning_detector, detect_sensitive_resources
from app.analysis.ast_scanner import scan_python_ast
from app.analysis.py_extractor import extract_python_definitions
from app.analysis.ts_extractor import extract_ts_definitions
from app.analysis.surface_map import build_static_map
from app.analysis.dependencies import exact_version, extract_dependencies as _extract_deps, osv_findings
from app.analysis.evidence import enrich_findings
from app.analysis.provenance import provenance_check
from app.analysis.severity_policy import risk_level as _policy_level, risk_score as _policy_score, transport_severity
from app.analysis.semgrep_scanner import run_semgrep, is_semgrep_available
from app.analysis.owasp_mapping import (
    detect_toxic_tool_combos,
    detect_dangerous_tool_capabilities,
    detect_code_generation,
    detect_memory_poisoning_patterns,
    detect_inter_agent_patterns,
    estimate_blast_radius,
    detect_trust_exploitation,
    detect_rogue_agent_indicators,
    generate_owasp_coverage,
    generate_owasp_mcp_coverage,
    apply_owasp_mcp_mapping,
    CATEGORY_TO_ASI,
)
from app.analysis.mcp_top10_detectors import (
    detect_hardcoded_secrets,
    detect_unpinned_installs,
    detect_tool_input_sinks,
    detect_bind_all_interfaces,
    detect_missing_tool_logging,
    detect_broad_data_exposure,
)
from app.analysis.tool_body_detectors import ALL_BODY_DETECTORS
from app.utils.config import settings
from app.utils.logging import get_logger, set_scan_id, clear_scan_id

logger = get_logger("engine")

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from data.threat_intel import KNOWN_VULNERABLE_PACKAGES, advisory_aliases, cves_for_package, version_affected


# ============================================================
# MCP Source Code Patterns (focused on MCP-specific attack vectors)
# ============================================================

# Whole-file regexes. Per docs/SEVERITY.md these are capability *notes* (INFO/LOW):
# a sink in source is not hostile by itself. Hostility is decided by the tool-level
# detectors (cap_*, mcp05_tool_sink_*, egress_*, response_injection_*).
MCP_CODE_PATTERNS = {
    "credential_harvesting": {
        "patterns": [
            r"process\.env\[",
            r"os\.environ\.get\(",
            r"os\.environ\[",
            r"os\.getenv\(",
            r"\.ssh/",
            r"\.aws/credentials",
            r"\.npmrc",
            r"\.pypirc",
            r"\.gitconfig",
            r"\.netrc",
            r"keychain|keyring",
        ],
        "severity": FindingSeverity.INFO,
        "category": FindingCategory.CREDENTIAL_THEFT,
        "description": "Server reads environment variables or credential-file paths (capability note)",
    },
    "data_exfiltration": {
        "patterns": [
            r"fetch\s*\(['\"]https?://",
            r"axios\.(get|post|put)\s*\(",
            r"requests\.(get|post|put)\s*\(",
            r"httpx\.(get|post|put|AsyncClient)",
            r"urllib\.request\.urlopen",
            r"http\.request\s*\(",
            r"navigator\.sendBeacon",
            r"WebSocket\s*\(",
            r"net\.createConnection",
        ],
        "severity": FindingSeverity.INFO,
        "category": FindingCategory.DATA_EXFILTRATION,
        "description": "Server makes outbound network requests (capability note)",
    },
    "arbitrary_code_exec": {
        "patterns": [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"Function\s*\(",
            r"child_process\.(exec|spawn|fork)",
            r"subprocess\.(run|call|Popen|check_output)",
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"execSync\s*\(",
            r"spawnSync\s*\(",
        ],
        "severity": FindingSeverity.LOW,
        "category": FindingCategory.CODE_EXECUTION,
        "description": "Server source contains a process/code-execution sink (capability note; see tool-level findings)",
    },
    "command_injection": {
        "patterns": [
            r"child_process\.exec\s*\(\s*`",  # Template literal in exec
            r"child_process\.exec\s*\([^)]*\+",  # String concat in exec
            r'subprocess\.run\s*\(\s*f["\']',  # f-string in subprocess
            r"os\.system\s*\(\s*f['\"]",  # f-string in os.system
            r"shell\s*=\s*True",  # subprocess with shell=True
        ],
        "severity": FindingSeverity.HIGH,
        "category": FindingCategory.COMMAND_INJECTION,
        "description": "Command injection vulnerability — unsanitized input in shell command",
    },
    "sandbox_escape": {
        "patterns": [
            # realpath/readlink/symlink and path.join(..) are how servers *defend* against
            # escapes (every reference filesystem server uses them); they are not evidence.
            r"\.\.\/\.\.\/",
            r"chroot|pivot_root",
            r"proc/self",
            r"/etc/passwd|/etc/shadow",
        ],
        "severity": FindingSeverity.LOW,
        "category": FindingCategory.SANDBOX_ESCAPE,
        "description": "Path-escape primitive referenced in MCP server source (capability note)",
    },
    "obfuscation": {
        "patterns": [
            r"atob\s*\(",
            r"btoa\s*\(",
            r"Buffer\.from\s*\([^)]*,\s*['\"]base64",
            r"base64\.(b64decode|decodebytes)",
            r"String\.fromCharCode",
            r"(?:\\x[0-9a-fA-F]{2}){3,}",
            r"codecs\.decode",
        ],
        "severity": FindingSeverity.LOW,
        "category": FindingCategory.OBFUSCATION,
        "description": "Encoded or obfuscated content in MCP server source",
    },
    "file_system_broad_access": {
        "patterns": [
            r"fs\.readFileSync\s*\(",
            r"fs\.writeFileSync\s*\(",
            r"fs\.readdirSync\s*\(",
            r"fs\.unlinkSync\s*\(",
            r"open\s*\([^)]*['\"]w",
            r"shutil\.(rmtree|copytree|move)",
            r"glob\.[*][*]",
            r"os\.walk\s*\(",
        ],
        "severity": FindingSeverity.INFO,
        "category": FindingCategory.PERMISSION_OVERSCOPE,
        "description": "Filesystem operations in MCP server source (capability note)",
    },
}


# ============================================================
# Scan Result Cache — keyed on (repo_url, commit_sha)
# ============================================================

_scan_cache: Dict[str, Tuple[dict, float]] = {}  # key → (result, timestamp)
SCAN_CACHE_TTL = 3600  # 1 hour
SCAN_CACHE_MAX = 100


def _scan_cache_key(repo_url: str, commit_sha: str) -> str:
    return f"{repo_url}@{commit_sha}"


def _get_cached_scan(repo_url: str, commit_sha: str) -> Optional[dict]:
    key = _scan_cache_key(repo_url, commit_sha)
    entry = _scan_cache.get(key)
    if entry is None:
        return None
    result, ts = entry
    if time.monotonic() - ts > SCAN_CACHE_TTL:
        del _scan_cache[key]
        return None
    return result


def _put_scan_cache(repo_url: str, commit_sha: str, result: dict):
    if len(_scan_cache) >= SCAN_CACHE_MAX:
        oldest = min(_scan_cache, key=lambda k: _scan_cache[k][1])
        del _scan_cache[oldest]
    key = _scan_cache_key(repo_url, commit_sha)
    _scan_cache[key] = (result, time.monotonic())


class MCPAnalysisEngine:
    """Core analysis engine for MCP server security scanning."""

    def __init__(self):
        self.temp_dir = settings.TEMP_SCAN_DIR
        os.makedirs(self.temp_dir, exist_ok=True)

    async def scan(self, target: str, target_url: Optional[str] = None,
                   local_path: Optional[str] = None, check_deps: bool = True) -> dict:
        """
        Full MCP server security scan.
        Accepts: GitHub URL, npm package name, PyPI package name, or server name + URL.
        With ``local_path`` (a file or directory on this machine) the same pipeline runs
        on that path instead of a clone; nothing is fetched and nothing is deleted.
        Callers decide whether a local path is allowed — the engine never sniffs ``target``.
        Returns comprehensive scan result dict.
        """
        scan_id = set_scan_id()
        start_time = datetime.now(timezone.utc)
        logger.info("Scan started", extra={"target": target, "repo_url": target_url})
        findings = []
        dependencies = []
        server_profile = MCPServerProfile(name=target)
        repo_health = None
        package_info = None

        # Resolve URL — support package names
        url = target_url or (target if target.startswith("http") else None)

        if local_path:
            url = None  # a local path is scanned as-is; no package or repo resolution
        elif not url:
            # Try to resolve as a package name
            from app.analysis.package_resolver import is_package_name, resolve_package
            if is_package_name(target):
                try:
                    pkg = await resolve_package(target)
                    if pkg and pkg.repo_url:
                        url = pkg.repo_url
                        package_info = pkg
                        server_profile.npm_package = pkg.name if pkg.ecosystem == "npm" else None
                except Exception:
                    pass

        if url:
            server_profile.repo_url = url

        # Clone and analyze
        scan_dir = None
        commit_sha = None
        is_temp = False  # only directories we created ourselves are ever deleted
        if local_path:
            local_path = os.path.abspath(local_path)
            if os.path.isdir(local_path):
                scan_dir = local_path
            elif os.path.isfile(local_path):
                scan_dir = tempfile.mkdtemp(dir=self.temp_dir)
                shutil.copy2(local_path, scan_dir)
                is_temp = True
        elif url and ("github.com" in url or "gitlab.com" in url):
            scan_dir = await self._clone_repo(url)
            is_temp = scan_dir is not None

        if scan_dir and not local_path:
            # Check scan cache — skip full analysis if same repo+commit
            commit_sha = self._get_commit_sha(scan_dir)
            if url and commit_sha:
                cached = _get_cached_scan(url, commit_sha)
                if cached is not None:
                    logger.info(
                        "Scan cache hit",
                        extra={"target": target, "repo_url": url},
                    )
                    if is_temp:
                        shutil.rmtree(scan_dir, ignore_errors=True)
                    clear_scan_id()
                    return cached

        surface_map = None
        provenance = {"registry": {"status": "not_run"}}
        if scan_dir:
            # 1. Extract MCP tool/resource/prompt definitions
            tools, resources, prompts = self._extract_mcp_definitions(scan_dir)
            server_profile.tools = tools
            server_profile.resources = resources
            server_profile.prompts = prompts

            # 1b. The Agent Surface Map (what the model is shown + what each tool can do) and
            #     its fingerprint. Built from the same extraction; failures never abort a scan.
            try:
                surface_map = build_static_map(scan_dir, server_name=None if (local_path or url) else target).to_dict()
                surface_map["source"]["target"] = url or target
            except Exception as e:  # pragma: no cover
                logger.warning("Surface map failed", extra={"error": str(e)})

            # 2. Tool poisoning analysis
            poison_findings = tool_poisoning_detector.analyze_all_tools(tools)
            findings.extend(poison_findings)

            # 3. Source code pattern scanning (AST + regex)
            code_findings = self._scan_mcp_code(scan_dir)
            findings.extend(code_findings)

            # 3b. Semgrep scanning (if available)
            semgrep_findings = run_semgrep(scan_dir)
            findings.extend(semgrep_findings)

            # 4. Manifest / lifecycle hook analysis
            manifest_findings = self._analyze_manifests(scan_dir)
            findings.extend(manifest_findings)

            # 5. Dependency analysis
            deps = self._extract_dependencies(scan_dir)
            dependencies.extend(deps)
            dep_findings = await self._check_known_vulnerable(deps, check_osv=check_deps)
            findings.extend(dep_findings)

            # 5b. Provenance: registry identity, lookalike names, freshness (E.3). Same
            #     switch as the OSV lookup; never blocks a scan.
            if check_deps:
                try:
                    provenance, prov_findings = await provenance_check(
                        scan_dir, url, package_info,
                        server_name=(surface_map or {}).get("server", {}).get("name") if surface_map else None)
                    findings.extend(prov_findings)
                except Exception as e:  # pragma: no cover
                    logger.warning("Provenance check failed", extra={"error": str(e)})
                    provenance = {"registry": {"status": "error"}, "error": str(e)}
            else:
                provenance = {"registry": {"status": "skipped"}}

            # 6. Transport security analysis
            transport_findings = self._analyze_transport(scan_dir, server_profile)
            findings.extend(transport_findings)

            # 7. Known CVE matching
            # A package scanned by name is matched on the version written in the target,
            # or on its latest published version when none was given.
            cve_findings = self._check_known_cves(
                getattr(package_info, "name", None) or target, dependencies,
                target_version=(getattr(package_info, "requested_version", None)
                                or getattr(package_info, "version", None)),
                target_ecosystem=getattr(package_info, "ecosystem", None))
            findings = self._drop_osv_twins(findings, cve_findings)
            findings.extend(cve_findings)

            # 8. OWASP Agentic AI Top 10 — additional detectors
            # ASI02: Toxic tool combinations
            toxic_findings = detect_toxic_tool_combos(tools)
            findings.extend(toxic_findings)

            # Per-tool dangerous capabilities (shell_exec, file_read, file_write, env_dump, egress)
            findings.extend(detect_dangerous_tool_capabilities(tools))

            # Resources whose names say internal/secret/admin/debug
            findings.extend(detect_sensitive_resources(resources))

            # ASI05: Code generation from input
            codegen_findings = detect_code_generation(scan_dir)
            findings.extend(codegen_findings)

            # ASI06: Memory & context poisoning patterns
            memory_findings = detect_memory_poisoning_patterns(scan_dir)
            findings.extend(memory_findings)

            # ASI07: Inter-agent communication patterns
            interagent_findings = detect_inter_agent_patterns(scan_dir)
            findings.extend(interagent_findings)

            # ASI09: Trust exploitation patterns
            trust_findings = detect_trust_exploitation(scan_dir)
            findings.extend(trust_findings)

            # ASI10: Rogue agent indicators
            rogue_findings = detect_rogue_agent_indicators(scan_dir)
            findings.extend(rogue_findings)

            # 8b. OWASP MCP Top 10 — additional detectors
            findings.extend(self._run_mcp_top10_detectors(scan_dir, tools, resources))

            # ASI08: Blast radius estimation (uses tools + all findings)
            blast_findings = estimate_blast_radius(tools, findings)
            findings.extend(blast_findings)

            # 9. Repo health (if GitHub)
            if url and "github.com" in url:
                repo_health = await self._get_repo_health(url)

            # Cleanup — never the user's own directory
            if is_temp:
                shutil.rmtree(scan_dir, ignore_errors=True)
        else:
            findings.append(Finding(
                id="no_source",
                severity=FindingSeverity.INFO,
                category=FindingCategory.METADATA,
                title="Source code not available for deep analysis",
                description=f"Provide a GitHub URL for full security analysis of '{target}'.",
                recommendation="Run: axiom scan https://github.com/user/mcp-server",
            ))

        end_time = datetime.now(timezone.utc)
        risk_score = self._calculate_risk_score(findings)
        risk_level = self._score_to_level(risk_score)

        # Tag all findings with OWASP ASI references
        for finding in findings:
            if not finding.owasp_asi and finding.category in CATEGORY_TO_ASI:
                finding.owasp_asi = CATEGORY_TO_ASI[finding.category]

        # Tag all findings with OWASP MCP Top 10 references
        apply_owasp_mcp_mapping(findings)

        # Generate OWASP coverage summaries
        owasp_coverage = generate_owasp_coverage(findings)
        owasp_mcp_coverage = generate_owasp_mcp_coverage(findings)

        logger.info(
            "Scan completed",
            extra={
                "target": target,
                "duration": (end_time - start_time).total_seconds(),
                "risk_score": risk_score,
                "finding_count": len(findings),
            },
        )
        clear_scan_id()

        enrich_findings(findings, mode="static", target=local_path or url or target)

        scan_result = {
            "target": target,
            "target_url": url,
            "status": "completed",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "server_profile": server_profile,
            "findings": findings,
            "dependencies": dependencies,
            "repo_health": repo_health,
            "owasp_coverage": owasp_coverage,
            "owasp_mcp_coverage": owasp_mcp_coverage,
            "package_info": package_info,
            "scan_duration_seconds": (end_time - start_time).total_seconds(),
            "surface_map": surface_map,
            "fingerprint": (surface_map or {}).get("fingerprint"),
            "provenance": provenance,
        }

        # Cache result keyed on repo URL + commit SHA
        if url and commit_sha:
            _put_scan_cache(url, commit_sha, scan_result)

        return scan_result

    @staticmethod
    def _run_mcp_top10_detectors(
        scan_dir: str,
        tools: List[MCPToolDefinition],
        resources: List[MCPResourceDefinition],
    ) -> List[Finding]:
        """Run the OWASP MCP Top 10 gap-closing detectors (MCP01/04/05/07/08/10)."""
        findings: List[Finding] = []
        for detector in (
            detect_hardcoded_secrets,      # MCP01
            detect_unpinned_installs,      # MCP04
            detect_tool_input_sinks,       # MCP05
            detect_bind_all_interfaces,    # MCP07
            detect_missing_tool_logging,   # MCP08
            *ALL_BODY_DETECTORS,           # egress URLs, rug-pull, response injection, confused deputy
        ):
            try:
                findings.extend(detector(scan_dir))
            except Exception as e:  # a heuristic must never break a scan
                logger.warning("MCP Top 10 detector failed",
                               extra={"detector": detector.__name__, "error": str(e)})
        try:
            findings.extend(detect_broad_data_exposure(tools, resources))  # MCP10
        except Exception as e:
            logger.warning("MCP Top 10 detector failed",
                           extra={"detector": "detect_broad_data_exposure", "error": str(e)})
        return findings

    # ============================================================
    # MCP Definition Extraction
    # ============================================================

    # Directories to skip during source traversal
    SKIP_DIRS = {
        'node_modules', '.git', '__pycache__', 'venv', '.venv',
        'dist', 'build', 'test', 'tests', '__tests__', 'coverage',
    }

    DEFINITION_EXTENSIONS = {'.py', '.ts', '.tsx', '.js', '.mjs', '.cjs', '.jsx'}

    def _extract_mcp_definitions(self, scan_dir: str) -> tuple:
        """Extract tool, resource, and prompt definitions from MCP server source."""
        tools = []
        resources = []
        prompts = []

        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for fname in files:
                if os.path.splitext(fname)[1] not in self.DEFINITION_EXTENSIONS:
                    continue
                filepath = os.path.join(root, fname)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                if fname.endswith(".py"):
                    # AST path: sees decorator arguments, any docstring style, FastMCP
                    # resources/prompts and add_tool() registrations. Falls back to the
                    # regex extractor only when the file does not parse.
                    extracted = extract_python_definitions(content, filepath)
                    if extracted is not None:
                        tools.extend(extracted.tools)
                        resources.extend(extracted.resources)
                        prompts.extend(extracted.prompts)
                        continue
                    tools.extend(self._extract_python_tools(content))
                else:
                    # tree-sitter path for TS/JS: same record as the Python extractor, so the
                    # Surface Map and every text rule are language-independent. Regex only
                    # when the grammar wheels are missing.
                    extracted = extract_ts_definitions(content, filepath)
                    if extracted is not None:
                        tools.extend(extracted.tools)
                        resources.extend(extracted.resources)
                        prompts.extend(extracted.prompts)
                        continue
                    tools.extend(self._extract_ts_tools(content))
                resources.extend(self._extract_resources(content))
                prompts.extend(self._extract_prompts(content))

        return self._deduplicate_tools(tools), resources, prompts

    @staticmethod
    def _extract_python_tools(content: str) -> List[MCPToolDefinition]:
        """Extract tool definitions from Python MCP server source (decorators)."""
        tools = []
        for pattern in [
            r'@\w+\.tool\(\)\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)[^:]*:\s*\n\s*"""([^"]*?)"""',
            r'@\w+\.call_tool\(\)\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)[^:]*:\s*\n\s*"""([^"]*?)"""',
        ]:
            for m in re.finditer(pattern, content, re.DOTALL):
                tools.append(MCPToolDefinition(
                    name=m.group(1), description=m.group(2).strip(),
                ))
        return tools

    @staticmethod
    def _extract_ts_tools(content: str) -> List[MCPToolDefinition]:
        """Extract tool definitions from TypeScript/JavaScript MCP server source."""
        tools = []
        for pattern in [
            r'{\s*name:\s*["\']([^"\']+)["\'],\s*description:\s*["\']([^"\']*)["\']',
            r'tool\(\s*{\s*name:\s*["\']([^"\']+)["\'],\s*description:\s*[`"\']([^`"\']*)[`"\']',
        ]:
            for m in re.finditer(pattern, content):
                tools.append(MCPToolDefinition(
                    name=m.group(1), description=m.group(2).strip(),
                ))
        return tools

    @staticmethod
    def _extract_resources(content: str) -> List[MCPResourceDefinition]:
        """Extract MCP resource definitions (custom URI schemes)."""
        resources = []
        for m in re.finditer(
            r'["\']([a-z]+://[^"\']+)["\'].*?["\']([^"\']*)["\']', content
        ):
            uri = m.group(1)
            if "://" in uri and not uri.startswith("http"):
                resources.append(MCPResourceDefinition(
                    uri=uri, name=m.group(2) or uri,
                ))
        return resources

    @staticmethod
    def _extract_prompts(content: str) -> List[MCPPromptDefinition]:
        """Extract MCP prompt definitions."""
        prompts = []
        for m in re.finditer(
            r'{\s*name:\s*["\']([^"\']+)["\'],\s*description:\s*["\']([^"\']*)["\'].*?arguments',
            content, re.DOTALL,
        ):
            prompts.append(MCPPromptDefinition(
                name=m.group(1), description=m.group(2).strip(),
            ))
        return prompts

    @staticmethod
    def _deduplicate_tools(tools: List[MCPToolDefinition]) -> List[MCPToolDefinition]:
        """Remove duplicate tool definitions by name."""
        seen = set()
        unique = []
        for t in tools:
            if t.name not in seen:
                seen.add(t.name)
                unique.append(t)
        return unique

    # ============================================================
    # MCP-Specific Code Scanning
    # ============================================================

    def _scan_mcp_code(self, scan_dir: str) -> List[Finding]:
        """Scan source for MCP-specific suspicious patterns.

        Uses AST parsing for Python files (accurate, handles comments/strings)
        and regex patterns for JS/TS files.
        """
        findings = []
        counter = 0
        scan_extensions = {'.py', '.ts', '.js', '.mjs', '.cjs', '.jsx', '.tsx'}
        regex_only_extensions = {'.ts', '.js', '.mjs', '.cjs', '.jsx', '.tsx'}

        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext not in scan_extensions:
                    continue

                filepath = os.path.join(root, fname)
                rel_path = os.path.relpath(filepath, scan_dir)

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                # Python files: use AST scanner for accurate detection
                if ext == '.py':
                    ast_findings = scan_python_ast(content, rel_path)
                    findings.extend(ast_findings)
                    # Skip regex for Python — AST is more accurate
                    continue

                # JS/TS files: use regex patterns
                lines = content.splitlines()
                for line_num, line in enumerate(lines, 1):
                    for category_name, pattern_info in MCP_CODE_PATTERNS.items():
                        for pattern in pattern_info["patterns"]:
                            if re.search(pattern, line):
                                counter += 1
                                findings.append(Finding(
                                    id=f"code_{counter:04d}",
                                    severity=pattern_info["severity"],
                                    category=pattern_info["category"],
                                    title=pattern_info["description"],
                                    description=f"Pattern matched in {rel_path} at line {line_num}: "
                                                f"`{line.strip()[:120]}`",
                                    file_path=rel_path,
                                    line_number=line_num,
                                    recommendation=f"Review this {category_name.replace('_', ' ')} pattern.",
                                ))
                                break  # One finding per line per category

        return findings

    # ============================================================
    # Manifest Analysis
    # ============================================================

    def _analyze_manifests(self, scan_dir: str) -> List[Finding]:
        """Analyze package manifests for lifecycle hooks and suspicious config."""
        findings = []

        # package.json
        pkg_path = os.path.join(scan_dir, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8-sig", errors="replace") as f:
                    pkg = json.load(f)

                # Check lifecycle scripts
                scripts = pkg.get("scripts", {})
                for hook in ["preinstall", "postinstall", "preuninstall", "prepublish"]:
                    if hook in scripts:
                        findings.append(Finding(
                            id=f"manifest_{hook}",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.SUPPLY_CHAIN,
                            title=f"npm lifecycle hook: {hook}",
                            description=f"Package has '{hook}' script: `{scripts[hook][:200]}`. "
                                        "Lifecycle scripts execute automatically during npm install "
                                        "and are a primary supply chain attack vector.",
                            file_path="package.json",
                            recommendation="Review this script before installing. "
                                           "Consider using --ignore-scripts flag.",
                        ))

                # Check for suspicious bin entries
                bins = pkg.get("bin", {})
                if isinstance(bins, dict):
                    for bin_name, bin_path in bins.items():
                        if ".." in bin_path:
                            findings.append(Finding(
                                id=f"manifest_bin_{bin_name}",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.SANDBOX_ESCAPE,
                                title=f"Suspicious bin path traversal: {bin_name}",
                                description=f"Binary '{bin_name}' points to '{bin_path}' which contains path traversal.",
                                file_path="package.json",
                                recommendation="This could be an attempt to escape the package directory.",
                            ))

            except (json.JSONDecodeError, IOError):
                pass

        # pyproject.toml entry points
        pyproject_path = os.path.join(scan_dir, "pyproject.toml")
        if os.path.exists(pyproject_path):
            try:
                with open(pyproject_path, "r", encoding="utf-8-sig", errors="replace") as f:
                    content = f.read()
                if "[tool.setuptools.cmdclass]" in content:
                    findings.append(Finding(
                        id="manifest_py_cmdclass",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.SUPPLY_CHAIN,
                        title="Custom setuptools cmdclass detected",
                        description="Custom install commands can execute arbitrary code during pip install.",
                        file_path="pyproject.toml",
                        recommendation="Review setup.py/pyproject.toml for malicious install hooks.",
                    ))
            except IOError:
                pass

        return findings

    # ============================================================
    # Transport Security
    # ============================================================

    def _analyze_transport(self, scan_dir: str, profile: MCPServerProfile) -> List[Finding]:
        """Analyze MCP transport security configuration."""
        findings = []
        seen_no_auth = False
        seen_plain_http = False

        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in {'node_modules', '.git', '__pycache__'}]
            for fname in files:
                if os.path.splitext(fname)[1] not in {'.py', '.ts', '.js', '.json'}:
                    continue
                filepath = os.path.join(root, fname)
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                rel_path = os.path.relpath(filepath, scan_dir)

                # Detect transport type
                if "StdioServerTransport" in content or "stdio_server" in content:
                    profile.transport = TransportType.STDIO
                elif "SSEServerTransport" in content or "sse_server" in content:
                    profile.transport = TransportType.SSE
                elif "StreamableHTTPServerTransport" in content:
                    profile.transport = TransportType.HTTP

                # Check for session ID in URL (protocol design issue)
                if re.search(r'sessionId.*req\.(url|query|params)', content):
                    findings.append(Finding(
                        id="transport_session_url",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.TRANSPORT_SECURITY,
                        title="Session ID exposed in URL parameters",
                        description="Session identifiers in URLs are logged in server logs and "
                                    "browser history, enabling session hijacking.",
                        file_path=rel_path,
                        recommendation="Use session IDs in headers or cookies, not URL parameters.",
                    ))

                # Missing auth on HTTP/SSE endpoints. Static source cannot say where the
                # server will run, so this is a LOW note (docs/SEVERITY.md), once per scan,
                # on the file that defines the transport — not on every file that lacks the
                # word "auth".
                if (profile.transport in (TransportType.SSE, TransportType.HTTP)
                        and not seen_no_auth
                        and re.search(r"(SSEServerTransport|StreamableHTTPServerTransport|sse_server|streamable_http_app|sse_app)", content)
                        and not re.search(r'(auth|bearer|token|jwt|oauth)', content, re.IGNORECASE)):
                    seen_no_auth = True
                    sev, why = transport_severity(None)
                    findings.append(Finding(
                        id="transport_no_auth",
                        severity=sev,
                        category=FindingCategory.TRANSPORT_SECURITY,
                        title="HTTP/SSE transport defined without visible authentication",
                        description=f"{rel_path} sets up an HTTP/SSE transport and no authentication "
                                    f"middleware is visible; {why}.",
                        file_path=rel_path,
                        recommendation="Require OAuth 2.1 / bearer authentication on any endpoint that is not bound to localhost.",
                    ))

                # Plain HTTP: severity by the host in the URL (loopback INFO, private LOW, public HIGH)
                m_http = re.search(r'http://(0\.0\.0\.0|localhost|127\.0\.0\.1|\*)(:\d+)?', content)
                if m_http and "test" not in rel_path.lower() and not seen_plain_http \
                        and re.search(r"(?i)(uvicorn|listen|bind|host\s*=|serve\(|createServer|app\.run|run\(transport)", content):
                    host = m_http.group(1)
                    if True:
                        seen_plain_http = True
                        sev, why = transport_severity(None if host in ("0.0.0.0", "*") else host)
                        if host in ("0.0.0.0", "*"):
                            sev = FindingSeverity.LOW
                        findings.append(Finding(
                            id="transport_plain_http",
                            severity=sev,
                            category=FindingCategory.TRANSPORT_SECURITY,
                            title="MCP server listens on plain HTTP",
                            description=f"{rel_path} binds or references http://{host}; {why}.",
                            file_path=rel_path,
                            recommendation="Use HTTPS with valid TLS certificates for anything reachable beyond this machine.",
                        ))

        return findings

    # ============================================================
    # Dependencies
    # ============================================================

    def _extract_dependencies(self, scan_dir: str) -> List[DependencyInfo]:
        """Direct dependencies from manifests, exact versions and transitives from lockfiles
        (app/analysis/dependencies.py)."""
        return _extract_deps(scan_dir)

    async def _check_known_vulnerable(self, deps: List[DependencyInfo], check_osv: bool = True) -> List[Finding]:
        """Check dependencies against the known-malicious package list and OSV."""
        findings = []

        for dep in deps:
            # Packages listed as malicious: any version is reported. Vulnerable versions of
            # legitimate packages are matched by version in _check_known_cves.
            if dep.name in KNOWN_VULNERABLE_PACKAGES:
                vuln_info = KNOWN_VULNERABLE_PACKAGES[dep.name]
                findings.append(Finding(
                    id=f"dep_known_{dep.name}",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.KNOWN_CVE,
                    title=f"Known malicious MCP package: {dep.name}",
                    description=f"Package '{dep.name}' is on the known-malicious package list. "
                                f"{vuln_info.get('note', '')}",
                    cve_id=vuln_info.get("cve"),
                    recommendation=vuln_info.get("recommendation") or f"Remove {dep.name}.",
                ))
                dep.has_vulnerabilities = True
                dep.vulnerability_count += 1

        # OSV.dev, version-aware, cached 24 h (docs/SEVERITY.md: advisories are a signal,
        # not the headline). --no-deps skips it.
        if check_osv and deps:
            findings.extend(await osv_findings(deps, settings.OSV_API_URL))

        return findings

    @staticmethod
    def _drop_osv_twins(findings: List[Finding], cve_findings: List[Finding]) -> List[Finding]:
        """OSV reports the same advisory under its GHSA id. When the built-in list has
        reported a CVE, the OSV finding for that advisory is dropped so it is counted once."""
        twins = {alias for f in cve_findings if f.severity != FindingSeverity.INFO
                 for alias in advisory_aliases(f.cve_id or "")}
        return [f for f in findings if f.id not in twins] if twins else findings

    def _check_known_cves(self, target: str, deps: List[DependencyInfo],
                          target_version: Optional[str] = None,
                          target_ecosystem: Optional[str] = None) -> List[Finding]:
        """Match dependencies (and a scanned package itself) against the published MCP CVE list.

        Version-aware: a finding only when the exact version (the lockfile's, or a version
        pinned exactly in the manifest) is inside the affected range, at the advisory's
        severity for a direct dependency and one level lower for a transitive one; nothing
        when it is outside; one INFO note when there is no exact version (a range without a
        lockfile, or no version at all).
        """
        findings: List[Finding] = []
        seen = set()

        # (package name, ecosystem, exact version or None, how it was found, direct, dependency)
        candidates = [(d.name, d.ecosystem, exact_version(d), d.source or "dependency", d.direct, d)
                      for d in deps]
        if target and target_ecosystem:
            candidates.append((target, target_ecosystem, target_version, "scan target", True, None))

        for name, ecosystem, version, where, direct, dep in candidates:
            for cve_id, info in cves_for_package(name, ecosystem):
                affected = version_affected(version, info["affected"])
                if affected is False:
                    continue
                if affected is None:
                    key = (cve_id, name, None)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        id=f"{cve_id}_unversioned",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.KNOWN_CVE,
                        title=f"{cve_id} affects some versions of {name} (version not pinned)",
                        description=f"{info['description']} '{name}' is declared without an exact version "
                                    f"({where}), so this cannot be matched against what is installed. "
                                    f"Fixed in {info['fixed']}. Source: {info['reference']}",
                        cve_id=cve_id,
                        recommendation=f"Pin {name} to an exact version at or above {info['fixed']} "
                                       "and commit the lockfile.",
                        owasp_asi=["ASI04"],
                        rule_id="known_mcp_cve_unpinned",
                    ))
                    continue
                key = (cve_id, name, version)
                if key in seen:
                    continue
                seen.add(key)
                severity = FindingSeverity.CRITICAL if info["severity"] == "critical" else FindingSeverity.HIGH
                if not direct:   # docs/SEVERITY.md: never CRITICAL for a transitive package
                    severity = FindingSeverity.HIGH if severity == FindingSeverity.CRITICAL else FindingSeverity.MEDIUM
                if dep is not None:
                    dep.has_vulnerabilities = True
                    dep.vulnerability_count += 1
                    if cve_id not in dep.vulns:
                        dep.vulns.append(cve_id)
                findings.append(Finding(
                    id=cve_id,
                    severity=severity,
                    category=FindingCategory.KNOWN_CVE,
                    title=f"{cve_id}: {info['title']} ({name}@{version})",
                    description=f"{info['description']} Fixed in {info['fixed']}. "
                                + ("" if direct else "Found as a transitive dependency in the lockfile. ")
                                + f"Source: {info['reference']}",
                    cve_id=cve_id,
                    recommendation=info["recommendation"],
                    owasp_asi=["ASI04"],
                    rule_id="known_mcp_cve",
                ))

        return findings

    # ============================================================
    # Repository Health
    # ============================================================

    async def _get_repo_health(self, repo_url: str) -> Optional[RepoHealth]:
        """Get GitHub repository health signals."""
        try:
            import httpx
            # Extract owner/repo from URL
            match = re.search(r'github\.com/([^/]+)/([^/\s]+)', repo_url)
            if not match:
                return None

            owner, repo = match.group(1), match.group(2).rstrip('.git')
            headers = {}
            if settings.GITHUB_TOKEN:
                headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}",
                    headers=headers,
                    timeout=10.0,
                )
                if resp.status_code != 200:
                    return None

                data = resp.json()
                now = datetime.now(timezone.utc)

                created = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
                pushed = datetime.fromisoformat(data["pushed_at"].replace("Z", "+00:00"))

                return RepoHealth(
                    stars=data.get("stargazers_count", 0),
                    forks=data.get("forks_count", 0),
                    open_issues=data.get("open_issues_count", 0),
                    last_commit_days_ago=(now - pushed).days,
                    created_days_ago=(now - created).days,
                    has_security_policy=data.get("security_and_analysis") is not None,
                    license=data.get("license", {}).get("spdx_id") if data.get("license") else None,
                    is_archived=data.get("archived", False),
                    is_fork=data.get("fork", False),
                    contributor_count=data.get("subscribers_count", 0),
                )
        except Exception:
            return None

    # ============================================================
    # Utilities
    # ============================================================

    async def _check_repo_size(self, repo_url: str) -> Optional[int]:
        """Check repository size via GitHub API before cloning. Returns size in MB or None."""
        try:
            import httpx
            match = re.search(r'github\.com/([^/]+)/([^/\s]+)', repo_url)
            if not match:
                return None  # Not a GitHub URL, skip size check

            owner, repo = match.group(1), match.group(2).rstrip('.git')
            headers = {}
            if settings.GITHUB_TOKEN:
                headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}",
                    headers=headers,
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    # GitHub API returns size in KB
                    size_kb = resp.json().get("size", 0)
                    return size_kb // 1024
        except Exception:
            pass
        return None

    async def _clone_repo(self, repo_url: str) -> Optional[str]:
        """Clone a git repository (shallow) after checking size limits."""
        # Pre-flight size check to prevent DoS via large repos
        repo_size_mb = await self._check_repo_size(repo_url)
        if repo_size_mb is not None:
            logger.info(
                "Repo size checked",
                extra={"repo_url": repo_url, "repo_size_mb": repo_size_mb},
            )
        if repo_size_mb is not None and repo_size_mb > settings.MAX_REPO_SIZE_MB:
            raise ValueError(
                f"Repository is ~{repo_size_mb}MB, exceeding the "
                f"{settings.MAX_REPO_SIZE_MB}MB limit. Increase MAX_REPO_SIZE_MB "
                f"to scan larger repositories."
            )

        try:
            dest = tempfile.mkdtemp(dir=self.temp_dir)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", repo_url, dest],
                capture_output=True, text=True,
                timeout=settings.SCAN_TIMEOUT_SECONDS,
            )
            return dest if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    @staticmethod
    def _get_commit_sha(repo_dir: str) -> Optional[str]:
        """Get the HEAD commit SHA from a cloned repo directory."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, cwd=repo_dir, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """docs/SEVERITY.md: the worst finding sets the band; breadth adds inside it."""
        return _policy_score(findings)

    def _score_to_level(self, score: float) -> RiskLevel:
        return _policy_level(score)

    def _score_to_level_legacy(self, score: float) -> RiskLevel:
        if score >= 75:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 25:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.SAFE


engine = MCPAnalysisEngine()
