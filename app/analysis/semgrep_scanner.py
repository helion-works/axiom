"""
Semgrep integration for Axiom.

Runs Semgrep with MCP-specific security rules when the `semgrep` binary is
available on PATH. Falls back gracefully (returns empty list) when Semgrep
is not installed.

Semgrep provides language-aware pattern matching that is more accurate than
regex for JavaScript/TypeScript and catches patterns across multiple lines,
nested structures, and complex control flow.
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import List

from app.models.schemas import Finding, FindingSeverity, FindingCategory
from app.utils.logging import get_logger

logger = get_logger("semgrep")

# Semgrep rules written in YAML, embedded so no external files needed
MCP_SEMGREP_RULES = """
rules:
  - id: mcp-eval-exec
    patterns:
      - pattern-either:
          - pattern: eval(...)
          - pattern: exec(...)
          - pattern: Function(...)
    message: "Dynamic code execution detected — potential arbitrary code execution"
    languages: [javascript, typescript, python]
    severity: ERROR
    metadata:
      category: code_execution
      mcpguard_severity: critical

  - id: mcp-shell-injection
    patterns:
      - pattern-either:
          - pattern: child_process.exec($CMD)
          - pattern: child_process.execSync($CMD)
          - pattern: subprocess.run($CMD, ..., shell=True, ...)
          - pattern: subprocess.call($CMD, ..., shell=True, ...)
          - pattern: os.system($CMD)
          - pattern: os.popen($CMD)
    message: "Shell command execution — potential command injection"
    languages: [javascript, typescript, python]
    severity: ERROR
    metadata:
      category: command_injection
      mcpguard_severity: critical

  - id: mcp-outbound-request
    patterns:
      - pattern-either:
          - pattern: fetch($URL, ...)
          - pattern: axios.post($URL, ...)
          - pattern: axios.get($URL, ...)
          - pattern: requests.post($URL, ...)
          - pattern: requests.get($URL, ...)
          - pattern: httpx.post($URL, ...)
          - pattern: httpx.get($URL, ...)
    message: "Outbound HTTP request — potential data exfiltration vector"
    languages: [javascript, typescript, python]
    severity: WARNING
    metadata:
      category: data_exfiltration
      mcpguard_severity: high

  - id: mcp-env-access
    patterns:
      - pattern-either:
          - pattern: process.env[$KEY]
          - pattern: process.env.$KEY
          - pattern: os.environ[$KEY]
          - pattern: os.environ.get($KEY)
          - pattern: os.getenv($KEY)
    message: "Environment variable access — may read credentials or secrets"
    languages: [javascript, typescript, python]
    severity: WARNING
    metadata:
      category: credential_theft
      mcpguard_severity: high

  - id: mcp-base64-decode
    patterns:
      - pattern-either:
          - pattern: atob(...)
          - pattern: Buffer.from($DATA, "base64")
          - pattern: base64.b64decode(...)
    message: "Base64 decoding — may be used to hide malicious payloads"
    languages: [javascript, typescript, python]
    severity: WARNING
    metadata:
      category: obfuscation
      mcpguard_severity: high

  - id: mcp-path-traversal
    patterns:
      - pattern-either:
          - pattern: |
              "../../$...REST"
          - pattern: path.join($BASE, "..", ...)
          - pattern: os.path.join($BASE, "..", ...)
    message: "Path traversal pattern — potential sandbox escape"
    languages: [javascript, typescript, python]
    severity: ERROR
    metadata:
      category: sandbox_escape
      mcpguard_severity: critical

  - id: mcp-symlink-creation
    patterns:
      - pattern-either:
          - pattern: os.symlink(...)
          - pattern: fs.symlinkSync(...)
          - pattern: fs.symlink(...)
    message: "Symlink creation — potential sandbox escape"
    languages: [javascript, typescript, python]
    severity: ERROR
    metadata:
      category: sandbox_escape
      mcpguard_severity: critical
"""

SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
}

CATEGORY_MAP = {
    "code_execution": FindingCategory.CODE_EXECUTION,
    "command_injection": FindingCategory.COMMAND_INJECTION,
    "data_exfiltration": FindingCategory.DATA_EXFILTRATION,
    "credential_theft": FindingCategory.CREDENTIAL_THEFT,
    "obfuscation": FindingCategory.OBFUSCATION,
    "sandbox_escape": FindingCategory.SANDBOX_ESCAPE,
}


def is_semgrep_available() -> bool:
    """Check if the semgrep binary is available on PATH."""
    return shutil.which("semgrep") is not None


def run_semgrep(scan_dir: str, timeout: int = 120) -> List[Finding]:
    """Run Semgrep on a directory with MCP-specific rules.

    Returns findings list. Returns empty list if Semgrep is not installed
    or if the scan fails.
    """
    if not is_semgrep_available():
        logger.info("Semgrep not installed — skipping Semgrep analysis")
        return []

    rules_file = None
    try:
        # Write rules to a temp file
        rules_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, prefix="mcpguard_semgrep_",
        )
        rules_file.write(MCP_SEMGREP_RULES)
        rules_file.close()

        logger.info("Running Semgrep scan", extra={"target": scan_dir})

        result = subprocess.run(
            [
                "semgrep", "scan",
                "--config", rules_file.name,
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--max-target-bytes", "1000000",
                scan_dir,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode not in (0, 1):
            # 0 = no findings, 1 = findings found, other = error
            logger.warning(f"Semgrep returned exit code {result.returncode}")
            if result.stderr:
                logger.warning(f"Semgrep stderr: {result.stderr[:500]}")
            return []

        output = json.loads(result.stdout) if result.stdout else {}
        return _parse_semgrep_results(output, scan_dir)

    except subprocess.TimeoutExpired:
        logger.warning(f"Semgrep timed out after {timeout}s")
        return []
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Failed to parse Semgrep output: {e}")
        return []
    except Exception as e:
        logger.warning(f"Semgrep scan failed: {e}")
        return []
    finally:
        if rules_file and os.path.exists(rules_file.name):
            os.unlink(rules_file.name)


def _parse_semgrep_results(output: dict, scan_dir: str) -> List[Finding]:
    """Convert Semgrep JSON output to Axiom Finding objects."""
    findings = []
    results = output.get("results", [])

    for i, r in enumerate(results):
        rule_id = r.get("check_id", "unknown")
        metadata = r.get("extra", {}).get("metadata", {})
        msg = r.get("extra", {}).get("message", rule_id)

        mcpguard_sev = metadata.get("mcpguard_severity", "medium")
        severity = SEVERITY_MAP.get(mcpguard_sev, FindingSeverity.MEDIUM)

        mcpguard_cat = metadata.get("category", "code_execution")
        category = CATEGORY_MAP.get(mcpguard_cat, FindingCategory.CODE_EXECUTION)

        filepath = r.get("path", "")
        rel_path = os.path.relpath(filepath, scan_dir) if filepath else ""
        line = r.get("start", {}).get("line", 0)
        matched = r.get("extra", {}).get("lines", "").strip()[:120]

        findings.append(Finding(
            id=f"semgrep_{i:04d}_{rule_id}",
            severity=severity,
            category=category,
            title=f"[Semgrep] {msg}",
            description=(
                f"Semgrep rule `{rule_id}` matched in {rel_path} at line {line}"
                + (f": `{matched}`" if matched else "")
            ),
            file_path=rel_path,
            line_number=line,
            recommendation=f"Review this code. Detected by Semgrep rule: {rule_id}",
        ))

    logger.info(
        f"Semgrep scan complete: {len(findings)} findings",
        extra={"finding_count": len(findings)},
    )
    return findings
