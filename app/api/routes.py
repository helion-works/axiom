"""Axiom API Routes — MCP-specific security scanning endpoints."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.models.schemas import (
    ScanRequest, ScanResponse, ScanListResponse,
    LocalConfigScanRequest, LocalConfigScanResponse,
    Finding, FindingSeverity, FindingCategory,
)
from app.analysis.engine import engine
from app.analysis.ai_analysis import generate_mcp_ai_analysis
from app.analysis.local_config import local_scanner
from app.analysis.live_scanner import live_scanner
from app.analysis.owasp_mapping import apply_owasp_mappings
from app.utils.database import save_scan, get_scan, list_scans
from app.utils.config import host_access_allowed


def require_host_access() -> None:
    """Hide endpoints that act on the API host's machine in production."""
    if not host_access_allowed():
        raise HTTPException(status_code=404, detail="Not found")

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(tags=["MCP Security"])


@router.post("/scan", response_model=ScanResponse)
@limiter.limit("10/minute")
async def scan_mcp_server(body: ScanRequest, request: Request):
    """Scan an MCP server for security issues."""
    try:
        result = await engine.scan(body.target, body.target_url)

        # AI analysis
        ai_sections = await generate_mcp_ai_analysis(
            target=body.target,
            findings=result["findings"],
            server_profile=result["server_profile"],
        )

        # Warn in findings if AI analysis was unavailable
        findings_dicts = [f.model_dump() for f in result["findings"]]
        ai_text = ai_sections.get("ai_analysis") or ""
        if "unavailable" in ai_text.lower() or "install anthropic" in ai_text.lower():
            findings_dicts.append(Finding(
                id="ai_unavailable",
                severity=FindingSeverity.INFO,
                category=FindingCategory.METADATA,
                title="AI-powered analysis was not performed",
                description=(
                    "Claude AI analysis (claimed-vs-actual, tool poisoning risk, "
                    "prompt injection assessment) was skipped. Set ANTHROPIC_API_KEY "
                    "in your .env file to enable deeper analysis."
                ),
                recommendation="Run: export ANTHROPIC_API_KEY=your-key-here",
            ).model_dump())

        # Build response
        scan_data = {
            "target": result["target"],
            "target_url": result["target_url"],
            "status": result["status"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"].value,
            "server_profile": result["server_profile"].model_dump() if result["server_profile"] else None,
            "findings": findings_dicts,
            "dependencies": [d.model_dump() for d in result["dependencies"]],
            "repo_health": result["repo_health"].model_dump() if result["repo_health"] else None,
            "ai_analysis": ai_sections.get("ai_analysis"),
            "tool_poisoning_report": ai_sections.get("tool_poisoning_report"),
            "prompt_injection_risk": ai_sections.get("prompt_injection_risk"),
            "claimed_vs_actual": ai_sections.get("claimed_vs_actual"),
            "scan_duration_seconds": result.get("scan_duration_seconds"),
            "owasp_coverage": result.get("owasp_coverage"),
            "owasp_mcp_coverage": result.get("owasp_mcp_coverage"),
        }

        scan_id = await save_scan(scan_data)
        scan_data["id"] = scan_id

        return ScanResponse(**scan_data)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_result(scan_id: str):
    """Get a specific scan result."""
    result = await get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(**result)


@router.get("/scans", response_model=ScanListResponse)
async def list_scan_results(limit: int = 50):
    """List recent scan results."""
    results = await list_scans(limit=limit)
    return ScanListResponse(
        scans=[ScanResponse(**r) for r in results],
        total=len(results),
    )


@router.post("/scan/local", response_model=LocalConfigScanResponse, dependencies=[Depends(require_host_access)])
@limiter.limit("20/minute")
async def scan_local_configs(request: Request, body: LocalConfigScanRequest = LocalConfigScanRequest()):
    """Scan local MCP configuration files for security issues."""
    try:
        result = local_scanner.scan_all(body.config_paths or None)
        apply_owasp_mappings(result["findings"])
        return LocalConfigScanResponse(
            config_files_found=result["config_files_found"],
            servers_discovered=[e.model_dump() for e in result["servers_discovered"]],
            findings=[f.model_dump() for f in result["findings"]],
            total_servers=result["total_servers"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Local scan failed: {str(e)}")


@router.get("/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Get formatted report."""
    result = await get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = result.get("findings", [])
    return {
        "scan_id": scan_id,
        "target": result["target"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
            "by_category": {},
        },
        "tool_count": len(result.get("server_profile", {}).get("tools", [])) if result.get("server_profile") else 0,
        "ai_analysis": result.get("ai_analysis"),
        "tool_poisoning_report": result.get("tool_poisoning_report"),
        "prompt_injection_risk": result.get("prompt_injection_risk"),
        "claimed_vs_actual": result.get("claimed_vs_actual"),
    }


# ============================================================
# Live Scanning Endpoints
# ============================================================

class LiveScanStdioRequest(BaseModel):
    """Request to live-scan an MCP server via stdio."""
    command: str = Field(..., description="Command to spawn the server (e.g., 'npx', 'python')")
    args: List[str] = Field(default=[], description="Command arguments")
    env: dict = Field(default={}, description="Environment variables")
    server_name: Optional[str] = Field(None, description="Display name")
    compare_url: Optional[str] = Field(None, description="GitHub URL to diff source vs runtime")

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "server_name": "filesystem",
                },
            ]
        }


class LiveScanSSERequest(BaseModel):
    """Request to live-scan an MCP server via SSE."""
    url: str = Field(..., description="SSE endpoint URL")
    server_name: Optional[str] = Field(None, description="Display name")


@router.post("/scan/live/stdio", dependencies=[Depends(require_host_access)])
@limiter.limit("5/minute")
async def live_scan_stdio(body: LiveScanStdioRequest, request: Request):
    """Live-connect to an MCP server via stdio and scan runtime tools."""
    try:
        source_tools = None
        if body.compare_url:
            source_result = await engine.scan(
                body.server_name or body.command, body.compare_url
            )
            source_profile = source_result.get("server_profile")
            if source_profile:
                source_tools = source_profile.tools

        result = await live_scanner.scan_stdio(
            command=body.command,
            args=body.args,
            env=body.env,
            server_name=body.server_name,
            source_tools=source_tools,
        )
        return result.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Live scan failed: {str(e)}")


@router.post("/scan/live/sse", dependencies=[Depends(require_host_access)])
@limiter.limit("5/minute")
async def live_scan_sse(body: LiveScanSSERequest, request: Request):
    """Live-connect to an MCP server via SSE and scan runtime tools."""
    try:
        result = await live_scanner.scan_sse(
            url=body.url,
            server_name=body.server_name,
        )
        return result.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Live SSE scan failed: {str(e)}")


@router.post("/scan/live/local", dependencies=[Depends(require_host_access)])
@limiter.limit("5/minute")
async def live_scan_local(request: Request, server_name: Optional[str] = None):
    """Live-scan all locally configured MCP servers."""
    try:
        results = await live_scanner.scan_all_local(server_filter=server_name)
        return {
            "servers_scanned": len(results),
            "results": [r.to_dict() for r in results],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Live local scan failed: {str(e)}")


# ============================================================
# Shadow MCP Discovery (Workstream B)
# ============================================================

from app.analysis.discovery import DiscoveryResult, discover_servers  # noqa: E402


class DiscoverRequest(BaseModel):
    """Request to inventory MCP servers from MCP client config files on the API host."""
    config_paths: List[str] = Field(
        default=[],
        description="Config files to read. If empty, the known client locations on the API host are read.",
    )
    allowlist: Optional[dict] = Field(
        None, description="Inline allowlist: {\"version\": 1, \"servers\": [{\"name\", \"package\", \"version\", \"url\"}]}",
    )
    include_processes: bool = Field(
        False, description="Also enumerate running MCP-like processes on the API host (opt-in).",
    )


@router.post("/discover", response_model=DiscoveryResult, dependencies=[Depends(require_host_access)])
@limiter.limit("10/minute")
async def discover_mcp_servers(request: Request, body: DiscoverRequest = DiscoverRequest()):
    """Inventory configured MCP servers and classify them against an optional allowlist.

    Secrets are never returned: env var values are not read and credential-like
    arguments/URL parts are redacted. Process enumeration only runs when
    include_processes is explicitly true.
    """
    try:
        return discover_servers(
            custom_paths=body.config_paths or None,
            include_processes=bool(body.include_processes),
            allowlist=body.allowlist,
            include_defaults=not body.config_paths,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid allowlist: {type(e).__name__}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Discovery failed: {type(e).__name__}")


# ============================================================
# A2A Agent Card Scanning (Workstream D)
# ============================================================

from starlette.concurrency import run_in_threadpool  # noqa: E402

from app.analysis.a2a_scanner import A2AScanError, scan_agent_card  # noqa: E402
from app.models.schemas import A2AScanRequest, A2AScanResult  # noqa: E402
from app.utils.safe_fetch import SafeFetchError, UnsafeURLError  # noqa: E402


@router.post("/a2a", response_model=A2AScanResult)
@limiter.limit("10/minute")
async def scan_a2a_agent(body: A2AScanRequest, request: Request):
    """Statically scan a remote A2A agent card (passive: card, optional JWKS, optional extended-card GET).

    Only http(s) URLs are accepted (no file paths) and private, loopback, link-local
    and metadata addresses are always refused. Only scan agents you own or are
    authorised to assess.
    """
    source = (body.source or "").strip()
    if not source.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="source must be an http(s) URL")
    try:
        return await run_in_threadpool(scan_agent_card, source, False)
    except UnsafeURLError as e:
        raise HTTPException(status_code=400, detail=f"Refused: {e}")
    except (A2AScanError, SafeFetchError) as e:
        raise HTTPException(status_code=422, detail=f"No usable agent card: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"A2A scan failed: {type(e).__name__}")


# ============================================================
# Threat Model Generation (Workstream C)
# ============================================================

import hashlib as _tm_hashlib  # noqa: E402
import re as _tm_re  # noqa: E402
from collections import OrderedDict as _TMOrderedDict  # noqa: E402

from fastapi.responses import Response as _TMResponse  # noqa: E402
from starlette.concurrency import run_in_threadpool as _tm_run_in_threadpool  # noqa: E402

from app.analysis.threat_model import (  # noqa: E402
    build_threat_model,
    render_json as _tm_render_json,
    render_markdown as _tm_render_markdown,
)

# Generated threat models are kept in a small in-memory LRU (no DB schema change),
# keyed by a content hash, so the Markdown report can be downloaded afterwards.
_THREATMODEL_CACHE_MAX = 100
_threatmodel_cache: "_TMOrderedDict[str, dict]" = _TMOrderedDict()
_TM_ID_RE = _tm_re.compile(r"^[0-9a-f]{16}$")


class ThreatModelRequest(BaseModel):
    """Build a threat model from any combination of sources (at least one)."""
    scan: Optional[dict] = Field(None, description="A scan result (ScanResponse JSON or `axiom scan -o json`).")
    scan_id: Optional[str] = Field(None, description="Id of a stored scan (POST /scan) to use as a source.")
    discovery: Optional[dict] = Field(None, description="A DiscoveryResult (POST /discover or `axiom discover -f json`).")
    a2a: Optional[dict] = Field(None, description="An A2AScanResult (POST /a2a), a raw agent card, or the duck-typed A2A dict.")
    ai: bool = Field(False, description="Add AI-suggested threats (needs ANTHROPIC_API_KEY; sends only the sanitised system model).")


def _tm_store(result: dict) -> str:
    tm_id = _tm_hashlib.sha256(_tm_render_json(result).encode("utf-8")).hexdigest()[:16]
    _threatmodel_cache[tm_id] = result
    _threatmodel_cache.move_to_end(tm_id)
    while len(_threatmodel_cache) > _THREATMODEL_CACHE_MAX:
        _threatmodel_cache.popitem(last=False)
    return tm_id


def _tm_get(tm_id: str) -> dict:
    result = _threatmodel_cache.get(tm_id) if _TM_ID_RE.match(tm_id or "") else None
    if result is None:
        raise HTTPException(status_code=404, detail="Threat model not found (it may have expired)")
    _threatmodel_cache.move_to_end(tm_id)
    return result


@router.post("/threatmodel")
@limiter.limit("10/minute")
async def generate_threat_model(body: ThreatModelRequest, request: Request):
    """Generate a deterministic threat model (STRIDE, CSA MAESTRO, OWASP ASI/MCP tags).

    Returns the full JSON (system model, threats, attack paths, coverage, AI section)
    plus an ``id``; the Markdown report is at GET /threatmodel/{id}/report.md.
    """
    scans = []
    if body.scan:
        scans.append(body.scan)
    if body.scan_id:
        stored = await get_scan(body.scan_id)
        if not stored:
            raise HTTPException(status_code=404, detail="Scan not found")
        scans.append(stored)
    discovery = [body.discovery] if body.discovery else []
    a2a = [body.a2a] if body.a2a else []
    if not (scans or discovery or a2a):
        raise HTTPException(status_code=400, detail="Provide at least one of scan, scan_id, discovery or a2a")
    try:
        result = await _tm_run_in_threadpool(build_threat_model, scans, discovery, a2a, ai=bool(body.ai))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid source: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat model failed: {type(e).__name__}")
    tm_id = _tm_store(result)
    return {"id": tm_id, "report_md_url": f"/api/v1/threatmodel/{tm_id}/report.md", **result}


@router.get("/threatmodel/{tm_id}")
@limiter.limit("30/minute")
async def get_threat_model(tm_id: str, request: Request):
    """Return a previously generated threat model as JSON."""
    return {"id": tm_id, **_tm_get(tm_id)}


@router.get("/threatmodel/{tm_id}/report.md")
@limiter.limit("30/minute")
async def download_threat_model_markdown(tm_id: str, request: Request, framework: str = "both"):
    """Download a previously generated threat model as a Markdown file."""
    result = _tm_get(tm_id)
    try:
        md = _tm_render_markdown(result, framework)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _TMResponse(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="threatmodel-{tm_id}.md"'},
    )
