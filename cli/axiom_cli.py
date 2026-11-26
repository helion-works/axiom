#!/usr/bin/env python3
"""
Axiom CLI — MCP Server Security Scanner

Usage:
    axiom scan https://github.com/user/my-mcp-server
    axiom scan my-server --url https://github.com/user/my-mcp-server
    axiom local                  # Scan all local MCP configs
    axiom local --path ~/.cursor/mcp.json
"""

import asyncio
import contextlib
import json
import sys
import os
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _utf8_streams() -> None:
    """Make stdout/stderr UTF-8 so emoji and box-drawing never crash a cp1252 console."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream and (stream.encoding or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


_utf8_streams()

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from app.analysis.engine import engine
from app.analysis.ai_analysis import generate_mcp_ai_analysis
from app.analysis.local_config import local_scanner
from app.analysis.live_scanner import live_scanner, LiveScanResult
from app.analysis.scan_history import scan_history, ScanDiff
from app.analysis.package_resolver import resolve_package, is_package_name
from app.models.schemas import FindingSeverity, RiskLevel

app = typer.Typer(
    name="axiom",
    help="🛡️  Axiom — security scanner for MCP servers and agent tooling.",
    add_completion=False,
    invoke_without_command=True,
)
console = Console() if HAS_RICH else None


@app.callback()
def _default(ctx: typer.Context):
    """With no sub-command, run `axiom check`: inventory the local MCP clients and print a
    short summary."""
    if ctx.invoked_subcommand is None:
        check(output="table")


def _json_aside(output: str):
    output = "json" if output in ("sarif", "aibom") else output
    """With --output json, stdout carries only the JSON document; progress, spinners and
    notes go to stderr so `axiom ... --output json > out.json` is always valid JSON."""
    return contextlib.redirect_stdout(sys.stderr) if output == "json" else contextlib.nullcontext()


_LEVELS = ["info", "low", "medium", "high", "critical"]


def _fail_on_exit(findings, fail_on: str):
    """Exit 2 when any finding is at or above --fail-on."""
    if not fail_on:
        return
    fail_on = fail_on.lower()
    if fail_on not in _LEVELS:
        raise typer.BadParameter(f"--fail-on must be one of {', '.join(_LEVELS)}")
    threshold = _LEVELS.index(fail_on)
    for f in findings:
        sev = f.severity.value if hasattr(f, "severity") else f.get("severity")
        if sev in _LEVELS and _LEVELS.index(sev) >= threshold:
            raise typer.Exit(2)


def _emit_export(result, fmt: str, mode: str) -> bool:
    """Print SARIF / AIBOM for a scan or live result. Returns True when it handled the format."""
    if fmt not in ("sarif", "aibom"):
        return False
    from app.analysis.exporters import dumps, to_aibom, to_sarif
    doc = to_sarif(result, mode=mode) if fmt == "sarif" else to_aibom(result, mode=mode)
    print(dumps(doc))
    return True


def _sev_color(sev: str) -> str:
    return {"critical": "red bold", "high": "red", "medium": "yellow",
            "low": "cyan", "info": "dim"}.get(sev, "white")


def _risk_color(level: str) -> str:
    return {"critical": "red bold", "high": "red", "medium": "yellow",
            "low": "green", "safe": "green bold"}.get(level, "white")


def _print_diff(diff):
    """Print scan diff results."""
    if diff is None:
        if HAS_RICH and console:
            console.print("[dim]First scan — results saved for future comparison.[/dim]")
        else:
            print("  First scan — results saved for future comparison.")
        return

    if not HAS_RICH or not console:
        print(f"\n  Compared against scan from {diff.previous_scan_at[:19]}")
        delta = f"+{diff.risk_score_delta}" if diff.risk_score_delta > 0 else str(diff.risk_score_delta)
        print(f"  Risk: {diff.risk_score_prev} → {diff.risk_score_curr} ({delta})")
        print(f"  New findings: {len(diff.new_findings)} | Resolved: {len(diff.resolved_findings)}")
        return

    # Determine trend
    if diff.improved:
        trend, trend_icon, trend_color = "improving", "📉", "green"
    elif diff.degraded:
        trend, trend_icon, trend_color = "degrading", "📈", "red"
    else:
        trend, trend_icon, trend_color = "stable", "➡️", "dim"

    delta = f"+{diff.risk_score_delta}" if diff.risk_score_delta > 0 else str(diff.risk_score_delta)

    lines = [
        f"[bold]Previous scan:[/bold] {diff.previous_scan_at[:19]}",
        f"[bold]Risk:[/bold] {diff.risk_score_prev} → "
        f"[{trend_color}]{diff.risk_score_curr} ({delta} {trend_icon})[/{trend_color}]",
    ]

    if diff.new_findings:
        lines.append(f"\n[red bold]🆕 {len(diff.new_findings)} NEW finding(s):[/red bold]")
        for f in diff.new_findings[:5]:
            sev = f.get("severity", "info")
            lines.append(f"  [red]• [{sev.upper()}] {f.get('title', '')[:60]}[/red]")
        if len(diff.new_findings) > 5:
            lines.append(f"  [dim]... and {len(diff.new_findings) - 5} more[/dim]")

    if diff.resolved_findings:
        lines.append(f"\n[green]✅ {len(diff.resolved_findings)} RESOLVED finding(s):[/green]")
        for f in diff.resolved_findings[:5]:
            sev = f.get("severity", "info")
            lines.append(f"  [green]• [{sev.upper()}] {f.get('title', '')[:60]}[/green]")

    if diff.tools_added:
        lines.append(f"\n[yellow]🔧 New tools: {', '.join(diff.tools_added)}[/yellow]")
    if diff.tools_removed:
        lines.append(f"[dim]🗑️ Removed tools: {', '.join(diff.tools_removed)}[/dim]")
    if diff.tools_description_changed:
        lines.append(f"[red bold]⚠️ {len(diff.tools_description_changed)} tool description(s) CHANGED[/red bold]")
        for m in diff.tools_description_changed[:3]:
            lines.append(f"  [yellow]{m['tool']}[/yellow]: description mutated since last scan")

    has_changes = (diff.new_findings or diff.resolved_findings or
                   diff.tools_added or diff.tools_removed or diff.tools_description_changed)
    if not has_changes:
        lines.append("\n[green]No changes since last scan.[/green]")

    border = "red" if diff.degraded else "green" if diff.improved else "dim"
    console.print(Panel("\n".join(lines), title="📊 Change Detection", border_style=border, box=box.ROUNDED))


def _print_package_info(pkg):
    """Print resolved package info."""
    if not pkg or not HAS_RICH or not console:
        return
    dl_str = f"{pkg.downloads:,}/week" if pkg.downloads else "unknown"
    console.print(
        f"[dim]📦 Resolved: {pkg.ecosystem}:{pkg.name} v{pkg.version} | "
        f"Downloads: {dl_str} | License: {pkg.license or 'unknown'} | "
        f"Author: {pkg.author or 'unknown'}[/dim]"
    )


def _print_scan_result(result: dict, fmt: str = "table"):
    """Print scan results with rich formatting."""
    if fmt == "json":
        profile = result.get("server_profile")
        if hasattr(profile, "model_dump"):
            profile = profile.model_dump(mode="json")
        output = {
            "schema_version": result.get("schema_version") or "0.5",
            "target": result["target"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"].value if hasattr(result["risk_level"], "value") else result["risk_level"],
            "tools_found": len(profile.get("tools") or []) if isinstance(profile, dict) else 0,
            "findings_count": len(result["findings"]),
            "findings": [
                {"id": f.id if hasattr(f, "id") else f.get("id"),
                 "severity": f.severity.value if hasattr(f, "severity") else f.get("severity"),
                 "category": f.category.value if hasattr(f, "category") else f.get("category"),
                 "title": f.title if hasattr(f, "title") else f.get("title"),
                 "description": f.description if hasattr(f, "description") else f.get("description"),
                 "owasp_asi": f.owasp_asi if hasattr(f, "owasp_asi") else f.get("owasp_asi"),
                 "owasp_mcp": f.owasp_mcp if hasattr(f, "owasp_mcp") else f.get("owasp_mcp"),
                 "file_path": f.file_path if hasattr(f, "file_path") else f.get("file_path"),
                 "line_number": f.line_number if hasattr(f, "line_number") else f.get("line_number"),
                 "recommendation": f.recommendation if hasattr(f, "recommendation") else f.get("recommendation"),
                 "rule_id": getattr(f, "rule_id", None) if hasattr(f, "id") else f.get("rule_id"),
                 "evidence": getattr(f, "evidence", None) if hasattr(f, "id") else f.get("evidence"),
                 "location": getattr(f, "location", None) if hasattr(f, "id") else f.get("location"),
                 "replay": getattr(f, "replay", None) if hasattr(f, "id") else f.get("replay")}
                for f in result["findings"]
            ],
            # Full server profile (tools/resources/prompts/env var names) so the JSON can be fed
            # straight into `axiom threatmodel --from-scan`.
            "server_profile": profile,
            "fingerprint": result.get("fingerprint"),
            "surface_map": result.get("surface_map"),
            "provenance": result.get("provenance"),
            "owasp_coverage": result.get("owasp_coverage"),
            "owasp_mcp_coverage": result.get("owasp_mcp_coverage"),
            "ai_analysis": result.get("ai_analysis"),
            "tool_poisoning_report": result.get("tool_poisoning_report"),
            "prompt_injection_risk": result.get("prompt_injection_risk"),
        }
        print(json.dumps(output, indent=2))
        return

    if not HAS_RICH:
        risk_level = result["risk_level"].value if hasattr(result["risk_level"], "value") else result["risk_level"]
        print(f"\n{'='*60}")
        print(f"Axiom Scan: {result['target']}")
        print(f"Risk: {result['risk_score']}/100 ({risk_level})")
        print(f"Findings: {len(result['findings'])}")
        print(f"{'='*60}")
        for f in result["findings"]:
            sev = f.severity.value if hasattr(f, "severity") else f.get("severity")
            title = f.title if hasattr(f, "title") else f.get("title")
            print(f"  [{sev.upper()}] {title}")
        return

    # --- Rich output ---
    risk_level = result["risk_level"].value if hasattr(result["risk_level"], "value") else result["risk_level"]
    rc = _risk_color(risk_level)
    profile = result.get("server_profile")

    # Header
    console.print()
    tool_count = len(profile.tools) if profile else 0
    transport = profile.transport.value if profile else "unknown"
    console.print(Panel(
        f"[bold]Target:[/bold] {result['target']}\n"
        f"[bold]Transport:[/bold] {transport}\n"
        f"[bold]Tools:[/bold] {tool_count}\n"
        f"[bold]Risk Score:[/bold] [{rc}]{result['risk_score']}/100 ({risk_level.upper()})[/{rc}]\n"
        f"[bold]Duration:[/bold] {result.get('scan_duration_seconds', 0):.1f}s",
        title="🛡️  Axiom Scan Report",
        border_style=rc,
        box=box.HEAVY,
    ))

    # Tool definitions found
    if profile and profile.tools:
        ttable = Table(title=f"MCP Tools ({len(profile.tools)})", box=box.ROUNDED, show_lines=True)
        ttable.add_column("Tool", width=25)
        ttable.add_column("Poisoning Risk", width=15, justify="center")
        ttable.add_column("Description", width=50)

        for t in profile.tools:
            pr = t.poisoning_risk.value if hasattr(t.poisoning_risk, "value") else "safe"
            ttable.add_row(
                t.name,
                f"[{_risk_color(pr)}]{pr.upper()}[/{_risk_color(pr)}]",
                t.description[:50] + "..." if len(t.description) > 50 else t.description
            )
        console.print(ttable)

    # Findings
    if result["findings"]:
        ftable = Table(title=f"Findings ({len(result['findings'])})", box=box.ROUNDED, show_lines=True)
        ftable.add_column("Sev", width=10, justify="center")
        ftable.add_column("Category", width=18)
        ftable.add_column("OWASP", width=12)
        ftable.add_column("Title", width=38)
        ftable.add_column("Location", width=18)

        for f in result["findings"]:
            sev = f.severity.value if hasattr(f, "severity") else f.get("severity", "info")
            cat = f.category.value if hasattr(f, "category") else f.get("category", "")
            title = f.title if hasattr(f, "title") else f.get("title", "")
            fp = f.file_path if hasattr(f, "file_path") else f.get("file_path", "")
            ln = f.line_number if hasattr(f, "line_number") else f.get("line_number")
            asi = f.owasp_asi if hasattr(f, "owasp_asi") else f.get("owasp_asi")
            mcp = f.owasp_mcp if hasattr(f, "owasp_mcp") else f.get("owasp_mcp")
            loc = f"{fp}:{ln}" if fp and ln else fp or "-"
            asi_str = ",".join(asi) if asi else "-"
            if mcp:
                asi_str += "\n" + ",".join(mcp)

            ftable.add_row(
                f"[{_sev_color(sev)}]{sev.upper()}[/{_sev_color(sev)}]",
                cat.replace("_", " "),
                f"[cyan]{asi_str}[/cyan]",
                title[:38],
                loc[:18],
            )
        console.print(ftable)

    # AI Analysis sections
    for section_key, section_title in [
        ("ai_analysis", "🤖 Overall Assessment"),
        ("tool_poisoning_report", "🎣 Tool Poisoning Analysis"),
        ("prompt_injection_risk", "💉 Prompt Injection Risk"),
        ("claimed_vs_actual", "🔍 Claimed vs. Actual Behavior"),
    ]:
        content = result.get(section_key)
        if content:
            console.print(Panel(content, title=section_title, border_style="blue", box=box.ROUNDED))

    # Repo health
    repo = result.get("repo_health")
    if repo:
        health_text = (
            f"⭐ {repo.stars} stars | 🍴 {repo.forks} forks | "
            f"📅 Last commit: {repo.last_commit_days_ago}d ago | "
            f"📜 License: {repo.license or 'None'} | "
            f"{'🗄️ ARCHIVED' if repo.is_archived else ''}"
        )
        console.print(Panel(health_text, title="📊 Repository Health", border_style="dim"))

    # OWASP Agentic AI Top 10 coverage
    owasp = result.get("owasp_coverage")
    if owasp and owasp.get("coverage"):
        otable = Table(
            title="OWASP Agentic AI Top 10 Coverage",
            box=box.ROUNDED, show_lines=True,
        )
        otable.add_column("ID", width=6)
        otable.add_column("Risk", width=35)
        otable.add_column("Coverage", width=10, justify="center")
        otable.add_column("Findings", width=8, justify="center")

        coverage_colors = {"strong": "green", "partial": "yellow"}
        for asi_id, info in owasp["coverage"].items():
            coverage = info["coverage_level"]
            count = info["findings_count"]
            cc = coverage_colors.get(coverage, "dim")
            count_str = f"[red bold]{count}[/red bold]" if count > 0 else "[dim]0[/dim]"
            otable.add_row(
                asi_id,
                info["name"],
                f"[{cc}]{coverage.upper()}[/{cc}]",
                count_str,
            )
        console.print(otable)

    # OWASP MCP Top 10 coverage
    mcp_cov = result.get("owasp_mcp_coverage")
    if mcp_cov and mcp_cov.get("coverage"):
        mtable = Table(
            title=f"OWASP MCP Top 10 Coverage ({mcp_cov.get('framework_version') or ''})",
            box=box.ROUNDED, show_lines=True,
        )
        mtable.add_column("ID", width=6)
        mtable.add_column("Risk", width=35)
        mtable.add_column("Coverage", width=10, justify="center")
        mtable.add_column("Findings", width=8, justify="center")
        mcolors = {"strong": "green", "partial": "yellow", "gap": "red"}
        for mcp_id, info in mcp_cov["coverage"].items():
            coverage = info["coverage_level"]
            count = info["findings_count"]
            cc = mcolors.get(coverage, "dim")
            count_str = f"[red bold]{count}[/red bold]" if count > 0 else "[dim]0[/dim]"
            mtable.add_row(mcp_id, info["name"], f"[{cc}]{coverage.upper()}[/{cc}]", count_str)
        console.print(mtable)

    console.print()


@app.command()
def scan(
    target: str = typer.Argument(..., help="MCP server: GitHub URL, npm package, PyPI package, or a local file/directory"),
    url: str = typer.Option(None, "--url", "-u", help="GitHub repo URL"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table, json, sarif (SARIF 2.1.0 for GitHub Code Scanning) or aibom (CycloneDX 1.5 agent bill of materials)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI analysis"),
    no_history: bool = typer.Option(False, "--no-history", help="Don't save to scan history"),
    no_deps: bool = typer.Option(False, "--no-deps", help="Skip the network lookups: OSV advisories and the registry provenance check (offline)"),
    fail_on: str = typer.Option(None, "--fail-on", help="Exit 2 if any finding is at or above this severity: info, low, medium, high, critical"),
):
    """🔍 Scan an MCP server for security vulnerabilities.

    Accepts GitHub URLs, npm packages, PyPI packages, or a local path:
        axiom scan ./my-mcp-server            # local directory (nothing is fetched)
        axiom scan server.py                  # single local file
        axiom scan https://github.com/user/my-mcp-server
        axiom scan @modelcontextprotocol/server-filesystem
        axiom scan mcp-server-sqlite
        axiom scan npm:my-mcp-package
        axiom scan pypi:mcp-server-fetch
    """

    # Local file or directory? Scan it in place (only the CLI may do this; the API never does).
    local_path = None
    if not url and not target.startswith("http") and os.path.exists(target):
        local_path = os.path.abspath(target)
    _scan_kw = {"local_path": local_path} if local_path else {}
    if no_deps:
        _scan_kw["check_deps"] = False

    # Auto-detect URL
    if target.startswith("http") and not url:
        url = target
        target = target.rstrip("/").split("/")[-1]

    def _aside():
        return _json_aside(output)

    async def _run():
        with _aside():
            if console:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as p:
                    task = p.add_task(f"Scanning {target}...", total=None)
                    result = await engine.scan(target, url, **_scan_kw)

                    if not no_ai:
                        p.update(task, description="Running AI analysis...")
                        ai = await generate_mcp_ai_analysis(target, result["findings"], result["server_profile"])
                        result.update(ai)

                    p.update(task, description="Done!", completed=True)
            else:
                print(f"Scanning {target}...")
                result = await engine.scan(target, url, **_scan_kw)
                if not no_ai:
                    ai = await generate_mcp_ai_analysis(target, result["findings"], result["server_profile"])
                    result.update(ai)

            # Show package info if resolved
            pkg = result.get("package_info")
            if pkg:
                _print_package_info(pkg)

        if not _emit_export(result, output, "static"):
            _print_scan_result(result, output)

        # Save to history and show diff
        if not no_history:
            scan_target = result.get("target_url") or target
            pkg = result.get("package_info")
            diff = scan_history.diff(scan_target, result)
            scan_history.save(
                scan_target, result,
                package_ecosystem=pkg.ecosystem if pkg else None,
                package_version=pkg.version if pkg else None,
            )
            with _aside():
                _print_diff(diff)

        _fail_on_exit(result["findings"], fail_on)
        risk = result["risk_level"].value if hasattr(result["risk_level"], "value") else result["risk_level"]
        if risk in ("critical", "high"):
            raise typer.Exit(2)
        elif risk == "medium":
            raise typer.Exit(1)

    asyncio.run(_run())


@app.command()
def local(
    path: str = typer.Option(None, "--path", "-p", help="Specific config file to scan (only this file unless --include-defaults)"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
    include_defaults: bool = typer.Option(False, "--include-defaults", help="With --path, also scan the known client config locations"),
):
    """🏠 Scan local MCP configuration files for security issues."""

    custom_paths = [path] if path else None
    result = local_scanner.scan_all(custom_paths, include_defaults=(include_defaults or not path))
    from app.analysis.owasp_mapping import apply_owasp_mappings
    apply_owasp_mappings(result["findings"])

    if output == "json":
        print(json.dumps({
            "config_files": result["config_files_found"],
            "total_servers": result["total_servers"],
            "servers": [e.model_dump() for e in result["servers_discovered"]],
            "findings": [f.model_dump() for f in result["findings"]],
        }, indent=2, default=str))
        return

    if not HAS_RICH or not console:
        print(f"\nFound {result['total_servers']} MCP servers in {len(result['config_files_found'])} config files")
        for entry in result["servers_discovered"]:
            print(f"  - {entry.name} ({entry.command} {' '.join(entry.args[:2])})")
        print(f"\n{len(result['findings'])} security findings")
        return

    # Rich output
    console.print()
    console.print(Panel(
        f"[bold]Config files scanned:[/bold] {len(result['config_files_found'])}\n"
        f"[bold]MCP servers found:[/bold] {result['total_servers']}\n"
        f"[bold]Security findings:[/bold] {len(result['findings'])}",
        title="🏠 Local MCP Configuration Scan",
        border_style="blue",
        box=box.HEAVY,
    ))

    # List discovered servers
    if result["servers_discovered"]:
        stable = Table(title="Discovered MCP Servers", box=box.ROUNDED, show_lines=True)
        stable.add_column("Name", width=20)
        stable.add_column("Command", width=30)
        stable.add_column("Transport", width=10)
        stable.add_column("Env Vars", width=10, justify="center")
        stable.add_column("Config File", width=30)

        for entry in result["servers_discovered"]:
            cmd = f"{entry.command} {' '.join(entry.args[:2])}"
            stable.add_row(
                entry.name,
                cmd[:30],
                entry.transport.value,
                str(len(entry.env)),
                os.path.basename(entry.source_file),
            )
        console.print(stable)

    # Findings
    if result["findings"]:
        ftable = Table(title=f"Findings ({len(result['findings'])})", box=box.ROUNDED, show_lines=True)
        ftable.add_column("Sev", width=10, justify="center")
        ftable.add_column("Category", width=20)
        ftable.add_column("Title", width=50)

        for f in result["findings"]:
            sev = f.severity.value
            ftable.add_row(
                f"[{_sev_color(sev)}]{sev.upper()}[/{_sev_color(sev)}]",
                f.category.value.replace("_", " "),
                f.title[:50],
            )
        console.print(ftable)
    else:
        console.print("[green]✅ No security issues found in local MCP configurations.[/green]")

    console.print()


def _print_live_result(result: LiveScanResult, fmt: str = "table"):
    """Print live scan results with rich formatting."""
    if fmt == "json":
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return

    if not HAS_RICH or not console:
        print(f"\n{'='*60}")
        print(f"Axiom Live Scan: {result.server_name}")
        print(f"Status: {result.status}")
        if result.error:
            print(f"Error: {result.error}")
        else:
            print(f"Transport: {result.transport}")
            print(f"Tools: {len(result.runtime_tools)}")
            print(f"Risk: {result.risk_score}/100 ({result.risk_level.value})")
            print(f"Findings: {len(result.findings)}")
        print(f"{'='*60}")
        for f in result.findings:
            sev = f.severity.value if hasattr(f, "severity") else "info"
            title = f.title if hasattr(f, "title") else ""
            print(f"  [{sev.upper()}] {title}")
        return

    # Rich output
    console.print()

    if result.status == "error":
        console.print(Panel(
            f"[bold]Server:[/bold] {result.server_name}\n"
            f"[bold]Transport:[/bold] {result.transport}\n"
            f"[bold]Status:[/bold] [red]{result.status}[/red]\n"
            f"[bold]Error:[/bold] {result.error}",
            title="🔴 Axiom Live Scan — Connection Failed",
            border_style="red",
            box=box.HEAVY,
        ))
        console.print()
        return

    rc = _risk_color(result.risk_level.value)
    server_version = result.server_info.get("version", "?")
    server_display = result.server_info.get("name", result.server_name)

    console.print(Panel(
        f"[bold]Server:[/bold] {server_display} v{server_version}\n"
        f"[bold]Transport:[/bold] {result.transport}\n"
        f"[bold]Protocol:[/bold] {result.protocol_version}\n"
        f"[bold]Tools:[/bold] {len(result.runtime_tools)} | "
        f"[bold]Resources:[/bold] {len(result.runtime_resources)} | "
        f"[bold]Prompts:[/bold] {len(result.runtime_prompts)}\n"
        f"[bold]Risk Score:[/bold] [{rc}]{result.risk_score}/100 "
        f"({result.risk_level.value.upper()})[/{rc}]\n"
        f"[bold]Duration:[/bold] {result.scan_duration_seconds:.1f}s",
        title="🔌 Axiom Live Scan Report",
        border_style=rc,
        box=box.HEAVY,
    ))

    # Runtime tools
    if result.runtime_tools:
        ttable = Table(
            title=f"Runtime Tools ({len(result.runtime_tools)})",
            box=box.ROUNDED, show_lines=True,
        )
        ttable.add_column("Tool", width=25)
        ttable.add_column("Poisoning", width=12, justify="center")
        ttable.add_column("Description", width=45)
        ttable.add_column("Params", width=10, justify="center")

        for t in result.runtime_tools:
            pr = t.poisoning_risk.value if hasattr(t.poisoning_risk, "value") else "safe"
            param_count = len(t.input_schema.get("properties", {})) if t.input_schema else 0
            ttable.add_row(
                t.name,
                f"[{_risk_color(pr)}]{pr.upper()}[/{_risk_color(pr)}]",
                t.description[:45] + "..." if len(t.description) > 45 else t.description,
                str(param_count),
            )
        console.print(ttable)

    # Diff results
    diff = result.diff_results
    if diff:
        console.print()
        parts = []
        if diff.get("runtime_only"):
            parts.append(f"[red bold]🚨 {len(diff['runtime_only'])} HIDDEN tools "
                         f"(runtime only):[/red bold] {', '.join(diff['runtime_only'])}")
        if diff.get("source_only"):
            parts.append(f"[dim]ℹ {len(diff['source_only'])} source-only tools:[/dim] "
                         f"{', '.join(diff['source_only'])}")
        if diff.get("description_mutations"):
            mutations = diff["description_mutations"]
            parts.append(f"[yellow]⚠ {len(mutations)} description mutation(s)[/yellow]")
            for m in mutations[:3]:
                parts.append(f"  [yellow]{m['tool']}[/yellow]: "
                             f"similarity {m['similarity']:.0%}")
        if diff.get("schema_mutations"):
            parts.append(f"[yellow]⚠ {len(diff['schema_mutations'])} schema mutation(s)[/yellow]")

        if parts:
            console.print(Panel(
                "\n".join(parts),
                title="🔍 Source vs Runtime Diff",
                border_style="yellow",
                box=box.ROUNDED,
            ))

    # Findings
    if result.findings:
        ftable = Table(
            title=f"Findings ({len(result.findings)})",
            box=box.ROUNDED, show_lines=True,
        )
        ftable.add_column("Sev", width=10, justify="center")
        ftable.add_column("Category", width=18)
        ftable.add_column("OWASP", width=12)
        ftable.add_column("Title", width=50)

        for f in result.findings:
            sev = f.severity.value
            cat = f.category.value
            asi = f.owasp_asi
            asi_str = ",".join(asi) if asi else "-"
            ftable.add_row(
                f"[{_sev_color(sev)}]{sev.upper()}[/{_sev_color(sev)}]",
                cat.replace("_", " "),
                f"[cyan]{asi_str}[/cyan]",
                f.title[:50],
            )
        console.print(ftable)

    # Server capabilities
    if result.server_capabilities:
        caps = ", ".join(result.server_capabilities.keys()) or "none declared"
        console.print(f"\n[dim]Server capabilities: {caps}[/dim]")

    console.print()


def _print_live_summary(results: List[LiveScanResult], fmt: str = "table"):
    """Print summary of all live scan results."""
    if fmt == "json":
        print(json.dumps({"schema_version": "0.5", "servers": [r.to_dict() for r in results]},
                         indent=2, default=str))
        return

    if not HAS_RICH or not console:
        print(f"\nScanned {len(results)} servers")
        for r in results:
            status = "✓" if r.status == "completed" else "✗"
            print(f"  {status} {r.server_name}: {r.risk_score}/100 ({r.status})")
        return

    console.print()
    console.print(Panel(
        f"[bold]Servers scanned:[/bold] {len(results)}\n"
        f"[bold]Connected:[/bold] {sum(1 for r in results if r.status == 'completed')}\n"
        f"[bold]Failed:[/bold] {sum(1 for r in results if r.status == 'error')}\n"
        f"[bold]Total findings:[/bold] {sum(len(r.findings) for r in results)}",
        title="🔌 Axiom Live Scan — All Servers",
        border_style="blue",
        box=box.HEAVY,
    ))

    stable = Table(box=box.ROUNDED, show_lines=True)
    stable.add_column("Server", width=25)
    stable.add_column("Status", width=10, justify="center")
    stable.add_column("Transport", width=10)
    stable.add_column("Tools", width=6, justify="center")
    stable.add_column("Risk", width=15, justify="center")
    stable.add_column("Findings", width=8, justify="center")
    stable.add_column("Duration", width=8, justify="right")

    for r in results:
        if r.status == "completed":
            rc = _risk_color(r.risk_level.value)
            risk_str = f"[{rc}]{r.risk_score}/100[/{rc}]"
            status_str = "[green]✅[/green]"
        else:
            risk_str = "[dim]-[/dim]"
            status_str = "[red]❌[/red]"

        stable.add_row(
            r.server_name,
            status_str,
            r.transport,
            str(len(r.runtime_tools)),
            risk_str,
            str(len(r.findings)),
            f"{r.scan_duration_seconds:.1f}s",
        )
    console.print(stable)
    console.print()


@app.command()
def live(
    server: str = typer.Option(None, "--server", "-s", help="Scan specific server by name"),
    command: str = typer.Option(None, "--command", "-c", help="Command to spawn MCP server"),
    args: str = typer.Option(None, "--args", "-a", help="Args (comma-separated)"),
    sse: str = typer.Option(None, "--sse", "--url", help="Remote MCP endpoint URL (Streamable HTTP /mcp or legacy /sse; transport auto-detected)"),
    transport: str = typer.Option("auto", "--transport", help="Remote transport: auto, streamable-http or sse"),
    header: List[str] = typer.Option(None, "--header", "-H", help="Extra request header 'Name: value' (repeatable), e.g. Authorization"),
    path: str = typer.Option(None, "--path", "-p", help="Custom config file path"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
    compare: str = typer.Option(None, "--compare", help="GitHub URL to compare runtime against source"),
    no_read: bool = typer.Option(False, "--no-read", help="Do not read resource contents or fetch prompt text (list only)"),
    source: str = typer.Option(None, "--source", help="Local source dir/file, a saved Surface Map JSON, or a baseline name: the live surface is compared with it (surface_mismatch findings)"),
    fail_on: str = typer.Option(None, "--fail-on", help="Exit 2 if any finding is at or above this severity: info, low, medium, high, critical"),
):
    """🔌 Live-connect to MCP servers and scan runtime tool definitions.

    Examples:
        axiom live                        # Scan all local MCP servers
        axiom live --server filesystem    # Scan specific server by name
        axiom live --command npx --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
        axiom live --url http://localhost:9001/mcp     # Streamable HTTP
        axiom live --sse http://localhost:3000/sse     # legacy HTTP+SSE
        axiom live --url https://host/mcp -H "Authorization: Bearer ..."
        axiom live --compare https://github.com/user/mcp-server   # Diff source vs runtime
        axiom live --command node --args server.js --source ./src  # surface_mismatch if live != source
    """

    def _apply_source(result: LiveScanResult) -> None:
        """Compare the on-the-wire Surface Map with a source map / baseline; never calls a tool."""
        if not source or result.status != "completed":
            return
        from app.analysis.surface_map import build_live_map, build_static_map, load_baseline, surface_mismatch_findings
        src_map = None
        if os.path.exists(source) and source.endswith(".json"):
            src_map = load_baseline(source)
        elif os.path.exists(source):
            src_map = build_static_map(source)
        else:
            src_map = load_baseline(source)
        if src_map is None:
            raise typer.BadParameter(f"--source: '{source}' is not a path, a Surface Map JSON or a saved baseline")
        live_map = build_live_map(result)
        extra = surface_mismatch_findings(src_map, live_map)
        result.findings.extend(extra)
        result.diff_results = (result.diff_results or {})
        result.diff_results["surface"] = {
            "source_fingerprint": src_map.fingerprint, "live_fingerprint": live_map.fingerprint,
            "mismatches": len(extra),
        }
        if extra:
            result.risk_score = live_scanner._calculate_risk_score(result.findings)
            result.risk_level = live_scanner._score_to_level(result.risk_score)

    async def _run():
        # Mode 1: Direct remote scan (Streamable HTTP or SSE)
        if sse:
            hdrs = {}
            for h in header or []:
                name, _, value = h.partition(":")
                if name.strip() and value.strip():
                    hdrs[name.strip()] = value.strip()
            with _json_aside(output):
                if console:
                    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as p:
                        task = p.add_task(f"Connecting to {sse}...", total=None)
                        result = await live_scanner.scan_sse(sse, read_contents=not no_read,
                                                             transport=transport, headers=hdrs)
                        p.update(task, description="Done!", completed=True)
                else:
                    print(f"Connecting to {sse}...")
                    result = await live_scanner.scan_sse(sse, read_contents=not no_read,
                                                         transport=transport, headers=hdrs)
            _apply_source(result)
            if not _emit_export(result, output, "live"):
                _print_live_result(result, output)
            _fail_on_exit(result.findings, fail_on)
            return _exit_code(result)

        # Mode 2: Direct command scan
        if command:
            cmd_args = [a.strip() for a in args.split(",")] if args else []
            with _json_aside(output):
                if console:
                    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as p:
                        task = p.add_task(f"Spawning {command}...", total=None)

                        # Optional source comparison
                        source_tools = None
                        if compare:
                            p.update(task, description=f"Scanning source at {compare}...")
                            source_result = await engine.scan(command, compare)
                            source_profile = source_result.get("server_profile")
                            if source_profile:
                                source_tools = source_profile.tools

                        p.update(task, description=f"Live scanning {command}...")
                        result = await live_scanner.scan_stdio(
                            command, cmd_args, source_tools=source_tools,
                            read_contents=not no_read,
                        )
                        p.update(task, description="Done!", completed=True)
                else:
                    source_tools = None
                    if compare:
                        print(f"Scanning source at {compare}...")
                        source_result = await engine.scan(command, compare)
                        source_profile = source_result.get("server_profile")
                        if source_profile:
                            source_tools = source_profile.tools
                    print(f"Live scanning {command}...")
                    result = await live_scanner.scan_stdio(
                        command, cmd_args, source_tools=source_tools,
                        read_contents=not no_read,
                    )
            _apply_source(result)
            if not _emit_export(result, output, "live"):
                _print_live_result(result, output)
            _fail_on_exit(result.findings, fail_on)
            return _exit_code(result)

        # Mode 3: Scan local servers (all or filtered)
        custom_paths = [path] if path else None
        with _json_aside(output):
            if console:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as p:
                    task = p.add_task("Discovering local MCP servers...", total=None)
                    results = await live_scanner.scan_all_local(custom_paths, server, read_contents=not no_read)

                    if not results:
                        p.update(task, description="No servers found.", completed=True)
                        console.print("[yellow]No MCP servers found in local configurations.[/yellow]")
                        if server:
                            console.print(f"[dim]Filter: '{server}' matched no servers.[/dim]")
                        console.print("[dim]Run 'axiom local' to see configured servers.[/dim]")
                        results = []

                    else:
                        p.update(task, description=f"Scanned {len(results)} servers.", completed=True)
            else:
                print("Discovering local MCP servers...")
                results = await live_scanner.scan_all_local(custom_paths, server, read_contents=not no_read)
                if not results:
                    print("No MCP servers found.")
                    results = []

        if not results:
            if output == "json":
                print(json.dumps({"schema_version": "0.5", "servers": []}, indent=2))
            return

        if len(results) == 1:
            _print_live_result(results[0], output)
        elif output == "json":
            # One JSON document on stdout, never several.
            _print_live_summary(results, output)
        else:
            _print_live_summary(results, output)
            # Show details for servers with findings
            for r in results:
                if r.findings and r.status == "completed":
                    _print_live_result(r, output)

        # Exit code based on worst result
        worst = max(
            (r.risk_score for r in results if r.status == "completed"),
            default=0,
        )
        if worst >= 50:
            raise typer.Exit(2)
        elif worst >= 25:
            raise typer.Exit(1)

    def _exit_code(result: LiveScanResult):
        if result.risk_level.value in ("critical", "high"):
            raise typer.Exit(2)
        elif result.risk_level.value == "medium":
            raise typer.Exit(1)

    asyncio.run(_run())


@app.command()
def version():
    """Show version."""
    print("Axiom v0.6.0 — OWASP Agentic AI + MCP Top 10 mapping, shadow MCP discovery, A2A agent card scanning, threat modelling")


@app.command()
def history(
    target: str = typer.Argument(None, help="Show history for specific target"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
    limit: int = typer.Option(10, "--limit", "-n", help="Max results"),
):
    """📜 View scan history and past results.

    Examples:
        axiom history                                    # List all scanned targets
        axiom history @modelcontextprotocol/server-filesystem  # History for specific target
        axiom history --output json                      # JSON output
    """
    if target:
        # Show history for specific target
        scans = scan_history.get_timeline(target, limit=limit)
        if not scans:
            if console:
                console.print(f"[yellow]No scan history found for '{target}'.[/yellow]")
            else:
                print(f"No scan history for '{target}'.")
            return

        if output == "json":
            print(json.dumps(scans, indent=2, default=str))
            return

        if not HAS_RICH or not console:
            print(f"\nScan history for {target} ({len(scans)} scans):")
            for s in scans:
                print(f"  {s.get('scanned_at', '?')[:19]} — risk: {s.get('risk_score', 0)}/100")
            return

        console.print()
        console.print(Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Total scans:[/bold] {len(scans)}",
            title="📜 Scan History",
            border_style="blue",
            box=box.HEAVY,
        ))

        htable = Table(box=box.ROUNDED, show_lines=True)
        htable.add_column("#", width=4, justify="right")
        htable.add_column("Date", width=20)
        htable.add_column("Risk Score", width=12, justify="center")
        htable.add_column("Risk Level", width=12, justify="center")
        htable.add_column("Findings", width=10, justify="center")
        htable.add_column("Version", width=12)

        for i, s in enumerate(scans, 1):
            saved = s.get("scanned_at", "?")[:19]
            score = s.get("risk_score", 0)
            level = s.get("risk_level", "safe")
            fc = s.get("findings_count", 0)
            ver = s.get("package_version") or "-"
            rc = _risk_color(level)
            htable.add_row(
                str(i), saved,
                f"[{rc}]{score}/100[/{rc}]",
                f"[{rc}]{level.upper()}[/{rc}]",
                str(fc), ver,
            )
        console.print(htable)
        console.print()
    else:
        # List all targets
        targets = scan_history.list_targets()
        if not targets:
            if console:
                console.print("[yellow]No scan history found. Run 'axiom scan' to start.[/yellow]")
            else:
                print("No scan history. Run 'axiom scan' to start.")
            return

        if output == "json":
            print(json.dumps(targets, indent=2, default=str))
            return

        if not HAS_RICH or not console:
            print(f"\n{len(targets)} targets in scan history:")
            for t in targets:
                print(f"  {t['target']}: {t.get('risk_score', 0)}/100 ({t.get('scan_count', 0)} scans)")
            return

        console.print()
        console.print(Panel(
            f"[bold]Targets tracked:[/bold] {len(targets)}",
            title="📜 Axiom Scan History",
            border_style="blue",
            box=box.HEAVY,
        ))

        ttable = Table(box=box.ROUNDED, show_lines=True)
        ttable.add_column("Target", width=40)
        ttable.add_column("Last Scan", width=20)
        ttable.add_column("Risk", width=12, justify="center")
        ttable.add_column("Findings", width=10, justify="center")
        ttable.add_column("Scans", width=8, justify="center")

        for t in targets:
            rc = _risk_color(t.get("risk_level", "safe"))
            ttable.add_row(
                t["target"][:40],
                t.get("last_scanned", "?")[:19],
                f"[{rc}]{t.get('risk_score', 0)}/100[/{rc}]",
                str(t.get("findings_count", 0)),
                str(t.get("scan_count", 0)),
            )
        console.print(ttable)
        console.print(f"\n[dim]Run 'axiom history <target>' for detailed history.[/dim]")
        console.print()


@app.command()
def owasp(
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
    framework: str = typer.Option(
        "asi", "--framework", "-f",
        help="Framework: asi (Agentic Top 10), mcp (MCP Top 10) or all",
    ),
):
    """📋 Show OWASP coverage matrix (Agentic AI Top 10 and/or MCP Top 10)."""
    from app.analysis.owasp_mapping import get_coverage_matrix

    framework = (framework or "asi").lower()
    if framework not in ("asi", "mcp", "all"):
        print(f"Unknown framework '{framework}'. Use asi, mcp or all.")
        raise typer.Exit(code=2)

    if output == "json":
        if framework == "all":
            matrix = get_coverage_matrix("all")
            out = {fw: {k: dict(v) for k, v in m.items()} for fw, m in matrix.items()}
        else:
            matrix = get_coverage_matrix(framework)
            # Make it JSON serializable
            out = {}
            for k, v in matrix.items():
                out[k] = {kk: vv for kk, vv in v.items()}
        print(json.dumps(out, indent=2))
        return

    if framework in ("asi", "all"):
        _print_owasp_asi_matrix(get_coverage_matrix("asi"))
    if framework in ("mcp", "all"):
        _print_owasp_mcp_matrix(get_coverage_matrix("mcp"))


def _print_owasp_asi_matrix(matrix: dict):
    """Render the OWASP Agentic AI Top 10 matrix."""
    if not HAS_RICH or not console:
        print("\nAxiom — OWASP Agentic AI Top 10 Coverage\n")
        for asi_id, info in matrix.items():
            cov = info["mcpguard_coverage"].upper()
            print(f"  {asi_id}: {info['name']:<42} [{cov}]")
            if "gap_note" in info:
                print(f"         ⚠ {info['gap_note']}")
        return

    console.print()
    console.print(Panel(
        "[bold]OWASP Top 10 for Agentic Applications 2026[/bold]\n"
        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        title="📋 Axiom OWASP Coverage Matrix",
        border_style="blue",
        box=box.HEAVY,
    ))

    otable = Table(box=box.ROUNDED, show_lines=True)
    otable.add_column("ID", width=6)
    otable.add_column("Risk Name", width=35)
    otable.add_column("Coverage", width=10, justify="center")
    otable.add_column("Detectors", width=40)
    otable.add_column("Published Example", width=40)

    coverage_icons = {"strong": "[green]✅ STRONG[/green]", "partial": "[yellow]🟡 PARTIAL[/yellow]"}

    for asi_id, info in matrix.items():
        cov = coverage_icons.get(info["mcpguard_coverage"], "[dim]—[/dim]")
        detectors = ", ".join(info["detectors"][:3])
        incidents = info.get("published_examples", [])
        incident_str = incidents[0][:40] if incidents else "—"

        otable.add_row(asi_id, info["name"], cov, detectors, incident_str)

    console.print(otable)

    # Show gap notes
    gaps = [(k, v) for k, v in matrix.items() if "gap_note" in v]
    if gaps:
        console.print()
        console.print("[bold yellow]Coverage Notes:[/bold yellow]")
        for asi_id, info in gaps:
            console.print(f"  [yellow]{asi_id}[/yellow]: {info['gap_note']}")

    console.print()


def _print_owasp_mcp_matrix(matrix: dict):
    """Render the OWASP MCP Top 10 matrix, with a one-line reason for partial/gap items."""
    from app.analysis.owasp_mapping import OWASP_MCP_TOP_10_DATA

    version = OWASP_MCP_TOP_10_DATA.get("framework_version", "")
    ref = OWASP_MCP_TOP_10_DATA.get("reference_url", "")

    if not HAS_RICH or not console:
        print(f"\nAxiom — OWASP MCP Top 10 Coverage ({version})\n")
        for mcp_id, info in matrix.items():
            cov = info["mcpguard_coverage"].upper()
            print(f"  {mcp_id}: {info['name']:<52} [{cov}]")
            if info["mcpguard_coverage"] in ("partial", "gap"):
                print(f"         ⚠ {info['reason']}")
        return

    console.print()
    console.print(Panel(
        f"[bold]OWASP MCP Top 10[/bold] ({version})\n{ref}",
        title="📋 Axiom OWASP MCP Top 10 Coverage Matrix",
        border_style="blue",
        box=box.HEAVY,
    ))

    mtable = Table(box=box.ROUNDED, show_lines=True)
    mtable.add_column("ID", min_width=5, no_wrap=True)
    mtable.add_column("Risk Name", min_width=20, max_width=40)
    mtable.add_column("Coverage", min_width=11, justify="center", no_wrap=True)
    mtable.add_column("Detectors", min_width=12, max_width=40)

    coverage_icons = {
        "strong": "[green]✅ STRONG[/green]",
        "partial": "[yellow]🟡 PARTIAL[/yellow]",
        "gap": "[red]❌ GAP[/red]",
    }
    for mcp_id, info in matrix.items():
        cov = coverage_icons.get(info["mcpguard_coverage"], "[dim]—[/dim]")
        detectors = ", ".join(info["detectors"][:3])
        mtable.add_row(mcp_id, info["name"], cov, detectors)
    console.print(mtable)

    notes = [(k, v) for k, v in matrix.items() if v["mcpguard_coverage"] in ("partial", "gap")]
    if notes:
        console.print()
        console.print("[bold yellow]Coverage Notes:[/bold yellow]")
        for mcp_id, info in notes:
            color = "red" if info["mcpguard_coverage"] == "gap" else "yellow"
            console.print(f"  [{color}]{mcp_id}[/{color}]: {info['reason']}")

    console.print()


# Shadow MCP discovery (Workstream B)
from cli.discover_cmd import discover  # noqa: E402
app.command(name="discover")(discover)

# A2A agent card scanning (Workstream D)
from cli.a2a_cmd import a2a  # noqa: E402
app.command(name="a2a")(a2a)


# Threat model generation (Workstream C)
from cli.threatmodel_cmd import threatmodel  # noqa: E402
app.command(name="threatmodel")(threatmodel)

# ---------------------------------------------------------------------------
# check (the default run) and telemetry  (README, "Usage ping")
# ---------------------------------------------------------------------------

@app.command()
def check(
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
):
    """✅ The default run: scan this machine's MCP client configs and summarise.
    Sends the anonymous usage ping afterwards (counts only) unless telemetry is off."""
    from app.analysis import telemetry as tm
    if tm.first_run_notice_due():
        print(tm.NOTICE, file=sys.stderr)
        tm.mark_notice_shown()
    result = local_scanner.scan_all(None, include_defaults=True)
    counts = tm.counts_from_check(result)
    if output == "json":
        doc = {"schema_version": "0.6", "config_files_found": result["config_files_found"],
               "total_servers": result["total_servers"],
               "findings": [f.model_dump() for f in result["findings"]],
               "counts": counts}
        print(json.dumps(doc, indent=2, default=str))
    else:
        msg = (f"Axiom check: {counts['clients_detected']} client config(s), {counts['servers_inventoried']} server(s); "
               f"findings critical={counts['findings_critical']} high={counts['findings_high']} medium={counts['findings_medium']}")
        (console.print(msg) if console else print(msg))
        if result["findings"] and console:
            console.print("[dim]Run `axiom local` for the detailed report.[/dim]")
    tm.maybe_send(counts)
    tm.flush()   # the ping runs on a daemon thread; without this the process exits before it is sent
    worst = {"critical": 2, "high": 2, "medium": 1}
    raise typer.Exit(max((worst.get(f.severity.value, 0) for f in result["findings"]), default=0))


telemetry_app = typer.Typer(help="📡 Anonymous usage ping: show exactly what would be sent, turn it off/on, reset the install id.", add_completion=False)
app.add_typer(telemetry_app, name="telemetry")


@telemetry_app.command("show")
def telemetry_show():
    """Print the exact JSON that would be sent now (counts from a fresh `check`)."""
    from app.analysis import telemetry as tm
    result = local_scanner.scan_all(None, include_defaults=True)
    payload = tm.build_payload(tm.counts_from_check(result))
    print(json.dumps(payload, indent=2))
    print(f"\nendpoint: POST {tm.endpoint()}   enabled: {tm.enabled()}"
          + ("   (disabled by environment: AXIOM_TELEMETRY=0 / DO_NOT_TRACK=1)" if tm.env_disabled() else ""), file=sys.stderr)


@telemetry_app.command("off")
def telemetry_off():
    from app.analysis import telemetry as tm
    tm.set_enabled(False)
    print("Telemetry off. Nothing will be sent.")


@telemetry_app.command("on")
def telemetry_on():
    from app.analysis import telemetry as tm
    tm.set_enabled(True)
    print("Telemetry on (anonymous counts, at most once per 24 h).")


@telemetry_app.command("reset")
def telemetry_reset():
    from app.analysis import telemetry as tm
    print(f"New install id: {tm.install_id(regenerate=True)}")


# Replayable findings
@app.command()
def explain(
    finding_id: str = typer.Argument(..., help="Finding id, e.g. poison_add_note_injection_marker"),
    from_json: str = typer.Option(None, "--from", help="A JSON file written by `axiom scan|live|local --output json` (default: the latest scan in history)"),
):
    """🔎 Print a finding's rule, evidence, location and replay command (what a reviewer needs to confirm it)."""
    from app.analysis.evidence import enrich_findings, explain as _explain
    from app.models.schemas import Finding, FindingCategory
    findings = []
    if from_json:
        with open(from_json, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        docs = doc.get("servers", [doc]) if isinstance(doc, dict) else []
        for d in docs:
            for raw in d.get("findings", []):
                try:
                    findings.append(Finding(**{k: v for k, v in raw.items() if k in Finding.model_fields}))
                except Exception:
                    continue
        mode = "live" if any("runtime_tools" in d or "server_name" in d for d in docs) else "static"
        target = docs[0].get("target") or docs[0].get("server_name") or from_json if docs else from_json
    else:
        targets = scan_history.list_targets(limit=1)
        if not targets:
            print("No scan history and no --from file. Run a scan with --output json and pass it with --from.")
            raise typer.Exit(1)
        latest = scan_history.get_latest(targets[0]["target"])
        for raw in (latest or {}).get("findings", []):
            try:
                findings.append(Finding(**{k: v for k, v in raw.items() if k in Finding.model_fields}))
            except Exception:
                continue
        mode, target = "static", targets[0]["target"]
    enrich_findings(findings, mode=mode, target=str(target))
    hit = [f for f in findings if f.id == finding_id]
    if not hit:
        print(f"No finding with id '{finding_id}' among {len(findings)} findings.")
        raise typer.Exit(1)
    print(_explain(hit[0]))


# Agent Surface Map: surface / baseline / drift
from cli.surface_cmd import surface, baseline, drift  # noqa: E402
app.command(name="surface")(surface)
app.command(name="baseline")(baseline)
app.command(name="drift")(drift)


if __name__ == "__main__":
    app()
