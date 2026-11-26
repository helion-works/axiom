"""`axiom discover` — shadow MCP server inventory.

Registered on the main Typer app in cli/axiom_cli.py.
"""

import asyncio
import os
import sys
from typing import List, Optional

import typer

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markup import escape
    from rich import box
    HAS_RICH = True
except ImportError:  # pragma: no cover - rich is a hard dependency, but mirror the CLI guard
    HAS_RICH = False

from app.analysis.discovery import (
    DiscoveryResult,
    discover_servers,
    result_to_json,
    result_to_markdown,
    run_static_scans,
)

_STATUS_STYLE = {
    "approved": "green",
    "unapproved": "red bold",
    "unknown-version": "yellow",
    "unchecked": "dim",
}
_SEV_STYLE = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _target(srv) -> str:
    if srv.package:
        return srv.package
    if srv.url:
        return srv.url
    return " ".join([srv.command or ""] + list(srv.args[:3])).strip()


def _print_plain(result: DiscoveryResult) -> None:
    s = result.summary
    print(f"\nMCP server inventory: {s.get('total', 0)} servers in {s.get('config_files', 0)} config files")
    print(f"Allowlist: {result.allowlist or 'none'}  approved={s.get('approved', 0)} "
          f"unapproved={s.get('unapproved', 0)} unknown-version={s.get('unknown_version', 0)} "
          f"unchecked={s.get('unchecked', 0)}")
    for srv in result.servers:
        print(f"  [{srv.classification}] {srv.client}: {srv.server_name} ({srv.install_source}: {_target(srv)})")
    for p in result.processes:
        print(f"  process {p.pid}: {p.indicator} -> {p.cmdline[:80]}")
    if result.findings:
        print(f"\n{len(result.findings)} findings")
        for f in result.findings:
            print(f"  {f.severity.value.upper()}: {f.title}")
    for n in result.notes:
        print(f"  note: {n}")


def _print_rich(result: DiscoveryResult) -> None:
    console = Console()
    s = result.summary
    console.print()
    console.print(Panel(
        f"[bold]Config files read:[/bold] {s.get('config_files', 0)}\n"
        f"[bold]MCP servers found:[/bold] {s.get('total', 0)}\n"
        f"[bold]Allowlist:[/bold] {escape(result.allowlist or 'none')}  "
        f"[green]approved {s.get('approved', 0)}[/green]  "
        f"[red]unapproved {s.get('unapproved', 0)}[/red]  "
        f"[yellow]unknown-version {s.get('unknown_version', 0)}[/yellow]  "
        f"[dim]unchecked {s.get('unchecked', 0)}[/dim]",
        title="MCP Server Inventory (shadow MCP discovery)",
        border_style="blue",
        box=box.HEAVY,
    ))

    if result.servers:
        table = Table(title="Configured MCP servers", box=box.ROUNDED, show_lines=True)
        table.add_column("Client")
        table.add_column("Server")
        table.add_column("Transport")
        table.add_column("Source")
        table.add_column("Package / URL / Command", overflow="fold")
        table.add_column("Version")
        table.add_column("Env var names", overflow="fold")
        table.add_column("Status")
        table.add_column("Config", overflow="fold")
        for srv in result.servers:
            style = _STATUS_STYLE.get(srv.classification, "white")
            table.add_row(
                escape(srv.client),
                escape(srv.server_name),
                srv.transport + (f" ({srv.remote_type})" if srv.remote_type else ""),
                srv.install_source,
                escape(_target(srv)),
                escape(srv.version_pin or "-"),
                escape(", ".join(srv.env_var_names) or "-"),
                f"[{style}]{srv.classification}[/{style}]",
                escape(os.path.basename(srv.config_path)),
            )
        console.print(table)
    else:
        console.print("[dim]No MCP servers found in the known client config locations.[/dim]")

    if result.processes:
        ptable = Table(title="Running MCP-like processes", box=box.ROUNDED)
        ptable.add_column("PID", justify="right")
        ptable.add_column("Indicator")
        ptable.add_column("Configured as")
        ptable.add_column("Command line", overflow="fold")
        for p in result.processes:
            ptable.add_row(str(p.pid), escape(p.indicator), escape(p.matches_server or "-"), escape(p.cmdline))
        console.print(ptable)

    if result.findings:
        ftable = Table(title=f"Findings ({len(result.findings)})", box=box.ROUNDED, show_lines=True)
        ftable.add_column("Sev", justify="center")
        ftable.add_column("Title", overflow="fold")
        ftable.add_column("OWASP")
        for f in result.findings:
            sev = f.severity.value
            st = _SEV_STYLE.get(sev, "white")
            refs = (f.owasp_asi or []) + (getattr(f, "owasp_mcp", None) or [])
            ftable.add_row(f"[{st}]{sev.upper()}[/{st}]", escape(f.title), ", ".join(refs))
        console.print(ftable)

    for n in result.notes:
        console.print(f"[dim]note: {escape(n)}[/dim]")
    console.print()


def discover(
    allowlist: Optional[str] = typer.Option(
        None, "--allowlist", "-a",
        help="Allowlist JSON of approved servers (see data/approved_servers.example.json).",
    ),
    scan: bool = typer.Option(
        False, "--scan",
        help="Also run the local config checks on every server and statically scan servers that "
             "resolve to an npm/PyPI package or GitHub repo (network).",
    ),
    offline: bool = typer.Option(
        False, "--offline", help="With --scan: run only the local config checks, no network.",
    ),
    processes: bool = typer.Option(
        False, "--processes", help="Also list running processes that look like MCP servers (local only).",
    ),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json or md."),
    config: Optional[List[str]] = typer.Option(
        None, "--config", "-c", help="Extra MCP config file to read (repeatable).",
    ),
    no_defaults: bool = typer.Option(
        False, "--no-defaults", help="Read only the --config files, not the known client locations.",
    ),
):
    """Inventory every MCP server configured on this machine (shadow MCP discovery).

    Reads ONLY local MCP client config files (Claude Desktop, Claude Code, Cursor,
    Windsurf, VS Code, Cline, Zed, Gemini CLI, Continue and project-level files)
    and never prints secret values: environment variable values are never read
    into the inventory and credential-like arguments, headers and URL parts are
    shown as [REDACTED].

    Exits with code 1 when --allowlist is given and an unapproved server is found.
    """
    fmt = (fmt or "table").lower()
    if fmt not in ("table", "json", "md", "markdown"):
        print(f"Unknown --format '{fmt}' (use table, json or md)", file=sys.stderr)
        raise typer.Exit(2)

    try:
        result = discover_servers(
            custom_paths=list(config or []),
            allowlist_path=allowlist,
            include_processes=processes,
            include_defaults=not no_defaults,
            scan=scan,
        )
    except (ValueError, OSError) as e:
        print(f"Could not load allowlist: {type(e).__name__}: {e}", file=sys.stderr)
        raise typer.Exit(2)

    if scan and not offline:
        result = asyncio.run(run_static_scans(result))

    if fmt == "json":
        print(result_to_json(result))
    elif fmt in ("md", "markdown"):
        print(result_to_markdown(result))
    elif HAS_RICH:
        _print_rich(result)
    else:
        _print_plain(result)

    if allowlist and result.unapproved:
        raise typer.Exit(1)
