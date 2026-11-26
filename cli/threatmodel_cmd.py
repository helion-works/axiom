"""`axiom threatmodel` - generate a threat model from scan / discovery / A2A sources.

Registered on the main Typer app in cli/axiom_cli.py.
"""

import asyncio
import json
import sys
from typing import Any, List, Optional

import typer

try:
    from rich.console import Console
    from rich.table import Table
    from rich.markup import escape
    from rich import box
    HAS_RICH = True
except ImportError:  # pragma: no cover - rich is a hard dependency, but mirror the CLI guard
    HAS_RICH = False

from app.analysis.threat_model import build_threat_model, render_json, render_markdown
from app.analysis.threat_model.render import FRAMEWORKS

_BAND_STYLE = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan"}


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def _run_scan(target: str) -> dict:
    from app.analysis.engine import engine
    url = None
    if target.startswith("http"):
        url = target
        target = target.rstrip("/").split("/")[-1]
    return asyncio.run(engine.scan(target, url))


def _load_a2a(source: str) -> Any:
    """A2A scan of a card file or URL; falls back to reading a saved JSON result."""
    try:
        from app.analysis.a2a_scanner import scan_agent_card
    except ImportError:  # pragma: no cover - A2A workstream not installed
        scan_agent_card = None
    if source.lower().startswith(("http://", "https://")):
        if scan_agent_card is None:
            raise ValueError("A2A scanning is not available in this installation")
        return scan_agent_card(source)
    data = _load_json_file(source)
    # A saved A2AScanResult / duck-typed dict / raw card are all understood by from_a2a.
    return data


def _summary(result: dict, output: Optional[str]) -> None:
    threats = result["threats"]
    bands = result["coverage"]["risk_bands"]
    line = (f"Threat model: {len(threats)} threats (critical {bands['critical']}, high {bands['high']}, "
            f"medium {bands['medium']}, low {bands['low']}), {len(result['attack_paths'])} attack paths")
    if not HAS_RICH:
        _err(line + (f" -> {output}" if output else ""))
        return
    console = Console(stderr=True)
    if not threats:
        console.print(line)
        if output:
            console.print(f"[green]Written to {escape(output)}[/green]")
        return
    table = Table(title=line, box=box.ROUNDED, show_lines=False)
    table.add_column("ID", no_wrap=True)
    table.add_column("Threat", overflow="fold")
    table.add_column("Risk", justify="right")
    for t in threats[:10]:
        st = _BAND_STYLE.get(t["risk_band"], "white")
        table.add_row(escape(t["id"]), escape(t["title"]), f"[{st}]{t['risk']} {t['risk_band']}[/{st}]")
    console.print(table)
    if len(threats) > 10:
        console.print(f"[dim]... {len(threats) - 10} more in the report[/dim]")
    if output:
        console.print(f"[green]Written to {escape(output)}[/green]")


def threatmodel(
    target: Optional[str] = typer.Argument(
        None, help="MCP server to statically scan first (GitHub URL, npm or PyPI package; network).",
    ),
    from_scan: Optional[List[str]] = typer.Option(
        None, "--from-scan", help="Saved scan JSON (ScanResponse / `axiom scan -o json`). Repeatable.",
    ),
    from_discover: bool = typer.Option(
        False, "--from-discover", help="Run local MCP client config discovery (no network).",
    ),
    from_a2a: Optional[List[str]] = typer.Option(
        None, "--from-a2a", help="A2A agent card file or URL (or a saved a2a scan JSON). Repeatable.",
    ),
    framework: str = typer.Option("both", "--framework", help="Tagging shown in Markdown: maestro, stride or both."),
    ai: bool = typer.Option(
        False, "--ai", help="Ask Claude for extra threats (needs ANTHROPIC_API_KEY; sends only the sanitised system model).",
    ),
    fmt: str = typer.Option("md", "--format", "-f", help="Output format: md or json."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write the report to this file."),
    allowlist: Optional[str] = typer.Option(None, "--allowlist", "-a", help="With --from-discover: allowlist JSON."),
    config: Optional[List[str]] = typer.Option(
        None, "--config", "-c", help="With --from-discover: extra MCP config file to read (repeatable).",
    ),
    no_defaults: bool = typer.Option(
        False, "--no-defaults", help="With --from-discover: read only the --config files.",
    ),
):
    """Generate a threat model (STRIDE + CSA MAESTRO, OWASP ASI/MCP tagged) for an agentic system.

    Sources can be combined and are merged into one system model.

    Examples:

        axiom threatmodel --from-scan scan.json

        axiom threatmodel https://github.com/user/mcp-server

        axiom threatmodel --from-discover --allowlist approved.json

        axiom threatmodel --from-scan scan.json --from-a2a https://agent.example.com

    Threats come from a deterministic rule catalogue (data/threat_catalogue.json); the
    same input gives byte-identical output. --ai adds clearly separated AI suggestions.
    """
    fmt = (fmt or "md").lower()
    if fmt == "markdown":
        fmt = "md"
    if fmt not in ("md", "json"):
        _err(f"Unknown --format '{fmt}' (use md or json)")
        raise typer.Exit(2)
    framework = (framework or "both").lower()
    if framework not in FRAMEWORKS:
        _err(f"Unknown --framework '{framework}' (use maestro, stride or both)")
        raise typer.Exit(2)

    scans: List[Any] = []
    discoveries: List[Any] = []
    a2a_results: List[Any] = []
    try:
        for path in from_scan or []:
            scans.append(_load_json_file(path))
        if target:
            scans.append(_run_scan(target))
        if from_discover:
            from app.analysis.discovery import discover_servers
            discoveries.append(discover_servers(
                custom_paths=list(config or []),
                allowlist_path=allowlist,
                include_defaults=not no_defaults,
            ))
        for src in from_a2a or []:
            a2a_results.append(_load_a2a(src))
    except (OSError, ValueError) as e:
        _err(f"Could not load a source: {type(e).__name__}: {e}")
        raise typer.Exit(2)
    except Exception as e:  # scanner / network errors
        _err(f"Source failed: {type(e).__name__}: {e}")
        raise typer.Exit(2)

    if not (scans or discoveries or a2a_results):
        _err("No source given. Use TARGET, --from-scan, --from-discover and/or --from-a2a.")
        raise typer.Exit(2)

    result = build_threat_model(scans, discoveries, a2a_results, ai=ai)
    text = render_json(result) if fmt == "json" else render_markdown(result, framework)

    if output:
        with open(output, "w", encoding="utf-8", newline="\n") as f:
            f.write(text if text.endswith("\n") else text + "\n")
        _summary(result, output)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
