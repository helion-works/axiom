"""`axiom a2a` — static A2A agent card scanning.

Registered on the main Typer app in cli/axiom_cli.py.
"""

import json
import sys

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

from app.analysis.a2a_scanner import A2AScanError, scan_agent_card
from app.models.schemas import A2AScanResult, FindingSeverity
from app.utils.safe_fetch import SafeFetchError, UnsafeURLError

AUTHORISED_USE = "Only scan agents you own or are authorised to assess."
PASSIVE_NOTE = (
    "Passive only: reads the agent card (plus at most one JWKS and one unauthenticated "
    "extended-card GET); never sends tasks or messages."
)

_SEV_STYLE = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
_RISK_STYLE = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green", "safe": "green bold"}


def _refs(f) -> str:
    return ", ".join((f.owasp_asi or []) + [f"~{r}" for r in (f.related or [])])


def result_to_markdown(result: A2AScanResult) -> str:
    c = result.card
    lines = [
        "# Axiom A2A Agent Card Scan",
        "",
        f"- **Source:** `{result.source}`",
        f"- **Card URL:** {result.final_url or '(local file)'}",
        f"- **Discovery path:** {result.discovery_path_used or '-'}",
        f"- **Protocol version:** {result.protocol_version or 'unknown'}",
        f"- **Risk:** {result.risk_level.value.upper()} ({result.risk_score}/100)",
    ]
    if c:
        lines += [
            f"- **Agent:** {c.name or '?'} {c.version or ''}".rstrip(),
            f"- **Provider:** {c.provider_organization or '-'} ({c.provider_url or '-'})",
            f"- **Skills:** {c.skill_count}",
            f"- **Security schemes:** {', '.join(c.scheme_names) or 'none'}",
            f"- **Signed:** {'yes' if c.signed else 'no'}"
            + ("" if c.signature_verified is None else f" (verified: {'yes' if c.signature_verified else 'NO'})"),
        ]
    lines += ["", "## Findings", ""]
    if result.findings:
        lines += ["| Severity | ID | Title | OWASP ASI | Related (MCP) |", "|---|---|---|---|---|"]
        for f in result.findings:
            title = f.title.replace("|", "\\|")
            lines.append(
                f"| {f.severity.value.upper()} | `{f.id}` | {title} | {', '.join(f.owasp_asi or [])} | "
                f"{', '.join(f.related or [])} |"
            )
        lines += ["", "### Details", ""]
        for f in result.findings:
            lines += [f"**{f.severity.value.upper()} `{f.id}`: {f.title}**", "", f.description, "",
                      f"_Recommendation:_ {f.recommendation}", ""]
    else:
        lines.append("No findings.")
    lines += ["", f"> {result.scope_note}", ""]
    return "\n".join(lines)


def _print_plain(result: A2AScanResult) -> None:
    c = result.card
    print(f"\nA2A agent card scan: {result.source}")
    print(f"  card URL: {result.final_url or '(local file)'}  discovery: {result.discovery_path_used}")
    print(f"  protocol: {result.protocol_version or 'unknown'}  risk: {result.risk_level.value.upper()} "
          f"({result.risk_score}/100)")
    if c:
        print(f"  agent: {c.name} {c.version or ''}  skills: {c.skill_count}  "
              f"schemes: {', '.join(c.scheme_names) or 'none'}  signed: {c.signed}")
    for f in result.findings:
        print(f"  {f.severity.value.upper():8} {f.id}: {f.title}")
    print(f"\n  {result.scope_note}")


def _print_rich(result: A2AScanResult) -> None:
    console = Console()
    c = result.card
    lvl = result.risk_level.value
    st = _RISK_STYLE.get(lvl, "white")
    body = (
        f"[bold]Source:[/bold] {escape(result.source)}\n"
        f"[bold]Card URL:[/bold] {escape(result.final_url or '(local file)')}"
        f"  [bold]Discovery:[/bold] {escape(result.discovery_path_used or '-')}\n"
        f"[bold]Protocol version:[/bold] {escape(result.protocol_version or 'unknown')}\n"
        f"[bold]Risk:[/bold] [{st}]{lvl.upper()} ({result.risk_score}/100)[/{st}]"
    )
    if c:
        sig = "no"
        if c.signed:
            sig = "yes" + ("" if c.signature_verified is None else
                           (" (verified)" if c.signature_verified else " ([red]NOT verified[/red])"))
        body += (
            f"\n[bold]Agent:[/bold] {escape(c.name or '?')} {escape(c.version or '')}"
            f"  [bold]Provider:[/bold] {escape(c.provider_organization or '-')}\n"
            f"[bold]Skills:[/bold] {c.skill_count}  [bold]Schemes:[/bold] "
            f"{escape(', '.join(c.scheme_names) or 'none')}  [bold]Signed:[/bold] {sig}"
        )
    console.print()
    console.print(Panel(body, title="A2A Agent Card Scan (static)", border_style="blue", box=box.HEAVY))
    if result.findings:
        t = Table(title=f"Findings ({len(result.findings)})", box=box.ROUNDED, show_lines=True)
        t.add_column("Sev", justify="center", no_wrap=True)
        t.add_column("ID", overflow="fold")
        t.add_column("Title / detail", overflow="fold")
        t.add_column("OWASP (~MCP)", overflow="fold")
        for f in result.findings:
            s = _SEV_STYLE.get(f.severity.value, "white")
            t.add_row(f"[{s}]{f.severity.value.upper()}[/{s}]", escape(f.id),
                      f"[bold]{escape(f.title)}[/bold]\n{escape(f.description)}", escape(_refs(f)))
        console.print(t)
    else:
        console.print("[green]No findings.[/green]")
    console.print(f"[dim]{escape(result.scope_note)}[/dim]")
    console.print()


def a2a(
    source: str = typer.Argument(..., help="Agent base URL, direct agent card URL, or local card file."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json or md."),
    allow_private: bool = typer.Option(
        False, "--allow-private",
        help="Allow fetching from private/loopback/link-local addresses (e.g. an agent on localhost).",
    ),
):
    """Statically scan an A2A agent card for security issues.

    Only scan agents you own or are authorised to assess.

    Passive only: reads the agent card (plus at most one JWKS and one
    unauthenticated extended-card GET); never sends tasks or messages.

    Exits with code 1 when any HIGH or CRITICAL finding is reported.
    """
    fmt = (fmt or "table").lower()
    if fmt not in ("table", "json", "md", "markdown"):
        print(f"Unknown --format '{fmt}' (use table, json or md)", file=sys.stderr)
        raise typer.Exit(2)

    try:
        result = scan_agent_card(source, allow_private=allow_private)
    except UnsafeURLError as e:
        print(f"Refused: {e}", file=sys.stderr)
        raise typer.Exit(2)
    except (A2AScanError, SafeFetchError, OSError) as e:
        print(f"A2A scan failed: {e}", file=sys.stderr)
        raise typer.Exit(2)

    try:  # card text may contain hidden Unicode; never crash a legacy console on it
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

    if fmt == "json":
        print(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=True))
    elif fmt in ("md", "markdown"):
        print(result_to_markdown(result))
    elif HAS_RICH:
        _print_rich(result)
    else:
        _print_plain(result)

    if any(f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL) for f in result.findings):
        raise typer.Exit(1)
