"""
`axiom surface` / `axiom baseline` / `axiom drift` — the Agent Surface Map commands.

    axiom surface ./server            # print the Surface Map (table) and its fingerprint
    axiom surface ./server -o json    # the Map as JSON
    axiom baseline ./server           # store the Map under the server's name
    axiom drift ./server              # diff the current Map against the stored baseline
    axiom drift ./server --against map.json
"""

from __future__ import annotations

import json
import os
from typing import Optional

import typer

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    console: Optional[Console] = Console()
except ImportError:  # pragma: no cover
    console = None

from app.analysis.surface_map import (
    SurfaceMap,
    build_static_map,
    diff_maps,
    list_baselines,
    load_baseline,
    save_baseline,
)


def _build(target: str, name: Optional[str]) -> SurfaceMap:
    if not os.path.exists(target):
        raise typer.BadParameter(f"'{target}' is not a local file or directory")
    return build_static_map(os.path.abspath(target), server_name=name)


def _print_map(m: SurfaceMap) -> None:
    if console is None:
        print(json.dumps(m.to_dict(), indent=2))
        return
    console.print(f"\n[bold]Surface Map[/bold] for [cyan]{m.server.get('name')}[/cyan]  "
                  f"transport={m.server.get('transport')}  auth={m.server.get('auth')}  "
                  f"languages={','.join(m.source.get('languages') or []) or '-'}")
    console.print(f"[bold]fingerprint[/bold] {m.fingerprint}")
    instr = (m.server.get("instructions") or "").strip()
    if instr:
        console.print(f"[bold]instructions[/bold] ({len(instr)} chars): {instr[:160]!r}{'…' if len(instr) > 160 else ''}")
    t = Table(box=box.SIMPLE, show_lines=False)
    t.add_column("tool", style="cyan")
    t.add_column("capabilities")
    t.add_column("params")
    t.add_column("reg")
    t.add_column("where", style="dim")
    for tool in m.tools:
        props = list((tool.input_schema or {}).get("properties", {}).keys())
        t.add_row(tool.name, ", ".join(tool.capabilities) or "-", ", ".join(props)[:60] or "-", tool.registration, tool.location)
    console.print(t)
    if m.resources:
        r = Table(box=box.SIMPLE)
        r.add_column("resource", style="cyan")
        r.add_column("name")
        r.add_column("literals")
        r.add_column("where", style="dim")
        for res in m.resources:
            r.add_row(res.uri, res.name, str(len(res.content_literals)), res.location)
        console.print(r)
    if m.prompts:
        p = Table(box=box.SIMPLE)
        p.add_column("prompt", style="cyan")
        p.add_column("args")
        p.add_column("literals")
        p.add_column("where", style="dim")
        for pr in m.prompts:
            p.add_row(pr.name, ", ".join(a.get("name", "") for a in pr.arguments) or "-", str(len(pr.message_literals)), pr.location)
        console.print(p)
    if m.mutations:
        console.print("[bold yellow]mutations[/bold yellow] (ways the surface can change after approval):")
        for mu in m.mutations:
            console.print(f"  • {mu.kind} {mu.name} {('inside ' + mu.inside + '()') if mu.inside else ''} [dim]{mu.location}[/dim]")


def surface(
    target: str = typer.Argument(..., help="Local server source: a file or a directory"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
    name: str = typer.Option(None, "--name", help="Server name to record (default: package name or directory)"),
):
    """🗺️  Build the Agent Surface Map of a server: everything an agent would see or could call, plus its fingerprint."""
    m = _build(target, name)
    if output == "json":
        print(json.dumps(m.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_map(m)


def baseline(
    target: str = typer.Argument(None, help="Local server source to baseline (omit with --list)"),
    name: str = typer.Option(None, "--name", help="Baseline name (default: server name)"),
    list_: bool = typer.Option(False, "--list", help="List stored baselines"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
):
    """📌 Store a server's Surface Map fingerprint so `axiom drift` can detect changes."""
    if list_:
        rows = list_baselines()
        if output == "json":
            print(json.dumps(rows, indent=2))
        elif console is None or not rows:
            print(json.dumps(rows, indent=2) if rows else "No baselines stored.")
        else:
            t = Table(box=box.SIMPLE)
            t.add_column("name", style="cyan")
            t.add_column("fingerprint")
            t.add_column("tools")
            t.add_column("generated")
            for r in rows:
                t.add_row(r["name"], r["fingerprint"][:16], str(r["tools"]), r["generated_at"])
            console.print(t)
        return
    if not target:
        raise typer.BadParameter("give a target, or --list")
    m = _build(target, name)
    path = save_baseline(m, name)
    if output == "json":
        print(json.dumps({"name": name or m.server.get("name"), "fingerprint": m.fingerprint, "path": path,
                          "tools": len(m.tools), "resources": len(m.resources), "prompts": len(m.prompts)}, indent=2))
    else:
        msg = f"Baseline stored: {path}\nfingerprint {m.fingerprint}  ({len(m.tools)} tools, {len(m.resources)} resources, {len(m.prompts)} prompts)"
        console.print(msg) if console else print(msg)


def drift(
    target: str = typer.Argument(..., help="Local server source to compare"),
    name: str = typer.Option(None, "--name", help="Baseline name (default: server name)"),
    against: str = typer.Option(None, "--against", help="A Surface Map JSON file to compare with instead of a stored baseline"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table or json"),
):
    """🔀 Diff a server's current Surface Map against its baseline. Exit 2 when what the agent sees has changed."""
    current = _build(target, name)
    old = load_baseline(against) if against else load_baseline(name or current.server.get("name") or "")
    if old is None:
        raise typer.BadParameter("no baseline found; run `axiom baseline <target>` first or pass --against <map.json>")
    d = diff_maps(old, current)
    if output == "json":
        print(json.dumps(d, indent=2))
    else:
        out = console.print if console else print
        if not d["changed"]:
            out(f"No drift. fingerprint {current.fingerprint}")
        else:
            out(f"[bold red]Surface changed[/bold red]  {d['old_fingerprint'][:16]} → {d['new_fingerprint'][:16]}" if console
                else f"Surface changed  {d['old_fingerprint'][:16]} -> {d['new_fingerprint'][:16]}")
            if d["instructions_changed"]:
                out("  • server instructions changed")
            for kind in ("tools", "resources", "prompts"):
                for n in d[kind]["added"]:
                    out(f"  + {kind[:-1]} {n}")
                for n in d[kind]["removed"]:
                    out(f"  - {kind[:-1]} {n}")
                for ch in d[kind]["changed"]:
                    out(f"  ~ {kind[:-1]} {ch.get('name') or ch.get('uri')}: {', '.join(ch['fields'])}")
    if d["changed"]:
        raise typer.Exit(2)
