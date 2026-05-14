"""
Bawbel Scanner - `bawbel report` command.

Scans a component and renders a full remediation guide - finding details,
OWASP mapping, AIVSS scores, and specific remediation steps.
"""

import sys
from pathlib import Path

import click
from rich import box
from rich.panel import Panel
from rich.table import Table

from scanner.scanner import scan
from scanner.cli.shared import (
    console,
    print_banner,
    print_summary,
    print_json,
    sev_value,
    sev_color,
    sev_icon,
)
from scanner.cli.shared.constants import OWASP_DESCRIPTIONS, REMEDIATION_GUIDE


@click.command("report")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format",
)
def report_cmd(path: str, fmt: str) -> None:
    """Scan a component and show a full remediation guide.

    Includes finding details, OWASP mapping, AIVSS v0.8 scores,
    and specific remediation steps for each finding.
    """
    result = scan(path)

    if fmt == "json":
        print_json([result])
        sys.exit(0 if result.is_clean else 1)

    print_banner()
    name = Path(result.file_path).name
    console.print(f"[dim]Report for:[/]  [bold white]{name}[/]")
    console.print(f"[dim]Type:[/]        [bold white]{result.component_type}[/]")
    console.print(
        "[dim]AVE Standard:[/] "
        "[link=https://github.com/bawbel/ave]"
        "github.com/bawbel/ave[/link]"
    )
    console.print()

    if result.has_error:
        console.print(f"[bold red]✗  Scan error:[/] {result.error}")
        sys.exit(1)

    if result.is_clean:
        console.print(
            Panel(
                "[bold #1DB894]✓  No vulnerabilities found[/]\n\n"
                "[dim]This component passed all AVE checks.\n"
                "It is safe to install and use.[/]",
                title="[bold #1DB894]Security Report[/]",
                border_style="#1DB894",
                padding=(1, 2),
            )
        )
        print_summary(result)
        sys.exit(0)

    console.print("[bold white]VULNERABILITIES FOUND[/]")
    console.print("[dim]" + "-" * 58 + "[/]")
    console.print()

    for i, f in enumerate(result.findings, 1):
        color = sev_color(f.severity)
        icon = sev_icon(f.severity)
        sv = sev_value(f.severity)

        console.print(f"[bold]{i}.[/]  {icon} [{color}]{sv}[/]  [bold white]{f.title}[/]")
        console.print()

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("key", style="dim", no_wrap=True)
        table.add_column("value", style="white")

        if f.ave_id:
            table.add_row(
                "AVE ID",
                (
                    f"[link=https://github.com/bawbel/ave"
                    f"/blob/main/records/{f.ave_id}.md]"
                    f"{f.ave_id}[/link]"
                ),
            )
        table.add_row("Rule ID", f.rule_id)
        table.add_row("AIVSS", f"{f.aivss_score:.1f} / 10.0  (OWASP AIVSS v0.8)")
        table.add_row("Engine", f.engine)
        if f.line:
            table.add_row("Location", f"Line {f.line}")
        if f.match:
            table.add_row("Matched", f"[italic]{f.match}[/italic]")
        if f.owasp:
            owasp_str = "\n".join(
                f"{code} - {OWASP_DESCRIPTIONS.get(code, code)}" for code in f.owasp
            )
            table.add_row("OWASP", owasp_str)
        if f.owasp_mcp:
            from scanner.owasp_mcp_map import OWASP_MCP_DESCRIPTIONS

            mcp_str = "\n".join(
                f"{code} - {OWASP_MCP_DESCRIPTIONS.get(code, code)}" for code in f.owasp_mcp
            )
            table.add_row("OWASP MCP", mcp_str)
        if f.piranha_url:
            table.add_row(
                "PiranhaDB",
                f"[link={f.piranha_url}]{f.piranha_url}[/link]",
            )

        console.print(table)
        console.print(f"   [bold]What:[/] [dim]{f.description}[/]")
        console.print()

        remediation = REMEDIATION_GUIDE.get(f.rule_id, "Review and remove this pattern.")
        console.print(
            Panel(
                f"[bold]How to fix:[/]\n{remediation}",
                border_style="yellow",
                padding=(0, 2),
            )
        )
        console.print()

    print_summary(result)

    console.print(
        Panel(
            "[bold red]⚠  Do not install this component[/]\n\n"
            "[dim]This component contains patterns associated with known attack "
            "classes.\nReview each finding above and remediate before use.[/]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()
    sys.exit(1)
