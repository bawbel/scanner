"""
Bawbel Scanner CLI
Usage: bawbel scan <path>
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from scanner.scanner import scan, Severity, ScanResult

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange3",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def print_banner():
    console.print()
    console.print(
        "[bold #1DB894]Bawbel Scanner[/] [dim]v0.1.0[/]  "
        "[dim]·  github.com/bawbel/bawbel-scanner[/]"
    )
    console.print("[dim]━" * 58 + "[/]")
    console.print()


def print_result(result: ScanResult):
    # File info
    console.print(f"[dim]Scanning:[/]  [bold white]{result.file_path}[/]")
    console.print(f"[dim]Type:[/]      [bold white]{result.component_type}[/]")
    console.print()

    if result.error:
        # Show error code and message — but not internal paths or stack traces
        # Full detail is in logs (BAWBEL_LOG_LEVEL=DEBUG for diagnostics)
        console.print(f"[bold red]✗  Scan error:[/] {result.error}")
        console.print("[dim]For diagnostics: set BAWBEL_LOG_LEVEL=DEBUG[/]")
        return

    if result.is_clean:
        console.print(
            Panel(
                "[bold #1DB894]✓  No vulnerabilities found[/]\n"
                "[dim]This component passed all AVE checks.[/]",
                border_style="#1DB894",
                padding=(0, 2),
            )
        )
    else:
        # Findings table
        console.print("[bold white]FINDINGS[/]")
        console.print("[dim]" + "─" * 58 + "[/]")

        for f in result.findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            color   = SEVERITY_COLORS.get(sev_val, "white")
            icon    = SEVERITY_ICONS.get(sev_val, "•")

            console.print(
                f"{icon}  [{color}]{sev_val:8}[/]  "
                f"[bold]{f.ave_id or 'N/A':18}[/]  "
                f"[white]{f.title}[/]"
            )
            if f.line:
                console.print(f"   [dim]Line {f.line}[/]  [dim italic]{f.match or ''}[/]")
            if f.owasp:
                console.print(f"   [dim]OWASP: {', '.join(f.owasp)}[/]")
            console.print()

    # Summary
    console.print("[dim]" + "─" * 58 + "[/]")
    console.print("[bold white]SUMMARY[/]")
    console.print("[dim]" + "─" * 58 + "[/]")

    risk_score = result.risk_score
    max_sev    = result.max_severity

    if max_sev:
        color = SEVERITY_COLORS.get(max_sev.value if hasattr(max_sev, "value") else str(max_sev), "white")
        console.print(
            f"Risk score:   [{color}]{risk_score:.1f} / 10  {max_sev.value if hasattr(max_sev, 'value') else max_sev}[/]"
        )
    else:
        console.print("Risk score:   [bold #1DB894]0.0 / 10  CLEAN[/]")

    console.print(f"Findings:     [bold]{len(result.findings)}[/]")
    console.print(f"Scan time:    [dim]{result.scan_time_ms}ms[/]")
    console.print()

    if not result.is_clean:
        console.print(
            "[dim]→  Run [bold]bawbel report " +
            result.file_path +
            "[/bold] for full A-BOM and remediation guide[/]"
        )
    console.print()


@click.group()
def cli():
    """Bawbel Scanner — agentic AI component security scanner."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt",
              type=click.Choice(["text", "json"]),
              default="text", show_default=True,
              help="Output format")
@click.option("--fail-on-severity",
              type=click.Choice(["critical", "high", "medium", "low"]),
              default=None,
              help="Exit code 2 if findings at or above this severity")
@click.option("--recursive", "-r", is_flag=True,
              help="Scan directory recursively")
def scan_cmd(path, fmt, fail_on_severity, recursive):
    """Scan an agentic AI component for AVE vulnerabilities."""

    import json as _json

    path_obj = Path(path)
    files = []

    if path_obj.is_dir():
        if recursive:
            for ext in [".md", ".json", ".yaml", ".yml", ".txt"]:
                files.extend(path_obj.rglob(f"*{ext}"))
        else:
            for ext in [".md", ".json", ".yaml", ".yml", ".txt"]:
                files.extend(path_obj.glob(f"*{ext}"))
    else:
        files = [path_obj]

    if not files:
        console.print("[yellow]No scannable files found.[/]")
        sys.exit(0)

    results = []
    worst_severity = 0

    if fmt == "text":
        print_banner()

    for f in files:
        result = scan(str(f))
        results.append(result)

        if fmt == "text":
            print_result(result)
        
        if result.max_severity:
            from scanner.scanner import SEVERITY_SCORES
            score = SEVERITY_SCORES.get(result.max_severity, 0)
            worst_severity = max(worst_severity, score)

    if fmt == "json":
        output = []
        for r in results:
            output.append({
                "file_path":      r.file_path,
                "component_type": r.component_type,
                "risk_score":     r.risk_score,
                "max_severity":   r.max_severity.value if r.max_severity else None,
                "scan_time_ms":   r.scan_time_ms,
                # Include error flag but not full message — may contain paths
                "has_error":      r.error is not None,
                "findings": [
                    {
                        "rule_id":  f.rule_id,
                        "ave_id":   f.ave_id,
                        "title":    f.title,
                        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                        "cvss_ai":  f.cvss_ai,
                        "line":     f.line,
                        "match":    f.match,
                        "engine":   f.engine,
                        "owasp":    f.owasp,
                    }
                    for f in r.findings
                ],
            })
        print(_json.dumps(output, indent=2, default=str))

    # Exit codes
    if fail_on_severity:
        from scanner.scanner import SEVERITY_SCORES
        threshold = SEVERITY_SCORES.get(fail_on_severity.upper(), 0)
        if worst_severity >= threshold:
            sys.exit(2)

    sys.exit(0)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def report(path):
    """Generate a full A-BOM report for a component."""
    print_banner()
    result = scan(path)
    print_result(result)
    console.print(
        "[dim]Full A-BOM report generation coming in v0.2.0[/]"
    )


# Entry point alias: bawbel scan → bawbel_scan
def main():
    cli()


if __name__ == "__main__":
    main()
