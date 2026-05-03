"""
Bawbel Scanner — CLI display helpers.

All Rich rendering lives here. Command modules call these functions —
they never import Rich directly. This keeps the visual contract in one
place so a redesign only touches this file.
"""

from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from scanner import __version__
from scanner.models import ScanResult
from scanner.scanner import SEVERITY_SCORES
from scanner.cli.shared.constants import (
    OWASP_DESCRIPTIONS,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
)
from scanner.owasp_mcp_map import get_owasp_mcp, OWASP_MCP_DESCRIPTIONS

console = Console()


# ── Severity helpers ──────────────────────────────────────────────────────────


def sev_value(sev) -> str:
    return sev.value if hasattr(sev, "value") else str(sev)


def sev_color(sev) -> str:
    return SEVERITY_COLORS.get(sev_value(sev), "white")


def sev_icon(sev) -> str:
    return SEVERITY_ICONS.get(sev_value(sev), "•")


def worst_severity_score(results: list[ScanResult]) -> int:
    worst = 0
    for r in results:
        if r.max_severity:
            score = SEVERITY_SCORES.get(sev_value(r.max_severity), 0)
            worst = max(worst, score)
    return worst


# ── Banner ────────────────────────────────────────────────────────────────────


def print_banner() -> None:
    console.print()
    console.print(
        f"[bold #1DB894]Bawbel Scanner[/] [dim]v{__version__}[/]  "
        "[dim]·  github.com/bawbel/bawbel-scanner[/]"
    )
    console.print("[dim]" + "━" * 58 + "[/]")
    console.print()


# ── Summary ───────────────────────────────────────────────────────────────────


def print_summary(result: ScanResult) -> None:
    console.print("[dim]" + "─" * 58 + "[/]")
    console.print("[bold white]SUMMARY[/]")
    console.print("[dim]" + "─" * 58 + "[/]")

    max_sev = result.max_severity
    if max_sev:
        color = sev_color(max_sev)
        console.print(
            f"Risk score:   [{color}]" f"{result.risk_score:.1f} / 10  {sev_value(max_sev)}[/]"
        )
    else:
        console.print("Risk score:   [bold #1DB894]0.0 / 10  CLEAN[/]")

    console.print(f"Findings:     [bold]{len(result.findings)}[/]")

    if result.suppressed_findings:
        n = len(result.suppressed_findings)
        console.print(
            f"Suppressed:   [dim]{n}" " (run with [bold]--no-ignore[/bold] to see all)[/]"
        )
    console.print(f"Scan time:    [dim]{result.scan_time_ms}ms[/]")
    console.print()


# ── Scan result panel ─────────────────────────────────────────────────────────


def build_scan_renderables(
    result: ScanResult,
    display_path: str,
    show_report_hint: bool,
) -> list:
    items: list = []

    items.append(
        Text.assemble(
            ("Scanning:  ", "dim"),
            (display_path, "bold white"),
        )
    )
    items.append(
        Text.assemble(
            ("Type:      ", "dim"),
            (result.component_type, "bold white"),
        )
    )

    if result.has_error:
        items.append(Text(""))
        items.append(
            Text.assemble(
                ("✗  Scan error: ", "bold red"),
                (result.error or "", ""),
            )
        )
        items.append(Text("Run with BAWBEL_LOG_LEVEL=DEBUG for details.", style="dim"))
        return items

    items.append(Text(""))

    if result.is_clean:
        items.append(Text("✓  No vulnerabilities found", style="bold #1DB894"))
        items.append(Text("This component passed all AVE checks.", style="dim"))
    else:
        items.append(Text("FINDINGS", style="bold white"))
        for f in result.findings:
            color = sev_color(f.severity)
            sv = sev_value(f.severity)
            icon = sev_icon(f.severity)

            items.append(Text(""))
            items.append(
                Text.assemble(
                    (f"{icon}  ", ""),
                    (sv, color),
                    ("  ", ""),
                    (f.ave_id or "N/A", "bold white"),
                )
            )
            items.append(Text(f"   {f.title}", style="white"))

            if f.line:
                items.append(
                    Text.assemble(
                        (f"   Line {f.line}", "dim"),
                        (f"  {f.match}" if f.match else "", "dim italic"),
                    )
                )
            items.append(
                Text.assemble(
                    ("   Engine: ", "dim"),
                    (f.engine, "dim italic"),
                )
            )
            if f.owasp:
                owasp_str = ", ".join(
                    f"{code} ({OWASP_DESCRIPTIONS.get(code, code)})" for code in f.owasp
                )
                items.append(
                    Text.assemble(
                        ("   OWASP:  ", "dim"),
                        (owasp_str, "dim"),
                    )
                )

            owasp_mcp = get_owasp_mcp(f.ave_id)
            if owasp_mcp:
                mcp_str = ", ".join(
                    f"{code} ({OWASP_MCP_DESCRIPTIONS.get(code, code)})" for code in owasp_mcp
                )
                items.append(
                    Text.assemble(
                        ("   OWASP MCP: ", "dim"),
                        (mcp_str, "dim"),
                    )
                )

    items.append(Text(""))
    items.append(Text("SUMMARY", style="bold white"))

    max_sev = result.max_severity
    if max_sev:
        color = sev_color(max_sev)
        items.append(
            Text.assemble(
                ("Risk score:   ", ""),
                (f"{result.risk_score:.1f} / 10  {sev_value(max_sev)}", color),
            )
        )
    else:
        items.append(Text("Risk score:   0.0 / 10  CLEAN", style="bold #1DB894"))

    items.append(
        Text.assemble(
            ("Findings:     ", ""),
            (str(len(result.findings)), "bold"),
        )
    )

    if result.suppressed_findings:
        n = len(result.suppressed_findings)
        items.append(
            Text.assemble(
                ("Suppressed:   ", ""),
                (f"{n}  (run with --no-ignore to see all)", "dim"),
            )
        )

    items.append(
        Text.assemble(
            ("Scan time:    ", ""),
            (f"{result.scan_time_ms}ms", "dim"),
        )
    )

    if show_report_hint and not result.is_clean:
        items.append(Text(""))
        items.append(
            Text.assemble(
                ("→  Run ", "dim"),
                (f"bawbel report {display_path}", "bold dim"),
                (" for full remediation guide", "dim"),
            )
        )

    return items


def print_scan_result(
    result: ScanResult,
    show_report_hint: bool = True,
    scan_root: Path = None,
) -> None:
    file_path = Path(result.file_path)
    base = scan_root or Path.cwd()
    try:
        display_path = str(file_path.relative_to(base))
    except ValueError:
        display_path = str(file_path)

    border_colors = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim white",
    }
    max_sev = sev_value(result.max_severity) if result.max_severity else None
    border = border_colors.get(max_sev, "#1DB894") if max_sev else "#1DB894"

    renderables = build_scan_renderables(result, display_path, show_report_hint)

    console.print(
        Panel(
            Group(*renderables),
            border_style=border,
            padding=(0, 1),
        )
    )
    console.print()
