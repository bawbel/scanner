"""
Bawbel Scanner - `bawbel scan-conformance` command.

Scores an MCP server manifest against the MCP spec and returns
a conformance report with grade A+-F and per-check results.

Sources:
    Local file:     bawbel scan-conformance ./server.json
    Server-card:    bawbel scan-conformance https://api.example.com
    Registry entry: bawbel scan-conformance --registry ac.inference.sh/mcp
"""

import json
import sys

import click
from rich import box
from rich.panel import Panel
from rich.table import Table

from scanner.conformance import score_conformance, CheckStatus, CheckCategory
from scanner.cli.shared import console, print_banner

# ── Grade colours ──────────────────────────────────────────────────────────────

_GRADE_COLORS = {
    "A+": "bold #1DB894",
    "A": "bold #1DB894",
    "B": "bold cyan",
    "C": "bold yellow",
    "D": "bold orange3",
    "F": "bold red",
}

_STATUS_ICONS = {
    CheckStatus.PASS: ("✓", "bold #1DB894"),
    CheckStatus.FAIL: ("✗", "bold red"),
    CheckStatus.WARN: ("~", "bold yellow"),
    CheckStatus.SKIP: ("-", "dim"),
}

_CATEGORY_LABELS = {
    CheckCategory.REQUIRED: "REQUIRED",
    CheckCategory.RECOMMENDED: "RECOMMENDED",
    CheckCategory.BEST_PRACTICE: "BEST PRACTICE",
}


# ── Loaders ────────────────────────────────────────────────────────────────────


def _load_from_file(path: str) -> tuple[dict | None, str | None]:
    """Load manifest from a local JSON file."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, f"File not found: {path}"
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"


def _load_from_url(url: str) -> tuple[dict | None, str | None]:
    """Load manifest from a server-card URL."""
    from scanner.fetcher import fetch_url, build_server_card_url

    card_url = build_server_card_url(url)
    return fetch_url(card_url)


def _load_from_registry(server_name: str) -> tuple[dict | None, str | None]:
    """Load manifest from the official MCP registry by server name."""
    try:
        import urllib.request
        import urllib.parse

        slug = urllib.parse.quote(server_name, safe="")
        url = f"https://registry.modelcontextprotocol.io/v0/servers/{slug}"
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "bawbel-scanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310  # noqa: S310
            data = json.loads(r.read())
            return data.get("server", data), None
    except Exception as e:  # noqa: BLE001
        return None, f"Registry lookup failed: {e}"


# ── Command ────────────────────────────────────────────────────────────────────


@click.command("scan-conformance")
@click.argument("target")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format",
)
@click.option(
    "--registry",
    "from_registry",
    is_flag=True,
    default=False,
    help="Look up TARGET as a name in the official MCP registry",
)
@click.option(
    "--fail-below",
    "fail_below",
    type=int,
    default=None,
    help="Exit code 2 if score is below this threshold (0-100)",
)
@click.option(
    "--fail-non-conformant",
    is_flag=True,
    default=False,
    help="Exit code 2 if any REQUIRED check fails",
)
def scan_conformance_cmd(
    target: str,
    fmt: str,
    from_registry: bool,
    fail_below: int | None,
    fail_non_conformant: bool,
) -> None:
    """Score an MCP server manifest against the MCP specification.

    TARGET can be:
        A local JSON file:    ./server.json
        A server base URL:    https://api.example.com
        A registry name:      ac.inference.sh/mcp  (use --registry)

    Examples:

        bawbel scan-conformance ./mcp-manifest.json

        bawbel scan-conformance https://api.example.com

        bawbel scan-conformance ac.inference.sh/mcp --registry

        bawbel scan-conformance https://api.example.com --format json

        bawbel scan-conformance https://api.example.com --fail-below 80
    """
    if fmt == "text":
        print_banner()

    manifest: dict | None = None
    err: str | None = None

    if from_registry:
        if fmt == "text":
            console.print(f"[dim]Registry lookup:[/]  [bold white]{target}[/]")
            console.print()
        manifest, err = _load_from_registry(target)

    elif target.startswith("http://") or target.startswith("https://"):
        if fmt == "text":
            console.print(f"[dim]Fetching:[/]  [bold white]{target}[/]")
            console.print()
        manifest, err = _load_from_url(target)

    else:
        if fmt == "text":
            console.print(f"[dim]Loading:[/]  [bold white]{target}[/]")
            console.print()
        manifest, err = _load_from_file(target)

    if err or manifest is None:
        if fmt == "json":
            print(json.dumps({"error": err or "unknown", "target": target}, indent=2))
        else:
            console.print(f"[bold red]✗  Failed to load manifest:[/] {err}")
        sys.exit(1)

    report = score_conformance(manifest)

    if fmt == "json":
        print(
            json.dumps(
                {"target": target, "conformance": report.to_dict()},
                indent=2,
            )
        )
    else:
        _print_report(report, target)

    if fail_non_conformant and not report.is_conformant:
        sys.exit(2)
    if fail_below is not None and report.score < fail_below:
        sys.exit(2)

    sys.exit(0)


def _print_report(report, target: str) -> None:
    grade_color = _GRADE_COLORS.get(report.grade, "white")

    conformant_str = (
        "[bold #1DB894]✓ CONFORMANT[/]" if report.is_conformant else "[bold red]✗ NON-CONFORMANT[/]"
    )

    console.print(
        Panel(
            f"[dim]Target:[/]     [bold white]{target}[/]\n"
            f"[dim]Score:[/]      [{grade_color}]{report.score:.1f} / 100  "
            f"Grade {report.grade}[/]\n"
            f"[dim]Status:[/]     {conformant_str}\n"
            f"[dim]Checks:[/]     "
            f"[bold #1DB894]{report.passed} passed[/]  "
            f"[bold red]{report.failed} failed[/]  "
            f"[bold yellow]{report.warned} warned[/]  "
            f"[dim]{report.skipped} skipped[/]",
            title="[bold]MCP Spec Conformance[/]",
            border_style=grade_color,
            padding=(0, 1),
        )
    )
    console.print()

    table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    table.add_column("", width=2, no_wrap=True)
    table.add_column("Check", style="white", no_wrap=False)
    table.add_column("Category", style="dim", no_wrap=True)
    table.add_column("Detail", style="dim", no_wrap=False)

    for r in report.results:
        icon, color = _STATUS_ICONS[r.status]
        label = _CATEGORY_LABELS[r.check.category]
        detail = (
            r.message
            if r.message
            else (r.check.remediation if r.status == CheckStatus.FAIL else "")
        )
        table.add_row(
            f"[{color}]{icon}[/]",
            r.check.title,
            label,
            detail[:80] + ("..." if len(detail) > 80 else ""),
        )

    console.print(table)

    if not report.is_conformant:
        console.print()
        failed_required = [
            r
            for r in report.results
            if r.status == CheckStatus.FAIL and r.check.category == CheckCategory.REQUIRED
        ]
        items = "\n".join(
            f"  [bold]{r.check.title}[/]\n  [dim]{r.check.remediation}[/]" for r in failed_required
        )
        console.print(
            Panel(
                f"[bold red]This server does not conform to the MCP specification.[/]\n\n"
                f"[dim]Fix these required checks:[/]\n\n{items}",
                border_style="red",
                padding=(0, 1),
            )
        )
