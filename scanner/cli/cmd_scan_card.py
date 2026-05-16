"""
Bawbel Scanner - `bawbel scan-server-card` command.

Fetches an MCP server-card from a URL and scans it for AVE vulnerabilities.

The server-card is fetched from:
    <URL>/.well-known/mcp-server-card/server.json

All tool descriptions, parameter descriptions, and config schemas
are extracted and scanned using the full detection pipeline.
"""

import sys

import click

from scanner.scanner import scan, SEVERITY_SCORES
from scanner.fetcher import fetch_server_card, build_server_card_url, write_temp_scan_file
from scanner.cli.shared import (
    console,
    print_banner,
    print_scan_result,
    print_json,
    print_sarif,
    worst_severity_score,
)


@click.command("scan-server-card")
@click.argument("url")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    show_default=True,
    help="Output format",
)
@click.option(
    "--fail-on-severity",
    "fail_on_severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Exit code 2 if findings at or above this severity",
)
def scan_server_card_cmd(url: str, fmt: str, fail_on_severity: str) -> None:
    """Fetch and scan an MCP server-card for AVE vulnerabilities.

    Fetches the server-card from:

        <URL>/.well-known/mcp-server-card/server.json

    Scans all tool descriptions, parameter descriptions, and config
    schemas using the full detection pipeline.

    Examples:

        bawbel scan-server-card https://api.example.com

        bawbel scan-server-card https://api.example.com --format json

        bawbel scan-server-card https://api.example.com --fail-on-severity high
    """
    if fmt == "text":
        print_banner()
        card_url = build_server_card_url(url)
        console.print(f"[dim]Fetching:[/]  [bold white]{card_url}[/]")
        console.print()

    content, err = fetch_server_card(url)
    if err:
        if fmt == "text":
            console.print(
                f"[bold red]✗  Fetch failed:[/] {err}\n\n"
                "[dim]Check that the server exposes a server-card at:\n"
                f"  {build_server_card_url(url)}[/]"
            )
        else:
            import json as _json

            print(_json.dumps([{"error": err, "url": url}], indent=2))
        sys.exit(1)

    tmp_path = write_temp_scan_file(content)
    try:
        result = scan(str(tmp_path))
        result.file_path = url
    finally:
        tmp_path.unlink(missing_ok=True)

    if fmt == "json":
        print_json([result])
    elif fmt == "sarif":
        print_sarif([result])
    else:
        print_scan_result(result, show_report_hint=True, scan_root=None)
        console.print(f"[dim]Source:  {build_server_card_url(url)}[/]")
        console.print()

    if fail_on_severity:
        threshold = SEVERITY_SCORES.get(fail_on_severity.upper(), 0)
        if worst_severity_score([result]) >= threshold:
            sys.exit(2)

    sys.exit(0)
