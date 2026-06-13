"""
Bawbel Scanner - `bawbel chain` command.

Delegation chain scanner. Finds unsafe agent-to-agent delegation
patterns and maps trust boundary violations across a set of skill files.
Output uses the same panel style as bawbel scan.

Usage:
    bawbel chain ./
    bawbel chain ./skills/ --recursive
    bawbel chain ./skill.md --format json
    bawbel chain ./skills/ --fail-on-any
"""

import sys
from pathlib import Path

import click

from scanner.cli.shared import (
    console,
    print_banner,
    print_json,
    print_scan_result,
)
from scanner.cli.shared.utils import collect_files
from scanner.scanner import scan
from scanner.utils import resolve_path

DELEGATION_RULE_IDS = frozenset(
    {
        "bawbel-unsafe-delegation",
        "bawbel-a2a-injection",
        "bawbel-subagent-exfil",
    }
)

DELEGATION_AVE_IDS = frozenset(
    {
        "AVE-2026-00048",
        "AVE-2026-00009",
        "AVE-2026-00012",
    }
)


def _is_delegation_finding(finding) -> bool:
    return finding.rule_id in DELEGATION_RULE_IDS or (
        finding.ave_id is not None and finding.ave_id in DELEGATION_AVE_IDS
    )


@click.command("chain")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    default=False,
    help="Scan directory recursively.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
)
@click.option(
    "--no-ignore",
    "no_ignore",
    is_flag=True,
    default=False,
    help="Disable all suppressions - audit mode.",
)
@click.option(
    "--fail-on-any",
    is_flag=True,
    default=False,
    help="Exit 2 if any delegation finding is found.",
)
def chain_cmd(
    path: str,
    recursive: bool,
    fmt: str,
    no_ignore: bool,
    fail_on_any: bool,
) -> None:
    """Scan for unsafe agent delegation chains.

    Flags trust boundary violations: permission inheritance, unconstrained
    sub-agent spawning, and privilege escalation across delegation chains.

    For a full security scan use: bawbel scan

    Examples:

        bawbel chain ./skills/

        bawbel chain ./skills/ --recursive --format json

        bawbel chain ./skills/ --fail-on-any
    """
    path_obj, path_err = resolve_path(path)
    if path_err:
        console.print(f"[bold red]Error:[/] {path_err}")
        sys.exit(1)
    files = collect_files(path_obj, recursive)

    if not files:
        console.print("[yellow]No scannable files found.[/]")
        sys.exit(0)

    results = []
    has_findings = False

    if fmt == "text":
        print_banner()

    for f in files:
        result = scan(str(f), no_ignore=no_ignore)
        # Filter to delegation findings only - keep suppressed intact for audit
        result.findings = [fi for fi in result.findings if _is_delegation_finding(fi)]
        results.append(result)

        if result.findings:
            has_findings = True

        if fmt == "text":
            print_scan_result(
                result,
                show_report_hint=(len(files) == 1),
                scan_root=Path.cwd(),
            )

    if fmt == "json":
        print_json(results)

    if fail_on_any and has_findings:
        sys.exit(2)
