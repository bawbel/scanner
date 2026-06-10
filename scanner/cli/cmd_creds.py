"""
Bawbel Scanner - `bawbel creds` command.

Credential-focused scan. Filters to AVE-2026-00047 and related
credential rules only. Output uses the same panel style as bawbel scan.

Usage:
    bawbel creds ./
    bawbel creds ./skills/ --recursive
    bawbel creds ./skill.md --format json
    bawbel creds ./skills/ --fail-on-any
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

CREDENTIAL_RULE_IDS = frozenset(
    {
        "bawbel-hardcoded-credential",
    }
)

CREDENTIAL_AVE_IDS = frozenset(
    {
        "AVE-2026-00047",
    }
)


def _is_cred_finding(finding) -> bool:
    return finding.rule_id in CREDENTIAL_RULE_IDS or (
        finding.ave_id is not None and finding.ave_id in CREDENTIAL_AVE_IDS
    )


@click.command("creds")
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
    help="Exit 2 if any credential finding is found.",
)
def creds_cmd(
    path: str,
    recursive: bool,
    fmt: str,
    no_ignore: bool,
    fail_on_any: bool,
) -> None:
    """Scan for hardcoded credentials in agent components.

    Filters to credential-related AVE rules only.
    For a full security scan use: bawbel scan

    Examples:

        bawbel creds ./skills/

        bawbel creds ./skills/ --recursive --format json

        bawbel creds ./skills/ --fail-on-any
    """
    path_obj = Path(path).resolve()
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
        # Filter to credential findings only - keep suppressed intact for audit
        result.findings = [fi for fi in result.findings if _is_cred_finding(fi)]
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
