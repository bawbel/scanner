"""
Bawbel Scanner - `bawbel accept` command.

J2: Write justified suppression comments to source files.
J3: List accepted findings and show expiry status.
J6: Warn on expiring accepts.

Usage:
    # Mark a finding as a false positive
    bawbel accept AVE-2026-00002 ./skill.md --line 27 \\
      --reason "Documentation example, not active code" \\
      --type false-positive

    # Mark as accepted risk with 90-day expiry
    bawbel accept AVE-2026-00003 ./skill.md --line 14 \\
      --reason "Legitimate API key read for authorized calls" \\
      --type accepted-risk \\
      --expires 90d

    # List all accepted findings
    bawbel accept --list

    # Show findings expiring within 30 days
    bawbel accept --expiring-soon --within 30

    # With PiranhaDB reporting
    bawbel accept AVE-2026-00002 ./skill.md --line 27 \\
      --reason "Documentation example" \\
      --type false-positive \\
      --report
"""

import sys
from datetime import date
from pathlib import Path
from typing import Optional

import click
from rich import box
from rich.panel import Panel
from rich.table import Table

from scanner.cli.shared import console, print_banner
from scanner.utils import resolve_path, is_safe_path
from scanner.suppression.justified import (
    check_expiring_soon,
    parse_accepted_findings,
    send_fp_signal,
)
from scanner.models.acceptance import (
    AcceptedFinding,
    SUPPRESSION_TYPE_FALSE_POSITIVE,
    SUPPRESSION_TYPE_ACCEPTED_RISK,
    parse_expiry,
)

# ── Comment templates ──────────────────────────────────────────────────────────

_FP_TEMPLATE = """\
<!-- bawbel-ignore: {id}
     reason: {reason}
     reviewer: {reviewer}
     reviewed: {reviewed}
-->"""

_AR_TEMPLATE = """\
<!-- bawbel-accept: {id}
     reason: {reason}
     reviewer: {reviewer}
     reviewed: {reviewed}
     expires: {expires}
-->"""


def _build_comment(
    id_str: str,
    stype: str,
    reason: str,
    reviewer: str,
    expires: Optional[str],
    report: bool,
) -> str:
    today = str(date.today())
    report_tag = "\n     report" if report else ""

    if stype == SUPPRESSION_TYPE_FALSE_POSITIVE:
        return (
            _FP_TEMPLATE.format(
                id=id_str,
                reason=reason,
                reviewer=reviewer,
                reviewed=today,
            )
            + report_tag
        )
    else:
        expires_val = expires or "90d"
        try:
            expires_date = str(parse_expiry(expires_val))
        except (ValueError, TypeError):
            expires_date = expires_val
        return (
            _AR_TEMPLATE.format(
                id=id_str,
                reason=reason,
                reviewer=reviewer,
                reviewed=today,
                expires=expires_date,
            )
            + report_tag
        )


def _insert_comment_at_line(
    content: str,
    line_no: int,
    comment: str,
) -> str:
    """
    Insert a comment block ABOVE line_no (1-indexed) in content.
    The comment is inserted as a new block before the target line.
    """
    lines = content.splitlines(keepends=True)
    if line_no < 1 or line_no > len(lines) + 1:
        raise ValueError(f"Line {line_no} out of range (file has {len(lines)} lines)")

    insert_at = line_no - 1  # convert to 0-indexed
    comment_block = comment + "\n"
    lines.insert(insert_at, comment_block)
    return "".join(lines)


def _collect_all_accepted(search_paths: list[Path]) -> list[AcceptedFinding]:
    """Walk paths and collect all AcceptedFinding records from source files."""
    extensions = {".md", ".yaml", ".yml", ".json", ".txt"}
    all_accepted: list[AcceptedFinding] = []

    for base in search_paths:
        if base.is_file():
            files = [base]
        elif base.is_dir():
            files = [p for p in base.rglob("*") if p.suffix.lower() in extensions]
        else:
            continue

        for fp in files:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                accepted = parse_accepted_findings(content, str(fp))
                all_accepted.extend(accepted)
            except OSError:
                continue

    return all_accepted


# ── Main command ───────────────────────────────────────────────────────────────


@click.command("accept")
@click.argument("id_str", default="", required=False)
@click.argument("file_path", default="", required=False)
@click.option(
    "--line",
    "-l",
    type=int,
    default=None,
    help="Line number of the finding (inserts comment above that line)",
)
@click.option(
    "--reason",
    "-r",
    default="",
    help="Human-readable justification (required when marking a finding)",
)
@click.option(
    "--type",
    "stype",
    type=click.Choice(["false-positive", "accepted-risk"], case_sensitive=False),
    default="false-positive",
    show_default=True,
    help="Suppression type: false-positive (permanent) or accepted-risk (with expiry)",
)
@click.option(
    "--expires",
    "-e",
    default=None,
    help="Expiry for accepted-risk: ISO date (2026-08-08) or relative (90d, 3m, 1y)",
)
@click.option(
    "--reviewer",
    default=None,
    help="Reviewer name or GitHub handle (defaults to git config user.name)",
)
@click.option(
    "--report",
    is_flag=True,
    default=False,
    help="Send anonymous FP signal to PiranhaDB (false-positive only)",
)
@click.option(
    "--list",
    "do_list",
    is_flag=True,
    default=False,
    help="List all accepted findings in the current directory",
)
@click.option(
    "--expiring-soon",
    is_flag=True,
    default=False,
    help="Show accepted-risk findings expiring within --within days",
)
@click.option(
    "--within",
    type=int,
    default=30,
    show_default=True,
    help="Days threshold for --expiring-soon",
)
@click.option(
    "--path",
    "search_path",
    default=".",
    help="Directory to search for accepted findings (used with --list / --expiring-soon)",
)
def accept_cmd(
    id_str: str,
    file_path: str,
    line: Optional[int],
    reason: str,
    stype: str,
    expires: Optional[str],
    reviewer: Optional[str],
    report: bool,
    do_list: bool,
    expiring_soon: bool,
    within: int,
    search_path: str,
) -> None:
    """Mark a finding as a false positive or accepted risk.

    Inserts a justified suppression comment directly into the source file.
    The comment is the canonical record - no external database is used.

    Examples:

        bawbel accept AVE-2026-00002 ./skill.md --line 27 \\
          --reason "Documentation example, not active code"

        bawbel accept AVE-2026-00003 ./skill.md --line 14 \\
          --reason "Legitimate API key read" \\
          --type accepted-risk --expires 90d

        bawbel accept --list

        bawbel accept --expiring-soon --within 30
    """
    print_banner()

    # ── --list mode ──────────────────────────────────────────────────────────
    if do_list:
        _cmd_list(Path(search_path))
        return

    # ── --expiring-soon mode ─────────────────────────────────────────────────
    if expiring_soon:
        _cmd_expiring_soon(Path(search_path), within)
        return

    # ── Mark a finding ───────────────────────────────────────────────────────
    if not id_str or not file_path:
        console.print(
            "[red]Usage:[/] bawbel accept <AVE-ID|rule-id> <file> --line N --reason '...'"
        )
        console.print()
        console.print("Or: bawbel accept --list")
        console.print("    bawbel accept --expiring-soon")
        sys.exit(1)

    if not reason:
        console.print("[bold red]Error:[/] --reason is required.")
        console.print("[dim]Provide a justification for why this finding is suppressed.[/]")
        sys.exit(1)

    target, path_err = resolve_path(file_path)
    if path_err:
        console.print(f"[bold red]Error:[/] {path_err}")
        sys.exit(1)
    safe, safe_err = is_safe_path(target)
    if not safe:
        console.print(f"[bold red]Error:[/] {safe_err}")
        sys.exit(1)

    # Resolve reviewer
    if not reviewer:
        try:
            import subprocess  # nosec B404  # noqa: S404

            result = subprocess.run(  # nosec B603 B607  # noqa: S603 S607
                ["git", "config", "user.name"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            reviewer = result.stdout.strip() or "unknown"
        except Exception:  # nosec B110
            reviewer = "unknown"

    # Normalise type
    suppression_type = (
        SUPPRESSION_TYPE_FALSE_POSITIVE
        if stype == "false-positive"
        else SUPPRESSION_TYPE_ACCEPTED_RISK
    )

    # Build comment
    comment = _build_comment(
        id_str=id_str,
        stype=suppression_type,
        reason=reason,
        reviewer=reviewer,
        expires=expires,
        report=report,
    )

    # Read file
    content = target.read_text(encoding="utf-8", errors="ignore")
    line_no = line or 1

    # Insert comment
    try:
        new_content = _insert_comment_at_line(content, line_no, comment)
    except ValueError as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    # Write back
    target.write_text(new_content, encoding="utf-8")

    # ── Output ────────────────────────────────────────────────────────────────
    type_label = (
        "false positive" if suppression_type == SUPPRESSION_TYPE_FALSE_POSITIVE else "accepted risk"
    )
    type_color = "cyan" if suppression_type == SUPPRESSION_TYPE_FALSE_POSITIVE else "yellow"

    console.print(
        Panel(
            f"[bold #{type_color}]{type_label.upper()}[/]  [bold white]{id_str}[/]  "
            f"[dim]line {line_no}[/]\n\n"
            f"[dim]File:[/]      [white]{target.name}[/]\n"
            f"[dim]Reason:[/]    [white]{reason}[/]\n"
            f"[dim]Reviewer:[/]  [white]{reviewer}[/]\n"
            f"[dim]Reviewed:[/]  [white]{date.today()}[/]"
            + (
                f"\n[dim]Expires:[/]   [yellow]{_expiry_str(expires)}[/]"
                if suppression_type == SUPPRESSION_TYPE_ACCEPTED_RISK
                else ""
            ),
            title="[bold]Justified suppression written[/]",
            border_style=(
                "cyan" if suppression_type == SUPPRESSION_TYPE_FALSE_POSITIVE else "yellow"
            ),
            padding=(0, 1),
        )
    )
    console.print()

    # ── FP reporting to PiranhaDB ──────────────────────────────────────────
    if report and suppression_type == SUPPRESSION_TYPE_FALSE_POSITIVE:
        import hashlib
        from scanner.models.acceptance import AcceptedFinding as AF

        af = AF(
            ave_id=id_str if id_str.startswith("AVE-") else None,
            rule_id=id_str if not id_str.startswith("AVE-") else None,
            line=line_no,
            file_path=str(target),
            suppression_type=suppression_type,
            reason=reason,
            reviewer=reviewer,
            report_to_piranha=True,
        )
        match_hash = hashlib.sha256(f"{id_str}:{line_no}:{len(reason)}".encode()).hexdigest()[:16]
        ok = send_fp_signal(af, engine="unknown", confidence=0.9, match_hash=match_hash)
        if ok:
            console.print("[dim]FP signal sent to PiranhaDB.[/]")
        else:
            console.print("[dim]FP signal could not be sent (offline or piranha unavailable).[/]")

    console.print("[dim]Run [bold]bawbel scan[/bold] to verify the finding is now suppressed.[/]")


def _expiry_str(expires: Optional[str]) -> str:
    if not expires:
        return str(parse_expiry("90d"))
    try:
        return str(parse_expiry(expires))
    except (ValueError, TypeError):
        return expires


def _cmd_list(search_path: Path) -> None:
    """--list: show all accepted findings in the tree."""
    accepted = _collect_all_accepted([search_path])
    if not accepted:
        console.print("[dim]No accepted findings found.[/]")
        console.print(
            f"[dim]Search path: {search_path.resolve()}[/]\n"
            "[dim]Use [bold]bawbel accept <ID> <file> --line N --reason '...'[/bold] "
            "to mark findings.[/]"
        )
        return

    table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    table.add_column("File", style="white", no_wrap=False)
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Type", style="dim", no_wrap=True)
    table.add_column("Line", style="dim", no_wrap=True)
    table.add_column("Reviewer", style="dim", no_wrap=True)
    table.add_column("Expires", style="yellow", no_wrap=True)
    table.add_column("Status", no_wrap=True)

    for af in sorted(accepted, key=lambda a: (a.file_path, a.line or 0)):
        path = Path(af.file_path).name
        id_s = af.ave_id or af.rule_id or "?"
        type_s = "FP" if af.suppression_type == SUPPRESSION_TYPE_FALSE_POSITIVE else "AR"

        if af.is_expired:
            status = "[bold red]EXPIRED[/]"
        elif af.is_expiring_soon:
            d = af.days_until_expiry
            status = f"[bold yellow]expires in {d}d[/]"
        else:
            status = "[bold #1DB894]active[/]"

        expires_s = str(af.expires_at) if af.expires_at else "-"
        table.add_row(
            path, id_s, type_s, str(af.line or "-"), af.reviewer or "-", expires_s, status
        )

    console.print(f"[bold]Accepted findings ({len(accepted)})[/]\n")
    console.print(table)

    expired = sum(1 for a in accepted if a.is_expired)
    expiring = sum(1 for a in accepted if a.is_expiring_soon and not a.is_expired)
    if expired:
        console.print(
            f"\n[bold red]{expired} expired finding(s)[/] - run [bold]bawbel scan[/bold] "
            "to see them resurfaced."
        )
    if expiring:
        console.print(
            f"[bold yellow]{expiring} finding(s) expiring soon[/] - " "review and re-accept or fix."
        )


def _cmd_expiring_soon(search_path: Path, within: int) -> None:
    """--expiring-soon: show accepted risks expiring within N days."""
    accepted = _collect_all_accepted([search_path])
    expiring = check_expiring_soon(accepted, warn_within=within)

    if not expiring:
        console.print(f"[bold #1DB894]No accepted-risk findings expiring within {within} days.[/]")
        return

    console.print(
        Panel(
            f"[bold yellow]{len(expiring)} accepted-risk finding(s) "
            f"expiring within {within} days.[/]\n"
            "[dim]Review each finding: did the risk condition change? "
            "Is there a safer alternative?[/]\n"
            "[dim]Re-accept with [bold]bawbel accept <ID> <file> "
            "--type accepted-risk --expires 90d[/bold][/]",
            border_style="yellow",
            padding=(0, 1),
        )
    )
    console.print()

    table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    table.add_column("File", style="white", no_wrap=False)
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Expires", style="yellow", no_wrap=True)
    table.add_column("Days left", style="yellow", no_wrap=True)
    table.add_column("Reviewer", style="dim", no_wrap=True)
    table.add_column("Reason", style="dim", no_wrap=False)

    for af in sorted(expiring, key=lambda a: a.days_until_expiry or 0):
        path = Path(af.file_path).name
        id_s = af.ave_id or af.rule_id or "?"
        days = str(af.days_until_expiry) if af.days_until_expiry is not None else "?"
        reason = (af.reason[:50] + "...") if len(af.reason) > 50 else af.reason
        table.add_row(path, id_s, str(af.expires_at), days, af.reviewer or "-", reason)

    console.print(table)

    # J6: exit 1 for CI
    if any(af.days_until_expiry is not None and af.days_until_expiry <= 14 for af in expiring):
        sys.exit(1)
