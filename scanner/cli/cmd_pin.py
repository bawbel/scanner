"""
Bawbel Scanner - `bawbel pin` command.

Hashes skill files and MCP manifests and stores the hashes in
.bawbel-pins.json. On subsequent scans with --check-pins, any file
whose hash has drifted is flagged as a rug pull candidate.

Why git-committed pins beat local pins:
    Bawbel stores pins in .bawbel-pins.json committed to the repo -
    visible in git diff, reviewable in PRs, shared automatically with
    every developer who clones the repo.
"""

import sys

import click
from rich.panel import Panel
from rich.table import Table
from rich import box

from scanner.pinner import pin, check_pins, PINS_FILE
from scanner.cli.shared import console, print_banner


@click.command("pin")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--update",
    "-u",
    is_flag=True,
    default=False,
    help="Re-hash and update all pins, including already-pinned files",
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    default=True,
    help="Pin files in subdirectories (default: true)",
)
@click.option(
    "--check",
    is_flag=True,
    default=False,
    help="Check for drift instead of pinning - alias for bawbel check-pins",
)
def pin_cmd(path: str, update: bool, recursive: bool, check: bool) -> None:
    """Hash skill files and save to .bawbel-pins.json.

    Pins are stored in .bawbel-pins.json at the project root.
    Commit this file to git - changes show in diffs and PRs.

    Examples:

        bawbel pin ./skills/                  pin all skill files

        bawbel pin ./skills/ --update         re-hash all, including already pinned

        bawbel pin ./skills/ --check          check for drift (same as bawbel check-pins)

        bawbel scan ./skills/ --check-pins    scan + check for drift in one step
    """
    if check:
        _run_check_pins(path, recursive)
        return

    print_banner()
    console.print(f"[dim]Pinning:[/]  [bold white]{path}[/]")
    if update:
        console.print("[dim]Mode:     update - re-hashing all files[/]")
    console.print()

    result = pin(path, recursive=recursive, update=update)

    if result.pinned:
        console.print(f"[bold #1DB894]✓[/]  Pinned [bold]{len(result.pinned)}[/] file(s):")
        for f in result.pinned[:10]:
            console.print(f"   [dim]{f}[/]")
        if len(result.pinned) > 10:
            console.print(f"   [dim]... and {len(result.pinned) - 10} more[/]")
        console.print()

    if result.unchanged:
        console.print(
            f"[dim]-[/]  [dim]{len(result.unchanged)} file(s) already pinned and unchanged[/]"
        )
        console.print()

    console.print(
        Panel(
            f"[bold #1DB894]Pins saved to {PINS_FILE}[/]\n\n"
            "[dim]Commit this file to git so your team shares the same pins.\n"
            "Any change to a pinned file will show in 'git diff'.[/]\n\n"
            f"  [bold]git add {PINS_FILE}[/]\n"
            f'  [bold]git commit -m "chore: pin skill files"[/]',
            border_style="#1DB894",
            padding=(0, 1),
        )
    )


@click.command("check-pins")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    default=True,
    help="Check files in subdirectories (default: true)",
)
@click.option(
    "--fail-on-drift",
    is_flag=True,
    default=False,
    help="Exit code 2 if any file has drifted from its pin",
)
def check_pins_cmd(path: str, recursive: bool, fail_on_drift: bool) -> None:
    """Check skill files for drift against .bawbel-pins.json.

    Any file whose content has changed since pinning is flagged as
    a rug pull candidate - the tool description may have been modified
    after you audited it.

    Examples:

        bawbel check-pins ./skills/

        bawbel check-pins ./skills/ --fail-on-drift

        bawbel scan ./skills/ --check-pins    scan + check in one step
    """
    _run_check_pins(path, recursive, fail_on_drift=fail_on_drift)


def _run_check_pins(
    path: str,
    recursive: bool,
    fail_on_drift: bool = False,
) -> None:
    """Shared implementation for both check-pins command and pin --check."""
    print_banner()
    console.print(f"[dim]Checking pins:[/]  [bold white]{path}[/]")
    console.print()

    result, err = check_pins(path, recursive=recursive)

    if err:
        console.print(f"[bold red]✗[/]  {err}")
        sys.exit(1)

    if result.changed:
        console.print(f"[bold red]⚠  {len(result.changed)} file(s) have drifted from their pins[/]")
        console.print("[dim]These files changed after you pinned them.[/]")
        console.print("[dim]Review the changes before using these components.[/]")
        console.print()

        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("File", style="bold white", no_wrap=False)
        table.add_column("Pinned hash", style="dim", no_wrap=True)
        table.add_column("Current hash", style="red", no_wrap=True)
        table.add_column("Pinned at", style="dim", no_wrap=True)

        for drift in result.changed:
            table.add_row(
                drift["file"],
                drift["pinned_hash"][:12] + "...",
                drift["current_hash"][:12] + "...",
                drift["pinned_at"][:10],
            )

        console.print(table)
        console.print()
        console.print(
            Panel(
                "[bold]What to do:[/]\n"
                "  1. Review the changes: [bold]git diff[/] or "
                "[bold]bawbel report <file>[/]\n"
                "  2. If the changes are safe: [bold]bawbel pin --update <path>[/]\n"
                "  3. If the changes are malicious: remove the component",
                border_style="red",
                padding=(0, 1),
            )
        )
        console.print()

    if result.new:
        console.print(f"[yellow]ℹ[/]  [yellow]{len(result.new)} new file(s) not yet pinned[/]")
        for f in result.new[:5]:
            console.print(f"   [dim]{f}[/]")
        if len(result.new) > 5:
            console.print(f"   [dim]... and {len(result.new) - 5} more[/]")
        console.print(f"[dim]   Run 'bawbel pin {path}' to pin them.[/]")
        console.print()

    if result.missing:
        console.print(f"[dim]ℹ  {len(result.missing)} pinned file(s) no longer exist[/]")
        for f in result.missing[:5]:
            console.print(f"   [dim]{f}[/]")
        console.print()

    if result.clean and not result.changed:
        console.print(
            f"[bold #1DB894]✓[/]  All [bold]{len(result.clean)}[/] "
            "pinned file(s) match their pins - no drift detected"
        )
        console.print()

    if fail_on_drift and result.changed:
        sys.exit(2)

    sys.exit(0)
