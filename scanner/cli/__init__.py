"""
Bawbel Scanner — CLI entry point.

This module is intentionally thin. It:
  1. Defines the Click group
  2. Registers all command modules
  3. Exposes main() for the pyproject.toml console_scripts entry point

Adding a new command:
  1. Create scanner/cli/cmd_<name>.py
  2. Define a @click.command("<name>") in it
  3. Import and add it here — nothing else changes

Commands:
    bawbel scan <path>                  Scan a file or directory
    bawbel scan-server-card <url>       Fetch and scan an MCP server-card
    bawbel ssc <url>                    Alias for scan-server-card
    bawbel scan-conformance <target>    MCP spec conformance scoring
    bawbel conform <target>             Alias for scan-conformance
    bawbel report <path>                Full remediation guide
    bawbel accept <id> <file>           Mark a finding as FP or accepted risk
    bawbel creds <path>                 Scan for hardcoded credentials only
    bawbel chain <path>                 Scan for unsafe delegation chains
    bawbel version                      Version and engine status
    bawbel init                         Initialise project config
    bawbel pin <path>                   Hash skill files -> .bawbel-pins.json
    bawbel check-pins <path>            Check for rug pull drift
    bawbel cp <path>                    Alias for check-pins
"""

import click

from scanner import __version__

# ── Command imports ───────────────────────────────────────────────────────────
from scanner.cli.cmd_scan import scan_cmd
from scanner.cli.cmd_scan_card import scan_server_card_cmd
from scanner.cli.cmd_report import report_cmd
from scanner.cli.cmd_version import version_cmd
from scanner.cli.cmd_init import init_cmd
from scanner.cli.cmd_pin import pin_cmd, check_pins_cmd
from scanner.cli.cmd_scan_conformance import scan_conformance_cmd
from scanner.cli.cmd_accept import accept_cmd
from scanner.cli.cmd_creds import creds_cmd
from scanner.cli.cmd_chain import chain_cmd

# ── CLI group ─────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(
    version=__version__,
    prog_name="Bawbel Scanner",
    message="%(prog)s v%(version)s",
)
def cli() -> None:
    """Bawbel Scanner — agentic AI component security scanner.

    Detects AVE vulnerabilities in SKILL.md files, MCP servers,
    system prompts, and agent plugins before they reach production.

    AVE Standard: github.com/bawbel/bawbel-ave
    """


# Full commands
cli.add_command(scan_cmd)
cli.add_command(scan_server_card_cmd)
cli.add_command(scan_conformance_cmd)
cli.add_command(report_cmd)
cli.add_command(version_cmd)
cli.add_command(init_cmd)
cli.add_command(pin_cmd)
cli.add_command(check_pins_cmd)
cli.add_command(accept_cmd)
cli.add_command(creds_cmd)
cli.add_command(chain_cmd)

# Shortcuts
cli.add_command(scan_server_card_cmd, name="ssc")  # scan-server-card
cli.add_command(scan_conformance_cmd, name="conform")  # scan-conformance
cli.add_command(check_pins_cmd, name="cp")  # check-pins

# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
