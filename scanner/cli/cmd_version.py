"""
Bawbel Scanner - `bawbel version` command.

Prints the scanner version and detection engine status.
"""

import click

from scanner.cli.shared import console, print_banner


@click.command("version")
def version_cmd() -> None:
    """Show version and detection engine status."""
    print_banner()

    from scanner import __version__

    console.print(f"[bold]Version:[/]  {__version__}")
    console.print()
    console.print("[bold]Detection Engines:[/]")

    # Pattern (always available)
    from scanner.engines.pattern_engine import PATTERN_RULES

    console.print(
        f"  [bold #1DB894]✓[/]  Pattern     "
        f"[dim]{len(PATTERN_RULES)} rules  ·  stdlib only  ·  always active[/]"
    )

    # YARA
    try:
        import yara

        console.print(f"  [bold #1DB894]✓[/]  YARA        [dim]v{yara.__version__}  ·  active[/]")
    except ImportError:
        console.print(
            "  [dim]✗  YARA        not installed  ·  " 'pip install "bawbel-scanner\\[yara]"[/]'
        )

    # Semgrep
    try:
        import subprocess  # nosec B404  # noqa: S404

        r = subprocess.run(  # nosec B603 B607  # noqa: S603 S607
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0:
            ver = r.stdout.strip().split()[-1]
            console.print(f"  [bold #1DB894]✓[/]  Semgrep     [dim]v{ver}  ·  active[/]")
        else:
            raise FileNotFoundError
    except Exception:  # noqa: BLE001
        console.print(
            "  [dim]✗  Semgrep     not installed  ·  " 'pip install "bawbel-scanner\\[semgrep]"[/]'
        )

    # LLM
    try:
        import litellm  # noqa: F401

        llm_installed = True
    except ImportError:
        llm_installed = False

    from scanner.engines.llm_engine import _resolve_model

    active_model = _resolve_model() if llm_installed else None

    if llm_installed and active_model:
        console.print(
            f"  [bold #1DB894]✓[/]  LLM         [dim]{active_model}  ·  Stage 2 active[/]"
        )
    elif llm_installed and not active_model:
        console.print(
            "  [dim]✗  LLM         installed  ·  " "set BAWBEL_LLM_MODEL or a provider API key[/]"
        )
    else:
        console.print(
            "  [dim]✗  LLM         not installed  ·  " r'pip install "bawbel-scanner\[llm]"[/]'
        )

    # Sandbox
    from scanner.engines.sandbox_engine import SANDBOX_ENABLED, is_docker_available

    if SANDBOX_ENABLED:
        if is_docker_available():
            console.print("  [bold #1DB894]✓[/]  Sandbox     [dim]active  ·  Docker available[/]")
        else:
            console.print("  [dim]✗  Sandbox     Docker not running  ·  start Docker to enable[/]")
    else:
        console.print(
            "  [dim]✗  Sandbox     disabled  ·  "
            "set BAWBEL_SANDBOX_ENABLED=true to enable Stage 3[/]"
        )

    console.print()
    console.print(
        "[dim]AVE Standard:  "
        "[link=https://github.com/bawbel/ave]"
        "github.com/bawbel/ave[/link][/]"
    )
    console.print("[dim]Documentation: [link=https://bawbel.io/docs]bawbel.io/docs[/link][/]")
    console.print()
