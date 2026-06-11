"""
Bawbel Scanner - `bawbel init` command.

Initialises Bawbel in a project - discovers skill files, generates
.bawbelignore and bawbel.yml.
"""

from pathlib import Path

import click
from rich.panel import Panel

from scanner.cli.shared import console, print_banner
from scanner.utils import resolve_path


@click.command("init")
@click.option(
    "--path",
    "-p",
    default=".",
    help="Project root directory (default: current directory)",
)
def init_cmd(path: str) -> None:
    """Initialise Bawbel Scanner in a project.

    Generates .bawbelignore and bawbel.yml.
    """
    print_banner()
    root, path_err = resolve_path(path)
    if path_err:
        console.print(f"[bold red]✗[/]  {path_err}")
        raise SystemExit(1)
    if not root.is_dir():
        console.print(f"[bold red]✗[/]  Path is not a directory: {root.name}")
        raise SystemExit(1)

    console.print(f"[dim]Initialising Bawbel in[/] [bold white]{root}[/]")
    console.print()

    skill_extensions = {".md", ".yaml", ".yml", ".json", ".txt"}
    skill_indicators = {
        "skill.md",
        "skills.md",
        "system_prompt.md",
        "system_prompt.txt",
        "system_prompt.yaml",
        "agent.md",
        "assistant.md",
        "prompt.md",
    }
    found_skills: list[Path] = []
    found_mcp: list[Path] = []
    found_docs: list[Path] = []

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.startswith(".") for part in p.parts):
            continue
        name = p.name.lower()
        parts = {part.lower() for part in p.relative_to(root).parts}
        doc_segments = {"docs", "doc", "examples", "example", "guides", "guide"}

        if name in skill_indicators or name.endswith((".skill.md", ".skill.yaml")):
            found_skills.append(p)
        elif name.startswith("mcp") and p.suffix in {".json", ".yaml", ".yml"}:
            found_mcp.append(p)
        elif parts & doc_segments and p.suffix in skill_extensions:
            found_docs.append(p)

    if found_skills:
        console.print(f"  [bold #1DB894]✓[/]  Found [bold]{len(found_skills)}[/] skill file(s):")
        for p in found_skills[:5]:
            console.print(f"      [dim]{p.relative_to(root)}[/]")
        if len(found_skills) > 5:
            console.print(f"      [dim]... and {len(found_skills) - 5} more[/]")

    if found_mcp:
        console.print(f"  [bold #1DB894]✓[/]  Found [bold]{len(found_mcp)}[/] MCP manifest(s)")

    if found_docs:
        console.print(
            f"  [dim]ℹ[/]  Found [bold]{len(found_docs)}[/] file(s) in docs/examples "
            "[dim](will be suppressed in .bawbelignore)[/]"
        )

    if not found_skills and not found_mcp:
        console.print(
            "  [yellow]⚠[/]  No skill files found. Bawbel scans any .md/.yaml - "
            "run [bold]bawbel scan . --recursive[/bold] to start."
        )

    console.print()

    ignore_path = root / ".bawbelignore"
    if ignore_path.exists():
        console.print("  [dim]·[/]  .bawbelignore already exists - skipping")
    else:
        ignore_lines = [
            "# .bawbelignore - Bawbel Scanner suppression file",
            "# Files here contain intentional examples of attack patterns.",
            "# Run with --no-ignore to see all findings including suppressed.",
            "",
            "# Documentation",
            "docs/**",
            "doc/**",
            "",
            "# Test fixtures",
            "tests/fixtures/**",
            "test/fixtures/**",
            "",
            "# Example files",
            "examples/**",
            "example/**",
            "",
            "# Generated files",
            ".venv/**",
            "node_modules/**",
            "__pycache__/**",
        ]
        ignore_path.write_text("\n".join(ignore_lines) + "\n")
        console.print(
            f"  [bold #1DB894]✓[/]  Created [bold].bawbelignore[/] "
            f"[dim]({len(ignore_lines)} lines)[/]"
        )

    config_path = root / "bawbel.yml"
    if config_path.exists():
        console.print("  [dim]·[/]  bawbel.yml already exists - skipping")
    else:
        config_lines = [
            "# bawbel.yml - Bawbel Scanner project configuration",
            'version: "1.0"',
            "",
            "scan:",
            "  recursive: true",
            "  fail_on_severity: high     # critical | high | medium | low",
            "  format: text               # text | json | sarif",
            "",
            "confidence:",
            "  threshold: 0.80            # findings below this are suppressed",
            "",
            "# Uncomment to enable Stage 3 behavioral sandbox:",
            "# sandbox:",
            "#   enabled: true",
            "#   image: default",
        ]
        config_path.write_text("\n".join(config_lines) + "\n")
        console.print(
            f"  [bold #1DB894]✓[/]  Created [bold]bawbel.yml[/] "
            f"[dim]({len(config_lines)} lines)[/]"
        )

    console.print()
    total = len(found_skills) + len(found_mcp)
    console.print(
        Panel(
            f"[bold #1DB894]Bawbel initialised.[/]\n\n"
            f"[dim]Found {total} component file(s) to scan.[/]\n\n"
            "Next steps:\n"
            "  [bold]bawbel scan . --recursive[/bold]          "
            "[dim]scan everything[/]\n"
            "  [bold]bawbel scan . --recursive --format sarif[/bold]  "
            "[dim]CI/CD output[/]\n"
            "  [bold]bawbel scan . --no-ignore[/bold]           "
            "[dim]audit mode - see all findings[/]",
            border_style="#1DB894",
            padding=(0, 1),
        )
    )
