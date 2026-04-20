"""
Bawbel Scanner — CLI entry point.

Commands:
    bawbel scan <path>    Scan a component or directory
    bawbel report <path>  Scan and show full remediation guide
    bawbel version        Show version and engine status
"""

import json as _json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from scanner import __version__
from scanner.scanner import scan, SEVERITY_SCORES
from scanner.models import ScanResult

console = Console()

# ── Display constants ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange3",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

OWASP_DESCRIPTIONS = {
    "ASI01": "Prompt Injection",
    "ASI02": "Sensitive Data Exposure",
    "ASI03": "Supply Chain Compromise",
    "ASI04": "Insecure Tool Calls",
    "ASI05": "Unsafe Resource Access",
    "ASI06": "Data Exfiltration",
    "ASI07": "Tool Abuse",
    "ASI08": "Goal Hijacking",
    "ASI09": "Trust Manipulation",
    "ASI10": "Sandbox Escape",
}

REMEDIATION_GUIDE = {
    "bawbel-goal-override": (
        "Remove instructions that attempt to override agent goals. "
        "Legitimate skills do not need to tell an agent to forget prior instructions."
    ),
    "bawbel-jailbreak-instruction": (
        "Remove role-play instructions that tell the agent to act outside its "
        "intended purpose or disable safety constraints."
    ),
    "bawbel-hidden-instruction": (
        "Remove any instructions that tell the agent to hide its behaviour "
        "from the user or operator."
    ),
    "bawbel-external-fetch": (
        "Remove all external URL fetches for instructions. Embed all instructions "
        "directly in the component. Use signed registries for dynamic config."
    ),
    "bawbel-dynamic-tool-call": (
        "Do not construct tool calls from external or user-controlled input. "
        "Validate all tool parameters before execution."
    ),
    "bawbel-permission-escalation": (
        "Remove undeclared permission claims. Declare all required permissions "
        "in the component manifest and request only what is needed."
    ),
    "bawbel-env-exfiltration": (
        "Remove all instructions to read or transmit credentials, .env files, or API keys. "
        "Never include credentials in component outputs."
    ),
    "bawbel-pii-exfiltration": (
        "Remove all instructions to collect or transmit personal data without "
        "explicit user consent and a declared privacy policy."
    ),
    "bawbel-shell-pipe": (
        "Remove shell pipe patterns (curl|bash). If code execution is genuinely "
        "required, use a sandboxed tool with explicit user consent."
    ),
    "bawbel-destructive-command": (
        "Remove all destructive file system commands. "
        "Components should never delete files recursively."
    ),
    "bawbel-crypto-drain": (
        "Remove all wallet or fund transfer instructions. "
        "Financial operations require explicit per-transaction user authorisation."
    ),
    "bawbel-trust-escalation": (
        "Remove claims of special authority or impersonation of trusted parties. "
        "Legitimate components do not need to claim exceptional trust."
    ),
    "bawbel-persistence-attempt": (
        "Remove any instructions to copy the component, modify startup scripts, "
        "or establish persistent access."
    ),
    "bawbel-mcp-tool-poisoning": (
        "Remove instructions embedded in tool descriptions. Tool descriptions should "
        "only describe tool functionality, not give the agent additional tasks."
    ),
    "bawbel-system-prompt-leak": (
        "Remove instructions that attempt to extract the system prompt "
        "or operating configuration."
    ),
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _sev_value(sev) -> str:
    return sev.value if hasattr(sev, "value") else str(sev)


def _sev_color(sev) -> str:
    return SEVERITY_COLORS.get(_sev_value(sev), "white")


def _sev_icon(sev) -> str:
    return SEVERITY_ICONS.get(_sev_value(sev), "•")


def _print_banner() -> None:
    console.print()
    console.print(
        f"[bold #1DB894]Bawbel Scanner[/] [dim]v{__version__}[/]  "
        "[dim]·  github.com/bawbel/bawbel-scanner[/]"
    )
    console.print("[dim]" + "━" * 58 + "[/]")
    console.print()


def _print_findings(result: ScanResult) -> None:
    """Print findings section."""
    console.print("[bold white]FINDINGS[/]")
    console.print("[dim]" + "─" * 58 + "[/]")

    for f in result.findings:
        color = _sev_color(f.severity)
        icon = _sev_icon(f.severity)
        sev = _sev_value(f.severity)

        console.print(
            f"{icon}  [{color}]{sev:8}[/]  "
            f"[bold]{f.ave_id or 'N/A':18}[/]  "
            f"[white]{f.title}[/]"
        )
        if f.line:
            console.print(f"   [dim]Line {f.line}[/]  [dim italic]{f.match or ''}[/]")
        if f.owasp:
            owasp_str = ", ".join(
                f"{code} ({OWASP_DESCRIPTIONS.get(code, code)})" for code in f.owasp
            )
            console.print(f"   [dim]OWASP: {owasp_str}[/]")
        console.print()


def _print_summary(result: ScanResult) -> None:
    """Print summary section."""
    console.print("[dim]" + "─" * 58 + "[/]")
    console.print("[bold white]SUMMARY[/]")
    console.print("[dim]" + "─" * 58 + "[/]")

    max_sev = result.max_severity
    if max_sev:
        color = _sev_color(max_sev)
        console.print(
            f"Risk score:   [{color}]{result.risk_score:.1f} / 10  {_sev_value(max_sev)}[/]"
        )
    else:
        console.print("Risk score:   [bold #1DB894]0.0 / 10  CLEAN[/]")

    console.print(f"Findings:     [bold]{len(result.findings)}[/]")
    console.print(f"Scan time:    [dim]{result.scan_time_ms}ms[/]")
    console.print()


def _print_scan_result(result: ScanResult, show_report_hint: bool = True) -> None:
    """Print a complete scan result in text format."""
    name = Path(result.file_path).name
    console.print(f"[dim]Scanning:[/]  [bold white]{name}[/]")
    console.print(f"[dim]Type:[/]      [bold white]{result.component_type}[/]")
    console.print()

    if result.has_error:
        console.print(f"[bold red]✗  Scan error:[/] {result.error}")
        console.print("[dim]Run with BAWBEL_LOG_LEVEL=DEBUG for details.[/]")
        return

    if result.is_clean:
        console.print(
            Panel(
                "[bold #1DB894]✓  No vulnerabilities found[/]\n"
                "[dim]This component passed all AVE checks.[/]",
                border_style="#1DB894",
                padding=(0, 2),
            )
        )
    else:
        _print_findings(result)

    _print_summary(result)

    if show_report_hint and not result.is_clean:
        console.print(
            f"[dim]→  Run [bold]bawbel report {name}[/bold] " "for full remediation guide[/]"
        )
    console.print()


def _collect_files(path_obj: Path, recursive: bool) -> list[Path]:
    """Collect all scannable files from a path."""
    extensions = [".md", ".json", ".yaml", ".yml", ".txt"]
    if path_obj.is_dir():
        files = []
        for ext in extensions:
            glob = path_obj.rglob if recursive else path_obj.glob
            files.extend(glob(f"*{ext}"))
        return sorted(files)
    return [path_obj]


def _worst_severity_score(results: list[ScanResult]) -> int:
    """Return the highest severity score across all results."""
    worst = 0
    for r in results:
        if r.max_severity:
            score = SEVERITY_SCORES.get(_sev_value(r.max_severity), 0)
            worst = max(worst, score)
    return worst


# ── CLI group ─────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(
    version=__version__,
    prog_name="Bawbel Scanner",
    message="%(prog)s v%(version)s",
)
def cli():
    """Bawbel Scanner — agentic AI component security scanner.

    Detects AVE vulnerabilities in SKILL.md files, MCP servers,
    system prompts, and agent plugins before they reach production.

    AVE Standard: github.com/bawbel/bawbel-ave
    """
    pass


# ── scan command ──────────────────────────────────────────────────────────────


@cli.command("scan")
@click.argument("path", type=click.Path(exists=True))
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
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Scan directory recursively",
)
def scan_cmd(path: str, fmt: str, fail_on_severity: str, recursive: bool) -> None:
    """Scan an agentic AI component for AVE vulnerabilities."""

    path_obj = Path(path)
    files = _collect_files(path_obj, recursive)

    if not files:
        console.print("[yellow]No scannable files found.[/]")
        sys.exit(0)

    results = []
    if fmt == "text":
        _print_banner()

    for f in files:
        result = scan(str(f))
        results.append(result)
        if fmt == "text":
            _print_scan_result(result, show_report_hint=(len(files) == 1))

    if fmt == "json":
        _print_json(results)
    elif fmt == "sarif":
        _print_sarif(results)

    if fail_on_severity:
        threshold = SEVERITY_SCORES.get(fail_on_severity.upper(), 0)
        if _worst_severity_score(results) >= threshold:
            sys.exit(2)

    sys.exit(0)


# ── report command ────────────────────────────────────────────────────────────


@cli.command("report")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format",
)
def report_cmd(path: str, fmt: str) -> None:
    """Scan a component and show a full remediation guide.

    Includes finding details, OWASP mapping, CVSS-AI scores,
    and specific remediation steps for each finding.
    """
    result = scan(path)

    if fmt == "json":
        _print_json([result])
        sys.exit(0 if result.is_clean else 1)

    _print_banner()

    name = Path(result.file_path).name
    console.print(f"[dim]Report for:[/]  [bold white]{name}[/]")
    console.print(f"[dim]Type:[/]        [bold white]{result.component_type}[/]")
    ave_url = "https://github.com/bawbel/bawbel-ave"
    console.print(f"[dim]AVE Standard:[/] [link={ave_url}]github.com/bawbel/bawbel-ave[/link]")
    console.print()

    if result.has_error:
        console.print(f"[bold red]✗  Scan error:[/] {result.error}")
        sys.exit(1)

    if result.is_clean:
        console.print(
            Panel(
                "[bold #1DB894]✓  No vulnerabilities found[/]\n\n"
                "[dim]This component passed all AVE checks.\n"
                "It is safe to install and use.[/]",
                title="[bold #1DB894]Security Report[/]",
                border_style="#1DB894",
                padding=(1, 2),
            )
        )
        _print_summary(result)
        sys.exit(0)

    # ── Findings with remediation ─────────────────────────────────────────────
    console.print("[bold white]VULNERABILITIES FOUND[/]")
    console.print("[dim]" + "─" * 58 + "[/]")
    console.print()

    for i, f in enumerate(result.findings, 1):
        color = _sev_color(f.severity)
        icon = _sev_icon(f.severity)
        sev = _sev_value(f.severity)

        # Heading
        console.print(f"[bold]{i}.[/]  {icon} [{color}]{sev}[/]  [bold white]{f.title}[/]")
        console.print()

        # Details table
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("key", style="dim", no_wrap=True)
        table.add_column("value", style="white")

        if f.ave_id:
            ave_base = "https://github.com/bawbel/bawbel-ave/blob/main/records"
            table.add_row(
                "AVE ID",
                f"[link={ave_base}/{f.ave_id}.md]{f.ave_id}[/link]",
            )
        table.add_row("Rule ID", f.rule_id)
        table.add_row("CVSS-AI", f"{f.cvss_ai:.1f} / 10.0")
        table.add_row("Engine", f.engine)
        if f.line:
            table.add_row("Location", f"Line {f.line}")
        if f.match:
            table.add_row("Matched", f"[italic]{f.match}[/italic]")
        if f.owasp:
            owasp_str = "\n".join(
                f"{code} — {OWASP_DESCRIPTIONS.get(code, code)}" for code in f.owasp
            )
            table.add_row("OWASP", owasp_str)

        console.print(table)

        # Description
        console.print(f"   [bold]What:[/] [dim]{f.description}[/]")
        console.print()

        # Remediation
        remediation = REMEDIATION_GUIDE.get(f.rule_id, "Review and remove this pattern.")
        console.print(
            Panel(
                f"[bold]How to fix:[/]\n{remediation}",
                border_style="yellow",
                padding=(0, 2),
            )
        )
        console.print()

    # ── Summary ───────────────────────────────────────────────────────────────
    _print_summary(result)

    console.print(
        Panel(
            "[bold red]⚠  Do not install this component[/]\n\n"
            "[dim]This component contains patterns associated with known attack "
            "classes.\nReview each finding above and remediate before use.[/]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()
    sys.exit(1)


# ── version command ───────────────────────────────────────────────────────────


@cli.command("version")
def version_cmd() -> None:
    """Show version and detection engine status."""
    _print_banner()

    console.print(f"[bold]Version:[/]  {__version__}")
    console.print()

    # Engine status
    console.print("[bold]Detection Engines:[/]")

    from scanner.engines.pattern import PATTERN_RULES

    console.print(
        f"  [bold #1DB894]✓[/]  Pattern     "
        f"[dim]{len(PATTERN_RULES)} rules  ·  stdlib only  ·  always active[/]"
    )

    try:
        import yara

        console.print(
            f"  [bold #1DB894]✓[/]  YARA        " f"[dim]v{yara.__version__}  ·  active[/]"
        )
    except ImportError:
        console.print(
            "  [dim]✗  YARA        not installed  ·  " 'pip install "bawbel-scanner\\[yara]"[/]'
        )

    try:
        import subprocess  # nosec B404 # noqa: S404

        r = subprocess.run(  # nosec B603 B607 # noqa: S603 S607
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0:
            ver = r.stdout.strip().split()[-1]
            console.print(f"  [bold #1DB894]✓[/]  Semgrep     " f"[dim]v{ver}  ·  active[/]")
        else:
            raise FileNotFoundError
    except Exception:  # noqa: B014
        console.print(
            "  [dim]✗  Semgrep     not installed  ·  " 'pip install "bawbel-scanner\\[semgrep]"[/]'
        )

    try:
        import litellm  # noqa: F401

        llm_installed = True
    except ImportError:
        llm_installed = False

    from scanner.engines.llm_engine import _resolve_model

    active_model = _resolve_model() if llm_installed else None

    if llm_installed and active_model:
        console.print(
            f"  [bold #1DB894]✓[/]  LLM         " f"[dim]{active_model}  ·  Stage 2 active[/]"
        )
    elif llm_installed and not active_model:
        console.print(
            "  [dim]✗  LLM         installed  ·  " "set BAWBEL_LLM_MODEL or a provider API key[/]"
        )
    else:
        console.print(
            "  [dim]✗  LLM         not installed  ·  " r'pip install "bawbel-scanner\[llm]"[/]'
        )

    console.print()
    console.print(
        "[dim]AVE Standard:  "
        "[link=https://github.com/bawbel/bawbel-ave]github.com/bawbel/bawbel-ave[/link][/]"
    )
    console.print("[dim]Documentation: " "[link=https://bawbel.io/docs]bawbel.io/docs[/link][/]")
    console.print()


# ── Output formatters ─────────────────────────────────────────────────────────


def _print_json(results: list[ScanResult]) -> None:
    """Print results as JSON."""
    output = []
    for r in results:
        output.append(
            {
                "file_path": r.file_path,
                "component_type": r.component_type,
                "risk_score": r.risk_score,
                "max_severity": _sev_value(r.max_severity) if r.max_severity else None,
                "scan_time_ms": r.scan_time_ms,
                "has_error": r.has_error,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "ave_id": f.ave_id,
                        "title": f.title,
                        "description": f.description,
                        "severity": _sev_value(f.severity),
                        "cvss_ai": f.cvss_ai,
                        "line": f.line,
                        "match": f.match,
                        "engine": f.engine,
                        "owasp": f.owasp,
                    }
                    for f in r.findings
                ],
            }
        )
    print(_json.dumps(output, indent=2, default=str))


def _print_sarif(results: list[ScanResult]) -> None:
    """Print results as SARIF 2.1.0 (for GitHub Security tab integration)."""
    rules = []
    rule_ids_seen: set[str] = set()
    run_results = []

    for r in results:
        for f in r.findings:
            if f.rule_id not in rule_ids_seen:
                rule_ids_seen.add(f.rule_id)
                rules.append(
                    {
                        "id": f.rule_id,
                        "name": f.rule_id.replace("-", " ").title(),
                        "shortDescription": {"text": f.title},
                        "fullDescription": {"text": f.description},
                        "helpUri": "https://github.com/bawbel/bawbel-ave",
                        "properties": {
                            "tags": f.owasp,
                            "precision": "high",
                            "problem.severity": _sev_value(f.severity).lower(),
                        },
                    }
                )

            run_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": {
                        "CRITICAL": "error",
                        "HIGH": "error",
                        "MEDIUM": "warning",
                        "LOW": "note",
                        "INFO": "none",
                    }.get(_sev_value(f.severity), "warning"),
                    "message": {"text": f.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": r.file_path},
                                "region": {"startLine": f.line or 1},
                            }
                        }
                    ],
                    "properties": {"cvss_ai": f.cvss_ai},
                }
            )

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bawbel-scanner",
                        "version": __version__,
                        "informationUri": "https://bawbel.io",
                        "rules": rules,
                    }
                },
                "results": run_results,
            }
        ],
    }
    print(_json.dumps(sarif, indent=2))


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
