"""
Bawbel Scanner - `bawbel scan` command.

Scans a file or directory for AVE vulnerabilities.
Supports text, JSON, and SARIF output formats.
Supports watch mode (re-scans on every file change).
"""

import sys
from pathlib import Path

import click

from scanner.scanner import scan, SEVERITY_SCORES
from scanner.cli.shared import (
    console,
    print_banner,
    print_scan_result,
    print_json,
    print_sarif,
    worst_severity_score,
)
from scanner.cli.shared.utils import (
    collect_files,
    missing_required_engines,
    parse_required_engines,
)
from scanner.config import EXIT_CODE_ENGINE_MISSING
from scanner.utils import resolve_path


def _engines_option(_ctx: click.Context, _param: click.Parameter, value: str) -> list[str]:
    """Click callback: parse --require-engines, turning an unknown name into a usage error."""
    try:
        return parse_required_engines(value or "")
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


# ── Watch helper ───────────────────────────────────────────────────────────────


def _run_watch(path: str, fmt: str, fail_on_severity: str, recursive: bool) -> None:
    """Watch a path for changes and re-scan on every modification."""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        console.print(
            "[red]watchdog not installed.[/] " 'Run: [bold]pip install "bawbel-scanner\\[watch]"[/]'
        )
        sys.exit(1)

    import time

    path_obj, path_err = resolve_path(path)
    if path_err:
        console.print(f"[bold red]Error:[/] {path_err}")
        sys.exit(1)
    watch_dir = path_obj if path_obj.is_dir() else path_obj.parent

    WATCHED_EXTS = {".md", ".yaml", ".yml", ".json", ".txt"}

    def _do_scan(changed_path: str | None = None) -> None:
        target = changed_path or path
        files = collect_files(Path(target) if changed_path else path_obj, recursive)
        if not files:
            return
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        console.print(f"\n[dim]{ts}[/]  [bold #1DB894]↺[/]  Re-scanning after change...\n")
        results = []
        for f in files:
            result = scan(str(f))
            results.append(result)
            if fmt == "text":
                print_scan_result(result, show_report_hint=False)
        if fmt == "json":
            print_json(results)
        elif fmt == "sarif":
            print_sarif(results)

    class _Handler(FileSystemEventHandler):
        def __init__(self) -> None:
            self._last: float = 0.0

        def on_modified(self, event) -> None:  # type: ignore[override]
            if event.is_directory:
                return
            if Path(event.src_path).suffix.lower() not in WATCHED_EXTS:
                return
            now = time.monotonic()
            if now - self._last < 0.5:
                return
            self._last = now
            _do_scan(event.src_path if path_obj.is_dir() else None)

        on_created = on_modified  # type: ignore[assignment]

    print_banner()
    console.print(f"[bold]Watching:[/]  [white]{path_obj}[/]\n[dim]Press Ctrl+C to stop[/]\n")
    _do_scan()

    observer = Observer()
    observer.schedule(_Handler(), str(watch_dir), recursive=recursive)
    observer.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
        console.print("\n[dim]Watch stopped.[/]")
    finally:
        observer.join()


# ── Command ────────────────────────────────────────────────────────────────────


@click.command("scan")
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
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--watch", "-w", is_flag=True, help="Watch for changes and re-scan")
@click.option(
    "--no-ignore",
    is_flag=True,
    default=False,
    help="Ignore all bawbel-ignore suppressions - audit mode",
)
@click.option(
    "--require-engines",
    "require_engines",
    default="",
    callback=_engines_option,
    metavar="ENGINES",
    help=(
        "Comma-separated engines that must run, for example yara,semgrep. "
        f"Exit {EXIT_CODE_ENGINE_MISSING} if one did not."
    ),
)
def scan_cmd(  # noqa: PLR0913
    path: str,
    fmt: str,
    fail_on_severity: str,
    recursive: bool,
    watch: bool,
    no_ignore: bool,
    require_engines: list[str],
) -> None:
    """Scan an agentic AI component for AVE vulnerabilities."""
    if watch:
        _run_watch(path, fmt, fail_on_severity, recursive)
        return

    path_obj, path_err = resolve_path(path)
    if path_err:
        console.print(f"[bold red]Error:[/] {path_err}")
        sys.exit(1)
    files = collect_files(path_obj, recursive)
    scan_root = Path.cwd()

    if not files:
        console.print("[yellow]No scannable files found.[/]")
        sys.exit(0)

    results = []
    if fmt == "text":
        print_banner()

    for f in files:
        result = scan(str(f), no_ignore=no_ignore)
        results.append(result)
        if fmt == "text":
            print_scan_result(
                result,
                show_report_hint=(len(files) == 1),
                scan_root=scan_root,
            )

    if fmt == "json":
        print_json(results)
    elif fmt == "sarif":
        print_sarif(results)

    # Fails closed: results from a scan that lacked a required engine cannot be trusted, so
    # this takes precedence over the severity threshold.
    missing = missing_required_engines(results, require_engines)
    for engine, reason in missing:
        click.echo(f"bawbel: required engine did not run: {engine} ({reason})", err=True)
    if missing:
        sys.exit(EXIT_CODE_ENGINE_MISSING)

    if fail_on_severity:
        threshold = SEVERITY_SCORES.get(fail_on_severity.upper(), 0)
        if worst_severity_score(results) >= threshold:
            sys.exit(2)

    sys.exit(0)
