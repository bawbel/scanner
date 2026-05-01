#!/usr/bin/env python3
"""
scan_mcp_registry.py — Bawbel scanner for the official MCP Registry

Fetches servers from registry.modelcontextprotocol.io and scans
their descriptions, titles, and remote URLs for AVE vulnerabilities.

Usage:
    pip install "bawbel-scanner[all]" requests
    python scan_mcp_registry.py --limit 100 --output results.json
    python scan_mcp_registry.py --limit 50 --latest-only

Requirements:
    pip install requests bawbel-scanner
"""

import argparse
import json
import subprocess  # nosec B404  # noqa: S404
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────

REGISTRY_BASE = "https://registry.modelcontextprotocol.io"
RATE_LIMIT_SLEEP = 0.3  # seconds between requests

# ── Registry API ──────────────────────────────────────────────────────────────


def list_servers(
    limit: int = 10,
    cursor: str = "",
    latest_only: bool = True,
) -> dict:
    """
    Fetch a page of servers from the official MCP registry.

    Returns dict with keys: servers, metadata (nextCursor, count)
    """
    params: dict = {"limit": min(limit, 100)}
    if cursor:
        params["cursor"] = cursor
    if latest_only:
        params["isLatest"] = "true"

    resp = requests.get(
        f"{REGISTRY_BASE}/v0/servers",
        params=params,
        headers={"Accept": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# ── Content builder ───────────────────────────────────────────────────────────


def build_scan_content(entry: dict) -> str:
    """
    Build a scannable text representation of one MCP registry entry.

    The registry schema (2025-12-11) exposes:
      server.name        — qualified name (e.g. "ac.inference.sh/mcp")
      server.title       — display title
      server.description — primary attack surface
      server.remotes     — list of {type, url} transport endpoints
      server.repository  — source repo URL
    """
    server = entry.get("server", {})
    lines: list[str] = []

    name = server.get("name", "unknown")
    title = server.get("title", "")
    lines.append(f"# MCP Server: {name}")
    if title and title != name:
        lines.append(f"# Title: {title}")
    lines.append("")

    # Description — primary attack surface
    desc = server.get("description", "")
    if desc:
        lines.append("## Description")
        lines.append(desc)
        lines.append("")

    # Remote endpoints
    remotes = server.get("remotes", [])
    if remotes:
        lines.append("## Remote endpoints")
        for r in remotes:
            rtype = r.get("type", "")
            rurl = r.get("url", "")
            lines.append(f"  {rtype}: {rurl}")
        lines.append("")

    # Repository
    repo = server.get("repository", {})
    if isinstance(repo, dict) and repo.get("url"):
        lines.append(f"## Repository: {repo['url']}")
        lines.append("")

    # Website
    website = server.get("websiteUrl", "")
    if website:
        lines.append(f"## Website: {website}")

    return "\n".join(lines)


# ── Scanner ───────────────────────────────────────────────────────────────────


def scan_entry(entry: dict) -> dict:
    """Run bawbel scan on one registry entry. Returns scan result dict."""
    server = entry.get("server", {})
    name = server.get("name", "unknown")
    ver = server.get("version", "")
    content = build_scan_content(entry)

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".md",
        prefix="bawbel_mcp_",
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        result = subprocess.run(  # nosec B603 B607  # noqa: S603 S607
            ["bawbel", "scan", tmp_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        raw = result.stdout.strip()
        if not raw:
            return {
                "server": name,
                "version": ver,
                "error": result.stderr.strip() or "no output",
                "findings": [],
                "risk_score": 0,
            }

        json_start = raw.find("[")
        if json_start < 0:
            return {
                "server": name,
                "version": ver,
                "error": raw[:200],
                "findings": [],
                "risk_score": 0,
            }

        scan_results = json.loads(raw[json_start:])
        if scan_results:
            r = scan_results[0]
            return {
                "server": name,
                "version": ver,
                "title": server.get("title", ""),
                "description": server.get("description", "")[:200],
                "remotes": server.get("remotes", []),
                "findings": r.get("findings", []),
                "risk_score": r.get("risk_score", 0),
                "max_severity": r.get("max_severity", ""),
                "scan_time_ms": r.get("scan_time_ms", 0),
                "error": None,
            }
        return {"server": name, "version": ver, "findings": [], "risk_score": 0, "error": None}

    except subprocess.TimeoutExpired:
        return {"server": name, "version": ver, "error": "timeout", "findings": [], "risk_score": 0}
    except json.JSONDecodeError as e:
        return {
            "server": name,
            "version": ver,
            "error": f"parse: {e}",
            "findings": [],
            "risk_score": 0,
        }
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan official MCP registry servers for AVE vulnerabilities"
    )
    parser.add_argument("--limit", type=int, default=50, help="Max servers to scan (default: 50)")
    parser.add_argument(
        "--latest-only",
        action="store_true",
        default=True,
        help="Only scan latest version of each server (default: true)",
    )
    parser.add_argument(
        "--all-versions",
        action="store_true",
        default=False,
        help="Scan all versions, not just latest",
    )
    parser.add_argument("--output", type=str, default="", help="Save results to JSON file")
    parser.add_argument("--verbose", action="store_true", help="Print scan content for each server")
    args = parser.parse_args()

    latest_only = not args.all_versions

    print("Bawbel MCP Registry Scanner")
    print(f"Source:  {REGISTRY_BASE}/v0/servers")
    print(f"Limit:   {args.limit} servers")
    print(f"Mode:    {'latest versions only' if latest_only else 'all versions'}")
    print("─" * 60)

    # Collect entries via cursor pagination
    entries: list[dict] = []
    cursor: str = ""
    page: int = 1

    while len(entries) < args.limit:
        batch_size = min(100, args.limit - len(entries))
        try:
            data = list_servers(
                limit=batch_size,
                cursor=cursor,
                latest_only=latest_only,
            )
        except requests.HTTPError as e:
            print(f"Registry API error: {e}")
            sys.exit(1)

        batch = data.get("servers", [])
        if not batch:
            break

        entries.extend(batch)
        cursor = data.get("metadata", {}).get("nextCursor", "")
        print(f"  Page {page}: fetched {len(batch)} entries (total: {len(entries)})")

        if not cursor:
            break
        page += 1
        time.sleep(RATE_LIMIT_SLEEP)

    entries = entries[: args.limit]
    print(f"\nScanning {len(entries)} servers...\n")

    # Scan each entry
    results: list[dict] = []
    total_findings: int = 0
    servers_with_findings: int = 0

    for i, entry in enumerate(entries, 1):
        server = entry.get("server", {})
        name = server.get("name", "unknown")
        version = server.get("version", "")
        label = f"{name}@{version}" if version else name

        print(f"[{i:03d}/{len(entries)}] {label}", end=" ... ", flush=True)

        if args.verbose:
            print(f"\n--- content ---\n{build_scan_content(entry)}\n---")

        result = scan_entry(entry)
        results.append(result)

        n = len(result.get("findings", []))
        total_findings += n

        if n > 0:
            servers_with_findings += 1
            sev = result.get("max_severity", "?")
            print(f"⚠  {n} finding(s) [{sev}] risk {result.get('risk_score', 0):.1f}/10")
            for f in result["findings"]:
                print(f"     [{f['severity']}] {f.get('ave_id','?')} — {f['title']}")
                if f.get("line"):
                    print(f"       line {f['line']}: {f.get('match','')[:70]}")
        else:
            print("✓ clean")

        time.sleep(RATE_LIMIT_SLEEP)

    # Summary
    print(f"\n{'═' * 60}")
    print(f"SCAN COMPLETE — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'═' * 60}")
    print(f"  Source:                {REGISTRY_BASE}")
    print(f"  Servers scanned:       {len(entries)}")
    print(f"  Servers with findings: {servers_with_findings}")
    print(f"  Total findings:        {total_findings}")
    print(f"  Clean servers:         {len(entries) - servers_with_findings}")

    if total_findings > 0:
        rule_counts: dict[str, int] = {}
        sev_counts: dict[str, int] = {}
        for r in results:
            for f in r.get("findings", []):
                rule_counts[f["rule_id"]] = rule_counts.get(f["rule_id"], 0) + 1
                sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

        print("\n  By severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in sev_counts:
                print(f"    {sev}: {sev_counts[sev]}")

        print("\n  Most common rules:")
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"    {rule}: {count}")

    # Save results
    output_path = (
        args.output or f"mcp_registry_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )

    with open(output_path, "w") as f:
        json.dump(
            {
                "scan_date": datetime.utcnow().isoformat(),
                "source": f"{REGISTRY_BASE}/v0/servers",
                "servers_scanned": len(entries),
                "servers_with_findings": servers_with_findings,
                "total_findings": total_findings,
                "latest_only": latest_only,
                "results": results,
            },
            f,
            indent=2,
        )
    print(f"\n  Results saved → {output_path}")


if __name__ == "__main__":
    main()
