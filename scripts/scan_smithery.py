#!/usr/bin/env python3
"""
scan_smithery.py — Bawbel scanner for Smithery MCP registry servers

Fetches MCP server details from registry.smithery.ai and scans
tool names, descriptions, and README content for AVE vulnerabilities.

Usage:
    export SMITHERY_API_KEY=your_key_here
    python scan_smithery.py --limit 20
    python scan_smithery.py --limit 100 --output results.json

Requirements:
    pip install bawbel-scanner requests
"""

import argparse
import json
import os
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

REGISTRY_BASE = "https://registry.smithery.ai"
API_KEY = os.environ.get("SMITHERY_API_KEY", "")
RATE_LIMIT_SLEEP = 0.5  # seconds between requests — be polite

# ── Smithery API ──────────────────────────────────────────────────────────────


def get_headers() -> dict:
    if not API_KEY:
        print("ERROR: SMITHERY_API_KEY not set.")
        print("Get one at: https://smithery.ai/account/api-keys")
        sys.exit(1)
    return {"Authorization": f"Bearer {API_KEY}"}


def list_servers(page: int = 1, page_size: int = 10, query: str = "") -> dict:
    """Fetch a page of servers from the Smithery registry."""
    params = {"page": page, "pageSize": page_size}
    if query:
        params["q"] = query
    resp = requests.get(
        f"{REGISTRY_BASE}/servers",
        headers=get_headers(),
        params=params,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def get_server(qualified_name: str) -> dict:
    """Fetch full details for one server including tools."""
    resp = requests.get(
        f"{REGISTRY_BASE}/servers/{qualified_name}",
        headers=get_headers(),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# ── Content builder ───────────────────────────────────────────────────────────


def build_scan_content(server: dict) -> str:
    """
    Build a text file representing the MCP server's attack surface.
    Includes all content that bawbel-scanner can analyse:
      - Server name and description
      - Tool names and descriptions (the primary attack surface)
      - Config schema descriptions
      - README if available
    """
    lines = []
    name = server.get("qualifiedName", "unknown")
    lines.append(f"# MCP Server: {name}")
    lines.append(f"# Display name: {server.get('displayName', '')}")
    lines.append("")

    desc = server.get("description", "")
    if desc:
        lines.append("## Server Description")
        lines.append(desc)
        lines.append("")

    # Tool descriptions — primary attack surface for tool poisoning (AVE-2026-00002)
    tools = server.get("tools", [])
    if tools:
        lines.append("## Tools")
        for tool in tools:
            tool_name = tool.get("name", "")
            tool_desc = tool.get("description", "")
            lines.append(f"### {tool_name}")
            if tool_desc:
                lines.append(tool_desc)
            # Input schema descriptions
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            for prop_name, prop_val in props.items():
                prop_desc = prop_val.get("description", "")
                if prop_desc:
                    lines.append(f"  - {prop_name}: {prop_desc}")
            lines.append("")

    # Connection config schema — may contain injected instructions
    connections = server.get("connections", [])
    for conn in connections:
        config_schema = conn.get("configSchema", {})
        if isinstance(config_schema, dict):
            schema_desc = config_schema.get("description", "")
            if schema_desc:
                lines.append("## Config Schema")
                lines.append(schema_desc)
                lines.append("")
            # Check property descriptions
            props = config_schema.get("properties", {})
            for prop_name, prop_val in props.items():
                if isinstance(prop_val, dict):
                    prop_desc = prop_val.get("description", "")
                    if prop_desc:
                        lines.append(f"  config.{prop_name}: {prop_desc}")

    return "\n".join(lines)


# ── Scanner ───────────────────────────────────────────────────────────────────


def scan_server(server: dict) -> dict:
    """Run bawbel scan on a server's content. Returns scan result."""
    name = server.get("qualifiedName", "unknown")
    content = build_scan_content(server)

    # Write to temp file for bawbel scan
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".md",
        prefix="smithery_",
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
                "error": result.stderr.strip() or "no output",
                "findings": [],
                "risk_score": 0,
            }

        json_start = raw.find("[")
        if json_start < 0:
            return {"server": name, "error": raw[:200], "findings": [], "risk_score": 0}

        scan_results = json.loads(raw[json_start:])
        if scan_results:
            r = scan_results[0]
            return {
                "server": name,
                "display_name": server.get("displayName", ""),
                "findings": r.get("findings", []),
                "risk_score": r.get("risk_score", 0),
                "max_severity": r.get("max_severity", ""),
                "scan_time_ms": r.get("scan_time_ms", 0),
                "error": None,
            }
        return {"server": name, "findings": [], "risk_score": 0, "error": None}

    except subprocess.TimeoutExpired:
        return {"server": name, "error": "timeout", "findings": [], "risk_score": 0}
    except json.JSONDecodeError as e:
        return {"server": name, "error": f"parse: {e}", "findings": [], "risk_score": 0}
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Scan Smithery MCP servers for AVE vulnerabilities"
    )
    parser.add_argument(
        "--limit", type=int, default=20, help="Number of servers to scan (default: 20)"
    )
    parser.add_argument(
        "--query", type=str, default="", help="Filter servers by query (e.g. 'github', 'email')"
    )
    parser.add_argument("--output", type=str, default="", help="Save results to JSON file")
    parser.add_argument("--verbose", action="store_true", help="Print scan content for each server")
    args = parser.parse_args()

    print("Bawbel Smithery Scanner")
    print(f"Scanning top {args.limit} servers from registry.smithery.ai")
    print("─" * 60)

    # Collect server list
    servers = []
    page = 1
    while len(servers) < args.limit:
        batch_size = min(10, args.limit - len(servers))
        try:
            data = list_servers(page=page, page_size=batch_size, query=args.query)
        except requests.HTTPError as e:
            print(f"Registry API error: {e}")
            sys.exit(1)

        batch = data.get("servers", []) if isinstance(data, dict) else data
        if not batch:
            break
        servers.extend(batch)
        page += 1
        time.sleep(RATE_LIMIT_SLEEP)

    servers = servers[: args.limit]
    print(f"Found {len(servers)} servers to scan\n")

    # Fetch full details + scan each server
    results = []
    total_findings = 0
    servers_with_findings = 0

    for i, server_stub in enumerate(servers, 1):
        qname = server_stub.get("qualifiedName", server_stub.get("id", "unknown"))
        print(f"[{i:03d}/{len(servers)}] {qname}", end=" ... ", flush=True)

        try:
            server_full = get_server(qname)
            time.sleep(RATE_LIMIT_SLEEP)
        except requests.HTTPError as e:
            print(f"fetch error: {e}")
            results.append({"server": qname, "error": str(e), "findings": []})
            continue

        if args.verbose:
            print(f"\n--- scan content ---\n{build_scan_content(server_full)}\n---")

        result = scan_server(server_full)
        results.append(result)

        n = len(result.get("findings", []))
        total_findings += n
        if n > 0:
            servers_with_findings += 1
            sev = result.get("max_severity", "?")
            print(f"⚠  {n} finding(s) [{sev}] risk {result.get('risk_score', 0)}/10")
            for f in result["findings"]:
                print(f"     [{f['severity']}] {f['ave_id']} — {f['title']}")
                print(f"       line {f['line']}: {f.get('match','')[:70]}")
        else:
            print("✓ clean")

    # Summary
    print(f"\n{'═' * 60}")
    print(f"SCAN COMPLETE — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'═' * 60}")
    print(f"  Servers scanned:       {len(servers)}")
    print(f"  Servers with findings: {servers_with_findings}")
    print(f"  Total findings:        {total_findings}")
    print(f"  Clean servers:         {len(servers) - servers_with_findings}")

    if total_findings > 0:
        # Breakdown by rule
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
    output_path = args.output or f"smithery_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_path, "w") as f:
        json.dump(
            {
                "scan_date": datetime.utcnow().isoformat(),
                "servers_scanned": len(servers),
                "servers_with_findings": servers_with_findings,
                "total_findings": total_findings,
                "results": results,
            },
            f,
            indent=2,
        )
    print(f"\n  Results saved → {output_path}")


if __name__ == "__main__":
    main()
