"""
scan_smithery.py

Scans MCP servers from the Smithery registry using Bawbel Scanner.
Fetches server tool descriptions and scans for AVE vulnerabilities.

Usage:
    pip install requests "bawbel-scanner[all]"
    export SMITHERY_API_KEY=your_key
    python3 scan_smithery.py --limit 500 --output smithery_scan_results.json

Requirements:
    - SMITHERY_API_KEY environment variable
    - bawbel-scanner installed
    - Optional: ANTHROPIC_API_KEY for LLM stage
"""

import argparse
import json
import os
import subprocess  # nosec B404  # noqa: S404
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: pip install requests")
    sys.exit(1)

SMITHERY_API = "https://registry.smithery.ai"
PIRANHA_API = "https://api.piranha.bawbel.io"
RESULTS_FILE = "smithery_scan_results.json"
PROGRESS_FILE = "smithery_scan_progress.json"


def post_to_piranha(output: dict, ingest_token: str) -> bool:
    """POST scan results to PiranhaDB registry-scan/ingest endpoint."""
    if not ingest_token:
        print("  Skipping PiranhaDB upload: PIRANHA_INGEST_TOKEN not set")
        return False
    try:
        resp = requests.post(
            f"{PIRANHA_API}/registry-scan/ingest?source=smithery",
            json=output,
            headers={
                "Content-Type": "application/json",
                "X-Ingest-Token": ingest_token,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        print(f"  PiranhaDB: {data.get('message', 'ok')}")
        return True
    except requests.RequestException as e:
        print(f"  PiranhaDB upload failed: {e}")
        return False


def get_headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "User-Agent": "bawbel-scanner/1.1.1 (https://bawbel.io)",
    }


def fetch_server_list(api_key: str, limit: int = 500) -> list:
    servers = []
    page = 1
    per_page = 50

    print(f"Fetching top {limit} servers from Smithery...")

    while len(servers) < limit:
        try:
            resp = requests.get(
                f"{SMITHERY_API}/servers",
                headers=get_headers(api_key),
                params={"page": page, "pageSize": per_page},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            print(f"  Error fetching page {page}: {e}")
            break

        items = data.get("servers", [])
        if not items:
            break

        servers.extend(items)
        pagination = data.get("pagination", {})
        total_pages = pagination.get("totalPages", 1)
        total_count = pagination.get("totalCount", 0)
        print(
            f"  Fetched {len(servers)} servers... (page {page}/{total_pages}, total: {total_count})"
        )

        if len(servers) >= limit:
            break
        if page >= total_pages:
            break

        page += 1
        time.sleep(0.3)

    return servers[:limit]


def fetch_server_details(api_key: str, qualified_name: str) -> dict:
    try:
        resp = requests.get(
            f"{SMITHERY_API}/servers/{qualified_name}",
            headers=get_headers(api_key),
            timeout=15,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return None


def extract_scannable_content(server: dict) -> str:
    lines = []
    name = server.get("qualifiedName", server.get("name", "unknown"))
    lines.append(f"# MCP Server: {name}")
    lines.append("")

    desc = server.get("description", "")
    if desc:
        lines.append(f"Server description: {desc}")
        lines.append("")

    tools = server.get("tools", [])
    for tool in tools:
        tname = tool.get("name", "")
        tdesc = tool.get("description", "")
        lines.append(f"## Tool: {tname}")
        if tdesc:
            lines.append(f"Description: {tdesc}")
        schema = tool.get("inputSchema", {})
        for pname, pdef in schema.get("properties", {}).items():
            pdesc = pdef.get("description", "")
            if pdesc:
                lines.append(f"Parameter {pname}: {pdesc}")
        lines.append("")

    config = server.get("config", {})
    if config:
        lines.append("## Config schema")
        lines.append(json.dumps(config, indent=2))

    return "\n".join(lines)


def run_bawbel_scan(content: str) -> dict:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", prefix="smithery_scan_", delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        tmp = f.name

    try:
        result = subprocess.run(  # nosec B603 B607  # noqa: S603 S607
            ["bawbel", "scan", tmp, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = result.stdout.strip()
        if not raw:
            return {
                "findings": [],
                "toxic_flows": [],
                "risk_score": 0,
                "error": result.stderr[:200],
            }

        start = raw.find("[")
        if start < 0:
            return {"findings": [], "toxic_flows": [], "risk_score": 0}

        results = json.loads(raw[start:])
        return results[0] if results else {"findings": [], "toxic_flows": [], "risk_score": 0}

    except subprocess.TimeoutExpired:
        return {"findings": [], "toxic_flows": [], "risk_score": 0, "error": "timeout"}
    except (json.JSONDecodeError, IndexError):
        return {"findings": [], "toxic_flows": [], "risk_score": 0, "error": "parse error"}
    finally:
        Path(tmp).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Scan Smithery MCP servers with Bawbel")
    parser.add_argument("--limit", type=int, default=500, help="Number of servers to scan")
    parser.add_argument("--output", default=RESULTS_FILE, help="Output JSON file")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    args = parser.parse_args()

    api_key = os.environ.get("SMITHERY_API_KEY", "")
    if not api_key:
        print("Error: set SMITHERY_API_KEY environment variable")
        sys.exit(1)

    check = subprocess.run(  # nosec B603 B607  # noqa: S603 S607
        ["bawbel", "version"], capture_output=True, text=True
    )
    if check.returncode != 0:
        print("Error: bawbel CLI not found. pip install bawbel-scanner")
        sys.exit(1)
    print(f"Using: {check.stdout.strip().splitlines()[0]}")

    completed: set = set()
    results: list = []

    if args.resume and Path(PROGRESS_FILE).exists():
        progress = json.loads(Path(PROGRESS_FILE).read_text())
        completed = set(progress.get("completed", []))
        results = progress.get("results", [])
        print(f"Resuming: {len(completed)} already scanned")

    servers = fetch_server_list(api_key, args.limit)
    print(f"\nScanning {len(servers)} servers...\n")
    print("-" * 60)

    stats = {
        "scanned": 0,
        "with_findings": 0,
        "with_toxic_flows": 0,
        "clean": 0,
        "errors": 0,
        "total_findings": 0,
        "total_toxic_flows": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_ave_id": {},
        "by_owasp_mcp": {},
    }

    for i, server in enumerate(servers, 1):
        qname = server.get("qualifiedName", server.get("name", f"server_{i}"))

        if qname in completed:
            continue

        details = fetch_server_details(api_key, qname) or server
        content = extract_scannable_content(details)

        if not content.strip() or len(content) < 50:
            print(f"[{i:03d}/{len(servers)}] {qname[:45]:<45} skip")
            continue

        scan = run_bawbel_scan(content)
        findings = scan.get("findings", [])
        toxic_flows = scan.get("toxic_flows", [])
        risk_score = scan.get("risk_score", 0)

        stats["scanned"] += 1
        stats["total_findings"] += len(findings)
        stats["total_toxic_flows"] += len(toxic_flows)

        if findings:
            stats["with_findings"] += 1
        else:
            stats["clean"] += 1

        if toxic_flows:
            stats["with_toxic_flows"] += 1

        if scan.get("error"):
            stats["errors"] += 1

        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            ave_id = f.get("ave_id", "")
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            if ave_id:
                stats["by_ave_id"][ave_id] = stats["by_ave_id"].get(ave_id, 0) + 1
            for owasp in f.get("owasp_mcp", []):
                stats["by_owasp_mcp"][owasp] = stats["by_owasp_mcp"].get(owasp, 0) + 1

        results.append(
            {
                "rank": i,
                "qualified_name": qname,
                "display_name": details.get("displayName", qname),
                "tools_count": len(details.get("tools", [])),
                "risk_score": risk_score,
                "findings_count": len(findings),
                "toxic_flows_count": len(toxic_flows),
                "findings": findings,
                "toxic_flows": toxic_flows,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        completed.add(qname)

        flag = (
            "CRIT"
            if any(f.get("severity") == "CRITICAL" for f in findings)
            else "HIGH" if any(f.get("severity") == "HIGH" for f in findings) else "ok"
        )
        status = (
            f"[{flag}] {len(findings)} finding(s)  risk {risk_score:.1f}"
            if findings
            else "[ok]  clean"
        )
        if toxic_flows:
            status += f"  chain: {len(toxic_flows)}"

        print(f"[{i:03d}/{len(servers)}] {qname[:45]:<45} {status}")

        if i % 50 == 0:
            Path(PROGRESS_FILE).write_text(
                json.dumps({"completed": list(completed), "results": results})
            )
            flaw_rate = stats["with_findings"] / max(stats["scanned"], 1) * 100
            print(
                f"\n  Checkpoint: {stats['scanned']} scanned, "
                f"{stats['with_findings']} with findings ({flaw_rate:.1f}%)\n"
            )

        time.sleep(0.1)

    flaw_rate = stats["with_findings"] / max(stats["scanned"], 1) * 100
    top_ave = sorted(stats["by_ave_id"].items(), key=lambda x: x[1], reverse=True)[:10]
    top_owasp = sorted(stats["by_owasp_mcp"].items(), key=lambda x: x[1], reverse=True)[:5]

    output = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "source": "smithery",
        "scanner_version": check.stdout.strip().splitlines()[0],
        "servers_scanned": stats["scanned"],
        "servers_with_findings": stats["with_findings"],
        "servers_clean": stats["clean"],
        "servers_with_toxic_flows": stats["with_toxic_flows"],
        "total_findings": stats["total_findings"],
        "total_toxic_flows": stats["total_toxic_flows"],
        "flaw_rate_pct": round(flaw_rate, 1),
        "by_severity": stats["by_severity"],
        "top_ave_ids": top_ave,
        "top_owasp_mcp": top_owasp,
        "results": results,
    }

    Path(args.output).write_text(json.dumps(output, indent=2))

    print("\n" + "-" * 60)
    print("SCAN COMPLETE")
    print("-" * 60)
    print(f"Servers scanned:       {stats['scanned']}")
    print(f"Servers with findings: {stats['with_findings']} ({flaw_rate:.1f}%)")
    print(f"Servers clean:         {stats['clean']}")
    print(f"Toxic flows detected:  {stats['with_toxic_flows']} servers")
    print(f"Total findings:        {stats['total_findings']}")
    print("")
    for sev, count in stats["by_severity"].items():
        if count:
            print(f"  {sev}: {count}")
    print("\nTop AVE IDs:")
    for ave_id, count in top_ave[:5]:
        print(f"  {ave_id}: {count} servers")
    print(f"\nResults: {args.output}")

    Path(PROGRESS_FILE).unlink(missing_ok=True)

    # Upload to PiranhaDB
    ingest_token = os.environ.get("PIRANHA_INGEST_TOKEN", "")
    print("\nUploading to PiranhaDB...")
    post_to_piranha(output, ingest_token)


if __name__ == "__main__":
    main()
