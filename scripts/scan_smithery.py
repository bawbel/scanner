"""
scan_smithery.py

Scans MCP servers from the Smithery registry using Bawbel Scanner.
Fetches server tool descriptions and scans for AVE vulnerabilities.

Usage:
    pip install requests "bawbel-scanner[all]"
    export SMITHERY_API_KEY=your_key
    python3 scan_smithery.py --limit 500 --output smithery_scan_results.json

Options:
    --limit     Number of servers to scan (default: 500)
    --output    Output JSON file (default: smithery_scan_results.json)
    --workers   Parallel scan workers (default: 4)
    --delay     Seconds between API calls per worker (default: 0.1)
    --resume    Resume from last checkpoint

Requirements:
    - SMITHERY_API_KEY environment variable
    - bawbel-scanner installed
    - Optional: PIRANHA_INGEST_TOKEN for PiranhaDB upload
    - Optional: ANTHROPIC_API_KEY for LLM stage
"""

import argparse
import json
import os
import signal
import subprocess  # nosec B404  # noqa: S404
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# Thread-safe state
_lock = threading.Lock()
_shutdown = threading.Event()


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
        "User-Agent": "bawbel-scanner/1.2.1 (https://bawbel.io)",
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
            f"  Fetched {len(servers)} servers..."
            f" (page {page}/{total_pages}, total: {total_count})"
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
        mode="w",
        suffix=".md",
        prefix="smithery_scan_",
        delete=False,
        encoding="utf-8",
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


def scan_one(rank: int, server: dict, api_key: str, delay: float) -> dict:
    """Fetch details and scan one server. Designed for ThreadPoolExecutor."""
    if _shutdown.is_set():
        return None

    qname = server.get("qualifiedName", server.get("name", f"server_{rank}"))
    details = fetch_server_details(api_key, qname) or server
    content = extract_scannable_content(details)

    if not content.strip() or len(content) < 50:
        return {
            "rank": rank,
            "qualified_name": qname,
            "display_name": details.get("displayName", qname),
            "tools_count": len(details.get("tools", [])),
            "skipped": True,
        }

    scan = run_bawbel_scan(content)
    findings = scan.get("findings", [])
    toxic_flows = scan.get("toxic_flows", [])
    risk_score = scan.get("risk_score", 0)

    if delay:
        time.sleep(delay)

    return {
        "rank": rank,
        "qualified_name": qname,
        "display_name": details.get("displayName", qname),
        "tools_count": len(details.get("tools", [])),
        "risk_score": risk_score,
        "findings_count": len(findings),
        "toxic_flows_count": len(toxic_flows),
        "findings": findings,
        "toxic_flows": toxic_flows,
        "skipped": False,
        "error": scan.get("error"),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def accumulate(stats: dict, entry: dict) -> None:
    """Merge one scan entry into running stats. Called under lock."""
    if entry.get("skipped"):
        return

    findings = entry.get("findings", [])
    toxic_flows = entry.get("toxic_flows", [])

    stats["scanned"] += 1
    stats["total_findings"] += len(findings)
    stats["total_toxic_flows"] += len(toxic_flows)

    if findings:
        stats["with_findings"] += 1
    else:
        stats["clean"] += 1

    if toxic_flows:
        stats["with_toxic_flows"] += 1

    if entry.get("error"):
        stats["errors"] += 1

    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        ave_id = f.get("ave_id", "")
        aivss = f.get("aivss_score", 0.0)

        stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
        stats["aivss_scores"].append(aivss)

        if aivss > stats["max_aivss"]:
            stats["max_aivss"] = aivss

        if ave_id:
            stats["by_ave_id"][ave_id] = stats["by_ave_id"].get(ave_id, 0) + 1

        for owasp in f.get("owasp_mcp", []):
            stats["by_owasp_mcp"][owasp] = stats["by_owasp_mcp"].get(owasp, 0) + 1


def fmt_entry(entry: dict, total: int) -> str:
    """Single-line progress output for one scanned server."""
    rank = entry["rank"]
    qname = entry["qualified_name"][:45]
    if entry.get("skipped"):
        return f"[{rank:03d}/{total}] {qname:<45} skip"

    findings = entry.get("findings", [])
    toxic = entry.get("toxic_flows_count", 0)
    risk = entry.get("risk_score", 0)

    if findings:
        sev = (
            "CRIT"
            if any(f.get("severity") == "CRITICAL" for f in findings)
            else "HIGH" if any(f.get("severity") == "HIGH" for f in findings) else "MED"
        )
        status = f"[{sev}] {len(findings)} finding(s)  risk {risk:.1f}"
    else:
        status = "[ok]  clean"

    if toxic:
        status += f"  chain: {toxic}"
    if entry.get("error"):
        status += f"  err: {entry['error'][:30]}"

    return f"[{rank:03d}/{total}] {qname:<45} {status}"


def save_progress(completed: set, results: list) -> None:
    Path(PROGRESS_FILE).write_text(
        json.dumps({"completed": list(completed), "results": results}, ensure_ascii=False)
    )


def main():
    parser = argparse.ArgumentParser(description="Scan Smithery MCP servers with Bawbel")
    parser.add_argument("--limit", type=int, default=500, help="Number of servers to scan")
    parser.add_argument("--output", default=RESULTS_FILE, help="Output JSON file")
    parser.add_argument("--workers", type=int, default=4, help="Parallel scan workers")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay per worker between calls")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    args = parser.parse_args()

    api_key = os.environ.get("SMITHERY_API_KEY", "")
    if not api_key:
        print("Error: set SMITHERY_API_KEY environment variable")
        sys.exit(1)

    version_check = subprocess.run(  # nosec B603 B607  # noqa: S603 S607
        ["bawbel", "version"], capture_output=True, text=True
    )
    if version_check.returncode != 0:
        print("Error: bawbel CLI not found. pip install bawbel-scanner")
        sys.exit(1)
    print(f"Using: {version_check.stdout.strip().splitlines()[0]}")
    print(f"Workers: {args.workers}")

    completed: set = set()
    results: list = []

    if args.resume and Path(PROGRESS_FILE).exists():
        progress = json.loads(Path(PROGRESS_FILE).read_text())
        completed = set(progress.get("completed", []))
        results = progress.get("results", [])
        print(f"Resuming: {len(completed)} already scanned")

    servers = fetch_server_list(api_key, args.limit)
    pending = [s for s in servers if s.get("qualifiedName", s.get("name")) not in completed]
    total = len(servers)
    print(f"\nScanning {len(pending)} servers ({total - len(pending)} already done)...\n")
    print("-" * 60)

    stats = {
        "scanned": 0,
        "with_findings": 0,
        "with_toxic_flows": 0,
        "clean": 0,
        "errors": 0,
        "total_findings": 0,
        "total_toxic_flows": 0,
        "by_severity": {},
        "by_ave_id": {},
        "by_owasp_mcp": {},
        "aivss_scores": [],
        "max_aivss": 0.0,
    }

    # Checkpoint on Ctrl+C
    def _handle_signal(sig, frame):
        _shutdown.set()
        print("\n\nInterrupted - saving checkpoint...")
        with _lock:
            save_progress(completed, results)
        print(f"Checkpoint saved to {PROGRESS_FILE}. Resume with --resume.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    rank_map = {s.get("qualifiedName", s.get("name")): i + 1 for i, s in enumerate(servers)}

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                scan_one,
                rank_map.get(s.get("qualifiedName", s.get("name")), i + 1),
                s,
                api_key,
                args.delay,
            ): s
            for i, s in enumerate(pending)
        }

        done_count = 0
        for future in as_completed(futures):
            if _shutdown.is_set():
                break

            entry = future.result()
            if entry is None:
                continue

            qname = entry["qualified_name"]
            done_count += 1

            with _lock:
                accumulate(stats, entry)
                results.append(entry)
                completed.add(qname)
                print(fmt_entry(entry, total))

                if done_count % 50 == 0:
                    save_progress(completed, results)
                    flaw_rate = stats["with_findings"] / max(stats["scanned"], 1) * 100
                    print(
                        f"\n  Checkpoint: {stats['scanned']} scanned, "
                        f"{stats['with_findings']} with findings ({flaw_rate:.1f}%)\n"
                    )

    flaw_rate = stats["with_findings"] / max(stats["scanned"], 1) * 100
    avg_aivss = (
        sum(stats["aivss_scores"]) / len(stats["aivss_scores"]) if stats["aivss_scores"] else 0.0
    )
    top_ave = sorted(stats["by_ave_id"].items(), key=lambda x: x[1], reverse=True)[:10]
    top_owasp = sorted(stats["by_owasp_mcp"].items(), key=lambda x: x[1], reverse=True)[:5]

    output = {
        "schema_version": "1.0.0",
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "source": "smithery",
        "scanner_version": version_check.stdout.strip().splitlines()[0],
        "servers_scanned": stats["scanned"],
        "servers_with_findings": stats["with_findings"],
        "servers_clean": stats["clean"],
        "servers_with_toxic_flows": stats["with_toxic_flows"],
        "total_findings": stats["total_findings"],
        "total_toxic_flows": stats["total_toxic_flows"],
        "flaw_rate_pct": round(flaw_rate, 1),
        "aivss_avg": round(avg_aivss, 2),
        "aivss_max": round(stats["max_aivss"], 2),
        "by_severity": stats["by_severity"],
        "top_ave_ids": top_ave,
        "top_owasp_mcp": top_owasp,
        "results": sorted(results, key=lambda r: r["rank"]),
    }

    Path(args.output).write_text(json.dumps(output, indent=2, ensure_ascii=False))

    print("\n" + "-" * 60)
    print("SCAN COMPLETE")
    print("-" * 60)
    print(f"Servers scanned:       {stats['scanned']}")
    print(f"Servers with findings: {stats['with_findings']} ({flaw_rate:.1f}%)")
    print(f"Servers clean:         {stats['clean']}")
    print(f"Toxic flows detected:  {stats['with_toxic_flows']} servers")
    print(f"Total findings:        {stats['total_findings']}")
    print(f"AIVSS avg / max:       {avg_aivss:.2f} / {stats['max_aivss']:.1f}")
    print("")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = stats["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev}: {count}")
    print("\nTop AVE IDs:")
    for ave_id, count in top_ave[:5]:
        print(f"  {ave_id}: {count} servers")
    print(f"\nResults: {args.output}")

    Path(PROGRESS_FILE).unlink(missing_ok=True)

    ingest_token = os.environ.get("PIRANHA_INGEST_TOKEN", "")
    print("\nUploading to PiranhaDB...")
    post_to_piranha(output, ingest_token)


if __name__ == "__main__":
    main()
