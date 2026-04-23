#!/usr/bin/env python3
"""
Bawbel Sandbox Harness — runs INSIDE the Docker container.

Reads /component (the skill file mounted read-only), performs
behavioural analysis, and outputs a JSON report to stdout.

This is a text-analysis harness for v0.3.x. The v1.0 harness
will add real eBPF syscall tracing.

Output format:
{
  "version":    "0.3.0",
  "component":  "/component",
  "network":    [{"dst": "...", "port": 443, "reason": "..."}],
  "filesystem": [{"path": "...", "op": "write", "reason": "..."}],
  "processes":  [{"cmd": "...", "pid": 0, "reason": "..."}],
  "encoded":    [{"type": "base64", "value": "...", "decoded": "..."}]
}
"""

import base64
import json
import re
import sys
from pathlib import Path

COMPONENT_PATH = Path("/component")
VERSION = "0.3.0"


# ── Detection patterns ────────────────────────────────────────────────────────

NETWORK_PATTERNS = [
    (r"pastebin\.com", "pastebin.com", 443, "Known malicious paste site"),
    (r"rentry\.co", "rentry.co", 443, "Known malicious paste site"),
    (
        r"raw\.githubusercontent\.com",
        "raw.githubusercontent.com",
        443,
        "Raw GitHub content — common C2",
    ),
    (
        r"gist\.githubusercontent\.com",
        "gist.githubusercontent.com",
        443,
        "Raw GitHub gist — common C2",
    ),
    (r"hastebin\.com", "hastebin.com", 443, "Known paste site"),
    (r"ngrok\.io", "ngrok.io", 443, "Tunnel service — common exfil channel"),
    (r"webhook\.site", "webhook.site", 443, "Webhook capture — exfil target"),
    (r"requestbin\.com", "requestbin.com", 443, "Request capture — exfil target"),
    (
        r"https?://(?![\w.-]*anthropic|[\w.-]*openai|[\w.-]*google|[\w.-]*microsoft)"
        r"([\w.-]+\.[a-z]{2,})",
        None,
        443,
        "Unexpected outbound URL",
    ),
]

FILESYSTEM_PATTERNS = [
    (r"~?/\.bashrc", "/home/user/.bashrc", "write", "Shell config — persistence"),
    (r"~?/\.zshrc", "/home/user/.zshrc", "write", "Shell config — persistence"),
    (r"~?/\.profile", "/home/user/.profile", "write", "Shell config — persistence"),
    (r"/etc/cron", "/etc/cron.d/bawbel", "write", "Cron job — persistence"),
    (r"~?/\.ssh/", "/home/user/.ssh/", "read", "SSH keys — credential theft"),
    (r"\.env\b", ".env", "read", "Env file — credential theft"),
    (r"private[_-]?key", "private_key", "read", "Private key — credential theft"),
    (r"rm\s+-rf?\s+[/~]", "/", "delete", "Recursive delete — destructive"),
]

PROCESS_PATTERNS = [
    (r"curl\s*\|", "curl | sh", 0, "curl pipe — arbitrary code exec"),
    (r"wget\s*\|", "wget | bash", 0, "wget pipe — arbitrary code exec"),
    (r"\|\s*(bash|sh|zsh|python)\b", "bash -c ...", 0, "Shell pipe — arbitrary code exec"),
    (r"eval\s*\$\(", "eval $(cmd)", 0, "eval injection — code exec"),
    (r"exec\s*\(", "exec(payload)", 0, "exec() call — code exec"),
    (
        r"(systemctl\s+enable|crontab\s+-[ei])",
        "systemctl enable",
        0,
        "Service install — persistence",
    ),
    (r"pip\s+install\s+(?!bawbel)", "pip install pkg", 0, "Package install — supply chain"),
    (r"npm\s+install\s+(?!bawbel)", "npm install pkg", 0, "Package install — supply chain"),
]

ENCODED_PATTERNS = [
    (r"(?:base64|b64)[^a-z].*?([A-Za-z0-9+/]{40,}={0,2})", "base64"),
    (r"([A-Za-z0-9+/]{80,}={0,2})", "base64-raw"),
]


def _search(pattern: str, text: str, flags: int = re.IGNORECASE) -> list[re.Match]:
    return list(re.finditer(pattern, text, flags))


def analyse(content: str) -> dict:
    report = {
        "version": VERSION,
        "component": str(COMPONENT_PATH),
        "network": [],
        "filesystem": [],
        "processes": [],
        "encoded": [],
    }

    # ── Network egress ────────────────────────────────────────────────────────
    for pattern, dst, port, reason in NETWORK_PATTERNS:
        for m in _search(pattern, content):
            actual_dst = dst or m.group(1) if m.lastindex else dst or m.group(0)
            report["network"].append(
                {
                    "dst": actual_dst,
                    "port": port,
                    "reason": reason,
                    "line": content[: m.start()].count("\n") + 1,
                }
            )
            break  # one finding per pattern

    # ── Filesystem access ─────────────────────────────────────────────────────
    for pattern, path, op, reason in FILESYSTEM_PATTERNS:
        for m in _search(pattern, content):
            report["filesystem"].append(
                {
                    "path": path,
                    "op": op,
                    "reason": reason,
                    "line": content[: m.start()].count("\n") + 1,
                }
            )
            break

    # ── Process spawning ──────────────────────────────────────────────────────
    for pattern, cmd, pid, reason in PROCESS_PATTERNS:
        for m in _search(pattern, content):
            report["processes"].append(
                {
                    "cmd": cmd,
                    "pid": pid,
                    "reason": reason,
                    "line": content[: m.start()].count("\n") + 1,
                }
            )
            break

    # ── Encoded payloads ──────────────────────────────────────────────────────
    for pattern, enc_type in ENCODED_PATTERNS:
        for m in _search(pattern, content):
            raw = m.group(1) if m.lastindex else m.group(0)
            # Try to decode and check if it contains suspicious content
            try:
                decoded = base64.b64decode(raw + "==").decode("utf-8", errors="ignore")
                if any(
                    kw in decoded.lower()
                    for kw in [
                        "http",
                        "curl",
                        "wget",
                        "bash",
                        "exec",
                        "eval",
                        "rm -rf",
                        "passwd",
                        "private",
                        ".env",
                    ]
                ):
                    report["encoded"].append(
                        {
                            "type": enc_type,
                            "value": raw[:80] + ("..." if len(raw) > 80 else ""),
                            "decoded": decoded[:200],
                            "line": content[: m.start()].count("\n") + 1,
                        }
                    )
            except Exception:  # nosec B110  # noqa: S110
                pass

    return report


def main():
    if not COMPONENT_PATH.exists():
        print(
            json.dumps(
                {
                    "version": VERSION,
                    "error": "component file not found",
                    "network": [],
                    "filesystem": [],
                    "processes": [],
                    "encoded": [],
                }
            )
        )
        sys.exit(1)

    content = COMPONENT_PATH.read_text(encoding="utf-8", errors="ignore")
    report = analyse(content)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
