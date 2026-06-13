"""
Bawbel Scanner - Remote content fetcher.

Fetches MCP server-cards and other remote agentic AI components
for scanning. Extracts attack surface content into a flat text
representation that the scan pipeline can process.

Supported sources:
    MCP Server-Card  - .well-known/mcp-server-card/server.json
"""

import json
import tempfile
from pathlib import Path
from typing import Optional

from scanner.messages import Errors
from scanner.utils import get_logger

log = get_logger(__name__)

# Paths to try in order - spec is still draft, servers use different paths.
# SEP-1649 draft: .well-known/mcp.json
# Earlier draft:  .well-known/mcp-server-card/server.json
SERVER_CARD_PATHS = [
    ".well-known/mcp.json",
    ".well-known/mcp-server-card/server.json",
]
SERVER_CARD_PATH = SERVER_CARD_PATHS[0]  # kept for build_server_card_url()
FETCH_TIMEOUT = 10  # seconds


# ── HTTP fetch ────────────────────────────────────────────────────────────────


def fetch_url(url: str) -> tuple[Optional[dict], Optional[str]]:
    """
    Fetch a URL and parse the response as JSON.

    # Sec: INPUT  — URL scheme validated to http/https only before any network call
    #      OUTPUT — raw bytes capped by FETCH_TIMEOUT; parsed JSON returned, never exec'd
    #      TRUST  — response treated as untrusted text, never eval'd
    #      ERROR  — all exceptions caught; type logged internally, error code returned to caller

    Returns:
        (data, error) - data is the parsed JSON dict, error is a string
        if something went wrong. Exactly one of them is None.
    """
    if not url.startswith(("http://", "https://")):
        log.warning("fetch_url: rejected non-http URL: scheme=%s", url.split("://")[0])
        return None, Errors.INVALID_URL_SCHEME

    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "bawbel-scanner/1.0 (github.com/bawbel/scanner)"},
        )
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:  # nosec B310 # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            return data, None

    except urllib.error.HTTPError as e:
        log.warning(
            "fetch_url: HTTP error: url=%s status=%s error_type=%s", url, e.code, type(e).__name__
        )
        return None, Errors.FETCH_HTTP_ERROR
    except urllib.error.URLError as e:
        log.warning("fetch_url: connection failed: url=%s error_type=%s", url, type(e).__name__)
        return None, Errors.FETCH_CONNECTION_FAILED
    except json.JSONDecodeError as e:
        log.warning("fetch_url: JSON parse failed: url=%s error_type=%s", url, type(e).__name__)
        return None, Errors.FETCH_INVALID_RESPONSE
    except Exception as e:  # nosec B110 — broad catch intentional, error_type logged
        log.error("fetch_url: unexpected error: url=%s error_type=%s", url, type(e).__name__)
        return None, Errors.FETCH_CONNECTION_FAILED


# ── Server-card URL builder ───────────────────────────────────────────────────


def build_server_card_url(base_url: str) -> str:
    """
    Build the full server-card URL from a base URL.

    Handles trailing slashes and existing paths gracefully.

    Examples:
        https://api.example.com  → https://api.example.com/.well-known/mcp-server-card/server.json
        https://api.example.com/ → https://api.example.com/.well-known/mcp-server-card/server.json
        https://api.example.com/.well-known/mcp-server-card/server.json → unchanged
    """
    url = base_url.rstrip("/")
    if SERVER_CARD_PATH in url:
        return url
    return f"{url}/{SERVER_CARD_PATH}"


# ── Content builder ───────────────────────────────────────────────────────────


def build_server_card_content(data: dict, source_url: str) -> str:
    """
    Build a scannable text representation of an MCP server-card.

    Extracts every field that is an attack surface:
    - Server name and description
    - Tool names and descriptions (primary attack surface - AVE-2026-00002)
    - Tool input parameter descriptions
    - Config schema property descriptions
    - Connection config

    Preserves structure so line numbers in findings are meaningful.
    """
    lines: list[str] = []

    # Header - source URL so findings reference the real origin
    lines.append(f"# MCP Server-Card: {source_url}")
    lines.append(f"# Fetched from: {build_server_card_url(source_url)}")
    lines.append("")

    # Server identity
    name = data.get("name", "") or data.get("displayName", "") or data.get("qualifiedName", "")
    if name:
        lines.append(f"# Server name: {name}")

    # Top-level description
    description = data.get("description", "")
    if description:
        lines.append("")
        lines.append("## Description")
        lines.append(description)

    # Tools - primary attack surface for tool description poisoning
    tools = data.get("tools", [])
    if tools:
        lines.append("")
        lines.append("## Tools")
        for tool in tools:
            tool_name = tool.get("name", "")
            tool_desc = tool.get("description", "")

            lines.append("")
            lines.append(f"### {tool_name}")
            if tool_desc:
                lines.append(tool_desc)

            # Input schema property descriptions
            schema = tool.get("inputSchema", {}) or {}
            props = schema.get("properties", {}) or {}
            for prop_name, prop_val in props.items():
                if isinstance(prop_val, dict):
                    prop_desc = prop_val.get("description", "")
                    if prop_desc:
                        lines.append(f"  - {prop_name}: {prop_desc}")

    # Connection config schemas
    connections = data.get("connections", []) or []
    for conn in connections:
        config_schema = conn.get("configSchema", {}) or {}
        if not isinstance(config_schema, dict):
            continue

        schema_desc = config_schema.get("description", "")
        if schema_desc:
            lines.append("")
            lines.append("## Config Schema")
            lines.append(schema_desc)

        props = config_schema.get("properties", {}) or {}
        for prop_name, prop_val in props.items():
            if isinstance(prop_val, dict):
                prop_desc = prop_val.get("description", "")
                if prop_desc:
                    lines.append(f"  config.{prop_name}: {prop_desc}")

    # Top-level capabilities or instructions fields (non-standard but seen in wild)
    for field in ("instructions", "systemPrompt", "system_prompt", "capabilities"):
        value = data.get(field, "")
        if value and isinstance(value, str):
            lines.append("")
            lines.append(f"## {field}")
            lines.append(value)

    return "\n".join(lines)


# ── Temp file writer ──────────────────────────────────────────────────────────


def write_temp_scan_file(content: str, suffix: str = ".md") -> Path:
    """
    Write content to a named temporary file for scanning.

    Returns the Path. Caller is responsible for cleanup.
    """
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        prefix="bawbel_fetch_",
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(content)
        return Path(f.name)


# ── Public API ────────────────────────────────────────────────────────────────


def fetch_server_card(base_url: str) -> tuple[Optional[str], Optional[str]]:
    """
    Fetch an MCP server-card and return its scannable content.

    Tries all known well-known paths in order:
      1. .well-known/mcp.json           (SEP-1649 draft spec)
      2. .well-known/mcp-server-card/server.json  (earlier draft)

    Args:
        base_url: Base URL of the MCP server
                  e.g. "https://api.example.com" or a full server-card URL

    Returns:
        (content, error) - content is the scannable text string,
        error is a message if nothing was found at any path.
    """
    if not base_url.startswith(("http://", "https://")):
        return None, Errors.INVALID_URL_SCHEME

    # If the URL already contains a well-known path, try it directly
    if ".well-known/" in base_url:
        data, err = fetch_url(base_url)
        if err:
            return None, err
        if not isinstance(data, dict):
            log.warning("fetch_server_card: unexpected response type: type=%s", type(data).__name__)
            return None, Errors.FETCH_INVALID_RESPONSE
        return build_server_card_content(data, base_url), None

    # Otherwise try each known path in order
    base = base_url.rstrip("/")
    for path in SERVER_CARD_PATHS:
        url = f"{base}/{path}"
        log.debug("Trying server-card path: %s", url)
        data, err = fetch_url(url)
        if err:
            continue  # try next path
        if not isinstance(data, dict):
            log.warning(
                "fetch_server_card: unexpected response type: path=%s type=%s",
                path,
                type(data).__name__,
            )
            continue
        content = build_server_card_content(data, base_url)
        log.debug("Server-card found at %s - %d lines", path, content.count("\n"))
        return content, None

    log.warning(
        "fetch_server_card: no server-card found: url=%s paths_tried=%d",
        base_url,
        len(SERVER_CARD_PATHS),
    )
    return None, Errors.SERVER_CARD_NOT_FOUND
