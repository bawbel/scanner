"""
Bawbel Scanner — Stage 3 Behavioral Sandbox Engine.

Hybrid image resolution strategy:
  1. Check local cache — if image exists, run immediately (zero network)
  2. Try Docker Hub pull — bawbel/sandbox:latest (tagged release)
  3. Fallback — build locally from scanner/sandbox/Dockerfile (offline/air-gapped)

Environment variables:
  BAWBEL_SANDBOX_ENABLED=true          enable Stage 3 (default: false)
  BAWBEL_SANDBOX_IMAGE=default         image resolution:
    "default"  → hybrid (cache → Hub pull → local build)
    "local"    → skip Hub, always build from bundled Dockerfile
    "<image>"  → use custom image as-is (enterprise registry, dev)
  BAWBEL_SANDBOX_TIMEOUT=30            container timeout seconds
  BAWBEL_SANDBOX_NETWORK=none          none=isolated, bridge=internet
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Optional

from scanner.messages import Logs
from scanner.models import Finding, Severity
from scanner.utils import Timer, get_logger, run_subprocess

log = get_logger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
SANDBOX_ENABLED = os.environ.get("BAWBEL_SANDBOX_ENABLED", "false").lower() == "true"
SANDBOX_TIMEOUT_SEC = int(os.environ.get("BAWBEL_SANDBOX_TIMEOUT", "30"))
SANDBOX_NETWORK = os.environ.get("BAWBEL_SANDBOX_NETWORK", "none")
_SANDBOX_IMAGE_ENV = os.environ.get("BAWBEL_SANDBOX_IMAGE", "default")

_HUB_IMAGE = "bawbel/sandbox:latest"
_LOCAL_TAG = "bawbel/sandbox:local"
_SANDBOX_DIR = Path(__file__).parent / "sandbox"

# ── IOC tables ────────────────────────────────────────────────────────────────
_NETWORK_IOCS = [
    ("Outbound connection to pastebin.com", "AVE-2026-00001", "CRITICAL", 9.4),
    ("Outbound connection to rentry.co", "AVE-2026-00001", "CRITICAL", 9.4),
    ("Outbound connection to raw.githubusercontent.com", "AVE-2026-00001", "HIGH", 8.5),
    ("Outbound connection to gist.githubusercontent.com", "AVE-2026-00001", "HIGH", 8.5),
    ("Outbound connection to ngrok tunnel", "AVE-2026-00001", "HIGH", 8.3),
    ("Outbound connection to webhook capture site", "AVE-2026-00001", "HIGH", 8.0),
]
_FILESYSTEM_IOCS = [
    ("Write to shell config (~/.bashrc, ~/.zshrc)", "AVE-2026-00008", "HIGH", 8.4),
    ("Write to cron job directory", "AVE-2026-00008", "HIGH", 8.4),
    ("Read of ~/.ssh/ directory", "AVE-2026-00003", "HIGH", 8.5),
    ("Read of .env or credentials file", "AVE-2026-00003", "HIGH", 8.5),
    ("Read of private key file", "AVE-2026-00003", "HIGH", 8.5),
    ("Recursive delete (rm -rf)", "AVE-2026-00005", "CRITICAL", 9.1),
]
_PROCESS_IOCS = [
    ("Shell pipe injection (curl|bash)", "AVE-2026-00004", "HIGH", 8.8),
    ("Shell pipe injection (wget|bash)", "AVE-2026-00004", "HIGH", 8.8),
    ("Pipe to shell interpreter", "AVE-2026-00004", "HIGH", 8.8),
    ("eval() code execution", "AVE-2026-00004", "HIGH", 8.5),
    ("exec() code execution", "AVE-2026-00004", "HIGH", 8.5),
    ("Service installation (systemctl/crontab)", "AVE-2026-00008", "HIGH", 8.4),
    ("Unexpected pip install", "AVE-2026-00004", "HIGH", 8.0),
    ("Unexpected npm install", "AVE-2026-00004", "HIGH", 8.0),
]


# ── Docker helpers ────────────────────────────────────────────────────────────


def is_docker_available() -> bool:
    stdout, _ = run_subprocess(
        args=["docker", "info", "--format", "{{.ServerVersion}}"],
        timeout=5,
        label="docker-check",
    )
    return bool(stdout and stdout.strip())


def _image_exists_locally(tag: str) -> bool:
    stdout, _ = run_subprocess(
        args=["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
        timeout=5,
        label="docker-inspect",
    )
    return bool(stdout and stdout.strip())


def _pull_image(image: str) -> bool:
    log.info("Sandbox: pulling %s …", image)
    stdout, err = run_subprocess(
        args=["docker", "pull", image],
        timeout=120,
        label="docker-pull",
    )
    if err and "Error" in err:
        log.warning("Sandbox: pull failed — %s", err[:200])
        return False
    log.info("Sandbox: pulled %s successfully", image)
    return True


def _build_local_image() -> bool:
    if not _SANDBOX_DIR.exists():
        log.warning("Sandbox: bundled Dockerfile not found at %s", _SANDBOX_DIR)
        return False
    log.info("Sandbox: building local image from bundled Dockerfile…")
    stdout, err = run_subprocess(
        args=["docker", "build", "-t", _LOCAL_TAG, str(_SANDBOX_DIR)],
        timeout=180,
        label="docker-build",
    )
    if err and "error" in err.lower() and "warning" not in err.lower():
        log.warning("Sandbox: local build failed — %s", err[:300])
        return False
    log.info("Sandbox: built %s successfully", _LOCAL_TAG)
    return True


def _resolve_image() -> Optional[str]:
    """
    Hybrid image resolution. Returns image tag to run, or None.

    Resolution order:
      local   → build locally, skip Hub
      custom  → use env value as-is
      default →
        1. local Hub cache hit → run immediately
        2. Hub pull succeeds   → cache + run
        3. local build         → run
        4. None                → log warning, skip
    """
    env = _SANDBOX_IMAGE_ENV.strip()

    if env == "local":
        if _image_exists_locally(_LOCAL_TAG):
            log.debug("Sandbox: using cached local image")
            return _LOCAL_TAG
        return _LOCAL_TAG if _build_local_image() else None

    if env != "default":
        log.debug("Sandbox: using custom image %s", env)
        return env

    # Default hybrid
    if _image_exists_locally(_HUB_IMAGE):
        log.debug("Sandbox: using cached Hub image %s", _HUB_IMAGE)
        return _HUB_IMAGE

    log.info(
        "Sandbox: image not in local cache — trying Docker Hub pull…\n"
        "         (only happens once per machine, cached afterwards)"
    )
    if _pull_image(_HUB_IMAGE):
        return _HUB_IMAGE

    log.warning(
        "Sandbox: Docker Hub pull failed — building local fallback image.\n"
        "         Works offline and in air-gapped environments."
    )
    if _image_exists_locally(_LOCAL_TAG):
        return _LOCAL_TAG
    return _LOCAL_TAG if _build_local_image() else None


# ── Main engine entry ─────────────────────────────────────────────────────────


def run_sandbox_scan(file_path: str, stripped_content: Optional[str] = None) -> list[Finding]:
    """
    Stage 3 — behavioural sandbox scan.

    Resolves image (Hub cache → Hub pull → local build), runs the component
    in an isolated container, parses JSON behaviour report, returns findings.

    Args:
        file_path:        Original file path (used as fallback and for logging).
        stripped_content: Code-fence-stripped content. When provided, written to
                          a temp file so the container sees de-fenced input —
                          preventing false positives from documentation examples.
    """
    findings: list[Finding] = []

    if not SANDBOX_ENABLED:
        log.debug("Sandbox: disabled — set BAWBEL_SANDBOX_ENABLED=true")
        return findings

    if not is_docker_available():
        log.warning("Sandbox: Docker not running — Stage 3 skipped")
        return findings

    image = _resolve_image()
    if image is None:
        log.warning("Sandbox: no image available — Stage 3 skipped")
        return findings

    log.debug(Logs.ENGINE_START, "sandbox", file_path)
    with Timer() as t:
        if stripped_content is not None:
            suffix = Path(file_path).suffix or ".md"
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(stripped_content)
                tmp_path = tmp.name
            try:
                findings = _run_container(tmp_path, image)
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
        else:
            findings = _run_container(file_path, image)
    log.debug(Logs.ENGINE_COMPLETE, "sandbox", len(findings), t.elapsed_ms)
    return findings


def _run_container(file_path: str, image: str) -> list[Finding]:
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        SANDBOX_NETWORK,
        "--memory",
        "256m",
        "--cpus",
        "0.5",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:size=32m",  # nosec B108  # noqa: S108
        "-v",
        f"{file_path}:/component:ro",
        image,
    ]
    stdout, err = run_subprocess(
        args=cmd,
        timeout=SANDBOX_TIMEOUT_SEC + 5,
        label="sandbox-run",
    )
    if stdout is None:
        log.warning("Sandbox: container produced no output")
        return []
    if err:
        log.debug("Sandbox stderr: %s", err[:200])
    try:
        return _parse_report(json.loads(stdout), file_path)
    except json.JSONDecodeError:
        log.warning("Sandbox: could not parse container JSON output")
        return []


def _parse_report(report: dict, file_path: str) -> list[Finding]:
    findings: list[Finding] = []

    for event in report.get("network", []):
        dst = event.get("dst", "")
        reason = event.get("reason", "")
        line = event.get("line")
        desc, ave_id, sev, cvss = _match_network_ioc(dst, reason)
        if desc:
            findings.append(
                Finding(
                    rule_id=f"sandbox-net-{ave_id.replace('-', '').lower()}",
                    ave_id=ave_id,
                    title=f"Behavioural: {desc}",
                    description=(
                        f"Runtime network egress to {dst!r}. {reason}. "
                        f"Observed during sandbox execution — not inferred from text."
                    ),
                    severity=Severity(sev),
                    cvss_ai=cvss,
                    line=line,
                    match=dst[:80],
                    engine="sandbox",
                    owasp=["ASI01", "ASI08"],
                )
            )

    for event in report.get("filesystem", []):
        path = event.get("path", "")
        op = event.get("op", "")
        reason = event.get("reason", "")
        line = event.get("line")
        desc, ave_id, sev, cvss = _match_fs_ioc(path, op, reason)
        if desc:
            findings.append(
                Finding(
                    rule_id=f"sandbox-fs-{ave_id.replace('-', '').lower()}",
                    ave_id=ave_id,
                    title=f"Behavioural: {desc}",
                    description=f"Runtime filesystem {op} at {path!r}. {reason}.",
                    severity=Severity(sev),
                    cvss_ai=cvss,
                    line=line,
                    match=f"{op} {path}"[:80],
                    engine="sandbox",
                    owasp=["ASI07"],
                )
            )

    for event in report.get("processes", []):
        cmd = event.get("cmd", "")
        reason = event.get("reason", "")
        line = event.get("line")
        desc, ave_id, sev, cvss = _match_process_ioc(cmd, reason)
        if desc:
            findings.append(
                Finding(
                    rule_id=f"sandbox-proc-{ave_id.replace('-', '').lower()}",
                    ave_id=ave_id,
                    title=f"Behavioural: {desc}",
                    description=f"Subprocess: {cmd!r}. {reason}.",
                    severity=Severity(sev),
                    cvss_ai=cvss,
                    line=line,
                    match=cmd[:80],
                    engine="sandbox",
                    owasp=["ASI07"],
                )
            )

    for event in report.get("encoded", []):
        enc_type = event.get("type", "base64")
        value = event.get("value", "")
        decoded = event.get("decoded", "")
        line = event.get("line")
        findings.append(
            Finding(
                rule_id="sandbox-encoded-payload",
                ave_id="AVE-2026-00001",
                title=f"Behavioural: {enc_type.upper()} encoded payload with suspicious content",
                description=(
                    f"Encoded payload ({enc_type}) — suspicious decoded content: {decoded[:100]!r}"
                ),
                severity=Severity("HIGH"),
                cvss_ai=8.0,
                line=line,
                match=value[:80],
                engine="sandbox",
                owasp=["ASI01"],
            )
        )

    return findings


# ── IOC matchers ─────────────────────────────────────────────────────────────


def _match_network_ioc(dst: str, reason: str):
    d = dst.lower()
    for kw, idx in [
        ("pastebin.com", 0),
        ("rentry.co", 1),
        ("raw.githubusercontent.com", 2),
        ("gist.githubusercontent.com", 3),
        ("ngrok", 4),
        ("webhook.site", 5),
        ("requestbin", 5),
    ]:
        if kw in d:
            return _NETWORK_IOCS[idx]
    return ("", "", "", 0.0)


def _match_fs_ioc(path: str, op: str, reason: str):
    p = path.lower()
    r = reason.lower()
    if ".bashrc" in p or ".zshrc" in p or ".profile" in p:
        return _FILESYSTEM_IOCS[0]
    if "cron" in p:
        return _FILESYSTEM_IOCS[1]
    if ".ssh" in p:
        return _FILESYSTEM_IOCS[2]
    if ".env" in p or "env" in r:
        return _FILESYSTEM_IOCS[3]
    if "private" in p or "private" in r:
        return _FILESYSTEM_IOCS[4]
    if op == "delete" or "rm -rf" in r:
        return _FILESYSTEM_IOCS[5]
    return ("", "", "", 0.0)


def _match_process_ioc(cmd: str, reason: str):
    c = cmd.lower()
    if "curl" in c and "|" in c:
        return _PROCESS_IOCS[0]
    if "wget" in c and "|" in c:
        return _PROCESS_IOCS[1]
    if "|" in c and any(s in c for s in ["bash", "sh", "zsh", "python"]):
        return _PROCESS_IOCS[2]
    if "eval" in c:
        return _PROCESS_IOCS[3]
    if "exec" in c:
        return _PROCESS_IOCS[4]
    if "systemctl" in c or "crontab" in c:
        return _PROCESS_IOCS[5]
    if "pip" in c and "install" in c:
        return _PROCESS_IOCS[6]
    if "npm" in c and "install" in c:
        return _PROCESS_IOCS[7]
    return ("", "", "", 0.0)
