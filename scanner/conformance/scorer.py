"""
Bawbel Scanner - MCP spec conformance scorer.

Takes a parsed MCP registry entry (server manifest dict) and runs
all conformance checks against it, returning a ConformanceReport.

Design principles:
    - Pure function - no side effects, safe to call concurrently
    - Fails safe - a check that errors marks itself as WARN, never crashes
    - All checks are independent - one failure never blocks others
    - Score is 0-100, normalized from weighted pass/fail results
"""

import re
from dataclasses import dataclass, field

from scanner.conformance.checks import (
    CATEGORY_WEIGHTS,
    CONFORMANCE_CHECKS,
    CheckCategory,
    CheckStatus,
    ConformanceCheck,
)

# ── Result types ───────────────────────────────────────────────────────────────


@dataclass
class CheckResult:
    """Result of running one conformance check."""

    check: ConformanceCheck
    status: CheckStatus
    message: str = ""  # extra context, populated on FAIL/WARN

    def to_dict(self) -> dict:
        return {
            "check_id": self.check.check_id,
            "category": self.check.category.value,
            "title": self.check.title,
            "status": self.status.value,
            "message": self.message,
            "remediation": self.check.remediation if self.status == CheckStatus.FAIL else "",
        }


@dataclass
class ConformanceReport:
    """
    Complete conformance report for one MCP server manifest.

    score:   0-100 - percentage of weighted checks passed
    grade:   A+/A/B/C/D/F based on score
    passed:  number of checks passed
    failed:  number of checks failed
    warned:  number of checks with warnings
    results: per-check results, sorted: FAIL first, then WARN, then PASS
    """

    score: float
    grade: str
    passed: int
    failed: int
    warned: int
    skipped: int
    results: list[CheckResult] = field(default_factory=list)

    @property
    def is_conformant(self) -> bool:
        """True if all applicable REQUIRED checks pass (SKIPs excluded)."""
        return all(
            r.status == CheckStatus.PASS
            for r in self.results
            if r.check.category == CheckCategory.REQUIRED and r.status != CheckStatus.SKIP
        )

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "grade": self.grade,
            "is_conformant": self.is_conformant,
            "passed": self.passed,
            "failed": self.failed,
            "warned": self.warned,
            "skipped": self.skipped,
            "results": [r.to_dict() for r in self.results],
        }


# ── Tool name validation regex ─────────────────────────────────────────────────

_VALID_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.\\-]{1,128}$")

_SENSITIVE_PARAM_NAMES = frozenset(
    {
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "secret",
        "key",
        "credential",
        "auth",
        "access_token",
        "private_key",
        "client_secret",
    }
)


# ── Individual check runners ───────────────────────────────────────────────────


def _check(check_id: str, status: CheckStatus, message: str = "") -> CheckResult:
    from scanner.conformance.checks import CHECKS_BY_ID

    return CheckResult(
        check=CHECKS_BY_ID[check_id],
        status=status,
        message=message,
    )


def _run_check(check_id: str, manifest: dict) -> CheckResult:
    """
    Run a single check against the manifest dict.
    Returns CheckResult. Never raises.
    """
    try:
        return _RUN_MAP[check_id](manifest)
    except Exception as e:  # noqa: BLE001
        return _check(check_id, CheckStatus.WARN, f"Check error: {e}")


# ── Check implementations ──────────────────────────────────────────────────────


def _c_has_name(m: dict) -> CheckResult:
    name = m.get("name") or m.get("displayName") or m.get("title") or ""
    if name.strip():
        return _check("has-name", CheckStatus.PASS)
    return _check("has-name", CheckStatus.FAIL, "No 'name' field found")


def _c_has_description(m: dict) -> CheckResult:
    desc = m.get("description") or ""
    if desc.strip():
        return _check("has-description", CheckStatus.PASS)
    return _check("has-description", CheckStatus.FAIL, "No 'description' field found")


def _c_has_version(m: dict) -> CheckResult:
    ver = m.get("version") or ""
    if ver.strip():
        return _check("has-version", CheckStatus.PASS)
    return _check("has-version", CheckStatus.FAIL, "No 'version' field found")


def _c_has_schema_ref(m: dict) -> CheckResult:
    schema = m.get("$schema") or ""
    if "modelcontextprotocol.io" in schema:
        return _check("has-schema-ref", CheckStatus.PASS)
    return _check("has-schema-ref", CheckStatus.WARN, "No '$schema' reference to MCP spec")


def _c_has_remotes(m: dict) -> CheckResult:
    remotes = m.get("remotes") or []
    if remotes:
        return _check("has-remotes", CheckStatus.PASS)
    return _check("has-remotes", CheckStatus.FAIL, "No 'remotes' transport endpoints declared")


def _c_uses_streamable_http(m: dict) -> CheckResult:
    remotes = m.get("remotes") or []
    if not remotes:
        return _check("uses-streamable-http", CheckStatus.SKIP)
    has_streamable = any(r.get("type") == "streamable-http" for r in remotes if isinstance(r, dict))
    if has_streamable:
        return _check("uses-streamable-http", CheckStatus.PASS)
    return _check(
        "uses-streamable-http",
        CheckStatus.WARN,
        "No streamable-http remote found - server may use deprecated transport",
    )


def _c_uses_https(m: dict) -> CheckResult:
    remotes = m.get("remotes") or []
    if not remotes:
        return _check("uses-https", CheckStatus.SKIP)
    http_urls = [
        r.get("url", "")
        for r in remotes
        if isinstance(r, dict) and str(r.get("url", "")).startswith("http://")
    ]
    if not http_urls:
        return _check("uses-https", CheckStatus.PASS)
    return _check(
        "uses-https", CheckStatus.FAIL, f"Non-HTTPS transport URLs: {', '.join(http_urls)}"
    )


def _c_tools_have_descriptions(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    if not tools:
        return _check("tools-have-descriptions", CheckStatus.SKIP)
    missing = [t.get("name", "?") for t in tools if not t.get("description", "").strip()]
    if not missing:
        return _check("tools-have-descriptions", CheckStatus.PASS)
    return _check(
        "tools-have-descriptions",
        CheckStatus.FAIL,
        f"Tools missing description: {', '.join(missing)}",
    )


def _c_tools_have_input_schema(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    if not tools:
        return _check("tools-have-input-schema", CheckStatus.SKIP)
    missing = [t.get("name", "?") for t in tools if not isinstance(t.get("inputSchema"), dict)]
    if not missing:
        return _check("tools-have-input-schema", CheckStatus.PASS)
    return _check(
        "tools-have-input-schema",
        CheckStatus.FAIL,
        f"Tools missing inputSchema: {', '.join(missing)}",
    )


def _c_tool_names_valid(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    if not tools:
        return _check("tool-names-valid", CheckStatus.SKIP)
    invalid = [t.get("name", "") for t in tools if not _VALID_TOOL_NAME.match(t.get("name", ""))]
    if not invalid:
        return _check("tool-names-valid", CheckStatus.PASS)
    return _check("tool-names-valid", CheckStatus.FAIL, f"Invalid tool names: {', '.join(invalid)}")


def _c_tool_names_unique(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    if not tools:
        return _check("tool-names-unique", CheckStatus.SKIP)
    names = [t.get("name", "") for t in tools]
    dupes = [n for n in set(names) if names.count(n) > 1]
    if not dupes:
        return _check("tool-names-unique", CheckStatus.PASS)
    return _check(
        "tool-names-unique", CheckStatus.FAIL, f"Duplicate tool names: {', '.join(dupes)}"
    )


def _c_tools_params_have_descriptions(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    if not tools:
        return _check("tools-params-have-descriptions", CheckStatus.SKIP)
    missing_params: list[str] = []
    for t in tools:
        schema = t.get("inputSchema", {}) or {}
        props = schema.get("properties", {}) or {}
        for param_name, param_def in props.items():
            if isinstance(param_def, dict) and not param_def.get("description", "").strip():
                missing_params.append(f"{t.get('name', '?')}.{param_name}")
    if not missing_params:
        return _check("tools-params-have-descriptions", CheckStatus.PASS)
    sample = missing_params[:3]
    extra = f" (+{len(missing_params) - 3} more)" if len(missing_params) > 3 else ""
    return _check(
        "tools-params-have-descriptions",
        CheckStatus.WARN,
        f"Parameters missing description: {', '.join(sample)}{extra}",
    )


def _c_tools_declare_required_params(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    if not tools:
        return _check("tools-declare-required-params", CheckStatus.SKIP)
    no_required = [
        t.get("name", "?")
        for t in tools
        if (t.get("inputSchema", {}) or {}).get("properties")
        and "required" not in (t.get("inputSchema", {}) or {})
    ]
    if not no_required:
        return _check("tools-declare-required-params", CheckStatus.PASS)
    return _check(
        "tools-declare-required-params",
        CheckStatus.WARN,
        f"Tools with parameters but no 'required' declaration: {', '.join(no_required)}",
    )


def _c_no_deprecated_sse(m: dict) -> CheckResult:
    remotes = m.get("remotes") or []
    sse = [r.get("url", "") for r in remotes if isinstance(r, dict) and r.get("type") == "http+sse"]
    if not sse:
        return _check("no-deprecated-sse-transport", CheckStatus.PASS)
    return _check(
        "no-deprecated-sse-transport",
        CheckStatus.WARN,
        f"Deprecated http+sse transport in use: {', '.join(sse)}",
    )


def _c_no_sensitive_headers(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    flagged: list[str] = []
    for t in tools:
        schema = t.get("inputSchema", {}) or {}
        props = schema.get("properties", {}) or {}
        for param_name, param_def in props.items():
            if (
                isinstance(param_def, dict)
                and "x-mcp-header" in param_def
                and param_name.lower() in _SENSITIVE_PARAM_NAMES
            ):
                flagged.append(f"{t.get('name', '?')}.{param_name}")
    if not flagged:
        return _check("no-sensitive-params-in-headers", CheckStatus.PASS)
    return _check(
        "no-sensitive-params-in-headers",
        CheckStatus.WARN,
        f"Sensitive params exposed as HTTP headers: {', '.join(flagged)}",
    )


def _c_has_repository(m: dict) -> CheckResult:
    repo = m.get("repository") or {}
    if isinstance(repo, dict) and repo.get("url"):
        return _check("has-repository", CheckStatus.PASS)
    if isinstance(repo, str) and repo.strip():
        return _check("has-repository", CheckStatus.PASS)
    return _check("has-repository", CheckStatus.WARN, "No source repository declared")


def _c_description_not_too_long(m: dict) -> CheckResult:
    desc = m.get("description") or ""
    if len(desc) <= 500:
        return _check("description-not-too-long", CheckStatus.PASS)
    return _check(
        "description-not-too-long",
        CheckStatus.WARN,
        f"Description is {len(desc)} chars - over 500 char limit",
    )


def _c_tool_descriptions_not_too_long(m: dict) -> CheckResult:
    tools = m.get("tools") or []
    if not tools:
        return _check("tool-descriptions-not-too-long", CheckStatus.SKIP)
    too_long = [
        f"{t.get('name', '?')} ({len(t.get('description', ''))} chars)"
        for t in tools
        if len(t.get("description", "")) > 1000
    ]
    if not too_long:
        return _check("tool-descriptions-not-too-long", CheckStatus.PASS)
    return _check(
        "tool-descriptions-not-too-long",
        CheckStatus.WARN,
        f"Overly long tool descriptions: {', '.join(too_long)}",
    )


# ── Dispatch map ───────────────────────────────────────────────────────────────

_RUN_MAP = {
    "has-name": _c_has_name,
    "has-description": _c_has_description,
    "has-version": _c_has_version,
    "has-schema-ref": _c_has_schema_ref,
    "has-remotes": _c_has_remotes,
    "uses-streamable-http": _c_uses_streamable_http,
    "uses-https": _c_uses_https,
    "tools-have-descriptions": _c_tools_have_descriptions,
    "tools-have-input-schema": _c_tools_have_input_schema,
    "tool-names-valid": _c_tool_names_valid,
    "tool-names-unique": _c_tool_names_unique,
    "tools-params-have-descriptions": _c_tools_params_have_descriptions,
    "tools-declare-required-params": _c_tools_declare_required_params,
    "no-deprecated-sse-transport": _c_no_deprecated_sse,
    "no-sensitive-params-in-headers": _c_no_sensitive_headers,
    "has-repository": _c_has_repository,
    "description-not-too-long": _c_description_not_too_long,
    "tool-descriptions-not-too-long": _c_tool_descriptions_not_too_long,
}


# ── Grading ────────────────────────────────────────────────────────────────────


def _grade(score: float) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ── Public API ─────────────────────────────────────────────────────────────────


def score_conformance(manifest: dict) -> ConformanceReport:
    """
    Run all conformance checks against a parsed MCP manifest dict.

    Args:
        manifest: Parsed server manifest - from registry API, server-card,
                  or any dict matching the MCP server schema.

    Returns:
        ConformanceReport with score 0-100, grade A+-F, and per-check results.
    """
    results: list[CheckResult] = []

    for check in CONFORMANCE_CHECKS:
        result = _run_check(check.check_id, manifest)
        results.append(result)

    # Score - weighted pass/fail
    earned = sum(
        CATEGORY_WEIGHTS[r.check.category] for r in results if r.status == CheckStatus.PASS
    )
    # WARN counts as half credit
    earned += sum(
        CATEGORY_WEIGHTS[r.check.category] * 0.5 for r in results if r.status == CheckStatus.WARN
    )

    # Exclude SKIP from denominator
    applicable_max = sum(
        CATEGORY_WEIGHTS[r.check.category] for r in results if r.status != CheckStatus.SKIP
    )

    score = (earned / applicable_max * 100) if applicable_max > 0 else 0.0

    # Sort results: FAIL -> WARN -> PASS -> SKIP
    _order = {
        CheckStatus.FAIL: 0,
        CheckStatus.WARN: 1,
        CheckStatus.PASS: 2,
        CheckStatus.SKIP: 3,
    }
    results.sort(key=lambda r: _order[r.status])

    return ConformanceReport(
        score=score,
        grade=_grade(score),
        passed=sum(1 for r in results if r.status == CheckStatus.PASS),
        failed=sum(1 for r in results if r.status == CheckStatus.FAIL),
        warned=sum(1 for r in results if r.status == CheckStatus.WARN),
        skipped=sum(1 for r in results if r.status == CheckStatus.SKIP),
        results=results,
    )
