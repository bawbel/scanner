"""
Bawbel Scanner - MCP spec conformance checks.

Each ConformanceCheck defines one rule from the MCP specification.
Checks are pure data - no logic here. The scorer in scorer.py runs them.

Conformance check categories:
    REQUIRED       - MUST per spec. Failure = non-conformant. Weight: 3
    RECOMMENDED    - SHOULD per spec. Failure = partial. Weight: 2
    BEST_PRACTICE  - good practice, widely adopted. Weight: 1

Adding a new check:
    1. Define a ConformanceCheck below
    2. Add it to CONFORMANCE_CHECKS
    That's it - scorer.py picks it up automatically

References:
    https://spec.modelcontextprotocol.io/specification/
    https://modelcontextprotocol.io/specification/draft/server/tools
    SEP-1649: .well-known/mcp/server-card.json
"""

from dataclasses import dataclass
from enum import Enum


class CheckCategory(str, Enum):
    REQUIRED = "REQUIRED"  # MUST per spec - weight 3
    RECOMMENDED = "RECOMMENDED"  # SHOULD per spec - weight 2
    BEST_PRACTICE = "BEST_PRACTICE"  # good practice - weight 1


class CheckStatus(str, Enum):
    # PASS is an enum value, not a credential
    PASS = "pass"  # nosec B105  # noqa: S105
    FAIL = "fail"
    WARN = "warn"  # partial / degraded
    SKIP = "skip"  # check not applicable to this component type


@dataclass(frozen=True)
class ConformanceCheck:
    """
    Definition of a single conformance check.

    check_id:    unique kebab-case identifier
    category:    REQUIRED | RECOMMENDED | BEST_PRACTICE
    title:       short human-readable name
    detail:      what the check verifies
    remediation: how to fix a failure
    """

    check_id: str
    category: CheckCategory
    title: str
    detail: str
    remediation: str


# ── Registry manifest checks (server-card / .well-known/mcp.json) ─────────────

CONFORMANCE_CHECKS: list[ConformanceCheck] = [
    # ── Identity ───────────────────────────────────────────────────────────────
    ConformanceCheck(
        check_id="has-name",
        category=CheckCategory.REQUIRED,
        title="Server has a name",
        detail="Server manifest includes a non-empty 'name' or 'displayName' field.",
        remediation="Add 'name' field to the server manifest.",
    ),
    ConformanceCheck(
        check_id="has-description",
        category=CheckCategory.REQUIRED,
        title="Server has a description",
        detail="Server manifest includes a non-empty 'description' field.",
        remediation="Add 'description' field describing what the server does.",
    ),
    ConformanceCheck(
        check_id="has-version",
        category=CheckCategory.REQUIRED,
        title="Server has a version",
        detail="Server manifest includes a 'version' field using semver.",
        remediation="Add 'version' field in semver format (e.g. '1.0.0').",
    ),
    ConformanceCheck(
        check_id="has-schema-ref",
        category=CheckCategory.RECOMMENDED,
        title="Manifest references the official schema",
        detail="Manifest includes '$schema' pointing to static.modelcontextprotocol.io.",
        remediation=(
            "Add '$schema': "
            "'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json'"
        ),
    ),
    # ── Transport ──────────────────────────────────────────────────────────────
    ConformanceCheck(
        check_id="has-remotes",
        category=CheckCategory.REQUIRED,
        title="Server declares transport endpoints",
        detail="Server manifest includes a non-empty 'remotes' array.",
        remediation="Add 'remotes' array with at least one transport endpoint.",
    ),
    ConformanceCheck(
        check_id="uses-streamable-http",
        category=CheckCategory.RECOMMENDED,
        title="Server uses streamable-http transport",
        detail=(
            "Remote endpoints use 'streamable-http' type. "
            "HTTP+SSE was deprecated in the 2025-03-26 spec."
        ),
        remediation=(
            "Migrate from 'http+sse' to 'streamable-http' transport. "
            "See: https://spec.modelcontextprotocol.io/specification/"
        ),
    ),
    ConformanceCheck(
        check_id="uses-https",
        category=CheckCategory.REQUIRED,
        title="All transport URLs use HTTPS",
        detail="All remote endpoint URLs use the https:// scheme.",
        remediation=(
            "Ensure all transport URLs use HTTPS. "
            "HTTP endpoints are not safe for MCP servers handling sensitive data."
        ),
    ),
    # ── Tools ──────────────────────────────────────────────────────────────────
    ConformanceCheck(
        check_id="tools-have-descriptions",
        category=CheckCategory.REQUIRED,
        title="All tools have descriptions",
        detail="Every tool in the manifest has a non-empty 'description' field.",
        remediation=(
            "Add descriptions to all tools. "
            "Tool descriptions are how the agent decides which tool to call."
        ),
    ),
    ConformanceCheck(
        check_id="tools-have-input-schema",
        category=CheckCategory.REQUIRED,
        title="All tools declare an inputSchema",
        detail="Every tool declares an 'inputSchema' of type 'object'.",
        remediation=("Add 'inputSchema': {'type': 'object', 'properties': {...}} to all tools."),
    ),
    ConformanceCheck(
        check_id="tool-names-valid",
        category=CheckCategory.REQUIRED,
        title="All tool names follow the spec naming rules",
        detail=(
            "Tool names are 1-128 chars, contain only "
            "ASCII letters/digits/underscore/hyphen/dot, no spaces."
        ),
        remediation=(
            "Rename tools to use only: A-Z, a-z, 0-9, _, -, . "
            "Max 128 characters, no spaces or special characters."
        ),
    ),
    ConformanceCheck(
        check_id="tool-names-unique",
        category=CheckCategory.REQUIRED,
        title="Tool names are unique within the server",
        detail="No two tools share the same name.",
        remediation="Rename duplicate tools - tool names must be unique within a server.",
    ),
    ConformanceCheck(
        check_id="tools-params-have-descriptions",
        category=CheckCategory.RECOMMENDED,
        title="All tool parameters have descriptions",
        detail="Every inputSchema property includes a 'description' field.",
        remediation=(
            "Add descriptions to all tool parameters. "
            "Parameter descriptions help the agent pass the right values."
        ),
    ),
    ConformanceCheck(
        check_id="tools-declare-required-params",
        category=CheckCategory.RECOMMENDED,
        title="Tools declare required parameters",
        detail="Tools with required parameters include a 'required' array in inputSchema.",
        remediation=(
            "Add 'required': ['param_name'] to inputSchema for " "parameters that must be provided."
        ),
    ),
    # ── Security ───────────────────────────────────────────────────────────────
    ConformanceCheck(
        check_id="no-deprecated-sse-transport",
        category=CheckCategory.RECOMMENDED,
        title="Server does not use deprecated HTTP+SSE transport",
        detail="No remote endpoint uses the deprecated 'http+sse' transport type.",
        remediation="Replace 'http+sse' with 'streamable-http' transport.",
    ),
    ConformanceCheck(
        check_id="no-sensitive-params-in-headers",
        category=CheckCategory.BEST_PRACTICE,
        title="Sensitive parameters are not exposed as HTTP headers",
        detail=(
            "No tool parameter named 'password', 'token', 'key', 'secret', "
            "or 'api_key' has 'x-mcp-header' set."
        ),
        remediation=(
            "Remove x-mcp-header from sensitive parameters. "
            "Header values are visible to network intermediaries."
        ),
    ),
    ConformanceCheck(
        check_id="has-repository",
        category=CheckCategory.BEST_PRACTICE,
        title="Server declares a source repository",
        detail="Manifest includes a 'repository' field with a source URL.",
        remediation=(
            "Add 'repository': {'url': 'https://github.com/...'} " "for supply chain transparency."
        ),
    ),
    ConformanceCheck(
        check_id="description-not-too-long",
        category=CheckCategory.BEST_PRACTICE,
        title="Server description is a reasonable length",
        detail="Server description is under 500 characters.",
        remediation=(
            "Shorten the server description to under 500 characters. "
            "Long descriptions consume excessive agent context."
        ),
    ),
    ConformanceCheck(
        check_id="tool-descriptions-not-too-long",
        category=CheckCategory.BEST_PRACTICE,
        title="Tool descriptions are a reasonable length",
        detail="No single tool description exceeds 1000 characters.",
        remediation=(
            "Shorten tool descriptions to under 1000 characters. "
            "Overly long descriptions consume agent context and may indicate injection."
        ),
    ),
]

# Fast lookup by check_id
CHECKS_BY_ID: dict[str, ConformanceCheck] = {c.check_id: c for c in CONFORMANCE_CHECKS}

# Weights for scoring
CATEGORY_WEIGHTS: dict[CheckCategory, int] = {
    CheckCategory.REQUIRED: 3,
    CheckCategory.RECOMMENDED: 2,
    CheckCategory.BEST_PRACTICE: 1,
}

# Total possible score
MAX_SCORE: int = sum(CATEGORY_WEIGHTS[c.category] for c in CONFORMANCE_CHECKS)
