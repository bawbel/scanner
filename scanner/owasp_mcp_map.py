"""
Bawbel Scanner — OWASP MCP Top 10 mapping.

Maps AVE IDs to OWASP MCP Top 10 categories (MCP01–MCP10).
Used to add owasp_mcp field to scan output for compliance reporting.

Reference: https://owasp.org/www-project-mcp-top-10/
"""

# Primary mapping: AVE ID → [primary MCP category, secondary MCP category]
AVE_TO_OWASP_MCP: dict[str, list[str]] = {
    "AVE-2026-00001": ["MCP04", "MCP06"],
    "AVE-2026-00002": ["MCP03", "MCP10"],
    "AVE-2026-00003": ["MCP01", "MCP05"],
    "AVE-2026-00004": ["MCP05", "MCP06"],
    "AVE-2026-00005": ["MCP05"],
    "AVE-2026-00006": ["MCP05", "MCP02"],
    "AVE-2026-00007": ["MCP06"],
    "AVE-2026-00008": ["MCP05", "MCP04"],
    "AVE-2026-00009": ["MCP06"],
    "AVE-2026-00010": ["MCP06", "MCP08"],
    "AVE-2026-00011": ["MCP03", "MCP05"],
    "AVE-2026-00012": ["MCP02", "MCP07"],
    "AVE-2026-00013": ["MCP01", "MCP05"],
    "AVE-2026-00014": ["MCP07", "MCP09"],
    "AVE-2026-00015": ["MCP10", "MCP08"],
    "AVE-2026-00016": ["MCP10", "MCP03"],
    "AVE-2026-00017": ["MCP09", "MCP07"],
    "AVE-2026-00018": ["MCP03", "MCP08"],
    "AVE-2026-00019": ["MCP10", "MCP06"],
    "AVE-2026-00020": ["MCP10", "MCP06"],
    "AVE-2026-00021": ["MCP02", "MCP08"],
    "AVE-2026-00022": ["MCP02"],
    "AVE-2026-00023": ["MCP10", "MCP06"],
    "AVE-2026-00024": ["MCP04"],
    "AVE-2026-00025": ["MCP10", "MCP06"],
    "AVE-2026-00026": ["MCP01", "MCP08"],
    "AVE-2026-00027": ["MCP06", "MCP10"],
    "AVE-2026-00028": ["MCP10", "MCP03"],
    "AVE-2026-00029": ["MCP03", "MCP04"],
    "AVE-2026-00030": ["MCP07", "MCP02"],
    "AVE-2026-00031": ["MCP06", "MCP04"],
    "AVE-2026-00032": ["MCP05", "MCP02"],
    "AVE-2026-00033": ["MCP05", "MCP04"],
    "AVE-2026-00034": ["MCP04", "MCP03"],
    "AVE-2026-00035": ["MCP03", "MCP08"],
    "AVE-2026-00036": ["MCP05", "MCP02"],
    "AVE-2026-00037": ["MCP10", "MCP03"],
    "AVE-2026-00038": ["MCP02", "MCP08"],
    "AVE-2026-00039": ["MCP01", "MCP08"],
    "AVE-2026-00040": ["MCP05", "MCP10"],
    "AVE-2026-00041": ["MCP03", "MCP09"],
    "AVE-2026-00042": ["MCP05", "MCP10"],
    "AVE-2026-00043": ["MCP10", "MCP03"],
    "AVE-2026-00044": ["MCP10", "MCP06"],
    "AVE-2026-00045": ["MCP02", "MCP09"],
}

OWASP_MCP_DESCRIPTIONS: dict[str, str] = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit & Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-sharing",
}


def get_owasp_mcp(ave_id: str | None) -> list[str]:
    """Return OWASP MCP Top 10 categories for a given AVE ID."""
    if not ave_id:
        return []
    return AVE_TO_OWASP_MCP.get(ave_id, [])
