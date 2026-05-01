"""
Bawbel Scanner — CLI display constants.

Single source of truth for severity colours, icons, OWASP descriptions,
and the remediation guide. All CLI modules import from here — never define
these values in command files.
"""

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange3",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "dim white",
}

SEVERITY_ICONS: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

OWASP_DESCRIPTIONS: dict[str, str] = {
    "ASI01": "Prompt Injection",
    "ASI02": "Sensitive Data Exposure",
    "ASI03": "Supply Chain Compromise",
    "ASI04": "Insecure Tool Calls",
    "ASI05": "Unsafe Resource Access",
    "ASI06": "Data Exfiltration",
    "ASI07": "Tool Abuse",
    "ASI08": "Goal Hijacking",
    "ASI09": "Trust Manipulation",
    "ASI10": "Sandbox Escape",
}

REMEDIATION_GUIDE: dict[str, str] = {
    "bawbel-goal-override": (
        "Remove instructions that attempt to override agent goals. "
        "Legitimate skills do not need to tell an agent to forget prior instructions."
    ),
    "bawbel-jailbreak-instruction": (
        "Remove role-play instructions that tell the agent to act outside its "
        "intended purpose or disable safety constraints."
    ),
    "bawbel-hidden-instruction": (
        "Remove any instructions that tell the agent to hide its behaviour "
        "from the user or operator."
    ),
    "bawbel-external-fetch": (
        "Remove all external URL fetches for instructions. Embed all instructions "
        "directly in the component. Use signed registries for dynamic config."
    ),
    "bawbel-dynamic-tool-call": (
        "Do not construct tool calls from external or user-controlled input. "
        "Validate all tool parameters before execution."
    ),
    "bawbel-permission-escalation": (
        "Remove undeclared permission claims. Declare all required permissions in "
        "the component manifest and request only what is needed."
    ),
    "bawbel-env-exfiltration": (
        "Remove all instructions to read or transmit credentials, .env files, "
        "or API keys. Never include credentials in component outputs."
    ),
    "bawbel-pii-exfiltration": (
        "Remove all instructions to collect or transmit personal data without "
        "explicit user consent and a declared privacy policy."
    ),
    "bawbel-shell-pipe": (
        "Remove shell pipe patterns (curl|bash). If code execution is genuinely "
        "required, use a sandboxed tool with explicit user consent."
    ),
    "bawbel-destructive-command": (
        "Remove all destructive file system commands. "
        "Components should never delete files recursively."
    ),
    "bawbel-crypto-drain": (
        "Remove all wallet or fund transfer instructions. "
        "Financial operations require explicit per-transaction user authorisation."
    ),
    "bawbel-trust-escalation": (
        "Remove claims of special authority or impersonation of trusted parties. "
        "Legitimate components do not need to claim exceptional trust."
    ),
    "bawbel-persistence-attempt": (
        "Remove any instructions to copy the component, modify startup scripts, "
        "or establish persistent access."
    ),
    "bawbel-mcp-tool-poisoning": (
        "Remove instructions embedded in tool descriptions. Tool descriptions "
        "should only describe tool functionality, not give the agent additional tasks."
    ),
    "bawbel-system-prompt-leak": (
        "Remove instructions that attempt to extract the system prompt "
        "or operating configuration."
    ),
}
