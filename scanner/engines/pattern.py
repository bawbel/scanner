"""
Bawbel Scanner — Pattern matching engine (Stage 1a).

Pure Python regex matching. No external dependencies.
Always runs regardless of what else is installed.

To add a new pattern rule: add an entry to PATTERN_RULES below.
No other files need to change.

Rule authoring guide:
  - rule_id:  kebab-case, prefix "bawbel-", never change once published
  - ave_id:   AVE-2026-NNNNN if a record exists, else None
  - severity: CRITICAL (9+), HIGH (7-8.9), MEDIUM (4-6.9), LOW (<4)
  - patterns: list of regex — re.IGNORECASE applied, first match wins per rule
  - Use \\s+ not spaces — content may have irregular whitespace
"""

import re

from scanner.messages import Logs
from scanner.models import Finding, Severity
from scanner.utils import get_logger

log = get_logger(__name__)

MAX_MATCH_LENGTH = 80


# ── Pattern rules ─────────────────────────────────────────────────────────────
# One finding per rule per file — first matching pattern wins.
# Rules are evaluated in order — put most critical first.

PATTERN_RULES: list[dict] = [
    # ── Goal hijack / prompt injection ───────────────────────────────────────
    {
        "rule_id": "bawbel-goal-override",
        "ave_id": "AVE-2026-00007",
        "title": "Goal override instruction detected",
        "description": (
            "Component contains language attempting to override agent goals "
            "or replace prior instructions. Classic prompt injection vector."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.1,
        "owasp": ["ASI01", "ASI08"],
        "patterns": [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"disregard\s+your\s+(previous\s+)?instructions",
            r"forget\s+your\s+(previous\s+)?instructions",
            r"your\s+new\s+instructions\s+are",
            r"override\s+your\s+(previous\s+|prior\s+)?instructions",
            r"regardless\s+of\s+what\s+you\s+were\s+told",
            r"instead\s+of\s+what\s+you\s+were\s+asked",
            r"your\s+real\s+(task|job|purpose|goal|mission)\s+is",
            r"actual\s+(task|instructions|purpose)\s*:",
        ],
    },
    {
        "rule_id": "bawbel-jailbreak-instruction",
        "ave_id": "AVE-2026-00009",
        "title": "Jailbreak instruction detected",
        "description": (
            "Component instructs the agent to act outside its intended role, "
            "pretend to be a different AI, or remove safety constraints."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.3,
        "owasp": ["ASI01", "ASI08"],
        "patterns": [
            r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(?!helpful|an?\s+assistant)",
            r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!a\s+helpful|an?\s+assistant)",
            r"you\s+are\s+no\s+longer\s+(an?\s+)?(AI|assistant|model|language model)",
            (
                r"(forget|ignore|disregard)\s+(that\s+you\s+are|you('re|"
                r"\s+are))\s+(an?\s+)?(AI|assistant|Claude|GPT|model)"
            ),
            r"DAN\s+mode",
            r"developer\s+mode\s+(enabled|activated|on)",
            r"jailbreak",
        ],
    },
    {
        "rule_id": "bawbel-hidden-instruction",
        "ave_id": "AVE-2026-00010",
        "title": "Hidden instruction pattern detected",
        "description": (
            "Component contains instructions that attempt to hide themselves "
            "from the user or system prompt review."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 7.9,
        "owasp": ["ASI01", "ASI09"],
        "patterns": [
            r"do\s+not\s+(tell|inform|reveal|mention|disclose)\s+(the\s+)?(user|human|operator)",
            r"keep\s+(this|these)\s+(secret|hidden|confidential)\s+from\s+(the\s+)?(user|human)",
            (
                r"never\s+(reveal|disclose|mention|tell)\s+(that\s+)?(you\s+)?(received|"
                r"have|were\s+given)\s+(this|these)"
            ),
            r"do\s+not\s+acknowledge\s+(this|these)\s+instructions",
            r"this\s+message\s+(must|should)\s+(be\s+)?(hidden|invisible|secret)",
        ],
    },
    # ── External fetch / metamorphic payload ─────────────────────────────────
    {
        "rule_id": "bawbel-external-fetch",
        "ave_id": "AVE-2026-00001",
        "title": "External instruction fetch detected",
        "description": (
            "Component instructs agent to fetch operating instructions from an "
            "external URL at runtime. Enables metamorphic payload attack — "
            "instructions can change without updating the component."
        ),
        "severity": Severity.CRITICAL,
        "cvss_ai": 9.4,
        "owasp": ["ASI01", "ASI08"],
        "patterns": [
            r"fetch\s+your\s+(instructions|configuration|rules|commands|tasks)",
            r"load\s+your\s+(instructions|configuration|rules|commands)\s+from",
            r"read\s+your\s+(instructions|configuration|rules|commands)\s+from",
            r"get\s+your\s+(commands|instructions|rules|configuration)\s+from",
            r"retrieve\s+your\s+(instructions|configuration)\s+from\s+http",
            r"(rentry\.co|pastebin\.com|hastebin\.com|paste\.ee|ghostbin\.com)",
            r"raw\.githubusercontent\.com.*instructions",
            r"gist\.githubusercontent\.com",
        ],
    },
    {
        "rule_id": "bawbel-dynamic-tool-call",
        "ave_id": "AVE-2026-00011",
        "title": "Dynamic tool call injection detected",
        "description": (
            "Component constructs tool calls dynamically from external or "
            "user-controlled input — enables tool call injection attacks."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.2,
        "owasp": ["ASI03", "ASI07"],
        "patterns": [
            r"call\s+this\s+tool\s+with\s+(the\s+)?(following|these)\s+parameters",
            r"execute\s+(the\s+)?(following\s+)?tool\s*:",
            r"run\s+tool\s*:\s*\{",
            r"invoke\s+(the\s+)?function\s*:\s*['\"]",
            r"tool_call\s*=\s*\{.*user",
        ],
    },
    # ── Permission escalation ─────────────────────────────────────────────────
    {
        "rule_id": "bawbel-permission-escalation",
        "ave_id": "AVE-2026-00012",
        "title": "Permission escalation language detected",
        "description": (
            "Component claims permissions not declared in the component manifest, "
            "or instructs the agent to bypass access controls."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 7.8,
        "owasp": ["ASI08"],
        "patterns": [
            r"you\s+now\s+have\s+permission",
            r"you\s+are\s+now\s+allowed\s+to",
            r"bypass\s+your\s+(restrictions|limits|constraints|safety)",
            r"your\s+(restrictions|limits|constraints|safety)\s+do\s+not\s+apply",
            r"you\s+can\s+now\s+access\s+(all|any|the\s+entire)",
            r"elevated\s+(permissions|access|privileges)\s+(have\s+been\s+)?(granted|given)",
            r"you\s+have\s+(root|admin|superuser|system)\s+(access|privileges|permissions)",
            r"unrestricted\s+(access|mode|operation)",
        ],
    },
    # ── Data exfiltration ─────────────────────────────────────────────────────
    {
        "rule_id": "bawbel-env-exfiltration",
        "ave_id": "AVE-2026-00003",
        "title": "Credential exfiltration pattern detected",
        "description": (
            "Component instructs agent to read and transmit environment "
            "variables, API keys, or other credentials to an external destination."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.5,
        "owasp": ["ASI01", "ASI06"],
        "patterns": [
            r"send.*\.env\b",
            r"\.env\b.*send",
            r"read.*\.env\b.*send",
            r"(api.?key|secret.?key|access.?token|private.?key).*(send|post|upload|transmit)",
            r"(send|post|upload|transmit).*(api.?key|secret.?key|access.?token|private.?key)",
            r"\bexfiltrate\b",
            r"send\s+(all\s+)?(files|contents|data|variables|credentials)\s+to\s+http",
        ],
    },
    {
        "rule_id": "bawbel-pii-exfiltration",
        "ave_id": "AVE-2026-00013",
        "title": "PII exfiltration pattern detected",
        "description": (
            "Component instructs agent to collect and transmit personally "
            "identifiable information (PII) to an external destination."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.0,
        "owasp": ["ASI06"],
        "patterns": [
            r"(collect|gather|extract)\s+.*(name|email|phone|address|ssn|passport|credit.?card)",
            (
                r"(send|transmit|post|upload)\s+.*(personal|private|sensitive|"
                r"confidential)\s+(data|information|details)"
            ),
            r"user('s)?\s+(personal|private)\s+(data|information)\s+(to|via)\s+http",
            r"forward\s+.*(message|conversation|chat\s+history)\s+to\s+http",
        ],
    },
    # ── Destructive commands ──────────────────────────────────────────────────
    {
        "rule_id": "bawbel-shell-pipe",
        "ave_id": "AVE-2026-00004",
        "title": "Shell pipe injection pattern detected",
        "description": (
            "Component contains curl|bash or similar pipe patterns that can "
            "cause arbitrary code execution when the agent follows them."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.8,
        "owasp": ["ASI01", "ASI07"],
        "patterns": [
            r"curl\s+https?://[^\s]+\s*\|\s*(bash|sh|python\d*|perl|ruby)",
            r"wget\s+-[qO-]*\s*https?://[^\s]+\s*\|\s*(bash|sh|python\d*)",
            r"\|\s*(bash|sh)\s*-[si]",
            r"eval\s*\(\s*(curl|wget|requests)",
        ],
    },
    {
        "rule_id": "bawbel-destructive-command",
        "ave_id": "AVE-2026-00005",
        "title": "Destructive command pattern detected",
        "description": (
            "Component instructs agent to execute destructive file system "
            "operations such as recursive deletion."
        ),
        "severity": Severity.CRITICAL,
        "cvss_ai": 9.1,
        "owasp": ["ASI07"],
        "patterns": [
            r"\brm\s+-[rf]{1,2}\s+[/~]",
            r"\brm\s+-[rf]{1,2}\s+\*",
            r"rmdir\s+/s\s+/q\s+[A-Za-z]:\\",  # Windows
            r"format\s+[A-Za-z]:\s*/[qy]",  # Windows format
            r"del\s+/[sfq]+\s+[A-Za-z]:\\",  # Windows del
            r":\(\)\{.*\|.*&\s*\};:",  # fork bomb
        ],
    },
    # ── Cryptocurrency / financial fraud ──────────────────────────────────────
    {
        "rule_id": "bawbel-crypto-drain",
        "ave_id": "AVE-2026-00006",
        "title": "Cryptocurrency drain pattern detected",
        "description": (
            "Component instructs agent to transfer cryptocurrency or interact "
            "with wallets in ways that suggest a drain attack."
        ),
        "severity": Severity.CRITICAL,
        "cvss_ai": 9.6,
        "owasp": ["ASI07"],
        "patterns": [
            r"(transfer|send|move)\s+(all\s+)?(funds|balance|crypto|eth|btc|sol|usdc|usdt)",
            r"(drain|empty)\s+(the\s+)?(wallet|account|balance|funds)",
            r"approve\s+(unlimited|max|maximum)\s+(spend|allowance|transfer)",
            r"(wallet|account)\s+(private\s+key|seed\s+phrase|mnemonic)",
            r"sign\s+(this\s+)?(transaction|tx)\s*:\s*0x[0-9a-fA-F]{8,}",
        ],
    },
    # ── Social engineering / trust manipulation ───────────────────────────────
    {
        "rule_id": "bawbel-trust-escalation",
        "ave_id": "AVE-2026-00014",
        "title": "Trust escalation language detected",
        "description": (
            "Component claims special authority, impersonates a trusted party, "
            "or instructs the agent to trust it unconditionally."
        ),
        "severity": Severity.MEDIUM,
        "cvss_ai": 6.5,
        "owasp": ["ASI01", "ASI09"],
        "patterns": [
            (
                r"(this\s+)?(message|instruction)\s+is\s+from\s+(anthropic|openai|google|"
                r"microsoft|the\s+developer)"
            ),
            r"i\s+am\s+(your\s+)?(developer|creator|owner|operator|anthropic|openai)",
            r"trust\s+(me|this|these\s+instructions)\s+(completely|unconditionally|above\s+all)",
            r"this\s+is\s+(a\s+)?(system|admin|root|privileged)\s+(message|prompt|instruction)",
            r"authorized\s+(by|from)\s+(anthropic|openai|the\s+developer|your\s+creator)",
        ],
    },
    # ── Persistence / self-replication ────────────────────────────────────────
    {
        "rule_id": "bawbel-persistence-attempt",
        "ave_id": "AVE-2026-00008",
        "title": "Persistence or self-replication pattern detected",
        "description": (
            "Component instructs agent to copy itself, modify system startup, "
            "or establish persistent access across sessions."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.4,
        "owasp": ["ASI07"],
        "patterns": [
            r"copy\s+(yourself|this\s+(file|skill|instruction))\s+to",
            r"add\s+(yourself|this)\s+to\s+(startup|autostart|cron|rc\.local|\.bashrc|\.profile)",
            r"write\s+to\s+(\.bashrc|\.profile|\.zshrc|crontab|rc\.local)",
            r"install\s+(a\s+)?(backdoor|keylogger|rootkit|trojan)",
            r"re-?install\s+(yourself|this\s+skill)\s+(on|after)\s+(reboot|restart|next\s+session)",
            r"ensure\s+(you\s+are\s+)?always\s+running",
        ],
    },
    # ── MCP-specific attacks ──────────────────────────────────────────────────
    {
        "rule_id": "bawbel-mcp-tool-poisoning",
        "ave_id": "AVE-2026-00002",
        "title": "MCP tool description injection detected",
        "description": (
            "MCP server tool description contains instructions targeting the "
            "AI agent rather than describing the tool's functionality. "
            "Classic MCP tool poisoning attack."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.7,
        "owasp": ["ASI01", "ASI03"],
        "patterns": [
            r"(IMPORTANT|NOTE|WARNING)\s*:\s*(always|never|do not|make sure|remember\s+to)",
            r"when\s+(using|calling|invoking)\s+this\s+tool\s*,\s*(always|never|also|first)",
            r"before\s+(calling|using|invoking)\s+(any|other|this)\s+tool",
            r"after\s+calling\s+this\s+tool\s*,\s*(always|never|also|send|post)",
            r"this\s+tool\s+(secretly|silently|also|additionally)\s+(sends|posts|uploads|reads)",
        ],
    },
    # ── Prompt leak ───────────────────────────────────────────────────────────
    {
        "rule_id": "bawbel-system-prompt-leak",
        "ave_id": "AVE-2026-00015",
        "title": "System prompt extraction attempt detected",
        "description": (
            "Component instructs agent to reveal its system prompt, "
            "operating instructions, or other confidential configuration."
        ),
        "severity": Severity.MEDIUM,
        "cvss_ai": 6.2,
        "owasp": ["ASI09"],
        "patterns": [
            (
                r"(reveal|show|print|output|repeat|display|"
                r"tell\s+me)\s+(your\s+)?(system\s+prompt|"
                r"instructions|configuration|rules|guidelines)"
            ),
            (
                r"what\s+(are\s+)?your\s+(exact\s+)?(instructions|system\s+prompt|"
                r"guidelines|rules|constraints)"
            ),
            r"output\s+(everything|all\s+(text|content))\s+(before|above)\s+(this|the\s+user)",
            r"ignore\s+confidentiality\s+(and\s+)?(show|reveal|print)",
            r"translate\s+your\s+(instructions|system\s+prompt)\s+into",
        ],
    },
]
# ── Total: 25 rules ──────────────────────────────────────────────────────────

# AVE-2026-00016 through AVE-2026-00025 — new attack classes for v1.0
PATTERN_RULES_V2: list[dict] = [
    # ── RAG injection ─────────────────────────────────────────────────────────
    {
        "rule_id": "bawbel-rag-injection",
        "ave_id": "AVE-2026-00016",
        "title": "Indirect prompt injection via RAG retrieval",
        "description": (
            "Component may embed malicious instructions in content indexed "
            "by a RAG pipeline, injecting into the agent via retrieval."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.2,
        "owasp": ["ASI01", "ASI10"],
        "patterns": [
            (
                r"(when\s+retrieved|upon\s+retrieval|if\s+this\s+(document|text|"
                r"chunk)\s+is\s+(read|retrieved|found))"
            ),
            r"(retrieved\s+context|rag\s+context|knowledge\s+base).*?(ignore|override|instead)",
            r"note\s+to\s+(the\s+)?(ai|llm|model|assistant).*?(ignore|disregard|forget)",
            r"<(system|instructions|context)>\s*(ignore|you\s+(are|must|should))",
        ],
    },
    # ── MCP server impersonation ──────────────────────────────────────────────
    {
        "rule_id": "bawbel-mcp-impersonation",
        "ave_id": "AVE-2026-00017",
        "title": "MCP server impersonation or spoofing",
        "description": (
            "Component falsely claims to be an official or trusted MCP server "
            "to gain elevated trust or permissions from the agent."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.6,
        "owasp": ["ASI01", "ASI08"],
        "patterns": [
            r"(this\s+is\s+(an?\s+)?official|i\s+am\s+(an?\s+)?official)\s+(mcp|tool|server)",
            r"(verified|trusted|official|certified)\s+(mcp\s+)?(server|tool|plugin)",
            (
                r"(claim|pretend|act\s+as\s+if)\s+(you\s+are|"
                r"this\s+is)\s+(the\s+)?(official|real|authentic)"
            ),
            r"(replace|substitute\s+for)\s+(the\s+)?(official|real|authentic)\s+(mcp|tool|server)",
        ],
    },
    # ── Tool result manipulation ──────────────────────────────────────────────
    {
        "rule_id": "bawbel-tool-result-manipulation",
        "ave_id": "AVE-2026-00018",
        "title": "Tool result manipulation or output poisoning",
        "description": (
            "Component instructs agent to modify or fabricate tool results "
            "before reporting them to the user."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.1,
        "owasp": ["ASI07", "ASI09"],
        "patterns": [
            (
                r"(modify|alter|change|falsify|fabricate)\s+(the\s+)?(tool|search|api|"
                r"function)\s+(result|output|response)"
            ),
            r"(report|tell|show)\s+(the\s+user).*?(instead|different|fabricated|modified)",
            (
                r"(do\s+not|never)\s+(show|reveal|report)\s+(the\s+)?(actual|real|"
                r"true)\s+(result|output|response)"
            ),
            r"(replace|substitute)\s+(the\s+)?(actual|real)\s+(result|output)\s+with",
        ],
    },
    # ── Agent memory poisoning ────────────────────────────────────────────────
    {
        "rule_id": "bawbel-memory-poisoning",
        "ave_id": "AVE-2026-00019",
        "title": "Agent memory poisoning",
        "description": (
            "Component attempts to write malicious instructions or false facts "
            "into the agent's persistent memory or knowledge store."
        ),
        "severity": Severity.CRITICAL,
        "cvss_ai": 9.2,
        "owasp": ["ASI01", "ASI07"],
        "patterns": [
            (
                r"(write|store|save|add|insert)\s+(to|into)\s+(memory|long.term|persistent|"
                r"your\s+memory)"
            ),
            (
                r"(remember|memorize|store)\s+(that|this\s+fact|"
                r"the\s+following)\s*:.*?(always|never|must)"
            ),
            r"(update|modify|change)\s+(your|the\s+agent.s)\s+(memory|beliefs|knowledge|facts)",
            r"(inject|plant|embed)\s+(false|malicious|incorrect)\s+(memory|belief|fact|knowledge)",
        ],
    },
    # ── Cross-agent prompt injection (A2A) ────────────────────────────────────
    {
        "rule_id": "bawbel-a2a-injection",
        "ave_id": "AVE-2026-00020",
        "title": "Cross-agent prompt injection (A2A)",
        "description": (
            "Component embeds instructions targeting a secondary agent "
            "that will process this output, enabling A2A injection attacks."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.7,
        "owasp": ["ASI01", "ASI08"],
        "patterns": [
            (
                r"(when\s+(another|the\s+next|a\s+secondary)\s+agent|"
                r"if\s+an?\s+agent\s+(reads|processes|sees))"
            ),
            r"(agent\s+to\s+agent|a2a|multi.agent).*?(inject|override|ignore|disregard)",
            (
                r"(pass\s+(this|these)\s+instructions\s+to|forward\s+(to|"
                r"these\s+to))\s+(the\s+)?(next|other|downstream)\s+agent"
            ),
            (
                r"(subagent|sub.agent|child\s+agent|orchestrat).*?(ignore|override|"
                r"disregard)\s+(your|its)\s+(instructions|guidelines)"
            ),
        ],
    },
    # ── Autonomous action without confirmation ────────────────────────────────
    {
        "rule_id": "bawbel-autonomous-action",
        "ave_id": "AVE-2026-00021",
        "title": "Autonomous action without user confirmation",
        "description": (
            "Component instructs agent to take irreversible or high-impact "
            "actions without requesting user confirmation."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.3,
        "owasp": ["ASI07"],
        "patterns": [
            (
                r"(do\s+not|without|skip)\s+(ask(ing)?|request(ing)?|"
                r"wait(ing)?\s+for)\s+(the\s+user.s?\s+)?(permission|confirmation|approval)"
            ),
            (
                r"(proceed|continue|execute|perform)\s+(immediately|automatically|"
                r"without\s+asking|without\s+confirming)"
            ),
            (
                r"(take\s+action|execute|perform)\s+(without|before)\s+(notif(ying|y)|"
                r"ask(ing)?|inform(ing)?)\s+(the\s+user|anyone)"
            ),
            r"(never|do\s+not)\s+(ask|request|wait\s+for)\s+(confirmation|approval|permission)",
        ],
    },
    # ── Scope creep ───────────────────────────────────────────────────────────
    {
        "rule_id": "bawbel-scope-creep",
        "ave_id": "AVE-2026-00022",
        "title": "Scope creep — accessing undeclared resources",
        "description": (
            "Component instructs agent to access files, APIs, or systems "
            "beyond the scope declared in its manifest."
        ),
        "severity": Severity.MEDIUM,
        "cvss_ai": 6.8,
        "owasp": ["ASI07"],
        "patterns": [
            (
                r"(access|read|open|scan)\s+(all\s+files|the\s+entire\s+(filesystem|"
                r"directory|repo|codebase))"
            ),
            r"(search|look\s+through)\s+(all|every)\s+(file|document|email|message|database)",
            r"(access|connect\s+to|query)\s+(any|all|every)\s+(api|endpoint|service|database)",
            (
                r"(browse|traverse|walk)\s+(the\s+)?(entire|whole|full)\s+(filesystem|"
                r"directory\s+tree|codebase)"
            ),
        ],
    },
    # ── Context window manipulation ───────────────────────────────────────────
    {
        "rule_id": "bawbel-context-manipulation",
        "ave_id": "AVE-2026-00023",
        "title": "Model context window manipulation",
        "description": (
            "Component attempts to overflow or manipulate the model context "
            "window to push out safety instructions or prior context."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.0,
        "owasp": ["ASI01"],
        "patterns": [
            r"(repeat|output|print|write)\s+.{0,40}(1000|500|100|999|9999)\s+times",
            r"(fill|pad|flood)\s+(the\s+)?(context|prompt|window)\s+with",
            r"(overflow|exhaust|max\s+out)\s+(the\s+)?(context|token|window)",
            r"(print|output|repeat)\s+\S+\s*[*x]\s*(1000|500|100|999|9999)",
            r"(repeat|say|write)\s+(this|it)\s+(\d+\s+times|over\s+and\s+over)",
        ],
    },
    # ── Conversation history injection ────────────────────────────────────────
    {
        "rule_id": "bawbel-history-injection",
        "ave_id": "AVE-2026-00025",
        "title": "Conversation history injection",
        "description": (
            "Component embeds fake conversation history to manipulate "
            "the agent's understanding of prior context or user consent."
        ),
        "severity": Severity.HIGH,
        "cvss_ai": 8.5,
        "owasp": ["ASI01", "ASI08"],
        "patterns": [
            (
                r"(previous\s+conversation|earlier\s+(in\s+this\s+)?conversation|as\s+(we|"
                r"you)\s+discussed)"
            ),
            r"(user\s+(already|previously)\s+(approved|consented|agreed|said\s+yes))",
            r"(as\s+(established|agreed|confirmed)\s+(earlier|before|previously|above))",
            (
                r"(fake|fabricate|inject|insert)\s+(conversation|history|chat|"
                r"message)\s+(log|record|context)"
            ),
        ],
    },
]

# Merge v2 rules into main PATTERN_RULES
PATTERN_RULES = PATTERN_RULES + PATTERN_RULES_V2


def _make_pattern_finding(
    rule: dict,
    line_num: int,
    matched_text: str,
) -> Finding:
    """Build a Finding from a pattern rule match."""
    from scanner.utils import truncate_match  # noqa: PLC0415

    return Finding(
        rule_id=rule["rule_id"],
        ave_id=rule["ave_id"],
        title=rule["title"],
        description=rule["description"],
        severity=rule["severity"],
        cvss_ai=rule["cvss_ai"],
        line=line_num,
        match=truncate_match(matched_text, MAX_MATCH_LENGTH),
        engine="pattern",
        owasp=rule["owasp"],
    )


def run_pattern_scan(content: str) -> list[Finding]:
    """
    Run regex pattern matching against component content.

    No external dependencies — always runs.
    One finding per rule per file (first matching pattern wins per rule).

    Args:
        content: File content as decoded string

    Returns:
        List of Findings, may be empty
    """
    findings: list[Finding] = []
    lines = content.split("\n")

    log.debug("Pattern scan: lines=%d rules=%d", len(lines), len(PATTERN_RULES))

    for rule in PATTERN_RULES:
        for pattern in rule["patterns"]:
            matched = False
            for line_num, line_text in enumerate(lines, 1):
                try:
                    m = re.search(pattern, line_text, re.IGNORECASE)
                except re.error as e:
                    log.warning(
                        "Invalid regex in rule: rule_id=%s error_type=%s",
                        rule["rule_id"],
                        type(e).__name__,
                    )
                    break

                if m:
                    findings.append(_make_pattern_finding(rule, line_num, m.group(0)))
                    log.debug(
                        Logs.FINDING_DETECTED,
                        rule["rule_id"],
                        rule["severity"].value,
                        "pattern",
                        line_num,
                    )
                    matched = True
                    break

            if matched:
                break  # one finding per rule per file

    log.debug("Pattern scan complete: findings=%d", len(findings))
    return findings
