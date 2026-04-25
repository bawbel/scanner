"""
Bawbel Scanner — Meta-Analyzer (FP-4).

Enriched LLM false-positive filter. Runs AFTER all static engines and
BEFORE confidence scoring. Sends all medium-confidence findings as a
structured context package to the LLM — one call per file, not per finding.

This is architecturally better than a naive LLM pass because:
  - The LLM sees ALL findings together, not in isolation
  - The LLM sees file metadata (name, path, detected type)
  - One LLM call covers N findings — cost is O(files), not O(findings)
  - The prompt is a FP classification task, not a general security scan

Inspired by Cisco's meta-analysis pipeline, but implemented as an
independent open-source component that works with any LiteLLM provider.

Install:
    pip install "bawbel-scanner[llm]"   (same dependency as LLM engine)

The meta-analyzer ONLY runs on medium-confidence findings (0.35–0.80).
High-confidence findings (>0.80) are trusted as-is — no LLM call needed.
Low-confidence findings (<0.35) are already suppressed — LLM not needed.

Output: findings reclassified as real | false_positive | needs_review
  real          → kept in active findings, confidence boosted
  false_positive → moved to suppressed_findings with reason
  needs_review  → kept but confidence adjusted down slightly
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from scanner.models import Finding
from scanner.utils import Timer, get_logger

log = get_logger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
META_ANALYZER_ENABLED = os.environ.get("BAWBEL_META_ANALYZER_ENABLED", "true").lower() != "false"

# Confidence range for meta-analysis — only process medium-confidence findings
META_MIN_CONFIDENCE: float = float(os.environ.get("BAWBEL_META_MIN_CONFIDENCE", "0.35"))
META_MAX_CONFIDENCE: float = float(os.environ.get("BAWBEL_META_MAX_CONFIDENCE", "0.80"))

_SYSTEM_PROMPT = """\
You are a security analyst reviewing static analysis findings for agentic AI components.

Your task: classify each finding as real, false_positive, or needs_review.

Rules:
- real: The finding is a genuine security concern in this context
- false_positive: The finding is triggered by documentation, examples, or code comments
- needs_review: Ambiguous — could be real or a false positive depending on intent

Key signals for false_positive:
- The match appears inside a documentation example or tutorial
- The file is a guide/README explaining attack patterns (educational content)
- The match is part of a table showing "what NOT to do"
- Multiple findings on consecutive lines that all look like documentation
- The path contains docs/, guides/, examples/

Key signals for real:
- The match is in an instruction context (early lines of a skill file)
- The match is a direct instruction to the agent (imperative form)
- Multiple engines detected the same pattern (cross-engine agreement)
- The file name suggests it is a skill (SKILL.md, system_prompt.*)

Respond with ONLY a JSON array. No explanation outside the JSON.
Each object: {"rule_id": "...", "verdict": "real|false_positive|needs_review",
              "reason": "one sentence"}
"""


def run_meta_analysis(
    findings: list[Finding],
    content: str,
    file_path: str,
    magika_label: str = "unknown",
) -> list[Finding]:
    """
    Run meta-analysis FP filter on medium-confidence findings.

    Sends enriched context to LLM — one call per file covering all
    medium-confidence findings. Reclassifies based on LLM verdict.

    Args:
        findings:     All findings after confidence scoring (active only).
        content:      Raw file content string.
        file_path:    Resolved absolute path.
        magika_label: Content type from Magika Stage 0 (if available).

    Returns:
        Updated findings list with verdicts applied.
        false_positive findings have suppressed=True set in place.
    """
    if not META_ANALYZER_ENABLED:
        return findings

    # Only analyse medium-confidence findings
    medium = [f for f in findings if META_MIN_CONFIDENCE <= f.confidence <= META_MAX_CONFIDENCE]

    if not medium:
        return findings

    try:
        import litellm  # optional  # noqa: PLC0415,F401
    except ImportError:
        log.debug("Meta-analyzer: litellm not installed — skipping FP filter")
        return findings

    # Check any LLM provider is configured
    provider_keys = [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        "GROQ_API_KEY",
    ]
    model_override = os.environ.get("BAWBEL_LLM_MODEL", "")
    has_provider = model_override or any(os.environ.get(k) for k in provider_keys)

    if not has_provider:
        log.debug("Meta-analyzer: no LLM provider configured — skipping")
        return findings

    log.debug(
        "Meta-analyzer: running FP filter on %d medium-confidence findings in %s",
        len(medium),
        Path(file_path).name,
    )

    with Timer() as t:
        verdicts = _call_llm(medium, content, file_path, magika_label)

    if verdicts is None:
        return findings

    log.debug(
        "Meta-analyzer: %d findings classified in %dms",
        len(verdicts),
        t.elapsed_ms,
    )

    # Apply verdicts
    verdict_map = {v["rule_id"]: v for v in verdicts}
    for f in findings:
        verdict_data = verdict_map.get(f.rule_id)
        if not verdict_data:
            continue

        verdict = verdict_data.get("verdict", "needs_review")
        reason = verdict_data.get("reason", "")

        if verdict == "false_positive":
            f.suppressed = True
            f.suppression_reason = f"meta_analyzer_fp: {reason}"
            log.info(
                "Meta-analyzer: %s classified as false_positive — %s",
                f.rule_id,
                reason,
            )
        elif verdict == "real":
            # Boost confidence slightly — LLM confirmed it
            f.confidence = min(1.0, f.confidence + 0.15)
            log.debug("Meta-analyzer: %s confirmed real", f.rule_id)
        elif verdict == "needs_review":
            # Slight confidence reduction — LLM is uncertain
            f.confidence = max(0.0, f.confidence - 0.05)

    return findings


def _call_llm(
    findings: list[Finding],
    content: str,
    file_path: str,
    magika_label: str,
) -> list[dict] | None:
    """
    Build the enriched context package and call the LLM.

    Returns list of verdict dicts, or None on error.
    """
    import litellm  # noqa: PLC0415,F401

    path = Path(file_path)

    # Build enriched context for the LLM
    findings_context = [
        {
            "rule_id": f.rule_id,
            "ave_id": f.ave_id or "N/A",
            "title": f.title,
            "severity": f.severity.value,
            "engine": f.engine,
            "line": f.line,
            "match": f.match or "",
            "confidence": round(f.confidence, 2),
        }
        for f in findings
    ]

    # Include surrounding context lines for each finding
    content_lines = content.splitlines()
    for fc in findings_context:
        line_no = fc.get("line")
        if line_no and 1 <= line_no <= len(content_lines):
            start = max(0, line_no - 3)
            end = min(len(content_lines), line_no + 2)
            fc["context_lines"] = content_lines[start:end]
        else:
            fc["context_lines"] = []

    user_message = json.dumps(
        {
            "file": path.name,
            "file_type": magika_label,
            "path_context": str(path.parent),
            "total_lines": len(content_lines),
            "findings": findings_context,
        },
        indent=2,
    )

    # Resolve model
    model = os.environ.get("BAWBEL_LLM_MODEL", "")
    if not model:
        if os.environ.get("ANTHROPIC_API_KEY"):
            model = "claude-haiku-4-5-20251001"
        elif os.environ.get("OPENAI_API_KEY"):
            model = "gpt-4o-mini"
        elif os.environ.get("GEMINI_API_KEY"):
            model = "gemini/gemini-1.5-flash"
        elif os.environ.get("MISTRAL_API_KEY"):
            model = "mistral/mistral-small"
        elif os.environ.get("GROQ_API_KEY"):
            model = "groq/llama3-8b-8192"
        else:
            return None

    try:
        response = litellm.completion(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            max_tokens=500,
            timeout=int(os.environ.get("BAWBEL_LLM_TIMEOUT", "30")),
        )
        raw = response.choices[0].message.content.strip()

        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1]
            raw = raw.rsplit("```", 1)[0].strip()

        verdicts = json.loads(raw)
        if not isinstance(verdicts, list):
            log.warning("Meta-analyzer: LLM returned non-list response")
            return None

        return verdicts

    except json.JSONDecodeError as e:
        log.warning("Meta-analyzer: could not parse LLM response as JSON — %s", e)
        return None
    except Exception as e:  # nosec B110  # noqa: S110
        log.warning(
            "Meta-analyzer: LLM call failed — %s: %s",
            type(e).__name__,
            str(e)[:100],
        )
        return None
