"""
Bawbel Scanner - AVE-derived lookups.

Evidence metadata and the OWASP MCP crosswalk for an AVE id. Both come from
scanner/_ave_snapshot.py, the vendored snapshot of the published AVE records that
scripts/sync_ave_snapshot.py generates from the pinned corpus (docs/AVE-CONSUMPTION.md in
bawbel/.github, R5, R6 and R9). Nothing in this module is typed from AVE. If the scanner
disagrees with AVE, regenerate the snapshot. Do not edit a value here.

Used by all engines to seed Finding.confidence before the FP pipeline runs.
No network calls - fully offline.
"""

from typing import NamedTuple, Optional

from scanner._ave_snapshot import AVE_SNAPSHOT


class EveMeta(NamedTuple):
    confidence_baseline: float
    evidence_kind: str
    detection_stage: str
    detection_layer: str


# One entry per record in the snapshot, derived from it when the module loads.
# Keys are the canonical AVE IDs; values are EveMeta tuples.
AVE_META: dict[str, EveMeta] = {
    ave_id: EveMeta(
        record["confidence_baseline"],
        record["evidence_kind_default"],
        record["detection_stage"],
        record["detection_layer"],
    )
    for ave_id, record in AVE_SNAPSHOT.items()
}

# Bawbel's own fallbacks, not AVE data. They apply only to a finding that has no AVE id or cites
# one the snapshot does not hold, for example a finding from the LLM engine.
_DEFAULT_STATIC = EveMeta(0.75, "multi_engine", "static_detection", "content")
_DEFAULT_LLM = EveMeta(0.52, "semantic_inference", "static_detection", "content")
_DEFAULT_RUNTIME = EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime")


def get_ave_meta(ave_id: Optional[str], engine: str = "pattern") -> EveMeta:
    """
    Return evidence metadata for an AVE ID.

    Falls back by engine type when ave_id is absent or not in the snapshot:
      - llm engine   → semantic_inference baseline (0.52)
      - all others   → multi_engine baseline (0.75)
    """
    if ave_id and ave_id in AVE_META:
        return AVE_META[ave_id]
    if engine == "llm":
        return _DEFAULT_LLM
    return _DEFAULT_STATIC


def in_snapshot(ave_id: Optional[str]) -> bool:
    """True when the AVE snapshot holds a record for this id."""
    return bool(ave_id) and ave_id in AVE_SNAPSHOT


def get_owasp_mcp(ave_id: Optional[str]) -> list[str]:
    """
    Return the OWASP MCP Top 10 categories AVE publishes for an AVE ID.

    The value is AVE's, as recorded in the snapshot. An id the snapshot does not hold gets an
    empty list: the scanner does not guess a mapping.
    """
    if not in_snapshot(ave_id):
        return []
    return list(AVE_SNAPSHOT[ave_id]["owasp_mcp"])
