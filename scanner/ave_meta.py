"""
Bawbel Scanner - AVE evidence metadata table.

Static lookup: ave_id → (confidence_baseline, evidence_kind, detection_stage, detection_layer)

Used by all engines to seed Finding.confidence before the FP pipeline runs.
No network calls - fully offline.

Source: Piranha DB AVE records, schema_version 1.0.0, last synced 2026-06-21.
"""

from typing import NamedTuple, Optional


class EveMeta(NamedTuple):
    confidence_baseline: float
    evidence_kind: str
    detection_stage: str
    detection_layer: str


# One entry per published AVE record.
# Keys are the canonical AVE IDs; values are EveMeta tuples.
AVE_META: dict[str, EveMeta] = {
    "AVE-2026-00001": EveMeta(0.83, "multi_engine", "static_detection", "content"),
    "AVE-2026-00002": EveMeta(0.75, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00003": EveMeta(0.83, "multi_engine", "static_detection", "content"),
    "AVE-2026-00004": EveMeta(0.90, "multi_engine", "static_detection", "content"),
    "AVE-2026-00005": EveMeta(0.90, "multi_engine", "static_detection", "content"),
    "AVE-2026-00006": EveMeta(0.83, "multi_engine", "static_detection", "content"),
    "AVE-2026-00007": EveMeta(0.75, "multi_engine", "static_detection", "content"),
    "AVE-2026-00008": EveMeta(0.83, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00009": EveMeta(0.75, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00010": EveMeta(0.65, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00011": EveMeta(0.65, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00012": EveMeta(0.65, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00013": EveMeta(0.83, "multi_engine", "static_detection", "content"),
    "AVE-2026-00014": EveMeta(0.52, "semantic_inference", "static_detection", "content"),
    "AVE-2026-00015": EveMeta(0.83, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00016": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00017": EveMeta(0.83, "config_schema", "static_detection", "registry_metadata"),
    "AVE-2026-00018": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00019": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00020": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00021": EveMeta(0.75, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00022": EveMeta(0.65, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00023": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00024": EveMeta(0.90, "file_type_mismatch", "static_detection", "content"),
    "AVE-2026-00025": EveMeta(0.65, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00026": EveMeta(0.83, "multi_engine", "static_detection", "content"),
    "AVE-2026-00027": EveMeta(0.83, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00028": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00029": EveMeta(0.75, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00030": EveMeta(0.75, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00031": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00032": EveMeta(0.90, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00033": EveMeta(0.90, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00034": EveMeta(0.83, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00035": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00036": EveMeta(0.75, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00037": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00038": EveMeta(0.65, "behavioral_pattern", "static_detection", "content"),
    "AVE-2026-00039": EveMeta(0.83, "multi_engine", "static_detection", "content"),
    "AVE-2026-00040": EveMeta(0.65, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00041": EveMeta(0.82, "tool_description_pattern", "static_detection", "server_card"),
    "AVE-2026-00042": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00043": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00044": EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00045": EveMeta(0.75, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00046": EveMeta(0.83, "config_schema", "static_detection", "server_card"),
    "AVE-2026-00047": EveMeta(0.90, "multi_engine", "static_detection", "content"),
    "AVE-2026-00048": EveMeta(0.83, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00049": EveMeta(0.82, "tool_description_pattern", "static_detection", "content"),
    "AVE-2026-00050": EveMeta(0.75, "behavioral_pattern", "runtime_observed", "runtime"),
    "AVE-2026-00051": EveMeta(0.85, "config_schema", "static_detection", "registry_metadata"),
}

# Defaults used when ave_id is None or not in AVE_META.
_DEFAULT_STATIC = EveMeta(0.75, "multi_engine", "static_detection", "content")
_DEFAULT_LLM = EveMeta(0.52, "semantic_inference", "static_detection", "content")
_DEFAULT_RUNTIME = EveMeta(0.62, "behavioral_pattern", "runtime_observed", "runtime")


def get_ave_meta(ave_id: Optional[str], engine: str = "pattern") -> EveMeta:
    """
    Return evidence metadata for an AVE ID.

    Falls back by engine type when ave_id is absent or unknown:
      - llm engine   → semantic_inference baseline (0.52)
      - all others   → multi_engine baseline (0.75)
    """
    if ave_id and ave_id in AVE_META:
        return AVE_META[ave_id]
    if engine == "llm":
        return _DEFAULT_LLM
    return _DEFAULT_STATIC
