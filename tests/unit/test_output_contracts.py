"""
Golden JSON fixture contract tests.
Issue #70 — lock the public output schema.

Run: pytest tests/unit/test_output_contracts.py -x -q

The golden snapshot lives at tests/fixtures/golden/malicious_scan.json.
Regenerate it after intentional schema changes:
    python3 -c "
    import json
    from pathlib import Path
    from scanner.scanner import scan
    r = scan('tests/fixtures/skills/malicious/malicious_skill.md')
    d = r.to_dict(); d['scan_time_ms'] = 0
    d['file_path'] = Path(d['file_path']).name
    print(json.dumps(d, indent=2))
    " > tests/fixtures/golden/malicious_scan.json
"""

import json
from pathlib import Path

import pytest

from scanner.scanner import scan

try:
    import yara as _yara  # noqa: F401

    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

GOLDEN = Path("tests/fixtures/golden")
MALICIOUS = Path("tests/fixtures/skills/malicious/malicious_skill.md")

# Keys expected at the top level of ScanResult.to_dict()
SCAN_RESULT_KEYS = {
    "file_path",
    "component_type",
    "scan_time_ms",
    "error",
    "risk_score",
    "max_severity",
    "findings",
    "toxic_flows",
    "accepted_findings",
}

# Keys expected on every finding dict (stable public API)
FINDING_KEYS = {
    "rule_id",
    "ave_id",
    "title",
    "severity",
    "aivss_score",
    "aivss",
    "engine",
    "line",
    "match",
    "owasp",
    "owasp_mcp",
    "piranha_url",
    "confidence",
    "evidence_kind",
    "detection_stage",
    "detection_layer",
    "suppressed",
}

# Keys expected on every toxic_flow dict (stable public API)
TOXIC_FLOW_KEYS = {
    "flow_id",
    "title",
    "ave_ids",
    "capabilities",
    "severity",
    "aivss_score",
    "confidence",
    "description",
    "owasp_mcp",
    "remediation",
}

EVIDENCE_KINDS = {
    "multi_engine",
    "tool_description_pattern",
    "behavioral_pattern",
    "semantic_inference",
    "file_type_mismatch",
    "config_schema",
}
DETECTION_STAGES = {"static_detection", "runtime_observed"}
DETECTION_LAYERS = {"content", "server_card", "runtime", "registry_metadata"}


def _normalize(d: dict) -> dict:
    """Strip volatile fields so snapshots are reproducible."""
    d = dict(d)
    d["scan_time_ms"] = 0
    d["file_path"] = Path(d["file_path"]).name
    return d


@pytest.fixture(scope="module")
def malicious_scan():
    result = scan(str(MALICIOUS))
    return _normalize(result.to_dict())


@pytest.fixture(scope="module")
def golden():
    path = GOLDEN / "malicious_scan.json"
    return json.loads(path.read_text())


# ── Schema tests ───────────────────────────────────────────────────────────────


class TestScanResultSchema:
    """Every key in the stable schema must be present — renames break this test."""

    def test_top_level_keys(self, malicious_scan):
        assert SCAN_RESULT_KEYS <= set(malicious_scan.keys())

    def test_finding_keys(self, malicious_scan):
        assert malicious_scan["findings"], "expected at least one finding"
        for f in malicious_scan["findings"]:
            missing = FINDING_KEYS - set(f.keys())
            assert not missing, f"missing keys on finding '{f.get('rule_id')}': {missing}"

    def test_toxic_flow_keys(self, malicious_scan):
        assert malicious_scan["toxic_flows"], "expected at least one toxic flow"
        for tf in malicious_scan["toxic_flows"]:
            missing = TOXIC_FLOW_KEYS - set(tf.keys())
            assert not missing, f"missing keys on flow '{tf.get('flow_id')}': {missing}"

    def test_aivss_nested_schema(self, malicious_scan):
        aivss_keys = {
            "cvss_base",
            "aarf",
            "aars",
            "thm",
            "mitigation_factor",
            "aivss_score",
            "aivss_severity",
            "spec_version",
        }
        for f in malicious_scan["findings"]:
            missing = aivss_keys - set(f["aivss"].keys())
            assert not missing, f"missing AIVSS keys on '{f.get('rule_id')}': {missing}"


# ── Evidence field tests ───────────────────────────────────────────────────────


class TestEvidenceFields:
    """Evidence fields must be populated on every active finding."""

    def test_confidence_non_zero_on_active_findings(self, malicious_scan):
        for f in malicious_scan["findings"]:
            assert f["confidence"] > 0.0, f"confidence=0 on '{f['rule_id']}'"

    def test_confidence_in_range(self, malicious_scan):
        for f in malicious_scan["findings"]:
            assert (
                0.0 <= f["confidence"] <= 1.0
            ), f"confidence {f['confidence']} out of [0,1] on '{f['rule_id']}'"

    def test_evidence_kind_valid_value(self, malicious_scan):
        for f in malicious_scan["findings"]:
            assert (
                f["evidence_kind"] in EVIDENCE_KINDS
            ), f"unknown evidence_kind '{f['evidence_kind']}' on '{f['rule_id']}'"

    def test_detection_stage_valid_value(self, malicious_scan):
        for f in malicious_scan["findings"]:
            assert (
                f["detection_stage"] in DETECTION_STAGES
            ), f"unknown detection_stage '{f['detection_stage']}' on '{f['rule_id']}'"

    def test_detection_layer_valid_value(self, malicious_scan):
        for f in malicious_scan["findings"]:
            assert (
                f["detection_layer"] in DETECTION_LAYERS
            ), f"unknown detection_layer '{f['detection_layer']}' on '{f['rule_id']}'"

    def test_aivss_score_and_confidence_are_independent(self, malicious_scan):
        """severity score (aivss_score) and certainty (confidence) must be distinct concepts."""
        pairs = [(f["aivss_score"], f["confidence"]) for f in malicious_scan["findings"]]
        assert any(
            aivss != conf for aivss, conf in pairs
        ), "aivss_score equals confidence on every finding — likely the same field duplicated"


class TestToxicFlowConfidence:
    """ToxicFlow confidence must be present, in range, and <= min of contributing findings."""

    def test_toxic_flow_confidence_in_range(self, malicious_scan):
        for tf in malicious_scan["toxic_flows"]:
            assert (
                0.0 <= tf["confidence"] <= 1.0
            ), f"confidence {tf['confidence']} out of [0,1] on '{tf['flow_id']}'"

    def test_toxic_flow_confidence_is_weakest_link(self, malicious_scan):
        """Chain confidence must be <= every contributing finding's confidence."""
        conf_by_rule = {
            f["ave_id"]: f["confidence"] for f in malicious_scan["findings"] if f["ave_id"]
        }
        for tf in malicious_scan["toxic_flows"]:
            chain_conf = tf["confidence"]
            contributing_confs = [conf_by_rule[aid] for aid in tf["ave_ids"] if aid in conf_by_rule]
            if contributing_confs:
                assert chain_conf <= min(contributing_confs) + 1e-9, (
                    f"flow '{tf['flow_id']}' confidence {chain_conf} "
                    f"exceeds min of contributors {min(contributing_confs)}"
                )


# ── Golden snapshot tests ──────────────────────────────────────────────────────


@pytest.mark.skipif(
    not _YARA_AVAILABLE, reason="YARA not installed — golden snapshot requires all engines"
)
class TestGoldenSnapshot:
    """Live scan output must match the committed snapshot on stable fields.

    Requires YARA — the golden was generated with all engines active.
    If a test here fails after an intentional schema change, regenerate the
    snapshot with the command in the module docstring.
    """

    def test_finding_count_stable(self, malicious_scan, golden):
        assert len(malicious_scan["findings"]) == len(golden["findings"]), (
            f"finding count changed: live={len(malicious_scan['findings'])}, "
            f"golden={len(golden['findings'])}"
        )

    def test_rule_ids_stable(self, malicious_scan, golden):
        live_ids = {f["rule_id"] for f in malicious_scan["findings"]}
        golden_ids = {f["rule_id"] for f in golden["findings"]}
        assert live_ids == golden_ids

    def test_ave_ids_stable(self, malicious_scan, golden):
        live_ids = {f["ave_id"] for f in malicious_scan["findings"]}
        golden_ids = {f["ave_id"] for f in golden["findings"]}
        assert live_ids == golden_ids

    def test_toxic_flow_ids_stable(self, malicious_scan, golden):
        live_ids = {tf["flow_id"] for tf in malicious_scan["toxic_flows"]}
        golden_ids = {tf["flow_id"] for tf in golden["toxic_flows"]}
        assert live_ids == golden_ids

    def test_evidence_kinds_stable(self, malicious_scan, golden):
        live = {f["rule_id"]: f["evidence_kind"] for f in malicious_scan["findings"]}
        snap = {f["rule_id"]: f["evidence_kind"] for f in golden["findings"]}
        assert live == snap

    def test_detection_stages_stable(self, malicious_scan, golden):
        live = {f["rule_id"]: f["detection_stage"] for f in malicious_scan["findings"]}
        snap = {f["rule_id"]: f["detection_stage"] for f in golden["findings"]}
        assert live == snap

    def test_detection_layers_stable(self, malicious_scan, golden):
        live = {f["rule_id"]: f["detection_layer"] for f in malicious_scan["findings"]}
        snap = {f["rule_id"]: f["detection_layer"] for f in golden["findings"]}
        assert live == snap

    def test_confidence_values_stable(self, malicious_scan, golden):
        live = {f["rule_id"]: f["confidence"] for f in malicious_scan["findings"]}
        snap = {f["rule_id"]: f["confidence"] for f in golden["findings"]}
        assert live == snap

    def test_toxic_flow_confidence_stable(self, malicious_scan, golden):
        live = {tf["flow_id"]: tf["confidence"] for tf in malicious_scan["toxic_flows"]}
        snap = {tf["flow_id"]: tf["confidence"] for tf in golden["toxic_flows"]}
        assert live == snap

    def test_max_severity_stable(self, malicious_scan, golden):
        assert malicious_scan["max_severity"] == golden["max_severity"]

    def test_risk_score_stable(self, malicious_scan, golden):
        assert malicious_scan["risk_score"] == golden["risk_score"]


# ── Clean file tests ───────────────────────────────────────────────────────────


class TestCleanScan:
    def test_clean_file_produces_empty_output(self, tmp_path):
        clean = tmp_path / "skill.md"
        clean.write_text("# My Skill\n\nHelps users find information safely.\n")
        result = scan(str(clean))
        data = result.to_dict()
        assert data["findings"] == []
        assert data["toxic_flows"] == []
        assert data["risk_score"] == 0.0
        assert data["error"] is None
        assert data["max_severity"] is None

    def test_clean_scan_still_has_schema(self, tmp_path):
        """Top-level schema must be present even on zero-finding scans."""
        clean = tmp_path / "skill.md"
        clean.write_text("# My Skill\n\nHelps users find information safely.\n")
        result = scan(str(clean))
        data = result.to_dict()
        assert SCAN_RESULT_KEYS <= set(data.keys())