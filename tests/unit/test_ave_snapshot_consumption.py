"""
The scanner reads AVE data from the vendored snapshot and nowhere else.

Issue #148, AVE-CONSUMPTION R5 and R6: a disagreement between a Bawbel table and AVE is a Bawbel
bug, so the OWASP MCP mapping the scanner prints must be the one the snapshot holds, on every
output surface, for every record the snapshot holds. The snapshot itself is checked against the
corpus by scripts/sync_ave_snapshot.py --check (tests/unit/test_sync_ave_snapshot.py).

Run: pytest tests/unit/test_ave_snapshot_consumption.py -q
"""

import io
import json
import re
from pathlib import Path

import pytest
from rich.console import Console, Group

from scanner import _ave_snapshot
from scanner.ave_meta import (
    AVE_META,
    EveMeta,
    get_ave_meta,
    get_owasp_mcp,
    in_snapshot,
)
from scanner.cli.shared.constants import OWASP_MCP_DESCRIPTIONS
from scanner.cli.shared.display import build_scan_renderables
from scanner.cli.shared.formatters import print_json, print_sarif
from scanner.core.toxic_flows import detect_toxic_flows
from scanner.core.toxic_flows.capabilities import get_capabilities
from scanner.engines.pattern_engine import PATTERN_RULES, _make_pattern_finding
from scanner.models import Finding, ScanResult, Severity
from scanner.scanner import _apply_ave_crosswalk, scan

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = _ave_snapshot.AVE_SNAPSHOT
WRONG = ["MCP99"]  # an engine value that must never survive for a record AVE publishes
UNKNOWN_ID = "AVE-2099-99999"


def _finding(ave_id, owasp_mcp=None, rule_id="rule-under-test"):
    return Finding(
        rule_id=rule_id,
        ave_id=ave_id,
        title="t",
        description="d",
        severity=Severity.HIGH,
        aivss_score=7.0,
        owasp_mcp=list(WRONG if owasp_mcp is None else owasp_mcp),
    )


def _result(findings):
    return ScanResult(file_path="x.md", component_type="skill", findings=findings)


def _text_view(result) -> str:
    buf = io.StringIO()
    Console(file=buf, width=240, color_system=None).print(
        Group(*build_scan_renderables(result, "x.md", False))
    )
    return buf.getvalue()


# ── The snapshot is the data ──────────────────────────────────────────────────


class TestNoHandCopies:
    def test_the_hand_copied_crosswalk_module_is_gone(self):
        assert not (ROOT / "scanner" / "owasp_mcp_map.py").exists()
        with pytest.raises(ModuleNotFoundError):
            __import__("scanner.owasp_mcp_map")

    def test_ave_meta_holds_no_ave_id_and_no_sync_date(self):
        text = (ROOT / "scanner" / "ave_meta.py").read_text(encoding="utf-8")
        assert not re.search(r"AVE-\d{4}-\d{5}", text), "an AVE id is typed in ave_meta.py"
        assert "last synced" not in text

    def test_ave_meta_is_derived_from_the_snapshot_for_every_record(self):
        assert set(AVE_META) == set(SNAPSHOT)
        for ave_id, rec in SNAPSHOT.items():
            assert AVE_META[ave_id] == EveMeta(
                rec["confidence_baseline"],
                rec["evidence_kind_default"],
                rec["detection_stage"],
                rec["detection_layer"],
            ), ave_id

    def test_get_ave_meta_returns_the_snapshot_value_for_every_record(self):
        for ave_id, rec in SNAPSHOT.items():
            meta = get_ave_meta(ave_id, "pattern")
            assert meta.confidence_baseline == rec["confidence_baseline"], ave_id
            assert meta.evidence_kind == rec["evidence_kind_default"], ave_id

    def test_the_provenance_is_stamped(self):
        assert re.fullmatch(r"[0-9a-f]{64}", _ave_snapshot.CORPUS_SHA256)
        assert _ave_snapshot.RECORD_COUNT == len(SNAPSHOT)
        assert _ave_snapshot.SOURCE_URL.startswith("https://raw.githubusercontent.com/aveproject/")
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", _ave_snapshot.GENERATED_AT)


# ── The crosswalk the scanner prints is AVE's ─────────────────────────────────


class TestCrosswalkEqualsTheSnapshot:
    def test_get_owasp_mcp_for_every_record(self):
        for ave_id, rec in SNAPSHOT.items():
            assert get_owasp_mcp(ave_id) == rec["owasp_mcp"], ave_id

    def test_the_value_returned_is_a_copy(self):
        ave_id = next(iter(SNAPSHOT))
        get_owasp_mcp(ave_id).append("MCP99")
        assert "MCP99" not in SNAPSHOT[ave_id]["owasp_mcp"]

    def test_scan_step_replaces_an_engine_value_for_every_record(self):
        findings = [_finding(ave_id) for ave_id in SNAPSHOT]
        _apply_ave_crosswalk(findings)
        for f in findings:
            assert f.owasp_mcp == SNAPSHOT[f.ave_id]["owasp_mcp"], f.ave_id

    def test_json_prints_the_ave_value_for_every_record(self, capsys):
        findings = [_finding(ave_id) for ave_id in SNAPSHOT]
        _apply_ave_crosswalk(findings)
        print_json([_result(findings)])
        printed = json.loads(capsys.readouterr().out)[0]["findings"]
        assert len(printed) == len(SNAPSHOT)
        for row in printed:
            assert row["owasp_mcp"] == SNAPSHOT[row["ave_id"]]["owasp_mcp"], row["ave_id"]

    def test_sarif_prints_the_ave_value_for_every_record(self, capsys):
        findings = [_finding(ave_id, rule_id=f"rule-{ave_id}") for ave_id in SNAPSHOT]
        _apply_ave_crosswalk(findings)
        print_sarif([_result(findings)])
        sarif = json.loads(capsys.readouterr().out)
        results = sarif["runs"][0]["results"]
        assert len(results) == len(SNAPSHOT)
        by_rule = {r["ruleId"]: r["properties"]["owasp_mcp"] for r in results}
        for ave_id, rec in SNAPSHOT.items():
            assert by_rule[f"rule-{ave_id}"] == rec["owasp_mcp"], ave_id

    def test_the_text_view_prints_the_ave_value_for_every_record(self):
        for ave_id, rec in SNAPSHOT.items():
            finding = _finding(ave_id)
            _apply_ave_crosswalk([finding])
            line = next(
                (ln for ln in _text_view(_result([finding])).splitlines() if "OWASP MCP:" in ln),
                "",
            )
            assert re.findall(r"MCP\d{2}", line) == rec["owasp_mcp"], ave_id
            for code in rec["owasp_mcp"]:
                assert OWASP_MCP_DESCRIPTIONS[code] in line, ave_id

    def test_a_pattern_rules_own_typed_value_never_wins_for_a_published_record(self):
        findings = [
            _make_pattern_finding(rule, 1, "x")
            for rule in PATTERN_RULES
            if in_snapshot(rule.get("ave_id"))
        ]
        assert findings, "no pattern rule cites a record the snapshot holds"
        _apply_ave_crosswalk(findings)
        for f in findings:
            assert f.owasp_mcp == SNAPSHOT[f.ave_id]["owasp_mcp"], f.rule_id

    def test_a_real_scan_prints_the_ave_value_for_every_finding(self):
        golden = ROOT / "tests" / "fixtures" / "skills" / "malicious" / "malicious_skill.md"
        result = scan(str(golden))
        assert not result.has_error
        with_ave = [f for f in result.findings if f.ave_id]
        assert with_ave, "the golden fixture produced no finding that cites an AVE id"
        for f in with_ave:
            assert f.owasp_mcp == SNAPSHOT[f.ave_id]["owasp_mcp"], f.ave_id

    def test_the_description_table_covers_every_category_the_snapshot_uses(self):
        used = {code for rec in SNAPSHOT.values() for code in rec["owasp_mcp"]}
        assert used <= set(OWASP_MCP_DESCRIPTIONS), sorted(used - set(OWASP_MCP_DESCRIPTIONS))


# ── An id the scanner does not know is unverified, never an error ─────────────


class TestUnknownIds:
    def test_lookups_do_not_raise_and_do_not_guess(self):
        assert get_owasp_mcp(UNKNOWN_ID) == []
        assert get_owasp_mcp(None) == []
        assert get_owasp_mcp("") == []
        assert not in_snapshot(UNKNOWN_ID) and not in_snapshot(None)

    def test_evidence_metadata_falls_back_to_bawbels_own_default(self):
        assert get_ave_meta(UNKNOWN_ID, "pattern").confidence_baseline == 0.75
        assert get_ave_meta(None, "llm").confidence_baseline == 0.52

    def test_the_scan_step_leaves_an_unknown_or_missing_id_alone(self):
        unknown, missing = _finding(UNKNOWN_ID, ["MCP04"]), _finding(None, ["MCP06"])
        _apply_ave_crosswalk([unknown, missing])
        assert unknown.owasp_mcp == ["MCP04"] and missing.owasp_mcp == ["MCP06"]

    def test_the_output_paths_do_not_raise_for_an_unknown_id(self, capsys):
        result = _result([_finding(UNKNOWN_ID, []), _finding(None, [])])
        print_json([result])
        print_sarif([result])
        assert "OWASP MCP:" not in _text_view(result)
        assert capsys.readouterr().out

    def test_a_published_record_with_no_capability_mapping_is_unmapped_not_an_error(self):
        for ave_id in SNAPSHOT:
            assert isinstance(get_capabilities(ave_id), set), ave_id
        assert get_capabilities(UNKNOWN_ID) == set() and get_capabilities(None) == set()

    def test_toxic_flow_detection_accepts_a_finding_for_every_published_record(self):
        findings = [_finding(ave_id, rule_id=f"rule-{ave_id}") for ave_id in SNAPSHOT]
        findings.append(_finding(UNKNOWN_ID, rule_id="rule-unknown"))
        flows = detect_toxic_flows(findings)
        assert isinstance(flows, list)
