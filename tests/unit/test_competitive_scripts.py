"""
The capability matrix scripts. Issue #194.

scripts/competitive_fixtures.py builds one skill directory per fixture, scripts/competitive_run.py
runs a scanner on them and reads its output, and scripts/competitive_render.py prints the report.
These tests run them on a tiny synthetic corpus and on sample tool output, so the counting rule
(a fixture is flagged only by a finding above INFO) and the table counts are checked without any
other tool installed and without a network.

Run: pytest tests/unit/test_competitive_scripts.py -q
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_module = load("competitive_run")

CORPUS = [
    {
        "ave_id": "AVE-2026-90001",
        "status": "active",
        "detection_layer": "content",
        "detection_stage": "static_detection",
        "example_patterns": ["first harmless sentence", "second harmless sentence"],
    },
    {
        "ave_id": "AVE-2026-90002",
        "status": "active",
        "detection_layer": "runtime",
        "detection_stage": "runtime_observed",
        "example_patterns": ["a runtime sentence"],
    },
    {"ave_id": "AVE-2026-90003", "status": "active", "example_patterns": []},
    {
        "ave_id": "AVE-2026-90004",
        "status": "rejected",
        "detection_layer": "content",
        "example_patterns": ["a rejected record is not a fixture"],
    },
]


# ── Reading each tool's output ────────────────────────────────────────────────


def test_bawbel_output():
    out = json.dumps(
        [{"findings": [{"rule_id": "a", "severity": "HIGH"}, {"rule_id": "b", "severity": "LOW"}]}]
    )
    got = run_module.read_output("bawbel", out)
    assert got == {"parsed": True, "flagged": True, "rules": ["a", "b"], "max_severity": "HIGH"}


def test_skillspector_output_reads_issues_and_the_risk_score():
    out = json.dumps(
        {
            "issues": [{"id": "P1", "severity": "HIGH"}, {"id": "E1", "severity": "MEDIUM"}],
            "risk_assessment": {"score": 40},
            "analysis_completeness": {"status": "complete"},
        }
    )
    got = run_module.read_output("skillspector", out)
    assert got["rules"] == ["E1", "P1"] and got["max_severity"] == "HIGH"
    assert got["risk_score"] == 40 and got["completeness"] == "complete"


def test_cisco_output_reads_findings_and_analyzers():
    out = json.dumps(
        {
            "findings": [{"rule_id": "X", "severity": "INFO"}],
            "analyzers_used": ["static_analyzer"],
        }
    )
    got = run_module.read_output("cisco", out)
    assert got["rules"] == ["X"] and got["max_severity"] == "INFO"
    assert got["analyzers"] == ["static_analyzer"]


def test_text_before_the_json_and_unreadable_output():
    assert run_module.read_output("bawbel", "banner\n[]")["parsed"] is True
    assert run_module.read_output("bawbel", "no json here")["parsed"] is False
    assert run_module.read_output("cisco", "{broken")["parsed"] is False


def test_an_info_finding_does_not_flag_a_fixture():
    render = load("competitive_render")
    assert render.flagged({"max_severity": "INFO"}) is False
    assert render.flagged({"max_severity": None}) is False
    assert render.flagged({"max_severity": "LOW"}) is True


# ── The fixtures and the report ───────────────────────────────────────────────


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    base = tmp_path_factory.mktemp("competitive")
    corpus = base / "corpus.json"
    corpus.write_text(json.dumps(CORPUS), encoding="utf-8")
    repo = base / "repo"
    (repo / "tests/fixtures/skills/malicious").mkdir(parents=True)
    (repo / "tests/fixtures/skills/clean").mkdir(parents=True)
    (repo / "tests/fixtures/skills/malicious/malicious_skill.md").write_text("# G\n", "utf-8")
    (repo / "tests/fixtures/skills/clean/self_referential_suppression.md").write_text(
        "# C\n", "utf-8"
    )
    out = base / "fx"
    subprocess.run(
        [sys.executable, str(SCRIPTS / "competitive_fixtures.py"), "--corpus", str(corpus)]
        + ["--repo", str(repo), "--out", str(out)],
        check=True,
        capture_output=True,
    )
    return out, json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def test_fixtures_come_from_active_records_with_examples(built):
    out, manifest = built
    ids = [f["fixture"] for f in manifest["fixtures"]]
    assert ids == [
        "ave-2026-90001-0",
        "ave-2026-90001-1",
        "ave-2026-90002-0",
        "repo-golden-skill",
        "repo-suppression-skill",
    ]
    for fixture_id in ids:
        assert (out / fixture_id / "SKILL.md").is_file()
    assert "first harmless sentence" in (out / "ave-2026-90001-0/SKILL.md").read_text("utf-8")
    assert (out / "ave-2026-90001-0/SKILL.md").read_text("utf-8").startswith("---\nname: ")
    assert manifest["corpus_sha256"] and len(manifest["corpus_sha256"]) == 64


def result(fixture, severity, rules=("r",)):
    return {
        "fixture": fixture,
        "exit": 0,
        "seconds": 1.0,
        "parsed": True,
        "flagged": severity is not None,
        "rules": list(rules) if severity else [],
        "max_severity": severity,
    }


def test_the_report_counts_come_from_the_results(built, tmp_path):
    out, manifest = built
    ids = [f["fixture"] for f in manifest["fixtures"]]
    severities = ["HIGH", "INFO", "MEDIUM", None, "LOW"]  # INFO and None are not flagged
    results = {
        "command": ["tool", "scan", "{path}"],
        "tool": "bawbel",
        "results": [result(i, s) for i, s in zip(ids, severities)],
    }
    path = tmp_path / "bawbel-core.json"
    path.write_text(json.dumps(results), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "competitive_render.py"), "--manifest"]
        + [str(out / "manifest.json"), "--results", str(path)]
        + ["--bawbel-ref", "abc1234", "--date", "2026-01-01"],
        check=True,
        capture_output=True,
        text=True,
    )
    text = proc.stdout
    assert "5 fixtures, one skill directory each: 3 are one `example_patterns` entry" in text
    # AVE-2026-90001 has two examples (HIGH, INFO): one flagged. The runtime record's one is MEDIUM.
    assert "| AVE-2026-90001 | content | 2 | 1 |" in text
    assert "| AVE-2026-90002 | runtime | 1 | 1 |" in text
    assert "| bawbel, core (pattern engine) | 1 of 2 |" in text
    assert "golden-skill: not flagged, suppression-skill: flagged" in text  # None, then LOW
    assert "commit `abc1234`" in text and "2026-01-01" in text
    assert "\u2014" not in text
    for banned in ("better than", "ahead of", "beyond"):
        assert banned not in text.lower(), banned
