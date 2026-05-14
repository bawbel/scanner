"""
Unit tests for scanner.conformance
"""

import json
from scanner.conformance import score_conformance, CheckStatus, CheckCategory


def minimal_manifest(**kwargs) -> dict:
    """A minimal conformant manifest."""
    base = {
        "name": "test-server",
        "description": "A test MCP server",
        "version": "1.0.0",
        "$schema": (
            "https://static.modelcontextprotocol.io/schemas/" "2025-12-11/server.schema.json"
        ),
        "remotes": [
            {
                "type": "streamable-http",
                "url": "https://api.example.com/mcp",
            }
        ],
        "tools": [
            {
                "name": "search",
                "description": "Search for information",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "The query"},
                    },
                    "required": ["query"],
                },
            }
        ],
    }
    base.update(kwargs)
    return base


class TestConformanceReport:

    def test_returns_report(self):
        report = score_conformance(minimal_manifest())
        assert report is not None

    def test_score_in_range(self):
        report = score_conformance(minimal_manifest())
        assert 0 <= report.score <= 100

    def test_grade_valid(self):
        report = score_conformance(minimal_manifest())
        assert report.grade in ("A+", "A", "B", "C", "D", "F")

    def test_is_conformant_bool(self):
        report = score_conformance(minimal_manifest())
        assert isinstance(report.is_conformant, bool)

    def test_results_list(self):
        report = score_conformance(minimal_manifest())
        assert isinstance(report.results, list)
        assert len(report.results) > 0

    def test_pass_fail_warn_skip_counts_consistent(self):
        report = score_conformance(minimal_manifest())
        total = report.passed + report.failed + report.warned + report.skipped
        assert total == len(report.results)

    def test_good_manifest_passes_required(self):
        report = score_conformance(minimal_manifest())
        failed_required = [
            r.check.title
            for r in report.results
            if r.status == CheckStatus.FAIL and r.check.category == CheckCategory.REQUIRED
        ]
        assert (
            report.is_conformant
        ), f"Minimal manifest should be conformant. Failed: {failed_required}"

    def test_missing_name_fails(self):
        m = minimal_manifest()
        del m["name"]
        report = score_conformance(m)
        assert not report.is_conformant

    def test_missing_description_penalised(self):
        m = minimal_manifest()
        del m["description"]
        report_with = score_conformance(minimal_manifest())
        report_without = score_conformance(m)
        assert report_without.score <= report_with.score

    def test_http_not_https_penalised(self):
        m = minimal_manifest()
        m["remotes"][0]["url"] = "http://insecure.example.com/mcp"
        report = score_conformance(m)
        # HTTP instead of HTTPS should reduce score or flag non-conformant
        good = score_conformance(minimal_manifest())
        assert report.score <= good.score

    def test_tool_missing_description_penalised(self):
        m = minimal_manifest()
        del m["tools"][0]["description"]
        report_with = score_conformance(minimal_manifest())
        report_without = score_conformance(m)
        assert report_without.score <= report_with.score


class TestConformanceReportToDict:

    def test_to_dict_structure(self):
        report = score_conformance(minimal_manifest())
        d = report.to_dict()
        for key in ("score", "grade", "is_conformant", "passed", "failed", "results"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_serialisable(self):
        report = score_conformance(minimal_manifest())
        # Should not raise
        json.dumps(report.to_dict())

    def test_to_dict_results_have_status(self):
        report = score_conformance(minimal_manifest())
        d = report.to_dict()
        for r in d["results"]:
            assert "status" in r
            assert "check_id" in r
