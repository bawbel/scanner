"""
Bawbel Scanner — CLI output formatters.

JSON and SARIF serialisation for scan results. Both functions write
directly to stdout (print) so they can be piped without buffering.
"""

import json
from scanner import __version__
from scanner.models import ScanResult
from scanner.cli.shared.display import sev_value
from scanner.owasp_mcp_map import get_owasp_mcp


def print_json(results: list[ScanResult]) -> None:
    """Print results as JSON — includes suppressed findings for audit."""

    def _finding_dict(f, suppressed: bool = False) -> dict:
        d = {
            "rule_id": f.rule_id,
            "ave_id": f.ave_id,
            "title": f.title,
            "description": f.description,
            "severity": sev_value(f.severity),
            "cvss_ai": f.cvss_ai,
            "line": f.line,
            "match": f.match,
            "engine": f.engine,
            "owasp": f.owasp,
            "owasp_mcp": get_owasp_mcp(f.ave_id),
        }
        if suppressed:
            d["suppressed"] = True
            d["suppression_reason"] = f.suppression_reason
        return d

    output = []
    for r in results:
        output.append(
            {
                "file_path": r.file_path,
                "component_type": r.component_type,
                "risk_score": r.risk_score,
                "max_severity": sev_value(r.max_severity) if r.max_severity else None,
                "scan_time_ms": r.scan_time_ms,
                "has_error": r.has_error,
                "findings": [_finding_dict(f) for f in r.findings],
                "suppressed_findings": [
                    _finding_dict(f, suppressed=True) for f in r.suppressed_findings
                ],
            }
        )
    print(json.dumps(output, indent=2, default=str))


def print_sarif(results: list[ScanResult]) -> None:
    """Print results as SARIF 2.1.0 (for GitHub Security tab integration)."""
    rules: list[dict] = []
    rule_ids_seen: set[str] = set()
    run_results: list[dict] = []

    for r in results:
        for f in r.findings:
            if f.rule_id not in rule_ids_seen:
                rule_ids_seen.add(f.rule_id)
                rules.append(
                    {
                        "id": f.rule_id,
                        "name": f.rule_id.replace("-", " ").title(),
                        "shortDescription": {"text": f.title},
                        "fullDescription": {"text": f.description},
                        "helpUri": "https://github.com/bawbel/bawbel-ave",
                        "properties": {
                            "tags": f.owasp,
                            "precision": "high",
                            "problem.severity": sev_value(f.severity).lower(),
                        },
                    }
                )

            run_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": {
                        "CRITICAL": "error",
                        "HIGH": "error",
                        "MEDIUM": "warning",
                        "LOW": "note",
                        "INFO": "none",
                    }.get(sev_value(f.severity), "warning"),
                    "message": {"text": f.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": r.file_path},
                                "region": {"startLine": f.line or 1},
                            }
                        }
                    ],
                    "properties": {"cvss_ai": f.cvss_ai},
                }
            )

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bawbel-scanner",
                        "version": __version__,
                        "informationUri": "https://bawbel.io",
                        "rules": rules,
                    }
                },
                "results": run_results,
            }
        ],
    }
    print(json.dumps(sarif, indent=2))
