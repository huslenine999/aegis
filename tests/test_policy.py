import json
from pathlib import Path
from policy_engine import (
    analyze_ruff,
    analyze_safety,
    analyze_trivy,
    run_policy_engine,
)

def test_analyze_ruff_pass():
    report = []
    result = analyze_ruff(report)
    assert result["status"] == "PASS"
    assert result["total_issues"] == 0

def test_analyze_ruff_fail():
    report = [
        {
            "code": "S102",
            "filename": "test.py",
            "location": {"row": 5, "column": 1},
            "message": "Use of exec"
        }
    ]
    result = analyze_ruff(report)
    assert result["status"] == "FAIL"
    assert result["blocking_issues"] == 1

def test_analyze_safety_fail():
    # Mocking safety report format
    report = [
        {"package": "flask", "advisory": "VULN-123", "version": "1.0.0", "fixed": "2.0.0", "reason": "Remote Code Execution"}
    ]
    result = analyze_safety(report)
    assert result["status"] == "FAIL"
    assert result["total_issues"] == 1

def test_analyze_trivy_pass():
    report = {"Results": []}
    result = analyze_trivy(report)
    assert result["status"] == "PASS"

def test_analyze_trivy_fail():
    report = {
        "Results": [
            {
                "Target": "aegis-demo:latest",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-0001", "Severity": "CRITICAL", "PkgName": "openssl", "InstalledVersion": "1.1.1", "FixedVersion": "1.1.1t", "Title": "Buffer overflow"}
                ]
            }
        ]
    }
    result = analyze_trivy(report)
    assert result["status"] == "FAIL"
    assert result["blocking_issues"] == 1


def test_policy_engine_reports_operational_error(tmp_path):
    reports = {
        "ruff-report.json": [],
        "safety-report.json": [],
        "trivy-report.json": {"Results": []},
        "secrets-report.json": {"results": {}},
        "yara-report.json": [],
        "semgrep-report.json": {"results": []},
        "clamav-report.json": [],
        "zap-report.json": [],
        "osv-report.json": [],
    }
    for filename, payload in reports.items():
        (tmp_path / filename).write_text(json.dumps(payload))

    html_report = tmp_path / "report.html"
    markdown_report = tmp_path / "report.md"
    exit_code = run_policy_engine(
        tmp_path,
        html_path=html_report,
        md_path=markdown_report,
        operational_failures=["Semgrep"],
    )

    assert exit_code == 2
    assert "DEPLOYMENT ERROR" in markdown_report.read_text()
    assert "Operational scanner failure(s): Semgrep" in markdown_report.read_text()
