import json
from pathlib import Path
from policy_engine import (
    analyze_bandit,
    analyze_safety,
    analyze_trivy,
)

def test_analyze_bandit_pass():
    report = {"results": []}
    result = analyze_bandit(report)
    assert result["status"] == "PASS"
    assert result["total_issues"] == 0

def test_analyze_bandit_fail():
    report = {
        "results": [
            {
                "issue_severity": "HIGH",
                "test_id": "B101",
                "filename": "test.py",
                "line_number": 5,
                "issue_text": "Use of assert"
            }
        ]
    }
    result = analyze_bandit(report)
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
