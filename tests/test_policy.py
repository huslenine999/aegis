import json
import policy_engine
from policy_engine import (
    analyze_iac,
    analyze_ruff,
    analyze_safety,
    analyze_trivy,
    evaluate_policy_results,
    generate_reports,
    run_policy_engine,
)


def test_analyze_iac_enforces_findings_and_unmanaged_suppressions():
    result = analyze_iac({
        "frameworks": ["terraform", "dockerfile"],
        "summary": {"candidate": 2, "passed": 0, "failed": 1, "skipped": 1},
        "findings": [{
            "rule_id": "CKV_DOCKER_2",
            "title": "Add a healthcheck",
            "framework": "dockerfile",
            "severity": "unknown",
            "resource": "Dockerfile",
            "path": "Dockerfile",
            "start_line": 2,
            "end_line": 3,
            "remediation": "Add a healthcheck.",
        }],
        "unmanaged_suppressions": [{
            "rule_id": "CKV_TF_1",
            "title": "Inline skip",
            "framework": "terraform",
            "path": "main.tf",
            "start_line": 1,
            "end_line": 1,
            "source": "repository-inline-checkov",
        }],
        "status": "completed",
    })

    assert result["status"] == "FAIL"
    assert result["total_issues"] == 2
    assert result["blocking_issues"] == 2
    assert {item["severity"] for item in result["findings"]} == {"MEDIUM"}

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
    finding = result["examples"][0]
    assert "Why it matters" not in finding["why_it_matters"]
    assert "exec" in finding["why_it_matters"].lower()
    assert "suppression_example" in finding

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


def test_global_fail_on_applies_to_every_scanner_family(monkeypatch):
    monkeypatch.setattr(policy_engine, "FAIL_ON_SEVERITIES", {"CRITICAL"})
    monkeypatch.setattr(policy_engine, "FAIL_ON_RUFF_SEVERITIES", {"CRITICAL"})
    monkeypatch.setattr(policy_engine, "FAIL_ON_SEMGREP_SEVERITIES", {"CRITICAL"})
    monkeypatch.setattr(policy_engine, "FAIL_ON_TRIVY_SEVERITIES", {"CRITICAL"})

    safety = policy_engine.analyze_safety([{"package": "flask"}])
    osv = policy_engine.analyze_osv([{"id": "OSV-1", "package": "flask", "cvss": 5.0}])
    secrets = policy_engine.analyze_secrets(
        {"results": {"app.py": [{"type": "API key"}]}}
    )
    yara = policy_engine.analyze_yara([{"rule": "Webshell", "filename": "app.py"}])
    clamav = policy_engine.analyze_clamav([{"virus": "EICAR", "filename": "eicar"}])
    dast = policy_engine.analyze_zap(
        [{"status": "EXPOSED", "vuln_type": "XSS", "route": "/xss"}]
    )

    assert {item["status"] for item in (safety, osv, secrets, yara, clamav, dast)} == {"PASS"}


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


def test_policy_decision_treats_scanner_error_as_operational_failure():
    decision = evaluate_policy_results([
        {
            "tool": "IaC",
            "status": "ERROR",
            "total_issues": 0,
            "blocking_issues": 0,
            "examples": [],
        }
    ])

    assert decision["status"] == "ERROR"
    assert decision["error_tools"] == ["IaC"]
    assert "IaC" in decision["reason"]


def test_failed_iac_report_forces_policy_engine_error(tmp_path):
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
        "iac-report.json": {"status": "failed", "findings": []},
    }
    for filename, payload in reports.items():
        (tmp_path / filename).write_text(json.dumps(payload))

    markdown_report = tmp_path / "report.md"
    exit_code = run_policy_engine(tmp_path, md_path=markdown_report)

    assert exit_code == 2
    assert "DEPLOYMENT ERROR" in markdown_report.read_text()
    assert "IaC" in markdown_report.read_text()


def test_html_report_escapes_untrusted_finding_content(tmp_path):
    html_report = tmp_path / "report.html"
    markdown_report = tmp_path / "report.md"
    payload = "<script>window.reportCompromised=true</script>"
    generate_reports(
        [
            {
                "tool": "Semgrep",
                "status": "FAIL",
                "total_issues": 1,
                "blocking_issues": 1,
                "examples": [
                    {
                        "severity": "HIGH",
                        "test_id": "test-rule",
                        "issue_text": payload,
                        "filename": payload,
                        "line_number": 1,
                    }
                ],
            }
        ],
        "BLOCKED",
        payload,
        html_path=html_report,
        md_path=markdown_report,
    )

    rendered = html_report.read_text()
    assert payload not in rendered
    assert "&lt;script&gt;window.reportCompromised=true&lt;/script&gt;" in rendered


def test_reports_include_remediation_and_copyable_fix(tmp_path):
    html_report = tmp_path / "report.html"
    markdown_report = tmp_path / "report.md"
    results = [
        analyze_ruff([
            {
                "code": "S307",
                "filename": "app.py",
                "location": {"row": 7},
                "message": "Use of possibly insecure function; consider using ast.literal_eval",
            }
        ])
    ]

    generate_reports(
        results,
        "BLOCKED",
        "Blocking security issues found by: Ruff (SAST)",
        html_path=html_report,
        md_path=markdown_report,
    )

    html = html_report.read_text()
    markdown = markdown_report.read_text()
    assert "Why it matters" in html
    assert "Copy fix" in html
    assert "ast.literal_eval" in html
    assert "## Finding Guidance" in markdown
    assert "Safe to suppress" in markdown
