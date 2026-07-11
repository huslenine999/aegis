import json
from policy_engine import parse_cvss_vector, calculate_exploitability_score as calculate_policy_score
import app.main as app_main

def test_parse_cvss_vector_critical():
    # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H is CVSS 10.0 (Network, Low complexity, no privileges, no user interaction, Scope Changed, High confidentiality, integrity, availability)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    score = parse_cvss_vector(vector)
    assert score == 10.0

def test_parse_cvss_vector_high():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is CVSS 9.8 (Network, Low complexity, no privileges, no user interaction, Scope Unchanged, High C/I/A)
    vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = parse_cvss_vector(vector)
    assert score == 9.8

def test_parse_cvss_vector_medium():
    # AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L is CVSS 3.8
    vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
    score = parse_cvss_vector(vector)
    assert score == 3.8

def test_parse_cvss_vector_invalid():
    assert parse_cvss_vector("") == 0.0
    assert parse_cvss_vector("INVALID_VECTOR") == 0.0

def test_policy_exploitability_score_calculation():
    results = [
        {"tool": "Ruff (SAST)", "total_issues": 1, "blocking_issues": 1, "status": "FAIL", "severity_counts": {"HIGH": 1}, "examples": [
            {"severity": "HIGH", "issue_text": "SQL Injection"}
        ]},
        {"tool": "OSV Dependency Audit", "total_issues": 1, "blocking_issues": 1, "status": "FAIL", "severity_counts": {"HIGH": 1}, "examples": [
            {"package": "flask", "cvss": 7.5, "id": "CVE-2024-1234"}
        ]}
    ]
    # The score uses the worst severity plus a logarithmic volume bonus.
    score_waf_off = calculate_policy_score(results, False)
    assert score_waf_off == 89.0

    # WAF state does not discount unrelated static or dependency findings.
    score_waf_on = calculate_policy_score(results, True)
    assert score_waf_on == 89.0

def test_app_exploitability_score_calculation(tmp_path):
    # Setup mock scan reports in temp directory
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    
    # Write blank reports
    (scans_dir / "ruff-report.json").write_text(json.dumps([]))
    (scans_dir / "semgrep-report.json").write_text(json.dumps({"results": []}))
    (scans_dir / "safety-report.json").write_text(json.dumps([]))
    (scans_dir / "trivy-report.json").write_text(json.dumps({"Results": []}))
    (scans_dir / "secrets-report.json").write_text(json.dumps({"results": {}}))
    (scans_dir / "yara-report.json").write_text(json.dumps([]))
    (scans_dir / "clamav-report.json").write_text(json.dumps([]))
    (scans_dir / "zap-report.json").write_text(json.dumps([]))
    (scans_dir / "osv-report.json").write_text(json.dumps([]))

    # Assert base score is 0.0 when no issues
    assert app_main.calculate_exploitability_score(scans_dir, False) == 0.0

    # Add a Ruff issue (HIGH = 8.5) and a ZAP exposed route issue (exposed multiplier = 1.5)
    (scans_dir / "ruff-report.json").write_text(json.dumps([
        {"code": "S608", "filename": "app.py", "location": {"row": 10}, "message": "SQL Injection"}
    ]))
    (scans_dir / "zap-report.json").write_text(json.dumps([
        {"status": "EXPOSED", "vuln_type": "SQL Injection", "route": "/user", "payload": "' OR 1=1", "description": "SQL Injection"}
    ]))

    # Two high-severity findings produce a high score without saturating at 100.
    score_waf_off = app_main.calculate_exploitability_score(scans_dir, False)
    assert score_waf_off == 89.0

    # The WAF does not discount the independent static finding.
    score_waf_on = app_main.calculate_exploitability_score(scans_dir, True)
    assert score_waf_on == 89.0
