import json
import pytest
from fastapi.testclient import TestClient
import app.main as app_main
from app.main import app
from app.worker import run_clamav_scan, run_dast_scan
from policy_engine import analyze_clamav, analyze_zap

@pytest.fixture
def client():
    from app.database import initialize_database
    initialize_database(reset=True)
    app_main.WAF_ENABLED = False
    yield TestClient(app)

def test_run_clamav_scan_eicar(tmp_path):
    # Create a temp file containing the EICAR signature
    eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    temp_file = tmp_path / "eicar_test.txt"
    temp_file.write_text(eicar_content)
    
    findings = run_clamav_scan(str(temp_file), job_id="test_job")
    assert len(findings) == 1
    assert findings[0]["virus"] == "EICAR-Test-Signature"
    assert "EICAR" in findings[0]["description"]
    assert findings[0]["filename"] == str(temp_file)

def test_run_clamav_scan_backdoor(tmp_path):
    # Create a temp python file with base64 backdoor patterns
    backdoor_content = """
import base64
eval(base64.b64decode("c3lzdGVtKCdpZCcp"))
"""
    temp_file = tmp_path / "backdoor_test.py"
    temp_file.write_text(backdoor_content)
    
    findings = run_clamav_scan(str(temp_file), job_id="test_job")
    assert len(findings) == 1
    assert findings[0]["virus"] == "Python.Backdoor.Base64Decoder"
    assert "backdoor" in findings[0]["description"].lower()

def test_run_dast_scan_waf_disabled(client):
    # Ensure WAF is disabled
    rules_resp = client.get('/get-waf-rules')
    if rules_resp.json().get('waf_enabled'):
        client.post('/toggle-waf')

    findings = run_dast_scan(job_id="test_job")
    # When WAF is disabled, all ZAP checks should find the vulnerability EXPOSED.
    exposed = [f for f in findings if f["status"] == "EXPOSED"]
    assert len(exposed) == 6  # SQLi, RCE, Eval, LFI, XSS, SSRF

def test_run_dast_scan_waf_enabled(client):
    # Ensure WAF is enabled
    rules_resp = client.get('/get-waf-rules')
    if not rules_resp.json().get('waf_enabled'):
        client.post('/toggle-waf')

    findings = run_dast_scan(job_id="test_job")
    # When WAF is enabled, all ZAP checks should be MITIGATED.
    mitigated = [f for f in findings if f["status"] == "MITIGATED"]
    if len(mitigated) != 6:
        print("\n\n--- DAST FINDINGS IN TEST ---")
        for f in findings:
            print(f"{f['vuln_type']}: status={f['status']}, code={f['response_code']}, route={f['route']}, payload={f['payload']}")
        print("-----------------------------\n")
    assert len(mitigated) == 6

    # Restore WAF to disabled (clean state)
    client.post('/toggle-waf')

def test_policy_engine_clamav():
    # Test analyze_clamav with mock reports
    clean_report = []
    assert analyze_clamav(clean_report)["status"] == "PASS"
    assert analyze_clamav(clean_report)["total_issues"] == 0

    infected_report = [
        {"filename": "test.txt", "virus": "EICAR-Test-Signature", "description": "Matched EICAR"}
    ]
    analysis = analyze_clamav(infected_report)
    assert analysis["status"] == "FAIL"
    assert analysis["total_issues"] == 1
    assert analysis["blocking_issues"] == 1

def test_policy_engine_zap():
    # Test analyze_zap with mock reports
    clean_report = [
        {"vuln_type": "SQL Injection", "route": "/user", "payload": "payload", "description": "desc", "status": "MITIGATED"}
    ]
    analysis = analyze_zap(clean_report)
    assert analysis["status"] == "PASS"
    assert analysis["blocking_issues"] == 0

    vulnerable_report = [
        {"vuln_type": "SQL Injection", "route": "/user", "payload": "payload", "description": "desc", "status": "EXPOSED"}
    ]
    analysis = analyze_zap(vulnerable_report)
    assert analysis["status"] == "FAIL"
    assert analysis["blocking_issues"] == 1

def test_get_scan_results_endpoint(client):
    # Trigger scan results endpoint
    response = client.get('/get-scan-results')
    assert response.status_code == 200
    assert 'clamav' in response.json()
    assert 'zap' in response.json()
