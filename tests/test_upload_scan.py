import io
import json
import pytest
from pathlib import Path
from app.main import app, SCANS_DIR

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_run_scan_default(client):
    """Ensure the default run-scan (no file uploaded) scans the codebase and runs successfully."""
    response = client.post('/run-scan')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # Check that reports were generated
    assert (SCANS_DIR / "bandit-report.json").exists()
    assert (SCANS_DIR / "safety-report.json").exists()
    assert (SCANS_DIR / "trivy-report.json").exists()
    assert (SCANS_DIR / "report.html").exists()

def test_run_scan_custom_clean(client):
    """Ensure a custom clean Python file upload runs successfully and passes the policy gate."""
    # Create a mock clean python file in memory
    clean_code = "print('Hello, secure world!')\n"
    data = {
        'file': (io.BytesIO(clean_code.encode('utf-8')), 'clean_test.py')
    }
    
    response = client.post('/run-scan', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # The uploads folder should be completely clean (no UUID subdirectories remaining)
    uploads_dir = SCANS_DIR / "uploads"
    if uploads_dir.exists():
        subdirs = list(uploads_dir.iterdir())
        assert len(subdirs) == 0

    # Ensure reports are generated
    assert (SCANS_DIR / "bandit-report.json").exists()
    bandit_report = json.loads((SCANS_DIR / "bandit-report.json").read_text())
    # Should find no issues
    assert len(bandit_report.get("results", [])) == 0

def test_run_scan_custom_vulnerable(client):
    """Ensure a custom vulnerable Python file upload runs successfully but fails the policy gate due to Bandit flagging it."""
    # Create a mock vulnerable python file using eval()
    vuln_code = "eval(input())\n"
    data = {
        'file': (io.BytesIO(vuln_code.encode('utf-8')), 'vuln_test.py')
    }
    
    response = client.post('/run-scan', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # Ensure it contains the vulnerability
    assert (SCANS_DIR / "bandit-report.json").exists()
    bandit_report = json.loads((SCANS_DIR / "bandit-report.json").read_text())
    assert len(bandit_report.get("results", [])) > 0
    assert any("eval" in issue.get("issue_text", "").lower() or "b307" in issue.get("test_id", "").lower() for issue in bandit_report.get("results", []))

    # The HTML report should reflect BLOCKED because of the medium/high vulnerability in Bandit
    assert (SCANS_DIR / "report.html").exists()
    report_html = (SCANS_DIR / "report.html").read_text()
    assert "BLOCKED" in report_html

def test_run_scan_vulnerable_target(client):
    """Test that scanning the vulnerable target (main.py) triggers Bandit and blocks the gate."""
    response = client.post('/run-scan', json={"target": "vulnerable"})
    assert response.status_code == 200
    assert response.json['status'] == 'success'

    # Ensure reports are generated
    assert (SCANS_DIR / "bandit-report.json").exists()
    assert (SCANS_DIR / "report.html").exists()

    bandit_report = json.loads((SCANS_DIR / "bandit-report.json").read_text())

    # If Bandit did not encounter internal errors, assert findings
    if not bandit_report.get("errors"):
        assert len(bandit_report.get("results", [])) > 0

    report_html = (SCANS_DIR / "report.html").read_text()
    assert "BLOCKED" in report_html

def test_run_scan_secure_target(client):
    """Test that scanning the secure target (secure_main.py) has no issues and allows deployment."""
    response = client.post('/run-scan', json={"target": "secure"})
    assert response.status_code == 200
    assert response.json['status'] == 'success'

    # Ensure reports are generated
    assert (SCANS_DIR / "bandit-report.json").exists()
    assert (SCANS_DIR / "report.html").exists()

    bandit_report = json.loads((SCANS_DIR / "bandit-report.json").read_text())

    # The secure secure_main.py has no issues
    assert len(bandit_report.get("results", [])) == 0

    report_html = (SCANS_DIR / "report.html").read_text()
    assert "ALLOWED" in report_html
