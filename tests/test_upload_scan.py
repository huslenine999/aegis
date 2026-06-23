import io
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import app.main as app_main
from app.main import SCANS_DIR

@pytest.fixture
def client():
    from app.database import initialize_database
    import shutil
    initialize_database()
    app_main.WAF_ENABLED = False
    
    # Clean up scans/uploads directory to avoid pollution from prior runs
    uploads_dir = SCANS_DIR / "uploads"
    if uploads_dir.exists():
        shutil.rmtree(uploads_dir)
        
    yield TestClient(app_main.app)

def test_run_scan_default(client):
    """Ensure the default run-scan (no file uploaded) scans the codebase and runs successfully."""
    response = client.post('/run-scan')
    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    
    # Check that reports were generated
    assert (SCANS_DIR / "ruff-report.json").exists()
    assert (SCANS_DIR / "safety-report.json").exists()
    assert (SCANS_DIR / "trivy-report.json").exists()
    assert (SCANS_DIR / "report.html").exists()

def test_run_scan_custom_clean(client):
    """Ensure a custom clean Python file upload runs successfully and passes the policy gate."""
    clean_code = "print('Hello, secure world!')\n"
    files = {
        'file': ('clean_test.py', clean_code.encode('utf-8'))
    }
    
    response = client.post('/run-scan', files=files)
    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    
    # The uploads folder should be completely clean (no UUID subdirectories remaining)
    uploads_dir = SCANS_DIR / "uploads"
    if uploads_dir.exists():
        subdirs = list(uploads_dir.iterdir())
        assert len(subdirs) == 0

    # Ensure reports are generated
    assert (SCANS_DIR / "ruff-report.json").exists()
    ruff_report = json.loads((SCANS_DIR / "ruff-report.json").read_text())
    # Should find no issues
    assert len(ruff_report) == 0

def test_run_scan_custom_vulnerable(client):
    """Ensure a custom vulnerable Python file upload runs successfully but fails the policy gate due to Bandit flagging it."""
    vuln_code = "eval(input())\n"
    files = {
        'file': ('vuln_test.py', vuln_code.encode('utf-8'))
    }
    
    response = client.post('/run-scan', files=files)
    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    
    # Ensure it contains the vulnerability
    assert (SCANS_DIR / "ruff-report.json").exists()
    ruff_report = json.loads((SCANS_DIR / "ruff-report.json").read_text())
    assert len(ruff_report) > 0
    assert any("eval" in issue.get("message", "").lower() or "s307" in issue.get("code", "").lower() for issue in ruff_report)

    # The HTML report should reflect BLOCKED because of the medium/high vulnerability in Bandit
    assert (SCANS_DIR / "report.html").exists()
    report_html = (SCANS_DIR / "report.html").read_text()
    assert "BLOCKED" in report_html

def test_run_scan_vulnerable_target(client):
    """Test that scanning the vulnerable target (main.py) triggers Bandit and blocks the gate."""
    response = client.post('/run-scan', json={"target": "vulnerable"})
    assert response.status_code == 200
    assert response.json()['status'] == 'success'

    # Ensure reports are generated
    assert (SCANS_DIR / "ruff-report.json").exists()
    assert (SCANS_DIR / "report.html").exists()

    ruff_report = json.loads((SCANS_DIR / "ruff-report.json").read_text())

    # Assert findings are parsed
    assert len(ruff_report) > 0

    report_html = (SCANS_DIR / "report.html").read_text()
    assert "BLOCKED" in report_html

def test_run_scan_secure_target(client):
    """Test that scanning the secure target (secure_main.py) has no issues and allows deployment."""
    response = client.post('/run-scan', json={"target": "secure"})
    assert response.status_code == 200
    assert response.json()['status'] == 'success'

    # Ensure reports are generated
    assert (SCANS_DIR / "ruff-report.json").exists()
    assert (SCANS_DIR / "report.html").exists()

    ruff_report = json.loads((SCANS_DIR / "ruff-report.json").read_text())

    # The secure secure_main.py has no issues
    assert len(ruff_report) == 0

    report_html = (SCANS_DIR / "report.html").read_text()
    assert "ALLOWED" in report_html

def test_run_scan_non_python_rejected(client):
    """Ensure a custom scan with a non-Python file (e.g. .c) is rejected with 400 Bad Request."""
    c_code = "#include <stdio.h>\n"
    files = {
        'file': ('test.c', c_code.encode('utf-8'))
    }
    response = client.post('/run-scan', files=files)
    assert response.status_code == 400
    assert "Invalid file type" in response.json()['detail']
