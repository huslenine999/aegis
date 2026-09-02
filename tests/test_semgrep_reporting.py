import json
from pathlib import Path
from policy_engine import analyze_semgrep
from app.main import app
from app.web_common import generate_fallback_tree
from fastapi.testclient import TestClient

def test_analyze_semgrep_pass():
    report = {"results": []}
    result = analyze_semgrep(report)
    assert result["status"] == "PASS"
    assert result["total_issues"] == 0
    assert result["blocking_issues"] == 0


def test_analyze_semgrep_fail():
    report = {
        "results": [
            {
                "check_id": "python-sqli",
                "path": "app/main.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": "Detected potential SQL injection",
                    "lines": "cursor.execute(query)"
                }
            },
            {
                "check_id": "python-weak-hash",
                "path": "app/main.py",
                "start": {"line": 50},
                "extra": {
                    "severity": "WARNING",
                    "message": "Detected weak hashing",
                    "lines": "hashlib.md5(v)"
                }
            }
        ]
    }
    result = analyze_semgrep(report)
    assert result["status"] == "FAIL"
    assert result["total_issues"] == 2
    assert result["blocking_issues"] == 2
    
    # Assert severities are mapped correctly
    mapped_sqli = [e for e in result["examples"] if e["test_id"] == "python-sqli"][0]
    mapped_hash = [e for e in result["examples"] if e["test_id"] == "python-weak-hash"][0]
    assert mapped_sqli["severity"] == "HIGH"
    assert mapped_hash["severity"] == "MEDIUM"


def test_analyze_semgrep_missing():
    result = analyze_semgrep(None)
    assert result["status"] == "MISSING"


def test_generate_fallback_tree():
    tree = generate_fallback_tree()
    assert isinstance(tree, list)
    if len(tree) > 0:
        # Check Flask is listed from requirements
        flask_pkg = [p for p in tree if p["package_name"].lower() == "flask"]
        assert len(flask_pkg) > 0
        assert flask_pkg[0]["installed_version"] != ""


def test_get_dependency_graph_route():
    client = TestClient(app)
    response = client.get('/get-dependency-graph')
    assert response.status_code == 200
    ct = response.headers.get('content-type', '') or response.headers.get('Content-Type', '')
    assert ct.startswith('application/json')
    
    data = response.json()
    assert "nodes" in data
    assert "links" in data
    
    # Verify root node is present
    root_node = [n for n in data["nodes"] if n["id"] == "aegis"]
    assert len(root_node) == 1
    assert root_node[0]["isRoot"] is True
    assert root_node[0]["vulnerable"] is False


def test_run_scan_generates_semgrep_report():
    client = TestClient(app)
    # Trigger scan
    response = client.post('/run-scan', json={"target": "secure"})
    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    
    semgrep_report_path = Path("scans/semgrep-report.json")
    assert semgrep_report_path.exists()
    
    data = json.loads(semgrep_report_path.read_text())
    assert "results" in data
