from policy_engine import analyze_semgrep

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


