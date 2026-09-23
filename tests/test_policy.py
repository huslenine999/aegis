import json
from pathlib import Path

import pytest

import policy_engine
from app.dependencies import DependencyManifest, DependencyPackage
from policy_engine import (
    analyze_codeql,
    analyze_report_set,
    analyze_ruff,
    evaluate_policy_results,
    generate_reports,
    run_policy_engine,
)


def test_active_report_set_ignores_retired_scanners_and_keeps_codeql_full_findings():
    codeql = {
        "status": "completed",
        "coverage": {"complete": True, "languages": ["python"], "source_scope": "repository", "isolation": "verified"},
        "findings": [
            {"rule_id": "py/sql-injection", "severity": "HIGH", "filename": f"src/{index}.py", "line_number": index, "issue_text": "SQL injection", "code_flows": []}
            for index in range(7)
        ],
    }
    results = analyze_report_set({
        "ruff": [], "semgrep": {"results": []}, "osv": [],
        "secrets": {"results": {}}, "codeql": codeql,
        "safety": [{"package": "old"}], "iac": {"status": "failed"},
    })
    assert {result["tool"] for result in results} == {
        "Ruff (SAST)", "Semgrep", "OSV Dependency Audit",
        "Secrets Scanner", "CodeQL",
    }
    analyzed = next(item for item in results if item["tool"] == "CodeQL")
    assert analyzed["status"] == "FAIL"
    assert analyzed["total_issues"] == 7
    assert len(analyzed["findings"]) == 7
    assert len(analyzed["examples"]) == 5


def test_codeql_incomplete_or_malformed_report_is_error():
    assert analyze_codeql(None)["status"] == "ERROR"
    assert analyze_codeql({"status": "completed", "findings": [], "coverage": {"complete": False}})["status"] == "ERROR"
    assert analyze_codeql({"status": "completed", "findings": [], "coverage": {"complete": True, "languages": []}})["status"] == "ERROR"
    assert analyze_codeql({"status": "completed", "findings": [], "coverage": {"complete": True, "languages": ["python"], "isolation": "unverified"}})["status"] == "ERROR"
    assert analyze_codeql({"status": "completed", "findings": [], "coverage": {"complete": True, "languages": ["python"]}})["status"] == "ERROR"


def test_missing_required_codeql_report_fails_closed(tmp_path):
    for filename, payload in {
        "ruff-report.json": [],
        "semgrep-report.json": {"results": []},
        "secrets-report.json": {"results": {}},
        "osv-report.json": [],
    }.items():
        (tmp_path / filename).write_text(json.dumps(payload))
    exit_code = run_policy_engine(
        tmp_path, html_path=tmp_path / "report.html", md_path=tmp_path / "report.md",
        tool_states={"CodeQL": "completed"},
    )
    assert exit_code == 2


def test_codeql_error_cannot_be_ignored_by_legacy_error_toggle():
    assert evaluate_policy_results([analyze_codeql(None)], fail_on_errors=False)["status"] == "ERROR"


def test_osv_query_preserves_advisory_aliases(tmp_path, monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        @staticmethod
        def read():
            return json.dumps({
                "vulns": [{
                    "id": "PYSEC-2099-1",
                    "aliases": ["GHSA-example"],
                    "summary": "Example advisory",
                    "details": "Example details",
                }],
            }).encode()

    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", tmp_path / "osv-cache.json")
    monkeypatch.setattr(policy_engine.time, "sleep", lambda _seconds: None)
    manifest = DependencyManifest(
        path=Path("requirements.txt"),
        kind="requirements.txt",
        ecosystem="PyPI",
        packages=(DependencyPackage("scanner-helper", "1.0.0", "PyPI"),),
    )

    findings = policy_engine.query_osv_vulnerabilities([manifest])

    assert findings[0]["id"] == "PYSEC-2099-1"
    assert findings[0]["aliases"] == ["GHSA-example"]


def test_osv_strict_mode_rejects_stale_clean_cache_on_outage(tmp_path, monkeypatch):
    cache = tmp_path / "osv-cache.json"
    cache.write_text(json.dumps({
        "PyPI:scanner-helper@1.0.0": {
            "timestamp": 0,
            "vulns": [],
        }
    }))
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", cache)
    monkeypatch.setattr(policy_engine.time, "time", lambda: 200000)
    monkeypatch.setattr(
        policy_engine.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("offline")),
    )
    manifest = DependencyManifest(
        path=Path("requirements.txt"),
        kind="requirements.txt",
        ecosystem="PyPI",
        packages=(DependencyPackage("scanner-helper", "1.0.0", "PyPI"),),
    )

    with pytest.raises(RuntimeError, match="OSV queries failed"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)


def test_osv_strict_mode_rejects_malformed_cache_on_outage(tmp_path, monkeypatch):
    cache = tmp_path / "osv-cache.json"
    cache.write_text("[]")
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", cache)
    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("offline")))
    manifest = DependencyManifest(
        path=Path("requirements.txt"),
        kind="requirements.txt",
        ecosystem="PyPI",
        packages=(DependencyPackage("scanner-helper", "1.0.0", "PyPI"),),
    )

    with pytest.raises(RuntimeError, match="OSV queries failed"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)


def test_osv_strict_mode_rejects_unresolved_dependency_inventory():
    manifest = DependencyManifest(
        path=Path("requirements.txt"),
        kind="requirements.txt",
        ecosystem="PyPI",
        packages=(DependencyPackage("scanner-helper", None, "PyPI"),),
    )

    with pytest.raises(RuntimeError, match="inventory incomplete"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)


def test_osv_strict_mode_requires_lockfile_to_cover_unresolved_packages():
    package_manifest = DependencyManifest(
        path=Path("package.json"),
        kind="package.json",
        ecosystem="npm",
        packages=(DependencyPackage("lodash", None, "npm"),),
    )
    empty_lock = DependencyManifest(
        path=Path("package-lock.json"),
        kind="package-lock.json",
        ecosystem="npm",
    )

    with pytest.raises(RuntimeError, match="inventory incomplete"):
        policy_engine.query_osv_vulnerabilities(
            [package_manifest, empty_lock], raise_on_error=True
        )


def test_osv_strict_mode_rejects_manifest_parse_errors():
    manifest = DependencyManifest(
        path=Path("pyproject.toml"),
        kind="pyproject.toml",
        ecosystem="PyPI",
        parse_error="TOMLDecodeError: invalid table",
    )

    with pytest.raises(RuntimeError, match="manifest parsing failed"):
        policy_engine.query_osv_vulnerabilities([manifest], raise_on_error=True)


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


def test_policy_engine_fails_closed_when_dependency_evidence_is_incomplete(tmp_path):
    reports = {
        "ruff-report.json": [],
        "safety-report.json": [],
        "trivy-report.json": {"Results": []},
        "secrets-report.json": {"results": {}},
        "yara-report.json": [],
        "semgrep-report.json": {"results": []},
        "clamav-report.json": [],
        "zap-report.json": [],
        "iac-report.json": {"status": "completed", "findings": []},
    }
    for filename, payload in reports.items():
        (tmp_path / filename).write_text(json.dumps(payload))

    manifest = DependencyManifest(
        path=tmp_path / "requirements.txt",
        kind="requirements.txt",
        ecosystem="PyPI",
        packages=(DependencyPackage("requests", None, "PyPI"),),
    )
    markdown_report = tmp_path / "report.md"
    exit_code = run_policy_engine(
        tmp_path,
        md_path=markdown_report,
        dependency_manifests=[manifest],
    )

    assert exit_code == 2
    assert "DEPLOYMENT ERROR" in markdown_report.read_text()
    assert "OSV" in markdown_report.read_text()


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
