"""CodeQL adapter trust-boundary and completeness regressions."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import codeql_scanner


def sarif_run(*, language: str, results: list[dict] | None = None) -> dict:
    return {
        "tool": {"driver": {
            "name": "CodeQL", "version": "2.20.0",
            "rules": [{"id": "py/sql-injection", "properties": {
                "security-severity": "8.8", "tags": ["external/cwe/cwe-089"]}}],
        }},
        "invocations": [{"executionSuccessful": True}],
        "automationDetails": {"id": language},
        "results": results if results is not None else [],
    }


def sarif_result(uri: str = "src/app.py") -> dict:
    return {
        "ruleIndex": 0,
        "message": {"text": "User input reaches SQL query"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": 42},
        }}],
        "partialFingerprints": {"primaryLocationLineHash": "abc123"},
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/input.py"}, "region": {"startLine": 5}}, "message": {"text": "source"}}},
            {"location": {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 42}}, "message": {"text": "sink"}}},
        ]}]}],
    }


def test_parse_all_runs_and_preserve_paths(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    report = tmp_path / "raw.sarif"
    report.write_text(json.dumps({"version": "2.1.0", "runs": [
        sarif_run(language="python", results=[sarif_result()]),
        sarif_run(language="python", results=[sarif_result("src/other.py")]),
    ]}), encoding="utf-8")

    findings = codeql_scanner.parse_codeql_sarif(report, source, language="python")

    assert len(findings) == 2
    assert findings[0]["rule_id"] == "py/sql-injection"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["cwe"] == ["CWE-089"]
    assert findings[0]["filename"] == "src/app.py"
    assert findings[0]["line_number"] == 42
    assert findings[0]["code_flows"][0][0]["filename"] == "src/input.py"
    assert findings[0]["code_flows"][0][-1]["message"] == "sink"


@pytest.mark.parametrize("mutate", [
    lambda doc: doc.update(version="2.0.0"),
    lambda doc: doc["runs"][0].pop("invocations"),
    lambda doc: doc["runs"][0]["invocations"][0].update(executionSuccessful=False),
    lambda doc: doc["runs"][0]["tool"]["driver"].update(name="Other"),
    lambda doc: doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].update(uri="../secret"),
    lambda doc: doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].update(uri="https://example.com/f"),
])
def test_parse_rejects_incomplete_or_hostile_sarif(tmp_path: Path, mutate) -> None:
    source = tmp_path / "source"
    source.mkdir()
    doc = {"version": "2.1.0", "runs": [sarif_run(language="python", results=[sarif_result()])]}
    mutate(doc)
    report = tmp_path / "raw.sarif"
    report.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(codeql_scanner.CodeQLScanError):
        codeql_scanner.parse_codeql_sarif(report, source, language="python")


def test_run_requires_trusted_runtime_and_raises_on_missing_sarif(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    codeql = tmp_path / "operator" / "codeql"
    codeql.parent.mkdir()
    codeql.write_text("#!/bin/sh\n", encoding="utf-8")
    codeql.chmod(0o755)
    suite = tmp_path / "operator" / "python-code-scanning.qls"
    suite.write_text("- include: test\n", encoding="utf-8")

    def fake_run(command, **kwargs):
        if command[1] == "version":
            kwargs["stdout_sink"].write(b"CodeQL command-line toolchain release 2.20.0\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess", fake_run)
    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess_to_file", fake_run)

    with pytest.raises(codeql_scanner.CodeQLScanError, match="missing SARIF"):
        codeql_scanner.run_codeql_scan(
            source, output, codeql_path=codeql,
            query_suites={"python": suite}, languages=["python"],
        )
    assert not (output / "codeql-report.json").exists()


def test_run_rejects_suite_inside_target_and_unsupported_language(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    codeql = source / "codeql"
    codeql.write_text("#!/bin/sh\n", encoding="utf-8")
    codeql.chmod(0o755)
    suite = source / "suite.qls"
    suite.write_text("[]\n", encoding="utf-8")
    with pytest.raises(codeql_scanner.CodeQLScanError):
        codeql_scanner.run_codeql_scan(source, tmp_path / "output", codeql_path=codeql, query_suites={"python": suite}, languages=["python"])
    with pytest.raises(codeql_scanner.CodeQLScanError):
        codeql_scanner.run_codeql_scan(source, tmp_path / "output", codeql_path=codeql, query_suites={"python": suite}, languages=["java"])
