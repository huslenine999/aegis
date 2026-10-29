"""CodeQL adapter trust-boundary and completeness regressions."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import codeql_scanner


def sarif_run(*, language: str, results: list[dict] | None = None) -> dict:
    return {
        "tool": {"driver": {
            "name": "CodeQL command-line toolchain", "version": "2.20.0",
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
    lambda doc: doc["runs"][0].pop("results"),
    lambda doc: doc["runs"][0]["invocations"][0].update(executionSuccessful=False),
    lambda doc: doc["runs"][0]["tool"]["driver"].update(name="Other"),
    lambda doc: doc.update(runs=[]),
    lambda doc: doc["runs"].append(None),
    lambda doc: doc["runs"][0]["results"].append(None),
    lambda doc: doc["runs"][0]["results"][0].update(ruleIndex=True),
    lambda doc: doc["runs"][0]["results"][0]["message"].update(text=False),
    lambda doc: doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"].update(tags="CWE-89"),
    lambda doc: doc["runs"][0]["results"][0].update(partialFingerprints="invalid"),
    lambda doc: doc["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0].update(location="invalid"),
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


@pytest.mark.parametrize("report_content, message", [(None, "missing SARIF"), ("{", "malformed")])
def test_run_requires_trusted_runtime_and_rejects_missing_or_malformed_sarif(tmp_path: Path, monkeypatch, report_content, message) -> None:
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
        if command[1:3] == ["database", "analyze"] and report_content is not None:
            kwargs["output_path"].write_text(report_content)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess", fake_run)
    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess_to_file", fake_run)

    with pytest.raises(codeql_scanner.CodeQLScanError, match=message):
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


def test_isolated_runner_uses_bounded_offline_container_and_preserves_evidence(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text("pass\n")
    (source / "src" / "index.ts").write_text("const value = 1;\n")
    for ignored in codeql_scanner.IGNORED_DIRS:
        directory = source / ignored
        directory.mkdir()
        (directory / "must-not-enter-analysis.py").write_text("raise RuntimeError()\n")
    outside = tmp_path / "outside.py"
    outside.write_text("raise RuntimeError()\n")
    (source / "src" / "escape.py").symlink_to(outside)
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\n")
    docker.chmod(0o755)
    image = "operator/codeql@sha256:" + "a" * 64
    socket_path = tmp_path / "docker.sock"
    socket_path.touch()
    monkeypatch.setattr(codeql_scanner.stat, "S_ISSOCK", lambda mode: True)
    commands = []
    scanner_environment = []
    archives = []
    decoded = []
    source_tar = codeql_scanner._source_tar
    load_json = codeql_scanner.load_bounded_json

    def counted_tar(source, destination):
        archives.append(destination)
        source_tar(source, destination)

    def counted_decode(path):
        decoded.append(path.name)
        return load_json(path)

    def fake_run(command, **kwargs):
        commands.append(command)
        scanner_environment.append(kwargs["env"])
        if "version" in " ".join(command):
            kwargs["stdout_sink"].write(b"CodeQL command-line toolchain release 2.20.0\n")
        return SimpleNamespace(returncode=0)

    def fake_scan(command, **kwargs):
        commands.append(command)
        scanner_environment.append(kwargs["env"])
        source_archive = kwargs["stdin"].read()
        kwargs["stdin"].seek(0)
        with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r") as archive:
            members = archive.getmembers()
        assert {member.name for member in members} == {"src/app.py", "src/index.ts"}
        assert all(member.isfile() for member in members)
        assert set(kwargs["env"]) == {"PATH", "DOCKER_HOST", "DOCKER_CONFIG"}
        assert "cat > /work/source.tar" in command[-1]
        assert "tar -xf /work/source.tar -C /work/source" in command[-1]
        assert "rm /work/source.tar" in command[-1]
        language = command[-1].split("--language=", 1)[1].split()[0]
        uri = "src/app.py" if language == "python" else "src/index.ts"
        kwargs["output_path"].write_text(json.dumps({
            "version": "2.1.0", "runs": [sarif_run(language=language, results=[sarif_result(uri)])]
        }))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess", fake_run)
    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess_stdout_to_file", fake_scan)
    monkeypatch.setattr(codeql_scanner, "_source_tar", counted_tar)
    monkeypatch.setattr(codeql_scanner, "load_bounded_json", counted_decode)
    report = codeql_scanner.run_codeql_scan_isolated(
        source, tmp_path / "output", image=image,
        query_suites={language: f"codeql/{language}-queries:security.qls" for language in ("python", "javascript-typescript")},
        docker_host=f"unix://{socket_path}", docker_path=docker,
    )
    command = next(item for item in commands if "database create" in " ".join(item))
    assert {
        "--network=none", "--read-only", "--cap-drop=ALL", "--pull=never",
        "--security-opt=no-new-privileges:true", "--pids-limit=128",
        "--memory=4g", "--cpus=2", "--user=10001:10001",
    } <= set(command)
    assert not any("type=bind" in item for item in command)
    assert not any(item.startswith("-v") or item.startswith("--volume") for item in command)
    assert all("DATABASE_URL" not in env and "AEGIS_EVIDENCE_SIGNING_KEY" not in env for env in scanner_environment)
    assert report["coverage"]["isolation"] == "verified"
    assert report["coverage"]["languages"] == ["javascript-typescript", "python"]
    assert len(archives) == 1
    assert sorted(decoded) == ["javascript-typescript.sarif", "python.sarif"]
    assert {finding["filename"] for finding in report["findings"]} == {"src/app.py", "src/index.ts"}
    assert report["findings"][0]["rule_id"] == "py/sql-injection"
    assert (tmp_path / "output" / "codeql.sarif").exists()


def test_run_preserves_all_languages_and_never_claims_isolation(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("pass\n", encoding="utf-8")
    (source / "index.js").write_text("const x = 1;\n", encoding="utf-8")
    operator = tmp_path / "operator"
    operator.mkdir()
    codeql = operator / "codeql"
    codeql.write_text("#!/bin/sh\n", encoding="utf-8")
    codeql.chmod(0o755)
    suites = {language: operator / f"{language}.qls" for language in ("python", "javascript-typescript")}
    for suite in suites.values():
        suite.write_text("- include: test\n", encoding="utf-8")
    commands = []
    decoded = []
    load_json = codeql_scanner.load_bounded_json

    def counted_decode(path):
        decoded.append(path.name)
        return load_json(path)

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1] == "version":
            kwargs["stdout_sink"].write(b"CodeQL command-line toolchain release 2.20.0\n")
        if command[1:3] == ["database", "analyze"]:
            language = next(item.split("=", 1)[1] for item in command if item.startswith("--sarif-category="))
            kwargs["output_path"].write_text(json.dumps({"version": "2.1.0", "runs": [
                sarif_run(language=language, results=[sarif_result("app.py" if language == "python" else "index.js")]),
            ]}), encoding="utf-8")
        assert "AEGIS_EVIDENCE_SIGNING_KEY" not in kwargs["env"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess", fake_run)
    monkeypatch.setattr(codeql_scanner, "run_bounded_subprocess_to_file", fake_run)
    monkeypatch.setattr(codeql_scanner, "load_bounded_json", counted_decode)
    output = tmp_path / "output"
    report = codeql_scanner.run_codeql_scan(source, output, codeql_path=codeql, query_suites=suites)

    assert report["coverage"] == {"complete": True, "languages": ["javascript-typescript", "python"], "source_scope": "repository", "isolation": "unverified"}
    assert len(report["findings"]) == 2
    assert sorted(decoded) == ["javascript-typescript.sarif", "python.sarif"]
    assert len(json.loads((output / "codeql.sarif").read_text())["runs"]) == 2
    assert json.loads((output / "codeql-report.json").read_text())["findings"] == report["findings"]
    assert all("--build-mode=none" in command for command in commands if command[1:3] == ["database", "create"])
    assert all(not any(part.startswith("--command") for part in command) for command in commands)


def test_parse_rejects_malformed_shapes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    report = tmp_path / "raw.sarif"
    report.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": [], "invocations": [{"executionSuccessful": True}]}]}), encoding="utf-8")
    with pytest.raises(codeql_scanner.CodeQLScanError):
        codeql_scanner.parse_codeql_sarif(report, source, language="python")


def test_parse_accepts_cli_sarif_without_optional_invocations(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    run = sarif_run(language="python", results=[sarif_result()])
    run.pop("invocations")
    report = tmp_path / "raw.sarif"
    report.write_text(json.dumps({"version": "2.1.0", "runs": [run]}), encoding="utf-8")
    assert len(codeql_scanner.parse_codeql_sarif(report, source, language="python")) == 1


@pytest.mark.parametrize("case", ["missing", "oversized", "unsupported"])
def test_public_parser_translates_file_errors_and_rejects_unsupported_languages(tmp_path, monkeypatch, case):
    report = tmp_path / "raw.sarif"
    if case != "missing":
        report.write_bytes(b"x" * 33)
    monkeypatch.setenv("AEGIS_MAX_PARSER_INPUT_BYTES", "32")
    with pytest.raises(codeql_scanner.CodeQLScanError):
        codeql_scanner.parse_codeql_sarif(
            report, tmp_path, language="java" if case == "unsupported" else "python"
        )


def test_imported_sarif_must_cover_every_language_and_gates_like_deep(tmp_path: Path) -> None:
    from policy_engine import analyze_codeql

    source = tmp_path / "repo"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text("print(1)\n")
    (source / "web.js").write_text("console.log(1)\n")
    python = tmp_path / "python.sarif"
    javascript = tmp_path / "javascript.sarif"
    # GitHub code scanning names runs "/language:<name>/" and calls JavaScript/TypeScript "javascript".
    python.write_text(json.dumps({"version": "2.1.0", "runs": [sarif_run(language="/language:python/", results=[sarif_result()])]}))
    javascript.write_text(json.dumps({"version": "2.1.0", "runs": [sarif_run(language="/language:javascript/")]}))

    with pytest.raises(codeql_scanner.CodeQLScanError, match="does not cover: javascript-typescript"):
        codeql_scanner.import_codeql_sarif([python], source, tmp_path / "partial")

    report = codeql_scanner.import_codeql_sarif([python, javascript], source, tmp_path / "out")

    assert report["coverage"]["isolation"] == "imported"
    assert report["coverage"]["languages"] == ["javascript-typescript", "python"]
    assert [item["filename"] for item in report["findings"]] == ["src/app.py"]
    assert json.loads((tmp_path / "out" / "codeql-report.json").read_text()) == report
    assert analyze_codeql(report)["status"] == "FAIL"


def test_imported_sarif_rejects_unknown_category(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n")
    sarif = tmp_path / "go.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": [sarif_run(language="/language:go")]}))

    with pytest.raises(codeql_scanner.CodeQLScanError, match="category '/language:go'"):
        codeql_scanner.import_codeql_sarif([sarif], source, tmp_path / "out")
