import os
import sys
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Ensure we can import app.cli
sys.path.append(str(Path(__file__).resolve().parent.parent))
sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))

from app.cli import install_hook, uninstall_hook, execute_scan, main, run_doctor, run_report
import app.cli as cli


def fake_scanner_command(command, *, stdout=None, timeout=120, label="Scanner"):
    if "ruff" in command:
        output_path = Path(command[command.index("-o") + 1])
        target_path = Path(command[command.index(str(output_path)) + 1])
        findings = []
        if target_path.read_text(errors="ignore").find("eval(") >= 0:
            findings.append({
                "code": "S307",
                "filename": str(target_path),
                "location": {"row": 1, "column": 1},
                "message": "Use of possibly insecure function; consider using ast.literal_eval",
            })
        output_path.write_text(json.dumps(findings))
    elif stdout is not None:
        stdout.write('{"results": {}}')
    return 0

def test_install_uninstall_hook(tmp_path, monkeypatch):
    # Setup mock git repository directory structure
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    
    # Change working directory to tmp_path so .git is detected locally
    monkeypatch.chdir(tmp_path)
    
    # Install the hook
    assert install_hook() == 0
    
    pre_push_hook = git_dir / "hooks" / "pre-push"
    assert pre_push_hook.exists()
    
    # Check that hook has execution permissions
    assert os.access(pre_push_hook, os.X_OK)
    
    # Uninstall the hook
    assert uninstall_hook() == 0
    assert not pre_push_hook.exists()


def test_start_generates_private_config_and_launches_complete_stack(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    env_file = tmp_path / ".env.aegis"
    monkeypatch.setattr(cli, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(cli, "LOCAL_ENV_FILE", env_file)
    monkeypatch.setattr(cli.shutil, "which", lambda command: "/usr/local/bin/docker")
    monkeypatch.setattr(cli, "_port_is_available", lambda port: True)
    monkeypatch.setattr(cli, "_wait_for_dashboard", lambda url: True)
    opened = []
    monkeypatch.setattr(cli.webbrowser, "open", opened.append)

    def fake_run(command, **kwargs):
        if command[:3] == ["docker", "compose", "version"]:
            return SimpleNamespace(returncode=0, stdout="Docker Compose version v2", stderr="")
        if "ps" in command:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        assert "up" in command
        assert "--build" in command
        assert "-d" in command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.run_start() == 0
    values = cli._read_environment_file(env_file)
    assert values["AEGIS_ENV"] == "development"
    assert len(values["AEGIS_SESSION_SECRET"]) >= 32
    assert len(values["AEGIS_SETUP_TOKEN"]) >= 32
    assert len(values["AEGIS_ENCRYPTION_KEY"]) >= 32
    assert env_file.stat().st_mode & 0o777 == 0o600
    assert opened == [f"http://localhost/setup#{values['AEGIS_SETUP_TOKEN']}"]

def test_execute_scan_safe_target(tmp_path, monkeypatch):
    # Setup a safe python target file
    target_file = tmp_path / "safe.py"
    target_file.write_text("def add(a, b):\n    return a + b\n")
    
    monkeypatch.chdir(tmp_path)
    
    # Run scan on safe.py
    # Since there are no vulnerability issues in safe.py, it should exit with 0 (ALLOWED)
    # We mock query_osv_vulnerabilities and other docker checks to be fast and deterministic
    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command):
        assert execute_scan(str(target_file), use_docker=False, tool_timeout=5) == 0

def test_execute_scan_unsafe_target(tmp_path, monkeypatch):
    # Setup an unsafe python target file with eval payload (which Semgrep/Bandit/YARA/ClamAV fallbacks will flag)
    target_file = tmp_path / "unsafe.py"
    target_file.write_text("eval(request.args.get('code'))\n")
    
    monkeypatch.chdir(tmp_path)
    
    # Run scan on unsafe.py
    # Since there are vulnerabilities in unsafe.py, it should exit with 1 (BLOCKED)
    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command):
        assert execute_scan(str(target_file), use_docker=False, tool_timeout=5) == 1

def test_execute_scan_custom_output_summary(tmp_path, monkeypatch):
    target_file = tmp_path / "safe.py"
    output_dir = tmp_path / "reports"
    target_file.write_text("def add(a, b):\n    return a + b\n")

    monkeypatch.chdir(tmp_path)

    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command):
        summary = execute_scan(
            str(target_file),
            use_docker=False,
            tool_timeout=5,
            output_dir=str(output_dir),
            quiet=True,
            return_summary=True,
        )

    assert summary["exit_code"] == 0
    assert summary["scan_dir"] == str(output_dir.resolve())
    assert (output_dir / "report.md").exists()
    assert (output_dir / "report.html").exists()
    manifest = json.loads((output_dir / "scan-manifest.json").read_text())
    assert manifest["status"] == "allowed"
    assert manifest["exit_code"] == 0
    assert any(tool["name"] == "Ruff" for tool in manifest["tools"])
    semgrep_result = next(result for result in summary["results"] if result["tool"] == "Semgrep")
    assert semgrep_result["status"] == "ERROR"
    assert any(timing["name"] == "Ruff" for timing in summary["timings"])
    assert any(timing["name"] == "Total" for timing in summary["timings"])


def test_execute_scan_uses_config_for_sarif_and_excludes(tmp_path, monkeypatch):
    target_file = tmp_path / "safe.py"
    output_dir = tmp_path / "configured-reports"
    target_file.write_text("def add(a, b):\n    return a + b\n")
    config_path = tmp_path / "aegis.yml"
    config_path.write_text(
        "scan:\n"
        "  output_dir: configured-reports\n"
        "  no_docker: true\n"
        "  sarif: results.sarif\n"
        "  exclude_paths:\n"
        "    - ignored_lab.py\n"
    )

    monkeypatch.chdir(tmp_path)
    commands = []

    def record_scanner_command(command, *, stdout=None, timeout=120, label="Scanner"):
        commands.append(command)
        return fake_scanner_command(command, stdout=stdout, timeout=timeout, label=label)

    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=record_scanner_command), \
         patch("app.cli.is_docker_available", return_value=True):
        summary = execute_scan(
            str(target_file),
            tool_timeout=None,
            config_path=str(config_path),
            quiet=True,
            return_summary=True,
        )

    assert summary["exit_code"] == 0
    assert summary["scan_dir"] == str(output_dir.resolve())
    assert summary["sarif_report"] == str((output_dir / "results.sarif").resolve())
    assert (output_dir / "results.sarif").exists()
    ruff_command = next(command for command in commands if "ruff" in command)
    assert "ignored_lab.py" in " ".join(ruff_command)
    secrets_command = next(command for command in commands if "detect_secrets" in command)
    assert "configured\\-reports" in secrets_command[secrets_command.index("--exclude-files") + 1]


def test_execute_scan_applies_config_suppressions(tmp_path, monkeypatch):
    target_file = tmp_path / "unsafe.py"
    output_dir = tmp_path / "reports"
    target_file.write_text("eval(input())\n")
    config_path = tmp_path / "aegis.yml"
    config_path.write_text(
        "scan:\n"
        "  fail_on: medium,high,critical\n"
        "  suppressions:\n"
        "    - tool: Ruff\n"
        "      rule: S307\n"
        "      path: unsafe.py\n"
        "      reason: Regression fixture for suppression behavior.\n"
    )

    monkeypatch.chdir(tmp_path)

    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command):
        summary = execute_scan(
            str(target_file),
            use_docker=False,
            tool_timeout=5,
            output_dir=str(output_dir),
            config_path=str(config_path),
            quiet=True,
            return_summary=True,
        )

    assert summary["exit_code"] == 0
    suppressions = json.loads((output_dir / "suppressions-report.json").read_text())
    assert suppressions == [{
        "tool": "Ruff",
        "rule": "S307",
        "path": str(target_file),
        "reason": "Regression fixture for suppression behavior.",
    }]

def test_execute_scan_fast_mode_skips_slow_scanners(tmp_path, monkeypatch):
    target_file = tmp_path / "safe.py"
    output_dir = tmp_path / "reports"
    target_file.write_text("def add(a, b):\n    return a + b\n")

    monkeypatch.chdir(tmp_path)
    labels = []

    def record_scanner_command(command, *, stdout=None, timeout=120, label="Scanner"):
        labels.append(label)
        return fake_scanner_command(command, stdout=stdout, timeout=timeout, label=label)

    with patch("app.cli.query_osv_vulnerabilities") as osv_query, \
         patch("app.cli.run_scanner_command", side_effect=record_scanner_command), \
         patch("app.cli.is_docker_available", return_value=True), \
         patch("app.cli.run_dast_scan") as dast_scan, \
         patch("app.cli.shared_run_clamav_scan") as clamav_scan:
        summary = execute_scan(
            str(target_file),
            use_docker=True,
            tool_timeout=5,
            output_dir=str(output_dir),
            fast=True,
            quiet=True,
            return_summary=True,
        )

    assert summary["exit_code"] == 0
    assert labels == ["Ruff", "Secrets"]
    osv_query.assert_not_called()
    dast_scan.assert_not_called()
    clamav_scan.assert_not_called()

def test_execute_scan_docker_uses_sandbox_helper_contract(tmp_path, monkeypatch):
    target_file = tmp_path / "safe.py"
    output_dir = tmp_path / "reports"
    target_file.write_text("def add(a, b):\n    return a + b\n")

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WAF_ENABLED", raising=False)

    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command), \
         patch("app.cli.is_docker_available", return_value=True), \
         patch("app.cli.find_free_host_port", return_value=5678), \
         patch("app.cli.scaffold_sandbox_context", return_value=5001) as scaffold, \
         patch("app.cli.build_sandbox_image", return_value=True) as build_image, \
         patch("app.cli.run_sandbox_container", return_value=True) as run_container, \
         patch("app.cli.wait_for_container", return_value=True) as wait_container, \
         patch("app.cli.run_trivy_scan", return_value=[]), \
         patch("app.cli.run_dast_scan", return_value=[]) as dast_scan, \
         patch("app.cli.stop_and_cleanup_sandbox") as cleanup:
        summary = execute_scan(
            str(target_file),
            use_docker=True,
            tool_timeout=5,
            output_dir=str(output_dir),
            quiet=True,
            return_summary=True,
        )

    assert summary["exit_code"] == 0
    scaffold.assert_called_once()
    build_image.assert_called_once()
    run_container.assert_called_once()
    cleanup.assert_called_once()

    image_tag, container_name, host_port, container_port, waf_enabled = run_container.call_args.args
    assert image_tag.startswith("aegis-sandbox-")
    assert container_name.startswith("aegis-sandbox-container-")
    assert host_port == 5678
    assert container_port == 5001
    assert waf_enabled is False

    target_url = f"http://127.0.0.1:{host_port}"
    wait_container.assert_called_once_with(target_url, timeout=6.0)
    dast_scan.assert_called_once_with(target_url)

def test_main_json_scan_outputs_machine_readable_summary(tmp_path, monkeypatch, capsys):
    target_file = tmp_path / "safe.py"
    target_file.write_text("def add(a, b):\n    return a + b\n")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["aegis", "scan", str(target_file), "--no-docker", "--json"])

    with patch("app.cli.query_osv_vulnerabilities", return_value=[]), \
         patch("app.cli.run_scanner_command", side_effect=fake_scanner_command):
        assert main() == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "allowed"
    assert payload["target"] == str(target_file.resolve())
    assert any(timing["name"] == "Total" for timing in payload["timings"])


def test_strict_scan_returns_operational_error_for_invalid_scanner_output(tmp_path, monkeypatch):
    target_file = tmp_path / "safe.py"
    output_dir = tmp_path / "reports"
    target_file.write_text("def add(a, b):\n    return a + b\n")

    def failing_ruff(command, *, stdout=None, timeout=120, label="Scanner"):
        if label == "Secrets" and stdout is not None:
            stdout.write('{"results": {}}')
            return 0
        return 127 if label == "Ruff" else 0

    monkeypatch.chdir(tmp_path)
    with patch("app.cli.run_scanner_command", side_effect=failing_ruff):
        summary = execute_scan(
            str(target_file),
            use_docker=False,
            tool_timeout=5,
            output_dir=str(output_dir),
            fast=True,
            strict=True,
            quiet=True,
            return_summary=True,
        )

    assert summary["exit_code"] == 2
    assert summary["status"] == "error"
    assert summary["policy_status"] == "ERROR"
    assert summary["operational_failures"] == ["Ruff"]
    skipped_tools = {
        result["tool"]
        for result in summary["results"]
        if result["status"] == "SKIPPED"
    }
    assert {"Semgrep", "Safety", "OSV Dependency Audit", "Trivy", "ClamAV", "OWASP ZAP DAST"} <= skipped_tools
    manifest = json.loads((output_dir / "scan-manifest.json").read_text())
    assert manifest["status"] == "error"
    assert next(tool for tool in manifest["tools"] if tool["name"] == "Ruff")["status"] == "failed"


def test_main_json_reports_configuration_errors_without_traceback(tmp_path, monkeypatch, capsys):
    target_file = tmp_path / "safe.py"
    target_file.write_text("print('safe')\n")
    missing_config = tmp_path / "missing.yml"
    monkeypatch.setattr(
        sys,
        "argv",
        ["aegis", "scan", str(target_file), "--config", str(missing_config), "--json"],
    )

    assert main() == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "error"
    assert payload["exit_code"] == 2
    assert "Config file does not exist" in payload["error"]

def test_report_command_prints_and_opens_report(tmp_path, capsys):
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report_path = report_dir / "report.html"
    report_path.write_text("<html>Aegis</html>")

    assert run_report(report_dir=str(report_dir), path_only=True) == 0
    assert capsys.readouterr().out.strip() == str(report_path.resolve())

    with patch("app.cli.open_report_file", return_value=0) as open_report:
        assert run_report(report_dir=str(report_dir), open_report=True) == 0
    open_report.assert_called_once_with(report_path.resolve())

def test_report_command_markdown_and_missing_report(tmp_path, capsys):
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    md_path = report_dir / "report.md"
    md_path.write_text("# Aegis")

    assert run_report(report_dir=str(report_dir), markdown=True, path_only=True) == 0
    assert capsys.readouterr().out.strip() == str(md_path.resolve())

    assert run_report(report_dir=str(tmp_path / "missing")) == 1
    assert "No Aegis report found" in capsys.readouterr().out

def test_doctor_and_version_commands(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["aegis", "version"])
    assert main() == 0
    assert capsys.readouterr().out.strip()

    with patch("app.cli.is_docker_available", return_value=False):
        assert run_doctor(json_output=True) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] in {"ok", "degraded"}
    assert any(check["name"] == "python" for check in payload["checks"])

def test_print_ascii_report(capsys):
    from app.cli import print_ascii_report
    results = [
        {"tool": "Ruff (SAST)", "status": "PASS", "total_issues": 0, "blocking_issues": 0},
        {"tool": "Secrets Scanner", "status": "FAIL", "total_issues": 3, "blocking_issues": 3}
    ]
    print_ascii_report(results, "BLOCKED", "Blocking issues found by: Secrets Scanner", 60.0)
    captured = capsys.readouterr()
    
    # Assert ASCII borders and headers exist
    assert "╔════════════" in captured.out
    assert "A E G I S   S E C U R I T Y" in captured.out
    assert "Ruff (SAST)" in captured.out
    assert "Secrets Scanner" in captured.out
    assert "VERDICT:" in captured.out and "DEPLOYMENT BLOCKED" in captured.out
    assert "REASON:" in captured.out and "Blocking issues found by: Secrets Scanner" in captured.out

    print_ascii_report([], "ERROR", "Semgrep failed", 0.0)
    assert "SCAN INCOMPLETE" in capsys.readouterr().out
