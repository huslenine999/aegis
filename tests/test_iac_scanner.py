import json
import subprocess
from pathlib import Path

import pytest

from app import iac_scanner


FIXTURES = Path(__file__).parent / "fixtures" / "iac"


def test_discovery_covers_all_supported_formats_and_multi_document_yaml():
    discovered = iac_scanner.discover_iac_files(FIXTURES / "insecure")

    assert {(item.path, item.framework) for item in discovered} == {
        ("Dockerfile", "dockerfile"),
        ("kubernetes.yaml", "kubernetes"),
        ("main.tf", "terraform"),
        ("template.json", "cloudformation"),
        ("template.yaml", "cloudformation"),
    }


def test_discovery_respects_ignored_directories_and_paths(tmp_path):
    target = tmp_path / "repo"
    (target / "ignored").mkdir(parents=True)
    (target / "ignored" / "main.tf").write_text("resource {}\n")
    (target / "skip.tf").write_text("resource {}\n")
    (target / "keep.tf").write_text("resource {}\n")

    discovered = iac_scanner.discover_iac_files(
        target,
        ignored_dirs={"ignored"},
        ignored_paths={str(target / "skip.tf")},
    )

    assert [item.path for item in discovered] == ["keep.tf"]


def test_discovery_handles_single_files_invalid_documents_and_missing_paths(tmp_path):
    terraform = tmp_path / "main.tf"
    terraform.write_text("terraform {}\n")
    invalid = tmp_path / "broken.yaml"
    invalid.write_text("resources: [\n")
    minimal_cloudformation = tmp_path / "minimal.yaml"
    minimal_cloudformation.write_text("Resources: {}\n")
    symlink = tmp_path / "linked.tf"
    try:
        symlink.symlink_to(terraform)
    except OSError:
        symlink = None

    assert iac_scanner.discover_iac_files(tmp_path / "does-not-exist") == ()
    assert iac_scanner.discover_iac_files(terraform) == (
        iac_scanner.DiscoveredIaCFile("main.tf", "terraform"),
    )
    assert iac_scanner.discover_iac_files(invalid) == ()
    assert iac_scanner.discover_iac_files(minimal_cloudformation) == (
        iac_scanner.DiscoveredIaCFile("minimal.yaml", "cloudformation"),
    )
    if symlink is not None:
        assert iac_scanner.discover_iac_files(symlink) == ()


def test_checkov_command_rejects_unsupported_or_empty_frameworks(tmp_path):
    with pytest.raises(ValueError, match="Unsupported"):
        iac_scanner.build_checkov_command(
            "/venv/bin/checkov",
            tmp_path,
            ("terraform", "ansible"),
            config_path=tmp_path / "checkov.yml",
        )
    with pytest.raises(ValueError, match="At least one"):
        iac_scanner.build_checkov_command(
            "/venv/bin/checkov",
            tmp_path,
            (),
            config_path=tmp_path / "checkov.yml",
        )


def test_checkov_command_is_fixed_framework_scoped_and_not_a_shell_string(tmp_path):
    command = iac_scanner.build_checkov_command(
        "/venv/bin/checkov",
        tmp_path,
        ("terraform", "dockerfile"),
        config_path=tmp_path / "checkov.yml",
        skipped_paths=("ignored",),
    )

    assert isinstance(command, tuple)
    assert command[:3] == ("/venv/bin/checkov", "--directory", str(tmp_path))
    framework_index = command.index("--framework")
    assert command[framework_index + 1:framework_index + 3] == ("terraform", "dockerfile")
    assert "--download-external-modules" in command
    assert command[command.index("--download-external-modules") + 1] == "false"
    assert "--skip-download" in command
    assert "--config-file" in command
    assert "--skip-path" in command


def test_parse_checkov_output_rejects_malformed_and_oversized_output():
    with pytest.raises(iac_scanner.IaCReportError):
        iac_scanner.parse_checkov_output("not-json")
    with pytest.raises(iac_scanner.IaCReportError):
        iac_scanner.parse_checkov_output("{}", max_bytes=1)
    with pytest.raises(iac_scanner.IaCReportError, match="empty"):
        iac_scanner.parse_checkov_output(b"  ")
    assert iac_scanner.parse_checkov_output(b'{"ok": true}') == {"ok": True}


def test_normalization_accepts_framework_maps_and_flat_check_results(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "main.tf").write_text("terraform {}\n")
    discovered = iac_scanner.discover_iac_files(target)
    payload = {
        "terraform": {
            "results": {
                "passed_checks": [{"check_id": "CKV_TF_1"}],
                "skipped_checks": [{
                    "check_id": "CKV_TF_2",
                    "check_name": "Skipped check",
                    "file_path": "main.tf",
                    "line_range": {"start_line": "bad", "end_line": 4},
                }],
            }
        },
        "k8s": {
            "results": [{"check_result": {"result": True}}],
        },
    }

    report = iac_scanner.normalize_checkov_report(payload, target, discovered)

    assert report["summary"] == {"candidate": 3, "passed": 2, "failed": 0, "skipped": 1}
    assert report["frameworks"] == ["terraform", "kubernetes"]
    assert report["unmanaged_suppressions"][0]["start_line"] == 1


def test_empty_scan_report_and_report_size_limit(tmp_path, monkeypatch):
    logs = []
    empty = iac_scanner.run_iac_scan(
        tmp_path / "empty",
        report_path=tmp_path / "empty-report.json",
        log=lambda message, level: logs.append((message, level)),
    )
    assert empty.status == "completed"
    assert logs and logs[0][1] == "muted"

    monkeypatch.setattr(iac_scanner, "MAX_CHECKOV_REPORT_BYTES", 1)
    oversized = iac_scanner.run_iac_scan(tmp_path / "empty", report_path=tmp_path / "oversized.json")
    assert oversized.status == "failed"
    assert json.loads((tmp_path / "oversized.json").read_text())["status"] == "failed"


def test_normalization_maps_severity_defaults_and_deduplicates_without_absolute_paths(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "main.tf").write_text("resource \"aws_s3_bucket\" \"logs\" {}\n")
    discovered = iac_scanner.discover_iac_files(target)
    payload = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Enable access logging",
                    "resource": "aws_s3_bucket.logs",
                    "file_path": str(target / "main.tf"),
                    "file_line_range": [4, 8],
                    "severity": "HIGH",
                    "guideline": "https://example.test/fix",
                },
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Enable access logging",
                    "resource": "aws_s3_bucket.logs",
                    "file_path": str(target / "main.tf"),
                    "file_line_range": [99, 100],
                    "severity": "HIGH",
                },
                {
                    "check_id": "CKV_AWS_20",
                    "resource": "aws_s3_bucket.logs",
                    "file_path": str(target / "main.tf"),
                    "severity": "not-a-severity",
                },
            ],
            "passed_checks": [],
            "skipped_checks": [],
        },
    }

    report = iac_scanner.normalize_checkov_report(payload, target, discovered)

    assert report["summary"] == {"candidate": 3, "passed": 0, "failed": 3, "skipped": 0}
    assert len(report["findings"]) == 2
    assert report["findings"][0]["path"] == "main.tf"
    assert all(str(target) not in json.dumps(item) for item in report["findings"])
    assert report["findings"][1]["severity"] == "MEDIUM"
    assert report["findings"][0]["remediation_url"] == "https://example.test/fix"


def test_normalization_preserves_inline_suppressions_as_unmanaged_evidence(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    terraform = target / "main.tf"
    terraform.write_text(
        "#checkov:skip=CKV_AWS_18: approved outside Aegis\n"
        "resource \"aws_s3_bucket\" \"logs\" {}\n"
    )
    discovered = iac_scanner.discover_iac_files(target)

    report = iac_scanner.normalize_checkov_report(
        {"check_type": "terraform", "results": {"passed_checks": [], "failed_checks": [], "skipped_checks": []}},
        target,
        discovered,
    )

    assert report["unmanaged_suppressions"] == [{
        "rule_id": "CKV_AWS_18",
        "path": "main.tf",
        "start_line": 1,
        "end_line": 1,
        "comment": "approved outside Aegis",
        "source": "repository-inline-checkov",
        "title": "Inline Checkov suppression for CKV_AWS_18",
        "framework": "terraform",
        "resource": "",
    }]


def test_run_iac_scan_accepts_checkov_findings_on_exit_one_and_writes_owned_report(tmp_path, monkeypatch):
    target = FIXTURES / "insecure"
    output = tmp_path / "iac-report.json"

    monkeypatch.setattr(iac_scanner, "find_runtime_executable", lambda *args: "/bin/checkov")
    monkeypatch.setattr(
        iac_scanner,
        "_run_checkov_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            1,
            stdout=json.dumps({
                "check_type": "dockerfile",
                "results": {
                    "passed_checks": [],
                    "failed_checks": [{
                        "check_id": "CKV_DOCKER_1",
                        "check_name": "Do not expose port 22",
                        "resource": "Dockerfile.EXPOSE",
                        "file_path": "/Dockerfile",
                        "file_line_range": [3, 3],
                        "severity": "HIGH",
                    }],
                    "skipped_checks": [],
                },
            }),
            stderr="",
        ),
    )

    execution = iac_scanner.run_iac_scan(target, report_path=output, timeout=5)

    assert execution.status == "completed"
    assert execution.return_code == 1
    assert json.loads(output.read_text())["findings"][0]["rule_id"] == "CKV_DOCKER_1"


def test_run_iac_scan_ignores_repository_checkov_config(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "main.tf").write_text("terraform {}\n")
    (target / ".checkov.yml").write_text("skip-check: [CKV_TF_1]\n")
    observed = {}

    monkeypatch.setattr(iac_scanner, "find_runtime_executable", lambda *args: "/bin/checkov")

    def fake_run(command, **kwargs):
        observed.update(command=command, **kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"results": {}}), stderr="")

    monkeypatch.setattr(iac_scanner, "_run_checkov_command", fake_run)
    execution = iac_scanner.run_iac_scan(target, timeout=5)

    assert execution.status == "completed"
    assert "--directory" not in observed["command"]
    assert "--file" in observed["command"]
    assert str(target / "main.tf") in observed["command"]
    assert observed["cwd"] != str(target)
    assert str(target) not in observed["env"]["HOME"]


def test_run_iac_scan_missing_timeout_and_crash_are_failures(tmp_path, monkeypatch):
    target = FIXTURES / "clean"
    monkeypatch.setattr(iac_scanner, "find_runtime_executable", lambda *args: None)
    missing = iac_scanner.run_iac_scan(target, report_path=tmp_path / "missing.json")
    assert missing.status == "failed"
    assert missing.report["status"] == "failed"

    monkeypatch.setattr(iac_scanner, "find_runtime_executable", lambda *args: "/bin/checkov")
    monkeypatch.setattr(
        iac_scanner,
        "_run_checkov_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired(args[0], 1)),
    )
    timed_out = iac_scanner.run_iac_scan(target, timeout=1)
    assert timed_out.status == "failed"
    assert "timed out" in str(timed_out.detail).lower()

    monkeypatch.setattr(
        iac_scanner,
        "_run_checkov_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 2, stdout="{}", stderr="crashed"),
    )
    crashed = iac_scanner.run_iac_scan(target)
    assert crashed.status == "failed"
    assert crashed.return_code == 2


def test_run_iac_scan_rejects_malformed_json_and_invalid_timeout(tmp_path, monkeypatch):
    target = FIXTURES / "clean"
    monkeypatch.setattr(iac_scanner, "find_runtime_executable", lambda *args: "/bin/checkov")
    monkeypatch.setattr(
        iac_scanner,
        "_run_checkov_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout="not-json", stderr=""),
    )
    malformed = iac_scanner.run_iac_scan(target)
    assert malformed.status == "failed"
    assert "malformed" in str(malformed.detail).lower()

    monkeypatch.setattr(
        iac_scanner,
        "_run_checkov_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout="{}", stderr=""),
    )
    malformed_envelope = iac_scanner.run_iac_scan(target)
    assert malformed_envelope.status == "failed"
    assert "malformed" in str(malformed_envelope.detail).lower()

    invalid_timeout = iac_scanner.run_iac_scan(target, timeout=0)
    assert invalid_timeout.status == "failed"
    assert invalid_timeout.detail == "invalid timeout"
