import json
import sys
from pathlib import Path

import pytest

from app.cli import main


def test_bac_run_cli_routes_validated_input_and_returns_violation(tmp_path, monkeypatch, capsys):
    import app.bac as bac

    matrix = {"schema_version": 1, "corpus_id": "cli-test", "description": "CLI matrix", "cases": [{
        "id": "read-case", "split": "development", "operation": "read", "actor": "alice", "resource": "bob-private-1", "expected_allowed": False,
    }]}
    matrix_path = tmp_path / "matrix.json"
    matrix_path.write_text(json.dumps(matrix))
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"status": "blocked", "exit_code": 1, "findings": [{}], "manifest_path": "manifest", "results": []}

    monkeypatch.setattr(bac, "run_research", fake_run)
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "run", "--mode", "vulnerable", "--matrix", str(matrix_path), "--output", str(tmp_path / "run"), "--json"])
    assert main() == 1
    assert captured["mode"] == "vulnerable"
    assert captured["matrix"] == matrix
    assert json.loads(capsys.readouterr().out)["exit_code"] == 1


def test_bac_invalid_matrix_returns_operational_error_without_run(tmp_path, monkeypatch, capsys):
    import app.bac as bac

    matrix_path = tmp_path / "invalid.json"
    matrix_path.write_text("{}")
    monkeypatch.setattr(bac, "run_research", lambda **kwargs: pytest.fail("invalid matrix was executed"))
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "run", "--mode", "fixed", "--matrix", str(matrix_path), "--json"])
    assert main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_bac_cli_requires_explicit_mode(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "run"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2


def test_benchmark_cli_keeps_expected_findings_separate_from_failure(tmp_path, monkeypatch, capsys):
    import app.bac_benchmark as benchmark

    calls = []

    def fake_benchmark(**kwargs):
        calls.append(kwargs)
        return {"status": "allowed", "exit_code": 0, "manifest_path": "manifest", "results": []}

    monkeypatch.setattr(benchmark, "run_benchmark", fake_benchmark)
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "benchmark", "--split", "evaluation", "--repeats", "2", "--output", str(tmp_path / "bench")])
    assert main() == 0
    assert calls[0]["repeats"] == 2
    assert calls[0]["split"] == "evaluation"
    assert "protocol" not in calls[0]
    assert "manifest" in capsys.readouterr().out


def test_bac_cli_handles_server_startup_error(monkeypatch, capsys):
    import app.bac as bac

    def failed_run(**kwargs):
        raise RuntimeError("Owned loopback lab startup failed.")

    monkeypatch.setattr(bac, "run_research", failed_run)
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "run", "--mode", "fixed", "--json"])
    assert main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def protocol_matrix():
    return {"schema_version": 1, "corpus_id": "cli-protocol-test", "description": "Owned CLI protocol corpus.", "cases": [
        {"id": f"cross-{operation}", "split": "evaluation", "operation": operation,
         "actor": "alice", "resource": "bob-private-2", "expected_allowed": False}
        for operation in ("read", "preview")
    ]}


def test_freeze_cli_routes_validated_definition_without_lab_and_uses_unique_defaults(tmp_path, monkeypatch, capsys):
    import app.bac as bac
    import app.bac_benchmark as benchmark
    import app.bac_reports as reports

    calls = []

    def fake_freeze(**kwargs):
        calls.append(kwargs)
        return {"status": "allowed", "exit_code": 0, "manifest_path": "study-protocol.json", "protocol": {"kind": "bac-study-protocol"}}

    monkeypatch.setattr(reports, "freeze_protocol", fake_freeze, raising=False)
    monkeypatch.setattr(bac, "run_research", lambda **kwargs: pytest.fail("freeze started research"))
    monkeypatch.setattr(benchmark, "run_benchmark", lambda **kwargs: pytest.fail("freeze started benchmark"))
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(protocol_matrix()))
    output = tmp_path / "protocol"
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "freeze", "--matrix", str(path), "--split", "all", "--repeats", "2", "--output", str(output), "--json"])
    assert main() == 0
    assert calls[0] == {"matrix": protocol_matrix(), "split": "all", "repeats": 2, "output_dir": str(output)}
    assert json.loads(capsys.readouterr().out)["protocol"]["kind"] == "bac-study-protocol"
    for _ in range(2):
        monkeypatch.setattr(sys, "argv", ["aegis", "bac", "freeze", "--json"])
        assert main() == 0
        assert json.loads(capsys.readouterr().out)["exit_code"] == 0
    assert all(call["split"] == "evaluation" and call["repeats"] == 3 for call in calls[1:])
    assert calls[1]["matrix"] == bac.load_matrix()
    assert calls[1]["output_dir"] != calls[2]["output_dir"]
    assert "mode" not in calls[0]


def test_freeze_cli_has_no_mode_option(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "freeze", "--mode", "fixed"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2


def test_benchmark_cli_passes_protocol_only_when_requested(tmp_path, monkeypatch, capsys):
    import app.bac_benchmark as benchmark

    calls = []

    def fake_benchmark(**kwargs):
        calls.append(kwargs)
        return {"status": "allowed", "exit_code": 0, "manifest_path": "manifest", "results": []}

    monkeypatch.setattr(benchmark, "run_benchmark", fake_benchmark)
    protocol = tmp_path / "study-protocol.json"
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "benchmark", "--protocol", str(protocol), "--json"])
    assert main() == 0
    assert calls[0]["protocol"] == str(protocol)
    assert json.loads(capsys.readouterr().out)["exit_code"] == 0


def test_bad_protocol_cli_returns_operational_error_before_lab_or_output(tmp_path, monkeypatch, capsys):
    import app.bac as bac

    monkeypatch.setattr(bac, "run_research", lambda **kwargs: pytest.fail("bad protocol reached research"))
    path = tmp_path / "invalid-protocol.json"
    path.write_text("{}")
    output = tmp_path / "not-created"
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "benchmark", "--protocol", str(path), "--output", str(output), "--json"])
    assert main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "error" and result["exit_code"] == 2
    assert not output.exists()


def test_live_cli_freeze_benchmark_protocol_and_verify_owned_loopback(tmp_path, monkeypatch, capsys):
    from app.evidence import evidence_public_key, verify_manifest

    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(protocol_matrix()))
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "freeze", "--matrix", str(path), "--repeats", "1", "--output", str(tmp_path / "protocol"), "--json"])
    assert main() == 0
    frozen = json.loads(capsys.readouterr().out)
    assert verify_manifest(frozen["protocol"], evidence_public_key()["public_key"])
    monkeypatch.setattr(sys, "argv", ["aegis", "bac", "benchmark", "--matrix", str(path), "--repeats", "1", "--protocol", frozen["manifest_path"], "--output", str(tmp_path / "benchmark"), "--json"])
    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["study_protocol"]["definition"] == frozen["protocol"]
    assert report["metrics"]["enhanced"]["overall"]["accuracy"] == 1.0
    assert report["metrics"]["http-status-only"]["by_operation"]["preview"]["fp"] == 1
    assert len(list(Path(report["output_dir"]).iterdir())) == 10
    monkeypatch.setattr(sys, "argv", ["aegis", "verify-evidence", report["manifest_path"], "--public-key", evidence_public_key()["public_key"]])
    assert main() == 0
    assert "Evidence verified" in capsys.readouterr().out
