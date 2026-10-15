"""Signed BAC study definitions and preflight, without starting a lab."""

import base64
import copy
import hashlib
import json
import platform
from contextlib import contextmanager
from datetime import datetime, timedelta
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from app.bac_benchmark import run_benchmark
from app.cli_reports import run_verify_evidence
from app.evidence import canonical_json, evidence_public_key, sign_manifest, verify_manifest
from app.version import get_package_version


MODULES = {"bac.py", "bac_config.py", "bac_lab.py", "bac_reports.py", "bac_benchmark.py"}
INDIVIDUAL_FILES = {
    "report.json", "matrix.json", "findings.json", "evidence.json", "server-events.json",
    "report.md", "report.html", "scan-manifest.json",
}
BENCHMARK_FILES = INDIVIDUAL_FILES | {"metrics.csv", "case-results.csv"}


def matrix():
    return {
        "schema_version": 1, "corpus_id": "protocol-test-v1", "description": "Owned synthetic protocol corpus.",
        "cases": [
            {"id": "cross-read", "split": "evaluation", "operation": "read", "actor": "alice",
             "resource": "bob-private-2", "expected_allowed": False},
            {"id": "own-read", "split": "development", "operation": "read", "actor": "alice",
             "resource": "alice-private-1", "expected_allowed": True},
        ],
    }


def freeze(directory, approved=None, *, split="evaluation", repeats=1):
    from app.bac_reports import freeze_protocol

    return freeze_protocol(matrix=approved or matrix(), split=split, repeats=repeats, output_dir=directory)


def expected_versions():
    return {
        "aegis": get_package_version(), "python": platform.python_version(), "requests": requests.__version__,
        "fastapi": version("fastapi"), "uvicorn": version("uvicorn"),
        "implementation_sha256": {name: hashlib.sha256(files("app").joinpath(name).read_bytes()).hexdigest() for name in MODULES},
    }


def forbid_execution(monkeypatch):
    import app.bac as bac

    def forbidden(*args, **kwargs):
        pytest.fail("Protocol preflight reached lab execution.")

    monkeypatch.setattr(bac, "run_research", forbidden)
    monkeypatch.setattr(bac, "local_bac_lab", forbidden)


def stub_research(monkeypatch):
    import app.bac as bac

    calls = []

    def research(**kwargs):
        calls.append(copy.deepcopy(kwargs))
        results = []
        for case in kwargs["matrix"]["cases"]:
            if kwargs["split"] != "all" and case["split"] != kwargs["split"]:
                continue
            violation = kwargs["mode"] == "vulnerable" and not case["expected_allowed"]
            results.append({**case, "status": "violation" if violation else "no_violation",
                            "http_status": 200 if violation or case["expected_allowed"] else 403,
                            "duration_seconds": 0.125, "reason": "Synthetic observed outcome.", "evidence": {}})
        return {"kind": "bac-research", "run_id": f"trial-{len(calls)}", "results": results,
                "status": "blocked" if any(row["status"] == "violation" for row in results) else "allowed"}

    monkeypatch.setattr(bac, "run_research", research)
    return calls


def test_definition_and_freeze_bind_exact_versions_matrix_and_signature_without_execution(tmp_path, monkeypatch):
    from app.bac_config import research_versions, study_definition, validate_study_protocol

    forbid_execution(monkeypatch)
    approved = matrix()
    before = copy.deepcopy(approved)
    definition = study_definition(matrix=approved, split="evaluation", repeats=1)
    assert definition == {
        "schema_version": 1, "kind": "bac-study-protocol", "matrix": approved,
        "matrix_sha256": hashlib.sha256(canonical_json(approved)).hexdigest(),
        "split": "evaluation", "repeats": 1, "versions": expected_versions(),
    }
    assert definition["matrix"] is not approved
    assert research_versions() == expected_versions()
    first = freeze(tmp_path / "first", approved)
    second = freeze(tmp_path / "second", approved)
    assert approved == before
    assert first["status"] == "allowed" and first["exit_code"] == 0
    path = Path(first["manifest_path"])
    assert path == Path(first["output_dir"]) / "study-protocol.json"
    assert {entry.name for entry in path.parent.iterdir()} == {"study-protocol.json"}
    document = json.loads(path.read_text())
    assert document == first["protocol"]
    assert set(document) == {*definition, "protocol_id", "created_at", "signed_at", "signature"}
    assert {key: document[key] for key in definition} == definition
    assert document["protocol_id"] and document["protocol_id"] != second["protocol"]["protocol_id"]
    assert datetime.fromisoformat(document["created_at"]).utcoffset() == timedelta(0)
    assert verify_manifest(document, evidence_public_key()["public_key"])
    checked = validate_study_protocol(path, matrix=approved, split="evaluation", repeats=1)
    assert checked == document
    assert checked is not document
    assert approved == before


def test_individual_versions_and_eight_file_shape_stay_exact_without_live_lab(tmp_path, monkeypatch):
    import app.bac as bac
    from app.bac_config import research_versions

    @contextmanager
    def lab(mode):
        yield SimpleNamespace(instance_id="synthetic-lab")

    client = SimpleNamespace(control=lambda *args: {"lab": "aegis-bac-v2", "instance_id": "synthetic-lab", "seed_sha256": "a" * 64}, close=lambda: None)
    monkeypatch.setattr(bac, "local_bac_lab", lab)
    monkeypatch.setattr(bac, "_LabClient", lambda owned: client)
    monkeypatch.setattr(bac, "_run_case", lambda owned, case: {
        **case, "status": "no_violation", "http_status": 403, "duration_seconds": 0.1,
        "reason": "Synthetic denied request.", "evidence": {},
    })
    report = bac.run_research(mode="fixed", matrix=matrix(), split="evaluation", output_dir=tmp_path / "individual")
    assert report["versions"] == research_versions() == expected_versions()
    assert set(report["versions"]) == {"aegis", "python", "requests", "fastapi", "uvicorn", "implementation_sha256"}
    assert set(report["versions"]["implementation_sha256"]) == MODULES
    assert {path.name for path in Path(report["output_dir"]).iterdir()} == INDIVIDUAL_FILES
    assert "study_protocol" not in report


@pytest.mark.parametrize("options", [
    {"split": "invalid"}, {"split": "development", "matrix": {**matrix(), "cases": matrix()["cases"][:1]}},
    {"repeats": 0}, {"repeats": True}, {"repeats": 21}, {"repeats": 1.5}, {"matrix": {}},
])
def test_invalid_freeze_definition_fails_before_output_or_execution(tmp_path, monkeypatch, options):
    from app.bac_reports import freeze_protocol

    forbid_execution(monkeypatch)
    output = tmp_path / "not-created"
    with pytest.raises(ValueError):
        freeze_protocol(**{"matrix": matrix(), "output_dir": output, **options})
    assert not output.exists()


def test_freeze_preserves_existing_evidence_and_rejects_output_symlink(tmp_path):
    from app.bac_reports import freeze_protocol

    existing = tmp_path / "existing"
    existing.mkdir()
    evidence = existing / "study-protocol.json"
    evidence.write_text("user-owned signed evidence")
    link = tmp_path / "linked"
    link.symlink_to(existing, target_is_directory=True)
    for output in (existing, link):
        with pytest.raises(ValueError):
            freeze_protocol(matrix=matrix(), output_dir=output)
    assert evidence.read_text() == "user-owned signed evidence"
    assert link.is_symlink()
    empty = tmp_path / "empty"
    empty.mkdir()
    assert Path(freeze(empty)["manifest_path"]).is_file()


@pytest.mark.parametrize("drift", ["matrix", "split", "repeats", "software", "runtime", "module", "other-key", "tampered"])
def test_signed_drift_rejects_before_any_experiment_output_or_lab_call(tmp_path, monkeypatch, drift):
    from app.bac_config import validate_study_protocol

    frozen = freeze(tmp_path / "protocol")
    document = copy.deepcopy(frozen["protocol"])
    if drift == "matrix":
        document["matrix"]["cases"][1]["resource"] = "alice-private-2"
        document["matrix_sha256"] = hashlib.sha256(canonical_json(document["matrix"])).hexdigest()
    elif drift == "split":
        document["split"] = "development"
    elif drift == "repeats":
        document["repeats"] = 2
    elif drift == "software":
        document["versions"]["aegis"] = "changed-software"
    elif drift == "runtime":
        document["versions"]["python"] = "changed-runtime"
    elif drift == "module":
        document["versions"]["implementation_sha256"]["bac.py"] = "0" * 64
    if drift == "other-key":
        with monkeypatch.context() as signer:
            signer.setenv("AEGIS_EVIDENCE_SIGNING_KEY", base64.urlsafe_b64encode(b"other-study-signing-key".ljust(32, b"!")).decode())
            document = sign_manifest(document)
        assert verify_manifest(document, allow_embedded_key=True)
        assert not verify_manifest(document, evidence_public_key()["public_key"])
    elif drift != "tampered":
        document = sign_manifest(document)
        assert verify_manifest(document, evidence_public_key()["public_key"])
    else:
        document["repeats"] = 2
    path = Path(frozen["manifest_path"])
    path.write_bytes(canonical_json(document))
    original = path.read_bytes()
    forbid_execution(monkeypatch)
    approved = matrix()
    before = copy.deepcopy(approved)
    output = tmp_path / "not-created"
    with pytest.raises(ValueError):
        validate_study_protocol(path, matrix=approved, split="evaluation", repeats=1)
    with pytest.raises(ValueError):
        run_benchmark(matrix=approved, split="evaluation", repeats=1, output_dir=output, protocol=path)
    assert not output.exists()
    assert approved == before
    assert path.read_bytes() == original


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"kind": "bac-research"}, {"repeats": True}, {"repeats": "1"},
    {"unknown": "field"}, {"protocol_id": None}, {"created_at": False}, {"versions": {}},
    {"matrix_sha256": "0" * 64}, {"matrix": []}, {"protocol_id": "bad\nidentifier"},
    {"created_at": "2026-10-08T00:00:00"}, {"created_at": "9999-01-01T00:00:00+00:00"},
    {"created_at": "2026-01-01T09:00:00+09:00"}, {"signed_at": "9999-01-01T09:00:00+09:00"},
])
def test_resigned_malformed_protocol_fields_are_rejected(tmp_path, change):
    from app.bac_config import validate_study_protocol

    frozen = freeze(tmp_path / "protocol")
    path = Path(frozen["manifest_path"])
    path.write_bytes(canonical_json(sign_manifest({**frozen["protocol"], **change})))
    with pytest.raises(ValueError):
        validate_study_protocol(path, matrix=matrix(), split="evaluation", repeats=1)


def test_protocol_timestamp_errors_do_not_echo_untrusted_field_content(tmp_path):
    from app.bac_config import validate_study_protocol

    frozen = freeze(tmp_path / "protocol")
    value = "synthetic-private-value-not-a-timestamp"
    path = Path(frozen["manifest_path"])
    path.write_bytes(canonical_json(sign_manifest({**frozen["protocol"], "created_at": value})))
    with pytest.raises(ValueError) as error:
        validate_study_protocol(path, matrix=matrix(), split="evaluation", repeats=1)
    assert value not in str(error.value)


@pytest.mark.parametrize("change", ["non-object", "extra-field", "embedded-key"])
def test_protocol_signature_metadata_cannot_select_its_own_trust(tmp_path, change):
    from app.bac_config import validate_study_protocol

    frozen = freeze(tmp_path / "protocol")
    document = copy.deepcopy(frozen["protocol"])
    if change == "non-object":
        document["signature"] = None
    elif change == "extra-field":
        document["signature"]["untrusted_label"] = "approved"
    else:
        document["signature"]["public_key"] = "A" * 43
        assert verify_manifest(document, evidence_public_key()["public_key"])
    path = Path(frozen["manifest_path"])
    path.write_bytes(canonical_json(document))
    with pytest.raises(ValueError):
        validate_study_protocol(path, matrix=matrix(), split="evaluation", repeats=1)


@pytest.mark.parametrize("malformed", ["invalid-json", "duplicate", "nonfinite", "depth", "oversize"])
def test_strict_bounded_json_protocol_loading_rejects_unsafe_input_before_output(tmp_path, monkeypatch, malformed):
    from app.bac_config import MAX_MATRIX_BYTES, validate_study_protocol

    frozen = freeze(tmp_path / "protocol")
    path = Path(frozen["manifest_path"])
    content = canonical_json(frozen["protocol"])
    if malformed == "invalid-json":
        content = b"{broken"
    elif malformed == "duplicate":
        content = content.replace(b'"repeats":1', b'"repeats":1,"repeats":1', 1)
    elif malformed == "nonfinite":
        content = content.replace(b'"repeats":1', b'"repeats":NaN', 1)
    elif malformed == "depth":
        content = b"[" * 2000 + b"0" + b"]" * 2000
    else:
        content += b" " * (MAX_MATRIX_BYTES * 4)
    path.write_bytes(content)
    forbid_execution(monkeypatch)
    output = tmp_path / "not-created"
    with pytest.raises(ValueError):
        validate_study_protocol(path, matrix=matrix(), split="evaluation", repeats=1)
    with pytest.raises(ValueError):
        run_benchmark(matrix=matrix(), split="evaluation", repeats=1, output_dir=output, protocol=path)
    assert not output.exists()


def test_matching_protocol_binds_exact_definition_and_hash_into_verified_benchmark(tmp_path, monkeypatch):
    approved = matrix()
    frozen = freeze(tmp_path / "protocol", approved)
    path = Path(frozen["manifest_path"])
    original = path.read_bytes()
    before = copy.deepcopy(approved)
    calls = stub_research(monkeypatch)

    report = run_benchmark(matrix=approved, split="evaluation", repeats=1, output_dir=tmp_path / "benchmark", protocol=path)

    assert [call["mode"] for call in calls] == ["fixed", "vulnerable"]
    assert report["exit_code"] == 0
    expected = {"definition": frozen["protocol"], "canonical_sha256": hashlib.sha256(canonical_json(frozen["protocol"])).hexdigest()}
    assert report["study_protocol"] == expected
    directory = Path(report["output_dir"])
    assert {entry.name for entry in directory.iterdir()} == BENCHMARK_FILES
    assert json.loads((directory / "report.json").read_text())["study_protocol"] == expected
    for name in ("report.md", "report.html"):
        content = (directory / name).read_text()
        assert frozen["protocol"]["protocol_id"] in content
        assert expected["canonical_sha256"] in content
        assert "preflight" in content
    key = evidence_public_key()["public_key"]
    assert run_verify_evidence(report["manifest_path"], key) == 0
    changed = json.loads((directory / "report.json").read_text())
    changed["study_protocol"]["definition"]["repeats"] = 2
    (directory / "report.json").write_bytes(canonical_json(changed))
    assert run_verify_evidence(report["manifest_path"], key) == 2
    assert approved == before
    assert path.read_bytes() == original


def test_benchmark_without_protocol_keeps_existing_report_shape_and_ten_files(tmp_path, monkeypatch):
    calls = stub_research(monkeypatch)
    report = run_benchmark(matrix=matrix(), split="evaluation", repeats=1, output_dir=tmp_path / "benchmark")
    assert len(calls) == 2
    assert report["status"] == "allowed" and report["exit_code"] == 0
    assert "study_protocol" not in report
    assert {entry.name for entry in Path(report["output_dir"]).iterdir()} == BENCHMARK_FILES
