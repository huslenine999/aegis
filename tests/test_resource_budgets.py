"""Regression tests for Phase 4 resource budgets and bounded cardinality."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi import HTTPException
from starlette.testclient import TestClient
from starlette.responses import StreamingResponse

from app import (
    artifact_storage,
    database,
    rate_limit,
    reporting,
    resource_budgets,
)
from app.routes import artifact_routes
from app.cli import run_scanner_command
from app.scanners import safety_report_is_complete
from app.resource_budgets import BoundedFindingList, ResourceLimitError
from app.safe_output import SafeOutputRoot


def test_json_report_parser_rejects_oversized_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_MAX_PARSER_INPUT_BYTES", "32")
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"finding": "x" * 128}), encoding="utf-8")

    with pytest.raises(ResourceLimitError):
        reporting.load_json_report(report)


def test_scanner_subprocess_is_terminated_when_output_budget_is_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES", "32")

    result = run_scanner_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 128)"],
        label="budget-test",
    )

    assert result != 0


def test_scanner_file_output_is_bounded_and_partial_report_is_discarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES", "32")
    report = tmp_path / "report.json"
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b'x' * 128)",
        str(report),
    ]

    result = run_scanner_command(
        command,
        output_path=report,
        label="file-budget-test",
    )

    assert result != 0
    assert not report.exists()
    assert not list(tmp_path.glob(".report.json.*.tmp"))


def test_scanner_file_output_commits_only_a_bounded_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES", "32")
    report = tmp_path / "report.json"
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b'{}')",
        str(report),
    ]

    result = run_scanner_command(
        command,
        output_path=report,
        label="file-budget-test",
    )

    assert result == 0
    assert report.read_bytes() == b"{}"


def test_scanner_stdout_file_transport_is_bounded_and_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES", "32")
    oversized_report = tmp_path / "oversized.json"
    oversized_result = run_scanner_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 128)"],
        stdout_output_path=oversized_report,
        label="stdout-file-budget-test",
    )

    assert oversized_result != 0
    assert not oversized_report.exists()
    assert not list(tmp_path.glob(".oversized.json.*.tmp"))

    bounded_report = tmp_path / "bounded.json"
    bounded_result = run_scanner_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('{}')"],
        stdout_output_path=bounded_report,
        label="stdout-file-budget-test",
    )

    assert bounded_result == 0
    assert bounded_report.read_bytes() == b"{}"


def test_scanner_stdout_file_transport_uses_windows_safe_pipe_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES", "32")
    monkeypatch.setattr(
        resource_budgets,
        "os",
        SimpleNamespace(name="nt", environ=os.environ, replace=os.replace),
    )
    oversized_report = tmp_path / "windows-oversized.json"

    with pytest.raises(ResourceLimitError):
        resource_budgets.run_bounded_subprocess_stdout_to_file(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 128)"],
            oversized_report,
        )
    assert not oversized_report.exists()

    report = tmp_path / "windows-safe.json"

    result = resource_budgets.run_bounded_subprocess_stdout_to_file(
        [sys.executable, "-c", "import sys; sys.stdout.write('{}')"],
        report,
    )

    assert result.returncode == 0
    assert report.read_bytes() == b"{}"


def test_scanner_findings_and_json_reports_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_MAX_SCANNER_REPORT_BYTES", "64")
    monkeypatch.setenv("AEGIS_MAX_SCANNER_FINDINGS", "2")
    findings = BoundedFindingList()
    findings.append({"rule": "one", "filename": "a.py"})
    with pytest.raises(ResourceLimitError):
        findings.append({"rule": "two", "filename": "b.py", "detail": "x" * 64})

    output = SafeOutputRoot(tmp_path / "reports")
    output.write_bounded_json("report.json", [{"rule": "one"}])
    assert json.loads((tmp_path / "reports" / "report.json").read_text()) == [
        {"rule": "one"}
    ]
    with pytest.raises(ResourceLimitError):
        output.write_bounded_json("report.json", [{"detail": "x" * 128}])
    assert json.loads((tmp_path / "reports" / "report.json").read_text()) == [
        {"rule": "one"}
    ]


def test_safety_report_validation_rejects_incomplete_json():
    assert safety_report_is_complete([])
    assert safety_report_is_complete({"vulnerabilities": []})
    assert safety_report_is_complete({"affected_packages": {}})
    assert not safety_report_is_complete({"status": "error"})
    assert not safety_report_is_complete({"vulnerabilities": ["truncated"]})


def test_s3_artifact_stream_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    class Body(io.BytesIO):
        def close(self) -> None:
            super().close()

    class Client:
        def get_object(self, **kwargs: object) -> dict[str, object]:
            return {"Body": Body(b"0123456789")}

    monkeypatch.setenv("AEGIS_S3_BUCKET", "bucket")
    monkeypatch.setenv("AEGIS_MAX_RESPONSE_BYTES", "4")
    store = artifact_storage.S3ArtifactStore(client=Client())

    with pytest.raises(ResourceLimitError):
        list(store.iter_bytes("artifact"))


def test_s3_artifact_key_must_match_recorded_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_S3_PREFIX", "aegis")
    valid = {
        "name": "report.html",
        "storage_key": "aegis/tenants/7/projects/11/runs/job-1/report.html",
    }
    forged = {
        **valid,
        "storage_key": "aegis/tenants/8/projects/11/runs/job-1/report.html",
    }

    assert artifact_storage.artifact_key_matches(
        valid, tenant_id=7, project_id=11, job_id="job-1"
    )
    assert not artifact_storage.artifact_key_matches(
        forged, tenant_id=7, project_id=11, job_id="job-1"
    )


def test_s3_artifact_route_rejects_namespace_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = {"job_id": "job-1", "tenant_id": 7, "project_id": 11}
    metadata = {
        "name": "report.html",
        "size": 2,
        "sha256": "a" * 64,
        "backend": "s3",
        "storage_key": "aegis/tenants/8/projects/11/runs/job-1/report.html",
    }
    monkeypatch.setattr(artifact_routes, "_authorized_scan", lambda *args, **kwargs: run)
    monkeypatch.setattr(artifact_routes, "get_scan_artifact", lambda *args, **kwargs: metadata)

    class UnexpectedStore:
        def __init__(self) -> None:
            raise AssertionError("namespace validation must precede S3 access")

    monkeypatch.setattr(artifact_routes, "S3ArtifactStore", UnexpectedStore)

    with pytest.raises(HTTPException) as error:
        artifact_routes.project_scan_artifact(11, 1, "report.html", principal=object())

    assert error.value.status_code == 409


def test_s3_artifact_listing_requires_payload_integrity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = {"job_id": "job-1", "tenant_id": 7, "project_id": 11}
    metadata = {
        "name": "report.html",
        "size": 2,
        "sha256": "a" * 64,
        "backend": "s3",
        "storage_key": "aegis/tenants/7/projects/11/runs/job-1/report.html",
    }

    class Store:
        def __init__(self) -> None:
            pass

        def verify(self, key: str, size: int, digest: str) -> bool:
            return False

    monkeypatch.setattr(artifact_routes, "_authorized_scan", lambda *args, **kwargs: run)
    monkeypatch.setattr(artifact_routes, "list_scan_artifacts", lambda *args, **kwargs: [metadata])
    monkeypatch.setattr(artifact_routes, "S3ArtifactStore", Store)

    response = artifact_routes.project_scan_artifacts(11, 1, principal=object())

    assert response["artifacts"][0]["integrity"] == "failed"


def test_s3_verified_download_rejects_tampered_get_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Client:
        def get_object(self, **kwargs: object) -> dict[str, object]:
            return {"Body": io.BytesIO(b"tampered")}

    monkeypatch.setenv("AEGIS_S3_BUCKET", "bucket")
    store = artifact_storage.S3ArtifactStore(client=Client())
    destination = tmp_path / "staged.artifact"
    expected = hashlib.sha256(b"original").hexdigest()

    with pytest.raises(ValueError, match="integrity verification"):
        store.download_verified("artifact", len(b"original"), expected, destination)

    assert not destination.exists()


def test_report_bundle_enforces_zip_entry_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_MAX_ZIP_ENTRIES", "1")

    with pytest.raises(ResourceLimitError):
        reporting.build_report_bundle_from_artifacts({"report.html": b"ok"})


def test_report_bundle_enforces_uncompressed_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_MAX_ZIP_UNCOMPRESSED_BYTES", "1")

    with pytest.raises(ResourceLimitError):
        reporting.build_report_bundle_from_artifacts({"report.html": b"ok"})


def test_report_bundle_can_be_written_and_streamed_from_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_MAX_ZIP_ENTRIES", "8")
    source = tmp_path / "report.html"
    source.write_bytes(b"ok")
    bundle = tmp_path / "bundle.zip"

    reporting.build_report_bundle_to_path({"report.html": source}, bundle)

    assert b"PK" == b"".join(reporting.iter_file_bytes(bundle))[:2]


def test_rate_limit_route_keys_use_finite_route_classes() -> None:
    class RecordingRedis(database.InMemoryRedis):
        def __init__(self) -> None:
            super().__init__()
            self.keys: list[str] = []

        def incr(self, key: str) -> int:
            self.keys.append(key)
            return super().incr(key)

    redis = RecordingRedis()
    app = FastAPI()

    @app.get("/attacker/{value}")
    async def attacker(value: str) -> dict[str, str]:
        return {"value": value}

    app.add_middleware(rate_limit.RateLimitMiddleware, redis_client=redis)

    with TestClient(app) as client:
        response = client.get("/attacker/unique-secret-path")

    assert response.status_code == 200
    route_keys = [key for key in redis.keys if key.startswith("rate:route:")]
    assert route_keys
    assert all("unique-secret-path" not in key for key in route_keys)


def test_response_boundary_rejects_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "report.html"
    path.write_bytes(b"0123456789")
    monkeypatch.setenv("AEGIS_MAX_RESPONSE_BYTES", "4")

    with pytest.raises(HTTPException) as error:
        artifact_routes._stream_file_response(
            path,
            media_type="text/html",
            filename="report.html",
        )

    assert error.value.status_code == 413


def test_bundle_response_is_streaming_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(artifact_routes, "SCANS_DIR", tmp_path)
    response = artifact_routes._stream_bundle_response(
        {"report.html": b"ok"},
        filename="bundle.zip",
    )

    assert isinstance(response, StreamingResponse)
    if response.background:
        asyncio.run(response.background())
