"""Regression tests for Phase 4 resource budgets and bounded cardinality."""

from __future__ import annotations

import asyncio
import io
import json
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi import HTTPException
from starlette.testclient import TestClient
from starlette.responses import StreamingResponse

from app import artifact_storage, database, main as app_main, rate_limit, reporting
from app.cli import run_scanner_command
from app.resource_budgets import ResourceLimitError


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
        app_main._stream_file_response(
            path,
            media_type="text/html",
            filename="report.html",
        )

    assert error.value.status_code == 413


def test_bundle_response_is_streaming_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_main, "SCANS_DIR", tmp_path)
    response = app_main._stream_bundle_response(
        {"report.html": b"ok"},
        filename="bundle.zip",
    )

    assert isinstance(response, StreamingResponse)
    if response.background:
        asyncio.run(response.background())
