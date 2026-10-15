"""Remote evidence remains downloadable after local run cleanup."""

import asyncio
import hashlib
import io
import tempfile
import zipfile
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException
from starlette.requests import ClientDisconnect

from app import artifact_storage
from app.resource_budgets import ResourceLimitError
from app.routes import artifact_routes


@pytest.fixture
def remote_run(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_S3_BUCKET", "evidence")
    monkeypatch.setenv("AEGIS_S3_PREFIX", "aegis")
    scans = tmp_path / "missing-local-scans"
    run = {"job_id": "retained-job", "tenant_id": 7, "project_id": 11, "target": "project"}
    content = {"report.html": b"<h1>Retained evidence</h1>", "codeql-report.json": b'{"findings":[]}'}
    metadata = [
        {"name": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
         "backend": "s3", "storage_key": f"aegis/tenants/7/projects/11/runs/retained-job/{name}"}
        for name, payload in content.items()
    ]

    class Client:
        def __init__(self):
            self.calls = []
            self.bodies = []
            self.error = None
            self.tamper = False

        def get_object(self, *, Bucket, Key):
            self.calls.append((Bucket, Key))
            if self.error:
                raise self.error
            payload = content[Key.rsplit("/", 1)[-1]]
            body = io.BytesIO(b"x" * len(payload) if self.tamper else payload)
            self.bodies.append(body)
            return {"Body": body}

    client = Client()
    store = artifact_storage.S3ArtifactStore(client=client)
    staging = []
    temporary_directory = tempfile.TemporaryDirectory

    def tracked_directory(*args, **kwargs):
        temporary = temporary_directory(*args, **kwargs)
        staging.append(Path(temporary.name))
        return temporary

    monkeypatch.setattr(artifact_routes, "SCANS_DIR", scans)
    monkeypatch.setattr(artifact_routes, "_authorized_scan", lambda *args, **kwargs: run)
    monkeypatch.setattr(artifact_routes, "list_scan_artifacts", lambda *args: metadata)
    monkeypatch.setattr(artifact_routes, "get_scan_artifact", lambda _, name: next(item for item in metadata if item["name"] == name))
    monkeypatch.setattr(artifact_routes, "S3ArtifactStore", lambda: store)
    monkeypatch.setattr(artifact_routes.tempfile, "TemporaryDirectory", tracked_directory)
    return scans, content, metadata, client, staging


async def read_response(response):
    content = b"".join([chunk async for chunk in response.body_iterator])
    if response.background:
        await response.background()
    return content


@pytest.mark.parametrize("name", ["report.html", "codeql-report.json"])
def test_s3_download_without_local_run_streams_verified_bytes_and_cleans_up(remote_run, name):
    scans, content, _, client, staging = remote_run
    response = artifact_routes.project_scan_artifact(11, 1, name, principal=object())

    assert not scans.exists()
    assert staging and all(path.is_dir() for path in staging)
    expected = content[name]
    if name == "report.html":
        expected += artifact_routes.REPORT_VIEW_STYLE
        assert "sandbox" in response.headers["content-security-policy"]
    assert asyncio.run(read_response(response)) == expected
    assert len(client.calls) == 1
    assert all(body.closed for body in client.bodies)
    assert all(not path.exists() for path in staging)


def test_s3_bundle_without_local_run_verifies_contents_and_cleans_up(remote_run):
    scans, content, _, client, staging = remote_run
    response = artifact_routes.project_scan_artifact(11, 1, "report-bundle.zip", principal=object())

    assert staging and all(not path.exists() for path in staging)
    assert not (scans / "runs").exists()
    with zipfile.ZipFile(io.BytesIO(asyncio.run(read_response(response)))) as archive:
        assert archive.read("report.html") == content["report.html"]
        assert archive.read("raw/codeql-report.json") == content["codeql-report.json"]
    assert len(client.calls) == 2
    assert all(body.closed for body in client.bodies)
    assert not list(scans.iterdir())


def test_s3_inline_response_budget_failure_cleans_verified_staging(remote_run, monkeypatch):
    _, content, _, client, staging = remote_run
    monkeypatch.setenv("AEGIS_MAX_RESPONSE_BYTES", str(len(content["report.html"])))

    with pytest.raises(HTTPException) as error:
        artifact_routes.project_scan_artifact(11, 1, "report.html", principal=object())
    assert error.value.status_code == 413
    assert len(client.calls) == 1
    assert staging and all(not path.exists() for path in staging)


@pytest.mark.parametrize("name", ["report.html", "report-bundle.zip"])
@pytest.mark.parametrize("failure", ["before-body", "during-body", "stream-budget", "cancelled"])
def test_s3_stream_failures_clean_up_without_background_task(remote_run, monkeypatch, name, failure):
    scans, _, _, _, staging = remote_run
    monkeypatch.setenv("AEGIS_MAX_RESPONSE_BYTES", "4096")
    response = artifact_routes.project_scan_artifact(11, 1, name, principal=object())
    bundle_paths = list(scans.glob(".aegis-bundle-*.zip"))
    if failure == "stream-budget":
        source_path = bundle_paths[0] if bundle_paths else staging[0] / "report.html"
        source_path.write_bytes(b"x" * 4097)

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        if failure == "cancelled":
            raise asyncio.CancelledError()
        message_type = "http.response.start" if failure == "before-body" else "http.response.body"
        if failure != "stream-budget" and message["type"] == message_type:
            raise OSError("Client disconnected")

    expected_error = (ResourceLimitError if failure == "stream-budget" else
                      asyncio.CancelledError if failure == "cancelled" else ClientDisconnect)
    with pytest.raises(expected_error):
        asyncio.run(response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send))

    assert staging and all(not path.exists() for path in staging)
    assert all(not path.exists() for path in bundle_paths)


@pytest.mark.parametrize("name", ["report.html", "report-bundle.zip"])
def test_asgi_20_disconnect_closes_artifact_before_background_cleanup(remote_run, monkeypatch, name):
    _, _, _, _, staging = remote_run
    response = artifact_routes.project_scan_artifact(11, 1, name, principal=object())
    opened_files = []
    open_file = Path.open

    def tracked_open(path, mode="r", *args, **kwargs):
        stream = open_file(path, mode, *args, **kwargs)
        if mode == "rb":
            opened_files.append(stream)
        return stream

    cleanup_observations = []
    cleanup = response.background.func

    def tracked_cleanup():
        cleanup_observations.append(any(not stream.closed for stream in opened_files))
        cleanup()

    monkeypatch.setattr(Path, "open", tracked_open)
    monkeypatch.setattr(response.background, "func", tracked_cleanup)

    async def disconnect_after_first_chunk():
        first_chunk = asyncio.Event()

        async def receive():
            await first_chunk.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.body" and message.get("body"):
                first_chunk.set()
                await asyncio.Future()

        await response({"type": "http", "asgi": {"spec_version": "2.0"}}, receive, send)

    asyncio.run(disconnect_after_first_chunk())
    assert opened_files and all(stream.closed for stream in opened_files)
    assert cleanup_observations == [False]
    assert all(not path.exists() for path in staging)


@pytest.mark.parametrize("name", ["report.html", "report-bundle.zip"])
@pytest.mark.parametrize("failure", ["tampered", "io-error", "s3-error"])
def test_s3_failed_downloads_clean_all_staging_files(remote_run, name, failure):
    _, _, _, client, staging = remote_run
    if failure == "tampered":
        client.tamper = True
    elif failure == "io-error":
        client.error = OSError("Remote evidence is unavailable")
    else:
        client.error = ClientError({"Error": {"Code": "NoSuchKey", "Message": "Missing"}}, "GetObject")

    expected_error = ClientError if failure == "s3-error" else HTTPException
    with pytest.raises(expected_error) as error:
        artifact_routes.project_scan_artifact(11, 1, name, principal=object())
    if isinstance(error.value, HTTPException):
        assert error.value.status_code == 409
    assert staging and all(not path.exists() for path in staging)
    assert all(body.closed for body in client.bodies)


@pytest.mark.parametrize("name", ["report.html", "report-bundle.zip"])
def test_s3_retained_download_still_rejects_foreign_namespace(remote_run, name):
    _, _, metadata, client, staging = remote_run
    metadata[0]["storage_key"] = "aegis/tenants/99/projects/11/runs/retained-job/report.html"

    with pytest.raises(HTTPException) as error:
        artifact_routes.project_scan_artifact(11, 1, name, principal=object())
    assert error.value.status_code == 409
    assert not client.calls
    assert all(not path.exists() for path in staging)
