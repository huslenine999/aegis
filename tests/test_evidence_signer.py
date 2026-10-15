"""The evidence signer signs only in-flight runs whose stored evidence matches."""

import hashlib
import json
from types import SimpleNamespace

import pytest

from app import database, evidence_signer, projects, signer_entrypoint, worker
from app.evidence import canonical_json, evidence_public_key, sign_manifest, verify_manifest
from app.evidence_signer import SigningRefused, sign_requested_manifest, validate_signing_request
from app.scan_engine import ScanJobPayload
from tests.test_projects import configure_project_database


def run_scan(tmp_path, monkeypatch, request_signature):
    """Run a real quick scan with remote signing routed to ``request_signature``."""
    configure_project_database(tmp_path, monkeypatch)
    source = tmp_path / "plain.txt"
    source.write_text("Synthetic project evidence.\n")
    project_id = projects.create_project(
        name="Signed", repository_url="", github_full_name="", default_branch="main",
        scan_preset="quick", user_id=10,
    )
    run_id = projects.create_scan_run(
        job_id="signed-job", project_id=project_id, requested_by=10, target="project", preset="quick",
    )
    monkeypatch.setenv("AEGIS_EVIDENCE_SIGNER", "remote")
    monkeypatch.setenv("AEGIS_ENABLE_YARA", "false")
    monkeypatch.setattr(worker, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(evidence_signer, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(worker, "redis_client", database.InMemoryRedis())
    monkeypatch.setattr(worker, "_source_revision", lambda _: "unavailable")
    monkeypatch.setattr(worker, "queue_project_notification", lambda *args: None)
    monkeypatch.setattr(worker, "_complete_github_scan_check", lambda *args: None)
    monkeypatch.setattr(evidence_signer, "_request_remote_signature", request_signature)
    worker.async_scan_task(ScanJobPayload(
        "signed-job", "project", custom_file_path=str(source), scan_run_id=run_id,
        project_id=project_id, requested_by=10, preset="quick",
    ))
    report_dir = next((tmp_path / "scans").rglob("signed-job"))
    return run_id, report_dir


@pytest.fixture
def in_flight(tmp_path, monkeypatch):
    """A captured worker manifest whose run is put back into the reporting state."""
    captured = []

    def capture(payload):
        captured.append(json.loads(json.dumps(payload)))
        return sign_manifest(payload)

    run_id, report_dir = run_scan(tmp_path, monkeypatch, capture)
    with database.get_connection() as connection:
        connection.execute("UPDATE scan_runs SET state = 'reporting' WHERE id = ?", (run_id,))
    return SimpleNamespace(payload=captured[0], run_id=run_id, report_dir=report_dir)


def test_worker_manifest_is_signed_by_the_signer_and_recorded_once(tmp_path, monkeypatch):
    requests = []

    def signer(payload):
        requests.append(payload)
        return sign_requested_manifest(payload)

    run_id, report_dir = run_scan(tmp_path, monkeypatch, signer)

    manifest = json.loads((report_dir / "scan-manifest.json").read_text())
    assert "signature" not in requests[0]
    assert verify_manifest(manifest, evidence_public_key()["public_key"])
    assert projects.get_scan_run(run_id)["state"] == "completed"
    with database.get_connection() as connection:
        ledger = connection.execute(
            "SELECT job_id, manifest_sha256, key_id FROM evidence_signatures WHERE scan_run_id = ?",
            (run_id,),
        ).fetchall()
    assert ledger == [(
        "signed-job",
        hashlib.sha256(canonical_json(manifest)).hexdigest(),
        evidence_public_key()["key_id"],
    )]


def test_signer_accepts_a_matching_in_flight_request(in_flight):
    assert validate_signing_request(in_flight.payload)["state"] == "reporting"


def test_signing_is_one_shot_per_scan_run(in_flight):
    sign_requested_manifest(in_flight.payload)

    with pytest.raises(SigningRefused, match="already been signed"):
        sign_requested_manifest(in_flight.payload)


def test_ledger_rows_cannot_be_rewritten(in_flight):
    sign_requested_manifest(in_flight.payload)

    with pytest.raises(Exception, match="append-only"):
        with database.get_connection() as connection:
            connection.execute("UPDATE evidence_signatures SET manifest_sha256 = 'forged'")


@pytest.mark.parametrize("state", ["completed", "failed", "cancelled", "queued"])
def test_runs_that_are_not_in_flight_cannot_be_signed(in_flight, state):
    with database.get_connection() as connection:
        connection.execute("UPDATE scan_runs SET state = ? WHERE id = ?", (state, in_flight.run_id))

    with pytest.raises(SigningRefused, match="still in progress"):
        validate_signing_request(in_flight.payload)


def test_artifacts_changed_on_disk_after_hashing_are_refused(in_flight):
    with (in_flight.report_dir / "report.md").open("a") as report:
        report.write("\nDEPLOYMENT ALLOWED\n")

    with pytest.raises(SigningRefused, match="Artifact hashes"):
        validate_signing_request(in_flight.payload)


def test_manifest_cannot_omit_or_invent_artifacts(in_flight):
    dropped = {**in_flight.payload, "artifacts": in_flight.payload["artifacts"][1:]}
    with pytest.raises(SigningRefused, match="Artifact hashes"):
        validate_signing_request(dropped)

    forged = json.loads(json.dumps(in_flight.payload))
    forged["artifacts"][0]["sha256"] = "0" * 64
    with pytest.raises(SigningRefused, match="Artifact hashes"):
        validate_signing_request(forged)


@pytest.mark.parametrize(("field", "value", "message"), [
    ("job_id", "other-job", "does not match"),
    ("tenant_id", 999, "does not match"),
    ("project_id", 999, "does not match"),
    ("scan_run_id", 999, "does not exist"),
    ("scan_run_id", None, "recorded scan run"),
    ("job_id", "../escape", "invalid job"),
    ("policy_status", "PASSED", "unknown policy decision"),
    ("schema_version", 2, "schema-3"),
])
def test_identity_and_schema_must_match_the_database(in_flight, field, value, message):
    with pytest.raises(SigningRefused, match=message):
        validate_signing_request({**in_flight.payload, field: value})


def test_allowed_decisions_cannot_hide_operational_failures(in_flight):
    request = {**in_flight.payload, "policy_status": "ALLOWED", "operational_failures": ["Semgrep"]}

    with pytest.raises(SigningRefused, match="operational failures"):
        validate_signing_request(request)


def test_source_descriptor_must_match_the_attestation(in_flight):
    descriptor_path = in_flight.report_dir / "source-descriptor.json"
    descriptor = json.loads(descriptor_path.read_text())
    descriptor["file_count"] += 1
    descriptor_path.write_text(json.dumps(descriptor))
    request = json.loads(json.dumps(in_flight.payload))
    for item in request["artifacts"]:
        if item["name"] == "source-descriptor.json":
            item["size"] = descriptor_path.stat().st_size
            item["sha256"] = hashlib.sha256(descriptor_path.read_bytes()).hexdigest()

    with pytest.raises(SigningRefused, match="source descriptor"):
        validate_signing_request(request)


def test_signed_documents_and_non_objects_are_refused(in_flight):
    with pytest.raises(SigningRefused, match="unsigned manifest"):
        validate_signing_request(sign_manifest(in_flight.payload))
    with pytest.raises(SigningRefused, match="unsigned manifest"):
        validate_signing_request(["not", "a", "manifest"])


def test_worker_fails_the_scan_when_the_signer_refuses(tmp_path, monkeypatch):
    def refuse(payload):
        raise SigningRefused("refused for test")

    with pytest.raises(SigningRefused):
        run_scan(tmp_path, monkeypatch, refuse)

    run = projects.get_scan_run(1)
    assert run["state"] == "failed"
    assert not list((tmp_path / "scans").rglob("scan-manifest.json"))


class FakeJob:
    def __init__(self, statuses, value=None):
        self.statuses = list(statuses)
        self.value = value
        self.cancelled = False

    def get_status(self, refresh=True):
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]

    def return_value(self):
        return self.value

    def cancel(self):
        self.cancelled = True


def use_fake_queue(monkeypatch, job):
    import rq

    class FakeQueue:
        def __init__(self, name, connection=None):
            assert name == "evidence-signing"

        def enqueue(self, func, *args, **kwargs):
            assert func is evidence_signer.sign_requested_manifest
            return job

    monkeypatch.setattr(rq, "Queue", FakeQueue)
    monkeypatch.setattr(evidence_signer.time, "sleep", lambda _seconds: None)


def test_remote_request_returns_the_signed_manifest(monkeypatch):
    use_fake_queue(monkeypatch, FakeJob(["queued", "started", "finished"], {"signature": {}, "a": 1}))

    assert evidence_signer._request_remote_signature({"a": 1}) == {"signature": {}, "a": 1}


@pytest.mark.parametrize(("statuses", "value", "message"), [
    (["failed"], None, "refused or failed"),
    (["finished"], {"unsigned": True}, "invalid manifest"),
])
def test_remote_request_fails_closed(monkeypatch, statuses, value, message):
    use_fake_queue(monkeypatch, FakeJob(statuses, value))

    with pytest.raises(SigningRefused, match=message):
        evidence_signer._request_remote_signature({})


def test_remote_request_times_out_and_cancels(monkeypatch):
    job = FakeJob(["queued"])
    use_fake_queue(monkeypatch, job)
    monkeypatch.setattr(evidence_signer, "SIGNING_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(SigningRefused, match="did not respond"):
        evidence_signer._request_remote_signature({})
    assert job.cancelled


def test_signer_holds_only_the_signing_key_in_production(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_EVIDENCE_SIGNING_KEY", raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_EVIDENCE_SIGNING_KEY is required"):
        signer_entrypoint.validate_signer_configuration()

    monkeypatch.setenv("AEGIS_EVIDENCE_SIGNING_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    signer_entrypoint.validate_signer_configuration()

    for secret in ("AEGIS_ENCRYPTION_KEY", "AEGIS_GITHUB_APP_PRIVATE_KEY_B64", "AEGIS_SESSION_SECRET"):
        monkeypatch.setenv(secret, "must-not-reach-signer")
        with pytest.raises(RuntimeError, match=secret):
            signer_entrypoint.validate_signer_configuration()
        monkeypatch.delenv(secret)
