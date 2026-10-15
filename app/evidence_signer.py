"""Evidence signing outside the scan worker.

Scan workers process hostile repositories, so in production they do not hold
the Ed25519 evidence key. A worker submits the unsigned scan manifest to the
``evidence-signing`` queue; a separate signer process, which holds the key and
reads the evidence volume read-only, signs it only when:

* the manifest names a scan run that exists and is still in flight, and its
  job, project, and tenant match the database record;
* the run has never been signed before (an append-only signature ledger);
* every artifact hash in the manifest matches the bytes on disk, and the
  source descriptor matches the manifest's source attestation; and
* the recorded decision is internally consistent (no ALLOWED decision with
  operational failures).

A compromised worker can still lie about a run that is in flight. It can no
longer steal the key, sign arbitrary documents, re-sign completed runs, or
sign artifacts that differ from what is stored.
"""

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from .artifact_storage import SAFE_JOB_ID, run_directory
from .database import SCANS_DIR, get_connection
from .evidence import (
    canonical_json,
    classify_source_attestation,
    evidence_public_key,
    sign_manifest,
    verify_source_descriptor,
)


SIGNING_QUEUE = "evidence-signing"
IN_FLIGHT_STATES = {"running", "analyzing", "correlating", "reporting"}
POLICY_STATUSES = {"ALLOWED", "BLOCKED", "ERROR"}
SIGNING_TIMEOUT_SECONDS = 60.0


class SigningRefused(RuntimeError):
    """The signer declined to sign a manifest."""


def remote_signing_enabled() -> bool:
    return os.environ.get("AEGIS_EVIDENCE_SIGNER", "local").strip().lower() == "remote"


def sign_scan_manifest(payload: dict) -> dict:
    """Sign a scan manifest, through the signer process when one is configured."""
    if not remote_signing_enabled():
        return sign_manifest(payload)
    return _request_remote_signature(payload)


def _request_remote_signature(payload: dict) -> dict:
    from rq import Queue

    from .database import redis_client

    queue = Queue(SIGNING_QUEUE, connection=redis_client)
    job = queue.enqueue(
        sign_requested_manifest,
        payload,
        job_timeout=int(SIGNING_TIMEOUT_SECONDS),
        result_ttl=300,
        failure_ttl=3600,
    )
    deadline = time.monotonic() + SIGNING_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        status = job.get_status(refresh=True)
        if status == "finished":
            signed = job.return_value()
            if not isinstance(signed, dict) or "signature" not in signed:
                raise SigningRefused("The evidence signer returned an invalid manifest.")
            return signed
        if status in {"failed", "stopped", "canceled"}:
            raise SigningRefused("The evidence signer refused or failed to sign the manifest.")
        time.sleep(0.2)
    job.cancel()
    raise SigningRefused("The evidence signer did not respond in time.")


def _artifact_inventory(report_dir) -> list[dict]:
    # Imported lazily: the worker module is heavy and only its hashing helper is needed.
    from .worker import _artifact_inventory as inventory

    return inventory(report_dir)


def validate_signing_request(payload: Any) -> dict:
    """Check a manifest against the database and the stored evidence.

    Returns the database record of the run. Raises SigningRefused otherwise.
    """
    if not isinstance(payload, dict) or "signature" in payload:
        raise SigningRefused("Signing requests must be unsigned manifest objects.")
    if payload.get("schema_version") != 3:
        raise SigningRefused("Only schema-3 scan manifests can be signed.")
    job_id = payload.get("job_id")
    scan_run_id = payload.get("scan_run_id")
    if not isinstance(job_id, str) or not SAFE_JOB_ID.fullmatch(job_id):
        raise SigningRefused("The manifest has an invalid job identifier.")
    if not isinstance(scan_run_id, int) or isinstance(scan_run_id, bool):
        raise SigningRefused("Only manifests bound to a recorded scan run can be signed.")
    if payload.get("policy_status") not in POLICY_STATUSES:
        raise SigningRefused("The manifest has an unknown policy decision.")
    if payload.get("policy_status") == "ALLOWED" and payload.get("operational_failures"):
        raise SigningRefused("An ALLOWED decision cannot carry operational failures.")

    with get_connection() as connection:
        row = connection.execute(
            """SELECT r.job_id, r.project_id, p.tenant_id, r.state,
                      (SELECT COUNT(*) FROM evidence_signatures s WHERE s.scan_run_id = r.id)
               FROM scan_runs r JOIN projects p ON p.id = r.project_id
               WHERE r.id = ?""",
            (scan_run_id,),
        ).fetchone()
    if not row:
        raise SigningRefused("The scan run does not exist.")
    run = {"job_id": row[0], "project_id": int(row[1]), "tenant_id": int(row[2]), "state": row[3]}
    if (
        run["job_id"] != job_id
        or run["project_id"] != payload.get("project_id")
        or run["tenant_id"] != payload.get("tenant_id")
    ):
        raise SigningRefused("The manifest does not match the recorded scan run.")
    if run["state"] not in IN_FLIGHT_STATES:
        raise SigningRefused("Only scan runs that are still in progress can be signed.")
    if int(row[4]):
        raise SigningRefused("This scan run has already been signed.")

    report_dir = run_directory(
        SCANS_DIR, job_id, tenant_id=run["tenant_id"], project_id=run["project_id"]
    )
    if not report_dir.is_dir():
        raise SigningRefused("The scan run has no stored evidence.")
    try:
        stored = _artifact_inventory(report_dir)
    except Exception as exc:
        raise SigningRefused(f"Stored evidence could not be inventoried: {exc}") from exc
    if canonical_json({"a": stored}) != canonical_json({"a": payload.get("artifacts")}):
        raise SigningRefused("Artifact hashes in the manifest do not match the stored evidence.")

    if classify_source_attestation(payload) != "source-bound":
        raise SigningRefused("The manifest is not bound to an attested source snapshot.")
    try:
        descriptor = json.loads((report_dir / "source-descriptor.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SigningRefused("The source descriptor is missing or unreadable.") from exc
    if not verify_source_descriptor(payload, descriptor):
        raise SigningRefused("The source descriptor does not match the manifest.")
    return run


def sign_requested_manifest(payload: dict) -> dict:
    """RQ job run by the signer process."""
    validate_signing_request(payload)
    signed = sign_manifest(payload)
    key_id = evidence_public_key()["key_id"]
    with get_connection() as connection:
        # The primary key makes signing one-shot even if two requests race.
        connection.execute(
            """INSERT INTO evidence_signatures
               (scan_run_id, job_id, manifest_sha256, key_id, signed_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                payload["scan_run_id"],
                payload["job_id"],
                hashlib.sha256(canonical_json(signed)).hexdigest(),
                key_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return signed
