"""Verified runtime research imports; never source coverage or release evidence."""

import base64
import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Mapping

from .artifact_storage import publish_artifacts
from .bac_imports import BAC_ARTIFACTS, validate_bac_bundle
from .database import SCANS_DIR, get_connection
from .evidence import canonical_json
from .findings import sync_findings
from .projects import claim_bac_import_run, record_scan_artifacts, update_scan_run
from .resource_budgets import iter_file_bytes
from .safe_output import SafeOutputRoot


# Public development identity: its signing seed is published in evidence.py.
_DEVELOPMENT_PUBLIC_KEY = "EK0UYtjq56IlHo4z3xlLpBJE5hT9MMJ-C5nzNSNwv8Y"


def configured_import_public_key() -> str:
    key = os.environ.get("AEGIS_BAC_IMPORT_PUBLIC_KEY", "").strip()
    try:
        decoded = base64.b64decode(key + "=" * (-len(key) % 4), altchars=b"-_", validate=True)
        if len(decoded) != 32:
            raise ValueError("Invalid key length")
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("Set AEGIS_BAC_IMPORT_PUBLIC_KEY to the research signer's Ed25519 public key before importing.") from exc
    if os.environ.get("AEGIS_ENV", "development").strip().lower() == "production" and decoded == base64.urlsafe_b64decode(_DEVELOPMENT_PUBLIC_KEY + "="):
        raise RuntimeError("Production BAC imports cannot trust the published development signing key.")
    return key


def _store_bundle(artifacts: Mapping[str, bytes], parent: Path, job_id: str) -> tuple[Path, bool]:
    final = parent / job_id
    if final.exists() or final.is_symlink():
        # A commit failure can leave private, signed files without database rows.
        # Adopt only byte-identical evidence; never replace an existing file.
        output = SafeOutputRoot(final)
        if {path.name for path in final.iterdir()} != set(artifacts):
            raise RuntimeError("Existing research evidence differs; refusing to overwrite it.")
        for name, content in artifacts.items():
            path = output.file(name)
            if path.stat().st_size != len(content):
                raise RuntimeError("Existing research evidence differs; refusing to overwrite it.")
            existing = hashlib.sha256()
            for chunk in iter_file_bytes(path, max_bytes=max(1, len(content))):
                existing.update(chunk)
            if existing.digest() != hashlib.sha256(content).digest():
                raise RuntimeError("Existing research evidence differs; refusing to overwrite it.")
        return final, False
    with tempfile.TemporaryDirectory(prefix=".bac-import-", dir=parent) as temporary:
        output = SafeOutputRoot(temporary)
        for name, content in artifacts.items():
            output.write_bytes(name, content).chmod(0o600)
        Path(temporary).rename(final)
    return final, True


def import_bac_report(*, project: dict, requested_by: int, artifacts: Mapping[str, bytes]) -> dict:
    validated = validate_bac_bundle(artifacts, configured_import_public_key())
    report = validated["report"]
    project_id, tenant_id = int(project["id"]), int(project["tenant_id"])
    digest = validated["manifest_sha256"]
    identity = {"tenant_id": tenant_id, "project_id": project_id, "manifest_sha256": digest}
    job_id = "bac-" + hashlib.sha256(canonical_json(identity)).hexdigest()
    result = {
        "research_only": True, "gate_eligible": False, "source_attestation": "not-claimed",
        "manifest_sha256": digest, "bac_report": report, "bac_findings": report["findings"],
    }
    with get_connection() as connection:
        run_id, imported = claim_bac_import_run(
            connection, job_id=job_id, project_id=project_id, tenant_id=tenant_id, requested_by=requested_by,
        )
        if imported:
            stored = None
            created = False
            try:
                parent = SafeOutputRoot(SCANS_DIR).directory(f"tenants/{tenant_id}/projects/{project_id}/runs")
                stored, created = _store_bundle(artifacts, parent, job_id)
                metadata = publish_artifacts(stored, set(BAC_ARTIFACTS), tenant_id=tenant_id, project_id=project_id, job_id=job_id)
                record_scan_artifacts(run_id, metadata, connection=connection)
                synced = sync_findings(run_id, result, connection=connection)
                update_scan_run(
                    run_id, state="failed" if report["exit_code"] == 2 else "completed", progress=100,
                    result={**result, "finding_sync": synced}, connection=connection,
                )
            except Exception:
                if stored is not None and created:
                    shutil.rmtree(stored)
                raise
    return {"scan_run_id": run_id, "imported": imported, "research_only": True}
