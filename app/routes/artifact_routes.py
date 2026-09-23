import hashlib
import itertools
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.background import BackgroundTask

from ..artifact_storage import (
    ArtifactLimitError,
    S3ArtifactStore,
    artifact_key_matches,
    artifact_limits,
    run_directory,
    validate_artifact_sizes,
)
from ..auth import require_role
from ..database import PROJECT_ROOT, SCANS_DIR
from ..observability import record_artifact_integrity_failure
from ..projects import get_scan_artifact, list_scan_artifacts
from ..reporting import ReportSource
from ..resource_budgets import ResourceLimitError, iter_file_bytes, resource_budgets
from ..web_common import RUN_ARTIFACTS, require_access, require_demo_boundary
from .project_routes import _authorized_scan

router = APIRouter()
logger = logging.getLogger("aegis.main")
REPORT_VIEW_STYLE = b"<style>.reveal{opacity:1!important;transform:none!important}</style>"


def _file_sha256(path: Path, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    for chunk in iter_file_bytes(path, max_bytes=max_bytes, chunk_size=1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _artifact_integrity(metadata: dict, path: Path) -> bool:
    try:
        validate_artifact_sizes([(str(metadata.get("name", "artifact")), metadata["size"])])
        expected_size = int(metadata["size"])
    except (ArtifactLimitError, KeyError, TypeError, ValueError):
        return False
    if metadata.get("backend") == "s3":
        key = metadata.get("storage_key")
        return bool(
            key
            and S3ArtifactStore().verify(key, metadata["size"], metadata["sha256"])
        )
    return (
        path.is_file()
        and path.stat().st_size == metadata["size"]
        and _file_sha256(path, max_bytes=expected_size) == metadata["sha256"]
    )


def _s3_artifact_key_is_valid(metadata: dict, run: dict, project_id: int) -> bool:
    return artifact_key_matches(
        metadata,
        tenant_id=int(run["tenant_id"]),
        project_id=project_id,
        job_id=str(run["job_id"]),
    )


def _artifact_bytes(metadata: dict, path: Path) -> bytes:
    try:
        validate_artifact_sizes([(str(metadata.get("name", "artifact")), metadata["size"])])
    except (ArtifactLimitError, KeyError, TypeError, ValueError) as exc:
        record_artifact_integrity_failure()
        raise HTTPException(status_code=413, detail="Artifact exceeds configured size limit.") from exc
    if not _artifact_integrity(metadata, path):
        record_artifact_integrity_failure()
        raise HTTPException(status_code=409, detail="Artifact integrity verification failed.")
    if metadata.get("backend") == "s3":
        content = S3ArtifactStore().read(
            metadata["storage_key"], max_bytes=int(metadata["size"])
        )
        if len(content) != metadata["size"] or hashlib.sha256(content).hexdigest() != metadata["sha256"]:
            record_artifact_integrity_failure()
            raise HTTPException(status_code=409, detail="Artifact integrity verification failed.")
        try:
            validate_artifact_sizes([(str(metadata.get("name", "artifact")), len(content))])
        except ArtifactLimitError as exc:
            record_artifact_integrity_failure()
            raise HTTPException(status_code=413, detail="Artifact exceeds configured size limit.") from exc
        return content
    content = b"".join(
        iter_file_bytes(path, max_bytes=int(metadata["size"]), chunk_size=1024 * 1024)
    )
    try:
        validate_artifact_sizes([(str(metadata.get("name", "artifact")), len(content))])
    except ArtifactLimitError as exc:
        record_artifact_integrity_failure()
        raise HTTPException(status_code=413, detail="Artifact exceeds configured size limit.") from exc
    return content


def _stream_file_response(
    path: Path,
    *,
    media_type: str,
    filename: str,
    cleanup: bool = False,
    inline: bool = False,
):
    response_limit = resource_budgets().max_response_bytes
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Artifact not found.") from exc
    if size + (len(REPORT_VIEW_STYLE) if inline else 0) > response_limit:
        raise HTTPException(status_code=413, detail="Response exceeds configured size limit.")
    background = BackgroundTask(path.unlink, missing_ok=True) if cleanup else None
    body = iter_file_bytes(path, max_bytes=response_limit)
    if inline:
        # The signed report remains unchanged; the browser view stays readable
        # when its untrusted inline scripts are blocked by the report CSP.
        body = itertools.chain(body, (REPORT_VIEW_STYLE,))
    return StreamingResponse(
        body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{filename}"',
            **({"Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:"} if inline else {}),
        },
        background=background,
    )


def _stream_bundle_response(
    artifacts: Mapping[str, ReportSource],
    *,
    filename: str,
):
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".aegis-bundle-", suffix=".zip", dir=SCANS_DIR
    )
    os.close(descriptor)
    bundle_path = Path(temporary_name)
    try:
        from ..reporting import build_report_bundle_to_path

        build_report_bundle_to_path(artifacts, bundle_path)
        response_limit = min(
            resource_budgets().max_response_bytes,
            artifact_limits()["bundle"],
        )
        if bundle_path.stat().st_size > response_limit:
            raise ResourceLimitError(
                f"Report bundle exceeds the response limit of {response_limit} bytes."
            )
    except (ArtifactLimitError, ResourceLimitError, OSError, ValueError) as exc:
        bundle_path.unlink(missing_ok=True)
        if isinstance(exc, (ArtifactLimitError, ResourceLimitError)):
            raise HTTPException(
                status_code=413,
                detail="Report bundle exceeds configured resource limits.",
            ) from exc
        raise
    return StreamingResponse(
        iter_file_bytes(bundle_path, max_bytes=response_limit),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        background=BackgroundTask(bundle_path.unlink, missing_ok=True),
    )


@router.get("/api/projects/{project_id}/scans/{run_id}/artifacts")
def project_scan_artifacts(
    project_id: int, run_id: int, principal=Depends(require_role("viewer"))
):
    run = _authorized_scan(project_id, run_id, principal)
    report_dir = run_directory(
        SCANS_DIR,
        run["job_id"],
        tenant_id=run.get("tenant_id"),
        project_id=project_id,
    )
    artifacts = []
    for metadata in list_scan_artifacts(run_id):
        name = metadata["name"]
        path = report_dir / name
        if name not in RUN_ARTIFACTS:
            continue
        try:
            integrity = (
                _s3_artifact_key_is_valid(metadata, run, project_id)
                and S3ArtifactStore().verify(
                    str(metadata["storage_key"]), metadata["size"], metadata["sha256"]
                )
                if metadata.get("backend") == "s3"
                else _artifact_integrity(metadata, path)
            )
        except Exception as exc:
            logger.warning(
                "Artifact integrity verification failed for run %s artifact %s: %s",
                run_id,
                name,
                exc,
            )
            integrity = False
        if not integrity:
            record_artifact_integrity_failure()
        artifacts.append(
            {
                **metadata,
                "url": f"/api/projects/{project_id}/scans/{run_id}/artifacts/{name}",
                "integrity": "verified" if integrity else "failed",
            }
        )
    if any(item["name"] == "report.html" for item in artifacts):
        artifacts.append(
            {
                "name": "report-bundle.zip",
                "url": f"/api/projects/{project_id}/scans/{run_id}/artifacts/report-bundle.zip",
                "size": None,
                "sha256": None,
            }
        )
    return {"artifacts": artifacts}


@router.get("/api/projects/{project_id}/scans/{run_id}/artifacts/{artifact_name}")
def project_scan_artifact(
    project_id: int,
    run_id: int,
    artifact_name: str,
    principal=Depends(require_role("viewer")),
):
    run = _authorized_scan(project_id, run_id, principal)
    report_dir = run_directory(
        SCANS_DIR,
        run["job_id"],
        tenant_id=run.get("tenant_id"),
        project_id=project_id,
    )
    if artifact_name == "report-bundle.zip":
        recorded = list_scan_artifacts(run_id)
        if not recorded or not any(item["name"] == "report.html" for item in recorded):
            raise HTTPException(status_code=404, detail="Report bundle is unavailable.")
        try:
            validate_artifact_sizes(
                (str(metadata.get("name", "artifact")), metadata["size"])
                for metadata in recorded
            )
        except (ArtifactLimitError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=413,
                detail="Report bundle exceeds configured artifact limits.",
            ) from exc
        artifact_sources: dict[str, ReportSource] = {}
        staged_s3_paths: list[Path] = []
        try:
            for metadata in recorded:
                if metadata.get("name") not in RUN_ARTIFACTS:
                    record_artifact_integrity_failure()
                    raise HTTPException(
                        status_code=409,
                        detail="Artifact integrity verification failed.",
                    )
                path = report_dir / metadata["name"]
                if metadata.get("backend") == "s3":
                    key = metadata.get("storage_key")
                    if not key or not _s3_artifact_key_is_valid(metadata, run, project_id):
                        record_artifact_integrity_failure()
                        raise HTTPException(
                            status_code=409,
                            detail="Artifact integrity verification failed.",
                        )
                    descriptor, temporary_name = tempfile.mkstemp(
                        prefix=f".s3-{metadata['name']}.",
                        suffix=".artifact",
                        dir=report_dir,
                    )
                    os.close(descriptor)
                    staged = Path(temporary_name)
                    staged_s3_paths.append(staged)
                    try:
                        S3ArtifactStore().download_verified(
                            str(key), metadata["size"], metadata["sha256"], staged
                        )
                    except (OSError, ResourceLimitError, TypeError, ValueError, KeyError) as exc:
                        record_artifact_integrity_failure()
                        raise HTTPException(
                            status_code=409,
                            detail="Artifact integrity verification failed.",
                        ) from exc
                    artifact_sources[metadata["name"]] = staged
                else:
                    if not _artifact_integrity(metadata, path):
                        record_artifact_integrity_failure()
                        raise HTTPException(
                            status_code=409,
                            detail="Artifact integrity verification failed.",
                        )
                    artifact_sources[metadata["name"]] = path
            return _stream_bundle_response(
                artifact_sources,
                filename=f"aegis-{project_id}-{run_id}.zip",
            )
        finally:
            for staged in staged_s3_paths:
                staged.unlink(missing_ok=True)
    media_type = RUN_ARTIFACTS.get(artifact_name)
    artifact_path = report_dir / artifact_name
    artifact_metadata = get_scan_artifact(run_id, artifact_name)
    if not media_type or not artifact_metadata:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    if artifact_metadata.get("backend") == "s3":
        try:
            validate_artifact_sizes(
                [(str(artifact_metadata.get("name", "artifact")), artifact_metadata["size"])]
            )
        except (ArtifactLimitError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=413, detail="Artifact exceeds configured size limit.") from exc
        if not _s3_artifact_key_is_valid(artifact_metadata, run, project_id):
            record_artifact_integrity_failure()
            raise HTTPException(
                status_code=409,
                detail="Artifact integrity verification failed.",
            )
        key = artifact_metadata.get("storage_key")
        if not key:
            record_artifact_integrity_failure()
            raise HTTPException(status_code=409, detail="Artifact integrity verification failed.")
        if int(artifact_metadata["size"]) > resource_budgets().max_response_bytes:
            raise HTTPException(status_code=413, detail="Response exceeds configured size limit.")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".s3-{artifact_name}.", suffix=".artifact", dir=report_dir
        )
        os.close(descriptor)
        staged = Path(temporary_name)
        try:
            S3ArtifactStore().download_verified(
                str(key), artifact_metadata["size"], artifact_metadata["sha256"], staged
            )
        except (OSError, ResourceLimitError, TypeError, ValueError, KeyError) as exc:
            staged.unlink(missing_ok=True)
            record_artifact_integrity_failure()
            raise HTTPException(
                status_code=409,
                detail="Artifact integrity verification failed.",
            ) from exc
        return _stream_file_response(
            staged,
            media_type=media_type,
            filename=artifact_name,
            cleanup=True,
            inline=artifact_name == "report.html",
        )
    if not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found.")
    if not _artifact_integrity(artifact_metadata, artifact_path):
        record_artifact_integrity_failure()
        raise HTTPException(status_code=409, detail="Artifact integrity verification failed.")
    return _stream_file_response(
        artifact_path,
        media_type=media_type,
        filename=artifact_name,
        inline=artifact_name == "report.html",
    )


@router.get(
    "/report",
    response_class=HTMLResponse,
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def get_report():
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        return HTMLResponse("<h1>Report not found</h1><p>Please run the security scans first.</p>", status_code=404)
    return _stream_file_response(
        report_path,
        media_type="text/html; charset=utf-8",
        filename="report.html",
    )

@router.get(
    "/download-sbom",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def download_sbom():
    sbom_path = SCANS_DIR / "sbom.json"
    if not sbom_path.exists():
        from policy_engine import generate_cyclonedx_sbom
        from ..dependencies import discover_dependency_manifests
        try:
            generate_cyclonedx_sbom(discover_dependency_manifests(PROJECT_ROOT), sbom_path)
        except Exception:
            logger.exception("SBOM generation failed")
            raise HTTPException(
                status_code=500, detail="SBOM generation failed. Check server logs."
            )
            
    return _stream_file_response(
        sbom_path,
        media_type="application/json",
        filename="cyclonedx-sbom.json",
    )


@router.get(
    "/download-report-bundle",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def download_report_bundle():
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report bundle is not available until a scan has completed.")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifacts = {
        path.name: path
        for path in SCANS_DIR.iterdir()
        if path.is_file()
    }
    return _stream_bundle_response(
        artifacts,
        filename=f"aegis-report-bundle-{timestamp}.zip",
    )


@router.get(
    "/export-dossier",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def export_dossier():
    report_path = SCANS_DIR / "report.md"
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="Dossier is not available until a scan has completed.")
    return _stream_file_response(
        report_path,
        media_type="text/markdown; charset=utf-8",
        filename="aegis-compliance-dossier.md",
    )
