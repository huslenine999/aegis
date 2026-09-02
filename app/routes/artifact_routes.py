import hashlib
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from fastapi import APIRouter, Depends, HTTPException, Response
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
from ..reporting import ReportSource, load_json_report
from ..resource_budgets import ResourceLimitError, iter_file_bytes, resource_budgets
from ..web_common import RUN_ARTIFACTS, require_access, require_demo_boundary
from .project_routes import _authorized_scan
from policy_engine import analyze_report_set, evaluate_policy_results, get_ruff_severity

router = APIRouter()
logger = logging.getLogger("aegis.main")


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
):
    response_limit = resource_budgets().max_response_bytes
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Artifact not found.") from exc
    if size > response_limit:
        raise HTTPException(status_code=413, detail="Response exceeds configured size limit.")
    background = BackgroundTask(path.unlink, missing_ok=True) if cleanup else None
    return StreamingResponse(
        iter_file_bytes(path, max_bytes=response_limit),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
    if artifacts:
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
    reports = {
        name: load_json_report(SCANS_DIR / filename)
        for name, filename in {
            "ruff": "ruff-report.json",
            "semgrep": "semgrep-report.json",
            "safety": "safety-report.json",
            "osv": "osv-report.json",
            "trivy": "trivy-report.json",
            "secrets": "secrets-report.json",  # pragma: allowlist secret
            "yara": "yara-report.json",
            "clamav": "clamav-report.json",
            "zap": "zap-report.json",
            "iac": "iac-report.json",
        }.items()
    }
    results = analyze_report_set(reports)
    result_by_tool = {result["tool"]: result for result in results}

    def metrics(tool: str) -> tuple[str, int, int]:
        result = result_by_tool[tool]
        return result["status"], result["total_issues"], result["blocking_issues"]

    ruff_report = reports["ruff"]
    semgrep_report = reports["semgrep"]
    safety_report = reports["safety"]
    trivy_report = reports["trivy"]
    secrets_report = reports["secrets"]
    yara_report = reports["yara"]
    clamav_report = reports["clamav"]
    zap_report = reports["zap"]
    iac_report = reports["iac"]

    ruff_status, ruff_total, ruff_blocking = metrics("Ruff (SAST)")
    semgrep_status, semgrep_total, semgrep_blocking = metrics("Semgrep")
    safety_status, safety_total, safety_blocking = metrics("Safety")
    trivy_status, trivy_total, trivy_blocking = metrics("Trivy")
    secrets_status, secrets_total, secrets_blocking = metrics("Secrets Scanner")
    yara_status, yara_total, yara_blocking = metrics("YARA Scanner")
    clamav_status, clamav_total, clamav_blocking = metrics("ClamAV")
    zap_status, zap_total, zap_blocking = metrics("Aegis DAST Probe")
    iac_status, iac_total, iac_blocking = metrics("IaC")

    iac_findings_list = (
        [item for item in iac_report.get("findings", []) if isinstance(item, dict)]
        if isinstance(iac_report, dict)
        else []
    )
    iac_suppressions_list = (
        [
            item
            for item in iac_report.get("unmanaged_suppressions", [])
            if isinstance(item, dict)
        ]
        if isinstance(iac_report, dict)
        else []
    )

    decision = evaluate_policy_results(results)
    gate_decision = decision["status"]
    reason = decision["reason"]

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Format Ruff
    ruff_findings = ""
    if ruff_report and isinstance(ruff_report, list):
        for issue in ruff_report[:5]:
            code = issue.get('code', 'UNKNOWN')
            severity = get_ruff_severity(code)
            ruff_findings += f"  - ID: {code} | Severity: {severity}\n"
            ruff_findings += f"    Location: {issue.get('filename')}:{issue.get('location', {}).get('row')}\n"
            ruff_findings += f"    Details: {issue.get('message')}\n"
            ruff_findings += "  ------------------------------------------------------------------\n"
    else:
        ruff_findings = "  No issues detected.\n"

    # Format Semgrep
    semgrep_findings = ""
    if semgrep_report and semgrep_report.get("results"):
        for issue in semgrep_report.get("results", [])[:5]:
            extra = issue.get("extra", {})
            semgrep_findings += f"  - ID: {issue.get('check_id')} | Severity: {extra.get('severity')}\n"
            semgrep_findings += f"    Location: {issue.get('path')}:{issue.get('start', {}).get('line')}\n"
            semgrep_findings += f"    Details: {extra.get('message')}\n"
            code = extra.get('lines', '')
            if code:
                code_lines = code.strip().split('\n')
                semgrep_findings += "    Source:\n"
                for cl in code_lines[:3]:
                    semgrep_findings += f"      >> {cl}\n"
            semgrep_findings += "  ------------------------------------------------------------------\n"
    else:
        semgrep_findings = "  No issues detected.\n"

    # Format Safety
    safety_findings = ""
    if safety_report:
        vulns = []
        if isinstance(safety_report, dict):
            vulns = safety_report.get("vulnerabilities", []) or safety_report.get("results", [])
        elif isinstance(safety_report, list):
            vulns = safety_report
        
        if vulns:
            for v in vulns[:5]:
                pkg = v.get("package_name") or v.get("package")
                vuln_id = v.get("vulnerability_id") or v.get("advisory")
                affected = v.get("affected_versions") or v.get("version")
                fixed = v.get("fixed_versions") or v.get("fixed")
                desc = v.get("description") or v.get("reason", "No description provided.")
                safety_findings += f"  - Package: {pkg} | ID: {vuln_id}\n"
                safety_findings += f"    Affected: {affected} | Fixed: {fixed}\n"
                safety_findings += f"    Description: {desc[:120]}...\n"
                safety_findings += "  ------------------------------------------------------------------\n"
        else:
            safety_findings = "  No issues detected.\n"
    else:
        safety_findings = "  No report file found.\n"

    # Format Trivy
    trivy_findings = ""
    if trivy_report:
        trivy_vulns = []
        for result in trivy_report.get("Results", []) or []:
            for vulnerability in result.get("Vulnerabilities", []) or []:
                trivy_vulns.append({
                    "target": result.get("Target"),
                    "vulnerability_id": vulnerability.get("VulnerabilityID"),
                    "package_name": vulnerability.get("PkgName"),
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "severity": vulnerability.get("Severity", "").upper(),
                    "title": vulnerability.get("Title"),
                })
        if trivy_vulns:
            for v in trivy_vulns[:5]:
                trivy_findings += f"  - Target: {v.get('target')} | Package: {v.get('package_name')} | ID: {v.get('vulnerability_id')}\n"
                trivy_findings += f"    Severity: {v.get('severity')} | Installed: {v.get('installed_version')} | Fixed: {v.get('fixed_version')}\n"
                trivy_findings += f"    Title: {v.get('title')}\n"
                trivy_findings += "  ------------------------------------------------------------------\n"
        else:
            trivy_findings = "  No issues detected.\n"
    else:
        trivy_findings = "  No report file found.\n"

    # Format Secrets
    secrets_findings = ""
    if secrets_report:
        secrets_results = secrets_report.get("results", {}) or {}
        secrets_list = []
        for filename, file_secrets in secrets_results.items():
            for secret in file_secrets:
                secrets_list.append({
                    "type": secret.get("type"),
                    "filename": filename,
                    "line_number": secret.get("line_number")
                })
        if secrets_list:
            for s in secrets_list[:5]:
                secrets_findings += f"  - Type: {s.get('type')}\n"
                secrets_findings += f"    Location: {s.get('filename')}:{s.get('line_number')}\n"
                secrets_findings += "  ------------------------------------------------------------------\n"
        else:
            secrets_findings = "  No secrets detected.\n"
    else:
        secrets_findings = "  No report file found.\n"

    # Format YARA
    yara_findings_text = ""
    if yara_report:
        yara_list = yara_report if isinstance(yara_report, list) else []
        if yara_list:
            for y in yara_list[:5]:
                yara_findings_text += f"  - Rule matched: {y.get('rule')}\n"
                yara_findings_text += f"    Target File: {y.get('filename')}\n"
                yara_findings_text += f"    Description: {y.get('description')}\n"
                yara_findings_text += "  ------------------------------------------------------------------\n"
        else:
            yara_findings_text = "  No malicious signatures matched.\n"
    else:
        yara_findings_text = "  No report file found.\n"

    # Format ClamAV
    clamav_findings_text = ""
    if clamav_report:
        clamav_list = clamav_report if isinstance(clamav_report, list) else []
        if clamav_list:
            for c in clamav_list[:5]:
                clamav_findings_text += f"  - Virus matched: {c.get('virus')}\n"
                clamav_findings_text += f"    Target File: {c.get('filename')}\n"
                clamav_findings_text += f"    Description: {c.get('description')}\n"
                clamav_findings_text += "  ------------------------------------------------------------------\n"
        else:
            clamav_findings_text = "  No malware signatures matched.\n"
    else:
        clamav_findings_text = "  No report file found.\n"

    # Format IaC (Checkov)
    iac_findings_text = ""
    if iac_findings_list or iac_suppressions_list:
        for finding in [*iac_findings_list, *iac_suppressions_list][:10]:
            iac_findings_text += f"  - ID: {finding.get('rule_id')} | Severity: {finding.get('severity', 'MEDIUM')}\n"
            iac_findings_text += f"    Framework: {finding.get('framework')} | Resource: {finding.get('resource') or 'n/a'}\n"
            iac_findings_text += f"    Location: {finding.get('path') or 'n/a'}:{finding.get('start_line') or 1}-{finding.get('end_line') or finding.get('start_line') or 1}\n"
            iac_findings_text += f"    Remediation: {finding.get('remediation') or finding.get('comment') or finding.get('title') or 'Review the Checkov finding.'}\n"
            iac_findings_text += "  ------------------------------------------------------------------\n"
    elif iac_status == "MISSING":
        iac_findings_text = "  No report file found.\n"
    else:
        iac_findings_text = "  No IaC findings detected.\n"

    # Format ZAP
    zap_findings_text = ""
    if zap_report:
        zap_list = zap_report if isinstance(zap_report, list) else []
        if zap_list:
            for z in zap_list[:6]:
                zap_findings_text += f"  - Vulnerability: {z.get('vuln_type')} | Status: {z.get('status')}\n"
                zap_findings_text += f"    Route: {z.get('route')} | Payload: {z.get('payload')}\n"
                zap_findings_text += f"    Description: {z.get('description')}\n"
                zap_findings_text += "  ------------------------------------------------------------------\n"
        else:
            zap_findings_text = "  No active DAST endpoints scanned.\n"
    else:
        zap_findings_text = "  No report file found.\n"

    dossier_text = f"""================================================================================
  █████╗ ███████╗ ██████╗ ██╗███████╗
 ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
 ███████║█████╗  ██║  ███╗██║███████╗
 ██╔══██║██╔══╝  ██║   ██║██║╚════██║
 ██║  ██║███████╗╚██████╔╝██║███████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
       AEGIS DEVSECOPS COMPLIANCE DOSSIER
================================================================================
TIMESTAMP: {timestamp}
GATE DECISION: {gate_decision}
REASON: {reason}
================================================================================

[1] PYTHON SECURITY LINTER - RUFF (SAST)
--------------------------------------------------------------------------------
Status: {ruff_status}
Total Issues Detected: {ruff_total}
Blocking Issues: {ruff_blocking}

FINDINGS (Top 5):
{ruff_findings}

[1.5] ADVANCED STATIC ANALYSIS ENGINE - SEMGREP
--------------------------------------------------------------------------------
Status: {semgrep_status}
Total Issues Detected: {semgrep_total}
Blocking Issues: {semgrep_blocking}

FINDINGS (Top 5):
{semgrep_findings}

[2] SOFTWARE COMPOSITION ANALYSIS (SCA) - SAFETY
--------------------------------------------------------------------------------
Status: {safety_status}
Total Issues Detected: {safety_total}
Blocking Issues: {safety_blocking}

FINDINGS (Top 5):
{safety_findings}

[3] CONTAINER IMAGE SCANNING - TRIVY
--------------------------------------------------------------------------------
Status: {trivy_status}
Total Issues Detected: {trivy_total}
Blocking Issues: {trivy_blocking}

FINDINGS (Top 5):
{trivy_findings}

[4] SECRET SCANNER - DETECT-SECRETS
--------------------------------------------------------------------------------
Status: {secrets_status}
Total Issues Detected: {secrets_total}
Blocking Issues: {secrets_blocking}

FINDINGS (Top 5):
{secrets_findings}

[5] MALWARE & BACKDOOR SIGNATURES - YARA
--------------------------------------------------------------------------------
Status: {yara_status}
Total Issues Detected: {yara_total}
Blocking Issues: {yara_blocking}

FINDINGS (Top 5):
{yara_findings_text}

[6] MALWARE SIGNATURE ANALYSIS - CLAMAV
--------------------------------------------------------------------------------
Status: {clamav_status}
Total Issues Detected: {clamav_total}
Blocking Issues: {clamav_blocking}

FINDINGS (Top 5):
{clamav_findings_text}

[6.5] INFRASTRUCTURE-AS-CODE CONFIGURATION - CHECKOV
--------------------------------------------------------------------------------
Status: {iac_status}
Total Issues Detected: {iac_total}
Blocking Issues: {iac_blocking}

FINDINGS:
{iac_findings_text}

[7] DYNAMIC APPLICATION SECURITY TESTING (DAST) - AEGIS PROBE
--------------------------------------------------------------------------------
Status: {zap_status}
Total Issues Detected: {zap_total}
Blocking Issues: {zap_blocking}

FINDINGS:
{zap_findings_text}

================================================================================
                    [ END OF SECURE TRANSMISSION ]
================================================================================
"""
    return Response(
        content=dossier_text,
        media_type="text/plain",
        headers={
            "Content-Disposition": "attachment;filename=aegis-compliance-dossier.txt"
        }
    )
