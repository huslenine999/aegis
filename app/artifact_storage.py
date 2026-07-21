import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO


SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def run_directory(
    scans_root: Path,
    job_id: str,
    *,
    tenant_id: int | None = None,
    project_id: int | None = None,
    create: bool = False,
) -> Path:
    """Resolve a run under an explicit tenant/project namespace.

    Existing unscoped runs remain readable for upgrades, but all new project
    runs are written to tenant-scoped paths.
    """
    if not SAFE_JOB_ID.fullmatch(str(job_id)):
        raise ValueError("Invalid scan job identifier.")
    root = scans_root.resolve()
    if tenant_id is not None and project_id is not None:
        scoped = (
            root
            / "tenants"
            / str(int(tenant_id))
            / "projects"
            / str(int(project_id))
            / "runs"
            / str(job_id)
        )
        if create or scoped.exists():
            resolved = scoped.resolve()
            if root not in resolved.parents:
                raise ValueError("Artifact path escaped the storage root.")
            return resolved
    legacy = (root / "runs" / str(job_id)).resolve()
    if root not in legacy.parents:
        raise ValueError("Artifact path escaped the storage root.")
    return legacy


def project_directory(scans_root: Path, tenant_id: int, project_id: int) -> Path:
    root = scans_root.resolve()
    path = (root / "tenants" / str(int(tenant_id)) / "projects" / str(int(project_id))).resolve()
    if root not in path.parents:
        raise ValueError("Artifact path escaped the storage root.")
    return path


def artifact_key(tenant_id: int, project_id: int, job_id: str, name: str) -> str:
    if not SAFE_JOB_ID.fullmatch(str(job_id)) or not SAFE_ARTIFACT_NAME.fullmatch(name):
        raise ValueError("Invalid artifact identity.")
    prefix = os.environ.get("AEGIS_S3_PREFIX", "aegis").strip("/")
    return "/".join(
        part for part in (
            prefix,
            "tenants", str(int(tenant_id)), "projects", str(int(project_id)),
            "runs", job_id, name,
        ) if part
    )


class S3ArtifactStore:
    """Private S3-compatible evidence storage with integrity metadata."""

    def __init__(self, client=None):
        self.bucket = os.environ.get("AEGIS_S3_BUCKET", "").strip()
        if not self.bucket:
            raise RuntimeError("AEGIS_S3_BUCKET is required for the S3 artifact backend.")
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise RuntimeError(
                    "The boto3 runtime dependency is required for S3 artifacts."
                ) from exc
            options = {
                "region_name": os.environ.get("AEGIS_S3_REGION") or None,
                "endpoint_url": os.environ.get("AEGIS_S3_ENDPOINT_URL") or None,
            }
            client = boto3.client("s3", **{k: v for k, v in options.items() if v})
        self.client = client

    def put(self, path: Path, key: str, sha256: str) -> None:
        extra: dict = {
            "Metadata": {"sha256": sha256},
            "ServerSideEncryption": "AES256",
        }
        kms_key = os.environ.get("AEGIS_S3_KMS_KEY_ID", "").strip()
        if kms_key:
            extra.update(
                {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": kms_key}
            )
        retention_days = int(os.environ.get("AEGIS_S3_OBJECT_LOCK_DAYS", "0") or 0)
        if retention_days > 0:
            extra.update(
                {
                    "ObjectLockMode": "GOVERNANCE",
                    "ObjectLockRetainUntilDate": datetime.now(timezone.utc)
                    + timedelta(days=retention_days),
                }
            )
        self.client.upload_file(str(path), self.bucket, key, ExtraArgs=extra)

    def open(self, key: str) -> BinaryIO:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"]

    def read(self, key: str) -> bytes:
        body = self.open(key)
        try:
            return body.read()
        finally:
            close = getattr(body, "close", None)
            if close:
                close()

    def verify(self, key: str, expected_size: int, expected_sha256: str) -> bool:
        response = self.client.head_object(Bucket=self.bucket, Key=key)
        metadata = response.get("Metadata") or {}
        return (
            int(response.get("ContentLength", -1)) == int(expected_size)
            and metadata.get("sha256") == expected_sha256
        )


def publish_artifacts(
    report_dir: Path,
    names: set[str],
    *,
    tenant_id: int,
    project_id: int,
    job_id: str,
) -> list[dict]:
    backend = os.environ.get("AEGIS_ARTIFACT_BACKEND", "local").strip().lower()
    if backend not in {"local", "s3"}:
        raise RuntimeError("AEGIS_ARTIFACT_BACKEND must be local or s3.")
    store = S3ArtifactStore() if backend == "s3" else None
    artifacts = []
    for name in sorted(names):
        path = report_dir / name
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
        sha256 = digest.hexdigest()
        key = artifact_key(tenant_id, project_id, job_id, name)
        if store:
            store.put(path, key, sha256)
        artifacts.append(
            {
                "name": name,
                "size": path.stat().st_size,
                "sha256": sha256,
                "backend": backend,
                "storage_key": key if store else None,
            }
        )
    return artifacts
