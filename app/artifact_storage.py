import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterable

from .resource_budgets import iter_bounded, resource_budgets


SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DEFAULT_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_ARTIFACT_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_REPORT_BUNDLE_BYTES = 64 * 1024 * 1024


class ArtifactLimitError(ValueError):
    """Raised when generated or downloaded evidence exceeds a configured budget."""


def _positive_limit(name: str, default: int) -> int:
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ArtifactLimitError(f"{name} must be a positive integer.") from exc
    if value < 1:
        raise ArtifactLimitError(f"{name} must be a positive integer.")
    return value


def artifact_limits() -> dict[str, int]:
    return {
        "per_artifact": _positive_limit(
            "AEGIS_MAX_ARTIFACT_BYTES", DEFAULT_MAX_ARTIFACT_BYTES
        ),
        "total": _positive_limit(
            "AEGIS_MAX_TOTAL_ARTIFACT_BYTES", DEFAULT_MAX_TOTAL_ARTIFACT_BYTES
        ),
        "bundle": _positive_limit(
            "AEGIS_MAX_REPORT_BUNDLE_BYTES", DEFAULT_MAX_REPORT_BUNDLE_BYTES
        ),
    }


def validate_artifact_sizes(artifacts: Iterable[tuple[str, int]]) -> int:
    """Validate per-artifact and per-run evidence sizes before reading or publishing."""
    limits = artifact_limits()
    total = 0
    for name, raw_size in artifacts:
        try:
            size = int(raw_size)
        except (TypeError, ValueError) as exc:
            raise ArtifactLimitError(f"Artifact {name!r} has an invalid size.") from exc
        if size < 0:
            raise ArtifactLimitError(f"Artifact {name!r} has an invalid size.")
        if size > limits["per_artifact"]:
            raise ArtifactLimitError(
                f"Artifact {name!r} exceeds the per-artifact limit of "
                f"{limits['per_artifact']} bytes."
            )
        total += size
        if total > limits["total"]:
            raise ArtifactLimitError(
                f"Artifacts exceed the total per-run limit of {limits['total']} bytes."
            )
    return total


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

    def iter_bytes(
        self,
        key: str,
        *,
        max_bytes: int | None = None,
        chunk_size: int | None = None,
    ) -> Iterable[bytes]:
        """Stream an object while enforcing an actual-read response budget."""

        limit = (
            resource_budgets().max_response_bytes
            if max_bytes is None
            else max_bytes
        )
        body = self.open(key)
        try:
            yield from iter_bounded(body, limit, chunk_size=chunk_size)
        finally:
            close = getattr(body, "close", None)
            if close:
                close()

    def read(self, key: str, *, max_bytes: int | None = None) -> bytes:
        return b"".join(self.iter_bytes(key, max_bytes=max_bytes))

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
    candidates: list[tuple[str, Path, int]] = []
    for name in sorted(names):
        path = report_dir / name
        if not path.is_file():
            continue
        if path.is_symlink():
            raise RuntimeError("Artifact paths must not be symbolic links.")
        candidates.append((name, path, path.stat().st_size))
    limits = artifact_limits()
    validate_artifact_sizes((name, size) for name, _, size in candidates)

    artifacts = []
    actual_total = 0
    for name, path, size in candidates:
        digest = hashlib.sha256()
        actual_size = 0
        with path.open("rb") as artifact:
            for chunk in iter_bounded(
                artifact,
                limits["per_artifact"],
                chunk_size=1024 * 1024,
            ):
                actual_size += len(chunk)
                digest.update(chunk)
        if actual_size != size:
            raise ArtifactLimitError(
                f"Artifact {name!r} changed while it was being published."
            )
        actual_total += actual_size
        if actual_total > limits["total"]:
            raise ArtifactLimitError(
                f"Artifacts exceed the total per-run limit of {limits['total']} bytes."
            )
        sha256 = digest.hexdigest()
        key = artifact_key(tenant_id, project_id, job_id, name)
        if store:
            store.put(path, key, sha256)
        artifacts.append(
            {
                "name": name,
                "size": size,
                "sha256": sha256,
                "backend": backend,
                "storage_key": key if store else None,
            }
        )
    return artifacts
