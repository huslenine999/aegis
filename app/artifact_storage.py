import re
from pathlib import Path


SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


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
