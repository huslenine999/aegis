import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .artifact_storage import (
    SAFE_ARTIFACT_NAME,
    ArtifactLimitError,
    artifact_limits,
    validate_artifact_sizes,
)
from .dependencies import discover_dependency_manifests, first_requirements_manifest
from .resource_budgets import (
    ResourceLimitError,
    iter_file_bytes,
    load_bounded_json,
    read_bounded_text,
    read_bounded,
    resource_budgets,
    run_bounded_subprocess,
)
from policy_engine import (
    analyze_report_set,
    calculate_exploitability_score as calculate_policy_exploitability_score,
)


logger = logging.getLogger("aegis.reporting")


def extract_json_values(data):
    if isinstance(data, dict):
        parts = []
        for key, value in data.items():
            parts.append(str(key))
            parts.append(extract_json_values(value))
        return " ".join(parts)
    if isinstance(data, list):
        return " ".join(extract_json_values(item) for item in data)
    return str(data)


def load_json_report(path: Path):
    if not path.exists():
        return None
    try:
        return load_bounded_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("Unable to read scanner report %s: %s", path, exc)
        return None


def calculate_exploitability_score(scans_dir: Path, waf_enabled: bool) -> float:

    reports = {
        name: load_json_report(scans_dir / f"{filename}-report.json")
        for name, filename in {
            "ruff": "ruff",
            "semgrep": "semgrep",
            "safety": "safety",
            "trivy": "trivy",
            "secrets": "secrets",  # pragma: allowlist secret
            "yara": "yara",
            "clamav": "clamav",
            "zap": "zap",
            "osv": "osv",
            "iac": "iac",
        }.items()
    }
    results = analyze_report_set(reports)
    return calculate_policy_exploitability_score(results, waf_enabled)


def generate_fallback_tree(project_root: Path) -> list[dict]:
    requirements_manifest = first_requirements_manifest(discover_dependency_manifests(project_root))
    tree: list[dict] = []
    if requirements_manifest:
        try:
            content = read_bounded_text(requirements_manifest.path)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(==|>=)\s*([a-zA-Z0-9_\-\.]+)", line)
                if match:
                    package_name = match.group(1)
                    package_version = match.group(3)
                    tree.append({
                        "key": package_name.lower(),
                        "package_name": package_name,
                        "installed_version": package_version,
                        "required_version": f"=={package_version}",
                        "dependencies": [],
                    })
        except OSError as exc:
            logger.warning(
                "Unable to build dependency fallback from %s: %s",
                requirements_manifest.path,
                exc,
            )
    return tree


def load_dependency_tree(project_root: Path) -> list[dict]:
    try:
        python_bin = sys.executable
        pipdeptree_bin = Path(python_bin).parent / "pipdeptree"
        if not pipdeptree_bin.exists():
            pipdeptree_cmd = [python_bin, "-m", "pipdeptree", "--json-tree"]
        else:
            pipdeptree_cmd = [str(pipdeptree_bin), "--json-tree"]

        output = BytesIO()
        result = run_bounded_subprocess(
            pipdeptree_cmd,
            stdout_sink=output,
            timeout=30,
        )
        if result.returncode == 0:
            return json.loads(output.getvalue().decode("utf-8"))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ResourceLimitError) as exc:
        logger.warning("Unable to load dependency tree with pipdeptree: %s", exc)
    return generate_fallback_tree(project_root)


ReportSource = bytes | Path | Callable[[], Iterable[bytes]]


def _selected_bundle_sources(
    artifacts: Mapping[str, ReportSource],
) -> list[tuple[str, str, ReportSource]]:
    preferred_files = [
        "report.html",
        "report.md",
        "aegis.sarif",
        "sbom.json",
        "scan-manifest.json",
        "source-descriptor.json",
        "suppressions-report.json",
    ]
    raw_patterns = ("*-report.json", "osv-cache.json", "sandbox-status.json")
    added: set[str] = set()
    selected: list[tuple[str, str, ReportSource]] = []

    for filename in artifacts:
        if not SAFE_ARTIFACT_NAME.fullmatch(filename):
            raise ArtifactLimitError(f"Invalid artifact name: {filename!r}.")

    for filename in preferred_files:
        if filename in artifacts:
            selected.append((filename, filename, artifacts[filename]))
            added.add(filename)

    for pattern in raw_patterns:
        for filename in sorted(artifacts):
            if Path(filename).match(pattern) and filename not in added:
                selected.append((filename, f"raw/{filename}", artifacts[filename]))
                added.add(filename)
    return selected


def _source_chunks(
    source: ReportSource,
    per_artifact_limit: int,
    *,
    enforce_limit: bool = True,
) -> Iterable[bytes]:
    if isinstance(source, bytes):
        if enforce_limit and len(source) > per_artifact_limit:
            raise ArtifactLimitError(
                f"Artifact exceeds the per-artifact limit of {per_artifact_limit} bytes."
            )
        yield source
        return
    if isinstance(source, Path):
        if source.is_symlink():
            raise RuntimeError("Artifact paths must not be symbolic links.")
        yield from iter_file_bytes(source, max_bytes=per_artifact_limit)
        return
    yield from source()


def build_report_bundle_to_path(
    artifacts: Mapping[str, ReportSource],
    destination: Path,
) -> None:
    """Build a bounded ZIP incrementally and atomically publish it."""

    limits = artifact_limits()
    budgets = resource_budgets()
    selected = _selected_bundle_sources(artifacts)
    if len(selected) + 1 > budgets.max_zip_entries:
        raise ResourceLimitError(
            f"Report bundle exceeds the configured ZIP entry limit of "
            f"{budgets.max_zip_entries}."
        )

    known_sizes: list[tuple[str, int]] = []
    for name, _, source in selected:
        if isinstance(source, bytes):
            known_sizes.append((name, len(source)))
        elif isinstance(source, Path):
            known_sizes.append((name, source.stat().st_size))
    validate_artifact_sizes(known_sizes)

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(temporary_fd)
    temporary_path = Path(temporary_name)
    total_artifact_bytes = 0
    total_uncompressed_bytes = 0

    def write_entry(
        archive: zipfile.ZipFile,
        entry_name: str,
        source: ReportSource,
        *,
        counts_as_artifact: bool,
    ) -> None:
        nonlocal total_artifact_bytes, total_uncompressed_bytes
        entry_bytes = 0
        with archive.open(entry_name, "w") as entry:
            for chunk in _source_chunks(
                source,
                limits["per_artifact"],
                enforce_limit=counts_as_artifact,
            ):
                if not isinstance(chunk, bytes):
                    chunk = bytes(chunk)
                entry_bytes += len(chunk)
                if counts_as_artifact and entry_bytes > limits["per_artifact"]:
                    raise ArtifactLimitError(
                        f"Artifact {entry_name!r} exceeds the per-artifact limit of "
                        f"{limits['per_artifact']} bytes."
                    )
                if counts_as_artifact:
                    total_artifact_bytes += len(chunk)
                    if total_artifact_bytes > limits["total"]:
                        raise ArtifactLimitError(
                            f"Artifacts exceed the total per-run limit of "
                            f"{limits['total']} bytes."
                        )
                total_uncompressed_bytes += len(chunk)
                if total_uncompressed_bytes > budgets.max_zip_uncompressed_bytes:
                    raise ResourceLimitError(
                        "Report bundle exceeds the configured ZIP uncompressed-size limit."
                    )
                entry.write(chunk)

    try:
        with temporary_path.open("w+b") as bundle_file:
            with zipfile.ZipFile(bundle_file, "w", zipfile.ZIP_DEFLATED) as archive:
                for _, entry_name, source in selected:
                    write_entry(archive, entry_name, source, counts_as_artifact=True)
                manifest = {
                    "bundle_format": "aegis-report-bundle-v1",
                    "included_files": [entry_name for _, entry_name, _ in selected],
                }
                manifest_content = (json.dumps(manifest, indent=2) + "\n").encode()
                write_entry(
                    archive,
                    "bundle-manifest.json",
                    manifest_content,
                    counts_as_artifact=False,
                )
        if temporary_path.stat().st_size > limits["bundle"]:
            raise ArtifactLimitError(
                f"Report bundle exceeds the configured limit of {limits['bundle']} bytes."
            )
        os.replace(temporary_path, destination)
    finally:
        temporary_path.unlink(missing_ok=True)


def build_report_bundle(scans_dir: Path) -> bytes:
    paths: dict[str, Path] = {}
    for path in scans_dir.iterdir():
        if path.is_symlink():
            raise RuntimeError("Artifact paths must not be symbolic links.")
        if path.is_file():
            paths[path.name] = path
    return _build_report_bundle_bytes(paths)


def _build_report_bundle_bytes(artifacts: Mapping[str, ReportSource]) -> bytes:
    with tempfile.TemporaryDirectory(prefix="aegis-bundle-") as temporary_dir:
        bundle_path = Path(temporary_dir) / "report-bundle.zip"
        build_report_bundle_to_path(artifacts, bundle_path)
        with bundle_path.open("rb") as bundle_file:
            return read_bounded(bundle_file, artifact_limits()["bundle"])


def build_report_bundle_from_artifacts(artifacts: dict[str, bytes]) -> bytes:
    return _build_report_bundle_bytes(artifacts)
