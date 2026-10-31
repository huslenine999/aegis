import json
import logging
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .artifact_storage import (
    SAFE_ARTIFACT_NAME,
    ArtifactLimitError,
    artifact_limits,
    validate_artifact_sizes,
)
from .resource_budgets import (
    ResourceLimitError,
    iter_file_bytes,
    load_bounded_json,
    resource_budgets,
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


ReportSource = bytes | Path | Callable[[], Iterable[bytes]]


def _selected_bundle_sources(
    artifacts: Mapping[str, ReportSource],
    *,
    include_all: bool = False,
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
    raw_patterns = ("*-report.json", "codeql.sarif", "osv-cache.json", "sandbox-status.json")
    added: set[str] = set()
    selected: list[tuple[str, str, ReportSource]] = []

    for filename in artifacts:
        if not SAFE_ARTIFACT_NAME.fullmatch(filename):
            raise ArtifactLimitError(f"Invalid artifact name: {filename!r}.")

    if include_all:
        return [(filename, filename, artifacts[filename]) for filename in sorted(artifacts)]

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
    *,
    include_all: bool = False,
) -> None:
    """Build a bounded ZIP incrementally and atomically publish it."""

    limits = artifact_limits()
    budgets = resource_budgets()
    selected = _selected_bundle_sources(artifacts, include_all=include_all)
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
