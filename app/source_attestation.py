"""Canonical source descriptors and immutable scan snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .sandbox import validate_untrusted_tree
from .resource_budgets import load_bounded_json


SOURCE_DESCRIPTOR_SCHEMA = 1
SOURCE_ATTESTATION_SCHEMA = 1
REPORT_PATH_KEYS = frozenset({"file", "file_path", "filename", "path", "target_path"})


class SourceAttestationError(RuntimeError):
    """Raised when a source cannot be admitted to a stable scan snapshot."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_file(path: Path) -> tuple[str, int, int]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SourceAttestationError(f"Unable to inspect source file {path}.") from exc
    if not stat.S_ISREG(before.st_mode):
        raise SourceAttestationError("Source snapshots may contain only regular files.")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise SourceAttestationError(f"Unable to read source file {path}.") from exc

    try:
        after = path.lstat()
    except OSError as exc:
        raise SourceAttestationError(f"Source file disappeared while reading: {path}.") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise SourceAttestationError(f"Source file changed while reading: {path}.")
    if size != after.st_size:
        raise SourceAttestationError(f"Source file changed while reading: {path}.")
    return digest.hexdigest(), size, stat.S_IMODE(before.st_mode)


def _reject_unsupported_entry(path: Path, *, directory: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceAttestationError(f"Unable to inspect source path {path}.") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise SourceAttestationError("Source snapshots may not contain symbolic links.")
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise SourceAttestationError("Source snapshots may contain only regular directories.")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise SourceAttestationError("Source snapshots may contain only regular files.")


def _path_is_excluded(path: Path, source_root: Path, excluded_paths: Iterable[str]) -> bool:
    for raw_value in excluded_paths:
        raw = Path(str(raw_value)).expanduser()
        candidate = raw if raw.is_absolute() else source_root / raw
        try:
            if path == candidate.resolve(strict=False) or candidate.resolve(strict=False) in path.parents:
                return True
        except (OSError, RuntimeError):
            continue
    return False


def _collect_descriptor(
    source_path: Path,
    *,
    ignored_names: set[str],
    excluded_paths: Iterable[str],
) -> dict[str, Any]:
    source = source_path.expanduser().absolute()
    if source.is_symlink():
        raise SourceAttestationError("Source snapshots may not contain symbolic links.")
    if not source.exists():
        raise SourceAttestationError(f"Source path does not exist: {source}")
    source = source.resolve()
    try:
        validate_untrusted_tree(source, ignored_names=ignored_names)
    except RuntimeError as exc:
        raise SourceAttestationError(str(exc)) from exc

    entries: list[dict[str, Any]] = []
    if source.is_file():
        digest, size, mode = _sha256_file(source)
        entries.append(
            {"mode": mode, "path": source.name, "sha256": digest, "size": size}
        )
    else:
        for root, directories, filenames in os.walk(source, followlinks=False):
            root_path = Path(root)
            for name in directories:
                _reject_unsupported_entry(root_path / name, directory=True)
            directories[:] = [name for name in directories if name not in ignored_names]
            for name in filenames:
                candidate = root_path / name
                _reject_unsupported_entry(candidate, directory=False)
                if _path_is_excluded(candidate, source, excluded_paths):
                    continue
                digest, size, mode = _sha256_file(candidate)
                relative = candidate.relative_to(source).as_posix()
                entries.append(
                    {"mode": mode, "path": relative, "sha256": digest, "size": size}
                )

    entries.sort(key=lambda item: item["path"])
    return {
        "schema_version": SOURCE_DESCRIPTOR_SCHEMA,
        "root_kind": "file" if source.is_file() else "directory",
        "files": entries,
        "file_count": len(entries),
        "total_bytes": sum(int(item["size"]) for item in entries),
    }


def _descriptor_digests(descriptor: dict[str, Any]) -> tuple[str, str]:
    descriptor_digest = hashlib.sha256(_canonical_json(descriptor)).hexdigest()
    content_digest = hashlib.sha256(
        _canonical_json(
            {
                "schema_version": SOURCE_DESCRIPTOR_SCHEMA,
                "files": [
                    {
                        "path": item["path"],
                        "sha256": item["sha256"],
                        "size": item["size"],
                    }
                    for item in descriptor["files"]
                ],
            }
        )
    ).hexdigest()
    return descriptor_digest, content_digest


def _copy_regular_file(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
        with os.fdopen(source_fd, "rb") as source_stream, destination.open("wb") as destination_stream:
            shutil.copyfileobj(source_stream, destination_stream, length=1024 * 1024)
        os.chmod(destination, mode)
    except OSError as exc:
        raise SourceAttestationError(f"Unable to copy source file {source}.") from exc


@dataclass(frozen=True)
class SourceSnapshot:
    source_path: Path
    scan_path: Path
    descriptor: dict[str, Any]
    descriptor_sha256: str
    content_sha256: str
    excluded_paths: frozenset[str]

    @property
    def file_count(self) -> int:
        return int(self.descriptor["file_count"])

    @property
    def total_bytes(self) -> int:
        return int(self.descriptor["total_bytes"])

    def cleanup(self) -> None:
        root = self.scan_path if self.source_path.is_file() else self.scan_path
        snapshot_root = root.parent if self.descriptor["root_kind"] == "file" else root
        shutil.rmtree(snapshot_root, ignore_errors=True)

    def manifest_source(
        self,
        *,
        identity: str,
        revision: str,
        policy_sha256: str,
        branch: str | None = None,
    ) -> dict[str, Any]:
        source: dict[str, Any] = {
            "identity": identity,
            "revision": revision,
            "attestation": {
                "schema_version": SOURCE_ATTESTATION_SCHEMA,
                "status": "source-bound",
                "method": "stable-copy",
                "descriptor_sha256": self.descriptor_sha256,
                "content_sha256": self.content_sha256,
                "policy_sha256": policy_sha256,
                "file_count": self.file_count,
                "total_bytes": self.total_bytes,
            },
        }
        if branch is not None:
            source["branch"] = branch
        return source

    def map_excluded_paths(self, excluded_paths: Iterable[str]) -> frozenset[str]:
        mapped: set[str] = set()
        source_base = self.source_path.parent if self.descriptor["root_kind"] == "file" else self.source_path
        for value in excluded_paths:
            raw = Path(str(value)).expanduser()
            candidate = raw if raw.is_absolute() else source_base / raw
            try:
                relative = candidate.resolve(strict=False).relative_to(source_base)
            except (OSError, RuntimeError, ValueError):
                mapped.add(str(value))
                continue
            mapped.add(str(relative))
            mapped.add(str(self.scan_path.parent / relative) if self.descriptor["root_kind"] == "file" else str(self.scan_path / relative))
        return frozenset(mapped)

    def source_path_for_snapshot_value(self, value: str) -> str:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            return value
        snapshot_base = self.scan_path.parent if self.descriptor["root_kind"] == "file" else self.scan_path
        try:
            relative = candidate.resolve(strict=False).relative_to(snapshot_base)
        except (OSError, RuntimeError, ValueError):
            return value
        if self.descriptor["root_kind"] == "file":
            if relative != Path(self.scan_path.name):
                return value
            return str(self.source_path)
        return str(self.source_path / relative)


def create_source_snapshot(
    source_path: str | Path,
    *,
    ignored_names: set[str] | None = None,
    excluded_paths: Iterable[str] = (),
) -> SourceSnapshot:
    source = Path(source_path).expanduser().absolute()
    ignored = set(ignored_names or set())
    excluded = tuple(str(value) for value in excluded_paths)
    descriptor = _collect_descriptor(
        source,
        ignored_names=ignored,
        excluded_paths=excluded,
    )
    descriptor_sha256, content_sha256 = _descriptor_digests(descriptor)
    snapshot_root = Path(tempfile.mkdtemp(prefix="aegis-source-")).resolve()
    scan_path = snapshot_root / source.name if descriptor["root_kind"] == "file" else snapshot_root
    try:
        for item in descriptor["files"]:
            relative = Path(item["path"])
            source_file = source if descriptor["root_kind"] == "file" else source / relative
            destination = scan_path if descriptor["root_kind"] == "file" else scan_path / relative
            _copy_regular_file(source_file, destination, int(item["mode"]))

        snapshot_descriptor = _collect_descriptor(
            scan_path,
            ignored_names=set(),
            excluded_paths=(),
        )
        if _canonical_json(snapshot_descriptor) != _canonical_json(descriptor):
            raise SourceAttestationError("Source changed while creating the stable snapshot.")
        current_descriptor = _collect_descriptor(
            source,
            ignored_names=ignored,
            excluded_paths=excluded,
        )
        if _canonical_json(current_descriptor) != _canonical_json(descriptor):
            raise SourceAttestationError("Source changed while creating the stable snapshot.")
    except Exception:
        shutil.rmtree(snapshot_root, ignore_errors=True)
        raise

    return SourceSnapshot(
        source_path=source.resolve(),
        scan_path=scan_path,
        descriptor=descriptor,
        descriptor_sha256=descriptor_sha256,
        content_sha256=content_sha256,
        excluded_paths=frozenset(),
    )


def normalize_scan_report_paths(
    scan_dir: Path,
    snapshot: SourceSnapshot,
    safe_output,
) -> None:
    """Translate scanner paths from the immutable snapshot back to the source."""
    report_names = (
        "ruff-report.json",
        "semgrep-report.json",
        "safety-report.json",
        "osv-report.json",
        "trivy-report.json",
        "secrets-report.json",
        "yara-report.json",
        "clamav-report.json",
        "zap-report.json",
        "iac-report.json",
    )

    def normalize(value: Any, key: str | None = None) -> Any:
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, dict):
            normalized_items = {}
            for name, item in value.items():
                normalized_name = (
                    snapshot.source_path_for_snapshot_value(name)
                    if isinstance(name, str)
                    else name
                )
                normalized_items[normalized_name] = normalize(item, name)
            return normalized_items
        if key in REPORT_PATH_KEYS and isinstance(value, str):
            return snapshot.source_path_for_snapshot_value(value)
        return value

    for name in report_names:
        path = safe_output.file(name)
        if not path.exists():
            continue
        try:
            payload = load_bounded_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            continue
        normalized = normalize(payload)
        if normalized != payload:
            safe_output.write_json(name, normalized)
