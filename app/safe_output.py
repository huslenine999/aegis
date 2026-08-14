"""Filesystem boundary helpers for scan-generated output."""

from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any


class SafeOutputError(RuntimeError):
    """Raised when scan output would escape or corrupt its output root."""


class SafeOutputRoot:
    """Own and validate a directory used exclusively for generated scan output."""

    def __init__(self, root: str | Path):
        requested = Path(root).expanduser()
        if not requested.is_absolute():
            requested = Path.cwd() / requested
        if requested.is_symlink():
            raise SafeOutputError("Output roots may not be symbolic links.")
        try:
            requested.mkdir(parents=True, exist_ok=True)
            metadata = requested.lstat()
        except OSError as exc:
            raise SafeOutputError(f"Unable to create output root {requested}.") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise SafeOutputError("Output roots may not be symbolic links.")
        if not stat.S_ISDIR(metadata.st_mode):
            raise SafeOutputError("Output root must be a directory.")
        self.root = requested.resolve()

    @staticmethod
    def _parts(relative: str | Path) -> tuple[str, ...]:
        candidate = Path(relative)
        if candidate.is_absolute():
            raise SafeOutputError("Output paths must be relative to the output root.")
        parts = candidate.parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise SafeOutputError("Output paths must be relative and cannot contain '..'.")
        return parts

    def _validate(self, parts: tuple[str, ...], *, directory: bool = False) -> Path:
        candidate = self.root.joinpath(*parts)
        current = self.root
        for index, part in enumerate(parts):
            current /= part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise SafeOutputError(f"Unable to inspect output path {current}.") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise SafeOutputError("Output paths may not contain symbolic links.")
            if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                raise SafeOutputError("Output path parents must be directories.")
            if index == len(parts) - 1:
                if directory and not stat.S_ISDIR(metadata.st_mode):
                    raise SafeOutputError("Output directories must be directories.")
                if not directory and not stat.S_ISREG(metadata.st_mode):
                    raise SafeOutputError("Output files must be regular files.")
        try:
            candidate.resolve(strict=False).relative_to(self.root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise SafeOutputError("Output path must remain inside the output root.") from exc
        return candidate

    def directory(self, relative: str | Path) -> Path:
        parts = self._parts(relative)
        candidate = self._validate(parts, directory=True)
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SafeOutputError(f"Unable to create output directory {candidate}.") from exc
        self._validate(parts, directory=True)
        return candidate

    def file(self, relative: str | Path) -> Path:
        parts = self._parts(relative)
        if len(parts) > 1:
            self.directory(Path(*parts[:-1]))
        return self._validate(parts)

    def relative_path(self, path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        try:
            relative = candidate.relative_to(self.root)
        except ValueError as exc:
            raise SafeOutputError("Output path must remain inside the output root.") from exc
        self._parts(relative)
        return relative

    def file_path(self, path: str | Path) -> Path:
        return self.file(self.relative_path(path))

    def write_bytes(self, relative: str | Path, content: bytes) -> Path:
        target = self.file(relative)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        temporary_relative = temporary.relative_to(self.root)
        self.file(temporary_relative)
        try:
            temporary.write_bytes(content)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return target

    def write_text(
        self,
        relative: str | Path,
        content: str,
        *,
        encoding: str = "utf-8",
    ) -> Path:
        return self.write_bytes(relative, content.encode(encoding))

    def write_json(self, relative: str | Path, value: Any) -> Path:
        return self.write_text(
            relative,
            json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        )

    def write_json_path(self, path: str | Path, value: Any) -> Path:
        return self.write_json(self.relative_path(path), value)
