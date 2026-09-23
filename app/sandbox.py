import os
import stat
from pathlib import Path

from .config import environment_positive_int

SCAN_MAX_FILES = environment_positive_int("AEGIS_SCAN_MAX_FILES", 100000)
SCAN_MAX_BYTES = environment_positive_int("AEGIS_SCAN_MAX_BYTES", 2 * 1024 * 1024 * 1024)


def validate_untrusted_tree(
    target_path: Path, *, ignored_names: set[str] | None = None
) -> dict:
    """Reject filesystem features that can escape or exhaust a scan workspace."""
    target = target_path.absolute()
    if target.is_symlink():
        raise RuntimeError("Scan targets may not be symbolic links.")
    if target.is_file():
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Scan targets must be regular files or directories.")
        if metadata.st_size > SCAN_MAX_BYTES:
            raise RuntimeError("Scan target exceeds the configured size limit.")
        return {"files": 1, "bytes": metadata.st_size}
    if not target.is_dir():
        raise RuntimeError("Scan target does not exist or is not a regular directory.")
    file_count = 0
    total_bytes = 0
    for root, directories, filenames in os.walk(target, followlinks=False):
        root_path = Path(root)
        for name in directories:
            child = root_path / name
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError("Scan targets may not contain symbolic links.")
            if not stat.S_ISDIR(metadata.st_mode):
                raise RuntimeError("Scan targets may contain only regular directories.")
        if ignored_names:
            directories[:] = [name for name in directories if name not in ignored_names]
        for name in filenames:
            child = root_path / name
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError("Scan targets may not contain symbolic links.")
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("Scan targets may contain only regular files.")
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > SCAN_MAX_FILES:
                raise RuntimeError("Scan target exceeds the configured file-count limit.")
            if total_bytes > SCAN_MAX_BYTES:
                raise RuntimeError("Scan target exceeds the configured size limit.")
    return {"files": file_count, "bytes": total_bytes}
