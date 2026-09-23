import os
import pytest

from app.sandbox import validate_untrusted_tree


def test_untrusted_tree_rejects_symlinks_and_reports_workspace_size(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('safe')\n")
    assert validate_untrusted_tree(target) == {
        "files": 1,
        "bytes": (target / "app.py").stat().st_size,
    }

    (target / "escape").symlink_to(tmp_path / "outside")
    with pytest.raises(RuntimeError, match="symbolic links"):
        validate_untrusted_tree(target)


def test_untrusted_tree_rejects_ignored_symlinks_and_special_files(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (target / ".venv").symlink_to(runtime, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symbolic links"):
        validate_untrusted_tree(target, ignored_names={".venv"})

    (target / ".venv").unlink()
    os.mkfifo(target / ".venv")
    with pytest.raises(RuntimeError, match="regular files"):
        validate_untrusted_tree(target, ignored_names={".venv"})
