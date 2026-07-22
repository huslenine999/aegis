import tempfile
from pathlib import Path

from app import scanners
from app.scanners import configure_semgrep_environment


def test_semgrep_runtime_files_use_writable_temp_directory():
    environment = {}

    configure_semgrep_environment(environment)

    temp_dir = Path(tempfile.gettempdir())
    assert environment["SEMGREP_SETTINGS_FILE"] == str(
        temp_dir / "aegis-semgrep-settings.yml"
    )
    assert environment["SEMGREP_LOG_FILE"] == str(temp_dir / "aegis-semgrep.log")


def test_runtime_executable_falls_back_to_active_python_environment(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    semgrep = bin_dir / "semgrep"
    python.touch()
    semgrep.touch()
    semgrep.chmod(0o755)
    monkeypatch.setattr(scanners.shutil, "which", lambda name: None)

    assert scanners.find_runtime_executable("semgrep", str(python)) == str(semgrep)


def test_runtime_executable_ignores_non_executable_adjacent_file(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    semgrep = bin_dir / "semgrep"
    python.touch()
    semgrep.touch()
    monkeypatch.setattr(scanners.shutil, "which", lambda name: None)

    assert scanners.find_runtime_executable("semgrep", str(python)) is None


def test_runtime_executable_prefers_path(monkeypatch):
    monkeypatch.setattr(
        scanners.shutil, "which", lambda name: f"/usr/local/bin/{name}"
    )

    assert scanners.find_runtime_executable("semgrep") == "/usr/local/bin/semgrep"
