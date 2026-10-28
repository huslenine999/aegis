import io
import tarfile

import pytest

from app import scanner_sandbox
from app.scanner_sandbox import ScannerSandboxError, run_in_sandbox, sandbox_enabled

IMAGE = "aegis-scanner@sha256:" + "a" * 64


def _provision(monkeypatch, tmp_path):
    socket_path = tmp_path / "docker.sock"
    socket_path.touch()
    monkeypatch.setenv("AEGIS_SCANNER_IMAGE", IMAGE)
    monkeypatch.setenv("AEGIS_CODEQL_DOCKER_HOST", f"unix://{socket_path}")
    monkeypatch.setattr(scanner_sandbox.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(scanner_sandbox.stat, "S_ISSOCK", lambda mode: True)


def test_sandbox_is_off_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_SANDBOX_SCANNERS", raising=False)
    assert not sandbox_enabled()
    monkeypatch.setenv("AEGIS_SANDBOX_SCANNERS", "true")
    assert sandbox_enabled()


@pytest.mark.parametrize("image", ["", "aegis-scanner:latest", "aegis-scanner@sha256:abc"])
def test_unpinned_image_fails_closed(monkeypatch, tmp_path, image):
    monkeypatch.setenv("AEGIS_SCANNER_IMAGE", image)
    with pytest.raises(ScannerSandboxError, match="Pinned scanner image"):
        run_in_sandbox(["ruff"], tmp_path, tmp_path / "out.json", timeout=5)


def test_missing_docker_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_SCANNER_IMAGE", IMAGE)
    monkeypatch.setattr(scanner_sandbox.shutil, "which", lambda name: None)
    with pytest.raises(ScannerSandboxError, match="Docker CLI"):
        run_in_sandbox(["ruff"], tmp_path, tmp_path / "out.json", timeout=5)


def test_missing_socket_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_SCANNER_IMAGE", IMAGE)
    monkeypatch.setenv("AEGIS_CODEQL_DOCKER_HOST", f"unix://{tmp_path}/absent.sock")
    monkeypatch.setattr(scanner_sandbox.shutil, "which", lambda name: "/usr/bin/docker")
    with pytest.raises(ScannerSandboxError, match="socket"):
        run_in_sandbox(["ruff"], tmp_path, tmp_path / "out.json", timeout=5)


def test_unmountable_target_path_fails_closed(monkeypatch, tmp_path):
    _provision(monkeypatch, tmp_path)
    odd = tmp_path / "a,b"
    odd.mkdir()
    with pytest.raises(ScannerSandboxError, match="cannot be mounted"):
        run_in_sandbox(["ruff"], odd, tmp_path / "out.json", timeout=5)


def test_command_isolates_and_ships_source_and_rules_by_stdin(monkeypatch, tmp_path):
    _provision(monkeypatch, tmp_path)
    source = tmp_path / "src"
    (source / "node_modules").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n")
    (source / "node_modules" / "skipped.js").write_text("")
    (source / "link.py").symlink_to(source / "app.py")
    rules = tmp_path / "rules" / "semgrep_rules.yaml"
    rules.parent.mkdir()
    rules.write_text("rules: []\n")
    seen = {}

    def fake_run(command, output_path, *, env, stdin, timeout, accepted_return_codes, check_callback):
        seen.update(command=command, env=env, timeout=timeout, members=tarfile.open(fileobj=io.BytesIO(stdin.read())).getnames())
        return "done"

    monkeypatch.setattr(scanner_sandbox, "run_bounded_subprocess_stdout_to_file", fake_run)
    monkeypatch.setattr(scanner_sandbox, "_remove_container", lambda *args: None)

    assert run_in_sandbox(["semgrep", "scan"], source, tmp_path / "out.json", timeout=7, rules=rules) == "done"

    command = seen["command"]
    for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--pull=never", "--user=10001:10001"):
        assert flag in command
    assert f"--tmpfs={source}:rw,nosuid,nodev,size=2g,mode=1777" in command
    assert f"--tmpfs={rules.parent}:rw,nosuid,nodev,size=2g,mode=1777" in command
    assert not any(part.startswith(("-v", "--volume", "--mount")) for part in command)
    assert command[-3:] == ["sh", "semgrep", "scan"]
    assert f"cd {tmp_path}" in command[-4]  # semgrep runs from the rules' project root
    assert seen["members"] == [f"{source}/app.py".lstrip("/"), str(rules).lstrip("/")]
    assert set(seen["env"]) == {"PATH", "DOCKER_HOST", "DOCKER_CONFIG"} and seen["timeout"] == 7
