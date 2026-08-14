import re
import logging
import shutil
import subprocess
import time
import os
import stat
from pathlib import Path
from typing import List, Dict, Any

from .dependencies import discover_dependency_manifests, first_requirements_manifest
from .resource_budgets import load_bounded_json, read_bounded_text, run_bounded_subprocess


logger = logging.getLogger("aegis.sandbox")
SANDBOX_UID = 10001
SANDBOX_GID = 10001
SANDBOX_FALLBACK_REQUIREMENTS = "Flask==3.1.3\nrequests==2.34.2\n"
SANDBOX_COMMAND_TIMEOUT = int(os.environ.get("AEGIS_SANDBOX_COMMAND_TIMEOUT_SECONDS", "300"))
SANDBOX_MAX_FILES = int(os.environ.get("AEGIS_SANDBOX_MAX_FILES", "100000"))
SANDBOX_MAX_CONTEXT_BYTES = int(
    os.environ.get("AEGIS_SANDBOX_MAX_CONTEXT_BYTES", str(2 * 1024 * 1024 * 1024))
)


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
        if metadata.st_size > SANDBOX_MAX_CONTEXT_BYTES:
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
            if file_count > SANDBOX_MAX_FILES:
                raise RuntimeError("Scan target exceeds the configured file-count limit.")
            if total_bytes > SANDBOX_MAX_CONTEXT_BYTES:
                raise RuntimeError("Scan target exceeds the configured size limit.")
    return {"files": file_count, "bytes": total_bytes}


def copy_sandbox_requirements(source: Path, destination: Path) -> None:
    """Copy registry requirements while rejecting pip directives and remote/local URLs."""
    content = read_bounded_text(source)
    for line_number, line in enumerate(content.splitlines(), start=1):
        requirement = line.split("#", 1)[0].strip()
        if not requirement:
            continue
        if (
            requirement.startswith(("-", ".", "/"))
            or "@" in requirement
            or "://" in requirement
            or "\\" in requirement
            or "${" in requirement
        ):
            raise RuntimeError(
                "Sandbox requirements may contain only package-index requirement "
                f"specifiers; rejected line {line_number}."
            )
    destination.write_text(content)

def is_docker_available() -> bool:
    """
    Checks if docker CLI is installed and the daemon is currently running.
    """
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(["docker", "ps"], capture_output=True, check=False, timeout=2)
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Docker availability check failed: %s", exc)
        return False

def is_trivy_available() -> bool:
    """
    Checks if trivy CLI is installed.
    """
    return bool(shutil.which("trivy"))

def detect_port_from_file(filepath: Path) -> int:
    """
    Scans a python file to detect the port Flask runs on, defaulting to 5001.
    """
    try:
        content = read_bounded_text(filepath, errors="ignore")
        match = re.search(r'port\s*=\s*(\d+)', content)
        if match:
            return int(match.group(1))
    except (OSError, UnicodeError, ValueError) as exc:
        logger.debug("Unable to detect application port from %s: %s", filepath, exc)
    return 5001


def sandbox_requirements_file(target_path: Path) -> Path | None:
    manifest = first_requirements_manifest(discover_dependency_manifests(target_path))
    if manifest:
        return manifest.path
    if target_path.parent.name == "app":
        manifest = first_requirements_manifest(discover_dependency_manifests(target_path.parent.parent))
        if manifest:
            return manifest.path
    return None

def scaffold_sandbox_context(target_path: Path, temp_dir: Path) -> int:
    """
    Prepares a clean Docker build context directory under temp_dir.
    Copies requirements, source code, and writes a production Dockerfile.
    Returns the target port.
    """
    validate_untrusted_tree(
        target_path,
        ignored_names={".git", ".venv", "venv", "node_modules", "__pycache__"},
    )
    temp_dir.mkdir(exist_ok=True, parents=True)
    port = detect_port_from_file(target_path)

    req_src = sandbox_requirements_file(target_path)
    if req_src and req_src.exists():
        copy_sandbox_requirements(req_src, temp_dir / "requirements.txt")
    else:
        (temp_dir / "requirements.txt").write_text(SANDBOX_FALLBACK_REQUIREMENTS)

    # Detect if target is local Aegis codebase (runs with app/ folder structure)
    is_local_app = "app" in target_path.parts or target_path.name in {"main.py", "secure_main.py"}

    if is_local_app:
        src_app = target_path.resolve().parent
        if src_app.name != "app":
            src_app = src_app / "app"
        
        if src_app.exists():
            def ignore_patterns(path, names):
                ignored = []
                for name in names:
                    if name in {"__pycache__", "aegis_demo.db", "downloads", "venv", ".git", ".pytest_cache"}:
                        ignored.append(name)
                    elif name.endswith(".pyc") or name.endswith(".db"):
                        ignored.append(name)
                return ignored
            shutil.copytree(src_app, temp_dir / "app", ignore=ignore_patterns, dirs_exist_ok=True)

        dockerfile_content = f"""FROM python:3.11-alpine
WORKDIR /app
ENV AEGIS_DATA_DIR=/tmp/aegis-data
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt \\
    && addgroup -S -g {SANDBOX_GID} aegis \\
    && adduser -S -D -H -u {SANDBOX_UID} -G aegis aegis \\
    && mkdir -p /app/app/downloads /tmp/aegis-data \\
    && chown -R {SANDBOX_UID}:{SANDBOX_GID} /app/app/downloads /tmp/aegis-data
COPY --chown={SANDBOX_UID}:{SANDBOX_GID} app/ app/
USER {SANDBOX_UID}:{SANDBOX_GID}
EXPOSE {port}
CMD ["python", "app/{target_path.name}"]
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)
    else:
        # Custom standalone python script upload
        shutil.copy2(target_path, temp_dir / "app.py")
        dockerfile_content = f"""FROM python:3.11-alpine
WORKDIR /app
ENV AEGIS_DATA_DIR=/tmp/aegis-data
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt \\
    && addgroup -S -g {SANDBOX_GID} aegis \\
    && adduser -S -D -H -u {SANDBOX_UID} -G aegis aegis \\
    && mkdir -p /tmp/aegis-data \\
    && chown -R {SANDBOX_UID}:{SANDBOX_GID} /tmp/aegis-data
COPY --chown={SANDBOX_UID}:{SANDBOX_GID} app.py .
USER {SANDBOX_UID}:{SANDBOX_GID}
EXPOSE {port}
CMD ["python", "app.py"]
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

    return port

def build_sandbox_image(temp_dir: Path, image_tag: str) -> bool:
    """
    Executes docker build on the context.
    """
    try:
        res = run_bounded_subprocess(
            ["docker", "build", "-t", image_tag, "."],
            cwd=str(temp_dir),
            timeout=SANDBOX_COMMAND_TIMEOUT,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Sandbox image build failed for %s: %s", image_tag, exc)
        return False

def create_sandbox_network(network_name: str) -> bool:
    """Create a per-scan network with no route to external networks."""
    try:
        result = subprocess.run(
            ["docker", "network", "create", "--internal", network_name],
            capture_output=True,
            check=False,
            timeout=30,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Sandbox network creation failed for %s: %s", network_name, exc)
        return False


def run_sandbox_container(
    image_tag: str,
    container_name: str,
    host_port: int,
    container_port: int,
    waf_enabled: bool,
    network_name: str | None = None,
) -> bool:
    """
    Starts container with resources constraints and WAF_ENABLED environment variable.
    """
    try:
        waf_env = "true" if waf_enabled else "false"
        cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "-p", f"127.0.0.1:{host_port}:{container_port}",
            "--memory", "128m",
            "--cpus", "0.5",
            "--pids-limit", "50",
            "--ulimit", "nofile=256:256",
            "--ulimit", "nproc=64:64",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--read-only",
            "--tmpfs", "/tmp:size=64m,mode=1777",
            "--tmpfs", "/run:size=16m,mode=0755",
            "--stop-timeout", "5",
            "--user", f"{SANDBOX_UID}:{SANDBOX_GID}",
            "-e", f"WAF_ENABLED={waf_env}",
        ]
        if network_name:
            cmd.extend(["--network", network_name])
        cmd.append(image_tag)
        res = subprocess.run(
            cmd,
            capture_output=True,
            check=False,
            timeout=SANDBOX_COMMAND_TIMEOUT,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Sandbox container launch failed for %s: %s", container_name, exc)
        return False

def wait_for_container(target_url: str, timeout: float = 6.0) -> bool:
    """
    Polls target container URL to verify Flask server is up and listening.
    """
    import requests
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            res = requests.get(target_url, timeout=0.5)
            if res.status_code in {200, 403, 404}:
                return True
        except requests.RequestException:
            logger.debug("Sandbox readiness probe has not succeeded yet: %s", target_url)
        time.sleep(0.2)
    return False

def run_trivy_scan(image_tag: str, output_path: Path) -> List[Dict[str, Any]]:
    """
    Runs Trivy scanning on the container image and fails when evidence is unavailable.
    """
    import json
    if not is_trivy_available():
        raise RuntimeError("Trivy executable is unavailable")
    try:
        completed = run_bounded_subprocess([
            "trivy", "image", "--format", "json",
            "--output", str(output_path), image_tag
        ], timeout=SANDBOX_COMMAND_TIMEOUT)
        if completed.returncode != 0:
            raise RuntimeError(f"Trivy exited with code {completed.returncode}.")
        if not output_path.exists():
            raise RuntimeError("Trivy did not produce a report")
        report = load_bounded_json(output_path)
        if not isinstance(report, dict) or not isinstance(report.get("Results", []), list):
            raise RuntimeError("Trivy produced an invalid report")
        return report.get("Results", [])
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Trivy scan failed: {exc}") from exc

def stop_and_cleanup_sandbox(
    container_name: str, image_tag: str, network_name: str | None = None
):
    """
    Cleans up docker container and image assets.
    """
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            check=False,
            timeout=SANDBOX_COMMAND_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Unable to remove sandbox container %s: %s", container_name, exc)
    try:
        subprocess.run(
            ["docker", "rmi", image_tag],
            capture_output=True,
            check=False,
            timeout=SANDBOX_COMMAND_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Unable to remove sandbox image %s: %s", image_tag, exc)
    if network_name:
        try:
            subprocess.run(
                ["docker", "network", "rm", network_name],
                capture_output=True,
                check=False,
                timeout=SANDBOX_COMMAND_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("Unable to remove sandbox network %s: %s", network_name, exc)

def get_active_sandbox_container() -> str | None:
    """
    Scans docker ps for any running container starting with aegis-sandbox-container-.
    """
    if not is_docker_available():
        return None
    try:
        res = subprocess.run([
            "docker", "ps",
            "--filter", "name=aegis-sandbox-container-",
            "--format", "{{.Names}}"
        ], capture_output=True, text=True, check=False, timeout=2)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Unable to discover active sandbox container: %s", exc)
    return None

def get_sandbox_stats(container_name: str) -> Dict[str, Any]:
    """
    Queries container CPU/Memory status via docker stats.
    """
    stats = {"cpu": 0.0, "memory": 0.0}
    if not container_name or not is_docker_available():
        return stats
    try:
        res = subprocess.run([
            "docker", "stats", container_name,
            "--no-stream", "--format", "{{.CPUPerc}}|{{.MemPerc}}"
        ], capture_output=True, text=True, check=False, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            parts = res.stdout.strip().split("|")
            if len(parts) == 2:
                cpu_str = parts[0].replace("%", "").strip()
                mem_str = parts[1].replace("%", "").strip()
                stats["cpu"] = float(cpu_str) if cpu_str else 0.0
                stats["memory"] = float(mem_str) if mem_str else 0.0
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        logger.debug("Unable to read sandbox stats for %s: %s", container_name, exc)
    return stats

def get_sandbox_logs(container_name: str, tail: int = 10) -> List[str]:
    """
    Returns stdout/stderr logs from the container.
    """
    if not container_name or not is_docker_available():
        return []
    try:
        res = subprocess.run([
            "docker", "logs", f"--tail={tail}", container_name
        ], capture_output=True, text=True, check=False, timeout=2)
        if res.returncode == 0:
            return res.stdout.splitlines()
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Unable to read sandbox logs for %s: %s", container_name, exc)
    return []
