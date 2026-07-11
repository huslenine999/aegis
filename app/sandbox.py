import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any

try:
    from .dependencies import discover_dependency_manifests, first_requirements_manifest
except ImportError:
    from dependencies import discover_dependency_manifests, first_requirements_manifest


SANDBOX_UID = 10001
SANDBOX_GID = 10001
SANDBOX_FALLBACK_REQUIREMENTS = "Flask==3.1.3\nrequests==2.34.2\n"

def is_docker_available() -> bool:
    """
    Checks if docker CLI is installed and the daemon is currently running.
    """
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(["docker", "ps"], capture_output=True, check=False, timeout=2)
        return res.returncode == 0
    except Exception:
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
        content = filepath.read_text(errors="ignore")
        match = re.search(r'port\s*=\s*(\d+)', content)
        if match:
            return int(match.group(1))
    except Exception:
        pass
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
    temp_dir.mkdir(exist_ok=True, parents=True)
    port = detect_port_from_file(target_path)

    req_src = sandbox_requirements_file(target_path)
    if req_src and req_src.exists():
        shutil.copy2(req_src, temp_dir / "requirements.txt")
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
RUN pip install --no-cache-dir -r requirements.txt \\
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
RUN pip install --no-cache-dir -r requirements.txt \\
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
        res = subprocess.run(["docker", "build", "-t", image_tag, "."], cwd=str(temp_dir), capture_output=True, check=False)
        return res.returncode == 0
    except Exception:
        return False

def run_sandbox_container(image_tag: str, container_name: str, host_port: int, container_port: int, waf_enabled: bool) -> bool:
    """
    Starts container with resources constraints and WAF_ENABLED environment variable.
    """
    try:
        waf_env = "true" if waf_enabled else "false"
        cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "-p", f"{host_port}:{container_port}",
            "--memory", "128m",
            "--cpus", "0.5",
            "--pids-limit", "50",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--read-only",
            "--tmpfs", "/tmp:size=64m,mode=1777",
            "--user", f"{SANDBOX_UID}:{SANDBOX_GID}",
            "-e", f"WAF_ENABLED={waf_env}",
            image_tag
        ]
        res = subprocess.run(cmd, capture_output=True, check=False)
        return res.returncode == 0
    except Exception:
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
        except Exception:
            pass
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
        completed = subprocess.run([
            "trivy", "image", "--format", "json",
            "--output", str(output_path), image_tag
        ], capture_output=True, check=False, timeout=30)
        if completed.returncode != 0:
            raise RuntimeError(
                f"Trivy exited with code {completed.returncode}: {completed.stderr.decode(errors='ignore')[-500:] if isinstance(completed.stderr, bytes) else str(completed.stderr)[-500:]}"
            )
        if not output_path.exists():
            raise RuntimeError("Trivy did not produce a report")
        report = json.loads(output_path.read_text())
        if not isinstance(report, dict) or not isinstance(report.get("Results", []), list):
            raise RuntimeError("Trivy produced an invalid report")
        return report.get("Results", [])
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Trivy scan failed: {exc}") from exc

def stop_and_cleanup_sandbox(container_name: str, image_tag: str):
    """
    Cleans up docker container and image assets.
    """
    try:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, check=False)
    except Exception:
        pass
    try:
        subprocess.run(["docker", "rmi", image_tag], capture_output=True, check=False)
    except Exception:
        pass

def get_active_sandbox_container() -> str:
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
    except Exception:
        pass
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
    except Exception:
        pass
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
    except Exception:
        pass
    return []
