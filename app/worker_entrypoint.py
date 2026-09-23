import os
import shutil
import subprocess
import sys
import socket
from pathlib import Path

from .evidence import evidence_public_key
from .codeql_scanner import SUPPORTED_LANGUAGES, operator_runtime_configuration


TRUE_VALUES = {"1", "true", "yes", "on"}
FORBIDDEN_PRODUCTION_SECRETS = {
    "AEGIS_ADMIN_TOKEN",
    "AEGIS_AUDIT_HMAC_KEY",
    "AEGIS_BOOTSTRAP_ADMIN_PASSWORD",
    "AEGIS_METRICS_TOKEN",
    "AEGIS_SESSION_SECRET",
    "AEGIS_SETUP_TOKEN",
    "AEGIS_SMTP_PASSWORD",
    "AEGIS_TOKEN_PEPPER",
}


def validate_worker_configuration() -> None:
    # Parsing the key proves that every production worker can sign evidence
    # before it accepts a single untrusted repository.
    evidence_public_key()
    allow_deep = os.environ.get("AEGIS_ALLOW_DEEP_SCANS", "false").lower() in TRUE_VALUES
    isolated = os.environ.get("AEGIS_ISOLATED_WORKER", "false").lower() in TRUE_VALUES
    if allow_deep and not isolated:
        raise RuntimeError(
            "Deep scans require AEGIS_ISOLATED_WORKER=true on the worker."
        )
    if isolated:
        image, suites = operator_runtime_configuration()
        if set(suites) != SUPPORTED_LANGUAGES:
            raise RuntimeError("Deep workers require trusted Python and JavaScript CodeQL suites.")
        docker_executable = shutil.which("docker")
        if not docker_executable or not Path(docker_executable).is_absolute():
            raise RuntimeError("Deep workers require the Docker CLI.")
        try:
            subprocess.run(
                [docker_executable, "image", "inspect", image],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("The pinned CodeQL image is unavailable to the Deep worker.") from exc
    if os.environ.get("AEGIS_ENV", "development").lower() == "production":
        exposed = sorted(
            name for name in FORBIDDEN_PRODUCTION_SECRETS if os.environ.get(name)
        )
        if exposed:
            raise RuntimeError(
                "Production scanner workers must not receive dashboard or notifier "
                "secrets: " + ", ".join(exposed)
            )


def main() -> None:
    validate_worker_configuration()
    isolated = os.environ.get("AEGIS_ISOLATED_WORKER", "false").lower() in TRUE_VALUES
    queues = ["deep"] if isolated else ["default"]
    arguments = [
        "rq", "worker", "--name",
        f"aegis-{'isolated' if isolated else 'standard'}-{socket.gethostname()}",
        "--worker-ttl", "900", "--maintenance-interval", "60",
        *sys.argv[1:], *queues,
    ]
    os.execvp(arguments[0], arguments)


if __name__ == "__main__":
    main()
