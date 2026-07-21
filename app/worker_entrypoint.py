import os
import sys
import socket

from .evidence import evidence_public_key


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
    safety_enabled = os.environ.get("AEGIS_ENABLE_SAFETY", "false").lower() in TRUE_VALUES
    if safety_enabled and not os.environ.get("SAFETY_API_KEY"):
        raise RuntimeError(
            "AEGIS_ENABLE_SAFETY requires a licensed SAFETY_API_KEY on the worker."
        )
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
    queues = ["default", "deep"] if isolated else ["default"]
    arguments = [
        "rq", "worker", "--name",
        f"aegis-{'isolated' if isolated else 'standard'}-{socket.gethostname()}",
        *sys.argv[1:], *queues,
    ]
    os.execvp(arguments[0], arguments)


if __name__ == "__main__":
    main()
