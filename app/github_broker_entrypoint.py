"""Start the GitHub credential broker: an RQ worker that holds GitHub secrets."""

import os
import sys

from .database import require_least_privilege_role
from .github_broker import BROKER_QUEUE


# The broker needs the database, Redis, the GitHub App key, and the key that
# decrypts users' OAuth tokens. It never sees evidence, sessions, or SMTP.
FORBIDDEN_PRODUCTION_SECRETS = {
    "AEGIS_ADMIN_TOKEN",
    "AEGIS_AUDIT_HMAC_KEY",
    "AEGIS_BOOTSTRAP_ADMIN_PASSWORD",
    "AEGIS_EVIDENCE_SIGNING_KEY",
    "AEGIS_METRICS_TOKEN",
    "AEGIS_SESSION_SECRET",
    "AEGIS_SETUP_TOKEN",
    "AEGIS_SMTP_PASSWORD",
    "AEGIS_TOKEN_PEPPER",
}


def validate_broker_configuration() -> None:
    if os.environ.get("AEGIS_ENV", "development").lower() != "production":
        return
    if not os.environ.get("AEGIS_ENCRYPTION_KEY"):
        raise RuntimeError("AEGIS_ENCRYPTION_KEY is required to read stored GitHub credentials.")
    exposed = sorted(name for name in FORBIDDEN_PRODUCTION_SECRETS if os.environ.get(name))
    if exposed:
        raise RuntimeError(
            "The GitHub credential broker must not receive dashboard, evidence, or "
            "notifier secrets: " + ", ".join(exposed)
        )
    require_least_privilege_role()


def main() -> None:
    validate_broker_configuration()
    arguments = [
        "rq", "worker", "--name", f"aegis-github-broker-{os.uname().nodename}",
        "--worker-ttl", "900", "--maintenance-interval", "60",
        *sys.argv[1:], BROKER_QUEUE,
    ]
    os.execvp(arguments[0], arguments)


if __name__ == "__main__":
    main()
