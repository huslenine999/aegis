"""Start the fixed-operation service that holds GitHub secrets."""

import os

from .database import require_least_privilege_role
from .github_broker import BROKER_QUEUE, complete_run_check, issue_clone_token
from .service_rpc import serve_service


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
    serve_service(BROKER_QUEUE, {"clone_token": issue_clone_token, "complete_check": complete_run_check})


if __name__ == "__main__":
    main()
