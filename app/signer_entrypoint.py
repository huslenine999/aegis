"""Start the evidence signer: an RQ worker that holds only the signing key."""

import os
import sys

from .database import require_least_privilege_role
from .evidence import evidence_public_key
from .evidence_signer import SIGNING_QUEUE


# The signer needs the database, Redis, the evidence volume (read-only), and
# the Ed25519 key. Nothing that decrypts credentials or talks to GitHub/SMTP.
FORBIDDEN_PRODUCTION_SECRETS = {
    "AEGIS_ADMIN_TOKEN",
    "AEGIS_AUDIT_HMAC_KEY",
    "AEGIS_BOOTSTRAP_ADMIN_PASSWORD",
    "AEGIS_ENCRYPTION_KEY",
    "AEGIS_GITHUB_APP_PRIVATE_KEY",
    "AEGIS_GITHUB_APP_PRIVATE_KEY_B64",
    "AEGIS_METRICS_TOKEN",
    "AEGIS_SESSION_SECRET",
    "AEGIS_SETUP_TOKEN",
    "AEGIS_SMTP_PASSWORD",
    "AEGIS_TOKEN_PEPPER",
}


def validate_signer_configuration() -> None:
    if os.environ.get("AEGIS_ENV", "development").lower() != "production":
        return
    if not os.environ.get("AEGIS_EVIDENCE_SIGNING_KEY"):
        raise RuntimeError("AEGIS_EVIDENCE_SIGNING_KEY is required for the evidence signer.")
    evidence_public_key()
    exposed = sorted(name for name in FORBIDDEN_PRODUCTION_SECRETS if os.environ.get(name))
    if exposed:
        raise RuntimeError(
            "The evidence signer must not receive dashboard, scanner, notifier, or "
            "GitHub App secrets: " + ", ".join(exposed)
        )
    require_least_privilege_role()


def main() -> None:
    validate_signer_configuration()
    arguments = [
        "rq", "worker", "--name", f"aegis-signer-{os.uname().nodename}",
        "--worker-ttl", "900", "--maintenance-interval", "60",
        *sys.argv[1:], SIGNING_QUEUE,
    ]
    os.execvp(arguments[0], arguments)


if __name__ == "__main__":
    main()
