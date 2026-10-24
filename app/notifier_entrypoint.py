import os

from . import service_rpc
from .notifications import dispatch_project_notification, dispatch_test_channel


FORBIDDEN_PRODUCTION_SECRETS = {
    "AEGIS_ADMIN_TOKEN",
    "AEGIS_AUDIT_HMAC_KEY",
    "AEGIS_BOOTSTRAP_ADMIN_PASSWORD",
    "AEGIS_EVIDENCE_SIGNING_KEY",
    "AEGIS_GITHUB_APP_PRIVATE_KEY",
    "AEGIS_GITHUB_APP_PRIVATE_KEY_B64",
    "AEGIS_METRICS_TOKEN",
    "AEGIS_SESSION_SECRET",
    "AEGIS_SETUP_TOKEN",
    "AEGIS_TOKEN_PEPPER",
}


def validate_notifier_configuration() -> None:
    if os.environ.get("AEGIS_ENV", "development").lower() != "production":
        return
    if not os.environ.get("AEGIS_ENCRYPTION_KEY"):
        raise RuntimeError(
            "AEGIS_ENCRYPTION_KEY is required for production notification delivery."
        )
    exposed = sorted(
        name for name in FORBIDDEN_PRODUCTION_SECRETS if os.environ.get(name)
    )
    if exposed:
        raise RuntimeError(
            "Production notifier workers must not receive dashboard, scanner, or "
            "GitHub App secrets: " + ", ".join(exposed)
        )
    from .database import require_least_privilege_role

    require_least_privilege_role()


def main() -> None:
    validate_notifier_configuration()
    service_rpc.serve_service("notifications", {
        "project_notification": dispatch_project_notification,
        "test_channel": dispatch_test_channel,
    })


if __name__ == "__main__":
    main()
