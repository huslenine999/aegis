"""Fail-closed container startup validation.

The dashboard image runs this module before starting Uvicorn so a bare
``docker run`` cannot accidentally expose the development authentication
principal or an unauthenticated non-loopback listener.
"""

import os
import sys

from .config import validate_runtime_configuration, validate_server_bind


TRUE_VALUES = {"1", "true", "yes", "on"}


def _authentication_required() -> bool:
    configured = os.environ.get("AEGIS_REQUIRE_AUTH", "").strip().lower()
    return configured in TRUE_VALUES or os.environ.get(
        "AEGIS_ENV", "development"
    ).strip().lower() == "production"


def validate_startup_configuration() -> None:
    """Validate runtime configuration and the effective server boundary."""
    validate_runtime_configuration()
    validate_server_bind(
        os.environ.get("AEGIS_HOST", "0.0.0.0"),
        auth_required=_authentication_required(),
    )


def main() -> None:
    validate_startup_configuration()
    command = sys.argv[1:]
    if not command:
        command = [
            "uvicorn",
            "app.main:app",
            "--host",
            os.environ.get("AEGIS_HOST", "0.0.0.0"),
            "--port",
            "5001",
        ]
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
