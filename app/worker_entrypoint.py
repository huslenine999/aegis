import os
import sys

try:
    from .evidence import evidence_public_key
except ImportError:
    from evidence import evidence_public_key


TRUE_VALUES = {"1", "true", "yes", "on"}


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


def main() -> None:
    validate_worker_configuration()
    arguments = ["rq", "worker", *sys.argv[1:]]
    os.execvp(arguments[0], arguments)


if __name__ == "__main__":
    main()
