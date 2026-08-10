"""Single source for the installed Aegis package version."""

from importlib import metadata
from pathlib import Path
import tomllib


PACKAGE_NAME = "aegis-security-console"


def get_package_version() -> str:
    try:
        return metadata.version(PACKAGE_NAME)
    except metadata.PackageNotFoundError:
        pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        if not pyproject_path.exists():
            return "unknown"
        try:
            return str(tomllib.loads(pyproject_path.read_text())["project"]["version"])
        except (KeyError, OSError, tomllib.TOMLDecodeError):
            return "unknown"
