import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .resource_budgets import read_bounded_text


IGNORED_DEPENDENCY_DIRS = {
    ".aegis",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "scanner-venv",
    "scans",
    "venv",
}


@dataclass(frozen=True)
class DependencyPackage:
    name: str
    version: str | None
    ecosystem: str


@dataclass(frozen=True)
class DependencyManifest:
    path: Path
    kind: str
    ecosystem: str
    packages: tuple[DependencyPackage, ...] = ()
    parse_error: str | None = None

    @property
    def safety_compatible(self) -> bool:
        return self.kind == "requirements.txt"


SUPPORTED_MANIFESTS = {
    "requirements.txt": ("requirements.txt", "PyPI"),
    "pyproject.toml": ("pyproject.toml", "PyPI"),
    "uv.lock": ("uv.lock", "PyPI"),
    "poetry.lock": ("poetry.lock", "PyPI"),
    "package.json": ("package.json", "npm"),
    "package-lock.json": ("package-lock.json", "npm"),
    "npm-shrinkwrap.json": ("npm-shrinkwrap.json", "npm"),
    "pnpm-lock.yaml": ("pnpm-lock.yaml", "npm"),
    "yarn.lock": ("yarn.lock", "npm"),
}


REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*(==|>=|~=|<=|>|<)\s*([A-Za-z0-9_.*!+.-]+)"
)
EXACT_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.!\-+_]*$")


def scan_root_for_target(target_path: str | Path) -> Path:
    target = Path(target_path)
    return target if target.is_dir() else target.parent


def discover_dependency_manifests(target_path: str | Path) -> list[DependencyManifest]:
    root = scan_root_for_target(target_path)
    manifests: list[DependencyManifest] = []
    if not root.exists():
        return manifests

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in IGNORED_DEPENDENCY_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        manifest_info = SUPPORTED_MANIFESTS.get(path.name)
        if manifest_info is None:
            continue
        kind, ecosystem = manifest_info
        parse_error = None
        try:
            packages = tuple(
                extract_packages_from_manifest(
                    path, kind, ecosystem, raise_errors=True
                )
            )
        except Exception as exc:
            packages = ()
            parse_error = f"{type(exc).__name__}: {exc}"
        manifests.append(
            DependencyManifest(
                path=path,
                kind=kind,
                ecosystem=ecosystem,
                packages=packages,
                parse_error=parse_error,
            )
        )
    return manifests


def first_requirements_manifest(manifests: list[DependencyManifest]) -> DependencyManifest | None:
    return next((manifest for manifest in manifests if manifest.safety_compatible), None)


def extract_packages_from_manifest(
    path: Path,
    kind: str | None = None,
    ecosystem: str | None = None,
    *,
    raise_errors: bool = False,
) -> list[DependencyPackage]:
    kind = kind or path.name
    ecosystem = ecosystem or SUPPORTED_MANIFESTS.get(path.name, (path.name, "unknown"))[1]
    try:
        if kind == "requirements.txt":
            return _packages_from_requirements(path)
        if kind == "pyproject.toml":
            return _packages_from_pyproject(path)
        if kind in {"uv.lock", "poetry.lock"}:
            return _packages_from_python_lock(path)
        if kind == "package.json":
            return _packages_from_package_json(path)
        if kind in {"package-lock.json", "npm-shrinkwrap.json"}:
            return _packages_from_package_lock(path)
        if kind == "pnpm-lock.yaml":
            return _packages_from_pnpm_lock(path)
        if kind == "yarn.lock":
            return _packages_from_yarn_lock(path)
    except Exception:
        if raise_errors:
            raise
        return []
    return []


def _packages_from_requirements(path: Path) -> list[DependencyPackage]:
    packages = []
    for line in read_bounded_text(path, errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        match = REQUIREMENT_RE.match(line)
        if match:
            operator = match.group(2)
            version = match.group(3) if operator == "==" else None
            packages.append(DependencyPackage(match.group(1), version, "PyPI"))
    return packages


def _packages_from_pyproject(path: Path) -> list[DependencyPackage]:
    data = tomllib.loads(read_bounded_text(path, errors="ignore"))
    packages = []
    project = data.get("project", {})
    for value in project.get("dependencies", []) or []:
        package = _python_dependency_from_spec(value)
        if package:
            packages.append(package)
    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for values in optional.values():
            for value in values or []:
                package = _python_dependency_from_spec(value)
                if package:
                    packages.append(package)
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            packages.append(DependencyPackage(name, _version_from_spec(spec), "PyPI"))
    return _dedupe_packages(packages)


def _packages_from_python_lock(path: Path) -> list[DependencyPackage]:
    data = tomllib.loads(read_bounded_text(path, errors="ignore"))
    packages = []
    for item in data.get("package", []) or []:
        if isinstance(item, dict) and item.get("name"):
            packages.append(DependencyPackage(str(item["name"]), _clean_exact_version(item.get("version")), "PyPI"))
    return _dedupe_packages(packages)


def _packages_from_package_json(path: Path) -> list[DependencyPackage]:
    data = json.loads(read_bounded_text(path, errors="ignore"))
    packages = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, spec in deps.items():
                packages.append(DependencyPackage(name, _version_from_spec(spec), "npm"))
    return _dedupe_packages(packages)


def _packages_from_package_lock(path: Path) -> list[DependencyPackage]:
    data = json.loads(read_bounded_text(path, errors="ignore"))
    packages = []
    package_entries = data.get("packages")
    if isinstance(package_entries, dict):
        for package_path, details in package_entries.items():
            if not package_path or not isinstance(details, dict):
                continue
            name = details.get("name") or _npm_name_from_lock_path(package_path)
            version = _clean_exact_version(details.get("version"))
            if name and version:
                packages.append(DependencyPackage(str(name), version, "npm"))
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        packages.extend(_packages_from_lock_dependencies(deps, "npm"))
    return _dedupe_packages(packages)


def _packages_from_pnpm_lock(path: Path) -> list[DependencyPackage]:
    packages: list[DependencyPackage] = []
    active_section = None
    seen_sections: set[str] = set()
    unparsed_entries: list[str] = []
    lines = read_bounded_text(path, errors="strict").splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            section = stripped[:-1]
            active_section = section if section in {"packages", "snapshots"} else None
            if active_section:
                seen_sections.add(active_section)
            continue
        if active_section is None:
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation != 2 or not stripped.endswith(":"):
            continue
        descriptor = stripped[:-1].strip("\"'")
        match = re.match(
            r"^/?(@[^/@]+/[^/@]+|[^/@]+)(?:@|/)([0-9][^():'\"]*)$",
            descriptor,
        )
        if not match:
            unparsed_entries.append(descriptor)
            continue
        version = _clean_exact_version(match.group(2))
        if version:
            packages.append(DependencyPackage(match.group(1), version, "npm"))
    if not seen_sections:
        meaningful = [
            line.strip()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        ]
        if meaningful:
            raise ValueError("pnpm lockfile has no supported package sections.")
    if unparsed_entries:
        raise ValueError(
            "pnpm lockfile contains unresolved package descriptors: "
            + ", ".join(unparsed_entries[:5])
        )
    return _dedupe_packages(packages)


def _packages_from_yarn_lock(path: Path) -> list[DependencyPackage]:
    """Parse the resolved package/version pairs in Yarn lockfiles.

    Yarn lockfiles are declaration-oriented, so a descriptor without a
    following resolved version is an invalid/incomplete inventory rather than a
    clean dependency set.
    """

    packages: list[DependencyPackage] = []
    descriptors_seen = 0
    versions_seen = 0
    current_names: list[str] = []
    saw_metadata = False
    entry_active = False
    metadata_active = False
    lines = read_bounded_text(path, errors="strict").splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and stripped in {
            "__metadata__:",
            "__metadata:",
        }:
            saw_metadata = True
            current_names = []
            entry_active = False
            metadata_active = True
            continue
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            current_names = [
                _npm_name_from_spec(item.strip().strip("\"'"))
                for item in stripped[:-1].split(",")
            ]
            current_names = [name for name in current_names if name]
            descriptors_seen += len(current_names)
            entry_active = True
            metadata_active = False
            continue
        version_match = re.match(r"^\s+version\s*[:=]?\s*[\"']?([^\"'\s]+)", line)
        if version_match and metadata_active:
            continue
        if version_match and entry_active and current_names:
            version = _clean_exact_version(version_match.group(1))
            if version:
                versions_seen += len(current_names)
                packages.extend(
                    DependencyPackage(name, version, "npm") for name in current_names
                )
            current_names = []
            continue
        if not line.startswith((" ", "\t")):
            raise ValueError(f"Unrecognized Yarn lockfile entry: {stripped[:80]}")
        if not entry_active and not metadata_active:
            raise ValueError(f"Yarn lockfile field has no descriptor: {stripped[:80]}")
    if descriptors_seen and versions_seen != descriptors_seen:
        raise ValueError(
            f"Yarn lockfile resolved {versions_seen} of {descriptors_seen} package descriptors."
        )
    if not descriptors_seen and not saw_metadata:
        meaningful = [
            line.strip()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        ]
        if meaningful:
            raise ValueError("Yarn lockfile contains no package descriptors.")
    return _dedupe_packages(packages)


def _npm_name_from_spec(spec: str) -> str:
    value = spec.strip()
    if value.startswith("npm:"):
        value = value[4:]
    if value.startswith("@"):
        separator = value.find("@", 1)
    else:
        separator = value.find("@")
    return value[:separator] if separator > 0 else value


def _npm_name_from_lock_path(package_path: str) -> str:
    marker = "node_modules/"
    name = package_path.rsplit(marker, 1)[-1]
    if name.startswith("@") and "/" in name:
        return name
    return name


def _packages_from_lock_dependencies(deps: dict[str, Any], ecosystem: str) -> list[DependencyPackage]:
    packages = []
    for name, details in deps.items():
        if isinstance(details, dict):
            packages.append(DependencyPackage(name, _clean_exact_version(details.get("version")), ecosystem))
            nested = details.get("dependencies")
            if isinstance(nested, dict):
                packages.extend(_packages_from_lock_dependencies(nested, ecosystem))
    return packages


def _python_dependency_from_spec(spec: str) -> DependencyPackage | None:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)", str(spec))
    if not match:
        return None
    return DependencyPackage(match.group(1), _version_from_spec(spec), "PyPI")


def _version_from_spec(spec: Any) -> str | None:
    if isinstance(spec, dict):
        spec = spec.get("version")
    if not isinstance(spec, str):
        return None
    spec = spec.strip()
    requirement_match = REQUIREMENT_RE.match(spec)
    if requirement_match:
        if requirement_match.group(2) != "==":
            return None
        return _clean_exact_version(requirement_match.group(3))
    if spec.startswith("=="):
        return _clean_exact_version(spec[2:].strip())
    if EXACT_VERSION_RE.match(spec):
        return spec
    return None


def _clean_exact_version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    version = value.strip().lstrip("v")
    return version if EXACT_VERSION_RE.match(version) else None


def _dedupe_packages(packages: list[DependencyPackage]) -> list[DependencyPackage]:
    seen = set()
    unique = []
    for package in packages:
        key = (package.ecosystem, package.name.lower(), package.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(package)
    return unique
