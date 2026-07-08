import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
        manifests.append(
            DependencyManifest(
                path=path,
                kind=kind,
                ecosystem=ecosystem,
                packages=tuple(extract_packages_from_manifest(path, kind, ecosystem)),
            )
        )
    return manifests


def first_requirements_manifest(manifests: list[DependencyManifest]) -> DependencyManifest | None:
    return next((manifest for manifest in manifests if manifest.safety_compatible), None)


def extract_packages_from_manifest(path: Path, kind: str | None = None, ecosystem: str | None = None) -> list[DependencyPackage]:
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
    except Exception:
        return []
    return []


def _packages_from_requirements(path: Path) -> list[DependencyPackage]:
    packages = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        match = REQUIREMENT_RE.match(line)
        if match:
            packages.append(DependencyPackage(match.group(1), match.group(3), "PyPI"))
    return packages


def _packages_from_pyproject(path: Path) -> list[DependencyPackage]:
    data = tomllib.loads(path.read_text(errors="ignore"))
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
    data = tomllib.loads(path.read_text(errors="ignore"))
    packages = []
    for item in data.get("package", []) or []:
        if isinstance(item, dict) and item.get("name"):
            packages.append(DependencyPackage(str(item["name"]), _clean_exact_version(item.get("version")), "PyPI"))
    return _dedupe_packages(packages)


def _packages_from_package_json(path: Path) -> list[DependencyPackage]:
    data = json.loads(path.read_text(errors="ignore"))
    packages = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, spec in deps.items():
                packages.append(DependencyPackage(name, _version_from_spec(spec), "npm"))
    return _dedupe_packages(packages)


def _packages_from_package_lock(path: Path) -> list[DependencyPackage]:
    data = json.loads(path.read_text(errors="ignore"))
    packages = []
    package_entries = data.get("packages")
    if isinstance(package_entries, dict):
        for package_path, details in package_entries.items():
            if not package_path or not isinstance(details, dict):
                continue
            name = details.get("name") or package_path.removeprefix("node_modules/")
            version = _clean_exact_version(details.get("version"))
            if name and version:
                packages.append(DependencyPackage(str(name), version, "npm"))
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        packages.extend(_packages_from_lock_dependencies(deps, "npm"))
    return _dedupe_packages(packages)


def _packages_from_pnpm_lock(path: Path) -> list[DependencyPackage]:
    packages = []
    in_packages = False
    for line in path.read_text(errors="ignore").splitlines():
        if line.startswith("packages:"):
            in_packages = True
            continue
        if in_packages and line and not line.startswith((" ", "\t")):
            break
        if not in_packages:
            continue
        match = re.match(r"^\s{2,}['\"]?/?(@?[^@/]+(?:/[^@/'\"]+)?)/([0-9][^():'\"]*)", line)
        if match:
            packages.append(DependencyPackage(match.group(1), _clean_exact_version(match.group(2)), "npm"))
    return _dedupe_packages(packages)


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
