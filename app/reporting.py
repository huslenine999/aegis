import json
import logging
import re
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

from .dependencies import discover_dependency_manifests, first_requirements_manifest
from policy_engine import (
    analyze_report_set,
    calculate_exploitability_score as calculate_policy_exploitability_score,
)


logger = logging.getLogger("aegis.reporting")


def extract_json_values(data):
    if isinstance(data, dict):
        parts = []
        for key, value in data.items():
            parts.append(str(key))
            parts.append(extract_json_values(value))
        return " ".join(parts)
    if isinstance(data, list):
        return " ".join(extract_json_values(item) for item in data)
    return str(data)


def load_json_report(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Unable to read scanner report %s: %s", path, exc)
        return None


def calculate_exploitability_score(scans_dir: Path, waf_enabled: bool) -> float:

    reports = {
        name: load_json_report(scans_dir / f"{filename}-report.json")
        for name, filename in {
            "ruff": "ruff",
            "semgrep": "semgrep",
            "safety": "safety",
            "trivy": "trivy",
            "secrets": "secrets",  # pragma: allowlist secret
            "yara": "yara",
            "clamav": "clamav",
            "zap": "zap",
            "osv": "osv",
            "iac": "iac",
        }.items()
    }
    results = analyze_report_set(reports)
    return calculate_policy_exploitability_score(results, waf_enabled)


def generate_fallback_tree(project_root: Path) -> list[dict]:
    requirements_manifest = first_requirements_manifest(discover_dependency_manifests(project_root))
    tree: list[dict] = []
    if requirements_manifest:
        try:
            content = requirements_manifest.path.read_text()
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(==|>=)\s*([a-zA-Z0-9_\-\.]+)", line)
                if match:
                    package_name = match.group(1)
                    package_version = match.group(3)
                    tree.append({
                        "key": package_name.lower(),
                        "package_name": package_name,
                        "installed_version": package_version,
                        "required_version": f"=={package_version}",
                        "dependencies": [],
                    })
        except OSError as exc:
            logger.warning(
                "Unable to build dependency fallback from %s: %s",
                requirements_manifest.path,
                exc,
            )
    return tree


def load_dependency_tree(project_root: Path) -> list[dict]:
    try:
        python_bin = sys.executable
        pipdeptree_bin = Path(python_bin).parent / "pipdeptree"
        if not pipdeptree_bin.exists():
            pipdeptree_cmd = [python_bin, "-m", "pipdeptree", "--json-tree"]
        else:
            pipdeptree_cmd = [str(pipdeptree_bin), "--json-tree"]

        result = subprocess.run(pipdeptree_cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        logger.warning("Unable to load dependency tree with pipdeptree: %s", exc)
    return generate_fallback_tree(project_root)


def build_report_bundle(scans_dir: Path) -> bytes:
    artifacts: dict[str, bytes] = {}
    for path in scans_dir.iterdir():
        if path.is_file():
            artifacts[path.name] = path.read_bytes()
    return build_report_bundle_from_artifacts(artifacts)


def build_report_bundle_from_artifacts(artifacts: dict[str, bytes]) -> bytes:
    bundle = BytesIO()
    preferred_files = [
        "report.html",
        "report.md",
        "aegis.sarif",
        "sbom.json",
        "scan-manifest.json",
        "suppressions-report.json",
    ]
    raw_patterns = ("*-report.json", "osv-cache.json", "sandbox-status.json")
    added: set[str] = set()

    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename in preferred_files:
            if filename in artifacts:
                archive.writestr(filename, artifacts[filename])
                added.add(filename)

        for pattern in raw_patterns:
            for filename in sorted(artifacts):
                if Path(filename).match(pattern) and filename not in added:
                    archive.writestr(f"raw/{filename}", artifacts[filename])
                    added.add(filename)

        manifest = {
            "bundle_format": "aegis-report-bundle-v1",
            "included_files": sorted(archive.namelist()),
        }
        archive.writestr("bundle-manifest.json", json.dumps(manifest, indent=2) + "\n")

    return bundle.getvalue()
