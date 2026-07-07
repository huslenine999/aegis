import json
import re
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

from policy_engine import get_ruff_severity


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


def calculate_exploitability_score(scans_dir: Path, waf_enabled: bool) -> float:
    def read_json_safe(path):
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                pass
        return None

    ruff = read_json_safe(scans_dir / "ruff-report.json")
    semgrep = read_json_safe(scans_dir / "semgrep-report.json")
    safety = read_json_safe(scans_dir / "safety-report.json")
    trivy = read_json_safe(scans_dir / "trivy-report.json")
    secrets = read_json_safe(scans_dir / "secrets-report.json")
    yara = read_json_safe(scans_dir / "yara-report.json")
    clamav = read_json_safe(scans_dir / "clamav-report.json")
    zap = read_json_safe(scans_dir / "zap-report.json")
    osv = read_json_safe(scans_dir / "osv-report.json")

    findings = []
    dast_exposed_multiplier = 1.0

    if ruff and isinstance(ruff, list):
        for finding in ruff:
            severity = get_ruff_severity(finding.get("code", "UNKNOWN"))
            cvss = 8.5 if severity == "HIGH" else (5.5 if severity == "MEDIUM" else 2.0)
            findings.append({"type": "sast", "cvss": cvss})

    if semgrep and isinstance(semgrep, dict):
        for finding in semgrep.get("results", []):
            severity = finding.get("extra", {}).get("severity", "ERROR").upper()
            cvss = 8.5 if severity == "ERROR" else (5.5 if severity == "WARNING" else 2.0)
            findings.append({"type": "sast", "cvss": cvss})

    if not osv and safety:
        vulnerabilities = []
        if isinstance(safety, dict):
            vulnerabilities = safety.get("vulnerabilities", []) or safety.get("results", [])
        elif isinstance(safety, list):
            vulnerabilities = safety
        for _ in vulnerabilities:
            findings.append({"type": "sca", "cvss": 6.5})

    if osv and isinstance(osv, list):
        for vulnerability in osv:
            findings.append({"type": "sca", "cvss": vulnerability.get("cvss") or 6.5})

    if trivy and isinstance(trivy, dict):
        for result in trivy.get("Results", []):
            for vulnerability in result.get("Vulnerabilities", []) or []:
                severity = vulnerability.get("Severity", "LOW").upper()
                cvss = 9.8 if severity == "CRITICAL" else (8.0 if severity == "HIGH" else (5.0 if severity == "MEDIUM" else 2.0))
                findings.append({"type": "container", "cvss": cvss})

    if secrets and isinstance(secrets, dict):
        for file_secrets in secrets.get("results", {}).values():
            for _ in file_secrets:
                findings.append({"type": "secrets", "cvss": 8.5})

    if yara and isinstance(yara, list):
        for _ in yara:
            findings.append({"type": "malware", "cvss": 9.0})

    if clamav and isinstance(clamav, list):
        for _ in clamav:
            findings.append({"type": "malware", "cvss": 9.0})

    if zap and isinstance(zap, list):
        exposed_count = len([finding for finding in zap if finding.get("status") == "EXPOSED"])
        if exposed_count > 0:
            dast_exposed_multiplier = 1.5
        for finding in zap:
            if finding.get("status") == "EXPOSED":
                findings.append({"type": "dast", "cvss": 8.5})

    if not findings:
        return 0.0

    weights = {
        "sast": 1.0,
        "sca": 0.8,
        "container": 0.9,
        "secrets": 1.2,
        "malware": 1.1,
        "dast": 1.0,
    }
    weighted_sum = sum(finding["cvss"] * weights.get(finding["type"], 1.0) for finding in findings)
    score = min(100.0, weighted_sum * 5.0) * dast_exposed_multiplier

    if waf_enabled:
        score *= 0.5

    return round(min(100.0, score), 1)


def generate_fallback_tree(project_root: Path) -> list[dict]:
    req_path = project_root / "requirements.txt"
    if not req_path.exists():
        req_path = Path("requirements.txt")

    tree = []
    if req_path.exists():
        try:
            content = req_path.read_text()
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
        except Exception:
            pass
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
    except Exception:
        pass
    return generate_fallback_tree(project_root)


def build_report_bundle(scans_dir: Path) -> bytes:
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
    added = set()

    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename in preferred_files:
            path = scans_dir / filename
            if path.exists() and path.is_file():
                archive.write(path, filename)
                added.add(path.resolve())

        for pattern in raw_patterns:
            for path in sorted(scans_dir.glob(pattern)):
                resolved = path.resolve()
                if path.is_file() and resolved not in added:
                    archive.write(path, f"raw/{path.name}")
                    added.add(resolved)

        manifest = {
            "bundle_format": "aegis-report-bundle-v1",
            "included_files": sorted(archive.namelist()),
        }
        archive.writestr("bundle-manifest.json", json.dumps(manifest, indent=2) + "\n")

    return bundle.getvalue()
