import json
import os
import sys
import math
from collections import Counter
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, select_autoescape

from app.dependencies import DependencyManifest, DependencyPackage, discover_dependency_manifests, extract_packages_from_manifest

# Use an explicit scanner directory when provided. Otherwise keep reports in
# the persistent Aegis data directory used by the dashboard and worker.
_data_dir = os.environ.get("AEGIS_DATA_DIR")
_default_scan_dir = Path(_data_dir) / "scans" if _data_dir else Path("scans")
SCAN_DIR = Path(os.environ.get("SCANS_DIR", _default_scan_dir))

SCRIPT_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = SCRIPT_DIR / "app" / "templates" / "report_template.html"

RUFF_REPORT = SCAN_DIR / "ruff-report.json"
SAFETY_REPORT = SCAN_DIR / "safety-report.json"
TRIVY_REPORT = SCAN_DIR / "trivy-report.json"
SECRETS_REPORT = SCAN_DIR / "secrets-report.json"
YARA_REPORT = SCAN_DIR / "yara-report.json"
SEMGREP_REPORT = SCAN_DIR / "semgrep-report.json"
CLAMAV_REPORT = SCAN_DIR / "clamav-report.json"
ZAP_REPORT = SCAN_DIR / "zap-report.json"

HTML_REPORT = SCAN_DIR / "report.html"
MD_REPORT = SCAN_DIR / "report.md"


def get_env_set(var_name: str, default: set) -> set:
    val = os.environ.get(var_name)
    if val is None:
        return default
    return {item.strip().upper() for item in val.split(",") if item.strip()}


FAIL_ON_SEVERITIES = get_env_set("FAIL_ON", {"MEDIUM", "HIGH", "CRITICAL"})
FAIL_ON_RUFF_SEVERITIES = get_env_set("FAIL_ON_RUFF", get_env_set("FAIL_ON_BANDIT", FAIL_ON_SEVERITIES))
FAIL_ON_SAFETY = os.environ.get("FAIL_ON_SAFETY", "true").lower() == "true"
FAIL_ON_TRIVY_SEVERITIES = get_env_set("FAIL_ON_TRIVY", FAIL_ON_SEVERITIES)
FAIL_ON_SEMGREP_SEVERITIES = get_env_set("FAIL_ON_SEMGREP", FAIL_ON_SEVERITIES)


def load_json(path: Path) -> Any:
    if not path.exists():
        print(f"[WARN] Missing report: {path}")
        return None

    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        print(f"[WARN] Invalid JSON report: {path}")
        return None


def get_ruff_severity(code: str) -> str:
    # Basic mapping of flake8-bandit S-rules in Ruff to severity levels
    high_rules = {
        "S102",  # exec
        "S105", "S106", "S107",  # hardcoded password
        "S301",  # pickle
        "S304", "S305",  # insecure ciphers
        "S307",  # eval
        "S312",  # telnet
        "S501",  # ssl no verify
        "S506",  # unsafe yaml load
        "S601", "S602", "S605",  # shell injection / subprocess shell=True
        "S608",  # SQL injection
        "S701",  # jinja2 autoescape=False
    }
    medium_rules = {
        "S103", "S104",  # bad permissions, bind all interfaces
        "S113",  # requests without timeout
        "S302",  # marshal
        "S303",  # insecure hash
        "S306",  # mktemp
        "S308",  # django mark_safe
        "S310",  # urllib urlopen
        "S313", "S314", "S315", "S316", "S317", "S318", "S319", "S320",  # xml issues
        "S324",  # hashlib insecure
        "S508",  # snmp insecure
        "S604",  # shell/subprocess
        "S607",  # partial path
        "S609",  # wildcard injection
    }
    code_upper = code.upper()
    if code_upper in high_rules:
        return "HIGH"
    elif code_upper in medium_rules:
        return "MEDIUM"
    return "LOW"


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = Counter(str(item.get("severity", "LOW")).upper() for item in findings)
    return dict(sorted(counts.items()))


def _format_dependency_fix(package_name: str | None, fixed_versions: Any = None) -> str:
    package = package_name or "package"
    if isinstance(fixed_versions, list):
        fixed = next((str(item) for item in fixed_versions if item), "")
    else:
        fixed = str(fixed_versions or "").strip()
    if fixed and fixed not in {"None", "[]"}:
        return f"python -m pip install --upgrade \"{package}>={fixed.split(',')[0].strip()}\""
    return f"python -m pip install --upgrade {package}"


def _suppression_example(tool: str, issue: Dict[str, Any]) -> str:
    rule = (
        issue.get("test_id")
        or issue.get("id")
        or issue.get("vulnerability_id")
        or issue.get("rule")
        or issue.get("type")
        or ""
    )
    path = issue.get("filename") or issue.get("path") or "requirements.txt"
    return "\n".join([
        "scan:",
        "  suppressions:",
        f"    - tool: {tool}",
        f"      rule: {rule}",
        f"      path: {path}",
        "      reason: Reviewed and accepted by the security owner.",
    ])


def enrich_finding(tool: str, issue: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(issue)
    rule = str(issue.get("test_id") or issue.get("id") or issue.get("vulnerability_id") or issue.get("rule") or "").upper()
    package_name = issue.get("package_name")

    guidance = {
        "why": "This finding can weaken the security gate and should be reviewed before release.",
        "fix": "Review the affected code or dependency, apply the smallest safe change, and rerun Aegis.",
        "suggestion": "aegis scan . --fast",
    }

    if tool == "Ruff (SAST)":
        guidance.update({
            "why": "A Python security rule matched source code that may allow unsafe runtime behavior.",
            "fix": "Replace the risky API or add input validation before user-controlled data reaches it.",
            "suggestion": "# Fix the flagged Python line, then rerun\naegis scan . --fast",
        })
        ruff_guidance = {
            "S307": {
                "why": "Using eval can execute attacker-controlled Python code.",
                "fix": "Replace eval with ast.literal_eval for literals, or use an explicit parser/allowlist.",
                "suggestion": "import ast\nvalue = ast.literal_eval(user_input)",
            },
            "S102": {
                "why": "exec can run arbitrary Python code if input is influenced by a user.",
                "fix": "Remove dynamic execution and dispatch through explicit functions or commands.",
                "suggestion": "handlers = {\"status\": show_status}\nhandlers[action]()",
            },
            "S602": {
                "why": "shell=True lets shell metacharacters change the command being executed.",
                "fix": "Pass command arguments as a list and keep shell=False.",
                "suggestion": "subprocess.run([\"git\", \"status\"], check=True, shell=False)",
            },
            "S608": {
                "why": "String-built SQL can let attackers change the query.",
                "fix": "Use parameterized queries instead of concatenating SQL.",
                "suggestion": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
            },
            "S506": {
                "why": "Unsafe YAML loading can construct arbitrary Python objects.",
                "fix": "Use yaml.safe_load for untrusted YAML.",
                "suggestion": "data = yaml.safe_load(raw_yaml)",
            },
            "S104": {
                "why": "Binding to all interfaces can expose a development service outside localhost.",
                "fix": "Bind local-only services to 127.0.0.1, or require auth/TLS before public exposure.",
                "suggestion": "uvicorn.run(app, host=\"127.0.0.1\", port=5001)",
            },
            "S113": {
                "why": "HTTP calls without timeouts can hang workers and exhaust resources.",
                "fix": "Set a bounded connect/read timeout.",
                "suggestion": "requests.get(url, timeout=10)",
            },
        }
        guidance.update(ruff_guidance.get(rule, {}))
    elif tool == "Semgrep":
        check_id = str(issue.get("test_id") or "").lower()
        guidance.update({
            "why": "A Semgrep rule matched a risky source pattern that may become exploitable in production.",
            "fix": "Follow the rule message, validate untrusted input, and prefer framework-safe APIs.",
            "suggestion": "# Inspect the matched line, apply the rule-specific fix, then rerun\naegis scan . --fast",
        })
        if "sql" in check_id:
            guidance.update({
                "why": "The matched code appears to build SQL from dynamic input.",
                "fix": "Use parameterized queries or an ORM query builder.",
                "suggestion": "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))",
            })
        elif "xss" in check_id:
            guidance.update({
                "why": "The matched code may render untrusted HTML or script content.",
                "fix": "Escape output by default and only allow sanitized HTML from trusted sources.",
                "suggestion": "{{ user_value | e }}",
            })
    elif tool in {"Safety", "OSV Dependency Audit"}:
        fixed_versions = issue.get("fixed_versions") or issue.get("fixed") or issue.get("version")
        guidance.update({
            "why": "The dependency version is associated with a published vulnerability advisory.",
            "fix": "Upgrade to a fixed version, verify compatibility, and commit the lockfile or requirements change.",
            "suggestion": _format_dependency_fix(package_name, fixed_versions),
        })
    elif tool == "Trivy":
        guidance.update({
            "why": "The container or OS package has a known vulnerability in the scanned image.",
            "fix": "Upgrade the base image or package to the fixed version and rebuild the image.",
            "suggestion": f"# Update {package_name or 'the affected package'} to {issue.get('fixed_version') or 'a fixed version'}\ndocker build --pull -t your-image .",
        })
    elif tool == "Secrets Scanner":
        guidance.update({
            "why": "A plaintext credential can be copied from source history and used outside the application.",
            "fix": "Revoke and rotate the credential, move it to a secret manager or environment variable, and remove it from history.",
            "suggestion": "export SERVICE_TOKEN=\"...\"\n# read it with os.environ[\"SERVICE_TOKEN\"]",
        })
    elif tool in {"YARA Scanner", "ClamAV"}:
        guidance.update({
            "why": "A malware or suspicious-code signature matched the target file.",
            "fix": "Quarantine the file, inspect its origin, and replace it from a trusted source.",
            "suggestion": "# Remove the suspicious file and restore from trusted source control\ngit restore path/to/file",
        })
    elif tool == "Aegis DAST Probe":
        guidance.update({
            "why": "A dynamic probe reached behavior that appears exposed at runtime.",
            "fix": "Validate input at the route boundary, enforce authorization, and add regression tests for the payload.",
            "suggestion": "# Add route validation and rerun a deep scan\naegis scan . --no-docker",
        })

    enriched.setdefault("finding_status", "Unclassified in this standalone report")
    enriched["why_it_matters"] = guidance["why"]
    enriched["remediation"] = guidance["fix"]
    enriched["fix_suggestion"] = guidance["suggestion"]
    enriched["suppression_guidance"] = "Suppress only after a named owner verifies the risk is accepted, non-exploitable, or covered by a compensating control."
    enriched["suppression_example"] = _suppression_example(tool, enriched)
    return enriched


def analyze_ruff(report: Any) -> Dict[str, Any]:
    if report is None or not isinstance(report, list):
        return {
            "tool": "Ruff (SAST)",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    results = report if isinstance(report, list) else []
    issues = []
    
    for r in results:
        code = r.get("code", "UNKNOWN")
        severity = get_ruff_severity(code)
        issues.append(enrich_finding("Ruff (SAST)", {
            "severity": severity,
            "test_id": code,
            "filename": r.get("filename"),
            "line_number": r.get("location", {}).get("row"),
            "issue_text": r.get("message"),
        }))

    blocking_issues = [
        issue for issue in issues
        if issue["severity"] in FAIL_ON_RUFF_SEVERITIES
    ]

    return {
        "tool": "Ruff (SAST)",
        "total_issues": len(issues),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
        "severity_counts": _severity_counts(issues),
        "examples": (blocking_issues if blocking_issues else issues)[:5],
    }


def analyze_semgrep(report: Dict[str, Any]) -> Dict[str, Any]:
    if not report:
        return {
            "tool": "Semgrep",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    results = report.get("results", []) if report else []
    issues = []
    
    for r in results:
        extra = r.get("extra", {})
        severity = extra.get("severity", "ERROR").upper()
        if severity == "ERROR":
            mapped_severity = "HIGH"
        elif severity == "WARNING":
            mapped_severity = "MEDIUM"
        else:
            mapped_severity = "LOW"
            
        issues.append(enrich_finding("Semgrep", {
            "severity": mapped_severity,
            "test_id": r.get("check_id"),
            "filename": r.get("path"),
            "line_number": r.get("start", {}).get("line"),
            "issue_text": extra.get("message"),
            "code": extra.get("lines"),
        }))

    blocking_issues = [
        issue for issue in issues
        if issue["severity"] in FAIL_ON_SEMGREP_SEVERITIES
    ]

    return {
        "tool": "Semgrep",
        "total_issues": len(issues),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
        "severity_counts": _severity_counts(issues),
        "examples": (blocking_issues if blocking_issues else issues)[:5],
    }


def analyze_safety(report: Any) -> Dict[str, Any]:
    """
    Supports Safety JSON output shapes from both 'check' and 'scan' commands.
    """
    vulnerabilities: List[Any] = []

    if report is None:
        return {
            "tool": "Safety",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    # Handle 'safety scan' format
    if isinstance(report, dict) and "vulnerabilities" in report:
        vulnerabilities = report["vulnerabilities"]
    # Handle older 'safety check' formats
    elif isinstance(report, list):
        vulnerabilities = report
    elif isinstance(report, dict) and "affected_packages" in report:
        for package_data in report["affected_packages"].values():
            vulns = package_data.get("vulnerabilities", [])
            vulnerabilities.extend(vulns)

    # Normalize examples for reporting
    normalized_examples = []
    for v in vulnerabilities:
        normalized_examples.append(enrich_finding("Safety", {
            "severity": "MEDIUM",
            "package_name": v.get("package_name") or v.get("package"),
            "vulnerability_id": v.get("vulnerability_id") or v.get("advisory"),
            "affected_versions": v.get("affected_versions") or v.get("version"),
            "fixed_versions": v.get("fixed_versions") or v.get("fixed"),
            "description": v.get("description") or v.get("reason", "No description provided."),
        }))

    blocking_count = (
        len(vulnerabilities)
        if FAIL_ON_SAFETY and "MEDIUM" in FAIL_ON_SEVERITIES
        else 0
    )
    return {
        "tool": "Safety",
        "total_issues": len(vulnerabilities),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count else "PASS",
        "severity_counts": {"MEDIUM": len(vulnerabilities)} if vulnerabilities else {},
        "examples": normalized_examples[:5],
    }


def analyze_osv(report: List[Dict[str, Any]]) -> Dict[str, Any]:
    if report is None:
        return {
            "tool": "OSV Dependency Audit",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    findings = []
    for f in report:
        cvss_score = f.get("cvss") or 0.0
        findings.append(enrich_finding("OSV Dependency Audit", {
            "severity": "HIGH" if cvss_score >= 7.0 else ("MEDIUM" if cvss_score >= 4.0 else "LOW"),
            "id": f.get("id"),
            "package_name": f.get("package"),
            "version": f.get("version"),
            "cvss": f.get("cvss"),
            "summary": f.get("summary"),
            "details": f.get("details"),
        }))

    blocking_issues = [f for f in findings if f["severity"] in FAIL_ON_SEVERITIES]

    return {
        "tool": "OSV Dependency Audit",
        "total_issues": len(findings),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:5],
    }


def analyze_trivy(report: Dict[str, Any]) -> Dict[str, Any]:
    vulnerabilities = []

    if not report:
        return {
            "tool": "Trivy",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    for result in report.get("Results", []):
        for vulnerability in result.get("Vulnerabilities", []) or []:
            severity = vulnerability.get("Severity", "").upper()
            vulnerabilities.append(enrich_finding("Trivy", {
                "target": result.get("Target"),
                "vulnerability_id": vulnerability.get("VulnerabilityID"),
                "package_name": vulnerability.get("PkgName"),
                "installed_version": vulnerability.get("InstalledVersion"),
                "fixed_version": vulnerability.get("FixedVersion"),
                "severity": severity,
                "title": vulnerability.get("Title"),
            }))

    blocking_issues = [v for v in vulnerabilities if v["severity"] in FAIL_ON_TRIVY_SEVERITIES]

    return {
        "tool": "Trivy",
        "total_issues": len(vulnerabilities),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
        "severity_counts": _severity_counts(vulnerabilities),
        "examples": (blocking_issues if blocking_issues else vulnerabilities)[:5],
    }


def analyze_secrets(report: Dict[str, Any]) -> Dict[str, Any]:
    if not report:
        return {
            "tool": "Secrets Scanner",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    results = report.get("results", {}) or {}
    findings = []
    
    for filename, file_secrets in results.items():
        for secret in file_secrets:
            findings.append(enrich_finding("Secrets Scanner", {
                "severity": "HIGH",
                "type": secret.get("type"),
                "filename": filename,
                "line_number": secret.get("line_number"),
            }))

    blocking_count = len(findings) if "HIGH" in FAIL_ON_SEVERITIES else 0
    return {
        "tool": "Secrets Scanner",
        "total_issues": len(findings),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:5],
    }


def analyze_yara(report: List[Dict[str, Any]]) -> Dict[str, Any]:
    if report is None:
        return {
            "tool": "YARA Scanner",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    findings = []
    for f in report:
        findings.append(enrich_finding("YARA Scanner", {
            "severity": "HIGH",
            "rule": f.get("rule"),
            "filename": f.get("filename"),
            "description": f.get("description"),
            "author": f.get("author")
        }))

    blocking_count = len(findings) if "HIGH" in FAIL_ON_SEVERITIES else 0
    return {
        "tool": "YARA Scanner",
        "total_issues": len(findings),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:5],
    }


def analyze_clamav(report: List[Dict[str, Any]]) -> Dict[str, Any]:
    if report is None:
        return {
            "tool": "ClamAV",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    findings = []
    for f in report:
        findings.append(enrich_finding("ClamAV", {
            "severity": "HIGH",
            "virus": f.get("virus"),
            "filename": f.get("filename"),
            "description": f.get("description")
        }))

    blocking_count = len(findings) if "HIGH" in FAIL_ON_SEVERITIES else 0
    return {
        "tool": "ClamAV",
        "total_issues": len(findings),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:5],
    }


def analyze_zap(report: List[Dict[str, Any]]) -> Dict[str, Any]:
    if report is None:
        return {
            "tool": "Aegis DAST Probe",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    findings = []
    blocking_count = 0
    for f in report:
        is_exposed = f.get("status") == "EXPOSED"
        findings.append(enrich_finding("Aegis DAST Probe", {
            "severity": "HIGH" if is_exposed else "LOW",
            "vuln_type": f.get("vuln_type"),
            "route": f.get("route"),
            "payload": f.get("payload"),
            "description": f.get("description"),
            "status": f.get("status")
        }))
        if is_exposed and "HIGH" in FAIL_ON_SEVERITIES:
            blocking_count += 1

    return {
        "tool": "Aegis DAST Probe",
        "total_issues": len(findings),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count > 0 else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:6],
    }


def _normalize_manifests(manifests_or_path: Any) -> list[DependencyManifest]:
    if manifests_or_path is None:
        return []
    if isinstance(manifests_or_path, DependencyManifest):
        return [manifests_or_path]
    if isinstance(manifests_or_path, (str, Path)):
        path = Path(manifests_or_path)
        ecosystem = "npm" if path.name in {
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        } else "PyPI"
        packages = tuple(extract_packages_from_manifest(path, path.name, ecosystem)) if path.exists() else ()
        return [DependencyManifest(path=path, kind=path.name, ecosystem=ecosystem, packages=packages)]
    return list(manifests_or_path)


def _package_purl(package: DependencyPackage) -> str:
    purl_type = "pypi" if package.ecosystem == "PyPI" else package.ecosystem.lower()
    base = f"pkg:{purl_type}/{package.name.lower()}"
    return f"{base}@{package.version}" if package.version else base


def generate_cyclonedx_sbom(manifests_or_path: Any, output_path: Path):
    import uuid
    from datetime import datetime
    
    components = []
    for manifest in _normalize_manifests(manifests_or_path):
        for package in manifest.packages:
            purl = _package_purl(package)
            component = {
                "type": "library",
                "name": package.name,
                "purl": purl,
                "bom-ref": purl,
                "properties": [
                    {"name": "aegis:manifest", "value": str(manifest.path)},
                    {"name": "aegis:ecosystem", "value": package.ecosystem},
                ],
            }
            if package.version:
                component["version"] = package.version
            components.append(component)
                
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Aegis SBOM Generator",
                        "version": "1.0.0"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "Aegis",
                "version": "1.0.0"
            }
        },
        "components": components
    }
    
    output_path.write_text(json.dumps(sbom, indent=2))
    print(f"[INFO] CycloneDX SBOM generated: {output_path}")


def parse_cvss_vector(vector_str: str) -> float:
    try:
        if not vector_str:
            return 0.0
        
        vector_upper = vector_str.upper()
        if "CVSS:3" not in vector_upper and "AV:" not in vector_upper:
            return 0.0

        if vector_upper.startswith("CVSS:"):
            parts = vector_upper.split("/", 1)[1].split("/")
        else:
            parts = vector_upper.split("/")
            
        metrics = {}
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.strip()] = v.strip()
                
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        ui_map = {"N": 0.85, "R": 0.62}
        c_map = {"H": 0.56, "L": 0.22, "N": 0.0}
        i_map = {"H": 0.56, "L": 0.22, "N": 0.0}
        a_map = {"H": 0.56, "L": 0.22, "N": 0.0}
        
        av = av_map.get(metrics.get("AV", "N"), 0.85)
        ac = ac_map.get(metrics.get("AC", "L"), 0.77)
        ui = ui_map.get(metrics.get("UI", "N"), 0.85)
        scope = metrics.get("S", "U")
        
        c = c_map.get(metrics.get("C", "N"), 0.0)
        i = i_map.get(metrics.get("I", "N"), 0.0)
        a = a_map.get(metrics.get("A", "N"), 0.0)
        
        pr_val = metrics.get("PR", "N")
        if scope == "C":
            pr_map = {"N": 0.85, "L": 0.68, "H": 0.5}
        else:
            pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr = pr_map.get(pr_val, 0.85)
        
        exploitability = 8.22 * av * ac * pr * ui
        iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        
        if scope == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
            
        if impact <= 0:
            return 0.0
            
        if scope == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)
            
        return math.ceil(score * 10.0) / 10.0
    except Exception:
        return 0.0


OSV_CACHE_FILE = SCAN_DIR / "osv-cache.json"

def query_osv_vulnerabilities(
    manifests_or_path: Any,
    *,
    raise_on_error: bool = False,
) -> List[Dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failed_queries = []
    packages_by_key: dict[tuple[str, str, str], DependencyPackage] = {}
    for manifest in _normalize_manifests(manifests_or_path):
        for package in manifest.packages:
            if package.version:
                key = (package.ecosystem, package.name.lower(), package.version)
                packages_by_key.setdefault(key, package)
    packages = list(packages_by_key.values())
    if not packages:
        print("[INFO] No pinned dependency versions found for OSV queries.")
        return findings

    cache = {}
    if OSV_CACHE_FILE.exists():
        try:
            cache = json.loads(OSV_CACHE_FILE.read_text())
        except Exception:
            pass

    current_time = time.time()
    cache_dirty = False
    CACHE_TTL = 86400  # 24 hours

    for pkg in packages:
        pkg_name = pkg.name
        pkg_ver = pkg.version
        ecosystem = pkg.ecosystem
        cache_key = f"{ecosystem}:{pkg_name.lower()}@{pkg_ver}"
        
        if cache_key in cache:
            entry = cache[cache_key]
            if current_time - entry.get("timestamp", 0) < CACHE_TTL:
                findings.extend(entry.get("vulns", []))
                continue

        url = "https://api.osv.dev/v1/query"
        payload = {
            "version": pkg_ver,
            "package": {
                "name": pkg_name,
                "ecosystem": ecosystem
            }
        }
        
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, 
            data=req_data,
            headers={"Content-Type": "application/json", "User-Agent": "Aegis-Scanner/2.0"},
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
                vuln_list = []
                for vuln in resp_data.get("vulns", []):
                    cvss_score = None
                    vector = None
                    
                    db_spec = vuln.get("database_specific", {})
                    if isinstance(db_spec, dict):
                        cvss_data = db_spec.get("cvss")
                        if isinstance(cvss_data, dict):
                            cvss_score = cvss_data.get("score")
                            vector = cvss_data.get("vector")
                            
                    if cvss_score is None:
                        for sev in vuln.get("severity", []):
                            if isinstance(sev, dict) and sev.get("type") in ("CVSS_V3", "CVSS_V2"):
                                vector = sev.get("score")
                                cvss_score = parse_cvss_vector(str(vector or ""))
                                break
                    
                    vuln_list.append({
                        "id": vuln.get("id"),
                        "package": pkg_name,
                        "version": pkg_ver,
                        "ecosystem": ecosystem,
                        "cvss": cvss_score,
                        "vector": vector,
                        "summary": vuln.get("summary", "No summary provided."),
                        "details": vuln.get("details", "No details provided.")
                    })
                
                cache[cache_key] = {
                    "timestamp": current_time,
                    "vulns": vuln_list
                }
                cache_dirty = True
                findings.extend(vuln_list)
                time.sleep(0.1)
        except Exception as e:
            print(f"[WARN] Failed to query OSV API for {cache_key}: {e}")
            if cache_key in cache:
                findings.extend(cache[cache_key].get("vulns", []))
            else:
                failed_queries.append(cache_key)

    if cache_dirty:
        try:
            OSV_CACHE_FILE.write_text(json.dumps(cache, indent=2))
        except Exception as e:
            print(f"[WARN] Failed to write OSV Cache: {e}")

    if raise_on_error and failed_queries:
        raise RuntimeError(
            "OSV queries failed without cached results for: "
            + ", ".join(failed_queries)
        )

    return findings


def calculate_exploitability_score(results: List[Dict[str, Any]], waf_enabled: bool) -> float:
    del waf_enabled
    severity_cvss = {"LOW": 2.0, "MEDIUM": 5.5, "HIGH": 8.5, "CRITICAL": 9.8}
    severities = []
    for result in results:
        if result.get("status") in {"SKIPPED", "MISSING", "ERROR"} or not result.get("blocking_issues"):
            continue
        for severity, count in (result.get("severity_counts") or {}).items():
            severities.extend([severity_cvss.get(severity.upper(), 2.0)] * int(count))

    if not severities:
        return 0.0
    # A risk score should reflect the worst credible finding without growing
    # linearly merely because a scanner emitted many low-confidence matches.
    maximum_risk = max(severities) * 10.0
    volume_bonus = min(15.0, math.log2(len(severities) + 1) * 2.5)
    return round(min(100.0, maximum_risk + volume_bonus), 1)


def generate_reports(
    results: List[Dict[str, Any]],
    final_status: str,
    reason: str,
    exploitability_score: float = 0.0,
    html_path: Path | None = None,
    md_path: Path | None = None
):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    h_path = html_path if html_path is not None else HTML_REPORT
    m_path = md_path if md_path is not None else MD_REPORT
    
    # Generate HTML Report
    if TEMPLATE_PATH.exists():
        environment = Environment(
            autoescape=select_autoescape(default_for_string=True),
        )
        template = environment.from_string(TEMPLATE_PATH.read_text())
        html_content = template.render(
            results=results,
            final_status=final_status,
            reason=reason,
            timestamp=timestamp,
            exploitability_score=exploitability_score
        )
        h_path.write_text(html_content)
        print(f"[INFO] HTML report generated: {h_path}")
    else:
        print(f"[WARN] Template not found at {TEMPLATE_PATH}, skipping HTML report.")

    # Generate Markdown Report (useful for GitHub Job Summaries)
    md_lines = [
        "# Aegis Security Scan Summary",
        f"**Generated on:** {timestamp}",
        f"**Final Decision:** DEPLOYMENT {final_status}",
        f"**Reason:** {reason}",
        f"**Exploitability Score:** {exploitability_score}%",
        "",
        "## Tool Results",
        "| Tool | Status | Total Issues | Blocking Issues |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        md_lines.append(f"| {r['tool']} | {r['status']} | {r['total_issues']} | {r['blocking_issues']} |")

    md_lines.extend([
        "",
        "## Finding Guidance",
        "",
        "Each finding below answers what failed, why it matters, how to fix it, whether Aegis can classify it as new, and when suppression is acceptable.",
    ])
    for result in results:
        if not result.get("examples"):
            continue
        md_lines.extend(["", f"### {result['tool']}"])
        for example in result["examples"]:
            title = (
                example.get("issue_text")
                or example.get("summary")
                or example.get("description")
                or example.get("title")
                or example.get("vulnerability_id")
                or example.get("id")
                or "Finding"
            )
            location = example.get("filename") or example.get("target") or example.get("package_name") or example.get("route") or "N/A"
            md_lines.extend([
                "",
                f"#### {title}",
                f"- **What failed:** {example.get('test_id') or example.get('id') or example.get('vulnerability_id') or example.get('rule') or result['tool']}",
                f"- **Location/package:** {location}",
                f"- **Why it matters:** {example.get('why_it_matters', 'Review before release.')}",
                f"- **How to fix:** {example.get('remediation', 'Apply the scanner recommendation and rerun Aegis.')}",
                f"- **New or pre-existing:** {example.get('finding_status', 'Unclassified in this standalone report')}",
                f"- **Safe to suppress:** {example.get('suppression_guidance', 'Suppress only with documented risk acceptance.')}",
                "",
                "```bash",
                str(example.get("fix_suggestion", "aegis scan . --fast")),
                "```",
                "",
                "Suppression example:",
                "",
                "```yaml",
                str(example.get("suppression_example", "")),
                "```",
            ])

    md_lines.append("\n---\n*Generated by Aegis Policy Engine*")
    m_path.write_text("\n".join(md_lines))
    print(f"[INFO] Markdown report generated: {m_path}")


def print_result(result: Dict[str, Any]) -> None:
    print(f"\n[{result['tool']}]")
    print(f"Status: {result['status']}")
    print(f"Total Issues: {result['total_issues']}")
    print(f"Blocking Issues: {result['blocking_issues']}")

    if result["examples"]:
        print("Examples (First 2):")
        for example in result["examples"][:2]:
            print(json.dumps(example, indent=2, ensure_ascii=False))


def run_policy_engine(
    scan_dir: Path,
    html_path: Path | None = None,
    md_path: Path | None = None,
    req_path: Path | None = None,
    dependency_manifests: list[DependencyManifest] | None = None,
    reporter_callback = None,
    operational_failures: List[str] | None = None,
    tool_states: Dict[str, str] | None = None,
    waf_enabled: bool | None = None,
) -> int:
    if dependency_manifests is None:
        if req_path:
            dependency_manifests = _normalize_manifests(req_path)
        elif os.environ.get("AEGIS_TARGET_PATH"):
            dependency_manifests = discover_dependency_manifests(Path(os.environ["AEGIS_TARGET_PATH"]))
        else:
            dependency_manifests = []

    # Run CycloneDX SBOM Generation
    try:
        generate_cyclonedx_sbom(dependency_manifests, scan_dir / "sbom.json")
    except Exception as e:
        print(f"[WARN] Failed to generate SBOM manifest: {e}")

    ruff_report = load_json(scan_dir / "ruff-report.json")
    safety_report = load_json(scan_dir / "safety-report.json")
    trivy_report = load_json(scan_dir / "trivy-report.json")
    secrets_report = load_json(scan_dir / "secrets-report.json")
    yara_report = load_json(scan_dir / "yara-report.json")
    semgrep_report = load_json(scan_dir / "semgrep-report.json")
    clamav_report = load_json(scan_dir / "clamav-report.json")
    zap_report = load_json(scan_dir / "zap-report.json")

    osv_report_path = scan_dir / "osv-report.json"
    cached_osv_report = load_json(osv_report_path)
    if cached_osv_report is not None:
        osv_findings = cached_osv_report
    elif not dependency_manifests:
        osv_findings = []
        osv_report_path.write_text(json.dumps(osv_findings, indent=2))
    else:
        try:
            osv_findings = query_osv_vulnerabilities(dependency_manifests)
            osv_report_path.write_text(json.dumps(osv_findings, indent=2))
            print(f"[INFO] OSV scan completed. Report written to {osv_report_path}")
        except Exception as e:
            print(f"[WARN] OSV scan execution failed: {e}")
            osv_findings = []

    results = [
        analyze_ruff(ruff_report),
        analyze_semgrep(semgrep_report),
        analyze_safety(safety_report),
        analyze_osv(osv_findings),
        analyze_trivy(trivy_report),
        analyze_secrets(secrets_report),
        analyze_yara(yara_report),
        analyze_clamav(clamav_report),
        analyze_zap(zap_report),
    ]

    state_aliases = {
        "Ruff (SAST)": "Ruff",
        "Semgrep": "Semgrep",
        "Safety": "Safety",
        "OSV Dependency Audit": "OSV",
        "Trivy": "Trivy",
        "Secrets Scanner": "Secrets",
        "YARA Scanner": "YARA",
        "ClamAV": "ClamAV",
        "Aegis DAST Probe": "DAST",
    }
    for result in results:
        scanner_state = (tool_states or {}).get(state_aliases[result["tool"]])
        if scanner_state == "skipped":
            result["status"] = "SKIPPED"
        elif scanner_state == "failed":
            result["status"] = "ERROR"

    failed_tools = [result["tool"] for result in results if result["status"] == "FAIL"]
    missing_tools = [result["tool"] for result in results if result["status"] == "MISSING"]

    final_status = "ALLOWED"
    reason = "No blocking security issues found."

    if operational_failures:
        final_status = "ERROR"
        reason = f"Operational scanner failure(s): {', '.join(operational_failures)}"
    elif failed_tools or missing_tools:
        final_status = "BLOCKED"
        reasons = []
        if failed_tools:
            reasons.append(f"Blocking security issues found by: {', '.join(failed_tools)}")
        if missing_tools:
            reasons.append(f"Required scan reports missing for: {', '.join(missing_tools)}")
        reason = " | ".join(reasons)

    # Determine WAF status from environment (injected by main.py)
    if waf_enabled is None:
        waf_enabled = os.environ.get("WAF_ENABLED", "false").lower() == "true"
    exploitability_score = calculate_exploitability_score(results, waf_enabled)

    if reporter_callback:
        reporter_callback(results, final_status, reason, exploitability_score)
    else:
        for result in results:
            print_result(result)
        print("\n=== Final Decision ===")
        print(f"DEPLOYMENT {final_status}")
        print(f"Reason: {reason}")
        print(f"Exploitability Score: {exploitability_score}%")

    generate_reports(results, final_status, reason, exploitability_score, html_path=html_path, md_path=md_path)

    if final_status == "ERROR":
        return 2
    return 1 if final_status == "BLOCKED" else 0


def main() -> int:
    print("=== Aegis Policy Engine ===")
    return run_policy_engine(SCAN_DIR)


if __name__ == "__main__":
    sys.exit(main())
