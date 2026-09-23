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
from app.findings import BASELINE_FINGERPRINT_KEY, extract_findings, strip_baseline_findings
from app.safe_output import SafeOutputRoot
from app.version import get_package_version
from app.resource_budgets import (
    ResourceLimitError,
    load_bounded_json,
    read_bounded,
    resource_budgets,
)

# Use an explicit scanner directory when provided. Otherwise keep reports in
# the persistent Aegis data directory used by the dashboard and worker.
_data_dir = os.environ.get("AEGIS_DATA_DIR")
_default_scan_dir = Path(_data_dir) / "scans" if _data_dir else Path("scans")
SCAN_DIR = Path(os.environ.get("SCANS_DIR", _default_scan_dir))

SCRIPT_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = SCRIPT_DIR / "app" / "templates" / "report_template.html"

HTML_REPORT = SCAN_DIR / "report.html"
MD_REPORT = SCAN_DIR / "report.md"


def get_env_set(var_name: str, default: set) -> set:
    val = os.environ.get(var_name)
    if val is None:
        return default
    return {item.strip().upper() for item in val.split(",") if item.strip()}


FAIL_ON_SEVERITIES = get_env_set("FAIL_ON", {"MEDIUM", "HIGH", "CRITICAL"})
FAIL_ON_RUFF_SEVERITIES = get_env_set("FAIL_ON_RUFF", get_env_set("FAIL_ON_BANDIT", FAIL_ON_SEVERITIES))
FAIL_ON_SEMGREP_SEVERITIES = get_env_set("FAIL_ON_SEMGREP", FAIL_ON_SEVERITIES)
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def load_json(path: Path) -> Any:
    if not path.exists():
        print(f"[WARN] Missing report: {path}")
        return None

    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ResourceLimitError):
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
    elif tool == "OSV Dependency Audit":
        fixed_versions = issue.get("fixed_versions") or issue.get("fixed") or issue.get("version")
        guidance.update({
            "why": "The dependency version is associated with a published vulnerability advisory.",
            "fix": "Upgrade to a fixed version, verify compatibility, and commit the lockfile or requirements change.",
            "suggestion": _format_dependency_fix(package_name, fixed_versions),
        })
    elif tool == "Secrets Scanner":
        guidance.update({
            "why": "A plaintext credential can be copied from source history and used outside the application.",
            "fix": "Revoke and rotate the credential, move it to a secret manager or environment variable, and remove it from history.",
            "suggestion": "export SERVICE_TOKEN=\"...\"\n# read it with os.environ[\"SERVICE_TOKEN\"]",
        })
    elif tool == "YARA Scanner":
        guidance.update({
            "why": "A malware or suspicious-code signature matched the target file.",
            "fix": "Quarantine the file, inspect its origin, and replace it from a trusted source.",
            "suggestion": "# Remove the suspicious file and restore from trusted source control\ngit restore path/to/file",
        })
    elif tool == "CodeQL":
        guidance.update({
            "why": "CodeQL identified a potentially unsafe data or control path that requires review.",
            "fix": "Inspect the reported path and validate input before it reaches the unsafe operation.",
            "suggestion": "# Review the CodeQL path, apply a targeted fix, then rerun a deep scan",
        })

    enriched.setdefault("finding_status", "Unclassified in this standalone report")
    enriched.pop(BASELINE_FINGERPRINT_KEY, None)
    enriched["why_it_matters"] = guidance["why"]
    enriched["remediation"] = guidance["fix"]
    enriched["fix_suggestion"] = guidance["suggestion"]
    enriched["suppression_guidance"] = "Suppress only after a named owner verifies the risk is accepted, non-exploitable, or covered by a compensating control."
    enriched["suppression_example"] = _suppression_example(tool, enriched)
    return enriched


def analyze_ruff(report: Any, fail_on: set[str] | None = None) -> Dict[str, Any]:
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
        if issue["severity"] in (fail_on if fail_on is not None else FAIL_ON_RUFF_SEVERITIES)
    ]

    return {
        "tool": "Ruff (SAST)",
        "total_issues": len(issues),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
        "severity_counts": _severity_counts(issues),
        "examples": (blocking_issues if blocking_issues else issues)[:5],
    }


def analyze_semgrep(
    report: Dict[str, Any] | None,
    fail_on: set[str] | None = None,
) -> Dict[str, Any]:
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
        if issue["severity"] in (fail_on if fail_on is not None else FAIL_ON_SEMGREP_SEVERITIES)
    ]

    return {
        "tool": "Semgrep",
        "total_issues": len(issues),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
        "severity_counts": _severity_counts(issues),
        "examples": (blocking_issues if blocking_issues else issues)[:5],
    }


def analyze_osv(
    report: List[Dict[str, Any]] | None,
    fail_on: set[str] | None = None,
) -> Dict[str, Any]:
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

    blocking_issues = [
        f for f in findings
        if f["severity"] in (fail_on if fail_on is not None else FAIL_ON_SEVERITIES)
    ]

    return {
        "tool": "OSV Dependency Audit",
        "total_issues": len(findings),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:5],
    }


def analyze_codeql(report: Any, fail_on: set[str] | None = None) -> Dict[str, Any]:
    """Analyze the complete normalized CodeQL report, independent of display limits."""
    error = {
        "tool": "CodeQL", "total_issues": 0, "blocking_issues": 0,
        "status": "ERROR", "examples": [], "findings": [],
    }
    if not isinstance(report, dict) or report.get("status") != "completed":
        return error
    coverage = report.get("coverage")
    raw_findings = report.get("findings")
    if (
        not isinstance(coverage, dict)
        or coverage.get("complete") is not True
        or not isinstance(coverage.get("languages"), list)
        or not coverage["languages"]
        or coverage.get("isolation") != "verified"
        or not isinstance(raw_findings, list)
    ):
        return error
    findings = []
    for item in raw_findings:
        if not isinstance(item, dict) or not item.get("rule_id") or not item.get("filename"):
            return error
        severity = str(item.get("severity") or "").upper()
        if severity not in SEVERITIES:
            return error
        findings.append(enrich_finding("CodeQL", {
            **item,
            "test_id": item["rule_id"],
            "severity": severity,
        }))
    threshold = fail_on if fail_on is not None else FAIL_ON_SEVERITIES
    blocking = [item for item in findings if item["severity"] in threshold]
    return {
        "tool": "CodeQL", "total_issues": len(findings),
        "blocking_issues": len(blocking),
        "status": "FAIL" if blocking else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": (blocking if blocking else findings)[:5],
        "findings": findings,
        "coverage": coverage,
    }


def analyze_secrets(
    report: Dict[str, Any] | None,
    fail_on: set[str] | None = None,
) -> Dict[str, Any]:
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

    threshold = fail_on if fail_on is not None else FAIL_ON_SEVERITIES
    blocking_count = len(findings) if "HIGH" in threshold else 0
    return {
        "tool": "Secrets Scanner",
        "total_issues": len(findings),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:5],
    }


def analyze_yara(
    report: List[Dict[str, Any]] | None,
    fail_on: set[str] | None = None,
) -> Dict[str, Any]:
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

    threshold = fail_on if fail_on is not None else FAIL_ON_SEVERITIES
    blocking_count = len(findings) if "HIGH" in threshold else 0
    return {
        "tool": "YARA Scanner",
        "total_issues": len(findings),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count else "PASS",
        "severity_counts": _severity_counts(findings),
        "examples": findings[:5],
    }


def analyze_report_set(
    reports: Dict[str, Any],
    fail_on: set[str] | None = None,
) -> List[Dict[str, Any]]:
    """Normalize scanner reports through the canonical analyzer set."""

    return [
        analyze_ruff(reports.get("ruff"), fail_on),
        analyze_semgrep(reports.get("semgrep"), fail_on),
        analyze_osv(reports.get("osv"), fail_on),
        analyze_secrets(reports.get("secrets"), fail_on),
        *([analyze_yara(reports.get("yara"), fail_on)] if "yara" in reports else []),
        *([analyze_codeql(reports.get("codeql"), fail_on)] if "codeql" in reports else []),
    ]


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
        parse_error = None
        if path.exists():
            try:
                packages = tuple(
                    extract_packages_from_manifest(
                        path, path.name, ecosystem, raise_errors=True
                    )
                )
            except Exception as exc:
                packages = ()
                parse_error = f"{type(exc).__name__}: {exc}"
        else:
            packages = ()
        return [
            DependencyManifest(
                path=path,
                kind=path.name,
                ecosystem=ecosystem,
                packages=packages,
                parse_error=parse_error,
            )
        ]
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
                
    aegis_version = get_package_version()
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
                        "version": aegis_version,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "Aegis",
                "version": aegis_version,
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
LOCKFILE_KINDS = {
    "uv.lock",
    "poetry.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}


def _dependency_inventory_errors(manifests: list[DependencyManifest]) -> list[str]:
    errors = [
        f"{manifest.path}: {manifest.parse_error}"
        for manifest in manifests
        if manifest.parse_error
    ]
    locked_package_names: dict[str, set[str]] = {}
    for manifest in manifests:
        if manifest.kind not in LOCKFILE_KINDS or manifest.parse_error:
            continue
        names = locked_package_names.setdefault(manifest.ecosystem, set())
        names.update(package.name.lower() for package in manifest.packages)
    unresolved_manifests = [
        manifest
        for manifest in manifests
        if any(
            package.version is None
            and package.name.lower()
            not in locked_package_names.get(manifest.ecosystem, set())
            for package in manifest.packages
        )
    ]
    if unresolved_manifests:
        descriptions = ", ".join(
            f"{manifest.path} ({manifest.ecosystem})"
            for manifest in unresolved_manifests
        )
        errors.append(
            "Dependency inventory incomplete; exact versions are required for "
            f"OSV queries: {descriptions}"
        )
    return errors


def query_osv_vulnerabilities(
    manifests_or_path: Any,
    *,
    raise_on_error: bool = False,
) -> List[Dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failed_queries = []
    packages_by_key: dict[tuple[str, str, str], DependencyPackage] = {}
    manifests = _normalize_manifests(manifests_or_path)
    inventory_errors = _dependency_inventory_errors(manifests)
    if inventory_errors and raise_on_error:
        raise RuntimeError(
            "Dependency manifest parsing failed or inventory incomplete: "
            + "; ".join(inventory_errors)
        )

    for manifest in manifests:
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
            loaded_cache = load_bounded_json(OSV_CACHE_FILE)
            cache = loaded_cache if isinstance(loaded_cache, dict) else {}
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

        entry = cache.get(cache_key)
        cached_vulns = None
        entry_age = None
        if isinstance(entry, dict) and isinstance(entry.get("vulns"), list):
            cached_vulns = entry["vulns"]
            try:
                entry_age = current_time - float(entry.get("timestamp", 0))
            except (TypeError, ValueError):
                entry_age = None
            if entry_age is not None and 0 <= entry_age < CACHE_TTL:
                findings.extend(cached_vulns)
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
                resp_data = json.loads(
                    read_bounded(
                        response,
                        resource_budgets().max_parser_input_bytes,
                    ).decode("utf-8")
                )
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
                        "aliases": [
                            str(alias) for alias in vuln.get("aliases", []) if alias
                        ],
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
            if cached_vulns is not None and entry_age is not None and 0 <= entry_age < CACHE_TTL:
                findings.extend(cached_vulns)
            elif cached_vulns is not None:
                # A stale result may be useful for a best-effort report, but it
                # must remain an operational failure for strict release gates.
                findings.extend(cached_vulns)
                failed_queries.append(cache_key)
            else:
                failed_queries.append(cache_key)

    if cache_dirty:
        try:
            OSV_CACHE_FILE.write_text(json.dumps(cache, indent=2))
        except Exception as e:
            print(f"[WARN] Failed to write OSV Cache: {e}")

    if raise_on_error and failed_queries:
        raise RuntimeError(
            "OSV queries failed or used stale cache for: "
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
    # This is a heuristic index, not a probability of exploitation. It reflects
    # the worst credible finding without growing linearly merely because a
    # scanner emitted many low-confidence matches.
    maximum_risk = max(severities) * 10.0
    volume_bonus = min(15.0, math.log2(len(severities) + 1) * 2.5)
    return round(min(100.0, maximum_risk + volume_bonus), 1)


def generate_reports(
    results: List[Dict[str, Any]],
    final_status: str,
    reason: str,
    exploitability_score: float = 0.0,
    html_path: Path | None = None,
    md_path: Path | None = None,
    output_root: SafeOutputRoot | None = None,
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
        if output_root:
            output_root.write_text(output_root.relative_path(h_path), html_content)
        else:
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
        f"**Heuristic risk index (0-100):** {exploitability_score}",
        "*This index is a relative severity signal, not a probability of exploitation.*",
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
    if output_root:
        output_root.write_text(output_root.relative_path(m_path), "\n".join(md_lines))
    else:
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


def evaluate_policy_results(
    results: List[Dict[str, Any]],
    operational_failures: List[str] | None = None,
    *,
    fail_on_errors: bool = True,
) -> Dict[str, Any]:
    """Return the single fail-closed decision used by every report surface."""

    failed_tools = [result["tool"] for result in results if result["status"] == "FAIL"]
    missing_tools = [
        result["tool"] for result in results if result["status"] == "MISSING"
    ]
    scanner_errors = [
        result["tool"] for result in results if result["status"] == "ERROR"
    ]
    error_tools = list(dict.fromkeys([*(operational_failures or []), *scanner_errors]))

    if error_tools and (fail_on_errors or "CodeQL" in error_tools):
        return {
            "status": "ERROR",
            "reason": f"Operational scanner failure(s): {', '.join(error_tools)}",
            "failed_tools": failed_tools,
            "missing_tools": missing_tools,
            "error_tools": error_tools,
        }

    if failed_tools or missing_tools:
        reasons = []
        if failed_tools:
            reasons.append(
                f"Blocking security issues found by: {', '.join(failed_tools)}"
            )
        if missing_tools:
            reasons.append(
                f"Required scan reports missing for: {', '.join(missing_tools)}"
            )
        return {
            "status": "BLOCKED",
            "reason": " | ".join(reasons),
            "failed_tools": failed_tools,
            "missing_tools": missing_tools,
            "error_tools": [],
        }

    return {
        "status": "ALLOWED",
        "reason": "No blocking security issues found.",
        "failed_tools": [],
        "missing_tools": [],
        "error_tools": [],
    }


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
    fail_on_severities: set[str] | None = None,
    fail_on_scanner_errors: bool = True,
    output_root: SafeOutputRoot | None = None,
    baseline_fingerprints: set[str] | None = None,
) -> int:
    effective_operational_failures = list(operational_failures or [])
    if dependency_manifests is None:
        if req_path:
            dependency_manifests = _normalize_manifests(req_path)
        elif os.environ.get("AEGIS_TARGET_PATH"):
            dependency_manifests = discover_dependency_manifests(Path(os.environ["AEGIS_TARGET_PATH"]))
        else:
            dependency_manifests = []

    # Run CycloneDX SBOM Generation
    sbom_path = output_root.file("sbom.json") if output_root else scan_dir / "sbom.json"
    try:
        generate_cyclonedx_sbom(dependency_manifests, sbom_path)
    except Exception as e:
        print(f"[WARN] Failed to generate SBOM manifest: {e}")

    ruff_report = load_json(scan_dir / "ruff-report.json")
    secrets_report = load_json(scan_dir / "secrets-report.json")
    semgrep_report = load_json(scan_dir / "semgrep-report.json")
    yara_report = load_json(scan_dir / "yara-report.json") if (scan_dir / "yara-report.json").exists() else None
    codeql_report = load_json(scan_dir / "codeql-report.json") if (scan_dir / "codeql-report.json").exists() else None

    osv_report_path = output_root.file("osv-report.json") if output_root else scan_dir / "osv-report.json"
    cached_osv_report = load_json(osv_report_path)
    inventory_errors = _dependency_inventory_errors(dependency_manifests)
    if inventory_errors and fail_on_scanner_errors:
        osv_findings: list[dict] = []
        if "OSV" not in effective_operational_failures:
            effective_operational_failures.append("OSV")
        if output_root:
            output_root.write_json_path(osv_report_path, osv_findings)
        else:
            osv_report_path.write_text(json.dumps(osv_findings, indent=2))
        print(
            "[WARN] Dependency manifest/inventory validation failed: "
            + "; ".join(inventory_errors)
        )
    elif cached_osv_report is not None:
        osv_findings = cached_osv_report
    elif not dependency_manifests:
        osv_findings = []
        if output_root:
            output_root.write_json_path(osv_report_path, osv_findings)
        else:
            osv_report_path.write_text(json.dumps(osv_findings, indent=2))
    else:
        try:
            osv_findings = query_osv_vulnerabilities(
                dependency_manifests,
                raise_on_error=fail_on_scanner_errors,
            )
            if output_root:
                output_root.write_json_path(osv_report_path, osv_findings)
            else:
                osv_report_path.write_text(json.dumps(osv_findings, indent=2))
            print(f"[INFO] OSV scan completed. Report written to {osv_report_path}")
        except Exception as e:
            print(f"[WARN] OSV scan execution failed: {e}")
            osv_findings = []
            if fail_on_scanner_errors and "OSV" not in effective_operational_failures:
                effective_operational_failures.append("OSV")

    report_set = {
        "ruff": ruff_report,
        "semgrep": semgrep_report,
        "osv": osv_findings,
        "secrets": secrets_report,
    }
    if (tool_states is None and yara_report is not None) or (tool_states or {}).get("YARA") in {"completed", "failed"}:
        report_set["yara"] = yara_report
    if (tool_states is None and codeql_report is not None) or (tool_states or {}).get("CodeQL") in {"completed", "failed"}:
        report_set["codeql"] = codeql_report

    # Diff-aware gating: tag raw entries with their durable fingerprints, then
    # exclude findings that already exist in the project baseline from the
    # blocking evaluation. Persisted evidence reports stay unfiltered.
    baseline_exempted_total = 0
    if baseline_fingerprints:
        extract_findings(report_set)
        filtered_reports = {}
        for key, report in report_set.items():
            filtered_reports[key], exempted = strip_baseline_findings(
                report, baseline_fingerprints
            )
            baseline_exempted_total += exempted
        report_set = filtered_reports

    results = analyze_report_set(
        report_set,
        fail_on_severities,
    )

    state_aliases = {
        "Ruff (SAST)": "Ruff",
        "Semgrep": "Semgrep",
        "OSV Dependency Audit": "OSV",
        "Secrets Scanner": "Secrets",
        "YARA Scanner": "YARA",
        "CodeQL": "CodeQL",
    }
    for result in results:
        scanner_state = (tool_states or {}).get(state_aliases[result["tool"]])
        if scanner_state == "skipped":
            result["status"] = "SKIPPED"
        elif scanner_state == "failed":
            result["status"] = "ERROR"

    decision = evaluate_policy_results(
        results,
        effective_operational_failures,
        fail_on_errors=fail_on_scanner_errors,
    )
    final_status = decision["status"]
    reason = decision["reason"]
    if baseline_exempted_total and final_status == "ALLOWED":
        reason += (
            f" Diff-aware gating: {baseline_exempted_total} pre-existing finding(s) "
            "excluded from this decision."
        )

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

    generate_reports(
        results,
        final_status,
        reason,
        exploitability_score,
        html_path=html_path,
        md_path=md_path,
        output_root=output_root,
    )

    if final_status == "ERROR":
        return 2
    return 1 if final_status == "BLOCKED" else 0


def main() -> int:
    print("=== Aegis Policy Engine ===")
    return run_policy_engine(SCAN_DIR)


if __name__ == "__main__":
    sys.exit(main())
