import json
import os
import re
import sys
import math
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, select_autoescape

from app.dependencies import DependencyManifest, DependencyPackage, discover_dependency_manifests, extract_packages_from_manifest
from app.findings import (
    BASELINE_FINGERPRINT_KEY,
    UNSCORED_ADVISORY_REASON,
    _stable_path,
    escalate_osv_severity,
    extract_findings,
    osv_base_severity,
    strip_baseline_findings,
)
from app.safe_output import SafeOutputRoot
from app.version import get_package_version
from app.resource_budgets import (
    ResourceLimitError,
    load_bounded_json,
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
    rank = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return dict(sorted(counts.items(), key=lambda item: (rank.index(item[0]) if item[0] in rank else len(rank), item[0])))


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
    # Suppressions match the first word of the tool name ("Ruff", not "Ruff (SAST)").
    scope = (
        [f"      fingerprint: {issue['occurrence']}"] if issue.get("occurrence")
        else [f"      path: {issue.get('display_path') or issue.get('path') or 'requirements.txt'}"]
    )
    return "\n".join([
        "scan:",
        "  suppressions:",
        f"    - tool: {tool.split()[0]}",
        f"      rule: {rule}",
        *scope,
        "      reason: Reviewed and accepted by the security owner.",
        "      approved_by: security-owner",
        "      ticket: SEC-000",
        "      expires_at: YYYY-MM-DD",
    ])


def enrich_finding(tool: str, issue: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(issue)
    rule = str(issue.get("test_id") or issue.get("id") or issue.get("vulnerability_id") or issue.get("rule") or "").upper()
    package_name = issue.get("package_name")

    guidance = {
        "why": "This finding can weaken the security gate and should be reviewed before release.",
        "fix": "Review the affected code or dependency, apply the smallest safe change, and rerun Aegis.",
        "suggestion": "",
    }

    if tool == "Ruff (SAST)":
        guidance.update({
            "why": "A Python security rule matched source code that may allow unsafe runtime behavior.",
            "fix": "Replace the risky API or add input validation before user-controlled data reaches it.",
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
        fixed_versions = issue.get("fixed_versions") or issue.get("fixed")
        guidance.update({
            "why": " ".join(filter(None, [
                "The dependency version is associated with a published vulnerability advisory.",
                f"Severity raised: {issue['severity_reason']}." if issue.get("severity_reason") else "",
            ])),
            "fix": "Upgrade to a fixed version, verify compatibility, and commit the lockfile or requirements change.",
            "suggestion": _format_dependency_fix(package_name, fixed_versions),
        })
    elif tool == "Secrets Scanner":
        guidance.update({
            "why": "A plaintext credential can be copied from source history and used outside the application.",
            "fix": "If this is a real credential, revoke and rotate it, load it from a secret manager or environment variable, and remove it from history. If it is a hash, commit ID, or public key, suppress it with that reason.",
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
        })

    path = _stable_path(issue.get("filename")) if issue.get("filename") else ""
    line = issue.get("line_number")
    package = " ".join(str(part) for part in (package_name, issue.get("version")) if part)
    enriched["display_path"] = path
    enriched["display_location"] = (f"{path}:{line}" if path and line else path) or package or issue.get("target") or ""
    # CodeQL messages carry SARIF link markup such as "[user-provided value](1)".
    enriched["display_title"] = re.sub(r"\[([^\]]+)\]\(\d+\)", r"\1", str(
        issue.get("issue_text")
        or issue.get("summary")
        or (f"Possible secret: {issue['type']}" if issue.get("type") else "")
        or (f"Signature match: {issue['rule']}" if issue.get("rule") else "")
        or issue.get("id")
        or tool
    ))
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
            "occurrence": r.get("aegis_occurrence"),
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


def semgrep_rule_id(check_id: Any) -> str:
    """Return the bare rule ID.

    Semgrep prefixes ``check_id`` with the rules file's path relative to the
    working directory (for example ``Users.alice.app.rules.python-eval``), so the
    raw value differs between machines and can expose local paths. Aegis rule
    IDs contain no dots.
    """
    return str(check_id or "").rsplit(".", 1)[-1]


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
            "test_id": semgrep_rule_id(r.get("check_id")),
            "filename": r.get("path"),
            "line_number": r.get("start", {}).get("line"),
            "issue_text": extra.get("message"),
            "code": extra.get("lines"),
            "occurrence": r.get("aegis_occurrence"),
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
        severity, reason = escalate_osv_severity(osv_base_severity(f.get("cvss")), f)
        if reason is None and f.get("cvss") is None:
            reason = UNSCORED_ADVISORY_REASON
        findings.append(enrich_finding("OSV Dependency Audit", {
            "severity": severity,
            "id": f.get("id"),
            "package_name": f.get("package"),
            "version": f.get("version"),
            "cvss": f.get("cvss"),
            "epss": f.get("epss"),
            "kev": f.get("kev"),
            "severity_reason": reason,
            "summary": f.get("summary"),
            "details": f.get("details"),
            "occurrence": f.get("aegis_occurrence"),
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
        or coverage.get("isolation") not in {"verified", "imported"}
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
            "occurrence": item.get("aegis_occurrence"),
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
                "occurrence": secret.get("aegis_occurrence"),
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
            "author": f.get("author"),
            "occurrence": f.get("aegis_occurrence"),
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

        if vector_upper.startswith("CVSS:4"):
            return 0.0  # CVSS v4 uses a different scoring system; see _normalize_osv_advisory.
        if vector_upper.startswith("CVSS:"):
            parts = vector_upper.split("/", 1)[1].split("/")
        else:
            parts = vector_upper.split("/")
            
        metrics = {}
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.strip()] = v.strip()
        if "AU" in metrics:
            return _cvss_v2_base_score(metrics)
                
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


def _cvss_v2_base_score(metrics: dict[str, str]) -> float:
    """CVSS v2 base score (FIRST CVSS v2 guide, section 3.2.1)."""
    impact_weights = {"N": 0.0, "P": 0.275, "C": 0.660}
    impact = 10.41 * (1 - math.prod(1 - impact_weights.get(metrics.get(key, "N"), 0.0) for key in ("C", "I", "A")))
    exploitability = (
        20
        * {"L": 0.395, "A": 0.646, "N": 1.0}.get(metrics.get("AV", "N"), 1.0)
        * {"H": 0.35, "M": 0.61, "L": 0.71}.get(metrics.get("AC", "L"), 0.71)
        * {"M": 0.45, "S": 0.56, "N": 0.704}.get(metrics.get("AU", "N"), 0.704)
    )
    if impact == 0:
        return 0.0
    score = (0.6 * impact + 0.4 * exploitability - 1.5) * 1.176
    return math.floor(score * 10 + 0.5 + 1e-9) / 10


# Representative scores for an advisory's qualitative severity (GitHub uses MODERATE).
QUALITATIVE_CVSS_SCORES = {"CRITICAL": 9.0, "HIGH": 7.0, "MODERATE": 4.0, "MEDIUM": 4.0, "LOW": 0.1}
OSV_CACHE_FILE = SCAN_DIR / "osv-cache.json"
OSV_API_URL = "https://api.osv.dev"
OSV_REQUEST_DEADLINE_SECONDS = 10.0
# Wall-clock budget for one complete dependency audit (all batches and advisories).
OSV_TOTAL_DEADLINE_SECONDS = 300.0
OSV_BATCH_SIZE = 1000  # queries per querybatch request
OSV_MAX_PAGES = 20
OSV_HYDRATION_WORKERS = 4
# Bump the version when _normalize_osv_advisory changes, so cached records are rebuilt.
OSV_ADVISORY_CACHE_PREFIX = "osv-advisory-v2:"
OSV_RECORD_SCHEMA = 2  # package cache entries written before this are re-queried
EXPLOIT_INTEL_CACHE_FILE = SCAN_DIR / "exploit-intel-cache.json"
# CISA's catalog, then CISA's own GitHub mirror of the same file.
KEV_FEED_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100  # the EPSS API returns at most 100 rows per page by default
EXPLOIT_INTEL_TTL_SECONDS = 86400  # both feeds publish daily
EXPLOIT_INTEL_MAX_STALE_SECONDS = 7 * 86400  # oldest copy a strict gate may rely on
EXPLOIT_INTEL_DEADLINE_SECONDS = 20.0
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


def _osv_request(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call one OSV endpoint with a byte budget and a wall-clock deadline."""
    request = urllib.request.Request(
        f"{OSV_API_URL}{path}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Aegis-Scanner/2.0"},
        method="GET" if payload is None else "POST",
    )
    deadline = time.monotonic() + OSV_REQUEST_DEADLINE_SECONDS
    limit = resource_budgets().max_parser_input_bytes
    body = b""
    with urllib.request.urlopen(request, timeout=OSV_REQUEST_DEADLINE_SECONDS) as response:
        # read1 returns after one socket read, so a dribbling server cannot outlast the deadline.
        while chunk := response.read1(64 * 1024):
            body += chunk
            if len(body) > limit:
                raise ResourceLimitError(f"OSV response exceeds the configured limit of {limit} bytes.")
            if time.monotonic() > deadline:
                raise TimeoutError("OSV response exceeded its deadline.")
    decoded = json.loads(body.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("OSV returned a non-object response.")
    return decoded


def _osv_batch_advisory_ids(packages: list[DependencyPackage]) -> list[dict[str, str]]:
    """Map each package to {advisory id: modified} with one querybatch call per page.

    The batch endpoint returns only advisory IDs. Results whose advisories do
    not fit on one page carry a next_page_token and are queried again.
    """
    queries = [
        {"version": package.version, "package": {"name": package.name, "ecosystem": package.ecosystem}}
        for package in packages
    ]
    advisories: list[dict[str, str]] = [{} for _ in packages]
    pending = list(range(len(packages)))
    tokens: dict[int, str] = {}
    for _page in range(OSV_MAX_PAGES):
        if not pending:
            return advisories
        response = _osv_request("/v1/querybatch", {
            "queries": [
                {**queries[index], **({"page_token": tokens[index]} if index in tokens else {})}
                for index in pending
            ],
        })
        results = response.get("results")
        if not isinstance(results, list) or len(results) != len(pending):
            raise ValueError("OSV batch response does not match the submitted queries.")
        next_pending = []
        for index, result in zip(pending, results):
            if not isinstance(result, dict):
                raise ValueError("OSV batch response contains a malformed result.")
            for vuln in result.get("vulns") or []:
                if isinstance(vuln, dict) and vuln.get("id"):
                    advisories[index][str(vuln["id"])] = str(vuln.get("modified") or "")
            if result.get("next_page_token"):
                tokens[index] = str(result["next_page_token"])
                next_pending.append(index)
        pending = next_pending
    raise ValueError("OSV pagination exceeded the page limit.")


def _normalize_osv_advisory(vuln: dict[str, Any]) -> dict[str, Any]:
    cvss_score = None
    vector = None
    db_spec = vuln.get("database_specific", {})
    if isinstance(db_spec, dict):
        cvss_data = db_spec.get("cvss")
        if isinstance(cvss_data, dict):
            cvss_score = cvss_data.get("score")
            vector = cvss_data.get("vector")
    if cvss_score is None:
        severities = vuln.get("severity")
        vectors = {
            sev.get("type"): str(sev.get("score") or "")
            for sev in (severities if isinstance(severities, list) else [])
            if isinstance(sev, dict) and sev.get("score")
        }
        qualitative = str(db_spec.get("severity") or "").upper() if isinstance(db_spec, dict) else ""
        # Prefer a computed CVSS v3 score, then the publisher's own rating (CVSS
        # v4 is not computed here), then CVSS v2. Otherwise leave it unscored.
        if "CVSS_V3" in vectors:
            vector = vectors["CVSS_V3"]
            cvss_score = parse_cvss_vector(vector)
        elif qualitative in QUALITATIVE_CVSS_SCORES:
            vector = vectors.get("CVSS_V4") or vectors.get("CVSS_V2")
            cvss_score = QUALITATIVE_CVSS_SCORES[qualitative]
        elif "CVSS_V2" in vectors:
            vector = vectors["CVSS_V2"]
            cvss_score = parse_cvss_vector(vector)
        else:
            vector = vectors.get("CVSS_V4")
    return {
        "id": vuln.get("id"),
        "aliases": [str(alias) for alias in vuln.get("aliases", []) if alias],
        "cvss": cvss_score,
        "vector": vector,
        "summary": vuln.get("summary", "No summary provided."),
        "details": vuln.get("details", "No details provided."),
    }


def _hydrate_osv_advisories(
    wanted: dict[str, str], cache: dict[str, Any], deadline: float | None = None
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Fetch full advisory records, reusing cached ones whose modified time is unchanged."""
    records: dict[str, dict[str, Any]] = {}
    to_fetch = []
    for advisory_id, modified in wanted.items():
        entry = cache.get(f"{OSV_ADVISORY_CACHE_PREFIX}{advisory_id}")
        if (
            modified
            and isinstance(entry, dict)
            and entry.get("modified") == modified
            and isinstance(entry.get("record"), dict)
        ):
            records[advisory_id] = entry["record"]
        else:
            to_fetch.append(advisory_id)
    failed: set[str] = set()
    if not to_fetch:
        return records, failed
    executor = ThreadPoolExecutor(max_workers=OSV_HYDRATION_WORKERS)
    try:
        futures = {
            advisory_id: executor.submit(
                _osv_request, f"/v1/vulns/{urllib.parse.quote(advisory_id, safe='')}"
            )
            for advisory_id in to_fetch
        }
        for advisory_id, future in futures.items():
            try:
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                record = _normalize_osv_advisory(future.result(timeout=remaining))
            except Exception as exc:
                print(f"[WARN] Failed to fetch OSV advisory {advisory_id}: {exc}")
                failed.add(advisory_id)
                continue
            records[advisory_id] = record
            cache[f"{OSV_ADVISORY_CACHE_PREFIX}{advisory_id}"] = {
                "modified": wanted[advisory_id],
                "record": record,
            }
    finally:
        # Do not wait for in-flight requests on cancel or error; each one ends at its deadline.
        executor.shutdown(wait=False, cancel_futures=True)
    return records, failed


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

    # 1. Split packages into fresh cache hits and packages that need a query.
    cached: dict[str, tuple[list[dict] | None, float | None]] = {}
    stale_packages = []
    for package in packages:
        cache_key = f"{package.ecosystem}:{package.name.lower()}@{package.version}"
        entry = cache.get(cache_key)
        cached_vulns: list[dict] | None = None
        entry_age: float | None = None
        if isinstance(entry, dict) and isinstance(entry.get("vulns"), list):
            cached_vulns = entry["vulns"]
            try:
                entry_age = current_time - float(entry.get("timestamp", 0))
            except (TypeError, ValueError):
                pass
        cached[cache_key] = (cached_vulns, entry_age)
        fresh = (
            isinstance(entry, dict) and entry.get("schema") == OSV_RECORD_SCHEMA
            and entry_age is not None and 0 <= entry_age < CACHE_TTL
        )
        if not (cached_vulns is not None and fresh):
            stale_packages.append(package)

    # 2. Ask OSV which advisories affect each stale package, in batches.
    package_advisories: dict[str, dict[str, str] | None] = {}
    deadline = time.monotonic() + OSV_TOTAL_DEADLINE_SECONDS
    for start in range(0, len(stale_packages), OSV_BATCH_SIZE):
        batch = stale_packages[start:start + OSV_BATCH_SIZE]
        keys = [f"{p.ecosystem}:{p.name.lower()}@{p.version}" for p in batch]
        if time.monotonic() > deadline:
            print(f"[WARN] OSV audit time budget exhausted; {len(batch)} packages not queried.")
            package_advisories.update(dict.fromkeys(keys))
            continue
        try:
            for cache_key, advisories in zip(keys, _osv_batch_advisory_ids(batch)):
                package_advisories[cache_key] = advisories
        except Exception as exc:
            print(f"[WARN] OSV batch query failed for {len(batch)} packages: {exc}")
            package_advisories.update(dict.fromkeys(keys))

    # 3. Fetch each distinct advisory once, however many packages share it.
    wanted: dict[str, str] = {}
    for package_ids in package_advisories.values():
        wanted.update(package_ids or {})
    records, failed_advisories = _hydrate_osv_advisories(wanted, cache, deadline)

    # 4. Assemble results in package order, falling back to cache on failure.
    for package in packages:
        cache_key = f"{package.ecosystem}:{package.name.lower()}@{package.version}"
        cached_vulns, _ = cached[cache_key]
        if cache_key not in package_advisories:
            findings.extend(cached_vulns or [])
            continue
        affecting = package_advisories[cache_key]
        if affecting is not None and not (set(affecting) & failed_advisories):
            vuln_list = [
                {
                    **records[advisory_id],
                    "aliases": list(records[advisory_id].get("aliases") or []),
                    "package": package.name,
                    "version": package.version,
                    "ecosystem": package.ecosystem,
                }
                for advisory_id in affecting
            ]
            cache[cache_key] = {"timestamp": current_time, "schema": OSV_RECORD_SCHEMA, "vulns": vuln_list}
            cache_dirty = True
            findings.extend(vuln_list)
            continue
        print(f"[WARN] Failed to query OSV API for {cache_key}")
        if cached_vulns is not None:
            # A stale result may be useful for a best-effort report, but it
            # must remain an operational failure for strict release gates.
            findings.extend(cached_vulns)
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

    return enrich_exploit_intelligence(findings, raise_on_error=raise_on_error)


def _exploit_intel_cache() -> dict[str, Any]:
    if EXPLOIT_INTEL_CACHE_FILE.exists():
        try:
            loaded = load_bounded_json(EXPLOIT_INTEL_CACHE_FILE)
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            pass
    return {}


def _fetch_json(url: str) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": "Aegis-Scanner/2.0", "Accept": "application/json"})
    deadline = time.monotonic() + EXPLOIT_INTEL_DEADLINE_SECONDS
    limit = resource_budgets().max_parser_input_bytes
    body = b""
    with urllib.request.urlopen(request, timeout=EXPLOIT_INTEL_DEADLINE_SECONDS) as response:
        while chunk := response.read1(64 * 1024):
            body += chunk
            if len(body) > limit:
                raise ResourceLimitError(f"Feed response exceeds the configured limit of {limit} bytes.")
            if time.monotonic() > deadline:
                raise TimeoutError("Feed response exceeded its deadline.")
    return json.loads(body.decode("utf-8"))


def _load_kev(cache: dict[str, Any], now: float) -> tuple[dict[str, Any] | None, str | None]:
    """Return the KEV catalog (CVE -> entry) and an error if no usable copy exists."""
    cached = cache.get("kev")
    age = None
    if isinstance(cached, dict) and isinstance(cached.get("entries"), dict):
        try:
            age = now - float(cached.get("fetched_at", 0))
        except (TypeError, ValueError):
            age = None
    if age is not None and 0 <= age < EXPLOIT_INTEL_TTL_SECONDS:
        return cached, None
    last_error: Exception = RuntimeError("no KEV sources configured")
    try:
        feed = None
        for url in KEV_FEED_URLS:
            try:
                feed = _fetch_json(url)
                break
            except Exception as exc:
                print(f"[WARN] CISA KEV source {url} failed: {exc}")
                last_error = exc
        if feed is None:
            raise last_error
        vulnerabilities = feed.get("vulnerabilities") if isinstance(feed, dict) else None
        if not isinstance(vulnerabilities, list) or not feed.get("catalogVersion"):
            raise ValueError("KEV feed is missing catalogVersion or vulnerabilities.")
        entries = {
            str(item["cveID"]).upper(): {
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "ransomware": item.get("knownRansomwareCampaignUse") == "Known",
            }
            for item in vulnerabilities
            if isinstance(item, dict) and str(item.get("cveID", "")).upper().startswith("CVE-")
        }
        catalog = {
            "fetched_at": now,
            "catalog_version": str(feed["catalogVersion"]),
            "date_released": feed.get("dateReleased"),
            "entries": entries,
        }
        cache["kev"] = catalog
        return catalog, None
    except Exception as exc:
        if age is not None and 0 <= age < EXPLOIT_INTEL_MAX_STALE_SECONDS:
            print(f"[WARN] CISA KEV refresh failed; using catalog cached {age / 3600:.0f}h ago: {exc}")
            return cached, None
        return None, f"CISA KEV catalog unavailable: {exc}"


def _load_epss(cves: list[str], cache: dict[str, Any], now: float) -> tuple[dict[str, Any], list[str]]:
    """Return CVE -> EPSS record for the given CVEs and the CVEs with no usable score."""
    store = cache.setdefault("epss", {})
    if not isinstance(store, dict):
        store = cache["epss"] = {}

    def age_of(cve: str) -> float | None:
        entry = store.get(cve)
        if not isinstance(entry, dict):
            return None
        try:
            return now - float(entry.get("fetched_at", 0))
        except (TypeError, ValueError):
            return None

    def within(cve: str, limit: float) -> bool:
        age = age_of(cve)
        return age is not None and 0 <= age < limit

    refresh = [cve for cve in cves if not within(cve, EXPLOIT_INTEL_TTL_SECONDS)]
    failed: set[str] = set()
    for start in range(0, len(refresh), EPSS_BATCH_SIZE):
        chunk = refresh[start:start + EPSS_BATCH_SIZE]
        try:
            response = _fetch_json(f"{EPSS_API_URL}?cve={urllib.parse.quote(','.join(chunk), safe=',')}")
            rows = response.get("data") if isinstance(response, dict) else None
            if not isinstance(rows, list):
                raise ValueError("EPSS response has no data array.")
            scored = set()
            for row in rows:
                if not isinstance(row, dict):
                    continue
                cve = str(row.get("cve", "")).upper()
                if cve in chunk:
                    store[cve] = {
                        "fetched_at": now,
                        "score": float(row["epss"]),
                        "percentile": float(row["percentile"]),
                        "date": row.get("date"),
                    }
                    scored.add(cve)
            # FIRST has no score yet for some new or rejected CVEs; record that
            # explicitly so the absence is evidence, not a lookup failure.
            for cve in set(chunk) - scored:
                store[cve] = {"fetched_at": now, "score": None, "percentile": None, "date": None}
        except Exception as exc:
            print(f"[WARN] EPSS lookup failed for {len(chunk)} CVEs: {exc}")
            failed.update(chunk)
    unavailable = []
    scores = {}
    for cve in cves:
        if not within(cve, EXPLOIT_INTEL_MAX_STALE_SECONDS):
            unavailable.append(cve)
            continue
        if cve in failed:
            print(f"[WARN] Using a cached EPSS score for {cve}.")
        scores[cve] = store[cve]
    return scores, unavailable


def enrich_exploit_intelligence(
    findings: List[Dict[str, Any]],
    *,
    raise_on_error: bool = False,
) -> List[Dict[str, Any]]:
    """Attach CISA KEV and FIRST EPSS evidence to OSV findings by CVE alias.

    Severity is never lowered here; escalate_osv_severity() applies the policy.
    In strict mode, missing or too-stale intelligence is an operational error,
    because a known-exploited dependency must not pass for lack of data.
    """
    cves_by_finding = [
        sorted({
            str(alias).upper()
            for alias in [finding.get("id"), *(finding.get("aliases") or [])]
            if str(alias or "").upper().startswith("CVE-")
        })
        for finding in findings
    ]
    all_cves = sorted({cve for cves in cves_by_finding for cve in cves})
    if not all_cves:
        return findings

    cache = _exploit_intel_cache()
    now = time.time()
    kev, kev_error = _load_kev(cache, now)
    epss, epss_unavailable = _load_epss(all_cves, cache, now)
    try:
        EXPLOIT_INTEL_CACHE_FILE.write_text(json.dumps(cache))
    except Exception as exc:
        print(f"[WARN] Failed to write exploit intelligence cache: {exc}")

    errors = [kev_error] if kev_error else []
    if epss_unavailable:
        errors.append("EPSS scores unavailable for: " + ", ".join(epss_unavailable))
    if errors:
        if raise_on_error:
            raise RuntimeError("Exploit intelligence unavailable: " + "; ".join(errors))
        print("[WARN] " + "; ".join(errors))

    enriched = []
    for finding, cves in zip(findings, cves_by_finding):
        item = dict(finding)
        if kev is not None:
            listed = next((cve for cve in cves if cve in kev["entries"]), None)
            item["kev"] = {
                **kev["entries"][listed],
                "cve": listed,
                "catalog_version": kev["catalog_version"],
            } if listed else None
        scored = [epss[cve] | {"cve": cve} for cve in cves if cve in epss and epss[cve].get("score") is not None]
        if scored:
            best = max(scored, key=lambda entry: entry["score"])
            item["epss"] = {key: best[key] for key in ("cve", "score", "percentile", "date")}
        enriched.append(item)
    return enriched


def calculate_exploitability_score(results: List[Dict[str, Any]]) -> float:
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
        "| Tool | Status | Total Issues | Blocking Issues | By severity |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in results:
        severities = " · ".join(f"{name} {count}" for name, count in (r.get("severity_counts") or {}).items())
        md_lines.append(f"| {r['tool']} | {r['status']} | {r['total_issues']} | {r['blocking_issues']} | {severities or '-'} |")

    md_lines.extend([
        "",
        "## Findings",
        "",
        "Up to five findings per scanner are listed, blocking ones first. This standalone report cannot tell new findings from existing ones. Suppress a finding only after a named owner accepts the risk, confirms it is not exploitable, or names a compensating control.",
    ])
    for result in results:
        if not result.get("examples"):
            continue
        md_lines.extend(["", f"### {result['tool']}"])
        for example in result["examples"]:
            rule = example.get("test_id") or example.get("id") or example.get("vulnerability_id") or example.get("rule") or example.get("type") or result["tool"]
            md_lines.extend([
                "",
                f"#### {' '.join(filter(None, [example.get('severity'), example.get('display_title') or rule]))}",
                f"- **Rule:** `{rule}`" + (f" · **Location:** `{example['display_location']}`" if example.get("display_location") else ""),
                f"- **Why it matters:** {example.get('why_it_matters', 'Review before release.')}",
                f"- **How to fix:** {example.get('remediation', 'Apply the scanner recommendation and rerun Aegis.')}",
            ])
            if example.get("fix_suggestion"):
                md_lines.extend(["", "```", str(example["fix_suggestion"]), "```"])
            if example.get("suppression_example"):
                md_lines.extend([
                    "",
                    "<details><summary>Suppression example</summary>",
                    "",
                    "```yaml",
                    str(example["suppression_example"]),
                    "```",
                    "",
                    "</details>",
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

    exploitability_score = calculate_exploitability_score(results)

    if reporter_callback:
        reporter_callback(results, final_status, reason, exploitability_score)
    else:
        for result in results:
            print_result(result)
        print("\n=== Final Decision ===")
        print(f"DEPLOYMENT {final_status}")
        print(f"Reason: {reason}")
        print(f"Heuristic risk index: {exploitability_score}/100")

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
