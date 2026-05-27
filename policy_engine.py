import json
import os
import re
import sys
import math
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template

# Use SCANS_DIR from environment if provided (useful for Vercel /tmp)
SCAN_DIR = Path(os.environ.get("SCANS_DIR", "scans"))

# First check if the template exists in the current working directory,
# otherwise fall back to locating it relative to the script's directory.
TEMPLATE_PATH = Path("app/templates/report_template.html")
if not TEMPLATE_PATH.exists():
    script_dir = Path(__file__).resolve().parent
    TEMPLATE_PATH = script_dir / "app" / "templates" / "report_template.html"

BANDIT_REPORT = SCAN_DIR / "bandit-report.json"
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


FAIL_ON_BANDIT_SEVERITIES = get_env_set("FAIL_ON_BANDIT", {"MEDIUM", "HIGH"})
FAIL_ON_SAFETY = os.environ.get("FAIL_ON_SAFETY", "true").lower() == "true"
FAIL_ON_TRIVY_SEVERITIES = get_env_set("FAIL_ON_TRIVY", {"MEDIUM", "HIGH", "CRITICAL"})
FAIL_ON_SEMGREP_SEVERITIES = get_env_set("FAIL_ON_SEMGREP", {"MEDIUM", "HIGH"})


def load_json(path: Path) -> Any:
    if not path.exists():
        print(f"[WARN] Missing report: {path}")
        return None

    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        print(f"[WARN] Invalid JSON report: {path}")
        return None


def analyze_bandit(report: Dict[str, Any]) -> Dict[str, Any]:
    if not report:
        return {
            "tool": "Bandit",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    results = report.get("results", []) if report else []
    issues = []
    
    for r in results:
        issues.append({
            "severity": r.get("issue_severity", "LOW").upper(),
            "test_id": r.get("test_id"),
            "filename": r.get("filename"),
            "line_number": r.get("line_number"),
            "issue_text": r.get("issue_text"),
        })

    blocking_issues = [
        issue for issue in issues
        if issue["severity"] in FAIL_ON_BANDIT_SEVERITIES
    ]

    return {
        "tool": "Bandit",
        "total_issues": len(issues),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
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
            
        issues.append({
            "severity": mapped_severity,
            "test_id": r.get("check_id"),
            "filename": r.get("path"),
            "line_number": r.get("start", {}).get("line"),
            "issue_text": extra.get("message"),
            "code": extra.get("lines"),
        })

    blocking_issues = [
        issue for issue in issues
        if issue["severity"] in FAIL_ON_SEMGREP_SEVERITIES
    ]

    return {
        "tool": "Semgrep",
        "total_issues": len(issues),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
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
        normalized_examples.append({
            "package_name": v.get("package_name") or v.get("package"),
            "vulnerability_id": v.get("vulnerability_id") or v.get("advisory"),
            "affected_versions": v.get("affected_versions") or v.get("version"),
            "fixed_versions": v.get("fixed_versions") or v.get("fixed"),
            "description": v.get("description") or v.get("reason", "No description provided."),
        })

    return {
        "tool": "Safety",
        "total_issues": len(vulnerabilities),
        "blocking_issues": len(vulnerabilities) if FAIL_ON_SAFETY else 0,
        "status": "FAIL" if vulnerabilities and FAIL_ON_SAFETY else "PASS",
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
        findings.append({
            "severity": "HIGH" if cvss_score >= 7.0 else ("MEDIUM" if cvss_score >= 4.0 else "LOW"),
            "id": f.get("id"),
            "package_name": f.get("package"),
            "version": f.get("version"),
            "cvss": f.get("cvss"),
            "summary": f.get("summary"),
            "details": f.get("details"),
        })

    blocking_issues = [f for f in findings if f["severity"] in {"MEDIUM", "HIGH"}]

    return {
        "tool": "OSV Dependency Audit",
        "total_issues": len(findings),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
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
            vulnerabilities.append({
                "target": result.get("Target"),
                "vulnerability_id": vulnerability.get("VulnerabilityID"),
                "package_name": vulnerability.get("PkgName"),
                "installed_version": vulnerability.get("InstalledVersion"),
                "fixed_version": vulnerability.get("FixedVersion"),
                "severity": severity,
                "title": vulnerability.get("Title"),
            })

    blocking_issues = [v for v in vulnerabilities if v["severity"] in FAIL_ON_TRIVY_SEVERITIES]

    return {
        "tool": "Trivy",
        "total_issues": len(vulnerabilities),
        "blocking_issues": len(blocking_issues),
        "status": "FAIL" if blocking_issues else "PASS",
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
            findings.append({
                "severity": "HIGH",
                "type": secret.get("type"),
                "filename": filename,
                "line_number": secret.get("line_number"),
            })

    return {
        "tool": "Secrets Scanner",
        "total_issues": len(findings),
        "blocking_issues": len(findings),
        "status": "FAIL" if findings else "PASS",
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
        findings.append({
            "severity": "HIGH",
            "rule": f.get("rule"),
            "filename": f.get("filename"),
            "description": f.get("description"),
            "author": f.get("author")
        })

    return {
        "tool": "YARA Scanner",
        "total_issues": len(findings),
        "blocking_issues": len(findings),
        "status": "FAIL" if findings else "PASS",
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
        findings.append({
            "severity": "HIGH",
            "virus": f.get("virus"),
            "filename": f.get("filename"),
            "description": f.get("description")
        })

    return {
        "tool": "ClamAV",
        "total_issues": len(findings),
        "blocking_issues": len(findings),
        "status": "FAIL" if findings else "PASS",
        "examples": findings[:5],
    }


def analyze_zap(report: List[Dict[str, Any]]) -> Dict[str, Any]:
    if report is None:
        return {
            "tool": "OWASP ZAP DAST",
            "total_issues": 0,
            "blocking_issues": 0,
            "status": "MISSING",
            "examples": [],
        }

    findings = []
    blocking_count = 0
    for f in report:
        is_exposed = f.get("status") == "EXPOSED"
        findings.append({
            "severity": "HIGH" if is_exposed else "LOW",
            "vuln_type": f.get("vuln_type"),
            "route": f.get("route"),
            "payload": f.get("payload"),
            "description": f.get("description"),
            "status": f.get("status")
        })
        if is_exposed:
            blocking_count += 1

    return {
        "tool": "OWASP ZAP DAST",
        "total_issues": len(findings),
        "blocking_issues": blocking_count,
        "status": "FAIL" if blocking_count > 0 else "PASS",
        "examples": findings[:6],
    }


def generate_cyclonedx_sbom(requirements_path: Path, output_path: Path):
    import re
    import uuid
    from datetime import datetime
    
    components = []
    if requirements_path.exists():
        content = requirements_path.read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Match package==version or package>=version
            match = re.match(r'^([a-zA-Z0-9_\-]+)\s*(==|>=)\s*([a-zA-Z0-9_\-\.]+)', line)
            if match:
                pkg_name = match.group(1)
                pkg_ver = match.group(3)
                purl = f"pkg:pypi/{pkg_name.lower()}@{pkg_ver}"
                components.append({
                    "type": "library",
                    "name": pkg_name,
                    "version": pkg_ver,
                    "purl": purl,
                    "bom-ref": purl
                })
                
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
        
        av = av_map.get(metrics.get("AV"), 0.85)
        ac = ac_map.get(metrics.get("AC"), 0.77)
        ui = ui_map.get(metrics.get("UI"), 0.85)
        scope = metrics.get("S", "U")
        
        c = c_map.get(metrics.get("C"), 0.0)
        i = i_map.get(metrics.get("I"), 0.0)
        a = a_map.get(metrics.get("A"), 0.0)
        
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

def query_osv_vulnerabilities(requirements_path: Path) -> List[Dict[str, Any]]:
    findings = []
    if not requirements_path.exists():
        print(f"[WARN] requirements.txt not found at {requirements_path}")
        return findings

    packages = []
    content = requirements_path.read_text()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.match(r'^([a-zA-Z0-9_\-]+)\s*(==|>=)\s*([a-zA-Z0-9_\-\.]+)', line)
        if match:
            packages.append({
                "name": match.group(1),
                "version": match.group(3)
            })

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
        pkg_name = pkg["name"]
        pkg_ver = pkg["version"]
        cache_key = f"{pkg_name.lower()}@{pkg_ver}"
        
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
                "ecosystem": "PyPI"
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
                                cvss_score = parse_cvss_vector(vector)
                                break
                    
                    vuln_list.append({
                        "id": vuln.get("id"),
                        "package": pkg_name,
                        "version": pkg_ver,
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

    if cache_dirty:
        try:
            OSV_CACHE_FILE.write_text(json.dumps(cache, indent=2))
        except Exception as e:
            print(f"[WARN] Failed to write OSV Cache: {e}")

    return findings


def calculate_exploitability_score(results: List[Dict[str, Any]], waf_enabled: bool) -> float:
    findings = []
    dast_exposed_multiplier = 1.0
    
    for r in results:
        tool = r.get("tool")
        if tool == "Bandit":
            for ex in r.get("examples", []):
                sev = ex.get("severity", "LOW").upper()
                cvss = 8.5 if sev == "HIGH" else (5.5 if sev == "MEDIUM" else 2.0)
                findings.append({"type": "sast", "cvss": cvss})
        elif tool == "Semgrep":
            for ex in r.get("examples", []):
                sev = ex.get("severity", "LOW").upper()
                cvss = 8.5 if sev == "HIGH" else (5.5 if sev == "MEDIUM" else 2.0)
                findings.append({"type": "sast", "cvss": cvss})
        elif tool == "Safety" and not any(other.get("tool") == "OSV Dependency Audit" and other.get("total_issues", 0) > 0 for other in results):
            for _ in range(r.get("total_issues", 0)):
                findings.append({"type": "sca", "cvss": 6.5})
        elif tool == "OSV Dependency Audit":
            for ex in r.get("examples", []):
                cvss = ex.get("cvss") or 6.5
                findings.append({"type": "sca", "cvss": cvss})
        elif tool == "Trivy":
            for ex in r.get("examples", []):
                sev = ex.get("severity", "LOW").upper()
                cvss = 9.8 if sev == "CRITICAL" else (8.0 if sev == "HIGH" else (5.0 if sev == "MEDIUM" else 2.0))
                findings.append({"type": "container", "cvss": cvss})
        elif tool == "Secrets Scanner":
            for _ in range(r.get("total_issues", 0)):
                findings.append({"type": "secrets", "cvss": 8.5})
        elif tool == "YARA Scanner":
            for _ in range(r.get("total_issues", 0)):
                findings.append({"type": "malware", "cvss": 9.0})
        elif tool == "ClamAV":
            for _ in range(r.get("total_issues", 0)):
                findings.append({"type": "malware", "cvss": 9.0})
        elif tool == "OWASP ZAP DAST":
            exposed_count = len([ex for ex in r.get("examples", []) if ex.get("status") == "EXPOSED"])
            if exposed_count > 0:
                dast_exposed_multiplier = 1.5
            for ex in r.get("examples", []):
                if ex.get("status") == "EXPOSED":
                    findings.append({"type": "dast", "cvss": 8.5})

    if not findings:
        return 0.0

    weighted_sum = 0.0
    weights = {
        "sast": 1.0,
        "sca": 0.8,
        "container": 0.9,
        "secrets": 1.2,
        "malware": 1.1,
        "dast": 1.0
    }
    
    for f in findings:
        w = weights.get(f["type"], 1.0)
        weighted_sum += f["cvss"] * w

    base_score = min(100.0, weighted_sum * 5.0)
    score = base_score * dast_exposed_multiplier
    
    if waf_enabled:
        score *= 0.5
        
    return round(min(100.0, score), 1)


def generate_reports(results: List[Dict[str, Any]], final_status: str, reason: str, exploitability_score: float = 0.0):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate HTML Report
    if TEMPLATE_PATH.exists():
        template = Template(TEMPLATE_PATH.read_text())
        html_content = template.render(
            results=results,
            final_status=final_status,
            reason=reason,
            timestamp=timestamp,
            exploitability_score=exploitability_score
        )
        HTML_REPORT.write_text(html_content)
        print(f"[INFO] HTML report generated: {HTML_REPORT}")
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
    
    md_lines.append("\n---\n*Generated by Aegis Policy Engine*")
    MD_REPORT.write_text("\n".join(md_lines))
    print(f"[INFO] Markdown report generated: {MD_REPORT}")


def print_result(result: Dict[str, Any]) -> None:
    print(f"\n[{result['tool']}]")
    print(f"Status: {result['status']}")
    print(f"Total Issues: {result['total_issues']}")
    print(f"Blocking Issues: {result['blocking_issues']}")

    if result["examples"]:
        print("Examples (First 2):")
        for example in result["examples"][:2]:
            print(json.dumps(example, indent=2, ensure_ascii=False))


def main() -> int:
    print("=== Aegis Policy Engine ===")

    # Run CycloneDX SBOM Generation
    try:
        req_path = Path("requirements.txt")
        if not req_path.exists():
            script_dir = Path(__file__).resolve().parent
            req_path = script_dir / "requirements.txt"
        generate_cyclonedx_sbom(req_path, SCAN_DIR / "sbom.json")
    except Exception as e:
        print(f"[WARN] Failed to generate SBOM manifest: {e}")

    bandit_report = load_json(BANDIT_REPORT)
    safety_report = load_json(SAFETY_REPORT)
    trivy_report = load_json(TRIVY_REPORT)
    secrets_report = load_json(SECRETS_REPORT)
    yara_report = load_json(YARA_REPORT)
    semgrep_report = load_json(SEMGREP_REPORT)
    clamav_report = load_json(CLAMAV_REPORT)
    zap_report = load_json(ZAP_REPORT)

    # Execute OSV scan
    osv_report_path = SCAN_DIR / "osv-report.json"
    try:
        osv_findings = query_osv_vulnerabilities(req_path)
        osv_report_path.write_text(json.dumps(osv_findings, indent=2))
        print(f"[INFO] OSV scan completed. Report written to {osv_report_path}")
    except Exception as e:
        print(f"[WARN] OSV scan execution failed: {e}")
        osv_findings = []

    results = [
        analyze_bandit(bandit_report),
        analyze_semgrep(semgrep_report),
        analyze_safety(safety_report),
        analyze_osv(osv_findings),
        analyze_trivy(trivy_report),
        analyze_secrets(secrets_report),
        analyze_yara(yara_report),
        analyze_clamav(clamav_report),
        analyze_zap(zap_report),
    ]

    for result in results:
        print_result(result)

    failed_tools = [result["tool"] for result in results if result["status"] == "FAIL"]
    missing_tools = [result["tool"] for result in results if result["status"] == "MISSING"]

    print("\n=== Final Decision ===")

    final_status = "ALLOWED"
    reason = "No blocking security issues found."

    if failed_tools or missing_tools:
        final_status = "BLOCKED"
        reasons = []
        if failed_tools:
            reasons.append(f"Blocking security issues found by: {', '.join(failed_tools)}")
        if missing_tools:
            reasons.append(f"Required scan reports missing for: {', '.join(missing_tools)}")
        reason = " | ".join(reasons)

    print(f"DEPLOYMENT {final_status}")
    print(f"Reason: {reason}")

    # Determine WAF status from environment (injected by main.py)
    waf_enabled = os.environ.get("WAF_ENABLED", "false").lower() == "true"
    exploitability_score = calculate_exploitability_score(results, waf_enabled)
    print(f"Exploitability Score: {exploitability_score}%")

    generate_reports(results, final_status, reason, exploitability_score)

    return 1 if final_status == "BLOCKED" else 0


if __name__ == "__main__":
    sys.exit(main())
