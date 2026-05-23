import json
import os
import sys
from datetime import datetime
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


def generate_reports(results: List[Dict[str, Any]], final_status: str, reason: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate HTML Report
    if TEMPLATE_PATH.exists():
        template = Template(TEMPLATE_PATH.read_text())
        html_content = template.render(
            results=results,
            final_status=final_status,
            reason=reason,
            timestamp=timestamp
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

    bandit_report = load_json(BANDIT_REPORT)
    safety_report = load_json(SAFETY_REPORT)
    trivy_report = load_json(TRIVY_REPORT)

    results = [
        analyze_bandit(bandit_report),
        analyze_safety(safety_report),
        analyze_trivy(trivy_report),
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

    generate_reports(results, final_status, reason)

    return 1 if final_status == "BLOCKED" else 0


if __name__ == "__main__":
    sys.exit(main())
