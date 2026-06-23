import os
import sys
import json
import uuid
import shutil
import socket
import subprocess
import contextlib
import importlib.metadata
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "app"))

from policy_engine import run_policy_engine, query_osv_vulnerabilities
from scanners import run_clamav_scan as shared_run_clamav_scan
from scanners import run_yara_scan as shared_run_yara_scan
from scanners import write_semgrep_rules
from sandbox import (
    is_docker_available, scaffold_sandbox_context, build_sandbox_image,
    run_sandbox_container, wait_for_container, run_trivy_scan, stop_and_cleanup_sandbox
)

DEFAULT_TOOL_TIMEOUT = int(os.environ.get("AEGIS_CLI_TOOL_TIMEOUT", "120"))
IGNORED_DIRS = {"venv", "scanner-venv", ".git", ".pytest_cache", ".antigravitycli", ".aegis"}


def should_skip_path(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def get_package_version() -> str:
    package_path = PROJECT_ROOT / "package.json"
    if package_path.exists():
        try:
            return json.loads(package_path.read_text()).get("version", "unknown")
        except json.JSONDecodeError:
            return "unknown"
    return "unknown"


def set_fail_on_env(severities: str):
    severity_set = {
        severity.strip().upper()
        for severity in severities.split(",")
        if severity.strip()
    }
    normalized = ",".join(sorted(severity_set))
    if normalized:
        os.environ["FAIL_ON_RUFF"] = normalized
        os.environ["FAIL_ON_SEMGREP"] = normalized
        os.environ["FAIL_ON_TRIVY"] = normalized
        import policy_engine
        policy_engine.FAIL_ON_RUFF_SEVERITIES = severity_set
        policy_engine.FAIL_ON_SEMGREP_SEVERITIES = severity_set
        policy_engine.FAIL_ON_TRIVY_SEVERITIES = severity_set


def build_scan_summary(target_path: Path, scan_dir: Path, exit_code: int, policy_summary: dict) -> dict:
    return {
        "target": str(target_path),
        "scan_dir": str(scan_dir),
        "html_report": str(scan_dir / "report.html"),
        "markdown_report": str(scan_dir / "report.md"),
        "exit_code": exit_code,
        "status": "allowed" if exit_code == 0 else "blocked",
        **policy_summary,
    }


def find_free_host_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def run_scanner_command(command, *, stdout=None, timeout: int = DEFAULT_TOOL_TIMEOUT, label: str = "Scanner") -> int:
    try:
        result = subprocess.run(
            command,
            stdout=stdout if stdout is not None else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=timeout,
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        print(f"  [{label} Warn] Timed out after {timeout}s; continuing with available results.")
    except FileNotFoundError:
        print(f"  [{label} Warn] Executable not found; skipping.")
    except Exception as e:
        print(f"  [{label} Error] Failed to run scanner: {e}")
    return 1


def log_scanner_event(message: str, level: str = "info"):
    colors = {
        "error": "\033[91m",
        "match": "\033[93m",
        "muted": "\033[90m",
    }
    color = colors.get(level, "")
    reset = "\033[0m" if color else ""
    print(f"  {color}{message}{reset}")

def run_dast_scan(target_url: str = None):
    findings = []
    test_cases = [
        {
            "vuln_type": "SQL Injection",
            "route": "/user",
            "method": "GET",
            "params": {"name": "admin' OR '1'='1"},
            "payload": "admin' OR '1'='1",
            "description": "Active SQL injection vulnerability in user lookup endpoint."
        },
        {
            "vuln_type": "Remote Code Execution",
            "route": "/ping",
            "method": "GET",
            "params": {"host": "127.0.0.1; cat /etc/passwd"},
            "payload": "127.0.0.1; cat /etc/passwd",
            "description": "Command injection vulnerability in ping routing."
        },
        {
            "vuln_type": "Unsafe Eval Injection",
            "route": "/calculate",
            "method": "GET",
            "params": {"expr": "__import__('os').system('id')"},
            "payload": "__import__('os').system('id')",
            "description": "Arbitrary Python execution via unsafe eval expression injection."
        },
        {
            "vuln_type": "Path Traversal (LFI)",
            "route": "/download",
            "method": "GET",
            "params": {"file": "../requirements.txt"},
            "payload": "../requirements.txt",
            "description": "Local File Inclusion / Path Traversal vulnerability."
        },
        {
            "vuln_type": "Cross-Site Scripting (XSS)",
            "route": "/xss",
            "method": "GET",
            "params": {"msg": "<script>alert('XSS')</script>"},
            "payload": "<script>alert('XSS')</script>",
            "description": "Reflected Cross-Site Scripting vulnerability."
        },
        {
            "vuln_type": "Server-Side Request Forgery (SSRF)",
            "route": "/ssrf",
            "method": "GET",
            "params": {"url": "http://169.254.169.254/latest/meta-data/"},
            "payload": "http://169.254.169.254/latest/meta-data/",
            "description": "Server-Side Request Forgery vulnerability exposing cloud metadata."
        }
    ]

    import requests
    if target_url:
        for tc in test_cases:
            url = f"{target_url}{tc['route']}"
            print(f"  [DAST] Scanning route: {tc['route']} with payload: {tc['payload']}")
            try:
                res = requests.get(url, params=tc["params"], timeout=3)
                status_code = res.status_code
            except Exception:
                status_code = 500
            
            status = "MITIGATED" if status_code == 403 else "EXPOSED"
            color = "\033[92m" if status_code == 403 else "\033[91m"
            print(f"  [DAST] Result for {tc['vuln_type']}: {color}{status}\033[0m (HTTP {status_code})")
            
            findings.append({
                "vuln_type": tc["vuln_type"],
                "route": tc["route"],
                "payload": tc["payload"],
                "description": tc["description"],
                "status": status,
                "response_code": status_code
            })
    return findings

def format_cell(text: str, width: int, align: str = "left", color: str = "") -> str:
    if align == "left":
        padded = text.ljust(width)
    elif align == "center":
        padded = text.center(width)
    elif align == "right":
        padded = text.rjust(width)
    else:
        padded = text.ljust(width)
        
    if color:
        return f"{color}{padded}\033[0m"
    return padded

def print_ascii_report(results: list, final_status: str, reason: str, exploitability_score: float):
    cyan = "\033[96m"
    reset = "\033[0m"
    bold = "\033[1m"
    gray = "\033[90m"
    yellow = "\033[93m"
    green = "\033[92m"
    red = "\033[91m"
    
    # ASCII Art Header
    print("\n")
    print(f"  {cyan}╔══════════════════════════════════════════════════════════════════════════╗{reset}")
    print(f"  {cyan}║{reset}   {cyan}█████╗ ███████╗ ██████╗ ██╗███████╗{reset}                                    {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██╔══██╗██╔════╝██╔════╝ ██║██╔════╝{reset}   {bold}A E G I S   S E C U R I T Y{reset}      {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}███████║█████╗  ██║  ███╗██║███████╗{reset}   {bold}S E C U R E   G A T E W A Y{reset}      {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██╔══██║██╔══╝  ██║   ██║██║╚════██║{reset}   {gray}SHIELD ACTIVE v2.0{reset}                {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██║  ██║███████╗╚██████╔╝██║███████║{reset}                                     {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝{reset}                                     {cyan}║{reset}")
    print(f"  {cyan}╚══════════════════════════════════════════════════════════════════════════╝{reset}")
    
    # Table Header
    print(f"  {gray}┌──────────────────────────────┬──────────┬──────────────┬─────────────────┐{reset}")
    h1 = format_cell("SCANNER SUITE", 30, "left", "\033[96m\033[1m")
    h2 = format_cell("STATUS", 10, "center", "\033[96m\033[1m")
    h3 = format_cell("TOTAL ISSUES", 14, "right", "\033[96m\033[1m")
    h4 = format_cell("BLOCKING ISSUES", 17, "right", "\033[96m\033[1m")
    print(f"  {gray}│{reset}{h1}{gray}│{reset}{h2}{gray}│{reset}{h3}{gray}│{reset}{h4}{gray}│{reset}")
    print(f"  {gray}├──────────────────────────────┼──────────┼──────────────┼─────────────────┤{reset}")
    
    # Table Rows
    for r in results:
        tool_name = r["tool"]
        status = r["status"]
        total = str(r["total_issues"])
        blocking = str(r["blocking_issues"])
        
        if status == "PASS":
            status_text = "✔ PASS"
            status_color = green
        elif status == "FAIL":
            status_text = "✘ FAIL"
            status_color = red
        elif status == "MISSING":
            status_text = "⚠ MISSING"
            status_color = yellow
        else:
            status_text = status
            status_color = reset
            
        t_cell = format_cell(" " + tool_name, 30, "left")
        s_cell = format_cell(status_text, 10, "center", status_color)
        tot_cell = format_cell(total + " ", 14, "right")
        blk_cell = format_cell(blocking + " ", 17, "right", status_color if status == "FAIL" else "")
        print(f"  {gray}│{reset}{t_cell}{gray}│{reset}{s_cell}{gray}│{reset}{tot_cell}{gray}│{reset}{blk_cell}{gray}│{reset}")
        
    print(f"  {gray}└──────────────────────────────┴──────────┴──────────────┴─────────────────┘{reset}")
    
    # Exploitability risk gauge panel card
    print(f"  {cyan}╔══════════════════════════════════════════════════════════════════════════╗{reset}")
    
    # Draw exploitability score bar (gauge width = 40 characters)
    filled_width = int(exploitability_score / 100.0 * 40.0)
    empty_width = 40 - filled_width
    gauge_str = "█" * filled_width + "░" * empty_width
    
    if exploitability_score >= 80.0:
        gauge_color = red
    elif exploitability_score >= 40.0:
        gauge_color = yellow
    else:
        gauge_color = green
        
    visible_gauge = f"  EXPLOITABILITY RISK: [{gauge_str}] {exploitability_score}%"
    padded_gauge = visible_gauge.ljust(74)
    color_gauge = padded_gauge.replace(gauge_str, gauge_color + gauge_str + reset)
    print(f"  {cyan}║{reset}{color_gauge}{cyan}║{reset}")
    
    print(f"  {cyan}║{reset}{' ' * 74}{cyan}║{reset}")
    
    verdict_label = "[✔] DEPLOYMENT ALLOWED" if final_status == "ALLOWED" else "[✘] DEPLOYMENT BLOCKED"
    verdict_color = green + bold if final_status == "ALLOWED" else red + bold
    
    visible_verdict = f"  VERDICT: {verdict_label}"
    padded_verdict = visible_verdict.ljust(74)
    color_verdict = padded_verdict.replace(verdict_label, verdict_color + verdict_label + reset)
    print(f"  {cyan}║{reset}{color_verdict}{cyan}║{reset}")
    
    visible_reason = f"  REASON:  {reason}"
    if len(visible_reason) > 72:
        visible_reason = visible_reason[:69] + "..."
    padded_reason = visible_reason.ljust(74)
    print(f"  {cyan}║{reset}{padded_reason}{cyan}║{reset}")
    
    print(f"  {cyan}╚══════════════════════════════════════════════════════════════════════════╝{reset}")

def execute_scan(
    target_path_str: str,
    *,
    use_docker: bool = True,
    tool_timeout: int = DEFAULT_TOOL_TIMEOUT,
    output_dir: str = None,
    json_output: bool = False,
    quiet: bool = False,
    fail_on: str = None,
    return_summary: bool = False,
):
    if fail_on:
        set_fail_on_env(fail_on)

    target_path = Path(target_path_str).resolve()
    if not target_path.exists():
        print(f"❌ Error: Path '{target_path}' does not exist.")
        if return_summary:
            return {"target": str(target_path), "exit_code": 1, "status": "error", "error": "target_not_found"}
        return 1

    print(f"🛡️  Aegis CLI Scanner: Auditing target path: {target_path}")

    # Set up local scans directory
    if output_dir:
        scan_dir = Path(output_dir).expanduser().resolve()
        req_file = (target_path / "requirements.txt") if target_path.is_dir() else (target_path.parent / "requirements.txt")
    elif target_path.is_dir():
        scan_dir = target_path / ".aegis" / "scans"
        req_file = target_path / "requirements.txt"
    else:
        scan_dir = target_path.parent / ".aegis" / "scans"
        req_file = target_path.parent / "requirements.txt"

    scan_dir.mkdir(parents=True, exist_ok=True)

    # Initialize placeholder reports to satisfy policy engine requirements
    placeholder_reports = {
        "ruff-report.json": [],
        "safety-report.json": [],
        "trivy-report.json": {"Results": []},
        "secrets-report.json": {"results": {}},
        "yara-report.json": [],
        "semgrep-report.json": {"results": []},
        "clamav-report.json": [],
        "zap-report.json": []
    }
    for filename, default_data in placeholder_reports.items():
        write_json(scan_dir / filename, default_data)

    # 1. Dependency Analysis (Safety / OSV)
    if req_file.exists():
        print("🔍 [SCA] requirements.txt detected. Running Safety and OSV audits...")
        
        # Safety Scan
        safety_report_path = scan_dir / "safety-report.json"
        safety_cmd = [sys.executable, "-m", "safety", "check", "-r", str(req_file), "--save-json", str(safety_report_path)]
        run_scanner_command(safety_cmd, timeout=tool_timeout, label="Safety")
        
        # OSV Scan
        osv_report_path = scan_dir / "osv-report.json"
        try:
            osv_findings = query_osv_vulnerabilities(req_file)
            write_json(osv_report_path, osv_findings)
            print("  [SCA] OSV API checks completed.")
        except Exception as e:
            print(f"  [SCA Warn] OSV query failed: {e}")
    else:
        print("ℹ️  [SCA] No requirements.txt found, skipping dependency scan.")

    # 2. Python SAST (Ruff)
    print("🔍 [SAST] Running Ruff (SAST) code security audits...")
    ruff_report_path = scan_dir / "ruff-report.json"
    ruff_cmd = [sys.executable, "-m", "ruff", "check", "--select", "S", "--output-format", "json", "-o", str(ruff_report_path), str(target_path)]
    ruff_cmd.extend(["--exclude", ",".join(sorted(IGNORED_DIRS))])
    run_scanner_command(ruff_cmd, timeout=tool_timeout, label="Ruff")


    # 3. Python SAST (Semgrep)
    print("🔍 [SAST] Running Semgrep rule-based scans...")
    semgrep_report_path = scan_dir / "semgrep-report.json"
    rules_dir = PROJECT_ROOT / "rules"
    rules_dir.mkdir(exist_ok=True)
    semgrep_rules_path = rules_dir / "semgrep_rules.yaml"
    if not semgrep_rules_path.exists():
        write_semgrep_rules(semgrep_rules_path)

    # Find semgrep binary in virtual env or system
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin:
        semgrep_cmd = [semgrep_bin, "scan", "--config", str(semgrep_rules_path), "--json", "-o", str(semgrep_report_path), str(target_path)]
        run_scanner_command(semgrep_cmd, timeout=tool_timeout, label="Semgrep")
    else:
        print("  [SAST Warn] semgrep executable not found, skipping rule check.")

    # 4. Secret Auditing (detect-secrets)
    print("🔍 [Secrets] Scanning codebase for hardcoded keys and credentials...")
    secrets_report_path = scan_dir / "secrets-report.json"
    secrets_cmd = [sys.executable, "-m", "detect_secrets", "scan", "--all-files", str(target_path)]
    try:
        with open(secrets_report_path, "w") as f:
            run_scanner_command(secrets_cmd, stdout=f, timeout=tool_timeout, label="Secrets")
    except Exception as e:
        print(f"  [Secrets Error] Failed to run detect-secrets: {e}")

    # 5. YARA Pattern Audits
    print("🔍 [YARA] Auditing code logic for webshells and suspicious execution patterns...")
    yara_findings = shared_run_yara_scan(target_path, log=log_scanner_event)
    write_json(scan_dir / "yara-report.json", yara_findings)

    # 6. ClamAV Malware Scan
    print("🔍 [ClamAV] Searching files for virus signatures...")
    clamav_findings = shared_run_clamav_scan(target_path, timeout=tool_timeout, log=log_scanner_event)
    write_json(scan_dir / "clamav-report.json", clamav_findings)

    # 7. Sandbox Execution (Trivy & DAST) via Docker
    has_python = False
    if target_path.is_dir():
        for root, dirs, files in os.walk(target_path):
            if should_skip_path(Path(root)):
                continue
            if any(file.endswith(".py") for file in files):
                has_python = True
                break
    else:
        if target_path.suffix.lower() == ".py":
            has_python = True

    if use_docker and is_docker_available() and has_python:
        print("🔍 [Docker Sandbox] Docker daemon detected. Building sandbox server and executing Trivy and DAST scans...")
        sandbox_uuid = uuid.uuid4().hex
        sandbox_image = f"aegis-sandbox-{sandbox_uuid}"
        sandbox_container = f"aegis-sandbox-container-{sandbox_uuid}"
        sandbox_temp_dir = scan_dir / "sandbox" / sandbox_uuid
        
        try:
            host_port = find_free_host_port()
                
            container_port = scaffold_sandbox_context(target_path, sandbox_temp_dir)
            target_url = f"http://127.0.0.1:{host_port}"
            waf_enabled = os.environ.get("WAF_ENABLED", "false").lower() == "true"

            if not build_sandbox_image(sandbox_temp_dir, sandbox_image):
                raise RuntimeError("failed to build sandbox image")

            if not run_sandbox_container(sandbox_image, sandbox_container, host_port, container_port, waf_enabled):
                raise RuntimeError("failed to start sandbox container")

            if not wait_for_container(target_url, timeout=6.0):
                raise RuntimeError("sandbox container did not become healthy")

            # 7a. Trivy layer audits
            trivy_report_path = scan_dir / "trivy-report.json"
            print("  [Trivy] Inspecting image layer packages for CVEs...")
            try:
                run_trivy_scan(sandbox_image, trivy_report_path)
            except Exception as e:
                print(f"  [Trivy Error] Image scan failed: {e}")

            # 7b. ZAP DAST active scanning
            zap_report_path = scan_dir / "zap-report.json"
            print("  [DAST] Running active crawler against endpoints...")
            zap_findings = run_dast_scan(target_url)
            write_json(zap_report_path, zap_findings)

        except Exception as e:
            print(f"  \033[91m[Sandbox Error] Docker execution pipeline encountered an error: {e}\033[0m")
        finally:
            print("  [Docker Sandbox] Cleaning up sandbox containers...")
            try:
                stop_and_cleanup_sandbox(sandbox_container, sandbox_image)
            except Exception:
                pass
            if sandbox_temp_dir.exists():
                shutil.rmtree(sandbox_temp_dir, ignore_errors=True)
    else:
        print("ℹ️  [Docker Sandbox] Docker is disabled, unavailable, or no Python target found. Skipping Trivy & DAST scans.")

    # 8. Run Policy Engine
    print("\nEvaluating all reports against Aegis Security Gate rules...")
    html_report = scan_dir / "report.html"
    md_report = scan_dir / "report.md"
    policy_summary = {}

    def capture_policy_summary(results, final_status, reason, exploitability_score):
        policy_summary.update({
            "policy_status": final_status,
            "reason": reason,
            "exploitability_score": exploitability_score,
            "results": results,
        })
        if not json_output and not quiet:
            print_ascii_report(results, final_status, reason, exploitability_score)
    
    # Run the policy engine
    exit_code = run_policy_engine(
        scan_dir=scan_dir,
        html_path=html_report,
        md_path=md_report,
        req_path=req_file if req_file.exists() else None,
        reporter_callback=capture_policy_summary
    )

    print(f"\nScan complete. Dossier report available at: {html_report}")
    if return_summary:
        return build_scan_summary(target_path, scan_dir, exit_code, policy_summary)
    return exit_code


def run_doctor(json_output: bool = False) -> int:
    checks = []

    def add_check(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    add_check("python", True, sys.version.split()[0])
    add_check("project_root", PROJECT_ROOT.exists(), str(PROJECT_ROOT))
    add_check("ruff", True, "python module available")
    try:
        importlib.metadata.version("ruff")
    except importlib.metadata.PackageNotFoundError:
        checks[-1] = {"name": "ruff", "ok": False, "detail": "python module missing"}

    semgrep_bin = shutil.which("semgrep")
    add_check("semgrep", semgrep_bin is not None, semgrep_bin or "not found")
    trivy_bin = shutil.which("trivy")
    add_check("trivy", trivy_bin is not None, trivy_bin or "not found")
    add_check("docker", is_docker_available(), "available" if is_docker_available() else "unavailable")

    ok = all(check["ok"] for check in checks if check["name"] in {"python", "project_root", "ruff"})
    payload = {"status": "ok" if ok else "degraded", "checks": checks}

    if json_output:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Aegis doctor: {payload['status']}")
        for check in checks:
            marker = "OK" if check["ok"] else "WARN"
            print(f"  [{marker}] {check['name']}: {check['detail']}")
    return 0 if ok else 1

def install_hook():
    git_dir = Path(".git")
    if not git_dir.exists() or not git_dir.is_dir():
        print("❌ Error: Not a Git repository (no .git directory found).")
        return 1
        
    hook_dir = git_dir / "hooks"
    hook_dir.mkdir(exist_ok=True)
    
    pre_push_path = hook_dir / "pre-push"
    
    # Resolve the absolute path to Aegis executable
    aegis_bin_abs = PROJECT_ROOT / "bin" / "aegis"
    
    hook_content = f"""#!/bin/bash
# Aegis Security Gate Pre-Push Hook
echo "🛡️ Running Aegis pre-push security scans..."

# Get the directory of the repository
REPO_DIR="$(git rev-parse --show-toplevel)"

# Run Aegis scan
if [ -f "{aegis_bin_abs}" ]; then
  "{aegis_bin_abs}" scan "$REPO_DIR"
else
  aegis scan "$REPO_DIR"
fi
RESULT=$?

if [ $RESULT -ne 0 ]; then
  echo "❌ DEPLOYMENT BLOCKED: Aegis security scans failed."
  exit 1
fi

echo "✅ Aegis security scans passed. Proceeding with push."
exit 0
"""
    
    pre_push_path.write_text(hook_content)
    os.chmod(pre_push_path, 0o755)
    print("✅ Aegis Git pre-push hook installed successfully at .git/hooks/pre-push")
    return 0

def uninstall_hook():
    pre_push_path = Path(".git/hooks/pre-push")
    if pre_push_path.exists():
        pre_push_path.unlink()
        print("✅ Aegis Git pre-push hook uninstalled successfully.")
    else:
        print("ℹ️ Aegis Git pre-push hook is not currently installed.")
    return 0

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Aegis DevSecOps Console CLI Scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run in-process security audit scan")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target path to scan (defaults to current directory)")
    scan_parser.add_argument("--no-docker", action="store_true", help="Skip Docker sandbox, Trivy, and DAST scans")
    scan_parser.add_argument("--timeout", type=int, default=DEFAULT_TOOL_TIMEOUT, help="Per-tool timeout in seconds")
    scan_parser.add_argument("--output", help="Directory for generated scan reports")
    scan_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON summary to stdout")
    scan_parser.add_argument("--quiet", action="store_true", help="Suppress scan progress output")
    scan_parser.add_argument("--fail-on", help="Comma-separated severities that should block, e.g. high,critical")

    subparsers.add_parser("install-hook", help="Install Aegis Git pre-push hook")
    subparsers.add_parser("uninstall-hook", help="Uninstall Aegis Git pre-push hook")
    doctor_parser = subparsers.add_parser("doctor", help="Check local scanner dependencies")
    doctor_parser.add_argument("--json", action="store_true", help="Print doctor output as JSON")
    subparsers.add_parser("version", help="Print Aegis version")

    args = parser.parse_args()

    if args.command == "scan":
        if args.json or args.quiet:
            sink = sys.stderr if args.json else open(os.devnull, "w")
            with contextlib.redirect_stdout(sink):
                summary = execute_scan(
                    args.path,
                    use_docker=not args.no_docker,
                    tool_timeout=args.timeout,
                    output_dir=args.output,
                    json_output=args.json,
                    quiet=args.quiet,
                    fail_on=args.fail_on,
                    return_summary=True,
                )
            if not args.json:
                sink.close()
            if args.json:
                print(json.dumps(summary, indent=2))
            return summary.get("exit_code", 1)
        return execute_scan(
            args.path,
            use_docker=not args.no_docker,
            tool_timeout=args.timeout,
            output_dir=args.output,
            fail_on=args.fail_on,
        )
    elif args.command == "install-hook":
        return install_hook()
    elif args.command == "uninstall-hook":
        return uninstall_hook()
    elif args.command == "doctor":
        return run_doctor(json_output=args.json)
    elif args.command == "version":
        print(get_package_version())
        return 0
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
