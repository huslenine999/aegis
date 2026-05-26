import base64
import hashlib
import os
import pickle
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

# Add the current directory to sys.path to allow imports when running from root
sys.path.append(str(Path(__file__).resolve().parent))

# Ensure the virtual environment's bin/Scripts directory is in PATH so that packages
# invoking subprocesses (like semgrep) can find their corresponding executables.
sys_exec_dir = os.path.dirname(sys.executable)
if sys_exec_dir and sys_exec_dir not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = sys_exec_dir + os.pathsep + os.environ.get("PATH", "")

from flask import Flask, Response, jsonify, render_template, request

from database import DB_PATH, initialize_database, BASE_DIR, PROJECT_ROOT, DOWNLOAD_DIR, SCANS_DIR

app = Flask(__name__)

# Global state for the WAF toggle (demo only)
WAF_ENABLED = False


def load_waf_rules_from_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT pattern, description, enabled FROM waf_rules")
        rows = cursor.fetchall()
        rules = []
        for row in rows:
            rules.append({
                "pattern": row[0],
                "description": row[1],
                "enabled": bool(row[2])
            })
        return rules
    except sqlite3.OperationalError:
        return [
            {"pattern": "' OR '", "description": "SQL Injection (OR operator bypass)", "enabled": True},
            {"pattern": "1=1", "description": "SQL Injection (tautology bypass)", "enabled": True},
            {"pattern": "--", "description": "SQL comment character block", "enabled": True},
            {"pattern": "cat /etc/passwd", "description": "LFI/Command execution pattern 1", "enabled": True},
            {"pattern": "\\.\\./", "description": "Directory Traversal pattern (../)", "enabled": True},
            {"pattern": "pickle\\.loads", "description": "Python deserialization hijack detector", "enabled": True},
            {"pattern": "eval\\(", "description": "Python dynamic expression injection detector", "enabled": True},
            {"pattern": "<\\s*script", "description": "XSS (Dangerous script tags)", "enabled": True},
            {"pattern": "on\\w+\\s*=", "description": "XSS (HTML event handler hijacking)", "enabled": True},
            {"pattern": "javascript\\s*:", "description": "XSS (Javascript URI prefix)", "enabled": True},
            {"pattern": "169\\.254\\.169\\.254", "description": "SSRF (Cloud metadata server IP)", "enabled": True},
            {"pattern": "localhost|127\\.0\\.0\\.1", "description": "SSRF (Localhost lookup blocker)", "enabled": True}
        ]
    finally:
        conn.close()


def save_waf_rules_to_db(rules):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM waf_rules")
        for r in rules:
            cursor.execute(
                "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
                (r["pattern"], r["description"], 1 if r["enabled"] else 0)
            )
        conn.commit()
    finally:
        conn.close()


def extract_json_values(data):
    if isinstance(data, dict):
        parts = []
        for k, v in data.items():
            parts.append(str(k))
            parts.append(extract_json_values(v))
        return " ".join(parts)
    elif isinstance(data, list):
        return " ".join(extract_json_values(item) for item in data)
    else:
        return str(data)


@app.before_request
def waf_middleware():
    """
    Simulated Web Application Firewall (WAF).
    Blocks suspicious patterns if enabled.
    """
    global WAF_ENABLED
    # Bypass WAF checks for WAF management, scanning, and dossier export routes
    if request.path in ["/toggle-waf", "/get-waf-rules", "/save-waf-rules", "/run-scan", "/export-dossier"]:
        return

    if not WAF_ENABLED:
        return

    # Check query params, form body, JSON, and raw data
    payload_parts = [str(request.args), str(request.form)]
    
    json_data = request.get_json(silent=True)
    if json_data:
        payload_parts.append(extract_json_values(json_data))
        
    if request.data:
        try:
            payload_parts.append(request.data.decode('utf-8', errors='ignore'))
        except Exception:
            payload_parts.append(str(request.data))

    payload = " ".join(payload_parts)
    
    rules = load_waf_rules_from_db()
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        pattern = rule.get("pattern", "")
        if not pattern:
            continue
        try:
            # Check with compiled regex pattern
            if re.search(pattern, payload, re.IGNORECASE):
                return jsonify({
                    "error": "Blocked by Aegis WAF",
                    "reason": f"Detected malicious pattern: {rule.get('description', pattern)}",
                    "status": "security_violation"
                }), 403
        except re.error:
            # Fallback to simple literal check
            if pattern in payload:
                return jsonify({
                    "error": "Blocked by Aegis WAF",
                    "reason": f"Detected malicious pattern (literal): {rule.get('description', pattern)}",
                    "status": "security_violation"
                }), 403


@app.route("/toggle-waf", methods=["POST"])
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    return jsonify({"status": "success", "waf_enabled": WAF_ENABLED})


@app.route("/get-waf-rules", methods=["GET"])
def get_waf_rules():
    global WAF_ENABLED
    rules = load_waf_rules_from_db()
    return jsonify({"status": "success", "rules": rules, "waf_enabled": WAF_ENABLED})


@app.route("/save-waf-rules", methods=["POST"])
def save_waf_rules():
    try:
        data = request.json
        rules = data.get("rules", [])
        new_rules = []
        for r in rules:
            if "pattern" in r:
                new_rules.append({
                    "pattern": str(r["pattern"]),
                    "description": str(r.get("description", "")),
                    "enabled": bool(r.get("enabled", True))
                })
        save_waf_rules_to_db(new_rules)
        return jsonify({"status": "success", "message": "WAF rules updated successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# Use environment variables for secrets.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "default-dev-secret-key")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "dev-password")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "DEV-AWS-ID")

# BASE_DIR, PROJECT_ROOT, DOWNLOAD_DIR, and SCANS_DIR are imported from database.py

# Initialize directories and sample file safely
DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
SCANS_DIR.mkdir(exist_ok=True, parents=True)

sample_file = DOWNLOAD_DIR / "sample.txt"
if not sample_file.exists():
    sample_file.write_text("This is a safe sample file.\n")

# Initialize database if it doesn't exist (critical for Vercel /tmp)
if not DB_PATH.exists():
    initialize_database()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/report")
def get_report():
    """
    Serves the latest security report.
    """
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        return "<h1>Report not found</h1><p>Please run the security scans first.</p>", 404
    return report_path.read_text()


@app.route("/run-scan", methods=["POST"])
def run_scan():
    """
    Triggers fresh security scans and then runs the policy engine.
    Supports either scanning the local application codebase or a custom uploaded file.
    """
    import uuid
    import shutil
    import json
    from werkzeug.utils import secure_filename

    if os.environ.get("VERCEL"):
        return jsonify({
            "status": "error",
            "message": "Security scans are not supported in the Vercel serverless environment due to read-only filesystem limits, execution timeouts, and missing native binaries (like semgrep-core). Please clone the repository and run the project locally using './setup.sh' to perform security scans."
        }), 400

    uploaded_file = request.files.get("file")
    is_custom_scan = False
    temp_dir = None

    try:
        # Determine the python executable.
        # Use current sys.executable to ensure we stay in the same environment.
        python_bin = sys.executable
        
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            if not filename.lower().endswith('.py'):
                return jsonify({
                    "status": "error",
                    "message": "Invalid file type. Only Python (.py) files are allowed for custom scans."
                }), 400
            is_custom_scan = True
            uuid_str = uuid.uuid4().hex
            temp_dir = SCANS_DIR / "uploads" / uuid_str
            temp_dir.mkdir(exist_ok=True, parents=True)
            temp_filepath = temp_dir / filename
            uploaded_file.save(str(temp_filepath))
            target_path = str(temp_filepath)
            
            # Write clean/empty mock results to safety-report.json and trivy-report.json
            with open(SCANS_DIR / "safety-report.json", "w") as f:
                json.dump([], f)
            with open(SCANS_DIR / "trivy-report.json", "w") as f:
                json.dump({"Results": []}, f)
        else:
            # Read target from request
            target_name = "vulnerable"
            if request.is_json:
                target_name = request.json.get("target", "vulnerable")
            else:
                target_name = request.form.get("target", "vulnerable")
                
            if target_name == "secure":
                target_path = str(BASE_DIR / "secure_main.py")
            else:
                target_path = str(BASE_DIR / "main.py")
            
            # Run Safety (SCA) - using 'check' which works with requirements.txt
            safety_cmd = [python_bin, "-m", "safety", "check", "-r", "requirements.txt", "--save-json", str(SCANS_DIR / "safety-report.json")]
            subprocess.run(safety_cmd, cwd=PROJECT_ROOT, check=False)
            
            # Ensure trivy-report.json exists
            trivy_path = SCANS_DIR / "trivy-report.json"
            if not trivy_path.exists():
                with open(trivy_path, "w") as f:
                    json.dump({"Results": []}, f)

        # Determine target file extension
        target_ext = Path(target_path).suffix.lower()
        is_dir = Path(target_path).is_dir()
        
        # Check if Python files are present
        has_python = False
        if is_dir:
            for root, dirs, files in os.walk(target_path):
                if any(file.endswith(".py") for file in files):
                    has_python = True
                    break
        else:
            if target_ext == ".py":
                has_python = True

        bandit_report_path = SCANS_DIR / "bandit-report.json"

        # 1. Run Python SAST (Bandit)
        if has_python:
            bandit_cmd = [
                python_bin,
                "-m",
                "bandit"
            ]
            if is_dir:
                bandit_cmd.append("-r")
            bandit_cmd.extend([
                target_path,
                "-f",
                "json",
                "-o",
                str(bandit_report_path)
            ])
            subprocess.run(bandit_cmd, cwd=PROJECT_ROOT, check=False)
        else:
            with open(bandit_report_path, "w") as f:
                json.dump({"results": []}, f)
        
        # Run the policy engine
        engine_path = PROJECT_ROOT / "policy_engine.py"
        subprocess.run([python_bin, str(engine_path)], cwd=PROJECT_ROOT, check=False, env={**os.environ, "SCANS_DIR": str(SCANS_DIR)})
        
        return jsonify({"status": "success", "message": "Scan completed and report generated."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if is_custom_scan and temp_dir and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                app.logger.error(f"Failed to clean up temp directory {temp_dir}: {e}")


@app.route("/health")
def health():
    return jsonify({
        "status": "running",
        "service": "aegis-vulnerable-demo"
    })


@app.route("/user")
def get_user():
    """
    SQL Injection vulnerability.

    Example:
    /user?name=admin

    Dangerous example:
    /user?name=admin' OR '1'='1
    """
    username = request.args.get("name", "guest")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Intentionally vulnerable string formatting.
    query = f"SELECT id, username, role, api_key FROM users WHERE username = '{username}'"
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()

    return jsonify({
        "query": query,
        "results": rows
    })


@app.route("/ping")
def ping_host():
    """
    Command Injection vulnerability.

    Example:
    /ping?host=127.0.0.1
    """
    host = request.args.get("host", "127.0.0.1")

    # Intentionally vulnerable shell=True usage.
    command = f"ping -c 1 {host}"
    output = subprocess.check_output(command, shell=True, text=True)

    return jsonify({
        "command": command,
        "output": output
    })


@app.route("/calculate")
def calculate():
    """
    Unsafe eval vulnerability.

    Example:
    /calculate?expr=2+2
    """
    expression = request.args.get("expr", "1+1")

    # Intentionally dangerous eval usage.
    result = eval(expression)

    return jsonify({
        "expression": expression,
        "result": result
    })


@app.route("/load-profile", methods=["POST"])
def load_profile():
    """
    Insecure deserialization vulnerability.

    The endpoint accepts base64 encoded pickle data.
    This is intentionally unsafe and should never be used in production.
    """
    encoded_profile = request.json.get("profile", "")

    raw_data = base64.b64decode(encoded_profile)

    # Intentionally dangerous pickle deserialization.
    profile = pickle.loads(raw_data)

    return jsonify({
        "loaded_profile": str(profile)
    })


@app.route("/download")
def download_file():
    """
    Path Traversal vulnerability.

    Example:
    /download?file=sample.txt

    Dangerous example:
    /download?file=../main.py
    """
    filename = request.args.get("file", "sample.txt")

    # Intentionally unsafe path join.
    target_file = DOWNLOAD_DIR / filename

    if not target_file.exists():
        return jsonify({"error": "File not found"}), 404

    return target_file.read_text()


@app.route("/hash")
def weak_hash():
    """
    Weak hashing vulnerability using MD5.

    Example:
    /hash?value=password123
    """
    value = request.args.get("value", "password123")

    # Intentionally weak hash.
    digest = hashlib.md5(value.encode()).hexdigest()

    return jsonify({
        "value": value,
        "md5": digest
    })


@app.route("/xss")
def xss_demo():
    """
    Cross-Site Scripting (XSS) vulnerability.

    Example:
    /xss?msg=<script>alert('XSS')</script>
    """
    msg = request.args.get("msg", "Welcome to Aegis console.")
    # Intentionally vulnerable HTML output reflection
    return f"<html><body><div id='xss-output'>{msg}</div></body></html>"


@app.route("/ssrf")
def ssrf_demo():
    """
    Server-Side Request Forgery (SSRF) vulnerability.

    Example:
    /ssrf?url=http://169.254.169.254/latest/meta-data/
    """
    url = request.args.get("url", "http://127.0.0.1:5001/health")

    import urllib.request
    try:
        # Intentionally vulnerable connection execution without checks
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Aegis-Simulated-Scanner/2.0'}
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return jsonify({
                "url": url,
                "status": "success",
                "response": content[:1000]
            })
    except Exception as e:
        return jsonify({
            "url": url,
            "status": "error",
            "message": str(e)
        }), 500



@app.route("/debug-info")
def debug_info():
    """
    Information exposure demo.
    """
    return jsonify({
        "database_password": DATABASE_PASSWORD,
        "aws_access_key": AWS_ACCESS_KEY_ID,
        "environment": dict(os.environ)
    })


@app.route("/export-dossier")
def export_dossier():
    """
    Generates and downloads a retro monospaced dot-matrix ASCII compliance report
    summarizing results from bandit, safety, and trivy.
    """
    import json
    from datetime import datetime
    
    def load_json(path):
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except Exception:
            return None

    bandit_report = load_json(SCANS_DIR / "bandit-report.json")
    safety_report = load_json(SCANS_DIR / "safety-report.json")
    trivy_report = load_json(SCANS_DIR / "trivy-report.json")

    # Determine status & counts for Bandit
    if not (SCANS_DIR / "bandit-report.json").exists():
        bandit_status = "MISSING"
        bandit_total = 0
        bandit_blocking = 0
    else:
        bandit_results = bandit_report.get("results", []) if bandit_report else []
        bandit_total = len(bandit_results)
        bandit_blocking = len([r for r in bandit_results if r.get("issue_severity", "").upper() in {"MEDIUM", "HIGH"}])
        bandit_status = "FAIL" if bandit_blocking > 0 else "PASS"

    # Determine status & counts for Safety
    if not (SCANS_DIR / "safety-report.json").exists():
        safety_status = "MISSING"
        safety_total = 0
        safety_blocking = 0
    else:
        safety_vulns = []
        if isinstance(safety_report, dict):
            safety_vulns = safety_report.get("vulnerabilities", []) or safety_report.get("results", [])
        elif isinstance(safety_report, list):
            safety_vulns = safety_report
        safety_total = len(safety_vulns)
        safety_blocking = safety_total
        safety_status = "FAIL" if safety_blocking > 0 else "PASS"

    # Determine status & counts for Trivy
    if not (SCANS_DIR / "trivy-report.json").exists():
        trivy_status = "MISSING"
        trivy_total = 0
        trivy_blocking = 0
    else:
        trivy_vulns = []
        for result in (trivy_report.get("Results", []) or []):
            for vulnerability in result.get("Vulnerabilities", []) or []:
                trivy_vulns.append(vulnerability)
        trivy_total = len(trivy_vulns)
        trivy_blocking = len([v for v in trivy_vulns if v.get("Severity", "").upper() in {"MEDIUM", "HIGH", "CRITICAL"}])
        trivy_status = "FAIL" if trivy_blocking > 0 else "PASS"

    # Final overall decision
    failed_tools = []
    missing_tools = []
    for tool, status in [
        ("Bandit", bandit_status),
        ("Safety", safety_status),
        ("Trivy", trivy_status)
    ]:
        if status == "FAIL":
            failed_tools.append(tool)
        elif status == "MISSING":
            missing_tools.append(tool)

    if failed_tools or missing_tools:
        gate_decision = "BLOCKED"
        reasons = []
        if failed_tools:
            reasons.append(f"Blocking security issues found by: {', '.join(failed_tools)}")
        if missing_tools:
            reasons.append(f"Required scan reports missing for: {', '.join(missing_tools)}")
        reason = " | ".join(reasons)
    else:
        gate_decision = "ALLOWED"
        reason = "No blocking security issues found."

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Format Bandit findings
    bandit_findings = ""
    if bandit_report and bandit_report.get("results"):
        for issue in bandit_report.get("results", [])[:5]:
            bandit_findings += f"  - ID: {issue.get('test_id')} | Severity: {issue.get('issue_severity')} | Confidence: {issue.get('issue_confidence')}\n"
            bandit_findings += f"    Location: {issue.get('filename')}:{issue.get('line_number')}\n"
            bandit_findings += f"    Details: {issue.get('issue_text')}\n"
            code = issue.get('code', '')
            if code:
                code_lines = code.strip().split('\n')
                bandit_findings += f"    Source:\n"
                for cl in code_lines[:3]:
                    bandit_findings += f"      >> {cl}\n"
            bandit_findings += "  ------------------------------------------------------------------\n"
    else:
        bandit_findings = "  No issues detected.\n"

    # Format Safety findings
    safety_findings = ""
    if safety_report:
        vulns = []
        if isinstance(safety_report, dict):
            vulns = safety_report.get("vulnerabilities", []) or safety_report.get("results", [])
        elif isinstance(safety_report, list):
            vulns = safety_report
        
        if vulns:
            for v in vulns[:5]:
                pkg = v.get("package_name") or v.get("package")
                vuln_id = v.get("vulnerability_id") or v.get("advisory")
                affected = v.get("affected_versions") or v.get("version")
                fixed = v.get("fixed_versions") or v.get("fixed")
                desc = v.get("description") or v.get("reason", "No description provided.")
                safety_findings += f"  - Package: {pkg} | ID: {vuln_id}\n"
                safety_findings += f"    Affected: {affected} | Fixed: {fixed}\n"
                safety_findings += f"    Description: {desc[:120]}...\n"
                safety_findings += "  ------------------------------------------------------------------\n"
        else:
            safety_findings = "  No issues detected.\n"
    else:
        safety_findings = "  No report file found.\n"

    # Format Trivy findings
    trivy_findings = ""
    if trivy_report:
        trivy_vulns = []
        for result in trivy_report.get("Results", []) or []:
            for vulnerability in result.get("Vulnerabilities", []) or []:
                trivy_vulns.append({
                    "target": result.get("Target"),
                    "vulnerability_id": vulnerability.get("VulnerabilityID"),
                    "package_name": vulnerability.get("PkgName"),
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "severity": vulnerability.get("Severity", "").upper(),
                    "title": vulnerability.get("Title"),
                })
        if trivy_vulns:
            for v in trivy_vulns[:5]:
                trivy_findings += f"  - Target: {v.get('target')} | Package: {v.get('package_name')} | ID: {v.get('vulnerability_id')}\n"
                trivy_findings += f"    Severity: {v.get('severity')} | Installed: {v.get('installed_version')} | Fixed: {v.get('fixed_version')}\n"
                trivy_findings += f"    Title: {v.get('title')}\n"
                trivy_findings += "  ------------------------------------------------------------------\n"
        else:
            trivy_findings = "  No issues detected.\n"
    else:
        trivy_findings = "  No report file found.\n"

    dossier_text = f"""================================================================================
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
      AEGIS DEVSECOPS COMPLIANCE DOSSIER
================================================================================
TIMESTAMP: {timestamp}
GATE DECISION: {gate_decision}
REASON: {reason}
================================================================================

[1] PYTHON SECURITY LINTER - BANDIT
--------------------------------------------------------------------------------
Status: {bandit_status}
Total Issues Detected: {bandit_total}
Blocking Issues: {bandit_blocking}

FINDINGS (Top 5):
{bandit_findings}

[2] SOFTWARE COMPOSITION ANALYSIS (SCA) - SAFETY
--------------------------------------------------------------------------------
Status: {safety_status}
Total Issues Detected: {safety_total}
Blocking Issues: {safety_blocking}

FINDINGS (Top 5):
{safety_findings}

[3] CONTAINER IMAGE SCANNING - TRIVY
--------------------------------------------------------------------------------
Status: {trivy_status}
Total Issues Detected: {trivy_total}
Blocking Issues: {trivy_blocking}

FINDINGS (Top 5):
{trivy_findings}

================================================================================
                    [ END OF SECURE TRANSMISSION ]
================================================================================
"""

    return Response(
        dossier_text,
        mimetype="text/plain",
        headers={
            "Content-Disposition": "attachment;filename=aegis-compliance-dossier.txt"
        }
    )


if __name__ == "__main__":
    initialize_database()

    # Debug mode disabled for hardening.
    app.run(host="0.0.0.0", port=5001, debug=False)
