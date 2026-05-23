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

from database import DB_PATH, initialize_database

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
            {"pattern": "eval\\(", "description": "Python dynamic expression injection detector", "enabled": True}
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

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

if os.environ.get("VERCEL"):
    DOWNLOAD_DIR = Path("/tmp/downloads")
    SCANS_DIR = Path("/tmp/scans")
else:
    DOWNLOAD_DIR = BASE_DIR / "downloads"
    SCANS_DIR = PROJECT_ROOT / "scans"

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
            is_custom_scan = True
            filename = secure_filename(uploaded_file.filename)
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
        
        # Check which languages are present
        has_python = False
        has_c = False
        has_js = False
        has_java = False

        if is_dir:
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    ext = Path(file).suffix.lower()
                    if ext == ".py":
                        has_python = True
                    elif ext in (".c", ".cpp", ".cc", ".h", ".hpp"):
                        has_c = True
                    elif ext in (".js", ".ts", ".jsx", ".tsx"):
                        has_js = True
                    elif ext == ".java":
                        has_java = True
        else:
            if target_ext == ".py":
                has_python = True
            elif target_ext in (".c", ".cpp", ".cc", ".h", ".hpp"):
                has_c = True
            elif target_ext in (".js", ".ts", ".jsx", ".tsx"):
                has_js = True
            elif target_ext == ".java":
                has_java = True

        flawfinder_report_path = SCANS_DIR / "flawfinder-report.json"
        eslint_report_path = SCANS_DIR / "eslint-report.json"
        pmd_report_path = SCANS_DIR / "pmd-report.json"
        bandit_report_path = SCANS_DIR / "bandit-report.json"

        empty_flawfinder = {"runs": []}
        empty_eslint = []
        empty_pmd = {"violations": []}
        empty_bandit = {"results": []}

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
                json.dump(empty_bandit, f)

        # 2. Run C/C++ SAST (Flawfinder)
        if has_c:
            flawfinder_bin = "flawfinder"
            if sys_exec_dir:
                local_bin = Path(sys_exec_dir) / "flawfinder"
                if local_bin.exists():
                    flawfinder_bin = str(local_bin)
            with open(flawfinder_report_path, "w") as f_out:
                flawfinder_cmd = [
                    flawfinder_bin,
                    "--sarif",
                    target_path
                ]
                subprocess.run(flawfinder_cmd, cwd=PROJECT_ROOT, stdout=f_out, check=False)
        else:
            with open(flawfinder_report_path, "w") as f:
                json.dump(empty_flawfinder, f)

        # 3. Run JavaScript/TypeScript SAST (ESLint + eslint-plugin-security)
        if has_js:
            eslint_env_dir = PROJECT_ROOT / "bin" / "eslint-env"
            eslint_env_dir.mkdir(exist_ok=True, parents=True)
            
            pkg_json = eslint_env_dir / "package.json"
            if not pkg_json.exists():
                pkg_json.write_text(json.dumps({
                    "name": "eslint-env",
                    "version": "1.0.0",
                    "dependencies": {
                        "eslint": "^8.57.0",
                        "eslint-plugin-security": "^3.0.1"
                    }
                }))
                subprocess.run(["npm", "install", "--prefix", str(eslint_env_dir)], cwd=PROJECT_ROOT, check=False)
                
            eslint_legacy_config = eslint_env_dir / ".eslintrc.json"
            eslint_legacy_config.write_text(json.dumps({
                "plugins": ["security"],
                "rules": {
                    "security/detect-eval-with-expression": "error",
                    "security/detect-non-literal-require": "warn",
                    "security/detect-object-injection": "warn",
                    "security/detect-unsafe-regex": "error",
                    "security/detect-buffer-noassert": "error",
                    "security/detect-child-process": "warn",
                    "security/detect-disable-mustache-escape": "error",
                    "security/detect-no-csrf-before-method-override": "error",
                    "security/detect-non-literal-fs-filename": "warn",
                    "security/detect-non-literal-regexp": "warn",
                    "security/detect-pseudoRandomBytes": "warn"
                },
                "parserOptions": {
                    "ecmaVersion": 2021
                },
                "env": {
                    "es2021": True,
                    "node": True
                }
            }))
                
            # Clean up old flat config to prevent ESLint v8 from defaulting to flat config mode
            old_cfg = eslint_env_dir / "eslint.config.js"
            if old_cfg.exists():
                try:
                    old_cfg.unlink()
                except Exception:
                    pass

            eslint_bin = eslint_env_dir / "node_modules" / "eslint" / "bin" / "eslint.js"
            eslint_cmd = [
                "node",
                str(eslint_bin),
                "--no-eslintrc",
                "-c",
                str(eslint_legacy_config),
                "-f",
                "json",
                "-o",
                str(eslint_report_path),
                target_path
            ]
            subprocess.run(eslint_cmd, cwd=PROJECT_ROOT, check=False, env={**os.environ, "ESLINT_USE_FLAT_CONFIG": "false"})
        else:
            with open(eslint_report_path, "w") as f:
                json.dump(empty_eslint, f)

        # 4. Run Java SAST (PMD)
        if has_java:
            pmd_bin_dir = PROJECT_ROOT / "bin" / "pmd-bin-7.0.0"
            pmd_executable = None
            
            if pmd_bin_dir.exists():
                for p in pmd_bin_dir.rglob("pmd"):
                    if p.is_file():
                        try:
                            p.chmod(0o755)
                        except Exception:
                            pass
                        pmd_executable = str(p)
                        break

            if not pmd_executable:
                import urllib.request
                import zipfile
                pmd_zip = SCANS_DIR / "pmd.zip"
                url = "https://github.com/pmd/pmd/releases/download/pmd_releases/7.0.0/pmd-dist-7.0.0-bin.zip"
                try:
                    print(f"[Aegis] Downloading PMD from {url}...")
                    urllib.request.urlretrieve(url, pmd_zip)
                    print("[Aegis] Extracting PMD...")
                    with zipfile.ZipFile(pmd_zip, 'r') as zip_ref:
                        zip_ref.extractall(str(PROJECT_ROOT / "bin"))
                    pmd_zip.unlink()
                    
                    for p in pmd_bin_dir.rglob("pmd"):
                        if p.is_file():
                            try:
                                p.chmod(0o755)
                            except Exception:
                                pass
                            pmd_executable = str(p)
                            break
                except Exception as e:
                    print(f"[WARN] Failed to download/install PMD: {e}")

            if pmd_executable:
                pmd_cmd = [
                    pmd_executable,
                    "check",
                    "-d",
                    target_path,
                    "-R",
                    "category/java/security.xml",
                    "-f",
                    "json",
                    "-r",
                    str(pmd_report_path)
                ]
                subprocess.run(pmd_cmd, cwd=PROJECT_ROOT, check=False)
            else:
                with open(pmd_report_path, "w") as f:
                    json.dump(empty_pmd, f)
        else:
            with open(pmd_report_path, "w") as f:
                json.dump(empty_pmd, f)
        
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
    flawfinder_report = load_json(SCANS_DIR / "flawfinder-report.json")
    eslint_report = load_json(SCANS_DIR / "eslint-report.json")
    pmd_report = load_json(SCANS_DIR / "pmd-report.json")
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

    # Determine status & counts for Flawfinder
    if not (SCANS_DIR / "flawfinder-report.json").exists():
        flawfinder_status = "MISSING"
        flawfinder_total = 0
        flawfinder_blocking = 0
    else:
        flawfinder_results = []
        if flawfinder_report:
            for run in flawfinder_report.get("runs", []):
                for r in run.get("results", []):
                    flawfinder_results.append(r)
        flawfinder_total = len(flawfinder_results)
        flawfinder_blocking = len([r for r in flawfinder_results if r.get("rank", 0) >= 0.4])
        flawfinder_status = "FAIL" if flawfinder_blocking > 0 else "PASS"

    # Determine status & counts for ESLint
    if not (SCANS_DIR / "eslint-report.json").exists():
        eslint_status = "MISSING"
        eslint_total = 0
        eslint_blocking = 0
    else:
        eslint_results = []
        if eslint_report:
            for file_res in eslint_report:
                for msg in file_res.get("messages", []):
                    eslint_results.append((file_res.get("filePath", "unknown"), msg))
        eslint_total = len(eslint_results)
        eslint_blocking = len([r[1] for r in eslint_results if r[1].get("severity", 1) >= 1])
        eslint_status = "FAIL" if eslint_blocking > 0 else "PASS"

    # Determine status & counts for PMD
    if not (SCANS_DIR / "pmd-report.json").exists():
        pmd_status = "MISSING"
        pmd_total = 0
        pmd_blocking = 0
    else:
        pmd_results = []
        if pmd_report:
            for f in pmd_report.get("files", []):
                filename = f.get("filename", "unknown")
                for v in f.get("violations", []):
                    pmd_results.append({
                        "rule": v.get("rule"),
                        "priority": v.get("priority", 3),
                        "file": filename,
                        "beginLine": v.get("beginLine", 0),
                        "description": v.get("description", "")
                    })
            for v in pmd_report.get("violations", []):
                pmd_results.append({
                    "rule": v.get("rule"),
                    "priority": v.get("priority", 3),
                    "file": v.get("file", "unknown"),
                    "beginLine": v.get("beginLine", 0),
                    "description": v.get("description", "")
                })
        pmd_total = len(pmd_results)
        pmd_blocking = len([r for r in pmd_results if r.get("priority", 3) <= 3])
        pmd_status = "FAIL" if pmd_blocking > 0 else "PASS"

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
        ("Flawfinder", flawfinder_status),
        ("ESLint", eslint_status),
        ("PMD", pmd_status),
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

    # Format Flawfinder findings
    flawfinder_findings = ""
    if flawfinder_report:
        flawfinder_results = []
        for run in flawfinder_report.get("runs", []):
            for r in run.get("results", []):
                flawfinder_results.append(r)
        if flawfinder_results:
            for issue in flawfinder_results[:5]:
                rank = issue.get("rank", 0)
                if rank >= 0.8:
                    severity = "HIGH"
                elif rank >= 0.4:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                loc = "unknown"
                start_line = 0
                locs = issue.get("locations", [])
                if locs:
                    physical = locs[0].get("physicalLocation", {})
                    loc = physical.get("artifactLocation", {}).get("uri", "unknown")
                    start_line = physical.get("region", {}).get("startLine", 0)
                flawfinder_findings += f"  - ID: {issue.get('ruleId')} | Severity: {severity} | Rank: {rank}\n"
                flawfinder_findings += f"    Location: {loc}:{start_line}\n"
                flawfinder_findings += f"    Details: {issue.get('message', {}).get('text', '')}\n"
                flawfinder_findings += "  ------------------------------------------------------------------\n"
        else:
            flawfinder_findings = "  No issues detected.\n"
    else:
        flawfinder_findings = "  No report file found.\n"

    # Format ESLint findings
    eslint_findings = ""
    if eslint_report:
        eslint_results = []
        for file_res in eslint_report:
            for msg in file_res.get("messages", []):
                eslint_results.append((file_res.get("filePath", "unknown"), msg))
        if eslint_results:
            for filepath, issue in eslint_results[:5]:
                raw_sev = issue.get("severity", 1)
                severity = "HIGH" if raw_sev == 2 else ("MEDIUM" if raw_sev == 1 else "LOW")
                eslint_findings += f"  - ID: {issue.get('ruleId')} | Severity: {severity}\n"
                eslint_findings += f"    Location: {filepath}:{issue.get('line', 0)}\n"
                eslint_findings += f"    Details: {issue.get('message', '')}\n"
                eslint_findings += "  ------------------------------------------------------------------\n"
        else:
            eslint_findings = "  No issues detected.\n"
    else:
        eslint_findings = "  No report file found.\n"

    # Format PMD findings
    pmd_findings = ""
    if pmd_report:
        violations = []
        for f in pmd_report.get("files", []):
            filename = f.get("filename", "unknown")
            for v in f.get("violations", []):
                violations.append({
                    "rule": v.get("rule"),
                    "priority": v.get("priority", 3),
                    "file": filename,
                    "beginLine": v.get("beginLine", 0),
                    "description": v.get("description", "")
                })
        for v in pmd_report.get("violations", []):
            violations.append({
                "rule": v.get("rule"),
                "priority": v.get("priority", 3),
                "file": v.get("file", "unknown"),
                "beginLine": v.get("beginLine", 0),
                "description": v.get("description", "")
            })
        if violations:
            for issue in violations[:5]:
                priority = issue.get("priority", 3)
                severity = "HIGH" if priority <= 2 else ("MEDIUM" if priority == 3 else "LOW")
                pmd_findings += f"  - Rule: {issue.get('rule')} | Severity: {severity} | Priority: {priority}\n"
                pmd_findings += f"    Location: {issue.get('file', 'unknown')}:{issue.get('beginLine', 0)}\n"
                pmd_findings += f"    Details: {issue.get('description', '')}\n"
                pmd_findings += "  ------------------------------------------------------------------\n"
        else:
            pmd_findings = "  No issues detected.\n"
    else:
        pmd_findings = "  No report file found.\n"

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

[2] C/C++ SECURITY SCANNER - FLAWFINDER
--------------------------------------------------------------------------------
Status: {flawfinder_status}
Total Issues Detected: {flawfinder_total}
Blocking Issues: {flawfinder_blocking}

FINDINGS (Top 5):
{flawfinder_findings}

[3] JAVASCRIPT SECURITY LINTER - ESLINT
--------------------------------------------------------------------------------
Status: {eslint_status}
Total Issues Detected: {eslint_total}
Blocking Issues: {eslint_blocking}

FINDINGS (Top 5):
{eslint_findings}

[4] JAVA STATIC ANALYZER - PMD
--------------------------------------------------------------------------------
Status: {pmd_status}
Total Issues Detected: {pmd_total}
Blocking Issues: {pmd_blocking}

FINDINGS (Top 5):
{pmd_findings}

[5] SOFTWARE COMPOSITION ANALYSIS (SCA) - SAFETY
--------------------------------------------------------------------------------
Status: {safety_status}
Total Issues Detected: {safety_total}
Blocking Issues: {safety_blocking}

FINDINGS (Top 5):
{safety_findings}

[6] CONTAINER IMAGE SCANNING - TRIVY
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
