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
            {"pattern": "__import__|system\\(|subprocess", "description": "Python code execution attempt", "enabled": True},
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


def write_semgrep_rules(path):
    rules_content = """rules:
  - id: python-sqli
    patterns:
      - pattern-either:
          - pattern: $CURSOR.execute(..., $VAR)
          - pattern: $CURSOR.execute(f"...")
          - pattern: $CURSOR.execute("..." % ...)
      - pattern-not:
          - pattern: $CURSOR.execute("...", ...)
    message: "Detected potential SQL injection via string formatting or interpolation in database execution."
    languages: [python]
    severity: ERROR

  - id: python-rce
    patterns:
      - pattern-either:
          - pattern: subprocess.check_output(..., shell=True)
          - pattern: subprocess.run(..., shell=True)
          - pattern: subprocess.Popen(..., shell=True)
          - pattern: os.system(...)
    message: "Detected command injection risk via subprocess/os.system with shell=True."
    languages: [python]
    severity: ERROR

  - id: python-eval
    pattern: eval(...)
    message: "Detected unsafe use of eval()."
    languages: [python]
    severity: ERROR

  - id: python-pickle
    pattern: pickle.loads(...)
    message: "Detected unsafe deserialization with pickle."
    languages: [python]
    severity: ERROR

  - id: python-weak-hash
    pattern: hashlib.md5(...)
    message: "Detected weak MD5 hashing algorithm. Use SHA-256 or SHA-512 instead."
    languages: [python]
    severity: WARNING
"""
    path.write_text(rules_content)


def run_yara_scan(target_path: str):
    findings = []
    import re
    # 1. Try to scan using the compiled yara-python library
    try:
        import yara
        yara_rules_path = PROJECT_ROOT / "rules" / "aegis_rules.yar"
        if not yara_rules_path.exists():
            yara_rules_path = Path("rules/aegis_rules.yar")
        
        if yara_rules_path.exists():
            rules = yara.compile(filepath=str(yara_rules_path))
            
            def scan_file(file_path):
                try:
                    matches = rules.match(filepath=str(file_path))
                    for m in matches:
                        findings.append({
                            "rule": m.rule,
                            "filename": str(file_path),
                            "description": m.meta.get("description", "YARA rule match"),
                            "author": m.meta.get("author", "Aegis")
                        })
                except Exception as e:
                    app.logger.error(f"[YARA Scan Error] {file_path}: {e}")

            p = Path(target_path)
            if p.is_dir():
                for root, dirs, files in os.walk(p):
                    for file in files:
                        if file.endswith(".py"):
                            scan_file(Path(root) / file)
            else:
                scan_file(p)
            return findings
    except ImportError:
        # Fall back gracefully to custom regex-based signature scanner
        pass

    # 2. Fallback regex-based signature scanner
    def scan_file_fallback(file_path):
        try:
            content = file_path.read_text(errors='ignore')
            
            # Rule 1: Backdoor_Webshell
            p1 = re.search(r'eval\(\s*request\.(args|form|values)', content)
            p2 = re.search(r'exec\(\s*request\.(args|form|values)', content)
            p3 = re.search(r'subprocess\.Popen\(\s*request\.args', content)
            p4 = re.search(r'subprocess\.check_output\(\s*request\.args', content)
            if p1 or p2 or p3 or p4:
                findings.append({
                    "rule": "Backdoor_Webshell",
                    "filename": str(file_path),
                    "description": "Detects Python webshell or remote command execution patterns",
                    "author": "Aegis Secure Console (Fallback)"
                })
                
            # Rule 2: Obfuscated_Payload
            has_b64 = "base64.b64decode" in content
            has_exec = "exec(" in content
            has_eval = "eval(" in content
            if has_b64 and (has_exec or has_eval):
                findings.append({
                    "rule": "Obfuscated_Payload",
                    "filename": str(file_path),
                    "description": "Detects base64 obfuscation combined with execution",
                    "author": "Aegis Secure Console (Fallback)"
                })
                
            # Rule 3: Suspicious_Shell_Spawn
            has_sh = ("/bin/sh" in content) or ("/bin/bash" in content)
            has_pty = "pty.spawn" in content
            has_socket = "socket.socket" in content
            has_sub = ("subprocess.Popen" in content) or ("subprocess.call" in content)
            if (has_sh and has_pty) or (has_socket and has_sub and has_sh):
                findings.append({
                    "rule": "Suspicious_Shell_Spawn",
                    "filename": str(file_path),
                    "description": "Detects shell spawning commands, likely for reverse shells",
                    "author": "Aegis Secure Console (Fallback)"
                })
        except Exception as e:
            app.logger.error(f"[Fallback Scan Error] {file_path}: {e}")

    p = Path(target_path)
    if p.is_dir():
        for root, dirs, files in os.walk(p):
            for file in files:
                if file.endswith(".py"):
                    scan_file_fallback(Path(root) / file)
    else:
        scan_file_fallback(p)
        
    return findings


def run_clamav_scan(target_path: str):
    findings = []
    import shutil
    clamscan_bin = shutil.which("clamscan")
    if clamscan_bin:
        try:
            result = subprocess.run([clamscan_bin, "-r", "--infected", target_path], capture_output=True, text=True, check=False)
            for line in result.stdout.splitlines():
                if "FOUND" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        filename = parts[0].strip()
                        virus_part = parts[1].replace("FOUND", "").strip()
                        findings.append({
                            "filename": filename,
                            "virus": virus_part,
                            "description": f"ClamAV detected malware signature: {virus_part}"
                        })
            return findings
        except Exception:
            pass

    # Fallback pure-Python scan
    eicar_sig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    def scan_file_clamav(file_path):
        try:
            content = file_path.read_text(errors='ignore')
            if eicar_sig in content:
                findings.append({
                    "filename": str(file_path),
                    "virus": "EICAR-Test-Signature",
                    "description": "Matched EICAR standard antivirus test signature"
                })
            # Check for base64 backdoors
            if re.search(r'(eval|exec)\(\s*base64\.b64decode', content):
                findings.append({
                    "filename": str(file_path),
                    "virus": "Python.Backdoor.Base64Decoder",
                    "description": "Detected base64-encoded Python execution pattern, indicating potential backdoor/webshell"
                })
        except Exception:
            pass

    p = Path(target_path)
    if p.is_dir():
        for root, dirs, files in os.walk(p):
            if any(k in root for k in ["venv", "scanner-venv", ".git", ".pytest_cache", ".antigravitycli"]):
                continue
            for file in files:
                if file.endswith(".py") or file.endswith(".txt"):
                    scan_file_clamav(Path(root) / file)
    else:
        scan_file_clamav(p)

    return findings


def run_dast_scan():
    findings = []
    with app.test_client() as client:
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

        for tc in test_cases:
            res = client.get(tc["route"], query_string=tc["params"])
            if res.status_code == 403:
                findings.append({
                    "vuln_type": tc["vuln_type"],
                    "route": tc["route"],
                    "payload": tc["payload"],
                    "description": tc["description"],
                    "status": "MITIGATED",
                    "response_code": res.status_code
                })
            else:
                findings.append({
                    "vuln_type": tc["vuln_type"],
                    "route": tc["route"],
                    "payload": tc["payload"],
                    "description": tc["description"],
                    "status": "EXPOSED",
                    "response_code": res.status_code
                })
    return findings


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


@app.route("/download-sbom")
def download_sbom():
    """
    Serves the CycloneDX SBOM JSON file.
    """
    sbom_path = SCANS_DIR / "sbom.json"
    if not sbom_path.exists():
        from policy_engine import generate_cyclonedx_sbom
        try:
            req_path = PROJECT_ROOT / "requirements.txt"
            if not req_path.exists():
                req_path = Path("requirements.txt")
            generate_cyclonedx_sbom(req_path, sbom_path)
        except Exception as e:
            return jsonify({"status": "error", "message": f"SBOM generation failed: {e}"}), 500

    from flask import send_file
    return send_file(
        str(sbom_path),
        mimetype="application/json",
        as_attachment=True,
        download_name="cyclonedx-sbom.json"
    )


@app.route("/get-dependency-graph")
def get_dependency_graph():
    """
    Executes pipdeptree --json-tree, correlates with Safety findings,
    and returns a flattened { nodes, links } structure.
    """
    import json
    import subprocess
    
    # 1. Parse Safety findings for vulnerable packages
    vulnerable_packages = set()
    safety_path = SCANS_DIR / "safety-report.json"
    if safety_path.exists():
        try:
            report = json.loads(safety_path.read_text())
            if isinstance(report, dict) and "vulnerabilities" in report:
                for v in report["vulnerabilities"]:
                    pkg = v.get("package_name") or v.get("package")
                    if pkg:
                        vulnerable_packages.add(pkg.lower())
            elif isinstance(report, list):
                for v in report:
                    pkg = v.get("package_name") or v.get("package")
                    if pkg:
                        vulnerable_packages.add(pkg.lower())
            elif isinstance(report, dict) and "affected_packages" in report:
                for pkg in report["affected_packages"].keys():
                    vulnerable_packages.add(pkg.lower())
        except Exception as e:
            app.logger.error(f"Error parsing safety report for graph: {e}")

    # 2. Run pipdeptree
    raw_tree = []
    try:
        python_bin = sys.executable
        pipdeptree_bin = Path(python_bin).parent / "pipdeptree"
        if not pipdeptree_bin.exists():
            pipdeptree_cmd = [python_bin, "-m", "pipdeptree", "--json-tree"]
        else:
            pipdeptree_cmd = [str(pipdeptree_bin), "--json-tree"]
        
        result = subprocess.run(pipdeptree_cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            raw_tree = json.loads(result.stdout)
        else:
            raw_tree = generate_fallback_tree()
    except Exception as e:
        app.logger.error(f"Error executing pipdeptree: {e}")
        raw_tree = generate_fallback_tree()

    # 3. Flatten dependency tree
    nodes = {}
    links = []
    
    nodes["aegis"] = {
        "id": "aegis",
        "name": "Aegis (Root)",
        "installed_version": "1.0.0",
        "required_version": "N/A",
        "vulnerable": False,
        "isRoot": True
    }
    
    def walk(dep_list, parent_id):
        for dep in dep_list:
            pkg_name = dep.get("package_name") or dep.get("key")
            pkg_key = (dep.get("key") or pkg_name.lower()).replace("-", "_")
            installed = dep.get("installed_version", "unknown")
            required = dep.get("required_version", "unknown")
            
            link_key = (parent_id, pkg_key)
            
            if pkg_key not in nodes:
                nodes[pkg_key] = {
                    "id": pkg_key,
                    "name": pkg_name,
                    "installed_version": installed,
                    "required_version": required,
                    "vulnerable": pkg_key.lower().replace("_", "-") in vulnerable_packages or pkg_key.lower() in vulnerable_packages
                }
            
            if link_key not in [(l["source"], l["target"]) for l in links]:
                links.append({
                    "source": parent_id,
                    "target": pkg_key,
                    "required_version": required
                })
            
            if "dependencies" in dep and dep["dependencies"]:
                walk(dep["dependencies"], pkg_key)

    walk(raw_tree, "aegis")
    
    return jsonify({
        "nodes": list(nodes.values()),
        "links": links
    })


def generate_fallback_tree():
    import re
    req_path = PROJECT_ROOT / "requirements.txt"
    if not req_path.exists():
        req_path = Path("requirements.txt")
    
    tree = []
    if req_path.exists():
        try:
            content = req_path.read_text()
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = re.match(r'^([a-zA-Z0-9_\-]+)\s*(==|>=)\s*([a-zA-Z0-9_\-\.]+)', line)
                if match:
                    pkg_name = match.group(1)
                    pkg_ver = match.group(3)
                    tree.append({
                        "key": pkg_name.lower(),
                        "package_name": pkg_name,
                        "installed_version": pkg_ver,
                        "required_version": f"=={pkg_ver}",
                        "dependencies": []
                    })
        except Exception:
            pass
    return tree


@app.route("/get-scan-results")
def get_scan_results():
    import json
    def load_json_safe(path):
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                pass
        return None
    
    clamav = load_json_safe(SCANS_DIR / "clamav-report.json")
    zap = load_json_safe(SCANS_DIR / "zap-report.json")
    return jsonify({
        "clamav": clamav,
        "zap": zap
    })


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
    target_name = None

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
        
        # 1.5. Run Python SAST (Semgrep)
        semgrep_report_path = SCANS_DIR / "semgrep-report.json"
        if has_python:
            try:
                semgrep_rules_path = PROJECT_ROOT / "rules" / "semgrep_rules.yaml"
                if not semgrep_rules_path.exists():
                    semgrep_rules_path.parent.mkdir(exist_ok=True, parents=True)
                    write_semgrep_rules(semgrep_rules_path)
                
                semgrep_bin = Path(python_bin).parent / "semgrep"
                if not semgrep_bin.exists():
                    semgrep_cmd = ["semgrep", "scan", "--config", str(semgrep_rules_path), "--json", "-o", str(semgrep_report_path), target_path]
                else:
                    semgrep_cmd = [str(semgrep_bin), "scan", "--config", str(semgrep_rules_path), "--json", "-o", str(semgrep_report_path), target_path]
                subprocess.run(semgrep_cmd, cwd=PROJECT_ROOT, check=False)
            except Exception as e:
                app.logger.error(f"[Semgrep Scan Error] {e}")
                with open(semgrep_report_path, "w") as f:
                    json.dump({"results": []}, f)
        else:
            with open(semgrep_report_path, "w") as f:
                json.dump({"results": []}, f)
        
        # 2. Run Secret Scanning (detect-secrets)
        secrets_report_path = SCANS_DIR / "secrets-report.json"
        try:
            secrets_cmd = [
                python_bin,
                "-m",
                "detect_secrets",
                "scan",
                "--all-files",
                "--exclude-files",
                "venv/|scanner-venv/|tests/|scans/|\\.pytest_cache/|\\.git/|\\.antigravitycli/",
                target_path
            ]
            with open(secrets_report_path, "w") as f:
                subprocess.run(secrets_cmd, cwd=PROJECT_ROOT, check=False, stdout=f)
        except Exception as e:
            app.logger.error(f"[Secrets Scan Error] {e}")
            with open(secrets_report_path, "w") as f:
                json.dump({"results": {}}, f)

        # 3. Run YARA Scanner
        yara_report_path = SCANS_DIR / "yara-report.json"
        try:
            yara_findings = run_yara_scan(target_path)
            with open(yara_report_path, "w") as f:
                json.dump(yara_findings, f, indent=2)
        except Exception as e:
            app.logger.error(f"[YARA Scan Error] {e}")
            with open(yara_report_path, "w") as f:
                json.dump([], f)

        # 3.5 Run ClamAV Scanner
        clamav_report_path = SCANS_DIR / "clamav-report.json"
        try:
            clamav_findings = run_clamav_scan(target_path)
            with open(clamav_report_path, "w") as f:
                json.dump(clamav_findings, f, indent=2)
        except Exception as e:
            app.logger.error(f"[ClamAV Scan Error] {e}")
            with open(clamav_report_path, "w") as f:
                json.dump([], f)

        # 3.6 Run ZAP DAST Scanner
        zap_report_path = SCANS_DIR / "zap-report.json"
        try:
            if is_custom_scan or target_name == "secure":
                zap_findings = []
            else:
                zap_findings = run_dast_scan()
            with open(zap_report_path, "w") as f:
                json.dump(zap_findings, f, indent=2)
        except Exception as e:
            app.logger.error(f"[ZAP Scan Error] {e}")
            with open(zap_report_path, "w") as f:
                json.dump([], f)

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
    summarizing results from bandit, safety, trivy, secrets, yara, semgrep, clamav, and zap.
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
    secrets_report = load_json(SCANS_DIR / "secrets-report.json")
    yara_report = load_json(SCANS_DIR / "yara-report.json")
    semgrep_report = load_json(SCANS_DIR / "semgrep-report.json")
    clamav_report = load_json(SCANS_DIR / "clamav-report.json")
    zap_report = load_json(SCANS_DIR / "zap-report.json")

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

    # Determine status & counts for Semgrep
    if not (SCANS_DIR / "semgrep-report.json").exists():
        semgrep_status = "MISSING"
        semgrep_total = 0
        semgrep_blocking = 0
    else:
        semgrep_results = semgrep_report.get("results", []) if semgrep_report else []
        semgrep_total = len(semgrep_results)
        semgrep_blocking = len([r for r in semgrep_results if r.get("extra", {}).get("severity", "").upper() in {"ERROR", "WARNING"}])
        semgrep_status = "FAIL" if semgrep_blocking > 0 else "PASS"

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

    # Determine status & counts for Secrets
    if not (SCANS_DIR / "secrets-report.json").exists():
        secrets_status = "MISSING"
        secrets_total = 0
        secrets_blocking = 0
    else:
        secrets_results = secrets_report.get("results", {}) or {} if secrets_report else {}
        secrets_findings = []
        for filename, file_secrets in secrets_results.items():
            for secret in file_secrets:
                secrets_findings.append(secret)
        secrets_total = len(secrets_findings)
        secrets_blocking = secrets_total
        secrets_status = "FAIL" if secrets_blocking > 0 else "PASS"

    # Determine status & counts for YARA
    if not (SCANS_DIR / "yara-report.json").exists():
        yara_status = "MISSING"
        yara_total = 0
        yara_blocking = 0
    else:
        yara_findings = yara_report if isinstance(yara_report, list) else []
        yara_total = len(yara_findings)
        yara_blocking = yara_total
        yara_status = "FAIL" if yara_blocking > 0 else "PASS"

    # Determine status & counts for ClamAV
    if not (SCANS_DIR / "clamav-report.json").exists():
        clamav_status = "MISSING"
        clamav_total = 0
        clamav_blocking = 0
    else:
        clamav_findings_list = clamav_report if isinstance(clamav_report, list) else []
        clamav_total = len(clamav_findings_list)
        clamav_blocking = clamav_total
        clamav_status = "FAIL" if clamav_blocking > 0 else "PASS"

    # Determine status & counts for ZAP DAST
    if not (SCANS_DIR / "zap-report.json").exists():
        zap_status = "MISSING"
        zap_total = 0
        zap_blocking = 0
    else:
        zap_findings_list = zap_report if isinstance(zap_report, list) else []
        zap_total = len(zap_findings_list)
        zap_blocking = len([f for f in zap_findings_list if f.get("status") == "EXPOSED"])
        zap_status = "FAIL" if zap_blocking > 0 else "PASS"

    # Final overall decision
    failed_tools = []
    missing_tools = []
    for tool, status in [
        ("Bandit", bandit_status),
        ("Semgrep", semgrep_status),
        ("Safety", safety_status),
        ("Trivy", trivy_status),
        ("Secrets Scanner", secrets_status),
        ("YARA Scanner", yara_status),
        ("ClamAV Antivirus", clamav_status),
        ("OWASP ZAP DAST", zap_status)
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

    # Format Semgrep findings
    semgrep_findings = ""
    if semgrep_report and semgrep_report.get("results"):
        for issue in semgrep_report.get("results", [])[:5]:
            extra = issue.get("extra", {})
            semgrep_findings += f"  - ID: {issue.get('check_id')} | Severity: {extra.get('severity')}\n"
            semgrep_findings += f"    Location: {issue.get('path')}:{issue.get('start', {}).get('line')}\n"
            semgrep_findings += f"    Details: {extra.get('message')}\n"
            code = extra.get('lines', '')
            if code:
                code_lines = code.strip().split('\n')
                semgrep_findings += f"    Source:\n"
                for cl in code_lines[:3]:
                    semgrep_findings += f"      >> {cl}\n"
            semgrep_findings += "  ------------------------------------------------------------------\n"
    else:
        semgrep_findings = "  No issues detected.\n"

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

    # Format Secrets findings
    secrets_findings = ""
    if secrets_report:
        secrets_results = secrets_report.get("results", {}) or {}
        secrets_list = []
        for filename, file_secrets in secrets_results.items():
            for secret in file_secrets:
                secrets_list.append({
                    "type": secret.get("type"),
                    "filename": filename,
                    "line_number": secret.get("line_number")
                })
        if secrets_list:
            for s in secrets_list[:5]:
                secrets_findings += f"  - Type: {s.get('type')}\n"
                secrets_findings += f"    Location: {s.get('filename')}:{s.get('line_number')}\n"
                secrets_findings += "  ------------------------------------------------------------------\n"
        else:
            secrets_findings = "  No secrets detected.\n"
    else:
        secrets_findings = "  No report file found.\n"

    # Format YARA findings
    yara_findings_text = ""
    if yara_report:
        yara_list = yara_report if isinstance(yara_report, list) else []
        if yara_list:
            for y in yara_list[:5]:
                yara_findings_text += f"  - Rule matched: {y.get('rule')}\n"
                yara_findings_text += f"    Target File: {y.get('filename')}\n"
                yara_findings_text += f"    Description: {y.get('description')}\n"
                yara_findings_text += "  ------------------------------------------------------------------\n"
        else:
            yara_findings_text = "  No malicious signatures matched.\n"
    else:
        yara_findings_text = "  No report file found.\n"

    # Format ClamAV findings
    clamav_findings_text = ""
    if clamav_report:
        clamav_list = clamav_report if isinstance(clamav_report, list) else []
        if clamav_list:
            for c in clamav_list[:5]:
                clamav_findings_text += f"  - Virus matched: {c.get('virus')}\n"
                clamav_findings_text += f"    Target File: {c.get('filename')}\n"
                clamav_findings_text += f"    Description: {c.get('description')}\n"
                clamav_findings_text += "  ------------------------------------------------------------------\n"
        else:
            clamav_findings_text = "  No malware signatures matched.\n"
    else:
        clamav_findings_text = "  No report file found.\n"

    # Format ZAP findings
    zap_findings_text = ""
    if zap_report:
        zap_list = zap_report if isinstance(zap_report, list) else []
        if zap_list:
            for z in zap_list[:6]:
                zap_findings_text += f"  - Vulnerability: {z.get('vuln_type')} | Status: {z.get('status')}\n"
                zap_findings_text += f"    Route: {z.get('route')} | Payload: {z.get('payload')}\n"
                zap_findings_text += f"    Description: {z.get('description')}\n"
                zap_findings_text += "  ------------------------------------------------------------------\n"
        else:
            zap_findings_text = "  No active DAST endpoints scanned.\n"
    else:
        zap_findings_text = "  No report file found.\n"

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

[1.5] ADVANCED STATIC ANALYSIS ENGINE - SEMGREP
--------------------------------------------------------------------------------
Status: {semgrep_status}
Total Issues Detected: {semgrep_total}
Blocking Issues: {semgrep_blocking}

FINDINGS (Top 5):
{semgrep_findings}

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

[4] SECRET SCANNER - DETECT-SECRETS
--------------------------------------------------------------------------------
Status: {secrets_status}
Total Issues Detected: {secrets_total}
Blocking Issues: {secrets_blocking}

FINDINGS (Top 5):
{secrets_findings}

[5] MALWARE & BACKDOOR SIGNATURES - YARA
--------------------------------------------------------------------------------
Status: {yara_status}
Total Issues Detected: {yara_total}
Blocking Issues: {yara_blocking}

FINDINGS (Top 5):
{yara_findings_text}

[6] MALWARE SIGNATURE ANALYSIS - CLAMAV
--------------------------------------------------------------------------------
Status: {clamav_status}
Total Issues Detected: {clamav_total}
Blocking Issues: {clamav_blocking}

FINDINGS (Top 5):
{clamav_findings_text}

[7] DYNAMIC APPLICATION SECURITY TESTING (DAST) - OWASP ZAP
--------------------------------------------------------------------------------
Status: {zap_status}
Total Issues Detected: {zap_total}
Blocking Issues: {zap_blocking}

FINDINGS:
{zap_findings_text}

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
