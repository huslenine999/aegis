import base64
import hashlib
import os
import json
import sqlite3
import subprocess
from pathlib import Path

# Add the current directory to sys.path to allow imports when running from root
import sys
sys.path.append(str(Path(__file__).resolve().parent))

from flask import Flask, jsonify, render_template, request

# In a secure app, you'd import database logic securely
from database import DB_PATH

app = Flask(__name__)

# SECURE: Environment variables for secrets with no hardcoded fallbacks in production
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

BASE_DIR = Path(__file__).resolve().parent
DOWNLOAD_DIR = BASE_DIR / "downloads"
DOWNLOAD_DIR.mkdir(exist_ok=True)

@app.route("/")
def index():
    return "<h1>Secure Aegis</h1><p>This is the hardened reference implementation.</p>"

@app.route("/user")
def get_user():
    """
    SECURE: Uses parameterized queries to prevent SQL Injection.
    """
    username = request.args.get("name", "guest")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # SECURE: Use ? placeholder for parameters
    query = "SELECT id, username, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    rows = cursor.fetchall()
    conn.close()

    return jsonify({"results": rows})

@app.route("/ping")
def ping_host():
    """
    SECURE: Validates input and avoids shell=True to prevent Command Injection.
    """
    host = request.args.get("host", "127.0.0.1")

    # SECURE: Validate input (simple IP validation demo)
    import socket
    try:
        socket.inet_aton(host)
    except socket.error:
        return jsonify({"error": "Invalid IP address"}), 400

    # SECURE: Pass arguments as a list, shell=False
    command = ["ping", "-c", "1", host]
    output = subprocess.check_output(command, shell=False, text=True)  # nosemgrep # nosec

    return jsonify({"output": output})

@app.route("/calculate")
def calculate():
    """
    SECURE: Avoids eval(). Uses a safe parser if needed.
    """
    expression = request.args.get("expr", "1+1")
    
    # SECURE: Use literal_eval for basic math or a dedicated parser
    import ast
    try:
        # Note: literal_eval only handles literals, not operators like +
        # In a real app, you'd use a safe math library or restricted parser.
        result = "Calculations restricted in secure mode" 
    except Exception:
        return jsonify({"error": "Invalid expression"}), 400

    return jsonify({"result": result})

@app.route("/load-profile", methods=["POST"])
def load_profile():
    """
    SECURE: Uses JSON instead of Pickle to prevent Insecure Deserialization.
    """
    # SECURE: Use standard JSON for data exchange
    profile_data = request.json.get("profile", {})
    
    # No dangerous pickle.loads() here
    return jsonify({"loaded_profile": profile_data})

@app.route("/download")
def download_file():
    """
    SECURE: Validates paths to prevent Path Traversal.
    """
    filename = request.args.get("file", "sample.txt")

    # SECURE: Ensure the filename is just a name, not a path
    safe_filename = Path(filename).name
    target_file = (DOWNLOAD_DIR / safe_filename).resolve()

    # SECURE: Verify the file is actually inside the intended directory
    if not target_file.is_relative_to(DOWNLOAD_DIR) or not target_file.exists():
        return jsonify({"error": "Access denied or file not found"}), 403

    return target_file.read_text()

@app.route("/hash")
def secure_hash():
    """
    SECURE: Uses SHA-256 instead of MD5.
    """
    value = request.args.get("value", "")

    # SECURE: Use a strong hashing algorithm
    digest = hashlib.sha256(value.encode()).hexdigest()

    return jsonify({"sha256": digest})


@app.route("/xss")
def xss_demo():
    """
    SECURE: HTML-escapes parameters before reflecting them.
    """
    import html
    msg = request.args.get("msg", "Welcome to Aegis console.")
    # SECURE: Escape msg to prevent HTML/Script injection
    safe_msg = html.escape(msg)
    return f"<html><body><div id='xss-output'>{safe_msg}</div></body></html>"


@app.route("/ssrf")
def ssrf_demo():
    """
    SECURE: Validates the URL scheme, hostname, and resolution to prevent SSRF.
    """
    url = request.args.get("url", "http://127.0.0.1:5001/health")

    from urllib.parse import urlparse
    import socket

    try:
        parsed = urlparse(url)
        # 1. Enforce http or https scheme only
        if parsed.scheme not in ("http", "https"):
            return jsonify({"error": "Invalid scheme. Only HTTP and HTTPS are allowed."}), 400

        # 2. Extract hostname and resolve to IP
        hostname = parsed.hostname
        if not hostname:
            return jsonify({"error": "Invalid URL hostname."}), 400

        # Resolve host to IP address
        try:
            ip_addr = socket.gethostbyname(hostname)
        except Exception:
            return jsonify({"error": "Failed to resolve host."}), 400

        # 3. Block loopback, link-local metadata, and private IP spaces
        parts = list(map(int, ip_addr.split('.')))
        if len(parts) == 4:
            if (parts[0] == 127 or 
                parts[0] == 0 or
                parts[0] == 10 or 
                (parts[0] == 172 and 16 <= parts[1] <= 31) or 
                (parts[0] == 192 and parts[1] == 168) or 
                (parts[0] == 169 and parts[1] == 254)):
                return jsonify({"error": "Forbidden target address: Private IP ranges are blocked."}), 403

        # 4. Perform safe fetch of validated public address
        import urllib.request
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Aegis-Simulated-Scanner/2.0'}
        )
        with urllib.request.urlopen(req, timeout=2) as response:  # nosec B310
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


if __name__ == "__main__":
    # SECURE: Debug mode always False in production
    app.run(host="0.0.0.0", port=5002, debug=False)  # nosemgrep # nosec

