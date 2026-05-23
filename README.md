# Aegis: Automated DevSecOps Pipeline & Retro CRT Security Console

Aegis is an interactive DevSecOps dashboard and policy scanner that automates security verification for multi-language source code (Python, C, C++, Java, JS, TS), third-party dependencies, and container images. It provides a visual demonstration of common vulnerability injections, live Web Application Firewall (WAF) mitigation controls, and automated policy scanning.

---

## 📺 The Retro CRT Phosphor Green Interface

Aegis features a premium, immersive **90s Retro CRT Terminal** theme styled with glowing phosphor elements, scanlines, and vignette shadow overlays:

* **3D Vanishing Grid Horizon**: The background features an animated HTML5 vector wireframe grid that scrolls forward and responds to mouse coordinates with elastic warp physics.
* **Threat Lab Mainframe Simulator**: A CLI emulator shell that prints live stream stdout logs when SQL Injection, Directory Traversal, or Remote Code Execution (RCE) vectors are simulated against local endpoints.
* **WAF Shield Control**: A toggle switch modeled as an analog hardware lever to dynamically shift the application status between `VULNERABLE` (raw bypasses allowed) and `ARMED_SHIELD` (WAF blocking active).
* **Consolidated Security Reports**: Clean, monospace visual layout utilizing custom web fonts (`VT323` and `Share Tech Mono`) for readability under high-density diagnostic data.

---

## 🛡️ Core Architecture

```mermaid
graph TD
    Dev[Developer/Source Code] -->|Pushes Code| CI[CI/CD pipeline]
    CI -->|Runs Semgrep/Safety| Scan[Scanners]
    Scan -->|Generates JSON logs| Engine[Policy Engine]
    Engine -->|Parses Results| Decision{Deployment Blocked?}
    Decision -->|Yes| Report[HTML Report generated]
    Decision -->|No| Deploy[Ship to Production]
```

* **HTML Report**: `scans/report.html` - Visual tactical mainframe report with diagnostic details of Semgrep and library scanner findings.
* **Markdown Report**: `scans/report.md` - Optimized for GitHub Job summaries.

---

## 📂 Project Structure

```txt
aegis/
├── app/
│   ├── main.py                # Main Flask dashboard & vulnerability routes
│   ├── secure_main.py         # Secure equivalent code (vulnerability fixes)
│   ├── database.py            # Simulated SQLite database for persistent actions
│   └── templates/
│       ├── index.html         # Main CRT terminal dashboard template
│       └── report_template.html # CRT diagnostics report template
├── scripts/
│   └── seed_db.py             # Pre-populates simulation database tables
├── scans/
│   ├── report.html            # Compiled static scan output
│   └── report.md              # Compiled markdown output
├── tests/
│   ├── test_policy.py         # Test suite for policy engine thresholds
│   └── test_waf.py            # Test suite for Web Application Firewall rules
├── policy_engine.py           # Evaluates scanner outputs against severity policies
├── setup.sh                   # Automated environment build and startup script
├── requirements.txt           # Production dependencies
├── requirements-dev.txt       # Dev & scanning dependencies (pytest, semgrep, safety, etc.)
├── Dockerfile                 # Containerized image file
└── README.md                  # Project documentation
```

---

## 🛠️ Getting Started

### 1. Automated Setup & Run (Recommended)
You can set up dependencies, configure the SQLite databases, and start the application in one command:
```bash
chmod +x setup.sh
./setup.sh
```

### 2. Manual Setup
Activate a virtual environment and install packages:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Seed the database
python scripts/seed_db.py

# Launch server
python app/main.py
```
Open your browser to `http://127.0.0.1:5001`.

---

## 🧪 Testing

Aegis includes pytest coverage for scanning policy rules and WAF intercept controls:
```bash
# Activate virtual environment
source venv/bin/activate

# Execute tests
pytest
```

---

## 🚀 DevSecOps Implementation Workflow for Teams

You can use the patterns shown in Aegis to strengthen security in your production pipelines:

1. **Adopt Automated Code Linters**: Run tools like `semgrep scan --config=auto --json -o semgrep-report.json` as a pre-commit hook or inside your PR tests.
2. **Fail Fast with Policy Engines**: Use `policy_engine.py` to assert scan findings. Return `exit 1` to fail pipelines automatically when any `HIGH` or `CRITICAL` vulnerability is introduced.
3. **Audit Third-Party Packages**: Run `safety check` to prevent outdated dependencies with known CVEs from reaching your production containers.

---

## 📦 Reusable GitHub Action Integration

Aegis is packaged as a reusable composite GitHub Action, allowing external teams to run unified security gates directly in their workflows.

### Usage Example

Include the Aegis action in your repository's workflow (e.g., `.github/workflows/security.yml`):

```yaml
name: Security Scan Gate

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Aegis Security Scan & Policy Gate
        uses: huslenine/Aegis@main
        with:
          python-version: '3.11'
          scan-target: 'app' # File or directory to scan
          requirements-file: 'requirements.txt'
          # Optional: Build and scan a container image (e.g., 'myapp:latest')
          image-name: ''
          # Thresholds
          fail-on-semgrep: 'MEDIUM,HIGH'
          fail-on-bandit: 'MEDIUM,HIGH'
          fail-on-safety: 'true'
          fail-on-trivy: 'MEDIUM,HIGH,CRITICAL'
```

This composite action installs dependencies, executes the scans (Semgrep, Bandit, Safety, and optional Trivy), executes the Aegis policy gate, generates static reports, and appends a security diagnostics summary to your GitHub Job Summary page.

