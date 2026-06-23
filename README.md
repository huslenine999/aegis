# Aegis: DevSecOps Security Console and CLI Scanner

Aegis is a Python security scanner and retro CRT-style DevSecOps dashboard. It can be used as a terminal gate with `aegis scan <filename>` or as a FastAPI web console with Redis Queue workers, WebSocket log streaming, WAF controls, Docker sandbox execution, and generated HTML/Markdown security reports.

The current scanner stack focuses on Python source, dependency risk, secrets, suspicious payload signatures, container image checks, and dynamic endpoint probes when Docker is available.

---

## Quick CLI Use

After installing or linking the package, scan a file with:

```bash
aegis scan app/main.py
```

Scan a directory:

```bash
aegis scan .
```

Skip Docker, Trivy, and DAST checks for a faster local-only scan:

```bash
aegis scan app/main.py --no-docker
```

Set a per-tool timeout:

```bash
aegis scan . --timeout 60
```

The CLI writes reports next to the target:

```txt
.aegis/scans/report.html
.aegis/scans/report.md
```

Exit codes:

```txt
0 = deployment allowed
1 = security gate blocked or command failed
```

---

## Local Development Commands

Run the CLI from the source checkout:

```bash
./bin/aegis scan app/main.py
```

Expose the short `aegis` command locally through npm:

```bash
npm link
aegis scan app/main.py
```

Or install shell aliases:

```bash
./scripts/setup_alias.sh
source ~/.zshrc
aegis scan app/main.py
```

Start the web console:

```bash
chmod +x setup.sh
./setup.sh
```

Open:

```txt
http://127.0.0.1:5001
```

---

## Package Installation

Install from npm:

```bash
npm install -g aegis-secure-console
aegis scan app/main.py
```

The package exposes both commands:

```txt
aegis
aegis-secure-console
```

Homebrew formula support is also present in `Formula/` for local tap-based installation.

---

## Scanner Coverage

Aegis coordinates these scanner paths:

1. Ruff SAST checks using the Bandit-compatible `S` rule family.
2. Semgrep custom Python rules for SQL injection, command execution, unsafe eval, pickle, and weak hashes.
3. Safety and OSV dependency analysis for `requirements.txt`.
4. CVSS v3.1 parsing and exploitability scoring.
5. detect-secrets scanning for hardcoded credentials.
6. YARA or fallback signature scans for webshell and suspicious execution patterns.
7. ClamAV or fallback malware signature checks.
8. Docker sandbox execution with memory, CPU, and PID limits.
9. Trivy image scanning when Docker and Trivy are available.
10. DAST-style endpoint probes against active sandbox containers.
11. WAF-aware risk reduction in the web console flow.

The CLI initializes placeholder reports for skipped tools so policy decisions stay deterministic. Docker-dependent checks are skipped cleanly when Docker is disabled or unavailable.

---

## Web Console Architecture

```mermaid
graph TD
    Dev[Developer or Upload] --> RunScan[POST /run-scan]
    RunScan --> Queue[Redis Queue]
    Queue --> Worker[app/worker.py]
    Worker --> Static[Static and Dependency Scans]
    Worker --> Sandbox[Docker Sandbox]
    Sandbox --> Trivy[Trivy Image Scan]
    Sandbox --> DAST[Dynamic Endpoint Probes]
    Static --> Policy[policy_engine.py]
    Trivy --> Policy
    DAST --> Policy
    Policy --> Reports[HTML and Markdown Reports]
    Worker --> Redis[Redis Pub/Sub]
    Redis --> WS[WebSocket /ws/scan/job_id]
    WS --> UI[CRT Dashboard]
```

The dashboard supports Simple and Tactical views, live scan state updates, EventSource telemetry, WAF rule controls, dependency graph visualization, and generated compliance reports.

---

## Project Structure

```txt
aegis/
├── app/
│   ├── cli.py                  # CLI scanner entrypoint for aegis scan
│   ├── main.py                 # FastAPI app, WAF middleware, routes, WebSockets
│   ├── worker.py               # Redis Queue worker for async scans
│   ├── secure_main.py          # Hardened demo target
│   ├── database.py             # SQLite setup and WAF rule seed data
│   ├── sandbox.py              # Docker sandbox lifecycle and telemetry
│   └── templates/
│       ├── index.html          # CRT dashboard UI
│       └── report_template.html
├── bin/
│   ├── aegis                   # Local shell wrapper
│   └── cli.js                  # npm executable wrapper
├── rules/
│   └── semgrep_rules.yaml
├── scripts/
│   ├── seed_db.py
│   └── setup_alias.sh
├── scans/                      # Web-console scan output
├── tests/
│   ├── test_cli.py
│   ├── test_policy.py
│   ├── test_upload_scan.py
│   └── ...
├── policy_engine.py
├── package.json
├── requirements.txt
└── setup.sh
```

---

## Testing

Focused CLI and policy verification:

```bash
./venv/bin/pytest tests/test_cli.py tests/test_policy.py
```

Syntax and help checks:

```bash
./venv/bin/python -m py_compile app/cli.py policy_engine.py tests/test_cli.py
./venv/bin/python app/cli.py --help
./venv/bin/python app/cli.py scan --help
```

Current focused verification status:

```txt
9 passed, 46 warnings
```

The full suite currently collects 64 tests. A previous full run was interrupted after 29 passing tests because a later integration test path hung, so the next QA task is to isolate that slow test before marking the complete suite green.

---

## Git Hook

Install Aegis as a pre-push gate in the current Git repo:

```bash
aegis install-hook
```

Remove it:

```bash
aegis uninstall-hook
```

The hook runs:

```bash
aegis scan "$REPO_DIR"
```

and blocks the push when the policy engine returns a non-zero exit code.

---

## Notes for Teams

- Use `aegis scan <filename>` for quick local review before committing.
- Use `aegis scan . --no-docker` in fast pre-push or CI jobs when Docker is unavailable.
- Run the full dashboard flow when you want live logs, WAF controls, sandbox telemetry, and visual reports.
- Treat generated `.aegis/scans/` output as local scan artifacts unless you explicitly want to archive reports.
