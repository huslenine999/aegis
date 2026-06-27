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

Run the quickest local iteration scan:

```bash
aegis scan . --fast
```

Fast mode skips Safety/OSV, Semgrep, ClamAV, Docker sandbox, Trivy, and DAST checks. It still runs Ruff SAST, detect-secrets, YARA/fallback signatures, and the policy engine.

Set a per-tool timeout:

```bash
aegis scan . --timeout 60
```

Write reports to a specific directory:

```bash
aegis scan app/main.py --output ./aegis-reports
```

Show the latest report path:

```bash
aegis report --path
```

Open the latest HTML report:

```bash
aegis report --open
```

Use a custom report directory:

```bash
aegis report --dir ./aegis-reports --path
```

Print a JSON summary for CI or scripts:

```bash
aegis scan app/main.py --no-docker --json
```

Write SARIF for GitHub code scanning or review tooling:

```bash
aegis scan . --sarif
```

Use a project config file:

```yaml
scan:
  no_docker: true
  fail_on: medium,high,critical
  timeout: 120
  sarif: aegis.sarif
  exclude_paths:
    - app/demo_lab.py
  suppressions:
    - tool: Ruff
      rule: S103
      path: app/cli.py
      reason: Git hook installer intentionally writes an executable pre-push hook.
```

Aegis discovers `aegis.yml`, `aegis.yaml`, `.aegis.yml`, or `.aegis.yaml` from the scan target upward. CLI flags override config values. Suppressed findings are written to `suppressions-report.json` so release exceptions stay auditable.

Suppress progress output:

```bash
aegis scan app/main.py --quiet
```

Override blocking severities for supported scanner families:

```bash
aegis scan . --fail-on high,critical
```

The CLI writes reports next to the target:

```txt
.aegis/scans/report.html
.aegis/scans/report.md
```

Normal terminal scans print per-tool timing output. JSON summaries include the same information in a `timings` array:

```txt
Scanner timings:
  Ruff: 0.16s
  Secrets: 0.40s
  YARA: 0.01s
  Policy Engine: 0.05s
  Total: 0.62s
```

Exit codes:

```txt
0 = deployment allowed
1 = security policy blocked
2 = operational or configuration error
```

For CI, use strict mode so a requested scanner failure cannot be interpreted as
a clean report:

```bash
aegis scan . --no-docker --strict --json
```

Every completed scan writes `scan-manifest.json` beside the reports. It records
the Aegis version, timestamps, requested modes, policy result, final exit code,
and the completion state of each scanner.

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

The web console starts in scanner-console mode by default. Intentionally vulnerable training routes are disabled unless you opt in:

```bash
AEGIS_ENABLE_DEMO_LAB=true ./setup.sh
```

For shared or remote deployments, protect state-changing dashboard actions with an admin token:

```bash
AEGIS_ADMIN_TOKEN="$(openssl rand -hex 24)" ./setup.sh
```

Requests to `/run-scan`, `/toggle-waf`, and `/save-waf-rules` must then include `X-Aegis-Token: <token>`. CORS defaults to localhost origins; set `AEGIS_CORS_ORIGINS` to a comma-separated allowlist when deploying elsewhere.

Run the dashboard with Redis through Docker Compose:

```bash
docker compose up --build
```

---

## Package Installation

Install as a Python CLI with pipx:

```bash
pipx install git+https://github.com/huslenine999/aegis
aegis scan app/main.py
```

Or install into an active Python environment:

```bash
pip install git+https://github.com/huslenine999/aegis
aegis scan app/main.py
```

For local development, install the checkout in editable mode:

```bash
pip install -e ".[dev]"
aegis scan app/main.py
```

The Python distribution name is `aegis-security-console`; it exposes the command:

```txt
aegis
```

The npm wrapper remains available from the GitHub package source:

```bash
npm install -g github:huslenine999/aegis
aegis scan app/main.py
```

The npm package also exposes the command:

```txt
aegis
```

The public npm name `aegis` is already taken by another package. If that registry name becomes available or transferred, the install command can become `npm install -g aegis`. Homebrew formula support is also present in `Formula/` for local tap-based installation.

---

## Health and Version Checks

Check local scanner dependencies:

```bash
aegis doctor
aegis doctor --json
```

Print the package version:

```bash
aegis version
```

---

## Cloud Approval Gate

Aegis can run as the approval gate after developers push code to GitHub:

```mermaid
graph LR
    Push[Developer pushes to Git] --> Action[GitHub Actions starts]
    Action --> Scan[Aegis scans the checkout]
    Scan --> Policy[Policy engine evaluates findings]
    Policy --> Reports[HTML, Markdown, JSON, and SBOM reports]
    Policy --> Decision{Decision}
    Decision -->|Allowed| Approved[Project approved]
    Decision -->|Blocked| Declined[Project declined]
    Decision -->|Operational error| Error[Scan failed closed]
```

This repository wires that flow in `.github/workflows/security-pipeline.yml`.
The `security-gate` job checks the pushed project out separately from a reviewed,
immutable Aegis scanner and policy revision, then runs:

```bash
aegis scan target --no-docker --strict --output aegis-reports --json --fail-on medium,high,critical
```

Exit code `0` approves the project, `1` means the security policy found blocking
issues, and `2` means the scan could not complete reliably. The Action exposes
the corresponding `decision` output as `approved`, `declined`, or `error`.

Generated cloud reports are available in the GitHub Actions run summary and in the `aegis-approval-reports` artifact.

To use Aegis from another GitHub repository:

```yaml
name: Aegis Security Gate

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
      - uses: huslenine999/aegis@1048b036a04a8a6a28a212ebc5d623a2fe23f8c0
        with:
          scan-target: .
          output-dir: aegis-reports
          no-docker: "true"
          strict: "true"
          fail-on: medium,high,critical
```

The example pins both Actions to reviewed commits. Update the Aegis SHA only
after validating a new release. Keep the policy configuration and required
workflow in a protected location; a pull request that can modify its own
security workflow is not an independent approval boundary.

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

The CLI records intentional skips and operational failures separately in
`scan-manifest.json`. In strict mode, failed requested scanners return exit code
`2`; explicitly disabled checks remain auditable skips.

Shared scanner implementations for Semgrep rule generation, YARA fallback matching, and ClamAV fallback matching live in `app/scanners.py`. The CLI and web worker call that shared module with different log adapters, so report shapes stay consistent across terminal and dashboard scans.

When Docker scanning is enabled, the CLI builds a temporary sandbox image, starts the container with memory, CPU, PID, and `WAF_ENABLED` controls, waits for the actual localhost sandbox URL to become healthy, then runs Trivy and DAST probes against that URL.

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
    WS --> UI[Simple Dashboard and Tactical Console]
```

The dashboard defaults to Simple view, a cleaner security workbench for daily use:

- Overview cards for verdict, exploitability, WAF status, and latest scan.
- Scan and upload actions.
- Stepper-style scan progress.
- Findings tab with severity filters and fix guidance.
- Reports tab with HTML, Markdown dossier, SBOM, and copy-path actions.
- WAF tab with status/toggle and a route to the advanced editor.
- Logs tab with live scan events and browser-local scan history.
- Settings tab with reduced-motion and default-view controls.

Tactical view preserves the original CRT-style console with live scan state updates, EventSource telemetry, WAF rule controls, dependency graph visualization, threat simulation, and generated compliance reports.

The intentionally vulnerable lab endpoints (`/user`, `/ping`, `/calculate`, `/load-profile`, `/download`, `/hash`, `/xss`, `/ssrf`, and `/debug-info`) live in `app/demo_lab.py` and are disabled in the default console process. Enable them only for local training or sandboxed demonstrations with `AEGIS_ENABLE_DEMO_LAB=true`.

---

## Project Structure

```txt
aegis/
├── app/
│   ├── cli.py                  # CLI scanner entrypoint for aegis scan
│   ├── main.py                 # FastAPI app, WAF middleware, routes, WebSockets
│   ├── demo_lab.py             # Opt-in intentionally vulnerable training routes
│   ├── worker.py               # Redis Queue worker for async scans
│   ├── secure_main.py          # Hardened demo target
│   ├── database.py             # SQLite setup and WAF rule seed data
│   ├── sandbox.py              # Docker sandbox lifecycle and telemetry
│   ├── scanners.py             # Shared Semgrep, YARA, and ClamAV scanner helpers
│   ├── static/
│   │   ├── enhanced-dashboard.css
│   │   └── enhanced-dashboard.js
│   └── templates/
│       ├── index.html          # Simple dashboard shell and tactical UI
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
├── aegis.yml
├── package.json
├── pyproject.toml
├── requirements.txt
└── setup.sh
```

---

## Testing

Focused scanner, CLI, sandbox, and policy-adjacent verification:

```bash
./venv/bin/python -m pytest tests/test_cli.py tests/test_sandbox.py tests/test_phase1.py tests/test_phase3.py::test_run_clamav_scan_eicar tests/test_phase3.py::test_run_clamav_scan_backdoor
```

Syntax and help checks:

```bash
./venv/bin/python -m py_compile app/main.py app/cli.py app/worker.py
./venv/bin/python -m py_compile app/scanners.py app/cli.py app/worker.py
node --check app/static/enhanced-dashboard.js
./venv/bin/python app/cli.py --help
./venv/bin/python app/cli.py scan --help
./venv/bin/python app/cli.py doctor --json
./venv/bin/python app/cli.py version
```

Dashboard smoke checks:

```txt
/ 200
/static/enhanced-dashboard.css 200
/static/enhanced-dashboard.js 200
/get-scan-results 200
```

Current verification status:

```txt
Full suite: 83 passed.
Focused CLI, policy, and Action contract suite: 25 passed.
Critical Ruff checks and pip dependency consistency checks pass.
```

If a Docker, WAF, or DAST integration path stalls, `pytest-timeout` fails the specific test instead of hanging the whole validation job.

The GitHub Actions workflow in `.github/workflows/security-pipeline.yml` runs
the cloud approval gate, package/wheel checks, Action contract validation,
focused CLI/policy tests, the full timeout-protected suite, and a SARIF smoke
scan on pushes and pull requests.

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
aegis scan "$REPO_DIR" --fast
```

and blocks the push when the policy engine returns a non-zero exit code.

---

## Notes for Teams

- Use `aegis scan <filename>` for quick local review before committing.
- Use `aegis scan . --fast` for quick local feedback when you do not need the slower optional scanners.
- Use `aegis scan . --no-docker` in fast pre-push or CI jobs when Docker is unavailable.
- Use `aegis scan . --json --output ./reports` when integrating with automation.
- Use `aegis report --open` after a scan to inspect the generated HTML report.
- Run the full dashboard flow when you want live logs, WAF controls, sandbox telemetry, and visual reports.
- Treat generated `.aegis/scans/` output as local scan artifacts unless you explicitly want to archive reports.
