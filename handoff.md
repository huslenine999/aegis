# Aegis Project Handoff

## Current State

Aegis is a CLI-first security scanner, reusable GitHub Actions approval gate, Python-installable command line package, and FastAPI DevSecOps dashboard.

The main user-facing command is:

```bash
aegis scan .
```

The fastest local feedback path is:

```bash
aegis scan . --fast
```

The cloud approval flow is:

```txt
Developer pushes to GitHub
-> GitHub Actions checks out the repo
-> Aegis scans the full project
-> policy_engine.py evaluates all reports
-> Aegis writes Markdown, HTML, JSON, SARIF, SBOM, and scan-manifest reports
-> workflow approves, declines on policy findings, or fails closed on scanner errors
```

The public product/command name is `aegis`. The Python distribution name is `aegis-security-console`. The npm package metadata also exposes the `aegis` command, but the public npm name `aegis` is already taken by another package, so public npm publishing still requires a transfer or a scoped package name.

## Install and Use

Install as a Python CLI with pipx:

```bash
pipx install git+https://github.com/huslenine999/aegis
aegis scan .
```

Install into an active Python environment:

```bash
pip install git+https://github.com/huslenine999/aegis
aegis scan .
```

Local editable install:

```bash
pip install -e ".[dev]"
aegis scan .
```

Install through the GitHub npm source wrapper:

```bash
npm install -g github:huslenine999/aegis
aegis scan .
```

Useful CLI commands:

```bash
aegis scan .
aegis scan . --fast
aegis scan . --no-docker
aegis scan . --output ./aegis-reports
aegis scan . --json
aegis scan . --strict --json
aegis scan . --sarif
aegis scan . --fail-on medium,high,critical
aegis report --path
aegis report --open
aegis doctor
aegis doctor --json
aegis version
```

Expected exit codes:

```txt
0 = project approved / deployment allowed
1 = project declined / security policy blocked
2 = operational or configuration error
```

## CLI Performance and Reports

`--fast` skips the slowest optional scanner paths:

- Safety/OSV dependency checks.
- Semgrep.
- ClamAV.
- Docker sandbox execution.
- Trivy.
- DAST endpoint probes.

Fast mode still runs:

- Ruff SAST.
- detect-secrets.
- YARA/fallback signatures.
- Policy engine/report generation.

The CLI now records scanner timings. Normal terminal output prints a `Scanner timings:` block, and JSON summaries include a `timings` array.

For CI, `--strict` makes requested scanner failures fail closed with exit code
`2`. Every completed scan writes `scan-manifest.json` with UTC timestamps,
version, requested modes, policy/final exit codes, and per-scanner
`completed`, `skipped`, or `failed` states. JSON reports are written atomically.

The report command locates generated reports:

```bash
aegis report
aegis report --path
aegis report --open
aegis report --markdown
aegis report --dir ./aegis-reports
```

## GitHub Actions Gate

The reusable action is defined in `action.yml`. It:

- Sets up Python.
- Installs the Aegis Python package and runs its installed `aegis` entry point.
- Passes inputs through environment variables and a Bash argument array.
- Validates boolean, timeout, and output-directory inputs.
- Enables strict fail-closed behavior by default.
- Writes reports to `aegis-reports` by default.
- Appends `report.md` to the GitHub job summary.
- Exposes `decision` as `approved`, `declined`, or `error`.
- Exposes `summary-json` and `exit-code`.
- Exits with the Aegis policy result so branch protection can block bad code.

Current action inputs:

```yaml
scan-target: .
output-dir: aegis-reports
no-docker: "true"
timeout: "120"
fail-on: medium,high,critical
config: ""
sarif: "false"
strict: "true"
```

Use from another repository:

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
      - uses: huslenine999/aegis@5725dcb63ebe0f0eac070c2b908ec6f1cd1a45ff
        with:
          scan-target: .
          output-dir: aegis-reports
          no-docker: "true"
          strict: "true"
          fail-on: medium,high,critical
```

This repo's workflow, `.github/workflows/security-pipeline.yml`, has:

- `security-gate`: scans each push/PR with an immutable Aegis revision and
  separately sourced policy.
- `validate`: runs dependency consistency, compile, critical lint, wheel,
  installed-command, Action contract, CLI/policy, full suite, and SARIF checks.
- Workflow/job timeouts, pip caching, concurrency cancellation, and
  least-privilege job permissions are configured.
- The approval gate checks PR code out under `target/` and separately installs
  the scanner and policy from immutable revision
  `5725dcb63ebe0f0eac070c2b908ec6f1cd1a45ff`.
- Third-party Actions are pinned to full commit SHAs and tracked by Dependabot.
- `.github/workflows/action-e2e.yml` runs for relevant main-branch changes,
  weekly, or manually against the published immutable Aegis revision and
  asserts Action outputs and reports.
- `.github/CODEOWNERS` assigns security-sensitive workflow, policy, and package
  files to `@huslenine999`; repository rules must require code-owner review for
  this to become an enforced boundary.

## Local Git Hook

Install a pre-push gate inside a Git repo:

```bash
aegis install-hook
```

Remove it:

```bash
aegis uninstall-hook
```

The hook now runs fast mode:

```bash
aegis scan "$REPO_DIR" --fast
```

and blocks `git push` when the policy engine returns non-zero.

## Web Console Runbook

Start the dashboard:

```bash
./setup.sh
```

The setup script verifies Redis, starts an RQ worker when Redis is available, and launches Uvicorn on:

```txt
http://127.0.0.1:5001
```

The dashboard now defaults to a cleaner Simple view. Tactical view preserves the original CRT/security-console experience.

Simple view includes:

- Overview cards for verdict, exploitability, WAF status, and latest scan.
- Scan and upload actions.
- Stepper-style scan progress.
- Findings tab with severity filters and fix guidance.
- Reports tab with HTML, Markdown dossier, SBOM, and copy-path actions.
- WAF tab with simple status/toggle and a route to the advanced editor.
- Logs tab with live scan events and local browser scan history.
- Settings tab with reduced-motion and default-view controls.

Tactical view includes:

- Live scan state streaming over `/ws/scan/{job_id}`.
- Legacy telemetry over `/stream-telemetry`.
- WAF custom rule editing.
- Threat simulation lab.
- Dependency graph visualization.
- Static, dependency, sandbox, Trivy, DAST, secrets, YARA, and ClamAV scan summaries.
- HTML and Markdown compliance reports.

## Scanner Pipeline

The active scanner path includes:

- Ruff SAST using Bandit-compatible `S` rules.
- Semgrep custom Python rules.
- Safety and OSV dependency checks.
- CVSS v3.1 scoring.
- detect-secrets scanning.
- YARA or fallback suspicious-pattern scanning.
- ClamAV or fallback malware checks.
- Docker sandbox execution when available.
- Trivy image scanning when available.
- DAST-style probes against sandboxed endpoints.
- Policy decisions through `policy_engine.py`.

The CLI records skipped and failed tools separately. Strict mode returns exit
code `2` for requested scanner failures, while checks explicitly disabled with
`--no-docker` or `--fast` remain auditable `SKIPPED` results.

Recent implementation notes:

- `pyproject.toml` packages Aegis as `aegis-security-console` and exposes `aegis = app.cli:main`.
- `app/__init__.py` and `rules/__init__.py` make package resources importable.
- `app/static/enhanced-dashboard.css` owns the cleaner dashboard styling.
- `app/static/enhanced-dashboard.js` owns Simple-view dashboard behavior.
- `app/main.py` mounts `/static` and expands `/get-scan-results` with scanner reports, latest report metadata, and report links.
- `app/scanners.py` owns shared Semgrep rule generation, YARA scanning/fallback matching, and ClamAV scanning/fallback matching.
- `app/worker.py` uses the shared scanner module with Redis/WebSocket log publishing wrappers.
- The CLI Docker path matches `app/sandbox.py`: it starts containers as `(image_tag, container_name, host_port, container_port, waf_enabled)`, waits on `http://127.0.0.1:{host_port}`, then runs DAST against that URL.

## Key Files

- `pyproject.toml`: Python package metadata and CLI entry point.
- `action.yml`: reusable GitHub Action approval gate.
- `.github/workflows/security-pipeline.yml`: repo CI with approval gate and validation job.
- `app/cli.py`: CLI scanner implementation.
- `app/main.py`: FastAPI web app, WAF middleware, dashboard routes, static assets, WebSockets.
- `app/worker.py`: Redis Queue scan worker and live log publisher.
- `app/scanners.py`: shared Semgrep, YARA, and ClamAV scanner helpers.
- `app/static/enhanced-dashboard.css`: Simple-view dashboard styles.
- `app/static/enhanced-dashboard.js`: Simple-view dashboard controller.
- `app/templates/index.html`: dashboard shell and preserved tactical UI.
- `policy_engine.py`: report analyzers, CVSS scoring, policy decision, report generation.
- `app/sandbox.py`: Docker sandbox lifecycle, telemetry, Trivy helpers.
- `bin/aegis`: local shell wrapper.
- `bin/cli.js`: npm wrapper.
- `package.json`: npm metadata; package/bin name is `aegis`.
- `rules/aegis_rules.yar`: Aegis YARA signatures.
- `tests/test_cli.py`: CLI regression tests.
- `tests/test_policy.py`: policy analyzer tests.
- `tests/test_action.py`: composite Action contract, Bash syntax, and invalid-input tests.

## Verification Performed

Recent passing checks:

```bash
./venv/bin/pytest -q --timeout=60 --timeout-method=thread
./venv/bin/pytest -q tests/test_action.py tests/test_cli.py tests/test_policy.py
./venv/bin/ruff check app/cli.py app/config.py policy_engine.py --select E9,F63,F7,F82
./venv/bin/python -m compileall -q app policy_engine.py tests
./venv/bin/pip check
```

Result:

```txt
Full suite: 83 passed, 194 upstream deprecation warnings.
Final focused suite: 25 passed.
Critical Ruff checks: passed.
Dependency consistency: no broken requirements.
```

Static/dashboard endpoint smoke checks passed through FastAPI `TestClient`:

```txt
/ 200
/static/enhanced-dashboard.css 200
/static/enhanced-dashboard.js 200
/get-scan-results 200
```

Python packaging checks passed, including a `2.1.0` wheel and installed entry
point:

```bash
python3 -m pip wheel . --no-deps -w /private/tmp/aegis-wheel-test
./venv/bin/python -m pip install -e . --no-deps --no-build-isolation
./venv/bin/aegis version
./venv/bin/aegis --help
```

Browser verification performed with the in-app browser:

- Simple view opens by default.
- New dashboard is visible.
- Tactical legacy experience is hidden in Simple view.
- Findings tab interaction works.
- Desktop screenshot had no console errors.
- Mobile viewport had no horizontal overflow.

## Next Production Priorities

- Move the required approval workflow to GitHub organization/repository rules
  or another protected location so a pull request cannot alter its own gate.
- After the next reviewed release, update both immutable Aegis SHA references
  and manually run the published Action E2E workflow.
- Resolve the 194 FastAPI/Starlette deprecation warnings before upgrading the
  supported Python runtime.

## Current Git/Workspace Notes

- Generated reports under `scans/` were restored after verification and are not
  part of this production-hardening change.
- The new dashboard assets are under `app/static/`.
- `scanner-venv/`, `.aegis/`, cache folders, build outputs, and egg metadata are ignored in `.gitignore`.
