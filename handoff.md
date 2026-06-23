# Aegis Project Handoff

## Current State

Aegis is now a CLI-first security scanner, GitHub Actions approval gate, and FastAPI DevSecOps dashboard.

The main user-facing command is:

```bash
aegis scan .
```

The desired cloud flow is wired:

```txt
Developer pushes to GitHub
-> GitHub Actions checks out the repo
-> Aegis scans the full project
-> policy_engine.py evaluates all reports
-> Aegis writes Markdown, HTML, JSON, and SBOM reports
-> workflow passes when approved and fails when declined
```

The public product/command name is now just `aegis`. The old `aegis-secure-console` package/bin naming has been removed from repo metadata and docs.

Important npm caveat: the public npm package name `aegis` is already taken by another package (`aegis@0.1.0`). This repo can package locally as `aegis`, but publishing to public npm as unscoped `aegis` requires getting that package name transferred or choosing a scoped name.

## Install and Use

Install from the GitHub repo source:

```bash
npm install -g github:huslenine999/aegis
```

Use the CLI:

```bash
aegis scan .
```

Fast local scan without Docker, Trivy, and DAST:

```bash
aegis scan . --no-docker
```

Write reports to a specific folder:

```bash
aegis scan . --no-docker --output ./aegis-reports
```

Print JSON for automation:

```bash
aegis scan . --no-docker --json
```

Override supported blocking severities:

```bash
aegis scan . --fail-on medium,high,critical
```

Expected exit codes:

```txt
0 = project approved / deployment allowed
1 = project declined / security gate blocked or command failed
```

Health and version checks:

```bash
aegis doctor
aegis doctor --json
aegis version
```

## GitHub Actions Gate

The reusable action is defined in `action.yml`. It:

- Sets up Python.
- Installs Aegis Python dependencies from `requirements.txt`.
- Runs `app/cli.py scan` on the target checkout.
- Writes reports to `aegis-reports` by default.
- Appends `report.md` to the GitHub job summary.
- Exposes `decision` as `approved` or `declined`.
- Exits with the Aegis policy result so branch protection can block bad code.

Current action inputs:

```yaml
scan-target: .
output-dir: aegis-reports
no-docker: "true"
timeout: "120"
fail-on: medium,high,critical
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
      - uses: actions/checkout@v4
      - uses: huslenine999/aegis@main
        with:
          scan-target: .
          output-dir: aegis-reports
          no-docker: "true"
          fail-on: medium,high,critical
```

This repo’s own workflow, `.github/workflows/security-pipeline.yml`, now has two jobs:

- `security-gate`: runs the Aegis approval scan on every push/PR.
- `validate`: runs syntax, CLI, package metadata, and focused policy tests.

## Local Git Hook

Install a pre-push gate inside a Git repo:

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

and blocks `git push` when the policy engine returns non-zero.

## Web Console Runbook

Start the dashboard:

```bash
./setup.sh
```

The setup script verifies Redis, starts an RQ worker, and launches Uvicorn on:

```txt
http://127.0.0.1:5001
```

The dashboard supports:

- Simple and Tactical view modes.
- Live scan state streaming over `/ws/scan/{job_id}`.
- Legacy telemetry over `/stream-telemetry`.
- WAF rule toggling and rule editing.
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

The CLI creates placeholder reports for skipped tools so policy decisions stay deterministic. Docker-dependent checks are skipped cleanly when Docker is unavailable or `--no-docker` is used.

Recent implementation notes:

- `app/scanners.py` now owns shared Semgrep rule generation, YARA scanning/fallback matching, and ClamAV scanning/fallback matching.
- `app/cli.py` uses the shared scanner module with a terminal log adapter.
- `app/worker.py` uses the shared scanner module with Redis/WebSocket log publishing wrappers, preserving the existing `run_yara_scan(..., job_id=...)` and `run_clamav_scan(..., job_id=...)` import surface.
- The CLI Docker path now matches `app/sandbox.py`: it starts containers as `(image_tag, container_name, host_port, container_port, waf_enabled)`, waits on `http://127.0.0.1:{host_port}`, then runs DAST against that URL.

## Key Files

- `action.yml`: reusable GitHub Action approval gate.
- `.github/workflows/security-pipeline.yml`: repo CI with approval gate and validation job.
- `app/cli.py`: CLI scanner implementation.
- `app/scanners.py`: shared Semgrep, YARA, and ClamAV scanner helpers.
- `policy_engine.py`: report analyzers, CVSS scoring, policy decision, report generation.
- `app/main.py`: FastAPI web app, WAF middleware, dashboard routes, WebSockets.
- `app/worker.py`: Redis Queue scan worker and live log publisher.
- `app/sandbox.py`: Docker sandbox lifecycle, telemetry, Trivy helpers.
- `bin/aegis`: local shell wrapper.
- `bin/cli.js`: npm wrapper.
- `package.json`: npm metadata; package/bin name is `aegis`.
- `rules/aegis_rules.yar`: Aegis YARA signatures.
- `tests/test_cli.py`: CLI regression tests.
- `tests/test_policy.py`: policy analyzer tests.

## Verification Performed

Passed:

```bash
./venv/bin/python -m py_compile app/scanners.py app/cli.py app/worker.py
./venv/bin/python -m pytest tests/test_cli.py tests/test_sandbox.py tests/test_phase1.py tests/test_phase3.py::test_run_clamav_scan_eicar tests/test_phase3.py::test_run_clamav_scan_backdoor
```

Result:

```txt
29 passed, 96 warnings
```

Additional note: a broader phase3 run was interrupted after 29 passing tests because later WAF/DAST integration tests hung. The scanner refactor and Docker CLI contract are covered by the focused passing suite above.

YAML validation passed:

```txt
action.yml: ok
.github/workflows/security-pipeline.yml: ok
```

Package metadata and packaging checks passed:

```bash
node -e "const p=require('./package.json'); if (p.name !== 'aegis') process.exit(1)"
env npm_config_cache=/private/tmp/aegis-npm-cache npm pack --dry-run --loglevel=warn
```

`npm pack --dry-run` produced:

```txt
aegis-2.0.0.tgz
```

Note: plain `npm pack --dry-run` initially failed because npm tried to write logs under `/Users/huslenine/.npm/_logs`, which was outside the writable sandbox. Using a temp npm cache fixed it.

## Current Git/Workspace Notes

There were pre-existing uncommitted changes before the latest edits, including changes in `app/cli.py`, `tests/test_cli.py`, `README.md`, `handoff.md`, and deleted generated files under `scans/`. Those were not reverted.

Current notable generated/deleted artifacts:

```txt
scans/report.html deleted
scans/report.md deleted
```

Decide before release whether generated `scans/` reports should remain tracked or be ignored.

## Recommended Next Moves

1. Decide npm publishing strategy:
   - get `aegis` transferred on npm, or
   - publish under a scoped name such as `@huslenine/aegis`, while keeping the command binary as `aegis`.
2. Run the GitHub Action in a real GitHub push/PR to verify artifact upload and branch-protection behavior.
3. Isolate the hanging full-suite test path and restore a clean full-suite result.
4. Update `CHANGELOG.md` with the cloud gate and `aegis` rename.
5. Tag a release after CI is stable.
