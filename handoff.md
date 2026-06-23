# Aegis Project Handoff

## Current State

Aegis is now both a CLI-first security scanner and a FastAPI-based DevSecOps dashboard. The main command target is:

```bash
aegis scan <filename>
```

The scanner writes local reports under `.aegis/scans/` for CLI runs and under `scans/` for the web-console workflow. The web console still runs on FastAPI with Redis Queue workers and streams scan progress over WebSockets.

The latest work added and hardened the CLI path:

- `app/cli.py` provides `scan`, `install-hook`, and `uninstall-hook`.
- `package.json` exposes the short npm binary name `aegis`.
- `bin/aegis` routes arguments to the CLI and starts the web app when no arguments are provided.
- `bin/cli.js` does the same for npm installs.
- `scripts/setup_alias.sh` can install shell aliases for local source checkouts.
- `tests/test_cli.py` covers scan exit codes, hook install/uninstall, and ASCII report output.

## How to Use the CLI

Scan one Python file:

```bash
aegis scan app/main.py
```

Scan a directory:

```bash
aegis scan .
```

Skip Docker, Trivy, and DAST checks:

```bash
aegis scan app/main.py --no-docker
```

Set a per-tool timeout:

```bash
aegis scan . --timeout 60
```

Expected exit codes:

```txt
0 = deployment allowed
1 = security gate blocked or command failed
```

CLI reports:

```txt
.aegis/scans/report.html
.aegis/scans/report.md
```

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

The CLI creates placeholder reports for skipped tools so the policy engine can make deterministic decisions. Docker-dependent checks are skipped cleanly when Docker is unavailable or `--no-docker` is used.

## Key Files

- `app/cli.py`: CLI scanner implementation.
- `app/main.py`: FastAPI web app, WAF middleware, dashboard routes, WebSockets.
- `app/worker.py`: Redis Queue scan worker and live log publisher.
- `app/sandbox.py`: Docker sandbox lifecycle, telemetry, Trivy helpers.
- `policy_engine.py`: Report analyzers, CVSS scoring, policy decision, report generation.
- `bin/aegis`: Local shell wrapper.
- `bin/cli.js`: npm wrapper.
- `package.json`: npm metadata and binary names.
- `scripts/setup_alias.sh`: Local alias installer.
- `tests/test_cli.py`: CLI regression tests.
- `tests/test_policy.py`: Policy analyzer tests.

## Verification Performed

Focused verification passed:

```bash
./venv/bin/pytest tests/test_cli.py tests/test_policy.py
```

Result:

```txt
9 passed, 46 warnings
```

Additional checks passed:

```bash
./venv/bin/python -m py_compile app/cli.py policy_engine.py tests/test_cli.py
./venv/bin/python app/cli.py --help
./venv/bin/python app/cli.py scan --help
node -e "const p=require('./package.json'); console.log(p.bin.aegis)"
```

The full suite currently collects 64 tests. A previous full run was interrupted after 29 passing tests because a later integration path hung. Before publishing a formal release, isolate that slow test and restore a clean full-suite result.

## Recommended Next Moves

1. Run `aegis scan <filename>` from an installed or linked package and confirm the UX matches the desired command.
2. Isolate the hanging full-suite test path and add a timeout or stronger mock around external scanner/subprocess work.
3. Update `CHANGELOG.md` with the CLI release notes.
4. Decide whether generated files in `scans/` should remain tracked or be ignored.
5. Tag a release after the full suite is stable.
