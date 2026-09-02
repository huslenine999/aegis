# Aegis — Engineering Handoff

Date: 2026-09-02
Branch: `main` (all changes committed and pushed to `origin/main`)

## What Aegis is

Private, explainable release-security gates for small engineering teams. One
workflow: scan a repository → evaluate against a versioned policy → allow /
block / error decision with an explanation → durable findings with owners and
due dates → Ed25519-signed evidence manifests verifiable offline.

Ships three ways:

1. CLI (`aegis scan . --strict`) — exit codes 0=allow, 1=blocked, 2=error
2. GitHub Action (`action.yml`) — fail-closed PR gate, installs from
   `requirements.txt` (hash-pinned `uv export`)
3. Self-hosted workbench — FastAPI dashboard + PostgreSQL + Redis/RQ workers +
   notifier + Caddy (`docker-compose.yml`)

Author: Khuslen Gan-Ochir. Version 2.4.0. MIT.

## Repository map

```
app/
  main.py            App factory only (~136 lines after refactor)
  web_common.py      Shared web state: access-control deps, templates, WAF flag
  routes/            Domain routers (auth, projects, github, admin,
                     artifacts, demo/scan) — moved out of main.py
  cli_config.py      Exclusions, path ignore rules, governance suppressions, fail-on validation
  cli_reports.py     JSON/SARIF writing, doctor, demo, report viewer, Ed25519 verification
  cli_runner.py      Scanner execution engine, multi-tool orchestration, timing, git hooks
  cli.py             CLI facade (~250 lines) with argument parsing & dynamic re-exports
  waf_rules.py       Single WAF rule loader/saver shared by dashboard + workers
  scan_engine.py     Shared job payload, event sinks, semgrep/exclude helpers
  findings.py        Finding normalization, durable fingerprints, baseline ops
  worker.py          RQ scan pipeline (sandbox -> scanners -> policy -> evidence)
  database.py        Raw-SQL adapter over SQLite (dev) / PostgreSQL (prod), migrations
policy_engine.py     Standalone verdict engine; fail-closed decision at
                     evaluate_policy_results() (repo root, importable without pkg context)
rules/               Semgrep YAML + YARA signature packs
tests/               ~30 suites incl. integration (compose lifecycle) and Playwright e2e
docs/                PRODUCTION, OPERATIONS, THREAT_MODEL, HARDENING, GITHUB, runbooks
```

## Recent Refactoring & Architecture Milestones

### 1. Monolithic `cli.py` Split into Domain Submodules
`app/cli.py` (1,949 lines) was decomposed into clean, focused submodules:
- [app/cli_config.py](file:///Users/huslenine/Aegis/app/cli_config.py): Configuration resolution, exclusions, ignore rules, and governance suppressions.
- [app/cli_reports.py](file:///Users/huslenine/Aegis/app/cli_reports.py): SARIF generation, JSON file helpers, `doctor`, `demo`, report rendering, and Ed25519 evidence verification.
- [app/cli_runner.py](file:///Users/huslenine/Aegis/app/cli_runner.py): Core scan execution engine, timing trackers, multi-tool orchestration (Ruff, Semgrep, Detect-Secrets, YARA, ClamAV, Checkov IaC, Trivy/DAST Docker Sandbox), and Git hook handlers.
- [app/cli.py](file:///Users/huslenine/Aegis/app/cli.py) Facade: Reduced to ~250 lines. Handles CLI argument parsing and subcommand routing while maintaining 100% backward compatibility for all imports and pytest dynamic mock patching (`sys.modules["app.cli"]`).

### 2. `main.py` Split into Domain Routers
`app/main.py` reduced from 3,040 → 136 lines. Handlers moved to `app/routes/{auth,project,github,admin,artifact,demo_scan}_routes.py`. Shared web state moved to `app/web_common.py`.

### 3. One-Step Developer Onboarding (`make setup`)
Added `make setup` target in `Makefile` (`uv venv` + `uv pip install -e ".[dev,scanner]"`). Once set up, developers run `source venv/bin/activate` and can run `aegis start`, `aegis scan .`, `aegis doctor` directly.

### 4. Diff-aware gating
PR scans gate on **newly introduced findings** instead of pre-existing technical debt.
Key files: `app/findings.py`, `policy_engine.py`, `app/scan_engine.py`, `app/worker.py`.

### 5. Linter & Type-Checking Baseline
- `ruff check .`: 0 errors across workspace.
- `mypy app policy_engine.py`: 0 errors across 52 source files.

## Current verification status

```
pytest:      312 passed, 2 skipped
ruff:        clean (0 errors)
mypy:        clean (52 source files)
lock-check:  ok
```

Run everything: `make verify` (adds e2e; needs `npm ci` + `npx playwright install chromium` once). Quick loop: `make verify-fast`.

## Upcoming Engineering Workstreams (v3.0 Target)

The team is actively scaling Aegis into a high-concurrency enterprise security gate platform. Below are the key parallel workstreams:

1. **Workstream 1: Database Repository Split (Immediate First Engineering Task)**
   - Extract raw SQL queries out of [app/database.py](file:///Users/huslenine/Aegis/app/database.py) (~62 KB) into domain query repositories (`app/db/db_projects.py`, `app/db/db_scans.py`, `app/db/db_findings.py`, `app/db/db_users.py`, `app/db/db_audit.py`).
   - Prevents database file merge conflicts across team members.

2. **Workstream 2: Worker Pipeline Decomposition**
   - Modularize [app/worker.py](file:///Users/huslenine/Aegis/app/worker.py) (~65 KB) into discrete execution stages (`worker_sandbox.py`, `worker_policy.py`, `worker_evidence.py`).

3. **Workstream 3: Diff-Aware Gating UI & Finding Lifecycle**
   - Surface "N pre-existing findings excluded" badges in the dashboard report view and add finding lifecycle tracking (`first_seen_run_id`, owner assignments, due dates).

4. **Workstream 4: Scanner Intelligence & Release Automation**
   - Move from dependency regex scanning to CycloneDX/SPDX SBOM-driven OSV matching.
   - Standardize severity and confidence metrics across all 7 scanners.
   - Automate PyPI releases (`aegis-security-console`) and versioned GitHub Action tags (`v2.4.0`, `v3.0.0`).

## Environment gotchas

- macOS/zsh; Makefile recipes use `/bin/sh` (no process substitution).
- `uv export` writes its own output path into the file header — never byte-compare two exports from different paths (see `lock-check` for the normalized header filter).
- Dynamic mock patching on `app.cli`: Submodules use dynamic attribute lookups against `sys.modules.get("app.cli")` during scan execution so unit test `unittest.mock.patch("app.cli.<func>")` statements take effect.
