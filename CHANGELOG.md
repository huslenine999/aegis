# Changelog

All notable changes to the Aegis project will be documented in this file.

## [Unreleased]

### Added

- Added durable finding deduplication, lifecycle events, ownership, due dates,
  expiring risk acceptance, and GitHub remediation issue handoff.
- Added immutable per-project policy versions, approval, scan binding, and
  historical-result simulation.
- Added optional S3-compatible artifact storage with integrity metadata, KMS
  encryption, and object-lock retention, plus OIDC authorization-code/PKCE login.
- Added a dedicated isolated deep-scan queue, recovery verification tooling, and
  a 30-case release benchmark.

### Changed

- Added a reproducible controlled-pilot readiness and recovery rehearsal.
- Tightened scanner/notifier secret boundaries and local artifact-backend claims.
- Consolidated development verification and current production limitations.

### Removed

- Removed the stale delivery handoff, unsupported Vercel target, and duplicate
  legacy setup script.

## [2.3.0] - 2026-07-10

### Changed

- Unified worker decisions with the CLI policy engine and fail closed when scanner evidence is incomplete.
- Added project/run-scoped artifact APIs, integrity hashes, retention controls, and authorized report downloads.
- Replaced self-contained browser sessions with revocable server-side sessions that honor current account roles and status.
- Added project update/deletion, member removal, user disable/role rotation, database indexes, and fresh-install constraints.
- Hardened DAST fallback behavior, request-body limits, webhook redirects/retries, API-token expiry validation, linting, and focused type checks.
- Made the GitHub Action install the full standard scanner extra and included Semgrep in the production worker image.

## [2.2.0] - 2026-06-30

### Added
- Strict CLI mode with a distinct operational-error exit code.
- Atomic JSON report writes and an auditable `scan-manifest.json`.
- Stable GitHub Action `decision`, `summary-json`, and `exit-code` outputs.
- Composite Action contract and Bash syntax tests.
- Scheduled runner-level verification of the published GitHub Action.
- Dependabot tracking for pinned GitHub Action revisions.
- CODEOWNERS coverage for security-sensitive workflow, policy, and package files.
- Production-mode configuration validation, browser support for protected
  dashboard actions, security response headers, bounded uploads, and RQ worker
  readiness checks.
- A container smoke job that builds the production Compose stack and verifies a
  dashboard-to-worker scan.
- A tag-gated release build that rejects Python/npm version mismatches and
  validates wheel contents before artifact publication.

### Changed
- GitHub Action arguments are passed through environment variables and Bash
  arrays instead of interpolated shell fragments.
- GitHub Action scans run through the installed Python entry point.
- CI now validates package installation, dependency consistency, critical lint
  rules, wheel construction, and Action syntax.
- CI third-party Actions are pinned to immutable commit SHAs.
- The approval gate scans PR code with a separately checked-out, immutable Aegis
  scanner and protected policy revision.
- FastAPI, Starlette, Uvicorn, and the httpx2 test client were upgraded to
  Python 3.14-compatible releases.
- Container images use immutable base-image digests, non-root processes,
  read-only root filesystems, dropped capabilities, persistent data volumes,
  and liveness/readiness probes.
- Docker Compose now runs a dedicated RQ worker and keeps Redis off the host
  network.
- Database initialization now preserves existing WAF rules across restarts.
- Production Compose deployments require an explicit strong admin token and
  host/CORS allowlists.

### Fixed
- Updated the custom Semgrep SQL-injection rule to the current schema and
  disabled telemetry/version checks for deterministic offline execution.
- Added CI validation for custom Semgrep rules and an audited suppression for
  the trusted scanner's immutable Git SHA.
- Test runs now restore checked-in example reports instead of dirtying the
  working tree with regenerated timestamps and assets.
- Removed machine-local absolute symlinks that prevented GitHub from staging
  the published composite Action.
- Removed the accidentally tracked local `scanner-venv/` environment, including
  platform-specific binaries and thousands of vendored dependency files.
- Separated the immutable application source root from `AEGIS_DATA_DIR` so
  persistent container data no longer redirects worker scans away from source.
- Removed unconditional third-party browser analytics from the dashboard and
  generated reports.
- Updated dashboard template rendering for the current Starlette API.
- Enabled HTML autoescaping for untrusted scanner findings in generated reports.
- Restricted the npm package manifest so local databases, bytecode, and scan
  artifacts cannot be published.

## [2.1.0] - 2026-06-26

### Added
- `aegis.yml` project config discovery for scan defaults, SARIF output, and path excludes.
- Audited config suppressions through `suppressions-report.json`.
- SARIF report generation via `aegis scan --sarif`.
- Optional `AEGIS_ADMIN_TOKEN` protection for state-changing web console routes.
- CI full-suite execution with per-test timeouts.
- Docker Compose stack for dashboard + Redis.
- Release checklist documentation.

### Changed
- Moved intentionally vulnerable training endpoints into `app/demo_lab.py`.
- Disabled the demo lab by default; enable it explicitly with `AEGIS_ENABLE_DEMO_LAB=true`.
- Restricted default CORS origins to localhost instead of `*`.
- Updated Docker image defaults to use port 5001 and a non-root user.
- GitHub Actions uploads Aegis SARIF when generated.

### Fixed
- Product self-scans can exclude intentional lab targets through `aegis.yml`.

## [1.1.0] - 2026-05-19

### Added
- **Interactive Cyber Range**: Introduced the "Threat Lab" terminal for real-time attack simulation (SQLi, RCE, Path Traversal).
- **Simulated WAF (Defense Shields)**: Implemented middleware-level Web Application Firewall logic with a toggleable dashboard control.
- **Interactive Scanning**: Added the ability to trigger a full DevSecOps scan directly from the web UI with automated redirection.
- **Enhanced Security Dashboard**: Completely redesigned the scan report with metric cards for severity, consolidated tool results, and modern dashboard aesthetics.
- **Team Implementation Guide**: Added a dedicated section to `README.md` explaining how to adopt Aegis patterns in professional environments.

### Changed
- **UI/UX Overhaul**: Redesigned the landing page into a professional "Security Control Center."
- **Flask Integration**: Added `/report`, `/run-scan`, and `/toggle-waf` routes to support new interactive features.
- **Report Template**: Optimized `report_template.html` for better readability and visual impact.

### Fixed
- Updated local run instructions to use the correct port (5001) and virtual environment activation steps.

---
## [1.0.0] - 2026-05-18

### Added
- Initial release of Aegis DevSecOps demo.
- Integration with Bandit (SAST), Safety (SCA), and Trivy (Container).
- Automated GitHub Actions pipeline.
- Policy Engine for unified security gatekeeping.
- Vulnerable Flask application with intentional security flaws.
