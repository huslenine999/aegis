# Changelog

All notable changes to the Aegis project will be documented in this file.

## [Unreleased]

### Added
- Strict CLI mode with a distinct operational-error exit code.
- Atomic JSON report writes and an auditable `scan-manifest.json`.
- Stable GitHub Action `decision`, `summary-json`, and `exit-code` outputs.
- Composite Action contract and Bash syntax tests.
- Scheduled runner-level verification of the published GitHub Action.
- Dependabot tracking for pinned GitHub Action revisions.
- CODEOWNERS coverage for security-sensitive workflow, policy, and package files.

### Changed
- GitHub Action arguments are passed through environment variables and Bash
  arrays instead of interpolated shell fragments.
- GitHub Action scans run through the installed Python entry point.
- CI now validates package installation, dependency consistency, critical lint
  rules, wheel construction, and Action syntax.
- CI third-party Actions are pinned to immutable commit SHAs.
- The approval gate scans PR code with a separately checked-out, immutable Aegis
  scanner and protected policy revision.

### Fixed
- Removed machine-local absolute symlinks that prevented GitHub from staging
  the published composite Action.
- Removed the accidentally tracked local `scanner-venv/` environment, including
  platform-specific binaries and thousands of vendored dependency files.

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
