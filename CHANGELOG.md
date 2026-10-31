# Changelog

All notable changes to the Aegis project will be documented in this file.

## [Unreleased]

### Added

- Suppressions can name one finding with `fingerprint:` instead of a whole
  file and rule. The fingerprint hashes the tool, rule, repository-relative
  path and flagged line text, so it survives line moves but not edits or
  copies of the line. Scanner reports carry it as `aegis_occurrence`; the
  `report.md` suppression example and SARIF `partialFingerprints` show it.
- `aegis scan --codeql-sarif FILE` and the Action's `codeql-sarif` input gate
  on SARIF from a team's own CodeQL run (for example GitHub code scanning)
  instead of running CodeQL. Every detected Python and JavaScript/TypeScript
  language must be covered, or the scan is an operational error.
- `aegis scan` lists blocking findings by file with line, severity, rule and
  message (up to 20; the full list stays in the report). Progress lines use
  one style. Color follows `NO_COLOR`, `FORCE_COLOR` and whether stdout is a
  terminal (always on in GitHub Actions).

### Fixed

- `--sarif` wrote at most five findings per tool, so GitHub code scanning
  missed the rest. Every finding is now written.
- The scan banner showed `v2.0` and its box edges did not line up; the risk
  index line overflowed the box.

- Deep scans failed on every TypeScript repository: the CodeQL image had no
  Node.js, which CodeQL needs to extract TypeScript. `Dockerfile.codeql` now
  includes Node.js 22.21.1. Re-run `make codeql-setup` to rebuild and re-pin
  the image.
- `python-tainted-request` no longer treats an ORM `session` as an HTTP client
  (`session.delete(row)` in FastAPI/SQLModel apps), and `python-rce` no longer
  flags constant command strings. Both raised blocking false alarms on the
  pinned real-repository set.
- The suppression example in `report.md` used analyzer names such as
  `Ruff (SAST)` that never match a suppression, and lacked the required
  approver, ticket and expiry fields.

- JavaScript rules missed common Express/Koa code. Request input is now tracked
  in named handler functions and controller methods (class, static and object
  methods) whose parameter is named `req`, `request` or `ctx`. Reflected XSS is
  found when the HTML is built in a variable first. `unescape`, `encodeURI`,
  `escapeRegExp` and calls in general no longer count as HTML escapers, and
  `encodeURIComponent` no longer sanitizes a URL whose host it builds.
- `pipx install` failed on Python 3.14 and later: `psycopg-binary` 3.2.10 and
  `yara-python` 4.5.0 have no wheels there. psycopg is now 3.3.6, yara-python
  4.5.4 (adds Python 3.13), and `requires-python` is `>=3.11,<3.14`, so newer
  Pythons get a clear version error instead of a failed C build.

## [2.6.0] - 2026-10-28

### Added

- Evidence signing runs in a separate `signer` service; scanner workers no
  longer hold the Ed25519 key. The signer signs each in-progress run once,
  after re-hashing its artifacts and checking its source attestation, and
  records it in an append-only `evidence_signatures` ledger. Production
  workers require `AEGIS_EVIDENCE_SIGNER=remote`, and the dashboard requires a
  live signer (`AEGIS_REQUIRE_SIGNER`).
- A `github-broker` service holds the GitHub App key and encryption key.
  Workers get read-only clone tokens scoped to one in-flight run's repository
  and ask the broker to complete that run's check; production workers refuse
  both keys (`AEGIS_GITHUB_BROKER=remote`, `AEGIS_REQUIRE_GITHUB_BROKER`).
- Least-privilege PostgreSQL logins for the worker, signer, broker, and
  notifier (`AEGIS_DB_*_PASSWORD`), created by the dashboard after migrations.
  Production services refuse superuser or schema-owning logins.
- Audit-chain checkpoints (`GET /api/admin/audit/checkpoint`,
  `POST /api/admin/audit/verify`) that detect deleted recent events and
  restored older databases.
- `aegis backup` writes a verified evidence inventory; `aegis restore`
  re-verifies every signed run before restoring and refuses on failure
  (`--public-key`, `--allow-evidence-failures`).
- Property-based fuzz tests for dependency manifests, advisory scoring, signed
  evidence, and BAC bundle admission (`tests/test_fuzz_inputs.py`; deeper runs
  with `AEGIS_FUZZ_EXAMPLES`), and a monkey test that sends random requests to
  every route as anonymous, viewer, operator, admin, and another tenant's admin
  (`tests/test_api_monkey.py`; `AEGIS_MONKEY_REQUESTS`, optionally on
  PostgreSQL). 30,000+ monkey requests on SQLite and PostgreSQL found no crash,
  server error, or access-boundary failure.
- Held-out CodeQL benchmark results in `benchmarks/results/`, and
  `--codeql-cli` / `--with-semgrep` options for `scripts/run_codeql_benchmark.py`.

### Security

- Test folders no longer hide code. Semgrep scans `test/`, `tests/`,
  `testsuite/` and `*_test.go`, and CodeQL findings there block. A trusted-config
  suppression with a folder path (`path: tests/`) and a named approver is the only
  way to make a test root non-blocking; suppressions now also apply to CodeQL.

- Finished scan runs and their artifact records are immutable at the database
  level (migrations 24 and 25), and scan-state updates no longer touch
  finished runs.
- Scanner workers mark themselves non-dumpable so scanner subprocesses cannot
  read their environment or memory through `/proc`.
- Upgraded PyJWT 2.13.0 to 2.15.0, urllib3 2.7.0 to 2.8.0, and Werkzeug 3.1.8
  to 3.1.9 to clear open advisories, and Semgrep 1.173.0 to 1.179.0, which
  pins fixed MCP (1.29.0), Click (8.4.2), and PyJWT releases. The seven
  Semgrep-dependency suppressions that expired on 2026-10-20 are removed.

### Changed

- `aegis doctor` reports scanner versions, requires detect-secrets, and warns
  when Semgrep differs from the release Aegis is tested with.
- A dependency audit has a five-minute overall budget, and the KEV catalog
  falls back to CISA's GitHub mirror.
- Opt-in PostgreSQL integration checks (`AEGIS_TEST_POSTGRES_URL`).

### Fixed

- Aegis's own Standard self-scan passes again: a fixed SQL clause is bound as
  a parameter, a regex no longer trips the hardcoded-password check, and the
  reviewed exception follows code moved to `app/finding_queries.py`.
- `python-rce` missed `shell=True` unless it was the last argument;
  `python-sqli` ignored Flask and Django request data;
  `javascript-command-injection` missed destructured `child_process` imports.
- The npm launcher no longer builds shell commands from home-directory paths.
- The secrets scanner found nothing in any scan. detect-secrets silently skips
  files outside its working directory, and Aegis scans an immutable snapshot
  in a temporary directory, so both the CLI and the worker reported a clean
  Secrets result even for a committed AWS key. It now runs from the scan root
  (with `python -I`, so the scanned tree cannot shadow the module), and inline
  `pragma: allowlist secret` comments no longer hide findings; reviewed
  exceptions belong in the trusted config. Aegis's own repository now passes
  with real secrets coverage (`aegis.yml` excludes generated benchmark and
  Playwright output and records one reviewed public-key exception).
- A repository with a non-UTF-8 file name (possible on Linux) crashed the source
  snapshot with an encoding error instead of failing admission with a clear
  reason.
- A signed GitHub webhook whose `repository`, `installation`, or
  `pull_request` field was not an object crashed with a server error, in some
  cases after recording the delivery, so GitHub's redelivery was then refused
  as a replay. Such payloads are now parsed defensively (found by fuzzing).
- Ruff honored the scanned repository's `.ignore` files (and `.gitignore` inside
  a git work tree), so a repository could hide Python files from the SAST
  gate. Ruff now runs with `--no-respect-gitignore`.
- A scanned repository could hide code from Semgrep: `# nosemgrep` comments
  and its own `.semgrepignore` files were honored, files over 1 MB were
  skipped silently, and per-file timeouts still produced a "completed"
  Semgrep run. Aegis now ignores both, applies Semgrep's default excludes
  itself, lifts the size limit, and marks Semgrep failed on timeouts or fatal
  errors, so findings in an unanalyzed file are not reported as resolved.
- Dependency inventory (found by fuzzing): a bare requirement such as
  `requests`, and `!=` or `===` specifiers, were dropped from
  `requirements.txt` instead of failing the inventory as unpinned; `==2.*`
  wildcards and npm tags such as `latest` or `1.x` counted as exact pins; and a
  bare `pyproject.toml` dependency was "pinned" to its own name. All of these
  could produce a clean OSV result for a dependency that was never checked.
  Unrecognized requirement lines now fail the inventory.
- Advisory scoring: CVSS v2 vectors were scored with the v3 formula (almost
  always 0.0, so LOW), and advisories with only a CVSS v4 vector or no vector
  were LOW. Aegis now computes CVSS v2 correctly, uses the publisher's own
  severity (for example GitHub's) when there is no v3 vector, and treats an
  unscored advisory as MEDIUM, which blocks by default. CVSS 9.0 and above is
  CRITICAL in the gate, as it already was in tracked findings. Cached advisory
  records are rebuilt.

## [2.5.0] - 2026-10-15

### Added

- Standard scans now apply Semgrep rules to JavaScript/TypeScript, Go, and
  Java as well as Python: injection, request input reaching file paths,
  outbound URLs, or redirects, HTML sinks, unsafe deserialization, XXE,
  disabled TLS verification, hard-coded JWT secrets, and weak hashing. Every
  rule has labeled vulnerable and safe fixtures enforced by the test suite.
- Dependency findings are prioritized with the CISA Known Exploited
  Vulnerabilities catalog (raised to CRITICAL) and FIRST EPSS (raised to at
  least HIGH at a 10% or greater 30-day exploitation probability). Severity is
  never lowered, and the evidence date is recorded on each finding.
- The GitHub Action can upload SARIF to GitHub code scanning
  (`upload-sarif: true`) so findings appear on the pull-request diff. SARIF
  rules carry `security-severity` for code-scanning ranking.
- Added the Broken Access Control research workflow (`aegis bac`) with
  vulnerable/fixed lab variants, evidence bundles, and a status-only baseline.
- Added tenant-scoped finding queries with status, severity, and search filters.
- BAC research v2: the instrumented oracle (`enhanced`) is now the reference,
  and benchmarks also score two black-box methods (`differential`,
  `content-leak`) alongside `http-status-only`. The lab adds `list` (unfiltered
  collection), `export` (record leaked in a 403 body), and `rename` (write before
  the ownership check). Corpus `aegis-bac-v2` (`rules/bac-matrix-v2.json`) has 40
  cases; `case-results.csv` gains `differential_prediction` and
  `content_leak_prediction`.

### Changed

- OSV lookups use `/v1/querybatch` and fetch each distinct advisory once,
  caching advisories by their modified time.
- Semgrep findings report the bare rule ID instead of a path-prefixed ID.
- Retired Checkov, Safety, ClamAV, Trivy, and custom DAST probes from new scans;
  Deep scans now use an offline, pinned CodeQL container on a dedicated worker.
- Scan history returns compact summaries and project access uses a single
  membership query.
- Moved thesis and capstone material to `docs/research/`.
- Split `docs/research/BAC_RESEARCH.md` into the research protocol and
  `BAC_OPERATIONS.md`; retitled and reframed the thesis outline.

### Removed

- Removed the public `/welcome` landing page, `AEGIS_COMMERCIAL_CONTACT_URL`,
  and the monetization, pilot offer, and SLA template documents.

### Fixed

- The GitHub Action no longer forwards `--no-docker`, which the CLI rejects
  since the scanner migration; with the default `no-docker: true` every Action
  run ended in an operational error. The input is now deprecated and ignored.
- `scripts/run_security_benchmark.py` runs again after the same removal.
- Semgrep suppressions written with the bare rule ID now match. Raw Semgrep
  rule IDs embedded the local path to the rules file, which also exposed the
  operator's username in reports and SARIF.
- A missing Semgrep rules file now fails the scanner instead of silently
  falling back to a Python-only copy.
- Reject non-object JSON bodies, oversized identifiers, and unhashable roles
  with `400` instead of server errors.
- Kill scanner process trees on timeout or cancellation even after partial output.
- Clean up S3 artifact staging files on failed, interrupted, or over-budget downloads.
- Mark scans failed when the worker dies or the queue rejects the job, instead
  of leaving them queued.
- Stop Redis rate limiting from blocking other async work.
- Initialize a pinned Docker Buildx builder before provenance-enabled image
  publication and provide a protected recovery workflow for immutable release tags.

## [2.4.0] - 2026-07-22

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
- Added tag-gated PyPI Trusted Publishing and a wheel entry-point smoke test.

### Fixed

- Normalize common GitHub repository inputs before cloning and ensure worker
  failures transition PostgreSQL scan records out of the queued state.
- Correct scanner-only and full-workbench installation guidance.
- Route PostgreSQL bulk inserts through a database cursor so production
  artifact metadata writes use psycopg's supported `executemany` API.
- Keep Semgrep settings and log files in writable temporary storage for
  read-only worker containers.
- Discover Semgrep beside the active virtual-environment or pipx interpreter
  even when that directory is not present in the caller's `PATH`.
- Exclude the generated `.env.aegis` workbench secrets file from repository
  self-scans and document the full scanner extra for Standard scans.

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
