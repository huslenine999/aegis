# Scanner simplification and CodeQL integration plan

Date: 2026-09-22. Status: proposed implementation plan; no scanner changes applied.

## Outcome and scope

Remove Checkov, Safety, ClamAV (including its regex fallback), Trivy, and the custom DAST probes from active scanning. Add CodeQL as the deeper source-analysis engine. Keep Semgrep, Ruff security rules, OSV, and detect-secrets. Retain YARA as an optional signature-analysis capability outside the default scan profiles.

The product becomes a source, dependency, and secret security workbench. Removing Checkov and Trivy relinquishes their infrastructure and container-image checks; removing DAST relinquishes runtime probing. CodeQL does not replace those categories. Update coverage claims accordingly. Signature matches and static paths remain suspected issues, not confirmed malware or proven exploits.

| Profile | Proposed detectors | Contract |
| --- | --- | --- |
| Quick | Ruff security rules where Python is present; detect-secrets | Fast feedback, explicitly limited coverage. |
| Standard | Quick plus Semgrep and OSV where applicable | Default repository scan. Initially preserve the existing Semgrep language scope. |
| Deep | Standard plus CodeQL for Python and JavaScript/TypeScript | CodeQL is required for supported source languages; unavailable or incomplete analysis is an error. |
| Optional signature analysis | YARA, explicitly enabled | Report the actual engine/rules and scope; no antivirus claim. |

Unsupported languages and absent dependency manifests are visible coverage limitations. A Deep scan with no supported CodeQL language is not a successful CodeQL scan. Do not advertise whole-repository coverage when other source languages were omitted. Single-file scans retain an explicit limited scope; do not infer a complete project from one uploaded file.

## Phase 1 — Freeze the coverage and compatibility contract

1. Record the new profile contract in shared code used by the CLI and queued worker. Version that contract in run metadata: the old and new `deep` presets have different meanings.
2. Capture baseline fixtures for existing findings, stored results, reports, signed manifests, and evidence ZIPs before removing adapters.
3. Preserve historical results and artifacts byte-for-byte. Old scanner findings remain open unless explicitly triaged or reassessed with equivalent detector coverage. A removed scanner is not evidence of remediation.
4. Keep only the legacy decoding needed to display old records; remove retired detectors from new-run policy aggregation. Preserve old signed manifests and their verification format.
5. Record changed detector coverage in the audit trail. New reports explain that historical findings from retired detectors were not reassessed. A new scan's policy decision must not imply that these older findings were fixed.

Primary files: `app/scan_engine.py`, `app/scan_status.py`, `app/findings.py`, `policy_engine.py`, `app/projects.py`.

Acceptance: a new scan cannot auto-resolve any retired-detector finding, reinterpret an old Deep scan as the new profile, or change the validity of an existing evidence bundle.

## Phase 2 — Remove the five scanners end to end

1. Delete their invocation paths from both `app/worker.py` and `app/cli_runner.py`; remove unused helpers in `app/scanners.py`, `app/iac_scanner.py`, and `app/sandbox.py` after checking callers.
2. Remove their active policy analyzers, status rows, default report placeholders, timing stages, and new-run artifact registrations. Do not emit empty legacy reports that look like clean results.
3. Remove Checkov and Safety dependencies and regenerate `uv.lock`. Remove the Checkov-specific CycloneDX pin only if no remaining consumer requires it; preserve Aegis SBOM exports.
4. Remove retired scanner environment/config options from Compose, example configuration, doctor checks, CLI help, and CI. Give old scanner-specific options an explicit migration error or deprecation message, not silent reinterpretation.
5. Remove application build/start/probe orchestration used only by Trivy/DAST. Keep Docker deployment support and any independently used demo features. A later isolated CodeQL job must not execute a target Dockerfile.
6. Update active UI descriptions and documentation. Historical review documents should retain dated observations with a follow-up note rather than rewriting history.

Additional files: `app/cli.py`, `app/cli_reports.py`, `app/reporting.py`, `app/routes/demo_scan_routes.py`, `Dockerfile`, `docker-compose.yml`, `pyproject.toml`, `.env.production.example`, `aegis.yml`, `.github/workflows/`, `app/templates/projects.html`, `app/templates/report_template.html`, `README.md`, relevant existing docs. Update demo payloads too so they do not advertise retired capabilities.

Acceptance: neither CLI nor worker invokes a retired scanner; new exports contain no fabricated retired-scanner results; historical evidence still opens and verifies.

## Phase 3 — Establish the CodeQL runtime boundary

Use one shared adapter, proposed as `app/codeql_scanner.py`, called by the existing CLI and worker. Reuse bounded subprocess/output utilities and run-status reporting. Do not introduce a general scanner plugin framework.

1. Provision a pinned CodeQL CLI and pinned query packs separately from published Aegis images. Verify platform compatibility on the actual development and worker machines. Extend doctor/preflight to check executable, packs, architecture, and available resources.
2. Start with Python and JavaScript/TypeScript, explicit language selection, and no application build or dependency-install commands. Use a trusted default security query suite; evaluate `security-extended` separately before adoption. GitHub documents database creation options in the [CLI reference](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-create).
3. Build the database from the existing immutable source snapshot; analyze it into a bounded SARIF artifact. Supply Aegis-owned query/configuration files outside the target. Target repository config, exclusions, suppressions, and custom query packs must not silently change gate policy.
4. Execute in a disposable unprivileged runtime: read-only source, dedicated writable output/temp space, no application DB/Redis credentials, signing keys, GitHub credentials, host Docker socket, or cross-run mounts. Disable network during extraction/analysis after provisioning packs. Test OS-enforced restrictions rather than relying only on stripped environment variables.
5. Apply CPU, memory, process, disk/output, and wall-clock limits. CodeQL thread/RAM hints supplement runtime limits. Cancel/timeout must terminate the full job and clean its database. Initially permit one CodeQL job per provisioned runtime; choose actual budgets from measurements.
6. Use a fresh database per run initially. Avoid shared database caching until source, configuration, and query identity can be safely bound to a cache entry.

The standard [CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) include research/open-source permissions subject to restrictions, and restrict redistribution and hosted availability. Public visibility alone is not a blanket entitlement. This plan targets an operator-provisioned capstone installation; published binaries/images and a hosted multi-user CodeQL offering require appropriate rights before rollout. Do not assume a private-repository subscription grants redistribution rights.

Acceptance: a real local fixture produces SARIF inside the intended runtime; credential access, cross-run reads, and prohibited egress fail; missing CodeQL or a missing pack causes a clear Deep-scan error, never a fallback pass.

## Phase 4 — Integrate findings, policy, and evidence

1. Parse all results from every expected SARIF run, including rules resolved by index and applicable rule metadata. Never use a report's display sample as the complete finding set.
2. Normalize rule ID, severity, CWE tags, relative location, message, fingerprints, and source-to-sink paths when present. Retain the original SARIF; CodeQL can produce SARIF locally through its [CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli).
3. Treat SARIF and repository-derived messages/paths as untrusted input. Validate schema/version, types and size limits; reject traversal/out-of-root paths and never fetch external SARIF references. Escape browser output.
4. Define severity mapping explicitly using available security-severity metadata, with a documented fallback for absent metadata. Finding severity and analysis completeness are separate decisions.
5. Check extraction/analysis completion and expected language coverage. Exit code alone or `results: []` does not establish success. Missing, malformed, truncated, or incomplete required output yields `ERROR`.
6. Give CodeQL its own detector identity. Use a documented stable fingerprint strategy and integrate baseline gating and approved suppressions. CodeQL cannot automatically resolve a Semgrep finding. Preserve separate detector observations when grouping duplicate issues for display.
7. Auto-resolution requires completed coverage for the same language and comparable source scope, profile version, exclusions, and query coverage. If equivalence cannot be established, leave findings open. Protect state from out-of-order concurrent completions and duplicate finalization.
8. Record commit/snapshot identity, CLI and query versions, configuration digest, language coverage, execution status, timings, and artifact hashes in signed evidence. Register `codeql.sarif` and a normalized `codeql-report.json` containing coverage metadata for authenticated downloads and ZIP exports. If per-language raw files are needed, name and register each explicitly. Preserve the existing HTML, Markdown, aggregate SARIF, SBOM, source descriptor, manifest, and retained-detector evidence exports.

Primary files: `policy_engine.py`, `app/findings.py`, `app/cli_reports.py`, `app/reporting.py`, `app/worker.py`, existing evidence/artifact modules.

Acceptance: worker and CLI reach the same policy decision for the same input; every normalized finding is represented in durable evidence; incomplete analysis cannot pass or resolve findings.

## Phase 5 — Finish the browser experience

1. Update profile descriptions and display actual stages: source preparation, CodeQL database creation, query analysis, report finalization. Show elapsed time and a heartbeat; avoid invented percentage precision during a long stage.
2. Display CodeQL findings and available data-flow paths directly in the authenticated browser report. Keep report content visible under its restrictive CSP without depending on report JavaScript.
3. Preserve optional evidence downloads. Enable them only when the corresponding artifacts exist, and show useful failure reasons otherwise.
4. Distinguish scan execution failure, a completed scan blocked by findings, and intentionally unassessed coverage. Retry and first-run paths both refresh until terminal status.

Acceptance: browser flows cover a successful scan, a blocked scan, timeout/missing runtime, retry, visible report content, and a valid evidence ZIP. No HTML download is necessary to read the report.

## Phase 6 — Validate and prepare the defense

Write regression tests before each implementation phase. Retain unrelated security tests; replace obsolete scanner-execution tests with migration/compatibility tests where appropriate.

| Test group | Required evidence |
| --- | --- |
| Removal and compatibility | No retired invocations; old reports/signatures survive; existing findings remain open. |
| SARIF and policy | Multiple languages/runs; rule indexes; missing severity; more findings than display limits; malformed/oversized input; unsupported coverage; failures never pass. |
| Finding lifecycle | Deep-to-Standard transition; changed queries/exclusions; one failed language; duplicate completion; reversed completion order; baseline consistency. |
| Trust boundaries | Hostile config and paths, output injection, attempted credential/cross-run reads, network attempts, resource exhaustion, process cleanup. |
| Integration and browser | Real CLI and queued Deep scan on controlled fixtures; report visibility; progress/retry; artifact authorization; ZIP and manifest verification. |
| Detection benchmark | Labeled vulnerable/safe fixture pairs; CodeQL versus Semgrep; unique true positives, false positives, misses, runtime, peak memory, and failure rate. |

Use SQL injection, command injection, path traversal, and cross-function taint examples with safe counterparts supported by the chosen queries/frameworks. Keep evaluation fixtures separate from default production scan scope through trusted, documented exclusions. Retain an untouched evaluation subset when tuning rules. Report precision/recall and actual misses; do not promise an accuracy percentage in advance.

Release gates: the full applicable regression suite passes; changed code has at least 80% measured coverage with exclusions disclosed; live CodeQL and browser checks pass; historical evidence remains valid; adversarial failure cases cannot produce `ALLOWED`; benchmark results and coverage losses are documented. The capstone review's earlier approximately 70% project-wide coverage remains a separate baseline, not something this plan claims has improved.

Update `docs/CAPSTONE_REVIEW.md`, `docs/THREAT_MODEL.md`, and `docs/ARCHITECTURE.md` with observed results and remaining limitations. Be ready to explain why these scanners were removed, which categories are no longer covered, what CodeQL misses, what prevents untrusted code from changing analysis, and what Aegis contributes beyond invoking scanners.

## Delivery order and rollback

Implement as reviewable increments: compatibility contract/tests → retired-scanner removal → isolated CodeQL adapter → policy/evidence integration → browser updates → measured evaluation. Do not label Deep available until its runtime and tests pass. Continue using Standard while CodeQL is provisioned.

Record the prior application/image version before rollout; drain or explicitly cancel old queued/running jobs before changing worker contracts. Retain previous artifacts and avoid destructive database changes. Roll back the application version if needed without modifying evidence. Unknown/new result versions must produce an explicit unsupported state rather than a clean policy decision.

This planning change installs no tools, removes no scanners, changes no secrets, and starts no scans.
