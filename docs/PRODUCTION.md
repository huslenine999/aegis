# Production deployment

1. Point the public DNS record at the deployment host.
2. Copy `.env.production.example` to `.env`.
3. Replace every placeholder with a unique secret.
4. Start the stack:

```bash
docker compose up --build -d
```

Caddy obtains TLS certificates and is the only publicly exposed service.
PostgreSQL and Redis remain on the internal Compose network.
The dashboard applies versioned database migrations at startup and records
completed versions in `schema_migrations`.

For a published release image:

```bash
export AEGIS_IMAGE=ghcr.io/huslenine999/aegis:v2.4.0
docker compose pull dashboard worker
docker compose up -d --no-build
```

Production readiness checks:

```bash
curl https://aegis.example.com/health
curl https://aegis.example.com/ready
curl -H "Authorization: Bearer $AEGIS_METRICS_TOKEN" \
  https://aegis.example.com/metrics
```

## Production hardening baseline

- Keep Caddy as the only public listener. Do not publish PostgreSQL, Redis, the
  dashboard container port, or the worker container port directly.
- Set `AEGIS_ALLOWED_HOSTS` and `AEGIS_CORS_ORIGINS` to exact production hosts
  and origins. Wildcards are rejected in production mode.
- Keep `AEGIS_REQUIRE_AUTH=true`, `AEGIS_REQUIRE_REDIS=true`, and
  `AEGIS_REQUIRE_WORKER=true` in production. Keep
  `AEGIS_REQUIRE_NOTIFIER=true`; scanner workers enqueue outbound delivery to
  the separate `notifier` service and do not receive SMTP credentials.
- Keep `AEGIS_SECURITY_PROFILE=standard`. The `bank` profile is deliberately
  fail-closed until external OIDC, KMS, scanner, immutable storage, and SIEM
  adapters are implemented; this prevents accidental bank-grade claims.
- Generate an independent `AEGIS_AUDIT_HMAC_KEY` of at least 32 random
  characters. Monitor structured `security_audit` log records and regularly
  call `/api/admin/audit/verify` from an authorized control-plane check.
- Set `AEGIS_RECENT_AUTH_SECONDS` to the approved step-up window (600 seconds
  by default). Sensitive operations require a fresh browser authentication or
  an admin-scoped machine token.
- Store `.env` outside source control and restrict it to the deployment user.
  Rotate all generated values before reusing an environment image or disk.
- Prefer setup-token-only initialization and leave
  `AEGIS_BOOTSTRAP_ADMIN_PASSWORD` empty. If a bootstrap password is used,
  remove it immediately after setup; completed setup never recreates that
  identity on restart.
- Treat scanner errors as release-blocking for CI gates by running
  `aegis scan --strict`. Non-strict mode is useful for local exploration, but
  scan summaries still include `operational_failures` when a scanner fails.
- Keep `AEGIS_ENABLE_DEMO_LAB=false`. The `secure` and `vulnerable` built-in
  targets are compatibility fixtures for demonstrations and tests, not
  production application routes.
- Set `AEGIS_ARTIFACT_RETENTION_DAYS` to the approved evidence-retention
  period. Run downloads remain authorized by project membership and include
  SHA-256 integrity metadata.
- Set `AEGIS_ARTIFACT_BACKEND=local` for filesystem evidence or `s3` for the
  reviewed S3-compatible backend. When using S3, set `AEGIS_S3_BUCKET`,
  `AEGIS_S3_REGION` when required by the provider, and use the deployment
  identity or environment credentials with write/read access only to the
  configured prefix. Enable bucket versioning, private access, KMS encryption,
  and object lock when the evidence policy requires them.
- Keep `AEGIS_MULTI_TENANT=false`. S3 provides durable artifact storage, but the
  current production topology remains one isolated Aegis stack per customer
  tenant.
- Generate and protect a unique 32-byte Ed25519 seed for
  `AEGIS_EVIDENCE_SIGNING_KEY`. Keep the private seed on workers only and pin
  the public key used by `aegis verify-evidence` in the customer's trust
  documentation.
- When enabling OIDC, keep discovery, token, authorization, and JWKS endpoints
  on the issuer origin where possible. If the reviewed provider uses separate
  origins, list only their exact HTTPS origins in
  `AEGIS_OIDC_ALLOWED_ORIGINS` (comma-separated); Aegis rejects private,
  cleartext, redirecting, and unapproved endpoint URLs.
- Configure `AEGIS_GITHUB_WEBHOOK_SECRET` with at least 32 random characters.
  Set `AEGIS_PUBLIC_URL`, `AEGIS_GITHUB_APP_ID`, and the base64-encoded
  `AEGIS_GITHUB_APP_PRIVATE_KEY_B64` to enable exact-head pull-request checks.
  Follow `docs/GITHUB.md`, test known safe and vulnerable pull requests, and
  rotate the App key through the deployment secret manager.
- Review `suppressions-report.json` in every release. Any exception without an
  approver, ticket, meaningful reason, or future expiry remains inactive and
  therefore cannot produce a clean result by hiding its finding.
- OSV is the default dependency advisory source. Safety CLI is optional because
  commercial use requires an appropriate Safety plan: enable it only with
  `AEGIS_ENABLE_SAFETY=true` and a licensed `SAFETY_API_KEY` on the worker.
- Keep the resource budgets explicit and size them against the largest approved
  scan: `AEGIS_MAX_SUBPROCESS_OUTPUT_BYTES` bounds scanner pipes,
  `AEGIS_MAX_SCANNER_REPORT_BYTES` and `AEGIS_MAX_SCANNER_FINDINGS` bound
  scanner-produced reports and in-process finding lists,
  `AEGIS_MAX_PARSER_INPUT_BYTES` bounds JSON and manifest parsing,
  `AEGIS_MAX_RESPONSE_BYTES` bounds streamed downloads,
  `AEGIS_MAX_ZIP_ENTRIES` and `AEGIS_MAX_ZIP_UNCOMPRESSED_BYTES` bound report
  bundles, and `AEGIS_STREAM_CHUNK_BYTES` controls bounded read chunks. Do not
  remove these limits to accommodate a single unusually large repository; raise
  them deliberately and review the resulting disk, memory, and bandwidth
  exposure.
- Before a release, verify Migrations 20 and 21 are applied and Migration 20
  has revoked/reissued every row from a legacy unsalted-hash format.
  `AEGIS_TOKEN_PEPPER` rotation does not replace that migration. Built-in
  scanner reports use a parent-owned bounded stdout pipe and atomic promotion;
  keep that transport when adding scanners rather than allowing a child to
  write directly into the report path. Verify GitHub OAuth completion is bound
  to the initiating session and that project WebSocket streams enforce tenant
  role checks.
- Notification webhook validation rejects every resolved address for which
  `ipaddress.ip_address(address).is_global` is false. HTTPS, TLS hostname
  validation, DNS pinning, and redirect denial remain required alongside the
  global-address check.

## Scanner runtime

Quick and Standard scans run entirely in the worker image; the production image
includes the Standard Semgrep dependency. Deep scans additionally require a
reviewed Docker endpoint and Trivy executable available to the worker. A Deep
scan fails with an operational error when either dependency is missing.

`AEGIS_SCAN_JOB_TIMEOUT_SECONDS` controls the total RQ job lifetime and defaults
to one hour. `AEGIS_SANDBOX_COMMAND_TIMEOUT_SECONDS` bounds individual Docker
build, image-scan, start, and cleanup operations. `AEGIS_SCANNER_TIMEOUT_SECONDS`
bounds streamed scanner subprocesses. Size these values for the largest approved
repository; the total job timeout must exceed the combined scanner deadlines.

Sandbox dependency installation rejects pip directives, local paths, VCS/URL
requirements, and source distributions. Projects that require those forms fail
closed in Deep mode and should be scanned only after their runtime is packaged as
reviewed binary wheels in an approved package index.

Do not mount the deployment host's Docker socket into the dashboard. Provision
a separate worker host or remote TLS-protected Docker runtime with no production
credentials, a restricted egress policy, disposable storage, and enforced CPU,
memory, process, and execution-time limits.

## Trust boundaries

Aegis executes local scanner binaries and, for deep scans, may build and run a
Docker sandbox from scanned source. Run the worker on infrastructure intended
for untrusted code execution. Do not mount host secrets, Docker credentials, or
production application data into the worker container.

GitHub OAuth tokens, notification credentials, and webhook secrets are encrypted
before persistence with `AEGIS_ENCRYPTION_KEY`. Losing this key makes those
stored integrations unreadable; leaking it requires immediate token rotation.

## Upgrades and rollback

Before upgrading:

1. Export a PostgreSQL dump and archive generated reports.
2. Record the current image tag, `.env` checksum, and database migration version.
3. Smoke-test the new image against a staging restore.

After upgrading, verify `/ready`, `/metrics`, login, project listing, a quick
scan, worker logs, notification delivery, and the worker/notifier health status
reported by `docker compose ps`.

Rollback is image-first: redeploy the previous image tag and restore the
pre-upgrade database only if a migration or data change prevents the previous
image from starting. Keep at least one known-good image and one pre-upgrade
database backup until the new release has completed a full scan cycle.

Back up before upgrades. `aegis backup` stores a plain SQL PostgreSQL dump in
`database.sql` together with the generated scan artifacts; restore replays that
dump with `psql` after stopping the application services:

```bash
aegis backup --output backups/pre-upgrade.zip
aegis upgrade
```

Restore requires explicit confirmation:

```bash
aegis restore backups/pre-upgrade.zip --yes
```

The recovery path is intentionally plain SQL rather than PostgreSQL's custom
format. Run the Compose recovery rehearsal from a Docker-capable control host
at least quarterly and after schema or storage changes:

```bash
python scripts/pilot_readiness.py --docker-smoke \
  --output .aegis/pilot-rehearsal.json
```

## Key rotation

- API tokens: revoke and reissue affected rows through the operations console
  after a planned `AEGIS_TOKEN_PEPPER` rotation or suspected disclosure.
- `AEGIS_SESSION_SECRET`: rotation invalidates browser sessions. Restart the
  dashboard after updating it.
- `AEGIS_TOKEN_PEPPER`: rotation invalidates API tokens and MFA recovery codes.
  Reissue them after a planned rotation and treat unexpected disclosure as a
  credential incident.
- `AEGIS_AUDIT_HMAC_KEY`: the current schema supports one verification key.
  Do not rotate it in place: first export and preserve the old chain and key,
  then use a reviewed migration that explicitly starts and records a new trust
  epoch.
- `AEGIS_METRICS_TOKEN`: rotate Prometheus scrape secrets and restart Prometheus
  after the dashboard is restarted.
- `AEGIS_ENCRYPTION_KEY`: create new GitHub/notification connections after
  rotation unless you have migrated existing encrypted values offline.

For GitHub offboarding, disconnect each affected OAuth account, disable the
affected user, and remove or suspend the GitHub App installation. These actions
revoke stored OAuth capabilities, active installation mappings, and queued work
that has not yet passed its worker authorization recheck.

For complete offboarding, also revoke every API token for the user, verify that
no legacy token-hash row remains active, delete or expire tenant artifacts under
the approved retention policy, and preserve the signed evidence and audit-chain
records required by the incident and deletion runbooks.
