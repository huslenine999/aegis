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
export AEGIS_IMAGE=ghcr.io/huslenine999/aegis:v2.3.0
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
- Keep `AEGIS_ARTIFACT_BACKEND=local`. This release rejects any other value so
  an environment variable cannot imply an object-storage control that has not
  been implemented and reviewed.
- Keep `AEGIS_MULTI_TENANT=false`. Until an external object-storage backend is
  available, deploy one isolated Aegis stack per customer tenant.
- Generate and protect a unique 32-byte Ed25519 seed for
  `AEGIS_EVIDENCE_SIGNING_KEY`. Keep the private seed on workers only and pin
  the public key used by `aegis verify-evidence` in the customer's trust
  documentation.
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
scan, worker logs, and notification delivery.

Rollback is image-first: redeploy the previous image tag and restore the
pre-upgrade database only if a migration or data change prevents the previous
image from starting. Keep at least one known-good image and one pre-upgrade
database backup until the new release has completed a full scan cycle.

Back up before upgrades:

```bash
aegis backup --output backups/pre-upgrade.zip
aegis upgrade
```

Restore requires explicit confirmation:

```bash
aegis restore backups/pre-upgrade.zip --yes
```

## Key rotation

- `AEGIS_ADMIN_TOKEN`: rotate by updating `.env`, restarting dashboard/worker,
  and replacing CI or automation callers.
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
