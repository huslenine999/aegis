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
export AEGIS_IMAGE=ghcr.io/huslenine999/aegis:v2.2.0
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
  `AEGIS_REQUIRE_WORKER=true` in production.
- Store `.env` outside source control and restrict it to the deployment user.
  Rotate all generated values before reusing an environment image or disk.
- Treat scanner errors as release-blocking for CI gates by running
  `aegis scan --strict`. Non-strict mode is useful for local exploration, but
  scan summaries still include `operational_failures` when a scanner fails.
- Keep `AEGIS_ENABLE_DEMO_LAB=false`. The `secure` and `vulnerable` built-in
  targets are compatibility fixtures for demonstrations and tests, not
  production application routes.

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
- `AEGIS_METRICS_TOKEN`: rotate Prometheus scrape secrets and restart Prometheus
  after the dashboard is restarted.
- `AEGIS_ENCRYPTION_KEY`: create new GitHub/notification connections after
  rotation unless you have migrated existing encrypted values offline.
