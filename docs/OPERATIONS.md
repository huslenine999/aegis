# Operations and recovery

## Administration and notifications

The `/admin` console provides user and role management, one-time API token
issuance/revocation, PostgreSQL/Redis/worker/GitHub/SMTP diagnostics, durable audit
events, and recent HTTP request latency. Project administrators configure Slack,
Microsoft Teams, signed generic webhooks, and SMTP email from `/projects`. Supported
events are `completed`, `blocked`, `failed`, and `cancelled`; destinations are
encrypted in PostgreSQL.

SMTP uses `AEGIS_SMTP_HOST`, `AEGIS_SMTP_PORT`, `AEGIS_SMTP_USERNAME`,
`AEGIS_SMTP_PASSWORD`, and `AEGIS_SMTP_FROM`.

## Service objectives

Choose and record an RPO and RTO before a pilot handles production repositories. A
reasonable starting point is a 15-minute database RPO and a four-hour RTO. Treat the
PostgreSQL database, artifact bucket, encryption/signing keys, and deployment
configuration as one recovery set.

## Backup and restore

- PostgreSQL: use encrypted, automated snapshots plus the plain SQL dump created
  by `aegis backup` (`pg_dump --format=plain --clean --if-exists`). Restore it
  with `psql` after quiescing dashboard, worker, and notifier services, start one
  dashboard replica so migrations run, and verify `/ready` before workers are
  enabled.
- S3-compatible artifacts: enable bucket versioning, private access, KMS encryption,
  and object lock with a retention period that matches policy. Replicate to a separate
  account or failure domain.
- Local evaluation installs: run
  `python scripts/verify_recovery.py /path/to/aegis.db`. This uses SQLite's online
  backup API, restores into a temporary location, checks database integrity, and
  reports recovered object counts.
- Keys: escrow the evidence-signing, credential-encryption, audit-HMAC, session, and
  token-pepper secrets in a managed secret store. Do not store them in the database
  backup or artifact bucket.

Redis job events are bounded transient state and are intentionally excluded from
backups. Generated local run artifacts are pruned after
`AEGIS_ARTIFACT_RETENTION_DAYS` (30 days by default); database summaries remain.
Coordinate bucket lifecycle, object lock, and backup retention with evidence policy.

Run a restore drill at least quarterly and after schema or storage changes. Record
elapsed restore time, the recovered schema version, sample artifact hash checks, and
the audit-chain verification result.

## Deployment sequence

1. Back up the database and confirm artifact replication health.
2. Deploy the dashboard first and wait for `/ready` so migrations complete.
3. Deploy standard workers, isolated deep-scan workers, then notifier workers.
4. Run `scripts/pilot_readiness.py` and the 30-case security benchmark.
5. Start a canary scan and verify its policy version, signed manifest, durable
   findings, notification delivery, and artifact download.

## Release-gate evidence and operator hold points

Before approving a tag, retain the SQLite and PostgreSQL schema versions,
migration rerun result, coverage output, lock check, dependency audit, E2E
result, Compose recovery evidence, and fresh Codex Security scan ID together.
The release gate is a hold point when any of these is missing or degraded.

In particular, an operator must confirm that Migrations 20 and 21 are applied;
Migration 20 has revoked or reissued legacy unsalted API-token rows; GitHub
OAuth state is bound to the initiating browser session; scanner file-writing
outputs use the monitored temporary sink; notification destinations reject
every non-global address; and the Semgrep dependency tree contains MCP 1.29.0
or newer. A pepper rotation alone is not evidence that legacy unsalted token
rows are safe.

Rollback application code only after checking whether the previous version supports
the current schema. Database migrations are forward-only; restore a coordinated
pre-deployment snapshot when a schema rollback is unavoidable.

## Alerts

Alert on readiness failure, no workers, no isolated worker while deep scans are
enabled, queue age, scanner operational errors, notification dead letters, migration
failure, database saturation, artifact integrity failure, and audit-chain failure.

Track dashboard readiness, worker completion/failure counts, queue age, HTTP 5xx and
p95 latency, notification failures, artifact integrity failures, audit-chain
failures, and PostgreSQL/Redis capacity. The `/metrics` endpoint exposes
`aegis_scan_queue_age_seconds`, `aegis_worker_failures_total`,
`aegis_notification_failures_total`, `aegis_artifact_integrity_failures_total`,
and `aegis_audit_integrity_failures_total`. Use
`deploy/prometheus.yml.example` and import `deploy/grafana-dashboard.json` for the
included baseline panels.

## Scanner failure handling

Every scan writes `scan-manifest.json` with per-tool status. A failed or required-but-
skipped tool means the evidence is incomplete. CI and release gates should use
`--strict`, which exits with code 2 for operational failures. Treat every non-empty
`operational_failures` field as degraded evidence, never as a clean approval.

## Incident response

If scanner infrastructure may be compromised:

1. Stop workers to prevent additional untrusted-code processing.
2. Rotate GitHub, notification, API, signing, and worker credentials.
3. Preserve PostgreSQL, immutable artifacts, audit events, and service/container logs.
4. Rebuild workers from a reviewed image digest before re-enabling queues.
5. Re-run release-blocking scans in strict mode and compare durable findings.
