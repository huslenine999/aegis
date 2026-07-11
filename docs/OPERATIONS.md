# Operations guide

## Administration

The `/admin` console provides:

- user creation and role assignment;
- one-time API token issuance and revocation;
- PostgreSQL, Redis, worker, GitHub, and SMTP diagnostics;
- durable security audit events;
- recent HTTP request IDs, statuses, and latency.

## Notifications

Project administrators configure notifications from `/projects`.

Supported channels:

- Slack incoming webhooks;
- Microsoft Teams Workflow webhooks;
- generic signed HTTPS webhooks;
- SMTP email.

Events are `completed`, `blocked`, `failed`, and `cancelled`. URLs and email
destinations are encrypted in PostgreSQL. Generic webhooks optionally include
`X-Aegis-Signature-256`.

SMTP uses:

```text
AEGIS_SMTP_HOST
AEGIS_SMTP_PORT
AEGIS_SMTP_USERNAME
AEGIS_SMTP_PASSWORD
AEGIS_SMTP_FROM
```

## Backups

`aegis backup` archives a clean PostgreSQL dump, generated scan reports, and a
versioned manifest. Redis job events are intentionally not backed up because
they are bounded transient state.

Recommended retention:

- hourly backups for 24 hours;
- daily backups for 14 days;
- monthly backups for 12 months when Aegis is used for release evidence.

Generated run artifacts are pruned after `AEGIS_ARTIFACT_RETENTION_DAYS`
(30 days by default). Database scan summaries remain available after artifact
expiry. Coordinate artifact retention with backup retention and regulatory
evidence requirements.

Test restore procedures regularly on a separate environment. A restore test is
not complete until an administrator can sign in, project history is visible,
reports open, and a worker can complete a quick scan.

## Scanner failure handling

Every scan writes `scan-manifest.json` with per-tool status. A `failed` tool
means the scanner did not produce a trustworthy report. CI and release gates
should use `--strict`, which exits with code `2` for operational failures.

For local or exploratory scans, non-strict mode may still return an allow/block
decision from available reports. Treat any non-empty `operational_failures`
field in the JSON summary as degraded evidence, not as a clean approval.

## Operational SLOs

Track these minimum signals:

- dashboard readiness success rate;
- worker job completion and failure counts;
- scan queue age;
- HTTP 5xx rate and p95 latency;
- failed notification delivery count;
- PostgreSQL and Redis disk usage.

Investigate immediately when `/ready` reports an unavailable worker or Redis,
or when scans remain queued longer than the expected worker startup time.

## Prometheus and Grafana

Use `deploy/prometheus.yml.example` as a scrape configuration and mount a file
containing `AEGIS_METRICS_TOKEN` at `/run/secrets/aegis_metrics_token`. Import
`deploy/grafana-dashboard.json` into Grafana for request-rate and latency panels.

## Incident response

If scanner execution infrastructure may be compromised:

1. Stop worker containers first to prevent additional untrusted code execution.
2. Rotate GitHub OAuth tokens, notification webhooks, and API tokens.
3. Preserve PostgreSQL, generated reports, worker logs, and container logs.
4. Rebuild workers from a reviewed image tag before re-enabling scan queues.
5. Re-run release-blocking scans with `--strict` after recovery.
