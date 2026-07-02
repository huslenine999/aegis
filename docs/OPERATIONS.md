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

Test restore procedures regularly on a separate environment.

## Prometheus and Grafana

Use `deploy/prometheus.yml.example` as a scrape configuration and mount a file
containing `AEGIS_METRICS_TOKEN` at `/run/secrets/aegis_metrics_token`. Import
`deploy/grafana-dashboard.json` into Grafana for request-rate and latency panels.
