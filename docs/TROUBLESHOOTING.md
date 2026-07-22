# Troubleshooting

## Startup fails

```bash
aegis doctor --json
aegis logs
docker compose ps
```

Confirm ports 80 and 443 are available and Docker Compose v2 is installed.

`aegis start` must be run from the virtual environment in an Aegis source
checkout. A scanner-only `pipx` installation intentionally does not contain the
Compose deployment files.

## `pipx install aegis-security-console` finds no distribution

The package is published only by a version tag after release approval. Before
the first tagged PyPI release, install directly from the repository:

```bash
pipx install "git+https://github.com/huslenine999/aegis.git#egg=aegis-security-console[scanner]"
```

## Readiness is unhealthy

Open `/admin` and inspect diagnostics, then check:

```bash
docker compose logs dashboard worker postgres redis
```

## A scan remains queued

Check `docker compose ps worker` and `docker compose logs worker`. Repository
values entered as `owner/repository` or `github.com/owner/repository` are
normalized automatically. Older workbench versions can leave a failed clone
displayed as queued; upgrade and rebuild the dashboard and worker together.

## GitHub connection fails

Verify the OAuth callback URL matches exactly, the encryption key is a valid
Fernet key, and the GitHub OAuth app has not been suspended.

## Private repository clone fails

Reconnect GitHub to refresh authorization and confirm the connected account can
read the repository and default branch.

## Notifications fail

Use the channel’s **Test** action. Webhook destinations must use HTTPS and must
resolve to public addresses. For Teams, use a current Teams Workflow webhook
rather than a legacy Microsoft 365 connector.

## Restore fails

Do not delete the backup. Restart services with `aegis start --no-open`, inspect
PostgreSQL logs, and retry only after resolving the underlying database error.
