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

Back up before upgrades:

```bash
aegis backup --output backups/pre-upgrade.zip
aegis upgrade
```

Restore requires explicit confirmation:

```bash
aegis restore backups/pre-upgrade.zip --yes
```
