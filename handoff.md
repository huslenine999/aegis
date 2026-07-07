# Aegis Delivery Handoff

## Delivery state

- Branch: `main`
- Package version: `2.2.0`
- Python suite: `120 passed`
- Playwright/axe suite: `6 passed`
- Compile and whitespace validation: passed
- Docker Compose runtime smoke: requires a Docker-capable host or CI runner
- Live GitHub, Slack, Teams, SMTP, and GHCR delivery: requires deployment credentials

Aegis is now a project-oriented DevSecOps workbench rather than a single shared
scanner dashboard. It supports authenticated teams, project membership,
repository import, persistent scan history, configurable notifications, and an
operations console while retaining the CLI scanner and GitHub Action.

## Delivered capabilities

### Authentication and authorization

- PBKDF2 password authentication with signed HTTP-only sessions.
- CSRF protection for cookie-authenticated mutations.
- `viewer`, `operator`, and `admin` global and project roles.
- Bearer API tokens with one-time display, listing, and revocation.
- Protected reports, exports, telemetry, scan APIs, and WebSockets.
- WebSocket job ownership enforcement.
- One-time setup wizard with a URL-fragment setup token.

### Projects and GitHub

- Project dashboard at `/projects`.
- Project repository, default branch, scan preset, member roles, and scan history.
- GitHub OAuth authorization-code flow with PKCE and expiring state.
- Encrypted GitHub tokens in PostgreSQL.
- Public and private repository import and shallow cloning.
- Clone credentials passed through Git environment configuration rather than
  process arguments or application logs.

Automated pull-request checks and review comments are not implemented. The
current GitHub integration covers account connection, repository import, and
project scans.

### Scan workflow

- `quick`, `standard`, and `deep` project scan presets.
- Persistent progress and terminal state in PostgreSQL.
- Live Redis/WebSocket updates.
- Cooperative cancellation and retry.
- New-finding comparison against the previous completed project scan.
- Bounded Redis logs and retention.

Generated HTML, Markdown, SBOM, and raw scanner artifacts still use shared file
storage. Project result summaries and histories are separated in PostgreSQL,
but fully isolated per-run artifact storage remains future work.

### Notifications and operations

- Project notification channels for Slack, Teams Workflows, generic signed
  HTTPS webhooks, and SMTP email.
- Encrypted notification destinations and secrets.
- `completed`, `blocked`, `failed`, and `cancelled` events.
- Delivery history that cannot fail an otherwise successful scan.
- Operations console at `/admin` with:
  - user and role management;
  - API token issuance and revocation;
  - PostgreSQL, Redis, worker, GitHub, and SMTP diagnostics;
  - durable security audit events;
  - recent structured HTTP request logs.
- Authenticated Prometheus endpoint and example Grafana dashboard.

### Persistence and deployment

- PostgreSQL-backed users, tokens, projects, memberships, scan histories,
  GitHub connections, notification channels, audit events, WAF rules, and
  application state.
- Versioned database migrations with recorded applied schema versions.
- Redis-backed queues, rate limits, live job state, and bounded logs.
- Caddy reverse proxy with automatic production TLS.
- Hardened dashboard, worker, PostgreSQL, and Redis Compose topology.
- JSON request logging with request IDs and latency.
- Liveness and dependency-aware readiness endpoints.
- Release workflow that publishes versioned Python wheels and GHCR images.

### User workflow

From a source checkout:

```bash
aegis start
```

This validates Docker and ports, generates `.env.aegis` with owner-only
permissions, starts the complete stack, waits for health, and opens the setup
wizard.

Lifecycle commands:

```bash
aegis logs --follow
aegis backup --output backups/aegis.zip
aegis restore backups/aegis.zip --yes
aegis upgrade
aegis stop
```

Task-focused documentation is under `docs/`.

## Production position

The current state is suitable for a controlled internal production pilot after
a successful Docker deployment rehearsal, backup/restore drill, and provider
credential testing.

Before treating Aegis as a public multi-tenant SaaS:

1. Move generated artifacts to project/run-scoped object storage.
2. Add MFA, password reset, account disablement, and session revocation.
3. Replace broad GitHub OAuth repository scope with a fine-grained GitHub App.
4. Add pull-request checks/comments and webhook automation.
5. Run load, soak, failover, penetration, and disaster-recovery tests.
6. Configure external log aggregation, alert rules, and error tracking.
7. Verify notification retries and provider rate-limit behavior.

## Required production configuration

Start from `.env.production.example`. Required values include:

- public domain, allowed hosts, and HTTPS origin;
- PostgreSQL password;
- administrator bootstrap and setup tokens;
- session, service, metrics, and encryption secrets;
- optional GitHub OAuth and SMTP credentials.

Do not commit `.env`, `.env.aegis`, webhook URLs, OAuth secrets, private keys, or
generated backup archives.

## Verification

Run locally:

```bash
./venv/bin/python -m compileall -q app policy_engine.py tests
./venv/bin/python -m pytest -q
npm run test:e2e
git diff --check
```

Run on a Docker-capable host:

```bash
cp .env.production.example .env
# Replace every placeholder.
docker compose config --quiet
docker compose build
docker compose up -d
curl --fail https://your-domain.example/health
curl --fail https://your-domain.example/ready
docker compose ps
docker compose logs --no-color proxy dashboard worker postgres redis
```

Then verify:

- first-run setup and subsequent login;
- project creation and private GitHub repository import;
- quick, standard, deep, cancel, retry, and WebSocket behavior;
- Slack, Teams, SMTP, and signed webhook test deliveries;
- authenticated Prometheus scraping;
- backup and restore on a separate environment;
- persistence across service restart.

## Important files

```text
app/main.py                         FastAPI routes and application orchestration
app/auth.py                         Sessions, passwords, API tokens, and RBAC
app/projects.py                     Projects, membership, and scan history
app/github_integration.py           OAuth PKCE and encrypted GitHub credentials
app/notifications.py                Notification configuration and delivery
app/audit.py                        Durable security audit events
app/observability.py                JSON request logs and Prometheus metrics
app/database.py                     PostgreSQL/SQLite schema and Redis client
app/worker.py                       RQ scan execution and project lifecycle
app/templates/projects.html         Project dashboard
app/templates/admin.html            Operations console
app/templates/setup.html            First-run setup wizard
docker-compose.yml                  Production service topology
deploy/Caddyfile                    TLS reverse proxy
deploy/prometheus.yml.example       Prometheus scrape example
deploy/grafana-dashboard.json       Grafana dashboard example
docs/QUICKSTART.md                  Initial installation and startup
docs/PRODUCTION.md                  Production deployment
docs/GITHUB.md                      GitHub OAuth setup
docs/OPERATIONS.md                  Notifications, backups, and monitoring
docs/TROUBLESHOOTING.md             Failure diagnosis
```
