# Aegis

Security scanning, project triage, and deployment decisions in one workbench.

Aegis combines a Python security-scanning CLI with a self-hosted web console.
Teams can connect repositories, run repeatable security pipelines, review new
findings, enforce deployment policy, and distribute results without sending
source code to a hosted third party.

## What Aegis provides

- CLI security gates for local development and CI.
- Project workspaces with member roles and persistent scan history.
- GitHub OAuth repository import for public and private repositories.
- Quick, standard, and deep scan presets.
- SAST, dependency, secret, malware, container, and dynamic checks.
- Live progress over authenticated WebSockets.
- Finding comparison against the previous completed scan.
- HTML, Markdown, SARIF, SBOM, and JSON outputs.
- Slack, Teams Workflow, email, and signed webhook notifications.
- PostgreSQL persistence, Redis queues, Caddy TLS, and Prometheus metrics.
- Administration for users, API tokens, audit events, and diagnostics.

## Choose your starting point

### Scan a repository from the terminal

Install the CLI from GitHub with `pipx`:

```bash
pipx install git+https://github.com/huslenine999/aegis
aegis scan . --fast
```

Run the standard local scan:

```bash
aegis scan .
```

Generate SARIF for code-scanning platforms:

```bash
aegis scan . --sarif
```

Exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | Deployment allowed |
| `1` | Security policy blocked |
| `2` | Scanner, configuration, or operational failure |

### Start the complete workbench

The complete stack requires a source checkout, Docker, and Docker Compose v2:

```bash
git clone https://github.com/huslenine999/aegis.git
cd aegis
python3 -m pip install -e ".[dev]"
aegis start
```

`aegis start`:

1. checks Docker and ports 80/443;
2. generates owner-only local secrets in `.env.aegis`;
3. starts PostgreSQL, Redis, the RQ worker, dashboard, and reverse proxy;
4. waits for the health endpoint;
5. opens the one-time setup wizard.

The local workbench is available at [http://localhost](http://localhost).

To avoid opening a browser:

```bash
aegis start --no-open
```

## Core workflow

1. Complete the first-run administrator setup.
2. Open `/projects`.
3. Create a project or connect GitHub and import a repository.
4. Select a scan preset.
5. Follow progress and scanner logs in real time.
6. Review new findings and the deployment verdict.
7. Retry, cancel, export, or notify the appropriate team.

### Scan presets

| Preset | Intended use | Included checks |
| --- | --- | --- |
| Quick | Local feedback | Fast SAST and signature checks |
| Standard | Pull requests and routine audits | Static analysis, dependencies, secrets, and malware |
| Deep | Release and exposure review | Standard checks plus sandbox execution, DAST, and container scanning |

## Scanner coverage

| Area | Tools and behavior |
| --- | --- |
| Python SAST | Ruff security rules |
| Pattern analysis | Semgrep with Aegis rules |
| Dependencies | Safety and OSV |
| Secrets | detect-secrets |
| Malware/signatures | YARA and ClamAV-compatible fallback checks |
| Containers | Trivy when Docker is available |
| Dynamic testing | Sandbox execution and DAST probes |
| Policy | Configurable severity gate and suppressions |

Scanner availability depends on the selected preset and local runtime. A
requested scanner failure is treated as an operational error in strict mode,
not as a clean result.

## Project configuration

Aegis discovers `aegis.yml`, `aegis.yaml`, `.aegis.yml`, or `.aegis.yaml` from
the target directory upward.

```yaml
scan:
  no_docker: true
  fail_on: medium,high,critical
  timeout: 120
  sarif: aegis.sarif
  exclude_paths:
    - app/demo_lab.py
  suppressions:
    - tool: Ruff
      rule: S103
      path: app/cli.py
      reason: Reviewed executable hook creation.
```

CLI options override configuration-file values. Applied suppressions are
recorded in `suppressions-report.json`.

Useful commands:

```bash
# Fast local feedback
aegis scan . --fast

# Skip Docker, Trivy, and DAST
aegis scan . --no-docker

# Machine-readable output
aegis scan . --json --quiet

# Fail closed when a scanner cannot complete
aegis scan . --strict

# Write reports elsewhere
aegis scan . --output ./aegis-reports

# Locate or open the latest report
aegis report --path
aegis report --open
```

## Architecture

```mermaid
flowchart LR
    User["Browser / CLI"] --> Caddy["Caddy TLS proxy"]
    Caddy --> API["FastAPI dashboard"]
    API --> Postgres["PostgreSQL"]
    API --> Redis["Redis"]
    Redis --> Worker["RQ scan worker"]
    Worker --> Sandbox["Docker sandbox and scanners"]
    Worker --> Postgres
    API --> Metrics["Prometheus metrics"]
    Worker --> Notify["Slack / Teams / Email / Webhooks"]
```

Production services:

- **Caddy** terminates TLS and proxies HTTP/WebSocket traffic.
- **FastAPI** provides authentication, RBAC, APIs, reports, and the UI.
- **PostgreSQL** stores users, projects, scan history, encrypted integrations,
  notification channels, audit events, WAF rules, and application state.
- **Redis/RQ** provides queues, rate limits, live job state, and bounded logs.
- **Worker** clones repositories and executes scanner pipelines.

## Authentication and access

Global and project roles:

| Role | Capabilities |
| --- | --- |
| Viewer | Read project results, reports, SBOMs, and scan streams |
| Operator | Viewer access plus start, cancel, and retry scans |
| Admin | User, token, membership, notification, WAF, and operations administration |

Security controls include:

- PBKDF2 password hashes;
- signed HTTP-only sessions;
- secure `SameSite` cookies in production;
- CSRF validation for session mutations;
- bearer API tokens with revocation;
- project membership checks;
- per-job WebSocket ownership;
- Redis-backed request and connection rate limits.

## GitHub integration

Create a GitHub OAuth app with this callback:

```text
https://aegis.example.com/api/github/callback
```

Configure:

```bash
AEGIS_GITHUB_CLIENT_ID=...
AEGIS_GITHUB_CLIENT_SECRET=...
AEGIS_GITHUB_CALLBACK_URL=https://aegis.example.com/api/github/callback
AEGIS_ENCRYPTION_KEY=...
```

Generate a valid encryption key:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

The OAuth flow uses PKCE and expiring state. Access tokens are encrypted in
PostgreSQL. Git clone credentials are passed through process environment
configuration rather than command arguments or logs.

See [GitHub integration setup](docs/GITHUB.md).

## Notifications

Project administrators can subscribe channels to `completed`, `blocked`,
`failed`, and `cancelled` events.

Supported destinations:

- Slack incoming webhooks;
- Microsoft Teams Workflow webhooks;
- generic HTTPS webhooks with optional HMAC signatures;
- SMTP email.

Webhook destinations must resolve to public addresses. Notification delivery
failure is recorded but does not convert a completed scan into a failed scan.

See [operations and notifications](docs/OPERATIONS.md).

## Production deployment

Copy the environment template:

```bash
cp .env.production.example .env
```

Replace every placeholder, point `AEGIS_DOMAIN` DNS at the deployment host,
then start the stack:

```bash
docker compose up --build -d
```

Production startup fails closed unless authentication, PostgreSQL, Redis,
workers, explicit host/origin allowlists, and required secrets are configured.

Health endpoints:

```text
/health   process liveness
/ready    PostgreSQL, Redis, and worker readiness
/metrics  authenticated Prometheus metrics
```

Tagged releases publish a wheel and container images to GHCR. To deploy a
published image:

```bash
export AEGIS_IMAGE=ghcr.io/huslenine999/aegis:v2.2.0
docker compose pull dashboard worker
docker compose up -d --no-build
```

See [production deployment](docs/PRODUCTION.md).

## Operations

Open `/admin` for:

- user and role management;
- API-token issuance and revocation;
- PostgreSQL, Redis, worker, GitHub, and SMTP diagnostics;
- durable audit events;
- recent request IDs, statuses, and latency.

Lifecycle commands:

```bash
aegis logs --follow
aegis backup --output backups/aegis.zip
aegis restore backups/aegis.zip --yes
aegis upgrade
aegis stop
```

Backups contain a clean PostgreSQL dump, generated reports, and a version
manifest. Redis job events are bounded transient state and are not backed up.

Prometheus and Grafana examples are available in [`deploy/`](deploy/).

## GitHub Action

Aegis can block a workflow using the repository Action:

```yaml
- name: Aegis security gate
  uses: huslenine999/aegis@<reviewed-commit-sha>
  with:
    scan-target: .
    no-docker: "true"
    fail-on: medium,high,critical
```

Pin the Action to a reviewed immutable commit SHA.

## Development and testing

Install development dependencies:

```bash
python3 -m venv venv
./venv/bin/python -m pip install -e ".[dev]"
npm install
npx playwright install chromium
```

Run verification:

```bash
./venv/bin/python -m compileall -q app policy_engine.py tests
./venv/bin/python -m pytest -q
npm run test:e2e
git diff --check
```

Current baseline:

- Python: **120 passing tests**
- Playwright/axe: **6 passing browser and accessibility tests**

The intentionally vulnerable demo routes are disabled by default. Enable them
only for isolated training:

```bash
AEGIS_ENABLE_DEMO_LAB=true ./setup.sh
```

## Current production position

Aegis is suitable for a controlled internal production pilot after a real
Docker deployment rehearsal and backup/restore drill.

Before operating it as a public multi-tenant SaaS:

- introduce versioned database migrations;
- move generated artifacts to project/run-scoped object storage;
- add MFA, password reset, account disablement, and session revocation;
- replace broad GitHub OAuth scope with a fine-grained GitHub App;
- add automated pull-request checks and review comments;
- run load, failover, penetration, and disaster-recovery testing;
- connect logs, metrics, errors, and alerts to production systems.

See [the delivery handoff](handoff.md) for the detailed assessment.

## Documentation

- [Quick start](docs/QUICKSTART.md)
- [Production deployment](docs/PRODUCTION.md)
- [GitHub integration](docs/GITHUB.md)
- [Operations and notifications](docs/OPERATIONS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)

## License

[MIT](LICENSE)
