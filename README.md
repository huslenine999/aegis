# Aegis

Private, explainable security gates for small engineering teams.

Aegis scans source code, dependencies, and secrets; turns the results into an allow, block, or operational-error decision;
and keeps the evidence in a self-hosted project workspace.

Use it as:

- a local command-line scanner;
- a pull-request security gate;
- or a self-hosted workbench for findings, policy, evidence, and remediation.

> [!IMPORTANT]
> Aegis is ready for local evaluation. Controlled single-customer pilots require
> an operator to provision secrets, backups, and monitoring and complete the
> validation described below. Deep scans require a separately provisioned
> CodeQL runtime. This release is not a public shared multi-tenant service.

## Why Aegis?

Many small teams want a dependable release-security check without sending
private source code to another hosted platform or assembling five unrelated
scanner reports by hand.

Aegis provides one workflow:

1. scan an approved repository;
2. evaluate it against an explicit policy version;
3. explain why the release passed, was blocked, or could not be evaluated;
4. track findings until they are fixed or formally accepted;
5. export signed evidence that can be verified independently.

## Choose your path

| Goal | Start here | Requirements |
| --- | --- | --- |
| Try the scanner | [CLI evaluation](#cli-evaluation) | Python 3.11+ |
| Run the complete workbench locally | [Local workbench](#local-workbench) | Source checkout, Docker, Compose v2 |
| Gate a repository in CI | [GitHub Action](#github-action) | A GitHub workflow |
| Operate an internal pilot | [Production pilot](#production-pilot) | DNS, TLS, PostgreSQL, Redis, workers, backups |

## CLI evaluation

Install a published Aegis release in an isolated environment:

```bash
pipx install aegis-security-console
```

For Standard scans with Semgrep included, install the scanner extra:

```bash
pipx install "aegis-security-console[scanner]"
```

If PyPI reports that no matching distribution exists before the first tagged
release is published, install the current repository revision instead:

```bash
pipx install "git+https://github.com/huslenine999/aegis.git#egg=aegis-security-console[scanner]"
```

Check the available scanner dependencies, then run the built-in demonstration:

```bash
aegis doctor
aegis demo --open
```

The demo creates a tiny intentionally vulnerable application. A blocked verdict
is expected.

Scan your own repository:

```bash
cd your-project
aegis scan . --fast
```

For a release or CI gate, use strict mode so missing scanner evidence is never
treated as a clean result:

```bash
aegis scan . \
  --strict \
  --fail-on medium,high,critical \
  --output .aegis/reports \
  --sarif .aegis/reports/aegis.sarif
```

Exit codes are stable and intended for automation:

| Code | Decision |
| ---: | --- |
| `0` | Allowed by policy |
| `1` | Blocked by security findings |
| `2` | Scanner, configuration, or operational failure |

Other useful commands:

```bash
aegis scan . --preset quick     # Ruff security rules and detect-secrets
aegis scan . --yara            # Optional YARA signature analysis
aegis scan . --json --quiet     # Machine-readable result
aegis report --open             # Open the latest HTML report
aegis install-hook              # Add a Git pre-push gate
aegis verify-evidence ./scan-manifest.json --public-key YOUR_PINNED_KEY
```

## Local workbench

The full workbench is started from a source checkout because the scanner-only
Python package does not include the Compose topology and deployment
configuration.

```bash
git clone https://github.com/huslenine999/aegis.git
cd aegis

make setup
source venv/bin/activate
aegis start
```

`aegis start` checks Docker and local ports, generates owner-only development
secrets in `.env.aegis`, starts the stack, waits for readiness, and opens the
one-time setup wizard at [http://localhost](http://localhost).

To leave the browser closed or inspect startup directly:

```bash
./venv/bin/aegis start --no-open
./venv/bin/aegis logs --follow
```

After signing in:

1. open **Projects**;
2. create a local project or connect GitHub and import a repository;
3. choose Quick or Standard scanning, or Deep after
   [enabling CodeQL](#enable-deep-codeql-scans);
4. run a scan from **Scan history**, then open its report in the browser;
5. review the policy decision and durable findings, assign owners, and create
   GitHub remediation issues;
6. download the evidence bundle, including its signed manifest, when needed.

### Enable Deep CodeQL scans

CodeQL is optional because its bundle is large and its license depends on the
repository being scanned. Review the [GitHub CodeQL availability and terms](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli), then provision the pinned local runtime:

```bash
make codeql-setup
aegis start --no-open
```

The setup command verifies the official CodeQL 2.27.0 bundle checksum, builds a
pinned local image, and enables the dedicated `deep` worker profile. In the
website, open **Projects**, select a project, choose **Deep** under **Project
settings**, save, then use **Run scan** in **Scan history**. Deep supports Python
and JavaScript/TypeScript; a repository with neither language fails explicitly.

Stop the stack without deleting its data:

```bash
./venv/bin/aegis stop
```

## What the workbench adds

The web application turns one-off scanner output into an operational workflow:

- project workspaces with viewer, operator, and administrator roles;
- immutable policy versions bound to individual scans;
- durable finding fingerprints, occurrences, owners, due dates, and event history;
- expiring accepted-risk and false-positive decisions with required rationale;
- GitHub repository import, pull-request checks, and remediation issues;
- cancellable Redis/RQ jobs with authenticated live progress;
- HTML, Markdown, JSON, SARIF, CycloneDX SBOM, and ZIP evidence exports;
- Ed25519-signed manifests and SHA-256 artifact integrity checks;
- Slack, Teams Workflow, email, and signed webhook notifications;
- local authentication with TOTP MFA, plus optional enterprise OIDC;
- append-only audit-chain verification, metrics, diagnostics, and API tokens;
- local or S3-compatible artifact storage with optional KMS and object lock.

## Scan presets

| Preset | Intended use | Runtime expectation |
| --- | --- | --- |
| **Quick** | Developer feedback | Ruff security rules for Python and detect-secrets |
| **Standard** | Pull requests and branch gates | Quick plus Python Semgrep rules and OSV dependency audit |
| **Deep** | Controlled release audit | Standard plus CodeQL for Python and JavaScript/TypeScript |

Deep scans are unavailable in the default local topology. `make codeql-setup`
provisions the pinned local image and trusted query suites for the optional
Deep worker. An unavailable runtime is an operational error, never a pass.

## Scanner coverage

| Area | Implementation |
| --- | --- |
| Python security analysis | Ruff security rules |
| Pattern analysis | Semgrep and Aegis rules |
| Dependency vulnerabilities | OSV |
| Secrets | detect-secrets |
| Deeper source analysis | CodeQL in the isolated Deep profile |
| Optional signatures | YARA, only when explicitly enabled |
| Correlation and gating | Versioned severity policy and audited suppressions |

Infrastructure, container-image, live-endpoint, and malware detection are
outside the current default scanner coverage. Optional YARA reports signature
matches, not confirmed malware. A finding is a lead for review, not proof of
exploitation.

Requested scanner failures are recorded as operational failures. Use strict mode
for any release decision.

## Project configuration

Aegis accepts `aegis.yml`, `aegis.yaml`, `.aegis.yml`, or `.aegis.yaml` as a
trusted configuration only when an operator selects it explicitly with
`--config` (the GitHub Action supplies its reviewed bundled configuration).
Target-local configuration discovered automatically is advisory-only and
cannot change scan execution, policy thresholds, suppressions, or output paths.
Command-line options override an explicitly selected configuration.

```sh
aegis scan . --config ./aegis.yml
```

```yaml
scan:
  no_docker: true
  fail_on: medium,high,critical
  timeout: 120
  sarif: .aegis/reports/aegis.sarif
  exclude_paths:
    - tests/fixtures
  suppressions:
    - tool: Ruff
      rule: S103
      path: app/cli.py
      reason: Required executable permission for the generated Git hook.
      approved_by: application-security
      ticket: SEC-123
      expires_at: 2027-07-20
```

A suppression is active only when it includes a meaningful reason, approver,
tracking ticket, and future ISO-8601 expiry. Applied, invalid, and expired
exceptions are written to `suppressions-report.json`; malformed exceptions never
hide findings.

Each completed scan also writes `source-descriptor.json` and a schema-3,
source-bound `scan-manifest.json`. The descriptor records the admitted regular
files and their content digests; scanners run against a stable copy so later
checkout changes cannot alter the evidence. Older schema-2 manifests remain
verifiable but are reported as `legacy-source-unbound` evidence.

## GitHub Action

Use the repository Action as a fail-closed pull-request gate:

```yaml
name: security

on:
  pull_request:

jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<reviewed-commit-sha>
      - name: Aegis security gate
        uses: huslenine999/aegis@<reviewed-commit-sha>
        with:
          scan-target: .
          fail-on: medium,high,critical
```

Pin Aegis and every third-party Action to reviewed immutable commit SHAs in a
protected production workflow.

For repository import, exact-head pull-request checks, and remediation tickets,
follow the [GitHub integration guide](docs/GITHUB.md).

## Production pilot

The supported production shape is one isolated Aegis deployment per customer or
trust boundary.

Start with the environment template:

```bash
cp .env.production.example .env
```

Replace every placeholder, point `AEGIS_DOMAIN` at the host, and validate the
configuration before exposing the service:

```bash
docker compose config
docker compose up --build -d

curl https://aegis.example.com/health
curl https://aegis.example.com/ready
```

Production mode fails closed when required authentication, PostgreSQL, Redis,
workers, notifier, host/origin allowlists, or secrets are missing.

Before giving a team access, complete all of the following:

- run a real backup and restore rehearsal;
- run `scripts/pilot_readiness.py` and a canary repository scan;
- configure metrics, logs, queue-age alerts, and notification failure alerts;
- pin and escrow the evidence-signing and encryption keys;
- verify GitHub permissions using known safe and vulnerable pull requests;
- configure S3/KMS/object lock if local artifact storage is not acceptable;
- configure and test OIDC and a break-glass administrator procedure if required;
- provision an isolated CodeQL runtime before enabling `AEGIS_ALLOW_DEEP_SCANS`.

S3 and OIDC adapters are included, but Aegis does not provision the provider,
bucket, KMS policy, DNS, TLS, CodeQL isolation, or disaster-recovery environment
for you. Those controls must be configured and reviewed in the deployment where
Aegis runs.

See the [production guide](docs/PRODUCTION.md), [operations and recovery
runbook](docs/OPERATIONS.md), and [controlled pilot runbook](docs/PILOT_RUNBOOK.md).

## Architecture

```mermaid
flowchart LR
    User["Browser / API"] --> Proxy["Caddy TLS proxy"]
    GitHub["GitHub App / OAuth"] --> Proxy
    Proxy --> API["FastAPI dashboard"]
    API --> DB["PostgreSQL"]
    API --> Redis["Redis queues and live state"]
    Redis --> Worker["Standard scan worker"]
    Redis --> Deep["Worker with isolated CodeQL child runtime"]
    Redis --> Notifier["Notifier worker"]
    Worker --> Evidence["Local or S3 evidence"]
    Deep --> Evidence
    API --> Evidence
    Notifier --> Channels["Slack / Teams / Email / Webhooks"]
```

The dashboard authorizes users and projects. Scanner workers process untrusted
source. The notifier owns outbound notification credentials. PostgreSQL stores
identity, project, policy, finding, audit, and scan metadata. Redis contains
bounded transient job state rather than authoritative evidence.

## Security model

Important controls include:

- project-scoped RBAC and tenant consistency guards;
- revocable server-side sessions, CSRF checks, login lockout, and TOTP MFA;
- OIDC authorization code flow with PKCE, state, nonce, issuer, audience, and
  signing-key validation;
- encrypted GitHub and notification credentials;
- replay-resistant GitHub webhooks and exact-head check runs;
- request limits, scanner deadlines, workspace limits, and fail-closed evidence;
- signed manifests, artifact hashes, and append-only audit-chain verification;
- a separate notifier process that does not expose SMTP credentials to scanners;
- production host and CORS allowlists with no wildcard defaults.

Aegis still executes security tooling against untrusted source. The disposable
CodeQL child has no application credentials, network, or host filesystem mounts.
Its trusted Deep-worker supervisor still holds database and evidence-signing
credentials and access to the local Docker socket. A compromise of that
supervisor crosses the isolation boundary; review the
[threat model](docs/THREAT_MODEL.md) before deployment.

## Operations

Common stack commands:

```bash
aegis logs --follow
aegis backup --output backups/aegis.zip
aegis restore backups/aegis.zip --yes
aegis upgrade
aegis stop
```

Health and monitoring endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/health` | Process liveness |
| `/ready` | Database, Redis, standard worker, notifier, and enabled deep-worker readiness |
| `/metrics` | Bearer-protected Prometheus metrics |

Open `/admin` for users, roles, API tokens, audit verification, diagnostics, and
recent request telemetry. Redis events are transient and are not included in
backups.

## Verification and development

Install development and browser dependencies:

```bash
make setup
source venv/bin/activate
npm ci
npx playwright install chromium
```

Run the complete repository readiness gate with one command:

```bash
make verify
```

For a quick local loop without browser tests or mypy, run `make verify-fast`.
Before a controlled pilot, also generate the operator-facing readiness artifact:

```bash
aegis doctor
python scripts/pilot_readiness.py \
  --output .aegis/pilot-readiness.json
```

The last local validation on 2026-09-23 recorded 313 passing Python tests, 2
skipped Compose integration tests, 80.13% coverage over the configured modules,
and passing Ruff and mypy checks. A live offline CodeQL scan found SQL injection
in a controlled Python fixture. The coverage percentage is not whole-project
coverage.

The existing 30-case benchmark exercises the Quick Python scanner. Seven
browser tests cover setup, access control, the dashboard, accessibility, and
output escaping. An authenticated Deep browser flow, adversarial isolation
checks, and a held-out CodeQL benchmark remain to be completed before claiming
production assurance. See the [capstone review](docs/CAPSTONE_REVIEW.md) and
[scanner migration plan](docs/SCANNER_MIGRATION_PLAN.md) for the open security
questions and release gates.

## Documentation

- [Quick start](docs/QUICKSTART.md)
- [Production deployment](docs/PRODUCTION.md)
- [GitHub integration](docs/GITHUB.md)
- [Operations and recovery](docs/OPERATIONS.md)
- [Controlled pilot runbook](docs/PILOT_RUNBOOK.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Capstone review](docs/CAPSTONE_REVIEW.md)
- [Scanner migration plan](docs/SCANNER_MIGRATION_PLAN.md)
- [Hardening baseline](docs/HARDENING.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE)
