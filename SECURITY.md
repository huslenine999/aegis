# Security policy

## Supported versions

Security fixes are provided for the latest minor release on `main`. Deployments
should pin a reviewed release image or immutable commit and keep PostgreSQL
backups before upgrading.

## Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability or exposed secret.
Use GitHub's private vulnerability-reporting feature for this repository and
include the affected version, deployment model, reproduction steps, impact, and
any suggested mitigation. Remove real credentials and customer source code from
all evidence.

The maintainer should acknowledge a complete report within five business days,
coordinate a fix and disclosure date with the reporter, and publish a security
advisory when the fix is available.

## Deployment assumptions

Aegis processes untrusted source code. Keep workers isolated from production
secrets and networks, require strict scans for release decisions, and never
interpret an unavailable scanner as a clean result. Deep scans require a
separate Docker/Trivy execution environment; mounting a host Docker socket into
the dashboard is not a supported production design.

See [the threat model](docs/THREAT_MODEL.md) and
[production guide](docs/PRODUCTION.md) for the maintained trust boundaries.
