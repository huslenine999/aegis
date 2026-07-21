# Aegis security hardening baseline

This document distinguishes controls enforced by the repository from controls
that require external infrastructure or an independent assessor. A control is
not considered complete merely because an environment variable exists.

## Enforced in the application

### Identity and tenancy

- Every authenticated principal carries an immutable tenant identifier.
- Projects, scan runs, users, API tokens, and audit queries are tenant-scoped.
- Tenant administrators cannot enumerate another tenant's projects or users.
- Project membership rejects users from another tenant.
- API tokens use keyed hashes, explicit `read`, `write`, or `admin` scopes,
  expiration, revocation, and last-used tracking.
- Repeated login failures produce a timed account lockout.
- Optional RFC 6238 TOTP MFA encrypts secrets at rest and provides ten
  single-use recovery codes.
- TOTP time steps cannot be replayed. Sensitive browser operations require
  recent password/MFA authentication; non-interactive callers need an
  admin-scoped API token.
- Enabling or disabling MFA revokes existing sessions.

### Scan and artifact trust

- New project artifacts use tenant/project/run-scoped filesystem paths.
- Artifact metadata includes SHA-256 size and integrity records.
- Scan manifests are signed with Ed25519 and contain source identity, revision,
  policy digest, scanner state, operational failures, and artifact hashes.
- `aegis verify-evidence` validates a pinned public key and every referenced
  artifact. Trusting a manifest's embedded key requires an explicit local-only
  override and is not the default.
- Source validation rejects symlinks, special files, oversized trees, and
  excessive file counts before project scanners execute.
- Required scanner failures remain operational failures and cannot become a
  clean release decision.
- Suppressions require a reason, approver, ticket, and future expiry. Invalid or
  expired exceptions never remove findings and remain visible in versioned
  suppression evidence.
- The repository currently carries four short-lived upstream exceptions for
  Semgrep 1.170.0's exact MCP 1.23.3 and Click 8.1.8 pins. The affected MCP
  server features and `click.edit` path are not invoked by Aegis. These
  exceptions expire on 2026-10-20 and must be removed as soon as Semgrep permits
  patched transitive versions; they are not blanket acceptance of those
  advisories in customer applications.

### Integrations and runtime boundaries

- GitHub webhooks require an HMAC-SHA-256 signature and validated delivery/event
  headers; delivery IDs are persisted to reject replay. GitHub App pull-request
  events create check runs, scan the exact head revision with a short-lived
  installation token, and return line-level Ruff, Semgrep, and secret findings.
- Database triggers enforce tenant consistency on project, member, and scan
  inserts and updates, and reject changes to immutable tenant identities.
- Production deep scans are disabled unless both `AEGIS_ALLOW_DEEP_SCANS` and
  `AEGIS_ISOLATED_WORKER` are explicitly enabled.
- Sandbox containers run as a non-root UID with all capabilities dropped,
  `no-new-privileges`, a read-only root, internal networking, bounded memory,
  CPU, PIDs, open files, processes, temporary storage, and execution time.
- Scanner subprocess environments exclude application credentials.
- Asynchronous scan completion only enqueues notification work. SMTP and
  outbound notification credentials live in a separate notifier service, not
  the scanner worker.
- Production configuration refuses unauthenticated exposure, wildcard hosts or
  origins, SQLite, missing Redis/workers, and unsafe multi-tenant mode.
- Audit events form a per-tenant HMAC chain, expose a verification endpoint,
  emit structured security logs, and are protected from update/delete by
  database triggers.
- `AEGIS_SECURITY_PROFILE=bank` deliberately refuses startup in this build. It
  cannot be enabled by setting decorative environment variables while the
  required external control adapters remain absent.

## External controls required before public multi-tenant SaaS

The following cannot be completed safely with repository code alone:

1. Tenant-scoped object storage with per-tenant encryption keys, quotas,
   lifecycle policies, signed downloads, and verified deletion.
2. A dedicated ephemeral VM or microVM scanner fleet with deny-by-default
   egress and no application, database, GitHub, notification, or cloud
   credentials.
3. A secret-broker boundary that keeps the GitHub App private key out of scanner
   workers. The current worker needs that key to mint installation tokens.
4. WebAuthn/passkeys and SAML/OIDC federation through a reviewed identity
   provider. TOTP is available now but does not replace enterprise federation.
5. Durable external SIEM transport, alert routing, and on-call response
   procedures. Local audit rows are now append-only and tamper-evident, but the
   database administrator remains inside their trust boundary.
6. Load, soak, failover, disaster-recovery, and cross-region restore exercises
   on the actual production architecture.
7. An independent penetration test, legal terms, DPA, support SLA, and incident
   response exercise.

`AEGIS_MULTI_TENANT=true` is intentionally rejected in production until the
external artifact backend exists. Sell one tenant per isolated deployment in
the meantime.

## Verification baseline

Use OWASP ASVS 5.0 as the application-control checklist, NIST SSDF SP 800-218
for the development lifecycle, and SLSA Build Track for release provenance.
For each public release:

```bash
python -m compileall -q app policy_engine.py tests
pytest -q --timeout=60 --timeout-method=thread
ruff check app policy_engine.py tests
mypy
npm run test:e2e
python scripts/run_security_benchmark.py --output benchmark-results.json
aegis verify-evidence /path/to/scan-manifest.json --public-key PINNED_KEY
```

Record external test evidence and exceptions alongside the release checklist.
