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
  expiration, revocation, and last-used tracking for current-format tokens.
  Migration 20 revokes rows that cannot be classified as current keyed hashes;
  there is no legacy unsalted-hash authentication fallback.
- Repeated login failures produce a timed account lockout.
- Optional RFC 6238 TOTP MFA encrypts secrets at rest and provides ten
  single-use recovery codes.
- TOTP time steps cannot be replayed. Sensitive browser operations require
  recent password/MFA authentication; non-interactive callers need an
  admin-scoped API token.
- Enabling or disabling MFA revokes existing sessions.

### Scan and artifact trust

- New project artifacts use tenant/project/run-scoped filesystem paths.
- `AEGIS_ARTIFACT_BACKEND` accepts `local` or the reviewed S3-compatible backend;
  unsupported storage values fail startup instead of creating a decorative
  assurance claim. Production still rejects multi-tenant mode with local
  storage, and the current topology uses one isolated deployment per tenant.
- Artifact metadata includes SHA-256 size and integrity records.
- Scanner subprocess pipe output, file-writing reports, in-process scanner
  findings, report/parser input, S3 downloads, ZIP entry and uncompressed
  sizes, and HTTP response bodies are bounded by shared resource budgets. S3
  artifacts and report bundles are streamed in chunks rather than assembled
  into an unbounded response buffer.
- Rate-limit keys and HTTP metrics use finite route classes/templates; raw
  request paths are not used as Redis keys or metric labels.
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
- The scanner extra pins Semgrep 1.173.0 and its fixed MCP 1.29.0
  dependency. Aegis invokes Semgrep through its CLI path and does not expose
  MCP server transports.

### Integrations and runtime boundaries

- GitHub webhooks require an HMAC-SHA-256 signature and validated delivery/event
  headers; delivery IDs are persisted to reject replay. GitHub App pull-request
  events resolve through immutable tenant-bound installation/repository mappings,
  create check runs, scan the exact head revision with a short-lived installation
  token, and return line-level Ruff, Semgrep, and secret findings. Legacy project
  names are explicitly downgraded until an exact signed repository identity is
  observed.
- GitHub OAuth connections and App installations share a centralized revocation
  path, and interactive OAuth state is bound to the initiating browser session.
  Queued scans re-read their database row, tenant, project membership, source
  context, and current credential capability immediately before source access.
- MFA recovery-code consumption and login-failure lockout updates use
  compare-and-swap/atomic database updates. WebSocket scan streams enforce the
  project role and tenant boundary for administrators as well as other roles.
- OIDC post-login redirects reject raw or encoded backslash, authority, and
  control-character normalization bypasses.
- Database triggers enforce tenant consistency on project, member, and scan
  inserts and updates, reject changes to immutable tenant identities, and reject
  unbound GitHub App installation IDs on scan rows.
- Production deep scans are disabled unless both `AEGIS_ALLOW_DEEP_SCANS` and
  `AEGIS_ISOLATED_WORKER` are explicitly enabled.
- Sandbox containers run as a non-root UID with all capabilities dropped,
  `no-new-privileges`, a read-only root, internal networking, bounded memory,
  CPU, PIDs, open files, processes, temporary storage, and execution time.
- Scanner subprocess environments exclude application credentials.
- Asynchronous scan completion only enqueues notification work. SMTP and
  outbound notification credentials live in a separate notifier service, not
  the scanner worker.
- Production scanner and notifier entrypoints reject secrets owned by the other
  service boundaries. This catches accidental Compose or secret-manager
  expansion before either worker accepts jobs.
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

`AEGIS_MULTI_TENANT=true` is intentionally rejected in production while the
broader tenant-isolation, object-store tenancy, and operational control plane
remain under review. The S3-compatible artifact backend exists for durable
single-tenant deployments; sell one tenant per isolated deployment in the
meantime.

Built-in scanner reports are emitted over a bounded stdout pipe into a
parent-owned temporary file, then atomically promoted on every supported
platform. The legacy adapter for scanners that insist on opening a report
path directly is POSIX-only and fails closed elsewhere; new scanner
integrations must use the stdout transport.

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
