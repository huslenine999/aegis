# Aegis threat model

## Security objectives

Aegis must keep scanned source and credentials private, produce an explainable
and reproducible policy decision, fail closed when required evidence is missing,
and prevent one project from reading another project's results.

## Primary trust boundaries

1. Browsers and API clients are untrusted. Authentication, CSRF validation,
   project RBAC, rate limits, and request-size limits apply at the dashboard.
2. Imported repositories and uploaded files are hostile. Static scanners run in
   the worker; dynamic execution belongs on an isolated Docker/Trivy runtime
   without production credentials or unrestricted internal-network access.
3. Redis carries transient job state and logs. PostgreSQL is the durable source
   for identities, authorization, projects, scan summaries, and audit events.
4. Run artifacts are immutable evidence addressed by project and scan run.
   Access is checked before listing or downloading an artifact.
5. GitHub, SMTP, Slack, Teams, and generic webhooks are external systems.
   Credentials are encrypted at rest and outbound webhook redirects are denied;
   the release gate still requires a strict global-address check.

## Important abuse cases and controls

| Abuse case | Current control |
| --- | --- |
| Scanner crashes but project is approved | Worker and CLI share the policy contract; required tool failures produce an operational error. |
| Viewer reads another project's report | Run-scoped artifact APIs require project membership; legacy shared reports are administrator-only. |
| Disabled user keeps an old session | Opaque server-side sessions join the current active user and role and can be revoked. |
| Oversized body exhausts WAF memory | A body-size middleware runs before WAF request buffering. |
| Webhook targets an internal service | HTTPS, strict global-address validation, redirect denial, bounded timeout, and bounded retries; the global-address check remains a release hold until implemented. |
| Deep scan runs on the dashboard host | Deep evidence fails closed unless an isolated Docker and Trivy runtime is available. |
| Malicious regex blocks the service | WAF rules are administrator-only, length-bounded, and syntax validated; deployment monitoring remains required. |
| Tenant administrator accesses another company | Tenant IDs are carried by principals and enforced in project, user, token, scan, artifact, membership, and audit queries; cross-tenant tests exercise denial paths. |
| Database token hashes are cracked offline | Current-format API tokens use server-keyed HMAC, explicit scopes, expiry, revocation, and last-used tracking; legacy unsalted rows remain a release-gate finding until revoked or migrated. |
| Scanner report output exhausts worker storage | Source and parser budgets reduce the blast radius, but file-writing scanner outputs still require a concurrent write-time byte budget before this objective is complete. |
| Scan evidence is changed after completion | Ed25519-signed manifests bind source identity, policy digest, scanner state, and artifact SHA-256 hashes. |
| GitHub retries or an attacker replays a webhook | HMAC-SHA-256 verification and persisted delivery IDs authenticate and deduplicate deliveries. |
| A signed GitHub event routes to another tenant's repository or installation | Immutable installation/repository bindings require one active tenant match; ambiguous and legacy mappings fail closed. |
| A GitHub capability is revoked while work is queued | OAuth disconnect, user deactivation, project offboarding, and App installation events use centralized revocation; the worker rechecks current authorization before cloning. |
| Pull request changes while a scan is queued | The webhook persists the head SHA; the worker rechecks the queued row and binding, then fetches and checks out that exact detached revision. |
| Cross-tenant row is written outside application authorization | Database triggers validate project, member, and scan tenant relationships on inserts and updates and make tenant IDs immutable. |
| A stale exception permanently hides a finding | Suppressions require approval metadata and a future expiry; expired or invalid entries remain reported and do not match findings. |
| Repository escapes through symlinks or special files | Source validation rejects symlinks, non-regular files, excessive files, and oversized workspaces before scanning. |
| Stolen old browser session changes identity or deletes evidence | Sensitive operations require recent password/MFA authentication; scoped machine tokens require admin scope. |
| TOTP code is reused within its validity window | The last accepted TOTP counter is atomically recorded and older or equal counters are denied. |
| Audit rows are silently rewritten | Per-tenant HMAC chaining detects tampering and database triggers reject updates and deletes. |

## Residual risks

- The tenant-scoped local artifact backend is suitable for one tenant per
  controlled deployment, not an untrusted public multi-tenant service. Public operation should use an
  object store with per-tenant keys, encryption, quotas, and lifecycle rules.
- GitHub OAuth still requests repository scope for interactive imports. The
  GitHub App uses narrower installation permissions for automated pull-request
  checks, but its private key is currently present in both dashboard and worker;
  a production scanner fleet should obtain clone tokens from a broker instead.
- TOTP MFA is implemented. Self-service password recovery, WebAuthn, and
  enterprise identity federation still require a reviewed identity workflow.
- The bundled DAST probes are intentionally narrow and Python-oriented; they do
  not replace a general web application scanner or penetration test.
- A database superuser can disable triggers or replace both audit data and the
  application-held audit key. Export chain heads and structured events to an
  independently administered SIEM before relying on them for regulated
  non-repudiation.
- The release-gate scan found three remaining application/dependency hold
  points: legacy unsalted API-token acceptance, unbounded file-writing scanner
  reports, and notification validation that does not yet require globally
  routable addresses. The optional Semgrep dependency tree also carries the
  documented MCP advisory exception until a patched compatible release is
  locked.

Review this model whenever a scanner, integration, artifact backend,
authentication method, or network boundary changes.
