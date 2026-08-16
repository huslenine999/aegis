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
   every resolved webhook address must also be globally routable.

## Important abuse cases and controls

| Abuse case | Current control |
| --- | --- |
| Scanner crashes but project is approved | Worker and CLI share the policy contract; required tool failures produce an operational error. |
| Viewer reads another project's report | Run-scoped artifact APIs require project membership; legacy shared reports are administrator-only. |
| Disabled user keeps an old session | Opaque server-side sessions join the current active user and role and can be revoked. |
| Oversized body exhausts WAF memory | A body-size middleware runs before WAF request buffering. |
| Webhook targets an internal service | HTTPS, strict global-address validation, redirect denial, bounded timeout, and bounded retries. |
| Deep scan runs on the dashboard host | Deep evidence fails closed unless an isolated Docker and Trivy runtime is available. |
| Malicious regex blocks the service | WAF rules are administrator-only, length-bounded, and syntax validated; deployment monitoring remains required. |
| Tenant administrator accesses another company | Tenant IDs are carried by principals and enforced in project, user, token, scan, artifact, membership, and audit queries; cross-tenant tests exercise denial paths. |
| Database token hashes are cracked offline | Current-format API tokens use server-keyed HMAC, explicit scopes, expiry, revocation, and last-used tracking; Migration 20 disables unclassifiable legacy rows and no legacy fallback remains. |
| Scanner report output exhausts worker storage | Built-in scanner output crosses a bounded stdout pipe into a parent-owned temporary sink; process-group termination, atomic promotion, in-process findings, and serialized reports are also bounded. |
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
| A recovery code is consumed twice concurrently | Recovery-code updates compare the stored recovery list before committing, so only one concurrent consumer succeeds. |
| Concurrent failed logins lose lockout increments | Failed-login counts are incremented atomically and the lockout predicate is evaluated in the same update. |
| An administrator streams another tenant's scan | WebSocket scan streams resolve the project and enforce project role plus principal tenant before accepting the socket. |
| OAuth or OIDC completion is attached to another browser or external redirect | GitHub OAuth state is bound to the initiating session; OIDC return paths reject authority, backslash, and control-character normalization cases. |
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
- The release-gate scan's application and dependency findings are addressed by
  Migrations 20–21, the portable bounded stdout scanner transport, global-only
  webhook and response validation, S3 namespace plus payload validation,
  browser-bound OAuth, and the Semgrep 1.173.0 / MCP 1.29.0 lockfile update.
  The completed follow-up scan is recorded as
  `95f06103-6ec8-4229-a9dc-9d7a2c84bccc`; its report has no reportable
  findings. Built-in scanner output no longer depends on a non-POSIX polling
  fallback.

Review this model whenever a scanner, integration, artifact backend,
authentication method, or network boundary changes.
