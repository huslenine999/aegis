# Aegis threat model

## Security objectives

Aegis must keep scanned source and credentials private, produce an explainable
and reproducible policy decision, fail closed when required evidence is missing,
and prevent one project from reading another project's results.

## Primary trust boundaries

1. Browsers and API clients are untrusted. Authentication, CSRF validation,
   project RBAC, rate limits, and request-size limits apply at the dashboard.
2. Imported repositories and uploaded files are hostile. Standard static
   scanners run in the standard worker. The opt-in Deep worker streams the
   admitted source snapshot into a disposable CodeQL child container. That
   child is unprivileged, read-only, offline, resource-bounded, and receives no
   application credentials or host filesystem mounts.
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
| Deep scan lacks a pinned CodeQL image, trusted suites, or registered Deep worker | Startup/readiness and request admission fail; incomplete CodeQL evidence produces `ERROR`, never `ALLOWED`. |
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
  checks. Its private key and the OAuth-token encryption key live only in the
  dashboard and a separate `github-broker` service; production workers refuse
  both. A worker asks the broker for a clone token for one in-flight run and
  receives a read-only installation token scoped to that run's repository, or
  the recorded requester's OAuth token, and asks it to complete that run's own
  check run. A compromised worker can still read the source of a run it is
  processing.
- TOTP MFA is implemented. Self-service password recovery, WebAuthn, and
  enterprise identity federation still require a reviewed identity workflow.
- The active scanner set does not test infrastructure configuration, container
  images, live endpoints, or malware signatures. CodeQL cannot substitute for
  these removed categories. Optional YARA matches indicate a signature match,
  not confirmed malware.
- The trusted Deep-worker supervisor has database and local Docker-daemon
  access so it can launch disposable CodeQL children. The hostile source and
  CodeQL process do not receive those capabilities, but compromise of the
  Python supervisor would cross this boundary. A production design should
  replace the socket with a narrow job broker.
- Evidence signing runs in a separate signer process; workers never hold the
  key. Each production service connects to PostgreSQL with its own login
  (`aegis_worker`, `aegis_signer`, `aegis_github_broker`, `aegis_notifier`)
  holding only the table and column grants it needs, and refuses to start under
  a superuser, role-creating, RLS-bypassing, or schema-owning login. Database
  triggers make finished scan runs and their artifact records immutable, so
  even the worker login cannot reopen a finished run. A compromised worker can
  still misreport a run that is in progress, and its login can still write
  scan state for any in-flight run, because PostgreSQL grants are per column,
  not per row.
- Scanner subprocesses run as the worker's user. The worker marks itself
  non-dumpable (`PR_SET_DUMPABLE=0`) so they cannot read its environment or
  memory through `/proc`, but there is no per-job OS sandbox (gVisor, seccomp,
  or a separate user per job). A scanner exploit runs with the worker's
  database login and network access.
- A database superuser can disable triggers or replace both audit data and the
  application-held audit key. Aegis exports chain-head checkpoints
  (`/api/admin/audit/checkpoint`) that detect truncation and rollback when
  verified later, but only if they are stored where that superuser cannot
  rewrite them and the audit key is held separately. Export structured events
  to an independently administered SIEM before relying on them for regulated
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
