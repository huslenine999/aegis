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
   Credentials are encrypted at rest and outbound webhook redirects are denied.

## Important abuse cases and controls

| Abuse case | Current control |
| --- | --- |
| Scanner crashes but project is approved | Worker and CLI share the policy contract; required tool failures produce an operational error. |
| Viewer reads another project's report | Run-scoped artifact APIs require project membership; legacy shared reports are administrator-only. |
| Disabled user keeps an old session | Opaque server-side sessions join the current active user and role and can be revoked. |
| Oversized body exhausts WAF memory | A body-size middleware runs before WAF request buffering. |
| Webhook targets an internal service | HTTPS/public-address validation, redirect denial, bounded timeout, and bounded retries. |
| Deep scan runs on the dashboard host | Deep evidence fails closed unless an isolated Docker and Trivy runtime is available. |
| Malicious regex blocks the service | WAF rules are administrator-only, length-bounded, and syntax validated; deployment monitoring remains required. |

## Residual risks

- The local artifact backend is suitable for a single controlled deployment,
  not an untrusted public multi-tenant service. Public operation should use an
  object store with per-tenant keys, encryption, quotas, and lifecycle rules.
- GitHub OAuth currently requests repository scope. A fine-grained GitHub App
  is preferred for organization-wide deployment and automated pull-request
  checks.
- MFA, password recovery, and enterprise identity federation are not yet
  implemented.
- The bundled DAST probes are intentionally narrow and Python-oriented; they do
  not replace a general web application scanner or penetration test.

Review this model whenever a scanner, integration, artifact backend,
authentication method, or network boundary changes.
