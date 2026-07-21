# Aegis security whitepaper

## Scope and supported deployment

Aegis is a self-hosted DevSecOps release-gating service. The supported paid
topology is one customer per isolated deployment. The current release is not a
public multi-tenant SaaS platform and is not represented as bank-grade or as a
compliance certification.

## Control design

Users authenticate with server-side sessions or keyed, scoped API tokens.
Passwords use PBKDF2-HMAC-SHA-256 with 600,000 iterations. Optional TOTP MFA has
encrypted secrets, one-time recovery codes, replay counters, login lockout and
recent-authentication requirements for sensitive actions. Roles and project
memberships are tenant-scoped, and database triggers reject inconsistent tenant
relationships.

GitHub webhooks use HMAC-SHA-256 and persisted delivery identifiers. GitHub App
automation uses short-lived installation tokens, scans the pull-request head
revision, and writes a check-run conclusion. Scanner failures remain operational
errors rather than clean decisions.

Untrusted source is rejected when it contains symlinks, special files, excessive
files or excessive bytes. Deep execution requires an explicitly isolated worker
and bounded container runtime. Scanner subprocesses receive a credential-filtered
environment. SMTP and notification delivery credentials are isolated in a
notifier worker.

Artifacts are stored under tenant/project/run namespaces with recorded SHA-256
digests. Evidence manifests use Ed25519 signatures and require a pinned external
public key for verification. Audit events use a per-tenant HMAC chain and
database update/delete guards. An independently administered SIEM and immutable
object store remain required for regulated non-repudiation.

## Secure development and release

CI runs compilation, linting, type checks, Python tests, browser accessibility
tests and the versioned security corpus. Actions are pinned to immutable commits.
Tagged wheels have checksums and GitHub/Sigstore provenance; containers publish
BuildKit SBOM and provenance metadata. NIST SSDF and OWASP ASVS self-assessments
are maintained in the repository.

## Residual risk

The scanner worker still needs database access and GitHub App credentials in the
standard topology. The target regulated architecture replaces it with a
credential broker and disposable source leases. Enterprise OIDC, WebAuthn,
customer-specific KMS keys, immutable object storage, durable SIEM delivery,
cross-region recovery and independent penetration testing are not complete.

Security claims must be validated against the deployed configuration and current
release evidence. Repository controls do not prove customer cloud settings,
staffing, legal compliance, operational response or auditor conclusions.
