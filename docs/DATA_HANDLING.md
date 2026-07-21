# Data handling schedule

This is an operational template, not legal advice or a signed data-processing
agreement.

Aegis processes repository source during scans, findings and evidence artifacts,
user identity and authorization data, GitHub installation metadata, encrypted
integration configuration, audit events, and operational telemetry. Customer
production data should not be intentionally submitted.

Default evidence retention is 30 days and is configurable per isolated customer
deployment. Queue results and temporary workspaces use shorter operational
retention. Source workspaces must be deleted after each job, including failure
paths. Backups inherit the agreed retention period and must expire through a
tested lifecycle policy.

Deletion requests require identity verification, scoped project and artifact
deletion, integration revocation, backup-expiry confirmation, and an audit event.
Cryptographic erasure requires customer-specific external storage keys, which
are not implemented by the local artifact backend.

The production subprocessor register must name the hosting provider, GitHub,
email or notification providers, monitoring/SIEM provider, support systems,
locations, purpose, data categories, and contractual transfer mechanism. Do not
publish a completed register until the actual production vendors are selected.
