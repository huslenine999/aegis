# Service level template

This template is non-contractual until customer, service boundaries, support
hours, exclusions, remedies, and legal terms are completed and signed.

Suggested pilot targets are 99.5% monthly dashboard availability, acknowledgement
of SEV-1 incidents within 30 minutes during agreed support hours, SEV-2 within two
hours, and customer updates at least every four hours for active SEV-1 incidents.
Scanner completion time is measured separately from dashboard availability and
must have repository-size and external-provider exclusions.

Exclude customer infrastructure failures, unauthorized configuration, GitHub or
cloud-provider outages, scheduled maintenance, force majeure, abusive workloads,
and unsupported versions. Define service credits only after monitoring can
produce independent monthly measurements.

Track dashboard availability, queue delay, scan duration by preset and repository
size, operational-error rate, notification latency, recovery-point achievement,
and recovery-time achievement. A target without an alert, owner, runbook, and
measurement source is not an SLA.
