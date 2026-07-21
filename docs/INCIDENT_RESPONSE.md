# Incident response plan

This runbook follows the Govern, Identify, Protect, Detect, Respond, and Recover
model. The incident commander owns decisions; the technical lead contains and
eradicates; communications handles customers and regulators; legal counsel
determines notification obligations. Assign named people before production.

## Severity

| Severity | Example | Initial response target |
| --- | --- | --- |
| SEV-1 | Confirmed customer data or signing-key compromise; active cross-tenant access | 30 minutes |
| SEV-2 | Exploitable production vulnerability or material service compromise | 2 hours |
| SEV-3 | Contained security weakness without known exploitation | 1 business day |
| SEV-4 | Hardening issue or unsuccessful attack | 3 business days |

## Procedure

1. Open an incident record with UTC timeline, reporter, affected assets, and
   current severity. Preserve logs, audit-chain heads, images, configuration
   hashes, and volatile evidence before changing systems.
2. Contain using scoped credential revocation, installation suspension, worker
   isolation, network denial, or deployment removal. Never destroy evidence to
   make containment faster.
3. Determine affected tenants, source revisions, credentials, artifacts, data
   categories, and earliest known compromise. Verify the audit chain and compare
   it with externally exported events.
4. Eradicate the root cause, rotate exposed credentials, rebuild from reviewed
   source, and validate with the release benchmark and targeted regression tests.
5. Recover in stages. Monitor authentication, token use, GitHub installations,
   queue depth, scanner failures, outbound delivery, and audit verification.
6. Communicate only confirmed facts, impact, containment, required customer
   action, and next update time. Legal review is required for breach notices.
7. Complete a blameless root-cause review within five business days and track
   corrective actions to evidence-backed closure.

Run a tabletop exercise every six months and after major architecture changes.
Exercise scenarios must include a GitHub App key leak, hostile repository escape,
database compromise, and signing-key misuse.
