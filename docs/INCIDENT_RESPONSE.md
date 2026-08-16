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

## Phase-specific containment notes

- If a database disclosure may include legacy API-token rows, immediately
  disable/revoke those rows, rotate the token pepper, issue replacement tokens,
  and review `last_used_at`, audit events, and access logs. Migration 20 is the
  fail-closed control for unclassifiable legacy rows; Migration 21 binds new
  GitHub OAuth transactions to browser sessions. Pepper rotation remains a
  separate incident-response action.
- If scanner output causes worker disk pressure, stop the affected workers,
  preserve the run directory and scanner logs, prevent new hostile scans, and
  inspect every report file before cleanup. The file-writing sink should already
  discard reports that exceed the configured byte budget.
- If a notification destination is suspected of reaching an internal or shared
  address range, disable the channel, preserve its encrypted configuration and
  delivery records, review outbound logs, and require a fresh global-address
  validation before re-enabling it.
- If an artifact metadata row contains a storage key outside the derived
  tenant/project/run namespace, stop artifact downloads, preserve the database
  and object-store metadata, and verify the affected tenant and run scope before
  restoring service.
