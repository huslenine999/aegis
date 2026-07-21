# Controlled pilot runbook

This runbook turns the founding offer into one repeatable customer workflow:

> Connect an approved repository, produce an explainable release decision, and
> export evidence that an independent reviewer can verify.

The supported topology is one isolated Aegis deployment for one customer. Do
not combine customer data or present this pilot as shared multi-tenant SaaS.

## Entry gate

Do not schedule customer onboarding until all of the following are true:

- `python scripts/pilot_readiness.py --output .aegis/pilot-readiness.json`
  passes;
- the Docker rehearsal has passed on the intended deployment class;
- a backup has been restored into a separate rehearsal project;
- the deployment public key used for evidence verification is pinned outside
  the Aegis database;
- the customer supplies written scan authorization, a technical owner, a
  security contact, a retention choice, and one initial repository; and
- known limitations in `docs/HARDENING.md` are included in the pilot scope.

## First useful decision

Target a useful result within 90 minutes after prerequisites are available:

1. deploy the isolated stack and complete administrator setup;
2. create one project and connect the approved repository;
3. configure one release policy and run a Standard scan;
4. classify the result as allowed, blocked, or operational error;
5. assign every blocker to an owner or a time-bounded suppression review; and
6. export the report bundle and verify `scan-manifest.json` with the pinned
   Ed25519 public key.

An operational error is never counted as a clean decision. If the first scan
cannot produce complete required evidence, record the failed tool and stop the
release workflow until it is repaired or explicitly removed from policy.

## Thirty-day cadence

### Week 1: prove the path

- Complete the first useful decision.
- Record setup time, scan duration, queue time, and every manual intervention.
- Confirm that a viewer cannot mutate projects and cannot access another
  project's scan stream or artifacts.

### Week 2: prove repeatability

- Add up to two more approved repositories.
- Enable the GitHub pull-request check on one repository.
- Run one safe and one intentionally blocked test change.
- Review every false-positive claim with the rule, source line, disposition,
  approver, ticket, and expiry.

### Week 3: prove operations

- Restart dashboard, worker, notifier, PostgreSQL, and Redis and complete a scan.
- Exercise cancellation, retry, scanner failure, and notification failure.
- Create and restore a backup in an isolated rehearsal project.
- Verify one evidence bundle from a machine that does not hold the signing key.

### Week 4: decide

- Review the scorecard with the technical owner and economic buyer.
- Document support hours, product defects, policy changes, and avoided manual work.
- Choose convert, extend with named exit criteria, or stop and export customer data.

## Required scorecard

| Metric | Source | Pilot target |
| --- | --- | ---: |
| Time from prerequisites to first useful decision | onboarding log | <= 1 business day |
| Pull requests receiving a terminal Aegis check | GitHub checks | >= 90% |
| Operational errors reported as clean | manifests and scan history | 0 |
| Blocked decisions with reproducible evidence and owner | evidence review | 100% |
| Median Standard scan duration | scan history | customer-agreed |
| Findings accepted without owner, ticket, and expiry | suppression report | 0 |
| Evidence bundles verified with the pinned key | verification log | 100% sample |
| Backup restorations completed successfully | rehearsal log | >= 1 |
| Aegis-related support time | delivery log | recorded weekly |

Record a baseline, weekly value, day-30 value, owner, and explanatory note for
each metric. Do not manufacture missing telemetry; mark it unavailable and make
collection part of the next decision.

## Stop conditions

Pause scanning and notify the customer when source or credentials cross an
unapproved boundary, tenant/project authorization fails, evidence integrity
verification fails, a required scanner silently degrades, backup recovery is
unreliable, or the worker runtime may be compromised. Follow
`docs/INCIDENT_RESPONSE.md` before resuming.

## External work that repository code cannot complete

The founder must recruit and contract pilot customers, obtain written scanning
authorization, provision customer-approved infrastructure, engage an independent
penetration tester, and make the commercial conversion decision. Store signed
contracts, assessor reports, customer credentials, and private findings outside
the repository.
