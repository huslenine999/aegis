# Founding customer pilot

## Customer profile

The initial offer is for a software company with 20–200 developers using GitHub
that wants enforceable release gates and exportable security evidence. The pilot
is one isolated Aegis deployment for one customer; shared multi-tenant hosting
is explicitly excluded.

## Thirty-day scope

Week 1 covers architecture review, isolated deployment, GitHub App installation,
policy configuration, and one repository. Weeks 2–3 cover pull-request scans,
triage, suppression review, and two additional repositories. Week 4 covers
metrics, evidence export, operational handoff, and the conversion decision.

Included deliverables are the deployment, three repositories, PR check runs,
weekly triage, signed evidence, administrator training, and a final value report.
Excluded items are compliance certification, penetration testing, 24×7 response,
custom scanner development, and production access to customer secrets.

## Success criteria

- Deployment completed within one business day after prerequisites are ready.
- At least 90% of configured pull requests receive a completed Aegis check.
- No scanner operational error is reported as a clean decision.
- Every blocked release has reproducible evidence and an identified rule.
- False-positive disposition and accepted-risk suppressions are recorded.
- The customer names an economic buyer and agrees whether to convert by day 30.

Use `docs/PILOT_RUNBOOK.md` as the operating checklist and scorecard. A pilot is
not complete until every required metric has an owner, source, baseline, and
day-30 result; anecdotes alone are not a conversion decision.

## Commercial experiment

Quote a fixed paid pilot rather than free consulting. Record the proposed price,
discount, implementation hours, support hours, customer value estimate, and
conversion outcome. Do not publish a permanent price until at least three paid
pilots establish delivery cost and willingness to pay.

## Required customer inputs

GitHub organization approval, an isolated host or approved cloud account,
named technical owner, named security contact, data-retention choice, three
repositories, and written authorization for scanning are required before work
starts.
