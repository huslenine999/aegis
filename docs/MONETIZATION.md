# Aegis monetization playbook

## Positioning

Aegis should sell one outcome to one buyer first:

> Private-by-default release security for small engineering teams that need a defensible deployment decision without buying a large AppSec platform.

The product already has the core proof for that promise: project workspaces,
policy gates, scan history, new-finding comparison, GitHub import, team roles,
notifications, and exportable evidence. Lead with those outcomes. Treat the
individual scanner integrations as implementation detail.

## Offer ladder

| Offer | Recommended price | Purpose |
| --- | ---: | --- |
| Community | $0 | Self-hosted CLI, GitHub Action, local reports, and open-source adoption |
| Founding pilot | $299 / workspace / month | Guided deployment, up to 10 repositories, policy tuning, monthly review, and priority support |
| Security partner | Custom | Private deployment architecture, evidence workflows, identity roadmap, and advisory support |

The founding price is a sales offer, not an automated entitlement in the
current codebase. Do not add payment collection until the first few pilots have
validated repository limits, scan volume, support load, and retention costs.

## First customer profile

Target 10–80 person SaaS and software teams that:

- deploy frequently but have no dedicated AppSec engineer;
- need security evidence for customers, procurement, or an upcoming audit;
- use GitHub and can run a small private deployment;
- are uncomfortable sending source code to a third-party scanner; and
- have a concrete release or customer-security deadline within 30 days.

Avoid selling to large enterprises first. Their SSO, legal, procurement, and
multi-tenant requirements are not yet productized.

## Sales motion

1. Offer a 30-minute “release gate review” using one real repository.
2. Install Aegis and run one standard scan in the prospect’s environment.
3. Turn the result into a short before/after report: blockers, remediation path,
   and evidence they can share.
4. Charge for the pilot only when there is a named deadline and success metric.
5. Convert to a monthly workspace subscription after the second release.

The success metric should be business-shaped: “every production release has a
recorded security decision within 10 minutes,” not “we ran more scanners.”

## What must be built before automated SaaS billing

- tenant-scoped object storage for reports and scan artifacts;
- GitHub App with fine-grained permissions and pull-request checks/comments;
- MFA, password reset, and enterprise identity federation;
- usage and entitlement tracking for workspaces, repositories, scan volume, and
  retention;
- billing provider integration with a real cancellation path;
- support and incident-response workflow; and
- a hosted deployment with backups, isolation, load testing, and a published
  security/trust page.

Until those exist, sell a controlled self-hosted pilot with a written scope and
manual invoicing. This keeps the promise honest and lets customer evidence fund
the next product investments.

## 30-day execution plan

- Week 1: publish `/welcome`, add a pilot CTA, and create a one-page pilot
  checklist.
- Week 2: run five repository reviews with target teams; record time-to-first
  useful decision and repeated objections.
- Week 3: fix the top onboarding failure, then publish one anonymized case study
  with permission.
- Week 4: close the first paid pilot and document the recurring support work
  before automating it.

The public page uses a GitHub issue URL by default for lead capture. Set
`AEGIS_COMMERCIAL_CONTACT_URL` to a calendaring, form, or sales URL before a
public launch.
