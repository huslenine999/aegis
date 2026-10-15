# Broken-access-control research protocol

New to Aegis? Start with [the thesis team beginner walkthrough](THESIS_TEAM_GUIDE.md).
Commands, freezing, signatures, dashboard import, and evidence review are in
[BAC_OPERATIONS.md](BAC_OPERATIONS.md). This file describes the study only.

## Research question

> How closely do black-box access-control detection methods match an
> instrumented oracle, and which kinds of API behaviour make each method fail?

A real tester only sees HTTP responses. The owned lab can also see the truth:
it plants a synthetic private marker in every record and exposes researcher-only
state snapshots. We use that privileged view as the **reference (oracle)**, and
we measure methods a real tester could use against it.

| Method | Sees | Predicts a violation when a denied request… |
| --- | --- | --- |
| `enhanced` (oracle) | Response, private markers, before/after state | exposes the target's private marker or changes its state |
| `http-status-only` | Status code | receives a 2xx status |
| `differential` | Attacker response and the owner's response to the same request | returns exactly the owner's status and body (Autorize-style “bypassed”) |
| `content-leak` | Attacker response and the owner's response to the same request | repeats any string (≥ 8 characters, excluding the resource ID and actor name) from the owner's view of the target record, at any status |

The oracle's verdicts must agree with the seeded labels. That agreement checks
that the lab and oracle are correct; it is not itself a finding. The black-box
methods are what the study evaluates.

## Bug patterns in the lab

The lab is one small FastAPI app with four actors (Alice, Bob, admin, guest),
six synthetic documents, and a fixed and a vulnerable variant. Its nine routes
cover five mistake patterns: a missing check (read, update, delete, admin
routes), a masked response (preview), an unfiltered collection (list), a leak in
an error body (export), and a write before the check (rename).

| Operation | Route | Seeded mistake (vulnerable) | OWASP API 2023 |
| --- | --- | --- | --- |
| `read` | `GET /documents/{id}` | Ownership check skipped for authenticated users | API1 BOLA |
| `preview` | `GET /documents/{id}/preview` | Same; fixed variant returns a masked 200 (ID and title only) | API1 / API3 BOPLA |
| `list` | `GET /documents` | Collection is not filtered by owner; fixed variant returns 200 with only permitted records | API1 BOLA |
| `export` | `GET /documents/{id}/export` | Denial is correct (403), but the error body includes the record | API1 / API3 |
| `update` | `PATCH /documents/{id}` | Ownership check skipped | API1 BOLA |
| `rename` | `PUT /documents/{id}/title` | Write happens before the ownership check; the response is still 403 | API1 BOLA |
| `delete` | `DELETE /documents/{id}` | Ownership check skipped | API1 BOLA |
| `admin-read` | `GET /admin/users` | Role check skipped | API5 BFLA |
| `admin-disable` | `POST /admin/users/{id}/disable` | Role check skipped | API5 BFLA |

These patterns put pressure on the black-box methods in both directions. A masked
or filtered 200 is a trap for status-only (false positive). A leak or write that
still returns 403 is a trap for status-only and differential (false negative).
A mutation whose effect is invisible in the response is a trap for every method
without state access. Guests stay masked or denied in both variants, so guest
cases are negative controls, not seeded bugs.

## Corpus

The default matrix is `rules/bac-matrix-v2.json` (corpus `aegis-bac-v2`): 40
cases, 20 development and 20 evaluation. Every case records its ID, split,
operation, actor, resource, and intended permission. The matrix contains no
secrets, URLs, response expectations, or vulnerability labels. Custom matrices
may select or reorder cases and assign splits, but may not relabel permissions or
introduce other actors, resources, or routes.

| Actor | Read, preview, list, export | Update, rename, delete | Admin functions |
| --- | --- | --- | --- |
| Alice or Bob | Own documents and public documents | Own documents only | Denied |
| Admin | All documents | All documents | Allowed |
| Guest | Public documents only | Denied | Denied |

`expected_allowed` means permission to obtain the protected data or perform the
action, not permission to receive a particular HTTP status. Private development
records end in `-1`; private evaluation records end in `-2`. Both splits share
the same routes, so the evaluation split guards against tuning on specific
records, not against tuning on the bug patterns.

**Ground truth.** In vulnerable mode, an authenticated actor's denied case is a
seeded violation. Allowed cases and guest-denied controls are never violations.
The detectors receive the permission intent and observations, never the mode or
the label.

## Procedure

For each case the runner:

1. resets the lab and takes a researcher snapshot;
2. for a denied case, confirms the owner's (or admin's) identity, performs the
   same request as that user, checks it worked, and resets again (this owner
   response is the black-box methods' reference);
3. confirms the test actor's identity, sends the probe, and takes a second snapshot;
4. classifies the observation with the oracle, then derives all black-box
   predictions from the same recorded trace;
5. requires a matching server-side audit event for the probe.

Failed sessions, redirects, rate limits, server errors, missing snapshot
resources, timeouts, and allowed controls that did not work are
**inconclusive**. Black-box methods inherit inconclusive outcomes, and also
become inconclusive when the owner reference is missing.

## Measurements

For each method, report TP, FP, TN, FN, precision `TP/(TP+FP)`, recall
`TP/(TP+FN)`, false-positive rate `FP/(FP+TN)`, accuracy `(TP+TN)/scored`, and
execution coverage `scored/attempted`, overall and by mode, operation, split,
and repetition. Undefined rates are `null`/blank, never 0 or 100%. Inconclusive
cases are reported separately and never counted as safe.

The most useful table for the thesis is **by operation**: it shows which bug
pattern defeats which method. Explain every disagreement with the oracle from
the saved evidence (`case-results.csv` plus `evidence.json`).

## Threats to validity and limitations

Collected here once. Keep them in the thesis limitations section.

- **Deterministic lab.** Lab state is in memory and reset per case, so repeated
  trials should be identical. Repetitions only test runner stability. They are
  not independent samples and support no significance test.
- **Predictable within the lab.** Each method's behaviour on each pattern follows
  from its definition. The in-lab benchmark *characterizes* methods against
  known patterns; it does not estimate real-world accuracy. External targets
  (below) are needed for that claim.
- **Designed corpus.** One small app, nine routes, and bug patterns chosen by
  the team. Evaluation records share routes with development records.
- **Privileged oracle.** Markers and snapshots exist only because we own the
  lab. A real black-box tester has neither.
- **Same-trace comparison.** Every method is scored on the oracle run's traces.
  None is an independently implemented or independently timed tool, and none
  represents a specific commercial product.
- **Black-box simplifications.** `differential` uses exact equality, not a
  similarity threshold. `content-leak` uses a fixed length cut-off and treats
  every repeated value as sensitive (the masked title is a deliberate example).
  Discuss threshold sensitivity rather than tuning on the evaluation split.
- **Evidence trust.** A valid signature proves the files are unchanged under the
  selected key. It does not prove findings are correct, who ran the
  experiment, or which code executed. See BAC_OPERATIONS.md.
- **Scope.** Local synthetic lab only. No real personal data, AI detector, cloud
  deployment evaluation, or claims about other Aegis scanners.

## External validation (planned, not implemented)

To test whether the in-lab failure modes appear in independently written code,
run the same black-box methods against deliberately vulnerable APIs with
documented BOLA issues, such as OWASP crAPI or VAmPI, deployed locally in
containers. Ground truth there comes from the projects' documented
vulnerabilities, not from an oracle. Each target needs its own permission
matrix and route mapping.

The current runner deliberately refuses any target except its own loopback lab.
Adding external targets requires a separate safety review: local containers
only, no public exposure, synthetic accounts only, and written team approval.
Do not point the runner at third-party systems.

## Team responsibilities

- **Red team:** owns the bug-pattern catalog, permission scenarios, and probe
  realism; proposes new patterns before the freeze.
- **Forensics:** owns evidence correlation, redaction, integrity checks, and
  the case-study reconstructions of each method's failures.
- **Cloud security:** owns reproducible containerized deployment of the lab and
  the external targets, environment records, resets, and network isolation of
  vulnerable services.

Run probes only against the owned ephemeral lab. AI-generated code and text
need human validation and disclosure under the university's academic rules.
