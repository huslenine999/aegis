# Bachelor's thesis outline

Working title: **Evaluating Black-Box Detection of Broken Object-Level Authorization Against an Instrumented Oracle**

Aegis is the tool used to run the study, not the subject of the thesis. The
outline follows the usual order: abstract, introduction, background and related
work, method, evaluation, and conclusion. It assumes one coordinated team study.
Confirm with the professor whether each student needs a separate manuscript and
which university template to use.

## The thesis in plain English

A real security tester cannot see inside an API. They send requests as
different users and judge the responses. We built an API where we *can* see
inside: every private record carries a hidden marker, and we can snapshot the
database before and after each request. That gives us the true answer for every
test. We then measure how often three practical, black-box ways of judging
responses agree with the truth, and which kinds of API behaviour fool each one.

**Main research question:** How closely do black-box access-control detection
methods (HTTP-status-only, owner/attacker response differential, and content-leak
matching) agree with an instrumented oracle, and which API behaviours cause
each method's false positives and false negatives?

**Working hypotheses, not results:**

- H1: Status-only produces false positives on masked or filtered 2xx responses,
  and false negatives when a leak or write happens behind a 403.
- H2: Response differential avoids masked-response false positives but misses
  leaks and writes that change the status code.
- H3: No response-only method detects a write that is invisible in the response.

The software exists. The final experiment, verified literature review, and
numerical results are pending. Development runs and passing software tests must
not be presented as the final evaluation.

## 0. Abstract

Write this last. Include:

1. Context: broken access control (OWASP API1 BOLA, API5 BFLA) lets users obtain
   data or perform actions outside their permissions.
2. Problem: testers judge authorization from HTTP responses alone, and responses
   can mislead in both directions.
3. Method: an owned lab with nine routes covering five authorization bug patterns, an instrumented
   oracle as ground truth, and three black-box methods scored on the same traces.
4. Results: **[RESULTS_PENDING: per-method errors, rates, coverage, the
   by-operation failure table, and the number of completed observations.]**
5. Conclusion: **[CONCLUSION_PENDING: which behaviours defeat which methods,
   within this lab and any external targets actually tested.]**

Suggested keywords: broken object-level authorization, BOLA, API security,
authorization testing, differential testing, test oracle.

## 1. Introduction

### 1.1 Research context

- Why APIs need rules controlling access to data and actions.
- Authentication (who you are) versus authorization (what you may do).
- Prevalence or impact claims only from verified sources (for example, the
  OWASP API Security Top 10 2023 ranking). Do not invent statistics.

### 1.2 Problem statement

- A 200 response to a forbidden request is not proof of a leak (masked preview,
  filtered list).
- A 403 response is not proof of safety (record in the error body, write before
  the check).
- A tester without database access cannot see some effects at all.

### 1.3 Objective and question

- State the main question above.
- Objective: characterize each black-box method's errors against known truth,
  by bug pattern.
- Supporting objective: preserve evidence so every error can be reconstructed
  and explained.

### 1.4 Contributions

1. Five authorization bug patterns (missing check, masked response, unfiltered
   collection, leak in an error body, write before the check) implemented across
   nine routes of an owned lab with fixed and vulnerable variants.
2. An instrumented oracle (private markers plus state snapshots) used as ground
   truth, with its agreement with the seeded labels reported.
3. A same-trace comparison of three black-box methods, with a per-pattern
   failure analysis.
4. Reproducible, signed evidence and a frozen study definition.

These are evaluation contributions. Do not claim to have invented authorization
testing or differential testing.

### 1.5 Scope and organization

- Scope: the owned local lab, synthetic data, object-level and function-level
  authorization. External targets only if actually completed (see 4.8).
- Exclusions: arbitrary websites, real personal data, AI detectors, claims about
  other Aegis scanners.
- Short description of Chapters 2 to 5.

## 2. Background and Related Work

### 2.1 Authorization concepts

- Actors, resources, operations, intended permissions; an example permission
  table for Alice, Bob, admin, and guest.

### 2.2 Broken access control in APIs

- OWASP API Security Top 10 2023: API1 BOLA, API3 BOPLA, API5 BFLA.
- Horizontal (another user's object) and vertical (admin function) violations.
- Permission to receive a response versus permission to obtain its content.

### 2.3 Test oracles

- The oracle problem in software testing: knowing the correct answer for a test.
- Why instrumentation gives a stronger oracle than response inspection, and why
  it is only available when you own the system.

### 2.4 Related authorization-testing work

Verify each source before citing. Record its method, required knowledge or
instrumentation, evaluation targets, metrics, and stated limitations.

- **RESTler security checkers.** Atlidakis, Godefroid, and Polishchuk,
  “Checking Security Properties of Cloud Service REST APIs,” ICST 2020. Includes
  a namespace rule checker for one user reaching another user's resources.
- **BOLABuster.** Palo Alto Networks Unit 42, “Harnessing LLMs for Automating
  BOLA Detection” (August 2024). Generates two-user tests from an OpenAPI spec;
  reports real CVEs but no precision or recall.
- **Petri-net BOLA detection.** “Automated broken object-level authorization
  attack detection in REST APIs through OpenAPI to colored Petri nets
  transformation,” International Journal of Information Security 24, article 83
  (2025). Detects attacks from server logs; reports accuracy above 95% on one
  deliberately vulnerable application.
- **Practitioner tools.** Burp Suite extensions such as Autorize and AuthMatrix
  replay requests as another user and compare responses. Our `differential`
  method follows that idea; check the tools' documentation before describing them.

The evaluation gap the thesis can address: existing work rarely reports
per-pattern false positives and false negatives against a known ground truth.
State this only after the literature review supports it.

### 2.5 Evidence and reproducibility

- Recording requests, responses, snapshots, and server events.
- What signatures and hashes establish (integrity) and what they do not
  (correctness, execution, identity).

### 2.6 Position of this thesis

- A controlled characterization study, not a new scanner.
- Do not present any of the three methods as representative of a specific
  commercial tool.

## 3. Method

Describe the BAC research workflow only, not the rest of Aegis.

### 3.1 System overview

- Inputs: permission matrix, synthetic accounts, lab variant, settings.
- Processing: reset, identity confirmation, owner reference request, attacker
  probe, snapshots, oracle classification, black-box predictions.
- Outputs: per-case results, metrics, signed evidence.

### 3.2 Lab and bug patterns

- Four actors, six documents, nine routes.
- The bug-pattern table from BAC_RESEARCH.md, with an OWASP category and the
  rationale for each pattern.
- Fixed versus vulnerable variants; guest cases as negative controls.

### 3.3 Oracle

- Reads and previews: the response is the target record with its synthetic
  private marker. Lists and exports: the marker appears anywhere in the response.
- Updates and renames: the requested title appears in post-request state.
- Deletes: the record is gone. Admin operations: admin marker returned, or the
  user is disabled.
- An effect on a denied case is a violation whatever the status code.
- Oracle agreement with the seeded labels is a validity check, not a finding.

### 3.4 Black-box methods

- Status-only: denied and 2xx.
- Differential: denied and the attacker response exactly equals the owner's
  response to the same request.
- Content-leak: denied and the attacker response repeats a non-trivial value from
  the owner's view of the target record, at any status.
- All three use only HTTP responses; explain what each cannot see.

### 3.5 Evidence preservation

- IDs, traces, snapshots, correlated server events, redaction, signed inventories.

## 4. Evaluation

The experiment below is a plan until the final artifacts are collected.

### 4.1 Environment and controls

- Record source revision, OS, Python and dependency versions, matrix digest,
  module fingerprints, and command settings.
- Freeze the study definition after development decisions are final.
- Preserve failed attempts; disclose any change prompted by evaluation results
  and freeze again.

### 4.2 Corpus and sample size

- 40 scenarios: 20 development, 20 evaluation (`rules/bac-matrix-v2.json`).
- Final run: 20 evaluation scenarios × 2 variants × 3 repetitions = 120
  attempts. Report 20 scenarios, 40 variant/scenario pairs, and 120 attempts
  separately.
- The lab is deterministic: repetitions check stability only and are not
  independent samples.

### 4.3 Ground truth

- Seeded labels from intended permissions and the vulnerable variant.
- Oracle verdicts must match them; report any disagreement as a lab defect.

### 4.4 Measurements

- TP, FP, TN, FN, precision, recall, false-positive rate, accuracy, execution
  coverage. Undefined rates stay undefined. Inconclusive outcomes are reported
  separately.
- Main table: per method, by operation.

### 4.5 Implementation verification

- Relevant unit, integration, and live-lab tests, cited only with recorded results.
- Signature and hash checks under the stated trust configuration.

### 4.6 Results

**[RESULTS_PENDING: all numbers must come from the final artifacts.]**

1. Dataset table: scenarios, pairs, attempts, completed, inconclusive.
2. Method table: confusion counts and rates for the oracle and the three
   black-box methods.
3. Failure table: method × operation, marking each FP and FN.
4. Case studies, reconstructed from evidence:
   - `eval-alice-cross-preview`: masked 200 versus real leak.
   - `eval-alice-cross-list`: filtered list versus unfiltered list.
   - `eval-alice-cross-export`: record leaked inside a 403 body.
   - `eval-bob-cross-rename`: write before the check, response 403.

### 4.7 Discussion and threats to validity

- Answer the question per method and per pattern.
- Explain that in-lab behaviour follows from each method's definition, so the
  lab characterizes methods rather than estimating real-world accuracy.
- Discuss threshold choices (`content-leak` length, exact-match `differential`).
- Copy the limitations list from BAC_RESEARCH.md.

### 4.8 External validation (if completed)

- Run the black-box methods against locally deployed, deliberately vulnerable
  APIs (OWASP crAPI, VAmPI) using their documented vulnerabilities as truth.
- Requires the safety review in BAC_RESEARCH.md. If not completed, move this to
  future work and say so plainly.

## 5. Conclusion

### 5.1 Answer to the research question

**[CONCLUSION_PENDING: summarize measured results and coverage.]** Report mixed
or negative results honestly.

### 5.2 Contributions and limitations

- Summarize the pattern catalog, oracle, comparison, and evidence workflow.
- State the corpus, oracle, and same-trace limits.

### 5.3 Future work

- External targets (if not completed), similarity-based differential testing,
  more patterns (mass assignment, nested resources, method override), and
  comparison with manual testers or real tools under a separate protocol.

## References and appendices

Use the university's citation style after verifying each source. Useful
appendices: permission matrix, bug-pattern rationale, frozen definition,
environment record, commands, result tables, and selected redacted evidence.
Never include real credentials or private signing keys.

## Writing order and team ownership

1. Confirm title, question, and scope with the professor.
2. Draft Chapters 1 and 2 from verified sources, then Chapter 3 from the code.
3. Agree on Chapter 4's methods, then freeze and run the final experiment.
4. Verify artifacts; write results, discussion, and Chapter 5.
5. Write the abstract last.

- **Red team:** bug-pattern catalog, seeded-bug rationale, probe behaviour (3.2, 4.6).
- **Forensics:** oracle and evidence chain, case-study reconstructions (3.3, 3.5, 4.6).
- **Cloud security:** containerized, isolated deployment of the lab and external
  targets; environment records (4.1, 4.8).
- **All:** literature review, label checking, interpretation, editing.

AI assistance must follow the university's rules. Every member must understand
and verify the submitted work.

Project references: [research protocol](BAC_RESEARCH.md),
[operations](BAC_OPERATIONS.md), and [beginner team guide](THESIS_TEAM_GUIDE.md).
