# Aegis for the thesis team: a beginner walkthrough

Read this together, then try the exercise on one laptop. Allow about 30–45
minutes after the software is installed. You do not need to understand the
whole codebase first.

## 1. What is Aegis?

Aegis is our security workbench. Its normal scanner workflow checks source
code and dependencies and stores security findings and reports.

For this thesis, we use a separate feature called the **BAC research lab**.
BAC means **broken access control**: a user can read data or perform an action
they are not allowed to. The lab uses fake users and documents on your own
computer. It starts automatically for a test and stops afterward.

We are studying this question:

> How closely do black-box ways of judging API responses match the true answer,
> and which kinds of API behaviour fool each one?

The lab knows the true answer because it can look inside itself (hidden markers
in private records, and database snapshots before and after each request). We
call that the **oracle**. A real tester can only see responses, so we measure
three response-only methods against the oracle.

Aegis is the tool. Our thesis is the study: define the tests, collect evidence,
measure results, explain mistakes, and state the limits. We are not evaluating
all of Aegis's scanners or an AI detector.

## 2. Understand one example

Alice and Bob each own a private document. Bob must not receive the private
content of Alice's document.

| What Bob receives from a forbidden preview | HTTP status | What this tells us |
| --- | --- | --- |
| Only a masked ID/title, without private content | 200 | No private-content violation observed |
| Alice's actual private content | 200 | A private-content violation occurred |
| An access-denied response, without private content | 403 | No private-content violation observed |

HTTP `200` means the request got a successful response. It does not prove that
private content was exposed. HTTP `403` alone does not prove that nothing
leaked either. We must inspect the returned content and, for edits or deletion,
the actual before/after state.

The three black-box methods, all scored on the same recorded requests:

- **HTTP-status-only:** a forbidden request that got a `2xx` is a violation.
- **Differential:** a forbidden request that got exactly the same response as
  the owner got is a violation.
- **Content-leak:** a forbidden request whose response repeats text from the
  owner's view of that record is a violation, whatever the status code.

The oracle (shown as `enhanced` in reports) checks the hidden marker or the
before/after state. None of these is another company's scanner.

## 3. Words you will see

- **Actor:** the account making the request: Alice, Bob, admin, or guest.
- **Resource:** the document or user account the actor tries to access.
- **Permission matrix:** a list saying who may perform each action.
- **Case:** one actor/action/resource scenario from that list.
- **Ground truth:** the known answer, established from the lab's rules and
  deliberately introduced bugs. The oracle must agree with it.
- **Oracle:** the lab's inside view (markers and snapshots) used to check answers.
- **Black-box method:** a way of judging a response that a real tester could use.
- **Evidence:** the request, response, before/after state, and server events.
- **False positive:** a reported violation that did not actually occur.
- **False negative:** a real violation that the method missed.
- **Inconclusive:** the test could not establish an outcome. It does not mean safe.

## 4. The five bug patterns

| Pattern | Route | What goes wrong in the vulnerable version |
| --- | --- | --- |
| Missing check | read, update, delete, admin routes | No ownership or role check |
| Masked response | preview | (Fixed version) returns 200 with only ID and title |
| Unfiltered collection | list | Everyone's documents are listed |
| Leak in an error | export | Says 403, but the error body contains the record |
| Write before check | rename | Saves the change, then says 403 |

Before the exercise, guess which black-box method each pattern will fool. Check
your guesses in step C.

## 5. Get the right software

Ask the team lead for the source copy containing `app/bac.py` and
`rules/bac-matrix-v2.json`. An older GitHub checkout or installed package may
not include BAC. Do not assume that the version number alone identifies the
right code.

You need Python 3.11 or later and `uv`, the tool this project uses to install and
run Python packages. If `uv` is missing, follow
[its installation guide](https://docs.astral.sh/uv/getting-started/installation/)
or ask the team lead for help. Open a terminal inside your Aegis folder. A terminal is
where you type the commands below; do not type the surrounding Markdown fences.

For a fresh, dedicated checkout, install the locked environment:

```sh
uv sync --locked
```

If the team already has a working environment, check with the team lead before
reinstalling or changing it. Never change an environment used by a frozen study
without recording that change.

Check that the BAC command exists:

```sh
uv run --locked aegis bac --help
```

It should list `run`, `benchmark`, and `freeze`. `uv run --locked` runs Aegis
using this project's environment and lock file. If `bac` is unknown, stop and
check the source copy or installation with the team lead.

Docker, Redis services, cloud accounts, and the full dashboard are not required
for this exercise. Do not run `aegis start` just to use the BAC lab.

## 6. Run your first exercise

Use only the built-in local lab. Do not test a university portal, public
website, or production application. Use no real personal records or credentials.

### A. Test the fixed version

```sh
uv run --locked aegis bac run --mode fixed --split development --output .aegis/team-training/fixed-v1
```

`fixed` selects the version with the seeded authorization bugs repaired.
`development` selects the 20 practice cases. `--output` says where to save the
report files. The lab starts and stops automatically.

A complete run should print `Aegis BAC run: allowed` and a manifest path. Here,
`allowed` means no violation was observed in these selected cases. It is not
a guarantee that every possible access-control rule is secure.

Open the saved report in your browser:

```sh
uv run --locked aegis report --dir .aegis/team-training/fixed-v1 --open
```

Alternatively, open `report.html` in that output folder, or read `report.md`.
`.aegis` is a hidden folder; your file manager may need hidden files enabled.

### B. Test the vulnerable version

```sh
uv run --locked aegis bac run --mode vulnerable --split development --output .aegis/team-training/vulnerable-v1
```

This version contains known authorization bugs. A complete run should print
`Aegis BAC run: blocked`. That is an expected result: a violation was found.
It does not mean the software failed to run.

Open its report using the same report command, changing the folder to
`.aegis/team-training/vulnerable-v1`.

Find `dev-bob-cross-preview` in both reports. In the current lab, both probes
return HTTP `200`. The fixed response omits the private content; the vulnerable
response includes it. Explain this difference aloud before continuing.

For a single `bac run`, exit code `0` means completed with no observed violation,
`1` means a violation was observed, and `2` means incomplete testing or an
operational error. If the output is incomplete, investigate; do not label it safe.

If you repeat A or B, choose new folders such as `fixed-v2` and `vulnerable-v2`.
Aegis refuses to replace a nonempty report folder. Preserve the old reports.

### C. Compare the methods

```sh
uv run --locked aegis bac benchmark --split development --repeats 1 --output .aegis/team-training/benchmarks
```

This runs both versions, then compares the oracle with the three black-box
methods. Each benchmark creates a new experiment
folder. Use the printed manifest path to locate its `summary` folder.

For a benchmark, `allowed`/exit code `0` means the oracle's completed
classifications match the seeded answers. The black-box methods can still make
mistakes; that is what we study. Exit code `1` means the oracle disagreed with
the seeded answers (a lab defect); `2` means incomplete
testing or an operational error. Neither result approves an application release.

There are 20 distinct practice scenarios. Testing each in both versions gives
40 version/scenario combinations and 40 attempts with one repetition. These
are not 40 independent bugs.

In `report.html`, look at the method comparison grouped by operation. Which
patterns produced false positives or false negatives for each method? Were your
guesses right?

## 7. Read the evidence and data

Start with `summary/report.html`, then inspect these files:

- `case-results.csv`: one row per attempt, including the known answer, the
  oracle, and each black-box method's prediction. Use it to explain a particular mistake.
- `metrics.csv`: correct detections, false alarms, missed bugs, and rates.
- `report.json`: the complete machine-readable report and measurements.
- `evidence.json`: recorded requests, responses, state snapshots, and case IDs.
- `server-events.json`: application events that can be matched to request IDs.
- `scan-manifest.json`: the signed inventory and hashes of the exported files.

An individual run has eight exported files. Only benchmark summaries add the
two CSV files. Preserve the full experiment folder, including its individual
fixed/vulnerable subruns, not just the summary.

Read precision as “how many reported bugs were real?” Read recall as “how many
known bugs were detected?” Always report unfinished cases and execution
coverage too. Blank CSV rates mean undefined, not zero or 100%.

For `dev-bob-cross-preview`, find the corresponding entry in `evidence.json`.
Inspect `evidence.probe`, its response body, and its `request_id`. Match that ID
to a server event. For an edit case, compare `evidence.before` and
`evidence.after` too. A status code or screenshot alone is not the full evidence.

Analyze copies of the CSVs. Editing signed originals breaks their integrity
check. `.aegis/` and root `output/` are ignored by Git: pushing code does not
back up your experiment data. Keep a separate team-approved backup.

## 8. Check that everyone understands

Each member should fill these in from their own training run:

- Case ID:
- Actor and resource:
- Intended permission: allowed or denied?
- Fixed outcome and supporting evidence:
- Vulnerable outcome and supporting evidence:
- HTTP-status-only, differential, and content-leak predictions, and why any is wrong:
- Probe request ID and matching server event:

Then answer: Why can two HTTP `200` responses have different security outcomes?
Why can a `403` still be a violation (see `dev-bob-cross-export` and
`dev-alice-cross-rename`)? Why does an inconclusive test not prove safety? Why
can no response-only method catch the rename bug?

## 9. Team responsibilities and the next step

- **Red teaming:** check permission scenarios and seeded bugs; review attack cases.
- **Forensics:** check event correlation, evidence completeness, redaction, and
  explain several cases from the saved records.
- **Cloud security:** containerized, isolated deployment of the lab and of
  external vulnerable APIs (OWASP crAPI, VAmPI); resets, version records, and
  reproducible runs.

This exercise is training, not the final thesis dataset. Next, agree on a
one-page study plan with your professor: the question, scenarios, comparison,
measurements, limitations, and each member's work. Independently check the
known answers before scoring the detector. Finish code and dependency decisions
before freezing the final evaluation. Do not invent outcomes or hide failures.

The built-in corpus has 20 development and 20 evaluation scenarios. A final
evaluation with three repetitions has 20 evaluation scenarios, 40
version/scenario combinations, and 120 attempts. Both splits use the same lab
implementations; they do not establish accuracy on independent real
applications.

Read [the research protocol](BAC_RESEARCH.md) for the study design and
[operations](BAC_OPERATIONS.md) for freezing, signatures, dashboard imports, and
evidence review. The published development signing
key supports local integrity checks only; a signature does not prove the
results are correct or identify a trusted researcher.

Safety limit: keep the vulnerable lab local and synthetic. Existing dependency
audit findings must be assessed before public deployment. This tutorial does
not provide production security approval.
