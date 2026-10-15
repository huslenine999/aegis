# BAC research operations

How to run, freeze, verify, export, import, and review BAC experiments. The
research design, bug patterns, metrics, and limitations are in
[BAC_RESEARCH.md](BAC_RESEARCH.md).

## Run the experiment

Install Aegis in the normal project environment first. No new dependencies,
cloud account, Redis instance, or external scanner service is required for BAC
research. Commands start an owned ephemeral lab, use loopback only, and stop
the lab when the run ends. There is no target-URL option.

```sh
aegis bac run --mode fixed --split development --output ./output/bac-fixed
aegis bac run --mode vulnerable --split development --output ./output/bac-vulnerable
aegis bac benchmark --split evaluation --repeats 3 --output ./output/bac-benchmark
```

Use `--split all` to exercise the whole corpus. Repetitions must be between 1
and 20. Treat the printed output directory and manifest path as authoritative.
Benchmark runs create a unique experiment directory under the requested root;
individual fixed/vulnerable reports and the aggregate `summary` are separate.
Research exports refuse to replace an existing nonempty output directory.

The research run returns exit code 0 for completed tests with no observed
violation, 1 for observed violations, and 2 for an incomplete experiment.
An allowed control that fails to work is incomplete, not proof of security.

The benchmark uses different meanings: exit code 0 means completed oracle (`enhanced`)
classifications match the seeded labels; 1 means an oracle false positive or
false negative; 2 means an operational error or inconclusive case. A vulnerable
subrun is expected to find violations and return 1. That does not make its
benchmark trial fail. Black-box method misclassifications are reported, but
do not determine the benchmark exit code. Do not interpret a successful benchmark as
a deployment approval or a claim that the vulnerable app is safe.

## Freeze a final evaluation definition

After development decisions are finished, create a signed local definition
before the final evaluation. Freezing does not start a lab:

```sh
aegis bac freeze --split evaluation --repeats 3 --output ./.aegis/final-study
aegis bac benchmark --split evaluation --repeats 3 --protocol ./.aegis/final-study/study-protocol.json
```

For a custom corpus, pass the same `--matrix` to both commands. Split and
repetition defaults remain `evaluation` and 3; a frozen protocol does not
silently override the benchmark's requested inputs.

`study-protocol.json` preserves the complete validated matrix and its digest,
selected split, repetition count, runtime versions, and the existing five BAC
module fingerprints. It has a unique protocol ID and signed UTC timestamps.
The output must be new or empty; freezing never intentionally replaces existing
evidence. Omit `--output` for a unique directory under `.aegis/bac-protocols`.

`benchmark --protocol` verifies the signature against the **currently configured
research signing identity**, not a key selected from the file. Keep the same
`AEGIS_EVIDENCE_SIGNING_KEY` configuration between freezing and running. The
publicly known development identity is only a non-authoritative local check.
Use a researcher-controlled private key and independently archive the frozen
definition if signer authenticity matters; this feature does not rotate keys.

Before creating experiment output or starting the lab, the benchmark requires
an exact match of the matrix, split, repetitions, runtime versions, and module
hashes. Malformed or altered definitions, a different signer, or drift return
operational error 2. Strict matching also rejects harmless code or dependency
updates. If anything changes, disclose why and freeze a new definition in a
new directory; preserve the old one instead of editing it.

The checked definition is embedded in the summary's `report.json` as
`study_protocol.definition`, with `canonical_sha256` over its canonical JSON.
This is a canonical-document digest, not a hash of the original file's spacing.
The report is covered by the summary's signed inventory; editing the preserved
definition fails evidence verification. Markdown/HTML reports show its reference.
No extra files or fields are added to individual research exports, so dashboard
imports remain compatible. Benchmarks without `--protocol` still work and do
not claim a frozen definition.

This is a **preflight consistency check**, not formal preregistration, a trusted
timestamp, complete environment capture, monitoring for changes during execution,
or proof that the hashed code executed. It does not turn the evaluation split
into an independent application dataset. Record the source revision, environment,
development iterations, and academic study approval separately.

## Evidence artifacts and verification

The exported trace links case ID, actor, resource, request, response, timestamps,
before/after state, and corresponding probe application events. Match application
events using the run/case correlation fields. Request credentials and actual
token values are redacted before export. Keep all state and markers synthetic;
redaction is not a substitute for permission to collect real personal data.

Exports contain JSON, Markdown, HTML, the matrix, and a signed
`scan-manifest.json`. The benchmark also records the hash of each available
subrun manifest. Preserve the complete experiment directory, not only the
summary. Verify each subrun and the summary separately when handing evidence
to another researcher.

```sh
aegis verify-evidence ./output/bac-fixed/scan-manifest.json --trust-embedded-key
aegis verify-evidence /path/printed/by/benchmark/summary/scan-manifest.json --trust-embedded-key
```

`--trust-embedded-key` is a local integrity check only. The default development
key is not a trusted production identity. Use an independently pinned public
key for an authenticity claim. A valid signature proves that the signed bytes
and listed artifact hashes have not changed under the selected key. It does
not prove the findings are correct, establish who ran the experiment, or attest
the lab source code. These research manifests do not invent source-bound
attestation. Record the source revision and environment independently in the
thesis experiment log.

Reports record runtime versions and SHA-256 digests of the installed BAC
implementation modules. These identify the software used, but do not attest
execution of that code. Benchmark evidence and events also retain the trial
run ID, mode, and repetition so repeated case IDs cannot be confused.

## Thesis-ready comparison exports

Run the existing benchmark command; no extra export step is required:

```sh
aegis bac benchmark --split evaluation --repeats 3
```

The printed summary directory contains readable comparison and case-outcome
tables in `report.md` and `report.html`, plus two CSVs:

- `metrics.csv`: every method's confusion counts and rates, overall and for each
  mode, operation, split, and repetition. Rates are unrounded ratios, not
  percentages; blank cells mean undefined, matching JSON `null`.
- `case-results.csv`: one row per attempted observation, with the oracle and
  all three black-box predictions,
  seeded truth, HTTP status, duration, reason, and benchmark/trial/case identity.
  A failed trial's unavailable run ID stays blank, not a fabricated identifier.

`report.json` and the readable reports separate distinct scenario IDs, distinct
`(mode, case)` pairs, and attempted observations. With the default evaluation
split and three repetitions, these counts are 20, 40, and 120 respectively.
The 120 attempts are **not 120 independent vulnerability examples**. Repetition
tables describe repeatability, not statistical significance or generalization.

All summary measurements are recalculated from the paired result rows before
export. Readable tables show percentages and explicitly mark undefined rates.
CSV text that could be interpreted as a spreadsheet formula receives a leading
apostrophe; the redacted JSON remains the authoritative original value.
Both CSVs are hashed in the summary's signed manifest; editing either fails
evidence verification. Preserve and verify the full experiment, including its
subruns. Individual research exports remain eight files for dashboard import;
benchmark summaries are not accepted by that import workflow.

## Import a verified individual run into a project

The dashboard imports evidence; it never starts the vulnerable lab. Imports are
optional and disabled until the dashboard operator sets
`AEGIS_BAC_IMPORT_PUBLIC_KEY` to a URL-safe base64 Ed25519 public key obtained
independently from the researcher. Never choose a trust key from an uploaded
manifest. The private signing seed stays with the researcher, not the dashboard.
The published development signing identity is rejected in production.

To display the researcher's public key, run this in the same trusted environment
and with the same signing configuration used to produce the BAC report:

```sh
python -c 'from app.evidence import evidence_public_key; print(evidence_public_key()["public_key"])'
```

Set the dashboard variable before starting it. With Compose, add the public key
to the environment file used by Compose (`.env.local` for `aegis start`, or your
production environment file), then recreate the dashboard. An unset or invalid
key leaves the rest of Aegis working but returns HTTP 503 for imports. The
development key is suitable only for non-authoritative local experiments; a
researcher-controlled private signing key is needed for meaningful signer trust.
Existing `AEGIS_MAX_REQUEST_BYTES` and artifact byte budgets still apply. Raise
the request budget deliberately if the eight-file upload exceeds it; imports
do not silently relax that global protection.

1. Create an individual `aegis bac run` export, or select one fixed/vulnerable
   subrun directory from a benchmark, not its aggregate `summary` directory.
2. Open the intended project and choose **Overview → Import BAC research**.
   Project operator access and recent authentication are required.
3. Select all eight original files: `scan-manifest.json`, `report.json`,
   `matrix.json`, `findings.json`, `evidence.json`, `server-events.json`,
   `report.md`, and `report.html`. Upload those files directly, not a ZIP.
4. Review the research history entry and BAC-tagged findings. Use **Download
   evidence** for a ZIP containing the byte-exact originals. The HTML preview
   uses Aegis's sandboxed report viewer and may add display-only styling.

The import verifies the pinned signature, exact inventory, artifact hashes,
matrix/case coverage, and consistency between outcomes and exported observations.
That checks the bundle's integrity and internal consistency, not whether the
claimed experiment actually ran. Runtime evidence still has no source-bound
attestation and never approves a release or changes the latest source decision.
Research finding fingerprints include the corpus and permission scenario, not
the source finding namespace. Re-importing the same canonical signed manifest
into the same project returns the original run without duplicate occurrences.
Separate completed experiments add occurrences while preserving manual triage.

Incomplete experiments remain incomplete in history. Any independently confirmed
violations they contain are retained, but missing or failed cases never imply
security. No research import closes or reopens an existing finding; source
scans cannot auto-resolve BAC findings. Imports cannot be retried as source scans,
simulated as release-policy evidence, or turned into repository remediation tickets.
The stored `quick` preset is only legacy schema compatibility, not scan coverage.

Run metadata, finding occurrences, and artifact metadata commit together. If a
database commit fails after private files were published, a retry can adopt only
the same eight byte-identical files. Different files, missing files, extra files,
and symlink paths are never overwritten. S3 publication failures may leave
unreferenced private objects; this workflow does not delete remote objects or
change the existing evidence-retention policy.

The API is `POST /api/projects/{project_id}/bac-imports` with repeated multipart
`files` fields. It returns HTTP 201 for a new import or 200 for an existing one,
with `scan_run_id`, `imported`, and `research_only`. Invalid evidence returns
400; configured byte-budget violations return 413. Access failures use the
existing 401/403/404 project boundaries. The bounded history response includes
`latest_source_scan` independently, so many research imports cannot hide the
project's source-release context.

## Review cases and reconstruct their evidence

In project **Overview**, choose **Review cases** on an imported BAC run. Viewers
can review evidence too; operator access is needed only to import or change
manual triage. Every attempted case is shown, including allowed controls and
inconclusive cases. **No observed violation** describes the recorded experiment,
not a guarantee that the application is secure. Inconclusive means the test
could not establish an outcome.

Expand a case to inspect its intended permission, classification reason,
recorded identity confirmations, authorized baseline, probe request/response,
before/after state, and correlated server events. Keep the import's scan ID,
exported run ID, case ID, and any trial/repetition attribution together when
citing evidence. Missing evidence is displayed as missing, not reconstructed
or assumed successful. Links in the reviewer download the original artifacts.

From **Findings**, use **Review BAC case** to open the exact scenario in that
finding's latest observed run. This uses the occurrence's case ID and
actor/operation/resource, not the first case with a similar title. A later
experiment may rename cases without changing their durable finding identity.
The finding-detail API exposes this reference as `research_case` for BAC
findings only; it is `null` if no matching, same-project research occurrence
exists. The findings-list response is unchanged.

The reviewer reads the existing authorized scan and integrity-checked
`report.json` artifact. An unavailable or altered original report prevents
review; there is no fallback to the inline database copy. Changing projects or
closing the reviewer discards pending results. Viewing evidence does not alter
the signed artifacts, finding status, occurrence count, source decision, or
release eligibility. It does not launch a lab or accept benchmark summaries.

## Optional independent manual comparison

No manual testing results or timings are built into this project. If the thesis
needs that comparison, run it as a separate recorded study. A suitable protocol:

1. Freeze the permission matrix, lab revision, environment, and participant
   instructions. Prepare randomized opaque trial identifiers so participants
   do not learn the fixed/vulnerable labels.
2. Give each tester the same allowed scope, permission rules, synthetic actor
   accounts, and time budget. Do not give them oracle or black-box findings.
3. Start from reset data for every case. Record elapsed time, request evidence,
   conclusion, and any inability to finish. Decide in advance whether manual
   testers receive the instrumented snapshot; keep that access equal and
   disclose it. An uninstrumented tester cannot verify state identically.
4. Have a separate evaluator reveal the seeded labels and score the conclusions.
   Record disagreements and inconclusive cases. Keep raw worksheets.
5. State the number of testers, experience, trial order, tools, learning effects,
   and limitations. Do not generalize a three-student convenience sample to
   professional penetration testers.

Use this worksheet without prefilled outcomes:

| Opaque trial ID | Tester | Start/end time | Actor/operation/resource | Evidence file | Conclusion | Incomplete reason |
| --- | --- | --- | --- | --- | --- | --- |
| | | | | | | |
