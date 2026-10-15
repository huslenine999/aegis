# Aegis — Engineering Handoff

Date: 2026-10-15
Branch: `main`. Version 2.5.0 (tagged locally as `v2.5.0`; see `CHANGELOG.md`). MIT.
Author: Khuslen Gan-Ochir.

## What Aegis is

Private, explainable release-security gates for small engineering teams. One
workflow: scan a repository → evaluate against a versioned policy → allow /
block / error decision with an explanation → durable findings with owners and
due dates → Ed25519-signed evidence manifests verifiable offline.

Ships three ways:

1. CLI (`aegis scan . --strict`) — exit codes 0=allow, 1=blocked, 2=error
2. GitHub Action (`action.yml`) — fail-closed PR gate, installs from
   `requirements.txt` (hash-pinned `uv export`)
3. Self-hosted workbench — FastAPI dashboard + PostgreSQL + Redis/RQ workers +
   notifier + Caddy (`docker-compose.yml`)

Scanners: Ruff, Semgrep (Aegis rules for Python, JS/TS, Go, Java), OSV
prioritized with CISA KEV and EPSS, secret detection, optional YARA. Deep scans add
an offline, pinned CodeQL container on a dedicated worker (`make codeql-setup`).
Checkov, Safety, ClamAV, Trivy, and the custom DAST probes were retired; see
`docs/SCANNER_MIGRATION_PLAN.md`.

The repository also hosts a Broken Access Control (BAC) research lab
(`aegis bac ...`) used for the bachelor's thesis. Research material lives in
`docs/research/`.

## Repository map

```
app/
  main.py              App factory
  web_common.py        Shared web state: access-control deps, templates, JSON body parsing
  routes/              Domain routers (auth, projects, github, admin, artifacts, demo/scan)
  cli.py               CLI facade; cli_config.py, cli_reports.py, cli_runner.py, cli_stack.py
  scan_engine.py       Shared job payload, event sinks, semgrep/exclude helpers
  worker.py            RQ scan pipeline (sandbox -> scanners -> policy -> evidence)
  codeql_scanner.py    Deep-scan CodeQL runner
  findings.py          Finding normalization, durable fingerprints, lifecycle
  finding_queries.py   Filtered, tenant-scoped finding queries
  database.py          Raw-SQL adapter over SQLite (dev) / PostgreSQL (prod), migrations
  bac*.py              BAC research lab, imports, benchmark, reports
policy_engine.py       Standalone verdict engine; fail-closed decision at
                       evaluate_policy_results() (importable without package context)
rules/                 Semgrep YAML + YARA signature packs
tests/                 Unit, integration (Compose lifecycle), BAC, Playwright e2e
docs/                  Operations, security, and deployment documentation
docs/research/         Thesis outline, team guide, BAC protocol, capstone review
```

## Current verification status (2026-10-15)

```
pytest:      1015 passed, 3 skipped (Compose x2, PostgreSQL opt-in)
e2e:         33 passed (Playwright, Chromium)
coverage:    88.8% over the gated modules
ruff:        clean
mypy:        clean (configured modules)
```

Run everything: `make verify` (adds e2e; needs `npm ci` + `npx playwright install chromium` once). Quick loop: `make verify-fast`.

## Open work

1. **Thesis evaluation.** Confirm the reframed question (black-box methods vs.
   instrumented oracle) with the professor, freeze, run the final BAC
   evaluation, and fill the `RESULTS_PENDING` / `CONCLUSION_PENDING` markers in
   `docs/research/THESIS_OUTLINE.md`. External targets (crAPI, VAmPI) are
   planned, not implemented; the runner still accepts only its own loopback lab.
   Training runs and passing tests are not final results.
2. **Re-pin CI trust anchors after review.** The approval gate scans with
   trusted revision `ed6b080`, whose `aegis.yml` predates
   `app/finding_queries.py`, so it blocks until re-pinned to a reviewed
   commit. `action-e2e.yml` pins `b2f00d3`, from before the `--no-docker` fix.
   Push first, review, then update both SHAs (`docs/RELEASE_CHECKLIST.md`
   step 12).
3. **First PyPI release.** `v2.5.0` is tagged locally. Register the PyPI
   Trusted Publisher (see `docs/RELEASE_CHECKLIST.md`), push `main` and the
   tag, and confirm `pipx install aegis-security-console` works.
4. **Deep-scan assurance.** Authenticated Deep browser flow and Docker-level
   adversarial isolation checks. The held-out CodeQL benchmark is done
   (`benchmarks/results/`); a larger fresh corpus is the next step.
5. **Per-job OS sandbox.** The last open piece of F06. Signing key, GitHub
   credentials, and database roles are split out (signer, `github-broker`,
   per-service PostgreSQL logins), but scanner subprocesses still run as the
   worker's user. Next step: gVisor or a seccomp profile per job, tested on the
   target host. See the 2026-10-16 follow-up table in
   `docs/research/CAPSTONE_REVIEW.md`.
6. **Large modules.** `app/database.py` and `app/worker.py` are the next split
   candidates if merge conflicts become a problem.

## Environment gotchas

- macOS/zsh; Makefile recipes use `/bin/sh` (no process substitution).
- `uv export` writes its own output path into the file header — never byte-compare two exports from different paths (see `lock-check` for the normalized header filter).
- Dynamic mock patching on `app.cli`: submodules look up attributes via `sys.modules.get("app.cli")` during scan execution so `unittest.mock.patch("app.cli.<func>")` takes effect.
