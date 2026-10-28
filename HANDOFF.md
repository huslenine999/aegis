# Aegis — Engineering Handoff

Date: 2026-10-16
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
   notifier + evidence signer + GitHub credential broker + Caddy
   (`docker-compose.yml`; each service has its own PostgreSQL login)

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

## Current verification status (2026-10-26)

```
pytest:      1152 passed, 8 skipped (opt-in or root-only)
             includes Hypothesis fuzz tests and a 500-request API monkey test
PostgreSQL:  the full suite passes with AEGIS_TEST_POSTGRES_URL on PostgreSQL 16
             (Linux x86_64), including per-service login checks
e2e:         35 passed (Playwright, Chromium; also 35 with AEGIS_E2E_DEEP=1)
coverage:    89.4% over the gated modules
ruff:        clean
mypy:        clean (configured modules)
```

Deeper fuzzing: `AEGIS_FUZZ_EXAMPLES=5000 pytest tests/test_fuzz_inputs.py` and
`AEGIS_MONKEY_REQUESTS=20000 pytest tests/test_api_monkey.py` (add
`AEGIS_TEST_POSTGRES_URL` for an empty PostgreSQL database).

Run everything: `make verify` (adds e2e; needs `npm ci` + `npx playwright install chromium` once). Quick loop: `make verify-fast`.

## Open work

1. **Thesis evaluation.** Confirm the reframed question (black-box methods vs.
   instrumented oracle) with the professor, freeze, run the final BAC
   evaluation, and fill the `RESULTS_PENDING` / `CONCLUSION_PENDING` markers in
   `docs/research/THESIS_OUTLINE.md`. External targets (crAPI, VAmPI) are
   planned, not implemented; the runner still accepts only its own loopback lab.
   Training runs and passing tests are not final results.
2. **Drop the semgrep-bound dependency suppressions.** Both CI pins point at
   reviewed commit `bcca71d` (2026-10-28). `certifi` is upgraded. `mcp` 1.29.0
   (GHSA-84m7-p3x7-pcfv, GHSA-5h93-6whr-6q8j, GHSA-rwrf-2pqf-9j8j,
   GHSA-w4fh-qvv9-3v23) and `opentelemetry-api` 1.37.0 (GHSA-xcq7-p3pf-p88h)
   are suppressed in `aegis.yml` (`AEGIS-RISK-017` to `-021`, expiring
   2027-01-27) because semgrep pins both, even in 1.182.1. When a semgrep
   release allows `mcp>=1.30` and a fixed OpenTelemetry, upgrade and delete the
   entries. After any later pin change, update both SHAs and
   `tests/test_action.py` (`docs/RELEASE_CHECKLIST.md` step 12).
3. **First PyPI release.** `v2.5.0` is tagged locally. Register the PyPI
   Trusted Publisher (see `docs/RELEASE_CHECKLIST.md`), push `main` and the
   tag, and confirm `pipx install aegis-security-console` works.
4. **Deep-scan assurance.** On 2026-10-26 (Docker 29.9.2, Mac, image rebuilt
   as `aegis-codeql@sha256:cdb756b8…`) the Deep browser flow passed (35/35,
   twice), the isolation probes
   (`AEGIS_CODEQL_ISOLATION=1 pytest tests/integration/test_codeql_isolation.py`)
   passed, and `pilot_readiness.py --docker-smoke` passed, including backup,
   restore and restart. Re-run after image, engine, or launch-flag changes. The fresh v2 corpus
   and a pinned real-repository inventory are in `benchmarks/results/`. The
   remaining work is a second-reviewer triage and labels for the training
   labs.
5. **Per-job OS sandbox (F06).** Ruff, Semgrep and detect-secrets now run in an
   offline scanner container when `AEGIS_SANDBOX_SCANNERS=true` and
   `AEGIS_SCANNER_IMAGE` is set (`make scanner-setup`;
   `docs/research/SCANNER_SANDBOX_DESIGN.md`). Isolation probes:
   `AEGIS_SCANNER_ISOLATION=1 pytest tests/integration/test_scanner_isolation.py`
   (passed 2026-10-28, Docker 29.9.2, Mac). Open: only the Deep worker and CLI
   have the Docker socket, so standard Compose scans stay unsandboxed; the
   supervisor is still privileged; no gVisor/seccomp; record the image digest
   per tool; re-run the browser/Compose flow with the flag on.
6. **Large modules.** `app/database.py` and `app/worker.py` are the next split
   candidates if merge conflicts become a problem.
7. **Held-out v3 done (2026-10-28).** Semgrep caught 13/14 with 0 false alarms,
   CodeQL 9/14 (misses all Starlette), combined 14/14. Semgrep miss: Koa open
   redirect. v3 is now a regression set; measure further rule changes on a
   new corpus. See `benchmarks/results/README.md`.

## Environment gotchas

- macOS/zsh; Makefile recipes use `/bin/sh` (no process substitution).
- `uv export` writes its own output path into the file header — never byte-compare two exports from different paths (see `lock-check` for the normalized header filter).
- Dynamic mock patching on `app.cli`: submodules look up attributes via `sys.modules.get("app.cli")` during scan execution so `unittest.mock.patch("app.cli.<func>")` takes effect.
