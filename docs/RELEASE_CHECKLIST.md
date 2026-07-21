# Aegis Release Checklist

Use this checklist before tagging a public release.

Start by generating the consolidated repository-side evidence:

```bash
python scripts/pilot_readiness.py --output pilot-readiness.json
```

On a clean Docker-capable rehearsal host with ports 80 and 443 available, run
`python scripts/pilot_readiness.py --docker-smoke --output pilot-rehearsal.json`.
The Docker mode uses a unique Compose project, rehearses database recovery and
service restart, then removes only its temporary containers and volumes.

1. Update versions in `pyproject.toml`, `package.json`, and `CHANGELOG.md`.
2. Run `python -m py_compile app/main.py app/cli.py app/worker.py app/scanners.py app/demo_lab.py`.
3. Run `pytest -q --timeout=60 --timeout-method=thread`.
4. Run `python app/cli.py scan . --config aegis.yml --sarif --json`.
5. Build the Python wheel with `python -m pip wheel . --no-deps -w dist`.
6. Smoke-test editable install with `pip install -e ".[dev]"` and `aegis doctor --json`.
7. Run `npm run test:e2e` and confirm the real-browser authentication and axe
   accessibility checks pass, including first-run setup and role enforcement.
8. Populate `.env` from `.env.production.example`, build the container image,
   and verify `/health`, `/ready`, and authenticated `/metrics`.
9. Run `docker compose up --build`, verify Caddy serves a valid TLS chain, trigger
   an operator scan, and confirm another non-admin user cannot access its WebSocket.
10. Connect a test GitHub account, import public and private repositories, and
    verify quick, standard, deep, cancel, retry, and new-finding behavior.
11. Restart dashboard and worker containers and verify PostgreSQL users/WAF state,
    Redis job state, and generated reports remain available.
12. Update the immutable Aegis SHA in the approval and published-Action E2E
   workflows, then run the E2E workflow manually.
13. Tag the release only after CI is green, then verify the `Release Build`
    workflow accepts the tag/version match and produces the reviewed wheel.
14. Verify backup and restore procedures for PostgreSQL, Redis, report, and Caddy volumes.
15. Run `python -m mypy`; expand the checked security-core modules as legacy
    orchestration code is incrementally typed.
16. Confirm every non-strict scan summary used as release evidence has an empty
    `operational_failures` list.
17. Verify the wheel against `SHA256SUMS` and confirm the published container has
    BuildKit SBOM and provenance attestations before promoting the tag.
18. Verify a signed `scan-manifest.json` with the deployment's pinned Ed25519
    public key and reject any manifest whose artifact hashes do not match.
19. Run `python scripts/run_security_benchmark.py --output benchmark-results.json`
    and require 100% recall with 0% false positives across the versioned 18-case
    corpus. Review the corpus hash and category-level results in the output.
20. Verify the tagged wheel's GitHub/Sigstore provenance with
    `gh attestation verify <wheel> --repo <owner/repository>`.
21. Confirm the `production-release` environment approval was performed by an
    independent reviewer, then verify the GHCR digest-bound attestation.
22. Review every suppression: require an owner, ticket, future expiry, and
    CODEOWNER approval; reject releases with expired or invalid exceptions.
