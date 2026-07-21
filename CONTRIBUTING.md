# Contributing

Create changes from a short-lived branch and keep security decisions,
operational failures, and report formats backward compatible unless the release
notes explicitly describe a migration.

Install and verify the development environment:

```bash
python3 -m venv venv
./venv/bin/python -m pip install -e ".[dev,scanner]"
npm ci
npx playwright install chromium
make verify
```

Use `make verify-fast` while iterating when browser coverage is unchanged. The
full `make verify` target runs linting, type checks, Python tests, Playwright and
axe checks, and whitespace validation.

New scanners must return a structured tool status, distinguish findings from
operational failures, write deterministic JSON, and include tests for clean,
blocked, unavailable, invalid-output, and timeout behavior. New project data or
artifacts must be authorized through project membership and have a deletion and
retention path.

Never add live secrets, private repository contents, generated reports, local
databases, or backup archives to commits.
