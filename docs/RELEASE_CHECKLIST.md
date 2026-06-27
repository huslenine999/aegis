# Aegis Release Checklist

Use this checklist before tagging a public release.

1. Update versions in `pyproject.toml`, `package.json`, and `CHANGELOG.md`.
2. Run `python -m py_compile app/main.py app/cli.py app/worker.py app/scanners.py app/demo_lab.py`.
3. Run `pytest -q --timeout=60 --timeout-method=thread`.
4. Run `python app/cli.py scan . --config aegis.yml --sarif --json`.
5. Build the Python wheel with `python -m pip wheel . --no-deps -w dist`.
6. Smoke-test editable install with `pip install -e ".[dev]"` and `aegis doctor --json`.
7. Build the container image and verify `/health` returns `aegis-security-console`.
8. Run `docker compose up --build` and verify the dashboard reaches `http://127.0.0.1:5001`.
9. Update the immutable Aegis SHA in the approval and published-Action E2E
   workflows, then run the E2E workflow manually.
10. Tag the release and publish artifacts only after CI is green.
