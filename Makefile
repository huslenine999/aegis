PYTHON := $(if $(wildcard venv/bin/python),venv/bin/python,python3)

.PHONY: verify verify-fast lint types test e2e

verify: lint types test e2e
	git diff --check

verify-fast: lint test
	git diff --check

lint:
	$(PYTHON) -m ruff check app policy_engine.py tests

types:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q --timeout=60 --timeout-method=thread

e2e:
	npm run test:e2e
