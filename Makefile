PYTHON := $(if $(wildcard venv/bin/python),venv/bin/python,python3)
UV ?= uv
COVERAGE_MODULES := --cov=app.observability --cov=app.preflight --cov=app.rate_limit --cov=app.scan_engine --cov=app.security_middleware --cov=app.iac_scanner

.PHONY: verify verify-fast lock lock-check lint types test e2e

verify: lock-check lint types test e2e
	git diff --check

verify-fast: lint test
	git diff --check

lock:
	$(UV) lock
	$(UV) export --locked --no-dev --extra scanner --format requirements-txt --no-emit-project --output-file requirements.txt
	$(UV) export --locked --all-extras --format requirements-txt --no-emit-project --output-file requirements-dev.txt

lock-check:
	$(UV) lock --check

lint:
	$(PYTHON) -m ruff check app policy_engine.py tests

types:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q --timeout=60 --timeout-method=thread $(COVERAGE_MODULES) --cov-report=term-missing

e2e:
	npm run test:e2e
