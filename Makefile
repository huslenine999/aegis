UV ?= uv
PYTHON := $(UV) run python
SECURITY_BOUNDARY_COVERAGE := --cov=app.observability --cov=app.preflight --cov=app.rate_limit --cov=app.scan_engine --cov=app.security_middleware --cov=app.iac_scanner --cov=app.artifact_storage --cov=app.reporting --cov=app.resource_budgets --cov=app.github_lifecycle

.PHONY: verify verify-fast lock lock-check lint types test e2e

verify: lock-check lint types test e2e
	git diff --check

verify-fast: lint test
	git diff --check

lock:
	$(UV) lock
	$(UV) export --locked --no-dev --extra scanner --format requirements-txt --no-emit-project --output-file requirements.txt

lock-check:
	$(UV) lock --check

lint:
	$(PYTHON) -m ruff check app policy_engine.py tests

types:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q --timeout=60 --timeout-method=thread $(SECURITY_BOUNDARY_COVERAGE) --cov-report=term-missing

e2e:
	npm run test:e2e
