UV ?= uv
PYTHON := $(UV) run python
SECURITY_BOUNDARY_COVERAGE := --cov=app.observability --cov=app.preflight --cov=app.rate_limit --cov=app.scan_engine --cov=app.security_middleware --cov=app.iac_scanner --cov=app.artifact_storage --cov=app.reporting --cov=app.resource_budgets --cov=app.github_lifecycle

.PHONY: verify verify-fast lock lock-check export-requirements lint types test e2e clean clean

verify: lock-check lint types test e2e
	git diff --check

verify-fast: lint test
	git diff --check

lock:
	$(UV) lock
	$(UV) export --locked --no-dev --extra scanner --format requirements-txt --no-emit-project --output-file requirements.txt

export-requirements:
	$(UV) export --locked --no-dev --extra scanner --format requirements-txt --no-emit-project --output-file requirements.txt

lock-check:
	$(UV) lock --check
	@mkdir -p .uv-lock-check
	@$(UV) export --locked --no-dev --extra scanner --format requirements-txt --no-emit-project --output-file .uv-lock-check/requirements.txt --quiet
	@grep -v '^#' requirements.txt > .uv-lock-check/current.txt
	@grep -v '^#' .uv-lock-check/requirements.txt > .uv-lock-check/fresh.txt
	@if ! cmp -s .uv-lock-check/current.txt .uv-lock-check/fresh.txt; then \
		echo "requirements.txt is out of date with uv.lock."; \
		echo "Run 'make lock' and commit the regenerated requirements.txt."; \
		exit 1; \
	fi
	@rm -rf .uv-lock-check
	@echo "lock check ok"

lint:
	$(PYTHON) -m ruff check app policy_engine.py tests

types:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q --timeout=60 --timeout-method=thread $(SECURITY_BOUNDARY_COVERAGE) --cov-report=term-missing

e2e:
	npm run test:e2e

clean:
	rm -rf build dist .coverage coverage.xml htmlcov \
		.pytest_cache .ruff_cache .mypy_cache .uv-lock-check \
		test-results playwright-report \
		aegis_security_console.egg-info
	find . -depth -type d -name __pycache__ -not -path "./venv/*" -not -path "./.venv/*" -exec rm -rf {} +
	find . -depth -type f -name .DS_Store -not -path "./venv/*" -not -path "./.venv/*" -delete
