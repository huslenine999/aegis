"""BAC research tests must not start the production stack or touch its data."""

import pytest


@pytest.fixture(scope="session", autouse=True)
def application_lifespan():
    yield


@pytest.fixture(scope="session", autouse=True)
def preserve_checked_in_reports():
    yield


@pytest.fixture(autouse=True)
def mock_rq_and_redis():
    yield
