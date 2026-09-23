from collections import defaultdict

import app.database as database
import app.observability as observability


def test_metrics_use_route_templates_and_one_unmatched_bucket():
    route = type("Route", (), {"path": "/api/projects/{project_id}"})()
    assert observability._metric_route({"path": "/api/projects/1", "route": route}) == "/api/projects/{project_id}"
    assert observability._metric_route({"path": "/attacker/one"}) == "/unmatched"
    assert observability._metric_route({"path": "/attacker/two"}) == "/unmatched"

    observability._requests = defaultdict(int)
    observability._latency_sum = defaultdict(float)
    observability._latency_count = defaultdict(int)
    observability._latency_buckets = defaultdict(int)

    assert observability.render_metrics().count('path="/unmatched"') == 0


def test_operational_metrics_are_shared_and_exposed(monkeypatch):
    store = database.InMemoryRedis()
    monkeypatch.setattr(database, "redis_client", store)
    monkeypatch.setattr(
        observability,
        "_operational_metrics",
        {name: 0.0 for name in observability._OPERATIONAL_METRICS},
    )

    observability.record_scan_queue_age(2.5)
    observability.record_worker_failure()
    observability.record_worker_failure()
    observability.record_notification_failure()
    observability.record_audit_integrity_failure()
    observability.record_artifact_integrity_failure()

    rendered = observability.render_metrics()
    assert "aegis_scan_queue_age_seconds 2.500000" in rendered
    assert "aegis_worker_failures_total 2.000000" in rendered
    assert "aegis_notification_failures_total 1.000000" in rendered
    assert "aegis_audit_integrity_failures_total 1.000000" in rendered
    assert "aegis_artifact_integrity_failures_total 1.000000" in rendered
    assert "# TYPE aegis_worker_failures_total counter" in rendered


def test_operational_metrics_ignore_invalid_queue_age_and_support_legacy_redis(monkeypatch):
    class LegacyRedis:
        def __init__(self):
            self.values = {}

        def hget(self, name, key):
            return self.values.get((name, key))

        def hset(self, name, key, value):
            self.values[(name, key)] = str(value).encode()

    store = LegacyRedis()
    monkeypatch.setattr(database, "redis_client", store)
    monkeypatch.setattr(
        observability,
        "_operational_metrics",
        {name: 0.0 for name in observability._OPERATIONAL_METRICS},
    )

    observability.record_scan_queue_age(-1.0)
    observability.record_scan_queue_age(float("nan"))
    observability.record_worker_failure()

    assert observability.render_metrics().count("aegis_scan_queue_age_seconds 0.000000") == 1
    assert "aegis_worker_failures_total 1.000000" in observability.render_metrics()


def test_operational_metrics_tolerate_redis_errors(monkeypatch):
    class BrokenRedis:
        def hget(self, name, key):
            raise ValueError("unavailable")

        def hset(self, name, key, value):
            raise OSError("unavailable")

    monkeypatch.setattr(database, "redis_client", BrokenRedis())
    monkeypatch.setattr(
        observability,
        "_operational_metrics",
        {name: 0.0 for name in observability._OPERATIONAL_METRICS},
    )

    observability.record_scan_queue_age(1.0)
    observability.record_worker_failure()

    assert "aegis_scan_queue_age_seconds 1.000000" in observability.render_metrics()
