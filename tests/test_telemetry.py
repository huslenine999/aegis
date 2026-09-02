import json
from collections import defaultdict
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
import app.main as app_main
import app.database as database
import app.observability as observability

@pytest.fixture
def client():
    yield TestClient(app_main.app)

def test_stream_telemetry_headers(client):
    with client.stream("GET", "/stream-telemetry") as response:
        assert response.status_code == 200
        # Header check case-insensitivity
        ct = response.headers.get('content-type', '') or response.headers.get('Content-Type', '')
        assert ct.startswith('text/event-stream')

def test_stream_telemetry_fallback_payload(client):
    with client.stream("GET", "/stream-telemetry") as response:
        first_event = None
        for line in response.iter_lines():
            if line:
                decoded = line.decode('utf-8') if isinstance(line, bytes) else line
                if decoded.startswith("data: "):
                    first_event = decoded
                    break
                    
        assert first_event is not None
        assert first_event.startswith("data: ")
        # Extract json payload
        payload_str = first_event[len("data: "):].strip()
        payload = json.loads(payload_str)
        
        assert "cpu" in payload
        assert "memory" in payload
        assert "latency" in payload
        assert "logs" in payload
        assert isinstance(payload["cpu"], (int, float))
        assert isinstance(payload["memory"], (int, float))
        assert isinstance(payload["latency"], (int, float))
        assert isinstance(payload["logs"], list)

def test_stream_telemetry_active_sandbox(client):
    mock_stats = {"cpu": 45.5, "memory": 52.1}
    
    # 1. Test clean logs (no CPU/latency spikes)
    mock_logs_clean = [
        '172.17.0.1 - - [27/May/2026 12:45:56] "GET /user?name=admin HTTP/1.1" 200 -'
    ]
    with patch("app.routes.demo_scan_routes.get_active_sandbox_container", return_value="aegis-sandbox-container-test"), \
         patch("app.routes.demo_scan_routes.get_sandbox_stats", return_value=mock_stats), \
         patch("app.routes.demo_scan_routes.get_sandbox_logs", return_value=mock_logs_clean):
         
        with client.stream("GET", "/stream-telemetry") as response:
            first_event = None
            for line in response.iter_lines():
                if line:
                    decoded = line.decode('utf-8') if isinstance(line, bytes) else line
                    if decoded.startswith("data: "):
                        first_event = decoded
                        break
                        
            assert first_event is not None
            payload = json.loads(first_event[len("data: "):].strip())
            
            # CPU/Mem match stats (within fluctuation limit)
            assert abs(payload["cpu"] - 45.5) <= 1.0
            assert abs(payload["memory"] - 52.1) <= 1.0
            assert payload["latency"] <= 10.0
            assert len(payload["logs"]) == 1
            assert "[PACKET] INBOUND TCP" in payload["logs"][0]["text"]
            assert "GET /user" in payload["logs"][0]["text"]

    # 2. Test exploit logs (telemetry should NOT spike)
    mock_logs_exploit = [
        '172.17.0.1 - - [27/May/2026 12:45:58] "GET /ping?host=127.0.0.1;+cat+/etc/passwd HTTP/1.1" 403 -'
    ]
    with patch("app.routes.demo_scan_routes.get_active_sandbox_container", return_value="aegis-sandbox-container-test"), \
         patch("app.routes.demo_scan_routes.get_sandbox_stats", return_value=mock_stats), \
         patch("app.routes.demo_scan_routes.get_sandbox_logs", return_value=mock_logs_exploit):
         
         with client.stream("GET", "/stream-telemetry") as response:
             first_event = None
             for line in response.iter_lines():
                 if line:
                     decoded = line.decode('utf-8') if isinstance(line, bytes) else line
                     if decoded.startswith("data: "):
                         first_event = decoded
                         break
                         
             assert first_event is not None
             payload = json.loads(first_event[len("data: "):].strip())
             
             # Telemetry should NOT spike
             assert abs(payload["cpu"] - 45.5) <= 1.0
             assert payload["latency"] <= 10.0
             assert len(payload["logs"]) == 1
             assert "GET /ping" in payload["logs"][0]["text"]


def test_job_sandbox_lookup_does_not_fall_back_to_global_container(monkeypatch):
    class JobStore:
        def __init__(self):
            self.values = {}

        def hget(self, name, key):
            return self.values.get((name, key))

    store = JobStore()
    store.values[("job:authorized", "sandbox_container_id")] = b"aegis-sandbox-container-authorized"
    from app.routes import demo_scan_routes

    monkeypatch.setattr(demo_scan_routes, "redis_client", store)

    assert (
        demo_scan_routes._job_sandbox_container("authorized")
        == "aegis-sandbox-container-authorized"
    )
    assert demo_scan_routes._job_sandbox_container("other") is None


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
