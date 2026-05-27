import json
import re
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
import app.main as app_main

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
    with patch("app.main.get_active_sandbox_container", return_value="aegis-sandbox-container-test"), \
         patch("app.main.get_sandbox_stats", return_value=mock_stats), \
         patch("app.main.get_sandbox_logs", return_value=mock_logs_clean):
         
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
    with patch("app.main.get_active_sandbox_container", return_value="aegis-sandbox-container-test"), \
         patch("app.main.get_sandbox_stats", return_value=mock_stats), \
         patch("app.main.get_sandbox_logs", return_value=mock_logs_exploit):
         
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
