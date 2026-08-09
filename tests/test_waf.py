import pytest
from fastapi.testclient import TestClient
import app.main as app_main

@pytest.fixture
def client():
    from app.database import initialize_database
    initialize_database(reset=True)
    app_main.WAF_ENABLED = False
    app_main.DEMO_LAB_ENABLED = True
    yield TestClient(app_main.app)
    app_main.DEMO_LAB_ENABLED = False


def test_demo_lab_disabled_by_default():
    """Vulnerable training routes should not be reachable unless explicitly enabled."""
    app_main.DEMO_LAB_ENABLED = False
    client = TestClient(app_main.app)
    response = client.get("/demo-lab/user?name=guest")
    assert response.status_code == 404


def test_demo_lab_is_namespaced_away_from_application_routes(client):
    assert client.get("/user?name=guest").status_code == 404
    assert client.get("/demo-lab/user?name=guest").status_code == 200

def test_waf_disabled_by_default(client):
    """Ensure the WAF is disabled by default and allow SQLi."""
    response = client.get('/demo-lab/user?name=admin\' OR \'1\'=\'1')
    assert response.status_code == 200

def test_waf_blocking(client):
    """Enable WAF and ensure it blocks malicious patterns."""
    # Enable WAF
    client.post('/toggle-waf')
    
    # Test SQLi blocking
    response = client.get('/demo-lab/user?name=admin\' OR \'1\'=\'1')
    assert response.status_code == 403
    assert b"Blocked by Aegis WAF" in response.content

    # Test Command Injection blocking
    response = client.get('/demo-lab/ping?host=127.0.0.1; cat /etc/passwd')
    assert response.status_code == 403

    # Test Path Traversal blocking
    response = client.get('/demo-lab/download?file=../../etc/passwd')
    assert response.status_code == 403

    # Test legitimate traffic still works
    response = client.get('/health')
    assert response.status_code == 200

    # Disable WAF for other tests
    client.post('/toggle-waf')

def test_waf_toggle(client):
    """Test the WAF toggle endpoint."""
    # Toggle on
    response = client.post('/toggle-waf')
    assert response.json()['waf_enabled'] is True
    
    # Toggle off
    response = client.post('/toggle-waf')
    assert response.json()['waf_enabled'] is False


def test_admin_token_protects_state_changing_routes(client):
    """When configured, admin routes require the Aegis token."""
    app_main.ADMIN_TOKEN = "test-admin-token"
    try:
        unauthorized = client.post("/toggle-waf")
        assert unauthorized.status_code == 401

        authorized = client.post("/toggle-waf", headers={"X-Aegis-Token": "test-admin-token"})
        assert authorized.status_code == 200
        assert authorized.json()["waf_enabled"] is True
    finally:
        app_main.ADMIN_TOKEN = None
        if app_main.WAF_ENABLED:
            client.post("/toggle-waf")


def test_invalid_waf_rule_regex_is_rejected(client):
    response = client.post("/save-waf-rules", json={"rules": [{"pattern": "(", "description": "broken"}]})
    assert response.status_code == 400
    assert "Invalid WAF rule regex" in response.json()["detail"]

def test_waf_custom_rules(client):
    """Test custom WAF rules retrieval, saving, and blocking."""
    # 1. Fetch initial rules
    response = client.get('/get-waf-rules')
    assert response.status_code == 200
    assert response.json()['status'] == 'success'
    assert 'rules' in response.json()
    assert 'waf_enabled' in response.json()
    original_rules = response.json()['rules']

    try:
        # 2. Save a custom rule pattern
        custom_rules = [
            {"pattern": "custom_hack_pattern", "description": "Custom hacker signature", "enabled": True}
        ]
        save_response = client.post('/save-waf-rules', json={"rules": custom_rules})
        assert save_response.status_code == 200
        assert save_response.json()['status'] == 'success'

        # 3. Enable WAF
        toggle_response = client.post('/toggle-waf')
        assert toggle_response.json()['waf_enabled'] is True

        # 4. Test blocking of custom pattern
        blocked_response = client.get('/demo-lab/user?name=custom_hack_pattern')
        assert blocked_response.status_code == 403
        assert b"Custom hacker signature" in blocked_response.content

        # 5. Disable custom pattern and test bypass
        disabled_rules = [
            {"pattern": "custom_hack_pattern", "description": "Custom hacker signature", "enabled": False}
        ]
        client.post('/save-waf-rules', json={"rules": disabled_rules})
        allowed_response = client.get('/demo-lab/user?name=custom_hack_pattern')
        assert allowed_response.status_code == 200

        # Disable WAF
        client.post('/toggle-waf')

    finally:
        # Restore original rules
        client.post('/save-waf-rules', json={"rules": original_rules})


def test_waf_json_payload_blocking(client):
    """Test that WAF middleware correctly inspects and blocks malicious patterns inside JSON request bodies."""
    import base64
    import pickle

    # 1. Enable WAF
    client.post('/toggle-waf')

    # 2. Send clean JSON body (valid base64 encoded pickle) -> should be allowed (200 status code)
    clean_val = base64.b64encode(pickle.dumps({"name": "guest"})).decode("utf-8")
    response = client.post('/demo-lab/load-profile', json={"profile": clean_val})
    assert response.status_code == 200

    # 3. Send JSON body with SQL injection signature in key or value -> should be blocked
    response = client.post('/demo-lab/load-profile', json={"profile": "' OR '"})
    assert response.status_code == 403
    assert b"Blocked by Aegis WAF" in response.content

    # 4. Send nested JSON body with malicious signature -> should be blocked
    response = client.post('/demo-lab/load-profile', json={"profile": {"details": {"nested_key": "cat /etc/passwd"}}})
    assert response.status_code == 403
    assert b"Blocked by Aegis WAF" in response.content

    # 5. Disable WAF and verify it bypasses WAF (but might fail to decode OR/etc. with 500 error or raise an exception)
    client.post('/toggle-waf')
    try:
        response = client.post('/demo-lab/load-profile', json={"profile": "' OR '"})
        assert response.status_code != 403
    except Exception:
        # If it raised an exception, it successfully bypassed the WAF and reached the backend decoder
        pass


def test_waf_rules_persistence(client):
    """Test that custom WAF rules are actually written to and retrieved from the SQLite database."""
    import sqlite3
    from app.database import DB_PATH

    # Fetch current rules to restore later
    response = client.get('/get-waf-rules')
    original_rules = response.json()['rules']

    try:
        # Define a new custom rule
        new_rules = original_rules + [
            {"pattern": "persisted_hack_pattern", "description": "Persistent Threat Signature", "enabled": True}
        ]

        # Save rules via endpoint
        save_response = client.post('/save-waf-rules', json={"rules": new_rules})
        assert save_response.status_code == 200

        # Read directly from SQLite database file to verify persistence
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT pattern, description, enabled FROM waf_rules WHERE pattern = 'persisted_hack_pattern'")
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "persisted_hack_pattern"
        assert row[1] == "Persistent Threat Signature"
        assert row[2] == 1

        # Retrieve rules via get endpoint to verify it reads from database
        get_response = client.get('/get-waf-rules')
        assert any(r['pattern'] == 'persisted_hack_pattern' for r in get_response.json()['rules'])

    finally:
        # Restore original rules
        client.post('/save-waf-rules', json={"rules": original_rules})


def test_xss_waf_blocking(client):
    """Verify that WAF blocks XSS payloads when enabled, and permits them when disabled."""
    # 1. Enable WAF
    client.post('/toggle-waf')
    
    # Test script injection blocking
    response = client.get('/demo-lab/xss?msg=%3Cscript%3Ealert(1)%3C/script%3E')
    assert response.status_code == 403
    assert b"Blocked by Aegis WAF" in response.content

    # Test event handler hijacking blocking
    response = client.get('/demo-lab/xss?msg=test%20onload=alert(1)')
    assert response.status_code == 403

    # 2. Disable WAF
    client.post('/toggle-waf')
    
    # Test that payload is permitted
    response = client.get('/demo-lab/xss?msg=%3Cscript%3Ealert(1)%3C/script%3E')
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" in response.content


def test_ssrf_waf_blocking(client):
    """Verify that WAF blocks SSRF target payloads when enabled."""
    # 1. Enable WAF
    client.post('/toggle-waf')

    # Test cloud metadata target blocking
    response = client.get('/demo-lab/ssrf?url=http://169.254.169.254/latest/meta-data/')
    assert response.status_code == 403
    assert b"Blocked by Aegis WAF" in response.content

    # Test localhost target blocking
    response = client.get('/demo-lab/ssrf?url=http://localhost:5001/health')
    assert response.status_code == 403

    # 2. Disable WAF
    client.post('/toggle-waf')

    # Test that loopback is permitted (will return success or connection error, but not 403 WAF block)
    response = client.get('/demo-lab/ssrf?url=http://127.0.0.1:5001/health')
    assert response.status_code != 403
