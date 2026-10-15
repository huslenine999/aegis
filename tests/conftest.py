import pytest
import os
from unittest.mock import patch, MagicMock
from pathlib import Path
from fastapi.testclient import TestClient


os.environ.setdefault("AEGIS_ENABLE_DEMO_LAB", "true")


PROJECT_ROOT = Path(__file__).resolve().parent.parent
GENERATED_REPORTS = (
    PROJECT_ROOT / "scans" / "report.html",
    PROJECT_ROOT / "scans" / "report.md",
)


@pytest.fixture(scope="session", autouse=True)
def preserve_checked_in_reports():
    originals = {
        path: path.read_bytes() if path.exists() else None
        for path in GENERATED_REPORTS
    }
    yield
    for path, content in originals.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(content)


@pytest.fixture(scope="session", autouse=True)
def application_lifespan():
    """Exercise the same startup path used by the ASGI server."""
    from app.main import app

    with TestClient(app):
        yield

class MockRedis:
    def __init__(self, *args, **kwargs):
        self.storage = {}
        self.lists = {}
        
    def hset(self, name, key=None, value=None, mapping=None):
        if name not in self.storage:
            self.storage[name] = {}
        if mapping:
            for k, v in mapping.items():
                self.storage[name][k] = str(v).encode() if not isinstance(v, bytes) else v
        else:
            self.storage[name][key] = str(value).encode() if not isinstance(value, bytes) else value
        return 1
            
    def hget(self, name, key):
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        val = self.storage.get(name, {}).get(key)
        if isinstance(val, str):
            return val.encode()
        return val
        
    def rpush(self, name, *values):
        if name not in self.lists:
            self.lists[name] = []
        for v in values:
            self.lists[name].append(v.encode() if isinstance(v, str) else v)
        return len(self.lists[name])
        
    def lrange(self, name, start, end):
        lst = self.lists.get(name, [])
        if end == -1:
            return lst[start:]
        return lst[start:end+1]
        
    def publish(self, channel, message):
        return 1
        
    def pubsub(self):
        m = MagicMock()
        m.get_message.return_value = None
        return m

@pytest.fixture(autouse=True)
def mock_rq_and_redis(monkeypatch):
    mock_redis = MockRedis()
    monkeypatch.setenv("AEGIS_SKIP_EXTERNAL_SCANNERS", "true")
    
    # Direct override to prevent real redis socket connections
    import app.main
    import app.worker
    from app.routes import project_routes, demo_scan_routes
    for module in (app.main, app.worker, project_routes, demo_scan_routes):
        module.redis_client = mock_redis
        module.REDIS_AVAILABLE = True
    app.worker.redis_client = mock_redis
    
    # Mock redis.Redis to return MockRedis
    redis_mock = patch("redis.Redis", return_value=mock_redis)
    
    # Mock RQ Queue.enqueue to execute target function synchronously
    def dummy_enqueue(func, *args, **kwargs):
        kwargs.pop("job_timeout", None)
        kwargs.pop("result_ttl", None)
        kwargs.pop("on_failure", None)
        return func(*args, **kwargs)
        
    queue_mock = patch("rq.Queue.enqueue", side_effect=dummy_enqueue)
    
    with redis_mock, queue_mock:
        yield


class FakeOSV:
    """In-process stand-in for the OSV querybatch and advisory endpoints."""

    def __init__(self):
        self.advisories = {}  # (ecosystem, name, version) -> list of advisory records
        self.failing = set()  # advisory IDs whose GET fails
        self.batch_fails = False
        self.page_size = None
        self.batches = []
        self.fetched = []
        self.urls = []
        self.kev = []  # CVE IDs in the CISA KEV catalog
        self.epss = {}  # CVE ID -> EPSS probability
        self.feed_failures = set()  # {"kev", "epss"}

    def add(self, ecosystem, name, version, *records):
        self.advisories.setdefault((ecosystem, name, version), []).extend(records)

    def __call__(self, request, **kwargs):
        import io
        import json
        import urllib.error
        import urllib.parse

        url = request.full_url
        self.urls.append(url)
        if url.startswith(("https://www.cisa.gov/", "https://raw.githubusercontent.com/cisagov/")):
            mirror = url.startswith("https://raw.githubusercontent.com/")
            if "kev" in self.feed_failures or ("kev-primary" in self.feed_failures and not mirror):
                raise TimeoutError("offline")
            return io.BytesIO(json.dumps({
                "catalogVersion": "2026.10.14",
                "dateReleased": "2026-10-14T16:00:00.000Z",
                "count": len(self.kev),
                "vulnerabilities": [
                    {"cveID": cve, "dateAdded": "2026-01-02", "dueDate": "2026-01-23",
                     "knownRansomwareCampaignUse": "Known" if cve.endswith("9") else "Unknown"}
                    for cve in self.kev
                ],
            }).encode())
        if url.startswith("https://api.first.org/"):
            if "epss" in self.feed_failures:
                raise TimeoutError("offline")
            requested = urllib.parse.unquote(url.split("cve=", 1)[1]).split(",")
            return io.BytesIO(json.dumps({"status": "OK", "data": [
                {"cve": cve, "epss": f"{self.epss[cve]:.9f}", "percentile": "0.9", "date": "2026-10-14"}
                for cve in requested if cve in self.epss
            ]}).encode())
        if url.endswith("/v1/querybatch"):
            if self.batch_fails:
                raise TimeoutError("offline")
            queries = json.loads(request.data)["queries"]
            self.batches.append(queries)
            results = []
            for query in queries:
                package = query["package"]
                records = self.advisories.get((package["ecosystem"], package["name"], query["version"]), [])
                start = int(query.get("page_token", 0))
                end = len(records) if self.page_size is None else start + self.page_size
                item = {"vulns": [
                    {"id": record["id"], "modified": record.get("modified", "2026-01-01T00:00:00Z")}
                    for record in records[start:end]
                ]}
                if end < len(records):
                    item["next_page_token"] = str(end)
                results.append(item)
            return io.BytesIO(json.dumps({"results": results}).encode())
        advisory_id = urllib.parse.unquote(url.rsplit("/", 1)[1])
        self.fetched.append(advisory_id)
        if advisory_id in self.failing:
            raise TimeoutError("offline")
        for records in self.advisories.values():
            for record in records:
                if record["id"] == advisory_id:
                    return io.BytesIO(json.dumps(record).encode())
        raise urllib.error.HTTPError(url, 404, "not found", {}, None)


@pytest.fixture
def fake_osv(monkeypatch, tmp_path):
    import policy_engine

    fake = FakeOSV()
    monkeypatch.setattr(policy_engine.urllib.request, "urlopen", fake)
    monkeypatch.setattr(policy_engine, "OSV_CACHE_FILE", tmp_path / "osv-cache.json")
    monkeypatch.setattr(policy_engine, "EXPLOIT_INTEL_CACHE_FILE", tmp_path / "exploit-intel-cache.json")
    return fake


import app.database as _database  # noqa: E402

REAL_REQUIRE_LEAST_PRIVILEGE_ROLE = _database.require_least_privilege_role


@pytest.fixture(autouse=True)
def database_role_checks(monkeypatch):
    """Record production least-privilege checks instead of requiring PostgreSQL.

    The real check runs against PostgreSQL in tests/integration/postgres_paths.py.
    """
    import app.database
    import app.github_broker_entrypoint
    import app.signer_entrypoint
    import app.worker_entrypoint

    calls = []
    for module in (app.database, app.worker_entrypoint, app.signer_entrypoint, app.github_broker_entrypoint):
        monkeypatch.setattr(module, "require_least_privilege_role", lambda *args, **kwargs: calls.append(True))
    return calls
