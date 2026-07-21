import pytest
import os
from unittest.mock import patch, MagicMock
from pathlib import Path


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
    app.main.redis_client = mock_redis
    app.worker.redis_client = mock_redis
    app.main.REDIS_AVAILABLE = True
    app.worker.REDIS_AVAILABLE = True
    
    # Mock redis.Redis to return MockRedis
    redis_mock = patch("redis.Redis", return_value=mock_redis)
    
    # Mock RQ Queue.enqueue to execute target function synchronously
    def dummy_enqueue(func, *args, **kwargs):
        kwargs.pop("job_timeout", None)
        kwargs.pop("result_ttl", None)
        return func(*args, **kwargs)
        
    queue_mock = patch("rq.Queue.enqueue", side_effect=dummy_enqueue)
    
    with redis_mock, queue_mock:
        yield
