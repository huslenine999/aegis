"""Privileged services accept bounded data, never executable queue jobs."""

import json
import pickle
import signal
import time

import pytest

from app import service_rpc


def request(operation="sign_manifest", payload=None, **extra):
    return json.dumps({
        "operation": operation,
        "payload": {} if payload is None else payload,
        "deadline": time.time() + 30,
        "reply": True,
        **extra,
    }).encode()


def test_only_the_fixed_handler_receives_the_json_payload():
    calls = []
    result = service_rpc.dispatch_request(
        request(payload={"scan_run_id": 7}),
        {"sign_manifest": lambda payload: calls.append(payload) or {"signature": "signed"}},
    )
    assert result == {"ok": True, "data": {"signature": "signed"}}
    assert calls == [{"scan_run_id": 7}]


@pytest.mark.parametrize("message", [
    pickle.dumps(("builtins.len", None, ([1, 2, 3],), {})),
    b"{broken",
    b"[]",
    request(operation="builtins.eval"),
    request(payload=[]),
    request(function="builtins.eval"),
    request(on_success="builtins.eval"),
    request(deadline=True),
    request(deadline=float("nan")),
    request(deadline=float("inf")),
    request(deadline=10 ** 1000),
    request(deadline=time.time() - 10),
    request(deadline=time.time() + 1000000),
    request(reply="yes"),
])
def test_hostile_or_expired_requests_cannot_dispatch(message, monkeypatch):
    monkeypatch.setattr(pickle, "loads", lambda _: pytest.fail("pickle must never be loaded"))
    result = service_rpc.dispatch_request(
        message, {"sign_manifest": lambda _: pytest.fail("invalid request dispatched")},
    )
    assert result == {"ok": False}


def test_oversized_and_deep_requests_cannot_dispatch(monkeypatch):
    handler = {"sign_manifest": lambda _: pytest.fail("invalid request dispatched")}
    monkeypatch.setattr(service_rpc, "MAX_MESSAGE_BYTES", 200)
    assert service_rpc.dispatch_request(request(payload={"x": "x" * 201}), handler) == {"ok": False}
    nested = {}
    for _ in range(40):
        nested = {"child": nested}
    monkeypatch.setattr(service_rpc, "MAX_MESSAGE_BYTES", 10000)
    assert service_rpc.dispatch_request(request(payload=nested), handler) == {"ok": False}


def test_handler_failure_does_not_leak_secrets_in_the_response():
    def fail(_):
        raise ValueError("secret-token-must-stay-server-side")

    assert service_rpc.dispatch_request(request(), {"sign_manifest": fail}) == {"ok": False}


def test_handler_timeout_interrupts_even_broad_exception_handlers(monkeypatch):
    monkeypatch.setattr(service_rpc, "MAX_HANDLER_SECONDS", 1)
    previous = signal.getsignal(signal.SIGALRM)

    def blocked(_):
        try:
            time.sleep(10)
        except Exception:
            pytest.fail("ordinary exception handlers must not swallow the service deadline")

    started = time.monotonic()
    assert service_rpc.dispatch_request(request(), {"sign_manifest": blocked}) == {"ok": False}
    assert time.monotonic() - started < 3
    assert signal.getsignal(signal.SIGALRM) == previous


@pytest.mark.parametrize("service", ["evidence-signing", "github-credentials", "notifications"])
def test_namespace_is_separate_from_legacy_executable_rq_jobs(service):
    key = service_rpc.service_key(service, "queue")
    assert key.startswith("aegis:service:v1:")
    assert not key.startswith("rq:")


def test_invalid_services_and_request_ids_cannot_choose_redis_keys():
    with pytest.raises(service_rpc.ServiceRefused):
        service_rpc.service_key("../signer", "queue")
    with pytest.raises(service_rpc.ServiceRefused):
        service_rpc.service_key("evidence-signing", "response", "rq:job:attacker")


class FakeRedis:
    """Only the small Redis interface used by synchronous callers."""

    def __init__(self, response=None):
        self.response = response
        self.sent = []
        self.deleted = []
        self.stored = []

    def eval(self, script, numkeys, *args):
        self.sent.append((numkeys, args))
        return 1

    def getrange(self, key, start, end):
        return b"" if self.response is None else self.response

    def delete(self, *keys):
        self.deleted.extend(keys)

    def set(self, key, value, ex=None):
        self.stored.append((key, value, ex))


def test_call_sends_data_and_consumes_a_valid_response(monkeypatch):
    connection = FakeRedis(b'{"ok":true,"data":{"signature":"signed"}}')
    monkeypatch.setattr(service_rpc, "service_connection", lambda: connection)
    assert service_rpc.call_service(
        "evidence-signing", "sign_manifest", {"scan_run_id": 7}, label="signer", timeout=2,
    ) == {"signature": "signed"}
    _, args = connection.sent[0]
    envelope = json.loads(args[3])
    assert envelope["operation"] == "sign_manifest"
    assert envelope["payload"] == {"scan_run_id": 7}
    assert envelope["reply"] is True
    assert all(not key.startswith("rq:") for key in connection.deleted)


@pytest.mark.parametrize("response", [b'{"ok":false}', b"invalid", b'{"ok":true}', pickle.dumps({"ok": True})])
def test_call_fails_closed_for_refusals_and_bad_responses(monkeypatch, response):
    monkeypatch.setattr(service_rpc, "service_connection", lambda: FakeRedis(response))
    with pytest.raises(service_rpc.ServiceRefused):
        service_rpc.call_service("evidence-signing", "sign_manifest", {}, label="signer", timeout=2)


def test_call_timeout_removes_pending_request_and_response(monkeypatch):
    connection = FakeRedis()
    monkeypatch.setattr(service_rpc, "service_connection", lambda: connection)
    monkeypatch.setattr(service_rpc.time, "sleep", lambda _: None)
    with pytest.raises(service_rpc.ServiceRefused, match="did not respond"):
        service_rpc.call_service("evidence-signing", "sign_manifest", {}, label="signer", timeout=0.01)
    assert any(":request:" in key for key in connection.deleted)
    assert any(":response:" in key for key in connection.deleted)


def test_queue_capacity_failure_is_explicit(monkeypatch):
    connection = FakeRedis()
    connection.eval = lambda *args: 0
    monkeypatch.setattr(service_rpc, "service_connection", lambda: connection)
    with pytest.raises(service_rpc.ServiceRefused, match="full"):
        service_rpc.enqueue_service("notifications", "test_channel", {"channel_id": 7})


@pytest.mark.parametrize("response", [b'{"ok":true,"data":{"signature":"signed"}}', b'{"ok":false}'])
def test_cleanup_failure_preserves_the_result_or_refusal(monkeypatch, response):
    connection = FakeRedis(response)

    def broken_cleanup(*keys):
        raise ConnectionError("Redis disconnected during cleanup")

    connection.delete = broken_cleanup
    monkeypatch.setattr(service_rpc, "service_connection", lambda: connection)
    if b'"data"' in response:
        assert service_rpc.call_service("evidence-signing", "sign_manifest", {}, label="signer", timeout=2) == {"signature": "signed"}
    else:
        with pytest.raises(service_rpc.ServiceRefused, match="refused or failed"):
            service_rpc.call_service("evidence-signing", "sign_manifest", {}, label="signer", timeout=2)


def test_malformed_timestamp_cannot_crash_the_consumer():
    connection = FakeRedis()
    connection.eval = lambda *args: request(deadline=10 ** 1000)
    service_rpc.process_request(
        connection, "evidence-signing", "a" * 32,
        {"sign_manifest": lambda _: pytest.fail("malformed request dispatched")},
    )


def test_consumer_dispatches_once_and_stores_a_bounded_response():
    connection = FakeRedis()
    connection.eval = lambda *args: request(payload={"scan_run_id": 7})
    calls = []
    service_rpc.process_request(
        connection, "evidence-signing", "a" * 32,
        {"sign_manifest": lambda payload: calls.append(payload) or {"signature": "signed"}},
    )
    assert calls == [{"scan_run_id": 7}]
    key, raw, ttl = connection.stored[0]
    assert key == service_rpc.service_key("evidence-signing", "response", "a" * 32)
    assert json.loads(raw) == {"ok": True, "data": {"signature": "signed"}}
    assert ttl == service_rpc.RESPONSE_SECONDS


@pytest.mark.parametrize("raw", [None, request(deadline=0), request(operation="builtins.eval")])
def test_expired_or_refused_notifications_record_a_delivery_failure(monkeypatch, raw):
    from app import observability

    failures = []
    connection = FakeRedis()
    connection.eval = lambda *args: raw
    monkeypatch.setattr(observability, "record_notification_failure", lambda: failures.append(True))
    service_rpc.process_request(connection, "notifications", "a" * 32, {})
    assert failures == [True]


def test_async_notification_outage_does_not_use_the_handler_timeout(monkeypatch):
    connection = FakeRedis()
    monkeypatch.setattr(service_rpc, "service_connection", lambda: connection)
    service_rpc.enqueue_service("notifications", "project_notification", {}, timeout=86400)
    _, args = connection.sent[0]
    envelope = json.loads(args[3])
    assert 86390 < envelope["deadline"] - time.time() <= 86400
    assert envelope["reply"] is False
    assert args[5] == 86400


@pytest.mark.parametrize(("entrypoint", "service", "operations"), [
    ("app.signer_entrypoint", "evidence-signing", {"sign_manifest"}),
    ("app.github_broker_entrypoint", "github-credentials", {"clone_token", "complete_check"}),
])
def test_privileged_entrypoints_only_register_fixed_handlers(monkeypatch, entrypoint, service, operations):
    import importlib

    module = importlib.import_module(entrypoint)
    started = []
    monkeypatch.setenv("AEGIS_ENV", "test")
    monkeypatch.setattr(module, "serve_service", lambda *args: started.append(args))
    monkeypatch.setattr(module.os, "execvp", lambda *args: pytest.fail("executable RQ consumer launched"))
    module.main()
    assert started[0][0] == service
    assert set(started[0][1]) == operations


def test_service_loop_ignores_legacy_jobs_and_invalid_identifiers(monkeypatch):
    class Finished(Exception):
        pass

    class ConsumerRedis(FakeRedis):
        def __init__(self):
            super().__init__()
            self.items = [b"rq:job:attacker", b"a" * 32]
            self.legacy_jobs = [pickle.dumps(("builtins.len", None, ([1],), {}))]

        def blpop(self, key, timeout):
            assert key == "aegis:service:v1:evidence-signing:queue"
            if not self.items:
                raise Finished()
            item, *remaining = self.items
            self.items = remaining
            return key.encode(), item

        def eval(self, script, numkeys, *args):
            assert args[0] == service_rpc.service_key("evidence-signing", "request", "a" * 32)
            return request()

    connection = ConsumerRedis()
    calls = []
    monkeypatch.setattr(service_rpc, "service_connection", lambda: connection)
    with pytest.raises(Finished):
        service_rpc.serve_service("evidence-signing", {
            "sign_manifest": lambda payload: calls.append(payload) or {"signature": "signed"},
        })
    assert calls == [{}]
    assert len(connection.legacy_jobs) == 1
    assert any(key.endswith(":heartbeat") and ttl == service_rpc.HEARTBEAT_SECONDS
               for key, _, ttl in connection.stored)


def test_service_readiness_reads_only_its_expiring_heartbeat():
    class HeartbeatRedis:
        def get(self, key):
            assert key == "aegis:service:v1:evidence-signing:heartbeat"
            return b"1"

    assert service_rpc.service_available("evidence-signing", connection=HeartbeatRedis())


def test_services_use_the_applications_configured_redis_endpoint(monkeypatch):
    from app import database

    monkeypatch.setattr(database, "REDIS_URL", "redis://cache.internal:6380/7")
    connection = service_rpc.service_connection()
    try:
        options = connection.connection_pool.connection_kwargs
        assert (options["host"], options["port"], options["db"]) == ("cache.internal", 6380, 7)
    finally:
        connection.close()
