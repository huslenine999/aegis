import pytest

from app import notifications, notifier_entrypoint


@pytest.mark.parametrize("kind", ["project", "test"])
def test_remote_notifications_enqueue_fixed_data_operations(monkeypatch, kind):
    monkeypatch.setenv("AEGIS_REQUIRE_NOTIFIER", "true")
    calls = []
    monkeypatch.setattr(
        notifications.service_rpc, "enqueue_service",
        lambda *args, **kwargs: calls.append((args, kwargs)), raising=False,
    )
    monkeypatch.setattr(notifications, "send_project_notification", lambda *args: pytest.fail("delivered in caller"))
    monkeypatch.setattr(notifications, "test_channel", lambda *args: pytest.fail("delivered in caller"))

    if kind == "project":
        assert notifications.queue_project_notification(7, "blocked", {"job_id": "scan-1"})
        expected = ("notifications", "project_notification", {
            "project_id": 7, "event": "blocked", "payload": {"job_id": "scan-1"},
        })
    else:
        assert notifications.queue_test_channel(9, 7)
        expected = ("notifications", "test_channel", {"channel_id": 9, "project_id": 7})
    assert calls == [(expected, {"timeout": 86400})]


@pytest.mark.parametrize("kind", ["project", "test"])
def test_notification_enqueue_failure_is_recorded(monkeypatch, kind):
    monkeypatch.setenv("AEGIS_REQUIRE_NOTIFIER", "true")
    failures = []

    def unavailable(*args, **kwargs):
        raise ConnectionError("unavailable")

    monkeypatch.setattr(notifications.service_rpc, "enqueue_service", unavailable, raising=False)
    monkeypatch.setattr(notifications, "record_notification_failure", lambda: failures.append(True))
    result = (notifications.queue_project_notification(7, "blocked", {}) if kind == "project"
              else notifications.queue_test_channel(9, 7))
    assert result is False
    assert failures == [True]


def test_project_notification_dispatch_validates_before_delivery(monkeypatch):
    delivered = []
    monkeypatch.setattr(notifications, "send_project_notification", lambda *args: delivered.append(args))

    notifications.dispatch_project_notification({
        "project_id": 7, "event": "blocked", "payload": {"job_id": "scan-1"},
    })

    assert delivered == [(7, "blocked", {"job_id": "scan-1"})]


@pytest.mark.parametrize("payload", [
    None, [], {}, {"project_id": 7, "event": "blocked"},
    {"project_id": 7, "event": "blocked", "payload": {}, "function": "builtins.eval"},
    *({"project_id": value, "event": "blocked", "payload": {}} for value in (True, 0, -1, "7")),
    *({"project_id": 7, "event": value, "payload": {}} for value in ("unknown", [], None)),
    {"project_id": 7, "event": "blocked", "payload": []},
])
def test_project_notification_dispatch_rejects_untrusted_requests(monkeypatch, payload):
    monkeypatch.setattr(notifications, "send_project_notification", lambda *args: pytest.fail("invalid request delivered"))
    with pytest.raises(ValueError):
        notifications.dispatch_project_notification(payload)


def test_test_channel_dispatch_validates_before_delivery(monkeypatch):
    delivered = []
    monkeypatch.setattr(notifications, "test_channel", lambda *args: delivered.append(args))

    notifications.dispatch_test_channel({"channel_id": 9, "project_id": 7})

    assert delivered == [(9, 7)]


@pytest.mark.parametrize("payload", [
    None, [], {}, {"project_id": 7},
    {"channel_id": 9, "project_id": 7, "function": "builtins.eval"},
    *({"channel_id": value, "project_id": 7} for value in (True, 0, -1, "9")),
    *({"channel_id": 9, "project_id": value} for value in (True, 0, -1, "7")),
])
def test_test_channel_dispatch_rejects_untrusted_requests(monkeypatch, payload):
    monkeypatch.setattr(notifications, "test_channel", lambda *args: pytest.fail("invalid request delivered"))
    with pytest.raises(ValueError):
        notifications.dispatch_test_channel(payload)


def test_notifier_starts_only_fixed_notification_handlers(monkeypatch):
    started = []
    monkeypatch.setattr(notifier_entrypoint, "validate_notifier_configuration", lambda: None)
    monkeypatch.setattr(notifier_entrypoint.service_rpc, "serve_service", lambda *args: started.append(args), raising=False)
    monkeypatch.setattr(notifier_entrypoint.os, "execvp", lambda *args: pytest.fail("unrestricted RQ launched"))

    notifier_entrypoint.main()

    assert started == [("notifications", {
        "project_notification": notifications.dispatch_project_notification,
        "test_channel": notifications.dispatch_test_channel,
    })]
