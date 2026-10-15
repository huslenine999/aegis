"""Ask a separate, privileged service to do one thing, and wait for the answer.

Scanner workers run hostile code, so secrets live in narrow services (the
evidence signer, the GitHub credential broker) that each accept a few request
types over an RQ queue and validate every request against the database.
"""

import time
from typing import Any, Callable


class ServiceRefused(RuntimeError):
    """The service declined the request, failed, or did not answer in time."""


def call_service(
    queue_name: str,
    function: Callable[[dict], Any],
    request: dict,
    *,
    label: str,
    timeout: float,
    error: type[ServiceRefused] = ServiceRefused,
) -> Any:
    from rq import Queue

    from .database import redis_client

    queue = Queue(queue_name, connection=redis_client)
    job = queue.enqueue(
        function,
        request,
        job_timeout=max(1, int(timeout)),
        result_ttl=300,
        failure_ttl=3600,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = job.get_status(refresh=True)
        if status == "finished":
            return job.return_value()
        if status in {"failed", "stopped", "canceled"}:
            raise error(f"The {label} refused or failed the request.")
        time.sleep(0.2)
    job.cancel()
    raise error(f"The {label} did not respond in time.")
