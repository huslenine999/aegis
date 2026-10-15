import asyncio
import threading

from app.rate_limit import RateLimitMiddleware


def test_redis_rate_limit_does_not_block_other_async_work():
    entered = threading.Event()
    released = threading.Event()
    observations = []

    class WaitingRedis:
        def incr(self, key):
            entered.set()
            observations.append(released.wait(timeout=0.5))
            return 2

        def expire(self, key, ttl):
            raise AssertionError("Existing counters must keep their expiry")

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def receive():
        return {"type": "http.request", "body": b""}

    async def exercise():
        responses = []

        async def send(message):
            responses.append(message)

        async def unrelated_work():
            while not entered.is_set():
                await asyncio.sleep(0.001)
            released.set()

        middleware = RateLimitMiddleware(app, WaitingRedis())
        await asyncio.gather(
            middleware({"type": "http", "path": "/api/projects", "method": "GET", "client": ("127.0.0.1", 1)}, receive, send),
            unrelated_work(),
        )
        assert responses[0]["status"] == 200

    asyncio.run(exercise())
    assert observations == [True, True]
