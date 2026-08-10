import json
import re
import secrets
import urllib.parse
from collections.abc import Callable
from typing import Any


class RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > self.max_bytes:
                raise RequestBodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send):
        body = json.dumps({"detail": "Request body is too large."}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        nonce = secrets.token_urlsafe(24)
        scope.setdefault("state", {})["csp_nonce"] = nonce

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"permissions-policy",
                            b"camera=(), microphone=(), geolocation=(), payment=(), usb=()",
                        ),
                        (b"cross-origin-opener-policy", b"same-origin"),
                        (
                            b"content-security-policy",
                            (
                                "default-src 'self'; "
                                f"script-src 'self' 'nonce-{nonce}'; "
                                "script-src-attr 'none'; "
                                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                "font-src 'self' https://fonts.gstatic.com; "
                                "img-src 'self' data:; "
                                "connect-src 'self' ws: wss:; "
                                "object-src 'none'; base-uri 'none'; "
                                "frame-ancestors 'none'; form-action 'self'"
                            ).encode(),
                        ),
                    ]
                )
                if not scope.get("path", "").startswith("/static/"):
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


class WafASGIMiddleware:
    """ASGI WAF middleware that keeps request-body replay explicit for TestClient."""

    DEFAULT_BYPASS_PATHS = {
        "/toggle-waf",
        "/get-waf-rules",
        "/save-waf-rules",
        "/run-scan",
        "/export-dossier",
        "/api/setup",
        "/api/auth/login",
        "/api/github/callback",
        "/api/github/webhook",
    }

    def __init__(
        self,
        app,
        *,
        enabled: Callable[[], bool],
        load_rules: Callable[[], list[dict[str, Any]]],
        bypass_paths: set[str] | None = None,
        protected_prefixes: tuple[str, ...] = ("/demo-lab",),
    ):
        self.app = app
        self.enabled = enabled
        self.load_rules = load_rules
        self.bypass_paths = bypass_paths or self.DEFAULT_BYPASS_PATHS
        self.protected_prefixes = protected_prefixes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if (
            path in self.bypass_paths
            or not path.startswith(self.protected_prefixes)
            or not self.enabled()
        ):
            await self.app(scope, receive, send)
            return

        query_string = scope.get("query_string", b"").decode("utf-8", errors="ignore")
        payload, cached_receive = await self._payload_and_receive(query_string, receive)
        block_reason = self._block_reason(payload)

        if block_reason:
            response_content = json.dumps(
                {
                    "error": "Blocked by Aegis WAF",
                    "reason": block_reason,
                    "status": "security_violation",
                }
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(response_content)).encode("utf-8")),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": response_content,
                    "more_body": False,
                }
            )
            return

        await self.app(scope, cached_receive, send)

    async def _payload_and_receive(self, query_string: str, receive):
        query_string_decoded = urllib.parse.unquote_plus(query_string)
        body_chunks = []
        more_body = True
        while more_body:
            message = await receive()
            body_chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)

        body = b"".join(body_chunks)
        payload_parts = [query_string_decoded]
        if body:
            try:
                body_str = body.decode("utf-8", errors="ignore")
                payload_parts.append(body_str)
                payload_parts.append(urllib.parse.unquote_plus(body_str))
            except Exception:
                payload_parts.append(str(body))

        sent_body = False

        async def cached_receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        return " ".join(payload_parts), cached_receive

    def _block_reason(self, payload: str) -> str:
        for rule in self.load_rules():
            if not rule.get("enabled", True):
                continue
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            description = rule.get("description", pattern)
            try:
                if re.search(pattern, payload, re.IGNORECASE):
                    return f"Detected malicious pattern: {description}"
            except re.error:
                if pattern in payload:
                    return f"Detected malicious pattern (literal): {description}"
        return ""
