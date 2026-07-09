import json
import re
import urllib.parse
from collections.abc import Callable
from typing import Any


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

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
                                b"default-src 'self'; "
                                b"script-src 'self' 'unsafe-inline'; "
                                b"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                b"font-src 'self' https://fonts.gstatic.com; "
                                b"img-src 'self' data:; "
                                b"connect-src 'self' ws: wss:; "
                                b"object-src 'none'; base-uri 'none'; "
                                b"frame-ancestors 'none'; form-action 'self'"
                            ),
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
    }

    def __init__(
        self,
        app,
        *,
        enabled: Callable[[], bool],
        load_rules: Callable[[], list[dict[str, Any]]],
        bypass_paths: set[str] | None = None,
    ):
        self.app = app
        self.enabled = enabled
        self.load_rules = load_rules
        self.bypass_paths = bypass_paths or self.DEFAULT_BYPASS_PATHS

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self.bypass_paths or not self.enabled():
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
