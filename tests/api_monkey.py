"""Monkey-test every HTTP route with random requests from each kind of caller.

Run by tests/test_api_monkey.py in a subprocess, because authentication and
data paths are fixed when the application is imported.

    python -m tests.api_monkey <requests> <seed>

Prints a JSON summary. Exits 1 when a request crashes the application,
returns a 5xx other than 502/503, lets an anonymous caller through a protected
route, or returns another tenant's object.
"""

import json
import os
import random
import sys
import tempfile
import traceback
import urllib.parse
from collections import Counter

from cryptography.fernet import Fernet

DATA_DIR = tempfile.mkdtemp(prefix="aegis-monkey-")
os.environ.update({
    "AEGIS_ENV": "development",
    "AEGIS_REQUIRE_AUTH": "true",
    "AEGIS_DATA_DIR": DATA_DIR,
    "AEGIS_SESSION_SECRET": "monkey-session-secret-" + "x" * 32,
    "AEGIS_AUDIT_HMAC_KEY": "a" * 40,
    "AEGIS_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "AEGIS_SKIP_EXTERNAL_SCANNERS": "true",
    "REDIS_URL": "redis://127.0.0.1:1/0",
    **{name: "1000000000" for name in ("AEGIS_RATE_LIMIT_PER_MINUTE", "AEGIS_AGGREGATE_RATE_LIMIT_PER_MINUTE",
                                       "AEGIS_SCAN_RATE_LIMIT_PER_MINUTE", "AEGIS_LOGIN_RATE_LIMIT_PER_MINUTE")},
})
os.environ.pop("DATABASE_URL", None)
if os.environ.get("AEGIS_TEST_POSTGRES_URL"):  # an empty database this run may reset
    os.environ["DATABASE_URL"] = os.environ["AEGIS_TEST_POSTGRES_URL"]

from unittest.mock import patch  # noqa: E402

import requests  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tests.conftest import MockRedis  # noqa: E402

# Routes anyone may call. Everything else must answer an anonymous caller with 401/403/404.
PUBLIC = {
    ("GET", "/"), ("GET", "/login"), ("GET", "/setup"), ("POST", "/api/setup"), ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"), ("GET", "/api/auth/oidc/start"), ("GET", "/api/auth/oidc/callback"),
    ("GET", "/account/security"), ("GET", "/health"), ("GET", "/ready"), ("GET", "/.well-known/security.txt"),
    ("POST", "/api/github/webhook"), ("GET", "/api/version"),
}
VOCABULARY = [
    "name", "repository_url", "github_full_name", "default_branch", "scan_preset", "preset", "target", "role",
    "username", "password", "second_factor", "code", "scopes", "expires_at", "active", "state", "status",
    "reason", "ticket", "expires", "config", "events", "channel_type", "type", "rules", "definition", "title",
    "full_name", "repository", "scan_run_id", "storage_key", "workspace_name", "backend", "diff_aware",
    "checkpoints", "body", "severity", "fingerprint", "approver", "settings", "current_password", "new_password",
]
TEXT = [
    "", "a", "admin", "viewer", "operator", "quick", "standard", "deep", "open", "resolved", "false_positive",
    "accepted_risk", "HIGH", "CRITICAL", "slack", "email", "webhook", "teams", "completed", "main",
    "example/api", "https://github.com/example/api", "http://169.254.169.254/latest", "file:///etc/passwd",
    "../../etc/passwd", "<script>alert(1)</script>", "' OR 1=1 --", "\x00", "‮\U0001f4a5", "%00", "*",
    "x" * 5000, "2026-01-01T00:00:00+00:00", "not-a-date", "read", "write", "admin-scope", "true", "1",
]
NUMBERS = [0, 1, 2, 3, -1, 7, 2**31, 2**63 - 1, 2**63, 2**64, 10**30, 1.5, -0.0, 1e308]


VALID_POLICY = {"fail_on_severities": ["HIGH", "CRITICAL"], "required_tools": ["Ruff"]}
FUTURE = "2027-01-01T00:00:00+00:00"


def templates(monkey, pick):
    """Well-formed bodies per route, so random mutations reach deeper than input validation."""
    name = f"monkey-{monkey.random.randrange(10**6)}"
    return {
        ("POST", "/api/projects"): {"name": name, "repository_url": "", "default_branch": "main",
                                    "scan_preset": monkey.random.choice(["quick", "standard", "deep"])},
        ("PATCH", "/api/projects/{project_id}"): {"name": name, "scan_preset": "quick"},
        ("POST", "/api/users"): {"username": name, "password": "monkey-password-123456",
                                 "role": monkey.random.choice(["viewer", "operator", "admin"])},
        ("PATCH", "/api/users/{user_id}"): {"role": monkey.random.choice(["viewer", "operator", "admin"]),
                                            "active": monkey.random.choice([True, False])},
        ("POST", "/api/users/{user_id}/tokens"): {"name": name, "scopes": ["read"], "expires_at": FUTURE},
        ("PATCH", "/api/projects/{project_id}/findings/{finding_id}"): {
            "status": monkey.random.choice(["open", "resolved", "false_positive", "accepted_risk"]),
            "resolution_note": "monkey", "accepted_until": FUTURE, "due_at": FUTURE},
        ("POST", "/api/projects/{project_id}/policies"): {"name": name, "definition": VALID_POLICY},
        ("POST", "/api/projects/{project_id}/policies/simulate"): {"scan_run_id": pick("run_id"), "definition": VALID_POLICY},
        ("PUT", "/api/projects/{project_id}/members"): {"username": "monkey-viewer", "role": "viewer"},
        ("POST", "/api/projects/{project_id}/notifications"): {
            "name": name, "channel_type": "email", "config": {"to": "ops@example.com"}, "events": ["completed"]},
        ("POST", "/api/projects/{project_id}/scans"): {"preset": "quick", "diff_aware": False},
        ("POST", "/api/auth/reauth"): {"password": "monkey-password-123456"},
        ("POST", "/api/auth/login"): {"username": "monkey-admin", "password": "monkey-password-123456"},
        ("POST", "/api/admin/audit/verify"): {"checkpoints": []},
    }


class Monkey:
    def __init__(self, seed: int):
        self.random = random.Random(seed)

    def scalar(self):
        roll = self.random.random()
        if roll < 0.45:
            return self.random.choice(TEXT)
        if roll < 0.75:
            return self.random.choice(NUMBERS)
        if roll < 0.85:
            return self.random.choice([True, False, None])
        return "".join(chr(self.random.randrange(1, 0x2FFF)) for _ in range(self.random.randrange(1, 40)))

    def value(self, depth=0):
        roll = self.random.random()
        if depth < 3 and roll < 0.12:
            return [self.value(depth + 1) for _ in range(self.random.randrange(0, 4))]
        if depth < 3 and roll < 0.2:
            return self.mapping(depth + 1)
        return self.scalar()

    def mapping(self, depth=0):
        keys = self.random.sample(VOCABULARY, self.random.randrange(0, 6))
        if self.random.random() < 0.2:
            keys.append(str(self.scalar())[:40])
        return {key: self.value(depth) for key in keys}

    def body(self, template=None):
        if template is not None and self.random.random() < 0.6:
            body = dict(template)
            if body and self.random.random() < 0.5:
                key = self.random.choice(sorted(body))
                if self.random.random() < 0.3:
                    body.pop(key)
                else:
                    body[key] = self.value()
            return {"json": body}
        roll = self.random.random()
        if roll < 0.7:
            return {"json": self.mapping()}
        if roll < 0.8:
            text = json.dumps(self.value()).replace("1e+308", self.random.choice(["1e+308", "NaN", "Infinity", "1e999"]))
            return {"content": text, "headers": {"Content-Type": "application/json"}}
        if roll < 0.88:
            return {"content": bytes(self.random.randrange(256) for _ in range(self.random.randrange(0, 64))),
                    "headers": {"Content-Type": self.random.choice(["application/json", "text/plain", ""])}}
        if roll < 0.95:
            name = self.random.choice(["report.json", "../x", "scan-manifest.json", "a.zip", ""])
            return {"files": [("files", (name, bytes(self.random.randrange(256) for _ in range(32)), "application/octet-stream"))]}
        return {}


def _seed():
    from app import auth, findings, notifications, policies, projects
    from app.database import get_connection, initialize_database

    initialize_database()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO tenants (slug, name, created_at) VALUES ('other', 'Other', '2026-01-01T00:00:00+00:00')"
        )
        tenant_two = int(connection.execute("SELECT id FROM tenants WHERE slug = 'other'").fetchone()[0])
    users = {}
    for label, role, tenant in (("viewer", "viewer", 1), ("operator", "operator", 1), ("admin", "admin", 1),
                                ("other-admin", "admin", tenant_two)):
        with get_connection() as connection:
            user_id = int(connection.execute(
                """INSERT INTO auth_users (username, password_hash, role, active, created_at, tenant_id)
                   VALUES (?, ?, ?, 1, '2026-01-01T00:00:00+00:00', ?) RETURNING id""",
                (f"monkey-{label}", auth.hash_password("monkey-password-123456"), role, tenant),
            ).fetchone()[0])
        principal = auth.Principal(user_id, f"monkey-{label}", role, f"csrf-{label}", tenant)
        users[label] = {"id": user_id, "tenant": tenant, "role": role, "username": f"monkey-{label}",
                        "cookie": auth.create_session(principal), "csrf": f"csrf-{label}"}
    owned = {}
    for label in ("admin", "other-admin"):
        user = users[label]
        project_id = projects.create_project(
            name=f"{label} project", repository_url="", github_full_name="", default_branch="main",
            scan_preset="quick", user_id=user["id"], tenant_id=user["tenant"],
        )
        run_id = projects.create_scan_run(
            job_id=f"monkey-{label}", project_id=project_id, requested_by=user["id"], target="project", preset="quick",
        )
        result = {"ruff": [{"code": "S307", "filename": "a.py", "message": "eval", "location": {"row": 1}}]}
        findings.sync_findings(run_id, result)
        projects.update_scan_run(run_id, state="completed", progress=100, result=result)
        channel_id = notifications.create_channel(
            project_id=project_id, name="ops", channel_type="email", config={"to": "ops@example.com"},
            events=["completed"], created_by=user["id"],
        )
        policy = policies.create_policy(project_id, user["id"], "baseline", {"fail_on_severities": ["HIGH"]})
        with get_connection() as connection:
            finding_ids = [row[0] for row in connection.execute(
                "SELECT id FROM security_findings WHERE project_id = ?", (project_id,)
            ).fetchall()]
        owned[user["tenant"]] = {
            "project_id": [project_id], "run_id": [run_id], "finding_id": finding_ids,
            "channel_id": [channel_id], "policy_id": [policy["id"]],
            "user_id": [item["id"] for item in users.values() if item["tenant"] == user["tenant"]],
        }
    return users, owned


def _restore(user):
    """Re-activate a seeded caller and give it a fresh session."""
    from app import auth
    from app.database import get_connection

    with get_connection() as connection:
        connection.execute(
            "UPDATE auth_users SET active = 1, role = ?, tenant_id = ? WHERE id = ?",
            (user["role"], user["tenant"], user["id"]),
        )
    if auth._decode_session(user["cookie"]) is None:
        principal = auth.Principal(user["id"], user["username"], user["role"], user["csrf"], user["tenant"])
        user["cookie"] = auth.create_session(principal)


def _api_routes(routes, prefix=""):
    """Yield (prefix, route) for every API route, including nested routers."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix, route
        elif hasattr(route, "original_router"):  # FastAPI's lazily included router
            yield from _api_routes(route.original_router.routes, prefix + (route.include_context.prefix or ""))


def main() -> int:
    total, seed = int(sys.argv[1]), int(sys.argv[2])
    monkey = Monkey(seed)
    offline = requests.ConnectionError("network disabled for monkey testing")
    with patch("rq.Queue.enqueue", return_value=type("Job", (), {"id": "monkey-job"})()), \
         patch("requests.Session.request", side_effect=offline), \
         patch("urllib.request.urlopen", side_effect=OSError("network disabled for monkey testing")):
        import app.main
        import app.worker
        from app.routes import project_routes, scan_routes

        redis = MockRedis()
        for module in (app.main, app.worker, project_routes, scan_routes):
            module.redis_client = redis
            module.REDIS_AVAILABLE = True
        users, owned = _seed()
        routes = [
            (method, prefix + route.path, route)
            for prefix, route in _api_routes(app.main.app.routes)
            for method in sorted(route.methods - {"HEAD"})
        ]
        client = TestClient(app.main.app, raise_server_exceptions=True, follow_redirects=False)
        failures: list[dict] = []
        statuses: Counter = Counter()
        reached: set[tuple[str, str]] = set()
        viewer_writes: set[str] = set()
        callers = ["anonymous", "viewer", "operator", "admin", "other-admin"]
        for _ in range(total):
            method, template, route = monkey.random.choice(routes)
            caller = monkey.random.choice(callers)
            path = template
            references_tenant_one = False
            # Mostly a consistent tenant's objects, so nested routes resolve; sometimes mixed or random.
            tenant = monkey.random.choice(sorted(owned))

            def pick(kind):
                pool = owned[tenant if monkey.random.random() < 0.85 else monkey.random.choice(sorted(owned))]
                return monkey.random.choice(pool.get(kind) or [0])

            for name in route.param_convertors:
                if name == "artifact_name":
                    value = monkey.random.choice(["report.html", "report.json", "scan-manifest.json", "../x", "%2e%2e"])
                elif monkey.random.random() < 0.85:
                    value = pick(name)
                    references_tenant_one |= value in owned[1].get(name, [])
                else:
                    value = monkey.scalar()
                value = urllib.parse.quote(str(value), safe="")
                path = path.replace("{" + name + "}", value).replace("{" + name + ":path}", value)
            params = {
                param.name: monkey.scalar() for param in route.dependant.query_params if monkey.random.random() < 0.6
            }
            template_body = templates(monkey, pick).get((method, template))
            arguments = monkey.body(template_body) if method in {"POST", "PUT", "PATCH", "DELETE"} else {}
            headers = dict(arguments.pop("headers", {}))
            client.cookies.clear()
            if caller != "anonymous":
                _restore(users[caller])  # earlier requests may have logged out, demoted, or disabled this caller
                client.cookies.set("aegis_session", users[caller]["cookie"])
                headers["X-CSRF-Token"] = users[caller]["csrf"]
            try:
                response = client.request(method, path, params=params, headers=headers, **arguments)
            except Exception as exc:  # noqa: BLE001 - every crash is a finding
                failures.append({"kind": "crash", "method": method, "route": template, "path": path[:200],
                                 "caller": caller, "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                                 "where": traceback.format_exc().strip().splitlines()[-3][:200]})
                continue
            status = response.status_code
            statuses[status] += 1
            if status < 300:
                reached.add((method, template))
                if caller == "viewer" and method != "GET":
                    viewer_writes.add(f"{method} {template}")
            problem = None
            if status >= 500 and status not in {502, 503}:  # 502/503: an unavailable dependency
                problem = "server-error"
            elif caller == "anonymous" and status < 300 and (method, template) not in PUBLIC:
                problem = "anonymous-access"
            elif caller == "other-admin" and status < 300 and references_tenant_one:
                problem = "cross-tenant"
            if problem:
                failures.append({"kind": problem, "method": method, "route": template, "path": path[:200],
                                 "caller": caller, "status": status, "body": response.text[:200]})
    distinct = {(item["kind"], item["method"], item["route"], item.get("error", item.get("status"))): item for item in failures}
    print(json.dumps({"requests": total, "routes": len(routes), "routes_reached": len(reached),
                      "statuses": dict(sorted(statuses.items())), "viewer_writes": sorted(viewer_writes),
                      "failures": list(distinct.values())}, default=str))
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
