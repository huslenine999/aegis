"""GitHub credentials outside the scan worker.

The scan worker clones private repositories and reports check results, but it
also runs scanners against hostile source, so in production it holds neither
the GitHub App private key nor the key that decrypts users' OAuth tokens. It
asks this broker instead, naming only a scan run. The broker reads the run,
project, requester, and installation from the database (never from the
request), refuses runs that have finished, and then either:

* returns a token for cloning: an installation token scoped to that one
  repository with read-only contents access, or, for projects imported with
  a user's OAuth connection, that user's token; or
* completes the run's GitHub check itself, so the worker never receives a
  token that can write check results.
"""

import os
from typing import Any

from .database import get_connection
from .github_integration import complete_check_run, github_installation_token, github_token
from .service_rpc import ServiceRefused, call_service


BROKER_QUEUE = "github-credentials"
ACTIVE_STATES = {"queued", "running", "analyzing", "correlating", "reporting"}
CHECK_CONCLUSIONS = {"success", "failure", "neutral", "cancelled", "timed_out", "action_required"}
BROKER_TIMEOUT_SECONDS = 60.0


class BrokerRefused(ServiceRefused):
    """The broker declined to issue a credential or perform an action."""


def remote_broker_enabled() -> bool:
    return os.environ.get("AEGIS_GITHUB_BROKER", "local").strip().lower() == "remote"


def _run_and_project(scan_run_id: Any) -> dict:
    if not isinstance(scan_run_id, int) or isinstance(scan_run_id, bool) or scan_run_id < 1:
        raise BrokerRefused("Requests must name a recorded scan run.")
    with get_connection() as connection:
        row = connection.execute(
            """SELECT r.state, r.requested_by, r.github_installation_id, r.github_check_run_id,
                      p.id, p.tenant_id, p.github_full_name
               FROM scan_runs r JOIN projects p ON p.id = r.project_id
               WHERE r.id = ?""",
            (scan_run_id,),
        ).fetchone()
    if not row:
        raise BrokerRefused("The scan run does not exist.")
    return {
        "state": row[0],
        "requested_by": int(row[1]),
        "installation_id": int(row[2]) if row[2] is not None else None,
        "check_run_id": int(row[3]) if row[3] is not None else None,
        "project_id": int(row[4]),
        "tenant_id": int(row[5]),
        "repository": row[6] or "",
    }


def issue_clone_token(request: dict) -> dict:
    """Fixed operation: a read-only credential for the run's own repository."""
    if not isinstance(request, dict) or set(request) != {"scan_run_id"}:
        raise BrokerRefused("Clone requests may contain only a scan run ID.")
    run = _run_and_project(request["scan_run_id"])
    if run["state"] not in ACTIVE_STATES:
        raise BrokerRefused("Credentials are issued only for scans that are still in progress.")
    if run["installation_id"]:
        if not run["repository"]:
            raise BrokerRefused("The project has no GitHub repository.")
        token = github_installation_token(
            run["installation_id"],
            tenant_id=run["tenant_id"],
            repository=run["repository"],
            permissions={"contents": "read"},
        )
        return {"token": token, "kind": "installation"}
    return {"token": github_token(run["requested_by"]), "kind": "oauth"}


def complete_run_check(request: dict) -> dict:
    """Fixed operation: report a run's verdict on its GitHub check."""
    allowed = {"scan_run_id", "conclusion", "title", "summary", "details_url", "annotations"}
    if not isinstance(request, dict) or not set(request) <= allowed or "scan_run_id" not in request:
        raise BrokerRefused("Malformed check completion request.")
    run = _run_and_project(request["scan_run_id"])
    if not (run["installation_id"] and run["check_run_id"] and run["repository"]):
        return {"completed": False}
    conclusion = request.get("conclusion")
    if conclusion not in CHECK_CONCLUSIONS:
        raise BrokerRefused("Unknown check conclusion.")
    annotations = request.get("annotations")
    if annotations is not None and not isinstance(annotations, list):
        raise BrokerRefused("Annotations must be a list.")
    complete_check_run(
        run["installation_id"],
        run["repository"],
        run["check_run_id"],
        conclusion=conclusion,
        title=str(request.get("title") or "Aegis security gate")[:255],
        summary=str(request.get("summary") or "")[:65000],
        details_url=str(request.get("details_url") or ""),
        annotations=annotations,
        tenant_id=run["tenant_id"],
    )
    return {"completed": True}


def _call(operation: str, function, request: dict) -> dict:
    if not remote_broker_enabled():
        return function(request)
    result = call_service(
        BROKER_QUEUE, operation, request,
        label="GitHub credential broker", timeout=BROKER_TIMEOUT_SECONDS, error=BrokerRefused,
    )
    if not isinstance(result, dict):
        raise BrokerRefused("The GitHub credential broker returned an invalid response.")
    return result


def clone_token(scan_run_id: int) -> str | None:
    """Worker-side: a credential for cloning the run's repository, if one exists."""
    token = _call("clone_token", issue_clone_token, {"scan_run_id": scan_run_id}).get("token")
    return str(token) if token else None


def complete_check(scan_run_id: int, **fields: Any) -> bool:
    """Worker-side: report the run's verdict on its GitHub check, if it has one."""
    return bool(_call("complete_check", complete_run_check, {"scan_run_id": scan_run_id, **fields}).get("completed"))
