from typing import Any

from . import database


FINDING_STATUSES = {"open", "acknowledged", "accepted", "false_positive", "resolved"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _finding_filters(
    project_id: int,
    *,
    finding_id: int | None = None,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
) -> tuple[str, list[Any]]:
    clauses = ["f.project_id = ?"]
    parameters: list[Any] = [project_id]
    if finding_id is not None:
        clauses.append("f.id = ?")
        parameters.append(int(finding_id))
    if status == "active":
        clauses.append("f.status IN ('open', 'acknowledged')")
    elif status and status != "all":
        if status not in FINDING_STATUSES:
            raise ValueError("Invalid finding status.")
        clauses.append("f.status = ?")
        parameters.append(status)
    if severity:
        severity = severity.upper()
        if severity not in SEVERITIES:
            raise ValueError("Invalid finding severity.")
        clauses.append("f.severity = ?")
        parameters.append(severity)
    if search is not None:
        if len(search) > 200:
            raise ValueError("Finding search must be at most 200 characters.")
        search = search.strip().lower()
        if search:
            escaped = search.replace("!", "!!").replace("%", "!%").replace("_", "!_")
            lower_function = "LOWER" if database.USING_POSTGRES else "unicode_lower"
            clauses.append(
                f"{lower_function}(f.title || ' ' || f.tool || ' ' || COALESCE(f.rule_id, '') || ' ' || COALESCE(f.path, '') "
                "|| ' ' || COALESCE(u.username, '')) "
                "LIKE ? ESCAPE '!'"
            )
            parameters.append(f"%{escaped}%")
    return " AND ".join(clauses), parameters


def _finding_page_bounds(limit: int, offset: int) -> None:
    if not 1 <= limit <= 500:
        raise ValueError("Finding limit must be between 1 and 500.")
    if not 0 <= offset <= 2_147_483_647:
        raise ValueError("Finding offset must be between 0 and 2147483647.")


def _read_findings(connection, where: str, parameters: list[Any], limit: int, offset: int) -> list[dict]:
    rows = connection.execute(
        f"""SELECT f.id, f.fingerprint, f.tool, f.rule_id, f.title,
                   f.severity, f.path, f.line_number, f.status, f.owner_id,
                   u.username, f.due_at, f.ticket_url, f.resolution_note,
                   f.accepted_until, f.first_seen_run_id, f.last_seen_run_id,
                   f.first_seen_at, f.last_seen_at, f.occurrence_count,
                   f.updated_at
            FROM security_findings f
            LEFT JOIN auth_users u ON u.id = f.owner_id
            WHERE {where}
            ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                     WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,
                     f.last_seen_at DESC, f.id ASC LIMIT ? OFFSET ?""",
        (*parameters, limit, offset),
    ).fetchall()
    return [
        {
            "id": int(row[0]), "fingerprint": row[1], "tool": row[2],
            "rule_id": row[3], "title": row[4], "severity": row[5],
            "path": row[6], "line_number": row[7], "status": row[8],
            "owner_id": int(row[9]) if row[9] is not None else None,
            "owner": row[10], "due_at": row[11], "ticket_url": row[12],
            "resolution_note": row[13], "accepted_until": row[14],
            "first_seen_run_id": row[15], "last_seen_run_id": row[16],
            "first_seen_at": row[17], "last_seen_at": row[18],
            "occurrence_count": int(row[19]), "updated_at": row[20],
        }
        for row in rows
    ]


def query_findings(
    connection,
    project_id: int,
    *,
    finding_id: int | None = None,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    _finding_page_bounds(limit, offset)
    where, parameters = _finding_filters(
        project_id, finding_id=finding_id, status=status, severity=severity, search=search,
    )
    return _read_findings(connection, where, parameters, limit, offset)


def query_findings_page(
    connection,
    project_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    _finding_page_bounds(limit, offset)
    where, parameters = _finding_filters(project_id, status=status, severity=severity, search=search)
    records = _read_findings(connection, where, parameters, limit, offset)
    total = connection.execute(
        f"""SELECT COUNT(*) FROM security_findings f
            LEFT JOIN auth_users u ON u.id = f.owner_id WHERE {where}""", tuple(parameters),
    ).fetchone()[0]
    summary = connection.execute(
        """SELECT COUNT(*),
                  COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') AND tool != 'BAC' THEN 1 END)
           FROM security_findings
           WHERE project_id = ? AND status NOT IN ('resolved', 'false_positive')""",
        (project_id,),
    ).fetchone()
    return {
        "findings": records, "total": int(total), "limit": limit, "offset": offset,
        "summary": {"open": int(summary[0]), "blockers": int(summary[1])},
    }
