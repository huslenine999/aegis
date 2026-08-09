import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .database import USING_POSTGRES, get_connection


FINDING_STATUSES = {
    "open",
    "acknowledged",
    "accepted",
    "false_positive",
    "resolved",
}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_TRANSITIONS = {
    "open": {"acknowledged", "accepted", "false_positive", "resolved"},
    "acknowledged": {"open", "accepted", "false_positive", "resolved"},
    "accepted": {"open", "resolved"},
    "false_positive": {"open", "resolved"},
    "resolved": {"open"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_datetime(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _stable_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/")
    for marker in ("/workspaces/", "/uploads/"):
        if marker in text:
            remainder = text.split(marker, 1)[1]
            text = remainder.split("/", 1)[1] if "/" in remainder else remainder
    try:
        return Path(text).as_posix() if text else ""
    except (TypeError, ValueError):
        return text


def _fingerprint(*parts: Any) -> str:
    canonical = json.dumps(
        [str(part or "").strip().lower() for part in parts],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _severity_from_ruff(code: str) -> str:
    high = {
        "S102", "S105", "S106", "S107", "S301", "S304", "S305", "S307",
        "S312", "S501", "S506", "S601", "S602", "S605", "S608", "S701",
    }
    medium = {
        "S103", "S104", "S113", "S302", "S303", "S306", "S308", "S310",
        "S313", "S314", "S315", "S316", "S317", "S318", "S319", "S320",
        "S324", "S508", "S604", "S607", "S609",
    }
    normalized = str(code or "").upper()
    return "HIGH" if normalized in high else "MEDIUM" if normalized in medium else "LOW"


def extract_findings(result: dict | None) -> list[dict]:
    """Normalize raw scanner payloads into stable, durable finding records."""
    result = result or {}
    normalized: list[dict] = []

    def add(
        tool: str,
        rule_id: Any,
        title: Any,
        severity: Any,
        *,
        path: Any = "",
        line_number: Any = None,
        identity: tuple[Any, ...] = (),
        raw: dict | None = None,
    ) -> None:
        stable_path = _stable_path(path)
        normalized_severity = str(severity or "LOW").upper()
        if normalized_severity not in SEVERITIES:
            normalized_severity = "LOW"
        try:
            line = int(line_number) if line_number is not None else None
        except (TypeError, ValueError):
            line = None
        normalized.append(
            {
                "fingerprint": _fingerprint(tool, rule_id, stable_path, *identity),
                "tool": tool,
                "rule_id": str(rule_id or ""),
                "title": str(title or rule_id or "Security finding")[:1000],
                "severity": normalized_severity,
                "path": stable_path,
                "line_number": line,
                "raw": raw or {},
            }
        )

    for item in result.get("ruff") or []:
        code = item.get("code")
        add(
            "Ruff",
            code,
            item.get("message"),
            _severity_from_ruff(str(code or "")),
            path=item.get("filename"),
            line_number=(item.get("location") or {}).get("row"),
            raw=item,
        )

    for item in (result.get("semgrep") or {}).get("results", []):
        extra = item.get("extra") or {}
        severity = {"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(
            str(extra.get("severity", "ERROR")).upper(), "LOW"
        )
        add(
            "Semgrep",
            item.get("check_id"),
            extra.get("message"),
            severity,
            path=item.get("path"),
            line_number=(item.get("start") or {}).get("line"),
            raw=item,
        )

    for item in result.get("osv") or []:
        score = float(item.get("cvss") or 0)
        severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        add(
            "OSV",
            item.get("id"),
            item.get("summary"),
            severity,
            path=item.get("package"),
            identity=(item.get("package"), item.get("version")),
            raw=item,
        )

    safety = result.get("safety") or []
    safety_items = (
        safety.get("vulnerabilities", []) or safety.get("results", [])
        if isinstance(safety, dict)
        else safety
    )
    for item in safety_items or []:
        rule = item.get("vulnerability_id") or item.get("advisory")
        package = item.get("package_name") or item.get("package")
        add(
            "Safety",
            rule,
            item.get("description") or item.get("reason"),
            "MEDIUM",
            path=package,
            identity=(package,),
            raw=item,
        )

    for target in (result.get("trivy") or {}).get("Results", []):
        for item in target.get("Vulnerabilities", []) or []:
            add(
                "Trivy",
                item.get("VulnerabilityID"),
                item.get("Title"),
                item.get("Severity"),
                path=target.get("Target"),
                identity=(item.get("PkgName"),),
                raw=item,
            )

    for filename, items in (result.get("secrets") or {}).get("results", {}).items():
        for item in items:
            add(
                "Secrets",
                item.get("type"),
                f"Potential {item.get('type') or 'secret'}",
                "HIGH",
                path=filename,
                line_number=item.get("line_number"),
                raw=item,
            )

    for item in result.get("yara") or []:
        add(
            "YARA",
            item.get("rule"),
            item.get("description") or item.get("rule"),
            "HIGH",
            path=item.get("filename"),
            raw=item,
        )

    for item in result.get("clamav") or []:
        add(
            "ClamAV",
            item.get("virus"),
            item.get("description") or item.get("virus"),
            "HIGH",
            path=item.get("filename"),
            raw=item,
        )

    for item in result.get("zap") or []:
        if item.get("status") != "EXPOSED":
            continue
        add(
            "DAST",
            item.get("vuln_type"),
            item.get("description") or item.get("vuln_type"),
            "HIGH",
            path=item.get("route"),
            identity=(item.get("route"),),
            raw=item,
        )

    unique = {item["fingerprint"]: item for item in normalized}
    return list(unique.values())


def _insert_event(
    connection,
    finding_id: int,
    event_type: str,
    *,
    actor_id: int | None = None,
    from_status: str | None = None,
    to_status: str | None = None,
    note: str = "",
    details: dict | None = None,
) -> None:
    connection.execute(
        """INSERT INTO finding_events
           (finding_id, actor_id, event_type, from_status, to_status, note,
            details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            actor_id,
            event_type,
            from_status,
            to_status,
            note or None,
            json.dumps(details or {}, separators=(",", ":")),
            _now(),
        ),
    )


def sync_findings(scan_run_id: int, result: dict) -> dict:
    observed = extract_findings(result)
    now = _now()
    with get_connection() as connection:
        run = connection.execute(
            "SELECT project_id, tenant_id, state FROM scan_runs WHERE id = ?",
            (scan_run_id,),
        ).fetchone()
        if not run:
            raise ValueError("Scan run not found.")
        project_id, tenant_id = int(run[0]), int(run[1])
        seen: set[str] = set()
        created = reopened = 0
        for item in observed:
            seen.add(item["fingerprint"])
            existing = connection.execute(
                """SELECT id, status, occurrence_count FROM security_findings
                   WHERE project_id = ? AND fingerprint = ?""",
                (project_id, item["fingerprint"]),
            ).fetchone()
            if existing:
                finding_id = int(existing[0])
                old_status = existing[1]
                next_status = "open" if old_status == "resolved" else old_status
                occurrence_exists = connection.execute(
                    """SELECT 1 FROM finding_occurrences
                       WHERE finding_id = ? AND scan_run_id = ?""",
                    (finding_id, scan_run_id),
                ).fetchone()
                connection.execute(
                    """UPDATE security_findings SET tool = ?, rule_id = ?, title = ?,
                       severity = ?, path = ?, line_number = ?, status = ?,
                       last_seen_run_id = ?, last_seen_at = ?,
                       occurrence_count = occurrence_count + ?, updated_at = ?
                       WHERE id = ?""",
                    (
                        item["tool"], item["rule_id"], item["title"],
                        item["severity"], item["path"], item["line_number"],
                        next_status, scan_run_id, now,
                        0 if occurrence_exists else 1, now, finding_id,
                    ),
                )
                if next_status != old_status:
                    reopened += 1
                    _insert_event(
                        connection, finding_id, "reopened",
                        from_status=old_status, to_status=next_status,
                        details={"scan_run_id": scan_run_id},
                    )
            else:
                insert = """INSERT INTO security_findings
                    (tenant_id, project_id, fingerprint, tool, rule_id, title,
                     severity, path, line_number, status, first_seen_run_id,
                     last_seen_run_id, first_seen_at, last_seen_at,
                     occurrence_count, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, 1, ?, ?)"""
                if USING_POSTGRES:
                    insert += " RETURNING id"
                cursor = connection.execute(
                    insert,
                    (
                        tenant_id, project_id, item["fingerprint"], item["tool"],
                        item["rule_id"], item["title"], item["severity"],
                        item["path"], item["line_number"], scan_run_id,
                        scan_run_id, now, now, now, now,
                    ),
                )
                finding_id = (
                    int(cursor.fetchone()[0])
                    if USING_POSTGRES
                    else int(getattr(cursor, "lastrowid"))
                )
                created += 1
                _insert_event(
                    connection, finding_id, "created", to_status="open",
                    details={"scan_run_id": scan_run_id},
                )
            connection.execute(
                """INSERT INTO finding_occurrences
                   (finding_id, scan_run_id, raw_json, observed_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT (finding_id, scan_run_id) DO NOTHING""",
                (
                    finding_id,
                    scan_run_id,
                    json.dumps(item["raw"], separators=(",", ":")),
                    now,
                ),
            )

        resolved = 0
        if not result.get("operational_failures"):
            candidates = connection.execute(
                """SELECT id, fingerprint, status FROM security_findings
                   WHERE project_id = ? AND status != 'resolved'""",
                (project_id,),
            ).fetchall()
            for finding_id, fingerprint, old_status in candidates:
                if fingerprint in seen:
                    continue
                connection.execute(
                    """UPDATE security_findings SET status = 'resolved',
                       resolution_note = ?, updated_at = ? WHERE id = ?""",
                    ("No longer observed in a complete scan.", now, finding_id),
                )
                _insert_event(
                    connection, int(finding_id), "auto_resolved",
                    from_status=old_status, to_status="resolved",
                    details={"scan_run_id": scan_run_id},
                )
                resolved += 1
    return {
        "observed": len(observed),
        "created": created,
        "reopened": reopened,
        "resolved": resolved,
    }


def list_findings(
    project_id: int,
    *,
    finding_id: int | None = None,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> list[dict]:
    clauses = ["f.project_id = ?"]
    parameters: list[Any] = [project_id]
    if finding_id is not None:
        clauses.append("f.id = ?")
        parameters.append(int(finding_id))
    if status:
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
    parameters.append(max(1, min(int(limit), 500)))
    with get_connection() as connection:
        rows = connection.execute(
            f"""SELECT f.id, f.fingerprint, f.tool, f.rule_id, f.title,
                       f.severity, f.path, f.line_number, f.status, f.owner_id,
                       u.username, f.due_at, f.ticket_url, f.resolution_note,
                       f.accepted_until, f.first_seen_run_id, f.last_seen_run_id,
                       f.first_seen_at, f.last_seen_at, f.occurrence_count,
                       f.updated_at
                FROM security_findings f
                LEFT JOIN auth_users u ON u.id = f.owner_id
                WHERE {' AND '.join(clauses)}
                ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                         WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,
                         f.last_seen_at DESC LIMIT ?""",
            tuple(parameters),
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


def get_finding(project_id: int, finding_id: int) -> dict | None:
    findings = list_findings(project_id, finding_id=finding_id, limit=1)
    if not findings:
        return None
    finding = findings[0]
    with get_connection() as connection:
        events = connection.execute(
            """SELECT e.event_type, e.from_status, e.to_status, e.note,
                      e.details_json, e.created_at, u.username
               FROM finding_events e LEFT JOIN auth_users u ON u.id = e.actor_id
               WHERE e.finding_id = ? ORDER BY e.id""",
            (finding_id,),
        ).fetchall()
    finding["events"] = [
        {
            "event_type": row[0], "from_status": row[1], "to_status": row[2],
            "note": row[3], "details": json.loads(row[4] or "{}"),
            "created_at": row[5], "actor": row[6],
        }
        for row in events
    ]
    return finding


def update_finding(
    project_id: int,
    finding_id: int,
    actor_id: int,
    changes: dict,
) -> dict:
    allowed_fields = {
        "status", "owner_id", "due_at", "ticket_url", "resolution_note",
        "accepted_until",
    }
    unknown = set(changes) - allowed_fields
    if unknown:
        raise ValueError("Unsupported finding fields: " + ", ".join(sorted(unknown)))
    with get_connection() as connection:
        row = connection.execute(
            """SELECT f.status, f.tenant_id FROM security_findings f
               WHERE f.id = ? AND f.project_id = ?""",
            (finding_id, project_id),
        ).fetchone()
        if not row:
            raise ValueError("Finding not found.")
        old_status, tenant_id = row[0], int(row[1])
        next_status = str(changes.get("status", old_status))
        if next_status not in FINDING_STATUSES:
            raise ValueError("Invalid finding status.")
        if next_status != old_status and next_status not in ALLOWED_TRANSITIONS[old_status]:
            raise ValueError(f"Finding cannot transition from {old_status} to {next_status}.")
        note = str(changes.get("resolution_note") or "").strip()
        if next_status in {"accepted", "false_positive"} and len(note) < 12:
            raise ValueError("Accepted risk and false positives require a meaningful note.")
        due_at = (
            _parse_datetime(changes.get("due_at"), "due_at")
            if "due_at" in changes
            else None
        )
        accepted_until = (
            _parse_datetime(changes.get("accepted_until"), "accepted_until")
            if "accepted_until" in changes
            else None
        )
        if next_status == "accepted":
            effective_expiry = accepted_until
            if "accepted_until" not in changes:
                current = connection.execute(
                    "SELECT accepted_until FROM security_findings WHERE id = ?",
                    (finding_id,),
                ).fetchone()
                effective_expiry = current[0] if current else None
            if not effective_expiry:
                raise ValueError("Accepted risk requires an expiration timestamp.")
            if datetime.fromisoformat(str(effective_expiry)) <= datetime.now(timezone.utc):
                raise ValueError("Accepted risk expiration must be in the future.")
        if "ticket_url" in changes and changes.get("ticket_url"):
            ticket_url = str(changes["ticket_url"])
            parsed_ticket = urlparse(ticket_url)
            if (
                parsed_ticket.scheme != "https"
                or not parsed_ticket.hostname
                or parsed_ticket.username
                or parsed_ticket.password
                or len(ticket_url) > 2000
            ):
                raise ValueError("ticket_url must be an absolute HTTPS URL.")
        owner_id = changes.get("owner_id")
        if owner_id is not None:
            owner = connection.execute(
                """SELECT u.id FROM auth_users u
                   JOIN project_members m ON m.user_id = u.id
                   WHERE u.id = ? AND u.tenant_id = ? AND u.active = 1
                   AND m.project_id = ?""",
                (int(owner_id), tenant_id, project_id),
            ).fetchone()
            if not owner:
                raise ValueError("Finding owner must be an active project member.")
        assignments = []
        parameters: list[Any] = []
        normalized_changes = dict(changes)
        if "due_at" in changes:
            normalized_changes["due_at"] = due_at
        if "accepted_until" in changes:
            normalized_changes["accepted_until"] = accepted_until
        for field in allowed_fields:
            if field not in normalized_changes:
                continue
            assignments.append(f"{field} = ?")
            parameters.append(normalized_changes[field] or None)
        if assignments:
            assignments.append("updated_at = ?")
            parameters.extend([_now(), finding_id, project_id])
            connection.execute(
                f"UPDATE security_findings SET {', '.join(assignments)} WHERE id = ? AND project_id = ?",
                tuple(parameters),
            )
        event_type = "status_changed" if next_status != old_status else "updated"
        _insert_event(
            connection,
            finding_id,
            event_type,
            actor_id=actor_id,
            from_status=old_status,
            to_status=next_status,
            note=note,
            details={key: changes[key] for key in changes if key != "resolution_note"},
        )
    updated = get_finding(project_id, finding_id)
    if not updated:
        raise ValueError("Finding not found after update.")
    return updated
