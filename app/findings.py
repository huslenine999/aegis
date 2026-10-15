import hashlib
import json
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .database import USING_POSTGRES, get_connection
from .finding_queries import FINDING_STATUSES, SEVERITIES, query_findings, query_findings_page


PRESET_RANK = {"quick": 0, "standard": 1, "deep": 2}
ACTIVE_TOOLS = {"Ruff", "Semgrep", "OSV", "Secrets", "YARA", "CodeQL"}
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


BASELINE_FINGERPRINT_KEY = "aegis_fingerprint"


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


# Probability of exploitation in the next 30 days at which a dependency
# finding is treated as at least HIGH, regardless of its CVSS score.
EPSS_ESCALATION_THRESHOLD = 0.1
_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def escalate_osv_severity(severity: str, item: dict) -> tuple[str, str | None]:
    """Raise a dependency finding's severity from exploit evidence; never lower it.

    CVSS describes how bad a flaw could be. CISA KEV records that it is being
    exploited now, and EPSS estimates how likely exploitation is soon.
    """
    kev = item.get("kev")
    if isinstance(kev, dict) and kev.get("cve"):
        ransomware = ", used in ransomware campaigns" if kev.get("ransomware") else ""
        return "CRITICAL", f"{kev['cve']} is in the CISA Known Exploited Vulnerabilities catalog (added {kev.get('date_added')}{ransomware})"
    epss = item.get("epss")
    if isinstance(epss, dict) and isinstance(epss.get("score"), (int, float)):
        if epss["score"] >= EPSS_ESCALATION_THRESHOLD and _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index("HIGH"):
            return "HIGH", f"EPSS gives {epss.get('cve')} a {epss['score']:.0%} probability of exploitation in the next 30 days"
    return severity, None


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
        fingerprint_parts: tuple[Any, ...] | None = None,
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
        fingerprint = _fingerprint(
            *(fingerprint_parts if fingerprint_parts is not None else (tool, rule_id, stable_path, *identity))
        )
        if isinstance(raw, dict):
            # Tag the raw report entry so downstream policy evaluation can
            # recognize pre-existing findings without recomputing identities.
            raw.setdefault(BASELINE_FINGERPRINT_KEY, fingerprint)
        normalized.append(
            {
                "fingerprint": fingerprint,
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

    for item in (result.get("codeql") or {}).get("findings", []):
        if not isinstance(item, dict):
            continue
        path = _stable_path(item.get("filename"))
        add(
            "CodeQL",
            item.get("rule_id"),
            item.get("issue_text") or item.get("rule_id"),
            item.get("severity"),
            path=path,
            line_number=item.get("line_number"),
            fingerprint_parts=(
                "CodeQL", item.get("rule_id"), path,
                item.get("fingerprint") or item.get("partial_fingerprint")
                or (item.get("line_number"), item.get("issue_text")),
            ),
            raw=item,
        )

    for item in result.get("osv") or []:
        score = float(item.get("cvss") or 0)
        severity, _ = escalate_osv_severity(
            "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW", item
        )
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

    iac = result.get("iac") or {}
    if isinstance(iac, dict):
        for item in iac.get("findings", []) or []:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity") or "MEDIUM").upper()
            if severity not in SEVERITIES:
                severity = "MEDIUM"
            add(
                "IaC",
                item.get("rule_id"),
                item.get("title") or item.get("rule_id"),
                severity,
                path=item.get("path"),
                line_number=item.get("start_line"),
                identity=(item.get("framework"), item.get("resource")),
                fingerprint_parts=(
                    "IaC",
                    item.get("rule_id"),
                    item.get("framework"),
                    item.get("resource"),
                    _stable_path(item.get("path")),
                ),
                raw=item,
            )
        for item in iac.get("unmanaged_suppressions", []) or []:
            if not isinstance(item, dict):
                continue
            add(
                "IaC",
                item.get("rule_id"),
                item.get("title") or f"Unmanaged inline Checkov suppression for {item.get('rule_id') or 'unknown rule'}",
                "MEDIUM",
                path=item.get("path"),
                line_number=item.get("start_line"),
                identity=(item.get("framework"), item.get("resource"), "unmanaged-suppression"),
                fingerprint_parts=(
                    "IaC",
                    item.get("rule_id"),
                    item.get("framework"),
                    item.get("resource"),
                    _stable_path(item.get("path")),
                    "unmanaged-suppression",
                ),
                raw=item,
            )

    if result.get("research_only") is True:
        corpus = (result.get("bac_report") or {}).get("corpus_id")
        for item in result.get("bac_findings") or []:
            add(
                "BAC", item["rule_id"],
                f"Synthetic BAC research: {item['actor']} / {item['rule_id']} / {item['resource']}",
                "HIGH",
                fingerprint_parts=("BAC", "bac-runtime-lab", corpus, item["rule_id"], item["actor"], item["resource"]),
                raw={**item},
            )

    unique = {item["fingerprint"]: item for item in normalized}
    return list(unique.values())


def project_baseline_fingerprints(project_id: int) -> set[str]:
    """Fingerprints this project already carries from previous scans.

    Resolved findings are excluded on purpose: if a finding reappears after a
    complete scan stopped observing it, that reintroduction is treated as new.
    """
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT fingerprint FROM security_findings
               WHERE project_id = ? AND status != 'resolved'""",
            (project_id,),
        ).fetchall()
    return {str(row[0]) for row in rows}


def strip_baseline_findings(report: Any, baseline: set[str]) -> tuple[Any, int]:
    """Return a copy of a raw scanner report without baseline-tagged entries.

    Only in-memory copies are filtered; persisted evidence artifacts keep the
    full unfiltered report. Entries without a fingerprint tag are always kept
    so fail-closed behavior is preserved for anything unrecognized.
    """
    if not baseline or report is None or not isinstance(report, (dict, list)):
        return report, 0

    def split(items: list) -> tuple[list, int]:
        kept = [item for item in items if item.get(BASELINE_FINGERPRINT_KEY) not in baseline]
        return kept, len(items) - len(kept)

    exempted = 0
    if isinstance(report, list):
        kept, exempted = split(report)
        return kept, exempted

    filtered = dict(report)
    if isinstance(filtered.get("results"), list):  # Semgrep
        filtered["results"], exempted = split(filtered["results"])
    elif isinstance(filtered.get("results"), dict):  # detect-secrets
        filtered_results = {}
        for filename, items in filtered["results"].items():
            kept, count = split(items if isinstance(items, list) else [])
            exempted += count
            filtered_results[filename] = kept
        filtered["results"] = filtered_results
    elif isinstance(filtered.get("Results"), list):  # Trivy
        targets = []
        for target in filtered["Results"]:
            target_copy = dict(target)
            if isinstance(target_copy.get("Vulnerabilities"), list):
                target_copy["Vulnerabilities"], count = split(target_copy["Vulnerabilities"])
                exempted += count
            targets.append(target_copy)
        filtered["Results"] = targets
    elif isinstance(filtered.get("findings"), list):  # IaC
        filtered["findings"], exempted = split(filtered["findings"])
    return filtered, exempted


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


def sync_findings(scan_run_id: int, result: dict, *, connection=None) -> dict:
    observed = extract_findings(result)
    now = _now()
    with (nullcontext(connection) if connection is not None else get_connection()) as connection:
        if not USING_POSTGRES and not connection.in_transaction:
            connection.execute("BEGIN IMMEDIATE")
        run = connection.execute(
            "SELECT project_id, tenant_id, state, preset, target FROM scan_runs WHERE id = ?",
            (scan_run_id,),
        ).fetchone()
        if not run:
            raise ValueError("Scan run not found.")
        project_id, tenant_id, current_preset = int(run[0]), int(run[1]), str(run[3])
        if USING_POSTGRES:
            # Serialize reconciliations before taking a finding snapshot. An
            # advisory lock, because the worker login cannot lock project rows.
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtext('aegis_findings'), hashtext(?))", (str(project_id),)
            ).fetchone()
        lock = " FOR UPDATE" if USING_POSTGRES else ""
        existing_rows = connection.execute(
            """SELECT id, status, occurrence_count, last_seen_run_id, tool, fingerprint
               FROM security_findings WHERE project_id = ? ORDER BY id""" + lock,
            (project_id,),
        ).fetchall()
        existing_by_fingerprint = {row[5]: row for row in existing_rows}
        provenance = {
            int(row[0]): (int(row[1]), bool(row[2]))
            for row in connection.execute(
                """SELECT o.finding_id,
                          MAX(CASE r.preset WHEN 'deep' THEN 2 WHEN 'standard' THEN 1
                              WHEN 'quick' THEN 0 ELSE -1 END),
                          MAX(CASE WHEN o.scan_run_id = ? THEN 1 ELSE 0 END)
                   FROM finding_occurrences o JOIN scan_runs r ON r.id = o.scan_run_id
                   WHERE r.project_id = ? GROUP BY o.finding_id""",
                (scan_run_id, project_id),
            ).fetchall()
        }
        research = run[4] == "bac-research"
        observed = [item for item in observed if (item["tool"] == "BAC") == research]
        seen: set[str] = set()
        created = reopened = 0
        for item in observed:
            seen.add(item["fingerprint"])
            existing = existing_by_fingerprint.get(item["fingerprint"])
            if existing:
                if existing[3] is not None and int(existing[3]) > scan_run_id:
                    continue
                finding_id = int(existing[0])
                old_status = existing[1]
                next_status = "open" if old_status == "resolved" and not research else old_status
                occurrence_exists = provenance.get(finding_id, (-1, False))[1]
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

        completed_tools = {
            str(tool.get("name", ""))
            for tool in result.get("tools", [])
            if isinstance(tool, dict) and tool.get("status") == "completed"
        }
        resolved = 0
        if not research and completed_tools and not result.get("operational_failures"):
            current_version = result.get("profile_version")
            report_column = ", result_json" if current_version == 2 else ""
            candidate_tools = sorted(completed_tools & ACTIVE_TOOLS if current_version == 2 else completed_tools)
            tool_placeholders = ",".join("?" for _ in candidate_tools)
            previous_runs = {}
            previous_rows = connection.execute(
                f"""SELECT id, preset{report_column} FROM scan_runs
                    WHERE project_id = ? AND id IN (
                        SELECT DISTINCT last_seen_run_id FROM security_findings
                        WHERE project_id = ? AND status != 'resolved'
                        AND last_seen_run_id < ? AND tool != 'BAC'
                        AND tool IN ({tool_placeholders})
                    )""",
                (project_id, project_id, scan_run_id, *candidate_tools),
            ).fetchall() if candidate_tools else []
            for previous_run in previous_rows:
                previous_result = {}
                if current_version == 2 and previous_run[2]:
                    try:
                        decoded = json.loads(previous_run[2])
                        if isinstance(decoded, dict):
                            previous_result = {
                                field: decoded.get(field)
                                for field in ("profile_version", "source_scope", "detector_coverage")
                            }
                    except (TypeError, ValueError):
                        pass
                previous_runs[int(previous_run[0])] = (previous_run[1], previous_result)
            for existing in existing_rows:
                finding_id, old_status, _, last_seen_run_id, tool, fingerprint = existing
                if old_status == "resolved":
                    continue
                if tool == "BAC":
                    continue
                if fingerprint in seen:
                    continue
                if last_seen_run_id is not None and int(last_seen_run_id) >= scan_run_id:
                    continue
                if tool not in completed_tools:
                    continue
                previous_preset, previous_result = previous_runs.get(last_seen_run_id, (None, {}))
                if current_version == 2:
                    if tool not in ACTIVE_TOOLS or not previous_result:
                        continue
                    current_coverage = (result.get("detector_coverage") or {}).get(tool)
                    previous_coverage = (previous_result.get("detector_coverage") or {}).get(tool)
                    if (
                        previous_result.get("profile_version") != current_version
                        or not result.get("source_scope")
                        or previous_result.get("source_scope") != result["source_scope"]
                        or not isinstance(current_coverage, dict)
                        or current_coverage.get("complete") is not True
                        or not current_coverage.get("source_scope")
                        or not (current_coverage.get("config_digest") or current_coverage.get("query_digest"))
                        or current_coverage != previous_coverage
                    ):
                        continue
                elif current_version is not None:
                    continue
                highest_observed_rank = max(
                    PRESET_RANK.get(str(previous_preset), -1),
                    provenance.get(int(finding_id), (-1, False))[0],
                )
                if PRESET_RANK.get(current_preset, -1) < highest_observed_rank:
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
    search: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    with get_connection() as connection:
        return query_findings(
            connection, project_id, finding_id=finding_id, status=status,
            severity=severity, search=search, limit=limit, offset=offset,
        )


def list_findings_page(
    project_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    with get_connection() as connection:
        return query_findings_page(
            connection, project_id, status=status, severity=severity,
            search=search, limit=limit, offset=offset,
        )


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
        research_case = None
        if finding["tool"] == "BAC":
            occurrence = connection.execute(
                """SELECT o.scan_run_id, o.raw_json FROM finding_occurrences o
                   JOIN scan_runs r ON r.id = o.scan_run_id
                   WHERE o.finding_id = ? AND o.scan_run_id = ?
                   AND r.project_id = ? AND r.target = 'bac-research'""",
                (finding_id, finding["last_seen_run_id"], project_id),
            ).fetchone()
            if occurrence:
                raw = json.loads(occurrence[1])
                research_case = {
                    "scan_run_id": int(occurrence[0]), "case_id": raw["case_id"],
                    "actor": raw["actor"], "operation": raw["rule_id"], "resource": raw["resource"],
                }
    return {
        **finding,
        "events": [{
            "event_type": row[0], "from_status": row[1], "to_status": row[2],
            "note": row[3], "details": json.loads(row[4] or "{}"),
            "created_at": row[5], "actor": row[6],
        } for row in events],
        **({"research_case": research_case} if finding["tool"] == "BAC" else {}),
    }


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
