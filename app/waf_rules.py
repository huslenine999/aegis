"""Shared WAF rule loading for the dashboard middleware and scan workers."""

from .database import get_connection

DEFAULT_WAF_RULES = [
    {"pattern": "' OR '", "description": "SQL Injection (OR operator bypass)", "enabled": True},
    {"pattern": "1=1", "description": "SQL Injection (tautology bypass)", "enabled": True},
    {"pattern": "--", "description": "SQL comment character block", "enabled": True},
    {"pattern": "cat /etc/passwd", "description": "LFI/Command execution pattern 1", "enabled": True},
    {"pattern": "\\.\\./", "description": "Directory Traversal pattern (../)", "enabled": True},
    {"pattern": "pickle\\.loads", "description": "Python deserialization hijack detector", "enabled": True},
    {"pattern": "eval\\(", "description": "Python dynamic expression injection detector", "enabled": True},
    {"pattern": "__import__|system\\(|subprocess", "description": "Python code execution attempt", "enabled": True},
    {"pattern": "<\\s*script", "description": "XSS (Dangerous script tags)", "enabled": True},
    {"pattern": "on\\w+\\s*=", "description": "XSS (HTML event handler hijacking)", "enabled": True},
    {"pattern": "javascript\\s*:", "description": "XSS (Javascript URI prefix)", "enabled": True},
    {"pattern": "169\\.254\\.169\\.254", "description": "SSRF (Cloud metadata server IP)", "enabled": True},
    {"pattern": "localhost|127\\.0\\.0\\.1", "description": "SSRF (Localhost lookup blocker)", "enabled": True},
]


def query_waf_rules() -> list[dict] | None:
    """Return the stored WAF rules, or None when they cannot be read."""
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT pattern, description, enabled FROM waf_rules"
        ).fetchall()
        return [
            {"pattern": row[0], "description": row[1], "enabled": bool(row[2])}
            for row in rows
        ]
    except Exception:
        return None
    finally:
        connection.close()


def load_waf_rules_for_scanning() -> list[dict]:
    """Worker-facing loader: no rules are enforced when the store is unavailable."""
    return query_waf_rules() or []


def load_waf_rules_with_defaults() -> list[dict]:
    """Dashboard-facing loader: fall back to the built-in demo patterns."""
    rules = query_waf_rules()
    if rules is not None:
        return rules
    return [dict(rule) for rule in DEFAULT_WAF_RULES]


def save_waf_rules(rules: list[dict]) -> None:
    """Replace the stored WAF rule set atomically."""
    with get_connection() as connection:
        connection.execute("DELETE FROM waf_rules")
        for rule in rules:
            connection.execute(
                "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
                (rule["pattern"], rule["description"], 1 if rule["enabled"] else 0),
            )
        connection.commit()
