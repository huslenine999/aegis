import os
import sys
import textwrap
from pathlib import Path

from .version import get_package_version

WIDTH = 74  # inner width of the boxes
MAX_LISTED_FINDINGS = 20
MAX_PER_FILE = 5
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_BANNER = (
    "   █████╗ ███████╗ ██████╗ ██╗███████╗",
    "  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝",
    "  ███████║█████╗  ██║  ███╗██║███████╗",
    "  ██╔══██║██╔══╝  ██║   ██║██║╚════██║",
    "  ██║  ██║███████╗╚██████╔╝██║███████║",
    "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝",
)


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("GITHUB_ACTIONS") == "true":
        return True
    return sys.stdout.isatty()


def _paint(text: str, *codes: str) -> str:
    if not codes or not _color_enabled():
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


CYAN, GRAY, RED, GREEN, YELLOW, BOLD = "96", "90", "91", "92", "93", "1"
SEVERITY_COLOR = {"CRITICAL": (RED, BOLD), "HIGH": (RED,), "MEDIUM": (YELLOW,), "LOW": (GRAY,)}


def _box_line(text: str, color_text: str | None = None) -> str:
    """One boxed line; padding is computed from the uncolored text."""
    text = text[:WIDTH]
    border = _paint("║", CYAN)
    return f"  {border}{color_text or text}{' ' * (WIDTH - len(text))}{border}"


def _box_edge(left: str, right: str) -> str:
    return "  " + _paint(left + "═" * WIDTH + right, CYAN)


def step(tool: str, message: str, level: str = "info") -> None:
    """Print one scan progress line in the shared CLI style."""
    marker = {"info": _paint("›", GRAY), "warn": _paint("!", YELLOW, BOLD), "error": _paint("✘", RED, BOLD)}[level]
    print(f"  {marker} {tool:<9} {message}")


def format_duration(seconds: float) -> str:
    return f"{seconds:.2f}s"


def print_timing_summary(timings: list[dict]):
    if not timings:
        return
    parts = []
    for item in timings:
        suffix = f" ({item['status']})" if item.get("status") and item["status"] != "completed" else ""
        parts.append(f"{item['name']} {format_duration(item['seconds'])}{suffix}")
    print(_paint("Timings: " + " · ".join(parts), GRAY))


def format_cell(text: str, width: int, align: str = "left", color: tuple[str, ...] = ()) -> str:
    padded = {"center": text.center, "right": text.rjust}.get(align, text.ljust)(width)
    return _paint(padded, *color)


def _display_path(finding: dict, base: Path | None) -> str:
    raw = str(finding.get("filename") or finding.get("path") or finding.get("package_name") or "?")
    if base is not None:
        try:
            return str(Path(raw).resolve().relative_to(base.resolve()))
        except (ValueError, OSError):
            pass
    return raw


def _finding_label(finding: dict) -> str:
    return str(
        finding.get("test_id") or finding.get("rule") or finding.get("type")
        or finding.get("id") or finding.get("vulnerability_id") or "finding"
    )


def _finding_message(finding: dict) -> str:
    return " ".join(str(
        finding.get("issue_text") or finding.get("description") or finding.get("summary")
        or finding.get("display_title") or ""
    ).split())


def print_findings(results: list, base: Path | None = None) -> None:
    """List blocking findings by file so a blocked verdict says where to look."""
    blocking = []
    other = 0
    for result in results:
        for finding in result.get("findings") or result.get("examples") or []:
            if finding.get("blocking", result.get("status") == "FAIL"):
                blocking.append((result["tool"], finding))
            else:
                other += 1
    if not blocking:
        return

    def sort_key(entry):
        tool, finding = entry
        line = str(finding.get("line_number") or "0")
        return (_display_path(finding, base), int(line) if line.isdigit() else 0,
                SEVERITY_ORDER.get(str(finding.get("severity")).upper(), 9))

    blocking.sort(key=sort_key)
    print()
    print("  " + _paint(f"BLOCKING FINDINGS ({len(blocking)})", CYAN, BOLD))
    by_file: dict[str, list] = {}
    for tool, finding in blocking:
        by_file.setdefault(_display_path(finding, base), []).append((tool, finding))
    shown = 0
    for path, entries in by_file.items():
        if shown >= MAX_LISTED_FINDINGS:
            break
        print("\n  " + _paint(path, BOLD))
        visible = entries[:min(MAX_PER_FILE, MAX_LISTED_FINDINGS - shown)]
        shown += len(visible)
        for tool, finding in visible:
            _print_finding(tool, finding)
        if len(entries) > len(visible):
            print(_paint(f"    … {len(entries) - len(visible)} more in this file", GRAY))
    hidden = len(blocking) - shown
    notes = []
    if hidden > 0:
        notes.append(f"{hidden} more blocking")
    if other:
        notes.append(f"{other} non-blocking")
    if notes:
        print("\n  " + _paint(f"+ {', '.join(notes)} finding(s) in the full report.", GRAY))


def _print_finding(tool: str, finding: dict) -> None:
    severity = str(finding.get("severity") or "MEDIUM").upper()
    line = str(finding.get("line_number") or "")
    location = f"L{line}" if line else "—"
    tool_name = tool.split(" (")[0].replace(" Scanner", "").replace(" Dependency Audit", "")
    head = (
        f"    {location:<6} "
        f"{_paint(severity.ljust(8), *SEVERITY_COLOR.get(severity, ()))} "
        f"{_finding_label(finding)} {_paint('[' + tool_name + ']', GRAY)}"
    )
    print(head)
    message = _finding_message(finding)
    if message and _finding_label(finding) not in message:
        for wrapped in textwrap.wrap(message, 68)[:2]:
            print(_paint(f"           {wrapped}", GRAY))


def print_ascii_report(
    results: list,
    final_status: str,
    reason: str,
    exploitability_score: float,
    base: Path | None = None,
):
    print("\n")
    print(_box_edge("╔", "╗"))
    titles = ("", "A E G I S   S E C U R I T Y", "S E C U R E   G A T E W A Y", f"v{get_package_version()}", "", "")
    for art, title in zip(_BANNER, titles):
        art_padded = art.ljust(39)
        colored_title = _paint(title, GRAY) if title.startswith("v") else _paint(title, BOLD)
        print(_box_line(art_padded + title, _paint(art_padded, CYAN) + colored_title))
    print(_box_edge("╚", "╝"))

    widths = (30, 10, 14, 17)
    print("  " + _paint("┌" + "┬".join("─" * w for w in widths) + "┐", GRAY))
    bar = _paint("│", GRAY)
    headers = ((" SCANNER SUITE", "left"), ("STATUS", "center"), ("TOTAL ISSUES ", "right"), ("BLOCKING ISSUES ", "right"))
    print("  " + bar + bar.join(format_cell(text, w, align, (CYAN, BOLD)) for (text, align), w in zip(headers, widths)) + bar)
    print("  " + _paint("├" + "┼".join("─" * w for w in widths) + "┤", GRAY))

    status_style = {
        "PASS": ("✔ PASS", (GREEN,)),
        "FAIL": ("✘ FAIL", (RED,)),
        "MISSING": ("⚠ MISSING", (YELLOW,)),
        "ERROR": ("✘ ERROR", (YELLOW,)),
    }
    for r in results:
        status_text, status_color = status_style.get(r["status"], (r["status"], ()))
        cells = (
            format_cell(" " + r["tool"], widths[0]),
            format_cell(status_text, widths[1], "center", status_color),
            format_cell(f"{r['total_issues']} ", widths[2], "right"),
            format_cell(f"{r['blocking_issues']} ", widths[3], "right", status_color if r["status"] == "FAIL" else ()),
        )
        print("  " + bar + bar.join(cells) + bar)
    print("  " + _paint("└" + "┴".join("─" * w for w in widths) + "┘", GRAY))

    print_findings(results, base)

    print()
    print(_box_edge("╔", "╗"))
    filled = max(0, min(36, int(exploitability_score / 100.0 * 36.0)))
    gauge = "█" * filled + "░" * (36 - filled)
    gauge_color = RED if exploitability_score >= 80.0 else YELLOW if exploitability_score >= 40.0 else GREEN
    prefix, suffix = "  HEURISTIC RISK INDEX: [", f"] {exploitability_score:g}/100"
    print(_box_line(prefix + gauge + suffix, prefix + _paint(gauge, gauge_color) + suffix))
    print(_box_line(""))

    verdict, verdict_color = {
        "ALLOWED": ("[✔] DEPLOYMENT ALLOWED", GREEN),
        "ERROR": ("[!] SCAN INCOMPLETE", YELLOW),
    }.get(final_status, ("[✘] DEPLOYMENT BLOCKED", RED))
    print(_box_line(f"  VERDICT: {verdict}", f"  VERDICT: {_paint(verdict, verdict_color, BOLD)}"))
    reason_lines = textwrap.wrap(" ".join(str(reason).split()), WIDTH - 12) or [""]
    for index, text in enumerate(reason_lines):
        print(_box_line(("  REASON:  " if index == 0 else " " * 11) + text))
    print(_box_edge("╚", "╝"))
