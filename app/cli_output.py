def format_duration(seconds: float) -> str:
    return f"{seconds:.2f}s"


def print_timing_summary(timings: list[dict]):
    if not timings:
        return
    print("\nScanner timings:")
    for item in timings:
        suffix = f" ({item['status']})" if item.get("status") and item["status"] != "completed" else ""
        print(f"  {item['name']}: {format_duration(item['seconds'])}{suffix}")


def format_cell(text: str, width: int, align: str = "left", color: str = "") -> str:
    if align == "left":
        padded = text.ljust(width)
    elif align == "center":
        padded = text.center(width)
    elif align == "right":
        padded = text.rjust(width)
    else:
        padded = text.ljust(width)

    if color:
        return f"{color}{padded}\033[0m"
    return padded


def print_ascii_report(results: list, final_status: str, reason: str, exploitability_score: float):
    cyan = "\033[96m"
    reset = "\033[0m"
    bold = "\033[1m"
    gray = "\033[90m"
    yellow = "\033[93m"
    green = "\033[92m"
    red = "\033[91m"

    print("\n")
    print(f"  {cyan}╔══════════════════════════════════════════════════════════════════════════╗{reset}")
    print(f"  {cyan}║{reset}   {cyan}█████╗ ███████╗ ██████╗ ██╗███████╗{reset}                                    {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██╔══██╗██╔════╝██╔════╝ ██║██╔════╝{reset}   {bold}A E G I S   S E C U R I T Y{reset}      {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}███████║█████╗  ██║  ███╗██║███████╗{reset}   {bold}S E C U R E   G A T E W A Y{reset}      {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██╔══██║██╔══╝  ██║   ██║██║╚════██║{reset}   {gray}SHIELD ACTIVE v2.0{reset}                {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██║  ██║███████╗╚██████╔╝██║███████║{reset}                                     {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝{reset}                                     {cyan}║{reset}")
    print(f"  {cyan}╚══════════════════════════════════════════════════════════════════════════╝{reset}")

    print(f"  {gray}┌──────────────────────────────┬──────────┬──────────────┬─────────────────┐{reset}")
    h1 = format_cell("SCANNER SUITE", 30, "left", "\033[96m\033[1m")
    h2 = format_cell("STATUS", 10, "center", "\033[96m\033[1m")
    h3 = format_cell("TOTAL ISSUES", 14, "right", "\033[96m\033[1m")
    h4 = format_cell("BLOCKING ISSUES", 17, "right", "\033[96m\033[1m")
    print(f"  {gray}│{reset}{h1}{gray}│{reset}{h2}{gray}│{reset}{h3}{gray}│{reset}{h4}{gray}│{reset}")
    print(f"  {gray}├──────────────────────────────┼──────────┼──────────────┼─────────────────┤{reset}")

    for r in results:
        tool_name = r["tool"]
        status = r["status"]
        total = str(r["total_issues"])
        blocking = str(r["blocking_issues"])

        if status == "PASS":
            status_text = "✔ PASS"
            status_color = green
        elif status == "FAIL":
            status_text = "✘ FAIL"
            status_color = red
        elif status == "MISSING":
            status_text = "⚠ MISSING"
            status_color = yellow
        else:
            status_text = status
            status_color = reset

        t_cell = format_cell(" " + tool_name, 30, "left")
        s_cell = format_cell(status_text, 10, "center", status_color)
        tot_cell = format_cell(total + " ", 14, "right")
        blk_cell = format_cell(blocking + " ", 17, "right", status_color if status == "FAIL" else "")
        print(f"  {gray}│{reset}{t_cell}{gray}│{reset}{s_cell}{gray}│{reset}{tot_cell}{gray}│{reset}{blk_cell}{gray}│{reset}")

    print(f"  {gray}└──────────────────────────────┴──────────┴──────────────┴─────────────────┘{reset}")
    print(f"  {cyan}╔══════════════════════════════════════════════════════════════════════════╗{reset}")

    filled_width = int(exploitability_score / 100.0 * 40.0)
    empty_width = 40 - filled_width
    gauge_str = "█" * filled_width + "░" * empty_width

    if exploitability_score >= 80.0:
        gauge_color = red
    elif exploitability_score >= 40.0:
        gauge_color = yellow
    else:
        gauge_color = green

    visible_gauge = f"  EXPLOITABILITY RISK: [{gauge_str}] {exploitability_score}%"
    padded_gauge = visible_gauge.ljust(74)
    color_gauge = padded_gauge.replace(gauge_str, gauge_color + gauge_str + reset)
    print(f"  {cyan}║{reset}{color_gauge}{cyan}║{reset}")

    print(f"  {cyan}║{reset}{' ' * 74}{cyan}║{reset}")

    if final_status == "ALLOWED":
        verdict_label = "[✔] DEPLOYMENT ALLOWED"
        verdict_color = green + bold
    elif final_status == "ERROR":
        verdict_label = "[!] SCAN INCOMPLETE"
        verdict_color = yellow + bold
    else:
        verdict_label = "[✘] DEPLOYMENT BLOCKED"
        verdict_color = red + bold

    visible_verdict = f"  VERDICT: {verdict_label}"
    padded_verdict = visible_verdict.ljust(74)
    color_verdict = padded_verdict.replace(verdict_label, verdict_color + verdict_label + reset)
    print(f"  {cyan}║{reset}{color_verdict}{cyan}║{reset}")

    visible_reason = f"  REASON:  {reason}"
    if len(visible_reason) > 72:
        visible_reason = visible_reason[:69] + "..."
    padded_reason = visible_reason.ljust(74)
    print(f"  {cyan}║{reset}{padded_reason}{cyan}║{reset}")

    print(f"  {cyan}╚══════════════════════════════════════════════════════════════════════════╝{reset}")
