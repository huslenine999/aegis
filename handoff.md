# Aegis DevSecOps Console - Project Handoff

This document outlines the final state of **Aegis** (a retro CRT-style DevSecOps simulation console), detailing implemented features, recent layout/legibility fixes, key files, and instructions for running and testing the codebase.

---

## 1. Project Overview
Aegis is an interactive DevSecOps dashboard and static/dynamic analysis gate designed to simulate vulnerability audits, runtime attack vectors, Web Application Firewall (WAF) mitigations, and automated deployment gate checks. It features a premium 90s CRT monitor design with customizable retro themes, screen-glare scanlines, and animated background canvases.

---

## 2. Implemented Features

### A. Dashboard Layout & View Modes
- **Simple View vs. Tactical View**: 
  - Accessible via a dropdown in the navigation bar.
  - **Simple View (Default)**: A clean, step-by-step layout hiding advanced logs and charts, designed for non-technical users to inspect codebase scans and run runtime threat testing.
  - **Tactical View**: Restores full high-density logs, the vector attack radar canvas, diagnostics telemetry, and the live custom WAF rules editor.
  - View states are persistently stored in `localStorage`.
- **Segmented Numbered Steps**: The layout is organized into sequential steps (Static Audit, Dependency Graph, Threat Lab, Vulnerability Registry, and Deployment Gate) to present a clean audit pipeline.

### B. Multi-Layer Scanner Suites
- **Python SAST Engine (Bandit & Semgrep)**: Audits code for SQL Injection, Command Injection (RCE), Unsafe Eval, Weak Hashes, and Pickle deserialization using custom rules.
- **Software Composition Analysis (Safety)**: Checks python dependencies for known security vulnerabilities.
- **Secret Scanner (detect-secrets)**: Analyzes the codebase for hardcoded passwords, keys, and tokens.
- **YARA Pattern Scanner**: Scans for webshell, obfuscated payload, and suspicious shell spawning signatures.
- **ClamAV Antivirus Scanner**: Checks the filesystem for malware (e.g. EICAR test string) and base64 backdoors.
- **OWASP ZAP DAST Scanner**: Performs in-memory dynamic crawling and scans against local endpoints, checking WAF mitigation block rates.
- **Tactical Dependency Network Graph**: Generates a physical network graph highlighting vulnerable dependencies and paths of exposure.

### C. CRT Custom Themes & Animation
- **Supported Themes**: 
  - **Phosphor Green** (Default Green CRT)
  - **Amber Mono** (Orange Amber CRT)
  - **Classic Grey** (Classic Monochrome Grey CRT)
  - **Matrix Digital Rain** (Black background with scrolling green code rain canvas stream)
- **Theme Synced Reports**: The theme selections and background canvas animations are shared and persistent between the dashboard and the generated Security Report page.

### D. Interactive CLI Shell & Telemetry
- **Terminal Shell**: Clicking the terminal card focuses a hidden prompt, enabling real-time terminal simulation commands (`help`, `clear`, `scan`, `waf [on/off]`, `theme [name]`, `exploit [vector]`).
- **Telemetry Gauges**: Segmented LED gauges monitor CPU, memory, and latency parameters, which dynamically spike and decay in response to simulated exploits (e.g., latency spikes during SSRF, CPU spikes during RCE).

---

## 3. Recent Bug Fixes & Accessibility Polish

### A. State Pollution & Variable Shadowing Fixes
- **WAF Test State Isolation**: Resolved a testing issue where tests setting `WAF_ENABLED = True` polluted the environment for subsequent tests. The client fixtures in `test_phase3.py`, `test_waf.py`, and `test_upload_scan.py` now run `initialize_database()` and force `app.main.WAF_ENABLED = False` before every test case runs.
- **Import Shadowing Resolution**: Fixed a Python namespace conflict where `import app.main` in fixtures shadowed the imported Flask `app` object name. Replaced it with `import app.main as app_main`.
- **Target DAST Conflicts**: Programmed the dynamic ZAP scanner to bypass running tests when scanning static target files (such as `secure_main.py` or uploaded scripts). It writes a clean empty list `[]` to `zap-report.json` instead, ensuring file scans are not blocked by the global running server status.
- **Python WAF Rule Mitigation**: Added a default WAF regex pattern rule `__import__|system\(|subprocess` to block dynamic Python code execution injection attempts against `/calculate`.
- **Landing Page JavaScript Crash**: Fixed a parser-blocking `SyntaxError: Unexpected end of input` in `index.html` by restoring a missing closing brace `}` at the end of the `setExplainMode()` function, which had completely broken client-side dashboard interactives (themes, view modes, uploader scans, and explain actions).

### B. Sizing & Legibility Improvements
- **Theme Accent Contrast**: Brightened `--text-muted` and `--secondary` color variables across all themes in both template files to resolve poor contrast against dark phosphor screen scanlines.
- **Typography Scale-Up**:
  - Explainer Box (`.explainer-box`): Upgraded font size to `1.12rem` and line-height to `1.6`.
  - Explainer Subtext (`.explainer-subtext`): Scaled font size to `1.05rem !important` and line-height to `1.6 !important` in CSS, removing constraining inline styles.
  - Terminal Feeds (`#terminal`, `#syslog-stream`): Configured to `1.02rem` and `1.6` line-height.
  - Report Descriptions (`.finding-desc`, `.finding-location`): Raised to `1.05rem` (desktop) / `0.95rem` (mobile) and `0.95rem` respectively.
  - Metrics & Telemetry: Boosted `.metric-label` to `0.95rem` with high-contrast text color overrides.
  - WAF List Editor: Increased custom regex rules row sizing to `0.98rem` (pattern) and `0.88rem` (description).

---

## 4. Key Files Directory

- [app/main.py](file:///Users/huslenine/Aegis/app/main.py): Core Flask application containing vulnerable simulation endpoints, dynamic WAF matching logic, and scanner route coordinates.
- [app/secure_main.py](file:///Users/huslenine/Aegis/app/secure_main.py): Hardened endpoint equivalents implementing input sanitization, HTML escaping, and secure socket/IP resolution rules.
- [app/database.py](file:///Users/huslenine/Aegis/app/database.py): SQLite seeding definitions containing default WAF regexes and mock databases.
- [app/templates/index.html](file:///Users/huslenine/Aegis/app/templates/index.html): Main retro CRT dashboard template containing CSS theme definitions, CLI shell bindings, SVG diagnostics monitors, and JavaScript WAF/dossier states.
- [app/templates/report_template.html](file:///Users/huslenine/Aegis/app/templates/report_template.html): Standalone Security Report compiler view equipped with custom uploader widgets and synced styling.
- [policy_engine.py](file:///Users/huslenine/Aegis/policy_engine.py): Core static scan processor running sub-audits and deciding pipeline pass/block verdicts.
- [rules/semgrep_rules.yaml](file:///Users/huslenine/Aegis/rules/semgrep_rules.yaml): Custom security rules for Python source scanning.
- [tests/test_phase1.py](file:///Users/huslenine/Aegis/tests/test_phase1.py): Unit tests verifying Secrets, YARA, and SBOM generation logic.
- [tests/test_phase2.py](file:///Users/huslenine/Aegis/tests/test_phase2.py): Unit tests verifying Semgrep SAST and dependency graphing logic.
- [tests/test_phase3.py](file:///Users/huslenine/Aegis/tests/test_phase3.py): Unit tests verifying ClamAV malware signatures and OWASP ZAP DAST scan rules.

---

## 5. Setup & Verification

### Running the App Locally
1. Start the Flask server:
   ```bash
   ./venv/bin/python app/main.py
   ```
2. Open the console dashboard at: `http://127.0.0.1:5001`.

### Running the Automated Tests
Run `pytest` to verify the WAF engine rules and scan routes:
```bash
./venv/bin/pytest
```
Currently, **43/43 tests pass successfully** with no regressions.
