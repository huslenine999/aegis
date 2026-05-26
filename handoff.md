# Aegis DevSecOps Console - Project Handoff

This document outlines the current state of **Aegis** (a retro CRT-style DevSecOps simulation console), detailing implemented features, recent layout/legibility fixes, key files, and instructions for running and testing the codebase.

---

## 1. Project Overview
Aegis is an interactive DevSecOps dashboard and static analysis gate designed to simulate vulnerability audits, runtime attack vectors, Web Application Firewall (WAF) mitigations, and automated deployment gate checks. It features a premium 90s CRT monitor design with customizable retro themes, screen-glare scanlines, and animated background canvases.

---

## 2. Implemented Features

### A. Dashboard Layout & View Modes
- **Simple View vs. Tactical View**: 
  - Accessible via a dropdown in the navigation bar.
  - **Simple View (Default)**: A clean, step-by-step layout hiding advanced logs and charts, designed for non-technical users to inspect codebase scans and run runtime threat testing.
  - **Tactical View**: Restores full high-density logs, the vector attack radar canvas, diagnostics telemetry, and the live custom WAF rules editor.
  - View states are persistently stored in `localStorage`.
- **Segmented Numbered Steps**: The layout is organized into 4 logical steps (Static Audit, Threat Lab, Vulnerability Registry, and Deployment Gate) to present a clean, sequential audit pipeline.

### B. Security Scans & Custom Uploader
- **Python Script Auditing**: A file input control allows users to upload local `.py` scripts directly from either the main dashboard or the report views.
- **Client-Side Validation**: Ensures only files ending in `.py` can be processed, alerting the user of incorrect formats immediately.
- **Automatic Scan Triggering**: Uploads automatically invoke backend audits (using Bandit, Safety, and Trivy) and hot-reload results dynamically.

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

### A. Layout Bug Fixes
- **Decision Banner Div Correction**: Resolved a missing closing `</div>` tag for the `.decision-banner` element inside [report_template.html](file:///Users/huslenine/Aegis/app/templates/report_template.html). This error had nested downstream blocks (such as the tool glossary, metrics grid, uploader card, and logs tables) inside the flex banner wrapper, resulting in massive unwanted empty spaces and layout misalignment.

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
Currently, **19/19 tests pass successfully** with no regressions.
