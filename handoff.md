# Aegis DevSecOps Console - Project Handoff

This document outlines the final state of **Aegis** (a retro CRT-style DevSecOps console), detailing implemented features, the new Docker sandbox environment, the background worker queue system, real-time WebSocket log streaming, key files, and instructions for running and testing the codebase.

---

## 1. Project Overview
Aegis is an interactive DevSecOps dashboard and static/dynamic analysis gate designed to simulate vulnerability audits, runtime attack vectors, Web Application Firewall (WAF) mitigations, and automated deployment gate checks. It features a premium 90s CRT monitor design with customizable retro themes, screen-glare scanlines, and animated background canvases. 

The console has been migrated from a synchronous Flask backend to an asynchronous **FastAPI + Redis + Redis Queue (RQ)** backend, streaming real-time scan job logs and container telemetry over **WebSockets** and **EventSource SSE**.

---

## 2. Implemented Features

### A. Dashboard Layout & View Modes
- **Simple View vs. Tactical View**: 
  - Accessible via a dropdown in the navigation bar.
  - **Simple View (Default)**: A clean, step-by-step layout hiding advanced logs and charts, designed for non-technical users to inspect codebase scans and run runtime threat testing.
  - **Tactical View**: Restores full high-density logs, the vector attack radar canvas, diagnostics telemetry, and the live WAF rules editor.
  - View states are persistently stored in `localStorage`.
- **Segmented Numbered Steps**: The layout is organized into sequential steps (Static Audit, Dependency Graph, Threat Lab, Vulnerability Registry, and Deployment Gate) to present a clean audit pipeline.

### B. Multi-Layer Scanner Suites & CVSS Calculator
- **Python SAST Engine (Bandit & Semgrep)**: Audits code for SQL Injection, Command Injection (RCE), Unsafe Eval, Weak Hashes, and Pickle deserialization using custom rules.
- **Live Software Composition Analysis (OSV API)**: Resolves requirements packages against the public Open Source Vulnerability (OSV) API, caching lookups locally in `scans/osv-cache.json` for 24 hours.
- **Mathematical CVSS v3.1 Calculator**: Implements the official CVSS v3.1 mathematical formula to parse base vectors and assign precise severity rankings.
- **Secret Scanner (detect-secrets)**: Analyzes the codebase for hardcoded passwords, keys, and tokens.
- **YARA Pattern Scanner**: Scans for webshell, obfuscated payload, and suspicious shell spawning signatures.
- **ClamAV Antivirus Scanner**: Checks the filesystem for malware (e.g. EICAR test string) and base64 backdoors.
- **Trivy Container Auditing**: Runs image scanning against container layers to identify operating system CVEs.
- **Dynamic DAST Routing (OWASP ZAP)**: Performs dynamic crawling and scans against local endpoints, routing scans directly against active sandbox containers.
- **Tactical Dependency Network Graph**: Generates a physical network graph highlighting vulnerable dependencies and paths of exposure with rich CVSS node tooltips.
- **Dynamic Exploitability Scoring**: Employs a CVSS-weighted, DAST-adjusted, and WAF-mitigated risk engine:
  $$Score = \min\left(100.0, \left( \sum_{i=1}^N CVSS_i \times W_{type} \right) \times E_{dast} \times (1.0 - M_{waf})\right)$$

### C. Dynamic Docker Sandbox Engine
- **Containerization Scaffolds**: Scaffolds temporary build directories and hardens target web servers via resource-constrained Docker files (`python:3.11-alpine`).
- **Resource Constraints**: Runs containers with strict execution constraints (`--memory="128m"`, `--cpus="0.5"`, `--pids-limit=50`).
- **Ephemeral Port Binders**: Dynamic sockets allocate free host ports automatically, avoiding port conflicts during concurrent scans.
- **Docker Detection & Fallback**: Diagnoses system Docker daemon availability. If unreachable, logs warnings and executes fallbacks gracefully.

### D. Asynchronous Background Worker System
- **Job Queueing**: Uses Redis Queue (RQ) to run security scans in background worker processes.
- **Scan States**: Security scan jobs progress through six discrete states: `queued` -> `running` -> `analyzing` -> `correlating` -> `reporting` -> `completed`/`failed`.
- **WebSocket Streaming (`/ws/scan/{job_id}`)**: Streams live scan execution state transitions, logs captured from stdout of running subprocesses, and custom scanner telemetry directly to the client.
- **Legacy SSE Endpoint (`/stream-telemetry`)**: Serves EventSource connections for legacy diagnostics, streaming live CPU/memory stats from running containers and syslog TCP packet captures.
- **Exploit Overload Spikes**: Spikes CPU (>85%) and latency (>250ms) gauges when payload signatures (`cat+/etc/passwd` or `subprocess` commands) appear in standard output logs.

### E. Immersive UI/UX & Visual Aesthetics
- **Developer Font Pairings**: Integrated **Fira Code** Google Font imports alongside classic military monospace styles for log readouts (`#terminal`, `#syslog-stream`), custom tooltip boxes, explainer cards, and inputs.
- **Cyber HUD Accents & Glassmorphism**:
  - Installed top-left and bottom-right absolute corner bracket lines (`::before` / `::after` pseudo-elements) to all console panels, diagnostic cards, and gate banners.
  - Layered glassmorphic background blurs (`backdrop-filter: blur(10px)`) to provide clean console transparency.
- **Responsive Mechanical Buttons**: Enhanced all dashboard and report buttons with micro-interactive hover translates, focus rings, and custom transitions.
- **Enhanced Vector Radar Canvas**: Dash radar rings, degree azimuth labels, and target impact waves.
- **Dynamic Dependency Network Graph**: Pulse animations on vulnerable library nodes, and flowing data packets sliding along dependency paths.
- **A11y Motion Compliance**: Disable screen CRT overlays, matrix rain iterations, and canvas packet streams if `@media (prefers-reduced-motion: reduce)` is enabled.

---

## 3. Key Files Directory

- [app/main.py](file:///Users/huslenine/Aegis/app/main.py): Core FastAPI web application containing vulnerable simulation endpoints, custom WAF ASGI middleware, REST routes, and WebSocket telemetry/log streaming handlers.
- [app/worker.py](file:///Users/huslenine/Aegis/app/worker.py): RQ background worker code executing scanner engines asynchronously, tracking progress states, and publishing logs to Redis [NEW].
- [app/secure_main.py](file:///Users/huslenine/Aegis/app/secure_main.py): Hardened endpoint equivalents supporting dynamic port parsing.
- [app/database.py](file:///Users/huslenine/Aegis/app/database.py): SQLite database seed code containing default WAF regexes.
- [app/sandbox.py](file:///Users/huslenine/Aegis/app/sandbox.py): Docker sandbox and telemetry queries coordinator.
- [app/templates/index.html](file:///Users/huslenine/Aegis/app/templates/index.html): CRT terminal dashboard template connecting to WebSocket and EventSource streams.
- [app/templates/report_template.html](file:///Users/huslenine/Aegis/app/templates/report_template.html): Standalone compliance report template.
- [policy_engine.py](file:///Users/huslenine/Aegis/policy_engine.py): Static scan processor running sub-audits, OSV lookups, and CVSS vector evaluations.
- [setup.sh](file:///Users/huslenine/Aegis/setup.sh): Automated environment startup script (handles Redis check/start, kills zombie workers, launches RQ worker and FastAPI via Uvicorn).
- [tests/conftest.py](file:///Users/huslenine/Aegis/tests/conftest.py): Global test configuration mocking Redis and executing RQ tasks synchronously for tests.
- [tests/test_osv_score.py](file:///Users/huslenine/Aegis/tests/test_osv_score.py): Tests CVSS base score vectors and exploitability logic.
- [tests/test_sandbox.py](file:///Users/huslenine/Aegis/tests/test_sandbox.py): Tests Docker port parser, building, running limits, and fallback.
- [tests/test_telemetry.py](file:///Users/huslenine/Aegis/tests/test_telemetry.py): Tests SSE endpoint headers, outputs, and exploit spikes.
- [tests/test_upload_scan.py](file:///Users/huslenine/Aegis/tests/test_upload_scan.py): Tests file upload vulnerability scans.
- [tests/test_waf.py](file:///Users/huslenine/Aegis/tests/test_waf.py): Tests WAF rules block and caching.

---

## 4. Setup & Verification

### Running the App Locally (Automated)
Run the setup script:
```bash
./setup.sh
```
This will:
1. Verify if Redis is running locally. If not found, it launches a Redis container via Docker.
2. Terminate any stale RQ workers.
3. Start the RQ background worker in the background.
4. Launch the FastAPI server via Uvicorn on `http://127.0.0.1:5001`.

### Running the Automated Tests
Run pytest to verify the full 60-test security scan suite:
```bash
./venv/bin/pytest
```
Currently, **60/60 tests pass successfully** with no regressions.
