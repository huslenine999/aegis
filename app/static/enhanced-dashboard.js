(function () {
    const HISTORY_KEY = "aegis.scanHistory.v1";
    const SETTINGS_KEY = "aegis.dashboardSettings.v1";
    const ADMIN_TOKEN_KEY = "aegis.adminToken.v1"; // pragma: allowlist secret
    const stateOrder = ["queued", "running", "analyzing", "correlating", "reporting", "completed"];
    let currentFilter = "all";
    let currentScanner = "all";
    let currentQuery = "";
    let latestResults = null;
    let currentJob = null;
    let csrfToken = "";
    let identityPromise = null;

    const $ = (id) => document.getElementById(id);

    function readJson(key, fallback) {
        try {
            return JSON.parse(localStorage.getItem(key)) || fallback;
        } catch (_) {
            return fallback;
        }
    }

    function writeJson(key, value) {
        localStorage.setItem(key, JSON.stringify(value));
    }

    function readAdminToken() {
        try {
            return sessionStorage.getItem(ADMIN_TOKEN_KEY) || "";
        } catch (_) {
            return "";
        }
    }

    function writeAdminToken(token) {
        try {
            if (token) {
                sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
            } else {
                sessionStorage.removeItem(ADMIN_TOKEN_KEY);
            }
        } catch (_) {
            // Browsers with disabled session storage can still enter a token per prompt.
        }
    }

    async function loadIdentity() {
        if (!identityPromise) {
            identityPromise = window.fetch("/api/auth/me", { credentials: "same-origin" })
                .then(async (response) => {
                    if (response.status === 401) {
                        window.location.assign("/login");
                        throw new Error("Authentication required");
                    }
                    if (!response.ok) throw new Error("Unable to load identity");
                    const identity = await response.json();
                    csrfToken = identity.csrf_token || "";
                    return identity;
                })
                .catch((error) => {
                    identityPromise = null;
                    throw error;
                });
        }
        return identityPromise;
    }

    async function authenticatedFetch(input, init) {
        const options = { ...(init || {}) };
        const headers = new Headers(options.headers || {});
        const token = readAdminToken();
        if (token) headers.set("X-Aegis-Token", token);
        const method = String(options.method || "GET").toUpperCase();
        if (!["GET", "HEAD", "OPTIONS"].includes(method) && !token) {
            if (!csrfToken) await loadIdentity();
            headers.set("X-CSRF-Token", csrfToken);
        }
        options.headers = headers;
        options.credentials = "same-origin";

        const response = await window.fetch(input, options);
        if (response.status === 401) window.location.assign("/login");
        return response;
    }

    async function loadWorkspaceSettings() {
        try {
            const response = await window.fetch("/api/settings", { credentials: "same-origin" });
            if (!response.ok) return;
            const settings = await response.json();
            setText("uxWorkspaceName", settings.workspace_name || "Aegis Core");
            const context = settings.repository
                ? `${settings.scan_preset || "standard"} · ${settings.repository}`
                : `${settings.scan_preset || "standard"} scan preset`;
            setText("uxWorkspaceContext", context);
        } catch (_) {
            // Keep the static workspace fallback when settings are unavailable.
        }
    }

    function setText(id, text) {
        const el = $(id);
        if (el) el.textContent = text;
    }

    function severityRank(severity) {
        const normalized = String(severity || "info").toLowerCase();
        return { critical: 0, high: 1, error: 1, medium: 2, warning: 2, low: 3, info: 4 }[normalized] ?? 4;
    }

    function normalizeSeverity(severity) {
        const s = String(severity || "info").toLowerCase();
        if (s === "error") return "high";
        if (s === "warning") return "medium";
        return s;
    }

    function formatDate(epochSeconds) {
        if (!epochSeconds) return "No report found";
        return new Date(epochSeconds * 1000).toLocaleString();
    }

    function guidanceFor(scanner, code, title, fallbackFix) {
        const rule = String(code || title || "").toLowerCase();
        const base = {
            what: title || `${scanner} finding`,
            why: "Security reviewers need to confirm whether this can be reached by untrusted input or shipped dependencies.",
            fix: fallbackFix || "Review the finding, apply the scanner recommendation, and rerun the audit.",
            status: "Pre-existing in the latest local evidence unless project baselines say otherwise.",
            suppress: "Suppress only with a named owner, a short reason, and a follow-up review date.",
            fixSuggestion: fallbackFix || "aegis scan .",
        };

        if (scanner === "Ruff") {
            if (rule.includes("s307") || rule.includes("eval")) {
                return {
                    ...base,
                    why: "Dynamic evaluation can execute attacker-controlled Python code.",
                    fix: "Replace eval or exec with a parser, allowlist, or explicit operation map.",
                    fixSuggestion: "Replace eval(user_input) with an allowlisted parser or command map.",
                };
            }
            if (rule.includes("s602") || rule.includes("shell")) {
                return {
                    ...base,
                    why: "Shell invocation can turn string input into command injection.",
                    fix: "Pass arguments as a list with shell disabled and validate every user-controlled value.",
                    fixSuggestion: "subprocess.run([\"cmd\", safe_arg], shell=False, check=True)",
                };
            }
            if (rule.includes("s608") || rule.includes("sql")) {
                return {
                    ...base,
                    why: "String-built SQL can let input change the query structure.",
                    fix: "Use parameterized queries or ORM bind parameters.",
                    fixSuggestion: "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))",
                };
            }
            if (rule.includes("s105") || rule.includes("s106") || rule.includes("secret")) {
                return {
                    ...base,
                    why: "Hardcoded credentials are easy to leak through source control and logs.",
                    fix: "Rotate the value and load it from environment variables or a secret manager.",
                    fixSuggestion: "export AEGIS_SECRET_NAME=\"value-from-secret-manager\"",
                };
            }
        }

        if (scanner === "Semgrep") {
            return {
                ...base,
                why: "The rule matched a risky source-to-sink pattern that can become exploitable in production paths.",
                fix: fallbackFix || "Follow the Semgrep rule guidance, then add a focused regression test.",
                fixSuggestion: fallbackFix || "Apply the Semgrep rule recommendation and rerun aegis scan .",
            };
        }

        if (scanner === "OSV") {
            return {
                ...base,
                why: "Vulnerable dependencies can expose the app even when first-party code looks clean.",
                fix: fallbackFix || "Upgrade to a patched dependency version and regenerate the lockfile.",
                fixSuggestion: fallbackFix || "python -m pip install --upgrade <package>",
            };
        }

        if (scanner === "IaC") {
            return {
                ...base,
                why: "Infrastructure configuration defines the security boundary before application code runs.",
                fix: fallbackFix || "Apply the least-privilege Checkov remediation and rerun the IaC audit.",
                fixSuggestion: fallbackFix || "Review the Checkov remediation, update the manifest, then rerun aegis scan .",
            };
        }

        return base;
    }

    function activateTab(tab) {
        const target = tab.dataset.tab;
        const dashboard = $("modern-dashboard");
        if (dashboard) dashboard.dataset.activePanel = target;
        document.querySelectorAll(".modern-tab").forEach((item) => {
            const isActive = item === tab;
            item.classList.toggle("active", isActive);
            item.setAttribute("aria-selected", String(isActive));
            item.tabIndex = isActive ? 0 : -1;
        });
        document.querySelectorAll(".modern-tab-panel").forEach((panel) => {
            const isActive = panel.dataset.panel === target;
            panel.classList.toggle("active", isActive);
            panel.hidden = !isActive;
        });
        setText("uxViewTitle", tab.querySelector("span")?.textContent || target);
    }

    function updateTabs() {
        const tabs = Array.from(document.querySelectorAll(".modern-tab"));
        tabs.forEach((tab, index) => {
            tab.addEventListener("click", () => activateTab(tab));
            tab.addEventListener("keydown", (event) => {
                const forward = event.key === "ArrowDown" || event.key === "ArrowRight";
                const backward = event.key === "ArrowUp" || event.key === "ArrowLeft";
                if (!forward && !backward) return;
                event.preventDefault();
                const nextIndex = forward
                    ? (index + 1) % tabs.length
                    : (index - 1 + tabs.length) % tabs.length;
                tabs[nextIndex].focus();
                activateTab(tabs[nextIndex]);
            });
        });
        document.querySelectorAll(".modern-tab-panel").forEach((panel) => {
            panel.hidden = !panel.classList.contains("active");
        });
    }

    function setScanBusy(isBusy) {
        ["uxScanBtn", "uxHeaderScanBtn"].forEach((id) => {
            const button = $(id);
            if (!button) return;
            button.disabled = isBusy;
            button.setAttribute("aria-busy", String(isBusy));
        });
        setText("uxHeaderScanLabel", isBusy ? "Audit running" : "Run audit");
        $("modern-dashboard")?.classList.toggle("scan-active", isBusy);
        document.querySelector(".progress-card")?.classList.toggle("is-scanning", isBusy);
    }

    function setProgress(state) {
        const normalized = String(state || "queued").toLowerCase();
        const activeIndex = stateOrder.indexOf(normalized);
        document.querySelectorAll(".modern-step").forEach((step) => {
            const index = stateOrder.indexOf(step.dataset.step);
            step.classList.toggle("done", activeIndex >= 0 && index < activeIndex);
            step.classList.toggle("active", step.dataset.step === normalized);
        });
        setText("uxProgressTitle", normalized.charAt(0).toUpperCase() + normalized.slice(1));
        const progressCard = document.querySelector(".progress-card");
        if (progressCard) progressCard.dataset.state = normalized;
    }

    function appendLog(text, color) {
        const log = $("uxLogStream");
        if (!log) return;
        if (log.classList.contains("empty-state") || log.textContent === "No live scan events yet.") {
            log.textContent = "";
            log.classList.remove("empty-state");
        }
        const line = document.createElement("div");
        line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
        if (color) line.style.color = color;
        log.appendChild(line);
        log.scrollTop = log.scrollHeight;
    }

    function buildFindings(data) {
        const findings = [];

        (data.ruff || []).forEach((item) => {
            const code = item.code || "RUFF";
            const severity = ["S102", "S105", "S106", "S107", "S301", "S307", "S601", "S602", "S608"].includes(code)
                ? "high"
                : "medium";
            findings.push({
                severity,
                scanner: "Ruff",
                code,
                title: item.message || code,
                location: `${item.filename || "unknown"}:${item.location?.row || "?"}`,
                ...guidanceFor("Ruff", code, item.message || code, item.remediation || item.fix_suggestion || "Review the flagged line and replace unsafe input handling with a safer API or validation path."),
                suppress: item.suppression_guidance || "Suppress only after reviewing exploitability and documenting the accepted risk.",
                status: item.finding_status || "Pre-existing in this local scan evidence.",
            });
        });

        ((data.semgrep || {}).results || []).forEach((item) => {
            const title = item.extra?.message || item.check_id || "Semgrep finding";
            const rule = item.check_id || title;
            findings.push({
                severity: normalizeSeverity(item.extra?.severity || "medium"),
                scanner: "Semgrep",
                code: rule,
                title,
                location: `${item.path || "unknown"}:${item.start?.line || "?"}`,
                ...guidanceFor("Semgrep", rule, title, item.extra?.fix || item.extra?.metadata?.fix || "Follow the rule message, then rerun the scan to confirm the issue is gone."),
                suppress: item.extra?.metadata?.suppression_guidance || "Suppress with a nosemgrep comment only when the specific data path is proven safe.",
                status: item.finding_status || "Pre-existing in this local scan evidence.",
            });
        });

        (data.osv || []).forEach((item) => {
            const title = `${item.package || "dependency"} ${item.id || "vulnerability"}`;
            findings.push({
                severity: (item.cvss || 0) >= 7 ? "high" : "medium",
                scanner: "OSV",
                code: item.id || item.package || "OSV",
                title,
                location: "requirements.txt",
                ...guidanceFor("OSV", item.id || item.package, title, item.fix || "Upgrade the affected dependency to a patched version."),
                suppress: item.suppression_guidance || "Suppress only when the vulnerable package is unreachable or protected by a compensating control.",
                status: item.finding_status || "Pre-existing in this local scan evidence.",
            });
        });

        const iacReport = data.iac || {};
        const iacItems = [
            ...(iacReport.findings || []).map((item) => ({ ...item, _unmanaged: false })),
            ...(iacReport.unmanaged_suppressions || []).map((item) => ({ ...item, _unmanaged: true })),
        ];
        iacItems.forEach((item) => {
            const rule = item.rule_id || "IaC";
            const title = item.title || `${item.framework || "IaC"} configuration finding`;
            const location = `${item.path || "unknown"}:${item.start_line || "?"}${item.end_line && item.end_line !== item.start_line ? `-${item.end_line}` : ""}`;
            const unmanaged = item._unmanaged || item.source === "repository-inline-checkov";
            findings.push({
                severity: unmanaged ? "medium" : normalizeSeverity(item.severity || "medium"),
                scanner: "IaC",
                code: rule,
                title,
                location,
                ...guidanceFor("IaC", rule, title, item.remediation || item.comment || "Apply the Checkov remediation and rerun the audit."),
                ...(unmanaged ? {
                    why: "A repository-controlled Checkov suppression is not an Aegis-approved, expiring disposition.",
                } : {}),
                suppress: unmanaged
                    ? "Replace this inline suppression with an Aegis-approved ticketed suppression with an expiry."
                    : "Suppress only with a named owner, ticket, and expiry after reviewing the configuration risk.",
                status: unmanaged ? "Unmanaged repository suppression" : (item.finding_status || "Pre-existing in this local scan evidence."),
            });
        });

        Object.entries((data.secrets || {}).results || {}).forEach(([file, secrets]) => {
            (secrets || []).forEach((secret) => {
                findings.push({
                    severity: "high",
                    scanner: "Secrets",
                    code: secret.type || "secret",
                    title: secret.type || "Potential secret",
                    location: `${file}:${secret.line_number || "?"}`,
                    ...guidanceFor("Secrets", secret.type, secret.type || "Potential secret", "Remove the secret from source, rotate it, and load it from a secret manager or environment variable."),
                    why: "Committed credentials can be copied from history even after the line is removed.",
                    suppress: "Suppress only for verified test fixtures or scanner false positives.",
                    status: "Pre-existing in this local scan evidence.",
                });
            });
        });

        (data.yara || []).forEach((item) => {
            findings.push({
                severity: "high",
                scanner: "YARA",
                code: item.rule || "YARA",
                title: item.rule || "Suspicious signature",
                location: item.filename || "unknown",
                ...guidanceFor("YARA", item.rule, item.rule || "Suspicious signature", item.description || "Review the matched code and remove suspicious behavior if it is not expected."),
                suppress: "Suppress only after confirming the matched behavior is intentional and documented.",
                status: "Pre-existing in this local scan evidence.",
            });
        });

        (data.clamav || []).forEach((item) => {
            findings.push({
                severity: "critical",
                scanner: "ClamAV",
                code: item.virus || "malware",
                title: item.virus || "Malware signature",
                location: item.filename || "unknown",
                ...guidanceFor("ClamAV", item.virus, item.virus || "Malware signature", item.description || "Quarantine the file and verify its origin before restoring it."),
                why: "Malware signatures indicate code or artifacts that can compromise developer and runtime systems.",
                suppress: "Do not suppress unless the signature is a verified scanner false positive.",
                status: "Pre-existing in this local scan evidence.",
            });
        });

        (data.zap || []).filter((item) => item.status === "EXPOSED").forEach((item) => {
            findings.push({
                severity: "high",
                scanner: "DAST",
                code: item.vuln_type || "DAST",
                title: item.vuln_type || "Exposed route",
                location: item.route || "runtime endpoint",
                ...guidanceFor("DAST", item.vuln_type, item.vuln_type || "Exposed route", item.description || "Add input validation, output encoding, or WAF coverage for this route."),
                why: "The running app accepted a hostile request path during dynamic testing.",
                suppress: "Suppress only if the route is intentionally exposed and protected by another control.",
                status: "Pre-existing in this local scan evidence.",
            });
        });

        return findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    }

    function renderFindings(data) {
        const container = $("uxFindings");
        if (!container) return;
        const findings = buildFindings(data);
        const scannerSelect = $("uxScannerFilter");
        if (scannerSelect) {
            const scanners = [...new Set(findings.map((finding) => finding.scanner))].sort();
            const existing = [...scannerSelect.options].slice(1).map((option) => option.value);
            if (existing.join("|") !== scanners.join("|")) {
                scannerSelect.innerHTML = '<option value="all">All scanners</option>';
                scanners.forEach((scanner) => {
                    const option = document.createElement("option");
                    option.value = scanner;
                    option.textContent = scanner;
                    scannerSelect.appendChild(option);
                });
                currentScanner = scanners.includes(currentScanner) ? currentScanner : "all";
                scannerSelect.value = currentScanner;
            }
        }

        const counts = findings.reduce((summary, finding) => {
            const severity = normalizeSeverity(finding.severity);
            summary[severity] = (summary[severity] || 0) + 1;
            return summary;
        }, {});
        setText("uxSummaryCritical", String(counts.critical || 0));
        setText("uxSummaryHigh", String(counts.high || 0));
        setText("uxSummaryMedium", String(counts.medium || 0));
        setText("uxSummaryLow", String((counts.low || 0) + (counts.info || 0)));

        const query = currentQuery.toLowerCase();
        const visible = findings.filter((finding) => {
            const normalizedSeverity = normalizeSeverity(finding.severity);
            const severityMatches = currentFilter === "all"
                || normalizedSeverity === currentFilter
                || (currentFilter === "low" && normalizedSeverity === "info");
            const scannerMatches = currentScanner === "all" || finding.scanner === currentScanner;
            const queryMatches = !query || [finding.title, finding.scanner, finding.location, finding.fix]
                .some((value) => String(value || "").toLowerCase().includes(query));
            return severityMatches && scannerMatches && queryMatches;
        });
        setText("uxFindingsCount", `${visible.length} ${visible.length === 1 ? "finding" : "findings"}`);

        if (!visible.length) {
            container.className = "modern-findings empty-state";
            container.innerHTML = findings.length
                ? '<div class="findings-empty"><strong>No matching findings</strong><span>Adjust the search or filters to widen the triage queue.</span></div>'
                : '<div class="findings-empty"><strong>No actionable findings</strong><span>The latest evidence contains no issues requiring triage.</span></div>';
            return;
        }

        container.className = "modern-findings";
        container.innerHTML = "";
        visible.forEach((finding, index) => {
            const item = document.createElement("div");
            item.className = "modern-finding";
            const severity = normalizeSeverity(finding.severity);
            item.innerHTML = `
                <div class="finding-index">${String(index + 1).padStart(2, "0")}</div>
                <div class="finding-main">
                    <div class="finding-title-row">
                        <div class="modern-finding-title">${escapeHtml(finding.title)}</div>
                        <div class="modern-severity ${severity}">${severity.toUpperCase()}</div>
                    </div>
                    <div class="modern-finding-meta"><span>${escapeHtml(finding.scanner)}</span>${escapeHtml(finding.location)}</div>
                    <div class="modern-finding-fix">${escapeHtml(finding.fix)}</div>
                    <div class="finding-help-grid">
                        <div><span>What failed</span><p>${escapeHtml(finding.what || finding.title)}</p></div>
                        <div><span>Why it matters</span><p>${escapeHtml(finding.why)}</p></div>
                        <div><span>How to fix</span><p>${escapeHtml(finding.fix)}</p></div>
                        <div><span>Status</span><p>${escapeHtml(finding.status)}</p></div>
                        <div><span>Safe to suppress</span><p>${escapeHtml(finding.suppress)}</p></div>
                    </div>
                </div>
                <div class="finding-actions">
                    <button class="modern-btn compact finding-copy" type="button" data-copy-fix="${escapeHtml(finding.fixSuggestion || finding.fix)}">Copy fix</button>
                    <a class="finding-evidence" href="/report">Evidence ↗</a>
                </div>
            `;
            item.querySelector(".finding-copy")?.addEventListener("click", async (event) => {
                const button = event.currentTarget;
                try {
                    await navigator.clipboard.writeText(button.dataset.copyFix || finding.fix || "");
                    button.textContent = "Copied";
                    setTimeout(() => { button.textContent = "Copy fix"; }, 1200);
                } catch (_) {
                    button.textContent = "Copy failed";
                    setTimeout(() => { button.textContent = "Copy fix"; }, 1200);
                }
            });
            container.appendChild(item);
        });
    }

    function escapeHtml(value) {
        return String(value || "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function showToast(title, message, tone = "neutral") {
        const region = $("uxToastRegion");
        if (!region) return;
        const toast = document.createElement("div");
        toast.className = `aegis-toast ${tone}`;
        toast.innerHTML = `<i></i><div><strong>${escapeHtml(title)}</strong><span>${escapeHtml(message)}</span></div>`;
        region.replaceChildren(toast);
        window.setTimeout(() => toast.classList.add("visible"), 10);
        window.setTimeout(() => {
            toast.classList.remove("visible");
            window.setTimeout(() => toast.remove(), 220);
        }, 3200);
    }

    function renderTelemetry(data) {
        const container = $("uxTelemetryScanners");
        if (!container) return;
        const findings = buildFindings(data);
        const sources = [
            ["ruff", "Ruff"], ["semgrep", "Semgrep"], ["osv", "OSV"],
            ["iac", "IaC"], ["secrets", "Secrets"], ["yara", "YARA"], ["clamav", "ClamAV"], ["zap", "DAST"],
        ];
        let alerts = 0;
        container.innerHTML = sources.map(([key, label]) => {
            const sourceFindings = findings.filter((finding) => finding.scanner === label);
            const hasEvidence = data[key] !== null && data[key] !== undefined;
            const state = sourceFindings.length ? "alert" : (hasEvidence ? "ready" : "standby");
            if (state === "alert") alerts += 1;
            return `<span class="telemetry-source ${state}"><i></i>${label}<small>${state === "alert" ? sourceFindings.length : state}</small></span>`;
        }).join("");
        setText("uxTelemetryState", alerts ? `${alerts} alert ${alerts === 1 ? "source" : "sources"}` : "Signals nominal");
    }

    async function loadTopology() {
        const container = $("uxTopologyMap");
        if (!container) return;
        container.className = "topology-map loading";
        container.setAttribute("aria-label", "Loading dependency topology");
        try {
            const response = await fetch("/get-dependency-graph");
            if (!response.ok) throw new Error(`Topology request failed (${response.status})`);
            const data = await response.json();
            const allNodes = Array.isArray(data.nodes) ? data.nodes : [];
            const allLinks = Array.isArray(data.links) ? data.links : [];
            const root = allNodes.find((node) => node.isRoot || node.id === "aegis");
            const prioritized = allNodes
                .filter((node) => node !== root)
                .sort((a, b) => Number(!!b.vulnerable) - Number(!!a.vulnerable));
            const selected = [root, ...prioritized].filter(Boolean).slice(0, 18);
            const selectedIds = new Set(selected.map((node) => node.id));
            const links = allLinks.filter((link) => selectedIds.has(link.source) && selectedIds.has(link.target));

            const depth = new Map([[root?.id || "aegis", 0]]);
            for (let pass = 0; pass < selected.length; pass += 1) {
                links.forEach((link) => {
                    if (depth.has(link.source) && !depth.has(link.target)) {
                        depth.set(link.target, depth.get(link.source) + 1);
                    }
                });
            }
            selected.forEach((node) => {
                if (!depth.has(node.id)) depth.set(node.id, 1);
            });
            const maxDepth = Math.max(1, ...depth.values());
            const groups = new Map();
            selected.forEach((node) => {
                const nodeDepth = depth.get(node.id);
                if (!groups.has(nodeDepth)) groups.set(nodeDepth, []);
                groups.get(nodeDepth).push(node);
            });

            const positions = new Map();
            groups.forEach((nodes, nodeDepth) => {
                nodes.forEach((node, index) => {
                    positions.set(node.id, {
                        x: 55 + (nodeDepth / maxDepth) * 590,
                        y: 24 + ((index + 1) / (nodes.length + 1)) * 226,
                    });
                });
            });

            const lineMarkup = links.map((link) => {
                const source = positions.get(link.source);
                const target = positions.get(link.target);
                const targetNode = selected.find((node) => node.id === link.target);
                if (!source || !target) return "";
                const mid = (source.x + target.x) / 2;
                return `<path class="${targetNode?.vulnerable ? "exposed" : ""}" d="M${source.x},${source.y} C${mid},${source.y} ${mid},${target.y} ${target.x},${target.y}"></path>`;
            }).join("");
            const nodeMarkup = selected.map((node) => {
                const point = positions.get(node.id);
                const className = node.isRoot ? "root" : (node.vulnerable ? "exposed" : "secure");
                const label = String(node.name || node.id).replace(" (Root)", "").slice(0, 13);
                return `<g class="topology-node ${className}" transform="translate(${point.x} ${point.y})"><circle r="${node.isRoot ? 10 : 7}"></circle><circle class="pulse" r="${node.isRoot ? 15 : 11}"></circle><text y="22">${escapeHtml(label)}</text></g>`;
            }).join("");
            container.innerHTML = `<svg viewBox="0 0 700 280" aria-hidden="true"><g class="topology-links">${lineMarkup}</g><g>${nodeMarkup}</g></svg>`;
            container.className = "topology-map ready";
            const exposed = allNodes.filter((node) => node.vulnerable).length;
            setText("uxTopologyExposed", String(exposed));
            setText("uxTopologySecure", String(Math.max(0, allNodes.length - exposed)));
            container.setAttribute("aria-label", `Dependency topology with ${allNodes.length} packages and ${exposed} exposed packages`);
        } catch (_) {
            container.className = "topology-map error";
            container.innerHTML = '<div class="topology-error"><strong>Topology unavailable</strong><span>Dependency evidence could not be loaded.</span><button type="button" data-retry-topology>Retry</button></div>';
            container.setAttribute("aria-label", "Dependency topology unavailable");
            container.querySelector("[data-retry-topology]")?.addEventListener("click", loadTopology);
        }
    }

    function updateOverview(data) {
        const verdict = $("uxVerdict");
        const reason = $("uxVerdictReason");
        const blockedBy = data.blocked_by || [];
        const findings = buildFindings(data);
        const criticalCount = findings.filter((finding) => normalizeSeverity(finding.severity) === "critical").length;
        const scannerKeys = ["ruff", "semgrep", "osv", "iac", "secrets", "yara", "clamav", "zap"];
        const scannerCount = scannerKeys.filter((key) => data[key] !== null && data[key] !== undefined).length;
        const decision = $("uxOverviewDecision");
        if (decision) {
            decision.classList.remove("allowed", "blocked", "neutral");
            if (!data.has_run) {
                decision.textContent = "Not evaluated";
                decision.classList.add("neutral");
            } else if (data.is_blocked) {
                decision.textContent = "Blocked";
                decision.classList.add("blocked");
            } else {
                decision.textContent = "Allowed";
                decision.classList.add("allowed");
            }
        }
        setText("uxOverviewUpdated", data.latest_scan_time ? `Updated ${formatDate(data.latest_scan_time)}` : "No scan yet");
        setText("uxOverviewFindings", String(findings.length));
        setText("uxOverviewBlockers", String(blockedBy.length));
        setText("uxOverviewScanners", String(scannerCount));
        setText("uxOverviewNextStep", !data.has_run
            ? "Run an audit to generate a release decision."
            : (data.is_blocked ? "Review the top blockers, apply fixes, then rerun the audit." : "No blockers found. Share the evidence package with reviewers."));
        if (verdict) {
            verdict.classList.remove("allowed", "blocked", "neutral");
            if (!data.has_run) {
                verdict.textContent = "No Scan Yet";
                verdict.classList.add("neutral");
            } else if (data.is_blocked) {
                verdict.textContent = "Blocked";
                verdict.classList.add("blocked");
            } else {
                verdict.textContent = "Allowed";
                verdict.classList.add("allowed");
            }
        }
        if (reason) {
            reason.textContent = blockedBy.length ? `Blocked by ${blockedBy.join(", ")}` : (data.has_run ? "No blocking security issues found." : "Run an audit to generate a deployment decision.");
        }
        setText("uxVerdictSignal", !data.has_run ? "Not evaluated" : (data.is_blocked ? "Release stopped" : "Gate passed"));
        const blockedByContainer = $("uxBlockedBy");
        if (blockedByContainer) {
            blockedByContainer.innerHTML = blockedBy.map((source) => `<span>${escapeHtml(source)}</span>`).join("");
        }
        const topFindings = $("uxOverviewTopFindings");
        if (topFindings) {
            if (!findings.length) {
                topFindings.className = "overview-top-findings empty-state";
                topFindings.textContent = data.has_run ? "No actionable findings in the latest scan." : "Top findings appear here after a scan.";
            } else {
                topFindings.className = "overview-top-findings";
                topFindings.innerHTML = findings.slice(0, 3).map((finding) => {
                    const severity = normalizeSeverity(finding.severity);
                    return `
                        <div class="overview-blocker-item">
                            <span class="summary-dot ${severity}"></span>
                            <div><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.scanner)} · ${escapeHtml(finding.location)}</small></div>
                            <span class="modern-severity ${severity}">${severity.toUpperCase()}</span>
                        </div>
                    `;
                }).join("");
            }
        }

        const risk = Math.round(data.exploitability_score || 0);
        setText("uxRiskScore", String(risk));
        const riskOrbit = $("uxRiskOrbit");
        if (riskOrbit) {
            riskOrbit.style.setProperty("--risk", String(Math.min(100, Math.max(0, risk))));
            riskOrbit.style.setProperty("--risk-color", risk >= 70 ? "var(--danger)" : (risk >= 35 ? "var(--secondary)" : "var(--primary)"));
        }
        setText("uxRiskLabel", !data.has_run ? "Risk not calculated" : (risk >= 70 ? "Critical exposure" : (risk >= 35 ? "Material exposure" : "Low exploitability")));
        const meter = $("uxRiskMeter");
        if (meter) {
            meter.style.width = `${Math.min(100, Math.max(0, risk))}%`;
            meter.style.backgroundColor = risk >= 70 ? "var(--danger)" : (risk >= 35 ? "var(--secondary)" : "var(--primary)");
        }

        setText("uxWafState", data.waf_enabled ? "Armed" : "Off");
        const wafState = $("uxWafState");
        if (wafState) wafState.style.color = data.waf_enabled ? "var(--primary)" : "var(--secondary)";
        setText("uxWafPanelState", data.waf_enabled ? "Protection armed" : "Protection inactive");
        setText("uxWafPanelToggle", data.waf_enabled ? "Disarm firewall" : "Arm firewall");
        setText("uxWafPanelCopy", data.waf_enabled
            ? "Known attack patterns are being evaluated before requests reach application routes."
            : "Application routes are exposed directly. Arm the firewall before testing hostile payloads.");
        const firewallPosture = document.querySelector(".firewall-posture");
        if (firewallPosture) firewallPosture.classList.toggle("armed", !!data.waf_enabled);
        setText("uxLatestScan", formatDate(data.latest_scan_time));
        setText("uxSandboxStatus", `Sandbox · ${String(data.sandbox_status || "unknown").replaceAll("_", " ")}`);
        setText("uxEvidenceFreshness", data.latest_scan_time ? `Updated ${formatDate(data.latest_scan_time)}` : "Awaiting evidence");

        setText("uxFindingTotal", String(findings.length));
        setText("uxCriticalTotal", String(criticalCount));
        setText("uxScannerTotal", String(scannerCount));

        const reportPath = $("uxReportPath");
        if (reportPath) {
            reportPath.textContent = data.report_url ? `${window.location.origin}${data.report_url}` : "Report path appears after a scan.";
        }
        setText("uxReportAvailability", data.report_url ? "Evidence package ready" : "No report generated");
        setText("uxReportVerdict", !data.has_run ? "No deployment verdict" : (data.is_blocked ? "Deployment blocked" : "Deployment allowed"));
        setText("uxReportSummary", !data.has_run
            ? "Run an audit to compile a complete evidence package."
            : `${findings.length} actionable ${findings.length === 1 ? "finding" : "findings"} across ${scannerCount} reporting scanners.`);
        setText("uxReportStamp", data.latest_scan_time ? new Date(data.latest_scan_time * 1000).toLocaleDateString() : "AWAITING SCAN");
        ["uxBundleLink", "uxReportBundleAction"].forEach((id) => {
            const link = $(id);
            if (!link) return;
            link.setAttribute("aria-disabled", data.report_url ? "false" : "true");
            link.title = data.report_url ? "Download the share bundle" : "Run a scan before downloading a share bundle";
        });
    }

    function renderHistory() {
        const history = readJson(HISTORY_KEY, []);
        const container = $("uxScanHistory");
        if (!container) return;
        if (!history.length) {
            container.className = "modern-history empty-state";
            container.textContent = "Scan history is stored locally in this browser.";
            return;
        }
        container.className = "modern-history";
        container.innerHTML = "";
        history.slice(0, 8).forEach((entry) => {
            const item = document.createElement("div");
            item.className = "modern-history-item";
            item.innerHTML = `
                <div class="modern-severity ${entry.status === "blocked" ? "high" : "low"}">${entry.status.toUpperCase()}</div>
                <div>
                    <div class="modern-finding-title">${escapeHtml(entry.target || "Scan")}</div>
                    <div class="modern-finding-meta">${escapeHtml(entry.time)} - Risk ${entry.risk ?? 0}/100</div>
                </div>
                <a class="modern-btn compact" href="/report">Open</a>
            `;
            container.appendChild(item);
        });
    }

    function saveHistory(result) {
        const history = readJson(HISTORY_KEY, []);
        const status = latestResults?.is_blocked ? "blocked" : "allowed";
        history.unshift({
            time: new Date().toLocaleString(),
            target: currentJob?.target || result.target || "Aegis scan",
            status,
            risk: Math.round(latestResults?.exploitability_score || result.exploitability_score || 0),
        });
        writeJson(HISTORY_KEY, history.slice(0, 20));
        renderHistory();
    }

    function setupFilters() {
        document.querySelectorAll(".modern-filter").forEach((button) => {
            button.addEventListener("click", () => {
                currentFilter = button.dataset.filter;
                document.querySelectorAll(".modern-filter").forEach((item) => item.classList.toggle("active", item === button));
                if (latestResults) renderFindings(latestResults);
            });
        });
        $("uxScannerFilter")?.addEventListener("change", (event) => {
            currentScanner = event.target.value;
            if (latestResults) renderFindings(latestResults);
        });
        $("uxFindingsSearch")?.addEventListener("input", (event) => {
            currentQuery = event.target.value.trim();
            if (latestResults) renderFindings(latestResults);
        });
    }

    function setupProxyControls() {
        document.querySelector(".skip-link")?.addEventListener("click", () => {
            window.setTimeout(() => $("workbench-main")?.focus(), 0);
        });
        $("uxScanBtn")?.addEventListener("click", () => $("scanBtn")?.click());
        $("uxHeaderScanBtn")?.addEventListener("click", () => $("uxScanBtn")?.click());
        $("uxUploadBtn")?.addEventListener("click", () => $("uploadBtn")?.click());
        $("uxWafToggle")?.addEventListener("click", () => {
            $("wafToggle")?.click();
            setTimeout(refreshResults, 100);
        });
        $("uxWafPanelToggle")?.addEventListener("click", () => $("uxWafToggle")?.click());
        $("uxShowWafEditor")?.addEventListener("click", () => {
            const select = $("viewSelect");
            if (select) {
                select.value = "tactical";
                select.dispatchEvent(new Event("change"));
            }
            setTimeout(() => $("waf-editor-card")?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
        });
        $("uxThreatLabBtn")?.addEventListener("click", () => {
            const select = $("viewSelect");
            if (!select) return;
            select.value = "tactical";
            select.dispatchEvent(new Event("change"));
        });
        $("uxScanTarget")?.addEventListener("change", (event) => {
            const scanTarget = $("scanTarget");
            if (scanTarget) {
                scanTarget.value = event.target.value;
                scanTarget.dispatchEvent(new Event("change"));
            }
        });
        $("uxCopyReport")?.addEventListener("click", async () => {
            const text = $("uxReportPath")?.textContent || `${window.location.origin}/report`;
            try {
                await navigator.clipboard.writeText(text);
                setText("uxCopyReportLabel", "Copied");
                setTimeout(() => setText("uxCopyReportLabel", "Copy link"), 1200);
            } catch (_) {
                setText("uxCopyReportLabel", "Copy failed");
                setTimeout(() => setText("uxCopyReportLabel", "Copy link"), 1200);
            }
        });
        ["uxBundleLink", "uxReportBundleAction"].forEach((id) => {
            $(id)?.addEventListener("click", (event) => {
                if (event.currentTarget.getAttribute("aria-disabled") === "true") {
                    event.preventDefault();
                    showToast("Bundle unavailable", "Run a scan before downloading a share bundle.", "neutral");
                }
            });
        });
        $("uxClearLogs")?.addEventListener("click", () => {
            const log = $("uxLogStream");
            if (log) {
                log.textContent = "No live scan events yet.";
                log.classList.add("empty-state");
            }
        });
        document.querySelectorAll("[data-go-tab]").forEach((button) => {
            button.addEventListener("click", () => {
                document.querySelector(`.modern-tab[data-tab="${button.dataset.goTab}"]`)?.click();
            });
        });
        document.querySelectorAll("[data-open-topology]").forEach((button) => {
            button.addEventListener("click", () => {
                const select = $("viewSelect");
                if (!select) return;
                select.value = "tactical";
                select.dispatchEvent(new Event("change"));
                setTimeout(() => $("dependency-graph-card")?.scrollIntoView({ behavior: "smooth", block: "start" }), 60);
            });
        });
        document.addEventListener("keydown", (event) => {
            if ((event.metaKey || event.ctrlKey) && event.key === "Enter" && document.body.classList.contains("view-simple")) {
                event.preventDefault();
                $("uxHeaderScanBtn")?.click();
            }
        });
    }

    function setupSettings() {
        const settings = readJson(SETTINGS_KEY, { reduceMotion: false, defaultSimple: true });
        const reduce = $("uxReduceMotion");
        const simple = $("uxDefaultSimple");
        const adminToken = $("uxAdminToken");
        const saveAdminToken = $("uxSaveAdminToken");
        if (reduce) reduce.checked = !!settings.reduceMotion;
        if (simple) simple.checked = settings.defaultSimple !== false;
        if (adminToken) adminToken.value = readAdminToken();
        document.body.classList.toggle("ux-reduce-motion", !!settings.reduceMotion);

        reduce?.addEventListener("change", () => {
            settings.reduceMotion = reduce.checked;
            document.body.classList.toggle("ux-reduce-motion", settings.reduceMotion);
            writeJson(SETTINGS_KEY, settings);
        });
        simple?.addEventListener("change", () => {
            settings.defaultSimple = simple.checked;
            localStorage.setItem("view", simple.checked ? "simple" : "tactical");
            writeJson(SETTINGS_KEY, settings);
        });
        saveAdminToken?.addEventListener("click", () => {
            writeAdminToken(adminToken?.value.trim() || "");
            setText("uxSaveAdminToken", adminToken?.value.trim() ? "Token Saved" : "Token Cleared");
            setTimeout(() => setText("uxSaveAdminToken", "Save Admin Token"), 1200);
        });
        $("uxSignOut")?.addEventListener("click", async () => {
            const response = await authenticatedFetch("/api/auth/logout", { method: "POST" });
            if (response.ok) window.location.assign("/login");
        });
    }

    function updateResults(data) {
        latestResults = data || {};
        updateOverview(latestResults);
        renderFindings(latestResults);
        renderTelemetry(latestResults);
    }

    function startScan(jobId, meta) {
        currentJob = { id: jobId, ...(meta || {}) };
        setScanBusy(true);
        setText("uxJobId", jobId ? `Job ${jobId.slice(0, 8)}` : "Queued");
        setProgress("queued");
        appendLog(`Scan queued${meta?.target ? ` for ${meta.target}` : ""}.`, "var(--secondary)");
        showToast("Audit queued", meta?.target ? `Evidence collection started for ${meta.target}.` : "Evidence collection has started.");
    }

    function handleScanMessage(data) {
        if (data.type === "state") {
            setProgress(data.state);
            appendLog(`State changed to ${data.state}.`, "var(--secondary)");
        } else if (data.type === "log") {
            appendLog(data.text, data.color);
        } else if (data.type === "result") {
            setProgress("completed");
            showToast("Evidence compiled", "The deployment decision is ready for review.", "success");
        }
    }

    async function recordScanComplete(result) {
        try {
            const response = await fetch("/get-scan-results");
            updateResults(await response.json());
        } catch (_) {
            appendLog("Could not refresh dashboard results.", "var(--danger)");
        }
        saveHistory(result || {});
        setScanBusy(false);
        loadTopology();
    }

    async function refreshResults() {
        try {
            const response = await fetch("/get-scan-results");
            updateResults(await response.json());
        } catch (_) {
            appendLog("Dashboard results endpoint unavailable.", "var(--danger)");
            showToast("Evidence unavailable", "The latest scan results could not be loaded.", "danger");
        }
    }

    function handleViewChange(view) {
        if (view === "simple") {
            setTimeout(refreshResults, 50);
        }
    }

    function init() {
        updateTabs();
        setupFilters();
        setupProxyControls();
        setupSettings();
        renderHistory();
        setScanBusy(false);
        refreshResults();
        loadTopology();
        loadWorkspaceSettings();
    }

    window.AegisUX = {
        updateResults,
        startScan,
        handleScanMessage,
        recordScanComplete,
        handleViewChange,
    };
    window.AegisAPI = {
        fetch: authenticatedFetch,
        loadIdentity,
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
    loadIdentity().catch(() => {});
})();
