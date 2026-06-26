(function () {
    const HISTORY_KEY = "aegis.scanHistory.v1";
    const SETTINGS_KEY = "aegis.dashboardSettings.v1";
    const stateOrder = ["queued", "running", "analyzing", "correlating", "reporting", "completed"];
    let currentFilter = "all";
    let latestResults = null;
    let currentJob = null;

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

    function updateTabs() {
        document.querySelectorAll(".modern-tab").forEach((tab) => {
            tab.addEventListener("click", () => {
                const target = tab.dataset.tab;
                document.querySelectorAll(".modern-tab").forEach((item) => item.classList.toggle("active", item === tab));
                document.querySelectorAll(".modern-tab-panel").forEach((panel) => {
                    panel.classList.toggle("active", panel.dataset.panel === target);
                });
            });
        });
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
                title: item.message || code,
                location: `${item.filename || "unknown"}:${item.location?.row || "?"}`,
                fix: "Review the flagged line and replace unsafe input handling with a safer API or validation path.",
            });
        });

        ((data.semgrep || {}).results || []).forEach((item) => {
            findings.push({
                severity: normalizeSeverity(item.extra?.severity || "medium"),
                scanner: "Semgrep",
                title: item.extra?.message || item.check_id || "Semgrep finding",
                location: `${item.path || "unknown"}:${item.start?.line || "?"}`,
                fix: "Follow the rule message, then rerun the scan to confirm the issue is gone.",
            });
        });

        (data.osv || []).forEach((item) => {
            findings.push({
                severity: (item.cvss || 0) >= 7 ? "high" : "medium",
                scanner: "OSV",
                title: `${item.package || "dependency"} ${item.id || "vulnerability"}`,
                location: "requirements.txt",
                fix: item.fix || "Upgrade the affected dependency to a patched version.",
            });
        });

        Object.entries((data.secrets || {}).results || {}).forEach(([file, secrets]) => {
            (secrets || []).forEach((secret) => {
                findings.push({
                    severity: "high",
                    scanner: "Secrets",
                    title: secret.type || "Potential secret",
                    location: `${file}:${secret.line_number || "?"}`,
                    fix: "Remove the secret from source, rotate it, and load it from a secret manager or environment variable.",
                });
            });
        });

        (data.yara || []).forEach((item) => {
            findings.push({
                severity: "high",
                scanner: "YARA",
                title: item.rule || "Suspicious signature",
                location: item.filename || "unknown",
                fix: item.description || "Review the matched code and remove suspicious behavior if it is not expected.",
            });
        });

        (data.clamav || []).forEach((item) => {
            findings.push({
                severity: "critical",
                scanner: "ClamAV",
                title: item.virus || "Malware signature",
                location: item.filename || "unknown",
                fix: item.description || "Quarantine the file and verify its origin before restoring it.",
            });
        });

        (data.zap || []).filter((item) => item.status === "EXPOSED").forEach((item) => {
            findings.push({
                severity: "high",
                scanner: "DAST",
                title: item.vuln_type || "Exposed route",
                location: item.route || "runtime endpoint",
                fix: item.description || "Add input validation, output encoding, or WAF coverage for this route.",
            });
        });

        return findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    }

    function renderFindings(data) {
        const container = $("uxFindings");
        if (!container) return;
        const findings = buildFindings(data);
        const visible = findings.filter((finding) => currentFilter === "all" || normalizeSeverity(finding.severity) === currentFilter);

        if (!visible.length) {
            container.className = "modern-findings empty-state";
            container.textContent = findings.length ? "No findings match this filter." : "No actionable findings in the latest scan.";
            return;
        }

        container.className = "modern-findings";
        container.innerHTML = "";
        visible.forEach((finding) => {
            const item = document.createElement("div");
            item.className = "modern-finding";
            const severity = normalizeSeverity(finding.severity);
            item.innerHTML = `
                <div class="modern-severity ${severity}">${severity.toUpperCase()}</div>
                <div>
                    <div class="modern-finding-title">${escapeHtml(finding.title)}</div>
                    <div class="modern-finding-meta">${escapeHtml(finding.scanner)} - ${escapeHtml(finding.location)}</div>
                    <div class="modern-finding-fix">${escapeHtml(finding.fix)}</div>
                </div>
                <a class="modern-btn compact" href="/report">Report</a>
            `;
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

    function updateOverview(data) {
        const verdict = $("uxVerdict");
        const reason = $("uxVerdictReason");
        const blockedBy = data.blocked_by || [];
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

        const risk = Math.round(data.exploitability_score || 0);
        setText("uxRiskScore", String(risk));
        const meter = $("uxRiskMeter");
        if (meter) {
            meter.style.width = `${Math.min(100, Math.max(0, risk))}%`;
            meter.style.backgroundColor = risk >= 70 ? "var(--danger)" : (risk >= 35 ? "var(--secondary)" : "var(--primary)");
        }

        setText("uxWafState", data.waf_enabled ? "Armed" : "Off");
        const wafState = $("uxWafState");
        if (wafState) wafState.style.color = data.waf_enabled ? "var(--primary)" : "var(--secondary)";
        setText("uxLatestScan", formatDate(data.latest_scan_time));
        setText("uxSandboxStatus", `Sandbox: ${data.sandbox_status || "unknown"}`);

        const reportPath = $("uxReportPath");
        if (reportPath) {
            reportPath.textContent = data.report_url ? `${window.location.origin}${data.report_url}` : "Report path appears after a scan.";
        }
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
    }

    function setupProxyControls() {
        $("uxScanBtn")?.addEventListener("click", () => $("scanBtn")?.click());
        $("uxUploadBtn")?.addEventListener("click", () => $("uploadBtn")?.click());
        $("uxWafToggle")?.addEventListener("click", () => $("wafToggle")?.click());
        $("uxShowWafEditor")?.addEventListener("click", () => {
            const select = $("viewSelect");
            if (select) {
                select.value = "tactical";
                select.dispatchEvent(new Event("change"));
            }
            setTimeout(() => $("waf-editor-card")?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
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
                setText("uxCopyReport", "Copied");
                setTimeout(() => setText("uxCopyReport", "Copy Report Path"), 1200);
            } catch (_) {
                setText("uxCopyReport", "Copy Failed");
            }
        });
        $("uxClearLogs")?.addEventListener("click", () => {
            const log = $("uxLogStream");
            if (log) log.textContent = "No live scan events yet.";
        });
    }

    function setupSettings() {
        const settings = readJson(SETTINGS_KEY, { reduceMotion: false, defaultSimple: true });
        const reduce = $("uxReduceMotion");
        const simple = $("uxDefaultSimple");
        if (reduce) reduce.checked = !!settings.reduceMotion;
        if (simple) simple.checked = settings.defaultSimple !== false;
        document.body.classList.toggle("ux-reduce-motion", !!settings.reduceMotion);

        reduce?.addEventListener("change", () => {
            settings.reduceMotion = reduce.checked;
            document.body.classList.toggle("ux-reduce-motion", settings.reduceMotion);
            writeJson(SETTINGS_KEY, settings);
        });
        simple?.addEventListener("change", () => {
            settings.defaultSimple = simple.checked;
            writeJson(SETTINGS_KEY, settings);
        });
    }

    function updateResults(data) {
        latestResults = data || {};
        updateOverview(latestResults);
        renderFindings(latestResults);
    }

    function startScan(jobId, meta) {
        currentJob = { id: jobId, ...(meta || {}) };
        setText("uxJobId", jobId ? `Job ${jobId.slice(0, 8)}` : "Queued");
        setProgress("queued");
        appendLog(`Scan queued${meta?.target ? ` for ${meta.target}` : ""}.`, "var(--secondary)");
    }

    function handleScanMessage(data) {
        if (data.type === "state") {
            setProgress(data.state);
            appendLog(`State changed to ${data.state}.`, "var(--secondary)");
        } else if (data.type === "log") {
            appendLog(data.text, data.color);
        } else if (data.type === "result") {
            setProgress("completed");
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
    }

    async function refreshResults() {
        try {
            const response = await fetch("/get-scan-results");
            updateResults(await response.json());
        } catch (_) {
            appendLog("Dashboard results endpoint unavailable.", "var(--danger)");
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
        refreshResults();
    }

    window.AegisUX = {
        updateResults,
        startScan,
        handleScanMessage,
        recordScanComplete,
        handleViewChange,
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
