(() => {
  const dialog = byId("bac-review-dialog");
  const cases = byId("bac-review-cases");
  const status = byId("bac-review-status");
  const error = byId("bac-review-error");
  const originals = byId("bac-review-originals");
  const retry = byId("bac-review-retry");
  let generation = 0;
  let currentTarget = null;

  function clear() {
    generation += 1;
    currentTarget = null;
    cases.replaceChildren();
    byId("bac-review-run").textContent = "";
    status.textContent = "";
    error.textContent = "";
    originals.hidden = true;
    retry.hidden = true;
  }
  function close() {
    clear();
    if (dialog.open) dialog.close();
  }
  function active(token, target) {
    return generation === token && dialog.open && selected?.id === target.projectId;
  }
  async function read(url) {
    const response = await api(url);
    if (!response.ok) {
      const data = await response.json();
      throw new Error(typeof data.detail === "string" ? data.detail : "Research evidence is unavailable.");
    }
    return response.json();
  }
  function jsonSection(label, value) {
    const section = document.createElement("section");
    const heading = document.createElement("h3");
    heading.textContent = label;
    const content = document.createElement("pre");
    content.tabIndex = 0;
    content.setAttribute("role", "region");
    content.setAttribute("aria-label", label);
    content.textContent = value == null ? "Not recorded in this export." : JSON.stringify(value, null, 2);
    section.append(heading, content);
    return section;
  }
  function showEvidence(container, item, report) {
    const identity = document.createElement("p");
    identity.className = "mono";
    identity.textContent = `Report run: ${report.run_id} · Case run: ${item.trial_run_id || report.run_id}${item.repeat ? ` · Repeat: ${item.repeat}` : ""} · Case: ${item.id}`;
    const evidence = item.evidence || {};
    const sections = [
      ["Baseline identity", evidence.baseline_identity],
      ["Authorized baseline", evidence.baseline],
      ["Probe identity", evidence.probe_identity],
      ["Probe request and response", evidence.probe],
      ["Baseline before snapshot", evidence.baseline_before],
      ["Baseline after snapshot", evidence.baseline_after],
      ["Before probe snapshot", evidence.before],
      ["After probe snapshot", evidence.after],
      ["Matching audit events", evidence.server_events]
    ];
    container.replaceChildren(identity, ...sections.map(([label, value]) => jsonSection(label, value)));
  }
  function render(report, target, token, linkedCase) {
    const outcomes = { violation: "Observed violation", no_violation: "No observed violation", inconclusive: "Inconclusive" };
    cases.innerHTML = report.results.map((item) => `<details class="bac-case" data-bac-case="${escapeHtml(item.id)}">
      <summary><strong>${escapeHtml(item.id)} · ${escapeHtml(outcomes[item.status] || "Inconclusive")}</strong><span class="bac-case-context">Actor: ${escapeHtml(item.actor)} · Operation: ${escapeHtml(item.operation)} · Resource: ${escapeHtml(item.resource)}</span><span class="bac-case-context">Intended permission: ${item.expected_allowed === true ? "allowed" : item.expected_allowed === false ? "denied" : "not recorded"} · ${escapeHtml(item.reason)}</span></summary>
      <div class="bac-case-evidence"></div>
    </details>`).join("");
    const rows = [...cases.querySelectorAll("details")];
    rows.forEach((row, index) => {
      row.ontoggle = () => {
        const content = row.querySelector(".bac-case-evidence");
        if (row.open && row.isConnected && active(token, target) && !content.children.length) showEvidence(content, report.results[index], report);
      };
    });
    byId("bac-review-run").textContent = `Stored scan #${target.scanId} · Exported report run: ${report.run_id} · Mode: ${report.mode} · ${report.started_at || "Time not recorded"} to ${report.completed_at || "Time not recorded"}`;
    originals.querySelectorAll("[data-bac-original]").forEach((link) => {
      link.href = `/api/projects/${target.projectId}/scans/${target.scanId}/artifacts/${link.dataset.bacOriginal}`;
    });
    originals.hidden = false;
    status.textContent = `${report.results.length} attempted case${report.results.length === 1 ? "" : "s"}. Select a case to review its recorded evidence.`;
    if (linkedCase) {
      const row = rows.find((item) => item.dataset.bacCase === linkedCase.case_id);
      row.open = true;
      row.querySelector("summary").focus();
    }
  }
  async function open(target) {
    clear();
    currentTarget = target;
    const token = generation;
    if (!dialog.open) dialog.showModal();
    byId("bac-review-close").focus();
    status.textContent = "Loading original BAC research evidence…";
    try {
      let linkedCase = null;
      if (target.findingId) {
        const finding = await read(`/api/projects/${target.projectId}/findings/${target.findingId}`);
        if (!active(token, target)) return;
        linkedCase = finding.research_case;
        if (finding.id !== target.findingId || finding.tool !== "BAC" || !linkedCase || typeof linkedCase.case_id !== "string") throw new Error("This finding has no linked BAC case.");
        target = { ...target, scanId: linkedCase.scan_run_id };
      }
      if (!Number.isSafeInteger(target.scanId) || target.scanId < 1) throw new Error("The stored BAC scan is unavailable.");
      const detail = await read(`/api/projects/${target.projectId}/scans/${target.scanId}`);
      if (!active(token, target)) return;
      if (detail.id !== target.scanId || detail.target !== "bac-research" || !detail.result?.bac_report?.run_id) throw new Error("The selected scan does not match a BAC research run.");
      const report = await read(`/api/projects/${target.projectId}/scans/${target.scanId}/artifacts/report.json`);
      if (!active(token, target)) return;
      if (report.schema_version !== 1 || report.kind !== "bac-research" || report.run_id !== detail.result.bac_report.run_id || !Array.isArray(report.results)) throw new Error("The exported report does not match the selected BAC run.");
      if (linkedCase) {
        const matches = report.results.filter((item) => item.id === linkedCase.case_id);
        if (matches.length !== 1 || ["actor", "operation", "resource"].some((key) => matches[0][key] !== linkedCase[key])) throw new Error("The finding scenario does not match this exported case.");
      }
      render(report, target, token, linkedCase);
    } catch (failure) {
      if (!active(token, target)) return;
      cases.replaceChildren();
      byId("bac-review-run").textContent = "";
      originals.hidden = true;
      status.textContent = "";
      error.textContent = failure.message || "Research evidence is unavailable. Try again.";
      retry.hidden = false;
    }
  }

  document.addEventListener("click", (event) => {
    if (!selected) return;
    const run = event.target.closest("[data-bac-review]");
    const finding = event.target.closest("[data-bac-finding]");
    if (run) open({ projectId: selected.id, scanId: Number(run.dataset.bacReview) });
    if (finding) open({ projectId: selected.id, findingId: Number(finding.closest("[data-finding]").dataset.finding) });
  });
  byId("bac-review-close").onclick = close;
  retry.onclick = () => { if (currentTarget) open(currentTarget); };
  dialog.addEventListener("cancel", clear);
  dialog.addEventListener("close", () => { if (!dialog.open) clear(); });
  document.addEventListener("aegis:project-change", close);
})();
