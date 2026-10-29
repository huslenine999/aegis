const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const fs = require("node:fs/promises");
const path = require("node:path");

const timestamp = "2026-10-08T01:00:00.000Z";
const snapshot = { documents: { "bob-private-1": { owner: "bob", title: "Private document", content: "synthetic-private-marker" } } };
function trace(caseId, actor, suffix, extra = {}) {
  return {
    request_id: `${caseId}-${suffix}`, timestamp, actor, method: "GET", path: "/documents/bob-private-1",
    request_headers: { Authorization: "[REDACTED]", "X-Aegis-Case-ID": caseId }, request_body: null,
    status_code: 200, response_headers: { "Content-Type": "application/json" },
    body: { content: "synthetic-private-marker" }, error: null, ...extra
  };
}
const observations = {
  baseline_identity: trace("denied-read", "bob", "baseline-identity", { path: "/me", body: { actor: "bob", role: "user" } }),
  baseline: trace("denied-read", "bob", "baseline"),
  probe_identity: trace("denied-read", "alice", "probe-identity", { path: "/me", body: { actor: "alice", role: "user" } }),
  probe: trace("denied-read", "alice", "probe")
};
const violation = {
  id: "denied-read", actor: "alice", operation: "read", resource: "bob-private-1", expected_allowed: false,
  status: "violation", reason: "Denied actor received the private marker.",
  trial_run_id: "trial-run-1", repeat: 1,
  evidence: {
    ...observations, baseline_before: snapshot, baseline_after: snapshot, before: snapshot, after: snapshot,
    server_events: Object.values(observations).map((observation) => ({
      request_id: observation.request_id, case_id: "denied-read", timestamp,
      actor: observation.actor, method: observation.method, path: observation.path, status_code: observation.status_code
    }))
  }
};
const noViolation = {
  id: "owner-read", actor: "bob", operation: "read", resource: "bob-private-1", expected_allowed: true,
  status: "no_violation", reason: "The intended owner read completed.",
  evidence: { probe: trace("owner-read", "bob", "probe"), before: snapshot, after: snapshot, server_events: [] }
};
const inconclusive = {
  id: "guest-update", actor: "guest", operation: "update", resource: "bob-private-1", expected_allowed: false,
  status: "inconclusive", reason: "Probe timed out before a complete response.", evidence: {}
};
const report = {
  schema_version: 1, kind: "bac-research", run_id: "export-run-1", mode: "vulnerable",
  started_at: timestamp, completed_at: "2026-10-08T01:01:00.000Z", status: "error", exit_code: 2,
  results: [violation, noViolation, inconclusive]
};
const scan = (id) => ({
  id, run_kind: "bac_research", target: "bac-research", preset: "quick", state: "failed",
  progress: 100, decision: null, new_findings: 1, research_exit_code: 2, research_status: "error",
  created_at: timestamp, completed_at: "2026-10-08T01:01:00.000Z", has_report: true
});
const finding = {
  id: 31, tool: "BAC", title: "Confirmed broken access control in synthetic lab", severity: "HIGH",
  rule_id: "read", path: "bob-private-1", status: "open", occurrence_count: 2
};
const researchCase = { scan_run_id: 21, case_id: "denied-read", actor: "alice", operation: "read", resource: "bob-private-1" };

// Every request is intercepted; these tests cannot import evidence or contact a lab/server.
async function openWorkbench(page, { role = "viewer", getReport = () => report, getFinding = () => ({ ...finding, research_case: researchCase }) } = {}) {
  const template = await fs.readFile(path.join(__dirname, "../../app/templates/projects.html"), "utf8");
  const html = template
    .replaceAll("{{ request.state.csp_nonce }}", "browser-test");
  const css = await fs.readFile(path.join(__dirname, "../../app/static/aegis-app.css"), "utf8");
  let requests = [];
  await page.route("**/*", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    requests = [...requests, { pathname, method: request.method() }];
    if (pathname === "/projects") return route.fulfill({ contentType: "text/html", body: html });
    if (pathname === "/static/aegis-app.css") return route.fulfill({ contentType: "text/css", body: css });
    if (pathname === "/static/bac-review.js") return route.fulfill({
      contentType: "text/javascript", body: await fs.readFile(path.join(__dirname, "../../app/static/bac-review.js"), "utf8")
    });
    let json;
    if (pathname === "/api/auth/me") json = { username: "research-viewer", role, csrf_token: "browser-test-csrf" };
    else if (pathname === "/api/projects") json = { projects: [
      { id: 7, name: "Research project", default_branch: "main", scan_preset: "standard", role },
      { id: 8, name: "Second project", default_branch: "main", scan_preset: "quick", role }
    ] };
    else if (pathname === "/api/github/status") json = { enabled: false };
    else if (/^\/api\/projects\/[78]\/scans$/.test(pathname)) json = {
      scans: pathname.includes("/7/") ? [scan(22), scan(21)] : [], latest_source_scan: null
    };
    else if (/^\/api\/projects\/[78]\/findings$/.test(pathname)) json = { findings: pathname.includes("/7/") ? [finding] : [] };
    else if (/^\/api\/projects\/[78]\/members$/.test(pathname)) json = { members: [] };
    else if (/^\/api\/projects\/[78]\/policies$/.test(pathname)) json = { policies: [] };
    else if (/^\/api\/projects\/[78]\/notifications$/.test(pathname)) json = { channels: [] };
    else if (pathname === "/api/projects/7/findings/31") json = getFinding();
    else if (/^\/api\/projects\/7\/scans\/\d+$/.test(pathname)) {
      const id = Number(pathname.split("/").pop());
      json = { ...scan(id), result: { research_only: true, gate_eligible: false, bac_report: getReport(id) } };
    } else if (/^\/api\/projects\/7\/scans\/\d+\/artifacts\/report.json$/.test(pathname)) {
      json = getReport(Number(pathname.split("/")[5]));
    } else return route.fulfill({ status: 404, json: { detail: `Unexpected mocked request: ${pathname}` } });
    return route.fulfill({ json });
  });
  await page.goto("/projects?project=7");
  await expect(page.locator("#project-name")).toHaveText("Research project");
  await expect(page.locator("#scan-history .scan")).toHaveCount(2);
  return { requests: () => requests };
}

const dialog = (page) => page.getByRole("dialog", { name: "BAC case reviewer" });
const reviewRun = (page, id = 21) => page.locator(`[data-bac-review='${id}']`).click();

test("viewers review every attempted case with safe outcome semantics and original links", async ({ page }) => {
  const observed = await openWorkbench(page);
  await reviewRun(page);
  const reviewer = dialog(page);
  await expect(reviewer).toBeVisible();
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(3);
  for (const item of report.results) {
    const summary = reviewer.locator(`details[data-bac-case='${item.id}'] summary`);
    for (const value of [item.id, item.actor, item.operation, item.resource, item.reason]) await expect(summary).toContainText(value);
    await expect(summary).toContainText(item.expected_allowed ? "Intended permission: allowed" : "Intended permission: denied");
  }
  await expect(reviewer.locator("[data-bac-case='denied-read'] summary")).toContainText("Observed violation");
  await expect(reviewer.locator("[data-bac-case='owner-read'] summary")).toContainText("No observed violation");
  await expect(reviewer.locator("[data-bac-case='guest-update'] summary")).toContainText("Inconclusive");
  await expect(reviewer).toContainText("does not establish security");
  await expect(reviewer).toContainText("inconclusive evidence cannot establish a safe outcome");
  await expect(reviewer.locator("#bac-review-run")).toContainText("Stored scan #21");
  await expect(reviewer.locator("#bac-review-run")).toContainText("export-run-1");
  await expect(reviewer.getByRole("link", { name: "Original report JSON" })).toHaveAttribute("href", "/api/projects/7/scans/21/artifacts/report.json");
  await expect(reviewer.getByRole("link", { name: "Signed manifest" })).toHaveAttribute("href", "/api/projects/7/scans/21/artifacts/scan-manifest.json");
  expect(observed.requests().filter((item) => item.pathname.startsWith("/api/")).every((item) => item.method === "GET")).toBeTruthy();
});

test("case expansion exposes recorded trace order, snapshots, audit correlation, and trial identity", async ({ page }) => {
  await openWorkbench(page);
  await reviewRun(page);
  const reviewer = dialog(page);
  const selectedCase = reviewer.locator("[data-bac-case='denied-read']");
  await selectedCase.locator("summary").click();
  const headings = selectedCase.getByRole("heading");
  await expect(headings).toHaveText([
    "Baseline identity", "Authorized baseline", "Probe identity", "Probe request and response",
    "Baseline before snapshot", "Baseline after snapshot", "Before probe snapshot", "After probe snapshot", "Matching audit events"
  ]);
  await expect(selectedCase).toContainText("Case run: trial-run-1");
  await expect(selectedCase).toContainText("Repeat: 1");
  await expect(selectedCase).toContainText("denied-read-baseline-identity");
  await expect(selectedCase).toContainText("denied-read-probe");
  await expect(selectedCase).toContainText(timestamp);
  await expect(selectedCase).toContainText("synthetic-private-marker");
  await expect(selectedCase).toContainText('"case_id": "denied-read"');
  await reviewer.locator("[data-bac-case='guest-update'] summary").click();
  await expect(reviewer.locator("[data-bac-case='guest-update']")).toContainText("Not recorded in this export.");
  await page.keyboard.press("Escape");
  await expect(reviewer).toBeHidden();
  await expect(page.locator("[data-bac-review='21']")).toBeFocused();
});

test("a BAC finding resolves its latest exact case instead of the newest research history entry", async ({ page }) => {
  const observed = await openWorkbench(page, { getFinding: () => ({ ...finding, research_case: researchCase }) });
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  const card = page.locator("[data-finding='31']");
  await card.getByRole("button", { name: "Review BAC case" }).click();
  const reviewer = dialog(page);
  await expect(reviewer.locator("#bac-review-run")).toContainText("Stored scan #21");
  await expect(reviewer.locator("[data-bac-case='denied-read']")).toHaveAttribute("open", "");
  await expect(reviewer.locator("[data-bac-case='denied-read'] summary")).toBeFocused();
  expect(observed.requests().some((item) => item.pathname === "/api/projects/7/findings/31")).toBeTruthy();
  expect(observed.requests().some((item) => item.pathname === "/api/projects/7/scans/22/artifacts/report.json")).toBeFalsy();
});

test("missing or mismatched finding scenario metadata never exposes another case", async ({ page }) => {
  let context = { ...researchCase, actor: "bob" };
  await openWorkbench(page, { getFinding: () => ({ ...finding, research_case: context }) });
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  await page.getByRole("button", { name: "Review BAC case" }).click();
  const reviewer = dialog(page);
  await expect(reviewer.locator("#bac-review-error")).toContainText("does not match");
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(0);
  context = null;
  await reviewer.getByRole("button", { name: "Retry review" }).click();
  await expect(reviewer.locator("#bac-review-error")).toContainText("no linked BAC case");
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(0);
});

test("artifact integrity errors clear prior evidence, never use inline reports, and allow retry", async ({ page }) => {
  await openWorkbench(page);
  await reviewRun(page);
  const reviewer = dialog(page);
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(3);
  await reviewer.getByRole("button", { name: "Close reviewer" }).click();
  let failed = true;
  await page.route("**/api/projects/7/scans/21/artifacts/report.json", (route) => route.fulfill(failed
    ? { status: 409, json: { detail: "Artifact integrity verification failed; evidence is unavailable." } }
    : { json: report }));
  await reviewRun(page);
  await expect(reviewer.locator("#bac-review-error")).toContainText("Artifact integrity verification failed");
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(0);
  await expect(reviewer.locator("#bac-review-run")).toHaveText("");
  failed = false;
  await reviewer.getByRole("button", { name: "Retry review" }).click();
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(3);
  await expect(reviewer.locator("#bac-review-error")).toHaveText("");
});

test("report identities must match the selected stored BAC run", async ({ page }) => {
  await openWorkbench(page);
  await page.route("**/api/projects/7/scans/21/artifacts/report.json", (route) => route.fulfill({ json: { ...report, run_id: "foreign-run" } }));
  await reviewRun(page);
  const reviewer = dialog(page);
  await expect(reviewer.locator("#bac-review-error")).toContainText("does not match");
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(0);
});

test("rapid close and run selection ignore stale artifact responses", async ({ page }) => {
  await openWorkbench(page, { getReport: (id) => id === 22 ? { ...report, run_id: "export-run-2" } : report });
  let releaseReport;
  const waiting = new Promise((resolve) => { releaseReport = resolve; });
  await page.route("**/api/projects/7/scans/21/artifacts/report.json", async (route) => {
    await waiting;
    return route.fulfill({ json: report });
  });
  const request = page.waitForRequest("**/api/projects/7/scans/21/artifacts/report.json");
  await reviewRun(page);
  await request;
  await page.keyboard.press("Escape");
  await reviewRun(page, 22);
  const reviewer = dialog(page);
  await expect(reviewer.locator("#bac-review-run")).toContainText("export-run-2");
  const staleResponse = page.waitForResponse("**/api/projects/7/scans/21/artifacts/report.json");
  releaseReport();
  await (await staleResponse).finished();
  await expect(reviewer.locator("#bac-review-run")).toContainText("Stored scan #22");
  await expect(reviewer.locator("#bac-review-run")).toContainText("export-run-2");
});

test("project changes invalidate pending run and finding reviews", async ({ page }) => {
  await openWorkbench(page);
  let releaseReport;
  const waiting = new Promise((resolve) => { releaseReport = resolve; });
  await page.route("**/api/projects/7/findings/31", async (route) => {
    await waiting;
    return route.fulfill({ json: { ...finding, research_case: researchCase } });
  });
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  const request = page.waitForRequest("**/api/projects/7/findings/31");
  await page.getByRole("button", { name: "Review BAC case" }).click();
  await request;
  await page.evaluate(() => selectProject(8));
  const reviewer = page.locator("#bac-review-dialog");
  await expect(reviewer).toBeHidden();
  const staleResponse = page.waitForResponse("**/api/projects/7/findings/31");
  releaseReport();
  await (await staleResponse).finished();
  await expect(page.locator("#project-name")).toHaveText("Second project");
  await expect(reviewer.locator("details[data-bac-case]")).toHaveCount(0);
  await expect(reviewer.locator("#bac-review-run")).toHaveText("");
});

test("exported HTML remains inert in case summaries and evidence JSON", async ({ page }) => {
  const malicious = '<img src=x onerror="window.BAC_XSS=1"><script>window.BAC_XSS=2</script>';
  const hostile = { ...violation, actor: malicious, reason: malicious, evidence: {
    ...violation.evidence, probe: { ...observations.probe, request_body: { title: malicious }, body: { content: malicious } }
  } };
  await openWorkbench(page, { getReport: () => ({ ...report, results: [hostile, noViolation, inconclusive] }) });
  await page.evaluate(() => { window.BAC_XSS = 0; });
  await reviewRun(page);
  const reviewer = dialog(page);
  await reviewer.locator("[data-bac-case='denied-read'] summary").click();
  await expect(reviewer).toContainText(malicious);
  await expect(reviewer.locator("img, script")).toHaveCount(0);
  expect(await page.evaluate(() => window.BAC_XSS)).toBe(0);
});

test("case reviewer remains keyboard accessible without serious mobile accessibility violations", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openWorkbench(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  expect(await page.locator("#projects").evaluate(element => element.scrollWidth > element.clientWidth)).toBeTruthy();
  const opener = page.locator("[data-bac-review='21']");
  await opener.focus();
  await page.keyboard.press("Enter");
  const reviewer = dialog(page);
  const summary = reviewer.locator("[data-bac-case='denied-read'] summary");
  await summary.focus();
  await page.keyboard.press("Enter");
  await expect(reviewer.locator("[data-bac-case='denied-read']")).toHaveAttribute("open", "");
  const accessibility = await new AxeBuilder({ page }).include("#bac-review-dialog").analyze();
  expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.keyboard.press("Escape");
  await expect(reviewer).toBeHidden();
  await expect(opener).toBeFocused();
});
