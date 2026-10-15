const { test, expect } = require("@playwright/test");
const fs = require("node:fs/promises");
const path = require("node:path");

const sourceScan = {
  id: 11, target: "repository", preset: "standard", state: "completed",
  progress: 100, decision: "BLOCKED", failure_reason: "Source policy found a blocker.",
  new_findings: 1, created_at: "2026-10-01T10:00:00Z", completed_at: "2026-10-01T10:01:00Z"
};
const finding = (id, changes = {}) => ({
  id, title: `Finding ${id}`, tool: "Ruff", rule_id: "S307", path: "app.py",
  severity: "HIGH", status: "open", occurrence_count: 1, ...changes
});

function findingsPage(findings, url) {
  const status = url.searchParams.get("status") || "all";
  const severity = url.searchParams.get("severity") || "all";
  const search = (url.searchParams.get("search") || "").toLowerCase();
  const limit = Number(url.searchParams.get("limit") || 200);
  const offset = Number(url.searchParams.get("offset") || 0);
  const matches = findings.filter((item) =>
    (status === "all" || (status === "active" ? ["open", "acknowledged"].includes(item.status) : item.status === status))
    && (severity === "all" || severity === item.severity)
    && [item.title, item.tool, item.rule_id, item.path, item.owner].join(" ").toLowerCase().includes(search));
  const active = findings.filter((item) => !["resolved", "false_positive"].includes(item.status));
  return {
    findings: matches.slice(offset, offset + limit), total: matches.length, limit, offset,
    summary: { open: active.length, blockers: active.filter((item) => item.tool !== "BAC" && ["HIGH", "CRITICAL"].includes(item.severity)).length }
  };
}

async function openWorkbench(page, { findings = [finding(1)], getScan = () => sourceScan } = {}) {
  const template = await fs.readFile(path.join(__dirname, "../../app/templates/projects.html"), "utf8");
  const html = template.replace(/{% if demo_lab_enabled %}.*?{% endif %}/s, "")
    .replaceAll("{{ request.state.csp_nonce }}", "browser-test");
  const requests = [];
  const projectResponse = (projectId, endpoint, url) => {
    if (endpoint === "scans") return { scans: [getScan()], latest_source_scan: getScan() };
    if (endpoint === "findings") return findingsPage(findings, url);
    if (endpoint === "members") return { members: [{ user_id: projectId, username: `Current member ${projectId}`, role: "operator" }] };
    if (endpoint === "policies") return { policies: [{ id: projectId, version: 1, name: `Current policy ${projectId}`, state: "approved", definition: { fail_on_severities: ["HIGH"] } }] };
    if (endpoint === "notifications") return { channels: [{ id: projectId, name: `Current channel ${projectId}`, channel_type: "webhook", events: ["failed"] }] };
    return { result: { policy: { status: "ALLOWED", reason: "Detail must not override the scan summary." } } };
  };
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    requests.push(url);
    if (url.pathname === "/projects") return route.fulfill({ contentType: "text/html", body: html });
    if (["/static/aegis-app.css", "/static/bac-review.js"].includes(url.pathname)) return route.fulfill({
      contentType: url.pathname.endsWith(".css") ? "text/css" : "text/javascript",
      body: await fs.readFile(path.join(__dirname, "../../app", url.pathname), "utf8")
    });
    let json;
    if (url.pathname === "/api/auth/me") json = { username: "project-admin", role: "admin", csrf_token: "browser-test-csrf" };
    else if (url.pathname === "/api/projects") json = { projects: [7, 8].map((id) => ({
      id, name: `Project ${id}`, default_branch: "main", scan_preset: "standard", role: "admin"
    })) };
    else if (url.pathname === "/api/github/status") json = { enabled: false };
    else {
      const match = url.pathname.match(/^\/api\/projects\/([78])\/([^/]+)/);
      if (!match) return route.fulfill({ status: 404, json: { detail: `Unexpected request: ${url.pathname}` } });
      json = projectResponse(Number(match[1]), match[2], url);
      if (/\/scans\/\d+$/.test(url.pathname)) json = projectResponse(Number(match[1]), "detail", url);
    }
    return route.fulfill({ json });
  });
  await page.goto("/projects");
  await expect(page.locator("#project-name")).toHaveText("Project 7");
  await expect(page.locator("#members")).toContainText("Current member 7");
  return { requests, projectResponse };
}

test("findings filters and pages reach the whole queue while summary counts remain complete", async ({ page }) => {
  const findings = [
    ...Array.from({ length: 200 }, (_, index) => finding(index + 1, { status: "resolved" })),
    finding(201, { title: "Weak hash", severity: "MEDIUM" }),
    finding(202, { title: "SQL injection" }),
    finding(203, { title: "Debug output", severity: "LOW", tool: "BAC" })
  ];
  const observed = await openWorkbench(page, { findings });
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  await expect(page.locator(".finding-row")).toHaveCount(3);
  await expect(page.locator("#summary-open")).toHaveText("3");
  await expect(page.locator("#summary-blockers")).toHaveText("1");
  await page.getByLabel("Filter by status").selectOption("all");
  await expect(page.locator(".finding-row")).toHaveCount(200);
  await expect(page.locator("#findings-page-status")).toHaveText("1–200 of 203 findings");
  await page.getByRole("button", { name: "Next findings page" }).click();
  await expect(page.locator(".finding-row")).toHaveCount(3);
  await expect(page.locator("#findings-page-status")).toHaveText("201–203 of 203 findings");
  await expect(page.getByRole("button", { name: "Next findings page" })).toBeDisabled();
  await expect(page.locator("#summary-open")).toHaveText("3");
  await page.getByRole("button", { name: "Previous findings page" }).click();
  await expect(page.locator(".finding-row")).toHaveCount(200);
  await page.getByRole("button", { name: "Next findings page" }).click();
  await expect(page.locator(".finding-row")).toHaveCount(3);
  await page.getByLabel("Filter by severity").selectOption("MEDIUM");
  await expect(page.locator(".finding-row")).toHaveCount(1);
  await expect(page.locator("#findings-page-status")).toHaveText("1–1 of 1 findings");
  await expect(page.locator("#summary-open")).toHaveText("3");
  expect(observed.requests.some((url) => url.searchParams.get("severity") === "MEDIUM" && url.searchParams.get("offset") === "0")).toBeTruthy();
});

test("paging recovers when another operator removes the last page", async ({ page }) => {
  const findings = Array.from({ length: 201 }, (_, index) => finding(index + 1));
  await openWorkbench(page, { findings });
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  await expect(page.getByRole("button", { name: "Next findings page" })).toBeEnabled();
  await page.route("**/api/projects/7/findings?**", (route) => route.fulfill({
    json: findingsPage(findings.slice(0, 200), new URL(route.request().url()))
  }));
  await page.getByRole("button", { name: "Next findings page" }).click();
  await expect(page.locator(".finding-row")).toHaveCount(200);
  await expect(page.locator("#findings-page-status")).toHaveText("1–200 of 200 findings");
  await expect(page.getByRole("button", { name: "Previous findings page" })).toBeDisabled();
});

test("returning to a project cannot revive its old findings, members, policies, or notifications", async ({ page }) => {
  const observed = await openWorkbench(page);
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  const intercepted = new Set();
  await page.route(/\/api\/projects\/7\/(findings|members|policies|notifications)(?:\?|$)/, async (route) => {
    const url = new URL(route.request().url());
    const endpoint = url.pathname.split("/").pop();
    if (intercepted.has(endpoint)) return route.fulfill({ json: observed.projectResponse(7, endpoint, url) });
    intercepted.add(endpoint);
    await waiting;
    const stale = {
      findings: { findings: [finding(99, { title: "Stale finding" })] },
      members: { members: [{ user_id: 99, username: "Stale member", role: "operator" }] },
      policies: { policies: [{ id: 99, version: 99, name: "Stale policy", state: "approved", definition: { fail_on_severities: [] } }] },
      notifications: { channels: [{ id: 99, name: "Stale channel", channel_type: "webhook", events: [] }] }
    };
    return route.fulfill({ json: stale[endpoint] });
  });
  const pending = ["findings", "members", "policies", "notifications"].map((endpoint) =>
    page.waitForRequest((request) => new URL(request.url()).pathname === `/api/projects/7/${endpoint}`));
  await page.evaluate(() => { window.pendingLoads = Promise.all([loadFindings(), loadMembers(), loadPolicies(), loadNotifications()]); });
  await Promise.all(pending);
  await page.evaluate(() => selectProject(8));
  await page.evaluate(() => selectProject(7));
  release();
  await page.evaluate(() => window.pendingLoads);
  await expect(page.locator("#findings")).toContainText("Finding 1");
  await expect(page.locator("#members")).toContainText("Current member 7");
  await expect(page.locator("#policies")).toContainText("Current policy 7");
  await expect(page.locator("#notifications")).toContainText("Current channel 7");
  await expect(page.locator("#project-detail")).not.toContainText("Stale");
});

test("a late search response cannot overwrite a newer filtered page", async ({ page }) => {
  const findings = [finding(1, { title: "Old result" }), finding(2, { title: "New result" })];
  await openWorkbench(page, { findings });
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  await page.route("**/api/projects/7/findings?**", async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("search") === "Old") await waiting;
    return route.fulfill({ json: findingsPage(findings, url) });
  });
  const pending = page.waitForRequest((request) => new URL(request.url()).searchParams.get("search") === "Old");
  await page.getByLabel("Search findings").fill("Old");
  await pending;
  await page.getByLabel("Search findings").fill("New");
  await expect(page.locator("#findings")).toContainText("New result");
  const stale = page.waitForResponse((response) => new URL(response.url()).searchParams.get("search") === "Old");
  release();
  await (await stale).finished();
  await expect(page.locator("#findings")).toContainText("New result");
  await expect(page.locator("#findings-page-status")).toHaveText("1–1 of 1 findings");
});

test("a failed status poll preserves evidence and retries until the scan finishes", async ({ page }) => {
  await page.clock.install();
  await openWorkbench(page, { getScan: () => ({ ...sourceScan, state: "analyzing", progress: 50, decision: null, completed_at: null }) });
  let polls = 0;
  await page.route("**/api/projects/7/scans", (route) => {
    polls += 1;
    return route.fulfill(polls === 1 ? { status: 503, json: { detail: "Temporarily unavailable" } }
      : { json: { scans: [sourceScan], latest_source_scan: sourceScan } });
  });
  const failed = page.waitForResponse((response) => response.url().endsWith("/api/projects/7/scans") && response.status() === 503);
  await page.clock.runFor(3000);
  await (await failed).finished();
  await expect(page.locator("#scan-history .scan")).toHaveCount(1);
  await expect(page.locator("#release-decision")).toHaveText("Scan in progress");
  await page.clock.runFor(3000);
  await expect(page.locator("#release-decision")).toHaveText("Blocked");
  await expect(page.locator("#release-reason")).toHaveText(sourceScan.failure_reason);
  expect(polls).toBe(2);
});

test("release summary uses compact scan fields without downloading the full result", async ({ page }) => {
  const observed = await openWorkbench(page);
  await expect(page.locator("#release-decision")).toHaveText("Blocked");
  await expect(page.locator("#release-reason")).toHaveText(sourceScan.failure_reason);
  expect(observed.requests.filter((url) => /\/scans\/\d+$/.test(url.pathname))).toHaveLength(0);
});

test("a missing compact decision cannot approve a release", async ({ page }) => {
  const observed = await openWorkbench(page, { getScan: () => ({ ...sourceScan, decision: null, failure_reason: null }) });
  await expect(page.locator("#release-decision")).toHaveText("Scan incomplete");
  expect(observed.requests.filter((url) => /\/scans\/\d+$/.test(url.pathname))).toHaveLength(0);
});
