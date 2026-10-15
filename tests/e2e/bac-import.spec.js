const { test, expect } = require("@playwright/test");
const fs = require("node:fs/promises");
const path = require("node:path");

const artifactNames = [
  "report.json", "matrix.json", "findings.json", "evidence.json",
  "server-events.json", "report.md", "report.html", "scan-manifest.json"
];
const artifacts = artifactNames.map((name) => ({
  name,
  mimeType: name.endsWith(".json") ? "application/json" : name.endsWith(".html") ? "text/html" : "text/markdown",
  buffer: Buffer.from(`Original exported bytes: ${name}\n`)
}));
const sourceScan = {
  id: 11, run_kind: "source", target: "repository", preset: "standard",
  state: "completed", progress: 100, decision: "ALLOWED", new_findings: 2,
  created_at: "2026-10-01T10:00:00Z", completed_at: "2026-10-01T10:01:00Z", has_report: true
};
const researchScan = {
  id: 21, run_kind: "bac_research", target: "bac-research", preset: "quick",
  state: "completed", progress: 100, decision: null, new_findings: 9,
  research_exit_code: 1, research_status: "blocked", research_mode: "vulnerable",
  created_at: "2026-10-08T10:00:00Z", completed_at: "2026-10-08T10:01:00Z", has_report: true
};
const researchFinding = {
  id: 31, tool: "BAC", rule_id: "read", title: "Synthetic BAC research: denied read succeeded",
  path: "lab/document", severity: "CRITICAL", status: "open", occurrence_count: 1
};

// Mock every request: exercise the browser UI without signing keys, a lab, or live imports.
async function openWorkbench(page, { role = "operator", getScans = () => [sourceScan], getLatestSourceScan, findings = [] } = {}) {
  const template = await fs.readFile(path.join(__dirname, "../../app/templates/projects.html"), "utf8");
  const html = template.replace(/{% if demo_lab_enabled %}.*?{% endif %}/s, "")
    .replaceAll("{{ request.state.csp_nonce }}", "browser-test");
  const css = await fs.readFile(path.join(__dirname, "../../app/static/aegis-app.css"), "utf8");
  let detailRequests = [];
  await page.route("**/*", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === "/projects") return route.fulfill({ contentType: "text/html", body: html });
    if (pathname === "/static/aegis-app.css") return route.fulfill({ contentType: "text/css", body: css });
    if (pathname === "/static/bac-review.js") return route.fulfill({
      contentType: "text/javascript", body: await fs.readFile(path.join(__dirname, "../../app/static/bac-review.js"), "utf8")
    });
    let json;
    if (pathname === "/api/auth/me") json = { username: "research-operator", role, csrf_token: "browser-test-csrf" };
    else if (pathname === "/api/projects") json = { projects: [{
      id: 7, name: "Research project", github_full_name: "example/repository",
      default_branch: "main", scan_preset: "standard", role
    }] };
    else if (pathname === "/api/github/status") json = { enabled: false };
    else if (pathname === "/api/projects/7/scans") json = {
      scans: getScans(), ...(getLatestSourceScan ? { latest_source_scan: getLatestSourceScan() } : {})
    };
    else if (pathname === "/api/projects/7/findings") json = { findings };
    else if (pathname === "/api/projects/7/members") json = { members: [] };
    else if (pathname === "/api/projects/7/policies") json = { policies: [] };
    else if (pathname === "/api/projects/7/notifications") json = { channels: [] };
    else if (/^\/api\/projects\/7\/scans\/\d+$/.test(pathname)) {
      detailRequests = [...detailRequests, Number(pathname.split("/").pop())];
      json = { result: { policy: { status: "ALLOWED", reason: "Source evidence passed." } } };
    } else return route.fulfill({ status: 404, json: { detail: `Unexpected mocked request: ${pathname}` } });
    return route.fulfill({ json });
  });
  await page.goto("/projects?welcome=1");
  await expect(page.locator("#project-name")).toHaveText("Research project");
  await expect(page.locator("#scan-history .scan")).toHaveCount(getScans().length);
  return { detailRequests: () => detailRequests };
}

test("BAC import sends eight original files with CSRF, reports duplicates, and refreshes history", async ({ page }) => {
  let scans = [sourceScan];
  await openWorkbench(page, { getScans: () => scans });
  let releaseImport;
  const waiting = new Promise((resolve) => { releaseImport = resolve; });
  let requests = 0;
  await page.route("**/api/projects/7/bac-imports", async (route) => {
    const request = route.request();
    expect(request.method()).toBe("POST");
    expect(request.headers()["x-csrf-token"]).toBe("browser-test-csrf");
    expect(request.headers()["content-type"]).toMatch(/^multipart\/form-data; boundary=/);
    const body = request.postDataBuffer().toString();
    expect(body.match(/name="files"; filename="/g)).toHaveLength(8);
    for (const artifact of artifacts) {
      expect(body).toContain(`filename="${artifact.name}"`);
      expect(body).toContain(artifact.buffer.toString());
    }
    await waiting;
    requests += 1;
    scans = [researchScan, sourceScan];
    await route.fulfill({ status: requests === 1 ? 201 : 200, json: {
      scan_run_id: researchScan.id, imported: requests === 1, research_only: true
    } });
  });
  const input = page.getByLabel("BAC run artifacts");
  await expect(input).toHaveAttribute("multiple", "");
  await expect(input).toHaveAttribute("accept", ".json,.md,.html");
  await input.setInputFiles(artifacts);
  const submit = page.getByRole("button", { name: "Import research run", exact: true });
  await submit.click();
  await expect(page.locator("#bac-import-status")).toContainText("Importing");
  await expect(page.locator("#bac-import-form button[type=submit]")).toBeDisabled();
  releaseImport();
  await expect(page.locator("#bac-import-status")).toContainText("Imported BAC research run #21");
  await expect(page.locator("#scan-history .scan")).toHaveCount(2);
  await expect(page.locator("#release-decision")).toHaveText("Allowed");
  await input.setInputFiles(artifacts);
  await submit.click();
  await expect(page.locator("#bac-import-status")).toContainText("already imported");
  await expect(page.locator("#scan-history .scan")).toHaveCount(2);
  expect(requests).toBe(2);
});

test("BAC import reports missing files and validation errors, then recovers with the same selection", async ({ page }) => {
  await openWorkbench(page);
  let requests = 0;
  await page.route("**/api/projects/7/bac-imports", async (route) => {
    requests += 1;
    return route.fulfill(requests === 1
      ? { status: 400, json: { detail: "Artifact signature or inventory is invalid." } }
      : { status: 201, json: { scan_run_id: 21, imported: true, research_only: true } });
  });
  const input = page.getByLabel("BAC run artifacts");
  const submit = page.getByRole("button", { name: "Import research run", exact: true });
  await input.setInputFiles(artifacts.slice(0, 1));
  await submit.click();
  await expect(page.locator("#bac-import-status")).toContainText("all eight original files");
  expect(requests).toBe(0);
  await input.setInputFiles(artifacts);
  await submit.click();
  await expect(page.getByRole("alert")).toContainText("Artifact signature or inventory is invalid.");
  await expect(submit).toBeEnabled();
  expect(await input.evaluate((element) => element.files.length)).toBe(8);
  await expect(page.locator("#scan-history .scan")).toHaveCount(1);
  await submit.click();
  await expect(page.locator("#bac-import-status")).toContainText("Imported BAC research run #21");
  await expect(page.locator("#error")).toHaveText("");
});

test("BAC outcomes and findings stay separate from source release evidence and actions", async ({ page }) => {
  const scans = [
    researchScan,
    { ...researchScan, id: 22, state: "failed", research_exit_code: 2, research_status: "error" },
    { ...researchScan, id: 23, new_findings: 0, research_exit_code: 0, research_status: "allowed" },
    sourceScan
  ];
  const observed = await openWorkbench(page, { getScans: () => scans, findings: [researchFinding] });
  await expect(page.locator("#release-decision")).toHaveText("Allowed");
  await expect(page.locator("#summary-blockers")).toHaveText("0");
  await expect(page.locator("#summary-new")).toHaveText("2");
  await expect(page.locator("#summary-last-note")).toHaveText("standard · completed");
  await expect(page.locator("#onboarding")).toBeHidden();
  const researchRows = page.locator("#scan-history .scan").filter({ hasText: "BAC research" });
  await expect(researchRows).toHaveCount(3);
  await expect(researchRows.nth(0).locator(".badge")).toHaveText("violation");
  await expect(researchRows.nth(1).locator(".badge")).toHaveText("incomplete");
  await expect(researchRows.nth(2).locator(".badge")).toHaveText("complete");
  await expect(researchRows.locator("[data-retry], [data-cancel]")).toHaveCount(0);
  await expect(page.locator("[data-retry='11']")).toBeVisible();
  await expect(researchRows.nth(0).getByRole("link", { name: "Open report" })).toHaveAttribute("href", "/api/projects/7/scans/21/artifacts/report.html");
  await expect(researchRows.nth(0).getByRole("link", { name: "Download evidence" })).toHaveAttribute("href", "/api/projects/7/scans/21/artifacts/report-bundle.zip");
  expect(observed.detailRequests()).toEqual([]);
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  const finding = page.locator(".finding-row");
  await expect(finding).toContainText("BAC research");
  await expect(finding.getByRole("button", { name: "Create GitHub issue" })).toHaveCount(0);
});

test("research-only history still needs a first source scan and keeps source polling active", async ({ page }) => {
  let scans = [researchScan];
  await openWorkbench(page, { getScans: () => scans });
  await expect(page.locator("#release-decision")).toHaveText("Not evaluated");
  await expect(page.locator("#summary-new")).toHaveText("0");
  await expect(page.locator("#summary-last-note")).toHaveText("No evidence yet");
  await expect(page.getByRole("button", { name: "Start quick scan" })).toBeEnabled();
  scans = [researchScan, { ...sourceScan, state: "analyzing", decision: null, progress: 50 }];
  await page.reload();
  await expect(page.locator("#release-decision")).toHaveText("Scan in progress");
  scans = [researchScan, sourceScan];
  await expect(page.locator("#release-decision")).toHaveText("Allowed", { timeout: 7000 });
});

test("viewers can read BAC research but cannot import artifacts", async ({ page }) => {
  await openWorkbench(page, { role: "viewer", getScans: () => [researchScan], findings: [researchFinding] });
  await expect(page.getByLabel("BAC run artifacts")).toBeHidden();
  await expect(page.getByRole("button", { name: "Import research run", exact: true })).toBeHidden();
  await expect(page.locator("#scan-history")).toContainText("BAC research");
});

test("bounded history preserves the pinned source decision, onboarding, and polling", async ({ page }) => {
  const scans = Array.from({ length: 50 }, (_, index) => ({ ...researchScan, id: 71 - index }));
  let latestSource = sourceScan;
  const observed = await openWorkbench(page, {
    getScans: () => scans, getLatestSourceScan: () => latestSource, findings: [researchFinding]
  });
  await expect(page.locator("#scan-history .scan")).toHaveCount(50);
  await expect(page.locator("#release-decision")).toHaveText("Allowed");
  await expect(page.locator("#summary-blockers")).toHaveText("0");
  await expect(page.locator("#summary-new")).toHaveText("2");
  await expect(page.locator("#summary-last-note")).toHaveText("standard · completed");
  await expect(page.locator("#onboarding")).toBeHidden();
  expect(observed.detailRequests()).toEqual([]);
  latestSource = { ...sourceScan, state: "analyzing", decision: null, progress: 50 };
  await page.reload();
  await expect(page.locator("#release-decision")).toHaveText("Scan in progress");
  latestSource = sourceScan;
  await expect(page.locator("#release-decision")).toHaveText("Allowed", { timeout: 7000 });
  await expect(page.locator("#scan-history .scan")).toHaveCount(50);
});

test("an explicit empty source context does not use legacy history fallback", async ({ page }) => {
  await openWorkbench(page, { getScans: () => [sourceScan], getLatestSourceScan: () => null });
  await expect(page.locator("#release-decision")).toHaveText("Not evaluated");
  await expect(page.locator("#summary-new")).toHaveText("0");
  await expect(page.getByRole("button", { name: "Start quick scan" })).toBeEnabled();
});

test("a stale scan response cannot replace another project's source context", async ({ page }) => {
  await openWorkbench(page);
  await expect(page.locator("#release-decision")).toHaveText("Allowed");
  const secondProject = {
    id: 8, name: "Second project", default_branch: "main", scan_preset: "quick", role: "operator"
  };
  await page.route("**/api/projects", (route) => route.fulfill({ json: { projects: [
    { ...secondProject, id: 7, name: "Research project", scan_preset: "standard" }, secondProject
  ] } }));
  await page.route("**/api/projects/8/**", (route) => {
    const endpoint = new URL(route.request().url()).pathname.split("/").pop();
    const responses = {
      scans: { scans: [], latest_source_scan: null }, findings: { findings: [] },
      members: { members: [] }, policies: { policies: [] }, notifications: { channels: [] }
    };
    return route.fulfill({ json: responses[endpoint] || { detail: "Unknown second-project endpoint" } });
  });
  await page.evaluate(() => loadProjects());
  let releaseScans;
  const waiting = new Promise((resolve) => { releaseScans = resolve; });
  await page.route("**/api/projects/7/scans", async (route) => {
    await waiting;
    return route.fulfill({ json: { scans: [sourceScan], latest_source_scan: sourceScan } });
  });
  const pendingRequest = page.waitForRequest("**/api/projects/7/scans");
  await page.evaluate(() => {
    window.staleScanLoad = loadScans();
  });
  await pendingRequest;
  await page.locator("[data-project='8']").click();
  await expect(page.locator("#project-name")).toHaveText("Second project");
  await expect(page.locator("#release-decision")).toHaveText("Not evaluated");
  releaseScans();
  await page.evaluate(() => window.staleScanLoad);
  await expect(page.locator("#scan-history .scan")).toHaveCount(0);
  await expect(page.locator("#release-decision")).toHaveText("Not evaluated");
});
