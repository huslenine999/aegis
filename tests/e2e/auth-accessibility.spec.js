const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const fs = require("node:fs/promises");

test.describe.configure({ mode: "serial" });

async function signInE2EOwner(page) {
  await page.goto("/setup#e2e-first-run-setup-token");
  const workspaceName = page.getByLabel("Workspace name");
  if (await workspaceName.isVisible()) {
    await workspaceName.fill("E2E Engineering");
    await page.getByLabel("GitHub HTTPS URL").fill("");
    await page.getByLabel("Default scan depth").selectOption("standard");
    await page.getByLabel("Administrator username").fill("e2e-owner");
    await page.getByLabel("Administrator password", { exact: true }).fill("e2e-owner-password");
    await page.getByLabel("Confirm password").fill("e2e-owner-password");
    await page.getByRole("button", { name: "Finish setup" }).click();
  } else {
    await page.goto("/login");
    await page.getByLabel("Username").fill("e2e-owner");
    await page.getByLabel("Password").fill("e2e-owner-password");
    await page.getByRole("button", { name: "Sign in" }).click();
  }
  await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);
}

test("first-run wizard claims the administrator and configures the workspace", async ({ page }) => {
  await page.goto("/setup#e2e-first-run-setup-token");
  const workspaceName = page.getByLabel("Workspace name");
  const isFirstRun = await workspaceName.isVisible();
  if (isFirstRun) {
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);

    await workspaceName.fill("E2E Engineering");
    await page.getByLabel("GitHub HTTPS URL").fill("https://github.com/example/project");
    await page.getByLabel("Default scan depth").selectOption("standard");
    await page.getByLabel("Administrator username").fill("e2e-owner");
    await page.getByLabel("Administrator password", { exact: true }).fill("e2e-owner-password");
    await page.getByLabel("Confirm password").fill("e2e-owner-password");
    await page.getByRole("button", { name: "Finish setup" }).click();
    await expect(page).toHaveURL(/\/projects\?welcome=1(?:&project=\d+)?$/);
  } else {
    // Serial retries reuse the already-configured server process.
    await expect(page).toHaveURL(/\/login(?:#.*)?$/);
    await page.getByLabel("Username").fill("e2e-owner");
    await page.getByLabel("Password").fill("e2e-owner-password");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);
  }
  await expect(page.locator("[data-project]").filter({ hasText: "project" })).toBeVisible();
  if (isFirstRun) {
    await expect(page.getByRole("button", { name: "Start quick scan" })).toBeEnabled();
  }
});

test("unauthenticated users sign in before accessing reports", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  expect((await page.request.get("/get-scan-results")).status()).toBe(401);
  const closeCode = await page.evaluate(() => new Promise((resolve) => {
    const socket = new WebSocket("ws://127.0.0.1:5011/ws/scan/unknown-job");
    socket.addEventListener("close", (event) => resolve(event.code));
  }));
  // Rejected before the HTTP upgrade; browsers expose this as abnormal close.
  expect(closeCode).toBe(1006);

  await page.getByLabel("Username").fill("e2e-owner");
  await page.getByLabel("Password").fill("wrong-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Invalid");

  await page.getByLabel("Password").fill("e2e-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);

  const reportResponse = await page.request.get("/get-scan-results");
  expect(reportResponse.ok()).toBeTruthy();
});

test("login and workbench have no serious accessibility violations", async ({ page }) => {
  await page.goto("/login");
  let results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);

  await page.getByLabel("Username").fill("e2e-owner");
  await page.getByLabel("Password").fill("e2e-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);
  results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("viewer, operator, and admin permissions are enforced by the API", async ({ page, browser }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill("e2e-owner");
  await page.getByLabel("Password").fill("e2e-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);

  const me = await (await page.request.get("/api/auth/me")).json();
  const suffix = Date.now();
  const viewer = `viewer-${suffix}`;
  const operator = `operator-${suffix}`;
  for (const [username, role] of [[viewer, "viewer"], [operator, "operator"]]) {
    const response = await page.request.post("/api/users", {
      headers: { "X-CSRF-Token": me.csrf_token },
      data: { username, role, password: "role-test-password" }
    });
    expect(response.status(), await response.text()).toBe(201);
  }

  const viewerContext = await browser.newContext({ baseURL: "http://127.0.0.1:5011" });
  await viewerContext.request.post("/api/auth/login", {
    data: { username: viewer, password: "role-test-password" }
  });
  const viewerMe = await (await viewerContext.request.get("/api/auth/me")).json();
  expect((await viewerContext.request.get("/get-scan-results")).status()).toBe(403);
  expect((await viewerContext.request.post("/run-scan", {
    headers: { "X-CSRF-Token": viewerMe.csrf_token },
    data: { target: "invalid" }
  })).status()).toBe(403);
  await viewerContext.close();

  const operatorContext = await browser.newContext({ baseURL: "http://127.0.0.1:5011" });
  await operatorContext.request.post("/api/auth/login", {
    data: { username: operator, password: "role-test-password" }
  });
  const operatorMe = await (await operatorContext.request.get("/api/auth/me")).json();
  expect((await operatorContext.request.post("/run-scan", {
    headers: { "X-CSRF-Token": operatorMe.csrf_token },
    data: { target: "invalid" }
  })).status()).toBe(400);
  expect((await operatorContext.request.get("/api/users")).status()).toBe(403);
  await operatorContext.close();
});

test("project dashboard creates and displays a project accessibly", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill("e2e-owner");
  await page.getByLabel("Password").fill("e2e-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);

  await page.getByRole("button", { name: "New project" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Project name").fill("Payments API");
  await dialog.getByLabel("Default branch").fill("main");
  await dialog.getByLabel("Scan preset").selectOption("quick");
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("button", { name: /Payments API/ })).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("project scan opens its report and downloads verified evidence", async ({ page }) => {
  const deepScanEnabled = process.env.AEGIS_E2E_DEEP === "1";
  test.setTimeout(deepScanEnabled ? 900_000 : 120_000);
  await signInE2EOwner(page);

  const projectName = `Browser scan ${Date.now()}`;
  await page.getByRole("button", { name: "New project" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Project name").fill(projectName);
  await dialog.getByLabel("GitHub HTTPS URL", { exact: true }).fill("https://github.com/aegis-e2e/scan-fixture.git");
  await dialog.getByLabel("Default branch").fill("main");
  await dialog.getByLabel("Scan preset").selectOption("quick");
  const createProject = page.waitForResponse((response) =>
    response.url().endsWith("/api/projects") && response.request().method() === "POST"
  );
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  const createResponse = await createProject;
  expect(createResponse.status()).toBe(201);
  await page.locator("[data-project]").filter({ hasText: projectName }).click();

  await page.getByRole("tab", { name: "Settings" }).click();
  await page.locator("#scan-preset").selectOption("deep");
  await page.getByRole("button", { name: "Save settings" }).click();
  await expect(page.locator("#notice")).toContainText("Project settings saved");
  await page.getByRole("tab", { name: "Overview" }).click();
  await page.getByRole("button", { name: "Run scan" }).click();

  if (deepScanEnabled) {
    await expect(page.locator("#notice")).toContainText("queued");
  } else {
    await expect(page.locator("#error")).toContainText("Deep scans require an isolated CodeQL runtime");
    await expect(page.locator("#scan-history")).toContainText("No scans yet");
    await page.getByRole("tab", { name: "Settings" }).click();
    await page.locator("#scan-preset").selectOption("quick");
    await page.getByRole("button", { name: "Save settings" }).click();
    await expect(page.locator("#notice")).toContainText("Project settings saved");
    await page.getByRole("tab", { name: "Overview" }).click();
    await page.getByRole("button", { name: "Run scan" }).click();
  }

  const reportLink = page.getByRole("link", { name: "Open report" });
  await expect(reportLink).toBeVisible({ timeout: deepScanEnabled ? 900_000 : 60_000 });
  const reportUrl = await reportLink.getAttribute("href");
  const match = reportUrl.match(/\/api\/projects\/(\d+)\/scans\/(\d+)\/artifacts\/report\.html$/);
  expect(match).not.toBeNull();

  const artifactResponse = await page.request.get(`/api/projects/${match[1]}/scans/${match[2]}/artifacts`);
  expect(artifactResponse.ok()).toBeTruthy();
  const artifacts = (await artifactResponse.json()).artifacts;
  expect(artifacts).toEqual(expect.arrayContaining([
    expect.objectContaining({ name: "report.html", integrity: "verified" }),
    expect.objectContaining({ name: "scan-manifest.json", integrity: "verified" })
  ]));
  const descriptorResponse = await page.request.get(`/api/projects/${match[1]}/scans/${match[2]}/artifacts/source-descriptor.json`);
  expect(descriptorResponse.ok()).toBeTruthy();
  const descriptor = await descriptorResponse.json();
  expect(descriptor.files.map((file) => file.path)).toEqual(["fixture.py"]);
  const manifestResponse = await page.request.get(`/api/projects/${match[1]}/scans/${match[2]}/artifacts/scan-manifest.json`);
  expect(manifestResponse.ok()).toBeTruthy();
  expect((await manifestResponse.json()).source.identity).toBe("https://github.com/aegis-e2e/scan-fixture.git");
  if (deepScanEnabled) {
    expect(artifacts).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "codeql.sarif", integrity: "verified" }),
      expect.objectContaining({ name: "codeql-report.json", integrity: "verified" })
    ]));
    const codeqlResponse = await page.request.get(
      `/api/projects/${match[1]}/scans/${match[2]}/artifacts/codeql-report.json`
    );
    expect(codeqlResponse.ok()).toBeTruthy();
    const codeqlReport = await codeqlResponse.json();
    expect(codeqlReport.coverage).toMatchObject({ complete: true, isolation: "verified" });
    expect(codeqlReport.coverage.languages).toContain("python");
  }

  const [reportPage] = await Promise.all([
    page.context().waitForEvent("page"),
    reportLink.click()
  ]);
  await expect(reportPage).toHaveTitle("Aegis | Security Assessment");
  await expect(reportPage.locator(".decision-banner")).toContainText(/Deployment (passed|blocked)|Scan incomplete/);
  await reportPage.close();

  const evidenceLink = page.getByRole("link", { name: "Download evidence" });
  const downloadPromise = page.waitForEvent("download");
  await evidenceLink.click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/\.zip$/);
  const downloadedFile = await download.path();
  const bundle = await fs.readFile(downloadedFile);
  expect(bundle.subarray(0, 2).toString()).toBe("PK");

  await page.getByRole("tab", { name: "Findings" }).click();
  const finding = page.locator(".finding-row").first();
  await expect(finding.getByRole("link", { name: "Latest evidence" })).toHaveAttribute("href", reportUrl);
  await finding.locator(".finding-history summary").click();
  await expect(finding.locator(".finding-history")).toContainText("created → open");
  await expect(finding.getByRole("link", { name: "scan evidence" })).toHaveAttribute("href", reportUrl);
});

test("tablet navigation stays labelled and phones can sign out", async ({ page }) => {
  await page.setViewportSize({ width: 900, height: 900 });
  await signInE2EOwner(page);
  const navigation = page.getByRole("complementary", { name: "Primary navigation" });
  for (const name of ["Projects", "Account security", "Operations"]) {
    await expect(navigation.getByRole("link", { name, exact: true })).toBeVisible();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await navigation.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect((await page.request.get("/api/auth/me")).status()).toBe(401);
});

test("operations console issues and revokes API tokens accessibly", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill("e2e-owner");
  await page.getByLabel("Password").fill("e2e-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);
  const me = await (await page.request.get("/api/auth/me")).json();
  const users = await (await page.request.get("/api/users")).json();
  const owner = users.users.find((user) => user.username === "e2e-owner");
  const issued = await page.request.post(`/api/users/${owner.id}/tokens`, {
    headers: { "X-CSRF-Token": me.csrf_token },
    data: { name: "e2e-token" }
  });
  expect(issued.status()).toBe(201);
  const tokens = await (await page.request.get("/api/tokens")).json();
  const token = tokens.tokens.find((item) => item.name === "e2e-token");
  expect((await page.request.delete(`/api/tokens/${token.id}`, {
    headers: { "X-CSRF-Token": me.csrf_token }
  })).status()).toBe(200);

  await page.goto("/admin");
  await expect(page.getByRole("heading", { name: "Administration and audit." })).toBeVisible();
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("scanner-controlled filenames remain inert text", async ({ page }) => {
  await page.goto("/login");
  if (page.url().includes("/setup")) {
    const setup = await page.request.post("/api/setup", {
      headers: { "X-Aegis-Setup-Token": "e2e-first-run-setup-token" },
      data: {
        workspace_name: "E2E Engineering",
        repository: "",
        scan_preset: "standard",
        username: "e2e-owner",
        password: "e2e-owner-password"
      }
    });
    expect(setup.status(), await setup.text()).toBe(200);
    await page.goto("/");
  } else {
    await page.getByLabel("Username").fill("e2e-owner");
    await page.getByLabel("Password").fill("e2e-owner-password");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/projects(?:\?.*)?$/);
  }
  await page.goto("/lab");
  await expect(page.locator("#uploadFile")).toBeAttached();
  await page.waitForFunction(() => typeof window.addSyslogEntry === "function");
  await page.evaluate(() => { window.AEGIS_XSS_PROBE = 0; });

  const filename = "<img src=x onerror=window.AEGIS_XSS_PROBE=1>.py";
  await page.locator("#uploadFile").setInputFiles({
    name: filename,
    mimeType: "text/x-python",
    buffer: Buffer.from("print('safe')\n")
  });

  await expect(page.locator("#syslog-stream")).toContainText(filename, { timeout: 1000 });
  expect(await page.evaluate(() => window.AEGIS_XSS_PROBE)).toBe(0);
});
