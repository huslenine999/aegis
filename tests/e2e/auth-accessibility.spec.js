const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

test.describe.configure({ mode: "serial" });

test("first-run wizard claims the administrator and configures the workspace", async ({ page }) => {
  await page.goto("/setup#e2e-first-run-setup-token");
  const workspaceName = page.getByLabel("Workspace name");
  const isFirstRun = await workspaceName.isVisible();
  if (isFirstRun) {
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);

    await workspaceName.fill("E2E Engineering");
    await page.getByLabel("Repository URL or path").fill("https://github.com/example/project");
    await page.getByLabel("Default scan depth").selectOption("standard");
    await page.getByLabel("Administrator username").fill("e2e-owner");
    await page.getByLabel("Administrator password", { exact: true }).fill("e2e-owner-password");
    await page.getByLabel("Confirm password").fill("e2e-owner-password");
    await page.getByRole("button", { name: "Finish setup" }).click();
    await expect(page).toHaveURL(/\/projects\?welcome=1$/);
  } else {
    // Serial retries reuse the already-configured server process.
    await expect(page).toHaveURL(/\/login(?:#.*)?$/);
    await page.getByLabel("Username").fill("e2e-owner");
    await page.getByLabel("Password").fill("e2e-owner-password");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/$/);
    await page.goto("/projects");
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
  await expect(page).toHaveURL(/\/$/);

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
  await expect(page).toHaveURL(/\/$/);
  results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("viewer, operator, and admin permissions are enforced by the API", async ({ page, browser }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill("e2e-owner");
  await page.getByLabel("Password").fill("e2e-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/$/);

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
  await expect(page).toHaveURL(/\/$/);
  await page.goto("/projects");

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

test("operations console issues and revokes API tokens accessibly", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill("e2e-owner");
  await page.getByLabel("Password").fill("e2e-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/$/);
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
  await expect(page.getByRole("heading", { name: "Administration and operations" })).toBeVisible();
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
    await expect(page).toHaveURL(/\/$/);
  }
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
