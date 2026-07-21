const { defineConfig } = require("@playwright/test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const python = fs.existsSync("venv/bin/python") ? "venv/bin/python" : "python";
const e2eDataDirectory = path.join(os.tmpdir(), `aegis-e2e-${process.pid}`);

module.exports = defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL: "http://127.0.0.1:5011",
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: `${python} -m uvicorn app.main:app --host 127.0.0.1 --port 5011`,
    url: "http://127.0.0.1:5011/health",
    reuseExistingServer: !process.env.CI,
    env: {
      AEGIS_ENV: "test",
      AEGIS_REQUIRE_AUTH: "true",
      AEGIS_SESSION_SECRET: "e2e-session-secret-at-least-thirty-two-characters",
      AEGIS_BOOTSTRAP_ADMIN_USERNAME: "e2e-admin",
      AEGIS_BOOTSTRAP_ADMIN_PASSWORD: "e2e-password-change-me",
      AEGIS_SETUP_TOKEN: "e2e-first-run-setup-token",
      AEGIS_ENABLE_DEMO_LAB: "true",
      AEGIS_DATA_DIR: e2eDataDirectory,
      AEGIS_LOGIN_RATE_LIMIT_PER_MINUTE: "20",
      AEGIS_SKIP_EXTERNAL_SCANNERS: "true"
    }
  }
});
