const { defineConfig } = require("@playwright/test");
const os = require("node:os");
const path = require("node:path");
const e2eDataDirectory = path.join(os.tmpdir(), `aegis-e2e-${process.pid}`);
const deepScanEnabled = process.env.AEGIS_E2E_DEEP === "1";

module.exports = defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  retries: process.env.CI ? 2 : 0,
  outputDir: path.join(os.tmpdir(), `aegis-playwright-results-${process.pid}`),
  use: {
    baseURL: "http://127.0.0.1:5011",
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: "uv run --locked python -m tests.e2e_server",
    url: "http://127.0.0.1:5011/health",
    reuseExistingServer: !process.env.CI && process.env.AEGIS_E2E_DEEP !== "1",
    env: {
      AEGIS_ENV: "test",
      AEGIS_REQUIRE_AUTH: "true",
      AEGIS_SESSION_SECRET: "e2e-session-secret-at-least-thirty-two-characters",
      AEGIS_BOOTSTRAP_ADMIN_USERNAME: "e2e-admin",
      AEGIS_BOOTSTRAP_ADMIN_PASSWORD: "e2e-password-change-me",
      AEGIS_SETUP_TOKEN: "e2e-first-run-setup-token",
      AEGIS_DATA_DIR: e2eDataDirectory,
      AEGIS_LOGIN_RATE_LIMIT_PER_MINUTE: "20",
      AEGIS_SKIP_EXTERNAL_SCANNERS: "true",
      AEGIS_ALLOW_DEEP_SCANS: deepScanEnabled ? "true" : "false",
      AEGIS_ISOLATED_WORKER: deepScanEnabled ? "true" : "false",
      AEGIS_CODEQL_IMAGE: process.env.AEGIS_CODEQL_IMAGE || "",
      AEGIS_CODEQL_DOCKER_HOST: process.env.AEGIS_CODEQL_DOCKER_HOST || "",
      AEGIS_CODEQL_PYTHON_SUITE: process.env.AEGIS_CODEQL_PYTHON_SUITE || "codeql/python-queries:codeql-suites/python-security-extended.qls",
      AEGIS_CODEQL_JAVASCRIPT_SUITE: process.env.AEGIS_CODEQL_JAVASCRIPT_SUITE || "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"
    }
  }
});
