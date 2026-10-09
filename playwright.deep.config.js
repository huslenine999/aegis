const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const aegisEnv = path.join(__dirname, ".env.aegis");
const imageLine = fs.readFileSync(aegisEnv, "utf8")
  .split(/\r?\n/)
  .find((line) => line.startsWith("AEGIS_CODEQL_IMAGE="));
const image = imageLine?.slice("AEGIS_CODEQL_IMAGE=".length).trim();
if (!image || !/^[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}$/.test(image)) {
  throw new Error("Run make codeql-setup before the Deep browser smoke test.");
}

const dockerHost = execFileSync(
  "docker",
  ["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
  { encoding: "utf8" },
).trim();
if (!dockerHost.startsWith("unix://")) {
  throw new Error("The Deep browser smoke test requires a local Docker Unix socket.");
}

process.env.AEGIS_E2E_DEEP = "1";
process.env.AEGIS_CODEQL_IMAGE = image;
process.env.AEGIS_CODEQL_DOCKER_HOST = dockerHost;
module.exports = require("./playwright.config");
