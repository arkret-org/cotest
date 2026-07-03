import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

// Canonical artifacts layout: every run writes under
// `cotest/artifacts/runs/<timestamp>/`. Orchestrated runs (run-joint-e2e.ps1 /
// run-cotest.ps1 / CI) pass COTEST_JOINT_RUN_DIR; ad-hoc `npx playwright test`
// invocations get a fresh `runs/<timestamp>-adhoc/joint-e2e` directory. The
// resolved dir is written back into the env so worker processes and the
// helpers in helpers/env.ts (screenshots, diagnostics, visual baselines) all
// agree on one directory.
function adhocRunDir(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp =
    `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}` +
    `-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return path.resolve(process.cwd(), "..", "artifacts", "runs", `${stamp}-adhoc`, "joint-e2e");
}
const runDir = process.env.COTEST_JOINT_RUN_DIR ?? adhocRunDir();
process.env.COTEST_JOINT_RUN_DIR = runDir;
const baseURL =
  process.env.YOUGEN_BASE_URL ??
  process.env.COTEST_YOUGEN_BASE_URL ??
  "http://127.0.0.1:4527";

// COT-08-004: file-level parallelism across spec files. Per-test state is
// isolated via `uniqueUser` / unique handles (the large majority of specs), and
// within-file ordering is preserved (`fullyParallel: false`) so multi-step
// strands stay intact. The worker count is env-tunable so CI can match it to the
// shared soland/yougen stack's capacity — set `COTEST_PW_WORKERS=1` to fall
// back to fully serial. Specs that share fixed identities or assert global
// directory/federation state must either isolate (prefer `uniqueUser`) or tag
// `test.describe.configure({ mode: "serial" })`; most federation/conformance
// specs already do.
const workersEnv = process.env.COTEST_PW_WORKERS?.trim();
const workers = workersEnv
  ? workersEnv.endsWith("%")
    ? workersEnv
    : Number(workersEnv)
  : 4;

export default defineConfig({
  testDir: "./tests",
  timeout: 180_000,
  expect: {
    timeout: 20_000,
  },
  fullyParallel: false,
  workers,
  outputDir: path.join(runDir, "playwright-output"),
  reporter: [
    ["list"],
    ["junit", { outputFile: path.join(runDir, "junit.xml") }],
    ["html", { outputFolder: path.join(runDir, "playwright-report"), open: "never" }],
  ],
  use: {
    baseURL,
    // Opt-in for live Caddy `tls internal` stacks (self-signed). Applies to the
    // `request` fixture's API calls; the browser context mirrors it in openUser.
    ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    trace: "retain-on-failure",
    video: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chrome",
      use: { ...devices["Desktop Chrome"], channel: "chrome" },
    },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "joint-yougen",
      testDir: "./tests/joint",
      use: { ...devices["Desktop Chrome"], baseURL },
    },
  ],
});
