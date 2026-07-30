import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

// Canonical artifacts layout: orchestrated runs write under
// `cotest/artifacts/runs/joint-e2e/`. Runners and CI pass COTEST_JOINT_RUN_DIR;
// ad-hoc `npx playwright test` invocations get a fresh
// `runs/joint-e2e-adhoc/<timestamp>` directory. The
// resolved dir is written back into the env so worker processes and the
// helpers in helpers/env.ts (screenshots, diagnostics, visual baselines) all
// agree on one directory.
function adhocRunDir(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp =
    `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}` +
    `-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return path.resolve(process.cwd(), "..", "artifacts", "runs", "joint-e2e-adhoc", stamp);
}
const runDir = process.env.COTEST_JOINT_RUN_DIR ?? adhocRunDir();
process.env.COTEST_JOINT_RUN_DIR = runDir;
const baseURL =
  process.env.INKSON_BASE_URL ??
  process.env.COTEST_INKSON_BASE_URL ??
  "http://127.0.0.1:4527";

// COT-08-004: bounded file-level parallelism across spec files. Per-test state is
// isolated via `uniqueUser` / unique handles (the large majority of specs), and
// within-file ordering is preserved (`fullyParallel: false`) so multi-step
// strands stay intact. Browser specs often create two or three Coauth sessions
// concurrently inside one test, so two file workers are the safe default for
// the shared Coauth/Soland stack. The count remains env-tunable; use
// `COTEST_PW_WORKERS=1` for fully serial execution or raise it only for a stack
// provisioned and verified for the resulting authentication fan-out.
const workersEnv = process.env.COTEST_PW_WORKERS?.trim();
const workers = workersEnv
  ? workersEnv.endsWith("%")
    ? workersEnv
    : Number(workersEnv)
  : 2;

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
      name: "joint-inkson",
      testDir: "./tests",
      testMatch: [
        "joint/*.spec.ts",
        "identity/device-key-lifecycle.spec.ts",
        "identity/oidc-login-flow.spec.ts",
        "identity/passkey-login-flow.spec.ts",
      ],
      use: { ...devices["Desktop Chrome"], baseURL },
    },
  ],
});
