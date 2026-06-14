import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

const runDir =
  process.env.COTEST_JOINT_RUN_DIR ??
  path.resolve(process.cwd(), "..", "artifacts", "joint-e2e-local");
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
