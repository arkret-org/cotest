import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

const runDir =
  process.env.COTEST_JOINT_RUN_DIR ??
  path.resolve(process.cwd(), "..", "artifacts", "joint-e2e-local");
const baseURL = process.env.COTEST_YOUGEN_BASE_URL ?? "http://127.0.0.1:4527";

export default defineConfig({
  testDir: "./tests",
  timeout: 180_000,
  expect: {
    timeout: 20_000,
  },
  fullyParallel: false,
  workers: 1,
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
      grepInvert: /@mobile/,
      use: { ...devices["Desktop Chrome"], channel: "chrome" },
    },
    {
      name: "chromium",
      grepInvert: /@mobile/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "mobile-chrome",
      grep: /@mobile/,
      use: { ...devices["Pixel 5"], channel: "chrome" },
    },
  ],
});
