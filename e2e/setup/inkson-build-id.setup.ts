// Stale-bundle gate for the browser lanes.
//
// This was `global-setup.ts`, which ran unconditionally: every Playwright
// invocation launched Chromium and demanded a served Inkson bundle, including
// runs whose whole selection reaches no browser. As a setup project it runs
// only for the projects that declare it in `dependencies`, so `joint-api` no
// longer pays for a check that says nothing about it.
//
// The check itself is unchanged, and so are its limits: it compares the bundle's
// build id against the Inkson checkout's short HEAD and tolerates a `+dirty`
// suffix, so it catches a bundle built from a different commit, not every
// difference a dirty working tree can produce within one commit. The runner's
// own freshness and marker verification stays the other half of that guard.

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test } from "@playwright/test";

test("served Inkson bundle was built from the checked-out source", async ({
  page,
  baseURL,
}) => {
  if (!baseURL) {
    throw new Error("build identity gate cannot resolve the Inkson base URL");
  }
  const here = path.dirname(fileURLToPath(import.meta.url));
  const workspaceRoot = path.resolve(here, "../../..");
  const inksonRoot =
    process.env.COTEST_INKSON_ROOT?.trim() || path.join(workspaceRoot, "inkson");
  const expectedSourceSha = execFileSync(
    "git",
    ["-C", inksonRoot, "rev-parse", "--short", "HEAD"],
    { encoding: "utf8" },
  ).trim();

  await page.goto(baseURL, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(
    () => document.documentElement.hasAttribute("data-inkson-build-id"),
    undefined,
    { timeout: 30_000 },
  );
  const buildId = await page
    .locator("html")
    .getAttribute("data-inkson-build-id");
  if (!buildId?.match(new RegExp(`\\b${expectedSourceSha}(?:\\+dirty)?$`))) {
    throw new Error(
      `stale Inkson bundle: expected source ${expectedSourceSha}, loaded ${buildId ?? "<missing>"}`,
    );
  }
});
