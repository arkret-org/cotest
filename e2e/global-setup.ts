import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type FullConfig } from "@playwright/test";

export default async function verifyInksonBuildIdentity(config: FullConfig) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const workspaceRoot = path.resolve(here, "../..");
  const inksonRoot = path.join(workspaceRoot, "inkson");
  const expectedSourceSha = execFileSync(
    "git",
    ["-C", inksonRoot, "rev-parse", "--short", "HEAD"],
    { encoding: "utf8" },
  ).trim();
  const baseURL = config.projects
    .map((project) => project.use.baseURL)
    .find((value): value is string => typeof value === "string");
  if (!baseURL) {
    throw new Error("build identity gate cannot resolve the Inkson base URL");
  }

  const tlsSpkiSha256 = process.env.COTEST_TLS_SPKI_SHA256?.trim();
  const browser = await chromium.launch({
    args: tlsSpkiSha256
      ? [`--ignore-certificate-errors-spki-list=${tlsSpkiSha256}`]
      : [],
  });
  try {
    const page = await browser.newPage({
      ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    });
    await page.goto(baseURL, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(
      () => {
        const root = document.documentElement;
        return root.hasAttribute("data-inkson-build-id");
      },
      undefined,
      { timeout: 30_000 },
    );
    const buildId = await page.locator("html").getAttribute("data-inkson-build-id");
    if (!buildId?.match(new RegExp(`\\b${expectedSourceSha}(?:\\+dirty)?$`))) {
      throw new Error(
        `stale Inkson bundle: expected source ${expectedSourceSha}, loaded ${buildId ?? "<missing>"}`,
      );
    }
  } finally {
    await browser.close();
  }
}
