import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type FullConfig } from "@playwright/test";

export default async function verifyBuildIdentity(config: FullConfig) {
  const solandBaseUrl = process.env.COTEST_SOLAND_BASE_URL?.replace(/\/$/, "");
  if (!solandBaseUrl) {
    return;
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const workspaceRoot = path.resolve(here, "../..");
  const inksonRoot = path.join(workspaceRoot, "inkson");
  const registryPath = path.join(
    workspaceRoot,
    "arkret-spec",
    "spec",
    "v1",
    "artifacts",
    "registry",
    "event-kind-registry.json",
  );
  const expectedSourceSha = execFileSync(
    "git",
    ["-C", inksonRoot, "rev-parse", "--short", "HEAD"],
    { encoding: "utf8" },
  ).trim();
  const expectedRegistrySha = createHash("sha256")
    .update(readFileSync(registryPath))
    .digest("hex");
  const baseURL = config.projects
    .map((project) => project.use.baseURL)
    .find((value): value is string => typeof value === "string");
  if (!baseURL) {
    throw new Error("build identity gate cannot resolve the Inkson base URL");
  }

  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.goto(baseURL, { waitUntil: "domcontentloaded" });
    const identity = await page.locator("html").evaluate((root) => ({
      buildId: root.getAttribute("data-inkson-build-id"),
      registrySha: root.getAttribute("data-arkret-event-registry-sha256"),
      sdkSourceSha: root.getAttribute("data-arkret-sdk-source-sha256"),
    }));
    if (!identity.buildId?.match(new RegExp(`\\b${expectedSourceSha}(?:\\+dirty)?$`))) {
      throw new Error(
        `stale Inkson bundle: expected source ${expectedSourceSha}, loaded ${identity.buildId ?? "<missing>"}`,
      );
    }
    if (identity.registrySha !== expectedRegistrySha) {
      throw new Error(
        `Inkson registry mismatch: expected ${expectedRegistrySha}, loaded ${identity.registrySha ?? "<missing>"}`,
      );
    }
    if (!identity.sdkSourceSha?.match(/^[0-9a-f]{64}$/)) {
      throw new Error(
        `Inkson SDK source identity is missing or invalid: ${identity.sdkSourceSha ?? "<missing>"}`,
      );
    }

    const response = await page.request.get(`${solandBaseUrl}/_arkret/describe`);
    if (!response.ok()) {
      throw new Error(`Soland describe failed during build identity gate: ${response.status()}`);
    }
    const describe = (await response.json()) as {
      x_arkret_build_identity?: {
        event_kind_registry_sha256?: string;
        sdk_source_sha256?: string;
      };
    };
    const serverRegistrySha =
      describe.x_arkret_build_identity?.event_kind_registry_sha256;
    if (serverRegistrySha !== expectedRegistrySha) {
      throw new Error(
        `Soland registry mismatch: expected ${expectedRegistrySha}, loaded ${serverRegistrySha ?? "<missing>"}`,
      );
    }
    const serverSdkSourceSha =
      describe.x_arkret_build_identity?.sdk_source_sha256;
    if (serverSdkSourceSha !== identity.sdkSourceSha) {
      throw new Error(
        `Inkson/Soland SDK build mismatch: Inkson ${identity.sdkSourceSha}, Soland ${serverSdkSourceSha ?? "<missing>"}`,
      );
    }
  } finally {
    await browser.close();
  }
}
