import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";

const here = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(here, "../../../..");
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

test("@fully-implemented loaded Inkson bundle matches source and SDK registry", async ({
  page,
  request,
}) => {
  const expectedSourceSha = execFileSync(
    "git",
    ["-C", inksonRoot, "rev-parse", "--short", "HEAD"],
    { encoding: "utf8" },
  ).trim();
  const expectedRegistrySha = createHash("sha256")
    .update(readFileSync(registryPath))
    .digest("hex");

  await page.goto("/", { waitUntil: "domcontentloaded" });
  const root = page.locator("html");
  await expect(root).toHaveAttribute(
    "data-inkson-build-id",
    new RegExp(`\\b${expectedSourceSha}(?:\\+dirty)?$`),
  );
  await expect(root).toHaveAttribute(
    "data-arkret-event-registry-sha256",
    expectedRegistrySha,
  );

  const describeResponse = await request.get(
    `${solandBaseUrl()}/_arkret/describe`,
  );
  expect(describeResponse.ok()).toBeTruthy();
  const describe = (await describeResponse.json()) as {
    x_arkret_build_identity?: { event_kind_registry_sha256?: string };
  };
  expect(
    describe.x_arkret_build_identity?.event_kind_registry_sha256,
  ).toBe(expectedRegistrySha);
});
