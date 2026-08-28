import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "../../helpers/arkret-test";

const here = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(here, "../../../..");
const inksonRoot = path.join(workspaceRoot, "inkson");

test("@fully-implemented loaded Inkson bundle matches its source checkout", async ({
  page,
}) => {
  const expectedSourceSha = execFileSync(
    "git",
    ["-C", inksonRoot, "rev-parse", "--short", "HEAD"],
    { encoding: "utf8" },
  ).trim();
  await page.goto("/", { waitUntil: "domcontentloaded" });
  const root = page.locator("html");
  await expect(root).toHaveAttribute(
    "data-inkson-build-id",
    new RegExp(`\\b${expectedSourceSha}(?:\\+dirty)?$`),
  );
});
