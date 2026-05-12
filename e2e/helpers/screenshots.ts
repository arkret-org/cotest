import fs from "node:fs";
import path from "node:path";
import type { Page, TestInfo } from "@playwright/test";
import { screenshotRoot } from "./env";

export async function stepShot(page: Page, testInfo: TestInfo, name: string) {
  const dir = path.join(screenshotRoot(), sanitize(testInfo.titlePath.slice(1, -1).join("-")));
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${sanitize(name)}.png`);
  await page.screenshot({ path: file, fullPage: true });
  await testInfo.attach(name, { path: file, contentType: "image/png" });
  return file;
}

function sanitize(value: string): string {
  const cleaned = value
    .trim()
    .replace(/[^a-zA-Z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "screenshot";
}
