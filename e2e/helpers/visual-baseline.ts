import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Locator, Page, TestInfo } from "@playwright/test";
import { visualBaselineRoot } from "./env";

const VISUAL_BASELINE_CSS = `
  *, *::before, *::after {
    animation-delay: 0s !important;
    animation-duration: 0s !important;
    caret-color: transparent !important;
    scroll-behavior: auto !important;
    transition-delay: 0s !important;
    transition-duration: 0s !important;
  }

  [data-testid="server-url-input"],
  [data-testid="login-server-url"],
  [data-testid="settings-server-url-input"],
  [data-testid="sync-cursor"],
  [data-testid="mobile-sync-cursor"],
  [data-testid="event-fact"],
  [data-testid="revision-entry"],
  [data-testid="space-metadata"] > .event-head span:last-child,
  [data-testid="principal-context"] .id {
    color: transparent !important;
    text-shadow: none !important;
  }

  [data-testid="timeline-event"] > .event-head span:last-child {
    color: transparent !important;
    text-shadow: none !important;
  }
`;

export async function stabilizeVisualBaseline(page: Page) {
  await page.addStyleTag({ content: VISUAL_BASELINE_CSS });
}

export async function visualBaselineShot(
  page: Page,
  testInfo: TestInfo,
  name: string,
  target?: Locator,
) {
  await stabilizeVisualBaseline(page);
  const dir = path.join(visualBaselineRoot(), sanitize(testInfo.titlePath.slice(1, -1).join("-")));
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${sanitize(name)}.png`);
  const buffer = target
    ? await target.screenshot({ path: file, animations: "disabled", caret: "hide" })
    : await page.screenshot({ path: file, fullPage: true, animations: "disabled", caret: "hide" });
  const dimensions = pngDimensions(buffer);
  const manifestEntry = {
    name,
    file,
    width: dimensions.width,
    height: dimensions.height,
    sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
  };
  fs.appendFileSync(path.join(visualBaselineRoot(), "manifest.jsonl"), `${JSON.stringify(manifestEntry)}\n`, "utf8");
  await testInfo.attach(`visual-baseline:${name}`, { path: file, contentType: "image/png" });
  return file;
}

function pngDimensions(buffer: Buffer): { width: number; height: number } {
  if (buffer.length < 24 || buffer.toString("ascii", 1, 4) !== "PNG") {
    return { width: 0, height: 0 };
  }
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

function sanitize(value: string): string {
  const cleaned = value
    .trim()
    .replace(/[^a-zA-Z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "visual-baseline";
}
