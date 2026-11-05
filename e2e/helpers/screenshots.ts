import fs from "node:fs";
import path from "node:path";
import type { Page, TestInfo } from "@playwright/test";
import { screenshotRoot } from "./env";

// Keep private security UI out of the retained artifact boundary. Capture to
// memory first; a privacy transition during rasterization taints the result.
export async function publicScreenshot(page: Page, options: Parameters<Page["screenshot"]>[0] = {}) {
  const observation = await page.evaluateHandle(() => {
    const visible = (element: Element) => element.getClientRects().length > 0
      && getComputedStyle(element).visibility !== "hidden";
    const privateUi = () => {
      if (Array.from(document.querySelectorAll(
        '.rk-word, .recovery-key-confirm-form, [class*="recovery"][class*="word"], [class*="mnemonic"], '
        + 'textarea[aria-label*="recovery key" i], input[aria-label*="private key" i]',
      )).some(visible)) return true;
      if (Array.from(document.querySelectorAll<HTMLInputElement>('input[autocomplete="one-time-code"]'))
        .some(element => visible(element) && element.value.length > 0)) return true;
      return Array.from(document.querySelectorAll('[role="dialog"]')).some(dialog => {
        if (!visible(dialog)) return false;
        const labelled = (dialog.getAttribute("aria-labelledby") ?? "").split(/\s+/)
          .map(id => document.getElementById(id)?.textContent ?? "").join(" ");
        const heading = dialog.querySelector('h1,h2,h3,[role="heading"]')?.textContent ?? "";
        return /recovery|encryption keys|private key|secret key/i
          .test(`${dialog.getAttribute("aria-label") ?? ""} ${labelled} ${heading}`);
      });
    };
    let tainted = privateUi();
    const observer = new MutationObserver(() => { tainted ||= privateUi(); });
    observer.observe(document, { childList: true, subtree: true, attributes: true });
    return { check: () => { tainted ||= privateUi(); return tainted; },
      dispose: () => observer.disconnect() };
  });
  try {
    if (await observation.evaluate(value => value.check())) {
      throw new Error("Screenshot blocked while private security UI is visible");
    }
    const { path: destination, ...capture } = options;
    if (!capture.type && destination) capture.type = /\.jpe?g$/i.test(destination) ? "jpeg" : "png";
    const bytes = await page.screenshot(capture);
    if (await observation.evaluate(value => value.check())) {
      throw new Error("Screenshot discarded after a private security UI transition");
    }
    if (destination) {
      await fs.promises.mkdir(path.dirname(destination), { recursive: true });
      await fs.promises.writeFile(destination, bytes);
    }
    return bytes;
  } finally {
    await observation.evaluate(value => value.dispose()).catch(() => {});
    await observation.dispose().catch(() => {});
  }
}

export async function stepShot(page: Page, testInfo: TestInfo, name: string) {
  const dir = path.join(screenshotRoot(), sanitize(testInfo.titlePath.slice(1, -1).join("-")));
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${sanitize(name)}.png`);
  await publicScreenshot(page, { path: file, fullPage: true });
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
