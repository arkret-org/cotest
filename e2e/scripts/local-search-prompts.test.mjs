import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "@playwright/test";
import { postponeSearchEncryptionPrompts } from "../helpers/local-search.ts";

test("optional search reminders leave foreground security controls untouched", async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.setContent(`<style>
      [role=dialog] { position:fixed; inset:0; background:white; }
      #security { z-index:2; }
    </style><div role="dialog" aria-label="Restore encryption keys" id="reminder">
      <button onclick="window.dismissed++; this.parentElement.remove()">Not now</button>
    </div><div role="dialog" aria-label="Authorize device" id="security">Foreground security workflow</div>
    <script>window.dismissed = 0;</script>`);
    const postpone = await postponeSearchEncryptionPrompts(page);
    assert.equal(await page.evaluate(() => window.dismissed), 0);
    await page.getByRole("dialog", { name: "Authorize device", exact: true }).isVisible().then(assert.ok);
    await page.evaluate(() => document.querySelector("#security").remove());
    await postpone();
    assert.equal(await page.evaluate(() => window.dismissed), 1);
    assert.equal(await page.getByRole("dialog", { name: "Restore encryption keys", exact: true }).count(), 0);
  } finally { await browser.close(); }
});

test("closing the owned page settles an in-flight optional reminder without an unhandled error", async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.setContent(`<div role="dialog" aria-label="Restore encryption keys">
      <button onclick="window.dismissalObserved = true">Not now</button>
    </div>`);
    const pending = postponeSearchEncryptionPrompts(page);
    void pending.catch(() => {});
    await page.waitForFunction(() => window.dismissalObserved === true);
    await page.close();
    await assert.doesNotReject(pending);
  } finally { await browser.close(); }
});
