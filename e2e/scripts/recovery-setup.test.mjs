import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { chromium } from "@playwright/test";
import { completeRecoverySetup, finishRecoverySetupBeforeClose, installRecoverySetupHandler } from "../helpers/recovery-setup.ts";

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });

const key = Array(24).fill("fixture").join(" ");

async function prompt(page, retryFirst = false, publicationDelayMs = 0) {
  page.setDefaultTimeout(10_000);
  await page.setContent(`
    <div data-testid="recovery-key-setup-banner">
      <textarea data-testid="recovery-key-setup-generated-key" readonly>${key}</textarea>
      <textarea data-testid="recovery-key-setup-confirm-key"></textarea>
      <button data-testid="recovery-key-setup-saved">Save</button>
    </div>
    <button data-testid="outside">Continue</button>
    <script>
      (() => {
      window.saves = 0;
      window.confirmations = [];
      const banner = document.querySelector('[data-testid="recovery-key-setup-banner"]');
      const save = document.querySelector('[data-testid="recovery-key-setup-saved"]');
      save.onclick = () => {
        window.saves++;
        window.confirmations.push(document.querySelector('[data-testid="recovery-key-setup-confirm-key"]').value);
        save.disabled = true;
        if (${retryFirst} && window.saves === 1) {
          setTimeout(() => { save.disabled = false; }, 20);
        } else {
          if (${publicationDelayMs} > 0) {
            setTimeout(() => { banner.style.display = 'none'; }, ${publicationDelayMs});
          } else {
            banner.style.display = 'none';
          }
        }
      };
      })();
    </script>`);
}

function observeHandlers(page) {
  let calls = 0;
  const add = page.addLocatorHandler.bind(page);
  page.addLocatorHandler = async (locator, callback, options) => add(locator, async (target) => {
    calls++;
    return callback(target);
  }, options);
  return () => calls;
}

test("publication retry cannot re-enter its own Recovery Key handler", async () => {
  const page = await browser.newPage();
  try {
    await prompt(page, true);
    const calls = observeHandlers(page);
    let completed = 0;
    await installRecoverySetupHandler(page, () => { completed++; });
    await page.getByTestId("outside").click({ timeout: 20_000 });
    await completeRecoverySetup(page, key);
    assert.equal(calls(), 1, "the sole completion writer must not trigger its own handler");
    assert.equal(completed, 1);
    assert.deepEqual(await page.evaluate(() => window.confirmations), [key, key]);
    assert.equal(await page.getByTestId("recovery-key-setup-banner").isHidden(), true);
  } finally { await page.close(); }
});

test("completion remains single-flight and the handler re-arms for a later prompt", async () => {
  const page = await browser.newPage();
  try {
    await prompt(page);
    let completed = 0;
    await installRecoverySetupHandler(page, () => { completed++; });
    await page.getByTestId("outside").click();
    await completeRecoverySetup(page, key);
    assert.equal(completed, 1);
    await prompt(page);
    await page.getByTestId("outside").click();
    await completeRecoverySetup(page, key);
    assert.equal(completed, 2);
    assert.equal(await page.evaluate(() => window.saves), 1);
  } finally { await page.close(); }
});

test("explicit concurrent callers share one publication and do not await themselves in a handler", async () => {
  const page = await browser.newPage();
  try {
    await prompt(page, true);
    const calls = observeHandlers(page);
    await installRecoverySetupHandler(page);
    const first = completeRecoverySetup(page, key);
    const second = completeRecoverySetup(page, key);
    assert.equal(first, second);
    await first;
    await second;
    assert.equal(calls(), 1);
    assert.deepEqual(await page.evaluate(() => window.confirmations), [key, key]);
  } finally { await page.close(); }
});

test("invalid confirmation source stays failed and cannot publish a replacement silently", async () => {
  const page = await browser.newPage();
  try {
    await prompt(page);
    const invalid = Array(23).fill("fixture").join(" ");
    let failure;
    try { await completeRecoverySetup(page, invalid); } catch (error) { failure = error; }
    assert.ok(failure);
    await assert.rejects(completeRecoverySetup(page, key), (error) => error === failure);
    assert.equal(await page.evaluate(() => window.saves), 0);
  } finally { await page.close(); }
});

test("cleanup drains delayed publication before closing and prevents handler re-arming", async () => {
  const page = await browser.newPage();
  try {
    await prompt(page, false, 8_000);
    let configured = 0;
    let registrations = 0;
    const add = page.addLocatorHandler.bind(page);
    page.addLocatorHandler = async (...args) => { registrations++; return add(...args); };
    await installRecoverySetupHandler(page, () => { configured++; });
    await page.getByTestId("outside").click({ timeout: 20_000 });
    assert.equal(configured, 0, "the short action returns while publication is still active");
    await finishRecoverySetupBeforeClose(page);
    assert.equal(page.isClosed(), false);
    assert.equal(configured, 1);
    assert.equal(await page.getByTestId("recovery-key-setup-banner").isHidden(), true);
    assert.equal(registrations, 1, "cleanup must not install another automatic writer");
  } finally { await page.close(); }
});

test("cleanup preserves a latched recovery failure instead of hiding it", async () => {
  const page = await browser.newPage();
  try {
    await prompt(page);
    const invalid = Array(23).fill("fixture").join(" ");
    let failure;
    try { await completeRecoverySetup(page, invalid); } catch (error) { failure = error; }
    assert.ok(failure);
    await assert.rejects(finishRecoverySetupBeforeClose(page), (error) => error === failure);
    assert.equal(await page.evaluate(() => window.saves), 0);
  } finally { await page.close(); }
});
