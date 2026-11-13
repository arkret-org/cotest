import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { chromium } from "@playwright/test";
import { clickCardSave } from "../helpers/card-save.ts";

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });

async function fixture(run) {
  const page = await browser.newPage();
  try {
    await page.setContent('<form class="card-detail-edit-form"><button type="button" class="card-detail-save-button">Save</button></form>');
    await page.evaluate(() => {
      window.activations = 0;
      document.querySelector("button").addEventListener("click", () => { window.activations++; });
    });
    await run(page, page.locator("form"));
  } finally { await page.close(); }
}

test("control: a single click can lose its activation when readiness changes at pointerdown", async () => {
  await fixture(async (page, form) => {
    await page.evaluate(() => {
      document.querySelector("button").addEventListener("pointerdown", event => {
        event.currentTarget.disabled = true;
        setTimeout(() => { document.querySelector("button").disabled = false; }, 150);
      }, { once: true });
    });
    await form.locator("button").click();
    assert.equal(await page.evaluate(() => window.activations), 0);
  });
});

test("a disabled pointer handoff retries the same editor to exactly one trusted click", async () => {
  await fixture(async (page, form) => {
    await page.evaluate(() => {
      document.querySelector("button").addEventListener("pointerdown", event => {
        event.currentTarget.disabled = true;
        setTimeout(() => { document.querySelector("button").disabled = false; }, 150);
      }, { once: true });
    });
    await clickCardSave(form, 3_000);
    assert.equal(await page.evaluate(() => window.activations), 1);
  });
});

test("an activated slow operation is never clicked again", async () => {
  await fixture(async (page, form) => {
    await page.evaluate(() => {
      document.querySelector("button").onclick = () => {
        setTimeout(() => { document.querySelector("form").remove(); }, 400);
      };
    });
    await clickCardSave(form, 3_000);
    await page.waitForTimeout(500);
    assert.equal(await page.evaluate(() => window.activations), 1);
  });
});

test("continuous denial remains a failure with no activation", async () => {
  await fixture(async (page, form) => {
    await form.locator("button").evaluate(button => { button.disabled = true; });
    await assert.rejects(clickCardSave(form, 300));
    assert.equal(await page.evaluate(() => window.activations), 0);
  });
});

test("a replacement editor never receives the previous editor's Save", async () => {
  await fixture(async (page, form) => {
    await page.evaluate(() => {
      document.querySelector("button").onpointerdown = event => {
        event.currentTarget.disabled = true;
        const replacement = document.createElement("form");
        replacement.className = "card-detail-edit-form";
        replacement.innerHTML = '<button type="button" class="card-detail-save-button">Save</button>';
        replacement.querySelector("button").onclick = () => { window.activations++; };
        document.querySelector("form").replaceWith(replacement);
      };
    });
    await assert.rejects(clickCardSave(form, 3_000), /editor retired/);
    assert.equal(await page.evaluate(() => window.activations), 0);
  });
});
