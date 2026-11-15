import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "@playwright/test";
import { readTextLineLayout, expectSingleTextLine } from "../helpers/text-layout.ts";

test("text fragments measure a boxless date and still detect actual wrapping", async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.setContent('<style>body { font: 16px Arial; line-height: normal; }'
      + '#wide { width: 600px; } #narrow { width: 60px; } .date { display: contents; }</style>'
      + '<div id="wide"><span class="date">Monday October 5, 2026 09:00</span></div>'
      + '<div id="narrow"><span class="date">Monday October 5, 2026 09:00</span></div>');
    const wide = page.locator("#wide .date");
    assert.equal(await wide.evaluate(element => element.getBoundingClientRect().height), 0);
    const one = await readTextLineLayout(wide);
    assert.ok(one.fragment_count > 0);
    assert.equal(one.line_count, 1);
    const wrapped = await readTextLineLayout(page.locator("#narrow .date"));
    assert.ok(wrapped.line_count > 1);
  } finally { await browser.close(); }
});

test("a live replacement waits for real text but persistent wrapping still fails", async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.setContent('<style>body { font: 16px Arial; } #date { min-height: 20px; width: 600px; }</style><p id="date"></p>');
    const date = page.locator("#date");
    await page.evaluate(() => {
      const replacement = document.createElement("p");
      replacement.id = "date";
      document.querySelector("#date").replaceWith(replacement);
      setTimeout(() => { replacement.textContent = "Monday October 5, 2026 09:00"; }, 250);
    });
    assert.equal((await readTextLineLayout(date)).fragment_count, 0);
    await expectSingleTextLine(date, 2_000);
    await date.evaluate(element => { element.style.width = "60px"; });
    await assert.rejects(expectSingleTextLine(date, 300));
    assert.ok((await readTextLineLayout(date)).line_count > 1);
    await date.evaluate(element => { element.textContent = ""; });
    await assert.rejects(expectSingleTextLine(date, 300));
    await date.evaluate(element => { element.remove(); });
    await assert.rejects(expectSingleTextLine(date, 300));
  } finally { await browser.close(); }
});
