import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "@playwright/test";
import { readTextLineLayout } from "../helpers/text-layout.ts";

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
