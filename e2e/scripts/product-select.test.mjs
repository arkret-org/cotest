import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "@playwright/test";
import { selectProductOptionByLabel } from "../helpers/product-select.ts";

// Harness-only controls exercise mounting and retirement of the public
// Select contract. No protocol result or product state is supplied.
const choice = '<button type="button" class="sapid-select" data-gly-combobox="select" '
  + 'aria-controls="sapid-select-test-listbox-4_root" aria-expanded="false" '
  + 'onclick="openChoice(this)">choose</button>';
const script = [
  "<script>",
  "window.opens = 0; window.changes = 0; window.retired = false;",
  "function openChoice(trigger) {",
  "window.opens++; trigger.setAttribute('aria-expanded', 'true');",
  "document.getElementById('sapid-select-test-listbox-4_root')?.remove();",
  "const panel = document.createElement('div');",
  "panel.id = 'sapid-select-test-listbox-4_root'; panel.setAttribute('role', 'listbox');",
  "const option = document.createElement('button'); option.type = 'button';",
  "option.setAttribute('role', 'option'); option.setAttribute('aria-label', 'allow');",
  "option.textContent = 'allow';",
  "option.onpointerenter = () => {",
  "if (window.retireFirst && !window.retired) {",
  "window.retired = true; panel.hidden = true; trigger.setAttribute('aria-expanded', 'false');",
  "}};",
  "option.onclick = () => {",
  "window.changes++; trigger.textContent = 'allow'; panel.hidden = true;",
  "trigger.setAttribute('aria-expanded', 'false');",
  "};",
  "panel.append(option); document.body.append(panel);",
  "}",
  "</script>",
].join("\n");

async function withPage(run) {
  const browser = await chromium.launch();
  try { await run(await browser.newPage()); }
  finally { await browser.close(); }
}

test("a visible field can mount its controlled Select after the first query", { timeout: 40_000 }, async () => {
  await withPage(async page => {
    await page.setContent('<div id="field">Loading options</div>' + script);
    await page.evaluate(html => {
      setTimeout(() => { document.getElementById("field").innerHTML = html; }, 500);
    }, choice);
    await selectProductOptionByLabel(page.locator("#field"), "allow");
    assert.equal(await page.evaluate(() => window.changes), 1);
  });
});

test("a retired open menu is reacquired before one real option activation", { timeout: 40_000 }, async () => {
  await withPage(async page => {
    await page.setContent('<div id="field">' + choice + "</div>" + script);
    await page.evaluate(() => { window.retireFirst = true; });
    await selectProductOptionByLabel(page.locator("#field"), "allow");
    assert.equal(await page.evaluate(() => window.retired), true);
    assert.equal(await page.evaluate(() => window.opens), 2);
    assert.equal(await page.evaluate(() => window.changes), 1);
  });
});

test("a native Select still changes its actual value once", { timeout: 40_000 }, async () => {
  await withPage(async page => {
    await page.setContent('<select id="field" onchange="window.changes++">'
      + '<option value="deny">deny</option><option value="allow">allow</option>'
      + "</select><script>window.changes = 0;</script>");
    await selectProductOptionByLabel(page.locator("#field"), "allow");
    assert.equal(await page.locator("#field").inputValue(), "allow");
    assert.equal(await page.evaluate(() => window.changes), 1);
  });
});
