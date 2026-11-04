import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium, expect } from "@playwright/test";
import { filterCardAssignee } from "../helpers/kanban-product-ui.ts";

test("member filtering survives replacement of the input without selecting or saving an assignment", async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.setContent(`<section class="card-detail-modal"></section><script>
window.replaced = false; window.selections = 0; window.submissions = 0;
function mount() {
  const host = document.querySelector('section');
  host.innerHTML = '<input aria-label="Filter members"><div class="options"></div><button class="save">Save</button>';
  const render = query => {
    host.querySelector('.options').innerHTML = ['alice', 'bob', 'carol'].filter(actor => actor.includes(query)).map(actor => '<button class="assignee-picker-option" aria-pressed="false">' + actor + '</button>').join('');
    host.querySelectorAll('.assignee-picker-option').forEach(button => button.onclick = () => window.selections++);
  };
  render('');
  host.querySelector('.save').onclick = () => window.submissions++;
  host.querySelector('input').oninput = event => {
    if (!window.replaced) { window.replaced = true; mount(); return; }
    render(event.target.value);
  };
}
mount();
</script>`);
    await page.getByRole("textbox", { name: "Filter members", exact: true }).fill("bob");
    await assert.rejects(expect(page.locator(".assignee-picker-option")).toHaveCount(1, { timeout: 200 }));
    assert.equal(await page.evaluate(() => window.replaced), true);
    const option = await filterCardAssignee(page, "bob");
    await expect(option).toHaveText("bob");
    await expect(option).toHaveAttribute("aria-pressed", "false");
    assert.deepEqual(await page.evaluate(() => [window.selections, window.submissions]), [0, 0]);
  } finally { await browser.close(); }
});
