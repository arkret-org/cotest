import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "@playwright/test";
import { prepareDirectStructureForm } from "../helpers/direct-structure-form.ts";

test("local form preparation survives a pending chat route replacing the selected controls, without submitting", async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.setContent(`<section class="direct-structure"></section><script>
window.replaced = false; window.submissions = 0;
function mount() {
  const host = document.querySelector('section');
  host.innerHTML = '<select aria-label="Action"><option value="unplace">Unplace</option><option value="delete_topic_target">Delete empty Topic</option></select><button>Save</button>';
  host.querySelector('button').onclick = () => window.submissions++;
  host.querySelector('select').onchange = event => {
    if (!window.replaced) { window.replaced = true; mount(); return; }
    if (event.target.value === 'delete_topic_target' && !host.querySelector('[aria-label="Topic"]')) {
      host.insertAdjacentHTML('beforeend', '<select aria-label="Topic"><option value="">Select Topic</option><option value="actual-topic">Actual Topic</option></select>');
    }
  };
}
mount();
</script>`);
    await prepareDirectStructureForm(page, "delete_topic_target", "actual-topic");
    assert.equal(await page.getByRole("combobox", { name: "Action", exact: true }).inputValue(), "delete_topic_target");
    assert.equal(await page.getByRole("combobox", { name: "Topic", exact: true }).inputValue(), "actual-topic");
    assert.equal(await page.evaluate(() => window.submissions), 0);
  } finally { await browser.close(); }
});
