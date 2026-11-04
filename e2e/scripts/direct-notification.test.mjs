import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { chromium } from "@playwright/test";
import { openDirectChatNotification } from "../helpers/direct-notification.ts";

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
const realm = "ak:realm:notification-fixture";
const chat = "ak:strand:notification-fixture";

async function fixture(page, wrongRoute = false) {
  await page.route("https://notification-fixture.invalid/**", route => route.fulfill({
    contentType: "text/html", body: `<button class="topbar-notifications-link" style="display:none">Mobile notifications</button>
<button id="open" class="topbar-notifications-link">Notifications</button>
<section class="notifications-drawer-panel" hidden><button id="close">Close</button>
<div class="notification-item" aria-label="another-Realm"><button class="notification-open-chat" id="decoy">Open chat</button></div>
<div class="notification-item" aria-label="${realm}"><button class="notification-open-chat" id="target">Open chat</button></div></section>
<div class="direct-structure"><select aria-label="Chat"><option value="main">Main</option><option value="${chat}">Actual chat, 1 unread</option></select></div>
<script>
window.closedByUser = 0;
document.getElementById('open').onclick = () => document.querySelector('section').hidden = false;
document.getElementById('decoy').onclick = () => history.pushState(null, '', '/wrong-realm');
document.getElementById('target').onclick = () => {
  document.querySelector('select').value = ${JSON.stringify(chat)};
  document.querySelector('select').selectedOptions[0].textContent = 'Actual chat';
  history.pushState(null, '', ${JSON.stringify(wrongRoute ? '/wrong-route' : `/direct/${realm}/${chat}`)});
};
document.getElementById('close').onclick = () => { window.closedByUser++; document.querySelector('section').remove(); };
</script>` }));
  await page.goto(`https://notification-fixture.invalid/direct/${realm}/main`);
}

test("a nonmodal notification uses the visible button, exact Realm and an explicit Close action", async () => {
  const page = await browser.newPage();
  try {
    await fixture(page);
    await openDirectChatNotification(page, realm, chat);
    assert.equal(await page.evaluate(() => window.closedByUser), 1);
    assert.equal(await page.locator('.notifications-drawer-panel').count(), 0);
    assert.equal(new URL(page.url()).pathname, `/direct/${realm}/${chat}`);
  } finally { await page.close(); }
});


test("a wrong notification route fails before the panel is dismissed", async () => {
  const page = await browser.newPage();
  try {
    await fixture(page, true);
    await assert.rejects(openDirectChatNotification(page, realm, chat));
    assert.equal(await page.evaluate(() => window.closedByUser), 0);
    assert.equal(await page.locator('.notifications-drawer-panel').isVisible(), true);
  } finally { await page.close(); }
});
