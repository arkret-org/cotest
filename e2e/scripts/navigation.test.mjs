import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { chromium } from "@playwright/test";
import { matchesRealmChatRoute } from "../helpers/navigation.ts";

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });
const realmId = "ak:realm:AffVDA0IfWsC0M6uYkCG_aspV5CY-GQiJ8cdiDZBOTBP";
const origin = "http://navigation.cotest.test";

async function navigationPage() {
  const page = await browser.newPage();
  await page.route(`${origin}/**`, (route) => route.fulfill({ contentType: "text/html", body: "navigation fixture" }));
  return page;
}

test("real browser navigation and router history preserve the same exact Realm", async () => {
  const page = await navigationPage();
  try {
    await page.goto(`${origin}/chat/${encodeURIComponent(realmId)}`);
    const encoded = new URL(page.url());
    assert.notEqual(encoded.pathname, `/chat/${realmId}`, "the old unencoded comparison rejects this valid navigation");
    assert.equal(matchesRealmChatRoute(encoded, realmId), true);
    await page.evaluate((id) => history.replaceState(null, "", `/chat/${id}`), realmId);
    assert.equal(matchesRealmChatRoute(new URL(page.url()), realmId), true);
  } finally { await page.close(); }
});

test("real browser paths cannot substitute another Realm, route or path boundary", async () => {
  const page = await navigationPage();
  try {
    const paths = [
      `/chat/${encodeURIComponent(`${realmId}-other`)}`,
      `/chat/${encodeURIComponent(encodeURIComponent(realmId))}`,
      `/chat/${encodeURIComponent(realmId)}/extra`,
      `/kanban/${encodeURIComponent(realmId)}`,
      `/chat%2F${encodeURIComponent(realmId)}`,
      "/chat/%",
    ];
    for (const path of paths) {
      await page.goto(`${origin}${path}`);
      assert.equal(matchesRealmChatRoute(new URL(page.url()), realmId), false, path);
    }
  } finally { await page.close(); }
});
