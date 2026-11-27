import { expect } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";
import { test } from "../../helpers/joint-fixture";
import { selfPathHeadersForDpopSession } from "../../helpers/users";

test("Realm chat opens without a nested scope picker and retired object routes return 404 @fully-implemented", async ({ jointRealm, request }) => {
  await jointRealm.alicePage.gotoTimelineRealm(jointRealm.realmId);
  const page = jointRealm.alicePage.page;
  await expect(page.locator(".circle-scope-picker")).toHaveCount(0);
  await expect(page.locator('a[href*="/circles"]')).toHaveCount(0);
  for (const path of ["/_arkret/self/circles", "/_arkret/self/agent-sidecar-threads:ensure"]) {
    const url = `${colandBaseUrl()}${path}`;
    const response = await request.post(url, {
      headers: selfPathHeadersForDpopSession(jointRealm.aliceSession, "POST", url),
      data: {},
    });
    expect(response.status()).toBe(404);
  }
});
