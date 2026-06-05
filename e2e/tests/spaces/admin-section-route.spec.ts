// Probe: does yougen's RealmAdminPanel see active_section correctly when
// the URL is /realms/<id>/admin/<section> on a fresh navigation? Helps
// diagnose why invite-member and refresh-members-button never render.

import { expect, test } from "@playwright/test";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe("admin section route @fully-implemented", () => {
  test("realm-admin-active-section reflects route on fresh nav", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("admin-probe");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, {
      sessionToken: aliceToken,
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `Admin section probe ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // Land directly on /admin/members via hard navigation (no tab click).
      await alicePage.page.goto(`/realms/${realmId}/admin/members`, {
        waitUntil: "domcontentloaded",
      });
      await expect(alicePage.page.getByTestId("realm-admin-panel")).toBeVisible(
        {
          timeout: 120_000,
        },
      );
      const sectionLabel = alicePage.page.getByTestId(
        "realm-admin-active-section",
      );
      await expect(sectionLabel).toBeVisible({ timeout: 30_000 });
      const text = (await sectionLabel.textContent())?.trim();
      console.log(`active_section text = ${JSON.stringify(text)}`);
      expect(text).toBe("Members");
      await expect(alicePage.page.getByTestId("invite-member")).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        alicePage.page.getByTestId("refresh-members-button"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await expect(alicePage.page.getByTestId("member-table")).toBeVisible({
        timeout: 30_000,
      });
    } finally {
      await alicePage.close();
    }
  });
});
