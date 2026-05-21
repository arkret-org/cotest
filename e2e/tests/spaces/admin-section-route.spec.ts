// Probe: does yougen's SpaceAdminPanel see active_section correctly when
// the URL is /space/<id>/admin/<section> on a fresh navigation? Helps
// diagnose why invite-member and refresh-members-button never render.

import { expect, test } from "@playwright/test";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe("admin section route @fully-implemented", () => {
  test("space-admin-active-section reflects route on fresh nav", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("admin-probe");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `Admin section probe ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // Land directly on /admin/members via hard navigation (no tab click).
      await alicePage.page.goto(`/space/${spaceId}/admin/members`, {
        waitUntil: "domcontentloaded",
      });
      await expect(alicePage.page.getByTestId("space-admin-panel")).toBeVisible({
        timeout: 120_000,
      });
      const sectionLabel = alicePage.page.getByTestId("space-admin-active-section");
      await expect(sectionLabel).toBeVisible({ timeout: 30_000 });
      const text = (await sectionLabel.textContent())?.trim();
      console.log(`active_section text = ${JSON.stringify(text)}`);
      expect(text).toBe("Members");
    } finally {
      await alicePage.close();
    }
  });
});
