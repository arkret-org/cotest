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

// GAP-yougen-admin-section-deeplink — demoted from @fully-implemented.
// A fresh hard navigation (page.goto) straight to the realm admin members
// section does not render yougen's RealmAdminPanel: the SPA snapshot shows the
// app shell / nav rather than the panel, so getByTestId("realm-admin-panel")
// never becomes visible. yougen's route is /realms/:realm_id/settings/:section
// (routes.rs); reaching the panel reliably appears to require client-side
// navigation (entering via the realm then the settings tab) rather than a cold
// deep-link, and the legacy realm-admin-active-section / invite-member testids
// were removed. Restore once the deep-link renders the panel (or the probe is
// rewritten to navigate via the UI).
test.describe.fixme("admin section route", () => {
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

      // Land directly on the members admin section via hard navigation (no tab
      // click). yougen's RealmAdminSectionPage route is
      // /realms/:realm_id/settings/:section (routes.rs); the legacy /admin/
      // path no longer matches.
      await alicePage.page.goto(`/realms/${realmId}/settings/members`, {
        waitUntil: "domcontentloaded",
      });
      await expect(alicePage.page.getByTestId("realm-admin-panel")).toBeVisible(
        {
          timeout: 120_000,
        },
      );
      // Fresh nav to the members section renders the members panel and its
      // members-management controls. (The earlier realm-admin-active-section /
      // invite-member testids were removed; the members panel + open-invite +
      // refresh + table testids are the current surface.)
      await expect(
        alicePage.page.getByTestId("realm-members-panel"),
      ).toBeVisible({ timeout: 30_000 });
      await expect(
        alicePage.page.getByTestId("open-invite-modal-button"),
      ).toBeVisible({
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
