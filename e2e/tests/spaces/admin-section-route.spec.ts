// Probe: does inkson's RealmAdminPanel see active_section correctly when
// the URL is /realms/<id>/settings/<section> on a fresh navigation?

import { expect, test } from "@playwright/test";
import { openDpopUserPage } from "../../helpers/users";

test.describe("admin section route", () => {
  test("realm-admin-active-section reflects route on fresh nav", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    // inkson intentionally discards token-only sessions after secure-store
    // bootstrap (secure_store_effects.rs), so the old dev-bearer injection
    // bounces back to Sign in. The supported UI entry is the full grant+DPoP
    // session injection used by every other UI flow.
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `admin-probe-${stamp}`,
    );
    expect(aliceFlow, "DPoP session provisioning").toBeTruthy();
    const alicePage = aliceFlow!.page;

    try {
      const realmId = await alicePage.createRealm({
        title: `Admin section probe ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
      });

      // Land directly on the access admin section via hard navigation (no tab
      // click). inkson's RealmAdminSectionPage route is
      // /realms/:realm_id/settings/:section (routes.rs); `access` is a current
      // RealmAdminSection slug.
      await alicePage.page.goto(`/realms/${realmId}/settings/access`, {
        waitUntil: "domcontentloaded",
      });
      await expect(alicePage.page.getByTestId("realm-admin-panel")).toBeVisible(
        {
          timeout: 120_000,
        },
      );
      // Fresh nav to the access section marks that section active. Members
      // management is now a sibling route (`/realms/:id/members`), not a
      // RealmAdminSection slug.
      await expect(
        alicePage.page.getByTestId("realm-admin-nav-item-access"),
      ).toHaveAttribute("aria-current", "page");
    } finally {
      await alicePage.close();
    }
  });
});
