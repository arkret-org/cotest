// Probe: does yougen's RealmAdminPanel see active_section correctly when
// the URL is /realms/<id>/settings/<section> on a fresh navigation?

import { expect, test } from "@playwright/test";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import { createRealmApi } from "../../helpers/soland-api";

test.describe("admin section route", () => {
  test("realm-admin-active-section reflects route on fresh nav", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("admin-probe");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });

    try {
      const realmId = await createRealmApi(request, aliceToken, {
        title: `Admin section probe ${stamp}`,
        discoverability: "listed",
        default_join_rule: "invite",
        ownerDid: alice.did,
      });

      // Land directly on the access admin section via hard navigation (no tab
      // click). yougen's RealmAdminSectionPage route is
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
