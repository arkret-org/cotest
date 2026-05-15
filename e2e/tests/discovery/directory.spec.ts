// Discovery (directory search / contacts / profile / presence / organization)
// Contract: e2e/scenarios/discovery/directory.md
// Spec: discovery/discovery-directory.md, discovery/profiles-presence.md, identity/identity-handles.md

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("discovery", () => {
  test("alice and bob complete the contact request → accept → list → directory-visible flow", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s24-alice-${stamp}`);
    const bob = uniqueUser(`s24-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

    try {
      // Pre-contact: directory search for bob from alice returns empty.
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-actors").click();
      await alicePage.page.getByTestId("directory-search-input").fill(bob.handle);
      await alicePage.page.getByTestId("directory-search-button").click();
      await expect(alicePage.page.getByTestId("directory-panel")).toContainText(/No actors found/, {
        timeout: 30_000,
      });

      // alice requests contact via directory contact tools.
      const aliceContact = alicePage.page.getByTestId("directory-contact-tools");
      await aliceContact.getByTestId("contact-target-did-input").fill(bob.did);
      await aliceContact.getByTestId("request-contact-button").click();
      await expect(aliceContact).toContainText(/pending/, { timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "contact-pending");

      // bob accepts via directory contact tools.
      await bobPage.gotoDirectory();
      const bobContact = bobPage.page.getByTestId("directory-contact-tools");
      await bobContact.getByTestId("contact-requester-did-input").fill(alice.did);
      await bobContact.getByTestId("accept-contact-button").click();
      await expect(bobContact).toContainText(/accepted/, { timeout: 30_000 });

      // bob lists; alice should appear with count 1.
      await bobContact.getByTestId("list-contacts-button").click();
      await expect(bobContact).toContainText(alice.did);
      await expect(bobContact).toContainText(/contacts 1/);

      // Post-contact: alice's directory search now sees bob.
      await alicePage.gotoDirectory();
      await alicePage.page.getByTestId("tab-actors").click();
      await alicePage.page.getByTestId("directory-search-input").fill(bob.handle);
      await alicePage.page.getByTestId("directory-search-button").click();
      await expect(alicePage.page.getByTestId("actor-result")).toContainText(bob.did, {
        timeout: 30_000,
      });
      await stepShot(alicePage.page, testInfo, "post-contact-visible");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test.fixme(
    "bob updates profile (display_name/bio/avatar); alice sees the change in directory results within 30s",
    async () => {
      // spec: profiles-presence.md §2
    },
  );

  test.fixme(
    "presence: bob closes tab → alice's directory shows presence-offline; bob reopens → presence-online within 5s",
    async () => {
      // spec: profiles-presence.md §3
    },
  );

  test.fixme(
    "E24.2 reject contact: alice's request rejected by bob → status=rejected; alice cannot re-request until cooldown",
    async () => {},
  );

  test.fixme(
    "organization search: tab-organizations returns the Acme org and its member count",
    async () => {
      // spec: discovery-directory.md §2
    },
  );
});
