// Offline edit / reconnect sync / conflict repair (bottom_cells)
// Contract: e2e/scenarios/sync/offline-conflict.md
// Spec: sync/client-sync.md §2, sync/operations-sync.md §2-§2.1, authz/event-auth-state-resolution.md §2, §8.1

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("offline sync + conflict repair", () => {
  test("bob composes a message while offline; on reconnect the message persists and is visible to alice", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s26-alice");
    const bob = uniqueUser("s26-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S26 Offline ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(spaceId);

      const offlineMsg = `S26 from offline ${stamp}`;

      // bob goes offline, composes, then reconnects.
      await bobPage.gotoTimelineSpace(spaceId);
      await bobPage.page.context().setOffline(true);
      await bobPage.page.getByTestId("composer-input").fill(offlineMsg);
      await bobPage.page.getByTestId("send-button").click();
      await stepShot(bobPage.page, testInfo, "B-offline-composed");

      await bobPage.page.context().setOffline(false);
      // Yougen's outbox flush may take a moment; tolerate up to 30s.
      await expect(bobPage.timelineEvent(offlineMsg)).toBeVisible({ timeout: 30_000 });
      await alicePage.gotoTimelineSpace(spaceId);
      await expect(alicePage.timelineEvent(offlineMsg)).toBeVisible({ timeout: 30_000 });
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test.fixme(
    "during offline window alice writes; on bob's reconnect both writes are visible with deterministic ordering",
    async () => {
      // spec: sync/operations-sync.md §2
    },
  );

  test.fixme(
    "concurrent writes to the same cas-register cell trigger bottom_expose; bottom-cells-banner shows the conflict",
    async () => {
      // spec: sync/operations-sync.md §2.1 + authz/event-auth-state-resolution.md §2
    },
  );

  test.fixme(
    "bob clicks prefer-safer-side-button to repair; reducer accepts repair Move with state_witness + inclusion_proof; banner clears",
    async () => {
      // spec: authz/event-auth-state-resolution.md §8.1
    },
  );

  test.fixme(
    "long offline → on reconnect, pull-operations backfills missing events; bob's timeline catches up to head",
    async () => {
      // spec: sync/federation.md §4.2 (single-server uses same pull endpoint)
    },
  );
});
