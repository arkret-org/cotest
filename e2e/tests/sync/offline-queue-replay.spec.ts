// Offline write fail-fast
// Contract: e2e/scenarios/sync/offline-queue-replay.md

import { expect, test, type APIRequestContext } from "@playwright/test";

import {
  createSharedRealmViaApi,
  listRealmEventsViaApi,
} from "../../helpers/api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
  type JointUser,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("offline write fail-fast", () => {
  test("offline compose is marked failed locally and is not written to soland", async ({
    browser,
    request,
  }) => {
    const fixture = await createOfflineFixture(browser, request, "fail-fast");
    try {
      await fixture.bobPage.page.context().setOffline(true);
      const body = `offline fail fast ${Date.now()}`;
      await composeMessage(fixture.bobPage, body);
      const row = fixture.bobPage.timelineEvent(body);
      await expect(row).toHaveClass(/is-failed/);
      await expect(row).not.toContainText("(pending)");
      await expect(row.getByTestId("chat-message-error")).toContainText(/error sending request/i);

      await fixture.bobPage.page.context().setOffline(false);
      const serialized = JSON.stringify(
        await listRealmEventsViaApi(request, fixture.aliceToken, fixture.realmId),
      );
      expect(serialized).not.toContain(body);
    } finally {
      await fixture.bobPage.page.context().setOffline(false).catch(() => undefined);
      await closeFixture(fixture);
    }
  });
});

type OfflineFixture = {
  alice: JointUser;
  bob: JointUser;
  aliceToken: string;
  bobToken: string;
  alicePage: JointUserPage;
  bobPage: JointUserPage;
  realmId: string;
};

async function createOfflineFixture(
  browser: Parameters<typeof openUserPage>[0],
  request: APIRequestContext,
  label: string,
): Promise<OfflineFixture> {
  const stamp = Date.now();
  const alice = uniqueUser(`offline-${label}-alice`);
  const bob = uniqueUser(`offline-${label}-bob`);
  await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
  const [aliceToken, bobToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
  ]);
  const realmId = await createSharedRealmViaApi(
    request,
    alice,
    aliceToken,
    bob,
    bobToken,
    {
      title: `offline queue ${label} ${stamp}`,
      historyVisibility: "shared",
    },
  );
  const [alicePage, bobPage] = await Promise.all([
    openUserPage(browser, alice, { sessionCredential: aliceToken }),
    openUserPage(browser, bob, { sessionCredential: bobToken }),
  ]);
  await Promise.all([alicePage.gotoTimelineRealm(realmId), bobPage.gotoTimelineRealm(realmId)]);
  return { alice, bob, aliceToken, bobToken, alicePage, bobPage, realmId };
}

async function composeMessage(userPage: JointUserPage, body: string) {
  await userPage.page.getByTestId("chat-input").fill(body);
  await userPage.page.getByTestId("send-chat-button").click();
  await expect(userPage.timelineEvent(body)).toBeVisible({ timeout: 30_000 });
}

async function closeFixture(fixture: OfflineFixture) {
  await Promise.allSettled([fixture.bobPage.close(), fixture.alicePage.close()]);
}
