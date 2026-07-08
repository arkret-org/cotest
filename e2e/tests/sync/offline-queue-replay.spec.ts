// Offline queue replay
// Contract: e2e/scenarios/sync/offline-queue-replay.md

import { expect, test, type APIRequestContext } from "@playwright/test";

import {
  createSharedRealmViaApi,
  listRealmEventsViaApi,
} from "../../helpers/api";
import {
  assertJointStackNotRequired,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  type JointUser,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("offline queue replay", () => {
  test("offline compose is queued locally and flushed after reconnect", async ({
    browser,
    request,
  }) => {
    const fixture = await createOfflineFixture(browser, request, "queue-replay");
    if (!fixture) {
      assertJointStackNotRequired("offline queue browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    try {
      await fixture.bobPage.page.context().setOffline(true);
      const body = `offline queued replay ${Date.now()}`;
      await composeMessage(fixture.bobPage, body);
      const row = fixture.bobPage.timelineEvent(body);
      await expect(row.getByTestId("message-send-status")).toHaveAttribute(
        "data-send-state",
        "queued_offline",
        { timeout: 30_000 },
      );
      await expect(fixture.bobPage.page.getByTestId("chat-outbox-banner")).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        fixture.bobPage.page.getByTestId("chat-outbox-count"),
      ).toContainText("1", { timeout: 30_000 });

      let serialized = JSON.stringify(
        await listRealmEventsViaApi(request, fixture.aliceToken, fixture.realmId),
      );
      expect(serialized).not.toContain(body);

      await fixture.bobPage.page.context().setOffline(false);
      await fixture.bobPage.gotoTimelineRealm(fixture.realmId);
      await fixture.bobPage.waitForTimelineEventSettled(body, 60_000);
      await expect(fixture.bobPage.page.getByTestId("chat-outbox-banner")).toHaveCount(0, {
        timeout: 60_000,
      });
      serialized = JSON.stringify(
        await listRealmEventsViaApi(request, fixture.aliceToken, fixture.realmId),
      );
      expect(serialized).toContain(body);
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
): Promise<OfflineFixture | undefined> {
  const stamp = Date.now();
  const [aliceFlow, bobFlow] = await Promise.all([
    openDpopUserPage(browser, request, `offline-${label}-alice-${stamp}`, {
      prepareMlsDevice: false,
    }),
    openDpopUserPage(browser, request, `offline-${label}-bob-${stamp}`, {
      prepareMlsDevice: false,
    }),
  ]);
  if (!aliceFlow || !bobFlow) {
    await Promise.allSettled([aliceFlow?.page.close(), bobFlow?.page.close()]);
    return undefined;
  }
  const alice = aliceFlow.user;
  const bob = bobFlow.user;
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
  const alicePage = aliceFlow.page;
  const bobPage = bobFlow.page;
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
