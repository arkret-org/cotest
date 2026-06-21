// Offline queue replay
// Contract: e2e/scenarios/sync/offline-queue-replay.md

import { expect, test, type APIRequestContext } from "@playwright/test";

import {
  createSharedRealmViaApi,
  listRealmEventsViaApi,
} from "../../helpers/api";
import { signedEventEnvelope, submitSignedEventApi } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
  type JointUser,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("offline queue replay", () => {
  test("offline compose shows a pending timeline badge", async ({ browser, request }) => {
    const fixture = await createOfflineFixture(browser, request, "pending-badge");
    try {
      await fixture.bobPage.page.context().setOffline(true);
      const body = `offline pending badge ${Date.now()}`;
      await composeMessage(fixture.bobPage, body);
      await expect(fixture.bobPage.timelineEvent(body)).toContainText("(pending)");
      await expect(fixture.bobPage.page.getByTestId("write-status")).toContainText(/pending sync/);
    } finally {
      await fixture.bobPage.page.context().setOffline(false).catch(() => undefined);
      await closeFixture(fixture);
    }
  });

  test("offline queued message auto-flushes when the browser comes back online", async ({
    browser,
    request,
  }) => {
    const fixture = await createOfflineFixture(browser, request, "single-flush");
    try {
      const body = `offline auto flush ${Date.now()}`;
      await fixture.bobPage.page.context().setOffline(true);
      await composeMessage(fixture.bobPage, body);
      await fixture.bobPage.page.context().setOffline(false);

      await expect(fixture.bobPage.timelineEvent(body)).not.toContainText("(pending)", {
        timeout: 30_000,
      });
      await expectServerEventsContain(request, fixture.aliceToken, fixture.realmId, [body]);
    } finally {
      await fixture.bobPage.page.context().setOffline(false).catch(() => undefined);
      await closeFixture(fixture);
    }
  });

  test("three offline messages flush and leave no pending markers", async ({ browser, request }) => {
    const fixture = await createOfflineFixture(browser, request, "multi-flush");
    try {
      const bodies = [0, 1, 2].map((idx) => `offline multi ${idx} ${Date.now()}`);
      await fixture.bobPage.page.context().setOffline(true);
      for (const body of bodies) {
        await composeMessage(fixture.bobPage, body);
        await expect(fixture.bobPage.timelineEvent(body)).toContainText("(pending)");
      }
      await fixture.bobPage.page.context().setOffline(false);

      await expectServerEventsContain(request, fixture.aliceToken, fixture.realmId, bodies);
      await expect
        .poll(async () => (await fixture.bobPage.page.getByTestId("timeline").innerText()).includes("(pending)"), {
          timeout: 30_000,
        })
        .toBe(false);
    } finally {
      await fixture.bobPage.page.context().setOffline(false).catch(() => undefined);
      await closeFixture(fixture);
    }
  });

  test("queued offline message is discarded when Bob is banned before reconnect", async ({
    browser,
    request,
  }) => {
    const fixture = await createOfflineFixture(browser, request, "ban-discard");
    try {
      const body = `offline banned discard ${Date.now()}`;
      await fixture.bobPage.page.context().setOffline(true);
      await composeMessage(fixture.bobPage, body);
      await banMember(request, fixture);
      await fixture.bobPage.page.context().setOffline(false);

      await expect(fixture.bobPage.page.getByTestId("write-status")).toContainText(
        /discarded pending change/,
        { timeout: 30_000 },
      );
      await expect(fixture.bobPage.timelineEvent(body)).not.toContainText("(pending)");
    } finally {
      await fixture.bobPage.page.context().setOffline(false).catch(() => undefined);
      await closeFixture(fixture);
    }
  });

  test("discarded offline message is not written to soland", async ({ browser, request }) => {
    const fixture = await createOfflineFixture(browser, request, "ban-not-written");
    try {
      const body = `offline banned not written ${Date.now()}`;
      await fixture.bobPage.page.context().setOffline(true);
      await composeMessage(fixture.bobPage, body);
      await banMember(request, fixture);
      await fixture.bobPage.page.context().setOffline(false);

      await expect(fixture.bobPage.page.getByTestId("write-status")).toContainText(
        /discarded pending change/,
        { timeout: 30_000 },
      );
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
  await userPage.page.getByTestId("composer-input").fill(body);
  await userPage.page.getByTestId("send-button").click();
  await expect(userPage.timelineEvent(body)).toBeVisible({ timeout: 30_000 });
}

async function expectServerEventsContain(
  request: APIRequestContext,
  token: string,
  realmId: string,
  bodies: string[],
) {
  await expect
    .poll(async () => JSON.stringify(await listRealmEventsViaApi(request, token, realmId)), {
      timeout: 30_000,
    })
    .toContain(bodies[bodies.length - 1]);
  const serialized = JSON.stringify(await listRealmEventsViaApi(request, token, realmId));
  for (const body of bodies) {
    expect(serialized).toContain(body);
  }
}

async function banMember(request: APIRequestContext, fixture: OfflineFixture) {
  await submitSignedEventApi(
    request,
    fixture.aliceToken,
    signedEventEnvelope({
      actorDid: fixture.alice.did,
      realmId: fixture.realmId,
      kind: "ck.member.state",
      payload: {
        realm_id: fixture.realmId,
        actor_id: fixture.bob.did,
        membership: "ban",
        reason: "offline_queue_discard_test",
      },
    }),
    { context: `ban ${fixture.bob.did} during offline queue test` },
  );
}

async function closeFixture(fixture: OfflineFixture) {
  await Promise.allSettled([fixture.bobPage.close(), fixture.alicePage.close()]);
}
