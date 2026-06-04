// Personal blocklist (client-side/server-assisted filter; distinct from realm ban / quarantine / mute)
// Contract: e2e/scenarios/governance/personal-blocklist.md
// Spec: governance/content-moderation.md §4-§6, discovery/client-preferences.md §2

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, solandServiceDid } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  addSpaceMemberApi,
  accountSubscribeDeltaApi,
  authHeaders,
  createSpaceApi,
  makeOperation,
  putAccountDataViaEventApi,
  pushFederationOperations,
  querySpaceEventsApi,
  sendMessageApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

const BLOCKLIST_DATA_TYPE = "ck.account.blocklist";

type BlocklistEntry = {
  target:
    | string
    | {
        kind?: string;
        did?: string;
        actor?: string;
        id?: string;
      };
  kind?: string;
  mode?: string;
  created_at?: string;
};

test.describe.configure({ mode: "serial" });

test.describe("personal blocklist", () => {
  test("personal-blocklist endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s31-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const auth = { authorization: `Bearer ${token}` };

    const accountData = await request.get(`${solandBaseUrl()}/_cokret/self/account/subscribe?catchup=true`, {
      headers: { ...auth, accept: "application/x-ndjson" },
    });
    expect(accountData.status()).toBe(200);
    expect(await accountData.text()).toContain("delta");

    const hints = await request.get(`${solandBaseUrl()}/_cokret/peer/federation/block-hints`);
    expect(hints.status()).toBeLessThan(500);
  });

  test(
    "alice blocks bob; bob's messages filtered from alice's timeline; unblock restores visibility; federation propagates block",
    async ({ browser, request }, testInfo) => {
      const stamp = Date.now();
      const alice = uniqueUser("s31-alice");
      const bob = uniqueUser("s31-bob");
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
      ]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        const spaceId = await alicePage.createSpace({
          title: `S31 Blocklist ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          historyVisibility: "joined",
          seedMembers: [bob.did],
        });
        await bobPage.acceptInvite(spaceId);

        const m1 = `S31 m1 ${stamp}`;
        await bobPage.sendTimelineMessage(spaceId, m1);
        await alicePage.gotoTimelineSpace(spaceId);
        await expect(alicePage.page.getByTestId("timeline")).toContainText(m1, {
          timeout: 30_000,
        });

        await alicePage.page.goto("/settings/blocked-users", {
          waitUntil: "domcontentloaded",
        });
        await expect(alicePage.page.getByTestId("blocked-users-panel")).toBeVisible({
          timeout: 30_000,
        });
        await alicePage.page.getByTestId("block-target-input").fill(bob.did);
        await alicePage.page.getByTestId("block-user-button").click();
        await expect(alicePage.page.getByTestId("blocked-users-list")).toContainText(bob.did, {
          timeout: 30_000,
        });
        await expect(alicePage.page.getByTestId("write-status")).toContainText(
          /blocklist updated/i,
          { timeout: 30_000 },
        );
        await stepShot(alicePage.page, testInfo, "blocked-users-after-block");

        await expect
          .poll(async () => await blocklistContains(request, aliceToken, bob.did), {
            timeout: 30_000,
            message: "alice account_data includes bob block entry",
          })
          .toBe(true);

        await expect
          .poll(async () => await blockHintSuppressed(request, alice.did, bob.did), {
            timeout: 30_000,
            message: "local federation block hint suppresses bob -> alice push",
          })
          .toBe(true);

        const m2 = `S31 m2 ${stamp}`;
        await bobPage.sendTimelineMessage(spaceId, m2);
        await alicePage.gotoTimelineSpace(spaceId);
        const aliceTexts = await alicePage.readTimelineTexts(spaceId);
        expect(aliceTexts.some((t) => t.includes(m2))).toBe(false);
        await expect(bobPage.page.getByTestId("timeline")).toContainText(m2, {
          timeout: 30_000,
        });

        const aliceNotifications = await readNotificationsText(request, aliceToken);
        expect(aliceNotifications).not.toContain(m2);
        await stepShot(alicePage.page, testInfo, "alice-timeline-after-block");

        await alicePage.page.goto("/settings/blocked-users", {
          waitUntil: "domcontentloaded",
        });
        await alicePage.page
          .getByTestId("blocked-user-row")
          .filter({ hasText: bob.did })
          .getByTestId("unblock-button")
          .click();
        await expect(alicePage.page.getByTestId("blocked-users-list")).not.toContainText(bob.did, {
          timeout: 30_000,
        });
        await expect
          .poll(async () => await blocklistContains(request, aliceToken, bob.did), {
            timeout: 30_000,
            message: "alice account_data removed bob block entry",
          })
          .toBe(false);
        await expect
          .poll(async () => await blockHintSuppressed(request, alice.did, bob.did), {
            timeout: 30_000,
            message: "unblock retracts local federation block hint",
          })
          .toBe(false);

        const m3 = `S31 m3 ${stamp}`;
        await bobPage.sendTimelineMessage(spaceId, m3);
        await alicePage.gotoTimelineSpace(spaceId);
        await expect(alicePage.page.getByTestId("timeline")).toContainText(m3, {
          timeout: 30_000,
        });
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test(
    "E11.1 quarantine vs block: server-side moderation hides a message for everyone; personal block only hides for the blocker",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s31e111-alice");
      const bob = uniqueUser("s31e111-bob");
      const carol = uniqueUser("s31e111-carol");
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
        ensureRegistered(request, carol),
      ]);
      const [aliceToken, bobToken, carolToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
        issueDevSession(request, carol),
      ]);
      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S31 E11.1 ${stamp}`,
        public: true,
        history_visibility: "shared",
      });
      await addSpaceMemberApi(request, aliceToken, spaceId, bob.did);
      await addSpaceMemberApi(request, aliceToken, spaceId, carol.did);
      await putBlocklist(request, aliceToken, alice.did, spaceId, [
        canonicalActorBlockEntry(bob.did),
      ]);

      const body = `S31 E11.1 bob ${stamp}`;
      const sent = await sendMessageApi(request, bobToken, spaceId, body);

      expect(eventsText(await querySpaceEventsApi(request, aliceToken, spaceId))).not.toContain(body);
      expect(eventsText(await querySpaceEventsApi(request, carolToken, spaceId))).toContain(body);

      const redactOperation = makeOperation({
        spaceId,
        objectType: "ck.message.redact",
        payload: {
          target_event_id: sent.event_id,
          redacts: sent.event_id,
          reason: "moderation_quarantine_equivalent",
          actor: alice.did,
        },
      });
      const redactPush = await pushFederationOperations(request, [redactOperation], {
        origin: solandServiceDid(),
        spaceId,
      });
      expect(redactPush.accepted).toContain(redactOperation.operation_id);

      expect(eventsText(await querySpaceEventsApi(request, carolToken, spaceId))).not.toContain(body);
    },
  );

  test(
    "E11.2 mute vs block: muted messages still render in timeline but produce no push; blocked messages render not at all",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s31e112-alice");
      const bob = uniqueUser("s31e112-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S31 E11.2 ${stamp}`,
        public: true,
        history_visibility: "shared",
      });
      await addSpaceMemberApi(request, aliceToken, spaceId, bob.did);

      const mutedVisible = `S31 E11.2 muted-visible ${stamp}`;
      await sendMessageApi(request, bobToken, spaceId, mutedVisible);
      expect(eventsText(await querySpaceEventsApi(request, aliceToken, spaceId))).toContain(
        mutedVisible,
      );

      const registerDevice = await request.post(`${solandBaseUrl()}/_cokret/edge/push/register-device`, {
        headers: authHeaders(aliceToken),
        data: {
          device_id: alice.deviceId,
          push_gateway: "https://push.example",
          push_key: `s31e112-${stamp}`,
          platform: "desktop",
          app_id: "yougen",
        },
      });
      expect(registerDevice.status()).toBe(200);

      await putAccountDataViaEventApi(request, aliceToken, alice.did, spaceId, "ck.push_rules", {
        rules: [
          {
            rule_id: `mute-${stamp}`,
            enabled: true,
            actions: ["dont_notify"],
            conditions: { device_id: alice.deviceId, type: "blind_wakeup" },
          },
        ],
      }, {
        context: "set ck.push_rules push mute",
      });
      const notify = await request.post(`${solandBaseUrl()}/_cokret/edge/push/notify`, {
        data: {
          notification: {
            type: "blind_wakeup",
            devices: [{ device_id: alice.deviceId }],
          },
        },
      });
      expect(notify.status()).toBe(200);
      const notifyBody = await notify.json();
      expect(JSON.stringify(notifyBody)).toContain("push_rule");

      await putBlocklist(request, aliceToken, alice.did, spaceId, [
        canonicalActorBlockEntry(bob.did),
      ]);
      const blockedHidden = `S31 E11.2 blocked-hidden ${stamp}`;
      await sendMessageApi(request, bobToken, spaceId, blockedHidden);
      expect(eventsText(await querySpaceEventsApi(request, aliceToken, spaceId))).not.toContain(
        blockedHidden,
      );
    },
  );

  test(
    "E11.3 blocked user's view: bob still sees his own messages and is never told he was blocked by alice",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s31e113-alice");
      const bob = uniqueUser("s31e113-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S31 E11.3 ${stamp}`,
        public: true,
        history_visibility: "shared",
      });
      await addSpaceMemberApi(request, aliceToken, spaceId, bob.did);
      await putBlocklist(request, aliceToken, alice.did, spaceId, [
        canonicalActorBlockEntry(bob.did),
      ]);

      const body = `S31 E11.3 bob own message ${stamp}`;
      await sendMessageApi(request, bobToken, spaceId, body);

      expect(eventsText(await querySpaceEventsApi(request, aliceToken, spaceId))).not.toContain(body);
      expect(eventsText(await querySpaceEventsApi(request, bobToken, spaceId))).toContain(body);

      expect(await blocklistContains(request, bobToken, alice.did)).toBe(false);
      expect(await readNotificationsText(request, bobToken)).not.toMatch(/blocked by|blocklist/i);
    },
  );
});

function canonicalActorBlockEntry(did: string): BlocklistEntry {
  return {
    target: { kind: "actor", did },
    mode: "block",
    created_at: new Date().toISOString(),
  };
}

async function putBlocklist(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  entries: BlocklistEntry[],
) {
  await putAccountDataViaEventApi(
    request,
    token,
    actorDid,
    realmId,
    BLOCKLIST_DATA_TYPE,
    { entries },
    { context: `set ${BLOCKLIST_DATA_TYPE}` },
  );
}

async function blocklistContains(
  request: APIRequestContext,
  token: string,
  target: string,
): Promise<boolean> {
  const body = await accountSubscribeDeltaApi(request, token);
  const accountData = body.account_data as { events?: Array<Record<string, unknown>> } | undefined;
  const blocklist = (accountData?.events ?? []).find((entry) => entry.data_type === BLOCKLIST_DATA_TYPE);
  const content = (blocklist?.content ?? {}) as Record<string, unknown>;
  const entries = ((content.entries ?? []) as Array<Record<string, unknown>>);
  return entries.some((entry) => {
    const entryTarget = targetDid(entry.target) ?? entry.did ?? entry.actor;
    return entryTarget === target && (entry.mode ?? entry.kind ?? "block") === "block";
  });
}

function targetDid(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object") {
    const target = value as Record<string, unknown>;
    return [target.did, target.actor, target.id].find((candidate): candidate is string => {
      return typeof candidate === "string";
    });
  }
  return undefined;
}

async function blockHintSuppressed(
  request: APIRequestContext,
  actor: string,
  blocked: string,
): Promise<boolean> {
  const response = await request.get(
    `${solandBaseUrl()}/_cokret/peer/federation/block-hints?actor=${encodeURIComponent(actor)}&blocked=${encodeURIComponent(blocked)}`,
  );
  expect(response.status()).toBe(200);
  const body = await response.json();
  return body.suppressed_push === true;
}

async function readNotificationsText(
  request: APIRequestContext,
  token: string,
): Promise<string> {
  const response = await request.get(`${solandBaseUrl()}/_soland/self/notifications`, {
    headers: authHeaders(token),
  });
  expect(response.status()).toBe(200);
  return JSON.stringify(await response.json());
}

function eventsText(body: Record<string, unknown>): string {
  return JSON.stringify(body);
}
