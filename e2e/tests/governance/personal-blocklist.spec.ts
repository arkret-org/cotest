// Personal blocklist (client-side/server-assisted filter; distinct from realm ban / quarantine / mute)
// Contract: e2e/scenarios/governance/personal-blocklist.md
// Spec: governance/content-moderation.md §4-§6, discovery/client-preferences.md §2

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  addRealmMemberApi,
  accountSubscribeDeltaApi,
  authHeaders,
  createRealmApi,
  putAccountDataViaEventApi,
  queryRealmEventsApi,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
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

    const accountData = await request.get(
      `${solandBaseUrl()}/_cokret/self/account/subscribe?catchup=true`,
      {
        headers: { ...auth, accept: "application/x-ndjson" },
      },
    );
    expect(accountData.status()).toBe(200);
    expect(await accountData.text()).toContain("delta");
  });

  test("Complement account_data control: same data_type overwrites and sync returns latest entry", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s31-accountdata");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const dataType = `client.complement_probe.${stamp}`;
    const first = { version: 1, label: `first-${stamp}` };
    const second = { version: 2, label: `second-${stamp}` };

    const firstPut = await request.put(
      `${solandBaseUrl()}/_cokret/self/account_data/${encodeURIComponent(dataType)}`,
      {
        headers: authHeaders(token),
        data: { content: first },
      },
    );
    expect(firstPut.status()).toBe(201);
    expect(
      ((await firstPut.json()) as { content?: Record<string, unknown> })
        .content,
    ).toMatchObject(first);

    const secondPut = await request.put(
      `${solandBaseUrl()}/_cokret/self/account_data/${encodeURIComponent(dataType)}`,
      {
        headers: authHeaders(token),
        data: { content: second },
      },
    );
    expect(secondPut.status()).toBe(200);
    expect(
      ((await secondPut.json()) as { content?: Record<string, unknown> })
        .content,
    ).toMatchObject(second);

    const get = await request.get(
      `${solandBaseUrl()}/_cokret/self/account_data/${encodeURIComponent(dataType)}`,
      { headers: authHeaders(token) },
    );
    expect(get.status()).toBe(200);
    expect(
      ((await get.json()) as { content?: Record<string, unknown> }).content,
    ).toMatchObject(second);

    const list = await request.get(
      `${solandBaseUrl()}/_cokret/self/account_data`,
      {
        headers: authHeaders(token),
      },
    );
    expect(list.status()).toBe(200);
    const listBody = (await list.json()) as {
      entries?: Array<Record<string, unknown>>;
    };
    const listEntries = (listBody.entries ?? []).filter(
      (entry) => entry.data_type === dataType,
    );
    expect(listEntries).toHaveLength(1);
    const listEntry = listEntries[0];
    expect(listEntry).toBeTruthy();
    expect(listEntry!.content).toMatchObject(second);

    const sync = await accountSubscribeDeltaApi(request, token);
    const accountData = sync.account_data as
      | { events?: Array<Record<string, unknown>> }
      | undefined;
    const syncEntries = (accountData?.events ?? []).filter(
      (entry) => entry.data_type === dataType,
    );
    expect(syncEntries).toHaveLength(1);
    const syncEntry = syncEntries[0];
    expect(syncEntry).toBeTruthy();
    expect(syncEntry!.content).toMatchObject(second);
    expect(JSON.stringify(syncEntry)).not.toContain(first.label);
  });

  test("alice blocks bob; bob's messages filtered from alice's timeline; unblock restores visibility; federation propagates block", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s31-alice");
    const bob = uniqueUser("s31-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionCredential: bobToken,
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `S31 Blocklist ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "none",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);

      const m1 = `S31 m1 ${stamp}`;
      await bobPage.sendTimelineMessage(realmId, m1);
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("message-list")).toContainText(
        m1,
        {
          timeout: 30_000,
        },
      );

      await alicePage.page.goto("/settings/blocked-users", {
        waitUntil: "domcontentloaded",
      });
      await expect(
        alicePage.page.getByTestId("blocked-users-panel"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await alicePage.page.getByTestId("block-target-input").fill(bob.did);
      await alicePage.page.getByTestId("block-user-button").click();
      await expect(
        alicePage.page.getByTestId("blocked-users-list"),
      ).toContainText(bob.did, {
        timeout: 30_000,
      });
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /blocklist updated/i,
        { timeout: 30_000 },
      );
      await stepShot(alicePage.page, testInfo, "blocked-users-after-block");

      await expect
        .poll(
          async () => await blocklistStoredOpaque(request, aliceToken, bob.did),
          {
            timeout: 30_000,
            message: "alice account_data stores an opaque blocklist entry",
          },
        )
        .toBe(true);

      const m2 = await bobPage.sendTimelineMentionMessage(
        realmId,
        alice.did,
        `S31 m2 ${stamp}`,
      );
      await alicePage.gotoTimelineRealm(realmId);
      await expect(
        alicePage.page
          .getByTestId("event-body")
          .filter({ hasText: m2 })
          .first(),
      ).toBeHidden({ timeout: 30_000 });
      await expect(bobPage.page.getByTestId("message-list")).toContainText(m2, {
        timeout: 30_000,
      });

      await alicePage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      await expect(
        alicePage.page.getByTestId("notification-item").filter({ hasText: m2 }),
      ).toHaveCount(0);
      await stepShot(alicePage.page, testInfo, "alice-timeline-after-block");

      await alicePage.page.goto("/settings/blocked-users", {
        waitUntil: "domcontentloaded",
      });
      await alicePage.page
        .getByTestId("blocked-user-row")
        .filter({ hasText: bob.did })
        .getByTestId("unblock-button")
        .click();
      await expect(
        alicePage.page.getByTestId("blocked-users-list"),
      ).not.toContainText(bob.did, {
        timeout: 30_000,
      });
      await expect
        .poll(
          async () =>
            await blocklistClearedOrTombstoned(request, aliceToken, bob.did),
          {
            timeout: 30_000,
            message: "alice account_data tombstoned the blocklist entry",
          },
        )
        .toBe(true);
      const m3 = `S31 m3 ${stamp}`;
      await bobPage.sendTimelineMessage(realmId, m3);
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("message-list")).toContainText(
        m3,
        {
          timeout: 30_000,
        },
      );
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("E11.1 quarantine vs block: server-side moderation hides a message for everyone; personal block only hides for the blocker", async ({
    request,
  }) => {
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
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S31 E11.1 ${stamp}`,
      public: true,
      history_visibility: "shared",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);
    await addRealmMemberApi(request, aliceToken, realmId, carol.did);
    await putBlocklist(request, aliceToken, alice.did, realmId, [
      canonicalActorBlockEntry(bob.did),
    ]);
    expect(await blocklistStoredOpaque(request, aliceToken, bob.did)).toBe(
      true,
    );

    const body = `S31 E11.1 bob ${stamp}`;
    const sent = await sendMessageApi(request, bobToken, realmId, body);

    expect(
      eventsText(await queryRealmEventsApi(request, aliceToken, realmId)),
    ).toContain(body);
    expect(
      eventsText(await queryRealmEventsApi(request, carolToken, realmId)),
    ).toContain(body);

    const redactEvent = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.message.redact",
      payload: {
        target_event_id: sent.event_id,
        redacts: sent.event_id,
        reason: "moderation_quarantine_equivalent",
        actor: alice.did,
      },
    });
    await submitSignedEventApi(request, aliceToken, redactEvent, {
      context: `redact ${sent.event_id}`,
    });

    expect(
      eventsText(await queryRealmEventsApi(request, carolToken, realmId)),
    ).not.toContain(body);
  });

  test("E11.2 mute vs private blocklist: ordinary server queries still render messages while private preferences stay opaque", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s31e112-alice");
    const bob = uniqueUser("s31e112-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S31 E11.2 ${stamp}`,
      public: true,
      history_visibility: "shared",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);

    const mutedVisible = `S31 E11.2 muted-visible ${stamp}`;
    await sendMessageApi(request, bobToken, realmId, mutedVisible);
    expect(
      eventsText(await queryRealmEventsApi(request, aliceToken, realmId)),
    ).toContain(mutedVisible);

    const registerDevice = await request.post(
      `${solandBaseUrl()}/_cokret/edge/push/register-device`,
      {
        headers: authHeaders(aliceToken),
        data: {
          device_id: alice.deviceId,
          push_gateway: "https://push.example",
          push_key: `s31e112-${stamp}`,
          platform: "desktop",
          app_id: "yougen",
        },
      },
    );
    expect(registerDevice.status()).toBe(200);
    const registeredDevice = await registerDevice.json();
    const pushTargetId = registeredDevice.registration_id;
    expect(pushTargetId).toBeTruthy();

    await putAccountDataViaEventApi(
      request,
      aliceToken,
      alice.did,
      realmId,
      "ck.push_rules",
      {
        rules: [
          {
            rule_id: `mute-${stamp}`,
            enabled: true,
            actions: ["dont_notify"],
            conditions: { device_id: alice.deviceId, wakeup_kind: "message" },
          },
        ],
      },
      {
        context: "set ck.push_rules push mute",
      },
    );
    const notify = await request.post(
      `${solandBaseUrl()}/_cokret/edge/push/notify`,
      {
        data: {
          notification: {
            push_target_id: pushTargetId,
            wakeup_kind: "message",
            devices: [{ device_id: alice.deviceId }],
          },
        },
      },
    );
    expect(notify.status()).toBe(200);
    const notifyBody = await notify.json();
    expect(JSON.stringify(notifyBody)).not.toContain(`mute-${stamp}`);

    await putBlocklist(request, aliceToken, alice.did, realmId, [
      canonicalActorBlockEntry(bob.did),
    ]);
    const blockedHidden = `S31 E11.2 blocked-hidden ${stamp}`;
    await sendMessageApi(request, bobToken, realmId, blockedHidden);
    expect(
      eventsText(await queryRealmEventsApi(request, aliceToken, realmId)),
    ).toContain(blockedHidden);
  });

  test("E11.3 blocked user's view: bob still sees his own messages and is never told he was blocked by alice", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s31e113-alice");
    const bob = uniqueUser("s31e113-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S31 E11.3 ${stamp}`,
      public: true,
      history_visibility: "shared",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);
    await putBlocklist(request, aliceToken, alice.did, realmId, [
      canonicalActorBlockEntry(bob.did),
    ]);

    const body = `S31 E11.3 bob own message ${stamp}`;
    await sendMessageApi(request, bobToken, realmId, body);

    expect(
      eventsText(await queryRealmEventsApi(request, aliceToken, realmId)),
    ).toContain(body);
    expect(
      eventsText(await queryRealmEventsApi(request, bobToken, realmId)),
    ).toContain(body);

    expect(await blocklistStoredOpaque(request, aliceToken, bob.did)).toBe(
      true,
    );
    expect(await blocklistStoredOpaque(request, bobToken, alice.did)).toBe(
      false,
    );
    expect(await readNotificationsText(request, bobToken)).not.toMatch(
      /blocked by|blocklist/i,
    );
  });
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

async function blocklistStoredOpaque(
  request: APIRequestContext,
  token: string,
  target: string,
): Promise<boolean> {
  const blocklist = await blocklistAccountDataEntry(request, token);
  if (!blocklist) {
    return false;
  }
  const serialized = JSON.stringify(blocklist);
  if (serialized.includes(target)) {
    return false;
  }
  const content = (blocklist.content ?? {}) as Record<string, unknown>;
  const marker = (content.client_side_conformance ?? {}) as Record<
    string,
    unknown
  >;
  return (
    marker.encrypted_account_data === true &&
    typeof marker.payload_digest === "string" &&
    /^sha256:[0-9a-f]{64}$/.test(marker.payload_digest) &&
    typeof content.ciphertext === "string" &&
    content.ciphertext.length > 0
  );
}

async function blocklistClearedOrTombstoned(
  request: APIRequestContext,
  token: string,
  target: string,
): Promise<boolean> {
  const blocklist = await blocklistAccountDataEntry(request, token);
  if (!blocklist) {
    return true;
  }
  if (JSON.stringify(blocklist).includes(target)) {
    return false;
  }
  const content = (blocklist.content ?? {}) as Record<string, unknown>;
  return content.tombstone === true;
}

async function blocklistAccountDataEntry(
  request: APIRequestContext,
  token: string,
): Promise<Record<string, unknown> | undefined> {
  const body = await accountSubscribeDeltaApi(request, token);
  const accountData = body.account_data as
    | { events?: Array<Record<string, unknown>> }
    | undefined;
  return (accountData?.events ?? []).find(
    (entry) => entry.data_type === BLOCKLIST_DATA_TYPE,
  );
}

async function readNotificationsText(
  request: APIRequestContext,
  token: string,
): Promise<string> {
  const body = await accountSubscribeDeltaApi(request, token);
  return JSON.stringify(body.notifications ?? {});
}

function eventsText(body: Record<string, unknown>): string {
  return JSON.stringify(body);
}
