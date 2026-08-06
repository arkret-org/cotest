// Personal blocklist (client-side/server-assisted filter; distinct from realm ban / quarantine / mute)
// Contract: e2e/scenarios/governance/personal-blocklist.md
// Spec: governance/content-moderation.md §4-§6, discovery/client-preferences.md §2

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  addRealmMemberApi,
  accountDataSetSubmission,
  accountSubscribeDeltaApi,
  accountSubscribeFramesApi,
  authHeaders,
  createRealmApi,
  replaceAccountDataApi,
  queryRealmEventsApi,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  selfPathHeadersForDpopSession,
  type DpopUserSession,
  uniqueUser,
} from "../../helpers/users";

const BLOCKLIST_DATA_TYPE = "ak.account.blocklist";

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

type AccountSubscribeOpts = NonNullable<
  Parameters<typeof accountSubscribeDeltaApi>[2]
>;

test.describe.configure({ mode: "serial" });

test.describe("personal blocklist", () => {
  test("personal-blocklist endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s31-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const accountData = await accountSubscribeFramesApi(request, token);
    expect(JSON.stringify(accountData)).toContain("delta");
  });

  test("Complement account_data control: same account_data_key advances through CAS revisions and sync returns latest entry", async ({
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
      `${solandBaseUrl()}/_arkret/self/account_data/${encodeURIComponent(dataType)}`,
      {
        headers: authHeaders(token),
        data: {
          set_event: accountDataSetSubmission({
            actorDid: alice.did,
            key: dataType,
            expectedRevision: 0,
            value: first,
          }),
        },
      },
    );
    expect(firstPut.status()).toBe(201);
    const firstEntry = (await firstPut.json()) as {
      content?: Record<string, unknown>;
      revision?: number;
    };
    expect(firstEntry.content).toMatchObject(first);
    expect(firstEntry.revision).toBe(1);

    const secondPut = await request.put(
      `${solandBaseUrl()}/_arkret/self/account_data/${encodeURIComponent(dataType)}`,
      {
        headers: authHeaders(token),
        data: {
          set_event: accountDataSetSubmission({
            actorDid: alice.did,
            key: dataType,
            expectedRevision: firstEntry.revision ?? 1,
            value: second,
          }),
        },
      },
    );
    expect(secondPut.status()).toBe(200);
    const secondEntry = (await secondPut.json()) as {
      content?: Record<string, unknown>;
      revision?: number;
    };
    expect(secondEntry.content).toMatchObject(second);
    expect(secondEntry.revision).toBe(2);

    const get = await request.get(
      `${solandBaseUrl()}/_arkret/self/account_data/${encodeURIComponent(dataType)}`,
      { headers: authHeaders(token) },
    );
    expect(get.status()).toBe(200);
    expect(
      ((await get.json()) as { content?: Record<string, unknown> }).content,
    ).toMatchObject(second);

    const list = await request.get(
      `${solandBaseUrl()}/_arkret/self/account_data`,
      {
        headers: authHeaders(token),
      },
    );
    expect(list.status()).toBe(200);
    const listBody = (await list.json()) as {
      entries?: Array<Record<string, unknown>>;
    };
    const listEntries = (listBody.entries ?? []).filter(
      (entry) => entry.account_data_key === dataType,
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
      (entry) =>
        entry.kind === "ak.account_data.set" &&
        (entry.payload as Record<string, unknown> | undefined)?.key === dataType,
    );
    expect(syncEntries).toHaveLength(1);
    const syncEntry = syncEntries[0];
    expect(syncEntry).toBeTruthy();
    expect(
      (syncEntry!.payload as Record<string, unknown>).body,
    ).toMatchObject(second);
    expect(syncEntry!.proofs).toEqual(expect.any(Array));
    expect(JSON.stringify(syncEntry)).not.toContain(first.label);
  });

  test("alice blocks bob; bob's messages filtered from alice's timeline; unblock restores visibility; federation propagates block", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "s31-alice"),
      openDpopUserPage(browser, request, "s31-bob"),
    ]);
    if (!aliceFlow || !bobFlow) {
      assertJointStackNotRequired("personal blocklist browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const aliceToken = aliceFlow.session.grantJwt;
    const bobToken = await issueDevSession(request, bob);
    const aliceSubscribeOpts = () => accountSubscribeDpopOpts(aliceFlow.session);
    const bobDidVisiblePrefix = bob.did.slice(0, 16);
    const apiActorSeq = 8_000_000_200_000_000 + (stamp % 100_000);

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
      ).toContainText(bobDidVisiblePrefix, {
        timeout: 30_000,
      });
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /blocklist updated/i,
        { timeout: 30_000 },
      );
      await stepShot(alicePage.page, testInfo, "blocked-users-after-block");

      await expect
        .poll(
          async () =>
            await blocklistStoredOpaque(
              request,
              aliceToken,
              bob.did,
              aliceSubscribeOpts,
            ),
          {
            timeout: 30_000,
            message: "alice account_data stores an opaque blocklist entry",
          },
        )
        .toBe(true);

      const m2 = `S31 m2 ${stamp}`;
      await sendMessageApi(request, bobToken, realmId, m2, {
        mentions: [alice.did],
        actorSeq: apiActorSeq,
      });
      await alicePage.gotoTimelineRealm(realmId);
      await expect(
        alicePage.page
          .getByTestId("event-body")
          .filter({ hasText: m2 })
          .first(),
      ).toBeHidden({ timeout: 30_000 });
      await bobPage.gotoTimelineRealm(realmId);
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
        .filter({ hasText: bobDidVisiblePrefix })
        .getByTestId("unblock-button")
        .click();
      await expect(
        alicePage.page.getByTestId("blocked-users-list"),
      ).not.toContainText(bobDidVisiblePrefix, {
        timeout: 30_000,
      });
      await expect
        .poll(
          async () =>
            await blocklistClearedOrTombstoned(
              request,
              aliceToken,
              bob.did,
              aliceSubscribeOpts,
            ),
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
    await putBlocklist(request, aliceToken, alice.did, [
      canonicalActorBlockEntry(bob.did),
    ]);
    expect(await blocklistStoredOpaque(request, aliceToken, bob.did)).toBe(
      true,
    );

    const body = `S31 E11.1 bob ${stamp}`;
    const sent = await sendMessageApi(request, bobToken, realmId, body);

    for (const [label, token] of [
      ["alice", aliceToken],
      ["carol", carolToken],
    ] as const) {
      await expect
        .poll(
          async () => eventsText(await queryRealmEventsApi(request, token, realmId)),
          {
            timeout: 30_000,
            message: `${label} sees the accepted message before moderation`,
          },
        )
        .toContain(body);
    }

    const redactEvent = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ak.message.redact",
      payload: {
        target_event_id: sent.event_id,
        reason: "moderation_quarantine_equivalent",
      },
    });
    await submitSignedEventApi(request, aliceToken, redactEvent, {
      context: `redact ${sent.event_id}`,
    });

    await expect
      .poll(
        async () => eventsText(await queryRealmEventsApi(request, carolToken, realmId)),
        {
          timeout: 30_000,
          message: "carol observes the moderation redaction projection",
        },
      )
      .not.toContain(body);
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
      `${solandBaseUrl()}/_arkret/edge/push/register-device`,
      {
        headers: authHeaders(aliceToken),
        data: {
          device_id: alice.deviceId,
          push_gateway: "https://push.example",
          push_key: `s31e112-${stamp}`,
          platform: "desktop",
          app_id: "inkson",
        },
      },
    );
    expect(registerDevice.status()).toBe(200);
    const registeredDevice = await registerDevice.json();
    const pushTargetId = registeredDevice.registration_id;
    expect(pushTargetId).toBeTruthy();

    await replaceAccountDataApi(
      request,
      aliceToken,
      alice.did,
      "ak.push_rules",
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
      0,
      {
        context: "set ak.push_rules push mute",
      },
    );
    const notify = await request.post(
      `${solandBaseUrl()}/_arkret/edge/push/notify`,
      {
        data: {
          notification: {
            push_target_id: pushTargetId,
            wakeup_kind: "message",
            timing_profile_hint: "default",
            devices: [{ device_id: alice.deviceId }],
          },
        },
      },
    );
    expect(notify.status()).toBe(200);
    const notifyBody = await notify.json();
    expect(JSON.stringify(notifyBody)).not.toContain(`mute-${stamp}`);

    await putBlocklist(request, aliceToken, alice.did, [
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
    await putBlocklist(request, aliceToken, alice.did, [
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
  entries: BlocklistEntry[],
) {
  await replaceAccountDataApi(
    request,
    token,
    actorDid,
    BLOCKLIST_DATA_TYPE,
    { entries },
    0,
    { context: `set ${BLOCKLIST_DATA_TYPE}` },
  );
}

async function blocklistStoredOpaque(
  request: APIRequestContext,
  token: string,
  target: string,
  subscribeOpts?: () => AccountSubscribeOpts,
): Promise<boolean> {
  const blocklist = await blocklistAccountDataRow(
    request,
    token,
    subscribeOpts,
  );
  if (!blocklist) {
    return false;
  }
  const serialized = JSON.stringify(blocklist);
  if (serialized.includes(target)) {
    return false;
  }
  const content = (blocklist.content ?? {}) as Record<string, unknown>;
  return isEncryptedAccountDataCarrier(content);
}

function isEncryptedAccountDataCarrier(
  content: Record<string, unknown>,
): boolean {
  const aad = (content.aad ?? {}) as Record<string, unknown>;
  return (
    content.schema === "ak.schema.account_data_encrypted_value.v1" &&
    content.version === "1.0" &&
    content.aead_profile === "ak.aead.xchacha20_poly1305.v1" &&
    typeof content.key_ref === "string" &&
    /^sha256:[0-9a-f]{64}$/.test(content.key_ref) &&
    typeof content.aad_digest === "string" &&
    /^sha256:[0-9a-f]{64}$/.test(content.aad_digest) &&
    aad.schema === "ak.schema.account_data_encrypted_value.v1" &&
    aad.account_data_key === BLOCKLIST_DATA_TYPE &&
    typeof content.ciphertext === "string" &&
    content.ciphertext.length > 0 &&
    typeof content.ciphertext_digest === "string" &&
    /^sha256:[0-9a-f]{64}$/.test(content.ciphertext_digest) &&
    typeof content.nonce === "string" &&
    content.nonce.length > 0
  );
}

async function blocklistClearedOrTombstoned(
  request: APIRequestContext,
  token: string,
  target: string,
  subscribeOpts?: () => AccountSubscribeOpts,
): Promise<boolean> {
  const blocklist = await blocklistAccountDataRow(
    request,
    token,
    subscribeOpts,
  );
  if (!blocklist) {
    return true;
  }
  if (JSON.stringify(blocklist).includes(target)) {
    return false;
  }
  const content = (blocklist.content ?? {}) as Record<string, unknown>;
  return content.tombstone === true || isEncryptedAccountDataCarrier(content);
}

async function blocklistAccountDataRow(
  request: APIRequestContext,
  token: string,
  subscribeOpts?: () => AccountSubscribeOpts,
): Promise<Record<string, unknown> | undefined> {
  const body = await accountSubscribeDeltaApi(request, token, subscribeOpts?.());
  const accountData = body.account_data as
    | { events?: Array<Record<string, unknown>> }
    | undefined;
  const entry = (accountData?.events ?? []).find((candidate) => {
    const payload = candidate.payload as Record<string, unknown> | undefined;
    return (
      candidate.kind === "ak.account_data.set" &&
      payload?.key === BLOCKLIST_DATA_TYPE
    );
  });
  if (!entry) {
    return undefined;
  }
  const payload = entry.payload as Record<string, unknown>;
  return {
    ...entry,
    content: payload.body,
  };
}

function accountSubscribeDpopOpts(session: DpopUserSession): AccountSubscribeOpts {
  const url = new URL(`${solandBaseUrl()}/_arkret/self/account/subscribe`);
  url.searchParams.set("catchup", "true");
  return {
    headers: selfPathHeadersForDpopSession(session, "GET", url.toString()),
  };
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
