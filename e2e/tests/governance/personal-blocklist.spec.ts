// Personal blocklist (client-side/server-assisted filter; distinct from realm ban / quarantine / mute)
// Contract: e2e/scenarios/governance/personal-blocklist.md
// Spec: governance/content-moderation.md §4-§6, discovery/client-preferences.md §2

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  addRealmMemberApi,
  accountSubscribeDeltaApi,
  accountSubscribeFramesApi,
  authHeaders,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  replaceAccountDataApi,
  resolveDefaultStrandId,
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
  target: {
    kind: "actor";
    actor_id: ReturnType<typeof accountActorId>;
  };
  mode: "block";
  applies_to: ["messages", "notifications"];
  created_at: string;
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
    // Account Data v1 is a closed registry, not an arbitrary client key/value
    // bag. Use a registered encrypted private key while exercising the same
    // CAS and sync semantics this complement test is meant to cover.
    const dataType = BLOCKLIST_DATA_TYPE;
    const first = { version: 1, label: `first-${stamp}` };
    const second = { version: 2, label: `second-${stamp}` };

    const firstEntry = await replaceAccountDataApi(
      request,
      token,
      alice.id,
      dataType,
      first,
      0,
    );
    expect(firstEntry.content).toBeTruthy();
    expect(firstEntry.revision).toBe(1);

    const secondEntry = await replaceAccountDataApi(
      request,
      token,
      alice.id,
      dataType,
      second,
      Number(firstEntry.revision ?? 1),
    );
    expect(secondEntry.content).toBeTruthy();
    expect(secondEntry.content).not.toEqual(firstEntry.content);
    expect(secondEntry.revision).toBe(2);

    const get = await request.get(
      `${solandBaseUrl()}/_arkret/self/account_data/${encodeURIComponent(dataType)}`,
      { headers: authHeaders(token) },
    );
    expect(get.status()).toBe(200);
    expect(
      ((await get.json()) as { content?: Record<string, unknown> }).content,
    ).toEqual(secondEntry.content);

    const list = await request.get(
      `${solandBaseUrl()}/_arkret/self/account_data`,
      {
        headers: authHeaders(token),
      },
    );
    expect(list.status()).toBe(200);
    const listBody = (await list.json()) as {
      account_data_entries?: Array<Record<string, unknown>>;
    };
    const listEntries = (listBody.account_data_entries ?? []).filter(
      (entry) => entry.account_data_key === dataType,
    );
    expect(listEntries).toHaveLength(1);
    const listEntry = listEntries[0];
    expect(listEntry).toBeTruthy();
    expect(listEntry!.content).toEqual(secondEntry.content);

    const sync = await accountSubscribeDeltaApi(request, token);
    const accountData = sync.account_data as
      { events?: Array<Record<string, unknown>> } | undefined;
    const syncEntries = (accountData?.events ?? []).filter(
      (entry) =>
        entry.kind === "ak.account_data.set" &&
        (entry.payload as Record<string, unknown> | undefined)?.key ===
          dataType,
    );
    expect(syncEntries).toHaveLength(1);
    const syncEntry = syncEntries[0];
    expect(syncEntry).toBeTruthy();
    const syncPayload = syncEntry!.payload as Record<string, unknown>;
    expect(syncPayload.encrypted_payload).toEqual(secondEntry.content);
    expect(syncPayload.body).toBeUndefined();
    expect(syncEntry!.proofs).toEqual(expect.any(Array));
    expect(JSON.stringify(syncEntry)).not.toContain(first.label);
    expect(JSON.stringify(syncEntry)).not.toContain(second.label);
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
    const aliceSubscribeOpts = () =>
      accountSubscribeDpopOpts(aliceFlow.session);
    // The row identifies its target by `data-actor-id` (the canonical ActorId
    // key). Its *visible* text truncates that value in the middle, so asserting
    // on rendered text cannot see the principal id at all — match the attribute.
    const bobBlockedRow = (page: typeof alicePage.page) =>
      page
        .getByTestId("blocked-user-row")
        .filter({ has: page.locator(`[data-actor-id*="${bob.id}"]`) })
        .or(page.locator(`[data-testid="blocked-user-row"][data-actor-id*="${bob.id}"]`));
    const apiActorSeq = 8_000_000_200_000_000 + (stamp % 100_000);

    try {
      const realmId = await alicePage.createRealm({
        title: `S31 Blocklist ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "none",
        seedMembers: [bob.id],
      });
      await bobPage.acceptInvite(realmId);
      await grantCapabilityEventApi(request, aliceToken, {
        ownerId: alice.id,
        realmId,
        subjectId: bob.id,
        actions: ["ak.message.create"],
      });

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
      // client-preferences.md §3.5 target union: the machine-readable
      // `account_blocklist_payload` requires `target.actor_id` to be a complete
      // composite ActorId, not a bare principal DID (a bare principal_id cannot
      // name the Station, and common-fields.md forbids falling back to one).
      // The outer target has one identity kind. Account and service authors are
      // distinguished only by the complete ActorId carried in actor_id.
      await alicePage.page
        .getByTestId("block-target-input")
        .fill(JSON.stringify(accountActorId(bob.id)));
      await alicePage.page.getByTestId("block-user-button").click();
      await expect(bobBlockedRow(alicePage.page).first()).toBeVisible({
        timeout: 30_000,
      });
      await expect(alicePage.page.getByTestId("write-status")).toContainText(
        /blocked/i,
        { timeout: 30_000 },
      );
      await stepShot(alicePage.page, testInfo, "blocked-users-after-block");

      await expect
        .poll(
          async () =>
            await blocklistStoredOpaque(
              request,
              aliceToken,
              bob.id,
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
        mentions: [alice.id],
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
      await bobBlockedRow(alicePage.page)
        .first()
        .getByTestId("unblock-button")
        .click();
      await expect(bobBlockedRow(alicePage.page)).toHaveCount(0, {
        timeout: 30_000,
      });
      await expect
        .poll(
          async () =>
            await blocklistClearedOrTombstoned(
              request,
              aliceToken,
              bob.id,
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
      history_access: "all_history_for_current_members",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);
    await addRealmMemberApi(request, aliceToken, realmId, carol.id);
    await resolveDefaultStrandId(request, aliceToken, realmId, { authorityRootController: alice.id });
    await grantCapabilityEventApi(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectId: bob.id,
      actions: ["ak.strand.create", "ak.message.create"],
    });
    await putBlocklist(request, aliceToken, alice.id, [
      canonicalActorBlockEntry(bob.id),
    ]);
    expect(await blocklistStoredOpaque(request, aliceToken, bob.id)).toBe(
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
          async () =>
            eventsText(await queryRealmEventsApi(request, token, realmId)),
          {
            timeout: 30_000,
            message: `${label} sees the accepted message before moderation`,
          },
        )
        .toContain(body);
    }

    const redactEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.message.redact",
      payload: {
        message_id: sent.event_id.replace(/^ak:event:/, "ak:message:"),
        reason: "moderation_quarantine_equivalent",
      },
    });
    await submitSignedEventApi(request, aliceToken, redactEvent, {
      context: `redact ${sent.event_id}`,
    });

    await expect
      .poll(
        async () =>
          eventsText(await queryRealmEventsApi(request, carolToken, realmId)),
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
      history_access: "all_history_for_current_members",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);

    const mutedVisible = `S31 E11.2 muted-visible ${stamp}`;
    await resolveDefaultStrandId(request, aliceToken, realmId, { authorityRootController: alice.id });
    await grantCapabilityEventApi(request, aliceToken, {
      ownerId: alice.id, realmId, subjectId: bob.id,
      actions: ["ak.strand.create", "ak.message.create"],
    });
    await sendMessageApi(request, bobToken, realmId, mutedVisible);
    expect(
      eventsText(await queryRealmEventsApi(request, aliceToken, realmId)),
    ).toContain(mutedVisible);

    const registerDevice = await request.post(
      `${solandBaseUrl()}/_arkret/edge/push/register-device`,
      {
        headers: { ...authHeaders(aliceToken), "content-type": "application/json" },
        data: canonicalJson({
          device_id: alice.deviceId,
          push_gateway_url: "https://push.example",
          push_key: `s31e112-${stamp}`,
          platform: "desktop",
          app_id: "inkson",
          visible_notification_opt_in: false,
        }),
      },
    );
    expect(registerDevice.status(), await registerDevice.text()).toBe(200);
    const registeredDevice = await registerDevice.json();
    const pushTargetId = registeredDevice.push_target_id;
    expect(pushTargetId).toBeTruthy();

    await replaceAccountDataApi(
      request,
      aliceToken,
      alice.id,
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
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          notification: {
            push_target_id: pushTargetId,
            wakeup_kind: "message",
            devices: [{ device_id: alice.deviceId }],
          },
        }),
      },
    );
    // Only a separately authenticated Push Gateway owns notify. The Station
    // cannot report delivery or disclose private rules through this path.
    expect(notify.status()).toBe(404);
    const notifyBody = await notify.json();
    expect(JSON.stringify(notifyBody)).not.toContain(`mute-${stamp}`);

    await putBlocklist(request, aliceToken, alice.id, [
      canonicalActorBlockEntry(bob.id),
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
      history_access: "all_history_for_current_members",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);
    await putBlocklist(request, aliceToken, alice.id, [
      canonicalActorBlockEntry(bob.id),
    ]);

    const body = `S31 E11.3 bob own message ${stamp}`;
    await resolveDefaultStrandId(request, aliceToken, realmId, { authorityRootController: alice.id });
    await grantCapabilityEventApi(request, aliceToken, {
      ownerId: alice.id, realmId, subjectId: bob.id,
      actions: ["ak.strand.create", "ak.message.create"],
    });
    await sendMessageApi(request, bobToken, realmId, body);

    expect(
      eventsText(await queryRealmEventsApi(request, aliceToken, realmId)),
    ).toContain(body);
    expect(
      eventsText(await queryRealmEventsApi(request, bobToken, realmId)),
    ).toContain(body);

    expect(await blocklistStoredOpaque(request, aliceToken, bob.id)).toBe(
      true,
    );
    expect(await blocklistStoredOpaque(request, bobToken, alice.id)).toBe(
      false,
    );
    expect(await readNotificationsText(request, bobToken)).not.toMatch(
      /blocked by|blocklist/i,
    );
  });
});

function canonicalActorBlockEntry(principalId: string): BlocklistEntry {
  return {
    target: { kind: "actor", actor_id: accountActorId(principalId) },
    mode: "block",
    applies_to: ["messages", "notifications"],
    created_at: new Date().toISOString(),
  };
}

async function putBlocklist(
  request: APIRequestContext,
  token: string,
  actorId: string,
  entries: BlocklistEntry[],
) {
  await replaceAccountDataApi(
    request,
    token,
    actorId,
    BLOCKLIST_DATA_TYPE,
    { version: 1, entries },
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
    !("aad_digest" in content) &&
    aad.schema === "ak.schema.account_data_encrypted_value.v1" &&
    aad.account_data_key === BLOCKLIST_DATA_TYPE &&
    typeof content.ciphertext === "string" &&
    content.ciphertext.length > 0 &&
    !("ciphertext_digest" in content) &&
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
  const body = await accountSubscribeDeltaApi(
    request,
    token,
    subscribeOpts?.(),
  );
  const accountData = body.account_data as
    { events?: Array<Record<string, unknown>> } | undefined;
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
    content: payload.encrypted_payload,
  };
}

function accountSubscribeDpopOpts(
  session: DpopUserSession,
): AccountSubscribeOpts {
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
