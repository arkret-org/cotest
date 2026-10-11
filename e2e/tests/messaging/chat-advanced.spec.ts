// Chat advanced (reactions/replies/mentions/polls/typing/presence)
// Contract: e2e/scenarios/messaging/chat-advanced.md
// Spec refs:
//   - models/strand-and-message.md §4.3, §8
//   - models/content-types.md §4.1 (mentions), §4.9 (polls)
//   - discovery/profiles-presence.md §3
//   - discovery/push-notifications.md §4.3.1, §4.5

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { cssStringEscape } from "../../helpers/dom";
import { colandBaseUrl } from "../../helpers/env";
import {
  acceptInviteViaApi,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { createTwoUserMessagingRealm } from "../../helpers/messaging-fixtures";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  accountSubscribeRealmFramesApi,
  authHeaders,
  canonicalJson,
  createRealmApi,
  eventPrincipalId,
  grantCapabilityEventApi,
  joinRealmMemberByInviteApi,
  resolveDefaultStrandId,
  rawSubmitSignedEventApi,
  readCommitStreamHeadApi,
  wireErrCode,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/coland-api";
import { addRealmMlsMemberApi, encryptMlsMessageContent, realmMlsCreatorGroupApi } from "../../helpers/coland-api/mls";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
  openDpopUserPage,
  openUserPage,
  uniqueUser,
  type JointUserPage,
} from "../../helpers/users";
import {
  buildSignalEnvelope,
  captureSubmittedSignalEnvelope,
  signalPlaintext,
} from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

async function gotoChat(page: JointUserPage, realmId: string) {
  if (!page.page.url().includes(`/chat/${realmId}`)) {
    await page.gotoTimelineRealm(realmId);
  }
  await expect(page.page.getByTestId("chat-panel")).toBeVisible({
    timeout: 120_000,
  });
  // Wait for the discussion list to populate at least one channel — inkson's
  // send-chat-button silently no-ops if no selected_channel matches a known
  // channel (chat.rs:2186-2189). Sync hydrates the channel list after mount.
  await expect(page.page.getByTestId("channel-item").first()).toBeVisible({
    timeout: 30_000,
  });
}

async function sendChat(page: JointUserPage, realmId: string, body: string) {
  await gotoChat(page, realmId);
  await page.page.getByTestId("chat-input").fill(body);
  await page.clickWithPassivePromptRetry(page.page.getByTestId("send-chat-button"));
  await expect(
    page.page.getByTestId("chat-message").filter({ hasText: body }),
  ).toBeVisible({ timeout: 30_000 });
}

// Local holder diagnostics only; never substitute these for authority proof.
async function reactionProjectionDiagnostic(page: JointUserPage, realmId: string) {
  return page.page.evaluate(async realm => {
    const result = <T>(request: IDBRequest<T>): Promise<T> => new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const db = await result(indexedDB.open("inkson.secret.inkson", 1));
    try {
      const tx = db.transaction(["entries", "wrapping_keys"], "readonly");
      const [key, names, encrypted] = await Promise.all([
        result(tx.objectStore("wrapping_keys").get("primary")) as Promise<CryptoKey>,
        result(tx.objectStore("entries").getAllKeys()),
        result(tx.objectStore("entries").getAll()),
      ]);
      if (!key || key.extractable) throw new Error("non-extractable wrapping key unavailable");
      const diagnostics = [];
      for (let index = 0; index < names.length; index += 1) {
        if (!String(names[index]).startsWith("inkson.local_state.v1.account.")) continue;
        const entry = encrypted[index] as { iv: Uint8Array; ct: Uint8Array };
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: Uint8Array.from(entry.iv).buffer }, key, Uint8Array.from(entry.ct).buffer,
        );
        const state = JSON.parse(new TextDecoder().decode(plaintext));
        const matches = (ref: Record<string, unknown>) => ref?.realm_id === realm;
        const messages = (state.verified_message_commits ?? []).filter(
          (row: Record<string, any>) => matches(row.accepted_ref?.stream_ref),
        ).map((row: Record<string, any>) => ({
          accepted_ref: row.accepted_ref, scope_ref: row.scope_ref,
        }));
        const reactions = (state.verified_reaction_assertions ?? []).filter(
          (row: Record<string, any>) => row.event?.realm_id === realm,
        ).map((row: Record<string, any>) => ({
          accepted_ref: row.accepted_ref, kind: row.event.kind,
          target_ref: row.event.payload?.target_ref, scope_ref: row.event.scope_ref,
        }));
        const prefixes = Object.values(state.verified_poll_prefixes ?? {}).filter(
          (row: any) => matches(row.head?.stream_ref),
        );
        diagnostics.push({ messages, reactions, prefixes });
      }
      return diagnostics;
    } finally {
      db.close();
    }
  }, realmId);
}

async function accountSubscribeTimelineEvents(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<Array<Record<string, unknown>>> {
  // account-subscribe-frame.schema.json `account_filter`: an absent or empty
  // `realm_ids` selects no Realm detail, so the Realm bucket is requested
  // explicitly. Its delivered rows are `realm_sync_entry.committed_events[]`
  // (`CommittedEventView`: a RealmCommit plus the exact signed Event, or a
  // withheld marker without Event bytes); a window may span several frames.
  const frames = await accountSubscribeRealmFramesApi(request, token, realmId, {
    filter: { realm_ids: [realmId], window_limit: 100 },
    onRead: async (diagnostic) => {
      await test.info().attach("safe-chat-account-timeline-read", {
        contentType: "application/json", body: JSON.stringify(diagnostic),
      });
    },
  });
  const buckets = frames.flatMap((frame) => {
    if (frame.kind !== "delta") return [];
    const realms = frame.realms as
      | Record<string, { committed_events?: Array<{ event?: Record<string, unknown> }> }>
      | undefined;
    const bucket = realms?.[realmId];
    return bucket ? [bucket] : [];
  });
  expect(buckets.length, `sync realm frame for ${realmId}`).toBeGreaterThan(0);
  return buckets.flatMap((bucket) =>
    (bucket.committed_events ?? []).flatMap((row) => (row.event ? [row.event] : [])),
  );
}

test.describe("chat advanced", () => {
  test("API reactions add/remove round-trip as projection events", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "reaction-api");
    await grantCapabilityEventApi(request, fixture.aliceToken, {
      ownerId: fixture.alice.id,
      realmId: fixture.realmId,
      subjectId: fixture.bob.id,
      actions: ["ak.reaction.add", "ak.reaction.remove"],
    });
    const message = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
      `reaction target ${Date.now()}`,
      { actorId: fixture.alice.id },
    );
    const messageRef = message.event_id.replace(/^ak:event:/, "ak:message:");

    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorId: fixture.bob.id,
        realmId: fixture.realmId,
        kind: "ak.reaction.add",
        payload: {
          target_ref: messageRef,
          key: "+1",
        },
      }),
      { context: "add reaction" },
    );
    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorId: fixture.bob.id,
        realmId: fixture.realmId,
        kind: "ak.reaction.remove",
        payload: {
          target_ref: messageRef,
          key: "+1",
        },
      }),
      { context: "remove reaction" },
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    expect(events.map((event) => event.kind)).toEqual(
      expect.arrayContaining(["ak.reaction.add", "ak.reaction.remove"]),
    );
    expect(
      events.find((event) => event.kind === "ak.reaction.add")?.payload,
    ).toMatchObject({
      target_ref: messageRef,
      key: "+1",
    });
  });

  test("API reply messages preserve reply_to and discussion track ordering", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "reply-api");
    const root = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
      `root ${Date.now()}`,
      { actorId: fixture.alice.id },
    );
    const rootMessageRef = root.event_id.replace(/^ak:event:/, "ak:message:");
    const strandId = await resolveDefaultStrandId(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const replyBody = `reply ${Date.now()}`;
    const reply = signedEventEnvelope({
      actorId: fixture.bob.id,
      realmId: fixture.realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        reply_to_id: rootMessageRef,
        content: { kind: "ak.content.text", body: replyBody },
      },
    });
    await submitSignedEventApi(request, fixture.bobToken, reply, {
      context: "reply message",
    });

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
      { order: "ascending" },
    );
    const messageEvents = events.filter(
      (event) => event.kind === "ak.message.create",
    );
    expect(messageEvents.map((event) => event.event_id)).toEqual([
      root.event_id,
      reply.event_id,
    ]);
    expect(messageEvents.at(-1)?.payload).toMatchObject({
      reply_to_id: rootMessageRef,
      track_name: "discussion",
    });
  });

  test("API mention payload persists canonical mention metadata", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "mention-api");
    const strandId = await resolveDefaultStrandId(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const body = `@${fixture.bob.handle.replace(/^@/, "")} review ${Date.now()}`;
    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorId: fixture.alice.id,
        realmId: fixture.realmId,
        kind: "ak.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body,
            mentions: [
              {
                kind: "mention",
                subject_account_id: accountActorId(fixture.bob.id).account_id,
              },
            ],
          },
        },
      }),
      { context: "mention message" },
    );

    const events = await listRealmEventsViaApi(
      request,
      fixture.bobToken,
      fixture.realmId,
    );
    const mention = events.find(
      (event) =>
        event.kind === "ak.message.create" &&
        JSON.stringify(event.payload).includes(fixture.bob.id),
    );
    expect(mention?.payload).toMatchObject({
      content: {
        mentions: [
          {
            kind: "mention",
            subject_account_id: accountActorId(fixture.bob.id).account_id,
          },
        ],
      },
    });
    expect(mention?.payload).not.toHaveProperty("mention_routing_hint");
  });

  test("API sync timeline preserves canonical mentions, reactions, and reply events", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "sync-projection-api");
    await grantCapabilityEventApi(request, fixture.aliceToken, {
      ownerId: fixture.alice.id,
      realmId: fixture.realmId,
      subjectId: fixture.bob.id,
      actions: ["ak.reaction.add", "ak.reaction.remove"],
    });
    const strandId = await resolveDefaultStrandId(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const body = `@${fixture.bob.handle.replace(/^@/, "")} sync projection ${Date.now()}`;
    const root = signedEventEnvelope({
      actorId: fixture.alice.id,
      realmId: fixture.realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        content: {
          kind: "ak.content.text",
          body,
          mentions: [
            {
              kind: "mention",
              subject_account_id: accountActorId(fixture.bob.id).account_id,
            },
          ],
        },
      },
    });
    await submitSignedEventApi(request, fixture.aliceToken, root, {
      context: "root mention",
    });
    const rootEventId = String(root.event_id);
    const rootMessageRef = rootEventId.replace(/^ak:event:/, "ak:message:");
    const reply = signedEventEnvelope({
      actorId: fixture.bob.id,
      realmId: fixture.realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        reply_to_id: rootMessageRef,
        content: { kind: "ak.content.text", body: `reply ${Date.now()}` },
      },
    });
    await submitSignedEventApi(request, fixture.bobToken, reply, {
      context: "reply message",
    });

    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorId: fixture.alice.id,
        realmId: fixture.realmId,
        kind: "ak.reaction.add",
        payload: { target_ref: rootMessageRef, key: "+1" },
      }),
      { context: "alice add reaction" },
    );
    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorId: fixture.bob.id,
        realmId: fixture.realmId,
        kind: "ak.reaction.add",
        payload: { target_ref: rootMessageRef, key: "+1" },
      }),
      { context: "bob add reaction" },
    );
    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorId: fixture.bob.id,
        realmId: fixture.realmId,
        kind: "ak.reaction.remove",
        payload: { target_ref: rootMessageRef, key: "+1" },
      }),
      { context: "bob remove reaction" },
    );

    const events = await accountSubscribeTimelineEvents(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const rootProjection = events.find(
      (event) => event.event_id === rootEventId,
    );
    expect(rootProjection).toMatchObject({
      payload: {
        content: {
          mentions: [
            {
              kind: "mention",
              subject_account_id: accountActorId(fixture.bob.id).account_id,
            },
          ],
        },
      },
    });
    expect(rootProjection?.payload).not.toHaveProperty("mention_routing_hint");

    const reactionEvents = events.filter(
      (event) =>
        (event.kind === "ak.reaction.add" ||
          event.kind === "ak.reaction.remove") &&
        (event.payload as { target_ref?: string })?.target_ref === rootMessageRef,
    );
    // Keep authorization evidence out of failure output while comparing the
    // same public reaction fields as the protocol assertion below.
    expect(reactionEvents.map((event) => ({
      actor_id: event.actor_id,
      kind: event.kind,
      payload: { key: (event.payload as { key?: string }).key },
    }))).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor_id: accountActorId(fixture.alice.id),
          kind: "ak.reaction.add",
          payload: expect.objectContaining({ key: "+1" }),
        }),
        expect.objectContaining({
          actor_id: accountActorId(fixture.bob.id),
          kind: "ak.reaction.add",
          payload: expect.objectContaining({ key: "+1" }),
        }),
        expect.objectContaining({
          actor_id: accountActorId(fixture.bob.id),
          kind: "ak.reaction.remove",
          payload: expect.objectContaining({ key: "+1" }),
        }),
      ]),
    );

    const replyProjection = events.find(
      (event) => event.event_id === reply.event_id,
    );
    expect(replyProjection).toMatchObject({
      payload: {
        reply_to_id: rootMessageRef,
      },
    });
  });

  test("API typing Signal is decrypted from the live rail and keeps its target opaque", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const aliceFlow = await openDpopUserPage(
      browser,
      request,
      `typing-api-alice-${stamp}`,
      { prepareMlsDevice: false },
    );
    if (!aliceFlow) {
      assertJointStackNotRequired("typing API device authorization");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bob = uniqueUser(`typing-api-bob-${stamp}`);
    await ensureRegistered(request, bob);
    const aliceToken = await issueUserSession(request, aliceFlow.user);
    const bobToken = await issueUserSession(request, bob);

    try {
      const realmId = await createRealmApi(request, aliceToken, {
        title: `typing API ${stamp}`,
        ownerId: aliceFlow.user.id,
        mls_activated: true,
        history_access: "since_join",
      });
      // common-fields.md section 4.5: only the target enters a Realm by its own
      // membership Event, here by accepting a directed Invite. The join
      // advances the MLS key-access revision, so an Add Commit must cover bob
      // before the scope admits new ciphertext (encryption-and-audit.md 2.4.1).
      await joinRealmMemberByInviteApi(request, aliceToken, realmId, {
        id: bob.id,
        token: bobToken,
      });
      await addRealmMlsMemberApi(request, realmId, {
        id: bob.id,
        deviceId: bob.deviceId,
        token: bobToken,
      });
      const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
      const envelope = buildSignalEnvelope({
        actorId: aliceFlow.user.id,
        deviceId: aliceFlow.user.deviceId,
        realmId,
        plaintext: {
          kind: "ak.typing",
          strand_id: strandId,
          typing: true,
          payload_sequence: Date.now(),
          ttl_ms: 25_000,
        },
      });
      const { result: typing, envelopes } =
        await captureSubmittedSignalEnvelope(
          request,
          aliceToken,
          bobToken,
          realmId,
          envelope,
        );
      const typingResponseText = await typing.text();
      expect(typing.status(), typingResponseText).toBe(200);
      const submit = JSON.parse(typingResponseText) as Record<string, unknown>;
      expect(submit).toMatchObject({ accepted: true, realm_id: realmId });
      expect(submit).not.toHaveProperty("kind");
      expect(submit).not.toHaveProperty("strand_id");

      const received = envelopes.find(
        (candidate) =>
          eventPrincipalId({ actor_id: candidate.sender_actor_id }) ===
            aliceFlow.user.id &&
          signalPlaintext(candidate).kind === "ak.typing",
      );
      expect(received, "bob received encrypted typing Signal").toBeTruthy();
      if (!received) throw new Error("typing Signal missing");
      expect(received).not.toHaveProperty("kind");
      expect(received).not.toHaveProperty("strand_id");
      expect(signalPlaintext(received)).toMatchObject({
        kind: "ak.typing",
        strand_id: strandId,
        typing: true,
      });
      expect(signalPlaintext(received)).not.toHaveProperty("track_name");
    } finally {
      await aliceFlow.page.close();
    }
  });

  test("chat route hydrates the default discussion channel on first mount", async ({
    browser,
    request,
  }) => {
    const aliceFlow = await openDpopUserPage(browser, request, "chat-route-alice", {
      prepareMlsDevice: false,
    });
    if (!aliceFlow) {
      assertJointStackNotRequired("chat route browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = uniqueUser("chat-route-bob");
    await ensureRegistered(request, bob);
    const [aliceToken, bobToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
    ]);
    const realmId = await createSharedRealmViaApi(
      request,
      alice,
      aliceToken,
      bob,
      {
        title: `chat-route ${Date.now()}`,
        historyAccess: "since_join",
      },
    );
    const alicePage = aliceFlow.page;
    try {
      const defaultStrandId = await resolveDefaultStrandId(request, aliceToken, realmId);
      await gotoChat(alicePage, realmId);
      await expect(
        alicePage.page.getByTestId("channel-item").first(),
      ).toContainText(defaultStrandId);
    } finally {
      await alicePage.close();
    }
  });

  test("reactions converge (OR-Set) and replies render with reply indicator", async ({
    browser,
    request,
  }, testInfo) => {
    // This chain includes three real logins, two invitations and four sealed
    // grants before any reaction is authored. Keep the individual convergence
    // assertions bounded while allowing the complete setup and UI flow to run.
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, `s14-alice-${stamp}`),
      openDpopUserPage(browser, request, `s14-bob-${stamp}`),
      openDpopUserPage(browser, request, `s14-carol-${stamp}`),
    ]);
    if (!aliceFlow || !bobFlow || !carolFlow) {
      assertJointStackNotRequired("chat reactions browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;
    const bob = bobFlow.user;
    const carol = carolFlow.user;

    const m1 = `S14 ship it ${stamp}`;
    const m2 = `S14 yes ship ${stamp}`;
    let diagnosticRealmId: string | undefined;

    try {
      const realmId = await alicePage.createRealm({
        title: `S14 Chat ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
        seedMembers: [bob.id, carol.id],
      });
      diagnosticRealmId = realmId;
      await bobPage.acceptInvite(realmId);
      await carolPage.acceptInvite(realmId);
      for (const member of [bobFlow, carolFlow]) {
        await alicePage.grantRealmCapability(
          realmId,
          member.session.accountId,
          "ak.message.create",
        );
        await alicePage.grantRealmCapability(
          realmId,
          member.session.accountId,
          "ak.reaction.add",
        );
      }

      await sendChat(alicePage, realmId, m1);

      await gotoChat(bobPage, realmId);
      const bobOnM1 = bobPage.page
        .getByTestId("chat-message")
        .filter({ hasText: m1 })
        .first();
      await expect(bobOnM1).toBeVisible({ timeout: 30_000 });
      await bobOnM1.hover();
      await bobOnM1.getByTestId("chat-message-menu-button").click();
      const bobReact = bobOnM1.getByTestId(
        "message-context-react-button",
      );
      await expect(bobReact).toBeVisible({ timeout: 5_000 });
      await bobReact.click();
      const bobPicker = bobPage.page.getByTestId("chat-reaction-picker");
      await expect(bobPicker).toBeVisible();
      await bobPicker.getByRole("button").first().click();
      await expect(bobOnM1.getByTestId("chat-reactions")).toBeVisible({
        timeout: 30_000,
      });

      await gotoChat(carolPage, realmId);
      const carolOnM1 = carolPage.page
        .getByTestId("chat-message")
        .filter({ hasText: m1 })
        .first();
      await expect(carolOnM1).toBeVisible({ timeout: 30_000 });
      await carolOnM1.hover();
      await carolOnM1.getByTestId("chat-message-menu-button").click();
      const carolReact = carolOnM1.getByTestId(
        "message-context-react-button",
      );
      await expect(carolReact).toBeVisible({ timeout: 5_000 });
      await carolReact.click();
      await carolPage.page
        .getByTestId("chat-reaction-picker")
        .getByRole("button")
        .first()
        .click();
      await expect(carolOnM1.getByTestId("chat-reactions")).toBeVisible({
        timeout: 30_000,
      });

      // Alice's tab authored the original message before the peer reactions.
      // Reload to prove both OR-Set additions survive the canonical account
      // projection instead of relying on a best-effort live-subscribe wakeup.
      await alicePage.page.reload({ waitUntil: "domcontentloaded" });
      await gotoChat(alicePage, realmId);
      const aliceOnM1 = alicePage.page
        .getByTestId("chat-message")
        .filter({ hasText: m1 })
        .first();
      await expect(aliceOnM1.getByTestId("chat-reactions")).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(alicePage.page, testInfo, "reactions-converged");

      await gotoChat(bobPage, realmId);
      await bobPage.clickTimelineReply(m1);
      await expect(bobPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await sendChat(bobPage, realmId, m2);
      const bobOnM2 = bobPage.page
        .getByTestId("chat-message")
        .filter({ hasText: m2 })
        .first();
      await expect(bobOnM2.getByTestId("chat-reply-indicator")).toBeVisible();
      await stepShot(bobPage.page, testInfo, "reply-chain");
    } finally {
      if (diagnosticRealmId) {
        for (const [name, page] of [["alice", alicePage], ["bob", bobPage], ["carol", carolPage]] as const) {
          try {
            const diagnostic = await reactionProjectionDiagnostic(page, diagnosticRealmId);
            await testInfo.attach(`safe-reaction-projection-${name}`, {
              contentType: "application/json", body: JSON.stringify(diagnostic),
            });
          } catch {
            await testInfo.attach(`safe-reaction-projection-${name}`, {
              contentType: "application/json", body: JSON.stringify({ unavailable: true }),
            });
          }
        }
      }
      await Promise.allSettled([
        carolPage.close(),
        bobPage.close(),
        alicePage.close(),
      ]);
    }
  });

  test("E14.D mentions route notifications only to the mentioned actor", async ({
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    browser,
    request,
  }, testInfo) => {
    // spec: discovery/push-notifications.md §4.3.1 mention_routing_hint
    const stamp = Date.now();
    const [aliceFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, `s14d-alice-${stamp}`),
      openDpopUserPage(browser, request, `s14d-bob-${stamp}`),
      openDpopUserPage(browser, request, `s14d-carol-${stamp}`),
    ]);
    if (!aliceFlow || !bobFlow || !carolFlow) {
      assertJointStackNotRequired("chat mention notification browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const carol = carolFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;
    const aliceToken = await issueUserSession(request, alice);

    const mentionSuffix = `can you review the incident note? ${stamp}`;
    const apiActorSeq = 8_000_000_300_000_000 + (stamp % 100_000);
    let mention = "";

    try {
      const realmId = await alicePage.createRealm({
        title: `S14D Mention ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        mlsActivated: false,
        seedMembers: [bob.id, carol.id],
      });
      await alicePage.grantRealmCapability(
        realmId,
        aliceFlow.session.accountId,
        "ak.message.create",
      );
      await Promise.all([
        bobPage.acceptInvite(realmId),
        carolPage.acceptInvite(realmId),
      ]);

      mention = mentionSuffix;
      await sendMessageApi(request, aliceToken, realmId, mention, {
        mentions: [bob.id],

      });
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("message-list")).toContainText(
        mention,
        { timeout: 30_000 },
      );
      await stepShot(alicePage.page, testInfo, "mention-sent");

      await bobPage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      await expect(bobPage.page.getByTestId("notifications-panel")).toBeVisible(
        {
          timeout: 30_000,
        },
      );
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: mention }),
      ).toBeVisible({ timeout: 30_000 });
      await expect(
        bobPage.page
          .getByTestId("notification-item")
          .filter({ hasText: /mention/i }),
      ).toBeVisible({ timeout: 30_000 });

      await carolPage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      await expect(
        carolPage.page.getByTestId("notifications-panel"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        carolPage.page
          .getByTestId("notification-item")
          .filter({ hasText: mention }),
      ).toHaveCount(0);
      await stepShot(bobPage.page, testInfo, "mention-notification-routed");
    } finally {
      await Promise.allSettled([
        carolPage.close(),
        bobPage.close(),
        alicePage.close(),
      ]);
    }
  });

  test("E14.E poll create + vote + close (vote replacement per actor)", async ({
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    // @expected-live-by: 2026Q3
    browser,
    request,
  }, testInfo) => {
    // spec: models/content-types.md §4.9 polls
    // coland projects poll content state; inkson hydrates poll cards from sync/backfill.
    test.setTimeout(420_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, "s14e-alice"),
      openDpopUserPage(browser, request, "s14e-bob"),
      openDpopUserPage(browser, request, "s14e-carol"),
    ]);
    if (!aliceFlow || !bobFlow || !carolFlow) {
      assertJointStackNotRequired("poll browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;
    const bob = bobFlow.user;
    const carol = carolFlow.user;

    const question = `Which rollout window should we use? ${stamp}`;
    const optionA = `Now ${stamp}`;
    const optionB = `After backup ${stamp}`;

    try {
      const realmId = await alicePage.createRealm({
        title: `S14E Poll ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        // content-types section 4.9 permits formal polls only in plaintext.
        mlsActivated: false,
        seedMembers: [bob.id, carol.id],
      });
      await Promise.all([
        bobPage.acceptInvite(realmId),
        carolPage.acceptInvite(realmId),
      ]);

      for (const member of [bobFlow, carolFlow]) {
        await alicePage.grantRealmCapability(
          realmId,
          member.session.accountId,
          "ak.message.create",
        );
      }
      await gotoChat(alicePage, realmId);
      await alicePage.page.getByTestId("open-poll-composer-button").click();
      await alicePage.page.getByTestId("poll-question-input").fill(question);
      await alicePage.page
        .getByTestId("poll-option-input")
        .nth(0)
        .fill(optionA);
      await alicePage.page
        .getByTestId("poll-option-input")
        .nth(1)
        .fill(optionB);
      await alicePage.page.getByTestId("send-poll-button").click();
      const poll = alicePage.page
        .getByTestId("poll-card")
        .filter({ hasText: question })
        .first();
      await expect(poll).toBeVisible({ timeout: 30_000 });
      await expect(poll).toHaveAttribute("data-poll-id", /^ak:message:/, { timeout: 60_000 });
      await stepShot(alicePage.page, testInfo, "poll-created");

      await gotoChat(bobPage, realmId);
      const bobPoll = bobPage.page
        .getByTestId("poll-card")
        .filter({ hasText: question })
        .first();
      await bobPoll
        .getByTestId("poll-option")
        .filter({ hasText: optionA })
        .click();
      await expect(
        bobPoll.getByTestId("poll-result-row").filter({ hasText: optionA }).getByTestId("poll-vote-count"),
      ).toHaveText("1");

      // Vote replacement: bob switches from optionA to optionB; optionA count
      // drops back to zero and optionB becomes bob's single vote.
      await bobPoll
        .getByTestId("poll-option")
        .filter({ hasText: optionB })
        .click();
      await expect(
        bobPoll.getByTestId("poll-result-row").filter({ hasText: optionA }).getByTestId("poll-vote-count"),
      ).toHaveText("0");
      await expect(
        bobPoll.getByTestId("poll-result-row").filter({ hasText: optionB }).getByTestId("poll-vote-count"),
      ).toHaveText("1");

      await gotoChat(carolPage, realmId);
      const carolPoll = carolPage.page
        .getByTestId("poll-card")
        .filter({ hasText: question })
        .first();
      await carolPoll
        .getByTestId("poll-option")
        .filter({ hasText: optionB })
        .click();
      await expect(
        carolPoll.getByTestId("poll-result-row").filter({ hasText: optionB }).getByTestId("poll-vote-count"),
      ).toHaveText("2");

      await gotoChat(alicePage, realmId);
      await poll.getByTestId("poll-close-button").click();
      await expect(poll.getByTestId("poll-state")).toContainText(/closed/i, {
        timeout: 30_000,
      });
      await expect(poll.getByTestId("poll-option")).toHaveCount(0);
      await stepShot(alicePage.page, testInfo, "poll-closed");
    } finally {
      await Promise.allSettled([
        carolPage.close(),
        bobPage.close(),
        alicePage.close(),
      ]);
    }
  });

  test("E14.F typing indicator (ak.typing ephemeral) appears in peer view within 1s and clears after ttl_ms=5000", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: profiles-presence.md §3.5
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, `s14f-alice-${stamp}`),
      openDpopUserPage(browser, request, `s14f-bob-${stamp}`),
    ]);
    if (!aliceFlow || !bobFlow) {
      await Promise.allSettled([
        aliceFlow?.page.close(),
        bobFlow?.page.close(),
      ]);
      assertJointStackNotRequired("typing indicator DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      for (const flow of [aliceFlow, bobFlow]) {
        expect(Boolean(flow.session.recoveryKey), "Signal sender retains its confirmed Recovery Key").toBe(true);
        await flow.page.completeMlsAccountRecoveryIfPrompted(flow.session.recoveryKey!);
      }
      const realmId = await alicePage.createRealm({
        title: `S14F Typing ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.id],
        mlsActivated: true,
      });
      await alicePage.completeMlsAccountRecoveryIfPrompted(aliceFlow.session.recoveryKey!);
      await bobPage.acceptInvite(realmId);
      await bobPage.completeMlsAccountRecoveryIfPrompted(bobFlow.session.recoveryKey!);
      await Promise.all([
        gotoChat(alicePage, realmId),
        gotoChat(bobPage, realmId),
      ]);

      // Bidirectional encrypted presence proves both Signal receivers and
      // current MLS key material are ready before measuring a typing burst.
      for (const [page, peer] of [[alicePage, bob], [bobPage, alice]] as const) {
        await expect(page.page.locator(
          `[data-testid="presence-row"][data-actor-id=${JSON.stringify(canonicalJson(accountActorId(peer.id)))}]`,
        )).toContainText(/online/i, { timeout: 90_000 });
      }
      await alicePage.page.getByTestId("chat-input").fill(`draft ${stamp}`);
      const aliceTypingIndicator = bobPage.page.locator(
        `[data-testid="typing-indicator"][data-typing-actors*="${cssStringEscape(alice.id)}"]`,
      );
      await expect(aliceTypingIndicator).toBeVisible({ timeout: 5_000 });
      await stepShot(bobPage.page, testInfo, "typing-visible");
      await expect(aliceTypingIndicator).toHaveCount(0, { timeout: 7_000 });
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });

  test("E14.G presence state propagates online/offline within 1s after page open/close", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: profiles-presence.md §3.2-§3.4
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, `s14g-alice-${stamp}`),
      openDpopUserPage(browser, request, `s14g-bob-${stamp}`),
    ]);
    if (!aliceFlow || !bobFlow) {
      await Promise.allSettled([
        aliceFlow?.page.close(),
        bobFlow?.page.close(),
      ]);
      assertJointStackNotRequired("presence propagation DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bob = bobFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;

    try {
      for (const flow of [aliceFlow, bobFlow]) {
        expect(Boolean(flow.session.recoveryKey), "Presence sender retains its confirmed Recovery Key").toBe(true);
        await flow.page.completeMlsAccountRecoveryIfPrompted(flow.session.recoveryKey!);
      }
      const realmId = await alicePage.createRealm({
        title: `S14G Presence ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.id],
        mlsActivated: true,
      });
      await alicePage.completeMlsAccountRecoveryIfPrompted(aliceFlow.session.recoveryKey!);
      await bobPage.acceptInvite(realmId);
      await bobPage.completeMlsAccountRecoveryIfPrompted(bobFlow.session.recoveryKey!);
      await Promise.all([
        gotoChat(alicePage, realmId),
        gotoChat(bobPage, realmId),
      ]);

      const bobPresenceRow = alicePage.page.locator(
        `[data-testid="presence-row"][data-actor-id=${JSON.stringify(canonicalJson(accountActorId(bob.id)))}]`,
      );
      await expect(bobPresenceRow).toContainText(/online/i, { timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "presence-online");

      await bobPage.close();
      await expect(bobPresenceRow).toContainText(/offline|last seen/i, { timeout: 45_000 });
    } finally {
      await Promise.allSettled([alicePage.close()]);
    }
  });

  test(// @user-promise: e2e/scenarios/messaging/chat-advanced.md
  "E14.2 encrypted mentions stay in ciphertext; dedicated mention routing is rejected", async ({
    browser,
    request,
  }, testInfo) => {
    // push-notifications.md §4.5(6): mentions stay encrypted; no routing sidecar.
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, `s142-alice-${stamp}`),
      openDpopUserPage(browser, request, `s142-bob-${stamp}`),
    ]);
    if (!aliceFlow || !bobFlow) {
      await Promise.allSettled([aliceFlow?.page.close(), bobFlow?.page.close()]);
      assertJointStackNotRequired("encrypted mention DPoP login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    try {
      for (const flow of [aliceFlow, bobFlow]) {
        expect(Boolean(flow.session.recoveryKey), "mention sender retains its confirmed Recovery Key").toBe(true);
        await flow.page.completeMlsAccountRecoveryIfPrompted(flow.session.recoveryKey!);
      }
      const realmId = await alicePage.createRealm({
        title: `S14.2 E2EE Mention ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        mlsActivated: true,
        seedMembers: [bobFlow.user.id],
      });
      await alicePage.completeMlsAccountRecoveryIfPrompted(aliceFlow.session.recoveryKey!);
      await bobPage.acceptInvite(realmId);
      await bobPage.completeMlsAccountRecoveryIfPrompted(bobFlow.session.recoveryKey!);
      await Promise.all([gotoChat(alicePage, realmId), gotoChat(bobPage, realmId)]);
      await expect(alicePage.page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 90_000 });
      const submitted = alicePage.page.waitForResponse(
        (response) => response.url().includes("/_arkret/self/events")
          && response.request().method() === "POST"
          && (response.request().postData() ?? "").includes("ak.message.create"),
        { timeout: 90_000 },
      );
      // Preserve the primary UI failure if its response waiter also expires;
      // awaiting the original Promise below still propagates that rejection.
      void submitted.catch(() => undefined);
      const suffix = `Encrypted mention ${stamp}`;
      const body = await alicePage.sendTimelineMentionMessage(
        realmId,
        bobFlow.session.accountId.principal_id,
        bobFlow.session.accountId.station_id,
        suffix,
      );
      const response = await submitted;
      expect([200, 201]).toContain(response.status());
      const envelope = JSON.parse(response.request().postData()!).event as Record<string, unknown>;
      const payload = envelope.payload as Record<string, unknown>;
      expect(payload.encrypted_content).toBeTruthy();
      expect(payload.content).toBeUndefined();
      expect(payload.mention_sidecar_digest).toBeUndefined();
      const rawSubmission = JSON.stringify(envelope);
      expect(rawSubmission).not.toContain(bobFlow.user.id);
      expect(rawSubmission).not.toContain(suffix);
      await gotoChat(bobPage, realmId);
      await expect(bobPage.timelineEvent(body)).toBeVisible({ timeout: 120_000 });

      const aliceToken = await issueUserSession(request, aliceFlow.user);
      const events = await listRealmEventsViaApi(request, aliceToken, realmId, { limit: 100 });
      const messageEvent = events.find((event) => event.event_id === envelope.event_id);
      expect(messageEvent, "accepted encrypted mention event").toBeTruthy();
      const rawServerView = JSON.stringify(messageEvent);
      expect(rawServerView).not.toContain(bobFlow.user.id);
      expect(rawServerView).not.toContain(suffix);
      expect(rawServerView).not.toContain("mention_sidecar_digest");

      // Reuse valid MLS payload bytes and change only the forbidden routing
      // carrier. The server must reject it without publishing a second Event.
      const forbidden = signedEventEnvelope({
        actorId: aliceFlow.user.id,
        realmId,
        kind: "ak.message.create",
        payload: { ...payload, mention_sidecar_digest: ["00".repeat(32)] },
      });
      const eventsUrl = `${colandBaseUrl()}/_arkret/self/events`;
      const rejected = await request.post(eventsUrl, {
        headers: { ...authHeaders(aliceToken, "POST", eventsUrl), "content-type": "application/json" },
        data: canonicalJson({ event: forbidden }),
      });
      expect(rejected.status()).toBe(422);
      expect((await rejected.json()).type).toBe("https://arkret.org/problems/schema_violation");
      const after = await listRealmEventsViaApi(request, aliceToken, realmId, { limit: 100 });
      expect(after.some((event) => event.event_id === forbidden.event_id)).toBe(false);
      await stepShot(bobPage.page, testInfo, "encrypted-mention-without-routing-sidecar");
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });
});


async function createChatApiFixture(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  return await createTwoUserMessagingRealm(request, {
    label,
    title: `${label} ${stamp}`,
    realm: {
      historyAccess: "all_history_for_current_members",
    },
  });
}
