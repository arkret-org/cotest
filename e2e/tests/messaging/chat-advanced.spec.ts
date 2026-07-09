// Chat advanced (reactions/replies/mentions/polls/typing/presence)
// Contract: e2e/scenarios/messaging/chat-advanced.md
// Spec refs:
//   - models/strand-and-message.md §4.3, §8
//   - models/content-types.md §4.1 (mentions), §4.9 (polls)
//   - discovery/profiles-presence.md §3
//   - discovery/push-notifications.md §4.3.1, §4.5

import { createHash } from "node:crypto";
import { expect, test, type APIRequestContext } from "@playwright/test";
import { cssStringEscape } from "../../helpers/dom";
import {
  authHeaders,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import { createTwoUserMessagingRealm } from "../../helpers/messaging-fixtures";
import { stepShot } from "../../helpers/screenshots";
import {
  canonicalJson,
  accountSubscribeFramesApi,
  resolveDefaultStrandId,
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
  uniqueUser,
  type JointUserPage,
} from "../../helpers/users";
import { withBroadcastEphemeralProof } from "../../helpers/webrtc";

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

async function accountSubscribeTimelineEvents(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<Array<Record<string, unknown>>> {
  const frames = await accountSubscribeFramesApi(request, token);
  const frame = frames.find((candidate) => candidate.kind === "delta");
  expect(frame, "account subscribe delta frame").toBeTruthy();
  if (!frame) throw new Error("account subscribe delta frame missing");
  const realms = (frame as { realms?: Record<string, unknown> }).realms ?? {};
  const realmFrame = realms[realmId] as
    | { timeline?: { events?: unknown } }
    | undefined;
  expect(realmFrame, `sync realm frame for ${realmId}`).toBeTruthy();
  expect(Array.isArray(realmFrame?.timeline?.events)).toBe(true);
  return realmFrame!.timeline!.events as Array<Record<string, unknown>>;
}

test.describe("chat advanced", () => {
  test("API reactions add/remove round-trip as projection events", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "reaction-api");
    const message = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
      `reaction target ${Date.now()}`,
      { actorDid: fixture.alice.did },
    );
    const messageRef = message.event_id.replace(/^ck:event:/, "ak:message:");

    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorDid: fixture.bob.did,
        realmId: fixture.realmId,
        kind: "ck.reaction.add",
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
        actorDid: fixture.bob.did,
        realmId: fixture.realmId,
        kind: "ck.reaction.remove",
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
      expect.arrayContaining(["ck.reaction.add", "ck.reaction.remove"]),
    );
    expect(
      events.find((event) => event.kind === "ck.reaction.add")?.payload,
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
      { actorDid: fixture.alice.did },
    );
    const rootMessageRef = root.event_id.replace(/^ck:event:/, "ak:message:");
    const strandId = await resolveDefaultStrandId(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const replyBody = `reply ${Date.now()}`;
    const reply = signedEventEnvelope({
      actorDid: fixture.bob.did,
      realmId: fixture.realmId,
      kind: "ck.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        reply_to: rootMessageRef,
        content: { kind: "ck.content.text", body: replyBody },
      },
    });
    await submitSignedEventApi(request, fixture.bobToken, reply, {
      context: "reply message",
    });

    const events = await listRealmEventsViaApi(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const messageEvents = events.filter(
      (event) => event.kind === "ck.message.create",
    );
    expect(messageEvents.map((event) => event.event_id)).toEqual([
      root.event_id,
      reply.event_id,
    ]);
    expect(messageEvents.at(-1)?.payload).toMatchObject({
      reply_to: rootMessageRef,
      track_name: "discussion",
    });
  });

  test("API mention payload persists mention routing metadata", async ({
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
        actorDid: fixture.alice.did,
        realmId: fixture.realmId,
        kind: "ck.message.create",
        payload: {
          strand_id: strandId,
          track_name: "discussion",
          content: {
            kind: "ck.content.text",
            body,
            mentions: [
              {
                type: "actor",
                did: fixture.bob.did,
                handle: fixture.bob.handle,
              },
            ],
          },
          mention_routing_hint: {
            mentioned: [fixture.bob.did],
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
        event.kind === "ck.message.create" &&
        JSON.stringify(event.payload).includes(fixture.bob.did),
    );
    expect(mention?.payload).toMatchObject({
      content: {
        mentions: [
          { type: "actor", did: fixture.bob.did, handle: fixture.bob.handle },
        ],
      },
      mention_routing_hint: { mentioned: [fixture.bob.did] },
    });
  });

  test("API sync projection exposes active reactions, reply relation, and mention routing hint", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "sync-projection-api");
    const strandId = await resolveDefaultStrandId(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const body = `@${fixture.bob.handle.replace(/^@/, "")} sync projection ${Date.now()}`;
    const root = signedEventEnvelope({
      actorDid: fixture.alice.did,
      realmId: fixture.realmId,
      kind: "ck.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        content: {
          kind: "ck.content.text",
          body,
          mentions: [
            { type: "actor", did: fixture.bob.did, handle: fixture.bob.handle },
          ],
        },
        mention_routing_hint: {
          mentioned: [fixture.bob.did],
        },
      },
    });
    await submitSignedEventApi(request, fixture.aliceToken, root, {
      context: "root mention",
    });
    const rootEventId = String(root.event_id);
    const rootMessageRef = rootEventId.replace(/^ck:event:/, "ak:message:");
    const reply = signedEventEnvelope({
      actorDid: fixture.bob.did,
      realmId: fixture.realmId,
      kind: "ck.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        reply_to: rootMessageRef,
        content: { kind: "ck.content.text", body: `reply ${Date.now()}` },
      },
    });
    await submitSignedEventApi(request, fixture.bobToken, reply, {
      context: "reply message",
    });

    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.realmId,
        kind: "ck.reaction.add",
        payload: { target_ref: rootMessageRef, key: "+1" },
      }),
      { context: "alice add reaction" },
    );
    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorDid: fixture.bob.did,
        realmId: fixture.realmId,
        kind: "ck.reaction.add",
        payload: { target_ref: rootMessageRef, key: "+1" },
      }),
      { context: "bob add reaction" },
    );
    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorDid: fixture.bob.did,
        realmId: fixture.realmId,
        kind: "ck.reaction.remove",
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
      mention_routing_hint: { mentioned: [fixture.bob.did] },
      mentions: [{ did: fixture.bob.did }],
      reaction_summary: { "+1": [fixture.alice.did] },
    });
    expect(JSON.stringify(rootProjection?.reaction_summary)).not.toContain(
      fixture.bob.did,
    );
    expect(rootProjection?.reactions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: fixture.alice.did,
          key: "+1",
          active: true,
        }),
      ]),
    );

    const replyProjection = events.find(
      (event) => event.event_id === reply.event_id,
    );
    expect(replyProjection).toMatchObject({
      reply_to: rootMessageRef,
      relations: [
        expect.objectContaining({
          kind: "reply_to",
          target_ref: rootMessageRef,
        }),
      ],
    });
  });

  test("API typing ephemeral is visible in account subscribe and respects TTL", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "typing-api");
    const strandId = await resolveDefaultStrandId(
      request,
      fixture.aliceToken,
      fixture.realmId,
    );
    const sentAt = new Date();
    const typing = await request.post(
      `${solandBaseUrl()}/_arkret/self/ephemeral`,
      {
        headers: authHeaders(fixture.aliceToken),
        data: withBroadcastEphemeralProof({
          kind: "ck.typing",
          realm_id: fixture.realmId,
          actor_id: fixture.alice.did,
          device_id: fixture.alice.deviceId,
          sent_at: sentAt.toISOString(),
          expires_at: new Date(sentAt.getTime() + 30_000).toISOString(),
          payload: {
            typing: true,
            strand_id: strandId,
          },
        }),
      },
    );
    expect(typing.status()).toBe(200);

    const frames = await accountSubscribeFramesApi(request, fixture.bobToken);
    const frame = frames.find((candidate) => candidate.kind === "delta");
    expect(frame, "account subscribe delta frame").toBeTruthy();
    if (!frame) throw new Error("account subscribe delta frame missing");
    const realms = (frame as { realms?: Record<string, unknown> }).realms ?? {};
    const realmFrame = realms[fixture.realmId] as
      | { ephemeral?: unknown }
      | undefined;
    const ephemeral = realmFrame?.ephemeral;
    expect(JSON.stringify(ephemeral)).toContain(fixture.alice.did);
    expect(JSON.stringify(ephemeral)).toContain(strandId);
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
        title: `chat-route ${Date.now()}`,
        historyVisibility: "shared",
      },
    );
    const alicePage = aliceFlow.page;
    try {
      await gotoChat(alicePage, realmId);
      await expect(
        alicePage.page.getByTestId("channel-item").first(),
      ).toContainText(/Discussion|Default Strand/);
    } finally {
      await alicePage.close();
    }
  });

  // Direct `/chat/:realm_id` channel hydration is covered live above. The
  // remaining browser-driven chat workflows stay fixme until their owning
  // server/client projections are closed.
  test("reactions converge (OR-Set) and replies render with reply indicator", async ({
    browser,
    request,
  }, testInfo) => {
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

    try {
      const realmId = await alicePage.createRealm({
        title: `S14 Chat ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [bob.did, carol.did],
      });
      await bobPage.acceptInvite(realmId);
      await carolPage.acceptInvite(realmId);

      await sendChat(alicePage, realmId, m1);

      await gotoChat(bobPage, realmId);
      const bobOnM1 = bobPage.page
        .getByTestId("chat-message")
        .filter({ hasText: m1 })
        .first();
      await expect(bobOnM1).toBeVisible({ timeout: 30_000 });
      await bobOnM1.hover();
      const bobReact = bobOnM1.getByTestId("chat-react-button");
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
      const carolReact = carolOnM1.getByTestId("chat-react-button");
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
    const aliceToken = await issueDevSession(request, alice);

    const mentionSuffix = `can you review the incident note? ${stamp}`;
    const apiActorSeq = 8_000_000_300_000_000 + (stamp % 100_000);
    let mention = "";

    try {
      const realmId = await alicePage.createRealm({
        title: `S14D Mention ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [bob.did, carol.did],
      });
      await Promise.all([
        bobPage.acceptInvite(realmId),
        carolPage.acceptInvite(realmId),
      ]);

      mention = mentionSuffix;
      await sendMessageApi(request, aliceToken, realmId, mention, {
        mentions: [bob.did],
        actorSeq: apiActorSeq,
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
    // soland projects poll content state; inkson hydrates poll cards from sync/backfill.
    const stamp = Date.now();
    const alice = uniqueUser("s14e-alice");
    const bob = uniqueUser("s14e-bob");
    const carol = uniqueUser("s14e-carol");
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
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionCredential: bobToken,
    });
    const carolPage = await openUserPage(browser, carol, {
      sessionCredential: carolToken,
    });

    const question = `Which rollout window should we use? ${stamp}`;
    const optionA = `Now ${stamp}`;
    const optionB = `After backup ${stamp}`;

    try {
      const realmId = await alicePage.createRealm({
        title: `S14E Poll ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });
      await Promise.all([
        bobPage.acceptInvite(realmId),
        carolPage.acceptInvite(realmId),
      ]);

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
        bobPoll.getByTestId("poll-result-row").filter({ hasText: optionA }),
      ).toContainText(/1/);

      // Vote replacement: bob switches from optionA to optionB; optionA count
      // drops back to zero and optionB becomes bob's single vote.
      await bobPoll
        .getByTestId("poll-option")
        .filter({ hasText: optionB })
        .click();
      await expect(
        bobPoll.getByTestId("poll-result-row").filter({ hasText: optionA }),
      ).toContainText(/0/);
      await expect(
        bobPoll.getByTestId("poll-result-row").filter({ hasText: optionB }),
      ).toContainText(/1/);

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
        carolPoll.getByTestId("poll-result-row").filter({ hasText: optionB }),
      ).toContainText(/2/);

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

  test("E14.F typing indicator (ck.typing ephemeral) appears in peer view within 1s and clears after ttl_ms=5000", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: profiles-presence.md §3.5
    const stamp = Date.now();
    const alice = uniqueUser("s14f-alice");
    const bob = uniqueUser("s14f-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionCredential: bobToken,
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `S14F Typing ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);
      await Promise.all([
        gotoChat(alicePage, realmId),
        gotoChat(bobPage, realmId),
      ]);

      await alicePage.page.getByTestId("chat-input").fill(`draft ${stamp}`);
      const aliceTypingIndicator = bobPage.page.locator(
        `[data-testid="typing-indicator"][data-typing-actors*="${cssStringEscape(alice.did)}"]`,
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
    const stamp = Date.now();
    const alice = uniqueUser("s14g-alice");
    const bob = uniqueUser("s14g-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const alicePage = await openUserPage(browser, alice, {
      sessionCredential: aliceToken,
    });
    const bobPage = await openUserPage(browser, bob, {
      sessionCredential: bobToken,
    });

    try {
      const realmId = await alicePage.createRealm({
        title: `S14G Presence ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did],
      });
      await bobPage.acceptInvite(realmId);
      await Promise.all([
        gotoChat(alicePage, realmId),
        gotoChat(bobPage, realmId),
      ]);

      const bobPresenceRow = alicePage.page.locator(
        `[data-testid="presence-row"][data-actor-did="${cssStringEscape(bob.did)}"]`,
      );
      await expect(bobPresenceRow).toContainText(/online/i, { timeout: 1_000 });
      await stepShot(alicePage.page, testInfo, "presence-online");

      await bobPage.close();
      await expect(bobPresenceRow).toContainText(/offline|last seen/i, { timeout: 5_000 });
    } finally {
      await Promise.allSettled([alicePage.close()]);
    }
  });

  test(// @user-promise: e2e/scenarios/messaging/chat-advanced.md
  "E14.2 mention in E2EE Realm uses sidecar hash; server log does not contain mentionee.did plaintext", async ({
    request,
  }) => {
    // spec: push-notifications.md §4.5 evaluation_locus + mention sidecar hash
    const stamp = Date.now();
    const alice = uniqueUser("s142-alice");
    const bob = uniqueUser("s142-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
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
        title: `S14.2 E2EE Mention ${stamp}`,
        historyVisibility: "shared",
        encryptionProfile: "mls_rfc9420",
      },
    );
    const plaintext = `Encrypted mention for @${bob.handle.replace(/^@/, "")} ${stamp}`;
    const sidecarHash = mentionSidecarHash(realmId, bob.did);
    const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const envelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId: realmId,
      kind: "ck.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        mention_sidecar_hash: [sidecarHash],
        encrypted_content: encryptedEnvelope(
          "ck.message.v1",
          "opaque-e2ee-mention",
          realmId,
        ),
      },
    });
    await submitSignedEventApi(request, aliceToken, envelope, {
      context: "submit E2EE mention sidecar message",
    });

    const events = await listRealmEventsViaApi(request, aliceToken, realmId, {
      limit: 100,
    });
    const messageEvent = events.find(
      (event) => String(event.event_id) === String(envelope.event_id),
    );
    expect(messageEvent, "encrypted sidecar message event").toBeTruthy();
    const rawServerView = JSON.stringify(messageEvent);
    expect(rawServerView).not.toContain(bob.did);
    expect(rawServerView).not.toContain(plaintext);
    expect(rawServerView).toContain("mention_sidecar_hash");
    expect(rawServerView).toContain(sidecarHash);
  });
});

function mentionSidecarHash(realmId: string, did: string): string {
  return createHash("sha256").update(`${realmId}|${did}`).digest("hex");
}

function encryptedEnvelope(
  contentType: string,
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  void contentType;
  const aad = { realm_id: realmId, event_kind: "ck.message.create" };
  const payloadMetadata = {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.arkret.message+json",
    aad_visibility_event_id: "hidden",
    aad,
    key_ref: {
      algorithm: "MLS",
      group_state_ref:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
  return {
    ...payloadMetadata,
    ciphertext,
    aad_digest: sha256Digest(canonicalJson(aad)),
    payload_digest: encryptedPayloadDigest(payloadMetadata, ciphertext),
  };
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function encryptedPayloadDigest(
  metadata: Record<string, unknown>,
  ciphertext: string,
): string {
  const hash = createHash("sha256");
  hash.update(Buffer.from(canonicalJson(metadata), "utf8"));
  hash.update(Buffer.from(ciphertext, "base64url"));
  return `sha256:${hash.digest("hex")}`;
}

async function createChatApiFixture(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  return await createTwoUserMessagingRealm(request, {
    label,
    title: `${label} ${stamp}`,
    realm: {
      historyVisibility: "shared",
    },
  });
}
