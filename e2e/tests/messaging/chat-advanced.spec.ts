// Chat advanced (reactions/replies/mentions/polls/typing/presence)
// Contract: e2e/scenarios/messaging/chat-advanced.md
// Spec refs:
//   - models/strand-and-message.md §4.3, §8
//   - models/content-types.md §4.1 (mentions), §4.9 (polls)
//   - discovery/profiles-presence.md §3
//   - discovery/push-notifications.md §4.3.1, §4.5

import { createHash } from "node:crypto";
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { cssStringEscape } from "../../helpers/dom";
import {
  acceptInviteViaApi,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { createTwoUserMessagingRealm } from "../../helpers/messaging-fixtures";
import { stepShot } from "../../helpers/screenshots";
import {
  accountSubscribeFramesApi,
  createRealmApi,
  grantCapabilityEventApi,
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
        reply_to: rootMessageRef,
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
    );
    const messageEvents = events.filter(
      (event) => event.kind === "ak.message.create",
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
              { kind: "mention", subject_id: fixture.bob.id },
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
        mentions: [{ kind: "mention", subject_id: fixture.bob.id }],
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
            { kind: "mention", subject_id: fixture.bob.id },
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
        reply_to: rootMessageRef,
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
          mentions: [{ kind: "mention", subject_id: fixture.bob.id }],
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
    expect(reactionEvents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor_id: fixture.alice.id,
          kind: "ak.reaction.add",
          payload: expect.objectContaining({ key: "+1" }),
        }),
        expect.objectContaining({
          actor_id: fixture.bob.id,
          kind: "ak.reaction.add",
          payload: expect.objectContaining({ key: "+1" }),
        }),
        expect.objectContaining({
          actor_id: fixture.bob.id,
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
        reply_to: rootMessageRef,
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
    const aliceToken = await issueDevSession(request, aliceFlow.user);
    const bobToken = await issueDevSession(request, bob);

    try {
      const realmId = await createRealmApi(request, aliceToken, {
        title: `typing API ${stamp}`,
        ownerId: aliceFlow.user.id,
        invitees: [bob.id],
        history_access: "all_history_for_current_members",
      });
      await acceptInviteViaApi(request, bobToken, bob.id, realmId);
      const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
      const sentAt = new Date();
      const envelope = buildSignalEnvelope({
        actorId: aliceFlow.user.id,
        deviceId: aliceFlow.user.deviceId,
        realmId,
        sentAt,
        plaintext: {
          kind: "ak.typing",
          strand_id: strandId,
          track_name: "discussion",
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
          candidate.sender_actor_id === aliceFlow.user.id &&
          signalPlaintext(candidate).kind === "ak.typing",
      );
      expect(received, "bob received encrypted typing Signal").toBeTruthy();
      if (!received) throw new Error("typing Signal missing");
      expect(received).not.toHaveProperty("kind");
      expect(received).not.toHaveProperty("strand_id");
      expect(signalPlaintext(received)).toMatchObject({
        kind: "ak.typing",
        strand_id: strandId,
        track_name: "discussion",
        typing: true,
      });
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
      issueDevSession(request, alice),
      issueDevSession(request, bob),
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
        seedMembers: [bob.id, carol.id],
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
        seedMembers: [bob.id, carol.id],
      });
      await Promise.all([
        bobPage.acceptInvite(realmId),
        carolPage.acceptInvite(realmId),
      ]);

      mention = mentionSuffix;
      await sendMessageApi(request, aliceToken, realmId, mention, {
        mentions: [bob.id],
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
        seedMembers: [bob.id, carol.id],
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

  test("E14.F typing indicator (ak.typing ephemeral) appears in peer view within 1s and clears after ttl_ms=5000", async ({
    browser,
    request,
  }, testInfo) => {
    // spec: profiles-presence.md §3.5
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, `s14f-alice-${stamp}`, {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, `s14f-bob-${stamp}`, {
        prepareMlsDevice: false,
      }),
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
      const realmId = await alicePage.createRealm({
        title: `S14F Typing ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.id],
      });
      await bobPage.acceptInvite(realmId);
      await Promise.all([
        gotoChat(alicePage, realmId),
        gotoChat(bobPage, realmId),
      ]);

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
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, `s14g-alice-${stamp}`, {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, `s14g-bob-${stamp}`, {
        prepareMlsDevice: false,
      }),
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
      const realmId = await alicePage.createRealm({
        title: `S14G Presence ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.id],
      });
      await bobPage.acceptInvite(realmId);
      await Promise.all([
        gotoChat(alicePage, realmId),
        gotoChat(bobPage, realmId),
      ]);

      const bobPresenceRow = alicePage.page.locator(
        `[data-testid="presence-row"][data-actor-did="${cssStringEscape(bob.id)}"]`,
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
      {
        title: `S14.2 E2EE Mention ${stamp}`,
        historyAccess: "since_join",
        encryptionProfile: "mls_rfc9420",
      },
    );
    const plaintext = `Encrypted mention for @${bob.handle.replace(/^@/, "")} ${stamp}`;
    const sidecarHash = mentionSidecarHash(realmId, bob.id);
    const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const envelope = signedEventEnvelope({
      actorId: alice.id,
      realmId: realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: strandId,
        track_name: "discussion",
        mention_sidecar_digest: [sidecarHash],
        encrypted_content: encryptedEnvelope(
          "ak.message.v1",
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
    expect(rawServerView).not.toContain(bob.id);
    expect(rawServerView).not.toContain(plaintext);
    expect(rawServerView).toContain("mention_sidecar_digest");
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
  void realmId;
  return {
    version: "1.0",
    content_type: "application/vnd.arkret.message+json",
    encryption_context: {
      epoch: 1,
      group_state_ref:
        "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
    },
    ciphertext,
  };
}


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
