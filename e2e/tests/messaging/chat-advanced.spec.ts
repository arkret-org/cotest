// Chat advanced (reactions/replies/mentions/polls/typing/presence)
// Contract: e2e/scenarios/messaging/chat-advanced.md
// Spec refs:
//   - models/flow-and-message.md §4.3, §8
//   - models/content-types.md §4.1 (mentions), §4.9 (polls)
//   - discovery/profiles-presence.md §3
//   - discovery/push-notifications.md §4.3.1, §4.5

import { createHash } from "node:crypto";
import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  authHeaders,
  createSharedSpaceViaApi,
  listSpaceEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  flowIdFromRealmId,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

async function gotoChat(page: JointUserPage, spaceId: string) {
  if (!page.page.url().includes(`/chat/${spaceId}`)) {
    await page.page.goto(`/chat/${spaceId}`, { waitUntil: "domcontentloaded" });
  }
  await expect(page.page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
  // Wait for the discussion list to populate at least one channel — yougen's
  // send-chat-button silently no-ops if no selected_channel matches a known
  // channel (chat.rs:2186-2189). Sync hydrates the channel list after mount.
  await expect(page.page.getByTestId("channel-item").first()).toBeVisible({ timeout: 30_000 });
}

async function sendChat(page: JointUserPage, spaceId: string, body: string) {
  await gotoChat(page, spaceId);
  await page.page.getByTestId("chat-input").fill(body);
  await page.page.getByTestId("send-chat-button").click();
  await expect(
    page.page.getByTestId("chat-message").filter({ hasText: body }),
  ).toBeVisible({ timeout: 30_000 });
}

async function accountSubscribeTimelineEvents(
  request: APIRequestContext,
  token: string,
  spaceId: string,
): Promise<Array<Record<string, unknown>>> {
  const subscribe = await request.get(`${solandBaseUrl()}/_cokret/self/account/subscribe?catchup=true`, {
    headers: authHeaders(token),
  });
  expect(subscribe.status()).toBe(200);
  const frame = JSON.parse((await subscribe.text()).trim().split(/\r?\n/)[0]);
  const realmId = spaceId.replace(/^ck:space:/, "ck:realm:");
  const realmFrame = frame.realms[realmId] ?? frame.realms[spaceId];
  expect(realmFrame, `sync realm frame for ${spaceId}`).toBeTruthy();
  expect(Array.isArray(realmFrame.timeline?.events)).toBe(true);
  return realmFrame.timeline.events as Array<Record<string, unknown>>;
}

test.describe("chat advanced", () => {
  test("API reactions add/remove round-trip as projection events", async ({ request }) => {
    const fixture = await createChatApiFixture(request, "reaction-api");
    const message = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.spaceId,
      `reaction target ${Date.now()}`,
      { actorDid: fixture.alice.did },
    );
    const messageRef = message.event_id.replace(/^ck:event:/, "ck:message:");

    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorDid: fixture.bob.did,
        realmId: fixture.spaceId,
        kind: "ck.reaction.add",
        payload: {
          target_ref: messageRef,
          actor: fixture.bob.did,
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
        realmId: fixture.spaceId,
        kind: "ck.reaction.remove",
        payload: {
          target_ref: messageRef,
          actor: fixture.bob.did,
          key: "+1",
        },
      }),
      { context: "remove reaction" },
    );

    const events = await listSpaceEventsViaApi(request, fixture.aliceToken, fixture.spaceId);
    expect(events.map((event) => event.event_kind)).toEqual(
      expect.arrayContaining(["ck.reaction.add", "ck.reaction.remove"]),
    );
    expect(events.find((event) => event.event_kind === "ck.reaction.add")?.payload).toMatchObject({
      target_ref: messageRef,
      actor: fixture.bob.did,
      key: "+1",
    });
  });

  test("API reply messages preserve reply_to and discussion track ordering", async ({ request }) => {
    const fixture = await createChatApiFixture(request, "reply-api");
    const root = await sendPlaintextMessageViaApi(
      request,
      fixture.aliceToken,
      fixture.spaceId,
      `root ${Date.now()}`,
      { actorDid: fixture.alice.did },
    );
    const rootMessageRef = root.event_id.replace(/^ck:event:/, "ck:message:");
    const replyBody = `reply ${Date.now()}`;
    const reply = signedEventEnvelope({
      actorDid: fixture.bob.did,
      realmId: fixture.spaceId,
      kind: "ck.message.create",
      payload: {
        flow_id: flowIdFromRealmId(fixture.spaceId),
        track_name: "discussion",
        thread_id: "discussion",
        reply_to: rootMessageRef,
        content: { kind: "ck.content.text", body: replyBody },
        encrypted: false,
      },
    });
    await submitSignedEventApi(request, fixture.bobToken, reply, { context: "reply message" });

    const events = await listSpaceEventsViaApi(request, fixture.aliceToken, fixture.spaceId);
    const messageEvents = events.filter((event) => event.event_kind === "ck.message.create");
    expect(messageEvents.map((event) => event.event_id)).toEqual([
      root.event_id,
      reply.event_id,
    ]);
    expect(messageEvents.at(-1)?.payload).toMatchObject({
      reply_to: rootMessageRef,
      thread_id: "discussion",
    });
  });

  test("API mention payload persists mention routing metadata", async ({ request }) => {
    const fixture = await createChatApiFixture(request, "mention-api");
    const body = `@${fixture.bob.handle.replace(/^@/, "")} review ${Date.now()}`;
    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.spaceId,
        kind: "ck.message.create",
        payload: {
          flow_id: flowIdFromRealmId(fixture.spaceId),
          track_name: "discussion",
          content: {
            kind: "ck.content.text",
            body,
            mentions: [{ type: "actor", did: fixture.bob.did, handle: fixture.bob.handle }],
          },
          mention_routing_hint: {
            mentioned: [fixture.bob.did],
          },
          encrypted: false,
        },
      }),
      { context: "mention message" },
    );

    const events = await listSpaceEventsViaApi(request, fixture.bobToken, fixture.spaceId);
    const mention = events.find(
      (event) =>
        event.event_kind === "ck.message.create" &&
        JSON.stringify(event.payload).includes(fixture.bob.did),
    );
    expect(mention?.payload).toMatchObject({
      content: {
        mentions: [{ type: "actor", did: fixture.bob.did, handle: fixture.bob.handle }],
      },
      mention_routing_hint: { mentioned: [fixture.bob.did] },
    });
  });

  test("API sync projection exposes active reactions, reply relation, and mention routing hint", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "sync-projection-api");
    const body = `@${fixture.bob.handle.replace(/^@/, "")} sync projection ${Date.now()}`;
    const root = signedEventEnvelope({
      actorDid: fixture.alice.did,
      realmId: fixture.spaceId,
      kind: "ck.message.create",
      payload: {
        flow_id: flowIdFromRealmId(fixture.spaceId),
        track_name: "discussion",
        thread_id: "discussion",
        content: {
          kind: "ck.content.text",
          body,
          mentions: [{ type: "actor", did: fixture.bob.did, handle: fixture.bob.handle }],
        },
        mention_routing_hint: {
          mentioned: [fixture.bob.did],
        },
        encrypted: false,
      },
    });
    await submitSignedEventApi(request, fixture.aliceToken, root, { context: "root mention" });
    const rootEventId = String(root.event_id);
    const rootMessageRef = rootEventId.replace(/^ck:event:/, "ck:message:");
    const reply = signedEventEnvelope({
      actorDid: fixture.bob.did,
      realmId: fixture.spaceId,
      kind: "ck.message.create",
      payload: {
        flow_id: flowIdFromRealmId(fixture.spaceId),
        track_name: "discussion",
        thread_id: "discussion",
        reply_to: rootMessageRef,
        content: { kind: "ck.content.text", body: `reply ${Date.now()}` },
        encrypted: false,
      },
    });
    await submitSignedEventApi(request, fixture.bobToken, reply, { context: "reply message" });

    await submitSignedEventApi(
      request,
      fixture.aliceToken,
      signedEventEnvelope({
        actorDid: fixture.alice.did,
        realmId: fixture.spaceId,
        kind: "ck.reaction.add",
        payload: { target_ref: rootMessageRef, actor: fixture.alice.did, key: "+1" },
      }),
      { context: "alice add reaction" },
    );
    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorDid: fixture.bob.did,
        realmId: fixture.spaceId,
        kind: "ck.reaction.add",
        payload: { target_ref: rootMessageRef, actor: fixture.bob.did, key: "+1" },
      }),
      { context: "bob add reaction" },
    );
    await submitSignedEventApi(
      request,
      fixture.bobToken,
      signedEventEnvelope({
        actorDid: fixture.bob.did,
        realmId: fixture.spaceId,
        kind: "ck.reaction.remove",
        payload: { target_ref: rootMessageRef, actor: fixture.bob.did, key: "+1" },
      }),
      { context: "bob remove reaction" },
    );

    const events = await accountSubscribeTimelineEvents(
      request,
      fixture.aliceToken,
      fixture.spaceId,
    );
    const rootProjection = events.find((event) => event.event_id === rootEventId);
    expect(rootProjection).toMatchObject({
      mention_routing_hint: { mentioned: [fixture.bob.did] },
      mentions: [{ did: fixture.bob.did }],
      reaction_summary: { "+1": [fixture.alice.did] },
    });
    expect(JSON.stringify(rootProjection?.reaction_summary)).not.toContain(fixture.bob.did);
    expect(rootProjection?.reactions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ actor: fixture.alice.did, key: "+1", active: true }),
      ]),
    );

    const replyProjection = events.find((event) => event.event_id === reply.event_id);
    expect(replyProjection).toMatchObject({
      reply_to: rootMessageRef,
      relations: [expect.objectContaining({ kind: "reply_to", target_ref: rootMessageRef })],
    });
  });

  test("API typing ephemeral is visible in account subscribe and respects TTL", async ({
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "typing-api");
    const sentAt = new Date();
    const typing = await request.post(`${solandBaseUrl()}/_cokret/self/ephemeral`, {
      headers: authHeaders(fixture.aliceToken),
      data: {
        kind: "cx.typing",
        realm_id: fixture.spaceId,
        actor_id: fixture.alice.did,
        device_id: fixture.alice.deviceId,
        sent_at: sentAt.toISOString(),
        expires_at: new Date(sentAt.getTime() + 5_000).toISOString(),
        payload: {
          typing: true,
          scope_id: "discussion",
        },
      },
    });
    expect(typing.status()).toBe(200);

    const subscribe = await request.get(`${solandBaseUrl()}/_cokret/self/account/subscribe`, {
      headers: authHeaders(fixture.bobToken),
    });
    expect(subscribe.status()).toBe(200);
    const frame = JSON.parse((await subscribe.text()).trim().split(/\r?\n/)[0]);
    const realmId = fixture.spaceId.replace(/^ck:space:/, "ck:realm:");
    const realmFrame = frame.realms[realmId] ?? frame.realms[fixture.spaceId];
    const ephemeral = realmFrame.ephemeral;
    expect(JSON.stringify(ephemeral)).toContain(fixture.alice.did);
    expect(JSON.stringify(ephemeral)).toContain("discussion");
  });

  test("chat route hydrates the default discussion channel on first mount", async ({
    browser,
    request,
  }) => {
    const fixture = await createChatApiFixture(request, "chat-route");
    const alicePage = await openUserPage(browser, fixture.alice, {
      sessionToken: fixture.aliceToken,
    });
    try {
      await gotoChat(alicePage, fixture.spaceId);
      await expect(alicePage.page.getByTestId("channel-item").first()).toContainText(
        /Discussion|Default Flow/,
      );
    } finally {
      await alicePage.close();
    }
  });

  // Direct `/chat/:space_id` channel hydration is covered live above. The
  // remaining browser-driven chat workflows stay fixme until their owning
  // server/client projections are closed.
  test.fixme(
    // @blocking-on: soland#messaging-chat-advanced-gap
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    // @expected-live-by: 2026Q3
    "reactions converge (OR-Set) and replies render with reply indicator",
    async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s14-alice");
    const bob = uniqueUser("s14-bob");
    const carol = uniqueUser("s14-carol");
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
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

    const m1 = `S14 ship it ${stamp}`;
    const m2 = `S14 yes ship ${stamp}`;

    try {
      const spaceId = await alicePage.createSpace({
        title: `S14 Chat ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });
      await bobPage.acceptInvite(spaceId);
      await carolPage.acceptInvite(spaceId);

      await sendChat(alicePage, spaceId, m1);

      await gotoChat(bobPage, spaceId);
      const bobOnM1 = bobPage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await expect(bobOnM1).toBeVisible({ timeout: 30_000 });
      await bobOnM1.getByTestId("chat-react-button").click();
      const bobPicker = bobPage.page.getByTestId("chat-reaction-picker");
      await expect(bobPicker).toBeVisible();
      await bobPicker.getByRole("button").first().click();
      await expect(bobOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });

      await gotoChat(carolPage, spaceId);
      const carolOnM1 = carolPage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await expect(carolOnM1).toBeVisible({ timeout: 30_000 });
      await carolOnM1.getByTestId("chat-react-button").click();
      await carolPage.page.getByTestId("chat-reaction-picker").getByRole("button").first().click();
      await expect(carolOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });

      await gotoChat(alicePage, spaceId);
      const aliceOnM1 = alicePage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await expect(aliceOnM1.getByTestId("chat-reactions")).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "reactions-converged");

      await gotoChat(bobPage, spaceId);
      const bobOnM1Reload = bobPage.page.getByTestId("chat-message").filter({ hasText: m1 }).first();
      await bobOnM1Reload.getByTestId("chat-reply-button").click();
      await expect(bobPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await sendChat(bobPage, spaceId, m2);
      const bobOnM2 = bobPage.page.getByTestId("chat-message").filter({ hasText: m2 }).first();
      await expect(bobOnM2.getByTestId("chat-reply-indicator")).toBeVisible();
      await stepShot(bobPage.page, testInfo, "reply-chain");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  },
  );

  test("E14.D mentions route notifications only to the mentioned actor", async ({
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    browser,
    request,
  }, testInfo) => {
    // spec: discovery/push-notifications.md §4.3.1 mention_routing_hint
    const stamp = Date.now();
    const alice = uniqueUser("s14d-alice");
    const bob = uniqueUser("s14d-bob");
    const carol = uniqueUser("s14d-carol");
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
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

    const mention = `@${bob.handle.replace(/^@/, "")} can you review the incident note? ${stamp}`;

    try {
      const spaceId = await alicePage.createSpace({
        title: `S14D Mention ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });
      await Promise.all([bobPage.acceptInvite(spaceId), carolPage.acceptInvite(spaceId)]);

      await sendChat(alicePage, spaceId, mention);
      await stepShot(alicePage.page, testInfo, "mention-sent");

      await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
      await expect(bobPage.page.getByTestId("notifications-panel")).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        bobPage.page.getByTestId("notification-item").filter({ hasText: mention }),
      ).toBeVisible({ timeout: 30_000 });
      await expect(
        bobPage.page.getByTestId("notification-item").filter({ hasText: /mention/i }),
      ).toBeVisible({ timeout: 30_000 });

      await carolPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
      await expect(carolPage.page.getByTestId("notifications-panel")).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        carolPage.page.getByTestId("notification-item").filter({ hasText: mention }),
      ).toHaveCount(0);
      await stepShot(bobPage.page, testInfo, "mention-notification-routed");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  });

  test("E14.E poll create + vote + close (vote replacement per actor)", async ({
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    // @expected-live-by: 2026Q3
    browser,
    request,
  }, testInfo) => {
    // spec: models/content-types.md §4.9 polls
    // soland projects poll content state; yougen hydrates poll cards from sync/backfill.
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
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

    const question = `Which rollout window should we use? ${stamp}`;
    const optionA = `Now ${stamp}`;
    const optionB = `After backup ${stamp}`;

    try {
      const spaceId = await alicePage.createSpace({
        title: `S14E Poll ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [bob.did, carol.did],
      });
      await Promise.all([bobPage.acceptInvite(spaceId), carolPage.acceptInvite(spaceId)]);

      await gotoChat(alicePage, spaceId);
      await alicePage.page.getByTestId("open-poll-composer-button").click();
      await alicePage.page.getByTestId("poll-question-input").fill(question);
      await alicePage.page.getByTestId("poll-option-input").nth(0).fill(optionA);
      await alicePage.page.getByTestId("poll-option-input").nth(1).fill(optionB);
      await alicePage.page.getByTestId("send-poll-button").click();
      const poll = alicePage.page.getByTestId("poll-card").filter({ hasText: question }).first();
      await expect(poll).toBeVisible({ timeout: 30_000 });
      await stepShot(alicePage.page, testInfo, "poll-created");

      await gotoChat(bobPage, spaceId);
      const bobPoll = bobPage.page.getByTestId("poll-card").filter({ hasText: question }).first();
      await bobPoll.getByTestId("poll-option").filter({ hasText: optionA }).click();
      await expect(bobPoll.getByTestId("poll-result-row").filter({ hasText: optionA })).toContainText(/1/);

      // Vote replacement: bob switches from optionA to optionB; optionA count
      // drops back to zero and optionB becomes bob's single vote.
      await bobPoll.getByTestId("poll-option").filter({ hasText: optionB }).click();
      await expect(bobPoll.getByTestId("poll-result-row").filter({ hasText: optionA })).toContainText(/0/);
      await expect(bobPoll.getByTestId("poll-result-row").filter({ hasText: optionB })).toContainText(/1/);

      await gotoChat(carolPage, spaceId);
      const carolPoll = carolPage.page.getByTestId("poll-card").filter({ hasText: question }).first();
      await carolPoll.getByTestId("poll-option").filter({ hasText: optionB }).click();
      await expect(carolPoll.getByTestId("poll-result-row").filter({ hasText: optionB })).toContainText(/2/);

      await gotoChat(alicePage, spaceId);
      await poll.getByTestId("poll-close-button").click();
      await expect(poll.getByTestId("poll-state")).toContainText(/closed/i, {
        timeout: 30_000,
      });
      await expect(poll.getByTestId("poll-option")).toHaveCount(0);
      await stepShot(alicePage.page, testInfo, "poll-closed");
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  });

  test(
    // @blocking-on: soland#messaging-chat-advanced-gap
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    // @expected-live-by: 2026Q3
    "E14.F typing indicator (cx.typing ephemeral) appears in peer view within 1s and clears after ttl_ms=5000",
    async ({ browser, request }, testInfo) => {
      // spec: profiles-presence.md §3.5
      const stamp = Date.now();
      const alice = uniqueUser("s14f-alice");
      const bob = uniqueUser("s14f-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        const spaceId = await alicePage.createSpace({
          title: `S14F Typing ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          seedMembers: [bob.did],
        });
        await bobPage.acceptInvite(spaceId);
        await Promise.all([gotoChat(alicePage, spaceId), gotoChat(bobPage, spaceId)]);

        await alicePage.page.getByTestId("chat-input").fill(`draft ${stamp}`);
        await expect(
          bobPage.page.getByTestId("typing-indicator").filter({ hasText: alice.displayName }),
        ).toBeVisible({ timeout: 1_000 });
        await stepShot(bobPage.page, testInfo, "typing-visible");
        await expect(
          bobPage.page.getByTestId("typing-indicator").filter({ hasText: alice.displayName }),
        ).toHaveCount(0, { timeout: 7_000 });
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test(
    // @blocking-on: soland#messaging-chat-advanced-gap
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    // @expected-live-by: 2026Q3
    "E14.G presence state propagates online/offline within 1s after page open/close",
    async ({ browser, request }, testInfo) => {
      // spec: profiles-presence.md §3.2-§3.4
      const stamp = Date.now();
      const alice = uniqueUser("s14g-alice");
      const bob = uniqueUser("s14g-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        const spaceId = await alicePage.createSpace({
          title: `S14G Presence ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          seedMembers: [bob.did],
        });
        await bobPage.acceptInvite(spaceId);
        await Promise.all([gotoChat(alicePage, spaceId), gotoChat(bobPage, spaceId)]);

        await expect(
          alicePage.page.getByTestId("presence-row").filter({ hasText: bob.did }),
        ).toContainText(/online/i, { timeout: 1_000 });
        await stepShot(alicePage.page, testInfo, "presence-online");

        await bobPage.close();
        await expect(
          alicePage.page.getByTestId("presence-row").filter({ hasText: bob.did }),
        ).toContainText(/offline|last seen/i, { timeout: 5_000 });
      } finally {
        await Promise.allSettled([alicePage.close()]);
      }
    },
  );

  test(
    // @user-promise: e2e/scenarios/messaging/chat-advanced.md
    "E14.2 mention in E2EE space uses sidecar hash; server log does not contain mentionee.did plaintext",
    async ({ request }) => {
      // spec: push-notifications.md §4.5 evaluation_locus + mention sidecar hash
      const stamp = Date.now();
      const alice = uniqueUser("s142-alice");
      const bob = uniqueUser("s142-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const spaceId = await createSharedSpaceViaApi(
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
      const sidecarHash = mentionSidecarHash(spaceId, bob.did);
      const envelope = signedEventEnvelope({
        actorDid: alice.did,
        realmId: spaceId,
        kind: "ck.message.create",
        payload: {
          flow_id: flowIdFromRealmId(spaceId),
          track_name: "discussion",
          encrypted: true,
          mention_sidecar_hash: [sidecarHash],
          encrypted_content: encryptedEnvelope("cx.message.v1", "opaque-e2ee-mention", spaceId),
        },
      });
      await submitSignedEventApi(request, aliceToken, envelope, {
        context: "submit E2EE mention sidecar message",
      });

      const events = await listSpaceEventsViaApi(request, aliceToken, spaceId, { limit: 100 });
      const messageEvent = events.find(
        (event) => String(event.event_id) === String(envelope.event_id),
      );
      expect(messageEvent, "encrypted sidecar message event").toBeTruthy();
      const rawServerView = JSON.stringify(messageEvent);
      expect(rawServerView).not.toContain(bob.did);
      expect(rawServerView).not.toContain(plaintext);
      expect(rawServerView).toContain("mention_sidecar_hash");
      expect(rawServerView).toContain(sidecarHash);
    },
  );
});

function mentionSidecarHash(spaceId: string, did: string): string {
  return createHash("sha256").update(`${spaceId}|${did}`).digest("hex");
}

function encryptedEnvelope(
  contentType: string,
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  return {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.cokret.message+json",
    ciphertext,
    authentication_tag: "opaque-tag",
    aad_visibility_event_id: "hidden",
    aad: { suite: "test", content_type: contentType, realm_id: realmId, event_kind: "ck.message.create" },
    key_ref: {
      algorithm: "MLS",
      group_state_ref: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
    aad_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    payload_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    digests: {
      ciphertext: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
}

async function createChatApiFixture(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice`);
  const bob = uniqueUser(`${label}-bob`);
  await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
  const [aliceToken, bobToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
  ]);
  const spaceId = await createSharedSpaceViaApi(request, alice, aliceToken, bob, bobToken, {
    title: `${label} ${stamp}`,
    historyVisibility: "shared",
  });
  return { alice, bob, aliceToken, bobToken, spaceId };
}
