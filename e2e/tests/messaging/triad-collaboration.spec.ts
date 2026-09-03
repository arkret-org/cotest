// Single-server triad collaboration
// Contract: e2e/scenarios/messaging/triad-collaboration.md
// Spec refs:
//   - models/realm-and-space.md §2-§3
//   - models/strand-and-message.md §8, §8.4, §8.5

import { expect, test } from "../../helpers/arkret-test";
import {
  createRealmViaApi,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl, solandServiceId } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  authHeaders,
  canonicalTimestamp,
  listInvitesApi,
  resolveDefaultStrandId,
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
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function eventKind(event: Record<string, unknown>): string {
  return String(event.kind ?? event.event_kind ?? "");
}

function eventPayload(event: Record<string, unknown> | undefined): Record<string, unknown> {
  const payload = event?.payload;
  return payload && typeof payload === "object"
    ? (payload as Record<string, unknown>)
    : {};
}

function expectRedactedPayload(
  event: Record<string, unknown> | undefined,
  leakedBody: string,
): void {
  expect(event, "redacted event must be present").toBeTruthy();
  const payload = eventPayload(event);
  // A normal member has no `redacted_history_allowed=true` read grant, so the
  // projection may suppress payload entirely. If a deployment does expose the
  // permitted stub, it must carry the canonical tombstone markers. Neither
  // form may leak the original body.
  if (Object.keys(payload).length > 0) {
    expect(payload).toMatchObject({ redacted: true, state: "redacted" });
  }
  expect(JSON.stringify(event)).not.toContain(leakedBody);
}

function visibleMemberIds(realm: Record<string, unknown>): string[] {
  const members = realm.member_ids;
  if (!Array.isArray(members)) {
    return [];
  }
  return members.flatMap((member) => {
    if (typeof member === "string") {
      return [member];
    }
    if (!member || typeof member !== "object") {
      return [];
    }
    const record = member as Record<string, unknown>;
    const id = [record.actor_id, record.id].find(
      (candidate): candidate is string => typeof candidate === "string",
    );
    return id ? [id] : [];
  });
}

test.describe("single-server triad collaboration", () => {
  test("API create → revise → redact updates projection visibility", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("triad-api-alice");
    const bob = uniqueUser("triad-api-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
    ]);
    const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, {
      title: `triad audit ${stamp}`,
      historyAccess: "all_history_for_current_members",
    });
    const createBody = `triad create ${stamp}`;
    const created = await sendPlaintextMessageViaApi(
      request,
      aliceToken,
      realmId,
      createBody,
      { actorId: alice.id },
    );

    const revisedBody = `triad revised ${stamp}`;
    const messageRef = created.event_id.replace(/^ak:event:/, "ak:message:");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId: realmId,
        kind: "ak.message.revise",
        payload: {
          message_id: messageRef,
          content: { kind: "ak.content.text", body: revisedBody },
        },
      }),
      { context: "revise message" },
    );

    const beforeRedact = await listRealmEventsViaApi(request, bobToken, realmId);
    expect(beforeRedact.map(eventKind)).toEqual(
      expect.arrayContaining(["ak.message.create", "ak.message.revise"]),
    );
    expect(eventPayload(beforeRedact.find((event) => eventKind(event) === "ak.message.revise")))
      .toMatchObject({ message_id: messageRef });

    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId: realmId,
        kind: "ak.message.redact",
        payload: {
          message_id: messageRef,
          reason: "author_redaction",
        },
      }),
      { context: "redact message" },
    );

    const events = await listRealmEventsViaApi(request, bobToken, realmId);
    const eventKinds = events.map(eventKind);
    expect(eventKinds).toContain("ak.message.revise");
    expect(eventKinds).toContain("ak.message.create");
    // The canonical Event log retains the redaction fact; only the target's
    // visible content is removed (strand-and-message sections 9.1/9.2).
    expect(eventKinds).toContain("ak.message.redact");
    expectRedactedPayload(
      events.find((event) => eventKind(event) === "ak.message.create"),
      createBody,
    );
    expectRedactedPayload(
      events.find((event) => eventKind(event) === "ak.message.revise"),
      revisedBody,
    );
  });

  test("API late-join triad member sees only post-join messages in joined history", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("triad-joined-alice");
    const bob = uniqueUser("triad-joined-bob");
    const carol = uniqueUser("triad-joined-carol");
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
    const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, {
      title: `triad joined ${stamp}`,
      historyAccess: "since_join",
    });
    const baseMs = Date.now() + 1_000;
    const defaultStrandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const pre = signedEventEnvelope({
      actorId: alice.id,
      realmId: realmId,
      kind: "ak.message.create",
      createdAt: canonicalTimestamp(new Date(baseMs)),
      payload: {
        strand_id: defaultStrandId,
        track_name: "discussion",
        content: { kind: "ak.content.text", body: `triad pre ${stamp}` },
      },
    });
    await submitSignedEventApi(request, aliceToken, pre, {
      context: "pre-join triad message",
    });
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId: realmId,
        kind: "ak.member.state",
        createdAt: canonicalTimestamp(new Date(baseMs + 60_000)),
        payload: {
          realm_id: realmId,
          member_id: accountActorId(carol.id),
          membership: "join",
        },
      }),
      { context: "join carol" },
    );
    const post = signedEventEnvelope({
      actorId: alice.id,
      realmId: realmId,
      kind: "ak.message.create",
      createdAt: canonicalTimestamp(new Date(baseMs + 120_000)),
      payload: {
        strand_id: defaultStrandId,
        track_name: "discussion",
        content: { kind: "ak.content.text", body: `triad post ${stamp}` },
      },
    });
    await submitSignedEventApi(request, aliceToken, post, {
      context: "post-join triad message",
    });

    const carolEvents = await listRealmEventsViaApi(request, carolToken, realmId);
    const ids = carolEvents.map((event) => event.event_id);
    expect(ids).not.toContain(pre.event_id);
    expect(ids).toContain(post.event_id);
  });

  // The history_access=since_join server gap is now covered live by the
  // API late-join case above plus spaces/history-joined-enforcement.spec.ts.
  // Phases A-D (space lifecycle, invite, mutual messaging, reply, edit) are
  // fully wired in inkson (chat-* reply/edit testids + the realm-members invite
  // modal). Phase E's *receive-side* redaction tombstone is now wired end-to-end:
  // soland folds a redacted ak.message.create into a per-message tombstone on the
  // sync timeline (projection/timeline.rs + sync/snapshot.rs call
  // apply_message_redaction_timeline_projection, which uses the SDK
  // redaction_tombstone_message_value shape: event_id preserved, body stripped,
  // redacted/state/redacted_at/redaction_ref markers added), and inkson's receive
  // path folds the tombstone onto the existing message (chat_message_from_event
  // sets redacted=true → chat-redacted-tombstone) so alice renders the tombstone
  // on reload, not just bob's optimistic local redact.
  test(
    "alice + bob + carol drive space lifecycle, mutual messaging, late-join history visibility, and redact tombstone",
    async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, "s1-alice"),
      openDpopUserPage(browser, request, "s1-bob"),
      openDpopUserPage(browser, request, "s1-carol"),
    ]);
    if (!aliceFlow || !bobFlow || !carolFlow) {
      assertJointStackNotRequired("triad collaboration browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bob = bobFlow.user;
    const carol = carolFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;

    const m1 = `M1 alice hello ${stamp}`;
    const m2 = `M2 bob reply ${stamp}`;
    const m2Edited = `${m2} (edited)`;
    const m3 = `M3 welcome carol ${stamp}`;

    try {
      // Phase A — alice creates space, seed-invites bob; bob accepts.
      const realmId = await alicePage.createRealm({
        title: `S1 Triad ${stamp}`,
        summary: "triad collaboration coverage",
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        encryptionProfile: "none",
        seedMembers: [bob.id],
      });
      await stepShot(alicePage.page, testInfo, "A-alice-space-created");

      await bobPage.acceptInvite(realmId);
      await alicePage.grantRealmCapability(
        realmId,
        bob.id,
        "ak.message.create",
      );
      await alicePage.grantRealmCapability(
        realmId,
        bob.id,
        "ak.message.revise",
      );
      await alicePage.grantRealmCapability(
        realmId,
        bob.id,
        "ak.message.redact",
      );
      await stepShot(bobPage.page, testInfo, "A-bob-accepted-invite");

      // Phase B — alice and bob exchange messages with reply chain + edit.
      await alicePage.sendTimelineMessage(realmId, m1);
      await stepShot(alicePage.page, testInfo, "B-m1-sent");

      await bobPage.gotoTimelineRealm(realmId);
      await expect(bobPage.page.getByTestId("message-list")).toContainText(m1, {
        timeout: 30_000,
      });
      await stepShot(bobPage.page, testInfo, "B-bob-received-m1");

      // Reply to M1, then edit. Chat view's reply testids use the `chat-*` prefix.
      await bobPage.clickTimelineReply(m1);
      await expect(bobPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await bobPage.sendTimelineMessage(realmId, m2);
      const m2EventOnBob = bobPage.timelineEvent(m2);
      await expect(m2EventOnBob.getByTestId("chat-reply-indicator")).toBeVisible();
      await stepShot(bobPage.page, testInfo, "B-bob-replied");

      await bobPage.clickTimelineEdit(m2);
      await bobPage.page.getByTestId("chat-edit-composer").locator("textarea").fill(m2Edited);
      await bobPage.page.getByTestId("chat-save-edit-button").click();
      await bobPage.waitForTimelineEventSettled(m2Edited);
      await expect(bobPage.page.getByTestId("chat-status")).toContainText(/Message updated/i);
      await stepShot(bobPage.page, testInfo, "B-bob-edited-m2");

      // Alice sees the edited reply.
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.timelineEvent(m2Edited)).toBeVisible({ timeout: 30_000 });

      // Phase C — alice invites carol, carol accepts, carol has restricted history.
      await alicePage.inviteFromAdmin(realmId, carol.id);
      await stepShot(alicePage.page, testInfo, "C-alice-invited-carol");

      await carolPage.acceptInvite(realmId);
      await alicePage.grantRealmCapability(
        realmId,
        carol.id,
        "ak.message.create",
      );
      await stepShot(carolPage.page, testInfo, "C-carol-accepted-invite");

      await carolPage.gotoTimelineRealm(realmId);
      // Spec models/realm-and-space.md §3.4: history_access=since_join →
      // carol sees nothing posted before she became a member.
      await expect(carolPage.timelineEvent(m1)).toHaveCount(0);
      await expect(carolPage.timelineEvent(m2Edited)).toHaveCount(0);
      await stepShot(carolPage.page, testInfo, "C-carol-pre-join-hidden");

      // Phase D — post-join message reaches all three.
      await alicePage.sendTimelineMessage(realmId, m3);
      await carolPage.expectTimelineEventVisible(m3, 30_000);
      await bobPage.expectTimelineEventVisible(m3, 30_000);
      await stepShot(carolPage.page, testInfo, "D-carol-sees-m3");

      // Phase E — bob redacts his own M2; alice sees tombstone; carol unaffected
      // (she never saw M2 anyway because of history_access).
      await bobPage.gotoTimelineRealm(realmId);
      await bobPage.clickTimelineRedact(m2Edited);
      await bobPage.page.getByTestId("chat-confirm-redact-button").click();
      await expect(bobPage.page.getByTestId("chat-redacted-tombstone")).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.page.getByTestId("chat-status")).toContainText(/Message removed/i);
      await stepShot(bobPage.page, testInfo, "E-bob-redacted");

      await expect
        .poll(
          async () => {
            await alicePage.gotoTimelineRealm(realmId);
            return alicePage.page.getByTestId("chat-redacted-tombstone").count();
          },
          { timeout: 60_000, intervals: [500, 1_000, 2_000, 5_000] },
        )
        .toBeGreaterThan(0);
      // The redacted body should not be visible in plain form anymore.
      await expect(alicePage.page.getByTestId("message-list")).not.toContainText(m2Edited);
      await stepShot(alicePage.page, testInfo, "E-alice-sees-tombstone");

      await carolPage.gotoTimelineRealm(realmId);
      // Carol only sees M3 (and possibly the tombstone marker for M2, but never
      // its original text).
      await carolPage.expectTimelineEventVisible(m3, 30_000);
      await expect(carolPage.page.getByTestId("message-list")).not.toContainText(m1);
      await expect(carolPage.page.getByTestId("message-list")).not.toContainText(m2Edited);
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  },
  );

  test.describe("E1 sub-cases", () => {
    // E1.1 — invite creation is idempotent on
    // (realm_id, invitee) pairs in `pending` state (soland/src/routing/spaces/
    // space.rs:627-644): the second create returns the existing invite_id
    // unchanged. inkson's invite modal drives the same endpoint via
    // submit_event_envelope, so re-issuing the same invite produces only one
    // invite-row in realm-admin.
    test("E1.1 idempotent invite — re-issuing the same invite does not duplicate", async ({
      browser,
      request,
    }) => {
      const stamp = Date.now();
      const bob = uniqueUser("s1e11-bob");
      await ensureRegistered(request, bob);
      const bobToken = await issueDevSession(request, bob);
      const aliceFlow = await openDpopUserPage(
        browser,
        request,
        `s1e11-alice-${stamp}`,
      );
      if (!aliceFlow) {
        assertJointStackNotRequired("triad invite browser login");
        test.skip(true, "coauth DPoP session-grant login is unavailable");
        return;
      }
      const alicePage = aliceFlow.page;

      try {
        const realmId = await alicePage.createRealm({
          title: `S1 Idempotent Invite ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });

        // First invite. inviteFromAdmin internally calls gotoRealmAdminSection
        // (Members) and opens the invite modal before submitting — that
        // already defeats the RealmAdminPanel hydration race that historically
        // caused fresh-nav fails (see scenarios/spaces/admin-section-route.md).
        // We add an explicit waitForInviteActionReady belt-and-suspenders only
        // on the second issue, where the helper's gotoRealmAdmin re-mounts.
        await alicePage.inviteFromAdmin(realmId, bob.id);

        // Re-issue same invite — soland MUST treat as idempotent (same
        // invite_id returned for any pending (space, invitee) pair).
        await alicePage.inviteFromAdmin(realmId, bob.id);

        // Bob's canonical invite projection should contain one pending invite.
        await expect.poll(async () => {
          const visible = await listInvitesApi(request, bobToken);
          return visible.filter((invite) =>
            invite.realm_id === realmId &&
            invite.invitee_account_id?.principal_id === bob.id && invite.invitee_account_id.station_id === solandServiceId() &&
            invite.state === "pending"
          ).length;
        }, { timeout: 30_000 }).toBe(1);
      } finally {
        await alicePage.close();
      }
    });

    // E1.2 — pre-join message is sent BEFORE carol is invited. With
    // history_access=all_history_for_current_members (spec §3.4), late joiners must see the
    // pre-join timeline. soland's default sync path currently exposes the
    // full timeline regardless of visibility (see main test's soland gap
    // comment), so this positive assertion passes today; once soland adds
    // history_access filtering, this test will still be the canonical
    // "shared visibility lets carol read history" coverage.
    test("E1.2 history_access=all_history_for_current_members exposes pre-join messages to late joiner", async ({
      request,
    }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s1e12-alice");
      const carol = uniqueUser("s1e12-carol");
      await ensureRegistered(request, alice);
      await ensureRegistered(request, carol);
      const aliceToken = await issueDevSession(request, alice);
      const carolToken = await issueDevSession(request, carol);

      const preMessage = `pre-join shared message ${stamp}`;
      const realmId = await createRealmViaApi(request, aliceToken, {
        title: `S1.2 Shared History ${stamp}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const pre = await sendPlaintextMessageViaApi(
        request,
        aliceToken,
        realmId,
        preMessage,
        { actorId: alice.id },
      );
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorId: alice.id,
          realmId: realmId,
          kind: "ak.member.state",
          payload: {
            realm_id: realmId,
            member_id: accountActorId(carol.id),
            membership: "join",
          },
        }),
        { context: "join carol shared history" },
      );

      const carolEvents = await listRealmEventsViaApi(request, carolToken, realmId);
      expect(carolEvents.map((event) => event.event_id)).toContain(pre.event_id);
      expect(JSON.stringify(carolEvents)).toContain(preMessage);
    });

    test("E1.4 membership leave gates writes; owner re-add restores membership", async ({
      request,
    }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s1e14-alice");
      const bob = uniqueUser("s1e14-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueDevSession(request, alice),
        issueDevSession(request, bob),
      ]);
      const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, {
        title: `S1.4 Leave Rejoin ${stamp}`,
        historyAccess: "all_history_for_current_members",
      });
      const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
      const beforeLeave = await sendPlaintextMessageViaApi(
        request,
        bobToken,
        realmId,
        `before leave ${stamp}`,
        { actorId: bob.id },
      );

      await submitSignedEventApi(
        request,
        bobToken,
        signedEventEnvelope({
          actorId: bob.id,
          realmId,
          kind: "ak.member.state",
          payload: {
            realm_id: realmId,
            member_id: accountActorId(bob.id),
            membership: "leave",
            reason: "self_leave",
          },
        }),
        { context: "bob leaves realm" },
      );

      const realmAfterLeave = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(aliceToken) },
      );
      expect(realmAfterLeave.status()).toBe(200);
      expect(visibleMemberIds(await realmAfterLeave.json())).not.toContain(bob.id);

      const afterLeaveBody = `after leave rejected ${stamp}`;
      const rejected = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(bobToken),
        data: signedEventEnvelope({
          actorId: bob.id,
          realmId,
          kind: "ak.message.create",
          payload: {
            strand_id: strandId,
            track_name: "discussion",
            content: { kind: "ak.content.text", body: afterLeaveBody },
          },
        }),
      });
      expect(
        rejected.status(),
        "left member cannot write ordinary messages",
      ).toBeGreaterThanOrEqual(400);

      const eventsAfterLeave = await listRealmEventsViaApi(request, aliceToken, realmId);
      const bobMemberEvents = eventsAfterLeave.filter(
        (event) =>
          eventKind(event) === "ak.member.state" &&
          eventPayload(event).actor_id === bob.id,
      );
      expect(eventPayload(bobMemberEvents[bobMemberEvents.length - 1])).toMatchObject({
        membership: "leave",
      });
      expect(JSON.stringify(eventsAfterLeave)).not.toContain(afterLeaveBody);

      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorId: alice.id,
          realmId,
          kind: "ak.member.state",
          payload: {
            realm_id: realmId,
            member_id: accountActorId(bob.id),
            membership: "join",
            reason: "owner_readd",
          },
        }),
        { context: "owner re-adds bob" },
      );
      const afterRejoin = await sendPlaintextMessageViaApi(
        request,
        bobToken,
        realmId,
        `after rejoin ${stamp}`,
        { actorId: bob.id },
      );
      const finalEvents = await listRealmEventsViaApi(request, aliceToken, realmId);
      expect(finalEvents.map((event) => event.event_id)).toEqual(
        expect.arrayContaining([beforeLeave.event_id, afterRejoin.event_id]),
      );
      expect(JSON.stringify(finalEvents)).not.toContain(afterLeaveBody);
    });
  });
});
