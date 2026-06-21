// Single-server triad collaboration
// Contract: e2e/scenarios/messaging/triad-collaboration.md
// Spec refs:
//   - models/realm-and-space.md §2-§3
//   - models/strand-and-message.md §8, §8.4, §8.5

import { expect, test } from "@playwright/test";
import {
  createRealmViaApi,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { stepShot } from "../../helpers/screenshots";
import {
  canonicalTimestamp,
  listInvitesApi,
  resolveDefaultStrandId,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
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
    const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, bobToken, {
      title: `triad audit ${stamp}`,
      historyVisibility: "shared",
    });
    const created = await sendPlaintextMessageViaApi(
      request,
      aliceToken,
      realmId,
      `triad create ${stamp}`,
      { actorDid: alice.did },
    );

    const revisedBody = `triad revised ${stamp}`;
    const messageRef = created.event_id.replace(/^ck:event:/, "ck:message:");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId: realmId,
        kind: "ck.message.revise",
        payload: {
          target_ref: messageRef,
          content: { kind: "ck.content.text", body: revisedBody },
        },
      }),
      { context: "revise message" },
    );

    const beforeRedact = await listRealmEventsViaApi(request, bobToken, realmId);
    expect(beforeRedact.map(eventKind)).toEqual(
      expect.arrayContaining(["ck.message.create", "ck.message.revise"]),
    );
    expect(eventPayload(beforeRedact.find((event) => eventKind(event) === "ck.message.revise")))
      .toMatchObject({ target_ref: messageRef });

    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId: realmId,
        kind: "ck.message.redact",
        payload: {
          target_event_id: created.event_id,
          target_ref: messageRef,
          reason: "author_redaction",
        },
      }),
      { context: "redact message" },
    );

    const events = await listRealmEventsViaApi(request, bobToken, realmId);
    const eventKinds = events.map(eventKind);
    expect(eventKinds).toContain("ck.message.revise");
    expect(eventKinds).not.toContain("ck.message.create");
    expect(eventKinds).not.toContain("ck.message.redact");
    expect(eventPayload(events.find((event) => eventKind(event) === "ck.message.revise")))
      .toMatchObject({ target_ref: messageRef });
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
    const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, bobToken, {
      title: `triad joined ${stamp}`,
      historyVisibility: "joined",
    });
    const baseMs = Date.now() + 1_000;
    const defaultStrandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const pre = signedEventEnvelope({
      actorDid: alice.did,
      realmId: realmId,
      kind: "ck.message.create",
      createdAt: canonicalTimestamp(new Date(baseMs)),
      payload: {
        strand_id: defaultStrandId,
        track_name: "discussion",
        content: { kind: "ck.content.text", body: `triad pre ${stamp}` },
      },
    });
    await submitSignedEventApi(request, aliceToken, pre, {
      context: "pre-join triad message",
    });
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId: realmId,
        kind: "ck.member.state",
        createdAt: canonicalTimestamp(new Date(baseMs + 60_000)),
        payload: {
          realm_id: realmId,
          actor_id: carol.did,
          membership: "join",
          delivery_status: "unroutable",
        },
      }),
      { context: "join carol" },
    );
    const post = signedEventEnvelope({
      actorDid: alice.did,
      realmId: realmId,
      kind: "ck.message.create",
      createdAt: canonicalTimestamp(new Date(baseMs + 120_000)),
      payload: {
        strand_id: defaultStrandId,
        track_name: "discussion",
        content: { kind: "ck.content.text", body: `triad post ${stamp}` },
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

  // The history_visibility=joined server gap is now covered live by the
  // API late-join case above plus spaces/history-joined-enforcement.spec.ts.
  // Keep this full UI workflow fixme until the remaining timeline reply/edit,
  // invite, propagation, and redaction UI sequence is reactivated as one
  // browser-driven scenario.
  test.fixme(
    // @blocking-on: yougen#triad-ui-workflow-reactivation
    // @user-promise: e2e/scenarios/messaging/triad-collaboration.md
    // @expected-live-by: 2026Q3
    "alice + bob + carol drive space lifecycle, mutual messaging, late-join history visibility, and redact tombstone",
    async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alice = uniqueUser("s1-alice");
    const bob = uniqueUser("s1-bob");
    const carol = uniqueUser("s1-carol");

    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    await ensureRegistered(request, carol);

    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const carolToken = await issueDevSession(request, carol);

    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionCredential: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionCredential: carolToken });

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
        historyVisibility: "joined",
        seedMembers: [bob.did],
      });
      await stepShot(alicePage.page, testInfo, "A-alice-space-created");

      await bobPage.acceptInvite(realmId);
      await stepShot(bobPage.page, testInfo, "A-bob-accepted-invite");

      // Phase B — alice and bob exchange messages with reply chain + edit.
      await alicePage.sendTimelineMessage(realmId, m1);
      await stepShot(alicePage.page, testInfo, "B-m1-sent");

      await bobPage.gotoTimelineRealm(realmId);
      await expect(bobPage.page.getByTestId("timeline")).toContainText(m1, {
        timeout: 30_000,
      });
      await stepShot(bobPage.page, testInfo, "B-bob-received-m1");

      // Reply to M1, then edit. Timeline view's reply testids:
      // reply-button, reply-to-banner (composer banner), reply-indicator (per
      // event marker). yougen/src/views/timeline.rs.
      const m1Event = bobPage.timelineEvent(m1);
      await m1Event.getByTestId("reply-button").click();
      await expect(bobPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await bobPage.sendTimelineMessage(realmId, m2);
      const m2EventOnBob = bobPage.timelineEvent(m2);
      await expect(m2EventOnBob.getByTestId("reply-indicator")).toBeVisible();
      await stepShot(bobPage.page, testInfo, "B-bob-replied");

      await m2EventOnBob.getByTestId("edit-button").click();
      await bobPage.page.getByTestId("edit-composer").locator("textarea").fill(m2Edited);
      await bobPage.page.getByTestId("save-edit-button").click();
      await expect(bobPage.timelineEvent(m2Edited)).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.page.getByTestId("write-status")).toContainText(/revised/);
      await stepShot(bobPage.page, testInfo, "B-bob-edited-m2");

      // Alice sees the edited reply.
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.timelineEvent(m2Edited)).toBeVisible({ timeout: 30_000 });

      // Phase C — alice invites carol, carol accepts, carol has restricted history.
      await alicePage.inviteFromAdmin(realmId, carol.did);
      await stepShot(alicePage.page, testInfo, "C-alice-invited-carol");

      await carolPage.acceptInvite(realmId);
      await stepShot(carolPage.page, testInfo, "C-carol-accepted-invite");

      await carolPage.gotoTimelineRealm(realmId);
      // Spec models/realm-and-space.md §3.4: history_visibility=joined →
      // carol sees nothing posted before she became a member.
      await expect(carolPage.timelineEvent(m1)).toHaveCount(0);
      await expect(carolPage.timelineEvent(m2Edited)).toHaveCount(0);
      await stepShot(carolPage.page, testInfo, "C-carol-pre-join-hidden");

      // Phase D — post-join message reaches all three.
      await alicePage.sendTimelineMessage(realmId, m3);
      await expect(carolPage.timelineEvent(m3)).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.timelineEvent(m3)).toBeVisible({ timeout: 30_000 });
      await stepShot(carolPage.page, testInfo, "D-carol-sees-m3");

      // Phase E — bob redacts his own M2; alice sees tombstone; carol unaffected
      // (she never saw M2 anyway because of history_visibility).
      await bobPage.gotoTimelineRealm(realmId);
      const m2Tombstone = bobPage.timelineEvent(m2Edited);
      await m2Tombstone.getByTestId("redact-button").click();
      await bobPage.page.getByTestId("confirm-redact-button").click();
      await expect(bobPage.page.getByTestId("redacted-tombstone")).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.page.getByTestId("write-status")).toContainText(/tombstoned/);
      await stepShot(bobPage.page, testInfo, "E-bob-redacted");

      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.page.getByTestId("redacted-tombstone")).toBeVisible({ timeout: 30_000 });
      // The redacted body should not be visible in plain form anymore.
      await expect(alicePage.page.getByTestId("timeline")).not.toContainText(m2Edited);
      await stepShot(alicePage.page, testInfo, "E-alice-sees-tombstone");

      await carolPage.gotoTimelineRealm(realmId);
      // Carol only sees M3 (and possibly the tombstone marker for M2, but never
      // its original text).
      await expect(carolPage.timelineEvent(m3)).toBeVisible();
      await expect(carolPage.page.getByTestId("timeline")).not.toContainText(m1);
      await expect(carolPage.page.getByTestId("timeline")).not.toContainText(m2Edited);
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  },
  );

  test.describe("E1 sub-cases", () => {
    // E1.1 — invite creation is idempotent on
    // (realm_id, invitee) pairs in `pending` state (soland/src/routing/spaces/
    // space.rs:627-644): the second create returns the existing invite_id
    // unchanged. yougen's invite modal drives the same endpoint via
    // submit_event_envelope, so re-issuing the same invite produces only one
    // invite-row in realm-admin.
    test("E1.1 idempotent invite — re-issuing the same invite does not duplicate", async ({
      browser,
      request,
    }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s1e11-alice");
      const bob = uniqueUser("s1e11-bob");
      await ensureRegistered(request, alice);
      await ensureRegistered(request, bob);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

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
        await alicePage.inviteFromAdmin(realmId, bob.did);

        // Re-issue same invite — soland MUST treat as idempotent (same
        // invite_id returned for any pending (space, invitee) pair).
        await alicePage.inviteFromAdmin(realmId, bob.did);

        // Bob's canonical invite projection should contain one pending invite.
        await expect.poll(async () => {
          const visible = await listInvitesApi(request, bobToken);
          return visible.filter((invite) =>
            invite.realm_id === realmId &&
            invite.invitee === bob.did &&
            (invite.state ?? invite.status ?? "pending") === "pending"
          ).length;
        }, { timeout: 30_000 }).toBe(1);
      } finally {
        await alicePage.close();
      }
    });

    // E1.2 — pre-join message is sent BEFORE carol is invited. With
    // history_visibility=shared (spec §3.4), late joiners must see the
    // pre-join timeline. soland's default sync path currently exposes the
    // full timeline regardless of visibility (see main test's soland gap
    // comment), so this positive assertion passes today; once soland adds
    // history_visibility filtering, this test will still be the canonical
    // "shared visibility lets carol read history" coverage.
    test("E1.2 history_visibility=shared exposes pre-join messages to late joiner", async ({
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
        historyVisibility: "shared",
        ownerDid: alice.did,
      });
      const pre = await sendPlaintextMessageViaApi(
        request,
        aliceToken,
        realmId,
        preMessage,
        { actorDid: alice.did },
      );
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId: realmId,
          kind: "ck.member.state",
          payload: {
            realm_id: realmId,
            actor_id: carol.did,
            membership: "join",
            delivery_status: "unroutable",
          },
        }),
        { context: "join carol shared history" },
      );

      const carolEvents = await listRealmEventsViaApi(request, carolToken, realmId);
      expect(carolEvents.map((event) => event.event_id)).toContain(pre.event_id);
      expect(JSON.stringify(carolEvents)).toContain(preMessage);
    });
  });
});
