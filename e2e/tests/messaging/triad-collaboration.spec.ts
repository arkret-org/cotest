// Single-server triad collaboration
// Contract: e2e/scenarios/messaging/triad-collaboration.md
// Spec refs:
//   - models/space-and-place.md §2-§3
//   - models/flow-and-message.md §8, §8.4, §8.5

import { expect, test, type Page } from "@playwright/test";
import {
  createSpaceViaApi,
  createSharedSpaceViaApi,
  listSpaceEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { stepShot } from "../../helpers/screenshots";
import {
  canonicalTimestamp,
  flowIdFromRealmId,
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

// Helper kept inline (per G2.T1 scope: do not extend helpers/users.ts).
// Waits for yougen's SpaceAdmin Members section to mount the invite card.
// gotoSpaceAdminSection already clicks the Members tab if hydration falls
// back to Overview; this extra poll defeats the rare case where the tab
// click lands before active_section signal settles. Bounded at 30s — the
// SpaceAdminPanel mounts well under that on a healthy dev server; if it
// hasn't rendered in 30s the panel itself is broken, not racing.
async function waitForInviteCardReady(page: Page) {
  await page.waitForFunction(
    () => document.querySelector('[data-testid="invite-member"]') !== null,
    null,
    { timeout: 30_000 },
  );
  await expect(page.getByTestId("invite-member")).toBeVisible({ timeout: 30_000 });
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
    const spaceId = await createSharedSpaceViaApi(request, alice, aliceToken, bob, bobToken, {
      title: `triad audit ${stamp}`,
      historyVisibility: "shared",
    });
    const created = await sendPlaintextMessageViaApi(
      request,
      aliceToken,
      spaceId,
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
        realmId: spaceId,
        kind: "cx.message.revise",
        payload: {
          target_event_id: created.event_id,
          target_ref: messageRef,
          content: { kind: "cx.content.text", body: revisedBody },
        },
      }),
      { context: "revise message" },
    );

    const beforeRedact = await listSpaceEventsViaApi(request, bobToken, spaceId);
    expect(beforeRedact.map((event) => event.event_kind)).toEqual(
      expect.arrayContaining(["cx.message.create", "cx.message.revise"]),
    );
    expect(beforeRedact.find((event) => event.event_kind === "cx.message.revise")?.payload)
      .toMatchObject({ target_event_id: created.event_id, target_ref: messageRef });

    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorDid: alice.did,
        realmId: spaceId,
        kind: "cx.message.redact",
        payload: {
          target_event_id: created.event_id,
          target_ref: messageRef,
          reason: "author_redaction",
        },
      }),
      { context: "redact message" },
    );

    const events = await listSpaceEventsViaApi(request, bobToken, spaceId);
    expect(events.map((event) => event.event_kind)).toContain("cx.message.revise");
    expect(events.map((event) => event.event_kind)).not.toContain("cx.message.create");
    expect(events.map((event) => event.event_kind)).not.toContain("cx.message.redact");
    expect(events.find((event) => event.event_kind === "cx.message.revise")?.payload)
      .toMatchObject({ target_event_id: created.event_id, target_ref: messageRef });
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
    const spaceId = await createSharedSpaceViaApi(request, alice, aliceToken, bob, bobToken, {
      title: `triad joined ${stamp}`,
      historyVisibility: "joined",
    });
    const baseMs = Date.now() + 1_000;
    const pre = signedEventEnvelope({
      actorDid: alice.did,
      realmId: spaceId,
      kind: "cx.message.create",
      createdAt: canonicalTimestamp(new Date(baseMs)),
      payload: {
        flow_id: flowIdFromRealmId(spaceId),
        track_name: "discussion",
        content: { kind: "cx.content.text", body: `triad pre ${stamp}` },
        encrypted: false,
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
        realmId: spaceId,
        kind: "cx.member.state",
        createdAt: canonicalTimestamp(new Date(baseMs + 60_000)),
        payload: {
          actor_id: carol.did,
          member: carol.did,
          membership: "join",
          delivery_status: "unroutable",
        },
      }),
      { context: "join carol" },
    );
    const post = signedEventEnvelope({
      actorDid: alice.did,
      realmId: spaceId,
      kind: "cx.message.create",
      createdAt: canonicalTimestamp(new Date(baseMs + 120_000)),
      payload: {
        flow_id: flowIdFromRealmId(spaceId),
        track_name: "discussion",
        content: { kind: "cx.content.text", body: `triad post ${stamp}` },
        encrypted: false,
      },
    });
    await submitSignedEventApi(request, aliceToken, post, {
      context: "post-join triad message",
    });

    const carolEvents = await listSpaceEventsViaApi(request, carolToken, spaceId);
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

    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
    const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

    const m1 = `M1 alice hello ${stamp}`;
    const m2 = `M2 bob reply ${stamp}`;
    const m2Edited = `${m2} (edited)`;
    const m3 = `M3 welcome carol ${stamp}`;

    try {
      // Phase A — alice creates space, seed-invites bob; bob accepts.
      const spaceId = await alicePage.createSpace({
        title: `S1 Triad ${stamp}`,
        summary: "triad collaboration coverage",
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        seedMembers: [bob.did],
      });
      await stepShot(alicePage.page, testInfo, "A-alice-space-created");

      await bobPage.acceptInvite(spaceId);
      await stepShot(bobPage.page, testInfo, "A-bob-accepted-invite");

      // Phase B — alice and bob exchange messages with reply chain + edit.
      await alicePage.sendTimelineMessage(spaceId, m1);
      await stepShot(alicePage.page, testInfo, "B-m1-sent");

      await bobPage.gotoTimelineSpace(spaceId);
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
      await bobPage.sendTimelineMessage(spaceId, m2);
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
      await alicePage.gotoTimelineSpace(spaceId);
      await expect(alicePage.timelineEvent(m2Edited)).toBeVisible({ timeout: 30_000 });

      // Phase C — alice invites carol, carol accepts, carol has restricted history.
      await alicePage.inviteFromAdmin(spaceId, carol.did);
      await stepShot(alicePage.page, testInfo, "C-alice-invited-carol");

      await carolPage.acceptInvite(spaceId);
      await stepShot(carolPage.page, testInfo, "C-carol-accepted-invite");

      await carolPage.gotoTimelineSpace(spaceId);
      // Spec models/space-and-place.md §3.4: history_visibility=joined →
      // carol sees nothing posted before she became a member.
      await expect(carolPage.timelineEvent(m1)).toHaveCount(0);
      await expect(carolPage.timelineEvent(m2Edited)).toHaveCount(0);
      await stepShot(carolPage.page, testInfo, "C-carol-pre-join-hidden");

      // Phase D — post-join message reaches all three.
      await alicePage.sendTimelineMessage(spaceId, m3);
      await expect(carolPage.timelineEvent(m3)).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.timelineEvent(m3)).toBeVisible({ timeout: 30_000 });
      await stepShot(carolPage.page, testInfo, "D-carol-sees-m3");

      // Phase E — bob redacts his own M2; alice sees tombstone; carol unaffected
      // (she never saw M2 anyway because of history_visibility).
      await bobPage.gotoTimelineSpace(spaceId);
      const m2Tombstone = bobPage.timelineEvent(m2Edited);
      await m2Tombstone.getByTestId("redact-button").click();
      await bobPage.page.getByTestId("confirm-redact-button").click();
      await expect(bobPage.page.getByTestId("redacted-tombstone")).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.page.getByTestId("write-status")).toContainText(/tombstoned/);
      await stepShot(bobPage.page, testInfo, "E-bob-redacted");

      await alicePage.gotoTimelineSpace(spaceId);
      await expect(alicePage.page.getByTestId("redacted-tombstone")).toBeVisible({ timeout: 30_000 });
      // The redacted body should not be visible in plain form anymore.
      await expect(alicePage.page.getByTestId("timeline")).not.toContainText(m2Edited);
      await stepShot(alicePage.page, testInfo, "E-alice-sees-tombstone");

      await carolPage.gotoTimelineSpace(spaceId);
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
    // E1.1 — soland's POST /api/v1/spaces/{id}/invite is idempotent on
    // (space_id, invitee) pairs in `pending` state (soland/src/routing/spaces/
    // space.rs:627-644): the second create returns the existing invite_id
    // unchanged. yougen's invite-member button drives the same endpoint via
    // submit_event_envelope, so re-issuing the same invite produces only one
    // invite-row in space-admin.
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
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

      try {
        const spaceId = await alicePage.createSpace({
          title: `S1 Idempotent Invite ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });

        // First invite. inviteFromAdmin internally calls gotoSpaceAdminSection
        // (Members) and asserts the invite-member card before clicking — that
        // already defeats the SpaceAdminPanel hydration race that historically
        // caused fresh-nav fails (see scenarios/spaces/admin-section-route.md).
        // We add an explicit waitForInviteCardReady belt-and-suspenders only
        // on the second issue, where the helper's gotoSpaceAdmin re-mounts.
        await alicePage.inviteFromAdmin(spaceId, bob.did);

        // Re-issue same invite — soland MUST treat as idempotent (same
        // invite_id returned for any pending (space, invitee) pair).
        await waitForInviteCardReady(alicePage.page);
        await alicePage.inviteFromAdmin(spaceId, bob.did);

        // Only one invite row for bob should be visible. Allow up to 30s
        // for the projection to settle — yougen polls /spaces/<id>/admin
        // and the row count toggles to 1 once the second submit returns the
        // pre-existing invite_id (no INSERT happens server-side).
        const rows = alicePage.page.getByTestId("invite-row").filter({ hasText: bob.did });
        await expect(rows).toHaveCount(1, { timeout: 30_000 });
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
      const spaceId = await createSpaceViaApi(request, aliceToken, {
        title: `S1.2 Shared History ${stamp}`,
        historyVisibility: "shared",
        ownerDid: alice.did,
      });
      const pre = await sendPlaintextMessageViaApi(
        request,
        aliceToken,
        spaceId,
        preMessage,
        { actorDid: alice.did },
      );
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId: spaceId,
          kind: "cx.member.state",
          payload: {
            actor_id: carol.did,
            member: carol.did,
            membership: "join",
            delivery_status: "unroutable",
          },
        }),
        { context: "join carol shared history" },
      );

      const carolEvents = await listSpaceEventsViaApi(request, carolToken, spaceId);
      expect(carolEvents.map((event) => event.event_id)).toContain(pre.event_id);
      expect(JSON.stringify(carolEvents)).toContain(preMessage);
    });
  });
});
