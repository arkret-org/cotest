// Single-server triad collaboration
// Contract: e2e/scenarios/messaging/triad-collaboration.md
// Spec refs:
//   - models/space-and-place.md §2-§3
//   - models/flow-and-message.md §8, §8.4, §8.5

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
  type JointUserPage,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("single-server triad collaboration", () => {
  // soland gap: history_visibility=joined is stored on the space policy but
  // not enforced server-side — a late joiner (carol) still receives the full
  // timeline history via /sync, so Phase C's "carol must not see pre-join M1"
  // check fails. Re-activate once soland honours history_visibility on read.
  test.fixme(
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
    // yougen gap: same SpaceAdmin hydration race as the main triad test —
    // inviteFromAdmin hits invite-member which doesn't render on fresh load.
    test.fixme("E1.1 idempotent invite — re-issuing the same invite does not duplicate", async ({
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

        await alicePage.inviteFromAdmin(spaceId, bob.did);
        // Re-issue same invite — yougen / soland MUST treat as idempotent.
        await alicePage.inviteFromAdmin(spaceId, bob.did);

        // Only one invite row for bob should be visible.
        const rows = alicePage.page.getByTestId("invite-row").filter({ hasText: bob.did });
        await expect(rows).toHaveCount(1);
      } finally {
        await alicePage.close();
      }
    });

    // yougen gap: inviteFromAdmin hits invite-member which doesn't render
    // on fresh /admin/members navigation (same race as the main triad test).
    test.fixme("E1.2 history_visibility=shared exposes pre-join messages to late joiner", async ({
      browser,
      request,
    }, testInfo) => {
      const stamp = Date.now();
      const alice = uniqueUser("s1e12-alice");
      const carol = uniqueUser("s1e12-carol");
      await ensureRegistered(request, alice);
      await ensureRegistered(request, carol);
      const aliceToken = await issueDevSession(request, alice);
      const carolToken = await issueDevSession(request, carol);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const carolPage = await openUserPage(browser, carol, { sessionToken: carolToken });

      const preMessage = `pre-join shared message ${stamp}`;

      try {
        const spaceId = await alicePage.createSpace({
          title: `S1.2 Shared History ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          historyVisibility: "shared",
        });
        await alicePage.sendTimelineMessage(spaceId, preMessage);
        await stepShot(alicePage.page, testInfo, "shared-pre-join-msg");

        await alicePage.inviteFromAdmin(spaceId, carol.did);
        await carolPage.acceptInvite(spaceId);
        await carolPage.gotoTimelineSpace(spaceId);
        // Spec §3.4: shared → new members see pre-join history meant to be shared.
        await expect(carolPage.timelineEvent(preMessage)).toBeVisible({ timeout: 30_000 });
        await stepShot(carolPage.page, testInfo, "shared-carol-sees-pre-join");
      } finally {
        await Promise.allSettled([carolPage.close(), alicePage.close()]);
      }
    });
  });
});
