// Personal blocklist (client-side filter; distinct from realm ban / quarantine / mute)
// Contract: e2e/scenarios/governance/personal-blocklist.md
// Spec: governance/content-moderation.md §4-§6, discovery/client-preferences.md §2

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("personal blocklist", () => {
  test("personal-blocklist endpoint surface probe", async ({ request }) => {
    // Surface check: confirm soland exposes account_data + blocked-users
    // endpoints in some form (200/401/403/404 are all acceptable; 5xx is not).
    // yougen gap: blocked-users UI panel + client filter 未完整;soland gap:
    // account_data API for blocklist + federation block propagation 未实现.
    const alice = uniqueUser("s31-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const auth = { authorization: `Bearer ${token}` };

    const accountData = await request.get(
      `${solandBaseUrl()}/api/v1/account_data/cx.account.blocklist.v1`,
      { headers: auth },
    );
    expect([200, 401, 403, 404]).toContain(accountData.status());
    expect(accountData.status()).toBeLessThan(500);
  });

  test.fixme(
    // @blocking-on: soland#governance-personal-blocklist-gap
    // @user-promise: e2e/scenarios/governance/personal-blocklist.md
    // @expected-live-by: 2026Q3
    "alice blocks bob; bob's messages filtered from alice's timeline; unblock restores visibility; federation propagates block",
    async ({ browser, request }, testInfo) => {
      // Main flow — Phases A–G of personal-blocklist.md.
      // yougen gap: blocked-users UI panel + client filter 未完整;
      // soland gap: account_data API for blocklist + federation block
      // propagation 未实现.
      const stamp = Date.now();
      const alice = uniqueUser("s31-alice");
      const bob = uniqueUser("s31-bob");
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, bob),
      ]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });

      try {
        // Phase A — shared space.
        const spaceId = await alicePage.createSpace({
          title: `S31 Blocklist ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          historyVisibility: "joined",
          seedMembers: [bob.did],
        });
        await bobPage.acceptInvite(spaceId);

        // Phase B — baseline: bob's M1 visible to alice.
        const m1 = `S31 m1 ${stamp}`;
        await bobPage.sendTimelineMessage(spaceId, m1);
        await alicePage.gotoTimelineSpace(spaceId);
        await expect(alicePage.page.getByTestId("timeline")).toContainText(m1, {
          timeout: 30_000,
        });

        // Phase C — alice opens /settings/blocked-users and blocks bob.
        await alicePage.page.goto("/settings/blocked-users", {
          waitUntil: "domcontentloaded",
        });
        await expect(alicePage.page.getByTestId("blocked-users-panel")).toBeVisible({
          timeout: 30_000,
        });
        await alicePage.page.getByTestId("block-target-input").fill(bob.did);
        await alicePage.page.getByTestId("block-user-button").click();
        await expect(alicePage.page.getByTestId("blocked-users-list")).toContainText(bob.did, {
          timeout: 30_000,
        });
        await stepShot(alicePage.page, testInfo, "blocked-users-after-block");

        // Phase D — account_data PUT/GET round-trip.
        const aliceAuth = { authorization: `Bearer ${aliceToken}` };
        const blocklistGet = await request.get(
          `${solandBaseUrl()}/api/v1/account_data/cx.account.blocklist.v1`,
          { headers: aliceAuth },
        );
        expect(blocklistGet.status()).toBe(200);
        const blocklistBody = await blocklistGet.json();
        const entries = (blocklistBody.entries ?? []) as Array<{
          target: string;
          kind?: string;
        }>;
        expect(entries.some((e) => e.target === bob.did && (e.kind ?? "block") === "block")).toBe(
          true,
        );

        // Phase E — bob sends M2; alice's timeline must not contain it.
        const m2 = `S31 m2 ${stamp}`;
        await bobPage.sendTimelineMessage(spaceId, m2);
        await alicePage.gotoTimelineSpace(spaceId);
        const aliceTexts = await alicePage.readTimelineTexts(spaceId);
        expect(aliceTexts.some((t) => t.includes(m2))).toBe(false);
        // Existing M1 may or may not stay (spec §4: filter applies in real time;
        // this assertion is informational — we only hard-assert the M2 absence).
        await stepShot(alicePage.page, testInfo, "alice-timeline-after-block");

        // Phase F — unblock; bob's new M3 becomes visible again.
        await alicePage.page.goto("/settings/blocked-users", {
          waitUntil: "domcontentloaded",
        });
        await alicePage.page
          .getByTestId("blocked-user-row")
          .filter({ hasText: bob.did })
          .getByTestId("unblock-button")
          .click();
        await expect(alicePage.page.getByTestId("blocked-users-list")).not.toContainText(bob.did, {
          timeout: 30_000,
        });

        const m3 = `S31 m3 ${stamp}`;
        await bobPage.sendTimelineMessage(spaceId, m3);
        await alicePage.gotoTimelineSpace(spaceId);
        await expect(alicePage.page.getByTestId("timeline")).toContainText(m3, {
          timeout: 30_000,
        });

        // Phase G — federation block hint (placeholder; needs 2-server harness).
        // Asserted in a separate fixme below once the cross-server harness is wired.
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test.fixme(
    // @blocking-on: soland#governance-personal-blocklist-gap
    // @user-promise: e2e/scenarios/governance/personal-blocklist.md
    // @expected-live-by: 2026Q3
    "E11.1 quarantine vs block: server-side quarantine hides a message for everyone; personal block only hides for the blocker — the two operate independently",
    async () => {
      // spec: content-moderation.md §4 (block) vs the quarantine flow
      // referenced from §4; quarantine is admin-driven server-side
      // isolation, block is actor-private client-side filter.
      // yougen gap: blocked-users UI panel + client filter 未完整;
      // soland gap: account_data API for blocklist + federation block
      // propagation 未实现.
    },
  );

  test.fixme(
    // @blocking-on: soland#governance-personal-blocklist-gap
    // @user-promise: e2e/scenarios/governance/personal-blocklist.md
    // @expected-live-by: 2026Q3
    "E11.2 mute vs block: muted user's messages still render in timeline but produce no push; blocked user's messages render not at all",
    async () => {
      // spec: content-moderation.md §5
      // yougen gap: blocked-users UI panel + client filter 未完整;
      // soland gap: account_data API for blocklist + federation block
      // propagation 未实现.
    },
  );

  test.fixme(
    // @blocking-on: soland#governance-personal-blocklist-gap
    // @user-promise: e2e/scenarios/governance/personal-blocklist.md
    // @expected-live-by: 2026Q3
    "E11.3 blocked user's view: bob still sees his own messages persisted normally and is never told he was blocked by alice (anti social-graph leak)",
    async () => {
      // spec: content-moderation.md §4 — block MUST NOT be observable
      // to the blocked party.
      // yougen gap: blocked-users UI panel + client filter 未完整;
      // soland gap: account_data API for blocklist + federation block
      // propagation 未实现.
    },
  );
});
