// Support escalation workflow — frontline Alex hands off to backend Sam
// Contract: e2e/scenarios/workflows/support-escalation.md
// Spec refs:
//   - models/strand-and-message.md §8 (reply / edit / redact)
//
// Realistic story: Alex opens an escalation space for ticket #1042 and seeds
// Sam. They walk a reply chain (summary → ask → answer → hypothesis → fix
// → verify), and Alex patches the original summary in place with the root
// cause. Kanban-driven status tracking is fixme'd until kanban + cross-user
// sync are ready.

import { expect, test } from "@playwright/test";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: support escalation", () => {
  test("alex escalates ticket #1042 to sam: reply chain + summary edit + verified resolution", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const alex = uniqueUser("wf-support-alex");
    const sam = uniqueUser("wf-support-sam");
    await Promise.all([ensureRegistered(request, alex), ensureRegistered(request, sam)]);
    const [alexToken, samToken] = await Promise.all([
      issueDevSession(request, alex),
      issueDevSession(request, sam),
    ]);
    const alexPage = await openUserPage(browser, alex, { sessionCredential: alexToken });
    const samPage = await openUserPage(browser, sam, { sessionCredential: samToken });

    const summary = `Ticket #1042 — customer X's checkout fails with 500 on /api/charge. ${stamp}`;
    const summaryEdited = `${summary} (ROOT CAUSE: payment gateway pool exhausted, see Sam's reply below)`;
    const samAsk = `Got logs? When did it start? ${stamp}`;
    const alexAnswer = `Started ~14:30 UTC; HTTP body says 'gateway timeout'. ${stamp}`;
    const samHypothesis = `Sounds like payment gateway pool exhausted. I'll bump max_conn. ${stamp}`;
    const samDeployed = `Fix deployed in 5min, can you verify? ${stamp}`;
    const alexVerified = `Verified — ticket resolved. Thanks Sam! ${stamp}`;

    try {
      // Phase A — escalation space, summary in.
      const realmId = await alexPage.createRealm({
        title: `Support escalation #1042 ${stamp}`,
        summary: "Backend escalation for checkout failures",
        discoverability: "listed",
        joinRule: "invite",
        seedMembers: [sam.did],
      });
      await samPage.acceptInvite(realmId);
      await alexPage.sendTimelineMessage(realmId, summary);
      await stepShot(alexPage.page, testInfo, "A-summary-in");

      // Phase B — reply chain: ask → answer → hypothesis.
      await samPage.gotoTimelineRealm(realmId);
      await expect(samPage.page.getByTestId("timeline")).toContainText(summary, {
        timeout: 30_000,
      });
      await samPage.timelineEvent(summary).getByTestId("reply-button").click();
      await expect(samPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await samPage.sendTimelineMessage(realmId, samAsk);
      await expect(samPage.timelineEvent(samAsk).getByTestId("reply-indicator")).toBeVisible({
        timeout: 30_000,
      });

      await alexPage.gotoTimelineRealm(realmId);
      await expect(alexPage.page.getByTestId("timeline")).toContainText(samAsk, {
        timeout: 30_000,
      });
      await alexPage.timelineEvent(samAsk).getByTestId("reply-button").click();
      await expect(alexPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await alexPage.sendTimelineMessage(realmId, alexAnswer);
      await expect(alexPage.timelineEvent(alexAnswer).getByTestId("reply-indicator")).toBeVisible({
        timeout: 30_000,
      });

      await samPage.gotoTimelineRealm(realmId);
      await expect(samPage.page.getByTestId("timeline")).toContainText(alexAnswer, {
        timeout: 30_000,
      });
      await samPage.timelineEvent(alexAnswer).getByTestId("reply-button").click();
      await expect(samPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await samPage.sendTimelineMessage(realmId, samHypothesis);
      await expect(samPage.timelineEvent(samHypothesis).getByTestId("reply-indicator")).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(samPage.page, testInfo, "B-reply-chain");

      // Phase C — Alex patches the original summary with root cause.
      await alexPage.gotoTimelineRealm(realmId);
      await expect(alexPage.timelineEvent(summary)).toBeVisible({ timeout: 30_000 });
      await alexPage.timelineEvent(summary).getByTestId("edit-button").click();
      await alexPage.page.getByTestId("edit-composer").locator("textarea").fill(summaryEdited);
      await alexPage.page.getByTestId("save-edit-button").click();
      await expect(alexPage.timelineEvent(summaryEdited)).toBeVisible({ timeout: 30_000 });
      await expect(alexPage.page.getByTestId("write-status")).toContainText(/revised/);
      await samPage.gotoTimelineRealm(realmId);
      await expect(samPage.timelineEvent(summaryEdited)).toBeVisible({ timeout: 30_000 });
      await stepShot(alexPage.page, testInfo, "C-summary-patched");

      // Phase D — deployment notice + verification close the loop.
      await samPage.timelineEvent(samHypothesis).getByTestId("reply-button").click();
      await expect(samPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await samPage.sendTimelineMessage(realmId, samDeployed);
      await expect(samPage.timelineEvent(samDeployed).getByTestId("reply-indicator")).toBeVisible({
        timeout: 30_000,
      });

      await alexPage.gotoTimelineRealm(realmId);
      await expect(alexPage.page.getByTestId("timeline")).toContainText(samDeployed, {
        timeout: 30_000,
      });
      await alexPage.timelineEvent(samDeployed).getByTestId("reply-button").click();
      await expect(alexPage.page.getByTestId("reply-to-banner")).toBeVisible();
      await alexPage.sendTimelineMessage(realmId, alexVerified);
      await expect(alexPage.timelineEvent(alexVerified).getByTestId("reply-indicator")).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(alexPage.page, testInfo, "D-verified");
    } finally {
      await Promise.allSettled([samPage.close(), alexPage.close()]);
    }
  });

  test.fixme(
    // @blocking-on: soland#workflows-support-escalation-gap
    // @user-promise: e2e/scenarios/workflows/support-escalation.md
    // @expected-live-by: 2026Q3
    "E-support.kanban alex tracks ticket on a Triage → In Progress → Resolved kanban",
    async () => {
      // yougen gap: locally-queued cards stay in "draft" state when the
      // reducer hasn't acked yet, which blocks the archive-then-recreate
      // promote pattern. Will revisit after the soland kanban Move ack lands.
    },
  );

  test.fixme(
    // @blocking-on: soland#workflows-support-escalation-gap
    // @user-promise: e2e/scenarios/workflows/support-escalation.md
    // @expected-live-by: 2026Q3
    "E-support.redact alex redacts a reply that leaked PII; tombstone replaces body for both",
    async () => {
      // Same redact-tombstone covered in messaging/triad — pulled out here
      // as a support-specific case (PII removal is a common ops workflow).
    },
  );
});
