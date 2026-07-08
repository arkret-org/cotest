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
import { openDpopUserPage } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: support escalation", () => {
  test("alex escalates ticket #1042 to sam: reply chain + summary edit + verified resolution", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(300_000);
    const stamp = Date.now();
    const [alexFlow, samFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-support-alex"),
      openDpopUserPage(browser, request, "wf-support-sam"),
    ]);
    test.skip(
      !alexFlow || !samFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!alexFlow || !samFlow) {
      return;
    }
    const sam = samFlow.user;
    const alexPage = alexFlow.page;
    const samPage = samFlow.page;

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
        encryptionProfile: "none",
        seedMembers: [sam.did],
      });
      await samPage.acceptInvite(realmId);
      await alexPage.sendTimelineMessage(realmId, summary);
      await stepShot(alexPage.page, testInfo, "A-summary-in");

      // Phase B — reply chain: ask → answer → hypothesis.
      await samPage.gotoTimelineRealm(realmId);
      await expect(samPage.page.getByTestId("message-list")).toContainText(summary, {
        timeout: 30_000,
      });
      await samPage.clickTimelineReply(summary);
      await expect(samPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await samPage.sendTimelineMessage(realmId, samAsk);
      await expect(samPage.timelineEvent(samAsk).getByTestId("chat-reply-indicator")).toBeVisible({
        timeout: 30_000,
      });

      await alexPage.gotoTimelineRealm(realmId);
      await expect(alexPage.page.getByTestId("message-list")).toContainText(samAsk, {
        timeout: 30_000,
      });
      await alexPage.clickTimelineReply(samAsk);
      await expect(alexPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await alexPage.sendTimelineMessage(realmId, alexAnswer);
      await expect(alexPage.timelineEvent(alexAnswer).getByTestId("chat-reply-indicator")).toBeVisible({
        timeout: 30_000,
      });

      await samPage.gotoTimelineRealm(realmId);
      await expect(samPage.page.getByTestId("message-list")).toContainText(alexAnswer, {
        timeout: 30_000,
      });
      await samPage.clickTimelineReply(alexAnswer);
      await expect(samPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await samPage.sendTimelineMessage(realmId, samHypothesis);
      await expect(samPage.timelineEvent(samHypothesis).getByTestId("chat-reply-indicator")).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(samPage.page, testInfo, "B-reply-chain");

      // Phase C — Alex patches the original summary with root cause.
      await alexPage.gotoTimelineRealm(realmId);
      await expect(alexPage.timelineEvent(summary)).toBeVisible({ timeout: 30_000 });
      await alexPage.clickTimelineEdit(summary);
      await alexPage.page.getByTestId("chat-edit-composer").locator("textarea").fill(summaryEdited);
      await alexPage.page.getByTestId("chat-save-edit-button").click();
      await alexPage.waitForTimelineEventSettled(summaryEdited);
      await expect(alexPage.page.getByTestId("chat-status")).toContainText(/Message updated/i);
      await samPage.gotoTimelineRealm(realmId);
      await expect(samPage.timelineEvent(summaryEdited)).toBeVisible({ timeout: 30_000 });
      await stepShot(alexPage.page, testInfo, "C-summary-patched");

      // Phase D — deployment notice + verification close the loop.
      await samPage.clickTimelineReply(samHypothesis);
      await expect(samPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await samPage.sendTimelineMessage(realmId, samDeployed);
      await expect(samPage.timelineEvent(samDeployed).getByTestId("chat-reply-indicator")).toBeVisible({
        timeout: 30_000,
      });

      await alexPage.gotoTimelineRealm(realmId);
      await expect(alexPage.page.getByTestId("message-list")).toContainText(samDeployed, {
        timeout: 30_000,
      });
      await alexPage.clickTimelineReply(samDeployed);
      await expect(alexPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await alexPage.sendTimelineMessage(realmId, alexVerified);
      await expect(alexPage.timelineEvent(alexVerified).getByTestId("chat-reply-indicator")).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(alexPage.page, testInfo, "D-verified");
    } finally {
      await Promise.allSettled([samPage.close(), alexPage.close()]);
    }
  });

  test("E-support.kanban alex tracks ticket on a Triage → In Progress → Resolved kanban", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const alexFlow = await openDpopUserPage(browser, request, "wf-support-kanban-alex");
    test.skip(
      !alexFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!alexFlow) {
      return;
    }
    const alexPage = alexFlow.page;
    const triage = `Triage-${stamp}`;
    const inProgress = `In Progress-${stamp}`;
    const resolved = `Resolved-${stamp}`;
    const boardTitle = `Escalation Board ${stamp}`;
    const ticketCard = `Ticket #1042 checkout 500 ${stamp}`;

    try {
      const realmId = await alexPage.createRealm({
        title: `Support kanban ${stamp}`,
        summary: "Triage -> In Progress -> Resolved",
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
      });

      await alexPage.page.goto(`/kanban/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(alexPage.page.getByTestId("kanban-panel")).toBeVisible({
        timeout: 120_000,
      });
      await alexPage.page.getByTestId("new-board-toggle").click();
      await alexPage.page.getByTestId("new-board-title-input").fill(boardTitle);
      await alexPage.page.getByTestId("create-board-space-button").click();
      await expect(
        alexPage.page.getByTestId("board-space-select-button"),
      ).toContainText(boardTitle, { timeout: 45_000 });

      for (const columnName of [triage, inProgress, resolved]) {
        await alexPage.page.getByTestId("new-column-input").fill(columnName);
        await alexPage.page.getByTestId("add-column-button").click();
        await expect(
          alexPage.page
            .getByTestId("kanban-column")
            .filter({ hasText: columnName }),
        ).toBeVisible({ timeout: 30_000 });
      }

      const triageColumn = alexPage.page
        .getByTestId("kanban-column")
        .filter({ hasText: triage });
      await triageColumn.getByTestId("add-card-button").click();
      await triageColumn.getByTestId("new-card-title-input").fill(ticketCard);
      await triageColumn.getByTestId("save-card-button").click();

      const card = triageColumn
        .getByTestId("kanban-card")
        .filter({ hasText: ticketCard });
      await expect(card).toBeVisible({ timeout: 30_000 });

      // Locally-queued card surfaces a draft state independently of the
      // server ack: the draft badge is visible and the archive button is
      // gated to "draft" so the archive-then-recreate promote pattern can't
      // act on an unacked card.
      const archiveButton = card.getByTestId("card-archive-button");
      const draftBadge = card.getByTestId("kanban-card-draft-badge");
      if (await draftBadge.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await expect(card).toHaveAttribute("data-card-draft", "true");
        await expect(archiveButton).toHaveAttribute("data-cap-gate", "draft");
      }
      await stepShot(alexPage.page, testInfo, "kanban-A-draft");

      // Once soland acks the card create, the draft state clears: the badge
      // disappears and archive unblocks. This is the gate the promote pattern
      // was waiting on.
      await expect(card).toHaveAttribute("data-card-draft", "false", {
        timeout: 60_000,
      });
      await expect(draftBadge).toHaveCount(0, { timeout: 30_000 });
      await expect(archiveButton).not.toHaveAttribute(
        "data-cap-gate",
        "draft",
        { timeout: 30_000 },
      );
      await stepShot(alexPage.page, testInfo, "kanban-B-settled");
    } finally {
      await alexPage.close();
    }
  });

  test("E-support.redact alex redacts a reply that leaked PII; tombstone replaces body for both", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(300_000);
    const stamp = Date.now();
    const [alexFlow, samFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-support-redact-alex"),
      openDpopUserPage(browser, request, "wf-support-redact-sam"),
    ]);
    test.skip(
      !alexFlow || !samFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!alexFlow || !samFlow) {
      return;
    }
    const sam = samFlow.user;
    const alexPage = alexFlow.page;
    const samPage = samFlow.page;
    const leaked = `Re #1042: customer SSN 123-45-6789, card 4111-1111-1111-1111 ${stamp}`;

    try {
      const realmId = await alexPage.createRealm({
        title: `Support PII redact #1042 ${stamp}`,
        summary: "Alex redacts a reply that leaked PII",
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "none",
        seedMembers: [sam.did],
      });
      await samPage.acceptInvite(realmId);

      // Alex posts the reply that accidentally leaked PII; Sam receives it.
      await alexPage.sendTimelineMessage(realmId, leaked);
      await samPage.gotoTimelineRealm(realmId);
      await expect(samPage.page.getByTestId("message-list")).toContainText(leaked, {
        timeout: 30_000,
      });

      // Alex redacts their own leaked reply. The sender-side tombstone
      // replaces the body in place.
      await alexPage.gotoTimelineRealm(realmId);
      await alexPage.clickTimelineRedact(leaked);
      await alexPage.page.getByTestId("chat-confirm-redact-button").click();
      await expect(
        alexPage.page.getByTestId("chat-redacted-tombstone"),
      ).toBeVisible({ timeout: 30_000 });
      await stepShot(alexPage.page, testInfo, "redact-A-alex-tombstone");

      // Both parties reload: the receiver-side tombstone fold is now wired
      // end-to-end (soland projects the redacted ck.message.create as a
      // tombstone on events_query/sync; inkson chat folds it into
      // chat-redacted-tombstone), so the plaintext disappears for both and
      // the tombstone surfaces on each reload.
      await alexPage.gotoTimelineRealm(realmId);
      await expect(
        alexPage.page.getByTestId("chat-redacted-tombstone"),
      ).toBeVisible({ timeout: 30_000 });
      await expect(alexPage.page.getByTestId("message-list")).not.toContainText(
        leaked,
        { timeout: 30_000 },
      );

      await samPage.gotoTimelineRealm(realmId);
      await expect(
        samPage.page.getByTestId("chat-redacted-tombstone"),
      ).toBeVisible({ timeout: 30_000 });
      await expect(samPage.page.getByTestId("message-list")).not.toContainText(
        leaked,
        { timeout: 30_000 },
      );
      await stepShot(samPage.page, testInfo, "redact-B-sam-tombstone");
    } finally {
      await Promise.allSettled([samPage.close(), alexPage.close()]);
    }
  });
});
