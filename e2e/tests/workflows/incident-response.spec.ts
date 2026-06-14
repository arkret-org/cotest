// Incident response workflow — alert triage, stakeholder updates, resolution
// Contract: e2e/scenarios/workflows/incident-response.md
// Spec refs:
//   - models/strand-and-message.md §8 (reply / edit / redact)
//   - discovery/push-notifications.md §3-§4 (routing, priority, DnD override)
//   - models/realm-and-space.md §4 (status board / FSM cells)
//   - models/morph.md §2-§4 (postmortem document morph)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import { selectDxcOption } from "../../helpers/dxc-select";

test.describe.configure({ mode: "serial" });

test.describe("workflow: incident response", () => {
  test.fixme(
    // @blocking-on: soland#workflows-incident-response-gap
    // @user-promise: e2e/scenarios/workflows/incident-response.md
    // @expected-live-by: 2026Q3
    "on-call opens SEV-2 war room; backend diagnoses; comms publishes sanitized updates; on-call edits final timeline",
    async ({ browser, request }, testInfo) => {
      // Current gaps: incident-specific status fields, priority notification
      // routing, and postmortem linkage are not wired end-to-end. The basic
      // timeline body is ready to promote once seed-member invite projection
      // and notification routing are stable.
      const stamp = Date.now();
      const oncall = uniqueUser("wf-incident-oncall");
      const backend = uniqueUser("wf-incident-backend");
      const comms = uniqueUser("wf-incident-comms");
      await Promise.all([
        ensureRegistered(request, oncall),
        ensureRegistered(request, backend),
        ensureRegistered(request, comms),
      ]);
      const [oncallToken, backendToken, commsToken] = await Promise.all([
        issueDevSession(request, oncall),
        issueDevSession(request, backend),
        issueDevSession(request, comms),
      ]);
      const oncallPage = await openUserPage(browser, oncall, { sessionToken: oncallToken });
      const backendPage = await openUserPage(browser, backend, { sessionToken: backendToken });
      const commsPage = await openUserPage(browser, comms, { sessionToken: commsToken });

      const alert = `SEV-2 checkout latency > 3s; impact: EU checkout. ${stamp}`;
      const ack = `Ack. I am taking incident commander. ${stamp}`;
      const diagnostic = `DB pool saturation from rollout 2026.05.21.1. ${stamp}`;
      const publicUpdate = `Public update: checkout latency elevated; no data loss. ${stamp}`;
      const mitigation = `Mitigation applied: rolled back payment worker. ${stamp}`;
      const finalSummary = `${alert} Root cause: payment worker rollback fixed DB pool saturation.`;

      try {
        const realmId = await oncallPage.createRealm({
          title: `SEV-2 checkout ${stamp}`,
          summary: "Incident response war room",
          discoverability: "listed",
          joinRule: "invite",
          historyVisibility: "shared",
          seedMembers: [backend.did, comms.did],
        });
        await Promise.all([backendPage.acceptInvite(realmId), commsPage.acceptInvite(realmId)]);

        await oncallPage.sendTimelineMessage(realmId, alert);
        await oncallPage.timelineEvent(alert).getByTestId("reply-button").click();
        await expect(oncallPage.page.getByTestId("reply-to-banner")).toBeVisible();
        await oncallPage.sendTimelineMessage(realmId, ack);
        await expect(oncallPage.timelineEvent(ack).getByTestId("reply-indicator")).toBeVisible({
          timeout: 30_000,
        });
        await stepShot(oncallPage.page, testInfo, "A-alert-ack");

        await backendPage.gotoTimelineRealm(realmId);
        await expect(backendPage.timelineEvent(alert)).toBeVisible({ timeout: 30_000 });
        await backendPage.timelineEvent(alert).getByTestId("reply-button").click();
        await backendPage.sendTimelineMessage(realmId, diagnostic);
        await expect(backendPage.timelineEvent(diagnostic).getByTestId("reply-indicator")).toBeVisible({
          timeout: 30_000,
        });
        await stepShot(backendPage.page, testInfo, "B-diagnostic");

        await commsPage.gotoTimelineRealm(realmId);
        await commsPage.timelineEvent(alert).getByTestId("reply-button").click();
        await commsPage.sendTimelineMessage(realmId, publicUpdate);
        await expect(commsPage.timelineEvent(publicUpdate).getByTestId("reply-indicator")).toBeVisible({
          timeout: 30_000,
        });
        await expect(commsPage.page.getByTestId("timeline")).not.toContainText("DB pool saturation");
        await stepShot(commsPage.page, testInfo, "C-public-update");

        await backendPage.gotoTimelineRealm(realmId);
        await backendPage.timelineEvent(diagnostic).getByTestId("reply-button").click();
        await backendPage.sendTimelineMessage(realmId, mitigation);
        await oncallPage.gotoTimelineRealm(realmId);
        await expect(oncallPage.timelineEvent(mitigation)).toBeVisible({ timeout: 30_000 });

        await oncallPage.timelineEvent(alert).getByTestId("edit-button").click();
        await oncallPage.page.getByTestId("edit-composer").locator("textarea").fill(finalSummary);
        await oncallPage.page.getByTestId("save-edit-button").click();
        await expect(oncallPage.timelineEvent(finalSummary)).toBeVisible({ timeout: 30_000 });
        await expect(oncallPage.page.getByTestId("write-status")).toContainText(/revised/);
        await stepShot(oncallPage.page, testInfo, "D-final-summary");
      } finally {
        await Promise.allSettled([commsPage.close(), backendPage.close(), oncallPage.close()]);
      }
    },
  );

  test(
    "E-incident.status status FSM rejects Resolved before Mitigated and records each transition in audit",
    async ({ browser, request }) => {
      // spec: realm-and-space.md §4 FSM-style status cells.
      const stamp = Date.now();
      const oncall = uniqueUser("wf-incident-fsm");
      await ensureRegistered(request, oncall);
      const token = await issueDevSession(request, oncall);
      const page = await openUserPage(browser, oncall, { sessionToken: token });

      try {
        const realmId = await page.createRealm({
          title: `SEV FSM ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });
        await page.page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
        await expect(page.page.getByTestId("kanban-panel")).toBeVisible({ timeout: 120_000 });
        await selectDxcOption(page.page.getByTestId("incident-status-select"), "resolved");
        await page.page.getByTestId("save-incident-status-button").click();
        await expect(page.page.getByTestId("incident-status-error")).toContainText(
          /invalid transition|must mitigate first/i,
          { timeout: 30_000 },
        );
        await selectDxcOption(page.page.getByTestId("incident-status-select"), "mitigated");
        await page.page.getByTestId("save-incident-status-button").click();
        await expect(page.page.getByTestId("incident-status-current")).toContainText(/mitigated/i, {
          timeout: 30_000,
        });
        await selectDxcOption(page.page.getByTestId("incident-status-select"), "resolved");
        await page.page.getByTestId("save-incident-status-button").click();
        await expect(page.page.getByTestId("incident-status-current")).toContainText(/resolved/i);

        const audit = await request.get(
          `${solandBaseUrl()}/_soland/self/audit/events?actor=${encodeURIComponent(oncall.did)}`,
          { headers: { authorization: `Bearer ${token}` } },
        );
        expect(audit.status()).toBe(200);
        const auditJson = await audit.json();
        const transitions = (auditJson.events ?? []).filter(
          (event: { action?: string }) => event.action === "incident.status.transition",
        );
        expect(transitions.length).toBeGreaterThanOrEqual(2);
        const payloads = transitions.map((event: { payload: Record<string, unknown> }) => event.payload);
        expect(payloads).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              actor: oncall.did,
              from: "investigating",
              to: "mitigated",
              realm_id: realmId,
              kind: "incident.status.transition",
            }),
            expect.objectContaining({
              actor: oncall.did,
              from: "mitigated",
              to: "resolved",
              realm_id: realmId,
              kind: "incident.status.transition",
            }),
          ]),
        );
        for (const payload of payloads) {
          expect(payload).toEqual(
            expect.objectContaining({
              actor: oncall.did,
              timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
            }),
          );
          expect(String(payload.strand_id ?? "")).toMatch(/^ck:strand:/);
          expect(String(payload.incident_id ?? "")).toMatch(/^ck:strand:/);
        }
      } finally {
        await page.close();
      }
    },
  );

  test(
    "E-incident.priority SEV-1 control and sanitized public update guard are active",
    async ({ browser, request }) => {
      // spec: push-notifications.md priority metadata + public status update hygiene.
      const stamp = Date.now();
      const commander = uniqueUser("wf-incident-priority-commander");
      await ensureRegistered(request, commander);
      const commanderToken = await issueDevSession(request, commander);
      const commanderPage = await openUserPage(browser, commander, { sessionToken: commanderToken });

      try {
        const realmId = await commanderPage.createRealm({
          title: `SEV-1 priority ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });

        await commanderPage.page.goto(`/timeline/${realmId}`, { waitUntil: "domcontentloaded" });
        await expect(commanderPage.page.getByTestId("incident-response-controls")).toBeVisible({
          timeout: 120_000,
        });
        await selectDxcOption(commanderPage.page.getByTestId("incident-priority-select"), "sev1");
        await expect(commanderPage.page.getByTestId("incident-priority-select")).toHaveValue("sev1");
        const blocked = `Public update: root cause leaked token ${stamp}`;
        await commanderPage.page.getByTestId("composer-input").fill(blocked);
        await commanderPage.page.getByTestId("send-button").click();
        await expect(commanderPage.page.getByTestId("public-update-guard-status")).toContainText(/blocked/i);
        await expect(commanderPage.page.getByTestId("write-status")).toContainText(/public update blocked/i);
        await expect(commanderPage.page.getByTestId("timeline")).not.toContainText(blocked);

        const safe = `SEV-1 public update: checkout latency is recovering ${stamp}`;
        await commanderPage.sendTimelineMessage(realmId, safe);
      } finally {
        await commanderPage.close();
      }
    },
  );

  test(
    "E-incident.postmortem links a document morph to the incident and preserves versioned final report",
    async ({ browser, request }) => {
      // spec: morph.md document morph + relation.md structural link.
      const stamp = Date.now();
      const oncall = uniqueUser("wf-incident-postmortem");
      await ensureRegistered(request, oncall);
      const token = await issueDevSession(request, oncall);
      const page = await openUserPage(browser, oncall, { sessionToken: token });

      try {
        const realmId = await page.createRealm({
          title: `SEV Postmortem ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });
        await page.page.goto(`/document/${realmId}`, { waitUntil: "domcontentloaded" });
        await page.page.getByTestId("document-title-input").fill(`Postmortem ${stamp}`);
        await page.page.getByTestId("document-body-editor").fill("Impact, root cause, action items.");
        await page.page.getByTestId("document-link-incident-input").fill(realmId);
        await page.page.getByTestId("save-document-button").click();
        await expect(page.page.getByTestId("document-status")).toContainText(/saved/i, {
          timeout: 30_000,
        });
        await page.page.getByTestId("document-body-editor").fill(
          "Impact, root cause, action items. Final owner assigned.",
        );
        await page.page.getByTestId("save-document-button").click();
        await page.page.getByTestId("document-versions-button").click();
        await expect(page.page.getByTestId("document-version-row")).toHaveCount(3, {
          timeout: 30_000,
        });
      } finally {
        await page.close();
      }
    },
  );
});
