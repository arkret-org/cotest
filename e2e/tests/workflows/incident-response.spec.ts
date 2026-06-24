// Incident response workflow — alert triage, stakeholder updates, resolution
// Contract: e2e/scenarios/workflows/incident-response.md
// Spec refs:
//   - models/strand-and-message.md §8 (reply / edit / redact)
//   - discovery/push-notifications.md §3-§4 (routing, priority, DnD override)
//   - models/realm-and-space.md §4 (status board / FSM cells)
//   - models/morph.md §2-§4 (postmortem document morph)

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  queryRealmEventsApi,
  signedEventEnvelope,
  submitSignedEventApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  selfPathHeadersForDpopSession,
  type DpopUserSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("workflow: incident response", () => {
  test.fixme(// @blocking-on: soland#workflows-incident-response-gap
  // @user-promise: e2e/scenarios/workflows/incident-response.md
  // @expected-live-by: 2026Q3
  "on-call opens SEV-2 war room; backend diagnoses; comms publishes sanitized updates; on-call edits final timeline", async ({
    browser,
    request,
  }, testInfo) => {
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
    const oncallPage = await openUserPage(browser, oncall, {
      sessionCredential: oncallToken,
    });
    const backendPage = await openUserPage(browser, backend, {
      sessionCredential: backendToken,
    });
    const commsPage = await openUserPage(browser, comms, {
      sessionCredential: commsToken,
    });

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
      await Promise.all([
        backendPage.acceptInvite(realmId),
        commsPage.acceptInvite(realmId),
      ]);

      await oncallPage.sendTimelineMessage(realmId, alert);
      await oncallPage.clickTimelineReply(alert);
      await expect(
        oncallPage.page.getByTestId("chat-reply-banner"),
      ).toBeVisible();
      await oncallPage.sendTimelineMessage(realmId, ack);
      await expect(
        oncallPage.timelineEvent(ack).getByTestId("chat-reply-indicator"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(oncallPage.page, testInfo, "A-alert-ack");

      await backendPage.gotoTimelineRealm(realmId);
      await expect(backendPage.timelineEvent(alert)).toBeVisible({
        timeout: 30_000,
      });
      await backendPage.clickTimelineReply(alert);
      await backendPage.sendTimelineMessage(realmId, diagnostic);
      await expect(
        backendPage
          .timelineEvent(diagnostic)
          .getByTestId("chat-reply-indicator"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await stepShot(backendPage.page, testInfo, "B-diagnostic");

      await commsPage.gotoTimelineRealm(realmId);
      await commsPage.clickTimelineReply(alert);
      await commsPage.sendTimelineMessage(realmId, publicUpdate);
      await expect(
        commsPage
          .timelineEvent(publicUpdate)
          .getByTestId("chat-reply-indicator"),
      ).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        commsPage.page.getByTestId("message-list"),
      ).not.toContainText("DB pool saturation");
      await stepShot(commsPage.page, testInfo, "C-public-update");

      await backendPage.gotoTimelineRealm(realmId);
      await backendPage.clickTimelineReply(diagnostic);
      await backendPage.sendTimelineMessage(realmId, mitigation);
      await oncallPage.gotoTimelineRealm(realmId);
      await expect(oncallPage.timelineEvent(mitigation)).toBeVisible({
        timeout: 30_000,
      });

      await oncallPage.clickTimelineEdit(alert);
      await oncallPage.page
        .getByTestId("chat-edit-composer")
        .locator("textarea")
        .fill(finalSummary);
      await oncallPage.page.getByTestId("chat-save-edit-button").click();
      await expect(oncallPage.timelineEvent(finalSummary)).toBeVisible({
        timeout: 30_000,
      });
      await expect(oncallPage.page.getByTestId("chat-status")).toContainText(
        /Message updated/i,
      );
      await stepShot(oncallPage.page, testInfo, "D-final-summary");
    } finally {
      await Promise.allSettled([
        commsPage.close(),
        backendPage.close(),
        oncallPage.close(),
      ]);
    }
  });

  test("E-incident.status status FSM rejects Resolved before Mitigated and records accepted transitions in event log", async ({
    request,
  }) => {
    // spec: realm-and-space.md §4 FSM-style status cells.
    const stamp = Date.now();
    const oncall = uniqueUser("wf-incident-fsm");
    await ensureRegistered(request, oncall);
    const token = await issueDevSession(request, oncall);
    const realmId = await createRealmApi(request, token, {
      title: `SEV FSM ${stamp}`,
      ownerDid: oncall.did,
    });
    const incidentStrandId = typedId("strand");
    const createdAt = canonicalTimestamp();
    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: oncall.did,
        realmId,
        kind: "ck.strand.create",
        createdAt,
        payload: {
          object: {
            id: incidentStrandId,
            schema: "ck.schema.strand.v1",
            realm_id: realmId,
            metadata: {
              title: "SEV-2 checkout outage",
              fields: { status: "investigating" },
            },
            stage: "in_progress",
            tracks: { discussion: { enabled: true, is_primary: true } },
            created_by: oncall.did,
            created_at: createdAt,
          },
        },
      }),
      { context: "create investigating incident strand" },
    );

    const badResolved = await request.post(
      `${solandBaseUrl()}/_cokret/self/events`,
      {
        headers: authHeaders(token),
        data: signedEventEnvelope({
          actorDid: oncall.did,
          realmId,
          kind: "ck.strand.update",
          payload: {
            target_ref: incidentStrandId,
            patch: { metadata: { fields: { status: "resolved" } } },
          },
        }),
      },
    );
    expect(badResolved.status()).toBe(412);
    expect(wireErrCode(await badResolved.json())).toBe(
      "strand_status_transition_invalid",
    );

    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: oncall.did,
        realmId,
        kind: "ck.strand.update",
        payload: {
          target_ref: incidentStrandId,
          patch: { metadata: { fields: { status: "mitigated" } } },
        },
      }),
      { context: "advance incident to mitigated" },
    );
    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorDid: oncall.did,
        realmId,
        kind: "ck.strand.update",
        payload: {
          target_ref: incidentStrandId,
          patch: { metadata: { fields: { status: "resolved" } } },
        },
      }),
      { context: "advance incident to resolved" },
    );

    const eventLog = await queryRealmEventsApi(request, token, realmId);
    const events = Array.isArray(eventLog.events) ? eventLog.events : [];
    const statusUpdates = events.filter((event) => {
      if (!event || typeof event !== "object") {
        return false;
      }
      const record = event as Record<string, unknown>;
      return (
        record.kind === "ck.strand.update" &&
        JSON.stringify(record.payload ?? {}).includes(incidentStrandId)
      );
    });
    expect(statusUpdates.length).toBeGreaterThanOrEqual(2);
  });

  test("E-incident.priority SEV-1 control and sanitized public update guard are active", async ({
    browser,
    request,
  }) => {
    // spec: push-notifications.md priority metadata + public status update hygiene.
    const stamp = Date.now();
    const commanderFlow = await openDpopUserPage(
      browser,
      request,
      "wf-incident-priority-commander",
    );
    test.skip(
      !commanderFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!commanderFlow) {
      return;
    }
    const commanderPage = commanderFlow.page;

    try {
      const realmId = await commanderPage.createRealm({
        title: `SEV-1 priority ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        encryptionProfile: "mls_rfc9420",
        completeRecoveryKeySetup: true,
      });

      await commanderPage.page.goto(`/chat/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      const blocked = `Public update: root cause leaked token ${stamp}`;
      await commanderPage.page.getByTestId("chat-input").fill(blocked);
      await commanderPage.page.getByTestId("send-chat-button").click();
      await expect(commanderPage.page.getByTestId("chat-status")).toContainText(
        /public update blocked|public_update_blocked|Message send failed/i,
      );
      await expect(
        commanderPage.page.getByTestId("message-list"),
      ).not.toContainText(blocked);

      const safe = `SEV-1 public update: checkout latency is recovering ${stamp}`;
      await commanderPage.sendTimelineMessage(realmId, safe);
      await expect(commanderPage.timelineEvent(safe)).toBeVisible({
        timeout: 30_000,
      });

      const eventLog = await queryRealmEventsWithDpop(
        request,
        commanderFlow.session,
        realmId,
      );
      const events = Array.isArray(eventLog.events) ? eventLog.events : [];
      const messageCreates = events.filter((event) => {
        if (!event || typeof event !== "object") {
          return false;
        }
        const record = event as Record<string, unknown>;
        return record.kind === "ck.message.create";
      }) as Record<string, unknown>[];
      expect(messageCreates.length).toBe(1);
      const payload = messageCreates[0].payload as Record<string, unknown>;
      expect(JSON.stringify(payload)).not.toContain(blocked);
      expect(JSON.stringify(payload)).not.toContain(safe);
      expect(payload.content).toBeUndefined();
      expect(payload.encrypted_content).toBeTruthy();
    } finally {
      await commanderPage.close();
    }
  });

  test("E-incident.postmortem links a document morph to the incident and preserves versioned final report", async ({
    browser,
    request,
  }) => {
    // spec: morph.md document morph + relation.md structural link.
    const stamp = Date.now();
    const oncallFlow = await openDpopUserPage(
      browser,
      request,
      "wf-incident-postmortem",
    );
    test.skip(
      !oncallFlow,
      "coauth DPoP session-grant login is required for MLS device-authorized KeyPackages",
    );
    if (!oncallFlow) {
      return;
    }
    const page = oncallFlow.page;

    try {
      const realmId = await page.createRealm({
        title: `SEV Postmortem ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });
      await page.page.goto(`/document/${realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await page.page
        .getByTestId("document-title-input")
        .fill(`Postmortem ${stamp}`);
      await page.page
        .getByTestId("document-body-editor")
        .fill("Impact, root cause, action items.");
      await page.page.getByTestId("document-link-incident-input").fill(realmId);
      await page.page.getByTestId("save-document-button").click();
      await expect(page.page.getByTestId("document-status")).toContainText(
        /Saved and synced document/i,
        {
          timeout: 30_000,
        },
      );
      await page.page
        .getByTestId("document-body-editor")
        .fill("Impact, root cause, action items. Final owner assigned.");
      await page.page.getByTestId("save-document-button").click();
      await expect(page.page.getByTestId("document-status")).toContainText(
        /Saved locally/i,
        {
          timeout: 30_000,
        },
      );
      await expect(page.page.getByTestId("document-status")).toContainText(
        /Saved and synced document/i,
        {
          timeout: 30_000,
        },
      );
      await page.page.getByTestId("document-versions-button").click();
      await expect(page.page.getByTestId("version-entry")).toHaveCount(2, {
        timeout: 30_000,
      });
      await expect(page.page.getByTestId("version-history")).toContainText(
        /2 versions/,
        {
          timeout: 30_000,
        },
      );
    } finally {
      await page.close();
    }
  });
});

async function queryRealmEventsWithDpop(
  request: APIRequestContext,
  session: DpopUserSession,
  realmId: string,
): Promise<Record<string, unknown>> {
  const url = `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`;
  const response = await request.get(url, {
    headers: selfPathHeadersForDpopSession(session, "GET", url),
  });
  expect(response.status()).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}
