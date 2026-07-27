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
  alignSignedEventToActorFrontierApi,
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
  assertJointStackNotRequired,
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
  test("on-call opens SEV-2 war room; backend diagnoses; comms publishes sanitized updates; on-call edits final timeline", async ({
    browser,
    request,
  }, testInfo) => {
    const stamp = Date.now();
    const [oncallFlow, backendFlow, commsFlow] = await Promise.all([
      openDpopUserPage(browser, request, "wf-incident-oncall", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "wf-incident-backend", {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, "wf-incident-comms", {
        prepareMlsDevice: false,
      }),
    ]);
    if (!oncallFlow || !backendFlow || !commsFlow) {
      assertJointStackNotRequired("incident response browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const backend = backendFlow.user;
    const comms = commsFlow.user;
    const oncallPage = oncallFlow.page;
    const backendPage = backendFlow.page;
    const commsPage = commsFlow.page;

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
        encryptionProfile: "none",
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
      await expect(commsPage.timelineEvent(publicUpdate)).not.toContainText(
        "DB pool saturation",
      );
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
        kind: "ak.strand.create",
        createdAt,
        payload: {
          object: {
            id: incidentStrandId,
            schema: "ak.schema.strand.v1",
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

    const badResolvedEvent = signedEventEnvelope({
      actorDid: oncall.did,
      realmId,
      kind: "ak.strand.update",
      payload: {
        target_ref: incidentStrandId,
        patch: { metadata: { fields: { status: "resolved" } } },
      },
    });
    await alignSignedEventToActorFrontierApi(request, token, badResolvedEvent);
    const badResolved = await request.post(
      `${solandBaseUrl()}/_arkret/self/events`,
      {
        headers: authHeaders(token),
        data: badResolvedEvent,
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
        kind: "ak.strand.update",
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
        kind: "ak.strand.update",
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
        record.kind === "ak.strand.update" &&
        JSON.stringify(record.payload ?? {}).includes(incidentStrandId)
      );
    });
    expect(statusUpdates.length).toBeGreaterThanOrEqual(2);
  });

  test("E-incident.priority SEV-1 control and sanitized public update guard are active", async ({
    browser,
    request,
  }) => {
    test.setTimeout(360_000);
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
        return record.kind === "ak.message.create";
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
});

async function queryRealmEventsWithDpop(
  request: APIRequestContext,
  session: DpopUserSession,
  realmId: string,
): Promise<Record<string, unknown>> {
  const url = `${solandBaseUrl()}/_arkret/self/events?realms=${encodeURIComponent(realmId)}&limit=100`;
  const response = await request.get(url, {
    headers: selfPathHeadersForDpopSession(session, "GET", url),
  });
  expect(response.status()).toBe(200);
  return (await response.json()) as Record<string, unknown>;
}
