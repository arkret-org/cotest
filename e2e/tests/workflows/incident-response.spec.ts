// Incident response workflow — alert triage, stakeholder updates, resolution
// Contract: e2e/scenarios/workflows/incident-response.md
// Spec refs:
//   - models/strand-and-message.md §8 (reply / edit / redact)
//   - discovery/push-notifications.md §3-§4 (routing, priority, DnD override)
//   - models/common-fields.md §5.3 (canonical Strand stage)
//   - models/morph.md §2-§4 (postmortem document morph)

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  queryRealmEventsApi,
  signedEventEnvelope,
  submitSignedEventApi,
  retypeEventDerivedId,
  typedId,
  type StreamScanOutcome,
} from "../../helpers/coland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
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
    test.setTimeout(360_000);
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
        historyAccess: "all_history_for_current_members",
        mlsActivated: false,
        seedMembers: [backend.id, comms.id],
      });
      await Promise.all([
        backendPage.acceptInvite(realmId),
        commsPage.acceptInvite(realmId),
      ]);
      await oncallPage.grantRealmCapability(
        realmId,
        backendFlow.session.accountId,
        "ak.message.create",
      );
      await oncallPage.grantRealmCapability(
        realmId,
        commsFlow.session.accountId,
        "ak.message.create",
      );

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

  test("E-incident.stage records the canonical direct stage transition when no workflow profile is installed", async ({
    request,
  }) => {
    // spec: common-fields.md §5.3.3-§5.3.4 — core stage has no directional
    // lifecycle transition rule. A Realm profile may narrow it, but this fixture installs none.
    const stamp = Date.now();
    const oncall = uniqueUser("wf-incident-lifecycle");
    await ensureRegistered(request, oncall);
    const token = await issueUserSession(request, oncall);
    const realmId = await createRealmApi(request, token, {
      title: `SEV lifecycle ${stamp}`,
      ownerId: oncall.id,
    });
    const createdAt = canonicalTimestamp();
    // `ak.strand.create` derives `ak:strand:` from the create Event, so the
    // object carries no `id` and the caller retypes the finished envelope.
    const incidentStrandEnvelope = signedEventEnvelope({
        actorId: oncall.id,
        realmId,
        kind: "ak.strand.create",
        createdAt,
        payload: {
          object: {
            schema: "ak.schema.strand.v1",
            realm_id: realmId,
            metadata: { title: "SEV-2 checkout outage" },
            tracks: { discussion: { enabled: true, is_primary: true } },
            created_by: accountActorId(oncall.id),
            created_at: createdAt,
          },
        },
      });
    await submitSignedEventApi(request, token, incidentStrandEnvelope, {
      context: "create investigating incident strand",
    });
    const incidentStrandId = retypeEventDerivedId(
      String(incidentStrandEnvelope.event_id),
      "strand",
    );

    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorId: oncall.id,
        realmId,
        kind: "ak.strand.stage.set",
        payload: {
          strand_id: incidentStrandId,
          stage: "in_progress",
        },
      }),
      { context: "start incident investigation at the protocol stage layer" },
    );

    await submitSignedEventApi(
      request,
      token,
      signedEventEnvelope({
        actorId: oncall.id,
        realmId,
        kind: "ak.strand.stage.set",
        payload: {
          strand_id: incidentStrandId,
          stage: "done",
          expected_stage: "in_progress",
        },
      }),
      { context: "resolve incident directly at the protocol stage layer" },
    );

    const eventLog = await queryRealmEventsApi(request, token, realmId);
    const events = Array.isArray(eventLog.events) ? eventLog.events : [];
    const stageUpdates = events.filter((event) => {
      if (!event || typeof event !== "object") {
        return false;
      }
      const record = event as Record<string, unknown>;
      return (
        record.kind === "ak.strand.stage.set" &&
        JSON.stringify(record.payload ?? {}).includes(incidentStrandId)
      );
    });
    expect(stageUpdates).toHaveLength(2);
    expect(stageUpdates.map((event) => (event.payload as Record<string, unknown>)?.stage)).toEqual([
      "in_progress", "done",
    ]);
    expect((stageUpdates[1]?.payload as Record<string, unknown>)?.stage).toBe(
      "done",
    );
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
        mlsActivated: true,
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
      const blockedRow = commanderPage.timelineEvent(blocked);
      await expect(blockedRow).toBeVisible();
      await expect(blockedRow.getByTestId("message-send-status")).toHaveAttribute(
        "title",
        "Message send failed",
      );
      await expect(blockedRow.getByTestId("chat-message-error")).toContainText(
        "public_update_blocked",
      );

      const safe = `SEV-1 public update: checkout latency is recovering ${stamp}`;
      await commanderPage.sendTimelineMessage(realmId, safe);
      await expect(commanderPage.timelineEvent(safe)).toBeVisible({
        timeout: 30_000,
      });

      const eventLog = await scanRealmEventsWithDpop(
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

async function scanRealmEventsWithDpop(
  request: APIRequestContext,
  session: DpopUserSession,
  realmId: string,
): Promise<Record<string, unknown>> {
  const url = `${colandBaseUrl()}/_arkret/self/streams/scan`;
  const streamRef = { kind: "realm", realm_id: realmId };
  const response = await request.post(url, {
    data: canonicalJson({ realm_id: realmId, stream_ref: streamRef, after_position: null, limit: 100 }),
    headers: {
      ...selfPathHeadersForDpopSession(session, "POST", url),
      "content-type": "application/json",
    },
  });
  const text = await response.text();
  expect(response.status(), `incident authorized stream scan returned ${text}`).toBe(200);
  const scan = JSON.parse(text) as StreamScanOutcome;
  expect(Array.isArray(scan.committed_events)).toBe(true);
  expect(scan.truncated, "privacy readback must cover the complete authorized interval").toBe(false);
  const events = scan.committed_events.map((row) => {
    expect(row.commit.stream_ref).toEqual(streamRef);
    if (!("event" in row)) throw new Error("the owner's incident Event readback must be fully disclosed");
    expect(row.event.event_id).toBe(row.commit.event_ref);
    return row.event;
  });
  return { events };
}
