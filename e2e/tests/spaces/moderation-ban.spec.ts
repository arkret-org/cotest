// Moderation + ban
// Contract: e2e/scenarios/spaces/moderation-ban.md
// Spec refs:
//   - governance/content-moderation.md §2.5.0 (three-layer gate)
//   - §2.5 Moderation safety commands advance confirmed sequenced state
//   - §3 Report
//   - §5.1 Redact requires ak.moderation.decision
//   - §5.2 Ban via ak.member.state{membership="ban"}

import { readCurrentSnapshot } from "../../helpers/direct-current-snapshot";
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { colandBaseUrl, colandServiceId } from "../../helpers/env";
import { acceptInviteViaApi } from "../../helpers/api";
import {
  accountActorId,
  joinRealmMemberByInviteApi,
  authHeaders,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  queryRealmEventsApi,
  rawSubmitSignedEventApi,
  refreshEventEnvelopeProof,
  resolveDefaultStrandId,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/coland-api";
import {
  allowExplicitInviteNotifications,
  assertJointStackNotRequired,
  ensureRegistered,
  issueUserSession,
  openDpopUserPage,
  uniqueUser,
} from "../../helpers/users";

// Read the canonical report family through the standard authorized Snapshot.
// Realm moderation authority does not confer deployment admin.read scope.
async function reportCurrent(request: APIRequestContext, token: string, realm: string, eventId: string) {
  const url = `${colandBaseUrl()}/_arkret/self/realm-state-snapshot/head?realm_id=${encodeURIComponent(realm)}`;
  return readCurrentSnapshot(
    timeout => request.get(url, { headers: authHeaders(token, "GET", url), timeout }),
    async body => {
      const snapshot = body as Record<string, any>;
      expect(snapshot.realm_id).toBe(realm);
      expect(Array.isArray(snapshot.current_state_entries)).toBe(true);
      return snapshot.current_state_entries.filter((entry: Record<string, any>) =>
        entry.selector?.kind === "moderation_report" && entry.selector.event_id === eventId);
    },
  );
}

test.describe.configure({ mode: "serial" });

test.describe("moderation and ban", () => {
  test("report -> ak.member.state ban -> post-ban writes rejected -> redaction filters public timeline", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s5-alice");
    const bob = uniqueUser("s5-bob");
    const mallory = uniqueUser("s5-mallory");
    const carol = uniqueUser("s5-carol");

    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, mallory),
      ensureRegistered(request, carol),
    ]);

    const [aliceToken, bobToken, malloryToken, carolToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
      issueUserSession(request, mallory),
      issueUserSession(request, carol),
    ]);
    await Promise.all([
      allowExplicitInviteNotifications(request, bobToken),
      allowExplicitInviteNotifications(request, malloryToken),
      allowExplicitInviteNotifications(request, carolToken),
    ]);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S5 Moderation API ${stamp}`,
      summary: "moderation + ban API-first coverage",
      public: true,
      discoverability: "public",
      history_access: "all_history_for_current_members",
      invitees: [bob.id, mallory.id, carol.id],
      invitee_ids: {
        [bob.id]: colandServiceId(),
        [mallory.id]: colandServiceId(),
        [carol.id]: colandServiceId(),
      },
    });
    await acceptInviteViaApi(request, bobToken, bob.id, realmId);
    await acceptInviteViaApi(request, malloryToken, mallory.id, realmId);
    await acceptInviteViaApi(request, carolToken, carol.id, realmId);
    // The first message below is authored by a non-owner. Establish the
    // ordinary Realm's explicit default discussion Strand as the root
    // controller before that member write.
    await resolveDefaultStrandId(request, aliceToken, realmId);
    await grantCapabilityEventApi(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectId: mallory.id,
      actions: ["ak.message.create"],
    });

    const abusive = `S5 abusive content ${stamp}`;
    const postBan = `S5 after ban ${stamp}`;

    const sent = await sendMessageApi(request, malloryToken, realmId, abusive);
    expect(sent.event_id).toMatch(/^ak:event:/);

    const beforeRedaction = await queryRealmEventsApi(request, aliceToken, realmId);
    expect(JSON.stringify(beforeRedaction)).toContain(abusive);

    const reportDescription = "S5 abusive content posted by mallory";
    const reportEvent = signedEventEnvelope({
      actorId: bob.id,
      realmId,
      kind: "ak.self.moderation.report",
      payload: {
        realm_id: realmId,
        target_ref: sent.event_id,
        report_reason_code: "harassment",
        description: reportDescription,
        reporter_id: bob.id,
        evidence_refs: [sent.event_id],
      },
    });
    const reportUrl = `${colandBaseUrl()}/_arkret/self/moderation/report`;
    const reportResp = await request.post(reportUrl, {
      headers: {
        ...authHeaders(bobToken, "POST", reportUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({ report_event: { event: reportEvent } }),
    });
    const reportText = await reportResp.text();
    expect(reportResp.ok(), reportText).toBeTruthy();
    const reportBody = JSON.parse(reportText);
    expect(reportBody.report_id).toMatch(/^ak:report:/);
    expect(reportBody.status).toBe("submitted");
    // The queue is a View over the accepted report: its item id is the same
    // report Event token retyped to moderation_queue_item.
    const queueItemId = String(reportBody.report_id).replace(
      /^ak:report:/,
      "ak:moderation_queue_item:",
    );

    const reportEventId = String(reportBody.report_id).replace(/^ak:report:/, "ak:event:");
    for (const token of [bobToken, malloryToken, carolToken, aliceToken]) {
      const adminUrl = `${colandBaseUrl()}/_coland/admin/reports`;
      const response = await request.get(adminUrl, { headers: authHeaders(token, "GET", adminUrl) });
      expect(response.status(), "ordinary grants cannot read the deployment administrator queue").toBe(403);
      const problem = await response.json();
      expect(wireErrCode(problem)).toBe("capability_denied");
      expect(JSON.stringify(problem)).not.toContain(queueItemId);
      expect(JSON.stringify(problem)).not.toContain(reportDescription);
    }
    for (const token of [bobToken, malloryToken, carolToken]) {
      expect(await reportCurrent(request, token, realmId, reportEventId),
        "reporter, target and bystander receive no moderator-only report current").toEqual([]);
    }
    const ownerReports = await reportCurrent(request, aliceToken, realmId, reportEventId);
    expect(ownerReports).toHaveLength(1);
    expect(ownerReports[0].value).toEqual(reportEvent.payload);

    const unauthorizedBanEvent = signedEventEnvelope({
      actorId: bob.id,
      realmId,
      kind: "ak.member.state",
      payload: {
        realm_id: realmId,
        member_id: accountActorId(mallory.id),
        membership: "ban",
        reason: "non_moderator_attempt",
      },
    });
    // `ak.self.events.command.submit.v1`: the governance Station refuses a
    // non-moderator ban at admission; membership never mints Realm admin
    // rights.
    const unauthorizedBan = await rawSubmitSignedEventApi(
      request,
      bobToken,
      unauthorizedBanEvent,
    );
    const unauthorizedText = await unauthorizedBan.text();
    expect(unauthorizedBan.status(), unauthorizedText).toBe(403);
    expect(wireErrCode(JSON.parse(unauthorizedText)), unauthorizedText).toBe(
      "capability_denied",
    );

    const reports = await reportCurrent(request, aliceToken, realmId, reportEventId);
    expect(reports).toHaveLength(1);
    expect(reports[0].value).toEqual(reportEvent.payload);

    const banEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.member.state",
      payload: {
        realm_id: realmId,
        member_id: accountActorId(mallory.id),
        membership: "ban",
        reason: "moderation_report_upheld",
      },
    });
    await submitSignedEventApi(request, aliceToken, banEvent, {
      context: `ban ${mallory.id} from ${realmId}`,
    });

    const realmAfterBan = await request.get(
      `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken, "GET", `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`) },
    );
    expect(realmAfterBan.ok()).toBeTruthy();
    const realmAfterBanBody = await realmAfterBan.json();
    expect(realmAfterBanBody.member_ids ?? []).not.toContain(mallory.id);

    const defaultStrandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const bannedWriteUrl = `${colandBaseUrl()}/_arkret/self/events`;
    const bannedWriteEnvelope = signedEventEnvelope({
      actorId: mallory.id,
      realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: defaultStrandId,
        track_name: "discussion",
        content: {
          kind: "ak.content.text",
          body: postBan,
        },
      },
    });
    const bannedWrite = await request.post(bannedWriteUrl, {
      headers: {
        ...authHeaders(malloryToken, "POST", bannedWriteUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({ event: bannedWriteEnvelope }),
    });
    const bannedWriteText = await bannedWrite.text();
    expect(bannedWrite.status(), bannedWriteText).toBe(403);

    const redactEvent = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.message.redact",
      payload: {
        message_id: sent.event_id.replace(/^ak:event:/, "ak:message:"),
        reason: "moderator_redaction",
      },
    });
    await submitSignedEventApi(request, aliceToken, redactEvent, {
      context: `redact ${sent.event_id}`,
    });

    const afterRedactionAlice = await queryRealmEventsApi(request, aliceToken, realmId);
    const afterRedactionBob = await queryRealmEventsApi(request, bobToken, realmId);
    const afterRedactionCarol = await queryRealmEventsApi(request, carolToken, realmId);
    expect(JSON.stringify(afterRedactionAlice)).not.toContain(abusive);
    expect(JSON.stringify(afterRedactionBob)).not.toContain(abusive);
    expect(JSON.stringify(afterRedactionCarol)).not.toContain(abusive);

    const exportResp = await request.get(
      `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/export`,
      { headers: authHeaders(aliceToken, "GET", `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/export`) },
    );
    expect(exportResp.ok()).toBeTruthy();
    const exportText = JSON.stringify(await exportResp.json());
    expect(exportText).toContain('"membership":"ban"');
    expect(exportText).toContain('"event_kind":"ak.message.redact"');
    expect(exportText).toContain(sent.event_id);
  });

  test("E5.3 same-state ban is rejected and leaves mallory non-member", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s5e53-alice");
    const mallory = uniqueUser("s5e53-mallory");

    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, mallory),
    ]);
    const [aliceToken, malloryToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, mallory),
    ]);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S5.3 Repeated Ban Rejection ${stamp}`,
      public: true,
      discoverability: "public",
      history_access: "all_history_for_current_members",
    });
    await joinRealmMemberByInviteApi(request, aliceToken, realmId, {
      id: mallory.id,
      token: malloryToken,
    });

    const firstBan = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.member.state",
      payload: { realm_id: realmId, member_id: accountActorId(mallory.id), membership: "ban" },
    });
    const secondBan = signedEventEnvelope({
      actorId: alice.id,
      realmId,
      kind: "ak.member.state",
      payload: { realm_id: realmId, member_id: accountActorId(mallory.id), membership: "ban" },
    });

    await submitSignedEventApi(request, aliceToken, firstBan, {
      context: `first ban ${mallory.id}`,
    });
    const secondBanSubmit = await rawSubmitSignedEventApi(
      request,
      aliceToken,
      secondBan,
    );
    const secondBanProblem = (await secondBanSubmit.json()) as {
      type?: string;
      reason_code?: string;
    };
    expect(secondBanSubmit.status()).toBe(409);
    expect(wireErrCode(secondBanProblem)).toBe("failed_precondition");
    expect(secondBanProblem.reason_code).toBe("invalid_membership_transition");

    const realm = await request.get(`${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`, {
      headers: authHeaders(aliceToken, "GET", `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`),
    });
    expect(realm.ok()).toBeTruthy();
    const body = await realm.json();
    expect(body.member_ids ?? []).not.toContain(mallory.id);
  });

  test("owner can ban a member from the inkson admin member row", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const mallory = uniqueUser("s5-ui-mallory");

    await ensureRegistered(request, mallory);
    const aliceFlow = await openDpopUserPage(browser, request, "s5-ui-alice", {
      prepareMlsDevice: false,
    });
    if (!aliceFlow) {
      assertJointStackNotRequired("moderation ban browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceFlow.user;
    const aliceToken = await issueUserSession(request, alice);
    const malloryToken = await issueUserSession(request, mallory);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S5 UI Ban ${stamp}`,
      public: true,
      discoverability: "public",
      history_access: "all_history_for_current_members",
    });
    await joinRealmMemberByInviteApi(request, aliceToken, realmId, {
      id: mallory.id,
      token: malloryToken,
    });

    const alicePage = aliceFlow.page;
    try {
      await alicePage.gotoRealmAdminSection(realmId, "members");
      // The roster row keys itself by `data-member-id`, whose value is the
      // canonical ActorId key (`ActorId::to_string()` = canonical JSON), not a
      // bare principal DID: inkson renamed the attribute and switched to the
      // stable identity id in 6ff60d53. Match on the principal id as a
      // substring so this does not depend on canonical key byte order.
      const malloryRow = alicePage.page.locator(
        `.member-row[data-member-id*="${mallory.id}"]`,
      );
      await expect(malloryRow).toBeVisible({ timeout: 30_000 });
      // The "Recovery setup is incomplete" banner can render over the member
      // row and intercept pointer events; complete/dismiss it before banning.
      await alicePage.clickWithPassivePromptRetry(
        malloryRow.locator(".ban-member-button"),
      );
      await expect(alicePage.page.locator("main")).toContainText(/banned/i, {
        timeout: 30_000,
      });

      const realm = await request.get(
        `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(aliceToken, "GET", `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`) },
      );
      expect(realm.ok()).toBeTruthy();
      const body = await realm.json();
      expect(body.member_ids ?? []).not.toContain(mallory.id);
    } finally {
      await alicePage.close();
    }
  });
});
