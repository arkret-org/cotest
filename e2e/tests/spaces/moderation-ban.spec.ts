// Moderation + ban
// Contract: e2e/scenarios/spaces/moderation-ban.md
// Spec refs:
//   - governance/content-moderation.md §2.5.0 (three-layer gate)
//   - §2.5 Moderation MUST anchored
//   - §3 Report
//   - §5.1 Redact requires ak.moderation.decision
//   - §5.2 Ban via ak.member.state{membership="ban"}

import { expect, test } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import {
  accountActorId,
  addRealmMemberApi,
  advanceEnvelopeToActorFrontier,
  alignSignedEventToActorFrontierApi,
  authHeaders,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  issueAuthorizationLeasesApi,
  prepareEventForAuthorizationLeaseApi,
  prepareSignedEventCbaApi,
  queryRealmEventsApi,
  readRealmSealBasis,
  refreshEventEnvelopeProof,
  resolveDefaultStrandId,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  uniqueUser,
} from "../../helpers/users";

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
      issueDevSession(request, alice),
      issueDevSession(request, bob),
      issueDevSession(request, mallory),
      issueDevSession(request, carol),
    ]);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S5 Moderation API ${stamp}`,
      summary: "moderation + ban API-first coverage",
      public: true,
      discoverability: "public",
      history_access: "all_history_for_current_members",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);
    await addRealmMemberApi(request, aliceToken, realmId, mallory.id);
    await addRealmMemberApi(request, aliceToken, realmId, carol.id);
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

    const reportEvent = signedEventEnvelope({
      actorId: bob.id,
      realmId,
      kind: "ak.self.moderation.report",
      payload: {
        realm_id: realmId,
        target_ref: sent.event_id,
        report_reason_code: "harassment",
        description: "S5 abusive content posted by mallory",
        reporter_id: bob.id,
        evidence_refs: [sent.event_id],
      },
    });
    await advanceEnvelopeToActorFrontier(request, bobToken, reportEvent);
    const sealBasis = await readRealmSealBasis(request, bobToken, realmId);
    const sealRef = Array.isArray(sealBasis.leaves) ? sealBasis.leaves[0] : undefined;
    expect(typeof sealRef, "moderation report Seal reference").toBe("string");
    reportEvent.seal_ref = sealRef;
    const proof = Array.isArray(reportEvent.proofs)
      ? (reportEvent.proofs[0] as Record<string, unknown> | undefined)
      : undefined;
    const verificationMethod = String(proof?.verification_method ?? "");
    const keyIdFragment = verificationMethod.split("#").at(-1) ?? verificationMethod;
    reportEvent.auth_context = {
      key_id: keyIdFragment.startsWith("ak:")
        ? keyIdFragment.slice(3)
        : keyIdFragment,
      key_epoch: 0,
    };
    refreshEventEnvelopeProof(reportEvent, verificationMethod);
    const reportUrl = `${solandBaseUrl()}/_arkret/self/moderation/report`;
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

    const reporterReports = await request.get(`${solandBaseUrl()}/_soland/admin/reports`, {
      headers: authHeaders(bobToken),
    });
    expect(reporterReports.ok()).toBeTruthy();
    expect(JSON.stringify(await reporterReports.json())).not.toContain(reportBody.report_id);

    const targetReports = await request.get(`${solandBaseUrl()}/_soland/admin/reports`, {
      headers: authHeaders(malloryToken),
    });
    expect(targetReports.ok()).toBeTruthy();
    expect(JSON.stringify(await targetReports.json())).not.toContain(reportBody.report_id);

    const bystanderReports = await request.get(`${solandBaseUrl()}/_soland/admin/reports`, {
      headers: authHeaders(carolToken),
    });
    expect(bystanderReports.ok()).toBeTruthy();
    expect(JSON.stringify(await bystanderReports.json())).not.toContain(reportBody.report_id);

    const ownerReports = await request.get(`${solandBaseUrl()}/_soland/admin/reports`, {
      headers: authHeaders(aliceToken),
    });
    expect(ownerReports.ok()).toBeTruthy();
    expect(JSON.stringify(await ownerReports.json())).toContain(reportBody.report_id);

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
    await prepareSignedEventCbaApi(request, bobToken, unauthorizedBanEvent);
    await alignSignedEventToActorFrontierApi(
      request,
      bobToken,
      unauthorizedBanEvent,
    );
    const leaseUrl = `${solandBaseUrl()}/_arkret/self/authorization-leases`;
    const unauthorizedBan = await request.post(leaseUrl, {
      headers: {
        ...authHeaders(bobToken, "POST", leaseUrl),
        "content-type": "application/json",
        "idempotency-key": `cotest-unauthorized-ban-${unauthorizedBanEvent.event_id}`,
      },
      data: canonicalJson({ events: [unauthorizedBanEvent] }),
    });
    // Lease issuance runs the same read-only admission as final submission;
    // it may narrow existing authority but must never mint Realm admin rights.
    const unauthorizedText = await unauthorizedBan.text();
    expect(unauthorizedBan.status(), unauthorizedText).toBe(403);
    expect(unauthorizedText).toContain(
      "missing_capability",
    );

    const reports = await request.get(`${solandBaseUrl()}/_soland/admin/reports`, {
      headers: authHeaders(aliceToken),
    });
    expect(reports.ok()).toBeTruthy();
    expect(JSON.stringify(await reports.json())).toContain(reportBody.report_id);

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
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(realmAfterBan.ok()).toBeTruthy();
    const realmAfterBanBody = await realmAfterBan.json();
    expect(realmAfterBanBody.member_ids ?? []).not.toContain(mallory.id);

    const defaultStrandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const bannedWriteUrl = `${solandBaseUrl()}/_arkret/self/events`;
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
      data: canonicalJson(bannedWriteEnvelope),
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
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/export`,
      { headers: authHeaders(aliceToken) },
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
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S5.3 Idempotent Ban API ${stamp}`,
      public: true,
      discoverability: "public",
      history_access: "all_history_for_current_members",
    });
    await addRealmMemberApi(request, aliceToken, realmId, mallory.id);

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
    // common-fields.md §4.5: every same-state membership transition is
    // illegal. Full lease pre-admission must reject ban -> ban before it can
    // enter the governance cell and create a Bottom join.
    await prepareEventForAuthorizationLeaseApi(
      request,
      aliceToken,
      secondBan,
    );
    const secondBanLease = await issueAuthorizationLeasesApi(
      request,
      aliceToken,
      [secondBan],
    );
    const secondBanProblem = (await secondBanLease.json()) as {
      type?: string;
      reason_code?: string;
    };
    expect(secondBanLease.status()).toBe(422);
    expect(wireErrCode(secondBanProblem)).toBe("failed_precondition");
    expect(secondBanProblem.reason_code).toBe("invalid_membership_transition");

    const realm = await request.get(`${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`, {
      headers: authHeaders(aliceToken),
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
    const aliceToken = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S5 UI Ban ${stamp}`,
      public: true,
      discoverability: "public",
      history_access: "all_history_for_current_members",
    });
    await addRealmMemberApi(request, aliceToken, realmId, mallory.id);

    const alicePage = aliceFlow.page;
    try {
      await alicePage.gotoRealmAdminSection(realmId, "members");
      // The roster row keys itself by `data-member-id`, whose value is the
      // canonical ActorId key (`ActorId::to_string()` = canonical JSON), not a
      // bare principal DID: inkson renamed the attribute and switched to the
      // stable identity id in 6ff60d53. Match on the principal id as a
      // substring so this does not depend on canonical key byte order.
      const malloryRow = alicePage.page.locator(
        `[data-testid="member-row"][data-member-id*="${mallory.id}"]`,
      );
      await expect(malloryRow).toBeVisible({ timeout: 30_000 });
      // The "Recovery setup is incomplete" banner can render over the member
      // row and intercept pointer events; complete/dismiss it before banning.
      await alicePage.clickWithPassivePromptRetry(
        malloryRow.getByTestId("ban-member-button"),
      );
      await expect(alicePage.page.locator("main")).toContainText(/banned/i, {
        timeout: 30_000,
      });

      const realm = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(aliceToken) },
      );
      expect(realm.ok()).toBeTruthy();
      const body = await realm.json();
      expect(body.member_ids ?? []).not.toContain(mallory.id);
    } finally {
      await alicePage.close();
    }
  });
});
