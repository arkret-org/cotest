// Moderation + ban
// Contract: e2e/scenarios/spaces/moderation-ban.md
// Spec refs:
//   - governance/content-moderation.md §2.5.0 (three-layer gate)
//   - §2.5 Moderation MUST anchored
//   - §3 Report
//   - §5.1 Redact requires cx.space.moderate
//   - §5.2 Ban via cx.member.state{membership="ban"}

import { expect, test } from "@playwright/test";
import { solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  addSpaceMemberApi,
  authHeaders,
  createSpaceApi,
  makeOperation,
  pushFederationOperations,
  querySpaceEventsApi,
  sendMessageApi,
  signedEventEnvelope,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("moderation and ban", () => {
  test("report -> cx.member.state ban -> post-ban writes rejected -> redaction filters public timeline", async ({
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

    const spaceId = await createSpaceApi(request, aliceToken, {
      title: `S5 Moderation API ${stamp}`,
      summary: "moderation + ban API-first coverage",
      public: true,
      discoverability: "public",
      history_visibility: "shared",
    });
    await addSpaceMemberApi(request, aliceToken, spaceId, bob.did);
    await addSpaceMemberApi(request, aliceToken, spaceId, mallory.did);
    await addSpaceMemberApi(request, aliceToken, spaceId, carol.did);

    const abusive = `S5 abusive content ${stamp}`;
    const postBan = `S5 after ban ${stamp}`;

    const sent = await sendMessageApi(request, malloryToken, spaceId, abusive);
    expect(sent.event_id).toMatch(/^ck:event:/);

    const beforeRedaction = await querySpaceEventsApi(request, aliceToken, spaceId);
    expect(JSON.stringify(beforeRedaction)).toContain(abusive);

    const reportResp = await request.post(`${solandBaseUrl()}/api/v1/moderation/report`, {
      headers: authHeaders(bobToken),
      data: {
        space_id: spaceId,
        target_ref: sent.event_id,
        reason: "harassment",
        description: "S5 abusive content posted by mallory",
        reporter: bob.did,
        evidence_refs: [sent.event_id],
      },
    });
    expect(reportResp.ok()).toBeTruthy();
    const reportBody = await reportResp.json();
    expect(reportBody.report_id).toMatch(/^ck:report:/);
    expect(reportBody.status).toBe("queued");

    const reporterReports = await request.get(
      `${solandBaseUrl()}/api/v1/moderation/reports?realm_id=${encodeURIComponent(spaceId)}`,
      { headers: authHeaders(bobToken) },
    );
    expect(reporterReports.ok()).toBeTruthy();
    expect(JSON.stringify(await reporterReports.json())).toContain(reportBody.report_id);

    const targetReports = await request.get(
      `${solandBaseUrl()}/api/v1/moderation/reports?realm_id=${encodeURIComponent(spaceId)}`,
      { headers: authHeaders(malloryToken) },
    );
    expect(targetReports.ok()).toBeTruthy();
    expect(JSON.stringify(await targetReports.json())).not.toContain(reportBody.report_id);

    const bystanderReports = await request.get(
      `${solandBaseUrl()}/api/v1/moderation/reports?realm_id=${encodeURIComponent(spaceId)}`,
      { headers: authHeaders(carolToken) },
    );
    expect(bystanderReports.ok()).toBeTruthy();
    expect(JSON.stringify(await bystanderReports.json())).not.toContain(reportBody.report_id);

    const targetAdminReports = await request.get(`${solandBaseUrl()}/_soland/admin/reports`, {
      headers: authHeaders(malloryToken),
    });
    expect(targetAdminReports.ok()).toBeTruthy();
    expect(JSON.stringify(await targetAdminReports.json())).not.toContain(reportBody.report_id);

    const ownerReports = await request.get(
      `${solandBaseUrl()}/api/v1/moderation/reports?realm_id=${encodeURIComponent(spaceId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(ownerReports.ok()).toBeTruthy();
    expect(JSON.stringify(await ownerReports.json())).toContain(reportBody.report_id);

    const unauthorizedBan = await request.post(`${solandBaseUrl()}/api/v1/events`, {
      headers: authHeaders(bobToken),
      data: signedEventEnvelope({
        actorDid: bob.did,
        realmId: spaceId,
        kind: "cx.member.state",
        payload: {
          actor_id: mallory.did,
          member: mallory.did,
          membership: "ban",
          reason: "non_moderator_attempt",
        },
      }),
    });
    expect(unauthorizedBan.status()).toBe(403);
    expect(JSON.stringify(await unauthorizedBan.json())).toContain("missing_capability");

    const reports = await request.get(`${solandBaseUrl()}/_soland/admin/reports`, {
      headers: authHeaders(aliceToken),
    });
    expect(reports.ok()).toBeTruthy();
    expect(JSON.stringify(await reports.json())).toContain(reportBody.report_id);

    const banOperation = makeOperation({
      spaceId,
      objectType: "cx.member.state",
      payload: {
        actor_id: mallory.did,
        member: mallory.did,
        membership: "ban",
        reason: "moderation_report_upheld",
        report_ref: reportBody.report_id,
      },
    });
    const banPush = await pushFederationOperations(request, [banOperation], {
      origin: solandServiceDid(),
      spaceId,
    });
    expect(banPush.accepted).toContain(banOperation.operation_id);

    const spaceAfterBan = await request.get(
      `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(spaceAfterBan.ok()).toBeTruthy();
    const spaceAfterBanBody = await spaceAfterBan.json();
    expect(spaceAfterBanBody.members ?? []).not.toContain(mallory.did);

    const bannedWrite = await request.post(`${solandBaseUrl()}/api/v1/messages/send`, {
      headers: authHeaders(malloryToken),
      data: { space_id: spaceId, content: { body: postBan } },
    });
    expect([401, 403, 404]).toContain(bannedWrite.status());

    const redactOperation = makeOperation({
      spaceId,
      objectType: "cx.message.redact",
      payload: {
        target_event_id: sent.event_id,
        redacts: sent.event_id,
        reason: "moderator_redaction",
        actor: alice.did,
      },
    });
    const redactPush = await pushFederationOperations(request, [redactOperation], {
      origin: solandServiceDid(),
      spaceId,
    });
    expect(redactPush.accepted).toContain(redactOperation.operation_id);

    const afterRedactionAlice = await querySpaceEventsApi(request, aliceToken, spaceId);
    const afterRedactionBob = await querySpaceEventsApi(request, bobToken, spaceId);
    const afterRedactionCarol = await querySpaceEventsApi(request, carolToken, spaceId);
    expect(JSON.stringify(afterRedactionAlice)).not.toContain(abusive);
    expect(JSON.stringify(afterRedactionBob)).not.toContain(abusive);
    expect(JSON.stringify(afterRedactionCarol)).not.toContain(abusive);

    const exportResp = await request.get(
      `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/export`,
      { headers: authHeaders(aliceToken) },
    );
    expect(exportResp.ok()).toBeTruthy();
    const exportText = JSON.stringify(await exportResp.json());
    expect(exportText).toContain('"membership":"ban"');
    expect(exportText).toContain('"event_kind":"cx.message.redact"');
    expect(exportText).toContain(sent.event_id);
  });

  test("E5.3 idempotent ban smoke: re-issuing cx.member.state{ban} leaves mallory non-member", async ({
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

    const spaceId = await createSpaceApi(request, aliceToken, {
      title: `S5.3 Idempotent Ban API ${stamp}`,
      public: true,
      discoverability: "public",
      history_visibility: "shared",
    });
    await addSpaceMemberApi(request, aliceToken, spaceId, mallory.did);

    const firstBan = makeOperation({
      spaceId,
      objectType: "cx.member.state",
      payload: { actor_id: mallory.did, member: mallory.did, membership: "ban" },
    });
    const secondBan = makeOperation({
      spaceId,
      objectType: "cx.member.state",
      payload: { actor_id: mallory.did, member: mallory.did, membership: "ban" },
    });

    const first = await pushFederationOperations(request, [firstBan], {
      origin: solandServiceDid(),
      spaceId,
    });
    expect(first.accepted).toContain(firstBan.operation_id);

    const second = await pushFederationOperations(request, [secondBan], {
      origin: solandServiceDid(),
      spaceId,
    });
    expect(second.accepted).toContain(secondBan.operation_id);

    const space = await request.get(`${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}`, {
      headers: authHeaders(aliceToken),
    });
    expect(space.ok()).toBeTruthy();
    const body = await space.json();
    expect(body.members ?? []).not.toContain(mallory.did);
  });

  test("owner can ban a member from the yougen admin member row", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s5-ui-alice");
    const mallory = uniqueUser("s5-ui-mallory");

    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, mallory)]);
    const aliceToken = await issueDevSession(request, alice);
    const spaceId = await createSpaceApi(request, aliceToken, {
      title: `S5 UI Ban ${stamp}`,
      public: true,
      discoverability: "public",
      history_visibility: "shared",
    });
    await addSpaceMemberApi(request, aliceToken, spaceId, mallory.did);

    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
    try {
      await alicePage.gotoSpaceAdminSection(spaceId, "members");
      const malloryRow = alicePage.page.locator(
        `[data-testid="member-row"][data-member-did="${mallory.did}"]`,
      );
      await expect(malloryRow).toBeVisible({ timeout: 30_000 });
      await malloryRow.getByTestId("ban-member-button").click();
      await expect(alicePage.page.getByTestId("space-admin-panel")).toContainText(/banned/i, {
        timeout: 30_000,
      });

      const space = await request.get(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}`,
        { headers: authHeaders(aliceToken) },
      );
      expect(space.ok()).toBeTruthy();
      const body = await space.json();
      expect(body.members ?? []).not.toContain(mallory.did);
    } finally {
      await alicePage.close();
    }
  });
});
