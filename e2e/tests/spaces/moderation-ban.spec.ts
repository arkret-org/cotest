// Moderation + ban
// Contract: e2e/scenarios/spaces/moderation-ban.md
// Spec refs:
//   - governance/content-moderation.md §2.5.0 (three-layer gate)
//   - §2.5 Moderation MUST anchored
//   - §3 Report
//   - §5.1 Redact requires ck.moderation.decision
//   - §5.2 Ban via ck.member.state{membership="ban"}

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
  createRealmApi,
  queryRealmEventsApi,
  resolveDefaultStrandId,
  sendMessageApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("moderation and ban", () => {
  test("report -> ck.member.state ban -> post-ban writes rejected -> redaction filters public timeline", async ({
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
      history_visibility: "shared",
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);
    await addRealmMemberApi(request, aliceToken, realmId, mallory.did);
    await addRealmMemberApi(request, aliceToken, realmId, carol.did);

    const abusive = `S5 abusive content ${stamp}`;
    const postBan = `S5 after ban ${stamp}`;

    const sent = await sendMessageApi(request, malloryToken, realmId, abusive);
    expect(sent.event_id).toMatch(/^ck:event:/);

    const beforeRedaction = await queryRealmEventsApi(request, aliceToken, realmId);
    expect(JSON.stringify(beforeRedaction)).toContain(abusive);

    const reportResp = await request.post(`${solandBaseUrl()}/_cokret/self/moderation/report`, {
      headers: authHeaders(bobToken),
      data: {
        realm_id: realmId,
        target_ref: sent.event_id,
        report_reason_code: "harassment",
        description: "S5 abusive content posted by mallory",
        reporter: bob.did,
        evidence_refs: [sent.event_id],
      },
    });
    expect(reportResp.ok()).toBeTruthy();
    const reportBody = await reportResp.json();
    expect(reportBody.report_id).toMatch(/^ck:report:/);
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

    const unauthorizedBan = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(bobToken),
      data: signedEventEnvelope({
        actorDid: bob.did,
        realmId: realmId,
        kind: "ck.member.state",
        payload: {
          realm_id: realmId,
          actor_id: mallory.did,
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

    const banEvent = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.member.state",
      payload: {
        realm_id: realmId,
        actor_id: mallory.did,
        membership: "ban",
        reason: "moderation_report_upheld",
      },
    });
    await submitSignedEventApi(request, aliceToken, banEvent, {
      context: `ban ${mallory.did} from ${realmId}`,
    });

    const realmAfterBan = await request.get(
      `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(realmAfterBan.ok()).toBeTruthy();
    const realmAfterBanBody = await realmAfterBan.json();
    expect(realmAfterBanBody.members ?? []).not.toContain(mallory.did);

    const defaultStrandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const bannedWrite = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(malloryToken),
      data: signedEventEnvelope({
        actorDid: mallory.did,
        realmId,
        kind: "ck.message.create",
        payload: {
          strand_id: defaultStrandId,
          track_name: "discussion",
          content: {
            kind: "ck.content.text",
            body: postBan,
          },
        },
      }),
    });
    expect([401, 403, 404, 412]).toContain(bannedWrite.status());

    const redactEvent = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.message.redact",
      payload: {
        target_event_id: sent.event_id,
        redacts: sent.event_id,
        reason: "moderator_redaction",
        actor: alice.did,
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
      `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/export`,
      { headers: authHeaders(aliceToken) },
    );
    expect(exportResp.ok()).toBeTruthy();
    const exportText = JSON.stringify(await exportResp.json());
    expect(exportText).toContain('"membership":"ban"');
    expect(exportText).toContain('"event_kind":"ck.message.redact"');
    expect(exportText).toContain(sent.event_id);
  });

  test("E5.3 idempotent ban smoke: re-issuing ck.member.state{ban} leaves mallory non-member", async ({
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
      history_visibility: "shared",
    });
    await addRealmMemberApi(request, aliceToken, realmId, mallory.did);

    const firstBan = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.member.state",
      payload: { realm_id: realmId, actor_id: mallory.did, membership: "ban" },
    });
    const secondBan = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.member.state",
      payload: { realm_id: realmId, actor_id: mallory.did, membership: "ban" },
    });

    await submitSignedEventApi(request, aliceToken, firstBan, {
      context: `first ban ${mallory.did}`,
    });
    await submitSignedEventApi(request, aliceToken, secondBan, {
      context: `second ban ${mallory.did}`,
    });

    const realm = await request.get(`${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}`, {
      headers: authHeaders(aliceToken),
    });
    expect(realm.ok()).toBeTruthy();
    const body = await realm.json();
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
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S5 UI Ban ${stamp}`,
      public: true,
      discoverability: "public",
      history_visibility: "shared",
    });
    await addRealmMemberApi(request, aliceToken, realmId, mallory.did);

    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });
    try {
      await alicePage.gotoRealmAdminSection(realmId, "members");
      const malloryRow = alicePage.page.locator(
        `[data-testid="member-row"][data-member-did="${mallory.did}"]`,
      );
      await expect(malloryRow).toBeVisible({ timeout: 30_000 });
      await malloryRow.getByTestId("ban-member-button").click();
      await expect(alicePage.page.getByTestId("realm-admin-panel")).toContainText(/banned/i, {
        timeout: 30_000,
      });

      const realm = await request.get(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(aliceToken) },
      );
      expect(realm.ok()).toBeTruthy();
      const body = await realm.json();
      expect(body.members ?? []).not.toContain(mallory.did);
    } finally {
      await alicePage.close();
    }
  });
});
