// Real Circle current, membership and parent-join instance boundaries.
import { expect, test } from "../../helpers/arkret-test";
import { createRealmViaApi, sendPlaintextMessageViaApi } from "../../helpers/api";
import { addCircleMemberArkret, createCircleArkret, grantCircleMemberAddCapability,
  readParentMembershipRevisionApi, removeCircleMemberArkret } from "../../helpers/circle-api";
import { accountActorId, canonicalTimestamp, joinRealmMemberByInviteApi,
  resolveDefaultStrandId, signedEventEnvelope, submitSignedEventApi } from "../../helpers/coland-api";
import { postponeSearchEncryptionPrompts } from "../../helpers/local-search";
import { observeNativeSearch } from "../../helpers/native-search";
import { allowExplicitInviteNotifications, createDpopUserSession, issueUserSession,
  openDpopUserPageFromSession } from "../../helpers/users";

test("0540 real local search rechecks Circle revocation and the exact parent join instance", async ({
  browser, request,
}, testInfo) => {
  test.setTimeout(1_800_000);
  const owner = await createDpopUserSession(request, "search-circle-owner");
  const reader = await createDpopUserSession(request, "search-circle-reader");
  if (!owner || !reader) throw new Error("Circle search requires real issuer-backed sessions");
  const ownerToken = await issueUserSession(request, owner.user);
  const readerToken = await issueUserSession(request, reader.user);
  await allowExplicitInviteNotifications(request, reader);
  const realm = await createRealmViaApi(request, ownerToken, {
    ownerId: owner.user.id, title: "Circle search parent", discoverability: "listed",
    historyAccess: "all_history_for_current_members", mlsActivated: false,
  });
  const joinParent = () => joinRealmMemberByInviteApi(request, ownerToken, realm,
    { id: reader.user.id, token: readerToken });
  await joinParent();
  const parentBefore = await readParentMembershipRevisionApi(request, ownerToken, realm, reader.user.id);
  const circle = await createCircleArkret(request, ownerToken, {
    actorId: owner.user.id, realmId: realm, title: "Private search scope",
    joinRule: "public", historyAccess: "all_history_for_current_members",
  });
  for (const member of [owner, reader]) {
    await grantCircleMemberAddCapability(request, ownerToken, {
      ownerId: owner.user.id, realmId: realm, circleId: circle.circle_id, subjectId: member.user.id,
    });
  }
  await addCircleMemberArkret(request, ownerToken, circle.circle_id, {
    signerId: owner.user.id, actorId: owner.user.id, realmId: realm,
  });
  const joinCircle = () => addCircleMemberArkret(request, readerToken, circle.circle_id, {
    signerId: reader.user.id, actorId: reader.user.id, realmId: realm,
  });
  await joinCircle();
  const scope = { kind: "circle", realm_id: realm, circle_id: circle.circle_id };
  const createdAt = canonicalTimestamp();
  const strandCreate = signedEventEnvelope({ actorId: owner.user.id, realmId: realm,
    scopeRef: scope, kind: "ak.strand.create", createdAt, payload: { object: {
      schema: "ak.schema.strand.v1", realm_id: realm, scope_circle_id: circle.circle_id,
      tracks: { discussion: { enabled: true, is_primary: true, profile: "discussion" } },
      created_by: accountActorId(owner.user.id), created_at: createdAt,
    } } });
  await submitSignedEventApi(request, ownerToken, strandCreate, { context: "Circle search Strand" });
  const strand = String(strandCreate.event_id).replace(/^ak:event:/, "ak:strand:");
  const suffix = Date.now();
  const privateBody = `Circle exact source ${suffix}`;
  const sendPrivate = async (body: string) => {
    const event = signedEventEnvelope({ actorId: owner.user.id, realmId: realm,
      scopeRef: scope, kind: "ak.message.create", payload: {
        strand_id: strand, track_name: "discussion", content: { kind: "ak.content.text", body },
      } });
    await submitSignedEventApi(request, ownerToken, event, { context: "Circle search Message" });
    return String(event.event_id);
  };
  const original = await sendPrivate(privateBody);
  const publicStrand = await resolveDefaultStrandId(request, ownerToken, realm);
  const flow = await openDpopUserPageFromSession(browser, reader, { prepareMlsDevice: false, autoCompleteRecoveryKeySetup: false });
  if (!flow) throw new Error("Circle search reader did not initialize");
  const sendControl = async (body: string) => {
    await sendPlaintextMessageViaApi(request, ownerToken, realm, body,
      { actorId: owner.user.id, strandId: publicStrand });
    await flow.page.gotoTimelineRealm(realm, { completeRecoveryKeySetup: false });
    await expect(flow.page.page.getByTestId("message-list").getByText(body, { exact: true }))
      .toBeVisible({ timeout: 120_000 });
  };
  const observations: Array<Record<string, unknown>> = [];
  const page = flow.page.page;
  try {
    const postpone = await postponeSearchEncryptionPrompts(page, prompt =>
      observations.push({ step: "postpone-unpublished-plaintext-recovery", prompt }),
      { allowUnpublishedRecoverySetup: true });
    await flow.page.gotoTimelineRealm(realm, { completeRecoveryKeySetup: false });
    const panel = page.getByTestId("global-search-panel");
    const rows = panel.getByTestId("global-search-result-item");
    const paired = async (step: string, query: string, count: number) => {
      await postpone();
      if (!await panel.isVisible()) await page.keyboard.press("Control+F");
      await panel.getByTestId("global-search-input").fill(query);
      await panel.getByTestId("global-search-submit").click();
      await expect(rows).toHaveCount(count);
      if (count) await expect(rows.getByTestId("global-search-result-snippet")).toHaveText(query);
      else await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
      const native = await observeNativeSearch(reader, realm, query,
        testInfo.outputPath("native-circle.json"));
      expect(native.view.results).toHaveLength(count);
      if (count) {
        expect(native.view.results[0]!.event_id).toBe(await rows.getAttribute("data-event-id"));
        expect(native.view.results[0]!.covering_commit.commit_id).toBe(await rows.getAttribute("data-commit-id"));
        expect(native.view.results[0]!.content.body).toBe(query);
      }
      observations.push({ step, native });
      return native.view.results[0];
    };
    expect((await paired("initial-Circle-source", privateBody, 1))!.event_id).toBe(original);
    await removeCircleMemberArkret(request, readerToken, circle.circle_id, reader.user.id,
      { actorId: reader.user.id, realmId: realm });
    const removedControl = `Circle removed control ${suffix}`;
    await sendControl(removedControl);
    await paired("new-Realm-control-after-Circle-leave", removedControl, 1);
    await paired("retained-Circle-source-withdrawn", privateBody, 0);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await paired("cold-Circle-leave", privateBody, 0);
    await joinCircle();
    const rejoinedControl = `Circle rejoin control ${suffix}`;
    await sendControl(rejoinedControl);
    await paired("new-Realm-control-after-Circle-rejoin", rejoinedControl, 1);
    expect((await paired("same-parent-all-history-restores-original", privateBody, 1))!.event_id).toBe(original);

    await submitSignedEventApi(request, readerToken, signedEventEnvelope({ actorId: reader.user.id,
      realmId: realm, kind: "ak.member.state", payload: {
        member_id: accountActorId(reader.user.id), membership: "leave",
      } }), { context: "search parent join replacement" });
    await joinParent();
    const parentAfter = await readParentMembershipRevisionApi(request, ownerToken, realm, reader.user.id);
    expect(parentAfter).not.toEqual(parentBefore);
    const changedControl = `New parent control ${suffix}`;
    await sendControl(changedControl);
    await paired("new-parent-Realm-control", changedControl, 1);
    await paired("old-Circle-join-cannot-authorize-new-parent", privateBody, 0);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await paired("cold-parent-replacement", privateBody, 0);
    // The old canonical join is retained even when its parent revision is
    // ineffective. Leave it explicitly before the new parent-bound join.
    await removeCircleMemberArkret(request, readerToken, circle.circle_id, reader.user.id,
      { actorId: reader.user.id, realmId: realm });
    await joinCircle();
    const freshBody = `New Circle parent source ${suffix}`;
    const freshEvent = await sendPrivate(freshBody);
    await flow.page.gotoTimelineRealm(realm, { completeRecoveryKeySetup: false });
    expect((await paired("new-parent-Circle-join-reads-fresh-source", freshBody, 1))!.event_id).toBe(freshEvent);
  } finally {
    await testInfo.attach("real-Circle-search.json", {
      body: JSON.stringify({ original, parentBefore, observations }, null, 2), contentType: "application/json",
    });
    await flow.page.close();
  }
});
