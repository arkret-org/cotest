// Real Station history tightening and signed Message lifecycle through both readers.
import { expect, test } from "../../helpers/arkret-test";
import { createRealmViaApi, sendPlaintextMessageViaApi } from "../../helpers/api";
import { joinRealmMemberByInviteApi, resolveDefaultStrandId, signedEventEnvelope,
  submitSignedEventApi } from "../../helpers/coland-api";
import { observeNativeSearch, type NativeSearchObservation } from "../../helpers/native-search";
import { allowExplicitInviteNotifications, createDpopUserSession, issueUserSession,
  openDpopUserPageFromSession } from "../../helpers/users";

test("0540 real local search rechecks late-join history and preserves revision sources through redaction", async ({
  browser, request,
}, testInfo) => {
  test.setTimeout(1_800_000);
  const owner = await createDpopUserSession(request, "search-history-owner");
  const reader = await createDpopUserSession(request, "search-history-reader");
  if (!owner || !reader) throw new Error("search lifecycle acceptance requires real Coauth accounts");
  const ownerToken = await issueUserSession(request, owner.user);
  const readerToken = await issueUserSession(request, reader.user);
  await allowExplicitInviteNotifications(request, reader);
  const suffix = Date.now();
  const earlyBody = `history-before-reader-${suffix}`;
  const realmId = await createRealmViaApi(request, ownerToken, {
    ownerId: owner.user.id, title: `Search history ${suffix}`, discoverability: "listed",
    historyAccess: "all_history_for_current_members", mlsActivated: false,
  });
  const strandId = await resolveDefaultStrandId(request, ownerToken, realmId);
  const send = (body: string) => sendPlaintextMessageViaApi(request, ownerToken, realmId,
    body, { actorId: owner.user.id, strandId });
  const early = await send(earlyBody);
  // The reader joins after the first Message. A creator's stream-start floor
  // cannot exercise the tightening from all_history to since_join.
  await joinRealmMemberByInviteApi(request, ownerToken, realmId,
    { id: reader.user.id, token: readerToken });
  const flow = await openDpopUserPageFromSession(browser, reader, { prepareMlsDevice: false });
  if (!flow) throw new Error("search lifecycle reader did not initialize");
  const steps: Array<Record<string, unknown>> = [];
  const remoteSearches: string[] = [];
  const page = flow.page.page;
  page.on("request", request => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/_arkret/") && url.pathname.split("/").includes("search")) {
      remoteSearches.push(`${request.method()} ${url.pathname}`);
    }
  });
  try {
    await flow.page.gotoTimelineRealm(realmId);
    const panel = page.getByTestId("global-search-panel");
    const row = panel.getByTestId("global-search-result-item");
    const paired = async (step: string, query: string, count: number) => {
      await flow.page.completeRecoveryKeySetupIfPrompted(1_000);
      if (!await panel.isVisible()) await page.keyboard.press("Control+F");
      await expect(panel).toBeVisible();
      await panel.getByTestId("global-search-input").fill(query);
      await panel.getByTestId("global-search-submit").click();
      await expect(row).toHaveCount(count);
      let visible: Record<string, string | null> | null = null;
      if (count) {
        await expect(row.getByTestId("global-search-result-snippet")).toHaveText(query);
        visible = { event_id: await row.getAttribute("data-event-id"),
          commit_id: await row.getAttribute("data-commit-id") };
      } else {
        await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
      }
      const native: NativeSearchObservation = await observeNativeSearch(reader, realmId, query,
        testInfo.outputPath("native-history-account.json"));
      expect(native.account_id).toEqual(reader.accountId);
      expect(native.view.results).toHaveLength(count);
      if (count) {
        const result = native.view.results[0]!;
        expect(result.content.body).toBe(query);
        expect(result.event_id).toBe(visible!.event_id);
        expect(result.covering_commit.commit_id).toBe(visible!.commit_id);
        expect(Date.parse(native.recheck_at!)).toBeGreaterThan(Date.now());
      }
      steps.push({ step, query, visible, native });
      return { visible, result: native.view.results[0] };
    };
    const initial = await paired("all-history-before-tightening", earlyBody, 1);
    expect(initial.visible!.event_id).toBe(early.event_id);
    const originalBody = `revision-original-${suffix}`;
    const revisedBody = `revision-replacement-${suffix}`;
    const created = await send(originalBody);
    const original = await paired("message-create", originalBody, 1);
    const messageId = created.event_id.replace(/^ak:event:/, "ak:message:");
    const revision = signedEventEnvelope({ actorId: owner.user.id, realmId,
      kind: "ak.message.revise", payload: { message_id: messageId,
        content: { kind: "ak.content.text", body: revisedBody } } });
    await submitSignedEventApi(request, ownerToken, revision, { context: "search current Message revision" });
    const revised = await paired("current-revision-has-exact-signed-carrier", revisedBody, 1);
    expect(revised.visible).toEqual(original.visible);
    expect(revised.result!.source_event_id).toBe(revision.event_id);
    expect(revised.result!.source_commit.event_ref).toBe(revision.event_id);
    await paired("revision-does-not-search-the-stale-body", originalBody, 0);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    const coldRevision = await paired("cold-current-revision", revisedBody, 1);
    expect(coldRevision.result!.source_event_id).toBe(revision.event_id);
    await row.getByTestId("global-search-result-link").click();
    await expect(page.getByTestId("message-list").getByText(revisedBody, { exact: true })).toBeVisible();
    await expect(page.getByTestId("message-list").getByText(originalBody, { exact: true })).toHaveCount(0);

    const redact = signedEventEnvelope({ actorId: owner.user.id, realmId,
      kind: "ak.message.redact", payload: { message_id: messageId, reason: "author_redaction" } });
    await submitSignedEventApi(request, ownerToken, redact, { context: "search Message terminal redaction" });
    const terminalControl = `redaction-control-${suffix}`;
    await send(terminalControl);
    // Local search reads installed material. Re-enter the source to demand its
    // new accepted window after the result link and global Search navigation.
    await flow.page.gotoTimelineRealm(realmId);
    await expect(page.getByTestId("message-list").getByText(terminalControl, { exact: true })).toBeVisible({ timeout: 120_000 });
    await paired("fresh-post-redaction-control", terminalControl, 1);
    await paired("redaction-hides-the-current-revision", revisedBody, 0);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await paired("cold-terminal-redaction", revisedBody, 0);
    await paired("cold-independent-control", terminalControl, 1);
    const history = async (from: string, to: string) => {
      const event = signedEventEnvelope({ actorId: owner.user.id, realmId,
        kind: "ak.realm.history_access", payload: { from, to } });
      await submitSignedEventApi(request, ownerToken, event, { context: "search history transition" });
      return event;
    };
    await history("all_history_for_current_members", "since_join");
    const tightControl = `history-tight-control-${suffix}`;
    await send(tightControl);
    await flow.page.gotoTimelineRealm(realmId);
    await expect(page.getByTestId("message-list").getByText(tightControl, { exact: true })).toBeVisible({ timeout: 120_000 });
    await paired("fresh-post-tightening-control", tightControl, 1);
    await paired("since-join-hides-retained-prejoin-message", earlyBody, 0);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await paired("cold-since-join-still-hides-prejoin-message", earlyBody, 0);
    await paired("cold-since-join-keeps-postjoin-control", tightControl, 1);

    expect(remoteSearches).toEqual([]);
  } finally {
    await testInfo.attach("real-history-revision-search.json", {
      body: JSON.stringify({ realmId, earlyEvent: early.event_id, steps, remoteSearches }, null, 2),
      contentType: "application/json",
    });
    await flow.page.close();
  }
});
