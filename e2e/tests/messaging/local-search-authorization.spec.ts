// Real accepted sources, Account projection and native/browser local readers.
import { expect, test } from "../../helpers/arkret-test";
import { createRealmViaApi, sendPlaintextMessageViaApi } from "../../helpers/api";
import { accountActorId, resolveDefaultStrandId, signedEventEnvelope, submitSignedEventApi } from "../../helpers/coland-api";
import { observeNativeSearch, type NativeSearchObservation } from "../../helpers/native-search";
import { issueUserSession, openDpopUserPage } from "../../helpers/users";

test("0540 real local search preserves native/browser source identity and withdraws a departed Realm", async ({
  browser, request,
}, testInfo) => {
  test.setTimeout(900_000);
  const flow = await openDpopUserPage(browser, request, "search-current", { prepareMlsDevice: false });
  if (!flow) throw new Error("search authorization requires real Coauth DPoP login");
  const observed: Array<{ step: string; native: NativeSearchObservation }> = [];
  try {
    const token = await issueUserSession(request, flow.user);
    const suffix = Date.now();
    const targetBody = `accepted target search ${suffix}`;
    const controlBody = `accepted independent search ${suffix}`;
    const freshControl = `post-departure control search ${suffix}`;
    const realms: string[] = [];
    const strands: string[] = [];
    for (const [index, body] of [targetBody, controlBody].entries()) {
      const realmId = await createRealmViaApi(request, token, {
        ownerId: flow.user.id, title: `Search current ${suffix}-${index}`,
        discoverability: "listed", historyAccess: "all_history_for_current_members", mlsActivated: false,
      });
      const strandId = await resolveDefaultStrandId(request, token, realmId);
      await sendPlaintextMessageViaApi(request, token, realmId, body, { actorId: flow.user.id, strandId });
      realms.push(realmId);
      strands.push(strandId);
    }
    const page = flow.page.page;
    const panel = page.getByTestId("global-search-panel");
    const row = panel.getByTestId("global-search-result-item");
    const search = async (query: string, count: number) => {
      await flow.page.completeRecoveryKeySetupIfPrompted(100);
      if (!await panel.isVisible()) await page.keyboard.press("Control+F");
      await expect(panel).toBeVisible();
      await panel.getByTestId("global-search-input").fill(query);
      await panel.getByTestId("global-search-submit").click();
      await expect(row).toHaveCount(count);
      if (count) await expect(row.getByTestId("global-search-result-snippet")).toHaveText(query);
      else await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
    };
    const native = async (step: string, selectedRealm: string, query: string, count: number) => {
      const result = await observeNativeSearch(flow.session, selectedRealm, query,
        testInfo.outputPath("native-account.json"));
      expect(result.account_id).toEqual(flow.session.accountId);
      expect(result.view.results).toHaveLength(count);
      if (count) {
        expect(result.view.results[0]!.content.body).toBe(query);
        expect(Date.parse(result.recheck_at!)).toBeGreaterThan(Date.now());
      }
      observed.push({ step, native: result });
      return result.view.results[0];
    };
    await flow.page.gotoTimelineRealm(realms[0]!);
    await search(targetBody, 1);
    const originalEvent = await row.getAttribute("data-event-id");
    const originalCommit = await row.getAttribute("data-commit-id");
    const original = await native("initial-target", realms[0]!, targetBody, 1);
    expect(original!.event_id).toBe(originalEvent);
    expect(original!.covering_commit.commit_id).toBe(originalCommit);
    expect(original!.realm_id).toBe(realms[0]);

    await flow.page.gotoTimelineRealm(realms[1]!);
    await search(controlBody, 1);
    await native("independent-control", realms[1]!, controlBody, 1);
    // The target must still be searchable when only the other Realm is selected.
    await search(targetBody, 1);
    // Each observer is a cold native process. Demand the target complete cut
    // explicitly; the browser above separately proves retained cross-Realm UI search.
    await native("retained-target-before-departure", realms[0]!, targetBody, 1);
    const remoteSearches: string[] = [];
    page.on("request", request => {
      const url = new URL(request.url());
      if (url.pathname.startsWith("/_arkret/") && url.pathname.split("/").includes("search")) {
        remoteSearches.push(`${request.method()} ${url.pathname}`);
      }
    });
    const leave = signedEventEnvelope({
      actorId: flow.user.id, realmId: realms[0]!, kind: "ak.member.state",
      payload: { member_id: accountActorId(flow.user.id), membership: "leave" },
    });
    await submitSignedEventApi(request, token, leave, { context: "search target self departure" });
    await sendPlaintextMessageViaApi(request, token, realms[1]!, freshControl,
      { actorId: flow.user.id, strandId: strands[1]! });
    // A newly accepted independent source proves the post-departure Account
    // update was installed; an old cached control cannot satisfy this step.
    await flow.page.gotoTimelineRealm(realms[1]!);
    await expect(page.getByTestId("message-list").getByText(freshControl, { exact: true })).toBeVisible({ timeout: 120_000 });
    await search(freshControl, 1);
    await native("fresh-control-after-departure", realms[1]!, freshControl, 1);
    await search(targetBody, 0);
    await native("retained-target-after-departure", realms[1]!, targetBody, 0);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await search(targetBody, 0);
    await search(freshControl, 1);
    await native("cold-retained-target-after-departure", realms[1]!, targetBody, 0);
    expect(remoteSearches).toEqual([]);
    await testInfo.attach("real-native-browser-search-current.json", {
      body: JSON.stringify({ realms, originalEvent, originalCommit, observed }, null, 2),
      contentType: "application/json",
    });
  } finally {
    await flow.page.close();
  }
});
