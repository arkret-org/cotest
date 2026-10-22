// Real accepted MLS ciphertext; a new authorized Device has no group secrets.
import { expect, test } from "../../helpers/arkret-test";
import { createRealmViaApi, listRealmEventsViaApi, sendPlaintextMessageViaApi } from "../../helpers/api";
import { resolveDefaultStrandId } from "../../helpers/coland-api";
import { observeNativeSearch } from "../../helpers/native-search";
import { postponeSearchEncryptionPrompts } from "../../helpers/local-search";
import { createDpopUserSession, issueUserSession, openDpopUserPageFromSession,
  pairSiblingDeviceSession } from "../../helpers/users";

test("0540 real local search never treats missing MLS keys or opaque ciphertext as verified plaintext", async ({
  browser, request,
}, testInfo) => {
  test.setTimeout(1_200_000);
  const owner = await createDpopUserSession(request, "search-crypto-owner");
  if (!owner) throw new Error("crypto search requires a real issuer-backed session");
  const first = await openDpopUserPageFromSession(browser, owner);
  if (!first) throw new Error("encrypted sender did not initialize");
  const token = await issueUserSession(request, owner.user);
  const body = `encrypted current search ${Date.now()}`;
  let encryptedRealm = "";
  let source: Record<string, any>;
  try {
    encryptedRealm = await first.page.createRealm({ title: "Encrypted search source",
      discoverability: "listed", historyAccess: "since_join", mlsActivated: true });
    await first.page.sendTimelineMessage(encryptedRealm, body);
    const page = first.page.page;
    await page.keyboard.press("Control+F");
    const panel = page.getByTestId("global-search-panel");
    await panel.getByTestId("global-search-input").fill(body);
    await panel.getByTestId("global-search-submit").click();
    await expect(panel.getByTestId("global-search-result-item")).toHaveCount(1);
    await expect(panel.getByTestId("global-search-result-snippet")).toHaveText(body);
    const events = await listRealmEventsViaApi(request, token, encryptedRealm);
    source = events.filter(event => event.kind === "ak.message.create").at(-1)!;
    expect(source).toBeTruthy();
    expect(source.payload.content).toBeUndefined();
    expect(source.payload.encrypted_content).toBeTruthy();
    await expect(panel.getByTestId("global-search-result-item")).toHaveAttribute("data-event-id", source.event_id);
  } finally {
    await first.page.close();
  }
  const sibling = await pairSiblingDeviceSession(request, owner);
  const publicRealm = await createRealmViaApi(request, token, {
    ownerId: owner.user.id, title: "Independent crypto search control", discoverability: "listed",
    historyAccess: "all_history_for_current_members", mlsActivated: false,
  });
  const publicStrand = await resolveDefaultStrandId(request, token, publicRealm);
  const control = `verified unencrypted control ${Date.now()}`;
  const acceptedControl = await sendPlaintextMessageViaApi(request, token, publicRealm, control,
    { actorId: owner.user.id, strandId: publicStrand });
  const second = await openDpopUserPageFromSession(browser, sibling,
    { prepareMlsDevice: false, autoCompleteRecoveryKeySetup: false });
  if (!second) throw new Error("keyless accepted Device did not initialize");
  const observations: Array<Record<string, unknown>> = [];
  try {
    const page = second.page.page;
    await postponeSearchEncryptionPrompts(page, prompt =>
      observations.push({ step: "postpone-key-recovery-without-restoring-keys", prompt }));
    const panel = page.getByTestId("global-search-panel");
    const check = async (step: string, selectedRealm: string, query: string, count: number) => {
      await second.page.gotoTimelineRealm(selectedRealm);
      await second.page.completeRecoveryKeySetupIfPrompted(100);
      if (!await panel.isVisible()) await page.keyboard.press("Control+F");
      await panel.getByTestId("global-search-input").fill(query);
      await panel.getByTestId("global-search-submit").click();
      const rows = panel.getByTestId("global-search-result-item");
      await expect(rows).toHaveCount(count);
      if (!count) await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
      const native = await observeNativeSearch(sibling, selectedRealm, query,
        testInfo.outputPath("native-keyless.json"));
      expect(native.view.results).toHaveLength(count);
      if (count) {
        expect(native.view.results[0]!.event_id).toBe(acceptedControl.event_id);
        expect(native.view.results[0]!.event_id).toBe(await rows.getAttribute("data-event-id"));
        expect(native.view.results[0]!.content.body).toBe(control);
      }
      observations.push({ step, native });
    };
    await check("keyless-Device-can-read-independent-plaintext", publicRealm, control, 1);
    await check("accepted-ciphertext-does-not-release-the-body", encryptedRealm, body, 0);
    const ciphertext = source!.payload.encrypted_content.ciphertext;
    expect(typeof ciphertext).toBe("string");
    expect(ciphertext.length).toBeGreaterThan(12);
    await check("opaque-crypto-is-not-searchable-content", encryptedRealm, ciphertext.slice(0, 12), 0);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await check("cold-keyless-read-still-refuses-plaintext", encryptedRealm, body, 0);
    await check("cold-independent-control-still-works", publicRealm, control, 1);
  } finally {
    await testInfo.attach("real-crypto-search.json", {
      body: JSON.stringify({ encryptedEvent: source!.event_id, observations }, null, 2),
      contentType: "application/json",
    });
    await second.page.close();
  }
});
