// Contract: consent-model.md — complete exact-peer replacement and explicit empty.
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { colandBaseUrl, colandServiceId } from "../../helpers/env";
import { accountActorId, authHeaders, canonicalJson, expectJsonOk } from "../../helpers/coland-api";
import type { ConsentView } from "../../helpers/generated/spec-wire-objects";
import { assertJointStackNotRequired, issueUserSession, openDpopUserPage } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

async function summary(request: APIRequestContext, token: string, peerId: string) {
  const peer = { kind: "actor", actor_id: accountActorId(peerId) };
  const url = `${colandBaseUrl()}/_arkret/self/consent/result?peer=${encodeURIComponent(canonicalJson(peer))}`;
  return expectJsonOk<ConsentView>(await request.get(url, { headers: authHeaders(token, "GET", url) }), "exact peer summary");
}

test("holder edits the complete peer set, retains inactive fields, and writes a real empty revision", async ({ browser, request }) => {
  test.setTimeout(300_000);
  const [holder, peer] = await Promise.all([
    openDpopUserPage(browser, request, "consent-holder", { prepareMlsDevice: false }),
    openDpopUserPage(browser, request, "consent-peer", { prepareMlsDevice: false }),
  ]);
  if (!holder || !peer) {
    await Promise.allSettled([holder?.page.close(), peer?.page.close()]);
    assertJointStackNotRequired("complete Consent editor DPoP login");
    test.skip(true, "coauth DPoP session-grant login is unavailable");
    return;
  }
  const ui = holder.page;
  try {
    const token = await issueUserSession(request, holder.user);
    await ui.gotoAppPanel("/settings/consent", "consent-settings-panel");
    await ui.page.getByTestId("consent-peer-input").fill(peer.user.id);
    await ui.page.getByTestId("consent-peer-station-input").fill(colandServiceId());
    const read = async () => {
      await ui.clickWithPassivePromptRetry(ui.page.getByTestId("consent-load-peer-button"));
      await expect(ui.page.getByTestId("consent-full-editor")).toBeVisible();
    };
    const replace = async () => {
      await ui.clickWithPassivePromptRetry(ui.page.getByTestId("consent-replace-submit-button"));
      await expect(ui.page.getByTestId("write-status")).toContainText(/saved|已保存/i, { timeout: 30_000 });
      await expect(ui.page.getByTestId("consent-full-editor")).toHaveCount(0);
    };
    await read();
    const voice = ui.page.locator('fieldset[data-scope="voice_call"]');
    await voice.getByRole("checkbox").check();
    await voice.locator('[id^="consent-not_before-"]').fill("2026-01-01T00:00:00.000Z");
    await voice.locator('[id^="consent-expires_at-"]').fill("2026-02-01T00:00:00.000Z");
    await voice.locator('[id^="consent-constraints-"]').fill('[{"unknown_rule":true}]');
    await voice.locator('[id^="consent-reason-"]').fill("retained inactive permission");
    await replace();
    const first = await summary(request, token, peer.user.id);
    expect(first.permission_scopes).toEqual(["voice_call"]);
    expect(first).not.toHaveProperty("consent_id");
    expect(first).not.toHaveProperty("state");

    await read();
    await expect(voice.locator('[id^="consent-expires_at-"]')).toHaveValue("2026-02-01T00:00:00.000Z");
    expect(JSON.parse(await voice.locator('[id^="consent-constraints-"]').inputValue())).toEqual([{ unknown_rule: true }]);
    for (const scope of ["invite", "video_call", "presence"]) {
      await ui.page.locator(`fieldset[data-scope="${scope}"]`).getByRole("checkbox").check();
    }
    await replace();
    const extended = await summary(request, token, peer.user.id);
    expect(extended.permission_scopes).toEqual(["invite", "voice_call", "video_call", "presence"]);
    expect(extended.revision).not.toEqual(first.revision);

    // Restore from durable application state and read the authenticated full set.
    await ui.page.reload();
    await ui.gotoAppPanel("/settings/consent", "consent-settings-panel");
    await ui.page.getByTestId("consent-peer-input").fill(peer.user.id);
    await ui.page.getByTestId("consent-peer-station-input").fill(colandServiceId());
    await read();
    await expect(ui.page.getByTestId("consent-full-editor").getByRole("checkbox", { checked: true })).toHaveCount(4);
    await expect(voice.locator('[id^="consent-reason-"]')).toHaveValue("retained inactive permission");
    expect(JSON.parse(await voice.locator('[id^="consent-constraints-"]').inputValue())).toEqual([{ unknown_rule: true }]);
    await expect(voice.locator('[id^="consent-expires_at-"]')).toHaveValue("2026-02-01T00:00:00.000Z");
    for (const scope of ["invite", "voice_call", "video_call", "presence"]) {
      await ui.page.locator(`fieldset[data-scope="${scope}"]`).getByRole("checkbox").uncheck();
    }
    await replace();
    const empty = await summary(request, token, peer.user.id);
    expect(empty.permission_scopes).toEqual([]);
    expect(empty.revision.stream_position).toBeGreaterThan(extended.revision.stream_position);
    await read();
    await expect(ui.page.getByTestId("consent-full-editor").getByRole("checkbox", { checked: true })).toHaveCount(0);
  } finally {
    await Promise.allSettled([holder.page.close(), peer.page.close()]);
  }
});
