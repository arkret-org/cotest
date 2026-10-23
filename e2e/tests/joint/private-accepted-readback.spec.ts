import { test, expect, type Page, type APIRequestContext } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";
import { registrationEmailCode } from "../../helpers/coauth-register";
// mock_email supplies the delivered OTP; mock_savfox_model supplies fixed text
// to the real runtime. All identity, MLS and message operations use product UI.
import { openUserPage, uniqueUser, type JointUserPage } from "../../helpers/users";
import { decodeIngressEvents, type IngressEvent } from "../../helpers/event-ingress";
import { assertAuthoritySubmitOutcome } from "../../helpers/coland-api";
import { openSavfoxArkretChannel, provisionAgent, pairManagedSavfoxAgent,
  addAgentToRealm, createSidecarSourceCard, composeSourceAgentMention,
  waitForSidecarEnsureAcceptance, eventIdFromMessage, controlPrivateLiveHints,
} from "../../helpers/agent-sidecar-product-ui";

test.describe("Private accepted readback real UI @fully-implemented", () => {
  test("three private writes recover without live hints and survive a real reload", async ({ browser, request }, info) => {
    test.setTimeout(1_200_000);
    const gateway = process.env.COTEST_SAVFOX_BASE_URL;
    const gatewayToken = process.env.COTEST_SAVFOX_TOKEN;
    expect(gateway, "the managed real Savfox gateway is required").toBeTruthy();
    expect(gatewayToken).toBeTruthy();
    const user = uniqueUser("private-readback-ui");
    const owner = await openUserPage(browser, user, {
      neutralLoginConfig: true, autoCompleteRecoveryKeySetup: false,
    });
    const page = owner.page;
    const hints = await controlPrivateLiveHints(page);
    const runtimeContext = await browser.newContext();
    const runtime = await runtimeContext.newPage();
    const submissions = new Map<string, number>();
    page.on("request", outgoing => {
      if (outgoing.method() !== "POST" || new URL(outgoing.url()).pathname !== "/_arkret/self/events") return;
      for (const event of decodeIngressEvents(outgoing.postData(), { context: "real private UI write" })) {
        if (isPrivateMessage(event) && event.event_id) {
          submissions.set(event.event_id, (submissions.get(event.event_id) ?? 0) + 1);
        }
      }
    });
    try {
      const recovery = await registerController(owner, request);
      console.info("[private-readback-ui] real registration and first Device completed");
      expect(await page.evaluate(() => localStorage.getItem("inkson.test.session_injection.v1"))).toBeNull();
      const realm = await owner.createRealm({ title: `Private readback ${Date.now()}`,
        discoverability: "public", joinRule: "invite", historyAccess: "since_join", mlsActivated: false,
        completeRecoveryKeySetup: false, allowPassivePromptDismissal: false, allowRecoveryOverride: false });
      await owner.completeMlsAccountBackupIfPrompted(recovery);
      const pairing = await provisionAgent(page, `readback-${Date.now().toString(36)}`);
      await openSavfoxArkretChannel(runtime, gateway!, gatewayToken!);
      await pairManagedSavfoxAgent(page, runtime, pairing);
      await addAgentToRealm(page, realm, pairing.agentId);
      console.info("[private-readback-ui] real Agent paired and Realm participation ready");
      const card = await createSidecarSourceCard(page, realm, `Readback source ${Date.now()}`);
      const exchanges: Array<{ request: string; response: string; prompt: string }> = [];
      const replies = card.getByTestId("chat-message").filter({ has:
        page.getByTestId("content-block-text").filter({ hasText: /^pong(?:\r?\n|$)/ }) });
      for (let index = 0; index < 3; index += 1) {
        await card.getByTestId("card-detail-sidebar-tab-members").click();
        const member = card.locator(`[data-testid="card-detail-agent-row"][data-agent-id="${pairing.agentId}"]`);
        await expect(member).toBeVisible({ timeout: 120_000 });
        const prompt = `Readback ${index + 1}: please reply only pong`;
        await composeSourceAgentMention(card, member, pairing.agentId, prompt);
        await expect(card.getByTestId("composer-send-scope")).toHaveAttribute("data-send-route", "Sidecar");
        await expect(card.getByTestId("send-chat-button")).toBeEnabled({ timeout: 120_000 });
        if (index === 0) await hints.suppress();
        const ensure = index === 0 ? waitForSidecarEnsureAcceptance(page, info) : undefined;
        const receipt = page.waitForResponse(response => {
          const outgoing = response.request();
          return outgoing.method() === "POST" && new URL(response.url()).pathname === "/_arkret/self/events"
            && decodeIngressEvents(outgoing.postData(), { context: "private accepted receipt" })
              .some(isPrivateMessage);
        }, { timeout: 180_000 });
        await card.getByTestId("send-chat-button").click();
        if (ensure) await ensure;
        const accepted = await receipt;
        const original = decodeIngressEvents(accepted.request().postData(), { context: "private signed original" })
          .find(isPrivateMessage)!;
        expect(accepted.ok()).toBe(true);
        assertAuthoritySubmitOutcome(await accepted.json(), original, "real private UI accepted write");
        const authored = card.getByTestId("chat-message").filter({ hasText: prompt }).last();
        await expect(authored).toBeVisible({ timeout: 120_000 });
        await expect(authored).toHaveAttribute("data-crypto-state", "plaintext");
        await expect(replies).toHaveCount(index + 1, { timeout: 180_000 });
        const reply = replies.last();
        await expect(reply).toHaveAttribute("data-crypto-state", "plaintext");
        await expect(reply.getByTestId("member-badge-agent")).toBeVisible();
        await expect(reply.getByTestId("message-private-sidecar-badge")).toBeVisible();
        const requestId = await eventIdFromMessage(authored);
        const responseId = await eventIdFromMessage(reply);
        expect(requestId).toBe(original.event_id);
        expect(responseId).toMatch(/^ak:event:/);
        await assertFold(page, realm, requestId, responseId);
        console.info(`[private-readback-ui] private exchange ${index + 1} accepted, installed and visible without live hints`);
        exchanges.push({ request: requestId, response: responseId, prompt });
        await expect(card.getByTestId("chat-input")).toHaveValue("");
      }
      const blockedHints = hints.observations();
      expect(blockedHints.blocked_http_subscriptions + blockedHints.dropped_live_frames,
        "the cut must block an actual live transport, including a legal HTTP fallback").toBeGreaterThan(0);
      expect(submissions.size).toBe(3);
      expect([...submissions.values()]).toEqual([1, 1, 1]);
      await info.attach("private-no-hint-evidence", { contentType: "application/json",
        body: Buffer.from(JSON.stringify({ ...hints.observations(), real_registration_and_first_device: true,
          session_injection: false, private_accepted_writes: 3, authenticated_visible_replies: 3,
          original_discussion_fold_matches: true, writes_reauthored: 0 })) });
      // A cold page must obtain a fresh baseline; restored data is never an allow ticket.
      await hints.restore();
      await page.reload();
      const reopened = page.getByTestId("card-detail-modal");
      await expect(reopened).toBeVisible({ timeout: 180_000 });
      for (const exchange of exchanges) {
        await expect(reopened.getByTestId("chat-message").filter({ hasText: exchange.prompt })).toBeVisible({ timeout: 120_000 });
        await assertFold(page, realm, exchange.request, exchange.response);
      }
      await expect(reopened.getByTestId("chat-message").filter({ has:
        page.getByTestId("content-block-text").filter({ hasText: /^pong(?:\r?\n|$)/ }) })).toHaveCount(3);
      expect(submissions.size).toBe(3);
      expect([...submissions.values()]).toEqual([1, 1, 1]);
      await info.attach("private-cold-reload-evidence", { contentType: "application/json",
        body: Buffer.from(JSON.stringify({ fresh_baseline: true, retained_exchanges: 3, duplicate_writes: 0 })) });
      console.info("[private-readback-ui] real reload restored all three exchanges without duplicate writes");
    } finally {
      const projection = await page.evaluate(() => {
        const hook = (window as unknown as Record<string, unknown>).__inkson_sidecar_fold_evidence_v1;
        const config = JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}");
        const realm = decodeURIComponent(location.pathname).match(/\/kanban\/([^/]+)/)?.[1];
        if (typeof hook !== "function" || !realm) return { available: false };
        const fold = JSON.parse((hook as (realm: string) => string)(realm));
        const exchanges = fold.exchanges ?? [];
        const privateIds = new Set(exchanges.flatMap((entry: { projection: {
          private_request_event_id: string; user_facing_response_event_ids: string[];
        } }) => [entry.projection.private_request_event_id, ...entry.projection.user_facing_response_event_ids]));
        return { available: !fold.error, real_active_account: Boolean(config.active_account),
          exchanges: exchanges.length,
          replies: exchanges.reduce((sum: number, entry: { projection: { user_facing_response_event_ids: string[] } }) =>
            sum + entry.projection.user_facing_response_event_ids.length, 0),
          private_anchor_count: exchanges.filter((entry: { projection: { source_event_id?: string } }) =>
            privateIds.has(entry.projection.source_event_id)).length };
      }).catch(() => ({ available: false }));
      await info.attach("private-readback-final-stage", { contentType: "application/json",
        body: Buffer.from(JSON.stringify({ ...hints.observations(), ...projection,
          private_requests_submitted: submissions.size,
          repeated_submissions: [...submissions.values()].filter(count => count !== 1).length })) });
      await hints.restore();
      await runtimeContext.close();
      await owner.close();
    }
  });
});

function isPrivateMessage(event: IngressEvent): boolean {
  const scope = event.scope_ref;
  return event.kind === "ak.message.create" && scope !== null && typeof scope === "object"
    && "kind" in scope && scope.kind === "sidecar";
}

async function assertFold(page: Page, realm: string, request: string, response: string) {
  await expect.poll(async () => page.evaluate(({ realm, request, response }) => {
    const hook = (window as unknown as Record<string, unknown>).__inkson_sidecar_fold_evidence_v1;
    if (typeof hook !== "function") return false;
    const result = JSON.parse((hook as (realm: string) => string)(realm));
    return !result.error && result.exchanges?.some((entry: { projection: {
      private_request_event_id: string; user_facing_response_event_ids: string[];
    } }) => entry.projection.private_request_event_id === request
      && entry.projection.user_facing_response_event_ids.includes(response));
  }, { realm, request, response }), { timeout: 120_000 }).toBe(true);
}

async function registerController(owner: JointUserPage, request: APIRequestContext): Promise<string> {
  const page = owner.page;
  const user = owner.user;
  await owner.gotoLogin();
  await page.getByTestId("login-server-url").fill(colandBaseUrl());
  await page.getByTestId("start-server-login-button").click();
  await page.getByRole("link", { name: /create account/i }).click();
  await page.locator('input[autocomplete="username"]').fill(user.name);
  await page.locator('input[autocomplete="email"]').fill(`${user.name}@example.test`);
  const passwords = page.locator('input[type="password"]');
  await expect(passwords).toHaveCount(2);
  await passwords.nth(0).fill("1amTester!");
  await passwords.nth(1).fill("1amTester!");
  await page.getByRole("button", { name: /create account/i }).click();
  const code = page.locator('input[autocomplete="one-time-code"]');
  await expect(code).toBeVisible({ timeout: 120_000 });
  await code.fill(await registrationEmailCode(request, `${user.name}@example.test`));
  await page.getByRole("button", { name: /^verify$/i }).click();
  const display = page.locator('input[autocomplete="name"]');
  const approve = page.getByTestId("coauth-oauth-approve");
  // Visibility queries are immediate; wait for the actual post-verification
  // branch before deciding whether this new account needs its profile form.
  await expect(display.or(approve)).toBeVisible({ timeout: 120_000 });
  if (await display.isVisible()) {
    await display.fill(user.displayName);
    await page.getByRole("button", { name: /^continue$/i }).click();
  }
  await approve.click({ timeout: 120_000 });
  await page.getByTestId("choose-new-identity").click();
  const words = page.getByTestId("onboarding-recovery-key-display").locator("li");
  await expect(words).toHaveCount(24, { timeout: 120_000 });
  const key = (await words.allTextContents()).map(value => value.trim()).join(" ");
  await page.getByTestId("onboarding-recovery-key-confirm").evaluate((element, key) => {
    const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(element, key);
    element.dispatchEvent(new Event("input", { bubbles: true }));
  }, key);
  await page.getByTestId("onboarding-bind-identity").click();
  await expect(page.getByTestId("onboarding-complete")).toContainText("Identity ready", { timeout: 240_000 });
  await page.getByTestId("onboarding-complete").getByRole("link", { name: "Continue" }).click();
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  const identity = await page.evaluate(() => JSON.parse(localStorage.getItem("inkson.config.v1")!).active_account);
  expect(identity.authority.principal_id).toMatch(/^ak:did_core:/);
  // Fixture labels follow the identity produced by the UI; no browser state is seeded.
  Object.assign(user, { id: identity.authority.principal_id, did: identity.resolution.did, deviceId: identity.device_id });
  return key;
}
