import { test, expect } from "../../helpers/arkret-test";
import { createDpopUserSession, openUserPage } from "../../helpers/users";

test.use({ trace: "off", screenshot: "off", video: "off" });
test.setTimeout(360_000);

test("Agent creation checks recovery before generating or publishing its DID @agent-provision-recovery-prerequisite", async ({ browser, request }) => {
  const session = await createDpopUserSession(request, "agent-no-recovery", {});
  expect(session, "real Coauth session is required").toBeTruthy();
  if (!session) throw new Error("real Coauth session is required");
  const user = await openUserPage(browser, session.user, {
    grantJwt: session.grantJwt,
    dpopSeedB64url: session.dpopSeedB64url,
    eventSigningSeedB64url: session.eventSigningSeedB64url,
    grantId: session.grantId,
    accountId: session.accountId,
    principalControlRealmId: session.principalControlRealmId,
    grantAudience: session.grantAudience,
    recoveryMaterialEvidence: session.recoveryMaterialEvidence,
    autoCompleteRecoveryKeySetup: false,
  });
  const page = user.page;
  try {
    await page.addLocatorHandler(page.getByTestId("recovery-key-setup-dismiss-unpublished"), async () => {
      await page.getByTestId("recovery-key-setup-dismiss-unpublished").click();
    });
    await page.goto("/settings", { waitUntil: "domcontentloaded" });
    await page.getByTestId("settings-nav-item-agents").click();
    await expect(page.getByTestId("agent-admin")).toBeVisible();
    await page.getByTestId("agent-admin-create-open-button").click();
    await page.getByTestId("agent-admin-provision-agent-slug").fill("recovery-required");
    const agentKeyCount = () => page.evaluate(async () => {
      let count = 0;
      for (const info of await indexedDB.databases()) {
        if (!info.name?.startsWith("inkson.secret.")) continue;
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const opened = indexedDB.open(info.name!);
          opened.onsuccess = () => resolve(opened.result);
          opened.onerror = () => reject(opened.error);
        });
        try {
          const keys = await new Promise<IDBValidKey[]>((resolve, reject) => {
            const query = db.transaction("entries", "readonly").objectStore("entries").getAllKeys();
            query.onsuccess = () => resolve(query.result);
            query.onerror = () => reject(query.error);
          });
          count += keys.filter(key => String(key).startsWith("agent.did.keys.")
            || String(key).includes(".agent.did.keys.")).length;
        } finally {
          db.close();
        }
      }
      return count;
    });
    expect(await agentKeyCount()).toBe(0);
    const writes: string[] = [];
    page.on("request", request => {
      const path = new URL(request.url()).pathname;
      if (request.method() === "POST" && (path === "/_arkret/self/agents"
        || path === "/_arkret/root/identity/submit-did-operation")) {
        writes.push(path);
      }
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      const checked = page.waitForResponse(response => response.request().method() === "GET"
        && new URL(response.url()).pathname === "/_arkret/root/identity/recovery-policy");
      await page.getByTestId("agent-admin-provision-button").click();
      const response = await checked;
      expect(response.status()).toBe(200);
      const outcome = await response.json();
      expect(outcome.active_policy).toBeNull();
      await expect(page.getByTestId("agent-admin-last-op"))
        .toHaveText("Set up your recovery policy before creating an Agent.");
      await expect(page.getByTestId("agent-admin-provision-button")).toBeEnabled();
      expect(writes).toEqual([]);
      expect(await agentKeyCount()).toBe(0);
    }
  } finally {
    await user.close();
  }
});

test("Agent creation continues through the four stages with an active recovery policy @agent-provision-recovery-prerequisite", async ({ browser, request }) => {
  const session = await createDpopUserSession(request, "agent-with-recovery", {});
  if (!session) throw new Error("real Coauth session is required");
  const user = await openUserPage(browser, session.user, {
    grantJwt: session.grantJwt,
    dpopSeedB64url: session.dpopSeedB64url,
    eventSigningSeedB64url: session.eventSigningSeedB64url,
    grantId: session.grantId,
    accountId: session.accountId,
    principalControlRealmId: session.principalControlRealmId,
    grantAudience: session.grantAudience,
    recoveryMaterialEvidence: session.recoveryMaterialEvidence,
    autoCompleteRecoveryKeySetup: false,
  });
  const page = user.page;
  try {
    await user.gotoHome();
    const savedKey = await user.completeRecoveryKeySetupIfPrompted(120_000);
    expect(Boolean(savedKey), "the recovery policy must be saved through the product UI").toBe(true);
    await user.gotoSettings();
    await page.getByTestId("settings-nav-item-agents").click();
    await expect(page.getByTestId("agent-admin")).toBeVisible();
    await page.getByTestId("agent-admin-create-open-button").click();
    await page.getByTestId("agent-admin-provision-agent-slug").fill("recovery-ready");
    const checked = page.waitForResponse(response => response.request().method() === "GET"
      && new URL(response.url()).pathname === "/_arkret/root/identity/recovery-policy");
    const complete = page.waitForResponse(response => response.status() === 201
      && response.request().method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/self/agents"
      && response.request().postDataJSON()?.phase === "commit", { timeout: 180_000 });
    void complete.catch(() => undefined);
    await page.getByTestId("agent-admin-provision-button").click();
    const recovery = await checked;
    expect(recovery.status()).toBe(200);
    const policy = (await recovery.json()).active_policy;
    expect(policy.account_id).toEqual(session.accountId);
    // The complete outcome carries private pairing material. Retain only its
    // public locator; never attach or persist the response body.
    const agentId = (await (await complete).json()).agent_id;
    expect(agentId).toMatch(/^ak:did_core:/);
    await expect(page.getByTestId("agent-admin-last-op"))
      .toContainText("Station-committed Agent PCR", { timeout: 60_000 });
    const weakAgentKeys = await page.evaluate(() => Object.keys(localStorage)
      .filter(key => key.startsWith("agent.did.keys.") || key.includes(".agent.did.keys.")).length);
    expect(weakAgentKeys, "Agent DID binding keys must never enter the localStorage tier").toBe(0);
  } finally {
    await user.close();
  }
});
