import { createHash } from "node:crypto";
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

for (const cut of ["inception", "provision", "did-binding"] as const) {
  test(`Agent resumes its original durable ceremony after a lost ${cut} response @agent-provision-durable-recovery`, async ({ browser, request }) => {
    const session = await createDpopUserSession(request, `agent-crash-${cut}`, {});
    if (!session) throw new Error("real Coauth session is required");
    const user = await openUserPage(browser, session.user, {
      grantJwt: session.grantJwt, dpopSeedB64url: session.dpopSeedB64url,
      eventSigningSeedB64url: session.eventSigningSeedB64url, grantId: session.grantId,
      accountId: session.accountId, principalControlRealmId: session.principalControlRealmId,
      grantAudience: session.grantAudience, recoveryMaterialEvidence: session.recoveryMaterialEvidence,
      autoCompleteRecoveryKeySetup: false,
    });
    const page = user.page;
    const commitHashes: string[] = [];
    const didHashes: string[] = [];
    let stopped = false;
    let observedCut = false;
    let acceptedStage = "";
    let didCalls = 0;
    let releaseCut!: () => void;
    const cutReached = new Promise<void>(resolve => { releaseCut = resolve; });
    const digest = (bytes: string) => createHash("sha256").update(bytes).digest("hex");
    try {
      await user.gotoHome();
      expect(Boolean(await user.completeRecoveryKeySetupIfPrompted(120_000))).toBe(true);
      await user.gotoSettings();
      await page.getByTestId("settings-nav-item-agents").click();
      await page.getByTestId("agent-admin-create-open-button").click();
      await page.getByTestId("agent-admin-provision-agent-slug").fill(`crash-${cut}`);
      await page.route("**/_arkret/**", async route => {
        const outbound = route.request();
        const path = new URL(outbound.url()).pathname;
        if (outbound.method() !== "POST") { await route.continue(); return; }
        const isDid = path === "/_arkret/root/identity/submit-did-operation";
        const isCommit = path === "/_arkret/self/agents" && outbound.postDataJSON()?.phase === "commit";
        if (stopped) { await route.abort("failed"); return; }
        if (isDid) didHashes.push(digest(outbound.postData() ?? ""));
        if (isCommit) commitHashes.push(digest(outbound.postData() ?? ""));
        if (isDid) didCalls++;
        const target = cut === "inception" ? isDid && didCalls === 1
          : cut === "provision" ? isCommit && commitHashes.length === 1
            : isDid && didCalls === 2;
        if (!target || observedCut) { await route.continue(); return; }
        const accepted = await route.fetch({ maxRetries: 0 });
        expect(accepted.ok()).toBe(true);
        // Keep only the public stage; neither pairing material nor bodies are attached.
        acceptedStage = (await accepted.json()).status;
        stopped = true;
        observedCut = true;
        await route.abort("failed");
        releaseCut();
      });
      await page.getByTestId("agent-admin-provision-button").click();
      await cutReached;
      expect(acceptedStage).toBe(cut === "provision" ? "awaiting_pcr_genesis" : "accepted");
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("remains recoverable");
      await page.unroute("**/_arkret/**");
      stopped = false;
      page.on("request", outbound => {
        const path = new URL(outbound.url()).pathname;
        if (outbound.method() !== "POST") return;
        if (path === "/_arkret/root/identity/submit-did-operation") didHashes.push(digest(outbound.postData() ?? ""));
        if (path === "/_arkret/self/agents" && outbound.postDataJSON()?.phase === "commit") commitHashes.push(digest(outbound.postData() ?? ""));
      });
      const complete = page.waitForResponse(response => response.status() === 201
        && response.request().method() === "POST" && new URL(response.url()).pathname === "/_arkret/self/agents"
        && response.request().postDataJSON()?.phase === "commit", { timeout: 180_000 });
      void complete.catch(() => undefined);
      await page.goto("/", { waitUntil: "domcontentloaded" });
      expect((await (await complete).json()).status).toBe("complete");
      expect(new Set(commitHashes).size, "no replacement provision Event or publication evidence").toBe(1);
      expect(new Set(didHashes).size, "only the original inception and binding operations").toBe(2);
      if (cut === "provision") expect(commitHashes.filter(hash => hash === commitHashes[0]).length).toBeGreaterThan(1);
      if (cut === "inception") expect(didHashes.filter(hash => hash === didHashes[0]).length).toBeGreaterThan(1);
      if (cut === "did-binding") expect(didHashes.filter(hash => hash === didHashes[1]).length).toBeGreaterThan(1);
      expect(await page.evaluate(() => Object.keys(localStorage).filter(key => key.includes("agent.did.keys")).length)).toBe(0);
    } finally { await user.close(); }
  });
}
