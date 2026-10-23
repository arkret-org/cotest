import { test as jointTest, expect } from "../../helpers/joint-fixture";
import { decodeIngressEvents } from "../../helpers/event-ingress";
import { canonicalJson } from "../../helpers/coland-api";
import { openDpopUserPageFromSession, type JointUserPage } from "../../helpers/users";
import type { Page } from "../../helpers/arkret-test";
import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import os from "node:os";

type PersistentAgentClient = { user: JointUserPage; restart(beforeNavigate?: (page: Page) => Promise<void>): Promise<JointUserPage> };
const test = jointTest.extend<{ agentClient: PersistentAgentClient }>({
  agentClient: async ({ jointUsers, browser }, use) => {
    const prefix = path.join(os.tmpdir(), "cotest-agent-avatar-");
    const directory = await mkdtemp(prefix);
    let client = await openDpopUserPageFromSession(browser, jointUsers.aliceSession, {
      persistentUserDataDir: directory,
    });
    if (!client) throw new Error("Agent avatar requires the canonical controller session");
    try {
      await use({
        user: client.page,
        async restart(beforeNavigate) {
          await client!.page.close();
          client = await openDpopUserPageFromSession(browser, jointUsers.aliceSession, {
            persistentUserDataDir: directory, resumePersistentProfile: true, beforeNavigate,
          });
          if (!client) throw new Error("Agent controller could not reopen its durable profile");
          return client.page;
        },
      });
    } finally {
      await client?.page.close();
      if (!path.resolve(directory).startsWith(path.resolve(prefix))) throw new Error("unexpected browser custody directory");
      await rm(directory, { recursive: true, force: true });
    }
  },
});

test.use({ trace: "off", screenshot: "off", video: "off" });
test.setTimeout(720_000);

const avatarPng = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAICAYAAADN5B7xAAAAy0lEQVR4nBXLIRXEMBBAwRURHBwRK6I4OCJWRHFwRXwRxcH18u/d8IkIbIEjMAOvwBVYgXfgE0jgG/gFRnRsHUfH7Hh1XB2r493x6UjHt+PX/yGxJY7ETLwSV2Il3olPIolv4pf/MLFNHBNz4jVxTayJ98RnIhPfid/8h8JWOAqz8CpchVV4Fz6FFL6FX/3DxrZxbMyN18a1sTbeG5+NbHw3fvsfwAYOMMELXGCBN/iAgC/48Q8H28FxMA9eB9fBOngffA5y8D34HfwBl3vzwZTfUBgAAAAASUVORK5CYII=",
  "base64",
);

for (const mode of ["avatar", "lost-responses", "retryable-profile", "account-switch", "provision-rejected", "profile-rejected", "no-avatar"] as const) {
  test(`Agent creation persists accepted avatar: ${mode} @fully-implemented`, async ({ jointUsers, agentClient }) => {
    let user = agentClient.user;
    let page = user.page;
    const slug = `avatar-${Date.now().toString(36)}`;
    let avatar: string | undefined;
    let agent: string | undefined;
    let pcr: string | undefined;
    let delegation: string | undefined;
    let lostProvision = false;
    let lostProfile = false;
    let profileAttempts = 0;
    let profileConfirmed = false;
    let holdProfile = mode === "retryable-profile" || mode === "account-switch";
    let rejectProvision = mode === "provision-rejected";
    let clientGeneration = 0;
    const profileBytes = new Set<string>();
    const preparationBytes = new Set<string>();
    const provisionBytes = new Set<string>();
    const allocatedAgents = new Set<string>();
    const installRoutes = async (target: Page) => {
      const generation = ++clientGeneration;
      await target.route("**/_arkret/self/agents", async route => {
        const request = route.request();
        if (request.method() !== "POST") return route.continue();
        const body = request.postDataJSON();
        expect(body.avatar_blob_ref).toBeUndefined();
        if (body.phase === "prepare") preparationBytes.add(canonicalJson(body));
        if (rejectProvision) {
          return route.fulfill({ status: 403, contentType: "application/problem+json", body: JSON.stringify({
            type: "https://arkret.org/problems/capability_denied", title: "Capability denied",
            status: 403, detail: "Avatar test controller create denial",
          }) });
        }
        if (body.phase === "commit") provisionBytes.add(canonicalJson(body));
        const response = await route.fetch();
        expect(response.ok()).toBe(true);
        const result = await response.json();
        allocatedAgents.add(result.agent_id);
        if (result.status === "complete") {
          agent = result.agent_id;
          pcr = result.principal_control_realm_id;
          delegation = result.controller_authorization_ref;
          if (mode === "lost-responses" && generation === 1) {
            lostProvision = true;
            return route.abort("failed");
          }
        }
        await route.fulfill({ response });
      });
      await target.route("**/_arkret/self/events", async route => {
        const request = route.request();
        if (request.method() !== "POST") return route.continue();
        const events = decodeIngressEvents(request.postData());
        const profile = events.find(event => event.kind === "ak.profile.create");
        if (!profile) return route.continue();
        profileAttempts++;
        profileBytes.add(canonicalJson(profile));
        expect(profile.actor_id).toEqual({ kind: "account", account_id: {
          principal_id: agent, station_id: jointUsers.aliceSession.accountId.station_id,
        } });
        expect(profile.executed_by).toEqual({ kind: "account", account_id: jointUsers.aliceSession.accountId });
        expect(profile.authorization_ref).toBe(delegation);
        expect(profile.realm_id).toBe(pcr);
        expect(profile.payload?.object).toMatchObject({ principal_id: agent, actor_kind: "agent",
          avatar_blob_ref: avatar, accountable_principal_ids: [jointUsers.aliceSession.accountId.principal_id] });
        if (holdProfile) {
          return route.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({
            type: "https://arkret.org/problems/temporarily_unavailable", title: "Temporarily unavailable",
            status: 503, detail: "Avatar test retry boundary",
          }) });
        }
        if (mode === "profile-rejected") {
          return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
            status: "rejected", reason_code: "capability_denied",
          }) });
        }
        const response = await route.fetch();
        expect(response.ok()).toBe(true);
        const outcome = await response.json();
        expect(outcome.commit.event_ref).toBe(profile.event_id);
        if (mode === "lost-responses" && generation === 2) {
          lostProfile = true;
          return route.abort("failed");
        }
        await route.fulfill({ response });
        profileConfirmed = true;
      });
    };
    await installRoutes(page);
    await user.gotoSettings();
    await page.getByTestId("settings-nav-item-agents").click();
    await page.getByTestId("agent-admin-create-open-button").click();
    await page.getByTestId("agent-admin-provision-agent-slug").fill(slug);
    if (mode !== "no-avatar") {
      await page.getByTestId("agent-admin-provision-avatar-input").setInputFiles({ name: "agent.png", mimeType: "image/png", buffer: avatarPng });
      const uploaded = page.waitForResponse(response => response.request().method() === "POST"
        && new URL(response.url()).pathname === "/_arkret/self/blob/upload");
      await page.getByTestId("agent-admin-provision-avatar-upload-cropped").click();
      avatar = (await (await uploaded).json()).blob_ref;
      expect(avatar).toMatch(/^ak:blob:/);
      await expect(page.getByTestId("agent-admin-provision-avatar-crop-editor")).toHaveCount(0);
    }
    await page.getByTestId("agent-admin-provision-button").click();
    if (mode === "provision-rejected") {
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("Agent creation remains recoverable", { timeout: 180_000 });
      await expect(page.getByTestId("agent-admin-provision-agent-slug")).toHaveValue(slug);
      await expect(page.getByTestId("agent-admin-provision-avatar-preview")).not.toHaveClass(/generated-avatar/);
      expect(allocatedAgents.size).toBe(0);
      expect(profileAttempts).toBe(0);
      rejectProvision = false;
      await page.getByTestId("agent-admin-provision-button").click();
    }
    if (mode === "lost-responses") {
      await expect.poll(() => lostProvision, { timeout: 180_000 }).toBe(true);
      user = await agentClient.restart(installRoutes);
      page = user.page;
      await expect.poll(() => lostProfile, { timeout: 180_000 }).toBe(true);
      user = await agentClient.restart(installRoutes);
      page = user.page;
      await expect.poll(() => profileConfirmed, { timeout: 180_000 }).toBe(true);
      expect(profileAttempts).toBeGreaterThan(1);
      await user.gotoSettings();
      await page.getByTestId("settings-nav-item-agents").click();
    } else if (mode === "account-switch") {
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("Agent was created; its avatar is still pending", { timeout: 180_000 });
      await page.getByTestId("account-menu-button").click();
      await page.getByTestId("account-menu").getByTestId("account-add").click();
      await expect(page.getByTestId("login-panel")).toBeVisible();
      await page.waitForTimeout(500);
      const beforeSwitch = profileAttempts;
      holdProfile = false;
      await page.waitForTimeout(6_000);
      expect(profileAttempts).toBe(beforeSwitch);
      await page.getByTestId("return-previous-account").click();
      await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
      await expect.poll(() => profileConfirmed, { timeout: 180_000 }).toBe(true);
      await user.gotoSettings();
      await page.getByTestId("settings-nav-item-agents").click();
    } else if (mode === "retryable-profile") {
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("Agent was created; its avatar is still pending", { timeout: 180_000 });
      await expect(page.getByTestId("agent-admin-provision-agent-slug")).toHaveValue(slug);
      holdProfile = false;
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("Created", { timeout: 180_000 });
      await expect(page.getByTestId("agent-admin-provision")).toHaveCount(0);
    } else if (mode === "profile-rejected") {
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("Agent was created; its avatar is still pending", { timeout: 180_000 });
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("capability_denied");
      await expect(page.getByTestId("agent-admin-provision-agent-slug")).toHaveValue(slug);
      await expect(page.getByTestId("agent-admin-provision-avatar-preview")).not.toHaveClass(/generated-avatar/);
    } else {
      await expect(page.getByTestId("agent-admin-last-op")).toContainText("Created", { timeout: 180_000 });
      await expect(page.getByTestId("agent-admin-provision")).toHaveCount(0);
    }
    await expect.poll(() => agent, { timeout: 180_000 }).toMatch(/^ak:did_core:/);
    for (let reload = 0; reload < 2; reload++) {
      const readStartedAt = Date.now();
      const listed = page.waitForResponse(response => response.request().method() === "GET"
        && response.request().timing().startTime >= readStartedAt
        && new URL(response.url()).pathname === "/_arkret/self/agents")
        .then(response => response.json());
      await page.reload({ waitUntil: "domcontentloaded" });
      const directory = await listed;
      const matching = directory.agents.filter((row: { agent_id: string }) => row.agent_id === agent);
      expect(matching).toHaveLength(1);
      const acceptedAvatar = mode === "profile-rejected" ? undefined : avatar;
      expect(matching[0].avatar_blob_ref).toBe(acceptedAvatar);
      const row = page.getByTestId("agent-admin-row").filter({ hasText: slug });
      await expect(row).toHaveCount(1);
      const image = row.getByTestId("agent-admin-avatar");
      if (acceptedAvatar) await expect(image.locator("img")).toHaveAttribute("src", /^data:image\//, { timeout: 120_000 });
      else await expect(image).toHaveClass(/generated-avatar/);
      const bounds = await image.boundingBox();
      expect(bounds?.width).toBe(36);
      expect(bounds?.height).toBe(36);
      const details = page.waitForResponse(response => response.request().method() === "GET"
        && decodeURIComponent(new URL(response.url()).pathname).endsWith(`/_arkret/self/agents/${agent}`))
        .then(response => response.json());
      await row.click();
      // A selected row may already have loaded its authoritative details on mount.
      await page.getByTestId("agent-admin-filter-paused").click();
      await page.getByTestId("agent-admin-filter-all").click();
      await row.click();
      expect((await details).agent.avatar_blob_ref).toBe(acceptedAvatar);
    }
    expect(allocatedAgents.size).toBe(1);
    expect(preparationBytes.size).toBe(1);
    expect(provisionBytes.size).toBe(1);
    expect(profileBytes.size).toBe(mode === "no-avatar" ? 0 : 1);
    const before = profileAttempts;
    await page.waitForTimeout(6_000);
    expect(profileAttempts).toBe(before);
    const cold = await agentClient.restart();
    const directoryRead = cold.page.waitForResponse(response => response.request().method() === "GET"
      && new URL(response.url()).pathname === "/_arkret/self/agents")
      .then(response => response.json());
    await cold.gotoSettings();
    await cold.page.getByTestId("settings-nav-item-agents").click();
    const coldDirectory = await directoryRead;
    expect(coldDirectory.agents.filter((row: { agent_id: string }) => row.agent_id === agent)).toHaveLength(1);
    expect(coldDirectory.agents.find((row: { agent_id: string }) => row.agent_id === agent).avatar_blob_ref)
      .toBe(mode === "profile-rejected" ? undefined : avatar);
    await expect(cold.page.getByTestId("agent-admin-row").filter({ hasText: slug })).toHaveCount(1);
    await jointUsers.bobPage.gotoSettings();
    await jointUsers.bobPage.page.getByTestId("settings-nav-item-agents").click();
    await expect(jointUsers.bobPage.page.getByTestId("agent-admin-row").filter({ hasText: slug })).toHaveCount(0);
  });
}
