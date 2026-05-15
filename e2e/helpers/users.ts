import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type Locator,
  type Page,
} from "@playwright/test";
import { diagnosticsRoot, type SolandKey, solandBaseUrl } from "./env";

export type JointUser = {
  name: string;
  did: string;
  deviceId: string;
  handle: string;
  displayName: string;
};

export type UserSession = {
  context: BrowserContext;
  page: Page;
  diagnosticsDir: string;
  consoleLines: string[];
  networkLines: string[];
  serverUrl: string;
};

export type OpenUserOpts = {
  sessionToken?: string;
  server?: SolandKey;
};

export type CreateSpaceOpts = {
  title: string;
  summary?: string;
  discoverability?: string;
  joinRule?: string;
  historyVisibility?: string;
  seedMembers?: string[];
};

export class JointUserPage {
  readonly user: JointUser;
  readonly session: UserSession;

  constructor(user: JointUser, session: UserSession) {
    this.user = user;
    this.session = session;
  }

  get page(): Page {
    return this.session.page;
  }

  get serverUrl(): string {
    return this.session.serverUrl;
  }

  async gotoHome() {
    await this.page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  }

  async gotoLogin() {
    await this.page.goto("/login", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("login-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoSetup() {
    await this.page.goto("/setup", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("space-lifecycle-flow")).toBeVisible({ timeout: 120_000 });
  }

  async gotoOnboarding() {
    await this.page.goto("/onboarding", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("account-flow")).toBeVisible({ timeout: 120_000 });
  }

  async gotoDirectory() {
    await this.page.goto("/directory", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("directory-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoSettings() {
    await this.page.goto("/settings", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("settings-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoSpaceAdmin(spaceId: string) {
    await this.page.goto(`/space/${spaceId}/admin`, { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("space-admin-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoTimelineSpace(spaceId: string) {
    await this.page.goto(`/timeline/${spaceId}`, { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("timeline")).toBeVisible({ timeout: 120_000 });
  }

  async createSpace(opts: CreateSpaceOpts): Promise<string> {
    await this.gotoSetup();
    const flow = this.page.getByTestId("space-lifecycle-flow").first();

    await flow.getByTestId("space-title-input").fill(opts.title);
    if (opts.summary !== undefined) {
      await flow.getByTestId("space-summary-input").fill(opts.summary);
    }
    await flow.getByTestId("new-space-next-button").first().click();

    if (opts.discoverability !== undefined) {
      await flow.getByTestId("space-discoverability-input").selectOption(opts.discoverability);
    }
    if (opts.joinRule !== undefined) {
      await flow.getByTestId("space-policy-join-rule-input").selectOption(opts.joinRule);
    }
    if (opts.historyVisibility !== undefined) {
      await flow.getByTestId("space-policy-history-visibility-input").selectOption(opts.historyVisibility);
    }
    await flow.getByTestId("new-space-next-button").first().click();

    if (opts.seedMembers && opts.seedMembers.length > 0) {
      await flow.getByTestId("seed-members-input").fill(opts.seedMembers.join("\n"));
    }
    await flow.getByTestId("create-space-button").click();

    await expect(flow).toContainText(/created cx:space:/, { timeout: 30_000 });
    const text = await flow.innerText();
    const match = text.match(/created (cx:space:[^\s]+)/);
    expect(match, `created space id in: ${text}`).not.toBeNull();
    return match![1];
  }

  // Drive the space admin invite-member form to invite `targetDid` into spaceId.
  // Caller MUST already have gotoSpaceAdmin(spaceId) or this navigates there.
  async inviteFromAdmin(spaceId: string, targetDid: string) {
    await this.gotoSpaceAdmin(spaceId);
    const invite = this.page.getByTestId("invite-member");
    await invite.getByTestId("invite-target-input").fill(targetDid);
    await invite.getByTestId("send-invite-button").click();
    await expect(this.page.getByTestId("space-admin-panel")).toContainText(
      new RegExp(`invited ${escapeRegex(targetDid)}`),
      { timeout: 30_000 },
    );
  }

  // Find the invite row addressed to this user inside /space/:id/admin's
  // space-invites list and click accept. Yougen surfaces all invites in
  // the admin list (`invite-row`) regardless of whether the viewer is
  // currently a member; the row is keyed on target DID.
  async acceptInvite(spaceId: string) {
    await this.gotoSpaceAdmin(spaceId);
    const row = this.page
      .getByTestId("invite-row")
      .filter({ hasText: this.user.did })
      .first();
    await expect(row).toBeVisible({ timeout: 30_000 });
    await row.getByTestId("accept-invite-button").click();
    await expect(row).toContainText(/active|accepted|joined/, { timeout: 30_000 });
  }

  // Send a message into spaceId's timeline. Asserts persistence write-status.
  async sendTimelineMessage(spaceId: string, body: string) {
    if (!this.page.url().includes(`/timeline/${spaceId}`)) {
      await this.gotoTimelineSpace(spaceId);
    }
    await this.page.getByTestId("composer-input").fill(body);
    await this.page.getByTestId("send-button").click();
    await expect(this.page.getByTestId("timeline")).toContainText(body, { timeout: 30_000 });
    await expect(this.page.getByTestId("write-status")).toContainText(/persisted/, {
      timeout: 30_000,
    });
  }

  // Read visible timeline event texts as an array (deduped on `body`).
  async readTimelineTexts(spaceId: string): Promise<string[]> {
    if (!this.page.url().includes(`/timeline/${spaceId}`)) {
      await this.gotoTimelineSpace(spaceId);
    }
    const events = this.page.getByTestId("timeline-event");
    const count = await events.count();
    const out: string[] = [];
    for (let i = 0; i < count; i += 1) {
      out.push((await events.nth(i).innerText()).trim());
    }
    return out;
  }

  timelineEvent(body: string): Locator {
    return this.page.getByTestId("timeline-event").filter({ hasText: body }).first();
  }

  async close() {
    await closeUser(this.session);
  }
}

export function uniqueUser(prefix: string): JointUser {
  const stamp = randomUUID();
  const slug = `${prefix}-${stamp}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const deviceSuffix = stamp.replace(/-/g, "").slice(0, 12);
  return {
    name: slug,
    did: `did:web:${slug}.example`,
    deviceId: `cx:device:01904100-0000-7000-8000-${deviceSuffix}`,
    handle: `@${slug}`,
    displayName: `${prefix} ${stamp}`,
  };
}

export async function ensureRegistered(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
) {
  const response = await request.post(`${solandBaseUrl(opts.server)}/api/v1/account/register`, {
    data: {
      did: user.did,
      handle: user.handle,
      display_name: user.displayName,
      device_id: user.deviceId,
    },
  });
  expect([201, 409]).toContain(response.status());
}

export async function issueDevSession(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const response = await request.post(`${solandBaseUrl(opts.server)}/api/v1/auth/dev-login`, {
    data: {
      actor: user.did,
      device_id: user.deviceId,
      display_name: user.displayName,
    },
  });
  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(body.access_token).toBeTruthy();
  return body.access_token;
}

export async function openUser(
  browser: Browser,
  user: JointUser,
  opts: OpenUserOpts = {},
): Promise<UserSession> {
  const serverUrl = solandBaseUrl(opts.server);
  const sessionToken = opts.sessionToken ?? "";
  const diagnosticsDir = path.join(diagnosticsRoot(), sanitize(`${Date.now()}-${user.name}`));
  fs.mkdirSync(diagnosticsDir, { recursive: true });
  const context = await browser.newContext({
    recordHar: {
      path: path.join(diagnosticsDir, "network.har"),
      mode: "minimal",
      content: "omit",
    },
  });
  await context.addInitScript(
    (config) => {
      window.localStorage.setItem("yougen.config.v1", JSON.stringify(config));
    },
    {
      server_url: serverUrl,
      account_did: user.did,
      device_id: user.deviceId,
      session_token: sessionToken,
    },
  );
  const page = await context.newPage();
  const consoleLines: string[] = [];
  const networkLines: string[] = [];
  page.on("console", (message) => {
    consoleLines.push(
      JSON.stringify({
        ts: new Date().toISOString(),
        type: message.type(),
        text: message.text(),
        location: message.location(),
      }),
    );
  });
  page.on("pageerror", (error) => {
    consoleLines.push(
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "pageerror",
        text: error.message,
        stack: error.stack,
      }),
    );
  });
  page.on("requestfailed", (request) => {
    networkLines.push(
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "requestfailed",
        method: request.method(),
        url: request.url(),
        failure: request.failure()?.errorText,
      }),
    );
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      networkLines.push(
        JSON.stringify({
          ts: new Date().toISOString(),
          type: "http-error",
          status: response.status(),
          url: response.url(),
        }),
      );
    }
  });
  return { context, page, diagnosticsDir, consoleLines, networkLines, serverUrl };
}

export async function openUserPage(
  browser: Browser,
  user: JointUser,
  opts: OpenUserOpts = {},
): Promise<JointUserPage> {
  return new JointUserPage(user, await openUser(browser, user, opts));
}

export async function closeUser(session: UserSession) {
  fs.writeFileSync(path.join(session.diagnosticsDir, "console.jsonl"), session.consoleLines.join("\n"), "utf8");
  fs.writeFileSync(path.join(session.diagnosticsDir, "network.jsonl"), session.networkLines.join("\n"), "utf8");
  await session.context.close();
}

function sanitize(value: string): string {
  const cleaned = value
    .trim()
    .replace(/[^a-zA-Z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "session";
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
