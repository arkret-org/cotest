import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { expect, type APIRequestContext, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { diagnosticsRoot, solandBaseUrl } from "./env";

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

  async gotoSpaceAdmin(spaceId: string) {
    await this.page.goto(`/space/${spaceId}/admin`, { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("space-admin-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoDirectory() {
    await this.page.goto("/directory", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("directory-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoSettings() {
    await this.page.goto("/settings", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("settings-panel")).toBeVisible({ timeout: 120_000 });
  }

  async createSpace(opts: {
    title: string;
    summary?: string;
    discoverability?: string;
    joinRule?: string;
    historyVisibility?: string;
    seedMembers?: string[];
  }): Promise<string> {
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

  async connect() {
    await this.page.getByTestId("connect-button").click();
    await expect(this.page.getByTestId("status-label")).toContainText(
      /Connected|Online|Empty|authenticated|principal_server/,
    );
  }

  async expectPrincipal() {
    await expect(this.page.getByTestId("principal-context")).toContainText(this.user.did);
  }

  async close() {
    await closeUser(this.session);
  }
}

export const alice: JointUser = {
  name: "alice",
  did: "did:web:alice.example",
  deviceId: "cx:device:01904100-0000-7000-8000-000000000101",
  handle: "@alice-joint-e2e",
  displayName: "Alice Joint E2E",
};

export const bob: JointUser = {
  name: "bob",
  did: "did:web:bob.example",
  deviceId: "cx:device:01904100-0000-7000-8000-000000000102",
  handle: "@bob-joint-e2e",
  displayName: "Bob Joint E2E",
};

export const admin: JointUser = {
  name: "admin",
  did: "did:web:admin.example",
  deviceId: "cx:device:01904100-0000-7000-8000-000000000103",
  handle: "@admin-joint-e2e",
  displayName: "Admin Joint E2E",
};

export const guest: JointUser = {
  name: "guest",
  did: "did:web:guest.example",
  deviceId: "cx:device:01904100-0000-7000-8000-000000000104",
  handle: "@guest-joint-e2e",
  displayName: "Guest Joint E2E",
};

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

export async function ensureRegistered(request: APIRequestContext, user: JointUser) {
  const response = await request.post(`${solandBaseUrl()}/api/v1/account/register`, {
    data: {
      did: user.did,
      handle: user.handle,
      display_name: user.displayName,
      device_id: user.deviceId,
    },
  });
  expect([201, 409]).toContain(response.status());
}

export async function issueDevSession(request: APIRequestContext, user: JointUser): Promise<string> {
  const response = await request.post(`${solandBaseUrl()}/api/v1/auth/dev-login`, {
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
  sessionToken = "",
): Promise<UserSession> {
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
      server_url: solandBaseUrl(),
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
  return { context, page, diagnosticsDir, consoleLines, networkLines };
}

export async function openUserPage(
  browser: Browser,
  user: JointUser,
  sessionToken = "",
): Promise<JointUserPage> {
  return new JointUserPage(user, await openUser(browser, user, sessionToken));
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
