import fs from "node:fs";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type Locator,
  type Page,
} from "@playwright/test";
import { diagnosticsRoot, type SolandKey, solandBaseUrl } from "./env";
import { signedEventEnvelope } from "./soland-api";
import { selectDxcOption } from "./dxc-select";
import { dpopDeviceKeyFromSeedB64url, selfPathGrantHeaders } from "./session-grant-dpop";

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
  /// The bearer presented on `/_cokret/self/*`. Under the ②(A+②) model this is
  /// the `ck.session.grant` JWT; a request to a self-path also requires the DPoP
  /// + holder-proof material in `grant` below.
  sessionToken: string;
  /// Real grant + DPoP material for direct (non-browser) self-path API calls.
  /// Present when the session was opened with an injected grant.
  grant?: SessionGrantMaterial;
};

export type SessionGrantMaterial = {
  grantJwt: string;
  grantId: string;
  audience: string;
  /// base64url-no-pad 32-byte Ed25519 seed of the DPoP device key the grant is
  /// bound to (`cnf.jkt`).
  dpopSeedB64url: string;
};

export type OpenUserOpts = {
  sessionToken?: string;
  server?: SolandKey;
  /// Real `ck.session.grant` JWT to inject as yougen's bearer (②(A+②) model).
  /// When set together with `dpopSeedB64url`, yougen's dev-only boot injection
  /// rehydrates the grant + DPoP device key instead of relying on dev-login.
  grantJwt?: string;
  /// base64url-no-pad 32-byte Ed25519 seed of the DPoP device key the grant is
  /// bound to (its thumbprint == the grant's `cnf.jkt`).
  dpopSeedB64url?: string;
  /// coauth-assigned grant id (DB row id), required for yougen to mint the
  /// session-grant introspection holder proof soland forwards to coauth.
  grantId?: string;
  /// Audience the grant is bound to (the soland service DID).
  grantAudience?: string;
};

export type CreateRealmOpts = {
  title: string;
  summary?: string;
  discoverability?: string;
  joinRule?: string;
  historyVisibility?: string;
  encryptionProfile?: string;
  seedMembers?: string[];
};

function buildInviteLocatorUrl(serverUrl: string, subjectDid: string): string {
  const expiresAt = new Date(Date.now() + 15 * 60_000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
  const locatorToken = Buffer.from(
    JSON.stringify({
      subject_id: subjectDid,
      nonce: randomBytes(18).toString("base64url"),
      expires_at: expiresAt,
    }),
  ).toString("base64url");
  const base = serverUrl.replace(/\/$/, "");
  return `${base}/_cokret/open/invite-locators/resolve#token=${locatorToken}`;
}

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
    // yougen's /setup is the Overview; the Realm wizard lives at the
    // /setup/realms section. yougen/src/routes.rs §SetupSection.
    await this.page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("realm-lifecycle-strand")).toBeVisible({ timeout: 120_000 });
  }

  async gotoOnboarding() {
    await this.page.goto("/onboarding", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("account-strand")).toBeVisible({ timeout: 120_000 });
  }

  async gotoDirectory() {
    await this.page.goto("/directory", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("directory-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoSettings() {
    await this.page.goto("/settings", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("settings-panel")).toBeVisible({ timeout: 120_000 });
  }

  async gotoRealmAdmin(realmId: string) {
    await this.page.goto(`/realms/${realmId}/admin`, { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("realm-admin-panel")).toBeVisible({ timeout: 120_000 });
  }

  // Navigate to a specific Realm admin section (Members / Access / etc.).
  // yougen routes are `/realms/:id/admin/:section`; the Overview landing
  // doesn't show member rows or other section-specific testids.
  // After the panel mounts, click the section tab to ensure active_section
  // matches the URL — yougen's initial render can momentarily fall back
  // to Overview while signals settle.
  async gotoRealmAdminSection(realmId: string, section: string) {
    await this.page.goto(`/realms/${realmId}/admin/${section}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(this.page.getByTestId("realm-admin-panel")).toBeVisible({ timeout: 120_000 });
    const sectionLabel: Record<string, string> = {
      members: "Members",
      access: "Access",
      security: "Security & MLS",
      governance: "Governance",
      federation: "Federation",
      repair: "Repair & Danger",
    };
    const label = sectionLabel[section];
    if (label) {
      const tabs = this.page.getByTestId("realm-admin-sections");
      const tab = tabs.getByRole("link", { name: label, exact: true }).first();
      if ((await tab.count()) > 0) {
        await tab.click();
      }
    }
  }

  async gotoTimelineRealm(realmId: string) {
    await this.page.goto(`/timeline/${realmId}`, { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("timeline")).toBeVisible({ timeout: 120_000 });
  }

  async createRealm(opts: CreateRealmOpts): Promise<string> {
    await this.gotoSetup();
    const strand = this.page.getByTestId("realm-lifecycle-strand").last();

    await strand.getByTestId("realm-title-input").fill(opts.title);
    if (opts.summary !== undefined) {
      await strand.getByTestId("realm-summary-input").fill(opts.summary);
    }
    const basicsNext = strand.getByTestId("new-realm-next-button").first();
    await expect(basicsNext).toBeEnabled({ timeout: 30_000 });
    await basicsNext.click();

    if (opts.discoverability !== undefined) {
      await selectDxcOption(strand.getByTestId("realm-discoverability-input"), opts.discoverability);
    }
    if (opts.joinRule !== undefined) {
      await selectDxcOption(strand.getByTestId("realm-policy-join-rule-input"), opts.joinRule);
    }
    if (opts.historyVisibility !== undefined) {
      await selectDxcOption(strand.getByTestId("realm-policy-history-visibility-input"), opts.historyVisibility);
    }
    if (opts.encryptionProfile !== undefined) {
      await selectDxcOption(strand.getByTestId("realm-encryption-profile-input"), opts.encryptionProfile);
    }
    const policyNext = strand.getByTestId("new-realm-next-button").first();
    await expect(policyNext).toBeEnabled({ timeout: 30_000 });
    await policyNext.click();

    if (opts.seedMembers && opts.seedMembers.length > 0) {
      await strand.getByTestId("seed-members-input").fill(opts.seedMembers.join("\n"));
    }
    const createButton = strand.getByTestId("create-realm-button");
    await expect(createButton).toBeEnabled({ timeout: 30_000 });
    await createButton.click();

    // S6 recovery soft-gate (key-management §7.11): creating an end-to-end
    // encrypted Realm with no recovery path configured prompts the user to set
    // up the Recovery Key first. Test accounts generally have no recovery
    // configured, so accept the personal_node override and re-create. The gate
    // never appears for unencrypted Realms or when recovery is configured.
    const recoveryGate = this.page.getByTestId("encrypted-realm-recovery-gate").last();
    const gateAppeared = await recoveryGate
      .waitFor({ state: "visible", timeout: 2_000 })
      .then(() => true)
      .catch(() => false);
    if (gateAppeared) {
      await this.page.getByTestId("encrypted-realm-recovery-gate-override").last().click();
      await expect(recoveryGate).toBeHidden({ timeout: 10_000 });
      await expect(createButton).toBeEnabled({ timeout: 30_000 });
      await createButton.click();
    }

    await expect(strand).toContainText(/created ck:realm:/, { timeout: 30_000 });
    const text = await strand.innerText();
    const match = text.match(/created (ck:realm:[^\s]+)/);
    expect(match, `created realm id in: ${text}`).not.toBeNull();
    return match![1];
  }

  // Drive the Realm admin invite-member form to invite `targetDid` into realmId.
  // The invite-member card lives under the Members section in yougen, not the
  // Overview landing.
  async inviteFromAdmin(realmId: string, targetDid: string): Promise<string> {
    await this.gotoRealmAdminSection(realmId, "members");
    const invite = this.page.getByTestId("invite-member");
    await expect(invite).toBeVisible({ timeout: 30_000 });
    await invite
      .getByTestId("invite-target-input")
      .fill(buildInviteLocatorUrl(this.serverUrl, targetDid));
    await invite.getByTestId("send-invite-button").click();
    await expect(this.page.getByTestId("realm-admin-panel")).toContainText(
      new RegExp(`invited ${escapeRegex(targetDid)}`),
      { timeout: 30_000 },
    );
    const text = await this.page.getByTestId("realm-admin-panel").innerText();
    const match = text.match(/ck:invite:[a-zA-Z0-9:-]+/);
    expect(match, `invite id after inviting ${targetDid}: ${text}`).not.toBeNull();
    return match![0];
  }

  // Build the Authorization + DPoP + holder-proof headers for a direct
  // (non-browser) `/_cokret/self/*` call. Under the ②(A+②) model the bearer is
  // the ck.session.grant and soland requires a per-request DPoP proof plus the
  // session-grant introspection holder proof; a grant presented bearer-only is
  // rejected. When the session carries no grant material (legacy bearer), fall
  // back to bearer-only so dev-bearer call sites keep working.
  private selfPathHeaders(method: string, url: string): Record<string, string> {
    const grant = this.session.grant;
    if (grant) {
      return selfPathGrantHeaders({
        deviceKey: dpopDeviceKeyFromSeedB64url(grant.dpopSeedB64url),
        grantId: grant.grantId,
        grantJwt: grant.grantJwt,
        audience: grant.audience,
        method,
        url,
      });
    }
    const token = this.session.sessionToken;
    if (!token) {
      throw new Error("selfPathHeaders: no grant material or bearer captured on session");
    }
    return { authorization: `Bearer ${token}` };
  }

  // Accept a pending invite for this user. Yougen's realm-admin invite list
  // is session-local, so a fresh-context invitee can't see seed-member invites
  // via the UI. The old REST mutation endpoint was removed; acceptance now
  // strands through the canonical event path as an invite -> join member state.
  async acceptInvite(realmId: string) {
    const serverUrl = this.session.serverUrl;
    const listUrl = `${serverUrl}/_cokret/self/authz/invites`;
    const listResp = await this.page.request.get(listUrl, {
      headers: this.selfPathHeaders("GET", listUrl),
    });
    if (!listResp.ok()) {
      throw new Error(
        `acceptInvite: list /authz/invites returned ${listResp.status()} for ${this.user.did}`,
      );
    }
    const body = (await listResp.json()) as {
      invites?: Array<{ invite_id: string; realm_id: string; invitee?: string }>;
    };
    const invite = (body.invites ?? []).find(
      (i) => i.realm_id === realmId && i.invitee === this.user.did,
    );
    if (!invite) {
      throw new Error(
        `acceptInvite: no pending invite for ${this.user.did} in realm ${realmId} ` +
          `(visible invites: ${JSON.stringify(body.invites ?? [])})`,
      );
    }
    await this.acceptInviteById(realmId, invite.invite_id);
  }

  async acceptInviteById(realmId: string, inviteId: string) {
    const serverUrl = this.session.serverUrl;
    const envelope = signedEventEnvelope({
      actorDid: this.user.did,
      realmId,
      kind: "ck.member.state",
      payload: {
        actor_id: this.user.did,
        membership: "join",
        reason: "invite_accept",
        invite_ref: inviteId,
        delivery_status: "unroutable",
      },
    });
    const eventsUrl = `${serverUrl}/_cokret/self/events`;
    const acceptResp = await this.page.request.post(eventsUrl, {
      headers: this.selfPathHeaders("POST", eventsUrl),
      data: envelope,
    });
    if (![200, 201].includes(acceptResp.status())) {
      const text = await acceptResp.text();
      throw new Error(
        `acceptInviteById: ck.member.state{join} returned ${acceptResp.status()} for invite ${inviteId}: ${text}`,
      );
    }
  }

  // Send a message into realmId's timeline. Asserts persistence write-status.
  async sendTimelineMessage(realmId: string, body: string) {
    if (!this.page.url().includes(`/timeline/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
    }
    const writeResponse = this.page.waitForResponse(
      (response) => {
        const request = response.request();
        return (
          request.method() === "POST" &&
          /\/(?:api\/v1|_cokret\/self)\/events(?:\?|$)/.test(response.url()) &&
          (request.postData() ?? "").includes(body)
        );
      },
      { timeout: 30_000 },
    );
    await this.page.getByTestId("composer-input").fill(body);
    await this.page.getByTestId("send-button").click();
    const persisted = await writeResponse;
    if (![200, 201].includes(persisted.status())) {
      throw new Error(
        `sendTimelineMessage: /_cokret/self/events returned ${persisted.status()} for ${body}`,
      );
    }
    await expect(this.page.getByTestId("timeline")).toContainText(body, { timeout: 30_000 });
    await expect(this.page.getByTestId("write-status")).toContainText(/persisted/, {
      timeout: 30_000,
    });
  }

  // Read visible timeline event texts as an array (deduped on `body`).
  async readTimelineTexts(realmId: string): Promise<string[]> {
    if (!this.page.url().includes(`/timeline/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
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
    deviceId: `ck:device:01904100-0000-7000-8000-${deviceSuffix}`,
    handle: `@${slug}`,
    displayName: `${prefix} ${stamp}`,
  };
}

export async function ensureRegistered(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
) {
  // Spec-canonical registration binding (`ck.gate.account.command.register`):
  // `POST /_cokret/gate/account/register` with `AccountRegisterRequestBody
  // {principal_id, display_name?, device_id?}`. The bare `handle` field is no
  // longer accepted (the first handle arrives via a signed handle claim,
  // identity-handles.md); the account gets a synthetic localpart derived from
  // the DID. Success is 200 (200|409 here for idempotent setup).
  const response = await request.post(`${solandBaseUrl(opts.server)}/_cokret/gate/account/register`, {
    data: {
      principal_id: user.did,
      display_name: user.displayName,
      device_id: user.deviceId,
    },
  });
  expect([200, 409]).toContain(response.status());
}

export async function issueDevSession(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
): Promise<string> {
  const response = await request.post(
    `${solandBaseUrl(opts.server)}/_soland/gate/auth/dev-login`,
    {
      data: {
        actor: user.did,
        device_id: user.deviceId,
        display_name: user.displayName,
      },
    },
  );
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
  const sessionInjection =
    opts.grantJwt && opts.dpopSeedB64url
      ? {
          grant_jwt: opts.grantJwt,
          dpop_seed_b64url: opts.dpopSeedB64url,
          grant_id: opts.grantId ?? "",
          audience: opts.grantAudience ?? "",
        }
      : undefined;
  await context.addInitScript(
    (init) => {
      window.localStorage.setItem("yougen.config.v1", JSON.stringify(init.config));
      // The harness injects sessions into localStorage; yougen's wasm build is
      // IndexedDB-only for bearer/secrets by default (SubtleCrypto, non-
      // extractable). Opt into the localStorage compatibility tier so the
      // injected bearer/seed are accepted (test-only; production leaves this
      // unset). See yougen secure_key_store WASM_ALLOW_LOCALSTORAGE_SECRETS_FLAG.
      window.localStorage.setItem("yougen.security.allow_localstorage_secrets", "1");
      // ②(A+②) real-grant injection: hand yougen's dev-only boot path the real
      // ck.session.grant + the DPoP device seed it is bound to, so the wasm
      // client rehydrates a genuine grant (coauth introspection passes, device
      // enrollment runs) instead of a soland-only dev-login bearer. yougen reads
      // this key only when allow_localstorage_secrets is on. See yougen
      // app.rs inject_test_session_grant.
      if (init.sessionInjection) {
        window.localStorage.setItem(
          "yougen.test.session_injection.v1",
          JSON.stringify(init.sessionInjection),
        );
      }
    },
    {
      config: {
        server_url: serverUrl,
        account_did: user.did,
        device_id: user.deviceId,
        session_token: sessionToken,
      },
      sessionInjection,
    },
  );
  // Hide dioxus-cli's dev-mode rebuild toast (`#__dx-toast`). When dx serve's
  // dev WS reconnects mid-test the overlay covers the page and blocks pointer
  // events, even though the app underneath is interactive. We never want to
  // observe it during e2e — kill it permanently via CSS injected on every
  // navigation.
  await context.addInitScript(() => {
    const inject = () => {
      if (!document.head) return;
      const id = "__cotest_hide_dx_toast";
      if (document.getElementById(id)) return;
      const style = document.createElement("style");
      style.id = id;
      style.textContent =
        "#__dx-toast,#__dx-toast-container{display:none!important;visibility:hidden!important;pointer-events:none!important}";
      document.head.appendChild(style);
    };
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", inject);
    } else {
      inject();
    }
  });
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
      void response
        .text()
        .then((body) => {
          networkLines.push(
            JSON.stringify({
              ts: new Date().toISOString(),
              type: "http-error",
              status: response.status(),
              method: response.request().method(),
              url: response.url(),
              body: body.slice(0, 2000),
            }),
          );
        })
        .catch(() => {
          networkLines.push(
            JSON.stringify({
              ts: new Date().toISOString(),
              type: "http-error",
              status: response.status(),
              method: response.request().method(),
              url: response.url(),
            }),
          );
        });
    }
  });
  const grant =
    opts.grantJwt && opts.dpopSeedB64url
      ? {
          grantJwt: opts.grantJwt,
          grantId: opts.grantId ?? "",
          audience: opts.grantAudience ?? "",
          dpopSeedB64url: opts.dpopSeedB64url,
        }
      : undefined;
  return {
    context,
    page,
    diagnosticsDir,
    consoleLines,
    networkLines,
    serverUrl,
    sessionToken,
    grant,
  };
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
