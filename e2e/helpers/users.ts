import fs from "node:fs";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
  type Browser,
  type BrowserContext,
  type Locator,
  type Page,
} from "@playwright/test";
import {
  coauthBaseUrl,
  diagnosticsRoot,
  type SolandKey,
  solandBaseUrl,
  solandServiceDid,
} from "./env";
import { signedEventEnvelope } from "./soland-api";
import { selectDxcOption } from "./dxc-select";
import {
  registerCoauthPasswordAccount,
  type CoauthPasswordAccount,
} from "./coauth-register";
import {
  dpopDeviceSeedB64url,
  dpopDeviceKeyFromSeedB64url,
  generateDpopDeviceKey,
  kickoffDpopHeaders,
  selfPathGrantHeaders,
  type DpopDeviceKey,
} from "./session-grant-dpop";

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
  keepDeviceAuthorizationModal: boolean;
  /// The credential presented on `/_cokret/self/*`. Under the ②(A+②) model this
  /// is the `ck.session.grant` JWT; a request to a self-path also requires the
  /// DPoP + holder-proof material in `grant` below.
  sessionCredential: string;
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
  sessionCredential?: string;
  server?: SolandKey;
  keepDeviceAuthorizationModal?: boolean;
  /// Real `ck.session.grant` JWT to inject as yougen's session credential.
  /// When set together with `dpopSeedB64url`, yougen's dev-only boot injection
  /// rehydrates the grant + DPoP device key instead of relying on dev-login.
  grantJwt?: string;
  /// base64url-no-pad 32-byte Ed25519 seed of the DPoP device key the grant is
  /// bound to (its thumbprint == the grant's `cnf.jkt`).
  dpopSeedB64url?: string;
  /// coauth-assigned grant id (DB row id), persisted by yougen with the grant
  /// so refresh/logout paths can identify the current grant chain.
  grantId?: string;
  /// Audience the grant is bound to (the soland service DID).
  grantAudience?: string;
};

export type DpopUserSession = {
  user: JointUser;
  grantJwt: string;
  grantId: string;
  grantAudience: string;
  dpopSeedB64url: string;
  deviceKey: DpopDeviceKey;
};

export type DpopUserPageSession = {
  user: JointUser;
  session: DpopUserSession;
  page: JointUserPage;
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryAfterMs(response: APIResponse, fallbackMs: number): number {
  const raw = response.headers()["retry-after"];
  if (!raw) {
    return fallbackMs;
  }
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(Math.max(Math.ceil(seconds * 1000), 250), 65_000);
  }
  const dateMs = Date.parse(raw);
  if (Number.isFinite(dateMs)) {
    return Math.min(Math.max(dateMs - Date.now(), 250), 65_000);
  }
  return fallbackMs;
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : undefined;
}

function stringField(
  record: Record<string, unknown>,
  field: string,
): string | undefined {
  const value = record[field];
  return typeof value === "string" ? value : undefined;
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
    await expect(this.page.getByTestId("client-shell")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoLogin() {
    await this.page.goto("/login", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("login-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoSetup() {
    // yougen's /setup is the Overview; the Realm wizard lives at the
    // /setup/realms section. yougen/src/routes.rs §SetupSection.
    await this.page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("realm-lifecycle-strand")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoOnboarding() {
    await this.page.goto("/onboarding", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("account-strand")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoDirectory() {
    await this.page.goto("/directory", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("directory-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoSettings() {
    await this.page.goto("/settings", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("settings-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoNotifications() {
    await this.page.goto("/notifications", { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("notifications-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoRealmAdmin(realmId: string) {
    await this.page.goto(`/realms/${realmId}/settings`, {
      waitUntil: "domcontentloaded",
    });
    await expect(this.page.getByTestId("realm-admin-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  // Navigate to a specific Realm admin section (Members / Access / etc.).
  // Members is its own route; other admin sections live under settings.
  async gotoRealmAdminSection(realmId: string, section: string) {
    if (section === "members") {
      await this.page.goto(`/realms/${realmId}/members`, {
        waitUntil: "domcontentloaded",
      });
      await expect(this.page.getByTestId("realm-members-panel")).toBeVisible({
        timeout: 120_000,
      });
      await this.dismissDeviceAuthorizationPrompt();
      return;
    }

    await this.page.goto(`/realms/${realmId}/settings/${section}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(this.page.getByTestId("realm-admin-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
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
    await this.page.goto(`/chat/${realmId}`, { waitUntil: "domcontentloaded" });
    await expect(this.page.getByTestId("message-list")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  private async dismissDeviceAuthorizationPrompt() {
    if (!this.session.keepDeviceAuthorizationModal) {
      await dismissDeviceAuthorizationPrompt(this.page);
    }
  }

  async completeRecoveryKeySetupIfPrompted(
    timeoutMs = 5_000,
  ): Promise<string | undefined> {
    const modal = this.page.getByTestId("recovery-key-setup-modal").last();
    const visible = await modal
      .waitFor({ state: "visible", timeout: timeoutMs })
      .then(() => true)
      .catch(() => false);
    if (!visible) {
      return undefined;
    }

    const generatedKeyField = this.page
      .getByTestId("recovery-key-setup-generated-key")
      .last();
    await expect(generatedKeyField).toBeVisible({ timeout: 30_000 });
    const recoveryKey = (await generatedKeyField.inputValue()).trim();
    expect(
      recoveryKey.split(/\s+/),
      "recovery-key setup prompt must expose a 24-word key",
    ).toHaveLength(24);

    await this.page
      .getByTestId("recovery-key-setup-confirm-key")
      .last()
      .fill(recoveryKey);
    await this.page.getByTestId("recovery-key-setup-saved").last().click();
    await expect(modal).toBeHidden({ timeout: 30_000 });
    return recoveryKey;
  }

  async acknowledgeRecommendedEncryptionPromptIfVisible(
    timeoutMs = 5_000,
  ): Promise<boolean> {
    const modal = this.page
      .getByTestId("recommended-encryption-floor-modal")
      .last();
    const visible = await modal
      .waitFor({ state: "visible", timeout: timeoutMs })
      .then(() => true)
      .catch(() => false);
    if (!visible) {
      return false;
    }

    await this.page
      .getByTestId("recommended-encryption-floor-enable")
      .last()
      .click();
    await expect(modal).toBeHidden({ timeout: 10_000 });
    return true;
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
      await selectDxcOption(
        strand.getByTestId("realm-discoverability-input"),
        opts.discoverability,
      );
    }
    if (opts.joinRule !== undefined) {
      await selectDxcOption(
        strand.getByTestId("realm-policy-join-rule-input"),
        opts.joinRule,
      );
    }
    if (opts.historyVisibility !== undefined) {
      await selectDxcOption(
        strand.getByTestId("realm-policy-history-visibility-input"),
        opts.historyVisibility,
      );
    }
    if (opts.encryptionProfile !== undefined) {
      await selectDxcOption(
        strand.getByTestId("realm-encryption-profile-input"),
        opts.encryptionProfile,
      );
    }
    const policyNext = strand.getByTestId("new-realm-next-button").first();
    await expect(policyNext).toBeEnabled({ timeout: 30_000 });
    await policyNext.click();

    if (opts.seedMembers && opts.seedMembers.length > 0) {
      await strand
        .getByTestId("seed-members-input")
        .fill(opts.seedMembers.join("\n"));
    }
    const createButton = strand.getByTestId("create-realm-button");
    await expect(createButton).toBeEnabled({ timeout: 30_000 });
    await createButton.click();

    // S6 recovery soft-gate (key-management §7.11): creating an end-to-end
    // encrypted Realm with no recovery path configured prompts the user to set
    // up the Recovery Key first. Test accounts generally have no recovery
    // configured, so accept the personal_node override and re-create. The gate
    // never appears for unencrypted Realms or when recovery is configured.
    const recoveryGate = this.page
      .getByTestId("encrypted-realm-recovery-gate")
      .last();
    const gateAppeared = await recoveryGate
      .waitFor({ state: "visible", timeout: 2_000 })
      .then(() => true)
      .catch(() => false);
    if (gateAppeared) {
      await this.page
        .getByTestId("encrypted-realm-recovery-gate-override")
        .last()
        .click();
      await expect(recoveryGate).toBeHidden({ timeout: 10_000 });
      await expect(createButton).toBeEnabled({ timeout: 30_000 });
      await createButton.click();
    }

    await expect(strand).toContainText(/created ck:realm:/, {
      timeout: 30_000,
    });
    const text = await strand.innerText();
    const match = text.match(/created (ck:realm:[^\s]+)/);
    expect(match, `created realm id in: ${text}`).not.toBeNull();
    return match![1];
  }

  // Drive the Realm admin invite modal to invite `targetDid` into realmId.
  async inviteFromAdmin(realmId: string, targetDid: string): Promise<string> {
    await this.gotoRealmAdminSection(realmId, "members");
    const members = this.page.getByTestId("realm-members-panel");
    await expect(members).toBeVisible({ timeout: 120_000 });
    await members.getByTestId("open-invite-modal-button").click();
    const invite = this.page.getByTestId("invite-member-modal");
    await expect(invite).toBeVisible({ timeout: 30_000 });
    await invite
      .getByTestId("invite-target-input")
      .fill(buildInviteLocatorUrl(this.serverUrl, targetDid));
    await invite.getByTestId("send-invite-button").click();
    const status = members.getByTestId("realm-members-status");
    await expect(status).toContainText(
      new RegExp(`invited ${escapeRegex(targetDid)}`),
      { timeout: 30_000 },
    );
    return await status.innerText();
  }

  // Build the Authorization + DPoP headers for a direct (non-browser)
  // `/_cokret/self/*` call. Under the ②(A+②) model the credential is the
  // ck.session.grant and soland requires a per-request DPoP proof.
  private selfPathHeaders(method: string, url: string): Record<string, string> {
    const grant = this.session.grant;
    if (grant) {
      return selfPathGrantHeaders({
        deviceKey: dpopDeviceKeyFromSeedB64url(grant.dpopSeedB64url),
        grantJwt: grant.grantJwt,
        method,
        url,
      });
    }
    const credential = this.session.sessionCredential;
    if (!credential) {
      throw new Error(
        "selfPathHeaders: no grant material or credential captured on session",
      );
    }
    return { authorization: `Bearer ${credential}` };
  }

  // Accept a pending invite for this user. Yougen's realm-admin invite list
  // is session-local, so a fresh-context invitee can't see seed-member invites
  // via the UI. The old REST mutation endpoint was removed; acceptance now
  // strands through the canonical event path as an invite -> join member state.
  async acceptInvite(realmId: string) {
    const serverUrl = this.session.serverUrl;
    const list = new URL("/_cokret/self/authz/invites", serverUrl);
    list.searchParams.set("subject", this.user.did);
    list.searchParams.set("realm_id", realmId);
    const listUrl = list.toString();
    const listResp = await this.page.request.get(listUrl, {
      headers: this.selfPathHeaders("GET", listUrl),
    });
    if (!listResp.ok()) {
      throw new Error(
        `acceptInvite: list /authz/invites returned ${listResp.status()} for ${this.user.did}`,
      );
    }
    const body = objectRecord(await listResp.json()) ?? {};
    const invites = Array.isArray(body.invites)
      ? body.invites
          .map(objectRecord)
          .filter(
            (invite): invite is Record<string, unknown> => invite !== undefined,
          )
      : [];
    const invite = invites.find(
      (i) =>
        stringField(i, "realm_id") === realmId &&
        stringField(i, "invitee") === this.user.did,
    );
    if (!invite) {
      throw new Error(
        `acceptInvite: no pending invite for ${this.user.did} in realm ${realmId} ` +
          `(visible invites: ${JSON.stringify(invites)})`,
      );
    }
    const inviteId = stringField(invite, "id");
    if (!inviteId) {
      throw new Error(
        `acceptInvite: invite for ${this.user.did} in realm ${realmId} has no canonical id ` +
          `(invite: ${JSON.stringify(invite)})`,
      );
    }
    await this.acceptInviteById(realmId, inviteId);
  }

  async acceptInviteById(realmId: string, inviteId: string) {
    const serverUrl = this.session.serverUrl;
    const envelope = signedEventEnvelope({
      actorDid: this.user.did,
      realmId,
      kind: "ck.member.state",
      payload: {
        realm_id: realmId,
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

  // Accept a pending Realm invite through the visible yougen notification UI.
  async acceptInviteFromNotifications(realmId: string) {
    await this.gotoNotifications();
    const refresh = this.page.getByTestId("refresh-notifications");
    const inviteItem = this.page
      .getByTestId("notification-item")
      .filter({ has: this.page.locator(`[title="${realmId}"]`) })
      .filter({ hasText: /Realm invite|You were invited/i });

    await expect
      .poll(
        async () => {
          if (await refresh.isVisible().catch(() => false)) {
            await refresh.click();
          }
          return inviteItem.count();
        },
        { timeout: 45_000, intervals: [500, 1_000, 2_000, 5_000] },
      )
      .toBeGreaterThan(0);

    const accept = inviteItem.first().getByTestId("notification-action");
    await expect(accept).toBeVisible({ timeout: 30_000 });
    await accept.click();
    await expect(this.page.getByTestId("notifications-status")).toContainText(
      /Joined Realm/,
      { timeout: 45_000 },
    );
  }

  // Send a message into realmId's chat feed. Asserts chat-status persistence.
  async sendTimelineMessage(realmId: string, body: string) {
    if (!this.page.url().includes(`/chat/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
    }
    await this.page.getByTestId("chat-input").fill(body);
    await this.page.getByTestId("send-chat-button").click();
    await this.waitForTimelineEventSettled(body);
  }

  async sendTimelineMentionMessage(
    realmId: string,
    mentionDid: string,
    suffix: string,
  ): Promise<string> {
    if (!this.page.url().includes(`/chat/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
    }
    const input = this.page.getByTestId("chat-input");
    await input.fill("");
    await this.page.getByTestId("mention-trigger-button").click();
    const escapedDid = mentionDid.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    const suggestion = this.page.locator(
      `[data-testid="mention-suggestion"][data-mention-did="${escapedDid}"]`,
    );
    await expect(suggestion).toBeVisible({ timeout: 30_000 });
    await suggestion.click();
    const prefix = (await input.inputValue()).trimEnd();
    const body = `${prefix} ${suffix.trim()}`.trim();
    await input.fill(body);
    await this.page.getByTestId("send-chat-button").click();
    await this.waitForTimelineEventSettled(body);
    return body;
  }

  // Read visible timeline event texts as an array (deduped on `body`).
  async readTimelineTexts(realmId: string): Promise<string[]> {
    if (!this.page.url().includes(`/chat/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
    }
    const events = this.page.getByTestId("chat-message");
    const count = await events.count();
    const out: string[] = [];
    for (let i = 0; i < count; i += 1) {
      out.push((await events.nth(i).innerText()).trim());
    }
    return out;
  }

  timelineEvent(body: string): Locator {
    return this.page
      .getByTestId("chat-message")
      .filter({ hasText: body })
      .first();
  }

  async waitForTimelineEventSettled(body: string, timeout = 45_000) {
    const event = this.timelineEvent(body);
    await expect(event).toBeVisible({ timeout });
    await expect(event.getByTestId("message-send-status")).toHaveCount(0, {
      timeout,
    });
  }

  async clickTimelineReply(body: string) {
    await this.clickTimelineAction(body, "chat-reply-button");
  }

  async clickTimelineEdit(body: string) {
    await this.clickTimelineAction(body, "chat-edit-button");
  }

  private async clickTimelineAction(body: string, testId: string) {
    const event = this.timelineEvent(body);
    await expect(event).toBeVisible({ timeout: 30_000 });
    await event.hover();
    const action = event.getByTestId(testId);
    await expect(action).toBeVisible({ timeout: 30_000 });
    await action.click();
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
  const url = `${solandBaseUrl(opts.server)}/_cokret/gate/account/register`;
  const data = {
    principal_id: user.did,
    display_name: user.displayName,
    device_id: user.deviceId,
  };
  const backoffMs = [500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000];
  for (let attempt = 0; attempt < backoffMs.length; attempt += 1) {
    const response = await request.post(url, { data });
    if ([200, 409].includes(response.status())) {
      return;
    }
    const text = await response.text();
    if (response.status() !== 429 || attempt === backoffMs.length - 1) {
      throw new Error(
        `ensureRegistered: ${url} returned ${response.status()} for ${user.did}: ${text}`,
      );
    }
    await sleep(retryAfterMs(response, backoffMs[attempt]));
  }
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
  expect(body.session_credential).toBeTruthy();
  return body.session_credential;
}

export async function createDpopUserSession(
  request: APIRequestContext,
  prefix: string,
  opts: { server?: SolandKey; coauthBase?: string } = {},
): Promise<DpopUserSession | undefined> {
  const coauth = opts.coauthBase ?? coauthBaseUrl();
  if (!coauth) {
    return undefined;
  }
  const account = await registerCoauthPasswordAccount(request, coauth, {
    password: "1amTesting!",
  });
  return createDpopUserSessionForAccount(request, prefix, account, opts);
}

export async function createDpopUserSessionForAccount(
  request: APIRequestContext,
  prefix: string,
  account: CoauthPasswordAccount,
  opts: { server?: SolandKey; coauthBase?: string } = {},
): Promise<DpopUserSession | undefined> {
  const coauth = opts.coauthBase ?? coauthBaseUrl();
  if (!coauth) {
    return undefined;
  }
  const seed = uniqueUser(prefix);
  const deviceKey = generateDpopDeviceKey();
  const audience = solandServiceDid(opts.server);
  const loginUrl = `${coauth}/_coauth/gate/account/auth/login`;
  const login = await request.post(loginUrl, {
    headers: kickoffDpopHeaders({
      deviceKey,
      method: "POST",
      url: loginUrl,
    }),
    data: {
      handle: account.handle,
      password: account.password,
      audience,
      device_id: seed.deviceId,
    },
  });
  const raw = await login.text();
  let body: any = null;
  try {
    body = raw ? JSON.parse(raw) : {};
  } catch {
    body = null;
  }
  if (login.status() === 404) {
    return undefined;
  }
  if (!login.ok() || body?.status !== "success") {
    throw new Error(`coauth DPoP password login returned ${login.status()}: ${raw}`);
  }
  const grant = body?.session_grant;
  const principalDid = body?.viewer?.did;
  if (!principalDid || !grant?.grant_jwt || !grant?.id || !grant?.audience) {
    throw new Error(`coauth DPoP password login omitted principal grant: ${raw}`);
  }
  expect(grant.audience).toBe(audience);
  expect(Array.isArray(grant.scopes)).toBeTruthy();
  expect(grant.scopes).toContain(`urn:cokret:client:device:${seed.deviceId}`);
  const user = {
    ...seed,
    name: account.handle,
    did: principalDid,
    handle: `@${account.handle}`,
    displayName: account.displayName,
  };
  return {
    user,
    grantJwt: grant.grant_jwt,
    grantId: grant.id,
    grantAudience: grant.audience,
    dpopSeedB64url: dpopDeviceSeedB64url(deviceKey),
    deviceKey,
  };
}

export async function openDpopUserPage(
  browser: Browser,
  request: APIRequestContext,
  prefix: string,
  opts: {
    server?: SolandKey;
    coauthBase?: string;
    prepareMlsDevice?: boolean;
  } = {},
): Promise<DpopUserPageSession | undefined> {
  const session = await createDpopUserSession(request, prefix, opts);
  if (!session) {
    return undefined;
  }
  const page = await openUserPage(browser, session.user, {
    server: opts.server,
    grantJwt: session.grantJwt,
    dpopSeedB64url: session.dpopSeedB64url,
    grantId: session.grantId,
    grantAudience: session.grantAudience,
  });
  if (opts.prepareMlsDevice !== false) {
    await page.gotoHome();
    await page.completeRecoveryKeySetupIfPrompted();
    await page.acknowledgeRecommendedEncryptionPromptIfVisible();
  }
  return { user: session.user, session, page };
}

export function selfPathHeadersForDpopSession(
  session: DpopUserSession,
  method: string,
  url: string,
): Record<string, string> {
  return selfPathGrantHeaders({
    deviceKey: session.deviceKey,
    grantJwt: session.grantJwt,
    method,
    url,
  });
}

export async function openUser(
  browser: Browser,
  user: JointUser,
  opts: OpenUserOpts = {},
): Promise<UserSession> {
  const serverUrl = solandBaseUrl(opts.server);
  const sessionCredential = opts.sessionCredential ?? "";
  const diagnosticsDir = path.join(
    diagnosticsRoot(),
    sanitize(`${Date.now()}-${user.name}`),
  );
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
      window.localStorage.setItem(
        "yougen.config.v1",
        JSON.stringify(init.config),
      );
      // The harness injects sessions into localStorage; yougen's wasm build is
      // IndexedDB-only for session credentials/secrets by default (SubtleCrypto, non-
      // extractable). Opt into the localStorage compatibility tier so the
      // injected credential/seed are accepted (test-only; production leaves this
      // unset). See yougen secure_key_store WASM_ALLOW_LOCALSTORAGE_SECRETS_FLAG.
      window.localStorage.setItem(
        "yougen.security.allow_localstorage_secrets",
        "1",
      );
      // ②(A+②) real-grant injection: hand yougen's dev-only boot path the real
      // ck.session.grant + the DPoP device seed it is bound to, so the wasm
      // client rehydrates a genuine grant (coauth introspection passes, device
      // enrollment runs) instead of a soland-only dev-login credential. yougen reads
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
        session_credential: sessionCredential,
      },
      sessionInjection,
    },
  );
  // Hide dioxus-cli's dev-mode rebuild toast (`#__dx-toast`). When dx serve's
  // dev WS reconnects mid-test the overlay covers the page and blocks pointer
  // events, even though the app underneath is interactive. We never want to
  // observe it during e2e — kill it permanently via CSS injected on every
  // navigation.
  await context.addInitScript(
    (init) => {
      const inject = () => {
        if (!document.head) return;
        const id = "__cotest_hide_dx_toast";
        if (document.getElementById(id)) return;
        const style = document.createElement("style");
        style.id = id;
        style.textContent =
          "#__dx-toast,#__dx-toast-container{display:none!important;visibility:hidden!important;pointer-events:none!important}";
        if (init.hideDeviceAuthorizationPrompt) {
          style.textContent +=
            "\n[data-testid='device-authorization-modal'],[data-testid='device-authorization-reopen'],[class*='dx-dialog-backdrop']:has([data-testid='device-authorization-modal']){display:none!important;visibility:hidden!important;pointer-events:none!important}";
        }
        document.head.appendChild(style);
      };
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", inject);
      } else {
        inject();
      }
    },
    {
      hideDeviceAuthorizationPrompt: opts.keepDeviceAuthorizationModal !== true,
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
    keepDeviceAuthorizationModal: opts.keepDeviceAuthorizationModal === true,
    sessionCredential,
    grant,
  };
}

export async function openUserPage(
  browser: Browser,
  user: JointUser,
  opts: OpenUserOpts = {},
): Promise<JointUserPage> {
  const userPage = new JointUserPage(user, await openUser(browser, user, opts));
  if (!opts.keepDeviceAuthorizationModal) {
    await dismissDeviceAuthorizationPrompt(userPage.page);
  }
  return userPage;
}

export async function closeUser(session: UserSession) {
  fs.writeFileSync(
    path.join(session.diagnosticsDir, "console.jsonl"),
    session.consoleLines.join("\n"),
    "utf8",
  );
  fs.writeFileSync(
    path.join(session.diagnosticsDir, "network.jsonl"),
    session.networkLines.join("\n"),
    "utf8",
  );
  try {
    await session.context.close();
  } catch (error) {
    if (
      !(error instanceof Error) ||
      !/Target page, context or browser has been closed/.test(error.message)
    ) {
      throw error;
    }
  }
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

async function dismissDeviceAuthorizationPrompt(page: Page) {
  const dismiss = page.getByTestId("device-authorization-dismiss").last();
  if (await dismiss.isVisible({ timeout: 100 }).catch(() => false)) {
    await dismiss.click();
  }
}
