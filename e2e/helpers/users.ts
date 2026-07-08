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
  mintDpopBoundGrant,
  selfPathGrantHeaders,
  type DpopDeviceKey,
} from "./session-grant-dpop";
import { enrollOnboardedDeviceSigningKey } from "./device-holder-proof";

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
  /// Start with server-only config for tests that must exercise real login.
  /// This keeps diagnostics/page helpers but avoids seeding a fixture
  /// account/device into yougen.config.v1 before the product login flow runs.
  neutralLoginConfig?: boolean;
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
  completeRecoveryKeySetup?: boolean;
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

const MAX_SESSION_DIAGNOSTIC_LINES = 5000;
const MAX_SESSION_DIAGNOSTIC_LINE_CHARS = 4000;

function pushDiagnosticLine(lines: string[], line: string) {
  const value =
    line.length > MAX_SESSION_DIAGNOSTIC_LINE_CHARS
      ? `${line.slice(0, MAX_SESSION_DIAGNOSTIC_LINE_CHARS)}... [truncated]`
      : line;
  if (lines.length < MAX_SESSION_DIAGNOSTIC_LINES) {
    lines.push(value);
  } else if (lines.length === MAX_SESSION_DIAGNOSTIC_LINES) {
    lines.push(
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "diagnostic_truncated",
        retained_lines: MAX_SESSION_DIAGNOSTIC_LINES,
      }),
    );
  }
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
    await this.dismissCreateRealmBlockingPrompts({
      completeRecoveryKeySetup: true,
    });
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
    await this.dismissPassiveBlockingPrompts();
    await expect(this.page.getByTestId("message-list")).toBeVisible({
      timeout: 30_000,
    });
  }

  private async dismissDeviceAuthorizationPrompt() {
    if (!this.session.keepDeviceAuthorizationModal) {
      await dismissDeviceAuthorizationPrompt(this.page);
    }
  }

  private async dismissCreateRealmBlockingPrompts(opts: {
    completeRecoveryKeySetup: boolean;
  }): Promise<boolean> {
    let handled = false;
    if (opts.completeRecoveryKeySetup) {
      const openRecoverySetup = this.page
        .getByTestId("recovery-setup-open-recovery")
        .last();
      if (await openRecoverySetup.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await openRecoverySetup.click();
        handled = true;
      }
      const recoveryKey = await this.completeRecoveryKeySetupIfPrompted(2_000);
      handled ||= recoveryKey !== undefined;
    }
    for (const [testId, modalTestId] of [
      ["mls-backup-dismiss", "mls-backup-modal"],
      ["mls-recovery-missing-dismiss", "mls-recovery-missing-modal"],
      ["mls-unlock-dismiss", "mls-unlock-modal"],
    ] as const) {
      const button = this.page.getByTestId(testId).last();
      if (await button.isVisible({ timeout: 250 }).catch(() => false)) {
        await button.click();
        await expect(this.page.getByTestId(modalTestId).last()).toBeHidden({
          timeout: 10_000,
        });
        handled = true;
      }
    }
    return handled;
  }

  private async clickCreateRealmControl(
    locator: Locator,
    promptHandling: { completeRecoveryKeySetup: boolean },
  ) {
    let lastError: unknown;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await this.dismissCreateRealmBlockingPrompts(promptHandling);
      try {
        await locator.click({ timeout: 5_000 });
        return;
      } catch (error) {
        lastError = error;
        const handled =
          await this.dismissCreateRealmBlockingPrompts(promptHandling);
        if (!handled) {
          await this.page.waitForTimeout(250);
        }
      }
    }
    throw lastError;
  }

  private async selectCreateRealmOption(
    locator: Locator,
    value: string,
    promptHandling: { completeRecoveryKeySetup: boolean },
  ) {
    let lastError: unknown;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await this.dismissCreateRealmBlockingPrompts(promptHandling);
      try {
        await selectDxcOption(locator, value);
        return;
      } catch (error) {
        lastError = error;
        const handled =
          await this.dismissCreateRealmBlockingPrompts(promptHandling);
        if (!handled) {
          await this.page.waitForTimeout(250);
        }
      }
    }
    throw lastError;
  }

  private async withPassivePromptRetry(operation: () => Promise<void>) {
    let lastError: unknown;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await this.dismissPassiveBlockingPrompts();
      try {
        await operation();
        return;
      } catch (error) {
        lastError = error;
        const handled = await this.dismissPassiveBlockingPrompts();
        if (!handled) {
          await this.page.waitForTimeout(250);
        }
      }
    }
    throw lastError;
  }

  async clickWithPassivePromptRetry(locator: Locator) {
    await this.withPassivePromptRetry(() => locator.click({ timeout: 5_000 }));
  }

  async fillWithPassivePromptRetry(locator: Locator, value: string) {
    await this.withPassivePromptRetry(() =>
      locator.fill(value, { timeout: 5_000 }),
    );
  }

  async checkWithPassivePromptRetry(locator: Locator) {
    await this.withPassivePromptRetry(() => locator.check({ timeout: 5_000 }));
  }

  async uncheckWithPassivePromptRetry(locator: Locator) {
    await this.withPassivePromptRetry(() =>
      locator.uncheck({ timeout: 5_000 }),
    );
  }

  async completeRecoveryKeySetupIfPrompted(
    timeoutMs = 5_000,
  ): Promise<string | undefined> {
    const modal = this.page
      .locator(
        [
          '[data-testid="recovery-key-setup-modal"]',
          '[data-testid="recovery-key-setup-banner"]',
        ].join(","),
      )
      .last();
    const visible = await modal
      .waitFor({ state: "visible", timeout: timeoutMs })
      .then(() => true)
      .catch(() => false);
    if (!visible) {
      return undefined;
    }

    const unauthorized = this.page
      .getByTestId("recovery-key-setup-device-unauthorized")
      .last();
    const restore = this.page.getByTestId("recovery-key-setup-restore").last();
    const status = this.page.getByTestId("recovery-key-setup-status").last();
    const closeRecoveryPrompt = async () => {
      const close = this.page.getByTestId("recovery-key-setup-dismiss").last();
      if (await close.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await close.click();
        await expect(modal).toBeHidden({ timeout: 10_000 });
      }
    };
    const hasRecoverableGenerationError = async () => {
      const text = ((await status.textContent({ timeout: 100 }).catch(() => "")) ?? "")
        .trim()
        .toLowerCase();
      return (
        text.includes("couldn't reach") ||
        text.includes("returned 409") ||
        text.includes("failed") ||
        text.includes("already exists") ||
        text.includes("version_not_monotonic") ||
        text.includes("try again")
      );
    };
    if (
      (await unauthorized.isVisible({ timeout: 250 }).catch(() => false)) ||
      (await restore.isVisible({ timeout: 250 }).catch(() => false))
    ) {
      await closeRecoveryPrompt();
      return undefined;
    }

    const generatedKeyField = this.page
      .getByTestId("recovery-key-setup-generated-key")
      .last();
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      if (await modal.isHidden({ timeout: 100 }).catch(() => false)) {
        return undefined;
      }
      if (
        (await unauthorized.isVisible({ timeout: 100 }).catch(() => false)) ||
        (await restore.isVisible({ timeout: 100 }).catch(() => false))
      ) {
        await closeRecoveryPrompt();
        return undefined;
      }
      if (
        await generatedKeyField
          .isVisible({ timeout: 100 })
          .catch(() => false)
      ) {
        break;
      }
      if (await hasRecoverableGenerationError()) {
        await closeRecoveryPrompt();
        return undefined;
      }
      await this.page.waitForTimeout(250);
    }
    if (await modal.isHidden({ timeout: 100 }).catch(() => false)) {
      return undefined;
    }
    if (!(await generatedKeyField.isVisible({ timeout: 100 }).catch(() => false))) {
      if (await hasRecoverableGenerationError()) {
        await closeRecoveryPrompt();
        return undefined;
      }
    }
    await expect(generatedKeyField).toBeVisible({ timeout: 0 });
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
    // The recommended encryption floor is auto-acknowledged by the client.
    // Keep this helper as a compatibility hook for tests that previously
    // clicked the old modal: the only visible follow-up can be Recovery Key
    // setup when the account has no configured recovery material.
    const recoveryKey = await this.completeRecoveryKeySetupIfPrompted(
      Math.min(timeoutMs, 1_000),
    );
    return recoveryKey !== undefined;
  }

  async createRealm(opts: CreateRealmOpts): Promise<string> {
    await this.gotoSetup();
    // Always complete the 24-word recovery-key setup modal when it appears — for
    // BOTH plaintext and encrypted realms. Historically this was suppressed for
    // `mls_rfc9420` (the encrypted path was assumed to use the post-create
    // `encrypted-realm-recovery-gate-override` instead), but once a device
    // genuinely participates in MLS (real authorized device, model-B principal
    // DID) the encrypted-realm wizard pops the recovery-key setup modal DURING the
    // basics/policy steps, whose dialog backdrop blocks every subsequent click. It
    // never surfaced before because MLS never actually worked in the harness
    // (silently-skipped/false-green). Completing recovery configures the account,
    // so the post-create gate simply no-ops.
    const promptHandling = {
      completeRecoveryKeySetup: opts.completeRecoveryKeySetup ?? true,
    };
    await this.dismissCreateRealmBlockingPrompts(promptHandling);
    const strand = this.page.getByTestId("realm-lifecycle-strand").last();

    await this.fillWithPassivePromptRetry(
      strand.getByTestId("realm-title-input"),
      opts.title,
    );
    if (opts.summary !== undefined) {
      await this.fillWithPassivePromptRetry(
        strand.getByTestId("realm-summary-input"),
        opts.summary,
      );
    }
    const basicsNext = strand.getByTestId("new-realm-next-button").first();
    await expect(basicsNext).toBeEnabled({ timeout: 30_000 });
    await this.clickCreateRealmControl(basicsNext, promptHandling);

    if (opts.discoverability !== undefined) {
      await this.selectCreateRealmOption(
        strand.getByTestId("realm-discoverability-input"),
        opts.discoverability,
        promptHandling,
      );
    }
    if (opts.joinRule !== undefined) {
      await this.selectCreateRealmOption(
        strand.getByTestId("realm-policy-join-rule-input"),
        opts.joinRule,
        promptHandling,
      );
    }
    if (opts.historyVisibility !== undefined) {
      await this.selectCreateRealmOption(
        strand.getByTestId("realm-policy-history-visibility-input"),
        opts.historyVisibility,
        promptHandling,
      );
    }
    if (opts.encryptionProfile !== undefined) {
      await this.selectCreateRealmOption(
        strand.getByTestId("realm-encryption-profile-input"),
        opts.encryptionProfile,
        promptHandling,
      );
    }
    const policyNext = strand.getByTestId("new-realm-next-button").first();
    await expect(policyNext).toBeEnabled({ timeout: 30_000 });
    await this.clickCreateRealmControl(policyNext, promptHandling);

    if (opts.seedMembers && opts.seedMembers.length > 0) {
      await this.fillWithPassivePromptRetry(
        strand.getByTestId("seed-members-input"),
        opts.seedMembers.join("\n"),
      );
    }
    const createButton = strand.getByTestId("create-realm-button");
    await expect(createButton).toBeEnabled({ timeout: 30_000 });
    await this.clickCreateRealmControl(createButton, promptHandling);

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
  async inviteFromAdmin(
    realmId: string,
    targetDid: string,
    expectedDisplayLabel?: string,
  ): Promise<string> {
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
    const displayLabel = expectedDisplayLabel ?? displayLabelForDid(targetDid);
    await expect(status).toContainText(
      new RegExp(`invited (${escapeRegex(displayLabel)}|${escapeRegex(targetDid)})`),
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

  // Accept a pending invite for this user. The standard v1 invite lifecycle is
  // `ck.invite.create` followed by invitee-authored `ck.invite.accept`; soland
  // then cascades the accepted invite into Realm membership.
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
      kind: "ck.invite.accept",
      payload: {
        invite_id: inviteId,
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
        `acceptInviteById: ck.invite.accept returned ${acceptResp.status()} for invite ${inviteId}: ${text}`,
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
    await this.dismissPassiveBlockingPrompts();
    await this.page.getByTestId("chat-input").fill(body);
    await this.clickWithPassivePromptRetry(
      this.page.getByTestId("send-chat-button"),
    );
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
    await this.clickWithPassivePromptRetry(
      this.page.getByTestId("send-chat-button"),
    );
    await this.waitForTimelineEventSettled(body);
    return body;
  }

  // Read visible timeline event texts as an array (deduped on `body`).
  async readTimelineTexts(realmId: string): Promise<string[]> {
    if (!this.page.url().includes(`/chat/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
    }
    await this.dismissPassiveBlockingPrompts();
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

  async expectTimelineEventVisible(body: string, timeout = 45_000) {
    await expect
      .poll(
        async () => {
          await this.dismissPassiveBlockingPrompts();
          return await this.timelineEvent(body).count();
        },
        { timeout, intervals: [250, 500, 1_000, 2_000] },
      )
      .toBeGreaterThan(0);
    await this.dismissPassiveBlockingPrompts();
    await expect(this.timelineEvent(body)).toBeVisible({ timeout: 5_000 });
  }

  async clickTimelineReply(body: string) {
    await this.clickTimelineAction(body, "chat-reply-button");
  }

  async clickTimelineEdit(body: string) {
    await this.clickTimelineAction(body, "chat-edit-button");
  }

  async clickTimelineRedact(body: string) {
    await this.clickTimelineAction(body, "chat-redact-button");
  }

  private async clickTimelineAction(body: string, testId: string) {
    const event = this.timelineEvent(body);
    await this.dismissPassiveBlockingPrompts();
    await expect(event).toBeVisible({ timeout: 30_000 });
    const action = event.getByTestId(testId);
    await this.withPassivePromptRetry(async () => {
      await event.scrollIntoViewIfNeeded({ timeout: 5_000 });
      await event.hover({ timeout: 5_000 });
      await expect(action).toBeVisible({ timeout: 5_000 });
      await action.click({ timeout: 5_000 });
    });
  }

  async close() {
    await closeUser(this.session);
  }

  private async dismissPassiveBlockingPrompts(): Promise<boolean> {
    return await this.dismissCreateRealmBlockingPrompts({
      completeRecoveryKeySetup: true,
    });
  }
}

// Anti-false-green guard for the crown-jewel cross-member paths.
//
// The heavy two-browser flows (MLS decrypt, cross-member kanban, multi-profile)
// need a live coauth to mint device-authorized DPoP session grants. Historically
// they self-disabled with `test.skip(!aliceSession || !bobSession, ...)` — so a
// run without coauth reported GREEN while never exercising the code that most
// often breaks in real usage. That is the exact "tests are green but manual
// testing finds everything" failure mode.
//
// This guard makes the skip OPT-IN to fail-loud: when the joint harness declares
// the stack present (COTEST_REQUIRE_JOINT_STACK=1, set by run-joint-e2e.ps1
// whenever it starts coauth), a missing session becomes a hard error instead of a
// silent skip. Ad-hoc local runs without the flag keep the old skip behavior, so
// this does not break anyone's existing CI — it only closes the false-green hole
// on the harness that is supposed to have the full stack up.
export function assertJointStackNotRequired(context: string): void {
  if (process.env.COTEST_REQUIRE_JOINT_STACK === "1") {
    throw new Error(
      `${context}: COTEST_REQUIRE_JOINT_STACK=1 (joint stack declared present) but the ` +
        `coauth DPoP session-grant login is unavailable — refusing to silently skip a ` +
        `critical cross-member path and report a false green. Start coauth ` +
        `(run-joint-e2e.ps1 -StartCoauth) or unset COTEST_REQUIRE_JOINT_STACK.`,
    );
  }
}

export function uniqueUser(prefix: string): JointUser {
  const stamp = randomUUID();
  const slug = `${prefix}-${stamp}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const deviceSuffix = stamp.replace(/-/g, "").slice(0, 12);
  return {
    name: slug,
    // did:webvh is the v1 core default principal method (identity-did.md).
    // Dev-login principals use the fixture SCID form from the spec
    // conformance vectors (`did:webvh:z6mkfixture:<host>`); did:web is
    // reserved for explicit no-history / negative fixtures only.
    did: `did:webvh:z6mkfixture:${slug}.example`,
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
  opts: { server?: SolandKey; deviceId?: string } = {},
): Promise<string> {
  const url = `${solandBaseUrl(opts.server)}/_soland/gate/auth/dev-login`;
  const data = {
    actor: user.did,
    // Same actor (DID) can hold multiple device sessions: pass `deviceId` to
    // override the default per-user device. soland's dev-login registers each
    // distinct device_id in the device inventory, which is what drives the
    // actor-private read-cursor to-device fan-out across devices.
    device_id: opts.deviceId ?? user.deviceId,
    display_name: user.displayName,
  };
  const backoffMs = [500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000];
  for (let attempt = 0; attempt < backoffMs.length; attempt += 1) {
    const response = await request.post(url, { data });
    if (response.status() === 200) {
      const body = await response.json();
      expect(body.session_credential).toBeTruthy();
      return body.session_credential;
    }
    const text = await response.text();
    if (response.status() !== 429 || attempt === backoffMs.length - 1) {
      throw new Error(
        `issueDevSession: ${url} returned ${response.status()} for ${user.did}: ${text}`,
      );
    }
    await sleep(retryAfterMs(response, backoffMs[attempt]));
  }
  throw new Error(`issueDevSession: exhausted retry loop for ${user.did}`);
}

export async function createDpopUserSession(
  request: APIRequestContext,
  prefix: string,
  opts: { server?: SolandKey; coauthBase?: string; skipDeviceEnrollment?: boolean } = {},
): Promise<DpopUserSession | undefined> {
  const coauth = opts.coauthBase ?? coauthBaseUrl();
  if (!coauth) {
    return undefined;
  }
  const account = await registerCoauthPasswordAccount(request, coauth, {
    password: "1amTester!",
  });
  return createDpopUserSessionForAccount(request, prefix, account, opts);
}

export async function createDpopUserSessionForAccount(
  request: APIRequestContext,
  prefix: string,
  account: CoauthPasswordAccount,
  opts: {
    server?: SolandKey;
    coauthBase?: string;
    // Skip the harness-side `ck.device.authorize`. Set this for browser MLS
    // sessions so yougen's own on-connect self-enrollment
    // (app/connect.rs enroll_current_session_device) becomes the sole device
    // authority — it enrolls the browser's REAL event-signer key, which is what
    // signs message proofs, so a receiver's chat proof gate resolves a matching
    // key. Leaving the harness enroll on would pre-authorize the device with the
    // DPoP *session* key and suppress self-enrollment (only unauthorized devices
    // self-enroll), stranding cross-member chat proofs.
    skipDeviceEnrollment?: boolean;
  } = {},
): Promise<DpopUserSession | undefined> {
  const coauth = opts.coauthBase ?? coauthBaseUrl();
  if (!coauth) {
    return undefined;
  }
  const seed = uniqueUser(prefix);
  const deviceKey = generateDpopDeviceKey();
  const audience = solandServiceDid(opts.server);
  const grant = await mintDpopBoundGrant(
    request,
    coauth,
    account.did,
    seed.deviceId,
    deviceKey,
    { audience },
  );
  if (!grant) {
    return undefined;
  }
  expect(grant.audience).toBe(audience);
  expect(grant.dpopJkt).toBe(deviceKey.thumbprint);
  expect(Array.isArray(grant.scopes)).toBeTruthy();
  expect(grant.scopes).toContain(`urn:cokret:client:device:${seed.deviceId}`);
  // Model-B identity: adopt the minted `did:webvh:…:webvh:<ulid>` principal DID
  // the grant subject is bound to (coauth debug seam), NOT the coauth-local
  // `user_did_for` fallback (`…:users:<ulid>`) that account.did carries. Only the
  // minted DID's document designates coauth's CokretDeviceEnrollmentAuthority, so
  // device enrollment + MLS KeyPackage publish resolve the right document.
  expect(grant.principalDid, "debug seam must return the minted principal DID").toBeTruthy();
  const user = {
    ...seed,
    name: account.handle,
    did: grant.principalDid,
    handle: `@${account.handle}`,
    displayName: account.displayName,
  };
  await ensureRegistered(request, user, { server: opts.server });
  // Device authorization up front, for API-only sessions that never open a
  // browser (no in-browser self-enrollment runs, so authorize here to make the
  // KeyPackage upload / MLS flows accepted).
  //
  // For BROWSER MLS sessions, pass `skipDeviceEnrollment: true`: this harness
  // enroll authorizes the DPoP *session* key, but the browser's real event-signer
  // key (what signs message proofs) is different — so a receiver's chat proof gate
  // (verify_chat_envelope_proof) would resolve a non-matching key and drop
  // cross-member chat messages. yougen's on-connect self-enrollment now works
  // under the injected-grant seam (connect.rs falls back to the connect-held
  // bearer when local_state has no reconstructed grant), so skipping this lets
  // self-enrollment authorize the correct event-signer key. Because a pre-existing
  // authorization suppresses self-enrollment (only unauthorized devices
  // self-enroll), the harness enroll MUST be skipped, not merely overwritten.
  if (!opts.skipDeviceEnrollment) {
    await enrollOnboardedDeviceSigningKey(
      request,
      coauth,
      {
        account,
        principalDid: user.did,
        deviceId: seed.deviceId,
        deviceKey,
        grantJwt: grant.grantJwt,
        grantId: grant.grantId,
        grantAudience: grant.audience,
        scopes: grant.scopes,
      },
      { server: opts.server },
    );
  }
  return {
    user,
    grantJwt: grant.grantJwt,
    grantId: grant.grantId,
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
    skipDeviceEnrollment?: boolean;
  } = {},
): Promise<DpopUserPageSession | undefined> {
  const session = await createDpopUserSession(request, prefix, {
    ...opts,
    skipDeviceEnrollment: opts.skipDeviceEnrollment ?? true,
  });
  return openDpopUserPageFromSession(browser, session, opts);
}

export async function openDpopUserPageForAccount(
  browser: Browser,
  request: APIRequestContext,
  prefix: string,
  account: CoauthPasswordAccount,
  opts: {
    server?: SolandKey;
    coauthBase?: string;
    prepareMlsDevice?: boolean;
    skipDeviceEnrollment?: boolean;
  } = {},
): Promise<DpopUserPageSession | undefined> {
  const session = await createDpopUserSessionForAccount(
    request,
    prefix,
    account,
    {
      ...opts,
      skipDeviceEnrollment: opts.skipDeviceEnrollment ?? true,
    },
  );
  return openDpopUserPageFromSession(browser, session, opts);
}

async function openDpopUserPageFromSession(
  browser: Browser,
  session: DpopUserSession | undefined,
  opts: {
    server?: SolandKey;
    prepareMlsDevice?: boolean;
  },
): Promise<DpopUserPageSession | undefined> {
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
    // Opt-in for running against a live Caddy stack whose TLS is `tls internal`
    // (self-signed). Default off so CI/headless harness runs are unaffected.
    ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
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
      if (init.neutralLoginConfig) {
        if (!window.localStorage.getItem("yougen.config.v1")) {
          window.localStorage.setItem(
            "yougen.config.v1",
            JSON.stringify(init.config),
          );
        }
      } else {
        window.localStorage.setItem(
          "yougen.config.v1",
          JSON.stringify(init.config),
        );
      }
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
        account_did: opts.neutralLoginConfig ? "" : user.did,
        device_id: opts.neutralLoginConfig ? "" : user.deviceId,
        session_credential: opts.neutralLoginConfig ? "" : sessionCredential,
      },
      neutralLoginConfig: opts.neutralLoginConfig === true,
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
          // The device-authorization MODAL and the in-shell BANNER both overlay
          // the app and intercept pointer events even when the app underneath is
          // interactive. Tests that navigate with raw page.goto (bypassing the
          // JointUserPage.goto* helpers that click device-authorization-dismiss)
          // otherwise get their clicks swallowed by the banner. No test asserts
          // this prompt is visible, so kill both permanently on every navigation.
          style.textContent +=
            "\n[data-testid='device-authorization-modal'],[data-testid='device-authorization-banner'],[data-testid='device-authorization-reopen'],[class*='dx-dialog-backdrop']:has([data-testid='device-authorization-modal']){display:none!important;visibility:hidden!important;pointer-events:none!important}";
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
    pushDiagnosticLine(
      consoleLines,
      JSON.stringify({
        ts: new Date().toISOString(),
        type: message.type(),
        text: message.text(),
        location: message.location(),
      }),
    );
  });
  page.on("pageerror", (error) => {
    pushDiagnosticLine(
      consoleLines,
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "pageerror",
        text: error.message,
        stack: error.stack,
      }),
    );
  });
  page.on("requestfailed", (request) => {
    pushDiagnosticLine(
      networkLines,
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
          pushDiagnosticLine(
            networkLines,
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
          pushDiagnosticLine(
            networkLines,
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

function displayLabelForDid(did: string): string {
  const materialized = did.match(/^did:web:([^:]+):users:([^:]+)$/);
  if (materialized) {
    return `${materialized[2]}:${materialized[1]}`;
  }
  const simpleExample = did.match(/^did:web:([a-z0-9._-]+)\.example$/i);
  if (simpleExample) {
    return `${simpleExample[1].toLowerCase()}:example.com`;
  }
  // did:webvh fixture principals minted by uniqueUser():
  // `did:webvh:<scid>:<slug>.example` — same label derivation as the
  // did:web simple-example form above.
  const webvhExample = did.match(/^did:webvh:[a-z0-9]+:([a-z0-9._-]+)\.example$/i);
  if (webvhExample) {
    return `${webvhExample[1].toLowerCase()}:example.com`;
  }
  return did;
}

async function dismissDeviceAuthorizationPrompt(page: Page) {
  const dismiss = page.getByTestId("device-authorization-dismiss").last();
  if (await dismiss.isVisible({ timeout: 100 }).catch(() => false)) {
    await dismiss.click();
  }
}
