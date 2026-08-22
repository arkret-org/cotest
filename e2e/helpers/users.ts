import fs from "node:fs";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import {
  expect,
  request as playwrightRequest,
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
  embeddedWebvhRegistrationBearer,
  inksonBaseUrl,
  type SolandKey,
  solandBaseUrl,
  solandServiceFullId,
  solandServiceId,
} from "./env";
import { selectDxcOption } from "./dxc-select";
import type { RealmObject } from "./generated/spec-wire-objects";
import {
  registerCoauthPasswordAccount,
  type CoauthPasswordAccount,
} from "./coauth-register";
import {
  dpopDeviceKeyFromSeedB64url,
  dpopDeviceSeedB64url,
  selfPathGrantHeaders,
  type DpopDeviceKey,
} from "./session-grant-dpop";
import {
  authHeaders,
  canonicalJson,
  cotestWire,
  projectFullDidToCoreId,
  registerEventSigner,
  registerPrincipalControlRealm,
  registerPrincipalControlEvents,
  registerRequestAuth,
  typedId,
} from "./soland-api";
import { base58btcEncode } from "./encoding";

export type JointUser = {
  name: string;
  /// Stable business identity projected through the active DID method adapter.
  did: string;
  /// Resolvable DID retained only for registration and proof-method boundaries.
  fullDid: string;
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
  /// The credential presented on `/_arkret/self/*`. Under the ②(A+②) model this
  /// is the `ak.session.grant` JWT; a request to a self-path also requires the
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
  /// Disable the recovery-key modal auto-completer for tests that inspect or
  /// drive that setup flow themselves.
  autoCompleteRecoveryKeySetup?: boolean;
  /// Start with server-only config for tests that must exercise real login.
  /// This keeps diagnostics/page helpers but avoids seeding a fixture
  /// account/device into inkson.config.v1 before the product login flow runs.
  neutralLoginConfig?: boolean;
  /// Real `ak.session.grant` JWT to inject as inkson's session credential.
  /// When set together with `dpopSeedB64url`, inkson's dev-only boot injection
  /// rehydrates the grant + DPoP device key instead of relying on dev-login.
  grantJwt?: string;
  /// base64url-no-pad 32-byte Ed25519 seed of the DPoP device key the grant is
  /// bound to (its thumbprint == the grant's `cnf.jkt`).
  dpopSeedB64url?: string;
  /// Test-only event-signing seed. This is deliberately distinct from the DPoP
  /// seed and lets browser and direct API submissions share one device identity.
  eventSigningSeedB64url?: string;
  /// coauth-assigned grant id (DB row id), persisted by inkson with the grant
  /// so refresh/logout paths can identify the current grant chain.
  grantId?: string;
  /// Audience the grant is bound to (the soland service DID).
  grantAudience?: string;
  recoveryKey?: string;
  recoveryMaterialEvidence?: Record<string, unknown>;
};

export type DpopUserSession = {
  user: JointUser;
  /// Test-harness account handle retained so a scenario can open and pair a
  /// genuinely distinct second device for the same principal.
  account: CoauthPasswordAccount;
  grantJwt: string;
  grantId: string;
  grantAudience: string;
  dpopSeedB64url: string;
  eventSigningSeedB64url: string;
  deviceKey: DpopDeviceKey;
  recoveryKey?: string;
  principalControlRealmId: string;
  principalControlEvents: Array<Record<string, unknown>>;
  recoveryMaterialEvidence?: Record<string, unknown>;
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
  historyAccess?: RealmObject["history_access"];
  encryptionProfile?: string;
  seedMembers?: string[];
  completeRecoveryKeySetup?: boolean;
};

function buildInviteLocatorUrl(
  serverUrl: string,
  locatorToken: string,
): string {
  const base = serverUrl.replace(/\/$/, "");
  return `${base}/_arkret/open/invite-locators/resolve#token=${locatorToken}`;
}

export async function issueInviteLocatorToken(
  request: APIRequestContext,
  sessionToken: string,
  server: SolandKey = "alpha",
): Promise<string> {
  const response = await request.post(
    `${solandBaseUrl(server)}/_arkret/self/invite-locators`,
    {
      headers: authHeaders(sessionToken),
      data: { ttl_seconds: 900 },
    },
  );
  expect(response.status(), await response.text()).toBe(200);
  expect(response.headers()["cache-control"]).toBe("private, no-store");
  const body = (await response.json()) as { locator_token: string };
  return body.locator_token;
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
    const shell = this.page.getByTestId("client-shell");
    for (let attempt = 0; attempt < 3; attempt += 1) {
      if (attempt === 0) {
        await this.page.goto("/", { waitUntil: "domcontentloaded" });
      } else {
        await this.page.reload({ waitUntil: "domcontentloaded" });
      }
      if (
        await shell
          .waitFor({ state: "visible", timeout: 40_000 })
          .then(() => true)
          .catch(() => false)
      ) {
        await this.dismissDeviceAuthorizationPrompt();
        return;
      }
    }
    await expect(shell).toBeVisible({ timeout: 1_000 });
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
    // inkson's /setup is the Overview; the Realm wizard lives at the
    // /setup/realms section. inkson/src/routes.rs §SetupSection.
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

  // Membership is not an authorization source (capabilities.md §3.2).
  // Drive Inkson's canonical grant UI, then wait for the accepted Control Move
  // to become visible in the authoritative grant projection before a workflow
  // relies on the delegated action.
  async grantRealmCapability(
    realmId: string,
    subjectDid: string,
    action: string,
  ): Promise<string> {
    const grantId = typedId("grant");
    await this.gotoRealmAdminSection(realmId, "security");
    await this.page.getByTestId("cap-grant-id-input").fill(grantId);
    await this.page.getByTestId("cap-grant-tag-input").fill(action);
    await this.page.getByTestId("cap-grant-subject-input").fill(subjectDid);
    await this.page.getByTestId("cap-grant-submit-button").click();
    const status = this.page.getByTestId("realm-admin-status");
    await expect(status).toContainText("ak.capability.grant event", {
      timeout: 60_000,
    });
    expect(await status.innerText()).not.toContain("failed");

    const grantsUrl = new URL(
      `${this.serverUrl}/_arkret/self/authz/effective-grants`,
    );
    grantsUrl.searchParams.set("subject", subjectDid);
    grantsUrl.searchParams.set("realm_id", realmId);
    await expect
      .poll(
        async () => {
          const response = await this.page.request.get(grantsUrl.toString(), {
            headers: this.selfPathHeaders("GET", grantsUrl.toString()),
          });
          if (response.status() !== 200) return false;
          const body = (await response.json()) as {
            grants?: Array<{ id?: string }>;
          };
          return body.grants?.some((grant) => grant.id === grantId) ?? false;
        },
        { timeout: 60_000, intervals: [250, 500, 1_000, 2_000] },
      )
      .toBe(true);
    return grantId;
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
      if (
        await openRecoverySetup.isVisible({ timeout: 1_000 }).catch(() => false)
      ) {
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
    const prompt = this.page
      .locator(
        [
          '[data-testid="recovery-key-setup-modal"]',
          '[data-testid="recovery-key-setup-banner"]',
        ].join(","),
      )
      .first();
    const dialog = this.page.getByTestId("recovery-key-setup-banner").last();
    const visible = await prompt
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
      if (await close.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await close.click({ timeout: 5_000 });
      } else {
        await this.page
          .getByRole("button", { name: /^(Close|Not now)$/ })
          .last()
          .click({ timeout: 2_000 })
          .catch(() => undefined);
      }
      await expect(dialog).toBeHidden({ timeout: 10_000 });
    };
    const hasRecoverableGenerationError = async () => {
      const text = (
        (await status.textContent({ timeout: 100 }).catch(() => "")) ?? ""
      )
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
      (await unauthorized.isVisible({ timeout: 1_000 }).catch(() => false)) ||
      (await restore.isVisible({ timeout: 1_000 }).catch(() => false))
    ) {
      await closeRecoveryPrompt();
      return undefined;
    }

    const generatedKeyField = this.page
      .getByTestId("recovery-key-setup-generated-key")
      .last();
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      if (await dialog.isHidden({ timeout: 100 }).catch(() => false)) {
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
        await generatedKeyField.isVisible({ timeout: 100 }).catch(() => false)
      ) {
        break;
      }
      if (await hasRecoverableGenerationError()) {
        await closeRecoveryPrompt();
        return undefined;
      }
      await this.page.waitForTimeout(250);
    }
    if (await dialog.isHidden({ timeout: 100 }).catch(() => false)) {
      return undefined;
    }
    if (
      !(await generatedKeyField.isVisible({ timeout: 100 }).catch(() => false))
    ) {
      if (await hasRecoverableGenerationError()) {
        await closeRecoveryPrompt();
        return undefined;
      }
    }
    // Pages opened via openUserPage register an addLocatorHandler on
    // recovery-key-setup-generated-key that auto-completes this modal
    // (fill confirm + save) the moment any auto-waiting call runs while
    // the generated key is visible. Every auto-waiting step below can
    // therefore trigger that handler and find the dialog already closed
    // underneath it. Treat "dialog gone" as handled at each step — the
    // dialog closing is the real success invariant either way.
    const recoveryKey = (
      await generatedKeyField.inputValue({ timeout: 10_000 }).catch(() => "")
    ).trim();
    const keyReadable = recoveryKey.split(/\s+/).filter(Boolean).length === 24;
    if (
      !keyReadable &&
      !(await dialog.isHidden({ timeout: 100 }).catch(() => false))
    ) {
      expect(
        recoveryKey.split(/\s+/).filter(Boolean),
        "recovery-key setup prompt must expose a 24-word key",
      ).toHaveLength(24);
    }
    if (keyReadable) {
      await this.page
        .getByTestId("recovery-key-setup-confirm-key")
        .last()
        .fill(recoveryKey, { timeout: 10_000 })
        .catch(() => undefined);
      await this.page
        .getByTestId("recovery-key-setup-saved")
        .last()
        .click({ timeout: 10_000 })
        .catch(() => undefined);
    }
    await expect(dialog).toBeHidden({ timeout: 30_000 });
    return keyReadable ? recoveryKey : undefined;
  }

  async unlockMlsAccountSecret(recoveryKey: string): Promise<void> {
    const unlockPrompt = this.page
      .locator(
        '[data-testid="mls-unlock-modal"], [data-testid="mls-unlock-banner"]',
      )
      .last();
    await expect(unlockPrompt).toBeVisible({ timeout: 90_000 });

    const showRecoveryKey = this.page.getByTestId(
      "mls-unlock-show-recovery-key",
    );
    if (await showRecoveryKey.isVisible().catch(() => false)) {
      await showRecoveryKey.click();
    }
    await this.page.getByTestId("mls-unlock-passphrase").fill(recoveryKey);
    await this.page.getByTestId("mls-unlock-submit").click();
    await expect(unlockPrompt).not.toBeVisible({ timeout: 120_000 });
  }

  async acknowledgeRecommendedEncryptionPromptIfVisible(
    timeoutMs = 5_000,
  ): Promise<boolean> {
    // The recommended encryption floor is auto-acknowledged by the client, so
    // no encryption-floor prompt is ever presented. The only visible follow-up
    // is Recovery Key setup, and only when the account has no configured
    // recovery material; that is what this helper drains.
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
    // The setup wizard remembers its last step in some Inkson builds. A page
    // reload can therefore land on Boundary/Policy while this helper expects
    // the Basics form. Explicitly select Basics when the title field is not
    // immediately present; this keeps the helper resilient to that harmless
    // UI state without weakening the subsequent field assertions.
    const titleInput = strand.getByTestId("realm-title-input");
    if (!(await titleInput.isVisible({ timeout: 1_000 }).catch(() => false))) {
      const basicsStep = strand
        .getByRole("button", { name: /^Basics/ })
        .first();
      if (await basicsStep.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await basicsStep.click();
      }
    }
    await expect(titleInput).toBeVisible({
      timeout: 120_000,
    });

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
    if (opts.historyAccess !== undefined) {
      await this.selectCreateRealmOption(
        strand.getByTestId("realm-policy-history-access-input"),
        opts.historyAccess,
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

    // A bare principal did_core_id is not an InviteAddress: it carries neither
    // the selected recipient service nor current service-resolution evidence.
    // Create the canonical owner-only genesis first, then use the ordinary
    // Realm admin invite path below with a closed InviteAddress for each seed.
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

    await expect(strand).toContainText(/created ak:realm:/, {
      timeout: 30_000,
    });
    const text = await strand.innerText();
    expect(text, `realm bootstrap failed: ${text}`).not.toContain(" failed:");
    const match = text.match(/created (ak:realm:[A-Za-z0-9_-]{44})\b/);
    expect(match, `created realm id in: ${text}`).not.toBeNull();
    const realmId = match![1];
    if ((opts.seedMembers?.length ?? 0) > 0) {
      await strand.getByRole("link", { name: "Open Realm" }).click();
    }
    for (const member of opts.seedMembers ?? []) {
      await this.inviteFromAdmin(realmId, member);
    }
    return realmId;
  }

  // Drive the Realm admin invite modal to invite `targetDid` into realmId.
  async inviteFromAdmin(
    realmId: string,
    targetDid: string,
    expectedDisplayLabel?: string,
    locator?: { token: string; serverUrl?: string },
  ): Promise<string> {
    let targetInput: string;
    if (locator) {
      targetInput = buildInviteLocatorUrl(
        locator.serverUrl ?? this.serverUrl,
        locator.token,
      );
    } else {
      const describe = await this.session.context.request.get(
        `${this.serverUrl.replace(/\/$/, "")}/_arkret/describe`,
      );
      expect(describe.status(), await describe.text()).toBe(200);
      const service = (await describe.json()) as { service_id: string };
      const resolutionUrl = `${this.serverUrl.replace(/\/$/, "")}/_arkret/open/services/${encodeURIComponent(service.service_id)}/resolution`;
      targetInput = JSON.stringify({
        subject_id: targetDid,
        recipient_service_id: service.service_id,
        service_resolution: {
          current_record_url: resolutionUrl.replace(/^http:/, "https:"),
        },
      });
    }
    const membersNav = this.page
      .getByRole("link", { name: "Members", exact: true })
      .first();
    if (await membersNav.isVisible({ timeout: 2_000 }).catch(() => false)) {
      await membersNav.click();
    } else {
      await this.gotoRealmAdminSection(realmId, "members");
    }
    const members = this.page.getByTestId("realm-members-panel");
    await expect(members).toBeVisible({ timeout: 120_000 });
    await members.getByTestId("open-invite-modal-button").click();
    const invite = this.page.getByTestId("invite-member-modal");
    await expect(invite).toBeVisible({ timeout: 30_000 });
    await invite.getByTestId("invite-target-input").fill(targetInput);
    await invite.getByTestId("send-invite-button").click();
    const status = members.getByTestId("realm-members-status");
    const displayLabel = expectedDisplayLabel ?? displayLabelForDid(targetDid);
    await expect(status).toContainText(
      new RegExp(
        `invited (${escapeRegex(displayLabel)}|${escapeRegex(targetDid)})`,
      ),
      { timeout: 30_000 },
    );
    return await status.innerText();
  }

  // Build the Authorization + DPoP headers for a direct (non-browser)
  // `/_arkret/self/*` call. Under the ②(A+②) model the credential is the
  // ak.session.grant and soland requires a per-request DPoP proof.
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
  // `ak.invite.create` followed by invitee-authored `ak.invite.accept`; soland
  // then cascades the accepted invite into Realm membership.
  async acceptInvite(realmId: string) {
    // Principal Events must be signed by the device key accepted in the PCR
    // genesis unit. A Node-side fixture signer cannot impersonate
    // that key, so drive Inkson's first-party action and let its active event
    // signer author the acceptance.
    await this.acceptInviteFromNotifications(realmId);
  }

  // Accept a pending Realm invite through the visible inkson notification UI.
  async acceptInviteFromNotifications(realmId: string) {
    // Inkson imports `/_arkret/self/authz/invites` only during the initial
    // notification bootstrap. If navigation wins the race with invite
    // projection, repeatedly clicking the UI refresh cannot recover that
    // missing bootstrap fact. Wait for the authoritative projection first,
    // then open the surface that imports it.
    const invitesUrl = new URL(
      "/_arkret/self/authz/invites",
      `${this.serverUrl.replace(/\/$/, "")}/`,
    );
    invitesUrl.searchParams.set("subject", this.user.did);
    invitesUrl.searchParams.set("realm_id", realmId);
    await expect
      .poll(
        async () => {
          const response = await this.session.context.request.get(
            invitesUrl.toString(),
            {
              headers: this.selfPathHeaders("GET", invitesUrl.toString()),
            },
          );
          if (response.status() !== 200) return false;
          const body = (await response.json()) as {
            invites?: Array<{ realm_id?: string; state?: string }>;
          };
          return (
            body.invites?.some(
              (invite) =>
                invite.realm_id === realmId && invite.state === "pending",
            ) ?? false
          );
        },
        { timeout: 45_000, intervals: [250, 500, 1_000, 2_000] },
      )
      .toBe(true);

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
    const pending = event.getByTestId("message-send-status");
    const initialTimeout = Math.min(timeout, 15_000);
    const settledWithoutReload = await expect(pending)
      .toHaveCount(0, { timeout: initialTimeout })
      .then(() => true)
      .catch(() => false);
    if (settledWithoutReload) {
      return;
    }

    // The durable Event may already be visible to peers while the sender still
    // holds an optimistic "Sending" row because its live cursor missed the
    // acknowledgement edge. Rehydrate from authoritative history before
    // classifying the operation as stuck.
    await this.page.reload({ waitUntil: "domcontentloaded" });
    await this.dismissPassiveBlockingPrompts();
    const rehydrated = this.timelineEvent(body);
    const remainingTimeout = Math.max(5_000, timeout - initialTimeout);
    await expect(rehydrated).toBeVisible({ timeout: remainingTimeout });
    await expect(rehydrated.getByTestId("message-send-status")).toHaveCount(0, {
      timeout: remainingTimeout,
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
    await this.clickTimelineAction(body, "message-context-reply-button");
  }

  async clickTimelineEdit(body: string) {
    await this.clickTimelineAction(body, "message-context-edit-button");
  }

  async clickTimelineRedact(body: string) {
    await this.clickTimelineAction(body, "message-context-redact-button");
  }

  private async clickTimelineAction(body: string, testId: string) {
    const event = this.timelineEvent(body);
    await this.dismissPassiveBlockingPrompts();
    await expect(event).toBeVisible({ timeout: 30_000 });
    await this.withPassivePromptRetry(async () => {
      await event.scrollIntoViewIfNeeded({ timeout: 5_000 });
      await event.hover({ timeout: 5_000 });
      const menuButton = event.getByTestId("chat-message-menu-button");
      await expect(menuButton).toBeVisible({ timeout: 5_000 });
      await menuButton.click({ timeout: 5_000 });
      const action = event.getByTestId(testId);
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

export function uniqueUser(prefix: string, server?: SolandKey): JointUser {
  const stamp = randomUUID();
  const slug = `${prefix}-${stamp}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const deviceSuffix = stamp.replace(/-/g, "").slice(0, 12);
  const scid = base58btcEncode(
    Buffer.concat([Buffer.from([0x12, 0x20]), randomBytes(32)]),
  );
  const principalFullDid = (() => {
    if (!server) {
      return `did:webvh:${scid}:${slug}.example`;
    }
    const serviceDid = solandServiceFullId(server);
    const webvh = /^did:webvh:[^:]+:([^:]+)(?::.*)?$/.exec(serviceDid);
    if (webvh?.[1]) {
      return `did:webvh:${scid}:${webvh[1]}:webvh:${slug}`;
    }
    const web = /^did:web:([^:]+)(?::.*)?$/.exec(serviceDid);
    if (web?.[1]) {
      return `did:web:${web[1]}:webvh:${slug}`;
    }
    throw new Error(`unsupported Principal Server DID method: ${serviceDid}`);
  })();
  return {
    name: slug,
    did: projectFullDidToCoreId(principalFullDid),
    fullDid: principalFullDid,
    deviceId: `ak:device:01904100-0000-7000-8000-${deviceSuffix}`,
    handle: `@${slug}`,
    displayName: `${prefix} ${stamp}`,
  };
}

// In-flight canonical provisioning per (server, user name). The first
// `ensureRegistered` call for a user drives the co-located coauth account +
// PCR genesis once; concurrent and repeat callers share the same promise.
const provisionedPrincipals = new Map<string, Promise<void>>();

export async function ensureRegistered(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
) {
  // When coauth is reachable, registration goes through the canonical
  // co-located provisioning (account → PCR genesis → verified binding) instead
  // of the bare gate register, so the principal exists with its real DID
  // document, founding device authorization, and bootstrap Seal. The caller's
  // `user` is rebound to the account-bound identity the ceremony returns.
  const coauth = coauthBaseUrl();
  if (coauth) {
    const key = `${opts.server ?? "default"}${user.name}`;
    let provisioning = provisionedPrincipals.get(key);
    if (!provisioning) {
      provisioning = (async () => {
        const accountRequest = await playwrightRequest.newContext({
          ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
        });
        try {
          const account = await registerCoauthPasswordAccount(
            accountRequest,
            coauth,
            {
              password: "1amTester!",
              server: opts.server,
            },
          );
          const session = await createDpopUserSessionForAccount(
            accountRequest,
            user.name,
            account,
            { server: opts.server, coauthBase: coauth },
          );
          if (!session) {
            throw new Error(
              `ensureRegistered: canonical provisioning returned no session for ${user.name}`,
            );
          }
          user.did = session.user.did;
          user.fullDid = session.user.fullDid;
          user.deviceId = session.user.deviceId;
          user.handle = session.user.handle;
          user.displayName = session.user.displayName;
        } finally {
          await accountRequest.dispose();
        }
      })();
      provisionedPrincipals.set(key, provisioning);
    }
    await provisioning;
    return;
  }
  await ensureRegisteredRaw(request, user, opts);
}

async function ensureRegisteredRaw(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
) {
  // Spec-canonical registration binding (`ak.gate.account.command.register`):
  // `POST /_arkret/gate/account/register` with `AccountRegisterRequestBody
  // {principal_id, display_name?, device_id?}`. The bare `handle` field is no
  // longer accepted (the first handle arrives via a signed handle claim,
  // identity-handles.md); the account gets a synthetic localpart derived from
  // the DID. Success is 200 (200|409 here for idempotent setup).
  const url = `${solandBaseUrl(opts.server)}/_arkret/gate/account/register`;
  const data = {
    principal_id: user.did,
    full_id: user.fullDid,
    display_name: user.displayName,
    device_id: user.deviceId,
  };
  const registrationBearer = embeddedWebvhRegistrationBearer();
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (registrationBearer) {
    headers.authorization = `Bearer ${registrationBearer}`;
  }
  registerEventSigner({
    actorDid: user.did,
    deviceId: user.deviceId,
    verificationMethod: `${user.fullDid}#${user.deviceId}`,
  });
  const backoffMs = [500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000];
  for (let attempt = 0; attempt < backoffMs.length; attempt += 1) {
    const response = await request.post(url, {
      data: canonicalJson(data),
      headers,
    });
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
  registerEventSigner({
    actorDid: user.did,
    deviceId: opts.deviceId ?? user.deviceId,
    verificationMethod: `${user.fullDid}#${opts.deviceId ?? user.deviceId}`,
  });
  const backoffMs = [500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000];
  for (let attempt = 0; attempt < backoffMs.length; attempt += 1) {
    const response = await request.post(url, {
      data: canonicalJson(data),
      headers: { "content-type": "application/json" },
    });
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
  _request: APIRequestContext,
  prefix: string,
  opts: {
    server?: SolandKey;
    coauthBase?: string;
  } = {},
): Promise<DpopUserSession | undefined> {
  const coauth = opts.coauthBase ?? coauthBaseUrl();
  if (!coauth) {
    return undefined;
  }
  // Account registration and OIDC handoff are cookie-bound. A single Playwright
  // `request` fixture is often shared by parallel user creation in one scenario;
  // isolating each flow prevents one account's Set-Cookie from switching the
  // other flow onto the wrong identity-creation lease.
  const accountRequest = await playwrightRequest.newContext({
    ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
  });
  try {
    const account = await registerCoauthPasswordAccount(
      accountRequest,
      coauth,
      {
        password: "1amTester!",
        server: opts.server,
      },
    );
    return await createDpopUserSessionForAccount(
      accountRequest,
      prefix,
      account,
      opts,
    );
  } finally {
    await accountRequest.dispose();
  }
}

export async function createDpopUserSessionForAccount(
  request: APIRequestContext,
  prefix: string,
  account: CoauthPasswordAccount,
  opts: {
    server?: SolandKey;
    coauthBase?: string;
  } = {},
): Promise<DpopUserSession | undefined> {
  if (!(opts.coauthBase ?? coauthBaseUrl())) {
    return undefined;
  }
  const seed = uniqueUser(prefix);
  const claimsPrincipalGenesis = !account.genesisClaimed;
  account.genesisClaimed = true;
  if (!claimsPrincipalGenesis) {
    // A second device must use the sibling-pairing ceremony. Reusing the
    // founding handoff would create a second founding transaction and is a
    // protocol violation; this harness has no pairing material at this call
    // boundary, so it fails closed.
    return undefined;
  }
  seed.deviceId = account.genesisDeviceId;
  const audience = solandServiceId(opts.server);
  const grant = account.initialGrant;
  const deviceKey = account.initialHolderKey;
  const eventSigningKey = grant.eventSigningKey;
  if (!eventSigningKey) {
    throw new Error("PCR genesis outcome omitted its founding device signer");
  }
  expect(grant.audience).toBe(audience);
  expect(grant.dpopJkt).toBe(deviceKey.thumbprint);
  expect(grant.scopes).toEqual([
    "ak.self.account.read.describe",
    "ak.self.events.read.scan",
  ]);
  // Consume only the verified DID returned by the atomic registration result.
  expect(
    grant.principalDid,
    "handoff session must return the bound principal DID",
  ).toBeTruthy();
  const user = {
    ...seed,
    name: account.handle,
    did: grant.principalDid,
    fullDid: account.fullDid,
    handle: `@${account.handle}`,
    displayName: account.displayName,
  };
  await ensureRegisteredRaw(request, user, { server: opts.server });
  const eventSigningSeedB64url = dpopDeviceSeedB64url(eventSigningKey);
  registerEventSigner({
    actorDid: user.did,
    deviceId: user.deviceId,
    verificationMethod: `${user.fullDid}#${user.deviceId}`,
    signingSeedB64url: eventSigningSeedB64url,
  });
  const session = {
    user,
    account,
    grantJwt: grant.grantJwt,
    grantId: grant.grantId,
    grantAudience: grant.audience,
    dpopSeedB64url: dpopDeviceSeedB64url(deviceKey),
    eventSigningSeedB64url,
    deviceKey,
    recoveryKey: claimsPrincipalGenesis ? account.recoveryKey : undefined,
    principalControlRealmId: "",
    principalControlEvents: [] as Array<Record<string, unknown>>,
    recoveryMaterialEvidence: undefined as Record<string, unknown> | undefined,
  };
  registerRequestAuth(session.grantJwt, (method, url) =>
    selfPathGrantHeaders({
      deviceKey: session.deviceKey,
      grantJwt: session.grantJwt,
      method,
      url,
    }),
  );
  const checkpoint = account.principalRegistrationCheckpoint;
  const pcrGenesisUnit = checkpoint.pcr_genesis_unit as {
    events?: Array<Record<string, unknown>>;
  };
  if (
    !Array.isArray(pcrGenesisUnit.events) ||
    pcrGenesisUnit.events.length !== 2
  ) {
    throw new Error(
      "principal registration checkpoint omitted its closed PCR genesis unit",
    );
  }
  session.principalControlEvents = pcrGenesisUnit.events.map(
    (event) => JSON.parse(canonicalJson(event)) as Record<string, unknown>,
  );
  const createEvent = session.principalControlEvents[0];
  const createEventId = createEvent?.event_id;
  if (
    createEvent?.kind !== "ak.realm.create" ||
    typeof createEventId !== "string" ||
    !createEventId.startsWith("ak:event:")
  ) {
    throw new Error(
      "principal registration checkpoint omitted its canonical PCR create",
    );
  }
  const principalControlRealmId = createEventId.replace(
    /^ak:event:/,
    "ak:realm:",
  );
  session.principalControlRealmId = principalControlRealmId;
  registerPrincipalControlRealm(user.did, principalControlRealmId);
  registerPrincipalControlEvents(user.did, session.principalControlEvents);
  const bootstrapSeal = cotestWire<Record<string, unknown>>(
    "principal-bootstrap-seal",
    {
      pcr_genesis_unit: checkpoint.pcr_genesis_unit,
      device_signing_seed_b64url: checkpoint.device_signing_seed_b64url,
    },
  );
  session.recoveryMaterialEvidence = {
    principal_id: user.fullDid,
    device_id: user.deviceId,
    principal_control_realm_id: principalControlRealmId,
    pcr_genesis_unit: checkpoint.pcr_genesis_unit,
    bootstrap_seal: bootstrapSeal,
  };
  const viewerUrl = `${solandBaseUrl(opts.server)}/_arkret/self/account/viewer`;
  const viewerResponse = await request.get(viewerUrl, {
    headers: selfPathHeadersForDpopSession(session, "GET", viewerUrl),
  });
  const viewerText = await viewerResponse.text();
  expect(
    viewerResponse.ok(),
    `principal bootstrap account viewer returned ${viewerResponse.status()}: ${viewerText}`,
  ).toBeTruthy();
  const sealUrl = `${solandBaseUrl(opts.server)}/_arkret/self/events/seals`;
  const sealResponse = await request.post(sealUrl, {
    headers: {
      ...selfPathHeadersForDpopSession(session, "POST", sealUrl),
      "content-type": "application/json",
    },
    data: canonicalJson(bootstrapSeal),
  });
  expect(
    sealResponse.ok(),
    `principal bootstrap Seal returned ${sealResponse.status()}: ${await sealResponse.text()}; account=${viewerText}`,
  ).toBeTruthy();
  return session;
}

export async function openDpopUserPage(
  browser: Browser,
  request: APIRequestContext,
  prefix: string,
  opts: {
    server?: SolandKey;
    coauthBase?: string;
    prepareMlsDevice?: boolean;
    allowExplicitInviteNotifications?: boolean;
  } = {},
): Promise<DpopUserPageSession | undefined> {
  const session = await createDpopUserSession(request, prefix, opts);
  if (session && opts.allowExplicitInviteNotifications !== false) {
    await allowExplicitInviteNotifications(request, session, opts.server);
  }
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
    autoCompleteRecoveryKeySetup?: boolean;
    allowExplicitInviteNotifications?: boolean;
  } = {},
): Promise<DpopUserPageSession | undefined> {
  const session = await createDpopUserSessionForAccount(
    request,
    prefix,
    account,
    {
      ...opts,
    },
  );
  if (session && opts.allowExplicitInviteNotifications !== false) {
    await allowExplicitInviteNotifications(request, session, opts.server);
  }
  return openDpopUserPageFromSession(browser, session, opts);
}

async function allowExplicitInviteNotifications(
  request: APIRequestContext,
  session: DpopUserSession,
  server?: SolandKey,
) {
  const url = `${solandBaseUrl(server)}/_arkret/self/invite-receive-policy`;
  const current = await request.get(url, {
    headers: selfPathHeadersForDpopSession(session, "GET", url),
  });
  expect(current.status(), await current.text()).toBe(200);
  const policy = (await current.json()) as Record<string, unknown>;
  const updated = await request.put(url, {
    headers: {
      ...selfPathHeadersForDpopSession(session, "PUT", url),
      "content-type": "application/json",
    },
    data: canonicalJson({
      ...policy,
      explicit_address_behavior: "notify",
    }),
  });
  expect(updated.status(), await updated.text()).toBe(200);
}

export async function openDpopUserPageFromSession(
  browser: Browser,
  session: DpopUserSession | undefined,
  opts: {
    server?: SolandKey;
    prepareMlsDevice?: boolean;
    autoCompleteRecoveryKeySetup?: boolean;
  } = {},
): Promise<DpopUserPageSession | undefined> {
  if (!session) {
    return undefined;
  }
  const page = await openUserPage(browser, session.user, {
    server: opts.server,
    grantJwt: session.grantJwt,
    dpopSeedB64url: session.dpopSeedB64url,
    eventSigningSeedB64url: session.eventSigningSeedB64url,
    grantId: session.grantId,
    grantAudience: session.grantAudience,
    recoveryKey: session.recoveryKey,
    recoveryMaterialEvidence: session.recoveryMaterialEvidence,
    autoCompleteRecoveryKeySetup: opts.autoCompleteRecoveryKeySetup,
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
  const sessionInjection =
    opts.grantJwt && opts.dpopSeedB64url
      ? {
          grant_jwt: opts.grantJwt,
          dpop_seed_b64url: opts.dpopSeedB64url,
          principal_full_id: user.fullDid,
          ...(opts.recoveryMaterialEvidence
            ? { recovery_material_evidence: opts.recoveryMaterialEvidence }
            : {}),
          ...(opts.eventSigningSeedB64url
            ? { event_signing_seed_b64url: opts.eventSigningSeedB64url }
            : {}),
          grant_id: opts.grantId ?? "",
          audience: opts.grantAudience ?? "",
        }
      : undefined;
  const localStorage = [
    {
      name: "inkson.config.v1",
      value: JSON.stringify({
        principal_servers: [serverUrl],
        active_account: opts.neutralLoginConfig
          ? null
          : {
              profile_id: `ak:profile:${randomUUID()}`,
              authority: {
                principal_id: user.did,
                principal_server_id: solandServiceId(opts.server),
              },
              resolution: {
                full_id: user.fullDid,
                method_history_head: "sha256:cotest-accepted-history-head",
                version_id: "cotest-accepted-version",
                resolution_event_ref: "ak:event:cotest-accepted-resolution",
                updated_at: new Date().toISOString(),
              },
              device_id: user.deviceId,
              server_url: serverUrl,
            },
        session_credential: opts.neutralLoginConfig ? "" : sessionCredential,
      }),
    },
  ];
  if (sessionInjection) {
    localStorage.push({
      name: "inkson.test.session_injection.v1",
      value: JSON.stringify(sessionInjection),
    });
  } else if (sessionCredential) {
    localStorage.push({
      name: "inkson.test.session_credential_injection.v1",
      value: sessionCredential,
    });
  }
  const context = await browser.newContext({
    baseURL: inksonBaseUrl(opts.server),
    // Opt-in for running against a live Caddy stack whose TLS is `tls internal`
    // (self-signed). Default off so CI/headless harness runs are unaffected.
    ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    recordHar: {
      path: path.join(diagnosticsDir, "network.har"),
      mode: "minimal",
      content: "omit",
    },
    // Seed the Inkson origin directly. An init script also runs once against
    // the initial opaque about:blank document, where localStorage access throws
    // SecurityError and can make session injection nondeterministic.
    storageState: {
      cookies: [],
      origins: [
        {
          origin: new URL(inksonBaseUrl(opts.server)).origin,
          localStorage,
        },
      ],
    },
  });
  const seededStorageState = await context.storageState();
  const seededOrigin = seededStorageState.origins.find(
    ({ origin }) => origin === new URL(inksonBaseUrl(opts.server)).origin,
  );
  const seededNames = new Set(
    seededOrigin?.localStorage.map(({ name }) => name) ?? [],
  );
  if (!seededNames.has("inkson.config.v1")) {
    await context.close();
    throw new Error("Inkson browser context is missing its seeded config");
  }
  if (
    sessionInjection &&
    !seededNames.has("inkson.test.session_injection.v1")
  ) {
    await context.close();
    throw new Error(
      "Inkson browser context is missing its test session fixture",
    );
  }
  if (
    !sessionInjection &&
    sessionCredential &&
    !seededNames.has("inkson.test.session_credential_injection.v1")
  ) {
    await context.close();
    throw new Error(
      "Inkson browser context is missing its test credential fixture",
    );
  }
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
  // With real-grant injection enabled, device enrollment triggers inkson's
  // mandatory "Set up your 24-word Recovery Key" modal ("required before
  // encryption"). It can pop asynchronously mid-flow and covers the page, so a
  // one-shot dismiss in the nav helpers races it. Register a Playwright locator
  // handler that auto-completes it whenever it blocks an action: read the
  // generated key, mirror it into the confirm field, and save. Idempotent and a
  // no-op when the modal is absent.
  if (opts.autoCompleteRecoveryKeySetup !== false) {
    await page.addLocatorHandler(
      page.getByTestId("recovery-key-setup-generated-key"),
      async (generated) => {
        const recoveryKey = (
          await generated.inputValue().catch(() => "")
        ).trim();
        if (recoveryKey.split(/\s+/).filter(Boolean).length !== 24) {
          return;
        }
        await page
          .getByTestId("recovery-key-setup-confirm-key")
          .last()
          .fill(recoveryKey)
          .catch(() => undefined);
        await page
          .getByTestId("recovery-key-setup-saved")
          .last()
          .click({ timeout: 10_000 })
          .catch(() => undefined);
      },
      { noWaitAfter: true },
    );
  }
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
  const webvhExample = did.match(
    /^did:webvh:[a-z0-9]+:([a-z0-9._-]+)\.example$/i,
  );
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
