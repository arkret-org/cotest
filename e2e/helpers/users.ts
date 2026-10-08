import fs from "node:fs";
import path from "node:path";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import {
  expect,
  request as playwrightRequest,
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type Locator,
  type Page,
} from "@playwright/test";
import {
  coauthBaseUrl,
  diagnosticsRoot,
  inksonBaseUrl,
  type SolandKey,
  solandBaseUrl,
  solandServiceDid,
  solandServiceId,
} from "./env";
import { selectDxcOption } from "./dxc-select";
import type { AccountId, PublicPrincipalResolution, RealmObject } from "./generated/spec-wire-objects";
import {
  accountHandoffHeaders,
  createCanonicalAccountHandoff,
  registerCoauthPasswordAccount,
  type CoauthPasswordAccount,
} from "./coauth-register";
import {
  dpopDeviceKeyFromSeedB64url,
  dpopDeviceSeedB64url,
  generateDpopDeviceKey,
  selfPathGrantHeaders,
  type DpopDeviceKey,
} from "./session-grant-dpop";
import {
  authHeaders,
  accountActorId,
  canonicalJson,
  cotestWire,
  expectJsonOk,
  projectDidToCoreId,
  registerEventSigner,
  registerPrincipalControlRealm,
  registerPrincipalControlEvents,
  registerRequestAuth,
  typedId,
  verifyRegisteredEventSignerDeviceApi,
} from "./soland-api";
import {
  ProvisioningLedger,
  assertCompleteIdentity,
  provisioningKey,
  type ProvisionedIdentity,
} from "./provisioning-cache";
import { deviceSuffix, newDeviceId } from "./ids";
import { base58btcEncode } from "./encoding";
import { withOperationSelectors } from "./arkret-test";
import { SessionDiagnostics, accountViewerHandleDiagnostic } from "./session-diagnostics";
import { revealTimelineEvent } from "./timeline-visibility";
import {
  completeRecoverySetup,
  finishRecoverySetupBeforeClose,
  installRecoverySetupHandler,
} from "./recovery-setup";
import { matchesRealmChatRoute } from "./navigation";


export type JointUser = {
  name: string;
  /// Stable business identity projected through the active DID method adapter.
  id: string;
  /// Resolvable DID retained only for registration and proof-method boundaries.
  did: string;
  deviceId: string;
  handle: string;
  displayName: string;
};
type UserSession = {
  context: BrowserContext;
  page: Page;
  diagnosticsDir: string;
  consoleLines: SessionDiagnostics;
  networkLines: SessionDiagnostics;
  serverUrl: string;
  keepDeviceAuthorizationModal: boolean;
  /// The credential presented on `/_arkret/self/*`. Under the ②(A+②) model this
  /// is the `ak.session.grant` JWT; a request to a self-path also requires the
  /// DPoP + holder-proof material in `grant` below.
  sessionCredential: string;
  /// Real grant + DPoP material for direct (non-browser) self-path API calls.
  /// Present when the session was opened with an injected grant.
  grant?: SessionGrantMaterial;
  onRecoveryKeyConfigured?: (key: string) => void;
};
type SessionGrantMaterial = {
  grantJwt: string;
  grantId: string;
  accountId: { principal_id: string; station_id: string };
  audience: string;
  /// base64url-no-pad 32-byte Ed25519 seed of the DPoP device key the grant is
  /// bound to (`cnf.jkt`).
  dpopSeedB64url: string;
};
type OpenUserOpts = {
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
  /// Exact Station account that issued the injected grant.
  accountId?: { principal_id: string; station_id: string };
  /// Exact principal-control Realm created by the accepted PCR genesis unit.
  principalControlRealmId?: string;
  /// Audience the grant is bound to (the soland service DID).
  grantAudience?: string;
  recoveryKey?: string;
  recoveryMaterialEvidence?: Record<string, unknown>;
  onRecoveryKeyConfigured?: (key: string) => void;
  /// Keep this user's real browser storage, including IndexedDB secrets,
  /// across closing and relaunching the Chromium process.
  persistentUserDataDir?: string;
  resumePersistentProfile?: boolean;
};

export type DpopUserSession = {
  user: JointUser;
  /// Test-harness account handle retained so a scenario can open and pair a
  /// genuinely distinct second device for the same principal.
  account: CoauthPasswordAccount;
  grantJwt: string;
  grantId: string;
  accountId: { principal_id: string; station_id: string };
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
type CreateRealmOpts = {
  title: string;
  summary?: string;
  discoverability?: string;
  joinRule?: string;
  historyAccess?: RealmObject["history_access"];
  /// Turn MLS on for the new Realm. The UI no longer offers an encryption
  /// profile to declare: a scope is end-to-end encrypted exactly when an
  /// `ak.mls.genesis` has been accepted for it.
  mlsActivated?: boolean;
  seedMembers?: string[];
  completeRecoveryKeySetup?: boolean;
  allowPassivePromptDismissal?: boolean;
  allowRecoveryOverride?: boolean;
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
  server: SolandKey = "server1",
): Promise<string> {
  const issueUrl = `${solandBaseUrl(server)}/_arkret/self/invite-locators`;
  const response = await request.post(
    issueUrl,
    {
      headers: authHeaders(sessionToken, "POST", issueUrl),
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

function pushDiagnosticLine(lines: SessionDiagnostics, line: string) {
  lines.push(line);
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
        // Session injection can mount the authenticated shell while the URL
        // still names the transient `/login` route (whose authenticated
        // content is Dashboard). Normalize it through the live router before
        // handing the page to a scenario, so later feature navigation cannot
        // be overwritten by login-route state.
        if (new URL(this.page.url()).pathname !== "/") {
          const homeLink = this.page
            .locator('a[href="/"]:visible')
            .filter({ hasText: /^Home$/ })
            .first();
          await expect(homeLink).toBeVisible({ timeout: 30_000 });
          await homeLink.click();
          await expect(this.page).toHaveURL((url) => url.pathname === "/", {
            timeout: 30_000,
          });
        }
        await this.dismissDeviceAuthorizationPrompt();
        return;
      }
    }
    const storageKeys = await this.page
      .evaluate(() => Object.keys(window.localStorage).sort())
      .catch(() => [] as string[]);
    pushDiagnosticLine(
      this.session.consoleLines,
      JSON.stringify({
        ts: new Date().toISOString(),
        type: "goto_home_failure",
        url: this.page.url(),
        local_storage_keys: storageKeys,
      }),
    );
    flushUserDiagnostics(this.session);
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

  async gotoSetup(opts: { completeRecoveryKeySetup?: boolean } = {}) {
    // inkson's /setup is the Overview; the Realm wizard lives at the
    // /setup/realms section. inkson/src/routes.rs §SetupSection.
    const lifecycle = this.page.getByTestId("realm-lifecycle-strand");
    const setupLink = this.page.locator('a[href="/setup/realms"]:visible').first();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      if (opts.completeRecoveryKeySetup ?? true) {
        await this.completeRecoveryKeySetupIfPrompted(2_000);
      }
      if (await setupLink.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await setupLink.click({ timeout: 10_000 }).catch(() => undefined);
      } else {
        await this.navigateWithinApp("/setup/realms");
      }
      if (opts.completeRecoveryKeySetup ?? true) {
        await this.completeRecoveryKeySetupIfPrompted(2_000);
      }
      if (
        await lifecycle
          .waitFor({ state: "visible", timeout: 20_000 })
          .then(() => true)
          .catch(() => false)
      ) {
        await this.dismissDeviceAuthorizationPrompt();
        return;
      }
      if (
        !(await this.page
          .getByTestId("client-shell")
          .isVisible({ timeout: 1_000 })
          .catch(() => false))
      ) {
        await this.gotoHome();
      }
    }
    await expect(lifecycle).toBeVisible({ timeout: 60_000 });
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
    // Preserve Inkson's authenticated in-memory session. A document reload can
    // race secure-store restoration and leave the router on its transient
    // login/home surface even though the injected grant is valid.
    await this.gotoAppPanel("/directory", "directory-panel");
    await this.dismissCreateRealmBlockingPrompts({
      completeRecoveryKeySetup: true,
      allowPassivePromptDismissal: true,
    });
  }

  async gotoSettings() {
    await this.gotoAppPanel("/settings", "settings-panel");
  }

  async gotoNotifications() {
    await this.gotoAppPanel("/notifications", "notifications-panel");
  }

  async gotoNotificationSettings() {
    await this.gotoAppPanel(
      "/notifications/settings",
      "notification-settings-panel",
    );
  }

  async gotoRealmAdmin(realmId: string) {
    await this.navigateWithinApp(`/realms/${realmId}/settings`);
    await expect(this.page.getByTestId("realm-admin-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissDeviceAuthorizationPrompt();
  }

  // Navigate to a specific Realm admin section (Members / Access / etc.).
  // Members is its own route; other admin sections live under settings.
  async gotoRealmAdminSection(realmId: string, section: string) {
    const destination =
      section === "members"
        ? `/realms/${encodeURIComponent(realmId)}/members`
        : `/realms/${encodeURIComponent(realmId)}/settings/${encodeURIComponent(section)}`;
    // Realm administration is a supported deep link. A real same-origin
    // navigation initializes the Dioxus router from that canonical route and
    // avoids replaying unrelated browser-history entries left by OIDC flows.
    await this.page.goto(destination, { waitUntil: "domcontentloaded" });
    await expect
      .poll(() => new URL(this.page.url()).pathname, { timeout: 120_000 })
      .toBe(destination);

    if (section === "members") {
      await expect(this.page.getByTestId("realm-members-panel")).toBeVisible({
        timeout: 120_000,
      });
      await this.dismissDeviceAuthorizationPrompt();
      return;
    }

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

  private async navigateWithinApp(path: string) {
    if (this.page.url().startsWith("about:")) {
      await this.gotoHome();
    }
    // Dioxus consumes the browser's native history notification. Constructing
    // a PopStateEvent in script updates the address bar but does not traverse
    // the browser history source observed by the router, leaving the rendered
    // surface on Home. Push the destination, then traverse back/forward so the
    // browser emits the real event while the authenticated shell stays mounted.
    await this.page.evaluate(async (nextPath) => {
      const nextPop = () =>
        new Promise<void>((resolve) =>
          window.addEventListener("popstate", () => resolve(), { once: true }),
        );
      window.history.pushState({}, "", nextPath);
      const back = nextPop();
      window.history.back();
      await back;
      const forward = nextPop();
      window.history.forward();
      await forward;
    }, path);
  }

  async gotoAppPanel(path: string, testId: string) {
    const panel = this.page.getByTestId(testId);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await this.navigateWithinApp(path);
      if (
        await panel
          .waitFor({ state: "visible", timeout: 20_000 })
          .then(() => true)
          .catch(() => false)
      ) {
        await this.dismissDeviceAuthorizationPrompt();
        return;
      }
      // Account bootstrap and the first authoritative sync can each restore
      // Home after a feature route was requested. Re-establish the durable
      // authenticated shell, then re-enter through the live SPA router.
      await this.gotoHome();
    }
    await expect(panel).toBeVisible({ timeout: 60_000 });
    await this.dismissDeviceAuthorizationPrompt();
  }

  async gotoTimelineRealm(realmId: string) {
    // Chat is a supported deep-link route but is no longer present in the
    // Realm context navigation (Board is the only top-level product surface).
    // Use a real same-origin document navigation so Dioxus initializes from
    // the canonical route while the browser keeps the durable account store.
    const destination = `/chat/${encodeURIComponent(realmId)}`;
    await this.page.goto(destination, {
      waitUntil: "domcontentloaded",
    });
    await expect(this.page).toHaveURL(
      (url) => matchesRealmChatRoute(url, realmId),
      { timeout: 60_000 },
    );
    await expect(this.page.getByTestId("chat-panel")).toBeVisible({
      timeout: 120_000,
    });
    await this.dismissPassiveBlockingPrompts();
    await expect(this.page.getByTestId("message-list")).toBeVisible({
      timeout: 120_000,
    });
    await expect(this.page.getByTestId("chat-panel")).toHaveAttribute(
      "data-initial-sync",
      "complete",
      { timeout: 120_000 },
    );
  }

  // Membership is not an authorization source (capabilities.md §3.2).
  // Drive Inkson's canonical grant UI, then wait for the accepted Control Move
  // to become visible in the authoritative grant projection before a workflow
  // relies on the delegated action.
  async grantRealmCapability(
    realmId: string,
    subjectAccount: AccountId,
    action: string,
  ): Promise<string> {
    await this.gotoRealmAdminSection(realmId, "security");
    await this.page.getByTestId("advanced-access-toggle").click();
    await this.page.getByTestId("cap-grant-tag-input").fill(action);
    await this.page.getByTestId("cap-grant-subject-input").fill(canonicalJson(subjectAccount));
    await this.page.getByTestId("cap-grant-submit-button").click();
    const status = this.page.getByTestId("realm-admin-status");
    await expect(status).toContainText("Permission granted. Grant ID:", {
      timeout: 120_000,
    });
    expect(await status.innerText()).not.toContain("failed");

    const grantsUrl = new URL(
      `${this.serverUrl}/_arkret/self/authz/effective-grants`,
    );
    const subject = { kind: "account" as const, account_id: subjectAccount };
    grantsUrl.searchParams.set("subject_actor_id", canonicalJson(subject));
    grantsUrl.searchParams.set("realm_id", realmId);
    let projectedGrantId: string | undefined;
    await expect
      .poll(
        async () => {
          const response = await this.page.request.get(grantsUrl.toString(), {
            headers: {
              ...this.selfPathHeaders("GET", grantsUrl.toString()),
              "Arkret-Operation":
                "ak.self.authz.grants.read.effective.v1",
            },
          });
          if (response.status() !== 200) return false;
          const body = (await response.json()) as {
            grants?: Array<{
              grant?: {
                id?: string;
                subject?: unknown;
                actions?: string[];
              };
            }>;
          };
          projectedGrantId = body.grants?.find(
            (row) =>
              row.grant?.subject !== undefined &&
              canonicalJson(row.grant.subject) === canonicalJson(subject) &&
              row.grant.actions?.includes(action),
          )?.grant?.id;
          return projectedGrantId?.startsWith("ak:grant:") ?? false;
        },
        { timeout: 120_000, intervals: [250, 500, 1_000, 2_000] },
      )
      .toBe(true);
    return projectedGrantId!;
  }

  private async dismissDeviceAuthorizationPrompt() {
    if (!this.session.keepDeviceAuthorizationModal) {
      await dismissDeviceAuthorizationPrompt(this.page);
    }
  }

  private async dismissCreateRealmBlockingPrompts(opts: {
    completeRecoveryKeySetup: boolean;
    allowPassivePromptDismissal: boolean;
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
        if (!opts.allowPassivePromptDismissal) {
          throw new Error(
            `${modalTestId} appeared; refusing an undeclared passive prompt dismissal`,
          );
        }
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
    promptHandling: {
      completeRecoveryKeySetup: boolean;
      allowPassivePromptDismissal: boolean;
    },
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
    promptHandling: {
      completeRecoveryKeySetup: boolean;
      allowPassivePromptDismissal: boolean;
    },
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
    const recoveryKey = (
      await generatedKeyField.inputValue({ timeout: 10_000 }).catch(() => "")
    ).trim();
    const keyReadable = recoveryKey.split(/\s+/).filter(Boolean).length === 24;
    if (
      !keyReadable &&
      !(await dialog.isHidden({ timeout: 100 }).catch(() => false))
    ) {
      expect(
        recoveryKey.split(/\s+/).filter(Boolean).length,
        "recovery-key setup prompt must expose a 24-word key",
      ).toBe(24);
    }
    const confirmedKey = keyReadable
      ? await completeRecoverySetup(this.page, recoveryKey)
      : undefined;
    // Recovery policy publication intentionally retries the retry-safe
    // revision_unavailable answer for up to 30 seconds.  Give that protocol retry a full window,
    // plus one locator-handler retry and UI propagation time, before failing.
    if (!confirmedKey) await expect(dialog).toBeHidden({ timeout: 90_000 });
    if (confirmedKey) this.session.onRecoveryKeyConfigured?.(confirmedKey);
    return confirmedKey;
  }

  async unlockMlsAccountSecret(recoveryKey: string): Promise<void> {
    // Recovery is an interaction on this device's foreground page.
    await this.page.bringToFront();
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

  async completeMlsAccountBackupIfPrompted(
    recoveryKey: string,
    timeoutMs = 15_000,
  ): Promise<boolean> {
    const prompt = this.page.getByTestId("mls-backup-modal").last();
    if (!(await prompt.waitFor({ state: "visible", timeout: timeoutMs })
      .then(() => true).catch(() => false))) return false;
    expect(recoveryKey.trim().split(/\s+/).length === 24,
      "the account's confirmed Recovery Key is required for the MLS backup").toBe(true);
    const existingKey = prompt.getByTestId("mls-backup-existing-key");
    await expect(existingKey).toBeVisible({ timeout: 30_000 });
    await existingKey.fill(recoveryKey);
    const submit = prompt.getByTestId("mls-backup-submit");
    await expect(submit).toBeEnabled({ timeout: 30_000 });
    const accepted = this.page.waitForResponse((response) =>
      response.request().method() === "PUT"
      && /\/_arkret\/self\/keys\/backups\/ak:backup:/.test(decodeURIComponent(new URL(response.url()).pathname))
      && response.status() === 200
      && /"item_kind"\s*:\s*"mls_account_secret"/.test(response.request().postData() ?? ""),
    { timeout: 120_000 });
    try {
      await Promise.all([accepted, submit.click()]);
    } catch (error) {
      // Classify only public status copy; never put recovery words or raw
      // request/response bodies into the Playwright error or its attachments.
      const status = await prompt.getByTestId("mls-backup-status").textContent().catch(() => "");
      const reasons = [
        ["missing-pcr-evidence", "Frozen PCR authority evidence is required"],
        ["wrong-pcr-evidence", "Frozen PCR authority evidence does not match this account"],
        ["missing-local-secret", "no local account MLS secret"],
        ["wrong-policy-recipient", "recovery public key must uniquely match"],
        ["unresolved-pcr", "server no longer resolves the exact committed PCR genesis unit"],
        ["invalid-key", "Enter a valid 24-word Recovery Key"],
        ["uploading", "Encrypting and uploading"],
        ["uploading-zh", "正在加密并上传备份"],
      ] as const;
      const reason = reasons.find(([, copy]) => status?.includes(copy))?.[0] ?? "unclassified";
      throw new Error(`MLS account backup did not upload: status=${reason}; modalVisible=${await prompt.isVisible()}; submitEnabled=${await submit.isEnabled().catch(() => false)}`, { cause: error });
    }
    await expect(prompt).toBeHidden({ timeout: 120_000 });
    this.session.onRecoveryKeyConfigured?.(recoveryKey);
    return true;
  }

  async completeMlsAccountRecoveryIfPrompted(recoveryKey: string): Promise<boolean> {
    const prompt = this.page.locator(
      '[data-testid="mls-unlock-modal"], [data-testid="mls-unlock-banner"], [data-testid="mls-backup-modal"]',
    ).last();
    if (!(await prompt.waitFor({ state: "visible", timeout: 15_000 })
      .then(() => true).catch(() => false))) return false;
    const unlock = this.page.locator(
      '[data-testid="mls-unlock-modal"], [data-testid="mls-unlock-banner"]',
    ).last();
    if (await unlock.isVisible()) {
      await this.unlockMlsAccountSecret(recoveryKey);
      return true;
    }
    return await this.completeMlsAccountBackupIfPrompted(recoveryKey);
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
      allowPassivePromptDismissal: opts.allowPassivePromptDismissal ?? true,
    };
    let strand = this.page.getByTestId("realm-lifecycle-strand").last();
    let titleInput = strand.getByTestId("realm-title-input");
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await this.gotoSetup({
        completeRecoveryKeySetup: promptHandling.completeRecoveryKeySetup,
      });
      await this.dismissCreateRealmBlockingPrompts(promptHandling);
      strand = this.page.getByTestId("realm-lifecycle-strand").last();
      titleInput = strand.getByTestId("realm-title-input");
      if (await titleInput.isVisible({ timeout: 1_000 }).catch(() => false)) {
        break;
      }
      const basicsStep = strand
        .getByRole("button", { name: /^Basics/ })
        .first();
      if (await basicsStep.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await basicsStep.click();
      }
      if (await titleInput.isVisible({ timeout: 2_000 }).catch(() => false)) {
        break;
      }
      // Account bootstrap may restore Home after the wizard first appears.
      // Re-run the full setup entry and prompt drain once in that case.
    }
    // The setup wizard remembers its last step in some Inkson builds. A page
    // reload can therefore land on Boundary/Policy while this helper expects
    // the Basics form. Explicitly select Basics when the title field is not
    // immediately present; this keeps the helper resilient to that harmless
    // UI state without weakening the subsequent field assertions.
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
    if (opts.mlsActivated !== undefined) {
      await this.selectCreateRealmOption(
        strand.getByTestId("realm-mls-activation-input"),
        opts.mlsActivated ? "after_create" : "not_now",
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

    // A configured account must never need this gate. Recovery override changes
    // the business outcome, so it is fail-closed unless the scenario declares
    // the bypass explicitly in its source/evidence metadata.
    const recoveryGate = this.page
      .getByTestId("encrypted-realm-recovery-gate")
      .last();
    const gateAppeared = await recoveryGate
      .waitFor({ state: "visible", timeout: 2_000 })
      .then(() => true)
      .catch(() => false);
    if (gateAppeared) {
      if (!opts.allowRecoveryOverride) {
        throw new Error(
          "encrypted-realm-recovery-gate appeared; refusing an undeclared recovery override",
        );
      }
      const override = this.page
        .getByTestId("encrypted-realm-recovery-gate-override")
        .last();
      for (let attempt = 0; attempt < 3; attempt += 1) {
        if (await recoveryGate.isHidden({ timeout: 100 }).catch(() => false)) {
          break;
        }
        await override.click({ timeout: 5_000 }).catch(() => undefined);
      }
      await expect(recoveryGate).toBeHidden({ timeout: 10_000 });
      const alreadyCreated = await strand
        .getByTestId("selected-realm-id")
        .last()
        .isVisible({ timeout: 100 })
        .catch(() => false);
      if (!alreadyCreated) {
        await expect(createButton).toBeEnabled({ timeout: 30_000 });
        await this.clickCreateRealmControl(createButton, promptHandling);
      }
    }

    // Realm acceptance is only the first part of bootstrap. The Done step keeps
    // its action disabled until governance and, where selected, MLS genesis are
    // complete. Do not hand a partially bootstrapped Realm to the next action.
    const done = strand.getByTestId("realm-setup-done");
    await expect(done).toBeVisible({ timeout: 120_000 });
    const selectedRealm = done.getByTestId("selected-realm-id");
    await expect(selectedRealm).toHaveAttribute(
      "title",
      /^ak:realm:[A-Za-z0-9_-]{44}$/,
      { timeout: 120_000 },
    );
    const openRealm = done.getByRole("link", {
      name: /Open (?:Realm|workspace)/i,
    });
    await expect(openRealm).toBeVisible({ timeout: 180_000 });
    const text = await strand.innerText();
    expect(text, `realm bootstrap failed: ${text}`).not.toContain(" failed:");
    const realmId = await selectedRealm.getAttribute("title");
    expect(realmId, `created realm id in: ${text}`).toMatch(
      /^ak:realm:[A-Za-z0-9_-]{44}$/,
    );
    if ((opts.seedMembers?.length ?? 0) > 0) {
      await openRealm.click();
    }
    for (const member of opts.seedMembers ?? []) {
      await this.inviteFromAdmin(realmId!, member);
    }
    return realmId!;
  }

  // Drive the Realm admin invite modal to invite `targetId` into realmId.
  /// `expectStatus` overrides the "invited <label>" success assertion for a
  /// call whose registered outcome is not a new Invite — re-issuing a directed
  /// invite for an account that already holds the Realm's live-target slot is
  /// refused by the reducer, and the client reports what it did about the
  /// existing invite instead (governance-objects.md section 5.3).
  async inviteFromAdmin(
    realmId: string,
    targetId: string,
    expectedDisplayLabel?: string,
    locator?: { token: string; serverUrl?: string },
    expectStatus?: RegExp,
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
        {
          headers: {
            "Arkret-Operation": "ak.server.read.describe.v1",
          },
        },
      );
      expect(describe.status(), await describe.text()).toBe(200);
      const service = (await describe.json()) as { service_id: string };
      const resolutionUrl = `${this.serverUrl.replace(/\/$/, "")}/_arkret/open/services/${encodeURIComponent(service.service_id)}/resolution`;
      targetInput = JSON.stringify({
        account_id: {
          principal_id: targetId,
          station_id: service.service_id,
        },
        service_resolution: {
          resolution_url: resolutionUrl.replace(/^http:/, "https:"),
        },
      });
    }
    // The responsive shell renders desktop and compact Realm navigation at the
    // same time. Selecting the first accessible-name match can pick the hidden
    // copy and incorrectly fall back to a cold page load. Prefer the visible,
    // Realm-bound link so the authenticated app/session stays mounted.
    const membersNav = this.page
      .locator(`a[href="/realms/${realmId}/members"]:visible`)
      .first();
    if (!(await membersNav.isVisible({ timeout: 15_000 }).catch(() => false))) {
      // Realm creation updates projections and the responsive context bar
      // asynchronously. Stay inside the mounted application: select the Realm
      // from the sidebar, then wait for its context navigation to appear.
      const realmNav = this.page
        .locator(`a[href="/realms/${realmId}"]:visible`)
        .first();
      await expect(realmNav).toBeVisible({ timeout: 60_000 });
      await realmNav.click();
      if (
        !(await membersNav.isVisible({ timeout: 5_000 }).catch(() => false))
      ) {
        // Narrow viewports collapse Realm destinations into the context menu;
        // its links are mounted only while the menu is open.
        const contextMenu = this.page.getByTestId("realm-context-menu-button");
        await expect(contextMenu).toBeVisible({ timeout: 30_000 });
        await contextMenu.click();
      }
      await expect(membersNav).toBeVisible({ timeout: 30_000 });
    }
    await membersNav.click();
    const members = this.page.getByTestId("realm-members-panel");
    await expect(members).toBeVisible({ timeout: 120_000 });
    await members.getByTestId("open-invite-modal-button").click();
    const invite = this.page.getByTestId("invite-member-modal");
    await expect(invite).toBeVisible({ timeout: 30_000 });
    await invite.getByTestId("invite-target-input").fill(targetInput);
    await invite.getByTestId("send-invite-button").click();
    const status = members.getByTestId("realm-members-status");
    const displayLabel = expectedDisplayLabel ?? targetId;
    const expected =
      expectStatus ??
      new RegExp(
        `invited (${escapeRegex(displayLabel)}|${escapeRegex(targetId)})`,
      );
    await expect(status).toContainText(expected, { timeout: 30_000 });
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
    invitesUrl.searchParams.set("realm_id", realmId);
    await expect
      .poll(
        async () => {
          const response = await this.session.context.request.get(
            invitesUrl.toString(),
            {
              headers: {
                ...this.selfPathHeaders("GET", invitesUrl.toString()),
                "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
              },
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
        { timeout: 90_000, intervals: [250, 500, 1_000, 2_000, 5_000] },
      )
      .toBe(true);

    await this.gotoNotifications();
    // A newly enrolled account may surface the mandatory recovery-key setup
    // while the invite projection is arriving. Drain that legitimate modal
    // before interacting with the notification toolbar; otherwise its dialog
    // backdrop intercepts the refresh click and the helper times out without
    // ever exercising invite acceptance.
    await this.dismissPassiveBlockingPrompts();
    const refresh = this.page.getByTestId("refresh-notifications");
    const inviteItem = this.page
      .getByTestId("notification-item")
      .filter({ has: this.page.locator(`[title="${realmId}"]`) })
      .filter({ hasText: /Realm invite|You were invited/i });

    await expect
      .poll(
        async () => {
          if (await refresh.isVisible().catch(() => false)) {
            await this.clickWithPassivePromptRetry(refresh);
          }
          return inviteItem.count();
        },
        { timeout: 90_000, intervals: [500, 1_000, 2_000, 5_000] },
      )
      .toBeGreaterThan(0);

    const accept = inviteItem.first().getByTestId("notification-action");
    await expect(accept).toBeVisible({ timeout: 30_000 });
    await accept.click();
    await expect(this.page.getByTestId("notifications-status")).toContainText(
      /Joined Realm/,
      { timeout: 90_000 },
    );
    await expect(
      this.page.getByTestId("notifications-status"),
    ).not.toContainText(/Governance verification pending/, { timeout: 1_000 });
  }

  // Send a message into realmId's chat feed. Asserts chat-status persistence.
  async sendTimelineMessage(realmId: string, body: string) {
    if (!this.page.url().includes(`/chat/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
    }
    await this.dismissPassiveBlockingPrompts();
    await this.page.getByTestId("chat-input").fill(body);
    // A restored history can render before the verified current cut opens the
    // send gate. Wait for the actual gate, then retain the ordinary click.
    await expect(this.page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 90_000 });
    await this.clickWithPassivePromptRetry(
      this.page.getByTestId("send-chat-button"),
    );
    await this.waitForTimelineEventSettled(body);
  }

  // A mention subject is a complete AccountId, so the picker row is selected
  // by both components (identity-handles.md 3.8). Matching on the principal
  // alone would pick the same principal hosted by another Station.
  async sendTimelineMentionMessage(
    realmId: string,
    principalId: string,
    stationId: string,
    suffix: string,
  ): Promise<string> {
    if (!this.page.url().includes(`/chat/${realmId}`)) {
      await this.gotoTimelineRealm(realmId);
    }
    const input = this.page.getByTestId("chat-input");
    await input.fill("");
    await this.page.getByTestId("mention-trigger-button").click();
    const escapeAttr = (value: string) =>
      value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    const suggestion = this.page.locator(
      `[data-testid="mention-suggestion"][data-mention-principal-id="${escapeAttr(principalId)}"][data-mention-station-id="${escapeAttr(stationId)}"]`,
    );
    await expect(suggestion).toBeVisible({ timeout: 30_000 });
    await suggestion.click();
    const prefix = (await input.inputValue()).trimEnd();
    const body = `${prefix} ${suffix.trim()}`.trim();
    await input.fill(body);
    await expect(this.page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 90_000 });
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

  async waitForTimelineEventSettled(body: string, timeout = 90_000) {
    const event = this.timelineEvent(body);
    await expect(event).toBeVisible({ timeout });
    const pending = event.getByTestId("message-send-status");
    const initialTimeout = Math.min(timeout, 15_000);
    const settledWithoutReload = await expect(pending)
      .toHaveCount(0, { timeout: initialTimeout })
      .then(() => true)
      .catch(() => false);
    const acceptedEventId = /^chat-msg-ak:event:[A-Za-z0-9_-]+$/;
    const acceptedWithoutReload = settledWithoutReload && acceptedEventId.test(
      (await event.getAttribute("id")) ?? "",
    );
    if (acceptedWithoutReload) {
      await expect(event.getByTestId("chat-message-error")).toHaveCount(0);
      return;
    }

    // The wasm events adapter returns each bounded stream window as one batch,
    // so an accepted Event can legitimately miss the first optimistic window.
    // Re-enter through the durable projection once: this both proves the write
    // survived reload and avoids treating a missed live-subscribe wakeup as an
    // indefinitely pending write.
    const remainingTimeout = Math.max(5_000, timeout - initialTimeout);
    await this.page.reload({ waitUntil: "domcontentloaded" });
    await this.dismissPassiveBlockingPrompts();
    await expect(this.page.getByTestId("chat-panel")).toBeVisible({
      timeout: Math.min(remainingTimeout, 60_000),
    });
    await expect(event).toBeVisible({ timeout: remainingTimeout });
    await expect(event).toHaveAttribute("id", acceptedEventId, { timeout: remainingTimeout });
    await expect(event.getByTestId("chat-message-error")).toHaveCount(0);
    await expect(pending).toHaveCount(0, {
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
    await revealTimelineEvent(this.page, event);
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
      allowPassivePromptDismissal: true,
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
  const suffix = deviceSuffix(stamp);
  const scid = base58btcEncode(
    Buffer.concat([Buffer.from([0x12, 0x20]), randomBytes(32)]),
  );
  const principalDid = (() => {
    if (!server) {
      return `did:webvh:${scid}:${slug}.example`;
    }
    const serviceDid = solandServiceDid(server);
    const webvh = /^did:webvh:[^:]+:([^:]+)(?::.*)?$/.exec(serviceDid);
    if (webvh?.[1]) {
      return `did:webvh:${scid}:${webvh[1]}:webvh:${slug}`;
    }
    const web = /^did:web:([^:]+)(?::.*)?$/.exec(serviceDid);
    if (web?.[1]) {
      return `did:web:${web[1]}:webvh:${slug}`;
    }
    throw new Error(`unsupported Station DID method: ${serviceDid}`);
  })();
  return {
    name: slug,
    id: projectDidToCoreId(principalDid),
    did: principalDid,
    deviceId: `ak:device:01904100-0000-7000-8000-${suffix}`,
    handle: `@${slug}`,
    displayName: `${prefix} ${stamp}`,
  };
}

// In-flight canonical provisioning per provisioning target. The first
// `ensureRegistered` call for a user drives the co-located coauth account +
// PCR genesis once; concurrent and repeat callers share the same promise.
//
// It caches the *identity*, not a `Promise<void>` whose body writes to one
// user object. With the latter, a second caller holding a different object
// with the same name got a settled promise and an untouched user: same name,
// same cache key, and none of `id`/`did`/`deviceId` rebound — a principal that
// was never registered, failing later and somewhere else.
//
// The key is a `provisioningKey`, not `${server}\0${name}`: `undefined`,
// `"default"` and `"server1"` are three names for one Station and all three are
// live in this suite, so an alias-keyed memo founded the same user once per
// alias and rebound the caller's object to the last one. See
// `provisioning-cache.ts` for the isolation rules and for why this memo is not
// a substitute for the Authority's own duplicate handling.
type ProvisionedPrincipal = ProvisionedIdentity & { session: DpopUserSession };
const provisionedPrincipals = new Map<string, Promise<ProvisionedPrincipal>>();
const canonicalSessionsByGrant = new Map<string, DpopUserSession>();
const provisioningLedger = new ProvisioningLedger();

// Test-owned native identity control is independent from the Event device key.
// Recovery derivation and signing stay in the SDK oracle; no root seed is exposed.
export function registeredSubjectIdentityControl(user: JointUser, server?: SolandKey) {
  const session = Array.from(canonicalSessionsByGrant.values()).find((candidate) =>
    candidate.user.id === user.id && candidate.user.did === user.did &&
    candidate.user.deviceId === user.deviceId &&
    candidate.accountId.station_id === solandServiceId(server));
  const verificationMethod = session?.account.principalRegistrationCheckpoint.root_verification_method;
  if (!session?.account.recoveryKey || typeof verificationMethod !== "string") {
    throw new Error("subject native identity control is unavailable");
  }
  return { did: user.did, verificationMethod, recoveryKey: session.account.recoveryKey };
}

export async function ensureRegistered(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
) {
  // When coauth is reachable, registration goes through the canonical
  // co-located provisioning (account → PCR genesis → verified binding) instead
  // of the bare gate register, so the principal exists with its real DID
  // document, founding device authorization, and committed PCR genesis. The caller's
  // `user` is rebound to the account-bound identity the ceremony returns.
  const coauth = coauthBaseUrl(opts.server);
  if (coauth) {
    const key = provisioningKey({
      stationBaseUrl: solandBaseUrl(opts.server),
      authorityBaseUrl: coauth,
      principalName: user.name,
    });
    // Before the await, so a caller that mixes Station aliases for one user is
    // told where, rather than getting a second principal.
    provisioningLedger.claim(user, key);
    let provisioning = provisionedPrincipals.get(key);
    if (!provisioning) {
      provisioning = (async (): Promise<ProvisionedPrincipal> => {
        const accountRequest = withOperationSelectors(
          await playwrightRequest.newContext({
            ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
          }),
        );
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
          const identity = assertCompleteIdentity(
            {
              id: session.user.id,
              did: session.user.did,
              deviceId: session.user.deviceId,
              handle: session.user.handle,
              displayName: session.user.displayName,
            },
            key,
          );
          return { ...identity, session };
        } finally {
          await accountRequest.dispose();
        }
      })();
      // A failed provisioning must not be cached as a settled rejection: every
      // later caller would inherit one deployment hiccup forever. Dropping the
      // entry lets the next caller try again, which is bounded by how many
      // callers there are rather than by a retry loop.
      provisioning.catch(() => {
        if (provisionedPrincipals.get(key) === provisioning) {
          provisionedPrincipals.delete(key);
        }
      });
      provisionedPrincipals.set(key, provisioning);
    }
    let identity: ProvisionedPrincipal;
    try {
      identity = await provisioning;
    } catch (error) {
      // The claim is released too, or the retry this failure invites would be
      // refused as a second target for the same user.
      provisioningLedger.release(user, key);
      throw error;
    }
    // One founding device belongs to one principal. Two principals under one
    // device id means a response was attributed to the wrong request, which no
    // later assertion in the scenario would name.
    provisioningLedger.recordDevice(identity);
    // Applied per caller, not inside the cached body. This is the line that
    // makes a repeat caller with its own user object get a registered
    // principal rather than an untouched one.
    user.id = identity.id;
    user.did = identity.did;
    user.deviceId = identity.deviceId;
    user.handle = identity.handle;
    user.displayName = identity.displayName;
    return;
  }
  throw new Error("canonical user provisioning requires a configured Account Authority");
}

export async function issueUserSession(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey; deviceId?: string } = {},
): Promise<string> {
  const accepted = Array.from(canonicalSessionsByGrant.values()).find(
    (session) => session.accountId.principal_id === user.id &&
      session.accountId.station_id === solandServiceId(opts.server) &&
      session.user.did === user.did &&
      session.user.deviceId === (opts.deviceId ?? user.deviceId),
  );
  if (accepted) {
    return accepted.grantJwt;
  }
  await ensureRegistered(request, user, opts);
  const authority = coauthBaseUrl(opts.server);
  if (!authority) {
    throw new Error("canonical user sessions require a configured Account Authority");
  }
  const key = provisioningKey({
    stationBaseUrl: solandBaseUrl(opts.server),
    authorityBaseUrl: authority,
    principalName: user.name,
  });
  const provisioned = await provisionedPrincipals.get(key);
  if (!provisioned) {
    throw new Error("canonical user session has no completed provisioning");
  }
  const session = provisioned.session;
  if (session.user.id !== user.id || session.user.deviceId !== (opts.deviceId ?? user.deviceId)) {
    throw new Error("a different device must complete canonical pairing before receiving a session");
  }
  return session.grantJwt;
}

/// Local test custody for a principal's accepted inception update key.
/// Recovery material stays in the oracle input; no root seed is returned.
export async function registeredPrincipalControlIdentity(
  request: APIRequestContext,
  user: JointUser,
  opts: { server?: SolandKey } = {},
) {
  await ensureRegistered(request, user, opts);
  const session = Array.from(canonicalSessionsByGrant.values()).find(
    (candidate) => candidate.accountId.principal_id === user.id &&
      candidate.accountId.station_id === solandServiceId(opts.server) &&
      candidate.user.did === user.did && candidate.user.deviceId === user.deviceId,
  );
  if (!session) throw new Error("native control identity has no accepted registration");
  const checkpoint = session.account.principalRegistrationCheckpoint;
  const verificationMethod = checkpoint.root_verification_method;
  const rootPublicKeyMultibase = checkpoint.root_public_key_multibase;
  if (checkpoint.did !== user.did || typeof verificationMethod !== "string" ||
      typeof rootPublicKeyMultibase !== "string" || !session.account.recoveryKey) {
    throw new Error("accepted registration omitted its native control material");
  }
  return {
    did: user.did,
    verificationMethod,
    rootPublicKeyMultibase,
    recoveryKey: session.account.recoveryKey,
  };
}

export async function createDpopUserSession(
  _request: APIRequestContext,
  prefix: string,
  opts: {
    server?: SolandKey;
    coauthBase?: string;
  } = {},
): Promise<DpopUserSession | undefined> {
  const coauth = opts.coauthBase ?? coauthBaseUrl(opts.server);
  if (!coauth) {
    return undefined;
  }
  // Account registration and OIDC handoff are cookie-bound. A single Playwright
  // `request` fixture is often shared by parallel user creation in one scenario;
  // isolating each flow prevents one account's Set-Cookie from switching the
  // other flow onto the wrong identity-creation lease.
  const accountRequest = withOperationSelectors(
    await playwrightRequest.newContext({
      ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    }),
  );
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
  if (!(opts.coauthBase ?? coauthBaseUrl(opts.server))) {
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
    "ak.self.account.read.describe.v1",
    "ak.self.committed_event.read.scan.v1",
  ]);
  // Consume only the verified DID returned by the atomic registration result.
  expect(
    grant.principalId,
    "handoff session must return the bound principal DID",
  ).toBeTruthy();
  const user = {
    ...seed,
    name: account.handle,
    id: grant.principalId,
    did: account.did,
    handle: `@${account.handle}`,
    displayName: account.displayName,
  };
  // Canonical registration already accepted the account and its founding
  // device. Retain that exact device's signer and proof-bound Standard grant.
  const eventSigningSeedB64url = dpopDeviceSeedB64url(eventSigningKey);
  registerEventSigner({
    actorId: user.id,
    deviceId: user.deviceId,
    verificationMethod: `${user.did}#${user.deviceId}`,
    signingSeedB64url: eventSigningSeedB64url,
  });
  const session = {
    user,
    account,
    grantJwt: grant.grantJwt,
    grantId: grant.grantId,
    accountId: grant.accountId,
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
  registerPrincipalControlRealm(user.id, principalControlRealmId);
  registerPrincipalControlEvents(user.id, session.principalControlEvents);
  // Registration already committed the closed PCR genesis unit as two
  // consecutive Principal Control Realm Commits. Carry their exact committed
  // coordinates as the recovery-material evidence; there is no separate
  // bootstrap write after acceptance.
  const pcrGenesisCommits = account.pcrGenesisCommits.map((commit) => ({
    event_id: commit.event_ref,
    commit_id: commit.commit_id,
    stream_ref: commit.stream_ref,
    stream_position: commit.stream_position,
  }));
  if (pcrGenesisCommits.length !== 2) {
    throw new Error(
      "principal registration outcome omitted its two PCR genesis Commits",
    );
  }
  session.recoveryMaterialEvidence = {
    account_id: session.accountId,
    principal_did: user.did,
    device_id: user.deviceId,
    principal_control_realm_id: principalControlRealmId,
    pcr_genesis_unit: checkpoint.pcr_genesis_unit,
    pcr_genesis_commits: pcrGenesisCommits,
    // Agent provisioning is controller-authority bound.  The browser fixture
    // must carry the exact Station-qualified authority proven by the handoff
    // grant instead of relying on the serde compatibility default (`None`).
    controller_authority: session.accountId,
  };
  // Re-read the typed viewer after the committed genesis and confirm this
  // session's exact device (never devices[0]) is the current signer. Every
  // Event it signs, Control or Data, then uses the same producer proof
  // (device-lifecycle.md section 8.2.2).
  await verifyRegisteredEventSignerDeviceApi(
    request,
    session.grantJwt,
    {
      actorId: session.user.id,
      accountId: session.accountId,
      deviceId: session.user.deviceId,
      verificationMethod: `${session.user.did}#${session.user.deviceId}`,
      server: opts.server,
    },
  );
  canonicalSessionsByGrant.set(session.grantJwt, session);
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

/**
 * Pair a genuinely distinct sibling device for `foundingSession`'s principal
 * through the protocol ceremony and return that device's accepted session.
 *
 * The harness plays both devices with keys it holds itself, as it already does
 * for the founding device (crypto-media/device-lifecycle.md section 2.1):
 * - the candidate generates its own device identity key, HPKE key and a
 *   separate grant-binding key (section 3.3), stages the account-less request
 *   on the Station and finalizes it with its own pending account handoff and
 *   signed target proof (section 2.1.1 items 1-2);
 * - the founding accepted device resolves the out-of-band pairing token,
 *   verifies the target proof and submits its own signed `accepted_device`
 *   authorize Event through `pair_device` (sections 2.1.1 item 4, 2.1.4, 5.4);
 * - the candidate observes `authorized` through status, takes its Standard
 *   grant from `issue_session_grant` with a fresh handoff and its
 *   accepted-device possession proof, and checks the accepted authorize Event
 *   against its own attestation before using the identity (section 5.4.1).
 *
 * The returned session is recorded like the founding one, so
 * `issueUserSession(request, user, { deviceId })` resolves it afterwards. Its
 * Event signer is registered explicit-only: the founding device stays the
 * implicit signer, and callers acting as the sibling name its method.
 */
export async function pairSiblingDeviceSession(
  request: APIRequestContext,
  foundingSession: DpopUserSession,
  opts: { server?: SolandKey } = {},
): Promise<DpopUserSession> {
  const coauth = coauthBaseUrl(opts.server);
  if (!coauth) {
    throw new Error("sibling device pairing requires a configured Account Authority");
  }
  const station = solandBaseUrl(opts.server);
  const founding = foundingSession.user;
  const accountId = foundingSession.accountId;
  const deviceId = newDeviceId();
  // Device identity key and grant-binding key are generated and kept apart
  // (device-lifecycle.md section 3.3); the HPKE key is the device's own too.
  const deviceKey = generateDpopDeviceKey();
  const holderKey = generateDpopDeviceKey();
  const hpkePublicKey = (
    generateKeyPairSync("x25519").publicKey.export({ format: "jwk" }) as { x?: string }
  ).x;
  if (!hpkePublicKey) {
    throw new Error("X25519 key generation returned no public key");
  }
  const deviceSeed = dpopDeviceSeedB64url(deviceKey);
  const candidate = withOperationSelectors(
    await playwrightRequest.newContext({
      ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    }),
  );
  try {
    const stageRequest = {
      new_device_pubkey: {
        kty: "OKP",
        kid: deviceId,
        algorithm: "Ed25519",
        key: deviceKey.publicJwk.x,
      },
      client_nonce: randomBytes(16).toString("base64url"),
    };
    const stage = await expectJsonOk<{
      device_pairing_request_id: string;
      pairing_code: string;
    }>(
      await candidate.post(`${station}/_arkret/open/device-pairing/requests`, {
        headers: { "content-type": "application/json" },
        data: canonicalJson(stageRequest),
      }),
      "stage sibling device pairing",
    );
    const pairingCredential = {
      device_pairing_request_id: stage.device_pairing_request_id,
      pairing_code: stage.pairing_code,
    };

    const pendingHandoff = await createCanonicalAccountHandoff(candidate, coauth, {
      audience: accountId.station_id,
      deviceId,
      deviceKey: holderKey,
      account: {
        handle: foundingSession.account.handle,
        password: foundingSession.account.password,
      },
    });
    expectBoundHandoff(pendingHandoff.binding, founding);
    const targetProof = cotestWire<Record<string, unknown>>(
      "device-pairing-target-proof",
      {
        account_id: accountId,
        stage_request: stageRequest,
        stage_outcome: stage,
        device_signing_seed_b64url: deviceSeed,
        hpke_public_key_b64url: hpkePublicKey,
      },
    );
    const finalizeUrl = `${coauth}/_arkret/gate/account/device-pairing/finalizations`;
    const finalized = await expectJsonOk<{ state?: string }>(
      await candidate.post(finalizeUrl, {
        data: canonicalJson({ ...pairingCredential, target_proof: targetProof }),
        headers: {
          "content-type": "application/json",
          ...accountHandoffHeaders({
            deviceKey: holderKey,
            accountHandoffGrant: pendingHandoff.accountHandoffGrant,
            method: "POST",
            url: finalizeUrl,
          }),
        },
      }),
      "finalize sibling device pairing",
    );
    expect(finalized.state).toBe("ready_for_claim");

    // The founding device receives the short link out of band: the token
    // resolves the staged bootstrap, the proof travels beside it.
    const bootstrap = await expectJsonOk<Record<string, unknown>>(
      await request.post(`${station}/_arkret/open/device-pairing/resolve`, {
        headers: { "content-type": "application/json" },
        data: canonicalJson({
          pairing_token: Buffer.from(
            canonicalJson({ r: stage.device_pairing_request_id, c: stage.pairing_code }),
            "utf8",
          ).toString("base64url"),
        }),
      }),
      "resolve sibling device pairing on the founding device",
    );
    const pairRequest = cotestWire<{
      authorize_event: { event: { event_id: string } };
    }>("device-pairing-approval", {
      bootstrap,
      target_proof: targetProof,
      approving_account_id: accountId,
      approving_did: founding.did,
      approving_device_id: founding.deviceId,
      approving_signing_seed_b64url: foundingSession.eventSigningSeedB64url,
      principal_control_realm_id: foundingSession.principalControlRealmId,
      authorized_generation_ref: await currentDeviceGeneration(
        request,
        foundingSession,
        station,
      ),
    });
    const authorizeEventId = pairRequest.authorize_event.event.event_id;
    const pairUrl = `${coauth}/_arkret/gate/account/device-pair`;
    const paired = await expectJsonOk<{
      device_id?: string;
      authorized_event_ref?: { event_id?: string };
    }>(
      await request.post(pairUrl, {
        headers: {
          ...authHeaders(foundingSession.grantJwt, "POST", pairUrl),
          "content-type": "application/json",
        },
        data: canonicalJson(pairRequest),
      }),
      "pair_device on the founding device",
    );
    expect(paired.device_id).toBe(deviceId);
    expect(paired.authorized_event_ref?.event_id).toBe(authorizeEventId);

    const status = await expectJsonOk<{
      state?: string;
      device_id?: string;
      authorized_event_ref?: { event_id?: string };
    }>(
      await candidate.post(`${station}/_arkret/open/device-pairing/requests/status`, {
        headers: { "content-type": "application/json" },
        data: canonicalJson(pairingCredential),
      }),
      "observe sibling device pairing status",
    );
    expect(status.state).toBe("authorized");
    expect(status.device_id).toBe(deviceId);
    expect(status.authorized_event_ref?.event_id).toBe(authorizeEventId);

    const returningHandoff = await createCanonicalAccountHandoff(candidate, coauth, {
      audience: accountId.station_id,
      deviceId,
      deviceKey: holderKey,
    });
    expectBoundHandoff(returningHandoff.binding, founding);
    const grantUrl = `${coauth}/_arkret/gate/account/session-grants`;
    const grant = await expectJsonOk<{
      session_grant?: string;
      session_grant_id?: string;
      account_id?: { principal_id?: string; station_id?: string };
      audience_id?: string;
      device_id?: string;
    }>(
      await candidate.post(grantUrl, {
        data: canonicalJson(
          cotestWire<Record<string, unknown>>("human-session-grant-request", {
            principal_did: founding.did,
            account_id: accountId,
            device_id: deviceId,
            holder_jkt: holderKey.thumbprint,
            account_subject: returningHandoff.accountSubject,
            account_handoff_grant: returningHandoff.accountHandoffGrant,
            handoff_expires_at: returningHandoff.expiresAt,
            device_signing_seed_b64url: deviceSeed,
          }),
        ),
        headers: {
          "content-type": "application/json",
          ...accountHandoffHeaders({
            deviceKey: holderKey,
            accountHandoffGrant: returningHandoff.accountHandoffGrant,
            method: "POST",
            url: grantUrl,
          }),
        },
      }),
      "issue the sibling device Standard grant",
    );
    const grantJwt = grant.session_grant;
    const grantId = grant.session_grant_id;
    expect(grantJwt, "sibling session grant").toBeTruthy();
    expect(grantId, "sibling session grant id").toBeTruthy();
    expect(grant.account_id).toEqual(accountId);
    expect(grant.audience_id).toBe(accountId.station_id);
    expect(grant.device_id).toBe(deviceId);
    registerRequestAuth(grantJwt!, (method, url) =>
      selfPathGrantHeaders({ deviceKey: holderKey, grantJwt: grantJwt!, method, url }),
    );

    await verifyAcceptedSiblingAuthorization(request, {
      station,
      grantJwt: grantJwt!,
      eventId: authorizeEventId,
      principalDid: founding.did,
      principalControlRealmId: foundingSession.principalControlRealmId,
      targetProof,
    });

    const user = { ...founding, deviceId };
    const eventSigningSeedB64url = deviceSeed;
    registerEventSigner({
      actorId: user.id,
      deviceId,
      verificationMethod: `${user.did}#${deviceId}`,
      signingSeedB64url: eventSigningSeedB64url,
      explicitOnly: true,
    });
    const session: DpopUserSession = {
      user,
      account: foundingSession.account,
      grantJwt: grantJwt!,
      grantId: grantId!,
      accountId,
      grantAudience: accountId.station_id,
      dpopSeedB64url: dpopDeviceSeedB64url(holderKey),
      eventSigningSeedB64url,
      deviceKey: holderKey,
      principalControlRealmId: foundingSession.principalControlRealmId,
      principalControlEvents: foundingSession.principalControlEvents,
    };
    await verifyRegisteredEventSignerDeviceApi(request, session.grantJwt, {
      actorId: user.id,
      accountId,
      deviceId,
      verificationMethod: `${user.did}#${deviceId}`,
      server: opts.server,
    });
    canonicalSessionsByGrant.set(session.grantJwt, session);
    return session;
  } finally {
    await candidate.dispose();
  }
}

function expectBoundHandoff(
  binding: Record<string, unknown>,
  principal: JointUser,
): void {
  expect(binding, "pairing handoff must be bound to the founding principal").toEqual({
    state: "bound",
    principal_id: principal.id,
    did: principal.did,
  });
}

/// The PCR's current device generation, which an `accepted_device` authorize
/// payload asserts (device-lifecycle.md section 5.5.2).
async function currentDeviceGeneration(
  request: APIRequestContext,
  session: DpopUserSession,
  station: string,
): Promise<number> {
  const url = `${station}/_arkret/self/keys/query`;
  const keys = await expectJsonOk<{
    device_generations?: Array<{
      account_id?: unknown;
      generation_state?: { current_device_generation_ref?: unknown };
    }>;
  }>(
    await request.post(url, {
      headers: {
        ...authHeaders(session.grantJwt, "POST", url),
        "content-type": "application/json",
      },
      data: canonicalJson({
        device_keys: [
          { account_id: session.accountId, device_ids: [session.user.deviceId] },
        ],
      }),
    }),
    "read the current PCR device generation",
  );
  const accountKey = canonicalJson(session.accountId);
  const generations = (keys.device_generations ?? []).filter(
    (entry) => canonicalJson(entry.account_id) === accountKey,
  );
  const generation = generations[0]?.generation_state?.current_device_generation_ref;
  if (
    generations.length !== 1 ||
    typeof generation !== "number" ||
    !Number.isSafeInteger(generation) ||
    generation < 1
  ) {
    throw new Error(`keys/query returned no current device generation for ${accountKey}`);
  }
  return generation;
}

/// Target-side check before the sibling identity is used
/// (device-lifecycle.md section 5.4.1): the accepted authorize Event must carry
/// the candidate's own attestation, under the exact account it signed, in the
/// principal control Realm, proven by the approving device it names.
async function verifyAcceptedSiblingAuthorization(
  request: APIRequestContext,
  args: {
    station: string;
    grantJwt: string;
    eventId: string;
    principalDid: string;
    principalControlRealmId: string;
    targetProof: Record<string, unknown>;
  },
): Promise<void> {
  const url = `${args.station}/_arkret/self/committed-events/${args.eventId}`;
  const view = await expectJsonOk<{
    event?: {
      kind?: string;
      realm_id?: string;
      actor_id?: { kind?: string; account_id?: unknown };
      payload?: Record<string, unknown>;
      producer_proof?: { verification_method?: string };
    };
  }>(
    await request.get(url, { headers: authHeaders(args.grantJwt, "GET", url) }),
    "read the accepted sibling authorize Event",
  );
  const event = view.event;
  const payload = event?.payload ?? {};
  const proof = args.targetProof;
  expect(event?.kind).toBe("ak.device.authorize");
  expect(event?.realm_id).toBe(args.principalControlRealmId);
  expect(event?.actor_id?.kind).toBe("account");
  expect(canonicalJson(event?.actor_id?.account_id ?? null)).toBe(
    canonicalJson(proof.account_id),
  );
  for (const member of [
    "device_id",
    "device_public_key_did",
    "hpke_key",
    "algorithms",
    "device_signature",
    "pairing_challenge_transcript_digest",
  ]) {
    expect(
      canonicalJson(payload[member] ?? null),
      `accepted authorize payload ${member} must equal the candidate attestation`,
    ).toBe(canonicalJson(proof[member] ?? null));
  }
  expect(payload.authorization_binding_kind).toBe("accepted_device");
  expect(event?.producer_proof?.verification_method).toBe(
    `${args.principalDid}#${String(payload.authorized_by)}`,
  );
}

/**
 * Complete the server-mediated (path A) pairing fallback on an already
 * authorized device. The QR/link flow deliberately sends no automatic
 * to-device notification; the approving device resolves the out-of-band link,
 * compares its code, then explicitly approves it.
 */
export async function approvePairingLinkOnAuthorizedDevice(
  authorizingDevice: JointUserPage,
  pairingLink: string,
  expectedCode: string,
): Promise<void> {
  expect(pairingLink).toContain("/_arkret/open/device-pairing/resolve#token=");
  await authorizingDevice.gotoAppPanel(
    "/settings/devices/pair",
    "settings-devices-panel",
  );
  await expect(
    authorizingDevice.page.getByTestId("accept-pairing-card"),
  ).toBeVisible({ timeout: 60_000 });
  await authorizingDevice.fillWithPassivePromptRetry(
    authorizingDevice.page.getByTestId("accept-pairing-input"),
    pairingLink,
  );
  await authorizingDevice.clickWithPassivePromptRetry(
    authorizingDevice.page.getByTestId("accept-pairing-resolve-button"),
  );
  await expect(
    authorizingDevice.page.getByTestId("accept-pairing-code"),
  ).toHaveText(expectedCode, { timeout: 90_000 });
  await authorizingDevice.clickWithPassivePromptRetry(
    authorizingDevice.page.getByTestId("accept-pairing-button"),
  );
  await expect(
    authorizingDevice.page.getByTestId("accept-pairing-status"),
  ).toContainText("Device authorization accepted", { timeout: 90_000 });
}

export async function allowExplicitInviteNotifications(
  request: APIRequestContext,
  session: DpopUserSession | string,
  server?: SolandKey,
) {
  const url = `${solandBaseUrl(server)}/_arkret/self/invite-receive-policy`;
  const headers = (method: "GET" | "PUT") =>
    typeof session === "string"
      ? authHeaders(session, method, url)
      : selfPathHeadersForDpopSession(session, method, url);
  const current = await request.get(url, {
    headers: headers("GET"),
  });
  expect(current.status(), await current.text()).toBe(200);
  const policy = (await current.json()) as Record<string, unknown>;
  const allowedKinds = Array.isArray(policy.holder_allowed_introduction_kinds)
    ? policy.holder_allowed_introduction_kinds.filter(
        (kind): kind is string => typeof kind === "string",
      )
    : [];
  const updated = await request.put(url, {
    headers: {
      ...headers("PUT"),
      "content-type": "application/json",
    },
    data: canonicalJson({
      ...policy,
      holder_allowed_introduction_kinds: Array.from(
        new Set([...allowedKinds, "same_station", "explicit_address"]),
      ),
      explicit_address_behavior: "notify",
    }),
  });
  expect(updated.status(), await updated.text()).toBe(200);
}

function canonicalSessionOptions(session: DpopUserSession): OpenUserOpts {
  return {
    grantJwt: session.grantJwt,
    dpopSeedB64url: session.dpopSeedB64url,
    eventSigningSeedB64url: session.eventSigningSeedB64url,
    grantId: session.grantId,
    accountId: session.accountId,
    principalControlRealmId: session.principalControlRealmId,
    grantAudience: session.grantAudience,
    recoveryKey: session.recoveryKey,
    recoveryMaterialEvidence: session.recoveryMaterialEvidence,
    onRecoveryKeyConfigured: (key) => {
      session.recoveryKey = key;
    },
  };
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
    ...canonicalSessionOptions(session),
    autoCompleteRecoveryKeySetup: opts.autoCompleteRecoveryKeySetup,
  });
  // Session injection is applied asynchronously after Inkson acquires the
  // browser-leader lock and initializes its IndexedDB secure store. Always let
  // that boot reach the authenticated shell before a scenario deep-links to a
  // feature route. `prepareMlsDevice: false` skips MLS/recovery preparation;
  // it must not also skip session initialization and race the router's
  // authenticated-login redirect.
  try {
    await page.gotoHome();
    if (opts.prepareMlsDevice !== false) {
      const recoveryKey = await page.completeRecoveryKeySetupIfPrompted();
      if (recoveryKey) session.recoveryKey = recoveryKey;
      await page.acknowledgeRecommendedEncryptionPromptIfVisible();
    }
    return { user: session.user, session, page };
  } catch (error) {
    // Provisioning can fail before the scenario receives the page. Retain
    // its existing redacted diagnostics and release the owned context too.
    await page.close();
    throw error;
  }
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
  if (!opts.neutralLoginConfig && !opts.grantJwt) {
    let session = opts.sessionCredential
      ? canonicalSessionsByGrant.get(opts.sessionCredential)
      : undefined;
    const authority = coauthBaseUrl(opts.server);
    if (!opts.sessionCredential && authority) {
      const key = provisioningKey({
        stationBaseUrl: solandBaseUrl(opts.server),
        authorityBaseUrl: authority,
        principalName: user.name,
      });
      session = (await provisionedPrincipals.get(key))?.session;
    }
    if (session) {
      if (session.accountId.principal_id !== user.id ||
          session.accountId.station_id !== solandServiceId(opts.server) ||
          session.user.deviceId !== user.deviceId || session.user.did !== user.did) {
        throw new Error("browser fixture does not match the canonical account/device session");
      }
      opts = { ...opts, ...canonicalSessionOptions(session), sessionCredential: undefined };
    } else if (opts.sessionCredential) {
      throw new Error("browser fixture credential has no canonical grant and holder material");
    }
  }
  const serverUrl = solandBaseUrl(opts.server);
  const sessionCredential = opts.sessionCredential ?? "";
  const diagnosticsDir = path.join(
    diagnosticsRoot(),
    sanitize(`${Date.now()}-${user.name}`),
  );
  fs.mkdirSync(diagnosticsDir, { recursive: true });
  if (
    opts.grantJwt &&
    opts.dpopSeedB64url &&
    (!opts.accountId || !opts.principalControlRealmId)
  ) {
    throw new Error(
      "Inkson test session injection requires account_id and principal_control_realm_id",
    );
  }
  const sessionInjection =
    opts.grantJwt && opts.dpopSeedB64url
      ? {
          grant_jwt: opts.grantJwt,
          account_id: opts.accountId,
          dpop_seed_b64url: opts.dpopSeedB64url,
          principal_did: user.did,
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
  // The accepted-device seam must retain the real projection coordinates.
  // Invented history and a local wall-clock timestamp poison anti-rollback checks.
  let resolution: PublicPrincipalResolution["resolution_projection"] | undefined;
  if (!opts.neutralLoginConfig) {
    const lookup = withOperationSelectors(await playwrightRequest.newContext({
      ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    }));
    try {
      const url = new URL(`${serverUrl}/_arkret/open/principals/${encodeURIComponent(user.id)}/resolution`);
      url.searchParams.set("station_id", solandServiceId(opts.server));
      const response = await lookup.get(url.toString());
      expect(response.status(), "accepted-device principal resolution lookup").toBe(200);
      const publicResolution = await response.json() as PublicPrincipalResolution;
      expect(publicResolution.account_id).toEqual({
        principal_id: user.id,
        station_id: solandServiceId(opts.server),
      });
      expect(publicResolution.projection_attestation.attestation.resolution_projection)
        .toEqual(publicResolution.resolution_projection);
      resolution = publicResolution.resolution_projection;
    } finally {
      await lookup.dispose();
    }
  }
  const localStorage = [
    {
      name: "inkson.config.v1",
      value: JSON.stringify({
        stations: [serverUrl],
        active_account: opts.neutralLoginConfig
          ? null
          : {
              profile_id: `ak:profile:${randomUUID()}`,
              authority: {
                principal_id: user.id,
                station_id: solandServiceId(opts.server),
              },
              principal_control_realm_id: opts.principalControlRealmId,
              resolution,
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
  }
  const contextOptions = {
    baseURL: inksonBaseUrl(opts.server),
    // Opt-in for running against a live Caddy stack whose TLS is `tls internal`
    // (self-signed). Default off so CI/headless harness runs are unaffected.
    ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    recordHar: {
      path: path.join(diagnosticsDir, "network.har"),
      mode: "minimal" as const,
      content: "omit" as const,
    },
    // Seed the Inkson origin directly. An init script also runs once against
    // the initial opaque about:blank document, where localStorage access throws
    // SecurityError and can make session injection nondeterministic.
  };
  const origin = new URL(inksonBaseUrl(opts.server)).origin;
  const context = opts.persistentUserDataDir
    ? await browser.browserType().launchPersistentContext(opts.persistentUserDataDir, contextOptions)
    : await browser.newContext({
        ...contextOptions,
        storageState: { cookies: [], origins: [{ origin, localStorage }] },
      });
  if (opts.persistentUserDataDir && !opts.resumePersistentProfile) {
    // Seed only the first launch. A resumed profile must use its own durable
    // localStorage and IndexedDB, including newer recovery-policy evidence.
    await context.addInitScript(({ origin, entries }) => {
      if (window.location.origin !== origin) return;
      for (const { name, value } of entries) {
        if (window.localStorage.getItem(name) === null) {
          window.localStorage.setItem(name, value);
        }
      }
    }, { origin, entries: localStorage });
  }
  if (!opts.persistentUserDataDir) {
    const seededStorageState = await context.storageState();
    const seededOrigin = seededStorageState.origins.find(({ origin: saved }) => saved === origin);
    const seededNames = new Set(seededOrigin?.localStorage.map(({ name }) => name) ?? []);
    if (!seededNames.has("inkson.config.v1") ||
        (sessionInjection && !seededNames.has("inkson.test.session_injection.v1"))) {
      await context.close();
      throw new Error("Inkson browser context is missing its seeded session config");
    }
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
  const page = context.pages()[0] ?? await context.newPage();
  // With real-grant injection enabled, device enrollment triggers inkson's
  // mandatory "Set up your 24-word Recovery Key" modal ("required before
  // encryption"). It can pop asynchronously mid-flow and covers the page, so a
  // one-shot dismiss in the nav helpers races it. Register a Playwright locator
  // handler that auto-completes it whenever it blocks an action: read the
  // generated key, mirror it into the confirm field, and save. Idempotent and a
  // no-op when the modal is absent.
  if (opts.autoCompleteRecoveryKeySetup !== false) {
    await installRecoverySetupHandler(page, opts.onRecoveryKeyConfigured);
  }
  const consoleLines = new SessionDiagnostics();
  const networkLines = new SessionDiagnostics();
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
    if (response.status() === 200 &&
        new URL(response.url()).pathname === "/_arkret/self/account/viewer") {
      const observedAt = Date.now();
      void response.json().then((viewer) => {
        networkLines.push(JSON.stringify({
          ts: new Date(observedAt).toISOString(),
          ...accountViewerHandleDiagnostic(viewer, user.id, observedAt),
        }), "critical");
      }).catch(() => {
        networkLines.push(JSON.stringify({
          ts: new Date(observedAt).toISOString(),
          type: "account-viewer-handle-unreadable",
        }), "critical");
      });
    }
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
          accountId: opts.accountId!,
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
    onRecoveryKeyConfigured: opts.onRecoveryKeyConfigured,
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
async function closeUser(session: UserSession) {
  try {
    await finishRecoverySetupBeforeClose(session.page);
  } finally {
    flushUserDiagnostics(session);
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
}

function flushUserDiagnostics(session: UserSession) {
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
