import { expect, test, type APIRequestContext, type Browser } from "./arkret-test";
import type { JointUsersFixture } from "./joint-fixture";
import { coauthBaseUrl, solandBaseUrl } from "./env";
import { serverLoginViaCoauth, submitCoauthPasswordCredentials } from "./real-oidc-login";
import { approvePairingLinkOnAuthorizedDevice, type DpopUserSession, type JointUserPage, openUserPage, selfPathHeadersForDpopSession, uniqueUser } from "./users";

export async function openAndPairSecondController(
  browser: Browser,
  request: APIRequestContext,
  jointRealm: JointUsersFixture,
): Promise<{
  page: JointUserPage;
  accountId: DpopUserSession["accountId"];
  deviceId: string;
}> {
  const coauth = coauthBaseUrl();
  expect(coauth, "joint stack must expose Coauth for Device 2").toBeTruthy();
  const device = await openUserPage(
    browser,
    uniqueUser(`sidecar-controller-device-2-${Date.now()}`),
    { neutralLoginConfig: true, autoCompleteRecoveryKeySetup: false },
  );
  try {
    await jointRealm.alicePage.gotoHome();
    await device.page.goto("/login", {
      waitUntil: "domcontentloaded",
    });
    await device.page.getByTestId("login-server-url").fill(solandBaseUrl());
    await device.page.getByTestId("start-server-login-button").click();
    await submitCoauthPasswordCredentials(device.page, jointRealm.aliceSession.account);
    const approve = device.page.getByTestId("coauth-oauth-approve");
    const consentShown = await approve
      .waitFor({ state: "visible", timeout: 20_000 })
      .then(() => true)
      .catch(() => false);
    if (consentShown) {
      await approve.click();
    }
    await expect(device.page.getByTestId("device-setup-required")).toBeVisible({
      timeout: 120_000,
    });
    await expect(device.page.getByTestId("client-shell")).toHaveCount(0);
    await device.page.getByTestId("device-setup-pairing-start").click();
    const pairingCode = device.page.getByTestId("device-setup-pairing-code");
    await expect(pairingCode).toBeVisible({ timeout: 30_000 });
    const code = (await pairingCode.textContent())?.trim() ?? "";
    expect(code).not.toBe("");
    const pairingLink = await device.page
      .getByTestId("device-setup-pairing-link")
      .inputValue();
    await approvePairingLinkOnAuthorizedDevice(
      jointRealm.alicePage,
      pairingLink,
      code,
    );

    await device.page.getByTestId("device-setup-pairing-status").click();
    await expect(device.page.getByTestId("device-setup-status")).toContainText(
      "Device authorization is accepted",
      { timeout: 90_000 },
    );
    await device.page.getByRole("link", { name: "Sign in again after approval" }).click();
    await expect(device.page.getByTestId("login-panel")).toBeVisible({ timeout: 30_000 });
    await serverLoginViaCoauth(device.page, jointRealm.aliceSession.account);
    await expect(device.page.getByTestId("device-setup-required")).toHaveCount(0);
    const identity = await device.page.evaluate(() => {
      const config = JSON.parse(window.localStorage.getItem("inkson.config.v1") ?? "{}");
      return {
        accountId: config.active_account?.authority,
        deviceId: config.active_account?.device_id ?? "",
      };
    });
    expect(identity.accountId).toEqual(jointRealm.aliceSession.accountId);
    expect(identity.deviceId).toMatch(/^ak:device:/);
    expect(identity.deviceId).not.toBe(jointRealm.alice.deviceId);
    const viewerUrl = `${solandBaseUrl()}/_arkret/self/account/viewer`;
    await expect.poll(async () => {
      const response = await request.get(viewerUrl, {
        headers: selfPathHeadersForDpopSession(jointRealm.aliceSession, "GET", viewerUrl),
      });
      if (!response.ok()) return `http-${response.status()}`;
      const body = await response.json();
      return body.devices?.find(
        (candidate: { device_id?: string; status?: string }) =>
          candidate.device_id === identity.deviceId,
      )?.status ?? "missing";
    }, { timeout: 90_000, intervals: [500, 1_000, 2_000] }).toBe("active");
    await device.gotoHome();
    await device.acknowledgeRecommendedEncryptionPromptIfVisible(30_000);
    return { page: device, ...identity };
  } catch (error) {
    // Capture public browser coordination state without tokens or page content.
    try {
      const locks = await device.page.evaluate(async () => {
        const snapshot = await navigator.locks.query();
        const writerLocks = (entries: LockInfo[] | undefined) =>
          (entries ?? []).filter(({ name }) => name === "inkson:web-writer:v1")
            .map(({ name, mode, clientId }) => ({ name, mode, clientId }));
        return {
          held: writerLocks(snapshot.held),
          pending: writerLocks(snapshot.pending),
          follower: document.querySelector('[data-testid="web-leader-follower"]') !== null,
          navigationType: (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type,
        };
      });
      const pages = device.page.context().pages().map((page) => {
        const url = new URL(page.url());
        return {
          origin: url.origin,
          route: ["/", "/login", "/auth/callback"].includes(url.pathname)
            ? url.pathname : "[other]",
        };
      });
      await test.info().attach("paired-controller-browser-coordination", {
        body: JSON.stringify({ locks, pages }, null, 2),
        contentType: "application/json",
      });
    } catch {
      // A closed document must not replace the original pairing failure.
    }
    await device.close();
    throw error;
  }
}
