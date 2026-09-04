import {
  expect,
  test,
  type Browser,
  type Page,
} from "../../helpers/arkret-test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  registerCoauthPasswordAccount,
  type CoauthPasswordAccount,
} from "../../helpers/coauth-register";
import {
  serverLoginViaCoauth,
  submitCoauthPasswordCredentials,
} from "../../helpers/real-oidc-login";
import {
  approvePairingLinkOnAuthorizedDevice,
  assertJointStackNotRequired,
  createDpopUserSessionForAccount,
  openDpopUserPageForAccount,
  openUserPage,
  selfPathHeadersForDpopSession,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";
import { canonicalJson } from "../../helpers/soland-api";

test.describe.configure({ mode: "serial" });

test.describe("fresh-browser device entry paths @fully-implemented", () => {
  test("a second-device login stays unauthorized until the first device explicitly approves it", async ({
    browser,
    request,
  }) => {
    test.setTimeout(420_000);
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("accepted-device login pairing");
      test.skip(true, "joint Coauth endpoint is unavailable");
      return;
    }

    const account = await registerCoauthPasswordAccount(request, coauth);
    const firstDeviceFlow = await openDpopUserPageForAccount(
      browser,
      request,
      "device-entry-first",
      account,
      {
        coauthBase: coauth,
        prepareMlsDevice: false,
      },
    );
    expect(
      firstDeviceFlow,
      "the registered account must expose its accepted founding device",
    ).toBeTruthy();
    const firstDevice = firstDeviceFlow!.page;
    const secondDevice = await openFreshLoginBrowser(
      browser,
      "device-entry-second",
    );
    const sessions: JointUserPage[] = [firstDevice, secondDevice];
    const firstDeviceResponses = collectProtocolResponses(firstDevice.page);
    const secondDeviceResponses = collectProtocolResponses(secondDevice.page);

    try {
      await loginFreshBrowserToDeviceSetup(secondDevice.page, account);

      await expect(
        secondDevice.page.getByTestId("device-setup-required"),
      ).toBeVisible({ timeout: 120_000 });
      // The device-setup panel MUST say that the account login by itself
      // authorized nothing. The exact sentence is product copy, not spec text
      // (crypto-media/device-lifecycle.md registers no wording), so this
      // asserts the invariant clause the panel is required to carry rather
      // than a full sentence that drifts with every copy edit.
      await expect(
        secondDevice.page.getByText(
          "Login alone cannot authorize a new device, and no session was issued.",
        ),
      ).toBeVisible();
      await expect(secondDevice.page.getByTestId("client-shell")).toHaveCount(
        0,
      );

      await secondDevice.page
        .getByTestId("device-setup-pairing-start")
        .click();
      const pairingCode = secondDevice.page.getByTestId(
        "device-setup-pairing-code",
      );
      await expect(pairingCode).toBeVisible({ timeout: 30_000 });
      const code = (await pairingCode.textContent())?.trim() ?? "";
      expect(code).not.toBe("");
      const pairingLink = await secondDevice.page
        .getByTestId("device-setup-pairing-link")
        .inputValue();
      await approvePairingLinkOnAuthorizedDevice(
        firstDevice,
        pairingLink,
        code,
      );

      await secondDevice.page
        .getByTestId("device-setup-pairing-status")
        .click();
      await expect(
        secondDevice.page.getByTestId("device-setup-status"),
      ).toContainText("Device authorization is accepted", {
        timeout: 90_000,
      });

      expectSuccessfulOperation(
        secondDeviceResponses,
        "POST",
        "/_arkret/open/device-pairing/requests",
      );
      expectSuccessfulOperation(
        firstDeviceResponses,
        "POST",
        "/_arkret/gate/account/device-pair",
      );
      expect(
        [...firstDeviceResponses, ...secondDeviceResponses].some((hit) =>
          hit.pathname.includes("/recovery-sessions"),
        ),
        "accepted-device pairing must not silently execute root recovery",
      ).toBe(false);

      await secondDevice.page
        .getByRole("link", { name: "Sign in again after approval" })
        .click();
      await expect(secondDevice.page.getByTestId("login-panel")).toBeVisible({
        timeout: 30_000,
      });
      await serverLoginViaCoauth(secondDevice.page, account);
      await expect(secondDevice.page.getByTestId("client-shell")).toBeVisible({
        timeout: 120_000,
      });
      await expect(
        secondDevice.page.getByTestId("device-setup-required"),
      ).toHaveCount(0);
      const acceptedDeviceId = await configuredDeviceId(secondDevice.page);
      expect(acceptedDeviceId).toMatch(/^ak:device:/);
      expect(acceptedDeviceId).not.toBe(account.genesisDeviceId);
    } finally {
      await Promise.allSettled(sessions.map((session) => session.close()));
    }
  });

  test("a fresh browser can use the 24-word Recovery Key instead of first-device approval", async ({
    browser,
    request,
  }) => {
    test.setTimeout(600_000);
    const coauth = coauthBaseUrl();
    if (!coauth) {
      assertJointStackNotRequired("24-word fresh-device recovery");
      test.skip(true, "joint Coauth endpoint is unavailable");
      return;
    }

    const account = await registerCoauthPasswordAccount(request, coauth);
    const foundingSession = await createDpopUserSessionForAccount(
      request,
      "device-recovery-founding",
      account,
      { coauthBase: coauth },
    );
    expect(
      foundingSession,
      "the recovery account must have a sealed PCR genesis and active policy",
    ).toBeTruthy();

    const replacement = await openFreshLoginBrowser(
      browser,
      "device-recovery-replacement",
    );
    const responses = collectProtocolResponses(replacement.page);
    try {
      await loginFreshBrowserToDeviceSetup(replacement.page, account);
      await expect(
        replacement.page.getByTestId("device-setup-required"),
      ).toBeVisible({ timeout: 120_000 });

      await replacement.page
        .getByTestId("device-setup-use-recovery-key")
        .click();
      const recoveryPanel = replacement.page.getByTestId(
        "pcr-policy-device-recovery",
      );
      await expect(recoveryPanel).toBeVisible();
      await expect(recoveryPanel).toContainText(
        "No approval from another device or administrator is required.",
      );
      await recoveryPanel
        .locator("#root-recovery-words")
        .fill(account.recoveryKey);
      await recoveryPanel
        .getByRole("button", { name: "Authorize this device" })
        .click();

      await expect(replacement.page.getByTestId("client-shell")).toBeVisible({
        timeout: 300_000,
      });
      await expect(replacement.page.getByTestId("onboarding-panel")).toHaveCount(
        0,
      );
      await expect(replacement.page.getByTestId("login-panel")).toHaveCount(0);

      expectSuccessfulOperation(
        responses,
        "POST",
        "/_arkret/root/identity/recovery-sessions",
      );
      expectSuccessfulPathMatch(
        responses,
        "POST",
        /^\/_arkret\/root\/identity\/recovery-sessions\/[^/]+\/proofs$/,
      );
      expectSuccessfulOperation(
        responses,
        "POST",
        "/_arkret/self/security-transactions",
      );
      expectSuccessfulPathMatch(
        responses,
        "POST",
        /^\/_arkret\/self\/security-transactions\/[^/]+\/continue$/,
      );
      expectSuccessfulOperation(
        responses,
        "POST",
        "/_arkret/gate/account/recovery-session-grants/issue",
      );
      expect(
        responses.some((hit) =>
          hit.pathname.includes("/_arkret/gate/account/device-pair"),
        ),
        "Recovery Key replacement must not depend on first-device approval",
      ).toBe(false);

      const replacementDeviceId = await configuredDeviceId(replacement.page);
      expect(replacementDeviceId).toMatch(/^ak:device:/);
      expect(replacementDeviceId).not.toBe(account.genesisDeviceId);

      // Re-anchor changes the durable device generation. A non-GET request
      // forces fresh grant introspection, so the superseded founding device
      // cannot survive through a resource-server cache window.
      const oldGenerationProbeUrl = `${solandBaseUrl()}/_arkret/self/events/frontier`;
      const oldGenerationProbe = await request.fetch(oldGenerationProbeUrl, {
        method: "QUERY",
        headers: {
          ...selfPathHeadersForDpopSession(
            foundingSession!,
            "QUERY",
            oldGenerationProbeUrl,
          ),
          "content-type": "application/json",
        },
        data: canonicalJson({
          actor_id: foundingSession!.user.id,
          realm_id: foundingSession!.principalControlRealmId,
        }),
      });
      expect(
        [401, 403],
        `old-generation grant remained usable: ${await oldGenerationProbe.text()}`,
      ).toContain(oldGenerationProbe.status());

      await replacement.page.reload({ waitUntil: "domcontentloaded" });
      await expect(replacement.page.getByTestId("client-shell")).toBeVisible({
        timeout: 120_000,
      });
      await expect(replacement.page.getByTestId("login-panel")).toHaveCount(0);
    } finally {
      await replacement.close();
    }
  });
});

type ProtocolResponse = {
  method: string;
  pathname: string;
  status: number;
};

async function openFreshLoginBrowser(
  browser: Browser,
  label: string,
): Promise<JointUserPage> {
  return openUserPage(browser, uniqueUser(label), {
    neutralLoginConfig: true,
    autoCompleteRecoveryKeySetup: false,
  });
}

async function loginFreshBrowserToDeviceSetup(
  page: Page,
  account: CoauthPasswordAccount,
): Promise<void> {
  await page.goto("/login", {
    waitUntil: "domcontentloaded",
  });
  await page.getByTestId("login-server-url").fill(solandBaseUrl());
  await page.getByTestId("start-server-login-button").click();
  await submitCoauthPasswordCredentials(page, account);

  const approve = page.getByTestId("coauth-oauth-approve");
  const consentShown = await approve
    .waitFor({ state: "visible", timeout: 20_000 })
    .then(() => true)
    .catch(() => false);
  if (consentShown) {
    await approve.click();
  }

  await expect(page.getByTestId("device-setup-required")).toBeVisible({
    timeout: 120_000,
  });
  await expect(page.getByTestId("client-shell")).toHaveCount(0);
}

function collectProtocolResponses(page: Page): ProtocolResponse[] {
  const responses: ProtocolResponse[] = [];
  page.on("response", (response) => {
    const request = response.request();
    const url = new URL(response.url());
    if (!url.pathname.startsWith("/_arkret/")) {
      return;
    }
    responses.push({
      method: request.method(),
      pathname: url.pathname,
      status: response.status(),
    });
  });
  return responses;
}

function expectSuccessfulOperation(
  responses: ProtocolResponse[],
  method: string,
  pathname: string,
): void {
  expectSuccessfulPathMatch(
    responses,
    method,
    new RegExp(`^${escapeRegExp(pathname)}$`),
  );
}

function expectSuccessfulPathMatch(
  responses: ProtocolResponse[],
  method: string,
  pathname: RegExp,
): void {
  expect(
    responses.some(
      (hit) =>
        hit.method === method &&
        pathname.test(hit.pathname) &&
        hit.status >= 200 &&
        hit.status < 300,
    ),
    `expected successful ${method} ${pathname}; observed ${JSON.stringify(responses)}`,
  ).toBe(true);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function configuredDeviceId(page: Page): Promise<string> {
  return page.evaluate(() => {
    const config = JSON.parse(
      window.localStorage.getItem("inkson.config.v1") ?? "{}",
    ) as { active_account?: { device_id?: string } };
    return config.active_account?.device_id ?? "";
  });
}
