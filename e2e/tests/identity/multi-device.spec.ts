import {
  expect,
  test,
  type Browser,
  type Page,
} from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl } from "../../helpers/env";
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
  openDpopUserPageFromSession,
  openUserPage,
  selfPathHeadersForDpopSession,
  type JointUserPage,
  uniqueUser,
} from "../../helpers/users";
import { canonicalJson, typedId } from "../../helpers/coland-api";

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
      "the recovery account must have a committed PCR genesis",
    ).toBeTruthy();
    const foundingFlow = await openDpopUserPageFromSession(
      browser,
      foundingSession,
      { prepareMlsDevice: false, autoCompleteRecoveryKeySetup: false },
    );
    expect(
      foundingFlow,
      "the founding device must be available to publish the genesis recovery policy",
    ).toBeTruthy();
    // Publish the accepted PCR recovery policy through the product UI.
    // Its Recovery Key is independent of the registration DID control key.
    const activeRecoveryKey =
      await foundingFlow!.page.completeRecoveryKeySetupIfPrompted(120_000);
    expect(Boolean(activeRecoveryKey), "the policy key must be saved through the product UI").toBe(true);

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
        .fill(activeRecoveryKey!);
      await recoveryPanel
        .getByRole("button", { name: "Authorize this device" })
        .click();

      const shell = replacement.page.getByTestId("client-shell");
      const terminalFailure = recoveryPanel
        .getByRole("status")
        .filter({ hasText: "Recovery could not finish:" });
      await Promise.race([
        expect(shell).toBeVisible({ timeout: 300_000 }),
        expect(terminalFailure)
          .toBeVisible({ timeout: 300_000 })
          .then(async () => {
            throw new Error(
              `${await terminalFailure.textContent()}; observed ${JSON.stringify(responses)}`,
            );
          }),
      ]);
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
      // `identity/security-transactions.md` §2.3: a RecoveryTransaction has
      // exactly one client-attested step. The old
      // `submit_reanchor_unit` -> `issue_terminal_receipt` pair is gone, so two
      // successful continues would mean the two-step shape survived somewhere.
      const continuePath =
        /^\/_arkret\/self\/security-transactions\/[^/]+\/continue$/;
      expectSuccessfulPathMatch(responses, "POST", continuePath);
      expectExactlyOnePathMatch(responses, "POST", continuePath);

      // Both re-anchor Events and the terminal result enter through that one
      // continue step, as two consecutive Principal Control Realm Commits.
      // Before it there is no accepted Event: recovery never submits through
      // the ordinary Event surface.
      const beforeCommit = responses.slice(
        0,
        responses.findIndex(
          (hit) => hit.method === "POST" && continuePath.test(hit.pathname),
        ),
      );
      expectNoWriteToPaths(beforeCommit, ["/_arkret/self/events"]);

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
      const oldGenerationProbeUrl = `${colandBaseUrl()}/_arkret/self/account/current-principal`;
      const oldGenerationProbe = await request.post(oldGenerationProbeUrl, {
        headers: {
          ...selfPathHeadersForDpopSession(
            foundingSession!,
            "POST",
            oldGenerationProbeUrl,
          ),
          "content-type": "application/json",
        },
        data: canonicalJson({
          request_id: typedId("request"),
          account_id: foundingSession!.accountId,
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
      await Promise.allSettled([
        replacement.close(),
        foundingFlow!.page.close(),
      ]);
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
  await page.getByTestId("login-server-url").fill(colandBaseUrl());
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

function expectExactlyOnePathMatch(
  responses: ProtocolResponse[],
  method: string,
  pathname: RegExp,
): void {
  const accepted = responses.filter(
    (hit) =>
      hit.method === method &&
      pathname.test(hit.pathname) &&
      hit.status >= 200 &&
      hit.status < 300,
  );
  expect(
    accepted.length,
    `expected exactly one successful ${method} ${pathname}; observed ${JSON.stringify(responses)}`,
  ).toBe(1);
}

/**
 * Assert that no accepted write reached any of `prefixes`.
 *
 * Reads are allowed through: the point is that recovery produces no
 * authoritative Event outside its own terminal commit, not that the
 * client never looks at those surfaces.
 */
function expectNoWriteToPaths(
  responses: ProtocolResponse[],
  prefixes: string[],
): void {
  const writes = responses.filter(
    (hit) =>
      hit.method !== "GET" &&
      hit.method !== "QUERY" &&
      hit.status >= 200 &&
      hit.status < 300 &&
      prefixes.some((prefix) => hit.pathname.startsWith(prefix)),
  );
  expect(
    writes,
    `recovery wrote through a surface outside its terminal commit: ${JSON.stringify(writes)}`,
  ).toEqual([]);
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
