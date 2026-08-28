import { expect, test, type Page } from "../../helpers/arkret-test";
import {
  coauthBaseUrl,
  optionalEnv,
  realOidcLoginHandle,
  realOidcLoginPassword,
} from "../../helpers/env";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import {
  hardLogoutViaAccountMenu,
  serverLoginViaCoauth,
  type RealOidcAccount,
} from "../../helpers/real-oidc-login";
import {
  assertJointStackNotRequired,
  openUserPage,
  uniqueUser,
  type JointUserPage,
} from "../../helpers/users";
import { encodeEd25519PubkeyMultibase } from "../../helpers/encoding";
import { projectDidToCoreId } from "../../helpers/soland-api";
import { jwkThumbprintEd25519 } from "../../helpers/session-grant-dpop";

type CapturedGrant = {
  jwt: string;
  jkt: string;
};

test.describe.configure({ mode: "serial" });

test.describe("holder device key lifecycle separation @fully-implemented", () => {
  const coauth = coauthBaseUrl();
  const optIn = optionalEnv("COTEST_REAL_OIDC_LOGIN");

  test("real OIDC hard re-login rotates cnf.jkt without rotating the device event signer @returning-device-key-gate", async ({
    browser,
    request,
  }) => {
    test.setTimeout(420_000);
    test.skip(!coauth, "coauth not started for this run");
    if (!optIn) {
      assertJointStackNotRequired("device key lifecycle real OIDC login");
      test.skip(
        true,
        "set COTEST_REAL_OIDC_LOGIN=1 to opt into the real browser login ceremony",
      );
    }

    const envHandle = realOidcLoginHandle();
    const envPassword = realOidcLoginPassword();
    const configuredDid = optionalEnv("COTEST_REAL_OIDC_PRINCIPAL_DID");
    const registeredAccount =
      envHandle && envPassword
        ? undefined
        : await registerCoauthPasswordAccount(request, coauth!);
    const account: RealOidcAccount = registeredAccount ?? {
      handle: envHandle!,
      password: envPassword!,
    };
    const principalDid = registeredAccount?.did ?? configuredDid;
    test.skip(
      !principalDid,
      "COTEST_REAL_OIDC_PRINCIPAL_DID is required with a preconfigured OIDC account",
    );
    const returningUser = uniqueUser("oidc-key-life");
    returningUser.did = principalDid!;
    returningUser.id =
      registeredAccount?.id ?? projectDidToCoreId(principalDid!);
    if (registeredAccount) {
      returningUser.deviceId = registeredAccount.genesisDeviceId;
    }
    const jointPage = await openUserPage(browser, returningUser);
    const page = jointPage.page;
    const grants = observeSessionGrants(page);
    const refreshes = observeSessionGrantRefreshes(page);
    const stamp = Date.now();
    const boardTitle = `OIDC Key Board ${stamp}`;
    const listTitle = `Todo-${stamp}`;
    const cardTitle = `OIDC encrypted card ${stamp}`;
    const cardDescription = `OIDC private detail ${stamp}`;
    const postReloginMessage = `OIDC post relogin message ${stamp}`;

    try {
      await test.step("first real OIDC login establishes the device identity", async () => {
        await jointPage.gotoLogin();
        await serverLoginViaCoauth(page, account);
      });

      let activeGrant = await grants.waitForLatest();

      let realmId = "";
      let boardId = "";
      let firstSignerDid = "";
      let firstSignerPublicKey = "";
      await test.step("the first session creates readable encrypted card content", async () => {
        await jointPage.gotoHome();
        await jointPage.completeRecoveryKeySetupIfPrompted();
        await jointPage.acknowledgeRecommendedEncryptionPromptIfVisible();
        realmId = await jointPage.createRealm({
          title: `OIDC key lifecycle ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
          historyAccess: "since_join",
          encryptionProfile: "mls_rfc9420",
        });
        boardId = await buildEncryptedBoardListCard(
          jointPage,
          realmId,
          boardTitle,
          listTitle,
          cardTitle,
        );
        await addEncryptedDescription(page, cardTitle, cardDescription);
        await assertCardDescription(
          jointPage,
          realmId,
          boardId,
          cardTitle,
          cardDescription,
        );
        firstSignerDid = await currentSettingsSignerDid(page);
        firstSignerPublicKey = didKeyMultibase(firstSignerDid);
      });

      await test.step("new-device pairing advertises the device identity key, not the grant-binding key", async () => {
        await page.goto("/settings/devices/pair", {
          waitUntil: "domcontentloaded",
        });
        await expect(page.getByTestId("pair-device-card")).toBeVisible({
          timeout: 120_000,
        });
        await page.getByTestId("pair-device-start-button").click();
        const secret = page.getByTestId("pair-device-secret");
        await expect(secret).toBeVisible({ timeout: 30_000 });
        const pairingLink = new URL(await secret.inputValue());
        expect(pairingLink.search).toBe("");
        const pairingToken = new URLSearchParams(pairingLink.hash.slice(1)).get(
          "token",
        );
        expect(
          pairingToken,
          "pairing token must be carried in the URL fragment",
        ).toBeTruthy();
        const resolve = await request.post(
          new URL(
            "/_arkret/open/device-pairing/resolve",
            pairingLink.origin,
          ).toString(),
          { data: { pairing_token: pairingToken } },
        );
        expect(resolve.status(), await resolve.text()).toBe(200);
        const bootstrap = (await resolve.json()) as {
          new_device_pubkey?: {
            key?: string;
            kid?: string;
            public_key?: string;
          };
        };
        const pairingPublicKey = bootstrap.new_device_pubkey?.key;
        expect(
          pairingPublicKey,
          "pairing request must publish the device identity signing public key",
        ).toBeTruthy();
        expect(
          encodeEd25519PubkeyMultibase(
            Buffer.from(pairingPublicKey as string, "base64url"),
          ),
          "pairing request raw key must encode to the device identity signing multibase",
        ).toBe(firstSignerPublicKey);
        expect(
          bootstrap.new_device_pubkey?.key,
          "pairing request must not publish the grant-binding cnf.jkt",
        ).not.toBe(activeGrant.jkt);
        expect(bootstrap.new_device_pubkey?.public_key).toBeUndefined();
      });

      await test.step("soft refresh preserves the grant-binding key and device signer", async () => {
        const refreshStartIndex = grants.count();
        await reloadWithSessionGrantExpiringSoon(page, activeGrant.jwt, 60);
        await expect(page.getByTestId("client-shell")).toBeVisible({
          timeout: 120_000,
        });
        await expect(page.getByTestId("login-panel")).toHaveCount(0);

        const refreshedGrant = await refreshes.waitForLatest();
        expect(
          refreshedGrant.jwt,
          "soft refresh must rotate the grant JWT",
        ).not.toBe(activeGrant.jwt);
        expect(
          refreshedGrant.jkt,
          "soft refresh must keep the same grant-binding DPoP key",
        ).toBe(activeGrant.jkt);
        await grants.waitForDifferentAfter(activeGrant.jwt, refreshStartIndex);
        const signerAfterRefresh = await currentSettingsSignerDid(page);
        expect(
          signerAfterRefresh,
          "soft refresh must not rotate the device event signer",
        ).toBe(firstSignerDid);
        activeGrant = refreshedGrant;
      });

      await test.step("hard logout clears the browser session", async () => {
        await hardLogoutViaAccountMenu(jointPage);
      });

      const reloginStartIndex = grants.count();
      await test.step("returning real OIDC login gets a fresh grant-binding key", async () => {
        await serverLoginViaCoauth(page, account);
      });
      const secondGrant = await grants.waitForDifferentAfter(
        activeGrant.jwt,
        reloginStartIndex,
      );
      expect(
        secondGrant.jkt,
        "hard re-login must rotate the grant-bound DPoP key",
      ).not.toBe(activeGrant.jkt);

      await test.step("the durable device event signer survives the hard re-login", async () => {
        const secondSignerDid = await currentSettingsSignerDid(page);
        expect(
          secondSignerDid,
          "event signer did:key should be stable across re-login",
        ).toBe(firstSignerDid);
      });

      await test.step("old encrypted content still decrypts and new events verify", async () => {
        await jointPage.completeRecoveryKeySetupIfPrompted(1_000);
        await assertCardDescription(
          jointPage,
          realmId,
          boardId,
          cardTitle,
          cardDescription,
        );
        await jointPage.sendTimelineMessage(realmId, postReloginMessage);
        await expect(jointPage.timelineEvent(postReloginMessage)).toBeVisible({
          timeout: 45_000,
        });
      });
    } finally {
      await jointPage.close();
    }
  });
});

function observeSessionGrants(page: Page) {
  const seen: CapturedGrant[] = [];
  page.on("request", (request) => {
    const authorization = request.headers().authorization;
    const jwt = authorization?.match(/^DPoP\s+(.+)$/i)?.[1];
    if (!jwt) return;
    const jkt = grantJkt(jwt);
    if (!jkt) return;
    if (seen.at(-1)?.jwt !== jwt) {
      seen.push({ jwt, jkt });
    }
  });
  return {
    count: () => seen.length,
    async waitForLatest(): Promise<CapturedGrant> {
      await expect
        .poll(() => seen.at(-1)?.jkt ?? "", { timeout: 90_000 })
        .not.toBe("");
      return seen.at(-1)!;
    },
    async waitForDifferentAfter(
      previousJwt: string,
      startIndex: number,
    ): Promise<CapturedGrant> {
      await expect
        .poll(
          () =>
            seen
              .slice(startIndex)
              .filter((grant) => grant.jwt !== previousJwt)
              .at(-1)?.jkt ?? "",
          { timeout: 120_000 },
        )
        .not.toBe("");
      return seen
        .slice(startIndex)
        .filter((grant) => grant.jwt !== previousJwt)
        .at(-1)!;
    },
  };
}

function observeSessionGrantRefreshes(page: Page) {
  const seen: CapturedGrant[] = [];
  page.on("response", (response) => {
    if (
      response.request().method() !== "POST" ||
      !response.url().includes("/session-grants/refresh") ||
      !response.ok()
    ) {
      return;
    }
    void response
      .json()
      .then((body) => {
        const jwt = typeof body?.grant_jwt === "string" ? body.grant_jwt : "";
        const jkt =
          typeof body?.dpop_jkt === "string" && body.dpop_jkt.trim()
            ? body.dpop_jkt
            : grantJkt(jwt);
        if (jwt && jkt && seen.at(-1)?.jwt !== jwt) {
          seen.push({ jwt, jkt });
        }
      })
      .catch(() => undefined);
  });
  return {
    async waitForLatest(): Promise<CapturedGrant> {
      await expect
        .poll(() => seen.at(-1)?.jkt ?? "", { timeout: 120_000 })
        .not.toBe("");
      return seen.at(-1)!;
    },
  };
}

function grantJkt(jwt: string): string | undefined {
  const parts = jwt.split(".");
  if (parts.length < 2) return undefined;
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    const encoded = payload?.session_public_key;
    const jwk = typeof encoded === "string" ? JSON.parse(encoded) : encoded;
    return jwk?.kty === "OKP" && jwk?.crv === "Ed25519" && typeof jwk?.x === "string"
      ? jwkThumbprintEd25519(jwk.x)
      : undefined;
  } catch {
    return undefined;
  }
}

function didKeyMultibase(did: string): string {
  expect(did, "expected a did:key signer").toMatch(/^did:key:z/);
  return did.slice("did:key:".length);
}

async function reloadWithSessionGrantExpiringSoon(
  page: Page,
  expectedGrantJwt: string,
  secondsFromNow: number,
): Promise<void> {
  const resultKey = `cotest.session-grant-expiry-override.${Date.now()}`;
  await page.evaluate(
    ({ expectedGrantJwt, secondsFromNow, resultKey }) => {
      window.localStorage.setItem(
        "inkson.test.session_grant_expiry_override.v1",
        JSON.stringify({
          expected_grant_jwt: expectedGrantJwt,
          seconds_from_now: secondsFromNow,
          result_key: resultKey,
        }),
      );
    },
    { expectedGrantJwt, secondsFromNow, resultKey },
  );
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect
    .poll(
      () =>
        page.evaluate((key) => window.sessionStorage.getItem(key), resultKey),
      {
        timeout: 30_000,
      },
    )
    .toBe("1");
}

async function currentSettingsSignerDid(page: Page): Promise<string> {
  await page.goto("/settings/release", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("settings-session-diagnostics")).toBeVisible({
    timeout: 120_000,
  });
  const signerDid = page.getByTestId("settings-signer-did");
  await expect
    .poll(async () => (await signerDid.getAttribute("title")) ?? "", {
      timeout: 60_000,
    })
    .toMatch(/^did:key:z/);
  return (await signerDid.getAttribute("title"))!;
}

async function buildEncryptedBoardListCard(
  userPage: JointUserPage,
  realmId: string,
  boardTitle: string,
  listTitle: string,
  cardTitle: string,
): Promise<string> {
  const page = userPage.page;
  await page.goto(`/kanban/${realmId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible({
    timeout: 120_000,
  });
  await userPage.clickWithPassivePromptRetry(
    page.getByTestId("new-board-toggle"),
  );
  await page.getByTestId("new-board-title-input").fill(boardTitle);
  await userPage.clickWithPassivePromptRetry(
    page.getByTestId("create-board-space-button"),
  );
  await expect(page.getByTestId("kanban-empty-board")).toContainText(
    /No lists yet/,
    {
      timeout: 45_000,
    },
  );
  await expect
    .poll(() => page.url(), { timeout: 30_000 })
    .toContain("/board/ak:space:");
  const boardId = decodeURIComponent(
    new URL(page.url()).pathname.split("/board/")[1]?.split("/")[0] ?? "",
  );
  expect(boardId, `board id from url ${page.url()}`).toMatch(/^ak:space:/);

  await page.getByTestId("new-column-input").fill(listTitle);
  await userPage.clickWithPassivePromptRetry(
    page.getByTestId("add-column-button"),
  );
  const column = page
    .getByTestId("kanban-column")
    .filter({ hasText: listTitle })
    .first();
  await expect(column).toBeVisible({ timeout: 45_000 });
  await userPage.clickWithPassivePromptRetry(
    column.getByTestId("add-card-button"),
  );
  await column.getByTestId("new-card-title-input").fill(cardTitle);
  await userPage.clickWithPassivePromptRetry(
    column.getByTestId("save-card-button"),
  );
  await expect(
    column.getByTestId("kanban-card").filter({ hasText: cardTitle }),
  ).toBeVisible({
    timeout: 45_000,
  });
  return boardId;
}

async function addEncryptedDescription(
  page: Page,
  cardTitle: string,
  description: string,
): Promise<void> {
  await page
    .getByTestId("kanban-card")
    .filter({ hasText: cardTitle })
    .first()
    .click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible({
    timeout: 45_000,
  });
  await page.getByTestId("card-detail-tab-description").click();
  await page.getByTestId("card-detail-add-description-button").click();

  const editor = page.getByTestId("card-detail-description-input");
  await expect(editor).toBeAttached({ timeout: 45_000 });
  await editor.evaluate((node, value) => {
    const textarea = node as HTMLTextAreaElement;
    textarea.value = value;
    textarea.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        inputType: "insertText",
        data: value,
      }),
    );
  }, description);

  const strandUpdate = page.waitForResponse(
    (response) =>
      response.url().includes("/_arkret/self/events") &&
      response.request().method() === "POST" &&
      (response.request().postData() ?? "").includes("ak.strand.update"),
    { timeout: 60_000 },
  );
  await page.getByTestId("card-detail-save-button").click();
  const response = await strandUpdate;
  const body = await response.text();
  expect(
    response.status(),
    `ak.strand.update should be accepted; body=${body.slice(0, 500)}`,
  ).toBeLessThan(400);
  expect(
    (response.request().postData() ?? "").includes(description),
    "description leaked as plaintext into the encrypted realm wire",
  ).toBe(false);
  await expect(page.getByTestId("card-description-panel")).toContainText(
    description,
    {
      timeout: 120_000,
    },
  );
  await page.getByTestId("card-detail-close-button").click();
}

async function assertCardDescription(
  userPage: JointUserPage,
  realmId: string,
  boardId: string,
  cardTitle: string,
  description: string,
): Promise<void> {
  const page = userPage.page;
  await page.goto(`/kanban/${realmId}/board/${boardId}`, {
    waitUntil: "domcontentloaded",
  });
  await dismissBlockingEncryptedPrompts(userPage);
  await expect(page.getByTestId("kanban-panel")).toBeVisible({
    timeout: 120_000,
  });
  const card = page
    .getByTestId("kanban-card")
    .filter({ hasText: cardTitle })
    .first();
  await expect(card).toBeVisible({ timeout: 90_000 });
  await expect(
    page.getByTestId("kanban-card-redacted").filter({ hasText: cardTitle }),
  ).toHaveCount(0);
  // The encrypted-write backup prompt is scheduled asynchronously and can
  // appear after the page-level cleanup above. Use the bounded prompt-aware
  // click so a prompt racing this interaction is dismissed and retried.
  await userPage.clickWithPassivePromptRetry(card);
  await expect(page.getByTestId("card-detail-modal")).toBeVisible({
    timeout: 45_000,
  });
  // The first accepted encrypted write can legitimately trigger the MLS
  // backup prompt after the earlier page-level prompt cleanup. Dismiss that
  // newly-created modal before interacting with the card detail underneath.
  await dismissBlockingEncryptedPrompts(userPage);
  await page.getByTestId("card-detail-tab-description").click();
  await expect(page.getByTestId("card-description-panel")).toContainText(
    description,
    {
      timeout: 120_000,
    },
  );
  await expect(page.getByTestId("card-detail-body-locked")).toHaveCount(0);
  await page.getByTestId("card-detail-close-button").click();
}

async function dismissBlockingEncryptedPrompts(
  userPage: JointUserPage,
): Promise<void> {
  await userPage.completeRecoveryKeySetupIfPrompted(500).catch(() => undefined);
  for (const testId of [
    "mls-backup-dismiss",
    "mls-recovery-missing-dismiss",
    "mls-unlock-dismiss",
  ]) {
    const button = userPage.page.getByTestId(testId).last();
    if (await button.isVisible({ timeout: 300 }).catch(() => false)) {
      await button.click({ timeout: 3_000 }).catch(() => {});
    }
  }
}
