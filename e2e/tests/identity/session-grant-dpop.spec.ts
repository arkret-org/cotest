// Session-grant + DPoP self-path authentication (②(A+②) model).
//
// Contract: cotask/tasks/_auth_todos.md "## ② 最终路线" (D1–D6) and
// arkret-spec/spec/v1/zh/sync/api-conventions.md §3.3.
//
// Under ②, soland does not mint a second local credential. A client reaches
// `/_arkret/self/*` by presenting
//   Authorization: Bearer <ak.session.grant>
//   DPoP: <RFC 9449 proof bound to htm/htu/ath(=hash(grant))>
// and soland verifies the DPoP against the grant's `cnf.jkt` (obtained via
// session-grant introspection at coauth), plus audience / scope / principal /
// device / expiry. The `DPoP` header distinguishes current session-grant
// presentation from development and deployment compatibility credentials.
//
// Minting approach: a real DPoP-bound grant is obtained from coauth's cotest
// debug seam (POST /_coauth/account/test/debug/issue-dpop-grant), which
// signs a grant whose `cnf.jkt` matches a supplied device public JWK — without
// driving the OIDC browser ceremony. That route is mounted only in debug builds
// with COAUTH_ENABLE_TEST_ENDPOINTS enabled; the grant-minting cases skip
// cleanly when it (or coauth) is absent. The "missing DPoP rejected" and
// "dev-bearer still works" cases need neither and run against soland directly.

import { expect, test, type APIRequestContext } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import { wireErrCode } from "../../helpers/soland-api";
import {
  dpopDeviceSeedB64url,
  generateDpopDeviceKey,
  mintDpopBoundGrant,
  mintDpopProof,
  type DpopBoundGrant,
  type DpopDeviceKey,
} from "../../helpers/session-grant-dpop";

// The self endpoint exercised throughout: it is a read-only `viewer` projection
// of the authenticated principal (ck.self.account.query.viewer), so a 200 here
// proves the inbound credential authenticated end-to-end.
const VIEWER_PATH = "/_arkret/self/account/viewer";

function grantLikeJwtWithoutDpop(): string {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ type: "ak.session.grant" })).toString("base64url");
  return `${header}.${payload}.signature`;
}

function viewerUrl(): string {
  return `${solandBaseUrl()}${VIEWER_PATH}`;
}

test.describe.configure({ mode: "serial" });

test.describe("session-grant + DPoP self-path (② A+②)", () => {
  // ── Cases needing a real DPoP-bound grant (coauth + debug seam) ──────────
  //
  // A per-describe shared setup: register a user, mint a device key + grant.
  // When the debug seam is unavailable the dependent tests skip with a clear
  // message rather than fail.
  let sharedAccount:
    | {
        coauth: string;
        actorDid: string;
        deviceId: string;
        displayName: string;
      }
    | undefined;

  async function setupAccount(
    request: APIRequestContext,
  ): Promise<
    | {
        coauth: string;
        actorDid: string;
        deviceId: string;
        displayName: string;
      }
    | undefined
  > {
    if (sharedAccount) {
      return sharedAccount;
    }
    const coauth = coauthBaseUrl();
    if (!coauth) {
      return undefined;
    }
    const account = await registerCoauthPasswordAccount(request, coauth);
    const seed = uniqueUser("dpop-self");
    const user = {
      ...seed,
      name: account.handle,
      did: account.did,
      handle: `@${account.handle}`,
      displayName: account.displayName,
    };
    await ensureRegistered(request, user);
    sharedAccount = {
      coauth,
      actorDid: user.did,
      deviceId: user.deviceId,
      displayName: user.displayName,
    };
    return sharedAccount;
  }

  async function setupGrant(
    request: APIRequestContext,
  ): Promise<
    | {
        coauth: string;
        actorDid: string;
        deviceId: string;
        displayName: string;
        deviceKey: DpopDeviceKey;
        grant: DpopBoundGrant;
      }
    | undefined
  > {
    const account = await setupAccount(request);
    if (!account) {
      return undefined;
    }
    const deviceKey = generateDpopDeviceKey();
    const grant = await mintDpopBoundGrant(
      request,
      account.coauth,
      account.actorDid,
      account.deviceId,
      deviceKey,
      { audience: solandServiceDid() },
    );
    if (!grant) {
      return undefined;
    }
    // Sanity: the grant the AA minted is bound to OUR device key.
    expect(grant.dpopJkt).toBe(deviceKey.thumbprint);
    expect(grant.audience).toBe(solandServiceDid());
    expect(grant.principalDid).toMatch(/^did:webvh:/);
    return {
      ...account,
      actorDid: grant.principalDid,
      deviceKey,
      grant,
    };
  }

  test("1. grant + matching DPoP authenticates the self-path (200)", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const ctx = await setupGrant(request);
    test.skip(
      !ctx,
      "coauth debug grant-mint seam unavailable (release build or COAUTH_ENABLE_TEST_ENDPOINTS unset)",
    );
    const { deviceKey, grant } = ctx!;

    const url = viewerUrl();
    const dpop = mintDpopProof({
      deviceKey,
      method: "GET",
      url,
      grantJwt: grant.grantJwt,
    });

    const response = await request.get(url, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop,
      },
    });
    const body = await response.text();
    expect(response.status(), `viewer with grant+DPoP returned ${response.status()}: ${body}`).toBe(
      200,
    );
    expect(ctx!.actorDid).toBeTruthy();
    expect(JSON.parse(body).principal_id).toBe(ctx!.actorDid);
  });

  test("1b. inkson boots with a real grant and sends self-path DPoP headers", async ({
    browser,
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const ctx = await setupGrant(request);
    test.skip(
      !ctx,
      "coauth debug grant-mint seam unavailable (release build or COAUTH_ENABLE_TEST_ENDPOINTS unset)",
    );
    const { actorDid, deviceId, displayName, deviceKey, grant } = ctx!;
    const user = {
      name: actorDid.split(":").pop() ?? "dpop-inkson",
      did: actorDid,
      deviceId,
      handle: "@dpop-inkson",
      displayName,
    };
    const jointPage = await openUserPage(browser, user, {
      grantJwt: grant.grantJwt,
      dpopSeedB64url: dpopDeviceSeedB64url(deviceKey),
      grantId: grant.grantId,
      grantAudience: grant.audience,
    });
    const seenGrantSelfRequests: Array<{ url: string; headers: Record<string, string> }> = [];
    const refreshRequests: string[] = [];
    jointPage.page.on("request", (browserRequest) => {
      const url = browserRequest.url();
      if (url.includes("/session-grants/refresh")) {
        refreshRequests.push(url);
      }
      if (!url.includes("/_arkret/self/") && !url.includes("/_arkret/root/")) {
        return;
      }
      const headers = browserRequest.headers();
      if (headers.authorization === `Bearer ${grant.grantJwt}`) {
        seenGrantSelfRequests.push({ url, headers });
      }
    });
    try {
      await jointPage.gotoHome();
      await expect(jointPage.page.getByTestId("client-shell")).toBeVisible({ timeout: 60_000 });
      await expect(jointPage.page.getByTestId("login-panel")).toHaveCount(0);
      await expect
        .poll(
          () =>
            seenGrantSelfRequests.some(
              ({ headers }) => Boolean(headers.dpop),
            ),
          { timeout: 30_000 },
        )
        .toBeTruthy();
      const missingProofs = seenGrantSelfRequests.filter(
        ({ headers }) => !headers.dpop,
      );
      expect(missingProofs, `grant self/root requests missing DPoP`).toEqual([]);
      expect(refreshRequests, "fresh boot must not rotate the injected grant").toEqual([]);

      await jointPage.page.reload({ waitUntil: "domcontentloaded" });
      await expect(jointPage.page.getByTestId("client-shell")).toBeVisible({ timeout: 60_000 });
      await expect(jointPage.page.getByTestId("login-panel")).toHaveCount(0);
      await expect
        .poll(
          () =>
            seenGrantSelfRequests.some(
              ({ headers }) => Boolean(headers.dpop),
            ),
          { timeout: 30_000 },
        )
        .toBeTruthy();
      expect(refreshRequests, "reload with a fresh grant must not rotate it").toEqual([]);
    } finally {
      await jointPage.close();
    }
  });

  test("3a. DPoP signed by a non-matching key is rejected (401)", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const ctx = await setupGrant(request);
    test.skip(!ctx, "coauth debug grant-mint seam unavailable");
    const { grant } = ctx!;

    const url = viewerUrl();
    // A second, unrelated device key: its JWK thumbprint != grant.cnf.jkt.
    const wrongKey = generateDpopDeviceKey();
    expect(wrongKey.thumbprint).not.toBe(grant.dpopJkt);
    const dpop = mintDpopProof({
      deviceKey: wrongKey,
      method: "GET",
      url,
      grantJwt: grant.grantJwt,
    });

    const response = await request.get(url, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop,
      },
    });
    expect([401, 403]).toContain(response.status());
  });

  test("3b. DPoP with a wrong htu/htm/ath binding is rejected (401)", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const ctx = await setupGrant(request);
    test.skip(!ctx, "coauth debug grant-mint seam unavailable");
    const { deviceKey, grant } = ctx!;
    const url = viewerUrl();

    // Wrong htu: signed for a different self path than the request hits.
    const wrongHtu = mintDpopProof({
      deviceKey,
      method: "GET",
      url: `${solandBaseUrl()}/_arkret/self/account/describe`,
      grantJwt: grant.grantJwt,
    });
    const r1 = await request.get(url, {
      headers: { authorization: `Bearer ${grant.grantJwt}`, dpop: wrongHtu },
    });
    expect([401, 403], `wrong-htu DPoP status`).toContain(r1.status());

    // Wrong htm: signed for POST but presented on a GET request.
    const wrongHtm = mintDpopProof({
      deviceKey,
      method: "POST",
      url,
      grantJwt: grant.grantJwt,
    });
    const r2 = await request.get(url, {
      headers: { authorization: `Bearer ${grant.grantJwt}`, dpop: wrongHtm },
    });
    expect([401, 403], `wrong-htm DPoP status`).toContain(r2.status());

    // Wrong ath: bound to a hash of a different token, not this grant.
    const wrongAth = mintDpopProof({
      deviceKey,
      method: "GET",
      url,
      grantJwt: grant.grantJwt,
      athOverride: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    const r3 = await request.get(url, {
      headers: { authorization: `Bearer ${grant.grantJwt}`, dpop: wrongAth },
    });
    expect([401, 403], `wrong-ath DPoP status`).toContain(r3.status());
  });

  test("4. logout invalidates the grant for subsequent self requests", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");
    const ctx = await setupGrant(request);
    test.skip(!ctx, "coauth debug grant-mint seam unavailable");
    const { deviceKey, grant } = ctx!;
    const url = viewerUrl();

    // Pre-condition: the grant authenticates before logout.
    const before = await request.get(url, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop: mintDpopProof({ deviceKey, method: "GET", url, grantJwt: grant.grantJwt }),
      },
    });
    expect(before.status(), `pre-logout viewer: ${await before.text()}`).toBe(200);

    // Hard logout: grant as Bearer + a DPoP bound to the logout endpoint.
    const logoutUrl = `${solandBaseUrl()}/_arkret/gate/account/logout`;
    const logout = await request.post(logoutUrl, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop: mintDpopProof({
          deviceKey,
          method: "POST",
          url: logoutUrl,
          grantJwt: grant.grantJwt,
        }),
      },
    });
    expect([200, 204], `logout: ${await logout.text()}`).toContain(logout.status());

    // After logout, sensitive account reads bypass soland's grant-introspection
    // cache and re-check coauth immediately, so revocation is visible without
    // waiting for the <=120s low-sensitivity cache TTL.
    const after = await request.get(url, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop: mintDpopProof({ deviceKey, method: "GET", url, grantJwt: grant.grantJwt }),
      },
    });
    expect(
      [401, 403],
      `post-logout sensitive self request still authenticated: ${after.status()} ${await after.text()}`,
    ).toContain(after.status());
  });

  // ── Cases that need neither coauth nor the debug seam ────────────────────

  test("2. a session grant presented WITHOUT a DPoP header is rejected (401)", async ({
    request,
  }) => {
    // §3.3 / D6: a grant presented as a bare Bearer (no DPoP) is NOT a
    // recognized session. soland classifies grant-shaped JWTs and rejects them
    // before any dev-bearer/OAuth compatibility lookup.
    // This holds whether or not we minted a real grant, so it runs everywhere:
    // a grant-shaped bearer with no DPoP must never authenticate the self-path.
    const response = await request.get(viewerUrl(), {
      headers: { authorization: `Bearer ${grantLikeJwtWithoutDpop()}` },
    });
    expect([401, 403]).toContain(response.status());
  });

  test("5. dev-login bearer (no DPoP) still authenticates the self-path (D6 no regression)", async ({
    request,
  }) => {
    // The dev-login path mints a plain soland bearer (never DPoP-bound). It MUST
    // keep working without any DPoP header — confirming the tri-modal inbound
    // contract did not regress the legacy dev path.
    const alice = uniqueUser("dpop-devbearer");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const response = await request.get(viewerUrl(), {
      headers: { authorization: `Bearer ${token}` },
    });
    const body = await response.text();
    expect(response.status(), `dev-bearer viewer returned ${response.status()}: ${body}`).toBe(200);
    expect(JSON.parse(body).principal_id).toBe(alice.did);
    // Defensive: not an auth error code.
    expect(wireErrCode(JSON.parse(body))).toBeUndefined();
  });
});
