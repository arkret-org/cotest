// Session-grant + DPoP self-path authentication (②(A+②) model).
//
// Contract: cotask/tasks/_auth_todos.md "## ② 最终路线" (D1–D6) and
// cokret-spec/spec/v1/zh/sync/api-conventions.md §3.3.
//
// Under ②, soland mints no local bearer and there is no grant→bearer exchange.
// A client reaches `/_cokret/self/*` by presenting
//   Authorization: Bearer <ck.session.grant>
//   DPoP: <RFC 9449 proof bound to htm/htu/ath(=hash(grant))>
// and soland verifies the DPoP against the grant's `cnf.jkt` (obtained via
// session-grant introspection at coauth), plus audience / scope / principal /
// device / expiry. Three inbound credential types coexist on soland and are
// distinguished by the presence of the `DPoP` header (D6): dev-login bearer,
// coauth OAuth access token, and grant+DPoP.
//
// Minting approach: a real DPoP-bound grant is obtained from coauth's cotest
// debug seam (POST /_coauth/gate/account/test/debug/issue-dpop-grant), which
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
  uniqueUser,
} from "../../helpers/users";
import { wireErrCode } from "../../helpers/soland-api";
import {
  generateDpopDeviceKey,
  mintDpopBoundGrant,
  mintDpopProof,
  type DpopBoundGrant,
  type DpopDeviceKey,
} from "../../helpers/session-grant-dpop";

// The self endpoint exercised throughout: it is a read-only `viewer` projection
// of the authenticated principal (ck.self.account.query.viewer), so a 200 here
// proves the inbound credential authenticated end-to-end.
const VIEWER_PATH = "/_cokret/self/account/viewer";

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

  async function setupGrant(
    request: APIRequestContext,
  ): Promise<
    | {
        coauth: string;
        actorDid: string;
        deviceId: string;
        deviceKey: DpopDeviceKey;
        grant: DpopBoundGrant;
      }
    | undefined
  > {
    const coauth = coauthBaseUrl();
    if (!coauth) {
      return undefined;
    }
    const user = uniqueUser("dpop-self");
    await ensureRegistered(request, user);
    const deviceKey = generateDpopDeviceKey();
    const grant = await mintDpopBoundGrant(
      request,
      coauth,
      user.did,
      user.deviceId,
      deviceKey,
      { audience: solandServiceDid() },
    );
    if (!grant) {
      return undefined;
    }
    // Sanity: the grant the AA minted is bound to OUR device key.
    expect(grant.dpopJkt).toBe(deviceKey.thumbprint);
    expect(grant.audience).toBe(solandServiceDid());
    return {
      coauth,
      actorDid: user.did,
      deviceId: user.deviceId,
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
      url: `${solandBaseUrl()}/_cokret/self/account/describe`,
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
    const logoutUrl = `${solandBaseUrl()}/_cokret/gate/account/logout`;
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
    // §3.3 / D6: soland branches on the presence of the `DPoP` header. A grant
    // presented as a bare Bearer (no DPoP) is NOT a recognized session — it
    // falls through to the dev-bearer/OAuth lookup, misses, and is rejected.
    // This holds whether or not we minted a real grant, so it runs everywhere:
    // a grant-shaped bearer with no DPoP must never authenticate the self-path.
    const ctx = await setupGrant(request);
    const bearer = ctx
      ? ctx.grant.grantJwt
      : // No debug seam: a syntactically grant-like but unknown bearer. The
        // assertion (no DPoP ⇒ rejected) is identical; only the realism differs.
        "ck.session.grant.unknown.no-dpop-presented";

    const response = await request.get(viewerUrl(), {
      headers: { authorization: `Bearer ${bearer}` },
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
