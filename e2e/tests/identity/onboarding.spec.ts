// Real account onboarding (not dev-login)
// Contract: e2e/scenarios/identity/onboarding.md
// Spec refs:
//   - identity/account-lifecycle.md §2.1
//   - identity/identity-did.md §2-§3.4
//   - identity/key-management.md §5.0-§5.1 (control space genesis, cross-signing)
//   - crypto-media/device-lifecycle.md §3 (registration paths)

import { expect, test } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("account onboarding", () => {
  test("dev-login path issues a token bound to a registered DID (baseline; the real onboarding spec is below)", async ({
    request,
  }) => {
    // Baseline sanity: the dev-login shortcut still works. This is NOT the
    // S7 contract — S7 demands the real WebAuthn / OIDC / email flow per
    // spec. But the dev-login path verifies the soland register/dev-login
    // surface is up before we exercise real onboarding.
    const alice = uniqueUser("s7-baseline");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    expect(token).toBeTruthy();

    const meResp = await request.get(`${solandBaseUrl()}/_cokret/self/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(meResp.ok()).toBeTruthy();
    const me = await meResp.json();
    expect(me.did).toBe(alice.did);
  });

  test("coauth exposes OIDC/passkey bridge metadata and email verification onboarding", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const bridgeResponse = await request.get(`${coauth}/_cokret/gate/auth/bridge/describe`);
    expect(bridgeResponse.status()).toBe(200);
    const bridge = await bridgeResponse.json();
    expect(bridge.todos).toEqual([]);
    expect(bridge.oauth.supported_flows).toContain("authorization_code_pkce_browser");
    expect(bridge.passkey.register_start_path).toBe("/_cokret/gate/auth/passkey/register/start");
    expect(bridge.cokret.session_grants_introspect_path).toBe(
      "/_cokret/gate/account/session-grants/introspect",
    );

    const user = uniqueUser("p1-025-webvh-email");
    const bridgeSessionResponse = await request.post(
      `${coauth}/_cokret/gate/auth/oidc/browser-bridge/session`,
      {
        data: {
          redirect_uri: "urn:yougen:oauth:callback",
          login_hint: user.handle.slice(1),
          device_id: user.deviceId,
          principal_audience: solandServiceDid(),
        },
      },
    );
    expect(bridgeSessionResponse.status()).toBe(200);
    const bridgeSession = await bridgeSessionResponse.json();
    expect(bridgeSession.authorize_url).toContain("code_challenge=");
    expect(bridgeSession.authorize_url).toContain(encodeURIComponent(solandServiceDid()));
    expect(bridgeSession.code_challenge_method).toBe("S256");

    const start = await request.post(`${coauth}/_cokret/gate/auth/register/webvh/start`, {
      data: {
        handle: user.handle.slice(1),
        principal_server_url: solandBaseUrl(),
      },
    });
    expect(start.status()).toBe(200);
    const started = await start.json();
    expect(started, JSON.stringify(started)).toMatchObject({ status: "success" });
    expect(started.email_verification_bypass_allowed).toBe(true);

    const email = await request.post(
      `${coauth}/_cokret/gate/auth/register/webvh/${started.registration_id}/email`,
      { data: { email: `${user.name}@example.test` } },
    );
    expect(email.status()).toBe(200);
    const emailBody = await email.json();
    expect(emailBody.status).toBe("sent");
    expect(emailBody.delivery).toBe("skipped");
    expect(emailBody.dev_code).toBeTruthy();

    const verify = await request.post(
      `${coauth}/_cokret/gate/auth/register/webvh/${started.registration_id}/verify-email`,
      { data: { code: emailBody.dev_code } },
    );
    expect(verify.status()).toBe(200);
    const verified = await verify.json();
    expect(verified.status).toBe("success");
    expect(verified.next_step).toBe("finish");
  });

  test("yougen starts the coauth OIDC bridge instead of dev-login", async ({ browser }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const user = uniqueUser("p1-025-yougen-oidc");
    const page = await openUserPage(browser, user);
    try {
      await page.gotoLogin();
      await page.page.getByTestId("login-server-url").fill(solandBaseUrl());
      await page.page.getByTestId("start-server-login-button").click();
      await page.page.waitForURL(
        (url) =>
          url.origin === new URL(coauth).origin &&
          url.pathname.endsWith("/authorize") &&
          url.searchParams.get("code_challenge_method") === "S256",
        { timeout: 60_000 },
      );
      const current = new URL(page.page.url());
      expect(current.searchParams.get("resource")).toBe(solandServiceDid());
      expect(current.searchParams.get("response_type")).toBe("code");
      expect(current.searchParams.get("code_challenge")).toBeTruthy();
    } finally {
      await page.close();
    }
  });

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "alice registers via passkey/WebAuthn; coauth binds principal DID and issues short-term ck.session.grant",
    async () => {
      // spec: account-lifecycle.md §2.1, device-lifecycle.md §3.2
      // soland/coauth gap: WebAuthn binding handler, principal DID provisioning.
      // yougen gap: /onboarding wizard with "Register with passkey" button.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "alice's did:webvh entry 0 is published; SCID derived; DID Document resolves and exposes CokretPrincipalServer service endpoint",
    async () => {
      // spec: identity-did.md §2.1, §3.4
      // soland gap: did:webvh genesis writer; DID Document publishing endpoint.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "principal control space is created (purpose=principal_control); first device registered via ck.device.authorize; cross-signing PSK/SSK/USK published",
    async () => {
      // spec: key-management.md §5.0.1 (4-step bootstrap)
      // soland gap: ck.profile.principal_control_space.v1 profile; ck.cross_signing.publish.v1.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "bob registers via OIDC bridge (mock IdP); coauth verifies ID token and binds a fresh DID",
    async () => {
      // spec: account-lifecycle.md §2.1 (OIDC binding)
      // soland/coauth gap: OIDC bridge handler; harness gap: mock IdP service.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "carol registers via email-only (3PID precursor); verification token consumed; DID issued",
    async () => {
      // spec: account-lifecycle.md §2.1 + sync/third-party-invites.md §3
      // soland/coauth gap: email verification flow; harness gap: mock email service.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "E7.1 re-registering the same WebAuthn credential is rejected with account_already_registered",
    async () => {
      // spec: account-lifecycle.md §2.1
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "E7.5 handle conflict (\"@alice-s7\" already claimed) rejects with handle_already_claimed",
    async () => {
      // spec: identity/identity-handles.md
    },
  );
});
