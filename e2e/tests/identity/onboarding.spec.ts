// Real account onboarding (not dev-login)
// Contract: e2e/scenarios/identity/onboarding.md
// Spec refs:
//   - identity/account-lifecycle.md §2.1
//   - identity/identity-did.md §2-§3.4
//   - identity/key-management.md §5.0-§5.1 (control space genesis, cross-signing)
//   - crypto-media/device-lifecycle.md §3 (registration paths)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
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

    const meResp = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(meResp.ok()).toBeTruthy();
    const me = await meResp.json();
    expect(me.did).toBe(alice.did);
  });

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "alice registers via passkey/WebAuthn; coauth binds principal DID and issues short-term cx.session.grant",
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
    "alice's did:webvh entry 0 is published; SCID derived; DID Document resolves and exposes ContrixPrincipalServer service endpoint",
    async () => {
      // spec: identity-did.md §2.1, §3.4
      // soland gap: did:webvh genesis writer; DID Document publishing endpoint.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "principal control space is created (purpose=principal_control); first device registered via cx.device.authorize; cross-signing PSK/SSK/USK published",
    async () => {
      // spec: key-management.md §5.0.1 (4-step bootstrap)
      // soland gap: cx.profile.principal_control_space.v1 profile; cx.cross_signing.publish.v1.
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
