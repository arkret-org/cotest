// Real account onboarding (not dev-login)
// Contract: e2e/scenarios/identity/onboarding.md
// Spec refs:
//   - identity/account-lifecycle.md §2.1
//   - identity/identity-did.md §2-§3.4
//   - identity/key-management.md §5.0-§5.1 (control Realm genesis, cross-signing)
//   - crypto-media/device-lifecycle.md §3 (registration paths)

import { expect, test } from "@playwright/test";
import {
  coauthBaseUrl,
  coauthServiceId,
  mockEmailBaseUrl,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import { latestMockEmailCode } from "../../helpers/coauth-register";
import { resolvePrincipalDid } from "../../helpers/onboarding";
import { submitCoauthPasswordCredentials } from "../../helpers/real-oidc-login";

test.describe.configure({ mode: "serial" });

test.describe("account onboarding", () => {
  test("dev-login path issues a token bound to a registered DID (baseline; the real onboarding spec is below)", async ({
    request,
  }) => {
    // Baseline sanity: the dev-login shortcut still works. This is NOT the
    // S7 contract — S7 demands the real WebAuthn / OIDC / email strand per
    // spec. But the dev-login path verifies the soland register/dev-login
    // surface is up before we exercise real onboarding.
    const alice = uniqueUser("s7-baseline");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    expect(token).toBeTruthy();

    const meResp = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
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

    const bridgeResponse = await request.get(`${coauth}/_coauth/account/integration/describe`);
    expect(bridgeResponse.status()).toBe(200);
    const bridge = await bridgeResponse.json();
    expect(bridge.contract).toBe("arkret.rest.integration_manifest.v1");
    expect(bridge.describe_path).toBe("/_coauth/account/integration/describe");
    expect(bridge.surfaces).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "session_grants",
          method: "POST",
          path: "/_arkret/gate/account/session-grants",
          contract: "ak.gate.account.command.issue_session_grant",
        }),
        expect.objectContaining({
          name: "passkey_auth",
          path: "/_coauth/account/auth/passkey/{register,auth}/{start,finish}",
        }),
      ]),
    );

    const user = uniqueUser("p1-025-webvh-email");
    const serviceDescribe = await request.get(`${coauth}/_arkret/describe`);
    expect(serviceDescribe.status()).toBe(200);
    const service = await serviceDescribe.json();
    expect(service.supported_operations).toContain("ak.gate.account.command.issue_session_grant");
    expect(service.auth_metadata?.issuer_did).toBe(coauthServiceId());
    expect(service.auth_metadata?.account_authority?.origin).toBe(new URL(coauth!).origin);
    expect(service.auth_metadata?.account_authority?.gate_account_base).toBe(
      `${coauth}/_arkret/gate/account`,
    );
    expect(JSON.stringify(service.auth_metadata)).not.toContain(solandServiceId());

    const start = await request.post(`${coauth}/_coauth/account/auth/register/webvh/start`, {
      data: {
        handle: user.handle.slice(1),
        principal_server_url: solandBaseUrl(),
      },
    });
    expect(start.status()).toBe(200);
    const started = await start.json();
    expect(started, JSON.stringify(started)).toMatchObject({ status: "success" });
    const mockEmail = mockEmailBaseUrl();
    expect(started.email_verification_bypass_allowed).toBe(!mockEmail);

    const emailAddress = `${user.name}@example.test`;
    const email = await request.post(
      `${coauth}/_coauth/account/auth/register/webvh/${started.registration_id}/email`,
      { data: { email: emailAddress } },
    );
    expect(email.status()).toBe(200);
    const emailBody = await email.json();
    expect(emailBody.status).toBe("sent");
    expect(emailBody.delivery).toBe(mockEmail ? "email" : "skipped");
    let verificationCode = emailBody.dev_code as string | undefined;
    if (mockEmail) {
      await expect
        .poll(() => latestMockEmailCode(request, emailAddress), { timeout: 30_000 })
        .toBeTruthy();
      verificationCode = await latestMockEmailCode(request, emailAddress);
    } else {
      expect(verificationCode).toBeTruthy();
    }

    const verify = await request.post(
      `${coauth}/_coauth/account/auth/register/webvh/${started.registration_id}/verify-email`,
      { data: { code: verificationCode } },
    );
    expect(verify.status()).toBe(200);
    const verified = await verify.json();
    expect(verified.status).toBe("success");
    expect(verified.next_step).toBe("finish");
  });

  test("inkson starts the coauth OIDC bridge instead of dev-login", async ({ browser }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const user = uniqueUser("p1-025-inkson-oidc");
    const page = await openUserPage(browser, user);
    try {
      await page.gotoLogin();
      await page.page.getByTestId("login-server-url").fill(solandBaseUrl());
      const coauthOrigin = new URL(coauth!).origin;
      const authorizeRequest = page.page.waitForRequest((request) => {
        const url = new URL(request.url());
        return (
          url.origin === coauthOrigin &&
          url.pathname.endsWith("/authorize") &&
          url.searchParams.get("code_challenge_method") === "S256"
        );
      }, { timeout: 60_000 });
      await page.page.getByTestId("start-server-login-button").click();
      const current = new URL((await authorizeRequest).url());
      expect(current.searchParams.get("resource")).toBe(solandServiceId());
      expect(current.searchParams.get("response_type")).toBe("code");
      expect(current.searchParams.get("code_challenge")).toBeTruthy();
      // Regression guard (inkson fix/authorize-device-scope): the authorize
      // request MUST bind the OAuth session to inkson's stable, persisted
      // device id via a `urn:arkret:client:device:{id}` scope token. Without
      // it coauth introspection emits no `org.arkret.device_id`, soland derives
      // a per-OAuth-session device id that drifts on every re-auth, and the
      // shared sync cursor fails with `cursor_integrity_invalid` ("cursor
      // device does not match request device").
      const requestedScope = current.searchParams.get("scope") ?? "";
      const deviceScope = requestedScope
        .split(/\s+/)
        .find((token) => token.startsWith("urn:arkret:client:device:"));
      expect(
        deviceScope,
        `authorize scope must carry a device-binding token, got: ${requestedScope}`,
      ).toBeTruthy();
      // The bound device id (suffix after the scope prefix) must be a real
      // `ak:device:` identifier, not empty.
      expect(deviceScope?.slice("urn:arkret:client:device:".length)).toMatch(
        /^ak:device:/,
      );
    } finally {
      await page.close();
    }
  });

  test("alice confirms cold recovery custody, binds client-signed entry 0, and completes atomic PCR bootstrap", async ({
    browser,
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const user = uniqueUser("s7-cold-root");
    const handle = user.handle.slice(1);
    const email = `${user.name}@example.test`;
    const password = "ArkretE2E!2026";
    const jointPage = await openUserPage(browser, user, {
      neutralLoginConfig: true,
      autoCompleteRecoveryKeySetup: false,
    });
    const page = jointPage.page;
    try {
      await page.goto("/register", { waitUntil: "domcontentloaded" });
      await expect(page.getByTestId("registration-panel")).toBeVisible();
      await page.getByTestId("register-server").fill(solandBaseUrl());
      await page.getByTestId("register-handle").fill(handle);
      await page.getByTestId("register-email").fill(email);
      await page.getByTestId("register-password").fill(password);
      await page.getByTestId("register-password-confirm").fill(password);
      await page.getByTestId("register-prepare").click();

      const generated = page.getByTestId("register-recovery-key");
      await expect(generated).toBeVisible({ timeout: 60_000 });
      const recoveryKey = (await generated.inputValue()).trim();
      expect(recoveryKey.split(/\s+/)).toHaveLength(24);
      await page.getByTestId("register-recovery-confirm").fill(recoveryKey);
      const devCodeText = await page.getByTestId("register-dev-code").innerText();
      const verificationCode = devCodeText.match(/\b\d{6}\b/)?.[0];
      expect(verificationCode).toBeTruthy();
      await page.getByTestId("register-email-code").fill(verificationCode!);
      await page.getByTestId("register-commit").click();

      await expect(
        page.locator("#login-handle").or(page.locator("#login-password")),
      ).toBeVisible({ timeout: 120_000 });
      await submitCoauthPasswordCredentials(page, { handle, password });
      const approve = page.getByTestId("coauth-oauth-approve");
      if (
        await approve
          .waitFor({ state: "visible", timeout: 20_000 })
          .then(() => true)
          .catch(() => false)
      ) {
        await approve.click();
      }

      await expect(page.getByTestId("onboarding-panel")).toBeVisible({
        timeout: 120_000,
      });
      await expect(page.getByTestId("pending-principal-bootstrap")).toBeVisible();
      const principalDid = await page.evaluate(() => {
        const config = JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}");
        return String(config.account_did ?? "");
      });
      expect(principalDid).toMatch(/^did:webvh:/);

      const resolved = await resolvePrincipalDid(request, principalDid);
      expect(resolved.log).toHaveLength(1);
      expect(resolved.document.verificationMethod).toBeUndefined();
      expect(resolved.document.assertionMethod).toBeUndefined();
      expect(resolved.document.capabilityDelegation).toBeUndefined();
      expect(resolved.document.service).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "ArkretDeviceEnrollmentAuthority",
            serviceEndpoint: expect.stringMatching(/^did:/),
          }),
        ]),
      );

      await page.getByTestId("bootstrap-recovery-key").fill(recoveryKey);
      const sealResponsePromise = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return (
          url.origin === new URL(solandBaseUrl()).origin &&
          url.pathname === "/_arkret/self/events/seals" &&
          response.request().method() === "POST"
        );
      });
      await page.getByTestId("bootstrap-submit").click();
      const sealResponse = await sealResponsePromise;
      expect(sealResponse.status(), await sealResponse.text()).toBe(200);
      const submittedSeal = sealResponse.request().postDataJSON() as {
        id: string;
        predecessor_refs: string[];
        delta: string[];
        covered_event_digests: string[];
        state_root: string;
        notary_signature: { verification_method: string };
      };
      const sealOutcome = await sealResponse.json();
      expect(submittedSeal.predecessor_refs).toEqual([]);
      expect(submittedSeal.delta).toHaveLength(2);
      expect(submittedSeal.covered_event_digests).toEqual(submittedSeal.delta);
      expect(submittedSeal.notary_signature.verification_method).toMatch(
        new RegExp(`^${principalDid.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}#ak:device:`),
      );
      expect(sealOutcome).toEqual({
        seal_id: submittedSeal.id,
        accepted_event_digests: submittedSeal.delta,
        post_state_root: submittedSeal.state_root,
      });
      await expect(page.getByTestId("pending-principal-bootstrap")).toHaveCount(0, {
        timeout: 120_000,
      });
      await page.getByRole("tab", { name: "3. Atomic bootstrap" }).click();
      await expect(page.getByTestId("onboarding-first-backup-gate")).toHaveAttribute(
        "data-gate-state",
        "satisfied",
        { timeout: 60_000 },
      );
    } finally {
      await jointPage.close();
    }
  });

  test.fixme("carol verifies email then finishes with her client-signed cold-root inception", async ({
    request,
  }) => {
    // spec: account-lifecycle.md §2.1 + sync/third-party-invites.md §3
    //
    // Keep the verified 3PID strand, then supply a client-authored entry 0 to
    // finish. No service is permitted to generate the identity root.
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const user = uniqueUser("s7-carol-email");
    const start = await request.post(
      `${coauth}/_coauth/account/auth/register/webvh/start`,
      { data: { handle: user.handle.slice(1), principal_server_url: solandBaseUrl() } },
    );
    expect(start.status(), await start.text()).toBe(200);
    const started = await start.json();
    expect(started.status).toBe("success");
    const mockEmail = mockEmailBaseUrl();
    expect(started.email_verification_bypass_allowed).toBe(!mockEmail);

    const email = `${user.name}@example.test`;
    const sent = await request.post(
      `${coauth}/_coauth/account/auth/register/webvh/${started.registration_id}/email`,
      { data: { email } },
    );
    expect(sent.status(), await sent.text()).toBe(200);
    const sentBody = await sent.json();
    expect(sentBody.status).toBe("sent");
    if (mockEmail) {
      expect(sentBody.dev_code).toBeFalsy();
    } else {
      expect(sentBody.dev_code).toBeTruthy();
    }

    // If a mock-email service is wired, the verification message landed in its
    // inbox for this recipient.
    let verificationCode = sentBody.dev_code as string | undefined;
    if (mockEmail) {
      await expect
        .poll(() => latestMockEmailCode(request, email), { timeout: 30_000 })
        .toBeTruthy();
      verificationCode = await latestMockEmailCode(request, email);
      const inbox = await request.get(`${mockEmail}/mock/email/verification/inbox?to=${encodeURIComponent(email)}`);
      const inboxText = await inbox.text();
      expect(inbox.status(), inboxText).toBe(200);
      const inboxBody = JSON.parse(inboxText) as {
        messages?: Array<Record<string, unknown>>;
      };
      const messages = inboxBody.messages ?? [];
      expect(messages.length, `mock inbox for ${email}: ${JSON.stringify(inboxBody)}`).toBeGreaterThan(0);
      const serializedMessages = JSON.stringify(messages);
      expect(
        [verificationCode, started.registration_id].some((needle) =>
          serializedMessages.includes(String(needle)),
        ),
        `mock inbox message should reference the verification code or registration id: ${serializedMessages}`,
      ).toBeTruthy();
    }

    const verify = await request.post(
      `${coauth}/_coauth/account/auth/register/webvh/${started.registration_id}/verify-email`,
      { data: { code: verificationCode } },
    );
    expect(verify.status(), await verify.text()).toBe(200);
    const verified = await verify.json();
    expect(verified.status).toBe("success");
    expect(verified.next_step).toBe("finish");

    // Re-submitting the same (now consumed) code must not re-advance the strand:
    // the token is single-use.
    const replay = await request.post(
      `${coauth}/_coauth/account/auth/register/webvh/${started.registration_id}/verify-email`,
      { data: { code: verificationCode } },
    );
    const replayBody = await replay.json();
    expect(replayBody.status).not.toBe("success");

  });

  test.fixme(
    "E7.5 a claimed handle remains unavailable after client-signed inception binding",
    async () => {
      // The first claimant must finish through the cold-root path before the
      // second start request is expected to return handle_exists.
    },
  );

  // ── Retained (honestly out of low-risk reach) ────────────────────────────
  //
  // The following remain `test.fixme` after this pass. They are NOT promotable
  // by a black-box harness test today; promoting them would assert behavior
  // that the running stack cannot satisfy, or require changes to modules owned
  // by other workstreams (device / webvh / upstream-OAuth). Rationale inline.

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "principal control Realm and first device are accepted as one B-model bootstrap unit before recovery-material gate closure",
    async () => {
      // Assert root-signed PCR create + authority-signed authorize are atomic,
      // then publish the recovery policy and backup/receipt gate material.
      // Model B has no SSK and device keys remain in the device registry, never
      // in DID Document verificationMethod.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-onboarding-gap
    // @user-promise: e2e/scenarios/identity/onboarding.md
    // @expected-live-by: 2026Q3
    "bob registers via OIDC bridge (mock IdP); coauth verifies ID token and binds a fresh DID",
    async () => {
      // coauth's OIDC bridge (handlers/account/auth/oidc_bridge.rs) treats an
      // EXTERNAL issuer (the mock IdP) as a Federated upstream provider. The
      // exchange requires the upstream subject to already be linked to a local
      // account (`upstream_oauth_link().find_by_subject` -> else
      // `upstream_link_required`); there is no auto-provision-fresh-DID path for
      // an unlinked external subject. Driving this needs the upstream-OAuth
      // browser link ceremony + seeded provider/link rows (DB + config), then
      // the same client-signed cold-root inception/binding flow used by every
      // other registration factor.
    },
  );
});
