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
import {
  latestMockEmailCode,
  registerCoauthPasswordAccount,
} from "../../helpers/coauth-register";
import { resolvePrincipalDid } from "../../helpers/onboarding";

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

  test("coauth exposes canonical handoff metadata and account-first registration", async ({
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

    const user = uniqueUser("p1-025-account-first");
    const serviceDescribe = await request.get(`${coauth}/_arkret/describe`);
    expect(serviceDescribe.status()).toBe(200);
    const service = await serviceDescribe.json();
    expect(service.supported_operations).toContain("ak.gate.account.command.issue_session_grant");
    expect(service.supported_operations).toContain("ak.gate.account.exchange.create_handoff");
    expect(service.supported_operations).toContain(
      "ak.gate.account.command.issue_identity_binding_challenge",
    );
    expect(service.auth_metadata?.issuer_did).toBe(coauthServiceId());
    expect(service.auth_metadata?.account_authority?.origin).toBe(new URL(coauth!).origin);
    expect(service.auth_metadata?.account_authority?.gate_account_base).toBe(
      `${coauth}/_arkret/gate/account`,
    );
    expect(JSON.stringify(service.auth_metadata)).not.toContain(solandServiceId());

    const account = await registerCoauthPasswordAccount(request, coauth!, {
      handle: user.handle.slice(1),
    });
    expect(account.did).toMatch(/^did:webvh:/);
    expect(account.recoveryKey.split(/\s+/)).toHaveLength(24);
    expect(account.pendingPrincipalRegistration).toMatchObject({
      handoff_request_id: expect.stringMatching(/^ak:request:/),
      stage: "binding_registered",
      binding_receipt: expect.objectContaining({ binding_state: "bound" }),
    });
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
    const coauthOrigin = new URL(coauth!).origin;

    const user = uniqueUser("s7-cold-root");
    const handle = user.handle.slice(1);
    const email = `${user.name}@example.test`;
    const password = "ArkretE2E!2026";
    const jointPage = await openUserPage(browser, user, {
      neutralLoginConfig: true,
      autoCompleteRecoveryKeySetup: false,
    });
    const page = jointPage.page;
    // Phase E secret audit: record every outbound request for the whole
    // registration ceremony so the confirmed Recovery Key can be proven to
    // never leave the page. Audit the URL (query params) and headers together
    // with the body — a secret is a leak on any of those surfaces — and keep
    // percent-/form-decoded variants so standard URL or form encoding cannot
    // hide a match.
    // Decoders are applied per surface (url / headers / body) so a malformed
    // escape in one part never drops another part out of the decoded audit.
    const softDecode = (text: string): string => {
      try {
        return decodeURIComponent(text);
      } catch {
        return text;
      }
    };
    const softFormDecode = (text: string): string => {
      // application/x-www-form-urlencoded additionally encodes space as '+'
      try {
        return decodeURIComponent(text.replace(/\+/g, "%20"));
      } catch {
        return text.replace(/\+/g, " ");
      }
    };
    const outboundRequests: Array<{ target: string; auditTexts: string[] }> = [];
    page.on("request", (outbound) => {
      const url = new URL(outbound.url());
      const parts = [
        outbound.url(),
        JSON.stringify(outbound.headers()),
        outbound.postData() ?? "",
      ];
      outboundRequests.push({
        // Query-less locator, safe to echo in assertion messages.
        target: `${outbound.method()} ${url.origin}${url.pathname}`,
        auditTexts: [
          parts.join("\n"),
          parts.map(softDecode).join("\n"),
          parts.map(softFormDecode).join("\n"),
        ],
      });
    });
    try {
      await page.goto("/register", { waitUntil: "domcontentloaded" });
      await expect(page.getByTestId("registration-panel")).toBeVisible();
      await page.getByTestId("register-server").fill(solandBaseUrl());
      await page.getByTestId("register-open-account-authority").click();
      await expect(page.locator("#login-handle")).toBeVisible({ timeout: 120_000 });
      await page.getByRole("link", { name: /create account/i }).click();
      await page.locator('input[autocomplete="username"]').fill(handle);
      await page.locator('input[autocomplete="email"]').fill(email);
      await page.locator("#new-password").fill(password);
      await page.locator("#confirm-new-password").fill(password);
      await page.getByRole("button", { name: /create account/i }).click();
      await expect(page.locator("#register-email-verify-code")).toBeVisible({
        timeout: 60_000,
      });
      let verificationCode = "123456";
      if (mockEmailBaseUrl()) {
        await expect
          .poll(() => latestMockEmailCode(request, email), { timeout: 30_000 })
          .toBeTruthy();
        verificationCode = (await latestMockEmailCode(request, email))!;
      }
      await page.locator("#register-email-verify-code").fill(verificationCode);
      const verifyEmailButton = page.getByRole("button", {
        name: "Verify",
        exact: true,
      });
      const verificationDeadline = Date.now() + 30_000;
      let emailVerified = false;
      do {
        const verificationResponse = page.waitForResponse((response) => {
          const url = new URL(response.url());
          return (
            url.origin === coauthOrigin &&
            url.pathname.endsWith("/verify-email") &&
            response.request().method() === "POST"
          );
        });
        await verifyEmailButton.click();
        const response = await verificationResponse;
        expect(response.status(), await response.text()).toBe(200);
        const outcome = (await response.json()) as {
          status?: string;
          error?: string;
        };
        if (outcome.status === "success") {
          emailVerified = true;
          break;
        }
        expect(outcome).toEqual({ status: "error", error: "invalid_code" });
        await page.waitForTimeout(250);
      } while (Date.now() < verificationDeadline);
      expect(
        emailVerified,
        "dev email verification code was not persisted before the retry deadline",
      ).toBe(true);
      const displayName = page.locator('input[autocomplete="name"]');
      await expect(displayName).toBeVisible({ timeout: 60_000 });
      await displayName.fill(user.displayName);
      await page.getByRole("button", { name: /continue/i }).click();
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
      await expect(page.getByTestId("account-handoff-onboarding")).toBeVisible();
      await page.getByTestId("choose-new-identity").click();
      const generated = page.getByTestId("onboarding-recovery-key-display");
      await expect(generated).toBeVisible();
      const recoveryWords = (await generated.locator("li").allTextContents()).map(
        (word) => word.trim(),
      );
      expect(recoveryWords).toHaveLength(24);
      const recoveryKey = recoveryWords.join(" ");
      await page
        .getByTestId("onboarding-recovery-key-confirm")
        .fill(recoveryKey);
      const sealResponsePromise = page.waitForResponse(
        (response) => {
          const url = new URL(response.url());
          return (
            url.origin === new URL(solandBaseUrl()).origin &&
            url.pathname === "/_arkret/self/events/seals" &&
            response.request().method() === "POST"
          );
        },
        { timeout: 120_000 },
      );
      const backupResponsePromise = page.waitForResponse(
        (response) => {
          const url = new URL(response.url());
          return (
            url.origin === new URL(solandBaseUrl()).origin &&
            url.pathname.startsWith("/_arkret/self/keys/backups/") &&
            response.request().method() === "PUT"
          );
        },
        { timeout: 120_000 },
      );
      await page.getByTestId("onboarding-bind-identity").click();
      const [sealResponse, backupResponse] = await Promise.all([
        sealResponsePromise,
        backupResponsePromise,
      ]);
      await expect(page.getByTestId("onboarding-complete")).toBeVisible({
        timeout: 120_000,
      });
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
      expect(backupResponse.ok(), await backupResponse.text()).toBe(true);
      expect(backupResponse.request().postDataJSON()).toMatchObject({
        actor_id: principalDid,
        backup_kind: "did_recovery",
        encryption: {
          recipient_method: "recovery_public_key",
        },
      });

      // The Recovery Key (full 24 words or any 3-consecutive-word run) must
      // never appear in a network request — URL, headers, or body — and no
      // request may carry an identity-root secret in a named plaintext field.
      // This is the client half of the "no mnemonic / seed / root key /
      // HKDF PRK on the wire" invariant; server logs are covered by the
      // harness secret scan. Assertion messages intentionally reference word
      // runs by index only: the failure log must not reproduce the secret.
      expect(outboundRequests.length).toBeGreaterThan(0);
      const lowerKey = recoveryKey.toLowerCase();
      const lowerWords = recoveryWords.map((word) => word.toLowerCase());
      const wordRuns = lowerWords
        .slice(0, -2)
        .map((_, index) =>
          `${lowerWords[index]} ${lowerWords[index + 1]} ${lowerWords[index + 2]}`,
        );
      // Common wire encodings of the full key, checked against the RAW text
      // (decoding cannot reverse base64; percent/plus forms are also matched
      // directly in case a variant failed to decode).
      const encodedKeyForms = [
        encodeURIComponent(lowerKey).toLowerCase(),
        lowerKey.replace(/ /g, "+"),
        Buffer.from(lowerKey, "utf8").toString("base64").toLowerCase(),
        Buffer.from(lowerKey, "utf8").toString("base64url").toLowerCase(),
      ];
      // Field names from key-management.md §3.3/§7.1/§7.7.1: mnemonic, seed,
      // PRK, derived private keys, and the §7.7.1-named secret_b64u.
      const identityRootSecretField =
        /(?:"(?:mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|secret_b64u)"\s*:|(?:^|[?&\s])(?:mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|secret_b64u)\s*=)/i;
      for (const plantedFieldShape of [
        '{"root_seed":"synthetic"}',
        "?hkdf_prk=synthetic",
        "mnemonic=synthetic&next=1",
      ]) {
        expect(
          identityRootSecretField.test(plantedFieldShape),
          `secret-field detector missed planted shape: ${plantedFieldShape}`,
        ).toBe(true);
      }
      for (const outbound of outboundRequests) {
        for (const [variantIndex, auditText] of outbound.auditTexts.entries()) {
          const lowerText = auditText.toLowerCase();
          expect(
            lowerText.includes(lowerKey),
            `full recovery key leaked to ${outbound.target} (variant ${variantIndex})`,
          ).toBe(false);
          for (const [runIndex, run] of wordRuns.entries()) {
            expect(
              lowerText.includes(run),
              `recovery key words ${runIndex}..${runIndex + 2} leaked to ${outbound.target} (variant ${variantIndex})`,
            ).toBe(false);
          }
          expect(
            identityRootSecretField.test(auditText),
            `identity-root secret field leaked to ${outbound.target} (variant ${variantIndex})`,
          ).toBe(false);
        }
        const rawLower = outbound.auditTexts[0].toLowerCase();
        for (const [formIndex, encodedForm] of encodedKeyForms.entries()) {
          expect(
            rawLower.includes(encodedForm),
            `encoded recovery key (form ${formIndex}) leaked to ${outbound.target}`,
          ).toBe(false);
        }
      }
    } finally {
      await jointPage.close();
    }
  });

  test("carol creates an account then binds her client-signed cold-root inception", async ({
    request,
  }) => {
    // spec: account-lifecycle.md §2.1 + sync/third-party-invites.md §3
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth not started for this run");

    const user = uniqueUser("s7-carol-email");
    const handle = user.handle.slice(1);
    const account = await registerCoauthPasswordAccount(request, coauth!, {
      handle,
    });
    const resolved = await resolvePrincipalDid(request, account.did);
    expect(resolved.log).toHaveLength(1);
    expect(resolved.document.verificationMethod).toBeUndefined();
    expect(resolved.document.assertionMethod).toBeUndefined();
    expect(resolved.document.capabilityDelegation).toBeUndefined();

    const duplicate = await request.post(
      `${coauth}/_coauth/account/auth/register`,
      {
        data: {
          handle,
          email: `${handle}-duplicate@example.test`,
          password: "ArkretE2E!2026",
          password_confirm: "ArkretE2E!2026",
        },
      },
    );
    expect(duplicate.status(), await duplicate.text()).toBe(200);
    expect(await duplicate.json()).toMatchObject({
      status: "error",
      error: "handle_exists",
    });
  });

});
