// Self-register a password-loginable coauth account through the client-signed
// did:webvh flow, so the account always has a verified principal binding before
// the real OIDC browser-login ceremony starts.
//
// Flow (coauth handlers/account/register.rs):
//   1. start WebVH registration and verify email
//   2. build and root-sign entry 0 in the client harness
//   3. finish with the signed DID operation and password
//
// The email code is minted asynchronously by coauth's notification worker. Under
// the dev email-delivery bypass (`registration_email_delivery_bypass_allowed`,
// which the joint harness always enables) it is the deterministic "123456" — the
// same fixed code the webvh path returns in-band as `dev_code`. We poll
// verify-email until the worker has stored it.

import { randomUUID } from "node:crypto";
import { type APIRequestContext } from "@playwright/test";
import { mockEmailBaseUrl, solandBaseUrl } from "./env";
import { cotestWire } from "./soland-api";

// The deterministic verification code coauth mints under the dev email-delivery
// bypass. Mirrors coauth tasks/notifications.rs + handlers/account/register.rs.
export const COAUTH_DEV_EMAIL_CODE = "123456";

export type CoauthPasswordAccount = {
  handle: string;
  email: string;
  password: string;
  displayName: string;
  did: string;
  principalId?: string;
  bootstrapDeviceId: string;
  recoveryKey: string;
  pendingPrincipalRegistration: Record<string, unknown>;
  bootstrapClaimed?: boolean;
};

type PrincipalRegistrationFixture = {
  did_operation: Record<string, unknown>;
  recovery_key: string;
  checkpoint: Record<string, unknown>;
};

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export async function latestMockEmailCode(
  request: APIRequestContext,
  email: string,
): Promise<string | undefined> {
  const base = mockEmailBaseUrl();
  if (!base) {
    return undefined;
  }
  const response = await request.get(
    `${base}/mock/email/verification/inbox?to=${encodeURIComponent(email)}`,
  );
  if (!response.ok()) {
    return undefined;
  }
  const body = objectRecord(await response.json());
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const token = objectRecord(messages[index])?.token;
    if (typeof token === "string" && token.length > 0) {
      return token;
    }
  }
  return undefined;
}

export async function registerCoauthPasswordAccount(
  request: APIRequestContext,
  coauthBase: string,
  opts: { handle?: string; password?: string } = {},
): Promise<CoauthPasswordAccount> {
  const slug = (opts.handle ?? `e2e-oidc-${randomUUID()}`).toLowerCase();
  if (!/^[a-z0-9_-]+$/.test(slug)) {
    throw new Error(`coauth test handle must be a bare localpart: ${slug}`);
  }
  const password = opts.password ?? "ArkretE2E!2026";
  const email = `${slug}@example.test`;
  const displayName = `E2E ${slug}`;
  const base = `${coauthBase}/_coauth/account/auth/register/webvh`;
  const startResponse = await request.post(`${base}/start`, {
    data: { handle: slug, principal_server_url: solandBaseUrl() },
  });
  const startRaw = await startResponse.text();
  const started = objectRecord(startRaw ? JSON.parse(startRaw) : {});
  const id = typeof started?.registration_id === "string"
    ? started.registration_id
    : undefined;
  const enrollmentAuthorityDid =
    typeof started?.enrollment_authority_did === "string"
      ? started.enrollment_authority_did
      : undefined;
  if (startResponse.status() !== 200 || started?.status !== "success" || !id || !enrollmentAuthorityDid) {
    throw new Error(`coauth WebVH register start failed (${startResponse.status()}): ${startRaw}`);
  }

  const emailResponse = await request.post(`${base}/${id}/email`, {
    data: { email },
  });
  const emailRaw = await emailResponse.text();
  const emailBody = objectRecord(emailRaw ? JSON.parse(emailRaw) : {});
  if (emailResponse.status() !== 200 || emailBody?.status !== "sent") {
    throw new Error(`coauth WebVH register email failed (${emailResponse.status()}): ${emailRaw}`);
  }
  const devCode = typeof emailBody.dev_code === "string" ? emailBody.dev_code : undefined;
  const code = mockEmailBaseUrl()
    ? await latestMockEmailCode(request, email)
    : devCode ?? COAUTH_DEV_EMAIL_CODE;
  if (!code) {
    throw new Error("coauth WebVH registration verification code is unavailable");
  }
  const verifyResponse = await request.post(`${base}/${id}/verify-email`, {
    data: { code },
  });
  const verifyRaw = await verifyResponse.text();
  const verified = objectRecord(verifyRaw ? JSON.parse(verifyRaw) : {});
  if (verifyResponse.status() !== 200 || verified?.status !== "success") {
    throw new Error(`coauth WebVH verify-email failed (${verifyResponse.status()}): ${verifyRaw}`);
  }

  const deviceSuffix = randomUUID().replace(/-/g, "").slice(0, 12);
  const bootstrapDeviceId = `ak:device:01904100-0000-7000-8000-${deviceSuffix}`;
  const describeResponse = await request.get(`${solandBaseUrl()}/_arkret/describe`);
  const describeRaw = await describeResponse.text();
  const describe = objectRecord(describeRaw ? JSON.parse(describeRaw) : {});
  const trustDomain = typeof describe?.trust_domain === "string"
    ? describe.trust_domain
    : undefined;
  if (!describeResponse.ok() || !trustDomain) {
    throw new Error(`soland describe omitted trust_domain (${describeResponse.status()}): ${describeRaw}`);
  }
  const fixture = cotestWire<PrincipalRegistrationFixture>(
    "principal-registration-fixture",
    {
      principal_server_url: solandBaseUrl(),
      gate_account_base: `${coauthBase.replace(/\/$/, "")}/_arkret/gate/account`,
      registration_id: id,
      handle: slug,
      email,
      device_id: bootstrapDeviceId,
      enrollment_authority_did: enrollmentAuthorityDid,
      trust_domain: trustDomain,
    },
  );
  const did = fixture.checkpoint.did;
  if (typeof did !== "string" || fixture.recovery_key.split(/\s+/).length !== 24) {
    throw new Error("cotest principal registration fixture is incomplete");
  }
  const finishResponse = await request.post(`${base}/${id}/finish`, {
    data: {
      did_operation: fixture.did_operation,
      password,
      password_confirm: password,
    },
  });
  const finishRaw = await finishResponse.text();
  const finished = objectRecord(finishRaw ? JSON.parse(finishRaw) : {});
  if (finishResponse.status() !== 200 || finished?.status !== "success") {
    throw new Error(`coauth WebVH register finish failed (${finishResponse.status()}): ${finishRaw}`);
  }
  const finishedDid = objectRecord(finished.did_operation)?.did;
  if (typeof finishedDid !== "string" || finishedDid !== did) {
    throw new Error(`coauth WebVH finish did not include the bound DID: ${finishRaw}`);
  }

  return {
    handle: slug,
    email,
    password,
    displayName,
    did,
    bootstrapDeviceId,
    recoveryKey: fixture.recovery_key,
    pendingPrincipalRegistration: fixture.checkpoint,
  };
}
