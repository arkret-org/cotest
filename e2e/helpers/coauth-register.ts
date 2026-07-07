// Self-register a password-loginable coauth account over the registration API,
// so the real OIDC browser-login ceremony (oidc-login-flow.spec.ts) can run
// self-contained instead of depending on a pre-seeded account.
//
// Flow (coauth handlers/account/register.rs):
//   1. POST /auth/register                {handle,email,password,password_confirm} → next:"verify_email"
//   2. POST /auth/register/:id/verify-email {code}                                 → next:"display_name"
//   3. POST /auth/register/:id/display-name {display_name}                         → next:"finish"
//   4. POST /auth/register/:id/finish                                              → account created
//
// The email code is minted asynchronously by coauth's notification worker. Under
// the dev email-delivery bypass (`registration_email_delivery_bypass_allowed`,
// which the joint harness always enables) it is the deterministic "123456" — the
// same fixed code the webvh path returns in-band as `dev_code`. We poll
// verify-email until the worker has stored it.

import { randomUUID } from "node:crypto";
import { type APIRequestContext } from "@playwright/test";

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
};

type RegStep = string | undefined;

type CoauthRegisterResponse = {
  status?: string;
  id?: string;
  next_step?: string;
  error?: string;
  did?: string;
};

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function parseRegisterResponse(raw: string): CoauthRegisterResponse | null {
  try {
    const parsed = raw ? JSON.parse(raw) : {};
    const record = objectRecord(parsed);
    if (!record) {
      return null;
    }
    return {
      status: typeof record.status === "string" ? record.status : undefined,
      id: typeof record.id === "string" ? record.id : undefined,
      next_step:
        typeof record.next_step === "string" ? record.next_step : undefined,
      error: typeof record.error === "string" ? record.error : undefined,
      did: typeof record.did === "string" ? record.did : undefined,
    };
  } catch {
    return null;
  }
}

async function postJson(
  request: APIRequestContext,
  url: string,
  data: Record<string, unknown>,
): Promise<{ status: number; body: CoauthRegisterResponse | null; raw: string }> {
  const resp = await request.post(url, { data });
  const raw = await resp.text();
  const body = parseRegisterResponse(raw);
  return { status: resp.status(), body, raw };
}

// Poll verify-email until the async-minted code lands. `invalid_code` (worker
// hasn't stored the code yet) and `rate_limited` are retryable; anything else
// is a hard failure.
async function verifyEmailWithRetry(
  request: APIRequestContext,
  coauthBase: string,
  id: string,
): Promise<RegStep> {
  const deadline = Date.now() + 30_000;
  let last = "";
  // Give the notification worker a beat to mint+store the code before the
  // first attempt, to avoid burning rate-limit budget on guaranteed misses.
  await new Promise((r) => setTimeout(r, 1_000));
  while (Date.now() < deadline) {
    const { status, body, raw } = await postJson(
      request,
      `${coauthBase}/_coauth/account/auth/register/${id}/verify-email`,
      { code: COAUTH_DEV_EMAIL_CODE },
    );
    if (status === 200 && body?.status === "success") {
      return body.next_step as RegStep;
    }
    last = raw;
    const err = body?.error;
    if (err && err !== "invalid_code" && err !== "rate_limited") {
      throw new Error(`coauth verify-email failed: ${raw}`);
    }
    await new Promise((r) => setTimeout(r, 1_500));
  }
  throw new Error(
    `coauth verify-email timed out waiting for the dev code (last: ${last})`,
  );
}

async function beginRegistrationWithRetry(
  request: APIRequestContext,
  base: string,
  data: Record<string, unknown>,
): Promise<{ id: string; next: RegStep }> {
  const deadline = Date.now() + 60_000;
  let last = "";
  while (Date.now() < deadline) {
    const begin = await postJson(request, base, data);
    if (
      begin.status === 200 &&
      begin.body?.status === "success" &&
      begin.body?.id
    ) {
      return {
        id: begin.body.id,
        next: begin.body.next_step,
      };
    }
    last = begin.raw;
    if (begin.body?.error !== "rate_limited") {
      throw new Error(`coauth register failed (${begin.status}): ${begin.raw}`);
    }
    await new Promise((r) => setTimeout(r, 2_000));
  }
  throw new Error(`coauth register timed out after rate limits (last: ${last})`);
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
  const password = opts.password ?? "CokretE2E!2026";
  const email = `${slug}@example.test`;
  const displayName = `E2E ${slug}`;
  const base = `${coauthBase}/_coauth/account/auth/register`;

  // 1. begin password registration
  const begin = await beginRegistrationWithRetry(request, base, {
    handle: slug,
    email,
    password,
    password_confirm: password,
  });
  const id = begin.id;
  let next = begin.next;

  // 2. verify email (async-minted dev code)
  if (next === "verify_email") {
    next = await verifyEmailWithRetry(request, coauthBase, id);
  }

  // 3. display name
  if (next === "display_name") {
    const dn = await postJson(request, `${base}/${id}/display-name`, {
      display_name: displayName,
    });
    if (dn.status !== 200 || dn.body?.status !== "success") {
      throw new Error(`coauth display-name failed (${dn.status}): ${dn.raw}`);
    }
    next = dn.body.next_step;
  }

  // 4. finish (creates the account and returns the local coauth subject DID)
  const fin = await postJson(request, `${base}/${id}/finish`, {});
  if (fin.status !== 200 || fin.body?.status !== "success") {
    throw new Error(`coauth finish failed (${fin.status}): ${fin.raw}`);
  }
  const did = fin.body?.did;
  if (!did) {
    throw new Error(`coauth finish did not include did: ${fin.raw}`);
  }

  return {
    handle: slug,
    email,
    password,
    displayName,
    did,
  };
}
