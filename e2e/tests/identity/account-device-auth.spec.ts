// Account auth + device authorization
// Contract: e2e/scenarios/identity/account-device-auth.md
// Spec: identity/account-lifecycle.md §2-§4, key-management.md §5-§6,
// crypto-media/device-lifecycle.md §2 and §5.4.

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";

test.describe.configure({ mode: "serial" });

test.describe("account auth + device strand", () => {
  test("session-grant refresh endpoint surface probe", async ({ request }) => {
    const probe = await request.post(
      `${solandBaseUrl()}/_arkret/gate/account/session-grants/refresh`,
      { data: { grant_jwt: "probe-grant", audience: "cotest" } },
    );
    expect(probe.status()).toBeLessThan(500);
  });

  test("expired session credential returns 401 on protected endpoint", async ({
    request,
  }) => {
    const meResp = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      { headers: { authorization: "Bearer expired-or-bogus-token" } },
    );
    expect([401, 403]).toContain(meResp.status());
  });

  test.fixme(
    "a bound principal authenticates and receives a short-lived device-bound grant without server-side DID minting",
    async () => {
      // Precondition: client-signed entry 0 is accepted and bound, the atomic
      // PCR bootstrap and recovery-material gate are complete, and Coauth has
      // never generated or retained principal root material.
    },
  );

  test.fixme(
    "a second authorized device receives its own grant for the same principal generation",
    async () => {
      // The second device must first complete the A/B-specific authorization
      // path. A login factor alone cannot mint a device authorization.
    },
  );

  test.fixme(
    "an active authorized device rotates a session grant with a holder proof",
    async () => {
      // Resolve the key from the device registry, not DID Document. The first
      // device authorization is already part of bootstrap and must not be
      // submitted later as an isolated Event.
    },
  );

  test.fixme(
    "hard logout terminates the grant chain and holder proof cannot restore it",
    async () => {
      // Run after the client-custodied onboarding and typed holder-proof
      // harness are live.
    },
  );
});
