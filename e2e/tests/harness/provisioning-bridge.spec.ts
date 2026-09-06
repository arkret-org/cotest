// The Playwright suite founding a principal through the Rust provisioning
// bridge.
//
// This is the seam 1725's P2 exists to create: the canonical registration chain
// lives once, in Rust, and the TypeScript suite calls it rather than carrying a
// second implementation. The assertions here are about that seam working — the
// chain's own correctness is asserted in `provisioning_live.rs`, against the
// same code, without a process boundary in the way.
//
// Browserless by construction: it drives a subprocess and reads JSON. It is in
// `api-only-migration.json`'s specialized lanes rather than pending migration
// because it has nowhere to migrate to — it *is* the Rust path.

import { expect, test } from "@playwright/test";

import { coauthBaseUrl, coauthOidcClientId, mockEmailBaseUrl, solandBaseUrl } from "../../helpers/env";
import { ProvisioningBridge } from "../../helpers/provisioning-bridge";

test.describe("provisioning bridge @fully-implemented", () => {
  test("the suite founds a principal through the Rust chain", async () => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "canonical provisioning requires a Coauth deployment");
    test.skip(
      !process.env.COTEST_PROVISION_BIN,
      "COTEST_PROVISION_BIN is set by the joint runner; this spec needs it",
    );
    const clientId = coauthOidcClientId();
    expect(clientId, "COTEST_OIDC_CLIENT_ID must be set alongside Coauth").toBeTruthy();

    const endpoints = {
      coauthBaseUrl: coauth as string,
      solandBaseUrl: solandBaseUrl(),
      mockEmailBaseUrl: mockEmailBaseUrl(),
    };
    const bridge = ProvisioningBridge.start();
    try {
      const slug = `ts-bridge-${Date.now()}${Math.floor(Math.random() * 1000)}`;
      await bridge.provisionUnboundAccount(endpoints, {
        handle: slug,
        password: "1amTester!",
      });

      const facts = await bridge.describeStation(endpoints);
      expect(facts.serviceId).toMatch(/^ak:did_core:/);
      expect(facts.trustDomain.trim()).not.toBe("");

      // The handoff authorizes as the account registered above. It only works
      // because the bridge kept that session — which is the property that makes
      // it a long-lived process rather than one spawn per call.
      const handoff = await bridge.createAccountHandoff({
        coauthBaseUrl: endpoints.coauthBaseUrl,
        clientId: clientId as string,
        audienceId: facts.serviceId,
        deviceLabel: slug,
      });
      expect(handoff.binding).toHaveProperty("identity_creation_lease");

      const deviceId = `ak:device:01904100-0000-7000-8000-${Date.now().toString(16).padStart(12, "0").slice(-12)}`;
      const principal = await bridge.foundPrincipal({
        handoffId: handoff.handoffId,
        endpoints,
        trustDomain: facts.trustDomain,
        audienceId: facts.serviceId,
        deviceId,
        displayName: `TS bridge ${slug}`,
      });

      expect(principal.recoveryKey.split(/\s+/)).toHaveLength(24);
      const grant = principal.sessionGrantOutcome as {
        audience_id?: string;
        device_id?: string;
        session_grant?: string;
        account_id?: { principal_id?: string; station_id?: string };
      };
      expect(grant.audience_id).toBe(facts.serviceId);
      expect(grant.device_id).toBe(deviceId);
      expect(grant.session_grant, "grant carried no session JWT").toBeTruthy();
      expect(grant.account_id?.principal_id).toMatch(/^ak:did_core:/);
      expect(grant.account_id?.station_id).toBe(facts.serviceId);

      // The grant material stays in the bridge. If this ever starts coming
      // back, the boundary has stopped protecting anything.
      expect(
        handoff.binding,
        "the bridge must not hand the account handoff grant to its caller",
      ).not.toHaveProperty("account_handoff_grant");
    } finally {
      await bridge.dispose();
    }
  });
});
