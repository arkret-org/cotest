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

import { expect, test } from "../../helpers/provisioning-fixture";

test.describe("provisioning bridge @fully-implemented", () => {
  test("the suite founds a principal through the Rust chain", async ({
    canonicalProvisioning,
  }) => {
    const { station } = canonicalProvisioning;
    expect(station.serviceId).toMatch(/^ak:did_core:/);
    expect(station.trustDomain.trim()).not.toBe("");

    const principal = await canonicalProvisioning.provisionPrincipal("ts-bridge");

    expect(principal.recoveryKey.split(/\s+/)).toHaveLength(24);
    expect(principal.accountId.principal_id).toMatch(/^ak:did_core:/);
    // The AccountId is closed: the Station half is the Station that registered
    // it, not whatever the caller asked for.
    expect(principal.accountId.station_id).toBe(station.serviceId);
    expect(principal.grant.sessionGrant, "grant carried no session JWT").toBeTruthy();
    expect(principal.grant.audienceId).toBe(station.serviceId);
    expect(principal.grant.deviceId).toBe(principal.deviceId);
    expect(principal.grant.grantedScope.length).toBeGreaterThan(0);
    // The Event signer's verification method names this principal's own DID and
    // its founding device. Its seed is not here, and must not be.
    expect(principal.eventVerificationMethod).toBe(
      `${principal.did}#${principal.deviceId}`,
    );
    expect(principal).not.toHaveProperty("eventSigningSeedB64url");
    expect(principal).not.toHaveProperty("checkpoint");
  });

  test("a second principal reuses the worker's bridge", async ({
    canonicalProvisioning,
  }) => {
    // Two principals from one bridge. This is the property the worker-scoped
    // fixture exists for: the second call re-registers and re-authenticates
    // against the same process, so its handoff authorizes as the account it
    // just created rather than as the one still signed in from the first.
    const first = await canonicalProvisioning.provisionPrincipal("ts-bridge-a");
    const second = await canonicalProvisioning.provisionPrincipal("ts-bridge-b");

    expect(second.accountId.principal_id).not.toBe(first.accountId.principal_id);
    expect(second.deviceId).not.toBe(first.deviceId);
    expect(second.accountId.station_id).toBe(first.accountId.station_id);
    expect(second.recoveryKey).not.toBe(first.recoveryKey);
  });

  test("the bridge does not hand its caller the account handoff grant", async ({
    canonicalProvisioning,
  }) => {
    // The founding device key and the handoff grant stay in the bridge process.
    // A caller that could read the grant could present it, so this asserts the
    // boundary rather than the chain.
    //
    // The account is registered here rather than borrowed from a sibling test:
    // a handoff authorizes against whatever session the bridge currently holds,
    // and a test that depended on the previous one having left one behind would
    // pass or fail on Playwright's worker assignment.
    const { deployment, station } = canonicalProvisioning;
    await canonicalProvisioning.bridge.provisionUnboundAccount(deployment, {
      handle: `ts-bridge-boundary-${Date.now()}${Math.floor(Math.random() * 1000)}`,
      password: "1amTester!",
    });
    const handoff = await canonicalProvisioning.bridge.createAccountHandoff({
      coauthBaseUrl: deployment.coauthBaseUrl,
      clientId: deployment.oidcClientId,
      audienceId: station.serviceId,
      deviceLabel: `ts-bridge-boundary-${Date.now()}`,
    });

    expect(handoff.handoffId).not.toBe("");
    expect(handoff.binding).toHaveProperty("identity_creation_lease");
    expect(handoff.binding).not.toHaveProperty("account_handoff_grant");
    expect(handoff.binding).not.toHaveProperty("founding_device_key");
  });
});
