// The old TypeScript orchestration and the Rust chain, run side by side.
//
// 1725 asks for this before any consumer is migrated: two isolated accounts,
// one founded by each path, compared on the invariants that have to hold rather
// than on values that are random by design. Nothing here requires the two to
// agree on a DID, a grant, a device id or a timestamp — those differ on every
// run of either path.
//
// The old path is not treated as an oracle. Where the two disagree, this suite
// says so and the disagreement is adjudicated against `arkret-spec`; it does
// not encode "whatever `coauth-register.ts` does" as the requirement. What it
// does establish is that the Rust path is not *missing* anything the old path
// produces, which is the question that gates migrating consumers off it.

import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import { coauthBaseUrl, colandBaseUrl } from "../../helpers/env";
import { expect, test } from "../../helpers/provisioning-fixture";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";

const SELF_ACCOUNT_VIEWER = "ak.self.account.read.viewer.v1";

test.describe("provisioning dual run @fully-implemented", () => {
  test("both paths found a principal the Station will answer for", async ({
    canonicalProvisioning,
    request,
  }) => {
    test.setTimeout(180_000);
    const { station } = canonicalProvisioning;

    // Isolated accounts, not one account founded twice: the paths must not be
    // able to pass by inheriting each other's server-side state.
    const rust = await canonicalProvisioning.provisionPrincipal("dual-rust");
    const legacy = await registerCoauthPasswordAccount(
      request,
      coauthBaseUrl() as string,
      { handle: `dual-ts-${Date.now()}${Math.floor(Math.random() * 1000)}` },
    );

    // --- identity binding ---------------------------------------------------
    expect(rust.accountId.principal_id).toMatch(/^ak:did_core:/);
    expect(legacy.initialGrant.accountId.principal_id).toMatch(/^ak:did_core:/);
    // Closed AccountId, same Station, both paths. A principal id without the
    // Station half is not addressable, and a Station half that is not this
    // deployment means the chain bound somewhere else.
    expect(rust.accountId.station_id).toBe(station.serviceId);
    expect(legacy.initialGrant.accountId.station_id).toBe(station.serviceId);
    expect(legacy.initialGrant.principalId).toBe(
      legacy.initialGrant.accountId.principal_id,
    );

    // --- grant scope and audience -------------------------------------------
    expect(rust.grant.audienceId).toBe(station.serviceId);
    expect(legacy.initialGrant.audience).toBe(station.serviceId);
    expect(rust.grant.deviceId).toBe(rust.deviceId);
    // Scopes are the one place a silently narrower Rust grant would show up as
    // a later permission failure in a migrated consumer rather than here. Both
    // come from `granted_scope` on the same register response; each side
    // renames it on the way out.
    expect(
      rust.grant.grantedScope.length,
      "the Rust path's grant carried no scope",
    ).toBeGreaterThan(0);
    expect(new Set(rust.grant.grantedScope)).toEqual(
      new Set(legacy.initialGrant.scopes),
    );

    // --- recovery material --------------------------------------------------
    expect(rust.recoveryKey.split(/\s+/)).toHaveLength(24);
    expect(legacy.recoveryKey.split(/\s+/)).toHaveLength(24);
    expect(rust.recoveryKey).not.toBe(legacy.recoveryKey);

    // --- the grant actually works -------------------------------------------
    // Everything above reads what the register step returned. This presents
    // each grant to the Station, which is what a well-formed but unusable grant
    // would fail.
    const rustRead = await canonicalProvisioning.readSelfAccountViewer(rust);
    expect(
      rustRead.status,
      `Station refused the Rust path's own grant: ${JSON.stringify(rustRead.body)}`,
    ).toBe(200);

    // `account/viewer`, not `account/describe`: the latter answers with the
    // service description and resolves no session, so both paths would have
    // "passed" it without either grant being honoured.
    const legacyUrl = `${colandBaseUrl()}/_arkret/self/account/viewer`;
    const legacyResponse = await request.get(legacyUrl, {
      headers: {
        ...selfPathGrantHeaders({
          deviceKey: legacy.initialHolderKey,
          grantJwt: legacy.initialGrant.grantJwt,
          method: "GET",
          url: legacyUrl,
        }),
        "arkret-operation": SELF_ACCOUNT_VIEWER,
      },
    });
    const legacyText = await legacyResponse.text();
    expect(
      legacyResponse.status(),
      `Station refused the TypeScript path's grant: ${legacyText}`,
    ).toBe(200);
    const legacyRead = JSON.parse(legacyText) as Record<string, unknown>;

    // --- the two answers have the same shape --------------------------------
    // Not the same values: these are different principals. The same keys, so a
    // consumer reading this response cannot tell which path founded the
    // principal it is looking at. That is the migration precondition.
    expect(new Set(Object.keys(rustRead.body))).toEqual(
      new Set(Object.keys(legacyRead)),
    );
    expect(rustRead.body.principal_id).toBe(rust.accountId.principal_id);
    expect(legacyRead.principal_id).toBe(
      legacy.initialGrant.accountId.principal_id,
    );
    // The founding device landed on the account in both paths. A grant that
    // authenticated while its device never registered would read fine here and
    // fail on the next DPoP-bound write.
    expect(deviceIds(rustRead.body)).toContain(rust.deviceId);
    expect(deviceIds(legacyRead)).toContain(legacy.genesisDeviceId);
  });

  test("a grant reads its own account and not a sibling's", async ({
    canonicalProvisioning,
  }) => {
    test.setTimeout(180_000);
    // Two principals founded through the same bridge process. If the bridge
    // leaked state between them — a reused device key, a stale grant, the wrong
    // handoff — this is where it shows, and it would show as one principal
    // reading the other's account rather than as an error.
    const first = await canonicalProvisioning.provisionPrincipal("dual-iso-a");
    const second = await canonicalProvisioning.provisionPrincipal("dual-iso-b");

    const firstRead = await canonicalProvisioning.readSelfAccountViewer(first);
    const secondRead =
      await canonicalProvisioning.readSelfAccountViewer(second);

    expect(firstRead.status).toBe(200);
    expect(secondRead.status).toBe(200);
    expect(firstRead.body.principal_id).toBe(first.accountId.principal_id);
    expect(secondRead.body.principal_id).toBe(second.accountId.principal_id);
    expect(firstRead.body.principal_id).not.toBe(secondRead.body.principal_id);
    expect(deviceIds(firstRead.body)).not.toContain(second.deviceId);
  });
});

function deviceIds(body: Record<string, unknown>): string[] {
  const devices = body.devices;
  expect(
    Array.isArray(devices),
    `account viewer carried no devices: ${JSON.stringify(body)}`,
  ).toBe(true);
  return (devices as Array<Record<string, unknown>>).map((device) =>
    String(device.device_id),
  );
}
