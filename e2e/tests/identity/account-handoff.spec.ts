import { expect, test } from "../../helpers/arkret-test";
import {
  createCanonicalAccountHandoff,
  registerCoauthPasswordAccount,
} from "../../helpers/coauth-register";
import { assertDualSolandNotRequired, coauthBaseUrl, hasDualSoland, solandBaseUrl, solandServiceId } from "../../helpers/env";
import { canonicalJson } from "../../helpers/soland-api";
import { selfPathGrantHeaders } from "../../helpers/session-grant-dpop";

test.describe("account handoff and PCR genesis @fully-implemented", () => {
  test("each Station registers through its own Account Authority and rejects the other Station grant", async ({ request }) => {
    if (!hasDualSoland()) {
      assertDualSolandNotRequired("Station Account Authority isolation");
      test.skip(true, "requires the dual Station topology");
    }
    expect(coauthBaseUrl("alpha")).toBeTruthy();
    expect(coauthBaseUrl("beta")).toBeTruthy();
    expect(coauthBaseUrl("alpha")).not.toBe(coauthBaseUrl("beta"));
    for (const server of ["alpha", "beta"] as const) {
      const account = await registerCoauthPasswordAccount(request, coauthBaseUrl(server)!, { server });
      expect(account.initialGrant.accountId).toEqual({ principal_id: account.id, station_id: solandServiceId(server) });
      const ownUrl = `${solandBaseUrl(server)}/_arkret/self/events`;
      const own = await request.fetch(ownUrl, { method: "QUERY", data: canonicalJson({ actor_ids: [{ kind: "account", account_id: account.initialGrant.accountId }], limit: 1 }), headers: { "Content-Type": "application/json", ...selfPathGrantHeaders({ deviceKey: account.initialHolderKey, grantJwt: account.initialGrant.grantJwt, method: "QUERY", url: ownUrl }) } });
      expect(own.status(), "the owning Station accepts the registered Account").toBe(200);
      const otherUrl = `${solandBaseUrl(server === "alpha" ? "beta" : "alpha")}/_arkret/self/events`;
      const other = await request.fetch(otherUrl, { method: "QUERY", data: canonicalJson({ actor_ids: [{ kind: "account", account_id: account.initialGrant.accountId }], limit: 1 }), headers: { "Content-Type": "application/json", ...selfPathGrantHeaders({ deviceKey: account.initialHolderKey, grantJwt: account.initialGrant.grantJwt, method: "QUERY", url: otherUrl }) } });
      expect(other.status(), "the same principal projection must not cross the grant audience boundary").toBe(401);
    }
  });

  test("registration atomically returns the PCR genesis receipt and first Standard grant", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "joint Coauth endpoint is unavailable");

    const account = await registerCoauthPasswordAccount(request, coauth!);
    expect(account.pcrGenesisReceipt.scope).toEqual(
      expect.objectContaining({ kind: "pcr_genesis_unit" }),
    );
    expect(account.initialGrant.principalId).toBe(account.id);
    expect(account.initialGrant.audience).toBe(solandServiceId());
    expect(account.initialGrant.scopes).toEqual([
      "ak.self.account.read.describe.v1",
      "ak.self.events.read.scan.v1",
    ]);

    const jwtPayload = JSON.parse(
      Buffer.from(
        account.initialGrant.grantJwt.split(".")[1],
        "base64url",
      ).toString("utf8"),
    ) as Record<string, unknown>;
    expect(jwtPayload.credential_class).toBe("standard");
    expect(jwtPayload.holder_binding).toEqual({
      kind: "human_device",
      device_binding: account.genesisDeviceId,
    });
    expect(jwtPayload).not.toHaveProperty("bootstrap_binding");
  });

  test("a bound account handoff preserves the principal identity", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "joint Coauth endpoint is unavailable");

    const account = await registerCoauthPasswordAccount(request, coauth!);
    const handoff = await createCanonicalAccountHandoff(request, coauth!, {
      audience: solandServiceId(),
      deviceId: account.genesisDeviceId,
      account,
    });
    expect(handoff.binding).toEqual(
      expect.objectContaining({ state: "bound", principal_id: account.id }),
    );
  });
});
