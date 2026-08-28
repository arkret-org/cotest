import { expect, test } from "../../helpers/arkret-test";
import {
  createCanonicalAccountHandoff,
  registerCoauthPasswordAccount,
} from "../../helpers/coauth-register";
import { coauthBaseUrl, solandServiceId } from "../../helpers/env";

test.describe("account handoff and PCR genesis @fully-implemented", () => {
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
