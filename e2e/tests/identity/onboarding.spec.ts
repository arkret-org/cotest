import { expect, test } from "@playwright/test";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import { coauthBaseUrl } from "../../helpers/env";

test.describe("first registration PCR genesis @fully-implemented", () => {
  test("the creating device is accepted without a second approver", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "joint Coauth endpoint is unavailable");

    const account = await registerCoauthPasswordAccount(request, coauth!);
    const checkpoint = account.principalRegistrationCheckpoint;
    const unit = checkpoint.pcr_genesis_unit as Record<string, unknown>;
    expect(unit).toBeTruthy();
    const events = unit.events as Array<Record<string, unknown>>;
    expect(events).toHaveLength(2);
    expect(events.map((event) => event.kind)).toEqual([
      "ak.realm.create",
      "ak.device.authorize",
    ]);
    expect(account.pcrGenesisReceipt).toBeTruthy();
    expect(account.initialGrant.eventSigningKey?.publicJwk.x).toBeTruthy();
  });
});
