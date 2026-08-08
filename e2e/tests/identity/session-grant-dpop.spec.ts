import { expect, test } from "@playwright/test";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  generateDpopDeviceKey,
  mintDpopProof,
} from "../../helpers/session-grant-dpop";

const VIEWER_PATH = "/_arkret/self/account/viewer";

test.describe("Standard session grant DPoP boundary @fully-implemented", () => {
  test("the post-genesis grant authenticates only with its bound holder key", async ({
    request,
  }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "joint Coauth endpoint is unavailable");
    const account = await registerCoauthPasswordAccount(request, coauth!);
    const url = `${solandBaseUrl()}${VIEWER_PATH}`;
    const grant = account.initialGrant;

    const accepted = await request.get(url, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop: mintDpopProof({
          deviceKey: account.initialHolderKey,
          method: "GET",
          url,
          grantJwt: grant.grantJwt,
        }),
      },
    });
    expect(accepted.status(), await accepted.text()).toBe(200);

    const wrongKey = generateDpopDeviceKey();
    const rejected = await request.get(url, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop: mintDpopProof({
          deviceKey: wrongKey,
          method: "GET",
          url,
          grantJwt: grant.grantJwt,
        }),
      },
    });
    expect([401, 403]).toContain(rejected.status());
  });

  test("wrong htu and missing DPoP fail closed", async ({ request }) => {
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "joint Coauth endpoint is unavailable");
    const account = await registerCoauthPasswordAccount(request, coauth!);
    const url = `${solandBaseUrl()}${VIEWER_PATH}`;
    const grant = account.initialGrant;

    const wrongHtu = await request.get(url, {
      headers: {
        authorization: `Bearer ${grant.grantJwt}`,
        dpop: mintDpopProof({
          deviceKey: account.initialHolderKey,
          method: "GET",
          url: `${solandBaseUrl()}/_arkret/self/account/describe`,
          grantJwt: grant.grantJwt,
        }),
      },
    });
    expect([401, 403]).toContain(wrongHtu.status());

    const missing = await request.get(url, {
      headers: { authorization: `Bearer ${grant.grantJwt}` },
    });
    expect([401, 403]).toContain(missing.status());
  });
});
