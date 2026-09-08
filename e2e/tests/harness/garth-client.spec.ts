// Garth's client runtime driven without Inkson or a browser.
//
// This is deliberately separate from `test-client-parity.spec.ts`. A test that
// declares Playwright's `browser` fixture starts a browser before its runtime
// client-kind branch runs, so putting the Garth branch in that spec made the
// `joint-api` lane browser-shaped even when it selected Garth. The parity spec
// remains useful in an Inkson lane; this one is the fail-closed joint-api
// assertion.

import { expect, test } from "../../helpers/arkret-test";
import {
  coauthBaseUrl,
  coauthOidcClientId,
  mockEmailBaseUrl,
  solandBaseUrl,
} from "../../helpers/env";
import { GarthTestClient } from "../../helpers/test-client-garth";

test.describe("Garth client without Inkson @fully-implemented", () => {
  test("founds a principal, syncs, and restores its durable cursor", async ({}, testInfo) => {
    testInfo.setTimeout(Math.max(testInfo.timeout, 300_000));
    const coauth = coauthBaseUrl();
    testInfo.skip(!coauth, "the Garth client journey requires a Coauth deployment");
    testInfo.skip(
      !process.env.COTEST_PROVISION_BIN,
      "the Garth client runs inside cotest-provision; run through run-joint-e2e.ps1",
    );

    const clientId = coauthOidcClientId();
    expect(clientId, "COTEST_OIDC_CLIENT_ID must be set alongside Coauth").toBeTruthy();
    const client = new GarthTestClient({
      endpoints: {
        coauthBaseUrl: coauth as string,
        solandBaseUrl: solandBaseUrl(),
        mockEmailBaseUrl: mockEmailBaseUrl(),
      },
      oidcClientId: clientId as string,
    });

    try {
      const user = await client.createUser("joint-api-garth");
      expect(user.principalId).toMatch(/^ak:did_core:/);
      expect(user.deviceId).toMatch(/^ak:device:/);
      expect(user.stationId).toMatch(/^ak:did_core:/);

      const sync = await client.syncAccount(user);
      testInfo.annotations.push({
        type: "client:garth",
        description: sync.detail,
      });
      expect(sync.hasCursor, "Garth completed a sync round but committed no cursor").toBe(
        true,
      );
      expect(sync.cursor).toBeTruthy();

      const restored = await client.cursorAfterRestart(user);
      expect(restored, "Garth lost its cursor across a restart").toBe(sync.cursor);
    } finally {
      await client.dispose();
    }
  });
});
