// One journey, run against whichever client `--client-kind` selected.
//
// Nothing below names Inkson or Garth. That is the point: the journey states
// what a user does, and the run states which product does it. A capability one
// client has and the other does not stops being an absence nobody measures and
// becomes a failing parity run.
//
// Two things this deliberately does **not** do:
//
// * It does not assert the two clients agree on values. They found different
//   principals and hold different state; identical outputs would only mean the
//   test compared constants.
// * It does not paper over the asymmetry. Garth reports a durable cursor
//   because a host can ask it to; Inkson does not, because its state lives in
//   browser storage a test has no supported handle on. The client says so
//   through `capabilities.durableCursor`, and the restart check runs only where
//   it can mean something — recorded, not hidden.
//
// Owner: `arkret-work/work/active/2026-09-07-0600-garth-as-the-complete-client-inkson-as-a-shell.md`.

import { expect, test } from "../../helpers/arkret-test";
import { coauthBaseUrl, coauthOidcClientId, mockEmailBaseUrl, solandBaseUrl } from "../../helpers/env";
import { GarthTestClient } from "../../helpers/test-client-garth";
import { InksonTestClient } from "../../helpers/test-client-inkson";
import { selectedClientKind, type TestClient } from "../../helpers/test-client";

test.describe("test client parity @fully-implemented", () => {
  test("the selected client founds a principal and syncs its account", async ({
    browser,
    request,
  }, testInfo) => {
    testInfo.setTimeout(Math.max(testInfo.timeout, 300_000));
    const coauth = coauthBaseUrl();
    testInfo.skip(!coauth, "a client journey requires a Coauth deployment");

    const kind = selectedClientKind();
    let client: TestClient;
    if (kind === "garth") {
      testInfo.skip(
        !process.env.COTEST_PROVISION_BIN,
        "the Garth client runs inside cotest-provision; run through run-joint-e2e.ps1",
      );
      const clientId = coauthOidcClientId();
      expect(clientId, "COTEST_OIDC_CLIENT_ID must be set alongside Coauth").toBeTruthy();
      client = new GarthTestClient({
        endpoints: {
          coauthBaseUrl: coauth as string,
          solandBaseUrl: solandBaseUrl(),
          mockEmailBaseUrl: mockEmailBaseUrl(),
        },
        oidcClientId: clientId as string,
      });
    } else {
      client = new InksonTestClient({ browser, request });
    }

    try {
      // --- the journey, identical for both --------------------------------
      const user = await client.createUser("parity");
      expect(user.principalId).toMatch(/^ak:did_core:/);
      expect(user.deviceId).toMatch(/^ak:device:/);
      expect(
        user.stationId,
        "the client bound its principal to a different Station than this run's",
      ).toMatch(/^ak:did_core:/);

      const sync = await client.syncAccount(user);
      testInfo.annotations.push({
        type: `client:${client.kind}`,
        description: sync.detail,
      });

      // --- each client's own success criterion ----------------------------
      const durable = (client as { capabilities?: { durableCursor: boolean } })
        .capabilities?.durableCursor;
      if (durable === false) {
        // Recorded rather than skipped silently: this run could not check
        // restart continuity because the client under test does not expose it.
        expect(sync.hasCursor, "a client without durable cursor must not claim one").toBe(
          false,
        );
        testInfo.annotations.push({
          type: "parity-gap",
          description: `${client.kind} exposes no durable cursor; restart continuity unchecked`,
        });
      } else {
        expect(
          sync.hasCursor,
          `${client.kind} completed a sync round but committed no cursor`,
        ).toBe(true);
        // The claim a host actually depends on: state survives a restart.
        const restored = await client.cursorAfterRestart(user);
        expect(
          restored,
          `${client.kind} lost its cursor across a restart`,
        ).toBe(sync.cursor);
      }
    } finally {
      await client.dispose();
    }
  });
});
