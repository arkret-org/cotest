// Federation security hardening
// Contract: e2e/scenarios/federation/security-hardening.md
//
// These checks are intentionally gated by an explicit harness flag because they
// require soland processes to be started with hardened deployment env:
// COTEST_EXPECT_FEDERATION_DENYLIST=1 means beta deny-lists alpha via
// SOLAND_FEDERATION_DENYLIST and alpha deny-lists beta via
// SOLAND_FEDERATION_PEER_DENYLIST.
//
// The topology must otherwise be fully reachable — see the CI wiring note in
// e2e/scenarios/federation/security-hardening.md. If the two nodes cannot talk
// at all, both assertions hold no matter what the denylist does.

import { expect, test } from "../../helpers/arkret-test";
import {
  assertDualSolandNotRequired,
  hasDualSoland,
  optionalEnv,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
import {
  createRealmApi,
  makeFederationEvent,
  peerEventFrontierApi,
  rawPushFederationEvents,
  sendMessageApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  if (!hasDualSoland()) {
    assertDualSolandNotRequired("federation security hardening");
    test.skip(true, "federation security hardening requires dual soland topology");
  }
});

test.describe("federation security hardening", () => {
  test("denylisted peer inbound push is hard-rejected", async ({ request }) => {
    test.skip(
      optionalEnv("COTEST_EXPECT_FEDERATION_DENYLIST") !== "1",
      "requires beta SOLAND_FEDERATION_DENYLIST to include alpha service DID/domain",
    );

    const realmId = typedId("realm");
    const op = makeFederationEvent({
      realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: typedId("strand"),
        track_name: "discussion",
        content: { kind: "ak.content.text", body: "denylisted inbound" },
      },
    });
    const response = await rawPushFederationEvents(request, [op], {
      origin: solandServiceId("alpha"),
      destination: solandServiceId("beta"),
      realmId,
      server: "beta",
    });

    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.status()).toBeLessThan(500);
    const body = await response.json().catch(() => ({}));
    expect(wireErrCode(body)).toMatch(/capability_denied|unauthenticated|signature_invalid/);
  });

  test("denylisted peer is filtered from outbound fanout", async ({ request }) => {
    test.skip(
      optionalEnv("COTEST_EXPECT_FEDERATION_DENYLIST") !== "1",
      "requires alpha SOLAND_FEDERATION_PEER_DENYLIST to include beta service DID/domain",
    );

    const alice = uniqueUser("fed-deny-alice");
    await ensureRegistered(request, alice, { server: "alpha" });
    const aliceToken = await issueDevSession(request, alice, { server: "alpha" });
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        title: "denylisted outbound",
        public: false,
        plaintext_visible_services: [solandServiceId("alpha"), solandServiceId("beta")],
      },
      { server: "alpha" },
    );
    await sendMessageApi(request, aliceToken, realmId, "must not fan out", {
      server: "alpha",
    });

    await expect
      .poll(
        async () => {
          const frontier = await peerEventFrontierApi(request, realmId, { server: "beta" });
          return frontier.heads.length;
        },
        { timeout: 10_000, intervals: [1_000, 2_000] },
      )
      .toBe(0);
  });

});
