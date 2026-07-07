// Federation security hardening
// Contract: e2e/scenarios/federation/security-hardening.md
//
// These checks are intentionally gated by explicit harness flags because they
// require soland processes to be started with hardened deployment env:
// - COTEST_EXPECT_FEDERATION_DENYLIST=1 means beta deny-lists alpha and alpha
//   deny-lists beta via SOLAND_FEDERATION_DENYLIST / SOLAND_FEDERATION_PEER_DENYLIST.
// - COTEST_EXPECT_PRIVATE_EGRESS_BLOCKED=1 means the soland under test was
//   started with SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS=0 even in dev mode.

import { expect, test } from "@playwright/test";
import {
  assertDualSolandNotRequired,
  hasDualSoland,
  optionalEnv,
  solandBaseUrl,
  solandServiceDid,
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
      kind: "ck.message.create",
      payload: {
        strand_id: typedId("strand"),
        track_name: "discussion",
        content: { kind: "ck.content.text", body: "denylisted inbound" },
      },
    });
    const response = await rawPushFederationEvents(request, [op], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      realmId,
      server: "beta",
    });

    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.status()).toBeLessThan(500);
    const body = await response.json().catch(() => ({}));
    expect(wireErrCode(body)).toMatch(/capability_denied|unauthenticated|invalid_signature/);
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
        plaintext_visible_services: [solandServiceDid("alpha"), solandServiceDid("beta")],
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
