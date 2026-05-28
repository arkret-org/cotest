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
  hasDualSoland,
  optionalEnv,
  solandBaseUrl,
  solandServiceDid,
} from "../../helpers/env";
import {
  authHeaders,
  createSpaceApi,
  makeOperation,
  operationFrontierApi,
  rawPushFederationOperations,
  sendMessageApi,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.beforeEach(() => {
  test.skip(
    !hasDualSoland(),
    "federation security hardening requires dual soland topology",
  );
});

test.describe("federation security hardening", () => {
  test("denylisted peer inbound push is hard-rejected", async ({ request }) => {
    test.skip(
      optionalEnv("COTEST_EXPECT_FEDERATION_DENYLIST") !== "1",
      "requires beta SOLAND_FEDERATION_DENYLIST to include alpha service DID/domain",
    );

    const spaceId = typedId("space");
    const op = makeOperation({
      spaceId,
      objectType: "cx.message.create",
      payload: {
        event_id: typedId("event"),
        sender: "did:web:alice.alpha.example",
        thread_id: "cx:thread:federation-security",
        content: { kind: "cx.content.text", body: "denylisted inbound" },
      },
    });
    const response = await rawPushFederationOperations(request, [op], {
      origin: solandServiceDid("alpha"),
      destination: solandServiceDid("beta"),
      spaceId,
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
    const spaceId = await createSpaceApi(
      request,
      aliceToken,
      {
        title: "denylisted outbound",
        public: false,
        plaintext_visible_services: [solandServiceDid("alpha"), solandServiceDid("beta")],
      },
      { server: "alpha" },
    );
    await sendMessageApi(request, aliceToken, spaceId, "must not fan out", {
      server: "alpha",
    });

    await expect
      .poll(
        async () => {
          const frontier = await operationFrontierApi(request, spaceId, { server: "beta" });
          return frontier.operation_count;
        },
        { timeout: 10_000, intervals: [1_000, 2_000] },
      )
      .toBe(0);
  });

  test("private-network federation pull target is rejected by egress guard", async ({
    request,
  }) => {
    test.skip(
      optionalEnv("COTEST_EXPECT_PRIVATE_EGRESS_BLOCKED") !== "1",
      "requires soland SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS=0 and beta configured as a peer",
    );

    const alice = uniqueUser("fed-egress-alice");
    await ensureRegistered(request, alice, { server: "alpha" });
    const aliceToken = await issueDevSession(request, alice, { server: "alpha" });
    const spaceId = await createSpaceApi(
      request,
      aliceToken,
      { title: "private egress rejection", public: false },
      { server: "alpha" },
    );

    const response = await request.post(
      `${solandBaseUrl("alpha")}/api/v1/federation/backfill-operations`,
      {
        headers: authHeaders(aliceToken),
        data: {
          peer_url: solandBaseUrl("beta"),
          peer_did: solandServiceDid("beta"),
          space_id: spaceId,
          limit: 1,
          max_pages: 1,
        },
      },
    );
    expect(response.status()).toBeGreaterThanOrEqual(400);
    const text = await response.text();
    expect(text).toMatch(/capability_denied|blocked address|private|localhost/i);
  });
});
