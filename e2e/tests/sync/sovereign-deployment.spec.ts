// Sovereign deployment + controlled external collaboration enclave
// Contract: e2e/scenarios/sync/sovereign-deployment.md
// Spec: sync/sovereign-deployment.md §2-§6

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";

import { solandBaseUrl, solandServiceId, hasDualSoland, type SolandKey } from "../../helpers/env";
import { issueDevSession, uniqueUser } from "../../helpers/users";
import { canonicalJson, projectDidToCoreId } from "../../helpers/soland-api";

test.describe.configure({ mode: "serial" });

let cleanupAdminTokens: { alpha: string; beta: string } | undefined;

// The deployment-admin harness seeds accepted projections directly, so each
// scenario uses frozen full Realm tokens standing for its accepted create
// Events. UUID-shaped Realm placeholders are not valid protocol identities.
const SOVEREIGN_REALM_FIXTURES = {
  core: [
    "ak:realm:AaRfbi5sqNgNzzcqaDDsD5tsVkRS_qMFGKFnTcnsjmVG",
    "ak:realm:AaucqKYsYtNwus16IgXDBl88-LWNZZVtRpZ-CqgnPQoi",
  ],
  escape: [
    "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
    "ak:realm:Abf_EFzG0z16A5W8192VSnWPMSNVFmuS4X2gQVKgT4ml",
  ],
  outage: [
    "ak:realm:AbL8oOUkpZusQ-VqkYVKoKNNlWviopqGNtOPvbl98WW4",
    "ak:realm:AdrCf1FpSdW2-osrupL1Va1DkS3PNlzZsPum0wyLnQwz",
  ],
  trust: [
    "ak:realm:Af-BcSQlU1OLsK_s3qms1wnA0sSHd7tqhZUbndr27MIr",
    "ak:realm:Af3OjcIxjJQXyc7V8D_U6DEKRicQF4XRAClC-IUu0EHg",
  ],
} as const;

test.describe("sovereign deployment", () => {
  test.beforeEach(() => {
    test.skip(!hasDualSoland(), "requires -DualSoland alpha/beta topology");
  });

  test.afterEach(async ({ request }) => {
    const tokens = cleanupAdminTokens;
    cleanupAdminTokens = undefined;
    if (!tokens) return;

    // Deployment configuration is process-global. Leave the trust-root list
    // empty (the normal permissive posture) so this serial scenario cannot
    // make unrelated files' subsequently-created test principals untrusted.
    await Promise.all([
      postJson(
        request,
        "alpha",
        "/_soland/admin/deployment/configure",
        { trust_root_ids: [], allow_external_via_enclave: false },
        tokens.alpha,
      ),
      postJson(
        request,
        "beta",
        "/_soland/admin/deployment/configure",
        { trust_root_ids: [], upstream_available: true },
        tokens.beta,
      ),
    ]);
  });

  test("alice_internal and bob_external collaborate in enclave realm; bob cannot escape; exit triggers audit log", async ({
    request,
  }) => {
    const fixture = await setupSovereignFixture(request, "core");

    const mainInfo = await getJson(
      request,
      "alpha",
      "/_soland/admin/deployment/info",
      fixture.adminTokens.alpha,
    );
    expect(mainInfo.profile).toBe("sovereign_main");
    expect(mainInfo.trusted_enclaves).toEqual(
      expect.arrayContaining([expect.objectContaining({ server_id: solandServiceId("beta") })]),
    );

    const enclaveInfo = await getJson(
      request,
      "beta",
      "/_soland/admin/deployment/info",
      fixture.adminTokens.beta,
    );
    expect(enclaveInfo.profile).toBe("enclave");
    expect(enclaveInfo.upstream_main).toBe(solandBaseUrl("alpha"));

    const rogue = await request.post(`${solandBaseUrl("alpha")}/_soland/self/account/register`, {
      data: {
        did: `did:web:rogue-${fixture.stamp}.evil`,
        handle: `@rogue${fixture.short}`,
        display_name: "Rogue",
        device_id: `ak:device:01904100-0000-7000-8000-${fixture.short}00000001`,
      },
    });
    expect(rogue.status()).toBe(403);
    await expectErrorCode(rogue, "did_method_not_trusted");

    // Deployment/enclave introspection is a soland product-private surface
    // (`/_soland/self/...`), not part of the `/_arkret/` protocol catalog.
    const betaRealm = await getJson(
      request,
      "beta",
      `/_soland/self/realm/${encodeURIComponent(fixture.enclaveRealmId)}`,
      fixture.adminTokens.beta,
    );
    expect(betaRealm.profile).toBe("enclave");
    expect(betaRealm.hosted_on).toBe(solandServiceId("beta"));

    const bobStatus = await getJson(
      request,
      "alpha",
      `/_soland/self/account/${encodeURIComponent(fixture.bobId)}`,
      fixture.adminTokens.alpha,
    );
    expect(bobStatus.external_via_enclave).toBe(true);
    expect(bobStatus.realm).toBe(fixture.enclaveRealmId);

    const audit = await getJson(
      request,
      "beta",
      `/_soland/admin/deployment/audit?subject=${encodeURIComponent(fixture.bobId)}`,
      fixture.adminTokens.beta,
    );
    expect(audit.entries.map((entry: any) => entry.action)).toContain("external_invite.accept");
  });

  test("E7.1 escape attempt rejected: bob cannot reach main domain via directory / direct API / enclave proxy", async ({
    request,
  }) => {
    const fixture = await setupSovereignFixture(request, "escape");

    const direct = await request.get(
      `${solandBaseUrl("alpha")}/_soland/self/realm/${encodeURIComponent(fixture.internalRealmId)}/access?actor=${encodeURIComponent(fixture.bobId)}`,
      { headers: { authorization: `Bearer ${fixture.adminTokens.alpha}` } },
    );
    expect(direct.status()).toBe(403);
    await expectErrorCode(direct, "external_user_no_main_access");

    // Directory discovery is over Realms (the replication/security boundary),
    // not pre-inversion "spaces". spec: find/directory/search-realms
    // (DirectoryRealmSearchOutcome → { realms[], has_more }). The escape-isolation
    // assertion is that the external user cannot discover the internal Realm:
    // the authorized search returns an empty realm set.
    const directoryResp = await request.post(
      `${solandBaseUrl("alpha")}/_arkret/find/directory/search-realms`,
      {
        data: {
          query: "internal",
          requester: fixture.bobId,
        },
      },
    );
    expect(directoryResp.status(), await directoryResp.text()).toBe(200);
    const directory = await directoryResp.json();
    expect(directory.realms).toEqual([]);
    expect(directory.has_more).toBe(false);

    const proxy = await request.post(`${solandBaseUrl("beta")}/_soland/self/deployment/enclave-proxy`, {
      headers: { authorization: `Bearer ${fixture.adminTokens.beta}` },
      data: {
        actor: fixture.bobId,
        target: solandBaseUrl("alpha"),
        path: `/_arkret/self/realms/${fixture.internalRealmId}`,
      },
    });
    expect(proxy.status()).toBe(403);
    await expectErrorCode(proxy, "enclave_no_upstream_proxy_for_external");

    const audit = await getJson(
      request,
      "beta",
      `/_soland/admin/deployment/audit?subject=${encodeURIComponent(fixture.bobId)}`,
      fixture.adminTokens.beta,
    );
    expect(audit.entries.map((entry: any) => entry.action)).toContain("boundary.enclave_proxy");
  });

  test("E7.2 network outage: when soland_main <-> soland_enclave loses connectivity the enclave uses store-and-forward, not a client-side offline outbox", async ({
    request,
  }) => {
    const fixture = await setupSovereignFixture(request, "outage");

    await postJson(request, "beta", "/_soland/admin/deployment/network/link", {
      upstream_available: false,
    }, fixture.adminTokens.beta);
    const accepted = await postJson(request, "beta", "/_soland/admin/deployment/store-and-forward/messages", {
      actor: fixture.bobId,
      realm_id: fixture.enclaveRealmId,
      content: { body: `store forward ${fixture.stamp}` },
    }, fixture.adminTokens.beta);
    expect(accepted.state).toBe("accepted");
    expect(accepted.delivery).toBe("store_forward");
    expect(accepted.pending_sync).toBe(false);
    expect(accepted.queue_depth).toBe(1);

    const lag = await getJson(
      request,
      "beta",
      `/_soland/admin/deployment/enclave-frontier?realm_id=${encodeURIComponent(fixture.enclaveRealmId)}`,
      fixture.adminTokens.beta,
    );
    expect(lag.status).toBe("enclave_sync_lag");

    await postJson(request, "beta", "/_soland/admin/deployment/network/link", {
      upstream_available: true,
    }, fixture.adminTokens.beta);
    const drained = await postJson(
      request,
      "beta",
      "/_soland/admin/deployment/store-and-forward/drain",
      {},
      fixture.adminTokens.beta,
    );
    expect(drained.operations).toHaveLength(1);

    const ingested = await postJson(request, "alpha", "/_soland/admin/deployment/store-and-forward/ingest", {
      operations: drained.operations,
    }, fixture.adminTokens.alpha);
    expect(ingested.converged).toBe(true);

    const converged = await getJson(
      request,
      "alpha",
      `/_soland/admin/deployment/enclave-frontier?realm_id=${encodeURIComponent(fixture.enclaveRealmId)}`,
      fixture.adminTokens.alpha,
    );
    expect(converged.status).toBe("converged");
    expect(converged.main_frontier).toBeGreaterThanOrEqual(1);
  });

  test("E7.3 enclave DID resolver policy: bob's DID must be validated through the enclave trust chain (not the main one)", async ({
    request,
  }) => {
    const fixture = await setupSovereignFixture(request, "trust");

    const mainReject = await request.post(`${solandBaseUrl("alpha")}/_soland/self/account/register`, {
      data: {
        did: fixture.bobDid,
        handle: `@direct${fixture.short}`,
        display_name: "Direct Bob",
        device_id: `ak:device:01904100-0000-7000-8000-${fixture.short}00000002`,
      },
    });
    expect(mainReject.status()).toBe(403);
    await expectErrorCode(mainReject, "did_method_not_trusted");

    const accepted = fixture.acceptBody;
    expect(accepted.session_metadata.trust_chain_profile).toBe("enclave");
    expect(accepted.session_metadata.actor).toBe(fixture.bobId);

    const enclaveReject = await request.post(
      `${solandBaseUrl("beta")}/_soland/self/account/accept-external-invite`,
      {
        headers: { authorization: `Bearer ${fixture.adminTokens.beta}` },
        data: {
          invite_token: `ak:external_invite:${fixture.short}-rogue`,
          actor_id: `ak:did_core:web:rogue-${fixture.stamp}.evil`,
          target_realm: fixture.enclaveRealmId,
          target_host: solandBaseUrl("beta"),
        },
      },
    );
    expect(enclaveReject.status()).toBe(403);
    await expectErrorCode(enclaveReject, "enclave_did_method_not_trusted");
  });
});

async function setupSovereignFixture(request: APIRequestContext, label: string) {
  const stamp = `${Date.now()}${Math.floor(Math.random() * 1000)}`;
  const short = stamp.slice(-12);
  const aliceDid = `did:web:alice-int-${label}-${stamp}.example`;
  const bobDid = `did:web:bob-ext-${label}-${stamp}.example.org`;
  const aliceId = projectDidToCoreId(aliceDid);
  const bobId = projectDidToCoreId(bobDid);
  const fixtureRealmIds = SOVEREIGN_REALM_FIXTURES[
    label as keyof typeof SOVEREIGN_REALM_FIXTURES
  ];
  if (!fixtureRealmIds) {
    throw new Error(`missing sovereign Realm fixture identities for ${label}`);
  }
  const [enclaveRealmId, internalRealmId] = fixtureRealmIds;
  const operator = uniqueUser(`sovereign-operator-${label}-${stamp}`);
  const [alphaAdminToken, betaAdminToken] = await Promise.all([
    issueDevSession(request, operator, { server: "alpha" }),
    issueDevSession(request, operator, { server: "beta" }),
  ]);
  const adminTokens = { alpha: alphaAdminToken, beta: betaAdminToken };
  cleanupAdminTokens = adminTokens;

  await postJson(request, "alpha", "/_soland/admin/deployment/configure", {
    profile: "sovereign_main",
    trust_root_ids: ["did:web:*.example"],
    allow_external_via_enclave: true,
  }, adminTokens.alpha);
  await postJson(request, "beta", "/_soland/admin/deployment/configure", {
    profile: "enclave",
    upstream_main: solandBaseUrl("alpha"),
    trust_root_ids: ["did:web:*.example", "did:web:*.example.org"],
    upstream_available: true,
  }, adminTokens.beta);
  await postJson(request, "alpha", "/_soland/admin/deployment/register-enclave", {
    server_id: solandServiceId("beta"),
    base_url: solandBaseUrl("beta"),
    trust_chain: ["did:web:*.example.org"],
  }, adminTokens.alpha);
  await postJson(request, "alpha", "/_soland/admin/deployment/realm.create", {
    realm_id: enclaveRealmId,
    hosted_on: solandServiceId("beta"),
    created_by: aliceId,
    external_invite_policy: "allowed",
  }, adminTokens.alpha);
  await postJson(request, "beta", "/_soland/admin/deployment/realm.create", {
    realm_id: enclaveRealmId,
    hosted_on: solandServiceId("beta"),
    created_by: aliceId,
    external_invite_policy: "allowed",
  }, adminTokens.beta);

  const invite = await postJson(request, "alpha", "/_soland/admin/deployment/external-invite", {
    target_realm: enclaveRealmId,
    invitee: bobId,
    inviter: aliceId,
  }, adminTokens.alpha);
  const acceptBody = await postJson(request, "beta", "/_soland/self/account/accept-external-invite", {
    invite_token: invite.invite_token,
    actor_id: bobId,
    target_realm: invite.target_realm,
    target_host: invite.target_host,
  }, adminTokens.beta);

  return {
    stamp,
    short,
    aliceDid,
    aliceId,
    bobDid,
    bobId,
    enclaveRealmId,
    internalRealmId,
    acceptBody,
    adminTokens,
  };
}

async function postJson(
  request: APIRequestContext,
  server: SolandKey,
  path: string,
  data: Record<string, unknown>,
  token?: string,
) {
  const response = await request.post(`${solandBaseUrl(server)}${path}`, {
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      "content-type": "application/json",
    },
    data: canonicalJson(data),
  });
  const text = await response.text();
  expect(response.status(), `${path}: ${text}`).toBe(200);
  return JSON.parse(text);
}

async function getJson(
  request: APIRequestContext,
  server: SolandKey,
  path: string,
  token?: string,
) {
  const response = await request.get(`${solandBaseUrl(server)}${path}`, {
    headers: token ? { authorization: `Bearer ${token}` } : undefined,
  });
  const text = await response.text();
  expect(response.status(), `${path}: ${text}`).toBe(200);
  return JSON.parse(text);
}

async function expectErrorCode(response: { json(): Promise<any> }, code: string) {
  const body = await response.json();
  expect(body.error?.code ?? body.code).toBe(code);
}
