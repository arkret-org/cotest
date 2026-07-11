// Sovereign deployment + controlled external collaboration enclave
// Contract: e2e/scenarios/sync/sovereign-deployment.md
// Spec: sync/sovereign-deployment.md §2-§6

import { expect, test, type APIRequestContext } from "@playwright/test";

import { solandBaseUrl, solandServiceId, hasDualSoland, type SolandKey } from "../../helpers/env";

test.describe.configure({ mode: "serial" });

test.describe("sovereign deployment", () => {
  test.beforeEach(() => {
    test.skip(!hasDualSoland(), "requires -DualSoland alpha/beta topology");
  });

  test("alice_internal and bob_external collaborate in enclave realm; bob cannot escape; exit triggers audit log", async ({
    request,
  }) => {
    const fixture = await setupSovereignFixture(request, "core");

    const mainInfo = await getJson(request, "alpha", "/_soland/admin/deployment/info");
    expect(mainInfo.profile).toBe("sovereign_main");
    expect(mainInfo.trusted_enclaves).toEqual(
      expect.arrayContaining([expect.objectContaining({ server_id: solandServiceId("beta") })]),
    );

    const enclaveInfo = await getJson(request, "beta", "/_soland/admin/deployment/info");
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
    );
    expect(betaRealm.profile).toBe("enclave");
    expect(betaRealm.hosted_on).toBe(solandServiceId("beta"));

    const bobStatus = await getJson(
      request,
      "alpha",
      `/_soland/self/account/${encodeURIComponent(fixture.bobDid)}`,
    );
    expect(bobStatus.external_via_enclave).toBe(true);
    expect(bobStatus.realm).toBe(fixture.enclaveRealmId);

    const audit = await getJson(
      request,
      "beta",
      `/_soland/admin/deployment/audit?subject=${encodeURIComponent(fixture.bobDid)}`,
    );
    expect(audit.entries.map((entry: any) => entry.action)).toContain("external_invite.accept");
  });

  test("E7.1 escape attempt rejected: bob cannot reach main domain via directory / direct API / enclave proxy", async ({
    request,
  }) => {
    const fixture = await setupSovereignFixture(request, "escape");

    const direct = await request.get(
      `${solandBaseUrl("alpha")}/_arkret/self/realms/${encodeURIComponent(fixture.internalRealmId)}?actor=${encodeURIComponent(fixture.bobDid)}`,
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
          requester: fixture.bobDid,
        },
      },
    );
    expect(directoryResp.status(), await directoryResp.text()).toBe(200);
    const directory = await directoryResp.json();
    expect(directory.realms).toEqual([]);
    expect(directory.has_more).toBe(false);

    const proxy = await request.post(`${solandBaseUrl("beta")}/_soland/self/deployment/enclave-proxy`, {
      data: {
        actor: fixture.bobDid,
        target: solandBaseUrl("alpha"),
        path: `/_arkret/self/realms/${fixture.internalRealmId}`,
      },
    });
    expect(proxy.status()).toBe(403);
    await expectErrorCode(proxy, "enclave_no_upstream_proxy_for_external");

    const audit = await getJson(
      request,
      "beta",
      `/_soland/admin/deployment/audit?subject=${encodeURIComponent(fixture.bobDid)}`,
    );
    expect(audit.entries.map((entry: any) => entry.action)).toContain("boundary.enclave_proxy");
  });

  test("E7.2 network outage: when soland_main <-> soland_enclave loses connectivity the enclave uses store-and-forward, not a client-side offline outbox", async ({
    request,
  }) => {
    const fixture = await setupSovereignFixture(request, "outage");

    await postJson(request, "beta", "/_soland/admin/deployment/network/link", {
      upstream_available: false,
    });
    const accepted = await postJson(request, "beta", "/_soland/admin/deployment/store-and-forward/messages", {
      actor: fixture.bobDid,
      realm_id: fixture.enclaveRealmId,
      content: { body: `store forward ${fixture.stamp}` },
    });
    expect(accepted.state).toBe("accepted");
    expect(accepted.delivery).toBe("store_forward");
    expect(accepted.pending_sync).toBe(false);
    expect(accepted.queue_depth).toBe(1);

    const lag = await getJson(
      request,
      "beta",
      `/_soland/admin/deployment/enclave-frontier?realm_id=${encodeURIComponent(fixture.enclaveRealmId)}`,
    );
    expect(lag.status).toBe("enclave_sync_lag");

    await postJson(request, "beta", "/_soland/admin/deployment/network/link", {
      upstream_available: true,
    });
    const drained = await postJson(request, "beta", "/_soland/admin/deployment/store-and-forward/drain", {});
    expect(drained.operations).toHaveLength(1);

    const ingested = await postJson(request, "alpha", "/_soland/admin/deployment/store-and-forward/ingest", {
      operations: drained.operations,
    });
    expect(ingested.converged).toBe(true);

    const converged = await getJson(
      request,
      "alpha",
      `/_soland/admin/deployment/enclave-frontier?realm_id=${encodeURIComponent(fixture.enclaveRealmId)}`,
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
    expect(accepted.session_metadata.actor).toBe(fixture.bobDid);

    const enclaveReject = await request.post(
      `${solandBaseUrl("beta")}/_soland/self/account/accept-external-invite`,
      {
        data: {
          invite_token: `ak:external_invite:${fixture.short}-rogue`,
          actor_id: `did:web:rogue-${fixture.stamp}.evil`,
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
  const enclaveRealmId = `ak:realm:019e0000-${short.slice(0, 4)}-7000-8000-${short}`;
  const internalRealmId = `ak:realm:019e0000-${short.slice(0, 4)}-7000-8000-${short}`;

  await postJson(request, "alpha", "/_soland/admin/deployment/configure", {
    profile: "sovereign_main",
    trust_roots: ["did:web:*.example"],
    allow_external_via_enclave: true,
  });
  await postJson(request, "beta", "/_soland/admin/deployment/configure", {
    profile: "enclave",
    upstream_main: solandBaseUrl("alpha"),
    trust_roots: ["did:web:*.example", "did:web:*.example.org"],
    upstream_available: true,
  });
  await postJson(request, "alpha", "/_soland/admin/deployment/register-enclave", {
    server_id: solandServiceId("beta"),
    base_url: solandBaseUrl("beta"),
    trust_chain: ["did:web:*.example.org"],
  });
  await postJson(request, "alpha", "/_soland/admin/deployment/realm.create", {
    realm_id: enclaveRealmId,
    hosted_on: solandServiceId("beta"),
    created_by: aliceDid,
    external_invite_policy: "allowed",
  });
  await postJson(request, "beta", "/_soland/admin/deployment/realm.create", {
    realm_id: enclaveRealmId,
    hosted_on: solandServiceId("beta"),
    created_by: aliceDid,
    external_invite_policy: "allowed",
  });

  const invite = await postJson(request, "alpha", "/_soland/admin/deployment/external-invite", {
    target_realm: enclaveRealmId,
    invitee: bobDid,
    inviter: aliceDid,
  });
  const acceptBody = await postJson(request, "beta", "/_soland/self/account/accept-external-invite", {
    invite_token: invite.invite_token,
    actor_id: bobDid,
    target_realm: invite.target_realm,
    target_host: invite.target_host,
  });

  return { stamp, short, aliceDid, bobDid, enclaveRealmId, internalRealmId, acceptBody };
}

async function postJson(
  request: APIRequestContext,
  server: SolandKey,
  path: string,
  data: Record<string, unknown>,
) {
  const response = await request.post(`${solandBaseUrl(server)}${path}`, { data });
  const text = await response.text();
  expect(response.status(), `${path}: ${text}`).toBe(200);
  return JSON.parse(text);
}

async function getJson(request: APIRequestContext, server: SolandKey, path: string) {
  const response = await request.get(`${solandBaseUrl(server)}${path}`);
  const text = await response.text();
  expect(response.status(), `${path}: ${text}`).toBe(200);
  return JSON.parse(text);
}

async function expectErrorCode(response: { json(): Promise<any> }, code: string) {
  const body = await response.json();
  expect(body.error?.code ?? body.code).toBe(code);
}
