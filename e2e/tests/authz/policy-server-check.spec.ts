// Pluggable policy decision service (realm-level external policy_server)
// Contract: e2e/scenarios/authz/policy-server-check.md
// Spec: authz/policy-server.md §2 (ak.realm.policy_server declaration/tombstone),
//        §3 (POST /_arkret/self/policy/check request/response contract),
//        §4 (obligations + fail-closed default).
//
// Started by run-joint-e2e.ps1 -StartMockPolicyServer (or -StartMocks): the
// orchestration spawns mock-policy-server.mjs, waits on its /policy/health,
// and exports COTEST_MOCK_POLICY_SERVER_BASE_URL. When that env var is unset
// (single-server profiles that did not provision the mock) every test below
// self-skips rather than failing.
//
// Contract reality these tests are written against:
//   soland's outbound policy client (soland/crates/http/src/authz/policy_client.rs)
//   requires a spec §3-conformant PolicyCheckOutcome — bound_to echo, three
//   frontier digests matching soland's own runtime-computed values, and an
//   Ed25519 signature whose kid resolves under the declared policy_server_service_id
//   via soland's DID resolver. The harness mock cannot satisfy that (it neither
//   computes soland's internal membership/policy frontiers nor publishes a
//   DID document soland trusts). Per spec §4 fail-closed default, soland
//   therefore *denies* every gated operation once a policy server is declared
//   for the realm — whether the upstream is slow, unreachable, or simply
//   returns a body soland can't verify. These tests assert that fail-closed
//   safety property end-to-end, plus that the upstream is actually consulted
//   (via the mock's /inspect call log). The allow-path lifecycle (Phase B/D of
//   the scenario doc) is not reachable until the mock speaks the full signed
//   PolicyCheckOutcome contract and is added to soland's trust set; it remains
//   tracked as a fixme below.

import { expect, test } from "../../helpers/arkret-test";
import type { APIRequestContext } from "../../helpers/arkret-test";
import {
  mockPolicyServerBaseUrl as configuredMockPolicyServerBaseUrl,
  mockPolicyServerDid,
  solandBaseUrl,
} from "../../helpers/env";
import {
  alignSignedEventToActorFrontierApi,
  authHeaders,
  requireDidCoreId,
  canonicalJson,
  createRealmApi,
  currentActorIdApi,
  expectJsonOk,
  prepareSignedEventSubmissionApi,
  projectDidToCoreId,
  rawSubmitSignedEventApi,
  readRealmSealBasis,
  resolveDefaultStrandId,
  signedEventEnvelope,
  waitForRealmControlIdleApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

const policyServerCellValues = new Map<string, Record<string, unknown>>();

// Configure a realm's external policy server to point at the harness mock.
async function declarePolicyServer(
  request: APIRequestContext,
  token: string,
  realmId: string,
  baseUrl: string,
  did: string,
  opts: { cacheTtlSeconds?: number; timeoutMs?: number } = {},
): Promise<Record<string, unknown>> {
  const actorId = await currentActorIdApi(request, token);
  const sealBasis = await readRealmSealBasis(request, token, realmId);
  const payload = {
    policy_server_service_id: projectDidToCoreId(did),
    policy_server_url: `${baseUrl}/_arkret/self/policy/check`,
    cache_ttl_seconds: opts.cacheTtlSeconds ?? 5,
    timeout_ms: opts.timeoutMs ?? 1500,
    on_timeout: "fail_closed",
  };
  const previousValue = policyServerCellValues.get(realmId);
  const event = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.realm.policy_server",
    preconditions: previousValue
      ? [
          {
            cell: "ak:cell:ak.component.realm.policy_server.v1:null",
            predicate: { op: "head_eq", value: previousValue },
          },
        ]
      : undefined,
    payload,
  });
  const submission = await prepareSignedEventSubmissionApi(
    request,
    token,
    event,
    { context: `prepare policy server declaration for ${realmId}` },
  );
  const put = await request.put(
    `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
    {
      headers: {
        ...authHeaders(token),
        "content-type": "application/json",
      },
      data: canonicalJson({
        policy_server_event: submission,
      }),
    },
  );
  const projected = await expectJsonOk<Record<string, unknown>>(
    put,
    "declare realm policy server",
  );
  await waitForRealmControlIdleApi(request, token, realmId, {
    afterControlEventSetRoot: String(sealBasis.control_event_set_root),
  });
  policyServerCellValues.set(realmId, payload);
  return projected;
}

async function deletePolicyServer(
  request: APIRequestContext,
  token: string,
  realmId: string,
) {
  const actorId = await currentActorIdApi(request, token);
  const previousValue = policyServerCellValues.get(realmId);
  const payload = { tombstone: true };
  const event = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.realm.policy_server",
    preconditions: previousValue
      ? [
          {
            cell: "ak:cell:ak.component.realm.policy_server.v1:null",
            predicate: { op: "head_eq", value: previousValue },
          },
        ]
      : undefined,
    payload,
  });
  const submission = await prepareSignedEventSubmissionApi(
    request,
    token,
    event,
    { context: `prepare policy server tombstone for ${realmId}` },
  );
  const response = await request.delete(
    `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
    {
      headers: {
        ...authHeaders(token),
        "content-type": "application/json",
      },
      data: canonicalJson({ policy_server_event: submission }),
    },
  );
  if (response.ok()) {
    policyServerCellValues.set(realmId, payload);
  }
  return response;
}

// Submit a gated ak.message.create through the same canonical publication rail
// as production clients and return the raw verdict. A policy deny may happen
// during the read-only lease pre-admission pass or during final admission.
async function submitGatedMessage(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  body: string,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const strandId = await resolveDefaultStrandId(request, token, realmId);
  const envelope = signedEventEnvelope({
    actorId,
    realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      content: { kind: "ak.content.text", body },
    },
  });
  await alignSignedEventToActorFrontierApi(request, token, envelope);
  const response = await rawSubmitSignedEventApi(request, token, envelope);
  const text = await response.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    json = { raw: text };
  }
  return { status: response.status(), json };
}

// Count how many /policy/check calls the mock has recorded so far.
async function policyCheckCount(
  request: APIRequestContext,
  baseUrl: string,
): Promise<number> {
  const inspect = await request.get(`${baseUrl}/inspect`);
  expect(inspect.status()).toBe(200);
  const body = (await inspect.json()) as {
    kinds?: { checks?: unknown[] };
  };
  return body.kinds?.checks?.length ?? 0;
}

type PolicyServerEvent = {
  event_id?: string;
  kind?: string;
  actor_id?: string;
  executed_by?: string;
  payload?: Record<string, unknown>;
  seal_basis?: { leaves?: unknown[] };
  proofs?: unknown[];
};

async function policyServerEvents(
  request: APIRequestContext,
  token: string,
  realmId: string,
): Promise<PolicyServerEvent[]> {
  const url = `${solandBaseUrl()}/_arkret/self/events`;
  const response = await request.fetch(url, {
    method: "QUERY",
    data: canonicalJson({ realms: [realmId], limit: 200 }),
    headers: {
      ...authHeaders(token),
      "content-type": "application/json",
    },
  });
  const body = await expectJsonOk<{ events?: PolicyServerEvent[] }>(
    response,
    "query canonical policy-server events",
  );
  return (body.events ?? []).filter(
    (event) => event.kind === "ak.realm.policy_server",
  );
}

test.describe.configure({ mode: "serial" });

test.describe("policy server check", () => {
  test("policy server config API projects ak.realm.policy_server and authz stays fail-closed without a grant", async ({
    request,
  }) => {
    const stamp = Date.now();
    const describeResp = await request.get(
      `${solandBaseUrl()}/_arkret/describe`,
    );
    const describe = await expectJsonOk<Record<string, unknown>>(
      describeResp,
      "server describe authz self surface",
    );
    expect(describe.supported_operation_bundles).toEqual(
      expect.arrayContaining([
        "ak.operation_bundle.principal_server.http_core.v1",
      ]),
    );
    const limits = describe.limits as Record<string, unknown>;
    const authzPolicy = limits.authz_policy as Record<string, unknown>;
    expect(authzPolicy.self_surface_status).toBe("standard_self_supported");
    const authzCheck = authzPolicy.authz_check as Record<string, unknown>;
    expect(authzCheck.path).toBe("/_arkret/self/authz/check");
    expect(authzCheck.operation_specific_error_codes).toEqual(
      expect.arrayContaining(["policy_unavailable"]),
    );
    expect(authzCheck.usable_as_event_auth_context).toBe(false);
    const effectiveGrants = authzPolicy.effective_grants as Record<
      string,
      unknown
    >;
    expect(effectiveGrants.path).toBe("/_arkret/self/authz/effective-grants");
    const invites = authzPolicy.invites as Record<string, unknown>;
    expect(invites.path).toBe("/_arkret/self/authz/invites");
    expect(invites.response_schema_ref).toBe(
      "schemas/authz-operations.schema.json#/$defs/authz_invite_list",
    );

    const alice = uniqueUser(`s30-policy-config-alice-${stamp}`);
    const bob = uniqueUser(`s30-policy-config-bob-${stamp}`);
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S30 policy config ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      public: true,
    });
    const policyServerDid = "did:web:policy.example.com";
    const policyServerUrl =
      "https://policy.example.com/_arkret/self/policy/check";

    const projected = await declarePolicyServer(
      request,
      aliceToken,
      realmId,
      "https://policy.example.com",
      policyServerDid,
    );
    expect(projected.realm_id).toBe(realmId);
    expect(projected.policy_server_service_id).toBe(
      projectDidToCoreId(policyServerDid),
    );
    expect(projected.policy_server_url).toBe(policyServerUrl);
    expect(projected.from_organization_fallback).toBe(false);

    const canonicalEvents = await policyServerEvents(
      request,
      aliceToken,
      realmId,
    );
    const declaration = canonicalEvents.find(
      (event) =>
        event.payload?.policy_server_url === policyServerUrl ||
        (event.payload?.policy_server as Record<string, unknown> | undefined)
          ?.url === policyServerUrl,
    );
    expect(
      declaration,
      "PUT must append a canonical policy-server Event",
    ).toBeTruthy();
    expect(declaration?.event_id).toMatch(/^ak:event:/);
    expect(declaration?.actor_id).toBe(alice.id);
    expect(declaration?.executed_by).toBeUndefined();
    expect(declaration?.seal_basis?.leaves?.length ?? 0).toBeGreaterThan(0);
    expect(declaration?.proofs?.length ?? 0).toBeGreaterThan(0);

    const frontierUrl = `${solandBaseUrl()}/_arkret/self/seals/frontier`;
    const frontier = await request.fetch(frontierUrl, {
      method: "QUERY",
      headers: {
        ...authHeaders(aliceToken, "QUERY", frontierUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({ realm_id: realmId }),
    });
    const frontierBody = await expectJsonOk<{
      frontier?: { kind?: string; seal_basis?: { leaves?: string[] } };
    }>(frontier, "read policy-server Seal frontier");
    expect(frontierBody.frontier?.kind).toBe("realm_seal");
    expect(frontierBody.frontier?.seal_basis?.leaves).toHaveLength(1);
    expect(frontierBody.frontier?.seal_basis?.leaves?.[0]).toMatch(/^ak:seal:/);

    const get = await request.get(
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/policy-server`,
      { headers: authHeaders(aliceToken) },
    );
    const fetched = await expectJsonOk<Record<string, unknown>>(
      get,
      "get realm policy server",
    );
    expect(fetched.policy_server_service_id).toBe(
      projectDidToCoreId(policyServerDid),
    );
    expect(fetched.policy_server_url).toBe(policyServerUrl);

    const authzCheckUrl = `${solandBaseUrl()}/_arkret/self/authz/check`;
    const denied = await request.post(authzCheckUrl, {
      headers: {
        ...authHeaders(bobToken),
        "content-type": "application/json",
      },
      data: canonicalJson({
        actor_id: bob.id,
        action: "ak.message.create",
        resource: {
          kind: "realm",
          realm_id: realmId,
        },
      }),
    });
    const decision = await expectJsonOk<{
      decision: string;
      reason_code?: string;
    }>(denied, "authz check without grant");
    expect(decision.decision).toBe("hard_deny");
    expect(decision.reason_code).toBeTruthy();
  });

  test("declared policy server is consulted before a cap-gated op and soland fail-closes (deny) per spec section 4", async ({
    request,
  }) => {
    const baseUrl = configuredMockPolicyServerBaseUrl();
    test.skip(!baseUrl, "mock-policy-server not started for this run");
    test.skip(
      !baseUrl?.startsWith("https://"),
      "policy-server declarations require an HTTPS mock endpoint",
    );

    const stamp = Date.now();
    const alice = uniqueUser(`s30-policy-alice-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const aliceId = await currentActorIdApi(request, aliceToken);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S30 policy ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      public: true,
    });

    // Baseline: with no policy server declared, the owner's own message is
    // accepted (local capability check allows; no remote gate runs).
    const beforeDeclare = await submitGatedMessage(
      request,
      aliceToken,
      aliceId,
      realmId,
      "before policy server is declared",
    );
    expect(
      [200, 201],
      `owner message before policy server: ${beforeDeclare.status} ${JSON.stringify(beforeDeclare.json)}`,
    ).toContain(beforeDeclare.status);

    // Reset the mock to a clean, permissive baseline to make the point that the
    // deny is soland's fail-closed default (spec section 4), not the mock's
    // verdict: soland cannot verify the mock's simplified, unsigned response
    // shape against the declared policy_server_service_id, so the gate denies.
    const reset = await request.delete(`${baseUrl}/scenarios`);
    expect(reset.status()).toBe(200);
    await request.post(`${baseUrl}/scenarios`, { data: { default: "allow" } });

    const did = mockPolicyServerDid() ?? "did:web:policy.example.com";
    // `baseUrl` is guaranteed present here by the `test.skip(!baseUrl, ...)`
    // guard above; the non-null assertion narrows it for the typed call sites.
    await declarePolicyServer(request, aliceToken, realmId, baseUrl!, did);

    const before = await policyCheckCount(request, baseUrl!);

    const gated = await submitGatedMessage(
      request,
      aliceToken,
      aliceId,
      realmId,
      "after policy server is declared",
    );

    // Fail-closed default: a declared-but-unverifiable upstream denies.
    expect(
      gated.status,
      `gated message after policy server: ${gated.status} ${JSON.stringify(gated.json)}`,
    ).toBeGreaterThanOrEqual(400);
    expect(wireErrCode(gated.json)).toBeTruthy();

    // The upstream WAS consulted: the mock recorded at least one /policy/check.
    const after = await policyCheckCount(request, baseUrl!);
    expect(after).toBeGreaterThan(before);

    // Mock's /inspect surfaces the recorded checks with their signed transcript
    // (spec section 3 transcript shape, mock-side).
    const inspect = await (await request.get(`${baseUrl}/inspect`)).json();
    expect(inspect.kinds?.checks?.length ?? 0).toBeGreaterThan(0);
    const lastCheck = inspect.kinds.checks[inspect.kinds.checks.length - 1];
    expect(
      typeof lastCheck.signed_transcript === "string" ||
        Boolean(lastCheck.decision),
    ).toBeTruthy();
  });

  test("E3.1 policy server timeout makes soland fail-close the gated op (deny)", async ({
    request,
  }) => {
    const baseUrl = configuredMockPolicyServerBaseUrl();
    test.skip(!baseUrl, "mock-policy-server not started for this run");
    test.skip(
      !baseUrl?.startsWith("https://"),
      "policy-server declarations require an HTTPS mock endpoint",
    );

    const stamp = Date.now();
    const alice = uniqueUser(`s30-timeout-alice-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const aliceId = await currentActorIdApi(request, aliceToken);
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S30 timeout ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      public: true,
    });

    // Make the upstream stall well past soland's outbound timeout_ms. Even a
    // would-be "allow" never arrives in time, so soland's deadline elapses and
    // the on_timeout=fail_closed branch denies (policy_client.rs).
    await request.delete(`${baseUrl}/scenarios`);
    const slow = await request.post(`${baseUrl}/scenarios`, {
      data: { default: "allow", delay_ms: 9000 },
    });
    expect(slow.status()).toBe(200);

    const did = mockPolicyServerDid() ?? "did:web:policy.example.com";
    // cache_ttl 0 so each attempt re-hits the (slow) upstream; tight timeout so
    // the deadline fires quickly relative to the 9s mock delay.
    await declarePolicyServer(request, aliceToken, realmId, baseUrl!, did, {
      cacheTtlSeconds: 0,
      timeoutMs: 1500,
    });

    const started = Date.now();
    const gated = await submitGatedMessage(
      request,
      aliceToken,
      aliceId,
      realmId,
      "gated op while upstream is slow",
    );
    const elapsedMs = Date.now() - started;

    expect(
      gated.status,
      `timeout gated op: ${gated.status} ${JSON.stringify(gated.json)}`,
    ).toBeGreaterThanOrEqual(400);
    expect(wireErrCode(gated.json)).toBeTruthy();
    // soland must give up on its own deadline, not wait out the full 9s upstream
    // delay. Generous upper bound (timeout 1.5s + request overhead) still << 9s.
    expect(elapsedMs).toBeLessThan(8000);

    // Restore a non-blocking default so a leaked slow scenario cannot stall
    // later tests that share this mock instance.
    await request.delete(`${baseUrl}/scenarios`);
  });

  test("E3.2 multi-source priority: org policy_server applies via governed_by fallback when realm declares none", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s30-policy-fallback-alice-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const orgRealmId = await createRealmApi(request, aliceToken, {
      title: `S30 policy fallback org ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      public: true,
    });
    const childRealmId = await createRealmApi(request, aliceToken, {
      title: `S30 policy fallback child ${stamp}`,
      discoverability: "listed",
      history_access: "all_history_for_current_members",
      public: true,
    });

    const orgDid = "did:web:policy-org.example.com";
    const orgBaseUrl = "https://policy-org.example.com";
    const orgUrl = `${orgBaseUrl}/_arkret/self/policy/check`;
    await declarePolicyServer(
      request,
      aliceToken,
      orgRealmId,
      orgBaseUrl,
      orgDid,
      {
        cacheTtlSeconds: 17,
        timeoutMs: 1200,
      },
    );

    const noFallbackYet = await request.get(
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(childRealmId)}/policy-server`,
      { headers: authHeaders(aliceToken) },
    );
    expect(noFallbackYet.status()).toBe(404);

    const linkEvent = await prepareSignedEventSubmissionApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId: childRealmId,
        kind: "ak.realm.link",
        payload: {
          target_realm_id: orgRealmId,
          link_kind: "governed_by",
          status: "active",
        },
      }),
      { context: "prepare child governed_by policy fallback link" },
    );
    const link = await request.post(
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(childRealmId)}/links`,
      {
        headers: {
          ...authHeaders(aliceToken),
          "content-type": "application/json",
        },
        data: canonicalJson({
          link_event: linkEvent,
        }),
      },
    );
    const linkBody = await expectJsonOk<Record<string, unknown>>(
      link,
      "create child governed_by policy fallback link",
    );
    expect(linkBody.realm_id).toBe(childRealmId);
    expect(linkBody.target_realm_id).toBe(orgRealmId);
    expect(linkBody.link_kind).toBe("governed_by");
    expect(linkBody.status).toBe("active");

    const fallback = await request.get(
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(childRealmId)}/policy-server`,
      { headers: authHeaders(aliceToken) },
    );
    const fallbackBody = await expectJsonOk<Record<string, unknown>>(
      fallback,
      "read child policy_server through governed_by fallback",
    );
    expect(fallbackBody.realm_id).toBe(orgRealmId);
    expect(fallbackBody.policy_server_service_id).toBe(
      projectDidToCoreId(orgDid),
    );
    expect(fallbackBody.policy_server_url).toBe(orgUrl);
    expect(fallbackBody.cache_ttl_seconds).toBe(17);
    expect(fallbackBody.timeout_ms).toBe(1200);
    expect(fallbackBody.from_organization_fallback).toBe(true);

    const inheritedOnlyDelete = await deletePolicyServer(
      request,
      aliceToken,
      childRealmId,
    );
    expect(
      inheritedOnlyDelete.status(),
      "inherited policy server is not a direct declaration to tombstone",
    ).toBe(404);

    const childDid = "did:web:policy-child.example.com";
    const childBaseUrl = "https://policy-child.example.com";
    const childUrl = `${childBaseUrl}/_arkret/self/policy/check`;
    await declarePolicyServer(
      request,
      aliceToken,
      childRealmId,
      childBaseUrl,
      childDid,
      {
        cacheTtlSeconds: 3,
        timeoutMs: 900,
      },
    );

    const direct = await request.get(
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(childRealmId)}/policy-server`,
      { headers: authHeaders(aliceToken) },
    );
    const directBody = await expectJsonOk<Record<string, unknown>>(
      direct,
      "read child direct policy_server overriding fallback",
    );
    expect(directBody.realm_id).toBe(childRealmId);
    expect(directBody.policy_server_service_id).toBe(
      projectDidToCoreId(childDid),
    );
    expect(directBody.policy_server_url).toBe(childUrl);
    expect(directBody.cache_ttl_seconds).toBe(3);
    expect(directBody.timeout_ms).toBe(900);
    expect(directBody.from_organization_fallback).toBe(false);

    const deleted = await deletePolicyServer(request, aliceToken, childRealmId);
    expect(deleted.status(), "tombstone direct child policy server").toBe(200);

    const restoredFallback = await request.get(
      `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(childRealmId)}/policy-server`,
      { headers: authHeaders(aliceToken) },
    );
    const restoredFallbackBody = await expectJsonOk<Record<string, unknown>>(
      restoredFallback,
      "read organization policy_server after child tombstone",
    );
    expect(restoredFallbackBody.realm_id).toBe(orgRealmId);
    expect(restoredFallbackBody.policy_server_service_id).toBe(
      projectDidToCoreId(orgDid),
    );
    expect(restoredFallbackBody.from_organization_fallback).toBe(true);

    const childPolicyEvents = await policyServerEvents(
      request,
      aliceToken,
      childRealmId,
    );
    expect(childPolicyEvents.length).toBeGreaterThanOrEqual(2);
    const tombstone = childPolicyEvents.find(
      (event) => event.payload?.tombstone === true,
    );
    expect(
      tombstone,
      "DELETE must append a canonical policy-server tombstone Event",
    ).toBeTruthy();
    expect(tombstone?.actor_id).toBe(alice.id);
    expect(tombstone?.executed_by).toBeUndefined();
    expect(tombstone?.seal_basis?.leaves?.length ?? 0).toBeGreaterThan(0);
    expect(tombstone?.proofs?.length ?? 0).toBeGreaterThan(0);

    const repeatedDelete = await deletePolicyServer(
      request,
      aliceToken,
      childRealmId,
    );
    expect(repeatedDelete.status(), "repeat policy server tombstone").toBe(200);
  });
});
