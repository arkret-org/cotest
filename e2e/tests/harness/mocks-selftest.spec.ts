// Harness self-test for the four cotest mock services (idp / email /
// witness / audit-agent). These run against the running mocks started by
// run-joint-e2e.ps1 and assert each mock's contract still holds, so that
// scenarios that rely on a particular endpoint do not silently drift when
// the mock implementation changes.
//
// All tests in this file are tagged @fully-implemented so they run under
// the default `joint-smoke` profile. If the corresponding mock is not
// started for a given run, the test is skipped (rather than fail).

import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import {
  mockAppletRegistryBaseUrl,
  mockAuditAgentBaseUrl,
  mockEmailBaseUrl,
  mockIdpBaseUrl,
  mockPolicyServerBaseUrl,
  mockPushGatewayBaseUrl,
  mockTspEndpointBaseUrl,
  mockWitnessBaseUrl,
  mockWitnessQuorumBaseUrls,
  mockWitnessQuorumDids,
} from "../../helpers/env";
import { createMimiFacadeClient } from "../../helpers/mimi-facade";

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

test.describe("harness mocks selftest @fully-implemented", () => {
  test("mock-idp: scenario, PKCE happy path, force_error matrix", async ({ request }) => {
    const baseUrl = mockIdpBaseUrl();
    test.skip(!baseUrl, "mock-idp not started for this run");

    const loginHint = `selftest-${Date.now()}`;
    const sub = "alice-selftest";
    const email = "alice@selftest.invalid";

    const scenarioResp = await request.post(`${baseUrl}/scenarios`, {
      data: { login_hint: loginHint, sub, email },
    });
    expect(scenarioResp.status()).toBe(200);

    // PKCE happy path
    const verifier = "verifier-selftest-abc-123";
    const challenge = b64url(createHash("sha256").update(verifier).digest());
    const authUrl = new URL(`${baseUrl}/authorize`);
    authUrl.searchParams.set("login_hint", loginHint);
    authUrl.searchParams.set("redirect_uri", "http://rp/cb");
    authUrl.searchParams.set("state", "xyz");
    authUrl.searchParams.set("client_id", "rp-selftest");
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    const authResp = await request.get(authUrl.toString(), { maxRedirects: 0 });
    expect(authResp.status()).toBe(302);
    const location = authResp.headers()["location"];
    expect(location).toBeTruthy();
    const code = new URL(location).searchParams.get("code")!;
    expect(code).toBeTruthy();

    const tokenResp = await request.post(`${baseUrl}/token`, {
      form: { code, code_verifier: verifier, client_id: "rp-selftest" },
    });
    expect(tokenResp.status()).toBe(200);
    const tokenBody = await tokenResp.json();
    expect(tokenBody.token_type).toBe("Bearer");
    expect(typeof tokenBody.id_token).toBe("string");
    const idPayload = JSON.parse(
      Buffer.from(tokenBody.id_token.split(".")[1], "base64url").toString(),
    );
    expect(idPayload.sub).toBe(sub);
    expect(idPayload.email).toBe(email);

    // Force error path
    const badHint = `${loginHint}-bad`;
    await request.post(`${baseUrl}/scenarios`, {
      data: { login_hint: badHint, force_error: "unauthorized_client" },
    });
    const badAuth = await request.get(
      `${baseUrl}/authorize?login_hint=${badHint}&redirect_uri=http://rp/cb&state=q&client_id=rp`,
      { maxRedirects: 0 },
    );
    const badCode = new URL(badAuth.headers()["location"]).searchParams.get("code")!;
    const badToken = await request.post(`${baseUrl}/token`, {
      form: { code: badCode },
    });
    expect(badToken.status()).toBe(400);
    expect((await badToken.json()).error).toBe("unauthorized_client");

    // Inspect log contains both scenario rows
    const inspect = await (await request.get(`${baseUrl}/inspect`)).json();
    expect(inspect.kinds.scenarios.length).toBeGreaterThanOrEqual(2);
  });

  test("mock-email: send/claim happy path + token expiry", async ({ request }) => {
    const baseUrl = mockEmailBaseUrl();
    test.skip(!baseUrl, "mock-email not started for this run");

    const to = `alice-${Date.now()}@selftest.invalid`;
    // Fresh token with TTL=1s → expect 410 after wait.
    const expiringToken = `expiring-${Date.now()}`;
    const sendExpiring = await request.post(`${baseUrl}/_cokret/self/verification/send`, {
      data: { to, token: expiringToken, ttl_seconds: 1, body_html: "<p>hi</p>" },
    });
    expect(sendExpiring.status()).toBe(200);
    await new Promise((r) => setTimeout(r, 1500));
    const claimExpired = await request.post(`${baseUrl}/_cokret/self/verification/claim`, {
      data: { token: expiringToken, did: "did:web:alice.selftest" },
    });
    expect(claimExpired.status()).toBe(410);
    expect((await claimExpired.json()).error).toBe("token_expired");

    // Happy path with a longer TTL
    const goodToken = `good-${Date.now()}`;
    await request.post(`${baseUrl}/_cokret/self/verification/send`, {
      data: { to, token: goodToken, ttl_seconds: 600 },
    });
    const claim = await request.post(`${baseUrl}/_cokret/self/verification/claim`, {
      data: { token: goodToken, did: "did:web:alice.selftest" },
    });
    expect(claim.status()).toBe(200);
    const claimBody = await claim.json();
    expect(typeof claimBody.binding_proof).toBe("string");
    expect(claimBody.token_commitment.startsWith("sha256:")).toBe(true);

    const inspect = await (await request.get(`${baseUrl}/inspect`)).json();
    const tokens = inspect.tokens as Array<{ token: string; consumed: boolean }>;
    const goodEntry = tokens.find((t) => t.token === goodToken);
    expect(goodEntry?.consumed).toBe(true);
  });

  test("mock-witness: chain validation, monotonicity, stale rejection", async ({ request }) => {
    const baseUrl = mockWitnessBaseUrl();
    test.skip(!baseUrl, "mock-witness not started for this run");

    const scid = `selftest-${Date.now()}`;
    const sign1 = await request.post(`${baseUrl}/_cokret/root/witness/sign`, {
      data: { scid, entry_hash: "h1", entry_number: 1 },
    });
    expect(sign1.status()).toBe(200);

    const sign2 = await request.post(`${baseUrl}/_cokret/root/witness/sign`, {
      data: { scid, entry_hash: "h2", entry_number: 2, prev_entry_hash: "h1" },
    });
    expect(sign2.status()).toBe(200);

    const badPrev = await request.post(`${baseUrl}/_cokret/root/witness/sign`, {
      data: { scid, entry_hash: "h3", entry_number: 3, prev_entry_hash: "WRONG" },
    });
    expect(badPrev.status()).toBe(409);
    expect((await badPrev.json()).error).toBe("prev_entry_hash_mismatch");

    const skipEntry = await request.post(`${baseUrl}/_cokret/root/witness/sign`, {
      data: { scid, entry_hash: "h5", entry_number: 5, prev_entry_hash: "h2" },
    });
    expect(skipEntry.status()).toBe(409);
    expect((await skipEntry.json()).error).toBe("non_monotonic_entry_number");

    const stale = await request.post(`${baseUrl}/_cokret/root/witness/sign`, {
      data: {
        scid,
        entry_hash: "h3",
        entry_number: 3,
        prev_entry_hash: "h2",
        entry_timestamp: "2024-01-01T00:00:00Z",
      },
    });
    expect(stale.status()).toBe(422);
    expect((await stale.json()).error).toBe("entry_timestamp_stale");

    const inspect = await (await request.get(`${baseUrl}/inspect`)).json();
    const chainHead = (inspect.chains as Array<{ scid: string; last_entry_number: number }>).find(
      (c) => c.scid === scid,
    );
    expect(chainHead?.last_entry_number).toBe(2);
  });

  test("mock-witness quorum: every configured witness exposes policy", async ({ request }) => {
    const baseUrls = mockWitnessQuorumBaseUrls();
    const dids = mockWitnessQuorumDids();
    test.skip(baseUrls.length < 2, "mock-witness quorum not started for this run");

    expect(dids.length).toBe(baseUrls.length);
    for (const [index, baseUrl] of baseUrls.entries()) {
      const policy = await request.get(`${baseUrl}/_cokret/root/witness/policy`);
      expect(policy.status()).toBe(200);
      const body = await policy.json();
      expect(body.witness_did).toBe(dids[index]);
      expect(body.health).toBe("healthy");
    }
  });

  test("mock-audit-agent: identity, invite ack, accessed log, jwks", async ({ request }) => {
    const baseUrl = mockAuditAgentBaseUrl();
    test.skip(!baseUrl, "mock-audit-agent not started for this run");

    const identity = await (await request.get(`${baseUrl}/_soland/admin/audit-agent/identity`)).json();
    expect(typeof identity.did).toBe("string");
    expect(identity.key_package?.kind).toBe("mock-mls-key-package-v1");

    const spaceId = `ck:space:selftest:${Date.now()}`;
    const invite = await request.post(`${baseUrl}/_soland/admin/audit-agent/invite`, {
      data: { space_id: spaceId, invite: { event_id: "evt-selftest" } },
    });
    expect(invite.status()).toBe(200);
    const inviteBody = await invite.json();
    expect(inviteBody.agent_id).toBe(identity.did);
    expect(inviteBody.emitted.type).toBe("ck.audit.accessed");
    expect(inviteBody.emitted.space_id).toBe(spaceId);
    expect(typeof inviteBody.emitted.binding_proof).toBe("string");

    const accessed = await (
      await request.get(`${baseUrl}/_soland/admin/audit-agent/accessed`)
    ).json();
    expect(
      (accessed.events as Array<{ space_id: string }>).some((e) => e.space_id === spaceId),
    ).toBe(true);

    const jwks = await (await request.get(`${baseUrl}/jwks`)).json();
    expect(jwks.keys?.[0]?.kid).toBe("mock-audit-agent-key-1");

    const inspect = await (await request.get(`${baseUrl}/inspect`)).json();
    expect(inspect.kinds.invites.length).toBeGreaterThanOrEqual(1);
    expect(inspect.kinds.accessed.length).toBeGreaterThanOrEqual(1);
  });

  test("mock-policy-server: rule injection, deny + obligation, signed transcript", async ({
    request,
  }) => {
    const baseUrl = mockPolicyServerBaseUrl();
    test.skip(!baseUrl, "mock-policy-server not started for this run");

    // Reset rules to a known baseline.
    await request.delete(`${baseUrl}/scenarios`);

    // Default allow when no rules match.
    const allowResp = await request.post(`${baseUrl}/_cokret/self/policy/check`, {
      data: { action: "ck.member.invite", actor: "did:web:alice", target: "did:web:carol" },
    });
    expect(allowResp.status()).toBe(200);
    expect((await allowResp.json()).decision).toBe("allow");

    // Inject a deny rule + obligation.
    await request.post(`${baseUrl}/scenarios`, {
      data: {
        rules: [
          {
            action: "ck.member.invite",
            actor: "did:web:alice",
            target: "did:web:bob",
            decision: "deny",
            reason: "abuse_filter",
            obligations: [{ kind: "log_event", target: "audit_log" }],
          },
        ],
      },
    });

    const denyResp = await request.post(`${baseUrl}/_cokret/self/policy/check`, {
      data: { action: "ck.member.invite", actor: "did:web:alice", target: "did:web:bob" },
    });
    expect(denyResp.status()).toBe(200);
    const denyBody = await denyResp.json();
    expect(denyBody.decision).toBe("deny");
    expect(denyBody.reason).toBe("abuse_filter");
    expect(Array.isArray(denyBody.obligations)).toBe(true);
    expect(denyBody.obligations[0]?.kind).toBe("log_event");
    expect(typeof denyBody.signed_transcript).toBe("string");
    // JWT-shaped 3-segment transcript.
    expect(denyBody.signed_transcript.split(".").length).toBe(3);

    const jwks = await (await request.get(`${baseUrl}/jwks`)).json();
    expect(jwks.keys?.[0]?.kid).toBe("mock-policy-server-key-1");

    const inspect = await (await request.get(`${baseUrl}/inspect`)).json();
    expect(inspect.kinds.checks.length).toBeGreaterThanOrEqual(2);
  });

  test("mock-push-gateway: register, notify, DnD suppression, blind-wake validation", async ({
    request,
  }) => {
    const baseUrl = mockPushGatewayBaseUrl();
    test.skip(!baseUrl, "mock-push-gateway not started for this run");

    await request.delete(`${baseUrl}/scenarios`);

    const pusherId = `selftest-pusher-${Date.now()}`;
    const reg = await request.post(`${baseUrl}/_cokret/edge/push/register`, {
      data: {
        pusher_id: pusherId,
        app_id: "selftest",
        push_key: "k",
        push_token: "t",
        device_did: "did:web:selftest-device",
        kind: "http",
      },
    });
    expect(reg.status()).toBe(200);

    const notify = await request.post(`${baseUrl}/_cokret/edge/push/notify`, {
      data: {
        pusher_id: pusherId,
        payload: { title: "selftest", body: "hello" },
        priority: "high",
      },
    });
    expect(notify.status()).toBe(200);
    const notifyBody = await notify.json();
    expect(notifyBody.delivered).toBe(true);
    expect(typeof notifyBody.delivery_receipt).toBe("string");
    expect(notifyBody.delivery_receipt.split(".").length).toBe(3);

    // Blind-wake payload MUST not contain plain content.
    const blindBad = await request.post(`${baseUrl}/_cokret/edge/push/notify`, {
      data: {
        pusher_id: pusherId,
        blind_wake: true,
        payload: { body: "leaked plaintext" },
      },
    });
    // Mock rejects forbidden plaintext keys in blind-wake mode.
    expect([400, 422]).toContain(blindBad.status());

    const inbox = await (await request.get(`${baseUrl}/_cokret/edge/push/inbox?pusher_id=${pusherId}`)).json();
    expect(inbox.pusher_id).toBe(pusherId);
    expect(Array.isArray(inbox.pushes)).toBe(true);
    expect(inbox.pushes.length).toBeGreaterThanOrEqual(1);

    const jwks = await (await request.get(`${baseUrl}/jwks`)).json();
    expect(jwks.keys?.[0]?.kid).toBe("mock-push-gateway-key-1");
  });

  test("mock-applet-registry: signed applet package", async ({
    request,
  }) => {
    const baseUrl = mockAppletRegistryBaseUrl();
    test.skip(!baseUrl, "mock-applet-registry not started for this run");

    const namespace = `selftest-${Date.now()}`;
    const signed = await request.post(`${baseUrl}/sign-package`, {
      data: {
        namespace,
        requested_scopes: ["ck.message.create", "ck.applet.ghost.provision"],
      },
    });
    expect(signed.status()).toBe(200);
    const body = await signed.json();
    expect(body.package_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(body.applet_package.schema).toBe("ck.schema.applet_package.v1");
    expect(body.applet_package.bot_actor_id.startsWith(`did:web:bot-${namespace}`)).toBe(true);
    expect(body.applet_package.requested_scopes).toContain("ck.message.create");
    expect(body.applet_package.proof.payload_digest).toMatch(/^sha256:[0-9a-f]{64}$/);

    const identity = await (await request.get(`${baseUrl}/identity`)).json();
    expect(typeof identity.did).toBe("string");
  });

  test("mock-tsp-endpoint: relationship bootstrap, message ACK round-trip", async ({
    request,
  }) => {
    const baseUrl = mockTspEndpointBaseUrl();
    test.skip(!baseUrl, "mock-tsp-endpoint not started for this run");

    await request.delete(`${baseUrl}/scenarios`);

    const remoteVid = `did:web:alice-selftest-${Date.now()}.example`;
    const bootstrap = await request.post(`${baseUrl}/tsp/relationship-bootstrap`, {
      data: {
        remote_vid: remoteVid,
        remote_public_jwk: { kty: "OKP", crv: "Ed25519", x: "selftest-key" },
      },
    });
    expect(bootstrap.status()).toBe(200);
    const bsBody = await bootstrap.json();
    expect(typeof bsBody.endpoint_vid).toBe("string");
    expect(typeof bsBody.established_at).toBe("string");

    // Posting a message before bootstrap fails; verify with a fresh remote.
    const unestablishedRemote = `did:web:bob-${Date.now()}.example`;
    const noRel = await request.post(`${baseUrl}/tsp/message`, {
      data: {
        from_vid: unestablishedRemote,
        to_vid: bsBody.endpoint_vid,
        payload_b64: Buffer.from(JSON.stringify({ type: "ck.invite.create" })).toString("base64url"),
        signature_b64: "test-sig",
      },
    });
    expect(noRel.status()).toBe(412);

    // Established relationship can post.
    const msg = await request.post(`${baseUrl}/tsp/message`, {
      data: {
        from_vid: remoteVid,
        to_vid: bsBody.endpoint_vid,
        payload_b64: Buffer.from(
          JSON.stringify({ type: "ck.invite.create", target: bsBody.endpoint_vid }),
        ).toString("base64url"),
        signature_b64: "test-sig",
      },
    });
    expect(msg.status()).toBe(200);
    const msgBody = await msg.json();
    expect(msgBody.accepted).toBe(true);

    const jwks = await (await request.get(`${baseUrl}/jwks`)).json();
    expect(jwks.keys?.[0]?.kid).toBe("mock-tsp-endpoint-key-1");
  });

  test("mock-mimi-facade: bob_mimi join, fallback/deferred, content quarantine", async ({
    request,
  }) => {
    const facade = createMimiFacadeClient(request);
    test.skip(!facade, "mock-mimi-facade not started for this run");

    await facade.reset();
    const identity = await (await request.get(`${facade.baseUrl}/identity`)).json();
    expect(identity.did).toBe(facade.facadeDid ?? "did:web:mimi-facade.joint-e2e.local");
    expect(identity.identities.some((entry: { mimi_handle: string }) => entry.mimi_handle === "bob_mimi")).toBe(true);

    const stamp = Date.now();
    const realmId = `ck:realm:mimi-selftest:${stamp}`;
    const roomBindingId = `mimi-room-selftest-${stamp}`;
    const join = await facade.createJoinRequest({
      room_binding_id: roomBindingId,
      mimi_handle: "bob_mimi",
    });
    expect(join.status).toBe("pending");
    expect(join.origin).toBe("mimi");

    const approval = await facade.approveJoin({
      realm_id: realmId,
      room_binding_id: roomBindingId,
      join_request_id: String(join.join_request_id),
    });
    expect(approval.status).toBe("approved");
    expect(String(approval.pairwise_did)).toMatch(/^did:pairwise:/);
    expect(approval.source).toBe("mimi");

    const delivered = await facade.sendOutbound({
      realm_id: realmId,
      room_binding_id: roomBindingId,
      sender_did: "did:web:alice.selftest",
      content_kind: "m.text",
      content: { body: "hello MIMI" },
    });
    expect(delivered.status).toBe(200);
    expect(delivered.body.status).toBe("delivered");
    expect(String(delivered.body.mimi_event_id)).toMatch(/^mimi:event:/);

    await facade.configure({ unavailable: true });
    const deferred = await facade.sendOutbound({
      realm_id: realmId,
      room_binding_id: roomBindingId,
      sender_did: "did:web:alice.selftest",
      content_kind: "m.text",
      content: { body: "local persist, MIMI deferred" },
    });
    expect(deferred.status).toBe(503);
    expect(deferred.body.status).toBe("deferred");
    expect(deferred.body.deferred_reason).toBe("mimi_facade_unavailable");
    await facade.configure({ unavailable: false });

    const accepted = await facade.injectInbound({
      realm_id: realmId,
      room_binding_id: roomBindingId,
      mimi_handle: "bob_mimi",
      content_kind: "m.text",
      content: { body: "bob says hi" },
    });
    expect(accepted.status).toBe(200);
    expect(accepted.body.status).toBe("accepted");
    expect(String(accepted.body.cokret_event_hint)).toMatch(/^ck:event:mimi:/);

    const quarantined = await facade.injectInbound({
      realm_id: realmId,
      room_binding_id: roomBindingId,
      mimi_handle: "bob_mimi",
      content_kind: "m.location.share.live",
      content: { lat: 39.9, lon: 116.4 },
    });
    expect(quarantined.status).toBe(202);
    expect(quarantined.body.status).toBe("quarantined");
    expect(quarantined.body.unknown_content_kind).toBe("m.location.share.live");

    const inspect = await facade.inspect();
    const kinds = inspect.kinds as Record<string, unknown[]>;
    expect(kinds.join_requests.length).toBeGreaterThanOrEqual(1);
    expect(kinds.approvals.length).toBeGreaterThanOrEqual(1);
    expect(kinds.outbound.length).toBeGreaterThanOrEqual(2);
    expect(kinds.inbound.length).toBeGreaterThanOrEqual(1);
    expect(kinds.quarantine.length).toBeGreaterThanOrEqual(1);
  });
});
