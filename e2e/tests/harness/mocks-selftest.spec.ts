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
  mockAuditAgentBaseUrl,
  mockEmailBaseUrl,
  mockIdpBaseUrl,
  mockWitnessBaseUrl,
} from "../../helpers/env";

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
    const sendExpiring = await request.post(`${baseUrl}/api/v1/verification/send`, {
      data: { to, token: expiringToken, ttl_seconds: 1, body_html: "<p>hi</p>" },
    });
    expect(sendExpiring.status()).toBe(200);
    await new Promise((r) => setTimeout(r, 1500));
    const claimExpired = await request.post(`${baseUrl}/api/v1/verification/claim`, {
      data: { token: expiringToken, did: "did:web:alice.selftest" },
    });
    expect(claimExpired.status()).toBe(410);
    expect((await claimExpired.json()).error).toBe("token_expired");

    // Happy path with a longer TTL
    const goodToken = `good-${Date.now()}`;
    await request.post(`${baseUrl}/api/v1/verification/send`, {
      data: { to, token: goodToken, ttl_seconds: 600 },
    });
    const claim = await request.post(`${baseUrl}/api/v1/verification/claim`, {
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
    const sign1 = await request.post(`${baseUrl}/api/v1/witness/sign`, {
      data: { scid, entry_hash: "h1", entry_number: 1 },
    });
    expect(sign1.status()).toBe(200);

    const sign2 = await request.post(`${baseUrl}/api/v1/witness/sign`, {
      data: { scid, entry_hash: "h2", entry_number: 2, prev_entry_hash: "h1" },
    });
    expect(sign2.status()).toBe(200);

    const badPrev = await request.post(`${baseUrl}/api/v1/witness/sign`, {
      data: { scid, entry_hash: "h3", entry_number: 3, prev_entry_hash: "WRONG" },
    });
    expect(badPrev.status()).toBe(409);
    expect((await badPrev.json()).error).toBe("prev_entry_hash_mismatch");

    const skipEntry = await request.post(`${baseUrl}/api/v1/witness/sign`, {
      data: { scid, entry_hash: "h5", entry_number: 5, prev_entry_hash: "h2" },
    });
    expect(skipEntry.status()).toBe(409);
    expect((await skipEntry.json()).error).toBe("non_monotonic_entry_number");

    const stale = await request.post(`${baseUrl}/api/v1/witness/sign`, {
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

  test("mock-audit-agent: identity, invite ack, accessed log, jwks", async ({ request }) => {
    const baseUrl = mockAuditAgentBaseUrl();
    test.skip(!baseUrl, "mock-audit-agent not started for this run");

    const identity = await (await request.get(`${baseUrl}/api/v1/audit-agent/identity`)).json();
    expect(typeof identity.did).toBe("string");
    expect(identity.key_package?.kind).toBe("mock-mls-key-package-v1");

    const spaceId = `cx:space:selftest:${Date.now()}`;
    const invite = await request.post(`${baseUrl}/api/v1/audit-agent/invite`, {
      data: { space_id: spaceId, invite: { event_id: "evt-selftest" } },
    });
    expect(invite.status()).toBe(200);
    const inviteBody = await invite.json();
    expect(inviteBody.agent_did).toBe(identity.did);
    expect(inviteBody.emitted.type).toBe("cx.audit.accessed");
    expect(inviteBody.emitted.space_id).toBe(spaceId);
    expect(typeof inviteBody.emitted.binding_proof).toBe("string");

    const accessed = await (
      await request.get(`${baseUrl}/api/v1/audit-agent/accessed`)
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
});
