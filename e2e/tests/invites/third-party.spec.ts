// Third-party invite (email -> token commitment -> binding proof -> claim)
// Contract: e2e/scenarios/invites/third-party.md
// Spec: sync/third-party-invites.md section 3-4

import { expect, test } from "@playwright/test";
import { solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  authHeaders,
  createRealmApi,
  expectJsonOk,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type ThirdPartyInviteIssueOutcome = {
  invite_id: string;
  realm_id: string;
  state: string;
  event_id: string;
  expires_at?: string;
  token_handoff: {
    transport: string;
    url: string;
  };
};

function fragmentToken(handoffUrl: string): string {
  const parsed = new URL(handoffUrl);
  expect(parsed.search).toBe("");
  expect(parsed.hash).toMatch(/^#token=/);
  const token = new URLSearchParams(parsed.hash.slice(1)).get("token");
  expect(token).toBeTruthy();
  return token ?? "";
}

function bogusClaimBody(
  inviteToken: string,
  subjectId: string,
  realmId: string,
  claimNonce: string,
) {
  const serviceDid = solandServiceDid();
  return {
    invite_token: inviteToken,
    claim_nonce: claimNonce,
    subject_id: subjectId,
    binding_proof: {
      subject_id: subjectId,
      realm_id: realmId,
      audience: "cokret.invite.claim",
      claim_nonce: claimNonce,
      verification_service_did: serviceDid,
      verification_method: `${serviceDid}#server-key-1`,
      expires_at: new Date(Date.now() + 5 * 60_000)
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z"),
      signature: "AAAA",
    },
    subject_proof: {
      alg: "EdDSA",
      verification_method: `${subjectId}#device-main`,
      transcript_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      signature: "AAAA",
    },
  };
}

test.describe("third-party invite", () => {
  test("third-party invite uses fragment handoff and fail-closed body claim", async ({
    request,
  }) => {
    const alice = uniqueUser("s3-fragment");
    const bob = uniqueUser("s3-claim");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const realmId = await createRealmApi(request, aliceToken, {
      title: "3PID invite wire strand",
      ownerDid: alice.did,
    });

    const probe = await request.post(`${solandBaseUrl()}/_cokret/self/invites/third-party`, {
      data: { realm_id: realmId, medium: "email", oob_code_kind: "offline_token" },
    });
    expect([401, 403]).toContain(probe.status());

    const issuedResponse = await request.post(
      `${solandBaseUrl()}/_cokret/self/invites/third-party`,
      {
        headers: authHeaders(aliceToken),
        data: {
          realm_id: realmId,
          medium: "email",
          oob_code_kind: "offline_token",
          verification_service_did: solandServiceDid(),
          verification_public_key: `${solandServiceDid()}#server-key-1`,
        },
      },
    );
    const issued = await expectJsonOk<ThirdPartyInviteIssueOutcome>(
      issuedResponse,
      "issue third-party invite",
    );
    expect(issued.realm_id).toBe(realmId);
    expect(issued.state).toBe("pending");
    expect(issued.token_handoff.transport).toBe("url_fragment");
    expect(issued.token_handoff.url).not.toContain("?token=");
    expect(issued.token_handoff.url).not.toContain("invite_token=");
    expect(issued.token_handoff.url).not.toMatch(/\/token[=/]/);
    const inviteToken = fragmentToken(issued.token_handoff.url);

    const queryTokenClaim = await request.post(
      `${solandBaseUrl()}/_cokret/self/invites/third-party/claim?token=${encodeURIComponent(inviteToken)}`,
      { headers: authHeaders(bobToken), data: {} },
    );
    expect(queryTokenClaim.status()).toBe(400);
    expect(wireErrCode(await queryTokenClaim.json())).toBe("third_party_invite_token_in_query");

    const wrongTokenClaim = await request.post(
      `${solandBaseUrl()}/_cokret/self/invites/third-party/claim`,
      {
        headers: authHeaders(bobToken),
        data: bogusClaimBody(`bad-${inviteToken}`, bob.did, realmId, "claim-wrong-token"),
      },
    );
    expect(wrongTokenClaim.status()).toBe(404);
    expect(wireErrCode(await wrongTokenClaim.json())).toBe("not_found");

    const invalidProofClaim = await request.post(
      `${solandBaseUrl()}/_cokret/self/invites/third-party/claim`,
      {
        headers: authHeaders(bobToken),
        data: bogusClaimBody(inviteToken, bob.did, realmId, "claim-invalid-proof"),
      },
    );
    expect(invalidProofClaim.status()).toBe(404);
    expect(wireErrCode(await invalidProofClaim.json())).toBe("not_found");

    const consumedTokenClaim = await request.post(
      `${solandBaseUrl()}/_cokret/self/invites/third-party/claim`,
      {
        headers: authHeaders(bobToken),
        data: bogusClaimBody(inviteToken, bob.did, realmId, "claim-consumed-token"),
      },
    );
    expect(consumedTokenClaim.status()).toBe(404);
    expect(wireErrCode(await consumedTokenClaim.json())).toBe("not_found");
  });

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "alice issues ck.invite.third_party with token_commitment; plaintext email never leaves client",
    async () => {
      // spec: third-party-invites.md section 3.1
    },
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "mock verification service receives invite token via email; bob registers DID; verification service signs binding_proof",
    async () => {
      // soland gap + harness gap: mock email service.
    },
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "bob submits ck.invite.claim with binding_proof + subject_proof; reducer accepts and converts to ck.invite.create + accept",
    async () => {
      // spec: third-party-invites.md section 4
    },
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "E3.1 expired token: reducer rejects claim with invite_expired",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "E3.2 wrong DID claim (subject_proof != binding_proof.subject) rejected with binding_mismatch",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#invites-third-party-gap
    // @user-promise: e2e/scenarios/invites/third-party.md
    // @expected-live-by: 2026Q3
    "E3.3 double-claim: second claim of same token rejected (token consumed)",
    async () => {},
  );
});
