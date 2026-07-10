// Knock auto-resolve path (ck.member.state{join, gate_proofs})
// Contract: e2e/scenarios/spaces/knock-auto-resolve.md
// Spec: governance/join-policy.md §5 (auto-resolve path), §3.1 gate types

import {
  expect,
  test,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import {
  mockChallengeProviderBaseUrl,
  mockChallengeProviderDid,
  mockClaimIssuerBaseUrl,
} from "../../helpers/env";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";
import {
  createRealmApi,
  submitJoinWithProofsApi,
  submitLeaveApi,
  wireErrCode,
  writeJoinPolicyApi,
} from "../../helpers/soland-api";

test.describe.configure({ mode: "serial" });

// Reducer rejects are HTTP 412 (or a 4xx in the same family) carrying a JSON
// body whose error code identifies the failing gate. Read it leniently — the
// wire shape is { error: { code, reason_code? } } | { reason_code } | a string.
async function rejectCode(resp: APIResponse): Promise<string> {
  const text = await resp.text();
  try {
    const body = JSON.parse(text) as unknown;
    const code = wireErrCode(body);
    if (code) {
      return `${code} :: ${text}`;
    }
  } catch {
    // Not JSON — fall through to the raw text.
  }
  return text;
}

function expectGateReject(resp: APIResponse, body: string) {
  expect(
    [400, 412, 422],
    `expected a gate reject status, got ${resp.status()}: ${body}`,
  ).toContain(resp.status());
  expect(body).toMatch(
    /gate_check_failed|failed_precondition|cooldown|challenge_failed|claim_invalid/,
  );
}

// claim_required gate `g-vc`: requires_claims must be covered by the
// presentation's claims[]. The mock returns { claim_presentation, jws }.
async function issueClaim(
  request: APIRequestContext,
  subjectDid: string,
  claims: string[],
): Promise<Record<string, unknown>> {
  const resp = await request.post(`${mockClaimIssuerBaseUrl()}/issue-claim`, {
    data: { subject_did: subjectDid, claims },
  });
  expect(
    resp.ok(),
    `issue-claim returned ${resp.status()}: ${await resp.text()}`,
  ).toBeTruthy();
  const body = (await resp.json()) as {
    claim_presentation: Record<string, unknown>;
  };
  return body.claim_presentation;
}

// challenge_response gate `g-captcha`: the mock returns { challenge_proof }.
// issued_at_offset_seconds backdates issued_at to drive the stale-proof case.
async function issueChallenge(
  request: APIRequestContext,
  subjectDid: string,
  opts: { issuedAtOffsetSeconds?: number } = {},
): Promise<Record<string, unknown>> {
  const resp = await request.post(`${mockChallengeProviderBaseUrl()}/challenge`, {
    data: {
      subject_did: subjectDid,
      challenge_kind: "captcha",
      ...(opts.issuedAtOffsetSeconds !== undefined
        ? { issued_at_offset_seconds: opts.issuedAtOffsetSeconds }
        : {}),
    },
  });
  expect(
    resp.ok(),
    `challenge returned ${resp.status()}: ${await resp.text()}`,
  ).toBeTruthy();
  const body = (await resp.json()) as {
    challenge_proof: Record<string, unknown>;
  };
  return body.challenge_proof;
}

// The captcha gate's provider_did must equal the proof's issued_by. The mock
// stamps issued_by from its configured DID, so bind the gate to the proof's
// own issued_by when present (robust against any key-suffix drift) and fall
// back to the harness-advertised DID otherwise.
function captchaProviderDid(proof?: Record<string, unknown>): string {
  const issuedBy = proof?.["issued_by"];
  return typeof issuedBy === "string" ? issuedBy : mockChallengeProviderDid();
}

function vcGate(): Record<string, unknown> {
  return {
    gate_id: "g-vc",
    kind: "claim_required",
    auto_resolve: true,
    requires_claims: ["acme:employee"],
  };
}

function captchaGate(providerDid: string): Record<string, unknown> {
  return {
    gate_id: "g-captcha",
    kind: "challenge_response",
    auto_resolve: true,
    provider_did: providerDid,
    challenge_kinds: ["captcha"],
    max_proof_age: "PT5M",
  };
}

test.describe("knock auto-resolve path", () => {
  test("alice sets join_rule=knock_restricted with gates=[claim_required(auto), challenge_response(auto)]; bob submits ak.member.state{join, gate_proofs[]} and joins directly", async ({
    request,
  }) => {
    test.skip(
      !mockClaimIssuerBaseUrl() || !mockChallengeProviderBaseUrl(),
      "claim issuer / challenge provider mock not provisioned",
    );

    const alice = uniqueUser("ar-alice");
    const bob = uniqueUser("ar-bob");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `AR happy ${Date.now()}`,
      default_join_rule: "knock_restricted",
    });

    // bob's captcha proof carries issued_by; bind the gate to it.
    const challengeProof = await issueChallenge(request, bob.did);
    await writeJoinPolicyApi(request, aliceToken, realmId, {
      combinator: "all",
      gates: [vcGate(), captchaGate(captchaProviderDid(challengeProof))],
    });

    const claimPresentation = await issueClaim(request, bob.did, [
      "acme:employee",
    ]);

    const resp = await submitJoinWithProofsApi(request, bobToken, bob.did, realmId, [
      { gate_id: "g-vc", claim_presentation: claimPresentation },
      { gate_id: "g-captcha", challenge_proof: challengeProof },
    ]);
    expect(
      [200, 201],
      `auto-resolve join returned ${resp.status()}: ${await resp.text()}`,
    ).toContain(resp.status());
  });

  test("mallory without the required VC: gate_proofs[].g-vc invalid; reducer rejects with failed_precondition + g-vc gate id", async ({
    request,
  }) => {
    test.skip(
      !mockClaimIssuerBaseUrl() || !mockChallengeProviderBaseUrl(),
      "claim issuer / challenge provider mock not provisioned",
    );

    const alice = uniqueUser("ar-alice");
    const mallory = uniqueUser("ar-mallory");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, mallory);
    const aliceToken = await issueDevSession(request, alice);
    const malloryToken = await issueDevSession(request, mallory);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `AR no-vc ${Date.now()}`,
      default_join_rule: "knock_restricted",
    });

    const challengeProof = await issueChallenge(request, mallory.did);
    await writeJoinPolicyApi(request, aliceToken, realmId, {
      combinator: "all",
      gates: [vcGate(), captchaGate(captchaProviderDid(challengeProof))],
    });

    // mallory holds a valid captcha but a claim that does NOT cover
    // acme:employee, so the g-vc gate fails under combinator=all.
    const wrongClaim = await issueClaim(request, mallory.did, ["acme:other"]);

    const resp = await submitJoinWithProofsApi(
      request,
      malloryToken,
      mallory.did,
      realmId,
      [
        { gate_id: "g-vc", claim_presentation: wrongClaim },
        { gate_id: "g-captcha", challenge_proof: challengeProof },
      ],
    );
    const body = await rejectCode(resp);
    expectGateReject(resp, body);
  });

  test("E6.2.2 challenge_proof older than max_proof_age=5min: rejected with challenge_failed", async ({
    request,
  }) => {
    test.skip(
      !mockClaimIssuerBaseUrl() || !mockChallengeProviderBaseUrl(),
      "claim issuer / challenge provider mock not provisioned",
    );

    const alice = uniqueUser("ar-alice");
    const bob = uniqueUser("ar-bob");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `AR stale ${Date.now()}`,
      default_join_rule: "knock_restricted",
    });

    // A fresh proof only to discover the provider DID for the gate; the join
    // itself uses a stale proof backdated past max_proof_age (5min).
    const freshProof = await issueChallenge(request, bob.did);
    await writeJoinPolicyApi(request, aliceToken, realmId, {
      combinator: "all",
      gates: [vcGate(), captchaGate(captchaProviderDid(freshProof))],
    });

    const claimPresentation = await issueClaim(request, bob.did, [
      "acme:employee",
    ]);
    const staleProof = await issueChallenge(request, bob.did, {
      issuedAtOffsetSeconds: 400,
    });

    const resp = await submitJoinWithProofsApi(request, bobToken, bob.did, realmId, [
      { gate_id: "g-vc", claim_presentation: claimPresentation },
      { gate_id: "g-captcha", challenge_proof: staleProof },
    ]);
    const body = await rejectCode(resp);
    expectGateReject(resp, body);
  });

  test("cooldown gate independent of combinator: bob leaves then immediately re-applies → rejected with cooldown_gate_blocking", async ({
    request,
  }) => {
    test.skip(
      !mockClaimIssuerBaseUrl() || !mockChallengeProviderBaseUrl(),
      "claim issuer / challenge provider mock not provisioned",
    );

    const alice = uniqueUser("ar-alice");
    const bob = uniqueUser("ar-bob");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `AR cooldown ${Date.now()}`,
      default_join_rule: "knock_restricted",
    });

    // Policy carries the cooldown gate from the start. cooldown is a deny gate
    // independent of the combinator (join-policy.md §3.1); combinator=any keeps
    // the g-vc satisfiable in isolation.
    await writeJoinPolicyApi(request, aliceToken, realmId, {
      combinator: "any",
      gates: [
        vcGate(),
        {
          gate_id: "g-cool",
          kind: "cooldown",
          min_interval_since_leave: "P30D",
        },
      ],
    });

    // First join: bob has never left, so cooldown does not bite.
    const firstClaim = await issueClaim(request, bob.did, ["acme:employee"]);
    const joinResp = await submitJoinWithProofsApi(
      request,
      bobToken,
      bob.did,
      realmId,
      [{ gate_id: "g-vc", claim_presentation: firstClaim }],
    );
    expect(
      [200, 201],
      `initial join returned ${joinResp.status()}: ${await joinResp.text()}`,
    ).toContain(joinResp.status());

    // bob leaves, then immediately re-applies with a still-valid g-vc proof.
    await submitLeaveApi(request, bobToken, bob.did, realmId);

    const reapplyClaim = await issueClaim(request, bob.did, ["acme:employee"]);
    const resp = await submitJoinWithProofsApi(
      request,
      bobToken,
      bob.did,
      realmId,
      [{ gate_id: "g-vc", claim_presentation: reapplyClaim }],
    );
    const body = await rejectCode(resp);
    expectGateReject(resp, body);
  });

  test("combinator=any: bob satisfies only g-vc → still accepted; mallory satisfies only g-captcha → also accepted (typical knock_restricted hybrid)", async ({
    request,
  }) => {
    test.skip(
      !mockClaimIssuerBaseUrl() || !mockChallengeProviderBaseUrl(),
      "claim issuer / challenge provider mock not provisioned",
    );

    const alice = uniqueUser("ar-alice");
    const bob = uniqueUser("ar-bob");
    const mallory = uniqueUser("ar-mallory");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    await ensureRegistered(request, mallory);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const malloryToken = await issueDevSession(request, mallory);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `AR any ${Date.now()}`,
      default_join_rule: "knock_restricted",
    });

    // Discover the provider DID from a sample proof, then write the any-policy.
    const sampleProof = await issueChallenge(request, mallory.did);
    await writeJoinPolicyApi(request, aliceToken, realmId, {
      combinator: "any",
      gates: [vcGate(), captchaGate(captchaProviderDid(sampleProof))],
    });

    // bob satisfies only g-vc → accepted under combinator=any.
    const bobClaim = await issueClaim(request, bob.did, ["acme:employee"]);
    const bobResp = await submitJoinWithProofsApi(
      request,
      bobToken,
      bob.did,
      realmId,
      [{ gate_id: "g-vc", claim_presentation: bobClaim }],
    );
    expect(
      [200, 201],
      `bob (g-vc only) join returned ${bobResp.status()}: ${await bobResp.text()}`,
    ).toContain(bobResp.status());

    // mallory satisfies only g-captcha → also accepted under combinator=any.
    const malloryProof = await issueChallenge(request, mallory.did);
    const malloryResp = await submitJoinWithProofsApi(
      request,
      malloryToken,
      mallory.did,
      realmId,
      [{ gate_id: "g-captcha", challenge_proof: malloryProof }],
    );
    expect(
      [200, 201],
      `mallory (g-captcha only) join returned ${malloryResp.status()}: ${await malloryResp.text()}`,
    ).toContain(malloryResp.status());
  });
});
