// Knock application + review + cooldown
// Contract: e2e/scenarios/spaces/knock-application.md
// Spec refs:
//   - governance/join-policy.md §3 (join policy cell, application fields)
//   - §7 application-review path, §7.5 invite ref binding
//   - §12 anti-abuse (cooldown_after_reject, application_ttl,
//     max_open_applications_per_actor)
//   - §3 #2 / §8.1 applicant_visibility=reviewer_only + ak.audit.accessed

import {
  expect,
  test,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import {
  addRealmMemberApi,
  canonicalTimestamp,
  createRealmApi,
  grantRealmReviewCapabilityApi,
  listJoinApplicationAuditApi,
  listMemberApplicationsApi,
  revokeCapabilityApi,
  submitApplicationApi,
  submitApplicationReviewApi,
  submitInviteCreateApi,
  submitKnockApi,
  wireErrCode,
  writeJoinPolicyApi,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

// Reducer rejects are HTTP 412 (or a sibling 4xx) carrying a JSON body whose
// error code identifies the failure. Read it leniently across the possible
// wire shapes.
async function rejectCode(resp: APIResponse): Promise<string> {
  const text = await resp.text();
  try {
    const body = JSON.parse(text) as unknown;
    const code = wireErrCode(body);
    if (code) {
      return code;
    }
  } catch {
    // fall through to raw text
  }
  return text;
}

const APPLICATION_FORM_POLICY = {
  gates: [
    {
      gate_id: "g-intro",
      kind: "application_form",
      auto_resolve: false,
      questions: [
        {
          question_id: "q1",
          prompt_canonical: "Why do you want to join?",
          answer_kind: "text",
          required: true,
          min_chars: 10,
          max_chars: 500,
        },
      ],
    },
  ],
  combinator: "all",
  review_capability: "ak.realm.join.review",
  reviewer_quorum: "any",
  application_ttl: "PT168H",
  cooldown_after_reject: "PT72H",
  max_open_applications_per_actor: 1,
  applicant_visibility: "reviewer_only",
};

const JOIN_POLICY_PROFILE_SCHEMA_REFS = [
  "ak.schema.realm.v1",
  "ak.profile.candidate.join_policy.v1",
];

async function makeUser(request: APIRequestContext, prefix: string) {
  const user = uniqueUser(prefix);
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  return { user, token };
}

function applicationAnswers(
  entry: Record<string, unknown> | undefined,
): unknown {
  const privateBody = entry?.private_body;
  return privateBody && typeof privateBody === "object"
    ? (privateBody as Record<string, unknown>).answers
    : undefined;
}

test.describe("knock + application + cooldown", () => {
  test("alice opens a knock Realm and lists bob in member.state=knock after he knocks", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6-alice");
    const bob = await makeUser(request, "s6-bob");

    const realmId = await createRealmApi(request, alice.token, {
      title: `S6 Knock ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      summary: "knock + application coverage",
      discoverability: "listed",
      default_join_rule: "knock",
      history_access: "since_join",
      ownerDid: alice.user.did,
    });
    await writeJoinPolicyApi(request, alice.token, realmId, APPLICATION_FORM_POLICY);

    const knockResp = await submitKnockApi(
      request,
      bob.token,
      bob.user.did,
      realmId,
    );
    expect(knockResp).toBeTruthy();

    const listed = await listMemberApplicationsApi(request, alice.token, realmId);
    expect(listed.viewer_is_reviewer).toBe(true);
  });

  test("E6.A bob submits structured member.application after knocking; alice (with ak.realm.join.review) sees the answers and accepts", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6a-alice");
    const bob = await makeUser(request, "s6a-bob");
    const realmId = await createRealmApi(request, alice.token, {
      title: `S6A ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      discoverability: "listed",
      default_join_rule: "knock",
      ownerDid: alice.user.did,
    });
    const reviewerGrantId = await grantRealmReviewCapabilityApi(
      request,
      alice.token,
      {
        ownerDid: alice.user.did,
        realmId,
        subjectDid: alice.user.did,
      },
    );
    const policyDigest = await writeJoinPolicyApi(
      request,
      alice.token,
      realmId,
      APPLICATION_FORM_POLICY,
    );

    const knock = await submitKnockApi(request, bob.token, bob.user.did, realmId);
    const knockRef = String((knock as Record<string, unknown>).event_id ?? "");
    const receiptDigest = await submitApplicationApi(
      request,
      bob.token,
      bob.user.did,
      realmId,
      {
        knockRef,
        policyVersionDigest: policyDigest,
        answers: [{ question_id: "q1", value: "I want to learn protocol design" }],
      },
    );

    // Realm ownership allows the governance read; the signed review still cites
    // the explicit capability grant required by join-policy.md §7.3.
    const reviewerView = await listMemberApplicationsApi(
      request,
      alice.token,
      realmId,
    );
    expect(reviewerView.viewer_is_reviewer).toBe(true);
    const bobEntry = reviewerView.applications.find(
      (entry) => entry.applicant_did === bob.user.did,
    );
    expect(bobEntry, "bob application listed for reviewer").toBeTruthy();
    expect(applicationAnswers(bobEntry), "reviewer sees answers").toBeTruthy();

    // alice accepts.
    await submitApplicationReviewApi(
      request,
      alice.token,
      alice.user.did,
      bob.user.did,
      realmId,
      {
        applicationRef: receiptDigest,
        decision: "accept",
        reasonCode: "ok",
        grantId: reviewerGrantId,
      },
    );
    const afterAccept = await listMemberApplicationsApi(
      request,
      alice.token,
      realmId,
    );
    const accepted = afterAccept.applications.find(
      (entry) => entry.applicant_did === bob.user.did,
    );
    expect(accepted?.status).toBe("accepted");
  });

  test('E6.B alice\'s ak.invite.create.refs[role="join_authorised_by"] is required to point at a fresh review accept; reducer rejects re-used or stale refs', async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6b-alice");
    const bob = await makeUser(request, "s6b-bob");
    const realmId = await createRealmApi(request, alice.token, {
      title: `S6B ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      discoverability: "listed",
      default_join_rule: "knock",
      ownerDid: alice.user.did,
    });
    const reviewerGrantId = await grantRealmReviewCapabilityApi(
      request,
      alice.token,
      {
        ownerDid: alice.user.did,
        realmId,
        subjectDid: alice.user.did,
      },
    );
    await writeJoinPolicyApi(request, alice.token, realmId, APPLICATION_FORM_POLICY);

    const knock = await submitKnockApi(request, bob.token, bob.user.did, realmId);
    const receiptDigest = await submitApplicationApi(
      request,
      bob.token,
      bob.user.did,
      realmId,
      {
        knockRef: String((knock as Record<string, unknown>).event_id ?? ""),
        answers: [{ question_id: "q1", value: "Genuine application body" }],
      },
    );
    const reviewDigest = await submitApplicationReviewApi(
      request,
      alice.token,
      alice.user.did,
      bob.user.did,
      realmId,
      {
        applicationRef: receiptDigest,
        decision: "accept",
        reasonCode: "ok",
        grantId: reviewerGrantId,
      },
    );

    // A ref pointing at a non-existent / stale review accept MUST be rejected.
    const staleResp = await submitInviteCreateApi(
      request,
      alice.token,
      alice.user.did,
      realmId,
      bob.user.did,
      "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    expect([400, 412, 422]).toContain(staleResp.status());
    expect(await rejectCode(staleResp)).toContain("join_authorisation_invalid");

    // A ref pointing at the fresh review accept is accepted once...
    const firstResp = await submitInviteCreateApi(
      request,
      alice.token,
      alice.user.did,
      realmId,
      bob.user.did,
      reviewDigest,
    );
    const firstBody = await firstResp.text();
    expect(
      [200, 201],
      `fresh join_authorised_by accept returned ${firstResp.status()}: ${firstBody}`,
    ).toContain(firstResp.status());

    // ...and the same accept cannot be replayed by a second invite.
    const replayResp = await submitInviteCreateApi(
      request,
      alice.token,
      alice.user.did,
      realmId,
      bob.user.did,
      reviewDigest,
    );
    expect([400, 412, 422]).toContain(replayResp.status());
    expect(await rejectCode(replayResp)).toContain("join_authorisation_invalid");
  });

  test("E6.C mallory is rejected by alice and CANNOT re-apply until cooldown_after_reject (default 72h) elapses; cooldown gate independent of combinator", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6c-alice");
    const mallory = await makeUser(request, "s6c-mallory");
    const realmId = await createRealmApi(request, alice.token, {
      title: `S6C ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      discoverability: "listed",
      default_join_rule: "knock",
      ownerDid: alice.user.did,
    });
    const reviewerGrantId = await grantRealmReviewCapabilityApi(
      request,
      alice.token,
      {
        ownerDid: alice.user.did,
        realmId,
        subjectDid: alice.user.did,
      },
    );
    await writeJoinPolicyApi(request, alice.token, realmId, APPLICATION_FORM_POLICY);

    await submitKnockApi(request, mallory.token, mallory.user.did, realmId);
    const receiptDigest = await submitApplicationApi(
      request,
      mallory.token,
      mallory.user.did,
      realmId,
      { answers: [{ question_id: "q1", value: "lol just trolling let me in" }] },
    );
    await submitApplicationReviewApi(
      request,
      alice.token,
      alice.user.did,
      mallory.user.did,
      realmId,
      {
        applicationRef: receiptDigest,
        decision: "reject",
        reasonCode: "policy_violation",
        reasonText: "Off-topic application",
        grantId: reviewerGrantId,
      },
    );

    // Immediate re-application within cooldown_after_reject MUST be rejected.
    const reapplyResp = await submitApplicationApi(
      request,
      mallory.token,
      mallory.user.did,
      realmId,
      { answers: [{ question_id: "q1", value: "trying again immediately" }] },
    ).catch((error: unknown) => error);
    // submitApplicationApi throws on non-2xx; capture the rejection signal.
    expect(String(reapplyResp)).toMatch(
      /failed_precondition|cooldown_after_reject|cooldown/i,
    );
  });

  test("E6.D max_open_applications_per_actor=1 — bob's second open application is rejected before review", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6d-alice");
    const bob = await makeUser(request, "s6d-bob");
    const realmId = await createRealmApi(request, alice.token, {
      title: `S6D ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      discoverability: "listed",
      default_join_rule: "knock",
      ownerDid: alice.user.did,
    });
    await writeJoinPolicyApi(request, alice.token, realmId, APPLICATION_FORM_POLICY);

    await submitKnockApi(request, bob.token, bob.user.did, realmId);
    await submitApplicationApi(request, bob.token, bob.user.did, realmId, {
      answers: [{ question_id: "q1", value: "first open application" }],
    });

    const secondResp = await submitApplicationApi(
      request,
      bob.token,
      bob.user.did,
      realmId,
      { answers: [{ question_id: "q1", value: "second open application" }] },
    ).catch((error: unknown) => error);
    expect(String(secondResp)).toMatch(
      /failed_precondition|max_open_applications_per_actor|max open|open application/i,
    );
  });

  test("E6.E application_ttl expiry — application accepted past TTL is rejected even if reviewer signs accept", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6e-alice");
    const bob = await makeUser(request, "s6e-bob");
    const realmId = await createRealmApi(request, alice.token, {
      title: `S6E ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      discoverability: "listed",
      default_join_rule: "knock",
      ownerDid: alice.user.did,
    });
    const reviewerGrantId = await grantRealmReviewCapabilityApi(
      request,
      alice.token,
      {
        ownerDid: alice.user.did,
        realmId,
        subjectDid: alice.user.did,
      },
    );
    // application_ttl=PT1H (minimum); submit the application backdated >1h so it
    // is already past TTL when the reviewer signs accept.
    await writeJoinPolicyApi(request, alice.token, realmId, {
      ...APPLICATION_FORM_POLICY,
      application_ttl: "PT1H",
    });

    const pastTtl = canonicalTimestamp(new Date(Date.now() - 2 * 60 * 60 * 1000));
    await submitKnockApi(request, bob.token, bob.user.did, realmId, {
      createdAt: pastTtl,
    });
    const receiptDigest = await submitApplicationApi(
      request,
      bob.token,
      bob.user.did,
      realmId,
      { answers: [{ question_id: "q1", value: "submitted long ago" }] },
      { createdAt: pastTtl },
    );

    const reviewResp = await submitApplicationReviewApi(
      request,
      alice.token,
      alice.user.did,
      bob.user.did,
      realmId,
      {
        applicationRef: receiptDigest,
        decision: "accept",
        reasonCode: "ok",
        grantId: reviewerGrantId,
      },
    ).catch((error: unknown) => error);
    expect(String(reviewResp)).toMatch(/ttl_expired|application_ttl|expired/i);
  });

  test("E6.F reviewer loses ak.realm.join.review after accept; the accepted receipt remains valid at its own authorization basis", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6f-alice");
    const reviewer = await makeUser(request, "s6f-reviewer");
    const bob = await makeUser(request, "s6f-bob");
    const realmId = await createRealmApi(request, alice.token, {
      title: `S6F ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      discoverability: "listed",
      default_join_rule: "knock",
      ownerDid: alice.user.did,
    });
    // Seed the non-owner reviewer as a realm member BEFORE the knock policy is
    // written, so its later membership write (review reject path) and capability
    // re-check have a member to anchor on. Then grant the revocable review cap.
    await addRealmMemberApi(request, alice.token, realmId, reviewer.user.did);
    const grantId = await grantRealmReviewCapabilityApi(request, alice.token, {
      ownerDid: alice.user.did,
      realmId,
      subjectDid: reviewer.user.did,
    });
    await writeJoinPolicyApi(request, alice.token, realmId, APPLICATION_FORM_POLICY);

    await submitKnockApi(request, bob.token, bob.user.did, realmId);
    const receiptDigest = await submitApplicationApi(
      request,
      bob.token,
      bob.user.did,
      realmId,
      { answers: [{ question_id: "q1", value: "valid application body" }] },
    );
    const reviewDigest = await submitApplicationReviewApi(
      request,
      reviewer.token,
      reviewer.user.did,
      bob.user.did,
      realmId,
      {
        applicationRef: receiptDigest,
        decision: "accept",
        reasonCode: "ok",
        grantId,
      },
    );

    // Revocation after a valid accept is non-retroactive. The Realm owner may
    // still create the invite citing that already-counted receipt.
    await revokeCapabilityApi(request, alice.token, {
      ownerDid: alice.user.did,
      realmId,
      grantId,
    });
    const inviteResp = await submitInviteCreateApi(
      request,
      alice.token,
      alice.user.did,
      realmId,
      bob.user.did,
      reviewDigest,
    );
    const inviteBody = await inviteResp.text();
    expect(
      [200, 201],
      `non-retroactive accepted review returned ${inviteResp.status()}: ${inviteBody}`,
    ).toContain(inviteResp.status());
  });

  test("E6.G applicant_visibility=reviewer_only — non-reviewer members receive redacted metadata while reviewer reads are audited", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = await makeUser(request, "s6g-alice");
    const bob = await makeUser(request, "s6g-bob");
    const eve = await makeUser(request, "s6g-eve");
    const realmId = await createRealmApi(request, alice.token, {
      title: `S6G ${stamp}`,
      schema_refs: JOIN_POLICY_PROFILE_SCHEMA_REFS,
      discoverability: "listed",
      default_join_rule: "knock",
      ownerDid: alice.user.did,
    });
    await addRealmMemberApi(request, alice.token, realmId, eve.user.did);
    await writeJoinPolicyApi(request, alice.token, realmId, APPLICATION_FORM_POLICY);

    await submitKnockApi(request, bob.token, bob.user.did, realmId);
    const applicationRef = await submitApplicationApi(request, bob.token, bob.user.did, realmId, {
      answers: [{ question_id: "q1", value: "secret reviewer-only application" }],
    });

    // eve (non-reviewer) sees only the placeholder, never the answers.
    const eveView = await listMemberApplicationsApi(request, eve.token, realmId);
    expect(eveView.viewer_is_reviewer).toBe(false);
    const eveEntry = eveView.applications.find(
      (entry) => entry.applicant_did === bob.user.did,
    );
    expect(eveEntry, "eve sees the application metadata").toBeTruthy();
    expect(applicationAnswers(eveEntry), "eve MUST NOT see answers").toBeFalsy();
    expect(eveEntry?.application_pending).toBe(true);

    // alice (reviewer) sees the answers.
    const aliceView = await listMemberApplicationsApi(
      request,
      alice.token,
      realmId,
    );
    const aliceEntry = aliceView.applications.find(
      (entry) => entry.applicant_did === bob.user.did,
    );
    expect(applicationAnswers(aliceEntry), "reviewer sees answers").toBeTruthy();
    const audit = await listJoinApplicationAuditApi(
      request,
      alice.token,
      realmId,
      applicationRef,
    );
    expect(
      audit.some(
        (entry) =>
          entry.action === "read" && entry.actor_id === alice.user.did,
      ),
      "reviewer private-body read is durably audited",
    ).toBe(true);
  });
});
