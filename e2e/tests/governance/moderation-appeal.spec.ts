// Moderation appeal
// Contract: e2e/scenarios/governance/moderation-appeal.md
// Spec refs:
//   - governance/content-moderation.md appeal FSM + separation of duties
//   - models/governance-objects.md moderation decision / appeal event family

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  authHeaders,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import {
  canonicalTimestamp,
  signedEventEnvelope,
  submitSignedEventApi,
  uuidV7,
} from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  openUserPage,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";
import { grantCallCapability } from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("moderation appeal", () => {
  test("appellant submits ck.moderation.appeal.submit against an admin decision", async ({
    request,
  }) => {
    const fixture = await createAppealFixture(request, "submit");
    const appeal = await submitAppeal(request, fixture);

    expect(appeal.state).toBe("submitted");
    const history = await getAppealHistory(request, fixture.reviewerToken, appeal.appeal_id);
    expect(history.map((event) => event.event_kind)).toEqual([
      "ck.moderation.appeal.submit",
    ]);
    expect(history[0]).toMatchObject({
      appeal_id: appeal.appeal_id,
      appeal_state: "submitted",
      appellant: fixture.appellant.did,
      decision_ref: fixture.decisionId,
    });
  });

  test("banned appellant sees Appeal this moderation decision entrypoint in inkson timeline", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const [appellantFlow, reviewerFlow] = await Promise.all([
      openDpopUserPage(browser, request, `appeal-ui-appellant-${stamp}`, {
        prepareMlsDevice: false,
      }),
      openDpopUserPage(browser, request, `appeal-ui-reviewer-${stamp}`, {
        prepareMlsDevice: false,
      }),
    ]);
    if (!appellantFlow || !reviewerFlow) {
      assertJointStackNotRequired("moderation appeal browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const appellant = appellantFlow.user;
    const reviewer = reviewerFlow.user;
    const [appellantToken, reviewerToken] = await Promise.all([
      issueDevSession(request, appellant),
      issueDevSession(request, reviewer),
    ]);
    const realmId = await createSharedRealmViaApi(
      request,
      reviewer,
      reviewerToken,
      appellant,
      appellantToken,
      { title: `appeal ui ${stamp}`, historyVisibility: "world_readable" },
    );
    const decisionNotice = await sendPlaintextMessageViaApi(
      request,
      reviewerToken,
      realmId,
      `Moderation decision: account restricted pending appeal ${stamp}`,
      { actorDid: reviewer.did },
    );
    const targetRef = decisionNotice.event_id.replace(/^ak:event:/, "ak:message:");
    const decision = await issueDecision(
      request,
      reviewerToken,
      realmId,
      targetRef,
      reviewer.did,
    );
    const appellantPage = appellantFlow.page;
    try {
      await appellantPage.gotoTimelineRealm(realmId);
      await expect(appellantPage.page.getByTestId("message-list")).toContainText(
        "Moderation decision",
        { timeout: 120_000 },
      );

      await banMemberViaApi(
        request,
        reviewerToken,
        realmId,
        reviewer.did,
        appellant.did,
      );
      const realmAfterBan = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(reviewerToken) },
      );
      expect(realmAfterBan.ok()).toBeTruthy();
      const body = await realmAfterBan.json();
      expect(body.members ?? []).not.toContain(appellant.did);

      const entrypoint = appellantPage.page.getByTestId("moderation-appeal-entrypoint");
      await expect(entrypoint).toBeVisible({ timeout: 30_000 });
      await expect(entrypoint.getByTestId("moderation-appeal-reason")).toBeVisible();
      const submit = entrypoint.getByTestId("moderation-appeal-submit");
      await expect(submit).toBeDisabled();
      await entrypoint
        .getByTestId("moderation-appeal-reason")
        .fill("The moderation decision misidentified my message.");
      await expect(submit).toBeEnabled();
    } finally {
      await Promise.allSettled([appellantPage.close(), reviewerFlow.page.close()]);
    }
  });

  test("appeal FSM reaches Submitted → UnderReview → Decided → Closed", async ({ request }) => {
    const fixture = await createAppealFixture(request, "fsm");
    const appeal = await submitAppeal(request, fixture);

    await reviewAppeal(request, fixture, appeal.appeal_id);
    await decideAppeal(request, fixture, appeal.appeal_id, {
      verdict: "uphold",
      reason_text_ref: "appeal reviewed; decision upheld",
    });
    await closeAppeal(request, fixture, appeal.appeal_id);

    const history = await getAppealHistory(request, fixture.reviewerToken, appeal.appeal_id);
    expect(history.map((event) => event.appeal_state)).toEqual([
      "submitted",
      "under_review",
      "decided",
      "closed",
    ]);
    expect(history.map((event) => event.event_kind)).toEqual([
      "ck.moderation.appeal.submit",
      "ck.moderation.appeal.review",
      "ck.moderation.appeal.decision",
      "ck.moderation.appeal.close",
    ]);
  });

  test("reviewer cannot be the original moderation decision issuer", async ({ request }) => {
    const fixture = await createAppealFixture(request, "self-review");
    const appeal = await submitAppeal(request, fixture);

    const response = await postModerationEvent(
      request,
      fixture.moderatorToken,
      fixture.moderator.did,
      fixture.realmId,
      "ck.moderation.appeal.review",
      {
        appeal_id: appeal.appeal_id,
        realm_id: fixture.realmId,
        reviewer: fixture.moderator.did,
        reviewed_at: canonicalTimestamp(),
        notes_ref: "self review attempt",
      },
    );
    expect(response.status()).toBe(412);
    expect(await response.text()).toContain("appeal_self_review_forbidden");
  });

  test("duplicate active appeal for the same decision is rejected", async ({ request }) => {
    const fixture = await createAppealFixture(request, "duplicate");
    await submitAppeal(request, fixture);

    const duplicate = await postModerationEvent(
      request,
      fixture.appellantToken,
      fixture.appellant.did,
      fixture.realmId,
      "ck.moderation.appeal.submit",
      appealPayload(fixture),
    );
    expect(duplicate.status()).toBe(412);
    expect(await duplicate.text()).toContain("moderation_appeal_duplicate_active");
  });

  test("appeal decision before review fails the FSM precondition", async ({ request }) => {
    const fixture = await createAppealFixture(request, "decision-before-review");
    const appeal = await submitAppeal(request, fixture);

    const response = await postModerationEvent(
      request,
      fixture.reviewerToken,
      fixture.reviewer.did,
      fixture.realmId,
      "ck.moderation.appeal.decision",
      {
        appeal_id: appeal.appeal_id,
        realm_id: fixture.realmId,
        reviewer: fixture.reviewer.did,
        verdict: "uphold",
        reason_text_ref: "too early",
        decided_at: canonicalTimestamp(),
      },
    );
    expect(response.status()).toBe(412);
    expect(await response.text()).toContain("moderation_appeal_invalid_transition");
  });

  test("appeal close before decision fails the FSM precondition", async ({ request }) => {
    const fixture = await createAppealFixture(request, "close-before-decision");
    const appeal = await submitAppeal(request, fixture);
    await reviewAppeal(request, fixture, appeal.appeal_id);

    const response = await postModerationEvent(
      request,
      fixture.reviewerToken,
      fixture.reviewer.did,
      fixture.realmId,
      "ck.moderation.appeal.close",
      {
        appeal_id: appeal.appeal_id,
        realm_id: fixture.realmId,
        closer: fixture.reviewer.did,
        closed_at: canonicalTimestamp(),
        auto_closed: false,
        close_reason: "reviewer_closed",
      },
    );
    expect(response.status()).toBe(412);
    expect(await response.text()).toContain("moderation_appeal_invalid_transition");
  });

  test("overturn verdict requires an explicit decision lift", async ({ request }) => {
    const fixture = await createAppealFixture(request, "overturn-missing-lift");
    const appeal = await submitAppeal(request, fixture);
    await reviewAppeal(request, fixture, appeal.appeal_id);

    const response = await postModerationEvent(
      request,
      fixture.reviewerToken,
      fixture.reviewer.did,
      fixture.realmId,
      "ck.moderation.appeal.decision",
      {
        appeal_id: appeal.appeal_id,
        realm_id: fixture.realmId,
        reviewer: fixture.reviewer.did,
        verdict: "overturn",
        reason_text_ref: "missing lift",
        decided_at: canonicalTimestamp(),
      },
    );
    expect(response.status()).toBe(412);
    expect(await response.text()).toContain("appeal_overturn_missing_lift");
  });

  test("decision lift lets reviewer overturn and close the appeal", async ({ request }) => {
    const fixture = await createAppealFixture(request, "overturn-with-lift");
    const appeal = await submitAppeal(request, fixture);
    await reviewAppeal(request, fixture, appeal.appeal_id);
    const lift = await liftDecision(request, fixture, appeal.appeal_id);

    await decideAppeal(request, fixture, appeal.appeal_id, {
      verdict: "overturn",
      reason_text_ref: "appeal accepted",
    });
    expect(lift.decision_id).toBe(fixture.decisionId);
    await closeAppeal(request, fixture, appeal.appeal_id);

    const history = await getAppealHistory(request, fixture.reviewerToken, appeal.appeal_id);
    expect(history.at(-2)).toMatchObject({
      appeal_state: "decided",
      verdict: "overturn",
    });
    expect(history.at(-1)).toMatchObject({ appeal_state: "closed" });
  });
});

type AppealFixture = {
  appellant: JointUser;
  moderator: JointUser;
  reviewer: JointUser;
  appellantToken: string;
  moderatorToken: string;
  reviewerToken: string;
  realmId: string;
  targetRef: string;
  decisionId: string;
};

async function createAppealFixture(
  request: APIRequestContext,
  label: string,
): Promise<AppealFixture> {
  const stamp = Date.now();
  const appellant = uniqueUser(`${label}-appellant`);
  const moderator = uniqueUser(`${label}-moderator`);
  const reviewer = uniqueUser(`${label}-reviewer`);
  await Promise.all([
    ensureRegistered(request, appellant),
    ensureRegistered(request, moderator),
    ensureRegistered(request, reviewer),
  ]);
  const [appellantToken, moderatorToken, reviewerToken] = await Promise.all([
    issueDevSession(request, appellant),
    issueDevSession(request, moderator),
    issueDevSession(request, reviewer),
  ]);
  const realmId = await createSharedRealmViaApi(
    request,
    moderator,
    moderatorToken,
    appellant,
    appellantToken,
    { title: `appeal ${label} ${stamp}`, historyVisibility: "shared" },
  );
  await submitSignedEventApi(
    request,
    moderatorToken,
    signedEventEnvelope({
      actorDid: moderator.did,
      realmId,
      kind: "ck.member.state",
      payload: {
        realm_id: realmId,
        actor_id: reviewer.did,
        membership: "join",
        delivery_status: "unroutable",
      },
    }),
    { context: `join ${reviewer.did}` },
  );
  await grantCallCapability(
    request,
    moderatorToken,
    moderator.did,
    realmId,
    reviewer.did,
    "ck.moderation.appeal.review",
  );
  await grantCallCapability(
    request,
    moderatorToken,
    moderator.did,
    realmId,
    reviewer.did,
    "ck.moderation.decision.lift",
  );
  const message = await sendPlaintextMessageViaApi(
    request,
    appellantToken,
    realmId,
    `appeal target ${label} ${stamp}`,
    { actorDid: appellant.did },
  );
  const targetRef = message.event_id.replace(/^ak:event:/, "ak:message:");
  const decision = await issueDecision(
    request,
    moderatorToken,
    realmId,
    targetRef,
    moderator.did,
  );
  return {
    appellant,
    moderator,
    reviewer,
    appellantToken,
    moderatorToken,
    reviewerToken,
    realmId,
    targetRef,
    decisionId: decision.decision_id,
  };
}

async function issueDecision(
  request: APIRequestContext,
  token: string,
  realmId: string,
  targetRef: string,
  actorDid: string,
) {
  const envelope = signedModerationEvent(actorDid, realmId, "ck.moderation.decision", {
    target_ref: targetRef,
    decision: "quarantine",
    action: "quarantine_message",
    issuer: actorDid,
    reason_code: "abuse_review",
    reason: "moderation decision rationale",
    request_canonical_digest:
      "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  });
  await submitSignedEventApi(request, token, envelope, {
    context: `submit moderation decision for ${targetRef}`,
  });
  return { decision_id: String(envelope.event_id) };
}

async function banMemberViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  actorDid: string,
  memberDid: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      payload: {
        realm_id: realmId,
        actor_id: memberDid,
        membership: "ban",
        reason: "moderation_decision",
      },
    }),
    { context: `ban ${memberDid} from ${realmId}` },
  );
}

function appealPayload(fixture: AppealFixture) {
  return {
    appeal_id: `ak:appeal:${uuidV7()}`,
    realm_id: fixture.realmId,
    decision_ref: fixture.decisionId,
    target_ref: fixture.targetRef,
    appellant: fixture.appellant.did,
    reason_text_ref: "appeal narrative",
    evidence_refs: [`ak:evidence:${fixture.decisionId}`],
    evidence_visibility: "reviewers_only",
    created_at: canonicalTimestamp(),
  };
}

async function submitAppeal(request: APIRequestContext, fixture: AppealFixture) {
  const payload = appealPayload(fixture);
  const envelope = signedModerationEvent(
    fixture.appellant.did,
    fixture.realmId,
    "ck.moderation.appeal.submit",
    payload,
  );
  await submitSignedEventApi(request, fixture.appellantToken, envelope, {
    context: `submit appeal ${payload.appeal_id}`,
  });
  return {
    appeal_id: String(payload.appeal_id),
    event_id: String(envelope.event_id),
    state: "submitted",
  };
}

async function reviewAppeal(
  request: APIRequestContext,
  fixture: AppealFixture,
  appealId: string,
) {
  return await submitModerationEvent(
    request,
    fixture.reviewerToken,
    fixture.reviewer.did,
    fixture.realmId,
    "ck.moderation.appeal.review",
    {
      appeal_id: appealId,
      realm_id: fixture.realmId,
      reviewer: fixture.reviewer.did,
      reviewed_at: canonicalTimestamp(),
      notes_ref: "review notes",
    },
  );
}

async function decideAppeal(
  request: APIRequestContext,
  fixture: AppealFixture,
  appealId: string,
  data: Record<string, unknown>,
) {
  return await submitModerationEvent(
    request,
    fixture.reviewerToken,
    fixture.reviewer.did,
    fixture.realmId,
    "ck.moderation.appeal.decision",
    {
      appeal_id: appealId,
      realm_id: fixture.realmId,
      reviewer: fixture.reviewer.did,
      ...data,
      decided_at: data.decided_at ?? canonicalTimestamp(),
    },
  );
}

async function closeAppeal(
  request: APIRequestContext,
  fixture: AppealFixture,
  appealId: string,
) {
  return await submitModerationEvent(
    request,
    fixture.reviewerToken,
    fixture.reviewer.did,
    fixture.realmId,
    "ck.moderation.appeal.close",
    {
      appeal_id: appealId,
      realm_id: fixture.realmId,
      closer: fixture.reviewer.did,
      closed_at: canonicalTimestamp(),
      auto_closed: false,
      close_reason: "reviewer_closed",
    },
  );
}

async function liftDecision(
  request: APIRequestContext,
  fixture: AppealFixture,
  appealId: string,
) {
  const envelope = signedModerationEvent(
    fixture.reviewer.did,
    fixture.realmId,
    "ck.moderation.decision.lift",
    {
      target_ref: fixture.targetRef,
      decision_ref: fixture.decisionId,
      reason_code: "policy_recall",
      reason: `appeal accepted ${appealId}`,
      effective_at: canonicalTimestamp(),
    },
  );
  await submitSignedEventApi(request, fixture.reviewerToken, envelope, {
    context: `lift moderation decision ${fixture.decisionId}`,
  });
  const events = await listRealmEventsViaApi(
    request,
    fixture.reviewerToken,
    fixture.realmId,
    { limit: 200 },
  );
  const projected = events.find(
    (event) =>
      event.event_id === envelope.event_id ||
      event.id === envelope.event_id ||
      event.event_ref === envelope.event_id,
  );
  expect(projected, `projected decision lift ${String(envelope.event_id)}`).toBeTruthy();
  const payload = isRecord(projected?.payload) ? projected.payload : {};
  const decisionRef = payload.decision_ref;
  expect(decisionRef, `decision lift payload in ${JSON.stringify(projected)}`).toBe(
    fixture.decisionId,
  );
  return { decision_id: String(decisionRef), event_id: String(envelope.event_id) };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function signedModerationEvent(
  actorDid: string,
  realmId: string,
  kind: string,
  payload: Record<string, unknown>,
) {
  return signedEventEnvelope({
    actorDid,
    realmId,
    kind,
    schemaId: kind.startsWith("ck.moderation.appeal.")
      ? "ck.schema.moderation_appeal.v1"
      : "ck.schema.event_payload.v1",
    payload,
  });
}

async function submitModerationEvent(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  kind: string,
  payload: Record<string, unknown>,
) {
  const envelope = signedModerationEvent(actorDid, realmId, kind, payload);
  await submitSignedEventApi(request, token, envelope, {
    context: `submit ${kind}`,
  });
  return { event_id: String(envelope.event_id) };
}

async function postModerationEvent(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  kind: string,
  payload: Record<string, unknown>,
) {
  return await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: signedModerationEvent(actorDid, realmId, kind, payload),
  });
}

async function getAppealHistory(request: APIRequestContext, token: string, appealId: string) {
  const response = await request.get(
    `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(appealId)}`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  const body = JSON.parse(text) as { history: Array<Record<string, unknown>> };
  return body.history;
}

