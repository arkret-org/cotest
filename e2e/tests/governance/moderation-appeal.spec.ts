// Moderation appeal
// Contract: e2e/scenarios/governance/moderation-appeal.md
// Spec refs:
//   - governance/content-moderation.md appeal FSM + separation of duties
//   - models/governance-objects.md moderation decision / appeal event family

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  authHeaders,
  createSharedRealmViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import { signedEventEnvelope, submitSignedEventApi } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  type JointUser,
  uniqueUser,
} from "../../helpers/users";

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

  test("banned appellant sees Appeal this moderation decision entrypoint in yougen timeline", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const appellant = uniqueUser("appeal-ui-appellant");
    const reviewer = uniqueUser("appeal-ui-reviewer");
    await Promise.all([
      ensureRegistered(request, appellant),
      ensureRegistered(request, reviewer),
    ]);
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
    const targetRef = decisionNotice.event_id.replace(/^ck:event:/, "ck:message:");
    const decision = await issueDecision(request, reviewerToken, realmId, targetRef);

    const appellantPage = await openUserPage(browser, appellant, { sessionToken: appellantToken });
    try {
      await appellantPage.gotoTimelineRealm(realmId);
      await expect(appellantPage.page.getByTestId("timeline")).toContainText(
        "Moderation decision",
        { timeout: 120_000 },
      );

      await banMemberViaApi(
        request,
        reviewerToken,
        realmId,
        reviewer.did,
        appellant.did,
        decision.decision_id,
      );
      const realmAfterBan = await request.get(
        `${solandBaseUrl()}/_soland/self/realms/${encodeURIComponent(realmId)}`,
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
      await appellantPage.close();
    }
  });

  test("appeal FSM reaches Submitted → UnderReview → Decided → Closed", async ({ request }) => {
    const fixture = await createAppealFixture(request, "fsm");
    const appeal = await submitAppeal(request, fixture);

    await reviewAppeal(request, fixture.reviewerToken, appeal.appeal_id);
    await decideAppeal(request, fixture.reviewerToken, appeal.appeal_id, {
      verdict: "uphold",
      reason_text_ref: "appeal reviewed; decision upheld",
    });
    await closeAppeal(request, fixture.reviewerToken, appeal.appeal_id);

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

    const response = await request.post(
      `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(
        appeal.appeal_id,
      )}/review`,
      {
        headers: authHeaders(fixture.moderatorToken),
        data: { notes_ref: "self review attempt" },
      },
    );
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(await response.text()).toContain("separation of duties");
  });

  test("duplicate active appeal for the same decision is rejected", async ({ request }) => {
    const fixture = await createAppealFixture(request, "duplicate");
    await submitAppeal(request, fixture);

    const duplicate = await request.post(`${solandBaseUrl()}/_cokret/self/moderation/appeal`, {
      headers: authHeaders(fixture.appellantToken),
      data: appealPayload(fixture),
    });
    expect(duplicate.status()).toBe(409);
    expect(await duplicate.text()).toContain("active appeal already exists");
  });

  test("appeal decision before review fails the FSM precondition", async ({ request }) => {
    const fixture = await createAppealFixture(request, "decision-before-review");
    const appeal = await submitAppeal(request, fixture);

    const response = await request.post(
      `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(
        appeal.appeal_id,
      )}/decision`,
      {
        headers: authHeaders(fixture.reviewerToken),
        data: { verdict: "uphold", reason_text_ref: "too early" },
      },
    );
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(await response.text()).toContain("cannot transition");
  });

  test("appeal close before decision fails the FSM precondition", async ({ request }) => {
    const fixture = await createAppealFixture(request, "close-before-decision");
    const appeal = await submitAppeal(request, fixture);
    await reviewAppeal(request, fixture.reviewerToken, appeal.appeal_id);

    const response = await request.post(
      `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(
        appeal.appeal_id,
      )}/close`,
      {
        headers: authHeaders(fixture.reviewerToken),
        data: { auto_closed: false },
      },
    );
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(await response.text()).toContain("cannot transition");
  });

  test("overturn verdict requires an explicit decision lift", async ({ request }) => {
    const fixture = await createAppealFixture(request, "overturn-missing-lift");
    const appeal = await submitAppeal(request, fixture);
    await reviewAppeal(request, fixture.reviewerToken, appeal.appeal_id);

    const response = await request.post(
      `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(
        appeal.appeal_id,
      )}/decision`,
      {
        headers: authHeaders(fixture.reviewerToken),
        data: { verdict: "overturn", reason_text_ref: "missing lift" },
      },
    );
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(await response.text()).toContain("decision_lift_ref");
  });

  test("decision lift lets reviewer overturn and close the appeal", async ({ request }) => {
    const fixture = await createAppealFixture(request, "overturn-with-lift");
    const appeal = await submitAppeal(request, fixture);
    await reviewAppeal(request, fixture.reviewerToken, appeal.appeal_id);
    const lift = await liftDecision(request, fixture.reviewerToken, fixture.decisionId, appeal.appeal_id);

    await decideAppeal(request, fixture.reviewerToken, appeal.appeal_id, {
      verdict: "overturn",
      reason_text_ref: "appeal accepted",
      decision_lift_ref: String(lift.decision_id ?? fixture.decisionId),
    });
    await closeAppeal(request, fixture.reviewerToken, appeal.appeal_id);

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
    appellant,
    appellantToken,
    reviewer,
    reviewerToken,
    { title: `appeal ${label} ${stamp}`, historyVisibility: "shared" },
  );
  const message = await sendPlaintextMessageViaApi(
    request,
    appellantToken,
    realmId,
    `appeal target ${label} ${stamp}`,
    { actorDid: appellant.did },
  );
  const targetRef = message.event_id.replace(/^ck:event:/, "ck:message:");
  const decision = await issueDecision(request, moderatorToken, realmId, targetRef);
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
) {
  const response = await request.post(`${solandBaseUrl()}/_soland/admin/moderation/decision`, {
    headers: authHeaders(token),
    data: {
      target_ref: targetRef,
      realm_id: realmId,
      action: "ban",
      reason_text_ref: "moderation decision rationale",
    },
  });
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as { decision_id: string };
}

async function banMemberViaApi(
  request: APIRequestContext,
  token: string,
  realmId: string,
  actorDid: string,
  memberDid: string,
  decisionRef: string,
) {
  await submitSignedEventApi(
    request,
    token,
    signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ck.member.state",
      payload: {
        actor_id: memberDid,
        member: memberDid,
        membership: "ban",
        reason: "moderation_decision",
        decision_ref: decisionRef,
      },
    }),
    { context: `ban ${memberDid} from ${realmId}` },
  );
}

function appealPayload(fixture: AppealFixture) {
  return {
    decision_ref: fixture.decisionId,
    target_ref: fixture.targetRef,
    realm_id: fixture.realmId,
    reason_text_ref: "appeal narrative",
    evidence_refs: [`ck:evidence:${fixture.decisionId}`],
  };
}

async function submitAppeal(request: APIRequestContext, fixture: AppealFixture) {
  const response = await request.post(`${solandBaseUrl()}/_cokret/self/moderation/appeal`, {
    headers: authHeaders(fixture.appellantToken),
    data: appealPayload(fixture),
  });
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as { appeal_id: string; state: string };
}

async function reviewAppeal(request: APIRequestContext, token: string, appealId: string) {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(appealId)}/review`,
    { headers: authHeaders(token), data: { notes_ref: "review notes" } },
  );
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as Record<string, unknown>;
}

async function decideAppeal(
  request: APIRequestContext,
  token: string,
  appealId: string,
  data: Record<string, unknown>,
) {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(appealId)}/decision`,
    { headers: authHeaders(token), data },
  );
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as Record<string, unknown>;
}

async function closeAppeal(request: APIRequestContext, token: string, appealId: string) {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(appealId)}/close`,
    { headers: authHeaders(token), data: { auto_closed: false } },
  );
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as Record<string, unknown>;
}

async function liftDecision(
  request: APIRequestContext,
  token: string,
  decisionId: string,
  appealId: string,
) {
  const response = await request.post(
    `${solandBaseUrl()}/_soland/admin/moderation/decision/${encodeURIComponent(decisionId)}/lift`,
    {
      headers: authHeaders(token),
      data: {
        reason_text_ref: "appeal accepted",
        appeal_ref: appealId,
      },
    },
  );
  const text = await response.text();
  expect(response.status(), text).toBe(200);
  return JSON.parse(text) as Record<string, unknown>;
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
