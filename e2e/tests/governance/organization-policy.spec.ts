// Organization directory + moderation policy inheritance
// Contract: e2e/scenarios/governance/organization-policy.md
// Spec: governance/content-moderation.md §7, identity/identity-did.md §6, models/governance-objects.md §3

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  signedEventEnvelope,
  submitSignedEventApi,
  uuidV7,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";
import { grantCallCapability } from "../../helpers/webrtc";

test.describe.configure({ mode: "serial" });

test.describe("organization policy inheritance", () => {
  test("organization policy endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s30-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const probe = await request.get(`${solandBaseUrl()}/_soland/self/organizations`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect([200, 401, 403, 404]).toContain(probe.status());
    expect(probe.status()).toBeLessThan(500);
  });

  test(
    "acme-org publishes ck.organization.moderation_policy with deny_join targets; Realms under acme inherit the policy automatically",
    async ({ request }) => {
      const { alice, mallory, aliceToken, orgDid } = await setupAcmeOrg(request, "s30-inherit");
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 inherited policy ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const policy = await request.get(
        `${solandBaseUrl()}/_soland/self/organizations/${encodeURIComponent(orgDid)}/policy`,
        { headers: authHeaders(aliceToken) },
      );
      expect(policy.ok()).toBeTruthy();
      const policyBody = await policy.json();
      expect(policyBody.policy.targets[0].did).toBe(mallory.did);
      expect(policyBody.applies_to_realms).toContain(realmId);

      const effective = await request.get(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/effective-policy`,
        { headers: authHeaders(aliceToken) },
      );
      expect(effective.ok()).toBeTruthy();
      const effectiveText = JSON.stringify(await effective.json());
      expect(effectiveText).toContain(orgDid);
      expect(effectiveText).toContain("deny_join");
      expect(effectiveText).toContain(mallory.did);
    },
  );

  test(
    "mallory's join attempt on an Acme Realm is rejected with organization_policy_denied; Realm-level override requires organization approval",
    async ({ request }) => {
      const { alice, mallory, aliceToken, orgDid } = await setupAcmeOrg(request, "s30-deny");
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 deny join ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const deniedJoin = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.member.state",
          payload: {
            realm_id: realmId,
            actor_id: mallory.did,
            membership: "join",
            delivery_status: "unroutable",
          },
        }),
      });
      expect(deniedJoin.status()).toBe(403);
      expect(JSON.stringify(await deniedJoin.json())).toContain("organization_policy_denied");

      const noApproval = await request.put(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/moderation-policy`,
        {
          headers: authHeaders(aliceToken),
          data: {
            allow_override: [{ target: mallory.did, action: "allow_join" }],
          },
        },
      );
      expect(noApproval.status()).toBe(403);
      expect(wireErrCode(await noApproval.json())).toBe("requires_organization_approval");

      const withApproval = await request.put(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/moderation-policy`,
        {
          headers: authHeaders(aliceToken),
          data: {
            allow_override: [{ target: mallory.did, action: "allow_join" }],
            organization_approval: {
              organization_id: orgDid,
              approved: true,
              decision_id: `ck:org-approval:${Date.now()}`,
            },
          },
        },
      );
      expect(withApproval.ok()).toBeTruthy();

      await addRealmMemberApi(request, aliceToken, realmId, mallory.did);
      const realm = await request.get(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(aliceToken) },
      );
      expect(realm.ok()).toBeTruthy();
      expect((await realm.json()).members ?? []).toContain(mallory.did);
    },
  );

  test(
    "policy update at organization level fans out to all member Realms without per-Realm rewrites",
    async ({ request }) => {
      const { aliceToken, orgDid } = await setupAcmeOrg(request, "s30-fanout");
      const first = await createRealmApi(request, aliceToken, {
        title: `S30 fanout one ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });
      const second = await createRealmApi(request, aliceToken, {
        title: `S30 fanout two ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const update = await request.post(
        `${solandBaseUrl()}/_soland/self/organizations/${encodeURIComponent(orgDid)}/policy`,
        {
          headers: authHeaders(aliceToken),
          data: {
            policy_id: `ck:org-policy:fanout-${Date.now()}`,
            targets: [
              {
                kind: "actor",
                did: "did:web:later-denied.example",
                action: "deny_join",
              },
            ],
          },
        },
      );
      expect(update.ok()).toBeTruthy();

      for (const realmId of [first, second]) {
        const effective = await request.get(
          `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/effective-policy`,
          { headers: authHeaders(aliceToken) },
        );
        expect(effective.ok()).toBeTruthy();
        const body = await effective.json();
        expect(JSON.stringify(body)).toContain("did:web:later-denied.example");
        const organizationPolicyLayers = body.effective_policy?.organization_policy_layers ?? [];
        expect(organizationPolicyLayers[0]?.version).toBe(2);
        expect(organizationPolicyLayers[0]?.applies_to_realms).toEqual(
          expect.arrayContaining([first, second]),
        );
        expect(body.effective_policy?.organization_policy_fanout?.rewrites_realm_policy).toBe(false);
      }
    },
  );

  test(
    "tab-organizations search returns acme-org with member count and verified badge",
    async ({ browser, request }) => {
      // spec: discovery-directory.md §2
      const label = `s30-dir-${Date.now()}`;
      const { alice, aliceToken, orgDid } = await setupAcmeOrg(request, label);
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 org directory ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const apiSearch = await request.post(`${solandBaseUrl()}/_cokret/find/directory/search-organizations`, {
        headers: authHeaders(aliceToken),
        data: { query: orgDid },
      });
      expect(apiSearch.ok()).toBeTruthy();
      const searchBody = await apiSearch.json();
      const apiEnvelope = searchBody.organizations?.find(
        (row: { organization_did?: string; preview?: { organization_id?: string; organization_did?: string } }) =>
          row.organization_did === orgDid ||
          row.preview?.organization_id === orgDid ||
          row.preview?.organization_did === orgDid,
      );
      const apiRow = apiEnvelope?.preview ?? apiEnvelope;
      expect(apiRow, "search-organizations should return the runtime Acme organization").toBeTruthy();
      expect(apiRow.verified_badge ?? apiRow.verified).toBe(true);
      expect(apiRow.member_count).toBe(2);
      expect(apiRow.realms).toEqual(expect.arrayContaining([realmId]));
      expect(apiRow.realm_count).toBeGreaterThanOrEqual(1);

      const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });
      try {
        await alicePage.gotoDirectory();
        await alicePage.page.getByTestId("tab-organizations").click();
        await alicePage.page.getByTestId("directory-search-input").fill(orgDid);
        await alicePage.page.getByTestId("directory-search-button").click();

        const row = alicePage.page.getByTestId("org-result").filter({ hasText: `Acme ${label}` }).first();
        await expect(row).toBeVisible({ timeout: 30_000 });
        await expect(row.getByTestId("organization-verified-badge")).toBeVisible();
        await expect(row.getByTestId("organization-member-count")).toContainText("2 member");
        await expect(row.getByTestId("organization-policy-hint")).toContainText("Policy inheritance: active");
        await expect(row.getByTestId("organization-policy-hint")).toContainText("1 realm");
      } finally {
        await alicePage.close();
      }
    },
  );

  test(
    "E30.1 cross-org space joining most-restrictive of the two organizations' policies",
    async ({ request }) => {
      // spec: content-moderation.md §7 — a Realm naming two owning
      // organizations merges their policy layers most-restrictively: a join is
      // denied if EITHER organization denies it, and a Realm override of an
      // organization deny requires approval from the organization that denies
      // the target (an unrelated org's approval does not suffice).
      const acme = await setupAcmeOrg(request, "s30-cross-acme");
      const globex = await setupGlobexOrg(request, "s30-cross-globex");

      // A Realm co-owned by both organizations.
      const realmId = await createRealmApi(request, acme.aliceToken, {
        title: `S30 cross-org ${Date.now()}`,
        public: true,
        owning_organizations: [acme.orgDid, globex.orgDid],
      });

      const effective = await request.get(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/effective-policy`,
        { headers: authHeaders(acme.aliceToken) },
      );
      expect(effective.ok()).toBeTruthy();
      const body = await effective.json();
      const layers = body.effective_policy?.organization_policy_layers ?? [];
      const layerOrgIds = layers.map(
        (layer: { organization_id?: string }) => layer.organization_id,
      );
      expect(layerOrgIds).toEqual(expect.arrayContaining([acme.orgDid, globex.orgDid]));
      expect(body.effective_policy?.organization_policy_merge_strategy).toBe(
        "most_restrictive",
      );
      const effectiveText = JSON.stringify(body);
      expect(effectiveText).toContain(acme.mallory.did);
      expect(effectiveText).toContain(globex.mallory.did);

      // mallory is denied by acme only; globex's mallory is denied by globex
      // only. The most-restrictive merge denies BOTH on this co-owned Realm.
      for (const denied of [acme.mallory.did, globex.mallory.did]) {
        const deniedJoin = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
          headers: authHeaders(acme.aliceToken),
          data: signedEventEnvelope({
            actorDid: acme.alice.did,
            realmId,
            kind: "ck.member.state",
            payload: {
              realm_id: realmId,
              actor_id: denied,
              membership: "join",
              delivery_status: "unroutable",
            },
          }),
        });
        expect(deniedJoin.status()).toBe(403);
        expect(JSON.stringify(await deniedJoin.json())).toContain("organization_policy_denied");
      }

      // An actor denied by neither organization joins without an override.
      const allowed = uniqueUser("s30-cross-allowed");
      await ensureRegistered(request, allowed);
      await addRealmMemberApi(request, acme.aliceToken, realmId, allowed.did);

      // Override of acme's deny: approval from globex (which does NOT deny
      // acme.mallory) is insufficient — the denying organization must approve.
      const wrongApproval = await request.put(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/moderation-policy`,
        {
          headers: authHeaders(acme.aliceToken),
          data: {
            allow_override: [{ target: acme.mallory.did, action: "allow_join" }],
            organization_approval: {
              organization_id: globex.orgDid,
              approved: true,
              decision_id: `ck:org-approval:wrong-${Date.now()}`,
            },
          },
        },
      );
      expect(wrongApproval.status()).toBe(403);
      expect(wireErrCode(await wrongApproval.json())).toBe("requires_organization_approval");

      // Approval from acme (the denying organization) satisfies the gate.
      const rightApproval = await request.put(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/moderation-policy`,
        {
          headers: authHeaders(acme.aliceToken),
          data: {
            allow_override: [{ target: acme.mallory.did, action: "allow_join" }],
            organization_approval: {
              organization_id: acme.orgDid,
              approved: true,
              decision_id: `ck:org-approval:right-${Date.now()}`,
            },
          },
        },
      );
      expect(rightApproval.ok()).toBeTruthy();

      await addRealmMemberApi(request, acme.aliceToken, realmId, acme.mallory.did);
      const realm = await request.get(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(acme.aliceToken) },
      );
      expect(realm.ok()).toBeTruthy();
      expect((await realm.json()).members ?? []).toContain(acme.mallory.did);
    },
  );

  test(
    "appeal strand: mallory submits appeal via policy.appeal.endpoint; moderator reviews; possible override",
    async ({ request }) => {
      // spec: content-moderation.md §5.5 / §5.5.4 — the organization policy's
      // appeal.endpoint (`/_cokret/self/events`, set in setupAcmeOrg) is the
      // wire submit path for the binding `ck.moderation.appeal.*` chain. mallory
      // is denied by the organization policy; a moderator records the denial as
      // a `ck.moderation.decision`, mallory appeals through the endpoint, a
      // distinct reviewer reviews, lifts the decision and overturns, after which
      // a Realm override (with the organization's approval) admits her.
      const stamp = Date.now();
      const { alice, mallory, bob, aliceToken, orgDid } = await setupAcmeOrg(
        request,
        "s30-appeal",
      );
      const [bobToken, malloryToken] = await Promise.all([
        issueDevSession(request, bob),
        issueDevSession(request, mallory),
      ]);
      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 appeal ${stamp}`,
        public: true,
        owning_organizations: [orgDid],
      });

      // The organization policy advertises its appeal endpoint; assert it is the
      // canonical self events path the binding chain submits to.
      const policy = await request.get(
        `${solandBaseUrl()}/_soland/self/organizations/${encodeURIComponent(orgDid)}/policy`,
        { headers: authHeaders(aliceToken) },
      );
      expect(policy.ok()).toBeTruthy();
      const policyBody = await policy.json();
      expect(policyBody.policy.appeal.enabled).toBe(true);
      expect(policyBody.policy.appeal.endpoint).toBe("/_cokret/self/events");

      // bob joins as the (distinct) appeal reviewer and is granted review + lift
      // capabilities. Separation of duties forbids the decision issuer (alice)
      // from reviewing.
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.member.state",
          payload: {
            realm_id: realmId,
            actor_id: bob.did,
            membership: "join",
            delivery_status: "unroutable",
          },
        }),
        { context: `join reviewer ${bob.did}` },
      );
      await grantCallCapability(
        request,
        aliceToken,
        alice.did,
        realmId,
        bob.did,
        "ck.moderation.appeal.review",
      );
      await grantCallCapability(
        request,
        aliceToken,
        alice.did,
        realmId,
        bob.did,
        "ck.moderation.decision.lift",
      );
      // mallory is the affected target but not a Realm member (she was denied),
      // so she needs an explicit appeal.submit grant per §5.5.1 (non-member
      // advocate / appellant authorization).
      await grantCallCapability(
        request,
        aliceToken,
        alice.did,
        realmId,
        mallory.did,
        "ck.moderation.appeal.submit",
      );

      // mallory is denied join by the inherited organization policy.
      const deniedJoin = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId,
          kind: "ck.member.state",
          payload: {
            realm_id: realmId,
            actor_id: mallory.did,
            membership: "join",
            delivery_status: "unroutable",
          },
        }),
      });
      expect(deniedJoin.status()).toBe(403);
      expect(JSON.stringify(await deniedJoin.json())).toContain("organization_policy_denied");

      // A moderator records the organization-policy denial as a sealed
      // moderation decision so the appeal chain has a decision_ref to target.
      const targetRef = `ck:member:${realmId}:${mallory.did}`;
      const decisionEnvelope = signedModerationEvent(
        alice.did,
        realmId,
        "ck.moderation.decision",
        {
          target_ref: targetRef,
          decision: "hard_deny",
          action: "deny_join",
          issuer: alice.did,
          reason_code: "organization_policy_denied",
          reason: "organization policy denies join",
          request_canonical_digest:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        },
      );
      await submitSignedEventApi(request, aliceToken, decisionEnvelope, {
        context: `record organization deny decision for ${mallory.did}`,
      });
      const decisionId = String(decisionEnvelope.event_id);

      // mallory submits the appeal via the organization policy's appeal.endpoint
      // (the canonical self events path).
      const appealId = `ck:appeal:${uuidV7()}`;
      await submitSignedEventApi(
        request,
        malloryToken,
        signedModerationEvent(mallory.did, realmId, "ck.moderation.appeal.submit", {
          appeal_id: appealId,
          realm_id: realmId,
          decision_ref: decisionId,
          target_ref: targetRef,
          appellant: mallory.did,
          reason_text_ref: "I should be allowed to join",
          evidence_refs: [`ck:evidence:${decisionId}`],
          evidence_visibility: "reviewers_only",
          created_at: canonicalTimestamp(),
        }),
        { context: `submit appeal ${appealId}` },
      );

      // bob (reviewer ≠ issuer) moves the appeal under review.
      await submitSignedEventApi(
        request,
        bobToken,
        signedModerationEvent(bob.did, realmId, "ck.moderation.appeal.review", {
          appeal_id: appealId,
          realm_id: realmId,
          reviewer: bob.did,
          reviewed_at: canonicalTimestamp(),
          notes_ref: "reviewing organization-policy appeal",
        }),
        { context: `review appeal ${appealId}` },
      );

      // The reviewer lifts the decision (overturn requires an explicit lift) and
      // decides overturn in the same control transaction.
      await submitSignedEventApi(
        request,
        bobToken,
        signedModerationEvent(bob.did, realmId, "ck.moderation.decision.lift", {
          target_ref: targetRef,
          decision_ref: decisionId,
          reason_code: "policy_recall",
          reason: `appeal accepted ${appealId}`,
          effective_at: canonicalTimestamp(),
        }),
        { context: `lift decision ${decisionId}` },
      );
      await submitSignedEventApi(
        request,
        bobToken,
        signedModerationEvent(bob.did, realmId, "ck.moderation.appeal.decision", {
          appeal_id: appealId,
          realm_id: realmId,
          reviewer: bob.did,
          verdict: "overturn",
          reason_text_ref: "organization-policy appeal upheld",
          decided_at: canonicalTimestamp(),
        }),
        { context: `decide appeal ${appealId}` },
      );
      await submitSignedEventApi(
        request,
        bobToken,
        signedModerationEvent(bob.did, realmId, "ck.moderation.appeal.close", {
          appeal_id: appealId,
          realm_id: realmId,
          closer: bob.did,
          closed_at: canonicalTimestamp(),
          auto_closed: false,
          close_reason: "reviewer_closed",
        }),
        { context: `close appeal ${appealId}` },
      );

      const history = await request.get(
        `${solandBaseUrl()}/_soland/admin/moderation/appeals/${encodeURIComponent(appealId)}`,
        { headers: authHeaders(bobToken) },
      );
      expect(history.ok()).toBeTruthy();
      const historyBody = await history.json();
      expect(
        historyBody.history.map((event: { appeal_state?: string }) => event.appeal_state),
      ).toEqual(["submitted", "under_review", "decided", "closed"]);
      expect(
        historyBody.history.map((event: { event_kind?: string }) => event.event_kind),
      ).toEqual([
        "ck.moderation.appeal.submit",
        "ck.moderation.appeal.review",
        "ck.moderation.appeal.decision",
        "ck.moderation.appeal.close",
      ]);
      const decided = historyBody.history.find(
        (event: { appeal_state?: string }) => event.appeal_state === "decided",
      );
      expect(decided).toMatchObject({ verdict: "overturn" });

      // The overturn enables the Realm override (with the organization's
      // approval) that finally admits mallory.
      const override = await request.put(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}/moderation-policy`,
        {
          headers: authHeaders(aliceToken),
          data: {
            allow_override: [{ target: mallory.did, action: "allow_join" }],
            organization_approval: {
              organization_id: orgDid,
              approved: true,
              decision_id: `ck:org-approval:appeal-${stamp}`,
            },
          },
        },
      );
      expect(override.ok()).toBeTruthy();

      await addRealmMemberApi(request, aliceToken, realmId, mallory.did);
      const realm = await request.get(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(aliceToken) },
      );
      expect(realm.ok()).toBeTruthy();
      expect((await realm.json()).members ?? []).toContain(mallory.did);
    },
  );
});

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

async function setupGlobexOrg(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice`);
  const mallory = uniqueUser(`${label}-mallory`);
  const orgDid = `did:web:globex-${label}-${stamp}.example`;
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, mallory),
  ]);
  const aliceToken = await issueDevSession(request, alice);

  const org = await request.post(`${solandBaseUrl()}/_soland/self/organizations`, {
    headers: authHeaders(aliceToken),
    data: {
      organization_did: orgDid,
      display_name: `Globex ${label}`,
      handle: `@globex-${label}`,
      verified: true,
      members: [alice.did],
      member_count: 1,
    },
  });
  expect(org.ok()).toBeTruthy();

  const policy = await request.post(
    `${solandBaseUrl()}/_soland/self/organizations/${encodeURIComponent(orgDid)}/policy`,
    {
      headers: authHeaders(aliceToken),
      data: {
        policy_id: `ck:org-policy:${label}-${stamp}`,
        targets: [{ kind: "actor", did: mallory.did, action: "deny_join" }],
        appeal: { enabled: true, endpoint: "/_cokret/self/events" },
      },
    },
  );
  expect(policy.ok(), `globex policy ${policy.status()}: ${await policy.text()}`).toBeTruthy();

  return { alice, mallory, aliceToken, orgDid };
}

async function setupAcmeOrg(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice`);
  const mallory = uniqueUser(`${label}-mallory`);
  const bob = uniqueUser(`${label}-bob`);
  const orgDid = `did:web:acme-${label}-${stamp}.example`;
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, mallory),
    ensureRegistered(request, bob),
  ]);
  const aliceToken = await issueDevSession(request, alice);

  const org = await request.post(`${solandBaseUrl()}/_soland/self/organizations`, {
    headers: authHeaders(aliceToken),
    data: {
      organization_did: orgDid,
      display_name: `Acme ${label}`,
      handle: `@acme-${label}`,
      verified: true,
      members: [alice.did, bob.did],
      member_count: 2,
    },
  });
  expect(org.ok()).toBeTruthy();

  const policy = await request.post(
    `${solandBaseUrl()}/_soland/self/organizations/${encodeURIComponent(orgDid)}/policy`,
    {
      headers: authHeaders(aliceToken),
      data: {
        policy_id: `ck:org-policy:${label}-${stamp}`,
        targets: [{ kind: "actor", did: mallory.did, action: "deny_join" }],
        appeal: { enabled: true, endpoint: "/_cokret/self/events" },
      },
    },
  );
  const policyText = await policy.text();
  expect(
    policy.ok(),
    `policy returned ${policy.status()}: ${policyText}`,
  ).toBeTruthy();

  return { alice, mallory, bob, aliceToken, orgDid };
}
