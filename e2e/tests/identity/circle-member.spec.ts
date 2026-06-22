// Circle membership (same principal server): a Realm member is pulled into a
// Circle by an admin with NO consent / accept from the pulled actor.
//
// This is the real-run replacement for the old `S8 circle member manage`
// placeholder that was `test.skip`'d in contact-graph.spec.ts (soland now ships
// the `/_cokret/self/circles/*` admin surface — CKP-0007).
//
// HTTP face: `/_cokret/self/circles` (now a normative Cokret surface — the
// `ck.self.circle.*` operations are published in the cokret-spec OpenAPI
// artifact, operation registry, and contract catalog; see helpers/circle-api.ts
// header for the full reasoning. The legacy `/_soland` mirror was retired).
// Spec refs: CKP-0007 — `ck.circle.*` data model, reducer invariant
// `Circle.members ⊆ Realm.members` (`circle_member_must_be_realm_member`), and
// §8 `ck.circle.member.manage` capability for cross-actor adds.
//
// Core property: the pulled actor does ZERO operations — admin's one-way add is
// authoritative, no `accept` round-trip exists for Circle membership.

import { expect, test } from "@playwright/test";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import { addRealmMemberApi, createRealmApi } from "../../helpers/soland-api";
import {
  addCircleMemberCokret,
  addCircleMemberRaw,
  createCircleCokret,
  errorWireCode,
  getCircleCokret,
  grantCircleMemberManageCapability,
} from "../../helpers/circle-api";

// Each test provisions fresh DIDs, so parallel execution is safe.

test.describe("circle membership (same principal server)", () => {
  // S8 core: realm member pulled into a Circle with the pulled actor doing
  // nothing. alice (realm owner) builds a realm, makes bob a `join` realm
  // member, creates a Circle, and pulls bob in. bob never calls anything ->
  // GET circle surfaces bob as a member.
  test("S8 admin pulls a realm member into a Circle — pulled actor does zero operations", async ({
    request,
  }) => {
    const alice = uniqueUser("circle-s8-alice");
    const bob = uniqueUser("circle-s8-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const [aliceToken] = await Promise.all([
      issueDevSession(request, alice),
      // bob registers + has a session but never USES it for circle ops; the
      // whole point is the pull needs no action from bob.
      issueDevSession(request, bob),
    ]);

    // alice owns the realm and pulls bob in as a `join` member (owner one-way
    // add — `addRealmMemberApi` submits ck.member.state{join}).
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S8 circle realm ${Date.now()}`,
      ownerDid: alice.did,
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);

    // alice creates an invite-rule Circle bound to that realm.
    const circle = await createCircleCokret(request, aliceToken, {
      realmId,
      title: `S8 circle ${Date.now()}`,
      joinRule: "invite",
    });
    expect(circle.circle_id).toMatch(/^ck:circle:/);
    expect(circle.realm_id).toBe(realmId);
    expect(circle.state).toBe("active");

    // Circle-local management is not inherited from Realm ownership. Alice
    // explicitly grants herself member management for this Circle, joins so she
    // can read the member list, then pulls Bob. Bob is NOT consulted.
    await grantCircleMemberManageCapability(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: alice.did,
      circleId: circle.circle_id,
    });
    await addCircleMemberCokret(request, aliceToken, circle.circle_id, {
      actorId: alice.did,
      membership: "join",
    });
    const membership = await addCircleMemberCokret(
      request,
      aliceToken,
      circle.circle_id,
      { actorId: bob.did, membership: "join" },
    );
    expect(membership.membership).toBe("join");
    expect(membership.actor_id).toBe(bob.did);

    // CORE ASSERTION: bob did zero operations yet is a Circle member.
    const fetched = await getCircleCokret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(fetched.members).toContain(bob.did);
  });

  // S8 negative: pulling a NON realm member (mallory never joined the realm)
  // into the Circle is rejected by the strict-subset invariant
  // (`Circle.members ⊆ Realm.members`).
  test("S8 pull a non-realm-member -> circle_member_must_be_realm_member", async ({
    request,
  }) => {
    const alice = uniqueUser("circle-s8n-alice");
    const mallory = uniqueUser("circle-s8n-mallory");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, mallory),
    ]);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S8n circle realm ${Date.now()}`,
      ownerDid: alice.did,
    });
    const circle = await createCircleCokret(request, aliceToken, {
      realmId,
      title: `S8n circle ${Date.now()}`,
      joinRule: "invite",
    });
    await grantCircleMemberManageCapability(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: alice.did,
      circleId: circle.circle_id,
    });
    await addCircleMemberCokret(request, aliceToken, circle.circle_id, {
      actorId: alice.did,
      membership: "join",
    });

    // mallory is NOT a realm member. Pulling her in must fail closed on the
    // strict-subset invariant.
    const response = await addCircleMemberRaw(
      request,
      aliceToken,
      circle.circle_id,
      { actorId: mallory.did, membership: "join" },
    );
    expect(response.ok()).toBeFalsy();
    expect(response.status()).toBe(422);
    expect(await errorWireCode(response)).toBe(
      "circle_member_must_be_realm_member",
    );

    // mallory is not a member.
    const fetched = await getCircleCokret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(fetched.members ?? []).not.toContain(mallory.did);
  });

  // S8 capability: a realm member who is NOT the owner and holds no
  // `ck.circle.member.manage` capability tries to pull ANOTHER member into the
  // Circle -> 403 `circle_member_manage_capability_required`. carol and dave
  // are both `join` realm members so the strict-subset check passes and the
  // failure is purely the missing manage capability.
  test("S8 non-owner without manage capability pulling another -> 403 circle_member_manage_capability_required", async ({
    request,
  }) => {
    const alice = uniqueUser("circle-s8c-alice");
    const carol = uniqueUser("circle-s8c-carol");
    const dave = uniqueUser("circle-s8c-dave");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, carol),
      ensureRegistered(request, dave),
    ]);
    const [aliceToken, carolToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, carol),
      issueDevSession(request, dave),
    ]);

    // alice owns the realm; carol + dave are both join members.
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S8c circle realm ${Date.now()}`,
      ownerDid: alice.did,
    });
    await addRealmMemberApi(request, aliceToken, realmId, carol.did);
    await addRealmMemberApi(request, aliceToken, realmId, dave.did);

    const circle = await createCircleCokret(request, aliceToken, {
      realmId,
      title: `S8c circle ${Date.now()}`,
      joinRule: "invite",
    });
    await grantCircleMemberManageCapability(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: alice.did,
      circleId: circle.circle_id,
    });
    await addCircleMemberCokret(request, aliceToken, circle.circle_id, {
      actorId: alice.did,
      membership: "join",
    });

    // carol (non-owner, no manage capability on the Circle) tries to pull dave
    // in. The HTTP surface evaluates `ck.circle.member.manage` and fails
    // closed with 403 + the canonical wire code.
    const response = await addCircleMemberRaw(
      request,
      carolToken,
      circle.circle_id,
      { actorId: dave.did, membership: "join" },
    );
    expect(response.ok()).toBeFalsy();
    expect(response.status()).toBe(403);
    expect(await errorWireCode(response)).toBe(
      "circle_member_manage_capability_required",
    );

    // dave is not a Circle member.
    const fetched = await getCircleCokret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(fetched.members ?? []).not.toContain(dave.did);
  });
});
