// Circle membership (same Station): a Realm member is pulled into a
// Circle by an admin with NO consent / accept from the pulled actor.
//
// This is the real-run replacement for the old `S8 circle member manage`
// placeholder that was `test.skip`'d in contact-graph.spec.ts (soland now ships
// the `/_arkret/self/circles/*` admin surface — AKP-0007).
//
// HTTP face: `/_arkret/self/circles` (now a normative Arkret surface — the
// `ak.self.circle.*` operations are published in the arkret-spec OpenAPI
// artifact, operation registry, and contract catalog; see helpers/circle-api.ts
// header for the full reasoning. `/_soland/self/circles` is not mounted).
// Spec refs: AKP-0007 — `ak.circle.*` data model, reducer invariant
// `Circle.members ⊆ Realm.members` (`circle_member_must_be_realm_member`), and
// §8 `ak.circle.member.manage` capability for cross-actor adds.
//
// Core property: the pulled actor does ZERO operations — admin's one-way add is
// authoritative, no `accept` round-trip exists for Circle membership.

import { expect, test } from "../../helpers/arkret-test";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";
import { accountActorId, addRealmMemberApi, createRealmApi } from "../../helpers/soland-api";
import {
  addCircleMemberArkret,
  addCircleMemberRaw,
  archiveCircleArkret,
  createCircleArkret,
  errorWireCode,
  getCircleArkret,
  grantCircleManageCapability,
  grantCircleMemberManageCapability,
  removeCircleMemberArkret,
  restoreCircleArkret,
} from "../../helpers/circle-api";

// Each test provisions fresh DIDs, so parallel execution is safe.

test.describe("circle membership (same Station)", () => {
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
    const [aliceToken, bobToken] = await Promise.all([
      issueDevSession(request, alice),
      // bob registers + has a session but never USES it for circle ops; the
      // whole point is the pull needs no action from bob.
      issueDevSession(request, bob),
    ]);

    // alice owns the realm and pulls bob in as a `join` member (owner one-way
    // add — `addRealmMemberApi` submits ak.member.state{join}).
    const realmId = await createRealmApi(request, aliceToken, {
      title: `S8 circle realm ${Date.now()}`,
      ownerId: alice.id,
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.id);

    // alice creates an invite-rule Circle bound to that realm.
    const circle = await createCircleArkret(request, aliceToken, {
      actorId: alice.id,
      realmId,
      title: `S8 circle ${Date.now()}`,
      joinRule: "invite",
      directoryVisibility: "realm_members",
    });
    expect(circle.circle_id).toMatch(/^ak:circle:/);
    expect(circle.realm_id).toBe(realmId);
    expect(circle.state).toBe("active");

    const bobDirectoryView = await getCircleArkret(
      request,
      bobToken,
      circle.circle_id,
    );
    expect(bobDirectoryView.member_ids).toEqual([]);
    expect(bobDirectoryView.member_count).toBeUndefined();
    expect(bobDirectoryView.viewer_membership).toBeUndefined();

    // Circle-local management is not inherited from Realm ownership. Alice
    // explicitly grants herself member management for this Circle, joins so she
    // can read the member list, then pulls Bob. Bob is NOT consulted.
    await grantCircleMemberManageCapability(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectId: alice.id,
      circleId: circle.circle_id,
    });
    await addCircleMemberArkret(request, aliceToken, circle.circle_id, {
      signerId: alice.id,
      realmId,
      actorId: alice.id,
      membership: "join",
    });
    const membership = await addCircleMemberArkret(
      request,
      aliceToken,
      circle.circle_id,
      { signerId: alice.id, realmId, actorId: bob.id, membership: "join" },
    );
    expect(membership.membership).toBe("join");
    expect(membership.member_id).toEqual(accountActorId(bob.id));

    // CORE ASSERTION: bob did zero operations yet is a Circle member.
    const fetched = await getCircleArkret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(fetched.member_ids).toContainEqual(accountActorId(bob.id));

    // The DELETE is itself a caller-signed membership Move. Its payload binds
    // both path ids and carries the observed joined head as the CAS guard.
    const removed = await removeCircleMemberArkret(
      request,
      aliceToken,
      circle.circle_id,
      bob.id,
      { actorId: alice.id, realmId },
    );
    expect(removed).toEqual({
      circle_id: circle.circle_id,
      member_id: accountActorId(bob.id),
      membership: "leave",
    });
    const afterRemoval = await getCircleArkret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(afterRemoval.member_ids).not.toContainEqual(accountActorId(bob.id));
  });

  test("S8 lifecycle archive then restore returns Circle to active", async ({
    request,
  }) => {
    const alice = uniqueUser("circle-s8r-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S8 restore circle realm ${Date.now()}`,
      ownerId: alice.id,
    });
    const circle = await createCircleArkret(request, aliceToken, {
      actorId: alice.id,
      realmId,
      title: `S8 restore circle ${Date.now()}`,
      joinRule: "invite",
    });
    await grantCircleManageCapability(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectId: alice.id,
      circleId: circle.circle_id,
    });
    await grantCircleMemberManageCapability(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectId: alice.id,
      circleId: circle.circle_id,
    });
    await addCircleMemberArkret(request, aliceToken, circle.circle_id, {
      signerId: alice.id,
      realmId,
      actorId: alice.id,
      membership: "join",
    });

    const archived = await archiveCircleArkret(
      request,
      aliceToken,
      circle.circle_id,
      { actorId: alice.id, realmId },
    );
    expect(archived.state).toBe("archived");

    const restored = await restoreCircleArkret(
      request,
      aliceToken,
      circle.circle_id,
      { actorId: alice.id, realmId },
    );
    expect(restored.state).toBe("active");

    const fetched = await getCircleArkret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(fetched.state).toBe("active");
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
      ownerId: alice.id,
    });
    const circle = await createCircleArkret(request, aliceToken, {
      actorId: alice.id,
      realmId,
      title: `S8n circle ${Date.now()}`,
      joinRule: "invite",
    });
    await grantCircleMemberManageCapability(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectId: alice.id,
      circleId: circle.circle_id,
    });
    await addCircleMemberArkret(request, aliceToken, circle.circle_id, {
      signerId: alice.id,
      realmId,
      actorId: alice.id,
      membership: "join",
    });

    // mallory is NOT a realm member. Pulling her in must fail closed on the
    // strict-subset invariant.
    const response = await addCircleMemberRaw(
      request,
      aliceToken,
      circle.circle_id,
      { signerId: alice.id, realmId, actorId: mallory.id, membership: "join" },
    );
    expect(response.ok()).toBeFalsy();
    expect(response.status()).toBe(422);
    expect(await errorWireCode(response), await response.text()).toBe(
      "circle_member_must_be_realm_member",
    );

    // mallory is not a member.
    const fetched = await getCircleArkret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(fetched.member_ids ?? []).not.toContainEqual(accountActorId(mallory.id));
  });

  // S8 capability: a realm member who is NOT the owner and holds no
  // `ak.circle.member.manage` capability tries to pull ANOTHER member into the
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
      ownerId: alice.id,
    });
    await addRealmMemberApi(request, aliceToken, realmId, carol.id);
    await addRealmMemberApi(request, aliceToken, realmId, dave.id);

    const circle = await createCircleArkret(request, aliceToken, {
      actorId: alice.id,
      realmId,
      title: `S8c circle ${Date.now()}`,
      joinRule: "invite",
    });
    await grantCircleMemberManageCapability(request, aliceToken, {
      ownerId: alice.id,
      realmId,
      subjectId: alice.id,
      circleId: circle.circle_id,
    });
    await addCircleMemberArkret(request, aliceToken, circle.circle_id, {
      signerId: alice.id,
      realmId,
      actorId: alice.id,
      membership: "join",
    });

    // carol (non-owner, no manage capability on the Circle) tries to pull dave
    // in. The HTTP surface evaluates `ak.circle.member.manage` and fails
    // closed with 403 + the canonical wire code.
    const response = await addCircleMemberRaw(
      request,
      carolToken,
      circle.circle_id,
      { signerId: carol.id, realmId, actorId: dave.id, membership: "join" },
    );
    expect(response.ok()).toBeFalsy();
    expect(response.status()).toBe(403);
    expect(await errorWireCode(response), await response.text()).toBe(
      "circle_member_manage_capability_required",
    );

    // dave is not a Circle member.
    const fetched = await getCircleArkret(
      request,
      aliceToken,
      circle.circle_id,
    );
    expect(fetched.member_ids ?? []).not.toContainEqual(accountActorId(dave.id));
  });
});
