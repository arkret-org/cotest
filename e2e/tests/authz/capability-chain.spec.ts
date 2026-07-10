// Capability chain on the event wire: grant / delegate (narrowing) / revoke cascade
// Contract: e2e/scenarios/authz/capability-chain.md
// Spec: authz/capabilities.md §3 (grant + §3.1a issuer upper bound),
//       §10 (delegation narrowing + §10.3 revoke propagation), §12 (revocation)
//
// Capabilities are event-minted: grants are `ck.capability.grant` events and
// revocations `ck.capability.revoke` events submitted to /_arkret/self/events
// and projected by the reducer. The only synchronous read surfaces are the
// registered diagnostics endpoints POST /_arkret/self/authz/check
// (ck.self.authz.query.check) and GET /_arkret/self/authz/effective-grants
// (ck.self.authz.grants.query.effective). The former synchronous REST
// grant/revoke/audit surface (POST/DELETE /_arkret/self/authz/grants*,
// GET /_soland/self/audit/events) was removed from the spec and MUST NOT be
// reintroduced (SPEC-CR-020: zero new operations).

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  addRealmMemberApi,
  buildCapabilityGrantEnvelope,
  createRealmApi,
  grantCapabilityEventApi,
  revokeCapabilityApi,
  wireErrCode,
  type CapabilityGrantEventArgs,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

function plusSeconds(deltaSec: number): string {
  return new Date(Date.now() + deltaSec * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}

// POST /_arkret/self/authz/check — spec AuthzCheckOutcome: five-valued
// `decision` enum; `allow` / `hard_deny` are the terminal values the local
// projection yields.
async function authzCheck(
  request: APIRequestContext,
  token: string,
  args: { actorDid: string; action: string; realmId: string },
): Promise<{ decision: string; reasonCode?: string }> {
  const response = await request.post(`${solandBaseUrl()}/_arkret/self/authz/check`, {
    headers: authHeaders(token),
    data: {
      actor_id: args.actorDid,
      action: args.action,
      resource: { kind: "realm", realm_id: args.realmId },
    },
  });
  const text = await response.text();
  expect(response.status(), `authz/check: ${text}`).toBe(200);
  const body = JSON.parse(text) as { decision: string; reason_code?: string };
  return { decision: body.decision, reasonCode: body.reason_code };
}

// Submit a `ck.capability.grant` envelope raw (no 200 assertion) so negative
// cases can pin the reducer's fail-closed rejection.
async function submitGrantRaw(
  request: APIRequestContext,
  token: string,
  args: CapabilityGrantEventArgs,
): Promise<{ status: number; text: string; body: unknown; grantId: string }> {
  const { envelope, grantId } = buildCapabilityGrantEnvelope(args);
  const response = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: envelope,
  });
  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { status: response.status(), text, body, grantId };
}

// Reducer fail-closed rejections surface as a 4xx wire error. The top-level
// code is the coarse spec class (`failed_precondition` / `schema_violation`);
// implementations may surface the fine-grained registry reason directly.
function expectGrantRejected(
  result: { status: number; text: string; body: unknown },
  acceptableReasons: string[],
) {
  expect(
    result.status,
    `expected fail-closed rejection, got ${result.status}: ${result.text}`,
  ).toBeGreaterThanOrEqual(400);
  expect(result.status).toBeLessThan(500);
  expect(
    ["failed_precondition", "schema_violation", ...acceptableReasons],
    `unexpected error code in ${result.text}`,
  ).toContain(wireErrCode(result.body));
}

async function setupOwnerRealm(request: APIRequestContext, label: string) {
  const alice = uniqueUser(`cap-${label}-alice`);
  const bob = uniqueUser(`cap-${label}-bob`);
  const carol = uniqueUser(`cap-${label}-carol`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
    ensureRegistered(request, carol),
  ]);
  const aliceToken = await issueDevSession(request, alice);
  const bobToken = await issueDevSession(request, bob);
  const realmId = await createRealmApi(request, aliceToken, {
    title: `cap ${label} ${Date.now()}`,
    discoverability: "listed",
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.did);
  await addRealmMemberApi(request, aliceToken, realmId, carol.did);
  return { alice, bob, carol, aliceToken, bobToken, realmId };
}

test.describe("capability chain (event wire)", () => {
  test("§3 grant lifecycle: bob is denied before the grant and allowed after alice mints ak.capability.grant; effective-grants surfaces it", async ({
    request,
  }) => {
    const { alice, bob, aliceToken, realmId } = await setupOwnerRealm(request, "grant");

    const before = await authzCheck(request, aliceToken, {
      actorDid: bob.did,
      action: "ak.message.create",
      realmId,
    });
    expect(before.decision).toBe("hard_deny");

    const { grantId } = await grantCapabilityEventApi(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: bob.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(3600),
    });

    const after = await authzCheck(request, aliceToken, {
      actorDid: bob.did,
      action: "ak.message.create",
      realmId,
    });
    expect(after.decision).toBe("allow");

    // GET /_arkret/self/authz/effective-grants — realm owner may query a
    // subject's direct grants (GrantList).
    const grantsResp = await request.get(
      `${solandBaseUrl()}/_arkret/self/authz/effective-grants?subject=${encodeURIComponent(bob.did)}&realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken) },
    );
    const grantsText = await grantsResp.text();
    expect(grantsResp.status(), grantsText).toBe(200);
    const grants = (JSON.parse(grantsText) as { grants?: Array<{ id?: string }> }).grants ?? [];
    expect(grants.map((grant) => grant.id)).toContain(grantId);
  });

  test("§10 narrowing delegation: bob re-grants to carol with a subset window via parent_grant_id; carol's check passes through the chain", async ({
    request,
  }) => {
    const { alice, bob, carol, aliceToken, bobToken, realmId } = await setupOwnerRealm(
      request,
      "delegate",
    );

    const parent = await grantCapabilityEventApi(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: bob.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(3600),
    });

    // Child grant narrows: same action set, strictly earlier expiry (§10.1).
    await grantCapabilityEventApi(request, bobToken, {
      ownerDid: bob.did,
      realmId,
      subjectDid: carol.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(1800),
      parentGrantId: parent.grantId,
    });

    const carolCheck = await authzCheck(request, aliceToken, {
      actorDid: carol.did,
      action: "ak.message.create",
      realmId,
    });
    expect(carolCheck.decision).toBe("allow");
  });

  test("§10.1/§3.1a over-action delegation fails closed: bob cannot re-grant an action bob does not hold", async ({
    request,
  }) => {
    const { alice, bob, carol, aliceToken, bobToken, realmId } = await setupOwnerRealm(
      request,
      "overaction",
    );

    const parent = await grantCapabilityEventApi(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: bob.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(3600),
    });

    // bob only holds ak.message.create; delegating moderation authority
    // violates child.actions ⊆ parent.actions (§10.1) / the issuer upper
    // bound (§3.1a, reason grant_exceeds_issuer_authority).
    const overAction = await submitGrantRaw(request, bobToken, {
      ownerDid: bob.did,
      realmId,
      subjectDid: carol.did,
      actions: ["ak.moderation.decision"],
      expiresAt: plusSeconds(1800),
      parentGrantId: parent.grantId,
    });
    expectGrantRejected(overAction, ["grant_exceeds_issuer_authority"]);

    const carolCheck = await authzCheck(request, aliceToken, {
      actorDid: carol.did,
      action: "ak.moderation.decision",
      realmId,
    });
    expect(carolCheck.decision).toBe("hard_deny");
  });

  test("§10.1 expiry widening fails closed: the child grant cannot outlive the parent grant", async ({
    request,
  }) => {
    const { alice, bob, carol, aliceToken, bobToken, realmId } = await setupOwnerRealm(
      request,
      "overexpire",
    );

    const parent = await grantCapabilityEventApi(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: bob.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(1800),
    });

    // child effective_expires_at MUST be <= parent.effective_expires_at
    // (§10.1, reason delegation_expiry_widening).
    const overExpire = await submitGrantRaw(request, bobToken, {
      ownerDid: bob.did,
      realmId,
      subjectDid: carol.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(7200),
      parentGrantId: parent.grantId,
    });
    expectGrantRejected(overExpire, [
      "delegation_expiry_widening",
      "grant_exceeds_issuer_authority",
    ]);

    const carolCheck = await authzCheck(request, aliceToken, {
      actorDid: carol.did,
      action: "ak.message.create",
      realmId,
    });
    expect(carolCheck.decision).toBe("hard_deny");
  });

  test("§12/§10.3 revoke cascade: revoking the parent grant invalidates the delegated child and blocks re-delegation from the revoked parent", async ({
    request,
  }) => {
    const { alice, bob, carol, aliceToken, bobToken, realmId } = await setupOwnerRealm(
      request,
      "revoke",
    );

    const parent = await grantCapabilityEventApi(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      subjectDid: bob.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(3600),
    });
    await grantCapabilityEventApi(request, bobToken, {
      ownerDid: bob.did,
      realmId,
      subjectDid: carol.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(1800),
      parentGrantId: parent.grantId,
    });

    // Sanity: both allowed before the revoke.
    expect(
      (
        await authzCheck(request, aliceToken, {
          actorDid: bob.did,
          action: "ak.message.create",
          realmId,
        })
      ).decision,
    ).toBe("allow");

    // Revocation is an explicit ak.capability.revoke event (§12), never a
    // record deletion.
    await revokeCapabilityApi(request, aliceToken, {
      ownerDid: alice.did,
      realmId,
      grantId: parent.grantId,
    });

    // §10.3: every derived child grant MUST be invalid in the revoke's causal
    // future — both checks fail closed.
    const bobAfter = await authzCheck(request, aliceToken, {
      actorDid: bob.did,
      action: "ak.message.create",
      realmId,
    });
    expect(bobAfter.decision).toBe("hard_deny");
    const carolAfter = await authzCheck(request, aliceToken, {
      actorDid: carol.did,
      action: "ak.message.create",
      realmId,
    });
    expect(carolAfter.decision).toBe("hard_deny");

    // Re-delegating from the revoked parent MUST fail closed with
    // grant_revoked_upstream (§10.3).
    const fromRevoked = await submitGrantRaw(request, bobToken, {
      ownerDid: bob.did,
      realmId,
      subjectDid: carol.did,
      actions: ["ak.message.create"],
      expiresAt: plusSeconds(600),
      parentGrantId: parent.grantId,
    });
    expectGrantRejected(fromRevoked, ["grant_revoked_upstream"]);
  });
});
