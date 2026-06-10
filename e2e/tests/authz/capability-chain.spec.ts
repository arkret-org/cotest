// Capability grant / revoke / delegate / constraints / audit
// Contract: e2e/scenarios/authz/capability-chain.md
// Spec: authz/capabilities.md §3 (Grant), §10 (Delegation), §12 (Revocation),
//        events/audit shape from admin/audit.rs
// E2E-CAP-1 — soland/_todos.md "E2E gap backlog".

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { wireErrCode } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type GrantBody = {
  realm_id: string;
  subject: string;
  resource?: string;
  actions: string[];
  constraints?: unknown[];
  expires_at?: string;
  delegated_from?: string;
};

async function createGrant(
  request: ReturnType<typeof Object>,
  token: string,
  body: GrantBody,
) {
  return await (request as import("@playwright/test").APIRequestContext).post(
    `${solandBaseUrl()}/_cokret/self/authz/grants`,
    {
      headers: { authorization: `Bearer ${token}` },
      data: body,
    },
  );
}

async function authzCheck(
  request: import("@playwright/test").APIRequestContext,
  token: string,
  body: { actor_id: string; action: string; resource: unknown },
) {
  return await request.post(`${solandBaseUrl()}/_cokret/self/authz/check`, {
    headers: { authorization: `Bearer ${token}` },
    data: body,
  });
}

function plusSeconds(deltaSec: number): string {
  return new Date(Date.now() + deltaSec * 1000).toISOString();
}

test.describe("capability chain @fully-implemented", () => {
  test("non-member writing to a space is rejected (missing_capability baseline)", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s20-alice");
    const mallory = uniqueUser("s20-mallory");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, mallory),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const malloryToken = await issueDevSession(request, mallory);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `S20 baseline ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // mallory (non-member, no capability) attempts to send a message via API.
      const send = await request.post(`${solandBaseUrl()}/_soland/self/realms/${encodeURIComponent(realmId)}/messages`, {
        headers: { authorization: `Bearer ${malloryToken}` },
        data: { content: { text: "mallory attempt" } },
      });
      expect([401, 403, 404, 405]).toContain(send.status());
    } finally {
      await alicePage.close();
    }
  });

  test("alice grants bob ck.space.write_message with expires_at=+1h; the grant is effective via /authz/check", async ({
    browser,
    request,
  }) => {
    // spec: capabilities.md §3 (Grant object) — temporal constraint accepted,
    // and /authz/check returns allowed=true with reason=explicit_grant.
    const stamp = Date.now();
    const alice = uniqueUser("cap-grant-alice");
    const bob = uniqueUser("cap-grant-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `cap grant ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      const expiresAt = plusSeconds(3600);
      const grantResp = await createGrant(request, aliceToken, {
        realm_id: realmId,
        subject: bob.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: expiresAt,
      });
      expect(grantResp.status()).toBe(200);
      const grant = await grantResp.json();
      expect(grant.grant_id).toBeTruthy();
      expect(grant.subject).toBe(bob.did);
      expect(grant.actions).toContain("ck.message.create");
      expect(grant.expires_at).toBeTruthy();
      expect(grant.delegated_from).toBeUndefined();

      const check = await authzCheck(request, aliceToken, {
        actor_id: bob.did,
        action: "ck.message.create",
        resource: { kind: "realm", realm_id: realmId },
      });
      expect(check.status()).toBe(200);
      const decision = await check.json();
      expect(decision.allowed).toBe(true);
      expect(decision.reason_code).toBeFalsy();
    } finally {
      await alicePage.close();
    }
  });

  test("bob delegates the capability to carol with stricter expires_at; carol's check passes through the delegation chain", async ({
    browser,
    request,
  }) => {
    // spec: capabilities.md §10 — delegation MUST NOT widen actions or expiry.
    const stamp = Date.now();
    const alice = uniqueUser("cap-delegate-alice");
    const bob = uniqueUser("cap-delegate-bob");
    const carol = uniqueUser("cap-delegate-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `cap delegate ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      const parentGrant = await createGrant(request, aliceToken, {
        realm_id: realmId,
        subject: bob.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(3600),
      });
      expect(parentGrant.status()).toBe(200);
      const parent = await parentGrant.json();

      // bob delegates to carol with a STRICTER (earlier) expires_at.
      const childGrant = await createGrant(request, bobToken, {
        realm_id: realmId,
        subject: carol.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(1800),
        delegated_from: parent.grant_id,
      });
      expect(childGrant.status()).toBe(200);
      const child = await childGrant.json();
      expect(child.delegated_from).toBe(parent.grant_id);

      const check = await authzCheck(request, aliceToken, {
        actor_id: carol.did,
        action: "ck.message.create",
        resource: { kind: "realm", realm_id: realmId },
      });
      expect(check.status()).toBe(200);
      const decision = await check.json();
      expect(decision.allowed).toBe(true);
    } finally {
      await alicePage.close();
    }
  });

  test("alice revokes bob's grant; cascade revokes carol's delegated capability; both subsequent checks rejected", async ({
    browser,
    request,
  }) => {
    // spec: capabilities.md §3.3 / §12 — revoke cascades through delegation chain.
    const stamp = Date.now();
    const alice = uniqueUser("cap-revoke-alice");
    const bob = uniqueUser("cap-revoke-bob");
    const carol = uniqueUser("cap-revoke-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `cap revoke ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      const parentResp = await createGrant(request, aliceToken, {
        realm_id: realmId,
        subject: bob.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(3600),
      });
      expect(parentResp.status()).toBe(200);
      const parent = await parentResp.json();

      const childResp = await createGrant(request, bobToken, {
        realm_id: realmId,
        subject: carol.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(1800),
        delegated_from: parent.grant_id,
      });
      expect(childResp.status()).toBe(200);
      const child = await childResp.json();

      // Sanity: both currently allowed.
      const bobBefore = await authzCheck(request, aliceToken, {
        actor_id: bob.did,
        action: "ck.message.create",
        resource: { kind: "realm", realm_id: realmId },
      });
      expect((await bobBefore.json()).allowed).toBe(true);

      // alice (space owner) revokes the parent grant — cascade revokes carol's.
      const revokeResp = await request.delete(
        `${solandBaseUrl()}/_cokret/self/authz/grants/${encodeURIComponent(parent.grant_id)}`,
        { headers: { authorization: `Bearer ${aliceToken}` } },
      );
      expect(revokeResp.status()).toBe(200);
      const revoke = await revokeResp.json();
      expect(revoke.revoked).toBe(true);
      expect(revoke.cascade_revoked).toContain(child.grant_id);

      // Both must now be rejected.
      const bobAfter = await authzCheck(request, aliceToken, {
        actor_id: bob.did,
        action: "ck.message.create",
        resource: { kind: "realm", realm_id: realmId },
      });
      const carolAfter = await authzCheck(request, aliceToken, {
        actor_id: carol.did,
        action: "ck.message.create",
        resource: { kind: "realm", realm_id: realmId },
      });
      expect((await bobAfter.json()).allowed).toBe(false);
      expect((await carolAfter.json()).allowed).toBe(false);
    } finally {
      await alicePage.close();
    }
  });

  test("E20.1 over-grant: bob cannot delegate an action bob does not hold (capability_not_held)", async ({
    browser,
    request,
  }) => {
    // spec: capabilities.md §10 — 再授权不得扩大动作范围.
    const stamp = Date.now();
    const alice = uniqueUser("cap-overgrant-alice");
    const bob = uniqueUser("cap-overgrant-bob");
    const carol = uniqueUser("cap-overgrant-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `cap overgrant ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // alice only gives bob `ck.message.create`.
      const parentResp = await createGrant(request, aliceToken, {
        realm_id: realmId,
        subject: bob.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(3600),
      });
      expect(parentResp.status()).toBe(200);
      const parent = await parentResp.json();

      // bob tries to delegate `ck.space.moderate` to carol — bob doesn't hold it.
      const childResp = await createGrant(request, bobToken, {
        realm_id: realmId,
        subject: carol.did,
        resource: "*",
        actions: ["ck.space.moderate"],
        expires_at: plusSeconds(1800),
        delegated_from: parent.grant_id,
      });
      expect(childResp.status()).toBe(412);
      const body = await childResp.json();
      expect(wireErrCode(body)).toBe("capability_not_held");
    } finally {
      await alicePage.close();
    }
  });

  test("E20.2 over-expire: bob's delegation cannot exceed bob's own expiry (capability_over_expire)", async ({
    browser,
    request,
  }) => {
    // spec: capabilities.md §10 — 再授权不得扩大资源范围 / temporal constraint.
    const stamp = Date.now();
    const alice = uniqueUser("cap-overexpire-alice");
    const bob = uniqueUser("cap-overexpire-bob");
    const carol = uniqueUser("cap-overexpire-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `cap overexpire ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // alice gives bob a grant expiring in 30 minutes.
      const parentResp = await createGrant(request, aliceToken, {
        realm_id: realmId,
        subject: bob.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(1800),
      });
      expect(parentResp.status()).toBe(200);
      const parent = await parentResp.json();

      // bob tries to delegate to carol expiring in 2 hours.
      const childResp = await createGrant(request, bobToken, {
        realm_id: realmId,
        subject: carol.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(7200),
        delegated_from: parent.grant_id,
      });
      expect(childResp.status()).toBe(412);
      const body = await childResp.json();
      expect(wireErrCode(body)).toBe("capability_over_expire");
    } finally {
      await alicePage.close();
    }
  });

  test("audit log contains grant, delegate, revoke entries with grantor/grantee/timestamp/actions", async ({
    browser,
    request,
  }) => {
    // spec: capabilities.md §3.4 — each grant lifecycle event MUST be auditable.
    const stamp = Date.now();
    const alice = uniqueUser("cap-audit-alice");
    const bob = uniqueUser("cap-audit-bob");
    const carol = uniqueUser("cap-audit-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `cap audit ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      const parentResp = await createGrant(request, aliceToken, {
        realm_id: realmId,
        subject: bob.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(3600),
      });
      const parent = await parentResp.json();

      const childResp = await createGrant(request, bobToken, {
        realm_id: realmId,
        subject: carol.did,
        resource: "*",
        actions: ["ck.message.create"],
        expires_at: plusSeconds(1800),
        delegated_from: parent.grant_id,
      });
      const child = await childResp.json();

      await request.delete(
        `${solandBaseUrl()}/_cokret/self/authz/grants/${encodeURIComponent(parent.grant_id)}`,
        { headers: { authorization: `Bearer ${aliceToken}` } },
      );

      // alice queries her own audit log — must contain authz.grant.create + authz.grant.revoke.
      const aliceAudit = await request.get(
        `${solandBaseUrl()}/_soland/self/audit/events?actor=${encodeURIComponent(alice.did)}`,
        { headers: { authorization: `Bearer ${aliceToken}` } },
      );
      expect(aliceAudit.status()).toBe(200);
      const aliceBody = await aliceAudit.json();
      const aliceEvents = aliceBody.events as Array<{
        action: string;
        actor?: string;
        target?: { grant_id?: string; subject?: string; actions?: string[] };
        created_at?: string;
      }>;
      const aliceCreate = aliceEvents.find(
        (e) => e.action === "authz.grant.create" && e.target?.grant_id === parent.grant_id,
      );
      expect(aliceCreate, "alice must have an authz.grant.create entry for the parent grant").toBeTruthy();
      expect(aliceCreate?.actor).toBe(alice.did);
      expect(aliceCreate?.target?.subject).toBe(bob.did);
      expect(aliceCreate?.target?.actions).toContain("ck.message.create");
      expect(aliceCreate?.created_at).toBeTruthy();

      const aliceRevoke = aliceEvents.find(
        (e) => e.action === "authz.grant.revoke" && e.target?.grant_id === parent.grant_id,
      );
      expect(aliceRevoke, "alice must have an authz.grant.revoke entry").toBeTruthy();
      expect(aliceRevoke?.actor).toBe(alice.did);

      // bob queries his own audit log — must contain authz.grant.delegate.
      const bobAudit = await request.get(
        `${solandBaseUrl()}/_soland/self/audit/events?actor=${encodeURIComponent(bob.did)}`,
        { headers: { authorization: `Bearer ${bobToken}` } },
      );
      expect(bobAudit.status()).toBe(200);
      const bobBody = await bobAudit.json();
      const bobEvents = bobBody.events as Array<{
        action: string;
        actor?: string;
        target?: { grant_id?: string; subject?: string };
      }>;
      const bobDelegate = bobEvents.find(
        (e) => e.action === "authz.grant.delegate" && e.target?.grant_id === child.grant_id,
      );
      expect(bobDelegate, "bob must have an authz.grant.delegate entry for the child grant").toBeTruthy();
      expect(bobDelegate?.actor).toBe(bob.did);
      expect(bobDelegate?.target?.subject).toBe(carol.did);
    } finally {
      await alicePage.close();
    }
  });
});
