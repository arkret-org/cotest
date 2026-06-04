// Account states (active / soft_logged_out / locked / suspended / deactivated)
// Contract: e2e/scenarios/identity/account-states.md
// Spec: identity/account-lifecycle.md §3

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  createSharedSpaceViaApi,
  listSpaceEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { wireErrCode } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("account states", () => {
  test("baseline active: /account/me returns state=active (or is silent on state)", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-baseline");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const meResp = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(meResp.ok()).toBeTruthy();
    const me = await meResp.json();
    expect(me.did).toBe(alice.did);
    if ("state" in me) {
      expect(me.state).toBe("active");
    }
  });

  test("soft logout revokes access token while account state remains active", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-soft-logout");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const logout = await request.post(`${solandBaseUrl()}/_soland/gate/auth/logout`, {
      headers: authHeaders(token),
    });
    expect(logout.status()).toBe(200);
    expect((await logout.json()).revoked).toBe(true);

    const oldMe = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: authHeaders(token),
    });
    expect(oldMe.status()).toBe(401);

    const newToken = await issueDevSession(request, alice);
    const me = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: authHeaders(newToken),
    });
    expect(me.status()).toBe(200);
    expect((await me.json()).state).toBe("active");
  });

  test("admin lock: /_soland/admin/accounts/<did>/lock invalidates sessions and blocks new login", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-lock-alice");
    const admin = uniqueUser("s28-lock-admin");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, admin)]);
    const aliceToken = await issueDevSession(request, alice);
    const adminToken = await issueDevSession(request, admin);

    const lock = await request.post(`${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/lock`, {
      headers: authHeaders(adminToken),
      data: { reason: "suspicious_login" },
    });
    expect(lock.status()).toBe(200);
    const lockBody = await lock.json();
    expect(lockBody.state).toBe("locked");
    expect(lockBody.previous_state).toBe("active");
    expect(lockBody.sessions_revoked).toBeGreaterThanOrEqual(1);

    const oldMe = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: authHeaders(aliceToken),
    });
    expect(oldMe.status()).toBe(401);
    expect(wireErrCode(await oldMe.json())).toBe("account_locked");

    const login = await request.post(`${solandBaseUrl()}/_soland/gate/auth/dev-login`, {
      data: {
        actor: alice.did,
        device_id: alice.deviceId,
        display_name: alice.displayName,
      },
    });
    expect(login.status()).toBe(403);
    expect(wireErrCode(await login.json())).toBe("account_locked");

    const unlock = await request.post(`${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/unlock`, {
      headers: authHeaders(adminToken),
      data: { reason: "recovery_complete" },
    });
    expect(unlock.status()).toBe(200);
    expect((await unlock.json()).state).toBe("active");
    await issueDevSession(request, alice);
  });

  test("governance suspend rejects new token requests while old sessions can observe suspended state", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-suspend-alice");
    const admin = uniqueUser("s28-suspend-admin");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, admin)]);
    const aliceToken = await issueDevSession(request, alice);
    const adminToken = await issueDevSession(request, admin);

    const suspend = await request.post(`${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/suspend`, {
      headers: authHeaders(adminToken),
      data: { reason: "abuse", duration: "30d" },
    });
    expect(suspend.status()).toBe(200);
    expect((await suspend.json()).state).toBe("suspended");

    const oldMe = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: authHeaders(aliceToken),
    });
    expect(oldMe.status()).toBe(200);
    expect((await oldMe.json()).state).toBe("suspended");

    const login = await request.post(`${solandBaseUrl()}/_soland/gate/auth/dev-login`, {
      data: {
        actor: alice.did,
        device_id: alice.deviceId,
        display_name: alice.displayName,
      },
    });
    expect(login.status()).toBe(403);
    expect(wireErrCode(await login.json())).toBe("account_suspended");

    const unsuspend = await request.post(`${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/unsuspend`, {
      headers: authHeaders(adminToken),
      data: { reason: "appeal_accepted" },
    });
    expect(unsuspend.status()).toBe(200);
    expect((await unsuspend.json()).state).toBe("active");
    await issueDevSession(request, alice);
  });

  test("user-initiated deactivate revokes tokens, hides directory row, and leaves messages visible", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-deactivate-alice");
    const bob = uniqueUser("s28-deactivate-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const spaceId = await createSharedSpaceViaApi(request, alice, aliceToken, bob, bobToken, {
      title: "deactivation visibility",
      ownerDid: alice.did,
    });
    const message = `message before deactivate ${Date.now()}`;
    await sendPlaintextMessageViaApi(request, aliceToken, spaceId, message, {
      actorDid: alice.did,
    });

    const deactivate = await request.post(`${solandBaseUrl()}/_soland/self/account/deactivate`, {
      headers: authHeaders(aliceToken),
    });
    expect(deactivate.status()).toBe(200);
    const deactivateBody = await deactivate.json();
    expect(deactivateBody.state).toBe("deactivated");
    expect(deactivateBody.sessions_revoked).toBeGreaterThanOrEqual(1);

    const oldMe = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: authHeaders(aliceToken),
    });
    expect(oldMe.status()).toBe(401);
    expect(wireErrCode(await oldMe.json())).toBe("account_deactivated");

    const login = await request.post(`${solandBaseUrl()}/_soland/gate/auth/dev-login`, {
      data: {
        actor: alice.did,
        device_id: alice.deviceId,
        display_name: alice.displayName,
      },
    });
    expect(login.status()).toBe(403);
    expect(wireErrCode(await login.json())).toBe("account_deactivated");

    const search = await request.post(`${solandBaseUrl()}/_cokret/find/directory/search-actors`, {
      headers: authHeaders(bobToken),
      data: { query: alice.handle },
    });
    expect(search.status()).toBe(200);
    const searchBody = await search.json();
    expect((searchBody.results as Array<{ did: string }>).some((row) => row.did === alice.did)).toBe(false);

    const events = await listSpaceEventsViaApi(request, bobToken, spaceId);
    expect(JSON.stringify(events)).toContain(message);
  });

  test("erasure moves account to erased state and audit snapshot records the transition", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-erased-alice");
    const bob = uniqueUser("s28-erased-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const erase = await request.post(`${solandBaseUrl()}/_soland/self/account/erase`, {
      headers: authHeaders(aliceToken),
    });
    expect(erase.status()).toBe(200);
    const eraseBody = await erase.json();
    expect(eraseBody.state).toBe("erased");
    const auditActions = (eraseBody.audit_log as Array<{ action: string; target?: unknown }>).map(
      (event) => event.action,
    );
    expect(auditActions).toContain("ck.account.state_change");
    expect(JSON.stringify(eraseBody.audit_log)).toContain('"to":"erased"');

    const oldMe = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: authHeaders(aliceToken),
    });
    expect(oldMe.status()).toBe(401);
    expect(wireErrCode(await oldMe.json())).toBe("account_erased");

    const search = await request.post(`${solandBaseUrl()}/_cokret/find/directory/search-actors`, {
      headers: authHeaders(bobToken),
      data: { query: alice.handle },
    });
    expect(search.status()).toBe(200);
    const searchBody = await search.json();
    expect((searchBody.results as Array<{ did: string }>).some((row) => row.did === alice.did)).toBe(false);
  });

  test("audit: each state transition writes ck.account.state_change with from/to/actor/reason/timestamp", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-audit-alice");
    const admin = uniqueUser("s28-audit-admin");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, admin)]);
    const adminToken = await issueDevSession(request, admin);

    const suspend = await request.post(`${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/suspend`, {
      headers: authHeaders(adminToken),
      data: { reason: "audit_probe" },
    });
    expect(suspend.status()).toBe(200);

    const audit = await request.get(
      `${solandBaseUrl()}/_soland/self/audit/events?actor=${encodeURIComponent(admin.did)}&limit=20`,
      { headers: authHeaders(adminToken) },
    );
    expect(audit.status()).toBe(200);
    const auditBody = await audit.json();
    const transition = (auditBody.events as Array<{ action: string; target: Record<string, unknown> }>).find(
      (event) => event.action === "ck.account.state_change" && event.target?.subject === alice.did,
    );
    expect(transition).toBeTruthy();
    expect(transition!.target.from).toBe("active");
    expect(transition!.target.to).toBe("suspended");
    expect(transition!.target.reason).toBe("audit_probe");
    expect(transition!.target.timestamp).toBeTruthy();
  });

  test.fixme(
    // @blocking-on: soland#identity-account-states-gap
    // @user-promise: e2e/scenarios/identity/account-states.md
    // @expected-live-by: 2026Q3
    "E28.2 cross-server suspension: alice suspended on α; β learns of suspension via sync within reconciliation window",
    async () => {},
  );
});
