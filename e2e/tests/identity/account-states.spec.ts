// Account states (active / soft_logged_out / locked / suspended / deactivated)
// Contract: e2e/scenarios/identity/account-states.md
// Spec: identity/account-lifecycle.md §3

import { expect, test } from "../../helpers/arkret-test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { wireErrCode } from "../../helpers/soland-api";
import {
  generateDpopDeviceKey,
  mintDpopBoundGrant,
  selfPathGrantHeaders,
} from "../../helpers/session-grant-dpop";
import { registerCoauthPasswordAccount } from "../../helpers/coauth-register";
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
    const meResp = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      {
        headers: { authorization: `Bearer ${token}` },
      },
    );
    expect(meResp.ok()).toBeTruthy();
    const me = await meResp.json();
    expect(me.did).toBe(alice.did);
    if ("state" in me) {
      expect(me.state).toBe("active");
    }
  });

  test("hard logout revokes session grant while account state remains active", async ({
    request,
  }) => {
    const coauthBase = coauthBaseUrl();
    test.skip(
      !coauthBase,
      "coauth debug DPoP grant issuer is required for hard logout",
    );
    const account = await registerCoauthPasswordAccount(request, coauthBase!);
    const seed = uniqueUser("s28-hard-logout");
    const alice = {
      ...seed,
      name: account.handle,
      did: account.did,
      fullDid: account.fullDid,
      handle: `@${account.handle}`,
      displayName: account.displayName,
    };
    await ensureRegistered(request, alice);

    const deviceKey = generateDpopDeviceKey();
    const grant = await mintDpopBoundGrant(
      request,
      coauthBase!,
      alice.did,
      alice.deviceId,
      deviceKey,
    );
    test.skip(!grant, "coauth DPoP grant debug endpoint is unavailable");

    const logoutUrl = `${solandBaseUrl()}/_arkret/gate/account/logout`;
    const logout = await request.post(logoutUrl, {
      headers: selfPathGrantHeaders({
        deviceKey,
        grantJwt: grant!.grantJwt,
        method: "POST",
        url: logoutUrl,
      }),
    });
    expect(logout.status()).toBe(200);
    expect((await logout.json()).revoked).toBe(true);

    const oldMe = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      {
        headers: selfPathGrantHeaders({
          deviceKey,
          grantJwt: grant!.grantJwt,
          method: "GET",
          url: `${solandBaseUrl()}/_soland/self/account/me`,
        }),
      },
    );
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
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, admin),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const adminToken = await issueDevSession(request, admin);

    const lock = await request.post(
      `${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/lock`,
      {
        headers: authHeaders(adminToken),
        data: { reason: "suspicious_login" },
      },
    );
    expect(lock.status()).toBe(200);
    const lockBody = await lock.json();
    expect(lockBody.state).toBe("locked");
    expect(lockBody.previous_state).toBe("active");
    expect(lockBody.sessions_revoked).toBeGreaterThanOrEqual(1);

    const oldMe = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      {
        headers: authHeaders(aliceToken),
      },
    );
    expect(oldMe.status()).toBe(401);
    expect(wireErrCode(await oldMe.json())).toBe("account_locked");

    const login = await request.post(
      `${solandBaseUrl()}/_soland/gate/auth/dev-login`,
      {
        data: {
          actor: alice.did,
          device_id: alice.deviceId,
          display_name: alice.displayName,
        },
      },
    );
    expect(login.status()).toBe(403);
    expect(wireErrCode(await login.json())).toBe("account_locked");

    const unlock = await request.post(
      `${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/unlock`,
      {
        headers: authHeaders(adminToken),
        data: { reason: "operator_verified" },
      },
    );
    expect(unlock.status()).toBe(200);
    expect((await unlock.json()).state).toBe("active");
    await issueDevSession(request, alice);
  });

  test("governance suspend rejects new token requests while old sessions can observe suspended state", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-suspend-alice");
    const admin = uniqueUser("s28-suspend-admin");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, admin),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const adminToken = await issueDevSession(request, admin);

    const suspend = await request.post(
      `${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/suspend`,
      {
        headers: authHeaders(adminToken),
        // Suspension expiry is only a management review hint in the protocol;
        // lifting it always requires an explicit successor status record. The
        // closed admin command therefore carries the audit reason only.
        data: { reason: "abuse" },
      },
    );
    expect(suspend.status()).toBe(200);
    expect((await suspend.json()).state).toBe("suspended");

    const oldMe = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      {
        headers: authHeaders(aliceToken),
      },
    );
    expect(oldMe.status()).toBe(200);
    expect((await oldMe.json()).state).toBe("suspended");

    const login = await request.post(
      `${solandBaseUrl()}/_soland/gate/auth/dev-login`,
      {
        data: {
          actor: alice.did,
          device_id: alice.deviceId,
          display_name: alice.displayName,
        },
      },
    );
    expect(login.status()).toBe(403);
    expect(wireErrCode(await login.json())).toBe("account_suspended");

    const unsuspend = await request.post(
      `${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/unsuspend`,
      {
        headers: authHeaders(adminToken),
        data: { reason: "appeal_accepted" },
      },
    );
    expect(unsuspend.status()).toBe(200);
    expect((await unsuspend.json()).state).toBe("active");
    await issueDevSession(request, alice);
  });

  test("admin-initiated deactivate revokes tokens, hides directory row, and leaves messages visible", async ({
    request,
  }) => {
    // soland task 2335 (方案 A): the self-service `/_soland/self/account/deactivate`
    // route was removed — account-lifecycle.md §10 assigns deactivation
    // initiation to the admin/support surface
    // (`/_soland/admin/accounts/{did}/deactivate`).
    const alice = uniqueUser("s28-deactivate-alice");
    const bob = uniqueUser("s28-deactivate-bob");
    const admin = uniqueUser("s28-deactivate-admin");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, admin),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const adminToken = await issueDevSession(request, admin);
    const realmId = await createSharedRealmViaApi(
      request,
      alice,
      aliceToken,
      bob,
      {
        title: "deactivation visibility",
        ownerDid: alice.did,
      },
    );
    const message = `message before deactivate ${Date.now()}`;
    await sendPlaintextMessageViaApi(request, aliceToken, realmId, message, {
      actorDid: alice.did,
    });

    const deactivate = await request.post(
      `${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/deactivate`,
      {
        headers: authHeaders(adminToken),
        data: { reason: "user_requested_via_support" },
      },
    );
    expect(deactivate.status()).toBe(200);
    const deactivateBody = await deactivate.json();
    expect(deactivateBody.state).toBe("deactivated");
    expect(deactivateBody.sessions_revoked).toBeGreaterThanOrEqual(1);

    const oldMe = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      {
        headers: authHeaders(aliceToken),
      },
    );
    expect(oldMe.status()).toBe(401);
    expect(wireErrCode(await oldMe.json())).toBe("account_deactivated");

    const login = await request.post(
      `${solandBaseUrl()}/_soland/gate/auth/dev-login`,
      {
        data: {
          actor: alice.did,
          device_id: alice.deviceId,
          display_name: alice.displayName,
        },
      },
    );
    expect(login.status()).toBe(403);
    expect(wireErrCode(await login.json())).toBe("account_deactivated");

    const search = await request.post(
      `${solandBaseUrl()}/_arkret/find/directory/search-actors`,
      {
        headers: authHeaders(bobToken),
        data: { query: alice.handle },
      },
    );
    expect(search.status()).toBe(200);
    const searchBody = await search.json();
    expect(
      (
        searchBody.actors as Array<{
          actor_id?: string;
          preview?: { did?: string };
        }>
      ).some(
        (row) => row.actor_id === alice.did || row.preview?.did === alice.did,
      ),
    ).toBe(false);

    const events = await listRealmEventsViaApi(request, bobToken, realmId);
    expect(JSON.stringify(events)).toContain(message);
  });

  test("erasure moves account to erasure_pending state and audit snapshot records the transition", async ({
    request,
  }) => {
    test.skip(
      true,
      "the product-private /_soland/self/account/erase rail was intentionally removed; the spec entry point " +
        "moved to the Account Authority gate face (account-lifecycle.md §8.1 " +
        "ak.gate.account.command.request_erasure.v1, POST /_arkret/gate/account/erasure-requests); the spec " +
        "questions closed (spec-done 2026-08-18-2325/2326) — blocked on the coauth gate-face " +
        "implementation (arkret-work work/active/2026-08-19-2212)",
    );
    const alice = uniqueUser("s28-erased-alice");
    const bob = uniqueUser("s28-erased-bob");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const erase = await request.post(
      `${solandBaseUrl()}/_soland/self/account/erase`,
      {
        headers: authHeaders(aliceToken),
      },
    );
    expect(erase.status()).toBe(200);
    const eraseBody = await erase.json();
    expect(eraseBody.state).toBe("erasure_pending");
    const auditActions = (
      eraseBody.audit_log as Array<{ action: string; target?: unknown }>
    ).map((event) => event.action);
    expect(auditActions).toContain("org.arkret.soland.account.state_change");
    expect(JSON.stringify(eraseBody.audit_log)).toContain(
      '"to":"erasure_pending"',
    );

    const oldMe = await request.get(
      `${solandBaseUrl()}/_soland/self/account/me`,
      {
        headers: authHeaders(aliceToken),
      },
    );
    expect(oldMe.status()).toBe(401);
    expect(wireErrCode(await oldMe.json())).toBe("account_erased");

    const search = await request.post(
      `${solandBaseUrl()}/_arkret/find/directory/search-actors`,
      {
        headers: authHeaders(bobToken),
        data: { query: alice.handle },
      },
    );
    expect(search.status()).toBe(200);
    const searchBody = await search.json();
    expect(
      (
        searchBody.actors as Array<{
          actor_id?: string;
          preview?: { did?: string };
        }>
      ).some(
        (row) => row.actor_id === alice.did || row.preview?.did === alice.did,
      ),
    ).toBe(false);
  });

  test("audit: each state transition writes org.arkret.soland.account.state_change with from/to/actor/reason/timestamp", async ({
    request,
  }) => {
    const alice = uniqueUser("s28-audit-alice");
    const admin = uniqueUser("s28-audit-admin");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, admin),
    ]);
    const adminToken = await issueDevSession(request, admin);

    const suspend = await request.post(
      `${solandBaseUrl()}/_soland/admin/accounts/${alice.did}/suspend`,
      {
        headers: authHeaders(adminToken),
        data: { reason: "audit_probe" },
      },
    );
    expect(suspend.status()).toBe(200);

    const audit = await request.get(
      `${solandBaseUrl()}/_soland/admin/audit/events?actor=${encodeURIComponent(admin.did)}&limit=20`,
      { headers: authHeaders(adminToken) },
    );
    expect(audit.status()).toBe(200);
    const auditBody = await audit.json();
    const transition = (
      auditBody.events as Array<{
        action: string;
        payload: Record<string, unknown>;
      }>
    ).find(
      (event) =>
        event.action === "org.arkret.soland.account.state_change" &&
        event.payload?.subject === alice.did,
    );
    expect(transition).toBeTruthy();
    expect(transition!.payload.from).toBe("active");
    expect(transition!.payload.to).toBe("suspended");
    expect(transition!.payload.actor).toBe(admin.did);
    expect(transition!.payload.reason).toBe("audit_probe");
    expect(transition!.payload.timestamp).toBeTruthy();
  });
});
