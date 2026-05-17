// Handle claim / transfer / release / conflict
// Contract: e2e/scenarios/identity/handle.md
// Spec: identity/identity-handles.md

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("handle management", () => {
  test("baseline: alice has the handle assigned at registration", async ({ request }) => {
    const alice = uniqueUser("s29-baseline");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const meResp = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(meResp.ok()).toBeTruthy();
    const me = await meResp.json();
    expect(me.handle).toBe(alice.handle);
  });

  test("alice claims a new handle via POST /api/v1/account/handle; profile.handle updates; directory resolve_handle finds alice", async ({
    request,
  }) => {
    // spec: identity/identity-handles.md §2 — handle claim updates the
    // authenticated principal's `profile.handle`, normalized lowercase
    // with leading `@`. Directory `POST /resolve-handle` MUST resolve
    // the new handle to alice's DID.
    const stamp = Date.now();
    const alice = uniqueUser(`s29-claim-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const newHandle = `@alice-renamed-${stamp}`;
    const claim = await request.post(`${solandBaseUrl()}/api/v1/account/handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: newHandle },
    });
    expect(claim.status()).toBe(200);
    const claimBody = await claim.json();
    expect(claimBody.handle).toBe(newHandle.toLowerCase());
    expect(claimBody.previous_handle).toBe(alice.handle.toLowerCase());

    // /account/me reflects the new handle.
    const me = await request.get(`${solandBaseUrl()}/api/v1/account/me`, {
      headers: { authorization: `Bearer ${aliceToken}` },
    });
    expect(me.ok()).toBeTruthy();
    expect((await me.json()).handle).toBe(newHandle.toLowerCase());

    // Directory resolve_handle finds alice by the new handle.
    const resolve = await request.post(`${solandBaseUrl()}/api/v1/directory/resolve-handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: newHandle },
    });
    expect(resolve.status()).toBe(200);
    const resolved = await resolve.json();
    expect(resolved.did).toBe(alice.did);
  });

  test("handle conflict: mallory attempts to claim alice's current handle → rejected with handle_already_claimed", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s29-conflict-alice-${stamp}`);
    const mallory = uniqueUser(`s29-conflict-mallory-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, mallory)]);
    const malloryToken = await issueDevSession(request, mallory);

    const claim = await request.post(`${solandBaseUrl()}/api/v1/account/handle`, {
      headers: { authorization: `Bearer ${malloryToken}` },
      data: { handle: alice.handle },
    });
    expect(claim.status()).toBe(409);
    const body = await claim.json();
    const code = body?.error?.errcode ?? body?.errcode;
    expect(code).toBe("handle_already_claimed");
  });

  test.fixme(
    "handle transfer: alice transfers handle to bob (alice signs cx.handle.transfer); bob's profile.handle becomes the transferred handle; alice's clears or rolls back",
    async () => {
      // server gap: cx.handle.transfer dual-sign flow + alice rollback path.
    },
  );

  test.fixme(
    "grace period: released handle cannot be claimed for N days; mallory's immediate claim is rejected, claim after grace succeeds",
    async () => {
      // server gap: handle release ledger + grace_period_ttl timer.
    },
  );

  test("E29.1 invalid handle format (too short / disallowed chars) is rejected with handle_invalid_format", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s29-format-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    // "@" alone normalizes to "@" which fails is_valid_handle (len > 1).
    const tooShort = await request.post(`${solandBaseUrl()}/api/v1/account/handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: "@" },
    });
    expect(tooShort.status()).toBe(400);
    const tooShortBody = await tooShort.json();
    expect(tooShortBody?.error?.errcode).toBe("handle_invalid_format");

    // Disallowed character (`!`) fails the alnum + -_. allowlist.
    const badChar = await request.post(`${solandBaseUrl()}/api/v1/account/handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: `@bad!handle-${stamp}` },
    });
    expect(badChar.status()).toBe(400);
    const badCharBody = await badChar.json();
    expect(badCharBody?.error?.errcode).toBe("handle_invalid_format");
  });

  test.fixme(
    "E29.2 transfer to non-existent DID is rejected with target_did_unknown",
    async () => {
      // server gap: paired with the transfer fixme above.
    },
  );
});
