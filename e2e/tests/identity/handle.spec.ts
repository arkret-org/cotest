// Handle claim / transfer / release / conflict
// Contract: e2e/scenarios/identity/handle.md
// Spec: identity/identity-handles.md

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { wireErrCode } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

// GAP-identity-handle-claim — demoted from @fully-implemented.
// The self-service handle surface this suite exercises has been removed:
//   - GET  /_soland/self/account/me            (account viewer moved to the
//                                                spec /_cokret/self/account/viewer)
//   - POST /_soland/self/account/handle         (claim/rename — removed)
//   - POST /_soland/self/account/handle/transfer (transfer — removed)
// The spec replacement is a *signed handle claim* (identity-handles.md §3.2.2),
// surfaced via account viewer `primary_handle_claim`. soland's account_viewer
// currently hardcodes `primary_handle_claim: None` (account.rs) and exposes no
// bare `handle`, so there is no working backing path to assert against. Restore
// to @fully-implemented once handle-claim issuance + viewer projection land.
test.describe.fixme("handle management", () => {
  test("baseline: alice has the handle assigned at registration", async ({ request }) => {
    const alice = uniqueUser("s29-baseline");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const meResp = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(meResp.ok()).toBeTruthy();
    const me = await meResp.json();
    expect(me.handle).toBe(alice.handle);
  });

  test("alice claims a new handle via POST /_soland/self/account/handle; profile.handle updates; directory resolve_handle finds alice", async ({
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
    const claim = await request.post(`${solandBaseUrl()}/_soland/self/account/handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: newHandle },
    });
    expect(claim.status()).toBe(200);
    const claimBody = await claim.json();
    expect(claimBody.handle).toBe(newHandle.toLowerCase());
    expect(claimBody.previous_handle).toBe(alice.handle.toLowerCase());

    // /account/me reflects the new handle.
    const me = await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer ${aliceToken}` },
    });
    expect(me.ok()).toBeTruthy();
    expect((await me.json()).handle).toBe(newHandle.toLowerCase());

    // Directory resolve_handle finds alice by the new handle.
    const resolve = await request.post(`${solandBaseUrl()}/_cokret/find/directory/resolve-handle`, {
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

    const claim = await request.post(`${solandBaseUrl()}/_soland/self/account/handle`, {
      headers: { authorization: `Bearer ${malloryToken}` },
      data: { handle: alice.handle },
    });
    expect(claim.status()).toBe(409);
    const body = await claim.json();
    expect(wireErrCode(body)).toBe("handle_already_claimed");
  });

  test("handle transfer: alice transfers handle to bob; bob's profile.handle becomes the transferred handle; alice's clears to a synthetic placeholder", async ({
    request,
  }) => {
    // spec: identity/identity-handles.md — handle transfer is a dual
    // operation: source clears, target receives. Verified via
    // `POST /_soland/self/account/handle/transfer`.
    const stamp = Date.now();
    const alice = uniqueUser(`s29-transfer-alice-${stamp}`);
    const bob = uniqueUser(`s29-transfer-bob-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);

    const transferred = alice.handle; // alice's handle string at registration time.
    const transfer = await request.post(
      `${solandBaseUrl()}/_soland/self/account/handle/transfer`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { target_did: bob.did },
      },
    );
    expect(transfer.status()).toBe(200);
    const transferBody = await transfer.json();
    expect(transferBody.handle).toBe(transferred.toLowerCase());
    expect(transferBody.to_did).toBe(bob.did);
    expect(transferBody.from_did).toBe(alice.did);
    // alice now carries a synthetic placeholder (not the transferred handle).
    expect(transferBody.from_handle).not.toBe(transferred.toLowerCase());

    // /account/me on each side reflects the new mapping.
    const aliceMe = await (await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer ${aliceToken}` },
    })).json();
    expect(aliceMe.handle).not.toBe(transferred.toLowerCase());
    const bobMe = await (await request.get(`${solandBaseUrl()}/_soland/self/account/me`, {
      headers: { authorization: `Bearer ${bobToken}` },
    })).json();
    expect(bobMe.handle).toBe(transferred.toLowerCase());
  });

  test("grace period: released handle cannot be claimed immediately; claim after the grace window succeeds", async ({
    request,
  }) => {
    // spec: identity/identity-handles.md — released handles enter a
    // cooldown so stale references resolve gracefully. Dev grace window
    // is HANDLE_GRACE_PERIOD_SECONDS = 5s; test rides that timer.
    const stamp = Date.now();
    const alice = uniqueUser(`s29-grace-alice-${stamp}`);
    const mallory = uniqueUser(`s29-grace-mallory-${stamp}`);
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, mallory)]);
    const aliceToken = await issueDevSession(request, alice);
    const malloryToken = await issueDevSession(request, mallory);

    const releasedHandle = alice.handle;
    // alice renames → original handle is released into grace.
    const rename = await request.post(`${solandBaseUrl()}/_soland/self/account/handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: `@alice-renamed-${stamp}` },
    });
    expect(rename.status()).toBe(200);

    // mallory's immediate claim is rejected with handle_in_grace_period.
    const immediate = await request.post(`${solandBaseUrl()}/_soland/self/account/handle`, {
      headers: { authorization: `Bearer ${malloryToken}` },
      data: { handle: releasedHandle },
    });
    expect(immediate.status()).toBe(409);
    const immediateBody = await immediate.json();
    expect(wireErrCode(immediateBody)).toBe("handle_in_grace_period");

    // After the grace window (5s) mallory's claim succeeds.
    await new Promise((resolve) => setTimeout(resolve, 6000));
    const afterGrace = await request.post(`${solandBaseUrl()}/_soland/self/account/handle`, {
      headers: { authorization: `Bearer ${malloryToken}` },
      data: { handle: releasedHandle },
    });
    expect(afterGrace.status()).toBe(200);
    expect((await afterGrace.json()).handle).toBe(releasedHandle.toLowerCase());
  });

  test("E29.1 invalid handle format (too short / disallowed chars) is rejected with handle_invalid_format", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s29-format-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    // "@" alone normalizes to "@" which fails is_valid_handle (len > 1).
    const tooShort = await request.post(`${solandBaseUrl()}/_soland/self/account/handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: "@" },
    });
    expect(tooShort.status()).toBe(400);
    const tooShortBody = await tooShort.json();
    expect(wireErrCode(tooShortBody)).toBe("handle_invalid_format");

    // Disallowed character (`!`) fails the alnum + -_. allowlist.
    const badChar = await request.post(`${solandBaseUrl()}/_soland/self/account/handle`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: { handle: `@bad!handle-${stamp}` },
    });
    expect(badChar.status()).toBe(400);
    const badCharBody = await badChar.json();
    expect(wireErrCode(badCharBody)).toBe("handle_invalid_format");
  });

  test("E29.2 transfer to non-existent DID is rejected with target_did_unknown", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser(`s29-e292-${stamp}`);
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const transfer = await request.post(
      `${solandBaseUrl()}/_soland/self/account/handle/transfer`,
      {
        headers: { authorization: `Bearer ${aliceToken}` },
        data: { target_did: `did:web:ghost-${stamp}.example` },
      },
    );
    expect(transfer.status()).toBe(404);
    const body = await transfer.json();
    expect(wireErrCode(body)).toBe("target_did_unknown");
  });
});
