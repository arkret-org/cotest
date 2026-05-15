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

  test.fixme(
    "alice claims a new handle via cx.handle.claim; profile.handle updates; directory search by new handle finds alice",
    async () => {
      // spec: identity-handles.md
    },
  );

  test.fixme(
    "handle conflict: mallory attempts to claim alice's current handle → rejected with handle_already_claimed",
    async () => {},
  );

  test.fixme(
    "handle transfer: alice transfers handle to bob (alice signs cx.handle.transfer); bob's profile.handle becomes the transferred handle; alice's clears or rolls back",
    async () => {},
  );

  test.fixme(
    "grace period: released handle cannot be claimed for N days; mallory's immediate claim is rejected, claim after grace succeeds",
    async () => {},
  );

  test.fixme(
    "E29.1 invalid handle format (too short / disallowed chars) is rejected with handle_invalid_format",
    async () => {},
  );

  test.fixme(
    "E29.2 transfer to non-existent DID is rejected with target_did_unknown",
    async () => {},
  );
});
