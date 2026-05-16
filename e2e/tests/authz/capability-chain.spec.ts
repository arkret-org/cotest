// Capability grant / revoke / delegate / constraints / audit
// Contract: e2e/scenarios/authz/capability-chain.md
// Spec: authz/capabilities.md §3, authz/event-auth-state-resolution.md §3

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("capability chain", () => {
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
      const spaceId = await alicePage.createSpace({
        title: `S20 baseline ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
      });

      // mallory (non-member, no capability) attempts to send a message via API.
      const send = await request.post(`${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/messages`, {
        headers: { authorization: `Bearer ${malloryToken}` },
        data: { content: { text: "mallory attempt" } },
      });
      expect([401, 403, 404, 405]).toContain(send.status());
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    "alice grants bob cx.space.write_message with expires_at=+1h; bob writes a message within the window",
    async () => {
      // spec: capabilities.md §3
    },
  );

  test.fixme(
    "bob delegates the capability to carol with stricter expires_at; carol writes via the delegation chain",
    async () => {
      // spec: capabilities.md §3.2
    },
  );

  test.fixme(
    "alice revokes bob's grant; cascade revokes carol's delegated capability; both subsequent writes rejected",
    async () => {
      // spec: capabilities.md §3.3 cascade
    },
  );

  test.fixme(
    "E20.1 over-grant: bob cannot delegate an action bob does not hold (capability_not_held)",
    async () => {},
  );

  test.fixme(
    "E20.2 over-expire: bob's delegation cannot exceed bob's own expiry",
    async () => {},
  );

  test.fixme(
    "audit log contains grant, delegate, revoke entries with grantor/grantee/timestamp/actions",
    async () => {
      // spec: capabilities.md §3.4
    },
  );
});
