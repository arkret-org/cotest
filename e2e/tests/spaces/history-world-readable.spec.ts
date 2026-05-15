// history_visibility=world_readable allows non-members and anonymous read
// Contract: e2e/scenarios/spaces/history-world-readable.md
// Spec: models/space-and-place.md §3.4 (cross-table), §3.7 (privacy + non-E2EE only)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("world_readable history", () => {
  test.fixme(
    "alice creates space with history_visibility=world_readable; outsider (registered, non-member) reads timeline via API",
    async () => {
      // spec: space-and-place.md §3.4
      // soland gap: API authz bypass for world_readable on read endpoints.
    },
  );

  test.fixme(
    "anonymous (no session token) GET /api/v1/spaces/<S>/events succeeds when history_visibility=world_readable",
    async () => {
      // spec: space-and-place.md §3.7
    },
  );

  test("outsider's WRITE on world_readable space is rejected (read-only public access)", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s13-alice");
    const outsider = uniqueUser("s13-outsider");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, outsider),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const outsiderToken = await issueDevSession(request, outsider);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S1.3 World ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "world_readable",
      });

      // outsider attempts to write a message via API — must be denied even with
      // world_readable history (capability is not granted to non-members).
      const write = await request.post(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/messages`,
        {
          headers: { authorization: `Bearer ${outsiderToken}` },
          data: { content: { text: "S1.3 outsider tries to write" } },
        },
      );
      expect([401, 403, 404]).toContain(write.status());
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    "E1.3.1 trying to set encryption_profile=mls_rfc9420 AND history_visibility=world_readable is rejected with incompatible_history_with_encryption",
    async () => {},
  );
});
