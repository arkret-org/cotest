// history_visibility=world_readable allows non-members and anonymous read
// Contract: e2e/scenarios/spaces/history-world-readable.md
// Spec: models/space-and-place.md §3.4 (cross-table), §3.7 (privacy + non-E2EE only),
//        §3.1.3 (mls_rfc9420 + world_readable incompatible)
// E2E-WORLD-READ-1 — soland/_todos.md.

import { expect, test } from "@playwright/test";
import { request as playwrightRequest } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("world_readable history @fully-implemented", () => {
  test("alice creates space with history_visibility=world_readable; outsider (registered, non-member) reads timeline via API", async ({
    browser,
    request,
  }) => {
    // spec: space-and-place.md §3.4 — non-members can read events when
    // history_visibility=world_readable, even on listed/non-public spaces.
    const stamp = Date.now();
    const alice = uniqueUser("worldread-alice");
    const outsider = uniqueUser("worldread-outsider");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, outsider),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const outsiderToken = await issueDevSession(request, outsider);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `worldread ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "world_readable",
      });

      // outsider is registered but NOT a member; with world_readable the
      // events query MUST succeed for them.
      const events = await request.get(
        `${solandBaseUrl()}/api/v1/events?space_id=${encodeURIComponent(spaceId)}`,
        { headers: { authorization: `Bearer ${outsiderToken}` } },
      );
      expect(events.status()).toBe(200);
      const body = await events.json();
      // Response shape is the spec's `cx.events.query` envelope; we only
      // need the request to be accepted, not its body content.
      expect(body).toBeDefined();
    } finally {
      await alicePage.close();
    }
  });

  test("anonymous (no session token) GET /api/v1/events succeeds when history_visibility=world_readable", async ({
    browser,
    request,
  }) => {
    // spec: space-and-place.md §3.7 — world_readable also opens the read
    // endpoint to anonymous (no bearer) callers. Discoverability remains
    // `listed`, so the space won't appear in unauthenticated directory
    // queries, but its event stream is readable by id.
    const stamp = Date.now();
    const alice = uniqueUser("worldread-anon-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `worldread anon ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "world_readable",
      });

      // Use a clean request context with no auth header to be sure.
      const anonRequest = await playwrightRequest.newContext({});
      try {
        const anonResp = await anonRequest.get(
          `${solandBaseUrl()}/api/v1/events?space_id=${encodeURIComponent(spaceId)}`,
        );
        expect(anonResp.status()).toBe(200);
      } finally {
        await anonRequest.dispose();
      }
    } finally {
      await alicePage.close();
    }
  });

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
      expect([401, 403, 404, 405]).toContain(write.status());
    } finally {
      await alicePage.close();
    }
  });

  test("E1.3.1 trying to set encryption_profile=mls_rfc9420 AND history_visibility=world_readable is rejected with incompatible_history_with_encryption", async ({
    request,
  }) => {
    // spec: space-and-place.md §3.1.3 — MLS-encrypted Spaces cannot be
    // world_readable (non-members lack the group key).
    const stamp = Date.now();
    const alice = uniqueUser("incompat-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const create = await request.post(`${solandBaseUrl()}/api/v1/spaces`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: {
        title: `incompat ${stamp}`,
        history_visibility: "world_readable",
        encryption_profile: "mls_rfc9420",
      },
    });
    expect([400, 422]).toContain(create.status());
    const body = await create.json();
    const code = body?.error?.errcode ?? body?.errcode;
    expect(code).toBe("incompatible_history_with_encryption");
  });
});
