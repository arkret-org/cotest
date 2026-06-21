// history_visibility=world_readable allows non-members and anonymous read
// Contract: e2e/scenarios/spaces/history-world-readable.md
// Spec: models/realm-and-space.md §3.4 (cross-table), §3.7 (privacy + non-E2EE only),
//        §3.1.3 (mls_rfc9420 + world_readable incompatible)
// E2E-WORLD-READ-1 — soland/_todos.md.

import { randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { request as playwrightRequest } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { eventProof, singleDidNotary, wireErrCode } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("world_readable history @fully-implemented", () => {
  test("alice creates Realm with history_visibility=world_readable; outsider (registered, non-member) reads timeline via API", async ({
    browser,
    request,
  }) => {
    // spec: realm-and-space.md §3.4 — non-members can read events when
    // history_visibility=world_readable, even on listed/non-public Realms.
    const stamp = Date.now();
    const alice = uniqueUser("worldread-alice");
    const outsider = uniqueUser("worldread-outsider");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, outsider),
    ]);
    const aliceToken = await issueDevSession(request, alice);
    const outsiderToken = await issueDevSession(request, outsider);
    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `worldread ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "world_readable",
        encryptionProfile: "none",
      });

      // outsider is registered but NOT a member; with world_readable the
      // events query MUST succeed for them.
      const events = await request.get(
        `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}`,
        { headers: { authorization: `Bearer ${outsiderToken}` } },
      );
      expect(events.status()).toBe(200);
      const body = await events.json();
      // Response shape is the spec's `ck.self.events.query.scan` envelope; we only
      // need the request to be accepted, not its body content.
      expect(body).toBeDefined();
    } finally {
      await alicePage.close();
    }
  });

  test("anonymous (no session token) GET /_cokret/self/events succeeds when history_visibility=world_readable", async ({
    browser,
    request,
  }) => {
    // spec: realm-and-space.md §3.7 — world_readable also opens the read
    // endpoint to anonymous (no bearer) callers. Discoverability remains
    // `listed`, so the Realm won't appear in unauthenticated directory
    // queries, but its event stream is readable by id.
    const stamp = Date.now();
    const alice = uniqueUser("worldread-anon-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `worldread anon ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "world_readable",
        encryptionProfile: "none",
      });

      // Use a clean request context with no auth header to be sure.
      const anonRequest = await playwrightRequest.newContext({});
      try {
        const anonResp = await anonRequest.get(
          `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}`,
        );
        expect(anonResp.status()).toBe(200);
      } finally {
        await anonRequest.dispose();
      }
    } finally {
      await alicePage.close();
    }
  });

  test("outsider's WRITE on world_readable Realm is rejected (read-only public access)", async ({
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
    const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });

    try {
      const realmId = await alicePage.createRealm({
        title: `S1.3 World ${stamp}`,
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "world_readable",
        encryptionProfile: "none",
      });

      // outsider attempts to write a message via API — must be denied even with
      // world_readable history (capability is not granted to non-members).
      const write = await request.post(
        `${solandBaseUrl()}/_soland/self/realms/${encodeURIComponent(realmId)}/messages`,
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
    // spec: realm-and-space.md §2.3 — encrypted Realms cannot be
    // world_readable (non-members lack the group key).
    const alice = uniqueUser("incompat-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);

    const event = encryptedWorldReadableRealmCreateEvent(alice.did);
    const create = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: { authorization: `Bearer ${aliceToken}` },
      data: event,
    });
    expect([400, 422]).toContain(create.status());
    const body = await create.json();
    expect(wireErrCode(body)).toBe("incompatible_history_with_encryption");
  });
});

function encryptedWorldReadableRealmCreateEvent(actorDid: string): Record<string, unknown> {
  const realmId = `ck:realm:${uuidV7()}`;
  const createdAt = canonicalTimestamp();
  const payload = {
    object: {
      id: realmId,
      schema: "ck.schema.realm.v1",
      title: `incompat ${Date.now()}`,
      created_by: actorDid,
      trust_domain: "ck:trust_domain:soland.local",
      schema_refs: ["ck.schema.realm.v1"],
      default_discoverability: "listed",
      default_join_rule: "invite",
      history_visibility: "world_readable",
      encryption_profile: "mls_rfc9420",
      security_class: "standard",
      federation_policy: "restricted",
      notary_profile: "single_did",
      digest_algorithm: "sha256",
      notary: singleDidNotary(actorDid),
      created_at: createdAt,
    },
  };
  const event = {
    event_id: `ck:event:${uuidV7()}`,
    kind: "ck.realm.create",
    realm_id: realmId,
    actor_id: actorDid,
    actor_seq: 1,
    created_at: createdAt,
    prev_refs: [],
    refs: [],
    requirements: {
      schema: ["ck.schema.realm.v1"],
      features: [],
      critical_extensions: [],
    },
    payload,
  };
  return {
    ...event,
    proofs: [eventProof({ actorDid, event })],
  };
}

function canonicalTimestamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function uuidV7(): string {
  const time = Date.now().toString(16).padStart(12, "0").slice(-12);
  const random = randomBytes(9).toString("hex");
  const variant = (8 + (randomBytes(1)[0] & 0x03)).toString(16);
  return [
    time.slice(0, 8),
    time.slice(8, 12),
    `7${random.slice(0, 3)}`,
    `${variant}${random.slice(3, 6)}`,
    random.slice(6, 18),
  ].join("-");
}
