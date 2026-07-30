// Contract: e2e/scenarios/events/batch-realm-bootstrap.md
// Regression guard for the registered Realm genesis transaction and its
// `(realm_id, actor_id)` authoring frontier.

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  queryRealmEventsApi,
  REALM_FOUNDING_GRANT_ACTIONS,
  sendMessageApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe("events submit batch Realm bootstrap @fully-implemented", () => {
  test("authors genesis as 0 -> 1 -> 2 without a pre-existing frontier", async ({
    request,
  }) => {
    const alice = uniqueUser("events-batch-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = typedId("realm");

    const missingFrontier = await request.get(
      `${solandBaseUrl()}/_arkret/self/events/frontier?actor_id=${encodeURIComponent(alice.did)}&realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(
      missingFrontier.status(),
      "a not-yet-created Realm must not expose a synthetic empty frontier",
    ).toBe(404);

    await createRealmApi(request, aliceToken, {
      realm_id: realmId,
      created_at: canonicalTimestamp(),
      ownerDid: alice.did,
      title: `Batch bootstrap ${Date.now()}`,
      summary: "cotest registered Realm genesis regression fixture",
      encryption_profile: "none",
    });

    const timeline = await queryRealmEventsApi(request, aliceToken, realmId);
    const events = (timeline.events ?? []) as Array<Record<string, unknown>>;
    const create = events.find((event) => event.kind === "ak.realm.create");
    const foundingGrant = events.find(
      (event) => event.kind === "ak.capability.grant",
    );
    const plaintextVisibleServices = events.find(
      (event) => event.kind === "ak.realm.plaintext_visible_services",
    );
    expect(create, "accepted Realm create Event").toBeTruthy();
    expect(foundingGrant, "accepted founding grant Event").toBeTruthy();
    expect(
      plaintextVisibleServices,
      "accepted plaintext-visible-services facet Event",
    ).toBeTruthy();
    expect(create!.actor_seq).toBe(0);
    expect(create!.prev_refs).toEqual([]);
    expect(
      (create!.payload as { object?: Record<string, unknown> }).object,
    ).not.toHaveProperty("plaintext_visible_services");
    expect(foundingGrant!.actor_seq).toBe(1);
    expect(foundingGrant!.prev_refs).toEqual([create!.event_id]);
    expect(
      (
        foundingGrant!.payload as {
          grant?: { actions?: string[] };
        }
      ).grant?.actions,
    ).toEqual([...REALM_FOUNDING_GRANT_ACTIONS]);
    expect(plaintextVisibleServices!.actor_seq).toBe(2);
    expect(plaintextVisibleServices!.prev_refs).toEqual([
      foundingGrant!.event_id,
    ]);

    const frontierResponse = await request.get(
      `${solandBaseUrl()}/_arkret/self/events/frontier?actor_id=${encodeURIComponent(alice.did)}&realm_id=${encodeURIComponent(realmId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(frontierResponse.status()).toBe(200);
    const frontierBody = (await frontierResponse.json()) as {
      frontier?: {
        kind?: string;
        realm_id?: string;
        actor_id?: string;
        next_actor_seq?: number;
        frontier_event_ids?: string[];
      };
    };
    expect(frontierBody.frontier).toMatchObject({
      kind: "realm_actor",
      realm_id: realmId,
      actor_id: alice.did,
      next_actor_seq: 3,
      frontier_event_ids: [plaintextVisibleServices!.event_id],
    });

    const message = await sendMessageApi(
      request,
      aliceToken,
      realmId,
      "owner write after registered Realm genesis",
    );
    expect(message.actor_seq).toBe(3);
    expect(message.prev_refs).toEqual([plaintextVisibleServices!.event_id]);
  });
});
