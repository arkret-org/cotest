// Contract: e2e/scenarios/events/batch-realm-bootstrap.md
// Regression guard for the registered Realm genesis transaction and its
// `(realm_id, actor_id)` authoring frontier.

import { expect, test } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  queryRealmEventsApi,
  sendMessageApi,
  submitSignedEventBatchApi,
  type AcceptedRealmBootstrap,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe("events submit batch Realm bootstrap @fully-implemented", () => {
  test("authors genesis as 0 -> 1 without a pre-existing frontier", async ({
    request,
  }) => {
    const alice = uniqueUser("events-batch-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const missingRealmId =
      "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    // `ak.self.events.read.frontier.v1` registers a QUERY binding only
    // (service-http-binding.md); a GET falls through to `events/{event_id}`
    // and its 404 would pass for the wrong reason.
    const frontierUrl = `${solandBaseUrl()}/_arkret/self/events/frontier`;
    const missingFrontier = await request.fetch(frontierUrl, {
      method: "QUERY",
      headers: {
        ...authHeaders(aliceToken, "QUERY", frontierUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({ actor_id: alice.id, realm_id: missingRealmId }),
    });
    expect(
      missingFrontier.status(),
      "a not-yet-created Realm must not expose a synthetic empty frontier",
    ).toBe(404);

    let acceptedBootstrap: AcceptedRealmBootstrap | undefined;
    const realmId = await createRealmApi(request, aliceToken, {
      created_at: canonicalTimestamp(),
      ownerId: alice.id,
      title: `Batch bootstrap ${Date.now()}`,
      summary: "cotest registered Realm genesis regression fixture",
      encryption_profile: "none",
    }, {
      onAcceptedBootstrap: (bootstrap) => {
        acceptedBootstrap = bootstrap;
      },
    });
    expect(acceptedBootstrap, "accepted bootstrap capture").toBeDefined();

    const timeline = await queryRealmEventsApi(request, aliceToken, realmId);
    const events = ((timeline.events ?? []) as Array<Record<string, unknown>>)
      .filter((event) => event.actor_id === alice.id)
      .sort((left, right) => Number(left.actor_seq) - Number(right.actor_seq));
    const expectedKinds = [
      "ak.realm.create",
      "ak.realm.profile",
      "ak.realm.policy_bundle",
      "ak.realm.join_rule",
      "ak.realm.history_access",
      "ak.realm.discovery",
      "ak.realm.plaintext_visible_services",
      "ak.realm.delivery_binding_policy",
      "ak.member.state",
    ];
    expect(events.map((event) => event.kind)).toEqual(expectedKinds);

    // realm-and-space.md section 2.7: an ordinary Collaboration bootstrap
    // establishes the creator's membership ONLY through the atomic unit's last
    // standalone `ak.member.state{membership="join"}`. That slot is the genesis
    // write of the creator's own member cell, so it MUST carry `head_eq null`,
    // and `ak.realm.create` MUST NOT write membership implicitly — which is why
    // exactly one member cell write may exist in the whole founding unit.
    const timelineEvents = (timeline.events ?? []) as Array<
      Record<string, unknown>
    >;
    const memberStates = timelineEvents.filter(
      (event) => event.kind === "ak.member.state",
    );
    expect(
      memberStates.map((event) => event.event_id),
      "genesis carries exactly one membership write",
    ).toEqual([events.at(-1)!.event_id]);
    const creatorMembership = events.at(-1)!;
    expect(
      creatorMembership.actor_id,
      "the creator membership slot is authored by the creator",
    ).toBe(alice.id);
    expect(creatorMembership.payload).toMatchObject({
      realm_id: realmId,
      actor_id: alice.id,
      membership: "join",
    });
    expect(
      creatorMembership.preconditions,
      "the creator member cell genesis write MUST carry head_eq null",
    ).toEqual([
      {
        cell_id: `ak:cell:ak.component.member.state.v1:${alice.id}`,
        predicate: { op: "head_eq", value: null },
      },
    ]);
    // The same slot has to sit inside the atomic unit the genesis Seal covers,
    // not arrive as a follow-up write after bootstrap.
    expect(
      String(acceptedBootstrap!.events.at(-1)!.event_id),
      "the membership slot belongs to the sealed genesis unit",
    ).toBe(String(creatorMembership.event_id));

    const create = events.find((event) => event.kind === "ak.realm.create");
    expect(create, "accepted Realm create Event").toBeTruthy();
    // realm-and-space.md section 2.5: v1 deleted the founding
    // `ak.capability.grant` slot. Genesis authority is the authority-root cell
    // the create Event's registered reducer contract writes, so an ordinary
    // Realm genesis batch MUST carry no capability grant at all.
    expect(
      events.some((event) => event.kind === "ak.capability.grant"),
      "genesis carries no founding capability grant",
    ).toBe(false);
    expect(create!.actor_seq).toBe(0);
    expect(create!.prev_refs).toEqual([]);
    const createObject = (create!.payload as { object?: Record<string, unknown> }).object;
    expect(createObject).not.toHaveProperty("title");
    expect(createObject).not.toHaveProperty("summary");
    expect(createObject).not.toHaveProperty("plaintext_visible_services");
    expect(String(createObject?.genesis_salt)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    events.forEach((event, index) => {
      expect(event.actor_seq).toBe(index);
      expect(event.prev_refs).toEqual(index === 0 ? [] : [events[index - 1]!.event_id]);
    });

    const first = acceptedBootstrap!;
    const eventIds = first.events.map((event) => String(event.event_id));
    expect(first.outcome.accepted).toEqual(eventIds);
    const duplicate = await submitSignedEventBatchApi(
      request,
      aliceToken,
      structuredClone(first.events),
      { context: `retry accepted Realm bootstrap ${realmId}` },
    );
    expect(duplicate.accepted ?? []).toEqual([]);
    expect(duplicate.duplicate).toEqual(eventIds);
    expect(duplicate.ingress_receipts).toEqual(first.outcome.ingress_receipts);

    const afterRetry = await queryRealmEventsApi(request, aliceToken, realmId);
    const afterRetryEvents = (afterRetry.events ?? []) as Array<Record<string, unknown>>;
    for (const eventId of eventIds) {
      expect(afterRetryEvents.filter((event) => event.event_id === eventId)).toHaveLength(1);
    }

    const frontierResponse = await request.fetch(frontierUrl, {
      method: "QUERY",
      headers: {
        ...authHeaders(aliceToken, "QUERY", frontierUrl),
        "content-type": "application/json",
      },
      data: canonicalJson({ actor_id: alice.id, realm_id: realmId }),
    });
    const frontierText = await frontierResponse.text();
    expect(
      frontierResponse.status(),
      `query actor frontier returned ${frontierResponse.status()}: ${frontierText}`,
    ).toBe(200);
    const frontierBody = JSON.parse(frontierText) as {
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
      actor_id: alice.id,
      next_actor_seq: events.length,
      frontier_event_ids: [events.at(-1)!.event_id],
    });

    const message = await sendMessageApi(
      request,
      aliceToken,
      realmId,
      "owner write after registered Realm genesis",
    );
    // An ordinary Realm bootstrap intentionally has no implicit Strand. The
    // message helper must therefore author the default discussion Strand and
    // the Realm's authoritative default-Strand pointer before the Message.
    // All three writes must continue the same accepted actor frontier.
    const afterMessage = await queryRealmEventsApi(request, aliceToken, realmId);
    const continuedEvents = (
      (afterMessage.events ?? []) as Array<Record<string, unknown>>
    )
      .filter((event) => event.actor_id === alice.id)
      .sort((left, right) => Number(left.actor_seq) - Number(right.actor_seq));
    expect(continuedEvents.slice(events.length).map((event) => event.kind)).toEqual([
      "ak.strand.create",
      "ak.realm.set_default_strand",
      "ak.message.create",
    ]);
    continuedEvents.forEach((event, index) => {
      expect(event.actor_seq).toBe(index);
      expect(event.prev_refs).toEqual(
        index === 0 ? [] : [continuedEvents[index - 1]!.event_id],
      );
    });
    expect(message.actor_seq).toBe(events.length + 2);
    expect(message.prev_refs).toEqual([
      continuedEvents.at(-2)!.event_id,
    ]);
  });
});
