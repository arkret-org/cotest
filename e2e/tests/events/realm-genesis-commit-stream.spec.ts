// Contract: e2e/scenarios/events/realm-genesis-commit-stream.md
// Regression guard for Realm genesis under the authority-commit protocol.
//
// Replaces the retired `batch-realm-bootstrap` spec. Genesis is no longer a
// client-side batch bound to an `(realm_id, actor_id)` authoring frontier: one
// registered atomic unit returns one RealmCommit per founding Event. The
// producer Event carries no position, predecessor, precondition or Cell write,
// so every ordering claim below is read off the commits instead.

import { expect, test } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";
import {
  accountActorId,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  scanRealmStreamApi,
  sendMessageApi,
  type AcceptedRealmBootstrap,
} from "../../helpers/coland-api";
import {
  ensureRegistered,
  issueUserSession,
  uniqueUser,
} from "../../helpers/users";

/// Members a producer Event must never carry again. Ordering, linkage and
/// coverage are properties of the commit, not of the authored envelope.
const RETIRED_ENVELOPE_MEMBERS = [
  "actor_seq",
  "prev_refs",
  "preconditions",
  "hlc",
  "seal_ref",
  "cell_writes",
  "basis",
];

test.describe("Realm genesis commit stream @fully-implemented", () => {
  test("the founding unit takes consecutive Realm stream positions from zero", async ({
    request,
  }) => {
    const alice = uniqueUser("realm-genesis-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
    const actor = accountActorId(alice.id);

    let acceptedBootstrap: AcceptedRealmBootstrap | undefined;
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        created_at: canonicalTimestamp(),
        ownerId: alice.id,
        title: `Realm genesis ${Date.now()}`,
        summary: "cotest Realm genesis commit-stream regression fixture",
        mls_activated: false,
      },
      {
        onAcceptedBootstrap: (bootstrap) => {
          acceptedBootstrap = bootstrap;
        },
      },
    );
    expect(acceptedBootstrap, "accepted bootstrap capture").toBeDefined();

    const scan = await scanRealmStreamApi(request, aliceToken, realmId);
    expect(scan.truncated, "the founding unit fits in one scan page").toBe(
      false,
    );
    expect(
      scan.events.map((event) => event.kind),
      "the founding unit is the genesis plus its initial policy and membership",
    ).toEqual([
      "ak.realm.create",
      "ak.realm.profile",
      "ak.realm.policy_bundle",
      "ak.realm.join_rule",
      "ak.realm.history_access",
      "ak.realm.discovery",
      "ak.realm.plaintext_visible_services",
      "ak.member.state",
    ]);

    // Every commit belongs to this Realm's own stream, at position n, naming
    // the commit before it. There is no Realm-global chain to compare against.
    scan.commits.forEach((commit, index) => {
      expect(commit.stream_ref, `commit ${index} left the Realm stream`).toEqual(
        { kind: "realm", realm_id: realmId },
      );
      expect(commit.stream_position, `commit ${index} position`).toBe(index);
      expect(
        commit.previous_commit_ref ?? null,
        `commit ${index} predecessor`,
      ).toEqual(index === 0 ? null : scan.commits[index - 1]!.commit_id);
      expect(commit.event_ref, `commit ${index} names its Event`).toBe(
        scan.events[index]!.event_id,
      );
    });

    for (const event of scan.events) {
      for (const member of RETIRED_ENVELOPE_MEMBERS) {
        expect(
          member in event,
          `${String(event.kind)} reintroduced the retired envelope member ${member}`,
        ).toBe(false);
      }
    }

    // Genesis owns the closed `realm-genesis.schema.json` object: the display
    // and visibility facets are their own Events, and v1 has no founding
    // capability grant at all.
    const create = scan.events[0]!;
    const createObject = (create.payload as { object?: Record<string, unknown> })
      .object;
    expect(createObject).not.toHaveProperty("title");
    expect(createObject).not.toHaveProperty("summary");
    expect(createObject).not.toHaveProperty("plaintext_visible_services");
    expect(String(createObject?.governance_station_id)).toMatch(/^ak:did_core:/);
    expect(String(createObject?.genesis_salt)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      scan.events.some((event) => event.kind === "ak.capability.grant"),
      "genesis carries no founding capability grant",
    ).toBe(false);

    // Exactly one membership write, authored by the creator, inside the unit.
    const memberStates = scan.events.filter(
      (event) => event.kind === "ak.member.state",
    );
    expect(
      memberStates.map((event) => event.event_id),
      "genesis carries exactly one membership write",
    ).toEqual([scan.events.at(-1)!.event_id]);
    expect(
      memberStates[0]!.actor_id,
      "the creator membership slot is authored by the creator",
    ).toEqual(actor);
    expect(memberStates[0]!.payload).toMatchObject({
      member_id: actor,
      membership: "join",
    });
  });

  test("replaying the complete bootstrap returns its original commits without new positions", async ({
    request,
  }) => {
    const alice = uniqueUser("realm-genesis-retry");
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);

    let acceptedBootstrap: AcceptedRealmBootstrap | undefined;
    const realmId = await createRealmApi(
      request,
      aliceToken,
      {
        created_at: canonicalTimestamp(),
        ownerId: alice.id,
        title: `Realm genesis retry ${Date.now()}`,
        mls_activated: false,
      },
      {
        onAcceptedBootstrap: (bootstrap) => {
          acceptedBootstrap = bootstrap;
        },
      },
    );
    const before = await scanRealmStreamApi(request, aliceToken, realmId);

    const eventsUrl = `${colandBaseUrl()}/_arkret/self/events`;
    const response = await request.post(eventsUrl, {
      headers: { ...authHeaders(aliceToken, "POST", eventsUrl), "content-type": "application/json" },
      data: canonicalJson(acceptedBootstrap!.submission),
    });
    const text = await response.text();
    expect([200, 201], `bootstrap replay: ${response.status()}: ${text}`).toContain(response.status());
    const retry = JSON.parse(text) as Record<string, unknown>;
    expect(retry.unit_kind).toBe("ordinary_realm_bootstrap");
    expect(retry.status).toBe("duplicate");
    expect(retry.commits).toEqual(acceptedBootstrap!.outcome.commits);

    const after = await scanRealmStreamApi(request, aliceToken, realmId);
    expect(
      after.commits.map((commit) => commit.commit_id),
      "a duplicate submission leaves the stream unchanged",
    ).toEqual(before.commits.map((commit) => commit.commit_id));
  });

  test("an ordinary write continues the same Realm stream", async ({
    request,
  }) => {
    const alice = uniqueUser("realm-genesis-continue");
    await ensureRegistered(request, alice);
    const aliceToken = await issueUserSession(request, alice);
    const realmId = await createRealmApi(request, aliceToken, {
      created_at: canonicalTimestamp(),
      ownerId: alice.id,
      title: `Realm genesis continue ${Date.now()}`,
      mls_activated: false,
    });
    const founding = await scanRealmStreamApi(request, aliceToken, realmId);

    await sendMessageApi(
      request,
      aliceToken,
      realmId,
      "owner write after Realm genesis",
    );

    // An ordinary Realm has no implicit Strand, so the message helper authors
    // the default discussion Strand and the Realm's default-Strand pointer
    // first. All three continue the one Realm stream with no gap.
    const after = await scanRealmStreamApi(request, aliceToken, realmId);
    expect(
      after.events.slice(founding.events.length).map((event) => event.kind),
    ).toEqual([
      "ak.strand.create",
      "ak.realm.set_default_strand",
      "ak.message.create",
    ]);
    after.commits.forEach((commit, index) => {
      expect(commit.stream_position, `commit ${index} position`).toBe(index);
      expect(
        commit.previous_commit_ref ?? null,
        `commit ${index} predecessor`,
      ).toEqual(index === 0 ? null : after.commits[index - 1]!.commit_id);
    });
  });
});
