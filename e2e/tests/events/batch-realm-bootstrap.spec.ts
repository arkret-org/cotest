// Contract: e2e/scenarios/events/batch-realm-bootstrap.md
// Regression guard for ck.self.events.command.submit batch responses and Realm creator
// membership materialization.

import { expect, test } from "@playwright/test";
import { solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  queryRealmEventsApi,
  sendMessageApi,
  signedEventEnvelope,
  singleDidNotary,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

// GAP-events-batch-strict-typed-event — demoted from @fully-implemented.
// The batch form of POST /_cokret/self/events deserializes its `events[]` as
// the SDK's strict `Event` (EventsSubmitBatchRequestBody.events: Vec<Event>,
// event_sync.rs), where `Event` is `#[serde(try_from = EventWire)]` with
// `deny_unknown_fields` + a required `hlc` and a spec-shaped `Proof`
// (kind/alg/verification_method/event_digest/created_at/jws). Crucially the
// non-dev-proof branch requires `event_digest == canonical envelope digest`
// (validation.rs) with no payload-only fallback, and the typed `Proof` cannot
// carry the dev-proof shorthand (no `type` field). cotest's fixture envelope is
// Value-shaped for the lenient single-event path and uses the dev-proof /
// payload-digest form, so it cannot satisfy the typed batch path without a
// dedicated strict-Event builder that reproduces soland's envelope
// canonicalization. Restore once such a builder exists.
test.describe.fixme("events submit batch Realm bootstrap", () => {
  test("batch ck.realm.create returns JSON and owner can write immediately", async ({
    request,
  }) => {
    const alice = uniqueUser("events-batch-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const realmId = typedId("realm");
    const createdAt = canonicalTimestamp();
    const plaintextVisibleServices = Array.from(
      new Set([solandServiceDid(), "did:web:soland.local"]),
    );
    const createEnvelope = signedEventEnvelope({
      actorDid: alice.did,
      realmId,
      kind: "ck.realm.create",
      createdAt,
      payload: {
        // realm_create_payload root is additionalProperties:false; the field
        // lives on the realm object (additionalProperties:true) below.
        object: {
          id: realmId,
          schema: "ck.schema.realm.v1",
          title: `Batch bootstrap ${Date.now()}`,
          summary: "cotest batch realm bootstrap fixture",
          created_by: alice.did,
          trust_domain: "ck:trust_domain:soland.local",
          schema_refs: ["ck.schema.realm.v1"],
          default_discoverability: "listed",
          default_join_rule: "invite",
          history_visibility: "shared",
          encryption_profile: "none",
          plaintext_visible_services: plaintextVisibleServices,
          security_class: "standard",
          federation_policy: "restricted",
          notary_profile: "single_did",
          digest_algorithm: "sha256",
          notary: singleDidNotary(alice.did),
          created_at: createdAt,
        },
      },
    });

    const response = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
      headers: authHeaders(aliceToken),
      data: {
        events: [createEnvelope],
        idempotency_key: typedId("operation"),
      },
    });
    const text = await response.text();
    expect(
      [200, 201],
      `batch realm create returned ${response.status()}: ${text}`,
    ).toContain(response.status());
    expect(text.trim(), "batch submit must return a JSON response body").not.toBe("");
    const body = JSON.parse(text) as {
      status?: string;
      accepted?: string[];
      rejected?: unknown[];
    };
    expect(body.status).toBe("accepted");
    expect(body.accepted).toContain(String(createEnvelope.event_id));
    expect(body.rejected ?? []).toEqual([]);

    const message = await sendMessageApi(
      request,
      aliceToken,
      realmId,
      "owner write after batch bootstrap",
    );
    const timeline = await queryRealmEventsApi(request, aliceToken, realmId);
    const events = (timeline.events ?? []) as Array<Record<string, unknown>>;
    expect(events.map((event) => event.event_id)).toContain(message.event_id);
  });
});
