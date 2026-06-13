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
  singleDidAnchorer,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe("events submit batch Realm bootstrap @fully-implemented", () => {
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
          anchor_profile: "single_did",
          digest_algorithm: "sha256",
          anchorer: singleDidAnchorer(alice.did),
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
